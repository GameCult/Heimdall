// Soul attack probes, third pass: R21.1 (attempt-handle binding), R21.2
// (runtime AppCaller brand), R21.3 (registered-app path deletion) and the
// partial unique index on auth_completions(app_slug, attempt_id).
//
// Same convention as the other two Soul files: plain `it` is an invariant
// that currently holds; `it.fails` is a hole this branch does not close.
// The "live postgres" block runs only when SOUL_PG_URL names a reachable
// database; it is skipped in the ordinary suite so the suite stays hermetic.
import { encode, decode } from "@msgpack/msgpack";
import { invokeCultNetOperation } from "cultnet-ts";
import { Pool } from "pg";
import { newDb } from "pg-mem";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp, getHeimdallRuntimeContext, refreshAppSession, startOAuthFlow } from "../src/app.js";
import { type AppCaller, isAppCaller, resolveAppCaller } from "../src/app-caller.js";
import { getAppProfile } from "../src/app-profiles.js";
import { type HeimdallConfig } from "../src/config.js";
import { type AppSlug } from "../src/contracts.js";
import { entitlementFacts } from "../src/facts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { startHeimdallPrivateCommandPlane } from "../src/private-command-plane.js";
import { openPrivateEnvelope, sealPrivateEnvelope, type HeimdallPrivateEnvelope } from "../src/private-command-security.js";
import { InMemoryStore } from "../src/store/index.js";
import { PostgresStore } from "../src/store/postgres.js";
import { CREATE_SCHEMA_SQL } from "../src/store/schema.js";
import { type CreateAuthCompletionInput, type HeimdallStore } from "../src/store/types.js";

const ghostlightSecret = "ghostlight-private-command-secret";
const resources: Array<{ close(): Promise<unknown> }> = [];

afterEach(async () => {
  await Promise.all(resources.splice(0).reverse().map((resource) => resource.close()));
});

function testConfig(overrides: Partial<HeimdallConfig> = {}): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    privateCommandHost: "127.0.0.1",
    privateCommandPort: 0,
    workspaceRoot: "F:/Projects/Heimdall",
    dataRoot: "F:/Projects/Heimdall/.heimdall-data",
    cultCachePath: "F:/Projects/Heimdall/.heimdall-data/cultcache/test.cc",
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    daemonId: "yggdrasil-heimdall",
    idunnRudpHealth: undefined,
    idunnHealthContract: "heimdall.cultnet-rudp-provider-health",
    providerHealthIdentityPath: "F:/Projects/Heimdall/.heimdall-data/provider-health-test.cc",
    sessionTtlSeconds: 3600,
    refreshTtlSeconds: 3600,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    appSharedSecrets: { repixelizer: "repixelizer-secret", ghostlight: ghostlightSecret },
    appRuntimeIds: { ghostlight: ["yggdrasil-ghostlight"] },
    appBackendCallbacks: {},
    storage: { backend: "memory", applySchemaOnStartup: true },
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: {},
      github: {},
      twitch: {},
      youtube: {},
      spotify: {},
    },
    ...overrides,
  };
}

// The provider "code" doubles as the identity: code `victim` resolves to
// discord user `victim`, so one runtime plays every party.
function identityByCodeRuntime(): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode({ code }) {
      return { accessToken: code, tokenType: "Bearer", scope: ["identify"], raw: {} };
    },
    async resolveIdentity({ accessToken }) {
      return { provider: "discord", providerUserId: accessToken, displayName: accessToken, profile: {} };
    },
    async evaluateEntitlements() {
      return { facts: [entitlementFacts.appAccess], snapshots: [] };
    },
  };
}

async function harness(overrides: Partial<HeimdallConfig> = {}) {
  const config = testConfig(overrides);
  const store = new InMemoryStore();
  const app = await buildApp({ config, store, oauthRuntimes: { discord: identityByCodeRuntime() } });
  resources.push(app);
  return { app, store, config };
}

type App = Awaited<ReturnType<typeof harness>>["app"];

async function start(app: App, payload: unknown, headers: Record<string, string> = {}) {
  return app.inject({ method: "POST", url: "/v1/oauth/discord/start", payload: payload as never, headers });
}

async function completeAs(app: App, stateToken: string, who: string) {
  return app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?code=${who}&state=${encodeURIComponent(stateToken)}`,
    headers: { accept: "application/json" },
  });
}

function jwtPayload(token: string): Record<string, unknown> {
  const [, body] = token.split(".");
  return JSON.parse(Buffer.from(body ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
}

function planeRequest(operation: string, messageId: string, envelope: HeimdallPrivateEnvelope) {
  return {
    schemaVersion: "cultnet.operation_request.v0" as const,
    messageId,
    serviceId: "heimdall.private.commands",
    operation,
    payloadSchema: "heimdall.private_command_envelope.v1",
    payloadEncoding: "messagepack-base64" as const,
    payload: Buffer.from(encode(envelope)).toString("base64"),
    sourceRuntimeId: "yggdrasil-ghostlight",
  };
}

async function planeCommand(
  endpoint: Parameters<typeof invokeCultNetOperation>[0],
  operation: string,
  idempotencyKey: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const contentSchema = operation === "heimdall.auth.begin" ? "heimdall.auth_begin_command.v1" : "heimdall.auth_complete_command.v1";
  const envelope = sealPrivateEnvelope({ appSlug: "ghostlight", operation, contentSchema, idempotencyKey, secret: ghostlightSecret, payload });
  const response = await invokeCultNetOperation(endpoint, planeRequest(operation, `msg-${idempotencyKey}`, envelope), {
    runtimeId: "yggdrasil-ghostlight",
  });
  expect(response.status, JSON.stringify(response.diagnostics)).toBe("accepted");
  const wire = decode(Buffer.from(response.payload, "base64")) as HeimdallPrivateEnvelope;
  return openPrivateEnvelope(wire, ghostlightSecret);
}

async function planeHarness() {
  const { app, store, config } = await harness();
  const plane = await startHeimdallPrivateCommandPlane(app, config);
  resources.push(plane);
  const begin = async (key: string) =>
    planeCommand(plane.endpoint, "heimdall.auth.begin", key, {
      provider: "discord",
      mode: "sign_in",
      returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
      entitlementPolicy: { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] },
    });
  const complete = async (key: string, handle: string) => planeCommand(plane.endpoint, "heimdall.auth.complete", key, { handle });
  return { app, store, config, begin, complete };
}

function completionInput(appSlug: AppSlug, accountId: string, sessionId: string, attemptId?: string): CreateAuthCompletionInput {
  const now = new Date();
  return {
    ...(attemptId ? { attemptId } : {}),
    appSlug,
    provider: "discord",
    mode: "sign_in",
    accountId,
    sessionId,
    returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    payloadJson: { marker: attemptId ?? "none" },
  };
}

// Seeds the account/session rows the FK constraints on auth_completions
// require in postgres; harmless in memory.
async function seedAccountAndSession(store: HeimdallStore, appSlug: AppSlug) {
  const now = new Date().toISOString();
  const account = await store.createAccount({ createdAt: now, lastSeenAt: now });
  const session = await store.createSession({
    id: `sess-${account.id}`,
    accountId: account.id,
    appSlug,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    claimsJson: {},
    accessRevision: 0,
  });
  return { accountId: account.id, sessionId: session.id };
}

describe("R21.1: the attempt handle is unreachable from the public start route", () => {
  const legitReturn = "https://yggdrasil.gamecult.org/ghostlight/";

  it("a well-formed browser_completion attemptId is dropped before the state token is signed", async () => {
    const { app, store } = await harness();
    const attempt = await store.createAuthAttempt({
      appSlug: "ghostlight",
      provider: "discord",
      mode: "sign_in",
      returnTo: legitReturn,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });
    const response = await start(app, {
      appSlug: "ghostlight",
      mode: "sign_in",
      returnTo: legitReturn,
      handoff: { kind: "browser_completion", attemptId: attempt.handle },
    });
    expect(response.statusCode, response.body).toBe(201);
    expect(response.json().handoff).toEqual({ kind: "browser_completion" });
    const state = jwtPayload(response.json().stateToken as string);
    expect(state.handoff).toEqual({ kind: "browser_completion" });
    expect(JSON.stringify(state)).not.toContain(attempt.handle);
  });

  // Fastify's default AJV runs with removeAdditional and coerceTypes:"array",
  // so `additionalProperties: false` strips unknown keys instead of
  // rejecting, and `["h"]` is coerced to "h". The oracle is therefore not
  // the status code: it is that the planted value is absent from the
  // response's handoff and from the signed state payload.
  const planted = "planted-handle-7f3a";
  it.each([
    ["differently-cased key", { kind: "browser_completion", AttemptId: planted }],
    ["snake_case key", { kind: "browser_completion", attempt_id: planted }],
    ["array value (coerced to a string by AJV)", { kind: "browser_completion", attemptId: [planted] }],
    ["object value", { kind: "browser_completion", attemptId: { value: planted } }],
    ["nested handoff", { kind: "browser_completion", handoff: { attemptId: planted } }],
    ["empty string", { kind: "browser_completion", attemptId: "" }],
  ])("a %s attemptId never reaches the state token", async (_label, handoff) => {
    const { app } = await harness();
    const response = await start(app, { appSlug: "ghostlight", mode: "sign_in", returnTo: legitReturn, handoff });
    expect(response.body).not.toContain(planted);
    if (response.statusCode === 201) {
      expect(response.json().handoff).toEqual({ kind: "browser_completion" });
      expect(jwtPayload(response.json().stateToken as string).handoff).toEqual({ kind: "browser_completion" });
    } else {
      expect(response.statusCode, response.body).toBe(400);
    }
  });

  it("a top-level attemptId / trustedBrowserAttemptId / options field on the body is stripped, never bound", async () => {
    const { app } = await harness();
    for (const extra of [{ attemptId: planted }, { trustedBrowserAttemptId: planted }, { options: { trustedBrowserAttemptId: planted } }]) {
      const response = await start(app, { appSlug: "ghostlight", mode: "sign_in", returnTo: legitReturn, ...extra });
      expect(response.statusCode, response.body).toBe(201);
      expect(response.body).not.toContain(planted);
      expect(jwtPayload(response.json().stateToken as string).handoff).toEqual({ kind: "browser_completion" });
    }
  });

  it("startOAuthFlow has exactly two callers and only beginAuth passes the options argument", async () => {
    const { readFileSync, readdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    const srcDir = join(process.cwd(), "src");
    const callers: string[] = [];
    for (const file of readdirSync(srcDir, { recursive: true }) as string[]) {
      if (!file.endsWith(".ts")) continue;
      const source = readFileSync(join(srcDir, file), "utf8");
      const calls = source.match(/(?<!function )startOAuthFlow\(/g) ?? [];
      if (calls.length) callers.push(`${file}:${calls.length}`);
      if (file.endsWith("app.ts")) {
        // The HTTP route's call ends at the body; no fifth argument.
        expect(source).toMatch(/startOAuthFlow\(\{ config, keys, store \}, request\.params\.provider, caller, request\.body\);/);
      }
    }
    expect(callers.sort()).toEqual(["app.ts:1", "private-command-plane.ts:1"]);
  });

  it("legit flow: beginAuth binds its own handle, the callback correlates it, completeAuth redeems it", async () => {
    const { app, store, begin, complete } = await planeHarness();
    const receipt = await begin("begin-legit");
    expect(receipt.status).toBe("pending");
    const handle = String(receipt.handle);
    const navigation = receipt.navigation as { url: string };
    const state = new URL(navigation.url).searchParams.get("state") ?? "";
    expect(jwtPayload(state).handoff).toEqual({ kind: "browser_completion", attemptId: handle });

    const callback = await completeAs(app, state, "victim");
    expect(callback.statusCode, callback.body).toBe(201);
    expect((await store.findAuthAttempt("ghostlight", handle))?.status).toBe("completed");

    const completed = await complete("complete-legit", handle);
    expect(completed.status).toBe("authenticated");
    expect(completed.handle).toBe(handle);
    expect(completed.accessToken).toEqual(expect.any(String));
    expect((await store.findAuthAttempt("ghostlight", handle))?.status).toBe("consumed");
  });

  it("a stranger cannot pre-occupy the app's pending handle so that the victim's own completion collides", async () => {
    const { app, store, begin, complete } = await planeHarness();
    const receipt = await begin("begin-victim");
    const handle = String(receipt.handle);
    const victimState = new URL((receipt.navigation as { url: string }).url).searchParams.get("state") ?? "";

    // Attacker names the victim's handle on the public start route, then
    // completes as themselves before the victim does.
    const attackerStart = await start(app, {
      appSlug: "ghostlight",
      mode: "sign_in",
      returnTo: legitReturn,
      handoff: { kind: "browser_completion", attemptId: handle },
    });
    expect(attackerStart.statusCode).toBe(201);
    const attackerCallback = await completeAs(app, attackerStart.json().stateToken as string, "attacker");
    expect(attackerCallback.statusCode, attackerCallback.body).toBe(201);
    expect((await store.findAuthAttempt("ghostlight", handle))?.status).toBe("pending");

    // Victim completes; the handle's single unconsumed slot is still free.
    const victimCallback = await completeAs(app, victimState, "victim");
    expect(victimCallback.statusCode, victimCallback.body).toBe(201);
    const completed = await complete("complete-victim", handle);
    expect(completed.status).toBe("authenticated");
    // ...and the tokens are the victim's, not the attacker's.
    const claims = jwtPayload(String(completed.accessToken));
    expect(JSON.stringify(claims)).toContain("victim");
    expect(JSON.stringify(claims)).not.toContain("attacker");
  });

  it("a backend_callback attemptId (the other handoff kind that carries one) never touches an auth attempt", async () => {
    const { app, store } = await harness({ appBackendCallbacks: { ghostlight: ["http://127.0.0.1:1/never"] } });
    const attempt = await store.createAuthAttempt({
      appSlug: "ghostlight",
      provider: "discord",
      mode: "sign_in",
      returnTo: legitReturn,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });
    const response = await start(app, {
      appSlug: "ghostlight",
      mode: "sign_in",
      returnTo: legitReturn,
      handoff: { kind: "backend_callback", attemptId: attempt.handle, callbackUrl: "http://127.0.0.1:1/never" },
    });
    expect(response.statusCode, response.body).toBe(201);
    // Delivery to port 1 fails; whatever the callback returns, the attempt
    // must be untouched and no completion may be bound to it.
    await completeAs(app, response.json().stateToken as string, "attacker");
    expect((await store.findAuthAttempt("ghostlight", attempt.handle))?.status).toBe("pending");
    expect(await store.consumeAuthCompletionByAttempt("ghostlight", attempt.handle, new Date().toISOString())).toBeNull();
  });
});

describe("R21.2: the WeakSet brand at every consumer", () => {
  it("every function that takes an AppCaller checks isAppCaller before reading appSlug", async () => {
    const { readFileSync, readdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    const srcDir = join(process.cwd(), "src");
    const consumers: string[] = [];
    for (const file of readdirSync(srcDir, { recursive: true }) as string[]) {
      if (!file.endsWith(".ts") || file.endsWith("app-caller.ts")) continue;
      const source = readFileSync(join(srcDir, file), "utf8");
      const readsSlug = source.match(/caller\.appSlug/g) ?? [];
      const guards = source.match(/isAppCaller\(caller\)/g) ?? [];
      if (readsSlug.length) consumers.push(`${file}: reads=${readsSlug.length} guards=${guards.length}`);
      // Every `caller.appSlug` read is on a line that also carries the guard.
      for (const line of source.split("\n")) {
        if (line.includes("caller.appSlug")) expect(line, `${file}: ${line.trim()}`).toContain("isAppCaller(caller)");
      }
    }
    expect(consumers).toEqual(["app.ts: reads=2 guards=2"]);
  });

  it("a caller minted for app A is refused where app B is expected, over HTTP and by direct call", async () => {
    const { app, config } = await harness();
    const ctx = getHeimdallRuntimeContext(app);
    const repixelizerCaller = resolveAppCaller(config, "repixelizer", { "x-heimdall-app-secret": "repixelizer-secret" });
    expect(isAppCaller(repixelizerCaller)).toBe(true);

    const startResult = await startOAuthFlow(ctx, "discord", repixelizerCaller, {
      appSlug: "ghostlight",
      mode: "sign_in",
      returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
      entitlementPolicy: { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] },
    });
    expect(startResult.statusCode).toBe(401);
    expect(startResult.body).toMatchObject({ error: "app_auth_required" });

    const refreshResult = await refreshAppSession(ctx, "ghostlight", repixelizerCaller, {
      refreshToken: "x",
      entitlementPolicies: [{ kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] }],
    });
    expect(refreshResult.statusCode).toBe(401);

    // Over HTTP: repixelizer's real secret on a ghostlight start with policy.
    const http = await start(
      app,
      {
        appSlug: "ghostlight",
        mode: "sign_in",
        returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
        entitlementPolicy: { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] },
      },
      { "x-heimdall-app-secret": "repixelizer-secret" },
    );
    expect(http.statusCode).toBe(401);
  });

  it("symbol-copying, prototype-chaining, Proxy-wrapping and structuredClone forgeries are all refused", async () => {
    const { config } = await harness();
    const real = resolveAppCaller(config, "repixelizer", { "x-heimdall-app-secret": "repixelizer-secret" }) as AppCaller;
    const [brandSymbol] = Object.getOwnPropertySymbols(real);
    expect(brandSymbol).toBeDefined();

    const symbolCopy = { appSlug: "ghostlight", [brandSymbol as symbol]: true };
    const chained = Object.assign(Object.create(real) as object, { appSlug: "ghostlight" });
    const proxied = new Proxy(real, { get: (target, key) => (key === "appSlug" ? "ghostlight" : Reflect.get(target, key)) });
    const spread = { ...real, appSlug: "ghostlight" };
    const cloned = structuredClone({ appSlug: real.appSlug });
    for (const forgery of [symbolCopy, chained, proxied, spread, cloned]) {
      expect(isAppCaller(forgery)).toBe(false);
    }
    // The real object is mutable in principle, but its slug is readonly by
    // type and there is no setter; a mutated real object would still be
    // branded. Record that as the one forgery the WeakSet cannot see.
    const mutated = real as { appSlug: string };
    mutated.appSlug = "ghostlight";
    expect(isAppCaller(mutated)).toBe(true);
    expect(Object.isFrozen(real)).toBe(false);
  });
});

async function twoCompletionsForOneHandle(store: HeimdallStore, appSlug: AppSlug = "ghostlight") {
  const { accountId, sessionId } = await seedAccountAndSession(store, appSlug);
  const results = await Promise.allSettled([
    store.createAuthCompletion(completionInput(appSlug, accountId, sessionId, "handle-1")),
    store.createAuthCompletion(completionInput(appSlug, accountId, sessionId, "handle-1")),
  ]);
  return { results, accountId, sessionId };
}

function partialUniqueIndexContract(label: string, makeStore: () => Promise<HeimdallStore>) {
  describe(`partial unique index contract: ${label}`, () => {
    it("two concurrent completions for one handle: exactly one is minted", async () => {
      const store = await makeStore();
      const { results } = await twoCompletionsForOneHandle(store);
      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      const live = await store.consumeAuthCompletionByAttempt("ghostlight", "handle-1", new Date().toISOString());
      expect(live?.attemptId).toBe("handle-1");
      expect(await store.consumeAuthCompletionByAttempt("ghostlight", "handle-1", new Date().toISOString())).toBeNull();
    });

    it("the predicate: NULL handles never collide, a consumed handle frees its slot, other apps do not collide", async () => {
      const store = await makeStore();
      const g = await seedAccountAndSession(store, "ghostlight");
      const r = await seedAccountAndSession(store, "repixelizer");
      await store.createAuthCompletion(completionInput("ghostlight", g.accountId, g.sessionId));
      await store.createAuthCompletion(completionInput("ghostlight", g.accountId, g.sessionId));
      const first = await store.createAuthCompletion(completionInput("ghostlight", g.accountId, g.sessionId, "shared"));
      await expect(store.createAuthCompletion(completionInput("repixelizer", r.accountId, r.sessionId, "shared"))).resolves.toBeTruthy();
      await expect(store.createAuthCompletion(completionInput("ghostlight", g.accountId, g.sessionId, "shared"))).rejects.toThrow();
      expect(await store.consumeAuthCompletion("ghostlight", first.code, new Date().toISOString())).toBeTruthy();
      const second = await store.createAuthCompletion(completionInput("ghostlight", g.accountId, g.sessionId, "shared"));
      expect(second.code).not.toBe(first.code);
      const byAttempt = await store.consumeAuthCompletionByAttempt("ghostlight", "shared", new Date().toISOString());
      expect(byAttempt?.code).toBe(second.code);
    });

    it("an expired-but-unconsumed completion still occupies the slot (both stores agree; neither frees it)", async () => {
      const store = await makeStore();
      const g = await seedAccountAndSession(store, "ghostlight");
      const stale = completionInput("ghostlight", g.accountId, g.sessionId, "stale");
      stale.expiresAt = new Date(Date.now() - 1000).toISOString();
      await store.createAuthCompletion(stale);
      expect(await store.consumeAuthCompletionByAttempt("ghostlight", "stale", new Date().toISOString())).toBeNull();
      await expect(store.createAuthCompletion(completionInput("ghostlight", g.accountId, g.sessionId, "stale"))).rejects.toThrow();
    });
  });
}

partialUniqueIndexContract("InMemoryStore", async () => new InMemoryStore());
partialUniqueIndexContract("PostgresStore over pg-mem", async () => {
  const adapter = newDb().adapters.createPg();
  const store = new PostgresStore(new adapter.Pool());
  await store.ensureSchema();
  return store;
});

describe("duplicate-handle error surfacing through the callback route", () => {
  it("state tokens are replayable, and a replay while the handle's completion is unconsumed echoes the store error in a 502", async () => {
    const { app, store, begin } = await planeHarness();
    const receipt = await begin("begin-replay");
    const handle = String(receipt.handle);
    const state = new URL((receipt.navigation as { url: string }).url).searchParams.get("state") ?? "";
    const first = await completeAs(app, state, "victim");
    expect(first.statusCode).toBe(201);
    const replay = await completeAs(app, state, "victim");
    // Nothing consumed the state's jti: the second exchange runs, reaches
    // createAuthCompletion, and the store's duplicate-handle throw is
    // caught by the route's generic catch (app.ts ~1290) as a 502 whose
    // `detail` is the raw store message. Postgres would put its constraint
    // name there instead (see the live block below).
    expect(replay.statusCode, replay.body).toBe(502);
    expect(replay.json()).toMatchObject({ error: "oauth_callback_failed", detail: "Attempt handle already has an unconsumed completion." });
    // The failed replay must not have damaged the real completion.
    expect((await store.findAuthAttempt("ghostlight", handle))?.status).toBe("completed");
    expect(await store.consumeAuthCompletionByAttempt("ghostlight", handle, new Date().toISOString())).toBeTruthy();
  });
});

describe("R21.3: sync getAppProfile at the seven former resolveAppProfile sites", () => {
  it("getAppProfile is a plain object index: prototype keys resolve to non-profiles", () => {
    expect(getAppProfile("nope" as AppSlug)).toBeUndefined();
    // Object.prototype members leak through a bare `record[key]` lookup.
    for (const key of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      const value = getAppProfile(key as AppSlug);
      expect(value, key).toBeDefined();
      expect(typeof (value as { slug?: unknown }).slug, key).not.toBe("string");
    }
  });

  // Open hole, inherited from main: the pre-R21.3 resolveAppProfile did the
  // same bare `builtInAppProfiles[slug]` index, and this is the one route
  // whose params schema has no slug enum. `constructor` returns 200 `{}`
  // because serializeAppProfile(Object) serialises undefined fields. Fix is
  // Object.hasOwn in getAppProfile (or the enum on this route); promote when
  // closed.
  it.fails("GET /v1/apps/:appSlug is the one route without the slug enum; a prototype key must still be a 404", async () => {
    const { app } = await harness();
    // Null prototype so the "__proto__" key is a key, not a setter.
    const statuses: Record<string, string> = Object.create(null) as Record<string, string>;
    for (const key of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) {
      const response = await app.inject({ method: "GET", url: `/v1/apps/${key}` });
      statuses[key] = `${response.statusCode} ${response.body.slice(0, 60)}`;
    }
    process.stdout.write(`\n[soul] GET /v1/apps/<prototype key>: ${JSON.stringify(statuses)}\n`);
    expect(statuses).toEqual(Object.fromEntries(Object.keys(statuses).map((key) => [key, expect.stringMatching(/^404 /)])));
  });

  it("every other appSlug parameter is enum-gated, so an unknown slug is a 400 there and a 404 only on the profile read", async () => {
    const { app } = await harness();
    expect((await app.inject({ method: "GET", url: "/v1/apps/nope" })).statusCode).toBe(404);
    expect((await start(app, { appSlug: "nope", mode: "sign_in", returnTo: "https://x.example/" })).statusCode).toBe(400);
    for (const url of [
      "/v1/apps/nope/auth-completions/redeem",
      "/v1/apps/nope/sessions/refresh",
      "/v1/apps/nope/patron-support/sync",
      "/v1/apps/nope/managed-credentials/resolve",
    ]) {
      const response = await app.inject({ method: "POST", url, payload: { completionCode: "c", refreshToken: "r", accountId: "a", provider: "discord" } });
      expect(response.statusCode, url).toBe(400);
    }
  });

  it("the migration adds attempt_id before the partial index that references it, and drops registered_apps first", () => {
    const addColumn = CREATE_SCHEMA_SQL.indexOf("ALTER TABLE auth_completions ADD COLUMN IF NOT EXISTS attempt_id TEXT");
    const dropOldIndex = CREATE_SCHEMA_SQL.indexOf("DROP INDEX IF EXISTS auth_completions_attempt_idx");
    const createIndex = CREATE_SCHEMA_SQL.indexOf("CREATE UNIQUE INDEX IF NOT EXISTS auth_completions_attempt_unconsumed_unique_idx");
    const dropTable = CREATE_SCHEMA_SQL.indexOf("DROP TABLE IF EXISTS registered_apps");
    expect(dropTable).toBeGreaterThanOrEqual(0);
    expect(addColumn).toBeGreaterThan(dropTable);
    expect(dropOldIndex).toBeGreaterThan(addColumn);
    expect(createIndex).toBeGreaterThan(dropOldIndex);
    // Statement count, not token count (the comment above the DROP names it too).
    expect(CREATE_SCHEMA_SQL.match(/DROP TABLE IF EXISTS registered_apps/g)).toHaveLength(1);
    expect(CREATE_SCHEMA_SQL).not.toMatch(/CREATE TABLE[^;]*registered_apps/);
  });
  // Re-running ensureSchema on a store built before this branch (table
  // present, column absent, old index name) cannot be simulated in pg-mem —
  // it rejects CREATE TABLE IF NOT EXISTS on an existing table — so that
  // path is proved only by the live block below.
});

const livePg = process.env.SOUL_PG_URL;
describe.skipIf(!livePg)("live postgres (SOUL_PG_URL)", () => {
  it("real partial index: 23505 names auth_completions_attempt_unconsumed_unique_idx; schema applies twice on a pre-branch store", async () => {
    const pool = new Pool({ connectionString: livePg });
    resources.push({ close: () => pool.end() });
    await pool.query(`
      DROP SCHEMA public CASCADE; CREATE SCHEMA public;
      CREATE TABLE registered_apps (slug TEXT PRIMARY KEY);
      CREATE TABLE accounts (id TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL, display_name TEXT, primary_email TEXT);
      CREATE TABLE sessions (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, app_slug TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, claims_json JSONB NOT NULL, access_revision INTEGER NOT NULL);
      CREATE TABLE auth_completions (
        code TEXT PRIMARY KEY, app_slug TEXT NOT NULL, provider TEXT NOT NULL, mode TEXT NOT NULL,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        return_to TEXT NOT NULL, payload_json JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ
      );
    `);
    const store = new PostgresStore(pool);
    await store.ensureSchema();
    await store.ensureSchema();
    const tables = await pool.query<{ table_name: string }>("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1");
    expect(tables.rows.map((r) => r.table_name)).not.toContain("registered_apps");
    const indexes = await pool.query<{ indexdef: string }>("SELECT indexdef FROM pg_indexes WHERE tablename = 'auth_completions' ORDER BY 1");
    const partial = indexes.rows.find((r) => r.indexdef.includes("auth_completions_attempt_unconsumed_unique_idx"));
    expect(partial?.indexdef).toContain("WHERE ((attempt_id IS NOT NULL) AND (consumed_at IS NULL))");

    const { results } = await twoCompletionsForOneHandle(store);
    const rejected = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const error = rejected?.reason as { code?: string; message?: string };
    expect(error.code).toBe("23505");
    expect(error.message).toContain("auth_completions_attempt_unconsumed_unique_idx");
    // What the callback route's catch would echo as `detail`.
    process.stdout.write(`\n[soul live pg] 23505 message: ${error.message}\n`);
  }, 30_000);
});
