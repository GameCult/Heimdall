// Soul attack probes for the caller-identity cut, second pass.
//
// Same convention as caller-identity-soul.test.ts: plain `it` is an invariant
// that currently holds; `it.fails` is a hole the cut does not close (vitest
// passes the case while the body fails; close the hole and promote it).
import { afterEach, describe, expect, it } from "vitest";
import { buildApp, refreshAppSession } from "../src/app.js";
import { type AppCaller } from "../src/app-caller.js";
import { builtInAppProfiles, isAllowedReturnOrigin } from "../src/app-profiles.js";
import { type HeimdallConfig } from "../src/config.js";
import { entitlementFacts } from "../src/facts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { InMemoryStore } from "../src/store/index.js";

const resources: Array<{ close(): Promise<unknown> }> = [];

afterEach(async () => {
  await Promise.all(resources.splice(0).reverse().map((resource) => resource.close()));
});

function testConfig(): HeimdallConfig {
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
    appSharedSecrets: { repixelizer: "repixelizer-secret", ghostlight: "ghostlight-secret" },
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
  };
}

// The provider "code" doubles as the identity so one runtime can play both
// victim and attacker: code `victim` resolves to discord user `victim`.
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

async function harness() {
  const store = new InMemoryStore();
  const app = await buildApp({ config: testConfig(), store, oauthRuntimes: { discord: identityByCodeRuntime() } });
  resources.push(app);
  return { app, store };
}

type App = Awaited<ReturnType<typeof harness>>["app"];

async function start(app: App, payload: Record<string, unknown>, headers: Record<string, string> = {}) {
  return app.inject({ method: "POST", url: "/v1/oauth/discord/start", payload, headers });
}

async function completeAs(app: App, stateToken: string, who: string) {
  return app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?code=${who}&state=${encodeURIComponent(stateToken)}`,
    headers: { accept: "application/json" },
  });
}

async function redeem(app: App, appSlug: string, completionCode: string) {
  return app.inject({ method: "POST", url: `/v1/apps/${appSlug}/auth-completions/redeem`, payload: { completionCode } });
}

const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("takeover chain: caller-chosen attemptId is never the redemption code", () => {
  it("attacker fixes attemptId, victim completes, attemptId does not redeem; the minted code is a fresh uuid v4", async () => {
    const { app } = await harness();
    const started = await start(app, {
      appSlug: "repixelizer",
      mode: "sign_in",
      returnTo: "https://repixelizer.gamecult.org/app/",
      handoff: { kind: "browser_completion", attemptId: "attacker-fixed" },
    });
    expect(started.statusCode).toBe(201);

    const callback = await completeAs(app, started.json().stateToken as string, "victim");
    expect(callback.statusCode).toBe(201);
    const minted = callback.json().completion.code as string;
    expect(minted).not.toBe("attacker-fixed");
    expect(minted).toMatch(uuidV4);

    const byAttempt = await redeem(app, "repixelizer", "attacker-fixed");
    expect(byAttempt.statusCode).toBe(410);
    expect(byAttempt.json()).toEqual({ error: "invalid_or_expired_completion_code" });
  });

  it("omitting handoff still mints a uuid v4 code; the attempt handle is absent from the completion", async () => {
    const { app, store } = await harness();
    const started = await start(app, { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" });
    expect(started.statusCode).toBe(201);
    const callback = await completeAs(app, started.json().stateToken as string, "victim");
    expect(callback.statusCode).toBe(201);
    const code = callback.json().completion.code as string;
    expect(code).toMatch(uuidV4);
    const stored = (store as unknown as { authCompletions: Map<string, { attemptId?: string }> }).authCompletions.get(code);
    expect(stored?.attemptId).toBeUndefined();
  });

  it("handoff.kind backend_callback with an attemptId is refused unless the callbackUrl is configured", async () => {
    const { app } = await harness();
    const started = await start(app, {
      appSlug: "repixelizer",
      mode: "sign_in",
      returnTo: "https://repixelizer.gamecult.org/app/",
      handoff: { kind: "backend_callback", attemptId: "attacker-fixed", callbackUrl: "https://attacker.example/cb" },
    });
    expect(started.statusCode).toBe(400);
    expect(started.json().error).toBe("untrusted_backend_callback");
  });

  it("an unknown handoff.kind is rejected by the schema", async () => {
    const { app } = await harness();
    const started = await start(app, {
      appSlug: "repixelizer",
      mode: "sign_in",
      returnTo: "https://repixelizer.gamecult.org/app/",
      handoff: { kind: "evil", attemptId: "attacker-fixed" },
    });
    expect(started.statusCode).toBe(400);
  });

  it("attemptId set to a real victim completion code does not let the attacker's flow touch the victim's completion", async () => {
    const { app } = await harness();
    const victimStart = await start(app, { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" });
    const victimCallback = await completeAs(app, victimStart.json().stateToken as string, "victim");
    const victimCode = victimCallback.json().completion.code as string;

    const attackerStart = await start(app, {
      appSlug: "repixelizer",
      mode: "sign_in",
      returnTo: "https://repixelizer.gamecult.org/app/",
      handoff: { kind: "browser_completion", attemptId: victimCode },
    });
    const attackerCallback = await completeAs(app, attackerStart.json().stateToken as string, "attacker");
    expect(attackerCallback.statusCode).toBe(201);
    expect(attackerCallback.json().completion.code).not.toBe(victimCode);

    // The victim's code still redeems the victim, once.
    const first = await redeem(app, "repixelizer", victimCode);
    expect(first.statusCode).toBe(201);
    expect(first.json().account.displayName).toBe("victim");
  });

  it("the redeem route is unauthenticated, so the code is the whole secret: 122 bits of CSPRNG, distinct across mints", async () => {
    const store = new InMemoryStore();
    const codes = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const completion = await store.createAuthCompletion({
        appSlug: "repixelizer",
        provider: "discord",
        mode: "sign_in",
        accountId: "a",
        sessionId: "s",
        returnTo: "https://repixelizer.gamecult.org/app/",
        createdAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2999-01-01T00:00:00.000Z",
        payloadJson: {},
      });
      expect(completion.code).toMatch(uuidV4);
      codes.add(completion.code);
    }
    expect(codes.size).toBe(200);
  });
});

describe("consumeAuthCompletion: single-use, scoped, expiring", () => {
  it("a code redeems exactly once under concurrent redemption, and never for another app", async () => {
    const { app } = await harness();
    const started = await start(app, { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" });
    const callback = await completeAs(app, started.json().stateToken as string, "victim");
    const code = callback.json().completion.code as string;

    const crossApp = await redeem(app, "bifrost", code);
    expect(crossApp.statusCode).toBe(410);

    const results = await Promise.all([redeem(app, "repixelizer", code), redeem(app, "repixelizer", code), redeem(app, "repixelizer", code)]);
    expect(results.map((r) => r.statusCode).sort()).toEqual([201, 410, 410]);
  });

  it("an expired completion is not consumable, by code or by attempt", async () => {
    const store = new InMemoryStore();
    const completion = await store.createAuthCompletion({
      attemptId: "h1",
      appSlug: "repixelizer",
      provider: "discord",
      mode: "sign_in",
      accountId: "a",
      sessionId: "s",
      returnTo: "https://repixelizer.gamecult.org/app/",
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:05:00.000Z",
      payloadJson: {},
    });
    expect(await store.consumeAuthCompletion("repixelizer", completion.code, "2026-01-01T00:05:00.000Z")).toBeNull();
    expect(await store.consumeAuthCompletionByAttempt("repixelizer", "h1", "2026-01-01T00:05:00.000Z")).toBeNull();
    expect(await store.consumeAuthCompletionByAttempt("bifrost", "h1", "2026-01-01T00:04:00.000Z")).toBeNull();
    expect(await store.consumeAuthCompletionByAttempt("repixelizer", "h1", "2026-01-01T00:04:00.000Z")).not.toBeNull();
    expect(await store.consumeAuthCompletionByAttempt("repixelizer", "h1", "2026-01-01T00:04:00.000Z")).toBeNull();
  });
});

describe("attempt-handle binding: the public start route may attach a completion to any attempt", () => {
  // Hole. The private plane creates attempt H for its app and later redeems
  // by handle (consumeAuthCompletionByAttempt). The public start route
  // accepts handoff.attemptId = H from anyone, and the callback stores a
  // completion under attempt_id = H and flips attempt H to "completed".
  // Nothing checks that the flow carrying attemptId H was the flow the plane
  // started for H. Whoever learns H (Bifrost puts it in the wait-page URL)
  // can bind their own provider identity to the app's pending attempt, and
  // the app's completeAuth(H) then authenticates the victim's app session as
  // the attacker. Exploitability rests on H leaking; the binding gap itself
  // is real. Close it by refusing an attemptId at the public start route
  // unless the caller is the app (AppCaller), or by having the store refuse
  // to create a completion for an attempt whose state token it did not mint.
  it.fails("a public flow carrying the app's attempt handle must not complete that attempt", async () => {
    const { app, store } = await harness();
    const attempt = await store.createAuthAttempt({
      appSlug: "ghostlight",
      provider: "discord",
      mode: "sign_in",
      returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });

    const attackerStart = await start(app, {
      appSlug: "ghostlight",
      mode: "sign_in",
      returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
      handoff: { kind: "browser_completion", attemptId: attempt.handle },
    });
    expect(attackerStart.statusCode).toBe(201);
    await completeAs(app, attackerStart.json().stateToken as string, "attacker");

    const after = await store.findAuthAttempt("ghostlight", attempt.handle);
    expect(after?.status).toBe("pending");
    const bound = await store.consumeAuthCompletionByAttempt("ghostlight", attempt.handle, new Date().toISOString());
    expect(bound).toBeNull();
  });
});

describe("isAllowedReturnOrigin: origin comparison, not string matching", () => {
  const profile = builtInAppProfiles.repixelizer;
  const rejected = [
    "https://repixelizer.gamecult.org.evil.com/",
    "https://evil.com/?x=https://repixelizer.gamecult.org",
    "https://repixelizer.gamecult.org@evil.com/",
    "https://evil.com#https://repixelizer.gamecult.org",
    "//repixelizer.gamecult.org/app/",
    "http://repixelizer.gamecult.org/app/",
    "https://repixelizer.gamecult.org:8443/app/",
    "https://repixelizer.gamecult.org./app/",
    "https://xn--repixelizer-gamecult.org/",
    "javascript:alert(1)",
    "data:text/html,hi",
    "not a url",
    "",
    "https://repixelizer.gamecult.org.",
    "https://repixelizer.gamecult.orgx/",
    "https://sub.repixelizer.gamecult.org/",
  ];
  it.each(rejected)("rejects %s", (returnTo) => {
    expect(isAllowedReturnOrigin(profile, returnTo)).toBe(false);
  });

  // Accepted variants are all the same origin after WHATWG normalisation;
  // they are listed so a future "fix" that switches to string comparison
  // shows up as a behaviour change here rather than silently in production.
  const acceptedSameOrigin = [
    "https://repixelizer.gamecult.org",
    "https://repixelizer.gamecult.org/app/",
    "https://REPIXELIZER.GameCult.org/app/",
    "https://repixelizer.gamecult.org:443/app/",
    "https:/\\repixelizer.gamecult.org/app/",
    "https://user:pw@repixelizer.gamecult.org/app/",
    "https://repixelizer.gamecult.org/app/?returnTo=https://evil.com",
  ];
  it.each(acceptedSameOrigin)("accepts %s (same origin after URL parsing)", (returnTo) => {
    expect(new URL(returnTo).origin).toBe("https://repixelizer.gamecult.org");
    expect(isAllowedReturnOrigin(profile, returnTo)).toBe(true);
  });

  it("an empty allowlist denies everything rather than passing vacuously", () => {
    expect(isAllowedReturnOrigin({ ...profile, allowedReturnOrigins: [] }, "https://repixelizer.gamecult.org/")).toBe(false);
  });

  it("a registered app with no parseable redirect URIs cannot start a flow through HTTP at all (slug enum) and gets an empty allowlist", async () => {
    const store = new InMemoryStore();
    store.seedRegisteredApp({
      slug: "newapp",
      displayName: "New",
      profileVersion: "1",
      identityProviders: ["discord"],
      entitlementSources: [],
      managedConnectionProviders: [],
      capabilities: [],
      redirectUris: ["garbage"],
      clientSecretHash: "x",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    } as never);
    const app = await buildApp({ config: testConfig(), store, oauthRuntimes: { discord: identityByCodeRuntime() } });
    resources.push(app);
    const started = await start(app, { appSlug: "newapp", mode: "sign_in", returnTo: "https://anything.example/" });
    expect(started.statusCode).toBe(400);
  });
});

describe("AppCaller brand: compile-time only", () => {
  // Hole, by construction rather than by accident: the symbol brand stops a
  // TypeScript importer from writing `{ appSlug }`, and nothing else. No
  // handler inspects the brand at runtime, so a forged literal that reaches
  // refreshAppSession via `as unknown as AppCaller`, plain JS, or a JSON
  // round-trip is honoured. The barrier is type-checking plus the two
  // constructor call sites, and the grep test in caller-identity-soul.test.ts
  // is what stands guard over those call sites.
  it.fails("a forged caller literal is refused at runtime", async () => {
    const { app } = await harness();
    const context = (app as unknown as { heimdallContext: Parameters<typeof refreshAppSession>[0] }).heimdallContext;
    const forged = { appSlug: "repixelizer" } as unknown as AppCaller;
    const result = await refreshAppSession(context, "repixelizer", forged, {
      refreshToken: "not-a-token",
      entitlementPolicies: [{ kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] }],
    } as never);
    // With a forged caller the request gets past the caller gate and fails
    // later on the bogus refresh token (401 invalid_refresh_token / similar);
    // a runtime brand check would return app_auth_required here.
    expect(result.body).toMatchObject({ error: "app_auth_required" });
  });
});
