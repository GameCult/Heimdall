// Soul falsification probes for the caller-identity cut (epiphany/heimdall-caller-identity).
//
// Two kinds of test live here:
//   - plain `it(...)`: an invariant the cut claims and that currently holds.
//   - `it.fails(...)`: an invariant the cut does NOT yet enforce. vitest passes
//     the case while the body fails; when someone closes the hole the case
//     flips to a real failure and must be promoted to a plain `it`.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { encode } from "@msgpack/msgpack";
import { invokeCultNetOperation } from "cultnet-ts";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp, refreshAppSession, startOAuthFlow } from "../src/app.js";
import { secretMatches } from "../src/app-caller.js";
import { type HeimdallConfig } from "../src/config.js";
import { entitlementFacts } from "../src/facts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { startHeimdallPrivateCommandPlane } from "../src/private-command-plane.js";
import { sealPrivateEnvelope, type HeimdallPrivateEnvelope } from "../src/private-command-security.js";
import { InMemoryStore } from "../src/store/index.js";

const ghostlightSecret = "ghostlight-private-command-secret";
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
  };
}

function mockDiscordRuntime(): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "provider-access", tokenType: "Bearer", scope: ["identify"], raw: {} };
    },
    async resolveIdentity() {
      return { provider: "discord", providerUserId: "discord-victim", displayName: "Victim", profile: {} };
    },
    async evaluateEntitlements() {
      return { facts: [entitlementFacts.appAccess], snapshots: [] };
    },
  };
}

describe("caller identity: unauthenticated mint paths", () => {
  // Item 1. The browser flow is public by design, but the completion code is
  // chosen by whoever starts the flow (handoff.attemptId becomes the
  // completion code verbatim, src/app.ts createAuthCompletion `code:
  // handoff.attemptId`), and auth-completions/redeem takes no app secret.
  // An unauthenticated party can therefore fix the code, get a victim to
  // finish provider login on the authorization URL, and redeem the victim's
  // signed access + refresh tokens. This is the pre-existing hole the cut
  // did not close.
  it.fails("a client-chosen attemptId must not be redeemable for signed tokens without app auth", async () => {
    const app = await buildApp({ config: testConfig(), oauthRuntimes: { discord: mockDiscordRuntime() } });
    resources.push(app);

    const start = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        handoff: { kind: "browser_completion", attemptId: "attacker-fixed-code" },
      },
      // no x-heimdall-app-secret
    });
    expect(start.statusCode).toBe(201);

    const callback = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=victim-code&state=${encodeURIComponent(start.json().stateToken as string)}`,
      headers: { accept: "text/html" },
    });
    expect(callback.statusCode).toBe(200);

    const redeem = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/auth-completions/redeem",
      payload: { completionCode: "attacker-fixed-code" },
      // still no x-heimdall-app-secret
    });

    // The invariant the cut claims. Today: 201 with accessToken + refreshToken.
    expect(redeem.statusCode).not.toBe(201);
    expect(redeem.json().accessToken).toBeUndefined();
  });

  // Same family: returnTo is only validated as `format: uri`. The success page
  // postMessages the completion payload to new URL(returnTo).origin and links
  // to returnTo with the code in the fragment (src/browser-handoff.ts). Nothing
  // binds returnTo to an app-owned origin.
  it.fails("an unauthenticated start must not accept an arbitrary returnTo origin", async () => {
    const app = await buildApp({ config: testConfig(), oauthRuntimes: { discord: mockDiscordRuntime() } });
    resources.push(app);

    const start = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://attacker.example/collect" },
    });

    expect(start.statusCode).not.toBe(201);
  });

  it("refuses to mint on refresh when the caller supplies policy without app auth", async () => {
    const app = await buildApp({ config: testConfig(), oauthRuntimes: { discord: mockDiscordRuntime() } });
    resources.push(app);
    const context = (app as unknown as { heimdallContext: Parameters<typeof refreshAppSession>[0] }).heimdallContext;
    const policy = { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] };

    const nullCaller = await refreshAppSession(context, "repixelizer", null, {
      refreshToken: "irrelevant",
      entitlementPolicy: policy,
    } as Parameters<typeof refreshAppSession>[3]);
    expect(nullCaller).toEqual({ statusCode: 401, body: { error: "app_auth_required" } });

    const wrongApp = await refreshAppSession(context, "repixelizer", { appSlug: "ghostlight" }, {
      refreshToken: "irrelevant",
      entitlementPolicy: policy,
    } as Parameters<typeof refreshAppSession>[3]);
    expect(wrongApp).toEqual({ statusCode: 401, body: { error: "app_auth_required" } });

    const nullStart = await startOAuthFlow(context, "discord", null, {
      appSlug: "repixelizer",
      mode: "sign_in",
      returnTo: "https://repixelizer.gamecult.org/app/",
      entitlementPolicy: policy,
    } as Parameters<typeof startOAuthFlow>[3]);
    expect(nullStart).toEqual({ statusCode: 401, body: { error: "app_auth_required" } });
  });
});

describe("caller identity: single authority", () => {
  // Item 2. Source tripwire: the header may be read in exactly one module,
  // and the per-app secret table may be read only by the two envelope
  // openers (HTTP header comparator, private-plane HMAC/AES-GCM opener).
  const srcRoot = join(__dirname, "..", "src");
  const sources = readdirSync(srcRoot)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => [name, readFileSync(join(srcRoot, name), "utf8")] as const);

  it("x-heimdall-app-secret is read only in app-caller.ts", () => {
    const readers = sources
      .filter(([, text]) => /headers\[\s*["']x-heimdall-app-secret["']\s*\]/.test(text))
      .map(([name]) => name);
    expect(readers).toEqual(["app-caller.ts"]);
  });

  it("appSharedSecrets is read only by the HTTP comparator and the private-plane envelope opener", () => {
    const readers = sources
      .filter(([, text]) => /appSharedSecrets\s*[\[.]/.test(text))
      .map(([name]) => name)
      .sort();
    expect(readers).toEqual(["app-caller.ts", "private-command-plane.ts"]);
  });

  it("no source file compares a shared secret with ===", () => {
    const offenders = sources
      .filter(([, text]) => /[sS]ecret\w*\s*===|===\s*\w*[sS]ecret/.test(text))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });

  it("AppCaller literals are constructed only where identity was actually checked", () => {
    // Item 3. `{ appSlug }` as an AppCaller argument must appear only in the
    // private plane (after openPrivateEnvelope + sourceRuntimeId) and nowhere
    // else; the HTTP path gets its caller from resolveAppCaller.
    const forgers = sources
      .filter(([name, text]) => name !== "app-caller.ts" && /(startOAuthFlow|refreshAppSession)\([^;]*\{\s*appSlug\s*\}/s.test(text))
      .map(([name]) => name);
    expect(forgers).toEqual(["private-command-plane.ts"]);
  });
});

describe("caller identity: timing-safe comparator", () => {
  // Item 4.
  it("secretMatches rejects mismatches of any length and both empty sides", () => {
    expect(secretMatches("abc", "abd")).toBe(false);
    expect(secretMatches("abc", "abcd")).toBe(false);
    expect(secretMatches("abc", "")).toBe(false);
    expect(secretMatches(undefined, "abc")).toBe(false);
    expect(secretMatches("abc", undefined)).toBe(false);
    expect(secretMatches("", "")).toBe(false);
    expect(secretMatches("abc", "abc")).toBe(true);
  });

  it("app-caller.ts is the only HTTP-side importer of timingSafeEqual", () => {
    const srcRoot = join(__dirname, "..", "src");
    const importers = readdirSync(srcRoot)
      .filter((name) => name.endsWith(".ts"))
      .filter((name) => /timingSafeEqual/.test(readFileSync(join(srcRoot, name), "utf8")))
      .sort();
    expect(importers).toEqual(["app-caller.ts", "private-command-security.ts"]);
  });
});

describe("caller identity: private plane envelope authority", () => {
  // Item 3. A correctly sealed envelope from the wrong sourceRuntimeId must
  // be refused before beginAuth constructs an AppCaller: no auth attempt may
  // be created.
  it("refuses a valid envelope from an unconfigured runtime before any attempt is created", async () => {
    const config = testConfig();
    const store = new InMemoryStore();
    const app = await buildApp({ config, store, oauthRuntimes: { discord: mockDiscordRuntime() } });
    resources.push(app);
    const plane = await startHeimdallPrivateCommandPlane(app, config);
    resources.push(plane);

    const envelope = sealPrivateEnvelope({
      appSlug: "ghostlight",
      operation: "heimdall.auth.begin",
      contentSchema: "heimdall.auth_begin_command.v1",
      idempotencyKey: "soul-begin-1",
      secret: ghostlightSecret,
      payload: {
        provider: "discord",
        mode: "sign_in",
        returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
        entitlementPolicy: { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] },
      },
    });

    const response = await invokeCultNetOperation(
      plane.endpoint,
      request("heimdall.auth.begin", "soul-wrong-runtime", envelope, "not-ghostlight"),
      { runtimeId: "not-ghostlight" }
    );
    expect(response.status).toBe("denied");

    const internals = store as unknown as { authAttempts: Map<string, unknown> };
    expect(internals.authAttempts.size).toBe(0);
  }, 20_000);
});

function request(operation: string, messageId: string, envelope: HeimdallPrivateEnvelope, sourceRuntimeId: string) {
  return {
    schemaVersion: "cultnet.operation_request.v0" as const,
    messageId,
    serviceId: "heimdall.private.commands",
    operation,
    payloadSchema: "heimdall.private_command_envelope.v1",
    payloadEncoding: "messagepack-base64" as const,
    payload: Buffer.from(encode(envelope)).toString("base64"),
    sourceRuntimeId,
  };
}
