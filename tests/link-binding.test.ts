import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildApp } from "../src/app.js";
import { type HeimdallConfig } from "../src/config.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { createRuntimeKeyMaterial, signJwt, verifyJwt } from "../src/signing.js";
import { InMemoryStore } from "../src/store/index.js";
import { launchFlow } from "./oauth-flow.js";

function createTestConfig(): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    workspaceRoot: "E:/Projects/Heimdall",
    dataRoot: "E:/Projects/Heimdall/.heimdall-data",
    cultCachePath: "E:/Projects/Heimdall/.heimdall-data/cultcache/heimdall.service.cc",
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    daemonId: "yggdrasil-heimdall",
    idunnRudpHealth: undefined,
    idunnHealthContract: "heimdall.cultnet-rudp-provider-health",
    providerHealthIdentityPath: "E:/Projects/Heimdall/.heimdall-data/provider-health-identity.cc",
    sessionTtlSeconds: 3600,
    refreshTtlSeconds: 60 * 60 * 24 * 30,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    appSharedSecrets: {
      streampixels: "streampixels-secret",
      repixelizer: "repixelizer-secret",
      bifrost: "bifrost-secret",
    },
    appBackendCallbacks: {
      bifrost: ["https://bifrost.gamecult.org/auth/heimdall/callback"],
      repixelizer: ["https://repixelizer.gamecult.org/api/auth/heimdall/callback"],
    },
    storage: {
      backend: "memory",
      applySchemaOnStartup: true,
    },
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: { clientId: "patreon-client", clientSecret: "patreon-secret" },
      github: { clientId: "github-client", clientSecret: "github-secret" },
      twitch: { clientId: "twitch-client", clientSecret: "twitch-secret" },
      youtube: { clientId: "youtube-client", clientSecret: "youtube-secret" },
      spotify: { clientId: "spotify-client", clientSecret: "spotify-secret" },
      joystick: { clientId: "joystick-client", clientSecret: "joystick-secret" },
      google: { clientId: "google-client", clientSecret: "google-secret" },
    },
  };
}


// Link mode binds a provider identity to the account an authenticated app
// named at start. These tests pin the three places that binding is decided:
// the callback (initiator), the completion row (target), and redeem (caller,
// target, replay).

const returnTo = "https://repixelizer.gamecult.org/app/";
const appAuth = { "x-heimdall-app-secret": "repixelizer-secret" };

function discordRuntime(providerUserId: string): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "at", refreshToken: "rt", tokenType: "Bearer", scope: ["identify"], raw: {} };
    },
    async resolveIdentity() {
      return { provider: "discord", providerUserId, username: providerUserId, profile: { id: providerUserId } };
    },
    async evaluateEntitlements() {
      return { facts: [], snapshots: [] };
    },
  };
}

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function rig(providerUserId: string, config: HeimdallConfig = createTestConfig()) {
  const store = new InMemoryStore();
  const app = await buildApp({ config, store, oauthRuntimes: { discord: discordRuntime(providerUserId) } });
  apps.push(app);
  const now = new Date().toISOString();
  const initiator = await store.createAccount({ createdAt: now, lastSeenAt: now });
  return { app, store, initiator };
}

type Rig = Awaited<ReturnType<typeof rig>>;

function start(r: Rig, payload: Record<string, unknown>, headers: Record<string, string> = appAuth) {
  return r.app.inject({ method: "POST", url: "/v1/oauth/discord/start", headers, payload: { appSlug: "repixelizer", returnTo, ...payload } });
}

/** The browser follows authorizationUrl through the launch hop, then returns with the state, or with `forged` in its place, and the cookie it was handed. */
async function callback(r: Rig, started: { authorizationUrl: string }, forged?: (state: string) => string) {
  const flow = await launchFlow(r.app, started);
  const state = forged ? forged(flow.state) : flow.state;
  return r.app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(state)}`,
    headers: { cookie: flow.cookie },
  });
}

function redeem(r: Rig, payload: Record<string, unknown>, headers: Record<string, string> = {}) {
  return r.app.inject({ method: "POST", url: "/v1/apps/repixelizer/auth-completions/redeem", headers, payload });
}

describe("link start names its initiator", () => {
  it("refuses an unauthenticated link start, a missing or unknown initiator, and an initiator outside link mode", async () => {
    const r = await rig("d-1");
    const mode = { mode: "link", initiatingAccountId: r.initiator.id };
    expect((await start(r, mode, {})).statusCode).toBe(401);
    expect((await start(r, mode, { "x-heimdall-app-secret": "wrong" })).statusCode).toBe(401);
    const missing = await start(r, { mode: "link" });
    expect([missing.statusCode, missing.json().error]).toEqual([400, "link_initiator_required"]);
    const unknown = await start(r, { mode: "link", initiatingAccountId: "no-such-account" });
    expect([unknown.statusCode, unknown.json().error]).toEqual([400, "link_initiator_unknown"]);
    const stray = await start(r, { mode: "sign_in", initiatingAccountId: r.initiator.id }, {});
    expect([stray.statusCode, stray.json().error]).toEqual([400, "initiator_only_in_link_mode"]);
  });
});

describe("sign_in start carries no connection target", () => {
  it("refuses connection.targetId on sign_in with connection_not_allowed_in_sign_in, with or without app auth", async () => {
    const r = await rig("d-si");
    const connection = { kind: "creator", targetId: "victim-target" };
    for (const headers of [{}, appAuth]) {
      const res = await start(r, { mode: "sign_in", connection }, headers);
      expect([res.statusCode, res.json().error]).toEqual([400, "connection_not_allowed_in_sign_in"]);
    }
    expect((await start(r, { mode: "sign_in" }, {})).statusCode).toBe(201);
  });
});

describe("link callback holds the provider identity to the initiator", () => {
  it("attaches an unlinked identity to the initiating account, not a new one", async () => {
    const r = await rig("d-new");
    const started = await start(r, { mode: "link", initiatingAccountId: r.initiator.id });
    expect(started.statusCode).toBe(201);
    const done = await callback(r, started.json());
    expect(done.statusCode).toBe(201);
    expect(done.json().account.id).toBe(r.initiator.id);
    expect((await r.store.findAccountByLinkedIdentity("discord", "d-new"))?.id).toBe(r.initiator.id);
  });

  it("refuses with link_initiator_mismatch when the identity already belongs to another account, and mints nothing", async () => {
    const r = await rig("d-held");
    const now = new Date().toISOString();
    const other = await r.store.createAccount({ createdAt: now, lastSeenAt: now });
    await r.store.upsertLinkedIdentity({ accountId: other.id, provider: "discord", providerUserId: "d-held", scopes: [], profileJson: {}, createdAt: now, updatedAt: now });
    const started = await start(r, { mode: "link", initiatingAccountId: r.initiator.id });
    const done = await callback(r, started.json());
    expect(done.statusCode).toBe(403);
    expect(done.json().error).toBe("link_initiator_mismatch");
    expect(done.json().completion).toBeUndefined();
    expect(done.body).not.toContain("accessToken");
    expect((await r.store.findAccountByLinkedIdentity("discord", "d-held"))?.id).toBe(other.id);
  });

  it("refuses a link state that carries no initiator (forged or stripped), before attaching anything", async () => {
    const dir = mkdtempSync(join(tmpdir(), "heimdall-link-"));
    try {
      const config = { ...createTestConfig(), signingPrivateKeyPath: join(dir, "signing.pem"), bootstrapSigningPrivateKeyOnMissing: true };
      const r = await rig("d-forged", config);
      const keys = createRuntimeKeyMaterial({ ...config, bootstrapSigningPrivateKeyOnMissing: false });
      const started = await start(r, { mode: "link", initiatingAccountId: r.initiator.id });
      const done = await callback(r, started.json(), (state) => {
        const verified = verifyJwt(state, keys.publicKey) as { valid: boolean; payload: Record<string, unknown> };
        expect(verified.valid).toBe(true);
        return signJwt({ ...verified.payload, initiator_account_id: null }, keys);
      });
      expect([done.statusCode, done.json().error]).toEqual([403, "link_initiator_missing"]);
      expect(await r.store.findAccountByLinkedIdentity("discord", "d-forged")).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("redeem binds caller, target and replay", () => {
  async function linked(r: Rig, targetId: string | undefined) {
    const started = await start(r, {
      mode: "link",
      initiatingAccountId: r.initiator.id,
      ...(targetId ? { connection: { kind: "account", targetId } } : {}),
    });
    const done = await callback(r, started.json());
    expect(done.statusCode).toBe(201);
    return done.json().completion.code as string;
  }

  it("redeems a link completion only for the authenticated app, and a refused caller does not burn the code", async () => {
    const r = await rig("d-r1");
    const completionCode = await linked(r, undefined);
    const anonymous = await redeem(r, { completionCode });
    expect([anonymous.statusCode, anonymous.json().error]).toEqual([401, "app_auth_required"]);
    expect((await redeem(r, { completionCode }, { "x-heimdall-app-secret": "wrong" })).statusCode).toBe(401);
    expect((await redeem(r, { completionCode }, appAuth)).statusCode).toBe(201);
  });

  it("refuses a wrong or missing target with completion_target_mismatch without consuming the code", async () => {
    const r = await rig("d-r2");
    const completionCode = await linked(r, "target-a");
    for (const payload of [{ completionCode, targetId: "target-b" }, { completionCode }]) {
      const refused = await redeem(r, payload, appAuth);
      expect([refused.statusCode, refused.json().error]).toEqual([403, "completion_target_mismatch"]);
      expect(refused.json().accessToken).toBeUndefined();
    }
    expect((await redeem(r, { completionCode, targetId: "target-a" }, appAuth)).statusCode).toBe(201);
  });

  it("refuses a target named against a completion that recorded none, without consuming the code", async () => {
    const r = await rig("d-r2b");
    const completionCode = await linked(r, undefined);
    const refused = await redeem(r, { completionCode, targetId: "target-a" }, appAuth);
    expect([refused.statusCode, refused.json().error]).toEqual([403, "completion_target_mismatch"]);
    expect(refused.json().accessToken).toBeUndefined();
    expect((await r.store.findAuthCompletion("repixelizer", completionCode))?.consumedAt).toBeUndefined();
    expect((await redeem(r, { completionCode }, appAuth)).statusCode).toBe(201);
  });

  it("refuses a replayed completion", async () => {
    const r = await rig("d-r3");
    const completionCode = await linked(r, "target-a");
    expect((await redeem(r, { completionCode, targetId: "target-a" }, appAuth)).statusCode).toBe(201);
    expect((await redeem(r, { completionCode, targetId: "target-a" }, appAuth)).statusCode).toBe(410);
  });

  it("refuses a completion at and after its expiry with 410, whatever the caller and target, and honours it just before", async () => {
    // completionTtlSeconds is 300. Only Date is faked: the app and store run on real timers.
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.parse("2026-11-03T00:00:00.000Z");
    const ttlMs = createTestConfig().completionTtlSeconds * 1000;
    const expired = { statusCode: 410, error: "invalid_or_expired_completion_code" };
    const outcome = async (r: Rig, payload: Record<string, unknown>) => {
      const res = await redeem(r, payload, appAuth);
      return { statusCode: res.statusCode, error: res.json().error };
    };

    vi.setSystemTime(t0);
    const r = await rig("d-exp");
    const code = await linked(r, "target-a");
    const row = await r.store.findAuthCompletion("repixelizer", code);
    expect(row?.expiresAt).toBe(new Date(t0 + ttlMs).toISOString());

    // Just before expiry the right caller and target redeem it.
    const early = await rig("d-exp-early");
    const earlyCode = await linked(early, "target-a");
    vi.setSystemTime(t0 + ttlMs - 1);
    expect((await redeem(early, { completionCode: earlyCode, targetId: "target-a" }, appAuth)).statusCode).toBe(201);

    // At the expiry instant and after it: 410, for the right target and for a wrong one (not 403), unconsumed.
    for (const at of [t0 + ttlMs, t0 + ttlMs + 1]) {
      vi.setSystemTime(at);
      expect(await outcome(r, { completionCode: code, targetId: "target-a" })).toEqual(expired);
      expect(await outcome(r, { completionCode: code, targetId: "target-b" })).toEqual(expired);
    }
    expect((await r.store.findAuthCompletion("repixelizer", code))?.consumedAt).toBeUndefined();
  });

  it("stores the target on the completion row", async () => {
    const r = await rig("d-r4");
    const completionCode = await linked(r, "target-a");
    expect((await r.store.findAuthCompletion("repixelizer", completionCode))?.targetId).toBe("target-a");
  });
});
