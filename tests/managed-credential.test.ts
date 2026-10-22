import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { type HeimdallConfig } from "../src/config.js";
import { type Provider } from "../src/contracts.js";
import { createTokenCustody } from "../src/custody.js";
import {
  MANAGED_CREDENTIAL_REFRESH_SKEW_MS,
  ManagedCredentialRefreshFailed,
  refreshManagedCredential,
} from "../src/managed-credential.js";
import { createOAuthRuntimeRegistry } from "../src/oauth.js";
import { providerCatalog } from "../src/providers.js";
import { InMemoryStore, PostgresStore, type HeimdallStore } from "../src/store/index.js";
import { type StoredLinkedIdentity } from "../src/store/types.js";
import { launchFlow } from "./oauth-flow.js";

const originalFetch = globalThis.fetch;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function testConfig(): HeimdallConfig {
  const clients = Object.fromEntries(
    ["discord", "patreon", "github", "twitch", "youtube", "spotify", "joystick"].map((p) => [
      p,
      { clientId: `${p}-client`, clientSecret: `${p}-secret` },
    ])
  );
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
    appSharedSecrets: { streampixels: "streampixels-secret", bifrost: "bifrost-secret" },
    appBackendCallbacks: {},
    storage: { backend: "memory", applySchemaOnStartup: true },
    bifrostPatronSupportEndpoint: "https://bifrost.gamecult.org/heimdall/patron-support/events",
    bifrostPatronSupportSecret: "bifrost-support-secret",
    providers: clients,
  } as unknown as HeimdallConfig;
}

type Mode =
  | "normal"
  | "invalid_grant"
  | "invalid_client"
  | "server_error"
  | "not_json"
  | "no_refresh_token"
  | "empty_refresh_token"
  | "bad_refresh_token"
  | "no_expires_in"
  | "unusable_expires_in"
  | "string_expires_in"
  | "huge_expires_in"
  | "huge_string_expires_in"
  | "hang";

function expiresInFor(mode: Mode): unknown {
  switch (mode) {
    case "unusable_expires_in":
      return "soon";
    case "string_expires_in":
      return "7200";
    case "huge_expires_in":
      return 3e11;
    case "huge_string_expires_in":
      return "300000000000";
    default:
      return 3600;
  }
}

/**
 * A provider token endpoint with single-use refresh tokens. Presenting a
 * consumed refresh token revokes the whole installation, as Joystick does:
 * every later refresh answers 400 invalid_grant.
 */
function installTokenEndpoint(provider: Provider, firstRefreshToken: string) {
  const state = {
    calls: 0,
    mode: "normal" as Mode,
    live: firstRefreshToken,
    issued: 0,
    installationRevoked: false,
    otherCalls: [] as string[],
  };
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url !== providerCatalog[provider].tokenEndpoint) {
      state.otherCalls.push(url);
      return new Response("unexpected", { status: 500 });
    }
    state.calls += 1;
    const presented = (init!.body as URLSearchParams).get("refresh_token");
    await sleep(25);
    switch (state.mode) {
      case "hang":
        return new Promise<Response>((_resolve, reject) => {
          init!.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        });
      case "invalid_grant":
        return new Response(JSON.stringify({ error: "invalid_grant", error_description: "CANARY" }), { status: 400 });
      case "invalid_client":
        return new Response(JSON.stringify({ error: "invalid_client", error_description: "CANARY" }), { status: 401 });
      case "server_error":
        return new Response("CANARY upstream exploded", { status: 500 });
      case "not_json":
        return new Response("CANARY <html>", { status: 200 });
      case "no_refresh_token":
        return new Response(JSON.stringify({ access_token: "access-norefresh", token_type: "Bearer", expires_in: 3600 }), {
          status: 200,
        });
      case "empty_refresh_token":
        return new Response(JSON.stringify({ access_token: "access-empty", refresh_token: "", token_type: "Bearer", expires_in: 3600 }), {
          status: 200,
        });
      case "bad_refresh_token":
        return new Response(JSON.stringify({ access_token: "access-bad", refresh_token: 42, token_type: "Bearer", expires_in: 3600 }), {
          status: 200,
        });
      case "normal":
      case "no_expires_in":
      case "unusable_expires_in":
      case "string_expires_in":
      case "huge_expires_in":
      case "huge_string_expires_in": {
        if (state.installationRevoked || presented !== state.live) {
          state.installationRevoked = true;
          return new Response(JSON.stringify({ error: "invalid_grant", error_description: "reused CANARY" }), { status: 400 });
        }
        state.issued += 1;
        state.live = `refresh-${state.issued}`;
        return new Response(
          JSON.stringify({
            access_token: `access-${state.issued}`,
            refresh_token: state.live,
            token_type: "Bearer",
            ...(state.mode === "no_expires_in" ? {} : { expires_in: expiresInFor(state.mode) }),
          }),
          { status: 200 }
        );
      }
    }
  }) as typeof fetch;
  return state;
}

interface Rig {
  stores: HeimdallStore[];
  apps: Awaited<ReturnType<typeof buildApp>>[];
  accountId: string;
  identityId: string;
  custody: ReturnType<typeof createTokenCustody>;
  config: HeimdallConfig;
  provider: Provider;
  databaseUrl: string | undefined;
  row(): Promise<StoredLinkedIdentity>;
  audit(): Promise<Array<{ eventType: string; payload: unknown }>>;
  resolve(appIndex?: number): Promise<{ statusCode: number; json: Record<string, unknown>; body: string }>;
  close(): Promise<void>;
}

const adminUrl = process.env.HEIMDALL_TEST_PG_ADMIN_URL;
const rigKinds = [
  { kind: "memory", live: false },
  { kind: "postgres one app", live: true },
  { kind: "postgres two apps", live: true },
] as const;
// Providers whose refresh goes through the real shared runtime; rotation differs by descriptor.
const refreshProviders: Provider[] = ["twitch", "joystick"];

for (const { kind, live } of rigKinds) describe.skipIf(live && !adminUrl)(`managed credential refresh, ${kind}`, () => {
  const admin = live && adminUrl ? new Pool({ connectionString: adminUrl, max: 2 }) : undefined;
  const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
  const template = `heimdall_mc_template_${suffix}`;
  const cleanup: Array<() => Promise<void>> = [];

  function urlFor(database: string): string {
    const url = new URL(adminUrl!);
    url.pathname = `/${database}`;
    return url.toString();
  }

  beforeAll(async () => {
    if (!live) return;
    await admin!.query(`CREATE DATABASE ${template}`);
    const pool = new Pool({ connectionString: urlFor(template), max: 1 });
    await new PostgresStore(pool).ensureSchema();
    await pool.end();
  }, 120_000);

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    for (const step of cleanup.splice(0).reverse()) await step();
  });

  afterAll(async () => {
    if (!admin) return;
    await admin.query(`DROP DATABASE IF EXISTS ${template}`);
    await admin.end();
  }, 120_000);

  async function makeRig(
    provider: Provider,
    options: { expiresInMs?: number; refreshToken?: string | null; accessToken?: string | null } = {}
  ): Promise<Rig> {
    const config = testConfig();
    const custody = createTokenCustody(config);
    const stores: HeimdallStore[] = [];
    let adminForDb: Pool | undefined;
    let databaseUrl: string | undefined;
    if (!live) {
      stores.push(new InMemoryStore());
    } else {
      const name = `heimdall_mc_${randomUUID().replace(/-/g, "")}`;
      await admin!.query(`CREATE DATABASE ${name} TEMPLATE ${template}`);
      const count = kind === "postgres two apps" ? 2 : 1;
      for (let i = 0; i < count; i += 1) {
        const pool = new Pool({ connectionString: urlFor(name), max: 12 });
        pool.on("error", () => undefined);
        stores.push(new PostgresStore(pool));
      }
      databaseUrl = urlFor(name);
      adminForDb = new Pool({ connectionString: urlFor(name), max: 1 });
      adminForDb.on("error", () => undefined);
      cleanup.push(async () => {
        await adminForDb!.end();
        await admin!.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      });
    }

    const now = new Date().toISOString();
    const account = await stores[0]!.createAccount({ createdAt: now, lastSeenAt: now });
    const expiresInMs = options.expiresInMs ?? 60_000;
    const input = {
      accountId: account.id,
      provider,
      providerUserId: "channel-1",
      username: "deru",
      displayName: "Deru",
      scopes: ["identity:read"],
      profileJson: { keep: "me" },
      tokenExpiresAt: new Date(Date.now() + expiresInMs).toISOString(),
      createdAt: now,
      updatedAt: now,
    };
    const seeded = await stores[0]!.upsertLinkedIdentity({
      ...input,
      ...(options.accessToken === null ? {} : { accessTokenEncrypted: custody.encrypt(options.accessToken ?? "access-0") }),
      ...(options.refreshToken === null ? {} : { refreshTokenEncrypted: custody.encrypt(options.refreshToken ?? "refresh-0") }),
    });

    const apps: Rig["apps"] = [];
    for (const store of stores) {
      apps.push(await buildApp({ config, store, tokenCustody: custody, oauthRuntimes: createOAuthRuntimeRegistry() }));
    }
    cleanup.push(async () => {
      for (const app of apps) await app.close().catch(() => undefined);
    });

    return {
      stores,
      apps,
      accountId: account.id,
      identityId: seeded.id,
      custody,
      config,
      provider,
      databaseUrl,
      async row() {
        const row = await stores[0]!.findStoredLinkedIdentityForAccount(account.id, provider);
        return row!;
      },
      async audit() {
        if (!live) {
          const events = (stores[0] as unknown as { auditEvents: Map<string, { eventType: string; eventPayloadJson: unknown }> }).auditEvents;
          return [...events.values()].map((e) => ({ eventType: e.eventType, payload: e.eventPayloadJson }));
        }
        const result = await adminForDb!.query<{ event_type: string; event_payload_json: unknown }>(
          "SELECT event_type, event_payload_json FROM audit_events ORDER BY created_at"
        );
        return result.rows.map((r) => ({ eventType: r.event_type, payload: r.event_payload_json }));
      },
      async resolve(appIndex = 0) {
        const response = await apps[appIndex]!.inject({
          method: "POST",
          url: "/v1/apps/streampixels/managed-credentials/resolve",
          headers: { "x-heimdall-app-secret": "streampixels-secret" },
          payload: { accountId: account.id, provider },
        });
        return { statusCode: response.statusCode, json: response.json() as Record<string, unknown>, body: response.body };
      },
      async close() {},
    };
  }

  const timeout = { timeout: 60_000 };

  describe.each(refreshProviders)("%s", (provider) => {
    it("refresh-once-per-token: 20 concurrent resolves present the refresh token once", timeout, async () => {
      const rig = await makeRig(provider);
      const endpoint = installTokenEndpoint(provider, "refresh-0");

      const answers = await Promise.all(Array.from({ length: 20 }, (_, i) => rig.resolve(i % rig.apps.length)));

      expect(endpoint.calls).toBe(1);
      expect(answers.map((a) => a.statusCode)).toEqual(Array(20).fill(200));
      expect(new Set(answers.map((a) => a.json.accessToken))).toEqual(new Set(["access-1"]));
      const row = await rig.row();
      expect(rig.custody.decrypt(row.accessTokenEncrypted!)).toBe("access-1");
      expect(rig.custody.decrypt(row.refreshTokenEncrypted!)).toBe("refresh-1");
      expect(await rig.audit()).toEqual([]);
    });

    it("rotated-pair-persisted-before-use: the stored pair is the one the caller was given", timeout, async () => {
      const rig = await makeRig(provider);
      installTokenEndpoint(provider, "refresh-0");
      const answer = await rig.resolve();
      const row = await rig.row();
      expect(rig.custody.decrypt(row.accessTokenEncrypted!)).toBe(answer.json.accessToken);
      expect(Date.parse(row.tokenExpiresAt!)).toBeGreaterThan(Date.now() + MANAGED_CREDENTIAL_REFRESH_SKEW_MS);
    });

    it("outside the skew: no token call, the stored token is returned", timeout, async () => {
      const rig = await makeRig(provider, { expiresInMs: 60 * 60 * 1000 });
      const endpoint = installTokenEndpoint(provider, "refresh-0");
      const answer = await rig.resolve();
      expect(endpoint.calls).toBe(0);
      expect(answer.statusCode).toBe(200);
      expect(answer.json.accessToken).toBe("access-0");
    });

    it("revocation-is-typed: invalid_grant clears the tokens, answers 410, audits once, and stops calling the provider", timeout, async () => {
      const rig = await makeRig(provider);
      const endpoint = installTokenEndpoint(provider, "refresh-0");
      endpoint.mode = "invalid_grant";

      const first = await rig.resolve();
      expect(first.statusCode).toBe(410);
      expect(first.json).toEqual({ error: "managed_credential_revoked", provider });
      const row = await rig.row();
      expect(row.accessTokenEncrypted).toBeUndefined();
      expect(row.refreshTokenEncrypted).toBeUndefined();
      expect(row.tokenExpiresAt).toBeUndefined();
      expect(row.username).toBe("deru");
      expect(row.profileJson).toEqual({ keep: "me" });
      expect(row.scopes).toEqual(["identity:read"]);

      const second = await rig.resolve();
      expect(second.statusCode).toBe(410);
      expect(endpoint.calls).toBe(1);

      const events = await rig.audit();
      expect(events.filter((e) => e.eventType === "managed_credential_revoked")).toEqual([
        { eventType: "managed_credential_revoked", payload: { provider, reason: "provider_revoked" } },
      ]);
      expect(first.body + second.body + JSON.stringify(events)).not.toContain("CANARY");
    });

    it.each(["invalid_client", "server_error", "not_json", "bad_refresh_token", "hang"] as const)(
      "transient failure (%s) keeps custody: 502, tokens byte-identical, nothing leaked",
      timeout,
      async (mode) => {
        const rig = await makeRig(provider);
        const before = await rig.row();
        const endpoint = installTokenEndpoint(provider, "refresh-0");
        endpoint.mode = mode;

        let answer;
        if (mode === "hang") {
          // The route's own bound is 10 s; the primitive takes an injected one.
          const failure = await refreshManagedCredential(
            { config: rig.config, store: rig.stores[0]!, tokenCustody: rig.custody, oauthRuntimes: createOAuthRuntimeRegistry(), timeoutMs: 100 },
            before
          ).then(
            () => undefined,
            (error: unknown) => error
          );
          expect(failure).toBeInstanceOf(ManagedCredentialRefreshFailed);
          expect((failure as ManagedCredentialRefreshFailed).provider).toBe(provider);
          expect(String(failure) + JSON.stringify(failure)).not.toContain("CANARY");
        } else {
          answer = await rig.resolve();
          expect(answer.statusCode).toBe(502);
          expect(answer.json).toEqual({ error: "managed_credential_refresh_failed", provider });
          expect(answer.body).not.toContain("CANARY");
        }

        const after = await rig.row();
        expect(after.accessTokenEncrypted).toBe(before.accessTokenEncrypted);
        expect(after.refreshTokenEncrypted).toBe(before.refreshTokenEncrypted);
        expect(after.tokenExpiresAt).toBe(before.tokenExpiresAt);
        expect(await rig.audit()).toEqual([]);
      }
    );

    it("bounded lock: a refresh that never answers is aborted and the next resolve takes the lock", timeout, async () => {
      const rig = await makeRig(provider);
      const endpoint = installTokenEndpoint(provider, "refresh-0");
      endpoint.mode = "hang";
      const ctx = { config: rig.config, store: rig.stores[0]!, tokenCustody: rig.custody, oauthRuntimes: createOAuthRuntimeRegistry(), timeoutMs: 100 };
      const started = Date.now();
      await expect(refreshManagedCredential(ctx, await rig.row())).rejects.toBeInstanceOf(ManagedCredentialRefreshFailed);
      expect(Date.now() - started).toBeLessThan(5_000);

      endpoint.mode = "normal";
      const outcome = await refreshManagedCredential(ctx, await rig.row());
      expect(outcome.kind).toBe("current");
      expect(rig.custody.decrypt(outcome.identity.accessTokenEncrypted!)).toBe("access-1");
    });

    it("single flight: concurrent refreshes against a never-answering endpoint make one provider call per process, and every caller gets the typed failure", timeout, async () => {
      const rig = await makeRig(provider);
      const endpoint = installTokenEndpoint(provider, "refresh-0");
      endpoint.mode = "hang";
      const snapshot = await rig.row();
      const ctxFor = (store: HeimdallStore) => ({ config: rig.config, store, tokenCustody: rig.custody, oauthRuntimes: createOAuthRuntimeRegistry(), timeoutMs: 150 });

      const results = await Promise.allSettled(
        Array.from({ length: 12 }, (_, i) => refreshManagedCredential(ctxFor(rig.stores[i % rig.stores.length]!), snapshot))
      );

      expect(results.map((r) => r.status)).toEqual(Array(12).fill("rejected"));
      for (const result of results) {
        expect((result as PromiseRejectedResult).reason).toBeInstanceOf(ManagedCredentialRefreshFailed);
      }
      expect(endpoint.calls).toBe(rig.stores.length);
      expect(rig.custody.decrypt((await rig.row()).refreshTokenEncrypted!)).toBe("refresh-0");

      // The burst is over: a later independent request tries again.
      endpoint.mode = "normal";
      const later = await refreshManagedCredential(ctxFor(rig.stores[0]!), await rig.row());
      expect(later.kind).toBe("current");
      expect(endpoint.calls).toBe(rig.stores.length + 1);
    });

    it("a snapshot taken before another caller's refresh does not decide: the locked row does", timeout, async () => {
      const rig = await makeRig(provider);
      const endpoint = installTokenEndpoint(provider, "refresh-0");
      const stale = await rig.row();
      await rig.resolve();
      expect(endpoint.calls).toBe(1);
      const outcome = await refreshManagedCredential(
        { config: rig.config, store: rig.stores[0]!, tokenCustody: rig.custody, oauthRuntimes: createOAuthRuntimeRegistry() },
        stale
      );
      expect(endpoint.calls).toBe(1);
      expect(outcome.kind).toBe("current");
      expect(rig.custody.decrypt(outcome.identity.accessTokenEncrypted!)).toBe("access-1");
    });

    if (providerCatalog[provider].rotatesRefreshTokens) {
      it.each(["no_refresh_token", "empty_refresh_token"] as const)("rotation-fails-closed: a response with %s revokes, 410, and the old token is never presented again", timeout, async (mode) => {
        const rig = await makeRig(provider);
        const endpoint = installTokenEndpoint(provider, "refresh-0");
        endpoint.mode = mode;

        const first = await rig.resolve();
        expect(first.statusCode).toBe(410);
        expect(first.json).toEqual({ error: "managed_credential_revoked", provider });
        expect(first.body).not.toContain("access-norefresh");
        expect(first.body).not.toContain("access-empty");
        const row = await rig.row();
        expect(row.accessTokenEncrypted).toBeUndefined();
        expect(row.refreshTokenEncrypted).toBeUndefined();
        expect(row.tokenExpiresAt).toBeUndefined();

        const second = await rig.resolve();
        expect(second.statusCode).toBe(410);
        expect(endpoint.calls).toBe(1);
        expect((await rig.audit()).filter((e) => e.eventType === "managed_credential_revoked")).toEqual([
          { eventType: "managed_credential_revoked", payload: { provider, reason: "rotation_missing" } },
        ]);
      });
    } else {
      it.each(["no_refresh_token", "empty_refresh_token"] as const)("a response with %s keeps the old one for a non-rotating provider", timeout, async (mode) => {
        const rig = await makeRig(provider);
        const endpoint = installTokenEndpoint(provider, "refresh-0");
        endpoint.mode = mode;
        const answer = await rig.resolve();
        expect(answer.statusCode).toBe(200);
        expect(answer.json.accessToken).toBe(mode === "no_refresh_token" ? "access-norefresh" : "access-empty");
        expect(rig.custody.decrypt((await rig.row()).refreshTokenEncrypted!)).toBe("refresh-0");
      });
    }

    it.each([
      ["no expires_in", "no_expires_in", 3600],
      ["an unusable expires_in", "unusable_expires_in", 3600],
      ["a numeric-string expires_in", "string_expires_in", 7200],
      ["a numeric expires_in beyond a year", "huge_expires_in", 3600],
      ["a numeric-string expires_in beyond a year", "huge_string_expires_in", 3600],
    ] as const)(
      "refresh-once-per-token: an answer with %s stores now plus %s s, not the old due expiry, and resolve refreshes again only once it passes",
      timeout,
      async (_name, mode, seconds) => {
        const rig = await makeRig(provider);
        const endpoint = installTokenEndpoint(provider, "refresh-0");
        endpoint.mode = mode;

        const before = Date.now();
        expect((await rig.resolve()).statusCode).toBe(200);
        expect(endpoint.calls).toBe(1);
        const stored = Date.parse((await rig.row()).tokenExpiresAt!);
        expect(stored - before).toBeGreaterThanOrEqual(seconds * 1000 - 1000);
        expect(stored - before).toBeLessThan(seconds * 1000 + 10_000);

        expect((await rig.resolve()).statusCode).toBe(200);
        expect(endpoint.calls).toBe(1);

        // The stored expiry passes: the next resolve refreshes.
        const past = new Date(Date.now() - 1000).toISOString();
        await rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async (locked) => ({
          kind: "rotate",
          accessTokenEncrypted: locked.accessTokenEncrypted!,
          refreshTokenEncrypted: locked.refreshTokenEncrypted!,
          tokenExpiresAt: past,
          scopes: locked.scopes,
          updatedAt: past,
        }));
        expect((await rig.resolve()).statusCode).toBe(200);
        expect(endpoint.calls).toBe(2);
        const again = Date.parse((await rig.row()).tokenExpiresAt!);
        expect(again).toBeGreaterThan(Date.now() + MANAGED_CREDENTIAL_REFRESH_SKEW_MS);
      }
    );

    it("a row with no access token resolves as revoked (410), a missing row as not found (404)", timeout, async () => {
      const rig = await makeRig(provider, { accessToken: null, refreshToken: null });
      const endpoint = installTokenEndpoint(provider, "refresh-0");
      const revoked = await rig.resolve();
      expect(revoked.statusCode).toBe(410);
      expect(revoked.json).toEqual({ error: "managed_credential_revoked", provider });
      expect(endpoint.calls).toBe(0);

      const missing = await rig.apps[0]!.inject({
        method: "POST",
        url: "/v1/apps/streampixels/managed-credentials/resolve",
        headers: { "x-heimdall-app-secret": "streampixels-secret" },
        payload: { accountId: "no-such-account", provider },
      });
      expect(missing.statusCode).toBe(404);
      expect(missing.json()).toEqual({ error: "managed_credential_not_found" });
    });
  });

  describe("what the callback mints is decided by mode and provider role", () => {
    const returnTo = "https://streampixels.gamecult.org/auth/connect";

    function stubProviders(identity: Record<string, string>, tokenAnswer: Record<string, unknown> = { refresh_token: "tok-refresh-CANARY" }) {
      globalThis.fetch = (async (input: string | URL) => {
        const url = String(input);
        const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
        if (url.startsWith("https://api.joystick.tv/api/oauth/token") || Object.values(providerCatalog).some((d) => d.tokenEndpoint === url)) {
          return json({ access_token: "tok-access", token_type: "Bearer", expires_in: 3600, ...tokenAnswer });
        }
        if (url === "https://api.joystick.tv/api/v1/me/identity") return json({ channel_id: identity.joystick, username: "deru" });
        if (url === "https://api.twitch.tv/helix/users") return json({ data: [{ id: identity.twitch, login: "deru", display_name: "Deru" }] });
        if (url.startsWith("https://www.googleapis.com/youtube/v3/channels")) {
          return json({ items: [{ id: identity.youtube, snippet: { title: "Deru" } }] });
        }
        return new Response("unexpected", { status: 500 });
      }) as typeof fetch;
    }

    async function flow(rig: Rig, provider: "joystick" | "twitch" | "youtube", mode: "connect" | "sign_in") {
      const app = rig.apps[0]!;
      const start = await app.inject({ method: "POST", url: `/v1/oauth/${provider}/start`, payload: { appSlug: "streampixels", mode, returnTo, ...(mode === "connect" ? { connection: { kind: "creator", targetId: "creator-1" } } : {}) } });
      expect(start.statusCode).toBe(201);
      const flow = await launchFlow(app, start.json());
      const callback = await app.inject({
        method: "GET",
        url: `/v1/oauth/${provider}/callback?code=c&state=${encodeURIComponent(flow.state)}`,
        headers: { cookie: flow.cookie },
      });
      expect(callback.statusCode).toBe(201);
      const redeem = await app.inject({
        method: "POST",
        url: "/v1/apps/streampixels/auth-completions/redeem",
        payload: { completionCode: callback.json().completion.code as string },
      });
      expect(redeem.statusCode).toBe(201);
      return { callback, redeem };
    }

    it("a joystick connect on streampixels stores custody and yields no viewer_access, no capability and no refresh token", timeout, async () => {
      const rig = await makeRig("joystick");
      stubProviders({ joystick: "channel-1", twitch: "t-1", youtube: "y-1" });
      const { callback, redeem } = await flow(rig, "joystick", "connect");

      for (const payload of [callback.json(), redeem.json()] as Array<Record<string, any>>) {
        expect(payload.mode).toBe("connect");
        expect(payload.claimSet.capabilities).toEqual([]);
        expect(payload.claimSet.facts).toEqual([]);
        expect(payload.sharedCapabilities).toEqual([]);
        expect(payload.hybridCapabilities).toEqual([]);
        expect(payload.claimSet.identities).toEqual([expect.objectContaining({ provider: "joystick", providerUserId: "channel-1" })]);
        expect(payload.account.id).toBe(rig.accountId);
        expect(payload.refreshToken).toBeUndefined();
        expect(payload.refresh).toBeUndefined();
      }
      expect(callback.body + redeem.body).not.toContain("viewer_access");
      expect(callback.body + redeem.body).not.toContain("tok-refresh-CANARY");
      const row = await rig.row();
      expect(rig.custody.decrypt(row.accessTokenEncrypted!)).toBe("tok-access");
      expect(rig.custody.decrypt(row.refreshTokenEncrypted!)).toBe("tok-refresh-CANARY");
    });

    it.each([
      ["no refresh_token", {}],
      ["an empty refresh_token", { refresh_token: "" }],
    ])("a rotating provider's code exchange with %s fails the callback before anything is written", timeout, async (_name, tokenAnswer) => {
      const rig = await makeRig("joystick");
      const before = await rig.row();
      const auditBefore = (await rig.audit()).length;
      stubProviders({ joystick: "channel-new", twitch: "t-1", youtube: "y-1" }, tokenAnswer);
      const app = rig.apps[0]!;
      const start = await app.inject({
        method: "POST",
        url: "/v1/oauth/joystick/start",
        payload: { appSlug: "streampixels", mode: "connect", returnTo, connection: { kind: "creator", targetId: "creator-1" } },
      });
      expect(start.statusCode).toBe(201);
      const flow = await launchFlow(app, start.json());
      const callback = await app.inject({
        method: "GET",
        url: `/v1/oauth/joystick/callback?code=c&state=${encodeURIComponent(flow.state)}`,
        headers: { cookie: flow.cookie },
      });
      expect(callback.statusCode).toBeGreaterThanOrEqual(400);
      expect(callback.body).not.toContain("tok-access");
      expect(await rig.row()).toEqual(before);
      expect(await rig.stores[0]!.findStoredLinkedIdentity("joystick", "channel-new")).toBeNull();
      const failures = (await rig.audit()).slice(auditBefore);
      expect(failures).toEqual([
        { eventType: "oauth_callback_failed", payload: expect.objectContaining({ errorClass: "ProviderResponseError", providerStatus: 200 }) },
      ]);
    });

    it.each(["twitch", "youtube"] as const)("a %s sign_in on streampixels still yields viewer_access and a refresh token", timeout, async (provider) => {
      const rig = await makeRig("joystick");
      stubProviders({ joystick: "channel-1", twitch: "t-1", youtube: "y-1" });
      const { callback, redeem } = await flow(rig, provider, "sign_in");
      for (const payload of [callback.json(), redeem.json()] as Array<Record<string, any>>) {
        expect(payload.claimSet.capabilities).toContain("viewer_access");
        expect(payload.refreshToken).toEqual(expect.any(String));
        expect(payload.hybridCapabilities.map((c: { key: string }) => c.key)).toEqual(["creator_access", "creator_admin"]);
      }
    });

    it("a twitch connect on streampixels keeps its current behaviour: an identity provider still signs the viewer in", timeout, async () => {
      const rig = await makeRig("joystick");
      stubProviders({ joystick: "channel-1", twitch: "t-1", youtube: "y-1" });
      const { redeem } = await flow(rig, "twitch", "connect");
      expect(redeem.json().claimSet.capabilities).toContain("viewer_access");
    });
  });

  describe("updateLinkedIdentityCredential", () => {
    it("returns null for a missing id and does not call decide", async () => {
      const rig = await makeRig("twitch");
      let called = false;
      const result = await rig.stores[0]!.updateLinkedIdentityCredential(randomUUID(), async () => {
        called = true;
        return { kind: "keep" };
      });
      expect(result).toBeNull();
      expect(called).toBe(false);
    });

    it("hands decide the committed row, and a throw writes nothing", async () => {
      const rig = await makeRig("twitch");
      const before = await rig.row();
      let seen: StoredLinkedIdentity | undefined;
      await expect(
        rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async (locked) => {
          seen = locked;
          throw new Error("boom");
        })
      ).rejects.toThrow("boom");
      expect(seen).toEqual(before);
      expect(await rig.row()).toEqual(before);
    });

    it("rotate writes token columns, scopes and updated_at and nothing else; keep writes nothing", async () => {
      const rig = await makeRig("twitch");
      const before = await rig.row();
      const kept = await rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async () => ({ kind: "keep" }));
      expect(kept).toEqual(before);

      const rotated = await rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async () => ({
        kind: "rotate",
        accessTokenEncrypted: "A2",
        refreshTokenEncrypted: "R2",
        tokenExpiresAt: "2999-01-01T00:00:00.000Z",
        scopes: ["a", "b"],
        updatedAt: "2999-01-02T00:00:00.000Z",
      }));
      expect(rotated).toEqual({
        ...before,
        accessTokenEncrypted: "A2",
        refreshTokenEncrypted: "R2",
        tokenExpiresAt: "2999-01-01T00:00:00.000Z",
        scopes: ["a", "b"],
        updatedAt: "2999-01-02T00:00:00.000Z",
      });
      expect(await rig.row()).toEqual(rotated);

      const revoked = await rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async () => ({
        kind: "revoke",
        updatedAt: "2999-01-03T00:00:00.000Z",
      }));
      const { accessTokenEncrypted: _a, refreshTokenEncrypted: _r, tokenExpiresAt: _e, ...rest } = rotated!;
      expect(revoked).toEqual({ ...rest, updatedAt: "2999-01-03T00:00:00.000Z" });
      expect(await rig.row()).toEqual(revoked);
    });

    it.runIf(live)("leaves no transaction open after a missing row or a throwing decide", timeout, async () => {
      const rig = await makeRig("twitch");
      const pool = new Pool({ connectionString: rig.databaseUrl, max: 1 });
      pool.on("error", () => undefined);
      try {
        const store = new PostgresStore(pool);
        const idle = async () => {
          await sleep(10);
          const result = await pool.query<{ fresh: boolean }>("SELECT now() = statement_timestamp() AS fresh");
          return result.rows[0]!.fresh;
        };
        expect(await store.updateLinkedIdentityCredential(randomUUID(), async () => ({ kind: "keep" }))).toBeNull();
        expect(await idle()).toBe(true);
        await expect(
          store.updateLinkedIdentityCredential(rig.identityId, async () => {
            throw new Error("boom");
          })
        ).rejects.toThrow("boom");
        expect(await idle()).toBe(true);
      } finally {
        await pool.end();
      }
    });

    it.runIf(!live)("a decider arriving after the first drains still waits for the one queued behind it", async () => {
      const rig = await makeRig("twitch");
      const events: string[] = [];
      const decider = (name: string, ms: number) => async (locked: StoredLinkedIdentity) => {
        events.push(`start ${name}`);
        await sleep(ms);
        events.push(`end ${name}`);
        return { kind: "keep" as const, seen: locked };
      };
      const a = rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, decider("A", 20));
      const b = rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, decider("B", 120));
      await a;
      const c = rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, decider("C", 1));
      await Promise.all([b, c]);
      expect(events).toEqual(["start A", "end A", "start B", "end B", "start C", "end C"]);
    });

    it.runIf(!live)("drops a drained row's chain entry", async () => {
      const rig = await makeRig("twitch");
      await Promise.all([1, 2, 3].map(() => rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async () => ({ kind: "keep" }))));
      await sleep(5);
      expect((rig.stores[0] as unknown as { credentialChains: Map<string, unknown> }).credentialChains.size).toBe(0);
    });

    it("serialises deciders on one row: each sees the previous commit", timeout, async () => {
      const rig = await makeRig("twitch");
      const order: string[] = [];
      await Promise.all(
        [1, 2, 3, 4, 5].map((n) =>
          rig.stores[0]!.updateLinkedIdentityCredential(rig.identityId, async (locked) => {
            order.push(`${n}:${locked.accessTokenEncrypted}`);
            await sleep(20);
            return {
              kind: "rotate",
              accessTokenEncrypted: `A${n}`,
              refreshTokenEncrypted: `R${n}`,
              tokenExpiresAt: new Date(Date.now() + 3600_000).toISOString(),
              scopes: locked.scopes,
              updatedAt: new Date().toISOString(),
            };
          })
        )
      );
      const seenValues = order.map((entry) => entry.split(":")[1]);
      // Each decider saw the value the one before it wrote, so their reads form a chain.
      expect(new Set(seenValues).size).toBe(5);
      const wrote = order.map((entry) => `A${entry.split(":")[0]}`);
      for (let i = 1; i < seenValues.length; i += 1) expect(seenValues[i]).toBe(wrote[i - 1]);
    });
  });
});

describe("refreshManagedCredential without the lock", () => {
  const config = testConfig();
  const custody = createTokenCustody(config);
  const now = Date.parse("2026-10-19T12:00:00.000Z");

  function identity(overrides: Partial<StoredLinkedIdentity> = {}, provider: Provider = "twitch"): StoredLinkedIdentity {
    return {
      id: "id-1",
      accountId: "acct-1",
      provider,
      providerUserId: "u1",
      scopes: ["s"],
      profileJson: {},
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      accessTokenEncrypted: custody.encrypt("access-0"),
      refreshTokenEncrypted: custody.encrypt("refresh-0"),
      tokenExpiresAt: new Date(now + 60 * 60 * 1000).toISOString(),
      ...overrides,
    };
  }

  function countingStore(locked: StoredLinkedIdentity | null) {
    const log = { locks: 0, decisions: [] as unknown[], audits: [] as unknown[] };
    const store = {
      async updateLinkedIdentityCredential(_id: string, decide: (row: StoredLinkedIdentity) => Promise<unknown>) {
        log.locks += 1;
        if (locked === null) return null;
        log.decisions.push(await decide(locked));
        return locked;
      },
      async createAuditEvent(event: unknown) {
        log.audits.push(event);
      },
    };
    return { store: store as unknown as HeimdallStore, log };
  }

  const ctxFor = (store: HeimdallStore) => ({ config, store, tokenCustody: custody, oauthRuntimes: createOAuthRuntimeRegistry(), clock: () => now });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("a snapshot with no access token is revoked without a lock or a provider call", async () => {
    const { store, log } = countingStore(null);
    const endpoint = installTokenEndpoint("twitch", "refresh-0");
    const outcome = await refreshManagedCredential(ctxFor(store), identity({ accessTokenEncrypted: undefined as never }));
    expect(outcome.kind).toBe("revoked");
    expect(log.locks).toBe(0);
    expect(endpoint.calls).toBe(0);
  });

  it.each([
    ["outside the skew", {}, "twitch"],
    ["without an expiry", { tokenExpiresAt: undefined as never }, "twitch"],
    ["without a refresh token", { refreshTokenEncrypted: undefined as never, tokenExpiresAt: new Date(now).toISOString() }, "twitch"],
    ["for a provider whose runtime cannot refresh", { tokenExpiresAt: new Date(now).toISOString() }, "github"],
  ] as const)("a credential %s is current with no lock and no provider call", async (_name, overrides, provider) => {
    const { store, log } = countingStore(null);
    const endpoint = installTokenEndpoint("twitch", "refresh-0");
    const snapshot = identity(overrides as Partial<StoredLinkedIdentity>, provider);
    const outcome = await refreshManagedCredential(ctxFor(store), snapshot);
    expect(outcome).toEqual({ kind: "current", identity: snapshot });
    expect(log.locks).toBe(0);
    expect(endpoint.calls).toBe(0);
  });

  it("an expiry exactly one skew away is due; one millisecond further is not", async () => {
    const due = identity({ tokenExpiresAt: new Date(now + MANAGED_CREDENTIAL_REFRESH_SKEW_MS).toISOString() });
    const notDue = identity({ tokenExpiresAt: new Date(now + MANAGED_CREDENTIAL_REFRESH_SKEW_MS + 1).toISOString() });
    const a = countingStore(due);
    installTokenEndpoint("twitch", "refresh-0");
    await refreshManagedCredential(ctxFor(a.store), due);
    expect(a.log.locks).toBe(1);
    const b = countingStore(notDue);
    await refreshManagedCredential(ctxFor(b.store), notDue);
    expect(b.log.locks).toBe(0);
  });

  it("decides revoke for a grant verdict and for a missing rotated token, rotate otherwise", async () => {
    const due = identity({ tokenExpiresAt: new Date(now).toISOString() });
    const grant = countingStore(due);
    installTokenEndpoint("twitch", "refresh-0").mode = "invalid_grant";
    await refreshManagedCredential(ctxFor(grant.store), due);
    expect(grant.log.decisions).toEqual([{ kind: "revoke", updatedAt: new Date(now).toISOString() }]);
    expect(grant.log.audits).toEqual([
      expect.objectContaining({ eventType: "managed_credential_revoked", eventPayloadJson: { provider: "twitch", reason: "provider_revoked" } }),
    ]);

    const rotating = identity({ tokenExpiresAt: new Date(now).toISOString() }, "joystick");
    const missing = countingStore(rotating);
    installTokenEndpoint("joystick", "refresh-0").mode = "no_refresh_token";
    await refreshManagedCredential(ctxFor(missing.store), rotating);
    expect(missing.log.decisions).toEqual([{ kind: "revoke", updatedAt: new Date(now).toISOString() }]);

    const fine = countingStore(due);
    installTokenEndpoint("twitch", "refresh-0");
    await refreshManagedCredential(ctxFor(fine.store), due);
    expect(fine.log.decisions).toEqual([expect.objectContaining({ kind: "rotate", refreshTokenEncrypted: expect.any(String), scopes: ["s"] })]);
    expect(fine.log.audits).toEqual([]);
  });

  it("a row that vanished is revoked with its tokens cleared", async () => {
    const due = identity({ tokenExpiresAt: new Date(now).toISOString() });
    const { store } = countingStore(null);
    installTokenEndpoint("twitch", "refresh-0");
    const outcome = await refreshManagedCredential(ctxFor(store), due);
    expect(outcome.kind).toBe("revoked");
    expect(outcome.identity.accessTokenEncrypted).toBeUndefined();
    expect(outcome.identity.refreshTokenEncrypted).toBeUndefined();
    expect(outcome.identity.tokenExpiresAt).toBeUndefined();
    expect(outcome.identity.providerUserId).toBe("u1");
  });

  it("a row revoked by someone else between the snapshot and the lock is revoked, with no provider call", async () => {
    const due = identity({ tokenExpiresAt: new Date(now).toISOString() });
    const gone = identity({ accessTokenEncrypted: undefined as never, refreshTokenEncrypted: undefined as never, tokenExpiresAt: undefined as never });
    const { store } = countingStore(gone);
    const endpoint = installTokenEndpoint("twitch", "refresh-0");
    const outcome = await refreshManagedCredential(ctxFor(store), due);
    expect(outcome.kind).toBe("revoked");
    expect(endpoint.calls).toBe(0);
  });

  it("names the provider in the failure and carries nothing the provider said", async () => {
    const due = identity({ tokenExpiresAt: new Date(now).toISOString() });
    const { store } = countingStore(due);
    installTokenEndpoint("twitch", "refresh-0").mode = "server_error";
    const failure = await refreshManagedCredential(ctxFor(store), due).catch((error: unknown) => error as ManagedCredentialRefreshFailed);
    expect(failure).toBeInstanceOf(ManagedCredentialRefreshFailed);
    expect((failure as Error).message).toBe("Twitch managed credential refresh failed.");
    expect((failure as ManagedCredentialRefreshFailed).code).toBe("managed_credential_refresh_failed");
  });
});

describe("refresh answer classification", () => {
  const config = testConfig();
  const custody = createTokenCustody(config);
  const now = Date.parse("2026-10-19T12:00:00.000Z");
  const dueAt = new Date(now).toISOString();

  async function seedRow(store: InMemoryStore, provider: Provider) {
    const created = new Date(now).toISOString();
    const account = await store.createAccount({ createdAt: created, lastSeenAt: created });
    return store.upsertLinkedIdentity({
      accountId: account.id,
      provider,
      providerUserId: `u-${randomUUID()}`,
      scopes: ["s"],
      profileJson: {},
      accessTokenEncrypted: custody.encrypt("access-0"),
      refreshTokenEncrypted: custody.encrypt("refresh-0"),
      tokenExpiresAt: dueAt,
      createdAt: created,
      updatedAt: created,
    });
  }

  const ctxFor = (store: HeimdallStore, extra: { timeoutMs?: number } = {}) => ({
    config,
    store,
    tokenCustody: custody,
    oauthRuntimes: createOAuthRuntimeRegistry(),
    clock: () => now,
    ...extra,
  });

  function answer(body: string, status: number) {
    const calls: string[] = [];
    globalThis.fetch = (async (_input: string | URL, init?: RequestInit) => {
      calls.push(String((init!.body as URLSearchParams).get("refresh_token")));
      return new Response(body, { status });
    }) as typeof fetch;
    return calls;
  }

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const grantVerdict = JSON.stringify({ error: "invalid_grant" });
  const keepsTokens: Array<[string, string, number]> = [
    ["an error code that only contains invalid_grant", JSON.stringify({ error: "invalid_grant_extra" }), 400],
    ["an error code that is contained in a longer one", JSON.stringify({ error: "not_invalid_grant" }), 400],
    ["a different error code", JSON.stringify({ error: "invalid_request" }), 400],
    ["a 401 carrying invalid_grant", grantVerdict, 401],
    ["a 500 carrying invalid_grant", grantVerdict, 500],
    ["a 503 carrying invalid_grant", grantVerdict, 503],
    ["a 2xx carrying invalid_grant", grantVerdict, 200],
    ["a 2xx carrying an error beside an access token", JSON.stringify({ access_token: "a", error: "server_error" }), 200],
    ["a 2xx with an empty object", "{}", 200],
    ["a 2xx with an empty body", "", 200],
    ["a 2xx with JSON null", "null", 200],
    ["a 2xx with a JSON array", "[]", 200],
    ["a 2xx with a non-string access token", JSON.stringify({ access_token: 7, refresh_token: "r" }), 200],
    ["a 2xx with a numeric refresh token", JSON.stringify({ access_token: "a", refresh_token: 42 }), 200],
    ["a 2xx with an object refresh token", JSON.stringify({ access_token: "a", refresh_token: { r: 1 } }), 200],
    ["a 2xx with an empty access token", JSON.stringify({ access_token: "", refresh_token: "r" }), 200],
    ["a 2xx that is not JSON", "<html>", 200],
    ["a 5xx page", "upstream exploded", 502],
  ];

  describe.each(["twitch", "joystick"] as const)("%s", (provider) => {
    it.each(keepsTokens)("keeps the tokens and fails typed for %s", async (_name, body, status) => {
      const store = new InMemoryStore();
      const row = await seedRow(store, provider);
      const calls = answer(body, status);
      await expect(refreshManagedCredential(ctxFor(store), row)).rejects.toBeInstanceOf(ManagedCredentialRefreshFailed);
      expect(calls).toEqual(["refresh-0"]);
      const after = (await store.findStoredLinkedIdentity(provider, row.providerUserId))!;
      expect(after.accessTokenEncrypted).toBe(row.accessTokenEncrypted);
      expect(after.refreshTokenEncrypted).toBe(row.refreshTokenEncrypted);
      expect(after.tokenExpiresAt).toBe(dueAt);
    });

    it("keeps the tokens and fails typed when the provider never answers", async () => {
      const store = new InMemoryStore();
      const row = await seedRow(store, provider);
      globalThis.fetch = ((_input: string | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init!.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        })) as typeof fetch;
      await expect(refreshManagedCredential(ctxFor(store, { timeoutMs: 30 }), row)).rejects.toBeInstanceOf(ManagedCredentialRefreshFailed);
      const after = (await store.findStoredLinkedIdentity(provider, row.providerUserId))!;
      expect(after.refreshTokenEncrypted).toBe(row.refreshTokenEncrypted);
    });

    it("revokes and clears the tokens on a 400 whose error is exactly invalid_grant", async () => {
      const store = new InMemoryStore();
      const row = await seedRow(store, provider);
      answer(grantVerdict, 400);
      const outcome = await refreshManagedCredential(ctxFor(store), row);
      expect(outcome.kind).toBe("revoked");
      const after = (await store.findStoredLinkedIdentity(provider, row.providerUserId))!;
      expect(after.accessTokenEncrypted).toBeUndefined();
      expect(after.refreshTokenEncrypted).toBeUndefined();
    });
  });

  it.each([
    ["without a refresh token", { access_token: "a", expires_in: 3600 }],
    ["with an empty refresh token", { access_token: "a", refresh_token: "", expires_in: 3600 }],
  ])("a rotating provider's well-formed answer %s still revokes (rotation_missing)", async (_n, body) => {
    const store = new InMemoryStore();
    const row = await seedRow(store, "joystick");
    answer(JSON.stringify(body), 200);
    expect((await refreshManagedCredential(ctxFor(store), row)).kind).toBe("revoked");
    expect((await store.findStoredLinkedIdentity("joystick", row.providerUserId))!.refreshTokenEncrypted).toBeUndefined();
  });

  it.each([
    ["no expires_in", {}],
    ["a non-numeric string expires_in", { expires_in: "soon" }],
  ])("an answer with %s stores now plus the default lifetime; resolve refreshes once it passes", async (_n, extra) => {
    const store = new InMemoryStore();
    const seeded = await seedRow(store, "twitch");
    // Due against the real clock, which the token answer's expiry is computed from.
    const row = (await store.updateLinkedIdentityCredential(seeded.id, async (locked) => ({
      kind: "rotate",
      accessTokenEncrypted: locked.accessTokenEncrypted!,
      refreshTokenEncrypted: locked.refreshTokenEncrypted!,
      tokenExpiresAt: new Date().toISOString(),
      scopes: locked.scopes,
      updatedAt: new Date().toISOString(),
    })))!;
    const calls = answer(JSON.stringify({ access_token: "access-1", refresh_token: "refresh-1", ...extra }), 200);
    let skew = 0;
    const ctx = { ...ctxFor(store), clock: () => Date.now() + skew };
    const before = Date.now();
    const first = await refreshManagedCredential(ctx, row);
    expect(first.kind).toBe("current");
    const stored = (await store.findStoredLinkedIdentity("twitch", row.providerUserId))!;
    const expiry = Date.parse(stored.tokenExpiresAt!);
    expect(expiry - before).toBeGreaterThanOrEqual(providerCatalog.twitch.defaultAccessTokenLifetimeSeconds * 1000);
    expect(expiry - before).toBeLessThan(providerCatalog.twitch.defaultAccessTokenLifetimeSeconds * 1000 + 5_000);
    expect(custody.decrypt(stored.accessTokenEncrypted!)).toBe("access-1");

    await refreshManagedCredential(ctx, stored);
    expect(calls).toEqual(["refresh-0"]);

    skew = providerCatalog.twitch.defaultAccessTokenLifetimeSeconds * 1000;
    await refreshManagedCredential(ctx, stored);
    expect(calls).toEqual(["refresh-0", "refresh-1"]);
  });

  it("a non-rotating provider keeps the locked row's refresh token, not the snapshot's", async () => {
    const store = new InMemoryStore();
    const snapshot = await seedRow(store, "twitch");
    // Another caller rotated the pair after the snapshot; its expiry is still due.
    await store.updateLinkedIdentityCredential(snapshot.id, async () => ({
      kind: "rotate",
      accessTokenEncrypted: custody.encrypt("access-1"),
      refreshTokenEncrypted: custody.encrypt("refresh-1"),
      tokenExpiresAt: dueAt,
      scopes: ["s"],
      updatedAt: dueAt,
    }));
    const calls = answer(JSON.stringify({ access_token: "access-2", expires_in: 3600 }), 200);
    await refreshManagedCredential(ctxFor(store), snapshot);
    expect(calls).toEqual(["refresh-1"]);
    const after = (await store.findStoredLinkedIdentity("twitch", snapshot.providerUserId))!;
    expect(custody.decrypt(after.refreshTokenEncrypted!)).toBe("refresh-1");
    expect(custody.decrypt(after.accessTokenEncrypted!)).toBe("access-2");
  });
});

describe("live Postgres availability", () => {
  it.skipIf(!!adminUrl)("is present whenever the job requires it", () => {
    // Local workstation runs skip the live suites; the verification job sets
    // HEIMDALL_REQUIRE_LIVE_PG=1 and fails here when they would have been skipped.
    expect(process.env.HEIMDALL_REQUIRE_LIVE_PG).toBeUndefined();
  });
});
