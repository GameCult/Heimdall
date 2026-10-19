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

type Mode = "normal" | "invalid_grant" | "invalid_client" | "server_error" | "not_json" | "no_refresh_token" | "hang";

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
      case "normal": {
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
            expires_in: 3600,
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

    it.each(["invalid_client", "server_error", "not_json", "hang"] as const)(
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
      it("rotation-fails-closed: a response without a refresh token revokes, 410, and the old token is never presented again", timeout, async () => {
        const rig = await makeRig(provider);
        const endpoint = installTokenEndpoint(provider, "refresh-0");
        endpoint.mode = "no_refresh_token";

        const first = await rig.resolve();
        expect(first.statusCode).toBe(410);
        expect(first.json).toEqual({ error: "managed_credential_revoked", provider });
        expect(first.body).not.toContain("access-norefresh");
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
      it("a response without a refresh token keeps the old one for a non-rotating provider", timeout, async () => {
        const rig = await makeRig(provider);
        const endpoint = installTokenEndpoint(provider, "refresh-0");
        endpoint.mode = "no_refresh_token";
        const answer = await rig.resolve();
        expect(answer.statusCode).toBe(200);
        expect(answer.json.accessToken).toBe("access-norefresh");
        expect(rig.custody.decrypt((await rig.row()).refreshTokenEncrypted!)).toBe("refresh-0");
      });
    }

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

describe("live Postgres availability", () => {
  it.skipIf(!!adminUrl)("is present whenever the job requires it", () => {
    // Local workstation runs skip the live suites; the verification job sets
    // HEIMDALL_REQUIRE_LIVE_PG=1 and fails here when they would have been skipped.
    expect(process.env.HEIMDALL_REQUIRE_LIVE_PG).toBeUndefined();
  });
});
