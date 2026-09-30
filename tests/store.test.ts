import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterEach, describe, expect, it } from "vitest";
import { newDb } from "pg-mem";
import { type HeimdallConfig } from "../src/config.js";
import { createStore } from "../src/store/index.js";
import { createPostgresStore, PostgresStore } from "../src/store/postgres.js";
import {
  REQUIRED_COLUMNS,
  REQUIRED_KEYS,
  REQUIRED_RELATIONS,
  REQUIRED_TABLE_PRIVILEGES,
  REQUIRED_TABLES,
} from "../src/store/schema.js";

describe("PostgresStore", () => {
  it("round-trips core auth records through postgres", async () => {
    const db = newDb();
    const adapter = db.adapters.createPg();
    const pool = new adapter.Pool();
    const store = new PostgresStore(pool);
    await store.ensureSchema();

    const now = "2026-04-26T12:00:00.000Z";
    const account = await store.createAccount({
      createdAt: now,
      lastSeenAt: now,
      displayName: "Meta",
      primaryEmail: "meta@gamecult.org",
    });

    await store.upsertLinkedIdentity({
      accountId: account.id,
      provider: "discord",
      providerUserId: "discord-user-123",
      username: "meta",
      displayName: "Meta",
      primaryEmail: "meta@gamecult.org",
      accessTokenEncrypted: "encrypted-access-token",
      refreshTokenEncrypted: "encrypted-refresh-token",
      tokenExpiresAt: "2026-04-26T13:00:00.000Z",
      scopes: ["identify", "email"],
      profileJson: { id: "discord-user-123", username: "meta" },
      createdAt: now,
      updatedAt: now,
    });

    const found = await store.findAccountByLinkedIdentity("discord", "discord-user-123");
    expect(found).toEqual(
      expect.objectContaining({
        id: account.id,
        displayName: "Meta",
        primaryEmail: "meta@gamecult.org",
      })
    );

    const linkedIdentities = await store.listLinkedIdentitiesForAccount(account.id);
    expect(linkedIdentities).toEqual([
      {
        provider: "discord",
        providerUserId: "discord-user-123",
        username: "meta",
        displayName: "Meta",
      },
    ]);

    const storedIdentity = await store.findStoredLinkedIdentity("discord", "discord-user-123");
    expect(storedIdentity).toEqual(
      expect.objectContaining({
        provider: "discord",
        accessTokenEncrypted: "encrypted-access-token",
        refreshTokenEncrypted: "encrypted-refresh-token",
      })
    );

    await store.createCapabilityGrant({
      accountId: account.id,
      scopeType: "app",
      scopeId: "repixelizer",
      capability: "app_access",
      source: "manual",
      status: "active",
      note: "Test grant",
      createdAt: now,
      updatedAt: now,
    });

    const grants = await store.listActiveGrants(account.id, "repixelizer", "2026-04-26T12:01:00.000Z");
    expect(grants).toEqual([
      expect.objectContaining({
        capability: "app_access",
        scopeType: "app",
        scopeId: "repixelizer",
      }),
    ]);

    await store.createSession({
      id: "session-123",
      accountId: account.id,
      appSlug: "repixelizer",
      createdAt: now,
      lastSeenAt: now,
      expiresAt: "2026-04-26T13:00:00.000Z",
      accessRevision: 1,
      claimsJson: {
        iss: "https://heimdall.gamecult.org",
        aud: "repixelizer",
      },
    });

    await store.upsertEntitlementSnapshot({
      accountId: account.id,
      provider: "discord",
      scope: "repixelizer:discord_role_access:gamecult-guild",
      evaluatedAt: now,
      isAllowed: true,
      reasonCode: "matched_role",
      reasonDetail: "Matched test role",
      rawSummaryJson: { matchedRoles: ["role-repixelizer"] },
    });

    await store.createAuditEvent({
      accountId: account.id,
      sessionId: "session-123",
      appSlug: "repixelizer",
      eventType: "oauth_callback_succeeded",
      eventPayloadJson: { provider: "discord" },
      createdAt: now,
    });

    const completion = await store.createAuthCompletion({
      appSlug: "repixelizer",
      provider: "discord",
      mode: "sign_in",
      accountId: account.id,
      sessionId: "session-123",
      returnTo: "https://repixelizer.gamecult.org/app/",
      createdAt: now,
      expiresAt: "2026-04-26T12:05:00.000Z",
      payloadJson: {
        status: "success",
        provider: "discord",
        appSlug: "repixelizer",
      },
    });

    const consumed = await store.consumeAuthCompletion("repixelizer", completion.code, "2026-04-26T12:01:00.000Z");
    expect(consumed).toEqual(
      expect.objectContaining({
        code: completion.code,
        appSlug: "repixelizer",
        consumedAt: "2026-04-26T12:01:00.000Z",
      })
    );

    const consumedAgain = await store.consumeAuthCompletion("repixelizer", completion.code, "2026-04-26T12:02:00.000Z");
    expect(consumedAgain).toBeNull();

    const attempt = await store.createAuthAttempt({
      handle: "attempt-123",
      appSlug: "ghostlight",
      provider: "discord",
      mode: "sign_in",
      returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
      createdAt: now,
      expiresAt: "2026-04-26T12:05:00.000Z",
    });
    expect(attempt.status).toBe("pending");
    expect((await store.updateAuthAttempt("ghostlight", attempt.handle, {
      status: "completed",
      at: "2026-04-26T12:01:00.000Z",
    }))?.status).toBe("completed");
    expect((await store.updateAuthAttempt("ghostlight", attempt.handle, {
      status: "pending",
      at: "2026-04-26T12:02:00.000Z",
    }))?.status).toBe("completed");

    const privateReceipt = await store.createPrivateCommandReceipt({
      appSlug: "ghostlight",
      idempotencyKey: "idem-123",
      requestFingerprint: "fingerprint-123",
      status: "accepted",
      contentSchema: "heimdall.auth_begin_receipt.v1",
      envelopeBase64: "encrypted-messagepack",
      createdAt: now,
      expiresAt: "2026-04-26T12:01:00.000Z",
    });
    expect(await store.findPrivateCommandReceipt("ghostlight", "idem-123")).toEqual(privateReceipt);
    await expect(store.createPrivateCommandReceipt({
      ...privateReceipt,
      requestFingerprint: "different-command",
    })).rejects.toThrow("Idempotency key was reused");

    await store.close();
  });
});

describe("createPostgresStore", () => {
  // pg emits an idle client's connection loss on the pool. With no listener
  // that event kills the process, and Node prints the pg Client with its
  // connection parameters.
  it("survives an idle connection's loss and says so by code alone", async () => {
    const store = createPostgresStore("postgres://heimdall:CANARYpw@127.0.0.1:1/heimdall");
    const pool = (store as unknown as { pool: { emit(event: string, ...args: unknown[]): boolean } }).pool;
    const logged: string[] = [];
    const originalError = console.error;
    console.error = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
    try {
      const terminated = Object.assign(new Error("terminating connection due to administrator command CANARY"), {
        code: "57P01",
        client: { connectionParameters: { password: "CANARYpw" } },
      });
      expect(() => pool.emit("error", terminated, terminated.client)).not.toThrow();
    } finally {
      console.error = originalError;
      await store.close();
    }
    expect(logged).toEqual([
      "Heimdall lost an idle Postgres connection (57P01); the pool reconnects on the next query.",
    ]);
  });
});

describe("PostgresStore.checkSchema", () => {
  it("requires every table, index, column and key the schema makes", () => {
    expect(REQUIRED_RELATIONS).toEqual(
      expect.arrayContaining(["accounts", "audit_events", "auth_completions_attempt_unconsumed_unique_idx", "audit_events_lookup_idx"])
    );
    expect(REQUIRED_RELATIONS).toHaveLength(17);
    expect(REQUIRED_TABLES).toEqual([
      "accounts",
      "linked_identities",
      "sessions",
      "auth_attempts",
      "private_command_receipts",
      "auth_completions",
      "capability_grants",
      "entitlement_snapshots",
      "audit_events",
    ]);
    expect(REQUIRED_COLUMNS).toHaveLength(85);
    expect(REQUIRED_COLUMNS).toEqual(
      expect.arrayContaining([
        { table: "auth_completions", column: "code" },
        { table: "auth_completions", column: "mode" },
        { table: "linked_identities", column: "profile_json" },
        { table: "auth_completions", column: "attempt_id" },
      ])
    );
    // The keys the store's ON CONFLICT clauses and the foreign keys rely on.
    expect(REQUIRED_KEYS).toEqual(
      expect.arrayContaining([
        { table: "linked_identities", columns: "provider,provider_user_id" },
        { table: "sessions", columns: "id" },
        { table: "private_command_receipts", columns: "app_slug,idempotency_key" },
        { table: "entitlement_snapshots", columns: "account_id,provider,scope" },
        { table: "accounts", columns: "id" },
        { table: "auth_completions", columns: "code" },
      ])
    );
    expect(REQUIRED_KEYS).toHaveLength(11);
    expect(REQUIRED_TABLE_PRIVILEGES).toEqual(["SELECT", "INSERT", "UPDATE"]);
  });

  function storeAnswering(kinds: string[]) {
    return new PostgresStore({
      query: (async () => ({ rows: kinds.map((kind) => ({ kind })) })) as never,
      end: async () => undefined,
    });
  }

  it("refuses with SCHEMA_MISSING when anything is missing, whatever else is", async () => {
    await expect(storeAnswering(["privilege", "missing"]).checkSchema()).rejects.toMatchObject({ code: "SCHEMA_MISSING" });
  });

  it("refuses with SCHEMA_PRIVILEGES when only a privilege is missing", async () => {
    await expect(storeAnswering(["privilege"]).checkSchema()).rejects.toMatchObject({ code: "SCHEMA_PRIVILEGES" });
  });

  it("passes when nothing is missing", async () => {
    await expect(storeAnswering([]).checkSchema()).resolves.toBeUndefined();
  });
});

// Against a real Postgres, through the startup path itself: createStore, with
// and without applying the schema. HEIMDALL_TEST_PG_ADMIN_URL names a role
// that may create databases and roles; each case gets its own database.
const adminUrl = process.env.HEIMDALL_TEST_PG_ADMIN_URL;
describe.skipIf(!adminUrl)("startup against a live Postgres (HEIMDALL_TEST_PG_ADMIN_URL)", () => {
  const refusal = (code: string) => `Postgres storage could not be prepared (${code}); check GC_ACCESS_DATABASE_URL_FILE.`;
  const cleanup: Array<() => Promise<void>> = [];
  afterEach(async () => {
    for (const step of cleanup.splice(0).reverse()) await step();
  });

  function urlFor(database: string, user?: string, password?: string): string {
    const url = new URL(adminUrl!);
    url.pathname = `/${database}`;
    if (user) url.username = user;
    if (password) url.password = password;
    return url.toString();
  }

  /** A fresh database with the schema applied by its owner, and an owner pool on it. */
  async function appliedDatabase(): Promise<{ name: string; pool: Pool }> {
    const name = `heimdall_check_${randomUUID().replace(/-/g, "")}`;
    const admin = new Pool({ connectionString: adminUrl });
    await admin.query(`CREATE DATABASE ${name}`);
    cleanup.push(async () => {
      await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await admin.end();
    });
    const pool = new Pool({ connectionString: urlFor(name) });
    cleanup.push(async () => {
      await pool.end();
    });
    await new PostgresStore(pool).ensureSchema();
    return { name, pool };
  }

  async function start(url: string, applySchemaOnStartup: boolean): Promise<string> {
    try {
      const store = await createStore({ storage: { backend: "postgres", databaseUrl: url, applySchemaOnStartup } } as HeimdallConfig);
      await store.close();
      return "started";
    } catch (error) {
      return (error as Error).message;
    }
  }

  it("starts on an applied database, applying or not", async () => {
    const { name } = await appliedDatabase();
    expect(await start(urlFor(name), false)).toBe("started");
    expect(await start(urlFor(name), true)).toBe("started");
  });

  it("refuses a role that may only read, by code and without its password", async () => {
    const { name, pool } = await appliedDatabase();
    const role = `heimdall_ro_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD 'CANARYrolepw'`);
    cleanup.push(async () => {
      await pool.query(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ${role}`);
      await pool.query(`DROP ROLE IF EXISTS ${role}`);
    });
    await pool.query(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role}`);

    const message = await start(urlFor(name, role, "CANARYrolepw"), false);
    expect(message).toBe(refusal("SCHEMA_PRIVILEGES"));
    expect(message).not.toContain("CANARY");
  });

  it("refuses a table whose primary key was dropped, even after applying the schema", async () => {
    const { name, pool } = await appliedDatabase();
    await pool.query("ALTER TABLE auth_completions DROP CONSTRAINT auth_completions_pkey");

    expect(await start(urlFor(name), false)).toBe(refusal("SCHEMA_MISSING"));
    expect(await start(urlFor(name), true)).toBe(refusal("SCHEMA_MISSING"));
  });

  it("refuses a unique key the store's ON CONFLICT needs, replaced by a partial one", async () => {
    const { name, pool } = await appliedDatabase();
    await pool.query("ALTER TABLE entitlement_snapshots DROP CONSTRAINT entitlement_snapshots_account_id_provider_scope_key");
    await pool.query(
      "CREATE UNIQUE INDEX entitlement_snapshots_partial ON entitlement_snapshots(account_id, provider, scope) WHERE is_allowed"
    );

    expect(await start(urlFor(name), false)).toBe(refusal("SCHEMA_MISSING"));
  });

  it("refuses a created table's dropped column", async () => {
    const { name, pool } = await appliedDatabase();
    await pool.query("ALTER TABLE auth_completions DROP COLUMN mode");

    expect(await start(urlFor(name), false)).toBe(refusal("SCHEMA_MISSING"));
  });
});
