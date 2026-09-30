import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { newDb } from "pg-mem";
import { type HeimdallConfig } from "../src/config.js";
import { createStore } from "../src/store/index.js";
import {
  createPostgresStore,
  PostgresStore,
  predicateConditions,
  printedDeclaredPredicates,
  samePredicate,
  STORE_TABLE_PRIVILEGES,
} from "../src/store/postgres.js";
import { REQUIRED_COLUMNS, REQUIRED_KEYS, REQUIRED_TABLES } from "../src/store/schema.js";

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
  it("derives every table, typed column and unique key from the schema", () => {
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
        { table: "auth_completions", column: "code", type: "TEXT", nullable: false },
        { table: "sessions", column: "access_revision", type: "INTEGER", nullable: false },
        { table: "linked_identities", column: "profile_json", type: "JSONB", nullable: false },
        { table: "linked_identities", column: "username", type: "TEXT", nullable: true },
        { table: "entitlement_snapshots", column: "is_allowed", type: "BOOLEAN", nullable: false },
        { table: "auth_completions", column: "attempt_id", type: "TEXT", nullable: true },
      ])
    );
    expect(REQUIRED_KEYS).toHaveLength(12);
    expect(REQUIRED_KEYS).toEqual(
      expect.arrayContaining([
        { table: "linked_identities", columns: "provider,provider_user_id", predicate: "" },
        { table: "private_command_receipts", columns: "app_slug,idempotency_key", predicate: "" },
        { table: "entitlement_snapshots", columns: "account_id,provider,scope", predicate: "" },
        { table: "auth_completions", columns: "app_slug,attempt_id", predicate: "attempt_id IS NOT NULL AND consumed_at IS NULL" },
      ])
    );
  });

  // Soul pass 6: stripping parentheses and case merged predicates of
  // different meaning. These are Postgres's own printed forms.
  it("splits a printed predicate only at its top-level ANDs", () => {
    expect(predicateConditions("((a OR b) AND c)")).toEqual(["a OR b", "c"]);
    expect(predicateConditions("(a OR (b AND c))")).toEqual(["a OR (b AND c)"]);
    expect(predicateConditions("((attempt_id IS NOT NULL) AND (consumed_at IS NULL))")).toEqual([
      "attempt_id IS NOT NULL",
      "consumed_at IS NULL",
    ]);
    expect(predicateConditions("(s = 'x AND (y'::text)")).toEqual(["s = 'x AND (y'::text"]);
    expect(predicateConditions("")).toEqual([]);
  });

  it("matches predicates by their conditions, never by case or by dropping structure", () => {
    const keys = ["app_slug", "attempt_id"];
    expect(samePredicate("((a OR b) AND c)", "(a OR (b AND c))", keys, false)).toBe(false);
    expect(samePredicate("(s = 'Pending'::text)", "(s = 'pending'::text)", keys, false)).toBe(false);
    expect(samePredicate("((a) AND (b))", "((b) AND (a))", keys, false)).toBe(true);
    expect(samePredicate("((a) AND (b))", "((a) AND (b) AND (c))", keys, false)).toBe(false);
  });

  it("lets a key column's IS NOT NULL be absent only where NULL keys cannot collide", () => {
    const keys = ["app_slug", "attempt_id"];
    const declared = "((attempt_id IS NOT NULL) AND (consumed_at IS NULL))";
    expect(samePredicate(declared, "(consumed_at IS NULL)", keys, false)).toBe(true);
    expect(samePredicate(declared, "(consumed_at IS NULL)", keys, true)).toBe(false);
    expect(samePredicate(declared, "((consumed_at IS NULL) AND (other IS NOT NULL))", keys, false)).toBe(false);
  });

  it("requires a key without a predicate to have none", () => {
    expect(samePredicate("", "", ["id"], false)).toBe(true);
    expect(samePredicate("", "(id IS NOT NULL)", ["id"], false)).toBe(false);
  });
});

/**
 * Every operation the store offers, once, in an order that makes each one
 * meaningful. Returns the names it called, so a test can prove it covered the
 * store. Throws on the first operation the database refuses.
 */
async function exerciseStore(store: PostgresStore): Promise<Set<string>> {
  const called = new Set<string>();
  const s = new Proxy(store, {
    get(target, name, receiver) {
      const value = Reflect.get(target, name, receiver) as unknown;
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        called.add(String(name));
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  const now = "2026-04-26T12:00:00.000Z";
  const later = "2999-01-01T00:00:00.000Z";
  const account = await s.createAccount({ createdAt: now, lastSeenAt: now, displayName: "Probe" });
  await s.touchAccount(account.id, now, { displayName: "Probe 2" });
  await s.findAccountById(account.id);
  const identity = {
    accountId: account.id,
    provider: "discord" as const,
    providerUserId: "u1",
    scopes: ["identify"],
    profileJson: {},
    createdAt: now,
    updatedAt: now,
  };
  await s.upsertLinkedIdentity(identity);
  await s.upsertLinkedIdentity({ ...identity, username: "again" });
  await s.findAccountByLinkedIdentity("discord", "u1");
  await s.findStoredLinkedIdentity("discord", "u1");
  await s.findStoredLinkedIdentityForAccount(account.id, "discord");
  await s.listStoredLinkedIdentitiesForAccount(account.id);
  await s.listLinkedIdentitiesForAccount(account.id);
  await s.createCapabilityGrant({
    accountId: account.id,
    scopeType: "app",
    scopeId: "ghostlight",
    capability: "app_access",
    source: "probe",
    status: "active",
    createdAt: now,
    updatedAt: now,
  });
  await s.listActiveGrants(account.id, "ghostlight", now);
  const session = { id: randomUUID(), accountId: account.id, appSlug: "ghostlight" as const, createdAt: now, lastSeenAt: now, expiresAt: later, accessRevision: 1, claimsJson: {} };
  await s.createSession(session);
  await s.createSession({ ...session, lastSeenAt: later });
  await s.findSession("ghostlight", session.id);
  await s.revokeSession("ghostlight", session.id, account.id, 1, now);
  const attempt = await s.createAuthAttempt({ appSlug: "ghostlight", provider: "discord", mode: "sign_in", returnTo: "https://x.test/", createdAt: now, expiresAt: later });
  await s.findAuthAttempt("ghostlight", attempt.handle);
  await s.updateAuthAttempt("ghostlight", attempt.handle, { status: "completed", at: now });
  const receipt = { appSlug: "ghostlight" as const, idempotencyKey: "k", requestFingerprint: "f", status: "accepted", contentSchema: "c", envelopeBase64: "e", createdAt: now, expiresAt: later };
  await s.createPrivateCommandReceipt(receipt);
  await s.createPrivateCommandReceipt(receipt);
  await s.findPrivateCommandReceipt("ghostlight", "k");
  const completion = { appSlug: "ghostlight" as const, provider: "discord" as const, mode: "sign_in" as const, accountId: account.id, sessionId: session.id, returnTo: "https://x.test/", createdAt: now, expiresAt: later, payloadJson: {} };
  const byCode = await s.createAuthCompletion(completion);
  await s.consumeAuthCompletion("ghostlight", byCode.code, now);
  await s.createAuthCompletion({ ...completion, attemptId: attempt.handle });
  await s.consumeAuthCompletionByAttempt("ghostlight", attempt.handle, now);
  const snapshot = { accountId: account.id, provider: "discord" as const, scope: "ghostlight:probe", evaluatedAt: now, isAllowed: true, reasonCode: "ok", rawSummaryJson: {} };
  await s.upsertEntitlementSnapshot(snapshot);
  await s.upsertEntitlementSnapshot({ ...snapshot, isAllowed: false });
  await s.createAuditEvent({ eventType: "probe", eventPayloadJson: {}, createdAt: now });
  return called;
}

// Against a real Postgres, through the startup path itself: createStore, with
// and without applying the schema. HEIMDALL_TEST_PG_ADMIN_URL names a role
// that may create databases and roles. Each case clones a template database
// that already holds the schema, and runs as its own login role.
const adminUrl = process.env.HEIMDALL_TEST_PG_ADMIN_URL;
describe.skipIf(!adminUrl)("startup against a live Postgres (HEIMDALL_TEST_PG_ADMIN_URL)", { timeout: 120_000 }, () => {
  const refusal = (code: string) => `Postgres storage could not be prepared (${code}); check GC_ACCESS_DATABASE_URL_FILE.`;
  const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
  const template = `heimdall_template_${suffix}`;
  const role = `heimdall_app_${suffix}`;
  const rolePassword = "CANARYrolepw";
  const admin = adminUrl ? new Pool({ connectionString: adminUrl, max: 2 }) : undefined;
  const cleanup: Array<() => Promise<void>> = [];

  /**
   * A pool the test itself uses. The forced drops end its connections,
   * possibly while pg is still closing them after end() resolved; that is
   * cleanup, not a finding, so it is not left to become an unhandled error.
   */
  function fixturePool(connectionString: string): Pool {
    const pool = new Pool({ connectionString, max: 2 });
    pool.on("error", () => undefined);
    return pool;
  }

  function urlFor(database: string, user?: string, password?: string): string {
    const url = new URL(adminUrl!);
    url.pathname = `/${database}`;
    if (user) url.username = user;
    if (password) url.password = password;
    return url.toString();
  }

  beforeAll(async () => {
    await admin!.query(`CREATE DATABASE ${template}`);
    const pool = fixturePool(urlFor(template));
    await new PostgresStore(pool).ensureSchema();
    await pool.end();
    await admin!.query(`CREATE ROLE ${role} LOGIN PASSWORD '${rolePassword}'`);
  }, 120_000);

  afterEach(async () => {
    for (const step of cleanup.splice(0).reverse()) await step();
  });

  afterAll(async () => {
    await admin!.query(`DROP DATABASE IF EXISTS ${template}`);
    await admin!.query(`DROP ROLE IF EXISTS ${role}`);
    await admin!.end();
  }, 120_000);

  /** A clone of the applied template, and a pool on it as its owner (the admin role). */
  async function appliedDatabase(): Promise<{ name: string; owner: Pool }> {
    const name = `heimdall_check_${randomUUID().replace(/-/g, "")}`;
    await admin!.query(`CREATE DATABASE ${name} TEMPLATE ${template}`);
    const owner = fixturePool(urlFor(name));
    cleanup.push(async () => {
      await owner.end();
      await admin!.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    });
    return { name, owner };
  }

  /** Grants the app role exactly `privileges`, per table, and nothing else. */
  async function grant(owner: Pool, privileges: Readonly<Record<string, readonly string[]>>): Promise<void> {
    await owner.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
    for (const [table, wanted] of Object.entries(privileges)) {
      if (wanted.length > 0) await owner.query(`GRANT ${wanted.join(", ")} ON ${table} TO ${role}`);
    }
  }

  /**
   * Starts Heimdall's store on `url` and reports "started" or the refusal's
   * message. A refusal must also leave no session of its own behind: the
   * refused store's pool is closed before the error is thrown.
   */
  async function start(url: string, applySchemaOnStartup: boolean): Promise<string> {
    const tagged = new URL(url);
    const tag = `heimdall_start_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    tagged.searchParams.set("application_name", tag);
    try {
      const store = await createStore({
        storage: { backend: "postgres", databaseUrl: tagged.toString(), applySchemaOnStartup },
      } as HeimdallConfig);
      await store.close();
      return "started";
    } catch (error) {
      let sessions = -1;
      for (let attempt = 0; attempt < 50 && sessions !== 0; attempt += 1) {
        if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 100));
        const result = await admin!.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name = $1",
          [tag]
        );
        sessions = result.rows[0]!.n;
      }
      expect(sessions, "a refused store left its connection open").toBe(0);
      return (error as Error).message;
    }
  }

  it("starts on an applied database as its owner, applying or not", async () => {
    const { name } = await appliedDatabase();
    expect(await start(urlFor(name), false)).toBe("started");
    expect(await start(urlFor(name), true)).toBe("started");
  });

  it("serves every store operation with exactly the privileges it checks for", async () => {
    const { name, owner } = await appliedDatabase();
    await grant(owner, STORE_TABLE_PRIVILEGES);

    expect(await start(urlFor(name, role, rolePassword), false)).toBe("started");
    const pool = fixturePool(urlFor(name, role, rolePassword));
    cleanup.push(async () => {
      await pool.end();
    });
    const called = await exerciseStore(new PostgresStore(pool));
    const offered = Object.getOwnPropertyNames(PostgresStore.prototype).filter(
      (method) => !["constructor", "ensureSchema", "checkSchema", "close"].includes(method)
    );
    expect([...called].sort()).toEqual(offered.sort());
  });

  it("refuses each privilege taken away, and the store needs each one", async () => {
    const pairs = Object.entries(STORE_TABLE_PRIVILEGES).flatMap(([table, wanted]) => wanted.map((privilege) => ({ table, privilege })));
    expect(Object.keys(STORE_TABLE_PRIVILEGES).sort()).toEqual([...REQUIRED_TABLES].sort());
    for (const { table, privilege } of pairs) {
      const { name, owner } = await appliedDatabase();
      await grant(owner, { ...STORE_TABLE_PRIVILEGES, [table]: STORE_TABLE_PRIVILEGES[table]!.filter((p) => p !== privilege) });

      const message = await start(urlFor(name, role, rolePassword), false);
      expect(message, `${table} without ${privilege}`).toBe(refusal("SCHEMA_PRIVILEGES"));
      expect(message).not.toContain("CANARY");

      const pool = fixturePool(urlFor(name, role, rolePassword));
      const failure = await exerciseStore(new PostgresStore(pool)).then(
        () => undefined,
        (error: unknown) => (error as { code?: string }).code
      );
      await pool.end();
      expect(failure, `the store runs without ${privilege} on ${table}, so the check need not ask for it`).toBe("42501");
      for (const step of cleanup.splice(0).reverse()) await step();
    }
  });

  it("refuses to apply the schema as a role that may not, and closes the store", async () => {
    const { name, owner } = await appliedDatabase();
    await grant(owner, STORE_TABLE_PRIVILEGES);

    expect(await start(urlFor(name, role, rolePassword), true)).toBe(refusal("42501"));
  });

  it("prints each declared predicate exactly as Postgres prints the applied index's", async () => {
    const { owner } = await appliedDatabase();
    const printed = await printedDeclaredPredicates(owner);
    const applied = await owner.query<{ predicate: string }>(
      "SELECT pg_get_expr(indpred, indrelid) AS predicate FROM pg_index WHERE indexrelid = 'auth_completions_attempt_unconsumed_unique_idx'::regclass"
    );
    const attemptKey = REQUIRED_KEYS.findIndex((key) => key.predicate !== "");
    expect(printed[attemptKey]).toBe(applied.rows[0]!.predicate);
    expect(printed.filter((predicate) => predicate !== "")).toHaveLength(1);
  });

  it("refuses a table whose primary key was dropped, even after applying the schema", async () => {
    const { name, owner } = await appliedDatabase();
    await owner.query("ALTER TABLE auth_completions DROP CONSTRAINT auth_completions_pkey");

    expect(await start(urlFor(name), false)).toBe(refusal("SCHEMA_MISSING"));
    expect(await start(urlFor(name), true)).toBe(refusal("SCHEMA_MISSING"));
  });

  it("serves every store operation with each privilege granted column by column", async () => {
    const { name, owner } = await appliedDatabase();
    await owner.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
    for (const [table, wanted] of Object.entries(STORE_TABLE_PRIVILEGES)) {
      const columns = REQUIRED_COLUMNS.filter((column) => column.table === table).map((column) => column.column).join(", ");
      for (const privilege of wanted) await owner.query(`GRANT ${privilege} (${columns}) ON ${table} TO ${role}`);
    }

    expect(await start(urlFor(name, role, rolePassword), false)).toBe("started");
    const pool = fixturePool(urlFor(name, role, rolePassword));
    cleanup.push(async () => {
      await pool.end();
    });
    await exerciseStore(new PostgresStore(pool));
  });

  it("refuses a privilege held on only some of a table's columns", async () => {
    const { name, owner } = await appliedDatabase();
    await grant(owner, { ...STORE_TABLE_PRIVILEGES, audit_events: [] });
    await owner.query(`GRANT INSERT (id) ON audit_events TO ${role}`);

    expect(await start(urlFor(name, role, rolePassword), false)).toBe(refusal("SCHEMA_PRIVILEGES"));
  });

  // Each damage below leaves a database whose shape still resembles the
  // schema but on which a store write fails or R21.1 no longer holds. A step
  // starting with "!" is expected to fail and leave its mark (a failed
  // CREATE INDEX CONCURRENTLY leaves an invalid index behind).
  const seedDuplicates = [
    "INSERT INTO accounts VALUES ('acc', now(), now(), null, null)",
    "INSERT INTO sessions VALUES ('s', 'acc', 'ghostlight', now(), now(), now() + interval '1 hour', '{}', 1)",
  ];
  it.each([
    ["a key made DEFERRABLE (ON CONFLICT refuses it as an arbiter)",
      ["ALTER TABLE private_command_receipts DROP CONSTRAINT private_command_receipts_pkey", "ALTER TABLE private_command_receipts ADD PRIMARY KEY (app_slug, idempotency_key) DEFERRABLE INITIALLY IMMEDIATE"]],
    ["a key narrowed to one column, the other only INCLUDEd",
      ["ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key", "CREATE UNIQUE INDEX li_include ON linked_identities(provider) INCLUDE (provider_user_id)"]],
    ["a key widened by an expression column",
      ["ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key", "CREATE UNIQUE INDEX li_expr ON linked_identities(provider, provider_user_id, lower(username))"]],
    ["a key replaced by a partial one",
      ["ALTER TABLE entitlement_snapshots DROP CONSTRAINT entitlement_snapshots_account_id_provider_scope_key", "CREATE UNIQUE INDEX es_partial ON entitlement_snapshots(account_id, provider, scope) WHERE is_allowed"]],
    ["a key replaced by a plain index on the same columns",
      ["ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key", "CREATE INDEX li_plain ON linked_identities(provider, provider_user_id)"]],
    ["a key replaced by one on other columns of the same count",
      ["ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key", "CREATE UNIQUE INDEX li_other ON linked_identities(provider, username)"]],
    ["a key left only as an invalid index by a failed concurrent build",
      [...seedDuplicates,
        "ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key",
        "INSERT INTO linked_identities (id, account_id, provider, provider_user_id, created_at, updated_at) VALUES ('l1', 'acc', 'youtube', 'dup', now(), now()), ('l2', 'acc', 'youtube', 'dup', now(), now())",
        "!CREATE UNIQUE INDEX CONCURRENTLY li_ccnew ON linked_identities(provider, provider_user_id)",
        "DELETE FROM linked_identities WHERE id = 'l2'"]],
    ["the attempt index left invalid over duplicate attempts by a failed concurrent build",
      [...seedDuplicates,
        "DROP INDEX auth_completions_attempt_unconsumed_unique_idx",
        "INSERT INTO auth_completions (code, attempt_id, app_slug, provider, mode, account_id, session_id, return_to, payload_json, created_at, expires_at) VALUES ('c1', 'att', 'ghostlight', 'discord', 'sign_in', 'acc', 's', 'https://x/', '{}', now(), now() + interval '1 hour'), ('c2', 'att', 'ghostlight', 'discord', 'sign_in', 'acc', 's', 'https://x/', '{}', now(), now() + interval '1 hour')",
        "!CREATE UNIQUE INDEX CONCURRENTLY auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id) WHERE attempt_id IS NOT NULL AND consumed_at IS NULL"]],
    // An interrupted DROP INDEX CONCURRENTLY leaves an index ready but not
    // valid; the fixture sets that state directly (the admin role may).
    ["a key left only as an index that is ready but not valid",
      ["ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key",
        "CREATE UNIQUE INDEX li_half_dropped ON linked_identities(provider, provider_user_id)",
        "UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'li_half_dropped'::regclass"]],
    ["a key compared under a case-insensitive collation (two users' ids become one row)",
      ["CREATE COLLATION heimdall_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false)",
        "ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key",
        "CREATE UNIQUE INDEX li_ci ON linked_identities(provider, provider_user_id COLLATE heimdall_ci)"]],
    ["the attempt index replaced by a plain one of the same name",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE INDEX auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id)"]],
    ["the attempt index made unique on every row (no predicate)",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id)"]],
    ["the attempt index given another predicate",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id) WHERE attempt_id IS NOT NULL"]],
    ["the attempt index narrowed by an extra condition",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id) WHERE attempt_id IS NOT NULL AND consumed_at IS NULL AND app_slug <> 'ghostlight'"]],
    ["the attempt index with a condition ORed into its predicate",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id) WHERE (attempt_id IS NOT NULL OR app_slug = 'x') AND consumed_at IS NULL"]],
    ["the attempt index made NULLS NOT DISTINCT without excluding NULL attempts",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX auth_completions_attempt_unconsumed_unique_idx ON auth_completions(app_slug, attempt_id) NULLS NOT DISTINCT WHERE consumed_at IS NULL"]],
    ["a column retyped", ["ALTER TABLE sessions ALTER COLUMN access_revision TYPE TEXT"]],
    ["a created table's column dropped", ["ALTER TABLE auth_completions DROP COLUMN mode"]],
    ["NOT NULL added to a column the store leaves null", ["ALTER TABLE auth_completions ALTER COLUMN attempt_id SET NOT NULL"]],
  ])("refuses %s", async (_damage, steps) => {
    const { name, owner } = await appliedDatabase();
    for (const step of steps) {
      if (step.startsWith("!")) await expect(owner.query(step.slice(1))).rejects.toBeDefined();
      else await owner.query(step);
    }

    expect(await start(urlFor(name), false)).toBe(refusal("SCHEMA_MISSING"));
  });

  // Each change below leaves a database the store serves exactly as before.
  it.each([
    ["a key index that carries extra INCLUDE columns",
      ["ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key", "CREATE UNIQUE INDEX li_covering ON linked_identities(provider, provider_user_id) INCLUDE (username)"]],
    ["the attempt index under another name", ["ALTER INDEX auth_completions_attempt_unconsumed_unique_idx RENAME TO attempt_idx_renamed"]],
    ["the attempt index's conditions in the other order",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX attempt_reordered ON auth_completions(app_slug, attempt_id) WHERE consumed_at IS NULL AND attempt_id IS NOT NULL"]],
    // NULL attempt ids never collide in a unique index that treats NULLs as
    // distinct (the default), so dropping that condition keeps the same rows unique.
    ["the attempt index without its redundant attempt_id IS NOT NULL",
      ["DROP INDEX auth_completions_attempt_unconsumed_unique_idx", "CREATE UNIQUE INDEX attempt_unconsumed ON auth_completions(app_slug, attempt_id) WHERE consumed_at IS NULL"]],
    ["a lookup index dropped", ["DROP INDEX audit_events_lookup_idx", "DROP INDEX auth_completions_lookup_idx"]],
  ])("accepts %s", async (_change, steps) => {
    const { name, owner } = await appliedDatabase();
    for (const step of steps) await owner.query(step);

    expect(await start(urlFor(name), false)).toBe("started");
  });
});
