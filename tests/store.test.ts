import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { newDb } from "pg-mem";
import { type HeimdallConfig } from "../src/config.js";
import { createStore, IdentityHeldElsewhereError, InMemoryStore, type HeimdallStore } from "../src/store/index.js";
import {
  createPostgresStore,
  PostgresStore,
  checkSchemaRequirements,
  HEIMDALL_SCHEMA_REQUIREMENTS,
  predicateConditions,
  printedDeclaredPredicates,
  samePredicate,
  STORE_TABLE_PRIVILEGES,
} from "../src/store/postgres.js";
import {
  OAUTH_STATE_PRUNE_BATCH,
  OAUTH_STATE_PRUNE_MARGIN_MS,
  OAUTH_STATE_SKEW_MS,
} from "../src/store/types.js";
import { CREATE_SCHEMA_SQL, REQUIRED_COLUMNS, REQUIRED_KEYS, REQUIRED_TABLES } from "../src/store/schema.js";

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

// linked_identities has one writer that can move a row between accounts: none.
// upsert refreshes the holder's own row and refuses another account's; unlink is
// the only delete, and it never takes an account's last identity.
const unlinkStores: Array<[string, () => Promise<HeimdallStore>]> = [
  ["InMemoryStore", async () => new InMemoryStore()],
  [
    "PostgresStore on pg-mem",
    async () => {
      const store = new PostgresStore(new (newDb().adapters.createPg().Pool)());
      await store.ensureSchema();
      return store;
    },
  ],
];
describe.each(unlinkStores)("linked_identities writes, %s", (_name, make) => {
  const at = "2026-11-13T12:00:00.000Z";
  const input = (accountId: string, providerUserId: string, extra: Record<string, unknown> = {}) => ({
    accountId,
    provider: "discord" as const,
    providerUserId,
    scopes: ["identify"],
    profileJson: {},
    createdAt: at,
    updatedAt: at,
    ...extra,
  });
  async function twoAccounts() {
    const store = await make();
    const a = await store.createAccount({ createdAt: at, lastSeenAt: at });
    const b = await store.createAccount({ createdAt: at, lastSeenAt: at });
    return { store, a, b };
  }

  // pg-mem has neither ON CONFLICT ... WHERE nor row locks: these two run on real Postgres below.
  const realPostgresOnly = _name !== "InMemoryStore";

  it.skipIf(realPostgresOnly)("upsert on an identity another account holds throws IdentityHeldElsewhereError and leaves the row untouched", async () => {
    const { store, a, b } = await twoAccounts();
    const held = await store.upsertLinkedIdentity(input(a.id, "u1", { username: "original", accessTokenEncrypted: "keep" }));
    await expect(
      store.upsertLinkedIdentity(input(b.id, "u1", { username: "thief", accessTokenEncrypted: "stolen", updatedAt: "2027-01-01T00:00:00.000Z" }))
    ).rejects.toBeInstanceOf(IdentityHeldElsewhereError);
    expect(await store.findStoredLinkedIdentity("discord", "u1")).toEqual(held);
    expect(await store.listStoredLinkedIdentitiesForAccount(b.id)).toEqual([]);
  });

  it.skipIf(realPostgresOnly)("moveIdentities keeps one contract: moved, replayed, conflict, lapsed proof, coverage, reversal", async () => {
    await exerciseMoveContract(await make());
  });

  it("upsert by the holder still refreshes its own row, keeping its id", async () => {
    const { store, a } = await twoAccounts();
    const first = await store.upsertLinkedIdentity(input(a.id, "u1", { username: "one" }));
    const again = await store.upsertLinkedIdentity(input(a.id, "u1", { username: "two", updatedAt: "2026-11-14T00:00:00.000Z" }));
    expect([again.id, again.accountId, again.username]).toEqual([first.id, a.id, "two"]);
  });

  it("unlink: deletes one of two, refuses the last, reports another account's or a missing id as not_found", async () => {
    const { store, a, b } = await twoAccounts();
    const one = await store.upsertLinkedIdentity(input(a.id, "u1"));
    const two = await store.upsertLinkedIdentity(input(a.id, "u2"));
    const theirs = await store.upsertLinkedIdentity(input(b.id, "u3"));
    expect(await store.unlinkLinkedIdentity(a.id, theirs.id)).toEqual({ kind: "not_found" });
    expect(await store.unlinkLinkedIdentity(a.id, "no-such")).toEqual({ kind: "not_found" });
    expect(await store.unlinkLinkedIdentity(b.id, theirs.id)).toEqual({ kind: "last_identity" });
    const done = await store.unlinkLinkedIdentity(a.id, one.id);
    expect(done).toMatchObject({ kind: "unlinked", identity: { id: one.id, provider: "discord", providerUserId: "u1" } });
    expect(await store.unlinkLinkedIdentity(a.id, two.id)).toEqual({ kind: "last_identity" });
    expect((await store.listStoredLinkedIdentitiesForAccount(a.id)).map((i) => i.id)).toEqual([two.id]);
    expect(await store.findStoredLinkedIdentity("discord", "u3")).toMatchObject({ id: theirs.id, accountId: b.id });
  });

  it.skipIf(realPostgresOnly)("two concurrent unlinks of an account's last two identities leave exactly one", async () => {
    const { store, a } = await twoAccounts();
    const one = await store.upsertLinkedIdentity(input(a.id, "u1"));
    const two = await store.upsertLinkedIdentity(input(a.id, "u2"));
    const results = await Promise.all([store.unlinkLinkedIdentity(a.id, one.id), store.unlinkLinkedIdentity(a.id, two.id)]);
    expect(results.map((r) => r.kind).sort()).toEqual(["last_identity", "unlinked"]);
    expect(await store.listStoredLinkedIdentitiesForAccount(a.id)).toHaveLength(1);
  });
});

describe("consent_receipts foreign key", () => {
  it("a revocation names a receipt of its own account: the schema says so and the memory store enforces it", async () => {
    expect(CREATE_SCHEMA_SQL).toContain("FOREIGN KEY (revokes_receipt_id, account_id) REFERENCES consent_receipts(id, account_id)");
    const store = new InMemoryStore();
    const base = { appSlug: "streampixels" as const, provider: "joystick" as const, createdAt: "2026-11-08T00:00:00.000Z" };
    const { receipt: grant } = await store.createConsentReceipt({ ...base, accountId: "a", kind: "grant", scopesAsked: [], scopesGranted: [], consentPageDigest: "d", consentText: "t" });
    await expect(store.createConsentReceipt({ ...base, accountId: "b", kind: "revocation", revokesReceiptId: grant.id })).rejects.toThrow(/own account/);
    await expect(store.createConsentReceipt({ ...base, accountId: "a", kind: "revocation", revokesReceiptId: "no-such" })).rejects.toThrow(/own account/);
    expect(await store.listConsentReceipts("a")).toHaveLength(1);
  });
});

describe("PostgresStore.createConsentReceipt revocation conflict", () => {
  async function granted() {
    const adapter = newDb().adapters.createPg();
    const store = new PostgresStore(new adapter.Pool());
    await store.ensureSchema();
    const now = "2026-11-08T00:00:00.000Z";
    const account = await store.createAccount({ createdAt: now, lastSeenAt: now, displayName: "Probe" });
    const base = { accountId: account.id, appSlug: "streampixels" as const, provider: "joystick" as const };
    const { receipt: grant } = await store.createConsentReceipt({ ...base, kind: "grant", createdAt: now, scopesAsked: ["a"], scopesGranted: ["a"], consentPageDigest: "d", consentText: "t" });
    return { store, base, grant };
  }

  it("a second revocation of one grant inserts nothing: created:false, the first row's id", async () => {
    const { store, base, grant } = await granted();
    const first = await store.createConsentReceipt({ ...base, kind: "revocation", createdAt: "2026-11-08T01:00:00.000Z", revokesReceiptId: grant.id });
    const second = await store.createConsentReceipt({ ...base, kind: "revocation", createdAt: "2026-11-08T02:00:00.000Z", revokesReceiptId: grant.id });
    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.receipt.id).toBe(first.receipt.id);
    expect(second.receipt.createdAt).toBe("2026-11-08T01:00:00.000Z");
    expect((await store.listConsentReceipts(base.accountId)).filter((r) => r.kind === "revocation")).toHaveLength(1);
  });

  it("the read-back returns the revocation of this grant, not another's or the grant", async () => {
    const { store, base, grant } = await granted();
    const other = (await store.createConsentReceipt({ ...base, kind: "grant", createdAt: "2026-11-08T00:30:00.000Z", scopesAsked: [], scopesGranted: [], consentPageDigest: "d2", consentText: "t2" })).receipt;
    const otherRevocation = await store.createConsentReceipt({ ...base, kind: "revocation", createdAt: "2026-11-08T01:00:00.000Z", revokesReceiptId: other.id });
    const first = await store.createConsentReceipt({ ...base, kind: "revocation", createdAt: "2026-11-08T01:10:00.000Z", revokesReceiptId: grant.id });
    const second = await store.createConsentReceipt({ ...base, kind: "revocation", createdAt: "2026-11-08T02:00:00.000Z", revokesReceiptId: grant.id });
    expect(second.receipt.id).toBe(first.receipt.id);
    expect(second.receipt.id).not.toBe(otherRevocation.receipt.id);
    expect(second.receipt).toMatchObject({ kind: "revocation", revokesReceiptId: grant.id });
  });
});

describe("InMemoryStore.createConsentReceipt", () => {
  it("writes one revocation per grant: the second names the first and is not created", async () => {
    const store = new InMemoryStore();
    const base = { accountId: "a", appSlug: "streampixels" as const, provider: "joystick" as const, createdAt: "2026-11-08T00:00:00.000Z" };
    const { receipt: grant } = await store.createConsentReceipt({ ...base, kind: "grant", scopesAsked: [], scopesGranted: [], consentPageDigest: "d", consentText: "t" });
    const first = await store.createConsentReceipt({ ...base, kind: "revocation", revokesReceiptId: grant.id });
    const second = await store.createConsentReceipt({ ...base, createdAt: "2026-11-09T00:00:00.000Z", kind: "revocation", revokesReceiptId: grant.id });
    expect([first.created, second.created]).toEqual([true, false]);
    expect(second.receipt).toEqual(first.receipt);
    expect(await store.listConsentReceipts("a")).toHaveLength(2);
  });
});

describe("InMemoryStore.claimOAuthStateUse", () => {
  const use = {
    jti: "state-1",
    phase: "launch" as const,
    appSlug: "repixelizer" as const,
    usedAt: "2026-04-26T12:00:00.000Z",
    expiresAt: "2026-04-26T12:10:00.000Z",
  };

  it("is true once per (jti, phase)", async () => {
    const store = new InMemoryStore();
    expect(await store.claimOAuthStateUse(use)).toBe(true);
    expect(await store.claimOAuthStateUse(use)).toBe(false);
    expect(await store.claimOAuthStateUse({ ...use, phase: "callback" })).toBe(true);
    expect(await store.claimOAuthStateUse({ ...use, phase: "callback" })).toBe(false);
    expect(await store.claimOAuthStateUse({ ...use, jti: "state-2" })).toBe(true);
  });

  it("drops a record only once its state's exp + skew + margin has passed", async () => {
    const store = new InMemoryStore();
    await store.claimOAuthStateUse(use);
    const expMs = Date.parse(use.expiresAt);
    const at = (ms: number) => new Date(ms).toISOString();
    // Inside the skew past expiry the state still verifies, and the margin keeps the record beyond that.
    await store.claimOAuthStateUse({ ...use, jti: "state-2", usedAt: at(expMs + OAUTH_STATE_SKEW_MS) });
    expect(await store.claimOAuthStateUse(use)).toBe(false);
    const boundary = expMs + OAUTH_STATE_SKEW_MS + OAUTH_STATE_PRUNE_MARGIN_MS;
    await store.claimOAuthStateUse({ ...use, jti: "state-3", usedAt: at(boundary - 1) });
    expect(await store.claimOAuthStateUse(use)).toBe(false);
    // At exactly exp + skew + margin the record is prunable (the rule is <=).
    await store.claimOAuthStateUse({ ...use, jti: "state-4", usedAt: at(boundary) });
    expect(await store.claimOAuthStateUse(use)).toBe(true);
  });

  it("removes at most one batch of prunable records per successful claim", async () => {
    const store = new InMemoryStore();
    const expMs = Date.parse(use.expiresAt);
    const total = OAUTH_STATE_PRUNE_BATCH * 2 + 7;
    for (let i = 0; i < total; i += 1) await store.claimOAuthStateUse({ ...use, jti: `old-${i}` });
    const size = () => (store as unknown as { oauthStateUses: Map<string, string> }).oauthStateUses.size;
    expect(size()).toBe(total);
    const later = new Date(expMs + OAUTH_STATE_SKEW_MS + OAUTH_STATE_PRUNE_MARGIN_MS).toISOString();
    await store.claimOAuthStateUse({ ...use, jti: "fresh-1", usedAt: later, expiresAt: later });
    expect(size()).toBe(total + 1 - OAUTH_STATE_PRUNE_BATCH);
    // A refused (replayed) claim prunes nothing, as on Postgres where the delete follows a new row.
    await store.claimOAuthStateUse({ ...use, jti: "fresh-1", usedAt: later, expiresAt: later });
    expect(size()).toBe(total + 1 - OAUTH_STATE_PRUNE_BATCH);
  });
});

describe("PostgresStore.claimOAuthStateUse retention", () => {
  const use = {
    jti: "state-1",
    phase: "launch" as const,
    appSlug: "repixelizer" as const,
    usedAt: "2026-04-26T12:00:00.000Z",
    expiresAt: "2026-04-26T12:10:00.000Z",
  };

  function doublePool(prune: "ok" | "throws", inserted = 1) {
    const calls: Array<{ sql: string; params: unknown[] }> = [];
    const pool = {
      query: async (sql: string, params: unknown[]) => {
        calls.push({ sql, params });
        if (calls.length === 1) return { rowCount: inserted, rows: [] };
        if (prune === "throws") throw Object.assign(new Error("permission denied for table oauth_state_uses"), { code: "42501" });
        return { rowCount: 0, rows: [] };
      },
    };
    return { calls, store: new PostgresStore(pool as unknown as Pool) };
  }

  it("runs one bounded delete after a new row, at the shared cutoff and batch", async () => {
    const { calls, store } = doublePool("ok");
    expect(await store.claimOAuthStateUse(use)).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[1]!.sql).toMatch(/DELETE FROM oauth_state_uses/);
    expect(calls[1]!.params).toEqual([
      new Date(Date.parse(use.usedAt) - OAUTH_STATE_SKEW_MS - OAUTH_STATE_PRUNE_MARGIN_MS),
      OAUTH_STATE_PRUNE_BATCH,
    ]);
  });

  it("prunes nothing when the claim is a replay", async () => {
    const { calls, store } = doublePool("ok", 0);
    expect(await store.claimOAuthStateUse(use)).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it("a failing prune does not change the claim's result", async () => {
    const { calls, store } = doublePool("throws");
    expect(await store.claimOAuthStateUse(use)).toBe(true);
    expect(calls).toHaveLength(2);
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
      "pending_links",
      "auth_completions",
      "oauth_state_uses",
      "capability_grants",
      "entitlement_snapshots",
      "consent_receipts",
      "identity_moves",
      "audit_events",
    ]);
    expect(REQUIRED_COLUMNS).toHaveLength(121);
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
    expect(REQUIRED_KEYS).toHaveLength(19);
    expect(REQUIRED_KEYS).toEqual(
      expect.arrayContaining([
        { table: "linked_identities", columns: "provider,provider_user_id", predicate: "" },
        { table: "private_command_receipts", columns: "app_slug,idempotency_key", predicate: "" },
        { table: "oauth_state_uses", columns: "jti,phase", predicate: "" },
        { table: "consent_receipts", columns: "revokes_receipt_id", predicate: "revokes_receipt_id IS NOT NULL" },
        { table: "consent_receipts", columns: "account_id,id", predicate: "" },
        { table: "identity_moves", columns: "reverses_move_id", predicate: "reverses_move_id IS NOT NULL" },
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
    expect(predicateConditions('(("odd AND (name" IS NULL) AND b)')).toEqual(['"odd AND (name" IS NULL', "b"]);
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
  const linked = await s.upsertLinkedIdentity(identity);
  await s.updateLinkedIdentityCredential(linked.id, async () => ({ kind: "keep" }));
  await s.upsertLinkedIdentity({ ...identity, username: "again" });
  const spare = await s.upsertLinkedIdentity({ ...identity, providerUserId: "u-spare" });
  expect((await s.unlinkLinkedIdentity(account.id, spare.id)).kind).toBe("unlinked");
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
  const found = await s.createAuthCompletion(completion);
  await s.findAuthCompletion("ghostlight", found.code);
  const pending = await s.createPendingLink({
    appSlug: "ghostlight",
    accountId: account.id,
    provider: "discord",
    providerUserId: "u2",
    identity: { ...identity, providerUserId: "u2" },
    returnTo: "https://x.test/",
    createdAt: now,
    expiresAt: later,
  });
  await s.consumePendingLink("ghostlight", pending.id, account.id, now);
  const snapshot = { accountId: account.id, provider: "discord" as const, scope: "ghostlight:probe", evaluatedAt: now, isAllowed: true, reasonCode: "ok", rawSummaryJson: {} };
  await s.upsertEntitlementSnapshot(snapshot);
  await s.upsertEntitlementSnapshot({ ...snapshot, isAllowed: false });
  const stateUse = { jti: randomUUID(), phase: "launch" as const, appSlug: "ghostlight" as const, usedAt: now, expiresAt: later };
  expect(await s.claimOAuthStateUse(stateUse)).toBe(true);
  expect(await s.claimOAuthStateUse(stateUse)).toBe(false);
  expect(await s.claimOAuthStateUse({ ...stateUse, phase: "callback" })).toBe(true);
  // The prune is swallowed when the role may not run it, so the exercise proves it ran: a long-expired
  // record is gone after the next new claim. A missing prune stands for the privilege refusal behind it.
  const stale = { ...stateUse, jti: randomUUID(), usedAt: "2000-01-01T00:00:00.000Z", expiresAt: "2000-01-01T00:10:00.000Z" };
  expect(await s.claimOAuthStateUse(stale)).toBe(true);
  expect(await s.claimOAuthStateUse({ ...stateUse, jti: randomUUID() })).toBe(true);
  const retained = await s.claimOAuthStateUse(stale);
  if (!retained) {
    throw Object.assign(new Error("oauth_state_uses was not pruned"), { code: "42501" });
  }
  const { receipt: grant } = await s.createConsentReceipt({ kind: "grant", accountId: account.id, appSlug: "streampixels", provider: "joystick", createdAt: now, scopesAsked: ["a", "b"], scopesGranted: ["a"], consentPageDigest: "d", consentText: "t" });
  const revocation = { kind: "revocation" as const, accountId: account.id, appSlug: "streampixels" as const, provider: "joystick" as const, createdAt: later, revokesReceiptId: grant.id };
  const first = await s.createConsentReceipt(revocation);
  // The second revocation of one grant hits ON CONFLICT DO NOTHING and reads the first back.
  const second = await s.createConsentReceipt(revocation);
  expect(first.created).toBe(true);
  expect(second.created).toBe(false);
  expect(second.receipt.id).toBe(first.receipt.id);
  expect((await s.listConsentReceipts(account.id)).map((r) => r.kind)).toEqual(["grant", "revocation"]);
  await s.createAuditEvent({ eventType: "probe", eventPayloadJson: {}, createdAt: now });
  const target = await s.createAccount({ createdAt: now, lastSeenAt: now });
  await s.upsertLinkedIdentity({ ...identity, accountId: target.id, provider: "patreon", providerUserId: "u-target" });
  const moveId = `move-${randomUUID()}`;
  expect((await s.moveIdentities({ moveId, appSlug: "bifrost", fromAccountId: account.id, toAccountId: target.id, identityIds: "all", covers: "account", proofSessions: [], proof: { from: [], to: null }, at: now })).kind).toBe("moved");
  expect((await s.findIdentityMove(moveId))?.id).toBe(moveId);
  expect(await s.resolveAccount(account.id)).toBe(target.id);
  return called;
}

/**
 * The move contract both stores keep, once. Each case builds its own accounts,
 * so the order of cases proves nothing and a store holding earlier moves is fine.
 */
async function exerciseMoveContract(store: HeimdallStore): Promise<void> {
  const at = "2026-11-14T12:00:00.000Z";
  const later = "2999-01-01T00:00:00.000Z";
  const proofTiers = { from: [{ tier: "strong" as const, method: "bifrost-passkey", identityId: null }], to: { tier: "weak" as const, method: null, identityId: null } };
  const side = async (providers: Array<"discord" | "google" | "patreon">) => {
    const account = await store.createAccount({ createdAt: at, lastSeenAt: at });
    const rows = [];
    for (const provider of providers) {
      rows.push(await store.upsertLinkedIdentity({ accountId: account.id, provider, providerUserId: `${provider}-${randomUUID()}`, accessTokenEncrypted: "A", refreshTokenEncrypted: "R", scopes: [], profileJson: {}, createdAt: at, updatedAt: at }));
    }
    const sessionId = randomUUID();
    await store.createSession({ id: sessionId, accountId: account.id, appSlug: "bifrost", createdAt: at, lastSeenAt: at, expiresAt: later, accessRevision: 1, claimsJson: {} });
    return { account, rows, proofSession: { appSlug: "bifrost" as const, sessionId, accountId: account.id, accessRevision: 1 } };
  };
  const input = (from: Awaited<ReturnType<typeof side>>, to: Awaited<ReturnType<typeof side>>, extra: Record<string, unknown> = {}) => ({
    moveId: `move-${randomUUID()}`,
    appSlug: "bifrost" as const,
    fromAccountId: from.account.id,
    toAccountId: to.account.id,
    identityIds: "all" as const,
    covers: "account" as const,
    proofSessions: [from.proofSession, to.proofSession],
    proof: proofTiers,
    at,
    ...extra,
  });
  const held = async (a: { account: { id: string } }) => (await store.listStoredLinkedIdentitiesForAccount(a.account.id)).map((i) => i.id).sort();

  // Moved: rows, credentials, sessions and the record.
  const a = await side(["discord", "google"]);
  const b = await side(["patreon"]);
  const first = input(a, b);
  const moved = await store.moveIdentities(first);
  expect(moved.kind).toBe("moved");
  expect(await held(a)).toEqual([]);
  expect(await held(b)).toEqual([...a.rows.map((r) => r.id), ...b.rows.map((r) => r.id)].sort());
  for (const row of await store.listStoredLinkedIdentitiesForAccount(b.account.id)) {
    if (a.rows.some((r) => r.id === row.id)) expect([row.accessTokenEncrypted, row.refreshTokenEncrypted]).toEqual([undefined, undefined]);
    else expect(row.accessTokenEncrypted, "the destination's own credential is untouched").toBe("A");
  }
  const record = await store.findIdentityMove(first.moveId);
  expect(record).toMatchObject({ id: first.moveId, fromAccountId: a.account.id, toAccountId: b.account.id, proof: proofTiers, createdAt: at });
  expect(record!.moved.map((m) => m.credentialStripped)).toEqual([true, true]);
  expect((await store.findSession("bifrost", a.proofSession.sessionId))!.accessRevision).toBe(2);
  expect((await store.findSession("bifrost", b.proofSession.sessionId))!.accessRevision).toBe(1);
  expect(await store.resolveAccount(a.account.id)).toBe(b.account.id);
  expect(await store.resolveAccount(b.account.id)).toBe(b.account.id);

  // Replay answers from the row, even though the proof session is gone; a different pair is a conflict.
  expect(await store.moveIdentities(first)).toEqual({ kind: "replayed", move: record });
  const c = await side(["discord"]);
  expect(await store.moveIdentities({ ...first, toAccountId: c.account.id })).toEqual({ kind: "move_id_conflict" });
  expect(await store.moveIdentities({ ...first, reversesMoveId: "x" })).toEqual({ kind: "move_id_conflict" });

  // Into or out of an alias.
  expect((await store.moveIdentities(input(a, c, { proofSessions: [c.proofSession] }))).kind).toBe("already_moved");
  expect((await store.moveIdentities(input(c, a, { proofSessions: [c.proofSession] }))).kind).toBe("already_moved");

  // A proof session that was revoked, or has moved on a revision, has lapsed.
  const d = await side(["google"]);
  const e = await side(["patreon"]);
  await store.revokeSession("bifrost", e.proofSession.sessionId, e.account.id, 1, at);
  expect((await store.moveIdentities(input(d, e))).kind).toBe("proof_lapsed");
  expect(await held(d)).toHaveLength(1);

  // Coverage and conflict.
  const f = await side(["discord", "google"]);
  const g = await side(["patreon"]);
  expect((await store.moveIdentities(input(f, g, { covers: [f.rows[0]!.id] }))).kind).toBe("identity_not_proved");
  expect((await store.moveIdentities(input(f, g, { identityIds: ["nope"] }))).kind).toBe("identity_not_found");
  const h = await side(["discord"]);
  expect(await store.moveIdentities(input(f, h))).toEqual({ kind: "provider_conflict", provider: "discord" });
  expect(await held(f)).toHaveLength(2);
  const onlyDiscord = await store.moveIdentities(input(f, g, { identityIds: [f.rows[0]!.id], covers: [f.rows[0]!.id] }));
  expect(onlyDiscord.kind).toBe("moved");
  expect(await held(f)).toEqual([f.rows[1]!.id]);

  // Reversal: moves exactly what the forward carried, once, and a reversal is not itself reversible.
  const forward = (moved as { move: { id: string } }).move;
  const back = input(b, a, { reversesMoveId: forward.id, proofSessions: [], identityIds: a.rows.map((r) => r.id), covers: a.rows.map((r) => r.id) });
  const reversed = await store.moveIdentities(back);
  expect(reversed.kind).toBe("moved");
  expect(await held(a)).toEqual(a.rows.map((r) => r.id).sort());
  expect(await held(b)).toEqual(b.rows.map((r) => r.id));
  expect(await store.resolveAccount(a.account.id)).toBe(a.account.id);
  expect((await store.moveIdentities({ ...back, moveId: `move-${randomUUID()}` })).kind).toBe("not_reversible");
  expect((await store.moveIdentities(input(a, b, { reversesMoveId: back.moveId, proofSessions: [], identityIds: "all" }))).kind).toBe("not_reversible");
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

  it("startup refuses a role that lacks DELETE on linked_identities", async () => {
    expect(STORE_TABLE_PRIVILEGES.linked_identities).toContain("DELETE");
    const { name, owner } = await appliedDatabase();
    await grant(owner, { ...STORE_TABLE_PRIVILEGES, linked_identities: ["SELECT", "INSERT", "UPDATE"] });
    expect(await start(urlFor(name, role, rolePassword), false)).toBe(refusal("SCHEMA_PRIVILEGES"));
  });

  it("startup refuses a role that lacks INSERT or SELECT on identity_moves", async () => {
    expect(STORE_TABLE_PRIVILEGES.identity_moves).toEqual(["SELECT", "INSERT"]);
    for (const [kept, dropped] of [[["SELECT"], "INSERT"], [["INSERT"], "SELECT"]] as const) {
      const { name, owner } = await appliedDatabase();
      await grant(owner, { ...STORE_TABLE_PRIVILEGES, identity_moves: kept });
      expect(await start(urlFor(name, role, rolePassword), false), `without ${dropped}`).toBe(refusal("SCHEMA_PRIVILEGES"));
    }
  });

  it("on real Postgres: the move contract holds", async () => {
    const { owner } = await appliedDatabase();
    await exerciseMoveContract(new PostgresStore(owner));
  });

  describe("concurrent moves", () => {
    const at = "2026-11-14T12:00:00.000Z";
    async function pair(store: PostgresStore) {
      const make = async (provider: "discord" | "patreon") => {
        const account = await store.createAccount({ createdAt: at, lastSeenAt: at });
        await store.upsertLinkedIdentity({ accountId: account.id, provider, providerUserId: `${provider}-${randomUUID()}`, scopes: [], profileJson: {}, createdAt: at, updatedAt: at });
        const sessionId = randomUUID();
        await store.createSession({ id: sessionId, accountId: account.id, appSlug: "bifrost", createdAt: at, lastSeenAt: at, expiresAt: "2999-01-01T00:00:00.000Z", accessRevision: 1, claimsJson: {} });
        return { id: account.id, proof: { appSlug: "bifrost" as const, sessionId, accountId: account.id, accessRevision: 1 } };
      };
      return { x: await make("discord"), y: await make("patreon") };
    }
    const request = (from: { id: string; proof: object }, to: { id: string; proof: object }, moveId: string) => ({
      moveId,
      appSlug: "bifrost" as const,
      fromAccountId: from.id,
      toAccountId: to.id,
      identityIds: "all" as const,
      covers: "account" as const,
      proofSessions: [from.proof, to.proof] as never,
      proof: { from: [], to: null },
      at,
    });

    it("opposite moves A->B and B->A over two pools leave one applied and never deadlock, ten rounds", async () => {
      const { name, owner } = await appliedDatabase();
      const storeA = new PostgresStore(owner);
      const other = fixturePool(urlFor(name));
      cleanup.push(async () => {
        await other.end();
      });
      const storeB = new PostgresStore(other);
      for (let round = 0; round < 10; round += 1) {
        const { x, y } = await pair(storeA);
        const results = await Promise.all([
          storeA.moveIdentities(request(x, y, `move-${randomUUID()}`)),
          storeB.moveIdentities(request(y, x, `move-${randomUUID()}`)),
        ]);
        const kinds = results.map((r) => r.kind).sort();
        expect(kinds[0], `round ${round}: ${kinds}`).toBe("moved");
        expect(["already_moved", "proof_lapsed"], `round ${round}: ${kinds}`).toContain(kinds[1]);
        const held = (await storeA.listStoredLinkedIdentitiesForAccount(x.id)).length + (await storeA.listStoredLinkedIdentitiesForAccount(y.id)).length;
        expect(held, "no identity is lost or duplicated").toBe(2);
      }
    });

    it("two concurrent identical moveIds: one moved, one replayed", async () => {
      const { name, owner } = await appliedDatabase();
      const storeA = new PostgresStore(owner);
      const other = fixturePool(urlFor(name));
      cleanup.push(async () => {
        await other.end();
      });
      const storeB = new PostgresStore(other);
      for (let round = 0; round < 5; round += 1) {
        const { x, y } = await pair(storeA);
        const body = request(x, y, `move-${randomUUID()}`);
        const results = await Promise.all([storeA.moveIdentities(body), storeB.moveIdentities(body)]);
        expect(results.map((r) => r.kind).sort(), `round ${round}`).toEqual(["moved", "replayed"]);
      }
    });
  });

  it("on real Postgres: an upsert never moves an identity, and concurrent unlinks of the last two leave one", async () => {
    const { name, owner } = await appliedDatabase();
    const clientA = new PostgresStore(owner);
    const at = "2026-11-13T12:00:00.000Z";
    const a = await clientA.createAccount({ createdAt: at, lastSeenAt: at });
    const b = await clientA.createAccount({ createdAt: at, lastSeenAt: at });
    const base = { provider: "discord" as const, scopes: [], profileJson: {}, createdAt: at, updatedAt: at };
    const held = await clientA.upsertLinkedIdentity({ ...base, accountId: a.id, providerUserId: "u1", username: "original" });
    await expect(clientA.upsertLinkedIdentity({ ...base, accountId: b.id, providerUserId: "u1", username: "thief" })).rejects.toBeInstanceOf(IdentityHeldElsewhereError);
    expect(await clientA.findStoredLinkedIdentity("discord", "u1")).toEqual(held);

    await clientA.upsertLinkedIdentity({ ...base, accountId: a.id, providerUserId: "u2" });
    // Two separate pools, as two Heimdall processes would be, race for the last two.
    const other = fixturePool(urlFor(name));
    cleanup.push(async () => {
      await other.end();
    });
    const storeB = new PostgresStore(other);
    for (let round = 0; round < 10; round += 1) {
      const [first, second] = await clientA.listStoredLinkedIdentitiesForAccount(a.id);
      expect(first && second, `round ${round} starts with two`).toBeTruthy();
      const results = await Promise.all([clientA.unlinkLinkedIdentity(a.id, first!.id), storeB.unlinkLinkedIdentity(a.id, second!.id)]);
      expect(results.map((r) => r.kind).sort(), `round ${round}`).toEqual(["last_identity", "unlinked"]);
      expect(await clientA.listStoredLinkedIdentitiesForAccount(a.id)).toHaveLength(1);
      await clientA.upsertLinkedIdentity({ ...base, accountId: a.id, providerUserId: `u-next-${round}` });
    }
  });

  describe("oauth_state_uses retention", () => {
    const expMs = Date.parse("2026-04-26T12:10:00.000Z");
    const boundary = expMs + OAUTH_STATE_SKEW_MS + OAUTH_STATE_PRUNE_MARGIN_MS;
    const use = (jti: string, usedAtMs: number, expiresAtMs = expMs) => ({
      jti,
      phase: "launch" as const,
      appSlug: "repixelizer" as const,
      usedAt: new Date(usedAtMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
    });
    const count = async (owner: Pool) => Number((await owner.query("SELECT count(*) AS n FROM oauth_state_uses")).rows[0].n);
    const seed = async (owner: Pool, jti: string) => {
      await owner.query(
        "INSERT INTO oauth_state_uses (jti, phase, app_slug, used_at, expires_at) VALUES ($1, 'launch', 'repixelizer', $2, $2)",
        [jti, new Date(expMs)]
      );
    };

    it.each([
      [boundary - 1, true],
      [boundary, false],
      [boundary + 1, false],
    ])("a claim at exp + skew + margin %i ms keeps the record: %s", async (usedAtMs, kept) => {
      const { owner } = await appliedDatabase();
      const store = new PostgresStore(owner);
      expect(await store.claimOAuthStateUse(use("old", expMs - 1000))).toBe(true);
      expect(await store.claimOAuthStateUse(use("other", usedAtMs, usedAtMs + 600_000))).toBe(true);
      expect(await store.claimOAuthStateUse(use("old", usedAtMs))).toBe(!kept);
    });

    it("removes at most one batch per claim and never the live record", async () => {
      const { owner } = await appliedDatabase();
      const store = new PostgresStore(owner);
      const total = OAUTH_STATE_PRUNE_BATCH * 2 + 7;
      for (let i = 0; i < total; i += 1) await seed(owner, `old-${i}`);
      const fresh = use("fresh", boundary + 5, boundary + 600_000);
      expect(await store.claimOAuthStateUse(fresh)).toBe(true);
      expect(await count(owner)).toBe(total + 1 - OAUTH_STATE_PRUNE_BATCH);
      expect(await store.claimOAuthStateUse(fresh)).toBe(false);
      expect(await count(owner)).toBe(total + 1 - OAUTH_STATE_PRUNE_BATCH);
    });

    it("keeps its expires_at index", async () => {
      const { owner } = await appliedDatabase();
      const found = await owner.query("SELECT 1 FROM pg_indexes WHERE indexname = 'oauth_state_uses_expires_at_idx'");
      expect(found.rowCount).toBe(1);
    });

    it("the step_up_assert nonce claim is single-use under the store's own role, and independent of the other phases", async () => {
      const { name, owner } = await appliedDatabase();
      await grant(owner, STORE_TABLE_PRIVILEGES);
      const pool = fixturePool(urlFor(name, role, rolePassword));
      cleanup.push(async () => {
        await pool.end();
      });
      const store = new PostgresStore(pool);
      const claim = { ...use("digest", boundary, boundary + 600_000), phase: "step_up_assert" as const, appSlug: "bifrost" };
      expect(await store.claimOAuthStateUse(claim)).toBe(true);
      expect(await store.claimOAuthStateUse(claim)).toBe(false);
      expect(await store.claimOAuthStateUse({ ...claim, phase: "callback" })).toBe(true);
    });

    it("a role without DELETE still claims, and leaves the old records", async () => {
      const { name, owner } = await appliedDatabase();
      await grant(owner, { ...STORE_TABLE_PRIVILEGES, oauth_state_uses: ["SELECT", "INSERT"] });
      await seed(owner, "old");
      const pool = fixturePool(urlFor(name, role, rolePassword));
      cleanup.push(async () => {
        await pool.end();
      });
      const store = new PostgresStore(pool);
      expect(await store.claimOAuthStateUse(use("fresh", boundary + 5, boundary + 600_000))).toBe(true);
      expect(await count(owner)).toBe(2);
    });
  });

  it("refuses to apply the schema as a role that may not, and closes the store", async () => {
    const { name, owner } = await appliedDatabase();
    await grant(owner, STORE_TABLE_PRIVILEGES);

    expect(await start(urlFor(name, role, rolePassword), true)).toBe(refusal("42501"));
  });

  it("prints each declared predicate exactly as Postgres prints the applied index's", async () => {
    const { owner } = await appliedDatabase();
    const printed = await printedDeclaredPredicates(owner, HEIMDALL_SCHEMA_REQUIREMENTS);
    const appliedByIndex = {
      auth_completions_attempt_unconsumed_unique_idx: "auth_completions",
      consent_receipts_revokes_unique_idx: "consent_receipts",
      identity_moves_reverses_unique_idx: "identity_moves",
    };
    const partialKeys = REQUIRED_KEYS.flatMap((key, index) => (key.predicate === "" ? [] : [{ key, index }]));
    expect(partialKeys.map(({ key }) => key.table).sort()).toEqual(Object.values(appliedByIndex).sort());
    for (const [indexName, table] of Object.entries(appliedByIndex)) {
      const applied = await owner.query<{ predicate: string }>(
        "SELECT pg_get_expr(indpred, indrelid) AS predicate FROM pg_index WHERE indexrelid = $1::regclass",
        [indexName]
      );
      const { index } = partialKeys.find(({ key }) => key.table === table)!;
      expect(printed[index], indexName).toBe(applied.rows[0]!.predicate);
    }
    expect(printed.filter((predicate) => predicate !== "")).toHaveLength(partialKeys.length);
  });

  it("refuses to boot with consent_receipts missing when the schema is not applied on startup", async () => {
    const { name, owner } = await appliedDatabase();
    await owner.query("DROP TABLE consent_receipts");

    expect(await start(urlFor(name), false)).toBe(refusal("SCHEMA_MISSING"));
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
      for (const privilege of wanted) {
        // DELETE removes rows and cannot be granted per column.
        await owner.query(privilege === "DELETE" ? `GRANT DELETE ON ${table} TO ${role}` : `GRANT ${privilege} (${columns}) ON ${table} TO ${role}`);
      }
    }

    expect(await start(urlFor(name, role, rolePassword), false)).toBe("started");
    const pool = fixturePool(urlFor(name, role, rolePassword));
    cleanup.push(async () => {
      await pool.end();
    });
    await exerciseStore(new PostgresStore(pool));
  });

  it("refuses a privilege missing on one column of another table", async () => {
    const { name, owner } = await appliedDatabase();
    await grant(owner, { ...STORE_TABLE_PRIVILEGES, auth_completions: [] });
    const columns = REQUIRED_COLUMNS.filter((column) => column.table === "auth_completions" && column.column !== "attempt_id")
      .map((column) => column.column)
      .join(", ");
    for (const privilege of STORE_TABLE_PRIVILEGES.auth_completions!) {
      await owner.query(`GRANT ${privilege} (${columns}) ON auth_completions TO ${role}`);
    }

    expect(await start(urlFor(name, role, rolePassword), false)).toBe(refusal("SCHEMA_PRIVILEGES"));
  });

  it("names the TEMPORARY privilege when the role may not create temporary tables", async () => {
    const { name, owner } = await appliedDatabase();
    await grant(owner, STORE_TABLE_PRIVILEGES);
    await owner.query(`REVOKE TEMPORARY ON DATABASE ${name} FROM PUBLIC`);

    expect(await start(urlFor(name, role, rolePassword), false)).toBe(
      "Postgres storage could not be prepared (SCHEMA_TEMP_PRIVILEGE); grant the database role TEMPORARY on its database."
    );
  });

  // The schema's own predicate splits into the same conditions raw or
  // printed, so only a predicate whose printed form differs (a literal gains
  // its cast) shows that the check compares Postgres's printing.
  it("matches a declared predicate that Postgres prints differently from how it is written", async () => {
    const { owner } = await appliedDatabase();
    await owner.query("CREATE TABLE predicate_probe (id INTEGER NOT NULL, state TEXT, attempts INTEGER)");
    await owner.query("CREATE UNIQUE INDEX predicate_probe_live ON predicate_probe (id) WHERE state = 'live' AND attempts > 0");
    const requirements = {
      tables: ["predicate_probe"],
      columns: [
        { table: "predicate_probe", column: "id", type: "INTEGER", nullable: false },
        { table: "predicate_probe", column: "state", type: "TEXT", nullable: true },
        { table: "predicate_probe", column: "attempts", type: "INTEGER", nullable: true },
      ],
      keys: [{ table: "predicate_probe", columns: "id", predicate: "state = 'live' AND attempts > 0" }],
      privileges: {},
    };

    expect((await printedDeclaredPredicates(owner, requirements))[0]).toBe("((state = 'live'::text) AND (attempts > 0))");
    await expect(checkSchemaRequirements(owner, requirements)).resolves.toBeUndefined();
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
    ["a key's first column compared under a case-insensitive collation",
      ["CREATE COLLATION heimdall_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false)",
        "ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key",
        "CREATE UNIQUE INDEX li_ci_first ON linked_identities(provider COLLATE heimdall_ci, provider_user_id)"]],
    // Soul pass 7: the key index compares under "C", but the column itself is
    // case-insensitive, so the store's own lookups by provider_user_id match
    // other users' ids.
    ["a column declared under a case-insensitive collation, its key index under C",
      ["CREATE COLLATION heimdall_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false)",
        "ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key",
        "ALTER TABLE linked_identities ALTER COLUMN provider_user_id TYPE text COLLATE heimdall_ci",
        'CREATE UNIQUE INDEX li_c ON linked_identities(provider, provider_user_id COLLATE "C")']],
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
    ["NOT NULL added to a nullable column of another table",
      ["UPDATE linked_identities SET username = ''", "ALTER TABLE linked_identities ALTER COLUMN username SET NOT NULL"]],
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
    // Only a key's own columns decide which rows collide; an INCLUDEd column's
    // collation does not, whatever it is.
    ["a key index that INCLUDEs an undeclared case-insensitive column",
      ["CREATE COLLATION heimdall_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false)",
        "ALTER TABLE linked_identities ADD COLUMN operator_note text COLLATE heimdall_ci",
        "ALTER TABLE linked_identities DROP CONSTRAINT linked_identities_provider_provider_user_id_key",
        "CREATE UNIQUE INDEX li_note ON linked_identities(provider, provider_user_id) INCLUDE (operator_note)"]],
  ])("accepts %s", async (_change, steps) => {
    const { name, owner } = await appliedDatabase();
    for (const step of steps) await owner.query(step);

    expect(await start(urlFor(name), false)).toBe("started");
  });
});
