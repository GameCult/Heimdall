import { describe, expect, it } from "vitest";
import { newDb } from "pg-mem";
import { createPostgresStore, PostgresStore } from "../src/store/postgres.js";
import { REQUIRED_COLUMNS, REQUIRED_RELATIONS } from "../src/store/schema.js";

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
  it("requires every table and index the schema creates and every column it adds", () => {
    expect(REQUIRED_RELATIONS).toEqual(
      expect.arrayContaining(["accounts", "audit_events", "auth_completions_attempt_unconsumed_unique_idx", "audit_events_lookup_idx"])
    );
    expect(REQUIRED_RELATIONS).toHaveLength(17);
    expect(REQUIRED_COLUMNS).toEqual([{ table: "auth_completions", column: "attempt_id" }]);
  });

  function storeAnswering(missing: string[]) {
    const queries: unknown[][] = [];
    const store = new PostgresStore({
      query: (async (_text: string, values: unknown[]) => {
        queries.push(values);
        return { rows: missing.map((name) => ({ missing: name })) };
      }) as never,
      end: async () => undefined,
    });
    return { store, queries };
  }

  it("refuses with SCHEMA_MISSING when anything is missing", async () => {
    const { store, queries } = storeAnswering(["auth_completions.attempt_id"]);
    await expect(store.checkSchema()).rejects.toMatchObject({ code: "SCHEMA_MISSING" });
    expect(queries).toEqual([[REQUIRED_RELATIONS, ["auth_completions"], ["attempt_id"]]]);
  });

  it("passes when nothing is missing", async () => {
    await expect(storeAnswering([]).store.checkSchema()).resolves.toBeUndefined();
  });
});
