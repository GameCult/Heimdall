import { randomUUID } from "node:crypto";
import { Pool, type PoolClient, type QueryResultRow } from "pg";
import { type AppSlug, type HeimdallAuthAttemptStatus, type LinkedIdentityInput, type Provider } from "../contracts.js";
import { CREATE_SCHEMA_SQL, REQUIRED_COLUMNS, REQUIRED_KEYS, REQUIRED_TABLES } from "./schema.js";
import {
  type CreateAccountInput,
  type CreateAuthAttemptInput,
  type CreateAuthCompletionInput,
  type CreateAuditEventInput,
  type CreateCapabilityGrantInput,
  type CreateEntitlementSnapshotInput,
  type CreateSessionInput,
  type CreatePrivateCommandReceiptInput,
  type HeimdallStore,
  type StoredAccount,
  type StoredAuthAttempt,
  type StoredAuthCompletion,
  type StoredCapabilityGrant,
  type StoredLinkedIdentity,
  type StoredSession,
  type StoredPrivateCommandReceipt,
  type UpsertLinkedIdentityInput,
} from "./types.js";

interface AccountRow extends QueryResultRow {
  id: string;
  created_at: string;
  last_seen_at: string;
  display_name: string | null;
  primary_email: string | null;
}

interface LinkedIdentityRow extends QueryResultRow {
  id: string;
  account_id: string;
  provider: Provider;
  provider_user_id: string;
  username: string | null;
  display_name: string | null;
  primary_email: string | null;
  access_token_encrypted: string | null;
  refresh_token_encrypted: string | null;
  token_expires_at: string | null;
  scopes: string;
  profile_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface GrantRow extends QueryResultRow {
  id: string;
  account_id: string;
  scope_type: "global" | "app";
  scope_id: AppSlug | null;
  capability: string;
  source: string;
  status: "active" | "revoked";
  expires_at: string | null;
  note: string | null;
  created_at: string;
  updated_at: string;
}

interface SessionRow extends QueryResultRow {
  id: string;
  account_id: string;
  app_slug: AppSlug;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  access_revision: number;
  claims_json: Record<string, unknown>;
}

interface AuthCompletionRow extends QueryResultRow {
  code: string;
  attempt_id: string | null;
  app_slug: AppSlug;
  provider: Provider;
  mode: "sign_in" | "link" | "connect";
  account_id: string;
  session_id: string;
  return_to: string;
  payload_json: Record<string, unknown>;
  created_at: string | Date;
  expires_at: string | Date;
  consumed_at: string | Date | null;
}

interface AuthAttemptRow extends QueryResultRow {
  handle: string;
  app_slug: AppSlug;
  provider: Provider;
  mode: "sign_in" | "link" | "connect";
  return_to: string;
  status: HeimdallAuthAttemptStatus;
  created_at: string | Date;
  expires_at: string | Date;
  completed_at: string | Date | null;
  consumed_at: string | Date | null;
  denial_code: string | null;
}

interface PrivateCommandReceiptRow extends QueryResultRow {
  app_slug: AppSlug;
  idempotency_key: string;
  request_fingerprint: string;
  status: string;
  content_schema: string;
  envelope_base64: string;
  created_at: string | Date;
  expires_at: string | Date;
}

function expectRow<T>(row: T | undefined, label: string): T {
  if (!row) {
    throw new Error(`${label} query returned no rows.`);
  }

  return row;
}

function nullable<T>(value: T | undefined): T | null {
  return value ?? null;
}

function normalizeTimestamp(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : value;
}

function parseScopes(value: string): string[] {
  return value.split(" ").map((item) => item.trim()).filter(Boolean);
}

function mapAccountRow(row: AccountRow): StoredAccount {
  const account: StoredAccount = {
    id: row.id,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
  };

  if (row.display_name) {
    account.displayName = row.display_name;
  }

  if (row.primary_email) {
    account.primaryEmail = row.primary_email;
  }

  return account;
}

function mapLinkedIdentityRow(row: LinkedIdentityRow): StoredLinkedIdentity {
  const identity: StoredLinkedIdentity = {
    id: row.id,
    accountId: row.account_id,
    provider: row.provider,
    providerUserId: row.provider_user_id,
    scopes: parseScopes(row.scopes),
    profileJson: row.profile_json,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };

  if (row.username) {
    identity.username = row.username;
  }

  if (row.display_name) {
    identity.displayName = row.display_name;
  }

  if (row.primary_email) {
    identity.primaryEmail = row.primary_email;
  }

  if (row.access_token_encrypted) {
    identity.accessTokenEncrypted = row.access_token_encrypted;
  }

  if (row.refresh_token_encrypted) {
    identity.refreshTokenEncrypted = row.refresh_token_encrypted;
  }

  if (row.token_expires_at) {
    identity.tokenExpiresAt = row.token_expires_at;
  }

  return identity;
}

function mapGrantRow(row: GrantRow): StoredCapabilityGrant {
  const grant: StoredCapabilityGrant = {
    id: row.id,
    accountId: row.account_id,
    scopeType: row.scope_type,
    capability: row.capability,
    source: row.source,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };

  if (row.scope_id) {
    grant.scopeId = row.scope_id;
  }

  if (row.expires_at) {
    grant.expiresAt = row.expires_at;
  }

  if (row.note) {
    grant.note = row.note;
  }

  return grant;
}

function mapSessionRow(row: SessionRow): StoredSession {
  return {
    id: row.id,
    accountId: row.account_id,
    appSlug: row.app_slug,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
    accessRevision: row.access_revision,
    claimsJson: row.claims_json,
  };
}

function mapAuthCompletionRow(row: AuthCompletionRow): StoredAuthCompletion {
  const completion: StoredAuthCompletion = {
    code: row.code,
    appSlug: row.app_slug,
    provider: row.provider,
    mode: row.mode,
    accountId: row.account_id,
    sessionId: row.session_id,
    returnTo: row.return_to,
    createdAt: normalizeTimestamp(row.created_at),
    expiresAt: normalizeTimestamp(row.expires_at),
    payloadJson: row.payload_json,
  };

  if (row.attempt_id) {
    completion.attemptId = row.attempt_id;
  }

  if (row.consumed_at) {
    completion.consumedAt = normalizeTimestamp(row.consumed_at);
  }

  return completion;
}

function mapPrivateCommandReceiptRow(row: PrivateCommandReceiptRow): StoredPrivateCommandReceipt {
  return {
    appSlug: row.app_slug,
    idempotencyKey: row.idempotency_key,
    requestFingerprint: row.request_fingerprint,
    status: row.status,
    contentSchema: row.content_schema,
    envelopeBase64: row.envelope_base64,
    createdAt: normalizeTimestamp(row.created_at),
    expiresAt: normalizeTimestamp(row.expires_at),
  };
}

function mapAuthAttemptRow(row: AuthAttemptRow): StoredAuthAttempt {
  const attempt: StoredAuthAttempt = {
    handle: row.handle,
    appSlug: row.app_slug,
    provider: row.provider,
    mode: row.mode,
    returnTo: row.return_to,
    status: row.status,
    createdAt: normalizeTimestamp(row.created_at),
    expiresAt: normalizeTimestamp(row.expires_at),
  };
  if (row.completed_at) attempt.completedAt = normalizeTimestamp(row.completed_at);
  if (row.consumed_at) attempt.consumedAt = normalizeTimestamp(row.consumed_at);
  if (row.denial_code) attempt.denialCode = row.denial_code;
  return attempt;
}

/**
 * The AND-ed conditions of a predicate as Postgres prints it, each without a
 * pair of parentheses that encloses all of it. Postgres flattens a chain of
 * ANDs into one list, so `((a) AND (b) AND (c))` yields `a`, `b`, `c`. An OR,
 * or an AND nested under one, stays whole: `((a OR b) AND c)` yields `a OR b`
 * and `c`, and `(a OR (b AND c))` yields itself. Quoted text is never split.
 */
export function predicateConditions(printed: string): string[] {
  const unwrap = (text: string): string => {
    let current = text.trim();
    while (current.startsWith("(") && closingParenthesis(current, 0) === current.length - 1) {
      current = current.slice(1, -1).trim();
    }
    return current;
  };
  const whole = unwrap(printed);
  if (whole === "") return [];
  const parts: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = 0;
  for (let position = 0; position < whole.length; position += 1) {
    const character = whole[position]!;
    if (quote) {
      if (character === quote) quote = undefined;
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
    } else if (depth === 0 && whole.startsWith(" AND ", position)) {
      parts.push(whole.slice(start, position));
      start = position + " AND ".length;
      position = start - 1;
    }
  }
  parts.push(whole.slice(start));
  return parts.map(unwrap);
}

/** The index of the parenthesis closing the one at `open`, outside quoted text, or -1. */
function closingParenthesis(text: string, open: number): number {
  let depth = 0;
  let quote: string | undefined;
  for (let position = open; position < text.length; position += 1) {
    const character = text[position]!;
    if (quote) {
      if (character === quote) quote = undefined;
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) return position;
    }
  }
  return -1;
}

/**
 * Whether an index predicate, as Postgres prints it, keeps exactly the rows
 * the declared one (printed the same way) does: the same set of AND-ed
 * conditions, ignoring `key_column IS NOT NULL` unless the index treats NULLs
 * as equal, since otherwise rows with a NULL key never collide anyway.
 */
export function samePredicate(declared: string, actual: string, keyColumns: string[], nullsNotDistinct: boolean): boolean {
  // A key without a predicate must have none: ON CONFLICT cannot infer a
  // partial index as its arbiter.
  if (predicateConditions(declared).length === 0) return actual.trim() === "";
  const redundant = new Set(nullsNotDistinct ? [] : keyColumns.map((column) => `${column} IS NOT NULL`));
  const conditions = (printed: string) =>
    [...new Set(predicateConditions(printed).filter((condition) => !redundant.has(condition)))].sort();
  const left = conditions(declared);
  const right = conditions(actual);
  return left.length === right.length && left.every((condition, index) => condition === right[index]);
}

/**
 * Each REQUIRED_KEYS predicate as Postgres prints it back (empty for none).
 * One simple-protocol round trip on one connection: a transaction that
 * builds a temporary copy of each keyed table's declared columns, indexes
 * it with the declared predicate, reads the printed form and rolls back.
 * The names and SQL are the schema's own constants, never input.
 */
async function printedDeclaredPredicates(pool: Pick<Pool, "query">): Promise<string[]> {
  const partial = REQUIRED_KEYS.flatMap((required, index) => (required.predicate ? [{ ...required, index }] : []));
  if (partial.length === 0) return REQUIRED_KEYS.map(() => "");
  const statements = partial.flatMap(({ table, columns, predicate, index }) => {
    const probe = `heimdall_key_probe_${index}`;
    const declared = REQUIRED_COLUMNS.filter((column) => column.table === table)
      .map((column) => `${column.column} ${column.type}`)
      .join(", ");
    return [
      `CREATE TEMP TABLE ${probe} (${declared}) ON COMMIT DROP`,
      `CREATE UNIQUE INDEX ${probe}_idx ON ${probe} (${columns}) WHERE ${predicate}`,
    ];
  });
  const select = partial
    .map(({ index }) => `SELECT ${index} AS key, pg_get_expr(indpred, indrelid) AS predicate FROM pg_index WHERE indexrelid = 'pg_temp.heimdall_key_probe_${index}_idx'::regclass`)
    .join(" UNION ALL ");
  const results = (await pool.query(["BEGIN", ...statements, select, "ROLLBACK"].join(";\n"))) as unknown as Array<{
    rows: Array<{ key: number; predicate: string }>;
  }>;
  const printed = results[results.length - 2]!.rows;
  return REQUIRED_KEYS.map((_, index) => printed.find((row) => row.key === index)?.predicate ?? "");
}

/**
 * What the store's statements do to each table, and so the privileges its
 * database role needs: it reads what it returns or looks up, inserts what it
 * creates, updates what it changes or upserts, and deletes nothing.
 * audit_events is written and never read back.
 */
export const STORE_TABLE_PRIVILEGES: Readonly<Record<string, readonly ("SELECT" | "INSERT" | "UPDATE")[]>> = {
  accounts: ["SELECT", "INSERT", "UPDATE"],
  linked_identities: ["SELECT", "INSERT", "UPDATE"],
  sessions: ["SELECT", "INSERT", "UPDATE"],
  auth_attempts: ["SELECT", "INSERT", "UPDATE"],
  private_command_receipts: ["SELECT", "INSERT"],
  auth_completions: ["SELECT", "INSERT", "UPDATE"],
  capability_grants: ["SELECT", "INSERT"],
  entitlement_snapshots: ["SELECT", "INSERT", "UPDATE"],
  audit_events: ["INSERT"],
};

export class PostgresStore implements HeimdallStore {
  constructor(private readonly pool: Pick<Pool, "query" | "end">) {}

  async ensureSchema(): Promise<void> {
    await this.pool.query(CREATE_SCHEMA_SQL);
  }

  /**
   * Proves, before Heimdall serves, that the database can take its requests:
   * every table the schema makes; every column with its declared type, and
   * nullable where the schema leaves it nullable; every unique key; and every
   * privilege in STORE_TABLE_PRIVILEGES, held on the table or on each of its
   * columns. A missing or altered piece fails with code SCHEMA_MISSING and a
   * missing privilege with SCHEMA_PRIVILEGES; neither error names the piece.
   *
   * A key is met by a unique index on its table that is valid and ready (a
   * failed CREATE INDEX CONCURRENTLY leaves one that is neither), immediate
   * (ON CONFLICT refuses a deferrable arbiter), has exactly the key's columns
   * as its key columns (INCLUDE columns aside), compares them under
   * deterministic collations (a case-insensitive one would merge two
   * providers' user ids into one row), and has the key's predicate. A
   * predicate matches when both, as Postgres prints them, are the same set of
   * AND-ed conditions; a `key_column IS NOT NULL` condition may be absent on
   * either side, because a unique index never makes NULL keys collide unless
   * it is NULLS NOT DISTINCT.
   *
   * Postgres prints the declared predicates itself: they are indexed on a
   * temporary copy of the table in a transaction that is rolled back.
   */
  async checkSchema(): Promise<void> {
    const declaredPredicates = await printedDeclaredPredicates(this.pool);
    const privileges = Object.entries(STORE_TABLE_PRIVILEGES).flatMap(([table, wanted]) =>
      wanted.map((privilege) => ({ table, privilege }))
    );
    const result = await this.pool.query<{
      kind: "missing" | "privilege" | "candidate";
      key: number | null;
      predicate: string | null;
      nulls_not_distinct: boolean | null;
    }>(
      `
      SELECT 'missing' AS kind, NULL::int AS key, NULL::text AS predicate, NULL::boolean AS nulls_not_distinct
      FROM unnest($1::text[]) AS name WHERE to_regclass(name) IS NULL
      UNION ALL
      SELECT 'missing', NULL, NULL, NULL
      FROM unnest($2::text[], $3::text[], $4::text[], $5::boolean[]) AS required(table_name, column_name, type_name, nullable)
      WHERE NOT EXISTS (
        SELECT 1 FROM pg_attribute a
        WHERE a.attrelid = to_regclass(required.table_name)
          AND a.attname = required.column_name
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND a.atttypid = to_regtype(required.type_name)
          AND (NOT required.nullable OR NOT a.attnotnull)
      )
      UNION ALL
      SELECT 'candidate', required.key::int, pg_get_expr(i.indpred, i.indrelid),
        coalesce((to_jsonb(i) ->> 'indnullsnotdistinct')::boolean, false)
      FROM unnest($6::text[], $7::text[]) WITH ORDINALITY AS required(table_name, columns, key)
      JOIN pg_index i ON i.indrelid = to_regclass(required.table_name)
      WHERE i.indisunique
        AND i.indisvalid
        AND i.indisready
        AND i.indimmediate
        AND i.indnkeyatts = cardinality(string_to_array(required.columns, ','))
        AND (
          SELECT string_agg(a.attname, ',' ORDER BY a.attname)
          FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS key(attnum, position)
          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = key.attnum
          WHERE key.position <= i.indnkeyatts
        ) = required.columns
        AND NOT EXISTS (
          SELECT 1 FROM unnest(i.indcollation::oid[]) WITH ORDINALITY AS key_collation(oid, position)
          JOIN pg_collation c ON c.oid = key_collation.oid
          WHERE key_collation.position <= i.indnkeyatts AND NOT c.collisdeterministic
        )
      UNION ALL
      SELECT 'privilege', NULL, NULL, NULL
      FROM unnest($8::text[], $9::text[]) AS required(table_name, privilege)
      WHERE EXISTS (
        SELECT 1 FROM unnest($2::text[], $3::text[]) AS used(table_name, column_name)
        JOIN pg_attribute a ON a.attrelid = to_regclass(used.table_name) AND a.attname = used.column_name AND NOT a.attisdropped
        WHERE used.table_name = required.table_name
          AND NOT has_column_privilege(a.attrelid, a.attnum, required.privilege)
      )
      `,
      [
        REQUIRED_TABLES,
        REQUIRED_COLUMNS.map((required) => required.table),
        REQUIRED_COLUMNS.map((required) => required.column),
        REQUIRED_COLUMNS.map((required) => required.type),
        REQUIRED_COLUMNS.map((required) => required.nullable),
        REQUIRED_KEYS.map((required) => required.table),
        REQUIRED_KEYS.map((required) => required.columns),
        privileges.map((required) => required.table),
        privileges.map((required) => required.privilege),
      ]
    );
    const keyMet = REQUIRED_KEYS.map((required, index) =>
      result.rows.some(
        (row) =>
          row.kind === "candidate" &&
          row.key === index + 1 &&
          samePredicate(declaredPredicates[index]!, row.predicate ?? "", required.columns.split(","), row.nulls_not_distinct === true)
      )
    );
    if (result.rows.some((row) => row.kind === "missing") || keyMet.includes(false)) {
      throw Object.assign(new Error("The Heimdall schema is not applied."), { code: "SCHEMA_MISSING" });
    }
    if (result.rows.some((row) => row.kind === "privilege")) {
      throw Object.assign(new Error("The Heimdall database role lacks a privilege the store needs."), {
        code: "SCHEMA_PRIVILEGES",
      });
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async createAccount(input: CreateAccountInput): Promise<StoredAccount> {
    const id = input.id ?? randomUUID();
    const result = await this.pool.query<AccountRow>(
      `
      INSERT INTO accounts (id, created_at, last_seen_at, display_name, primary_email)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [id, input.createdAt, input.lastSeenAt, nullable(input.displayName), nullable(input.primaryEmail)]
    );

    return mapAccountRow(expectRow(result.rows[0], "createAccount"));
  }

  async touchAccount(accountId: string, at: string, updates?: { displayName?: string; primaryEmail?: string }): Promise<void> {
    await this.pool.query(
      `
      UPDATE accounts
      SET last_seen_at = $2,
          display_name = COALESCE($3, display_name),
          primary_email = COALESCE($4, primary_email)
      WHERE id = $1
      `,
      [accountId, at, nullable(updates?.displayName), nullable(updates?.primaryEmail)]
    );
  }

  async findAccountById(accountId: string): Promise<StoredAccount | null> {
    const result = await this.pool.query<AccountRow>(
      `
      SELECT *
      FROM accounts
      WHERE id = $1
      LIMIT 1
      `,
      [accountId]
    );

    return result.rowCount ? mapAccountRow(expectRow(result.rows[0], "findAccountById")) : null;
  }

  async findAccountByLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredAccount | null> {
    const result = await this.pool.query<AccountRow>(
      `
      SELECT accounts.*
      FROM accounts
      INNER JOIN linked_identities ON linked_identities.account_id = accounts.id
      WHERE linked_identities.provider = $1
        AND linked_identities.provider_user_id = $2
      LIMIT 1
      `,
      [provider, providerUserId]
    );

    return result.rowCount ? mapAccountRow(expectRow(result.rows[0], "findAccountByLinkedIdentity")) : null;
  }

  async findStoredLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredLinkedIdentity | null> {
    const result = await this.pool.query<LinkedIdentityRow>(
      `
      SELECT *
      FROM linked_identities
      WHERE provider = $1
        AND provider_user_id = $2
      LIMIT 1
      `,
      [provider, providerUserId]
    );

    return result.rowCount ? mapLinkedIdentityRow(expectRow(result.rows[0], "findStoredLinkedIdentity")) : null;
  }

  async findStoredLinkedIdentityForAccount(accountId: string, provider: Provider): Promise<StoredLinkedIdentity | null> {
    const result = await this.pool.query<LinkedIdentityRow>(
      `
      SELECT *
      FROM linked_identities
      WHERE account_id = $1
        AND provider = $2
      ORDER BY updated_at DESC
      LIMIT 1
      `,
      [accountId, provider]
    );

    return result.rowCount ? mapLinkedIdentityRow(expectRow(result.rows[0], "findStoredLinkedIdentityForAccount")) : null;
  }

  async listStoredLinkedIdentitiesForAccount(accountId: string): Promise<StoredLinkedIdentity[]> {
    const result = await this.pool.query<LinkedIdentityRow>(
      `
      SELECT *
      FROM linked_identities
      WHERE account_id = $1
      ORDER BY created_at ASC
      `,
      [accountId]
    );

    return result.rows.map(mapLinkedIdentityRow);
  }

  async upsertLinkedIdentity(input: UpsertLinkedIdentityInput): Promise<StoredLinkedIdentity> {
    const id = input.id ?? randomUUID();
    const result = await this.pool.query<LinkedIdentityRow>(
      `
      INSERT INTO linked_identities (
        id,
        account_id,
        provider,
        provider_user_id,
        username,
        display_name,
        primary_email,
        access_token_encrypted,
        refresh_token_encrypted,
        token_expires_at,
        scopes,
        profile_json,
        created_at,
        updated_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8, $9, $10, $11, $12, $13, $14
      )
      ON CONFLICT (provider, provider_user_id)
      DO UPDATE SET
        account_id = EXCLUDED.account_id,
        username = EXCLUDED.username,
        display_name = EXCLUDED.display_name,
        primary_email = EXCLUDED.primary_email,
        access_token_encrypted = EXCLUDED.access_token_encrypted,
        refresh_token_encrypted = EXCLUDED.refresh_token_encrypted,
        token_expires_at = EXCLUDED.token_expires_at,
        scopes = EXCLUDED.scopes,
        profile_json = EXCLUDED.profile_json,
        updated_at = EXCLUDED.updated_at
      RETURNING *
      `,
      [
        id,
        input.accountId,
        input.provider,
        input.providerUserId,
        nullable(input.username),
        nullable(input.displayName),
        nullable(input.primaryEmail),
        nullable(input.accessTokenEncrypted),
        nullable(input.refreshTokenEncrypted),
        nullable(input.tokenExpiresAt),
        input.scopes.join(" "),
        JSON.stringify(input.profileJson),
        input.createdAt,
        input.updatedAt,
      ]
    );

    return mapLinkedIdentityRow(expectRow(result.rows[0], "upsertLinkedIdentity"));
  }

  async listLinkedIdentitiesForAccount(accountId: string): Promise<LinkedIdentityInput[]> {
    const result = await this.pool.query<LinkedIdentityRow>(
      `
      SELECT *
      FROM linked_identities
      WHERE account_id = $1
      ORDER BY created_at ASC
      `,
      [accountId]
    );

    return result.rows.map((row) => {
      const linkedIdentity: LinkedIdentityInput = {
        provider: row.provider,
        providerUserId: row.provider_user_id,
      };

      if (row.username) {
        linkedIdentity.username = row.username;
      }

      if (row.display_name) {
        linkedIdentity.displayName = row.display_name;
      }

      return linkedIdentity;
    });
  }

  async createCapabilityGrant(input: CreateCapabilityGrantInput): Promise<StoredCapabilityGrant> {
    const id = input.id ?? randomUUID();
    const result = await this.pool.query<GrantRow>(
      `
      INSERT INTO capability_grants (
        id, account_id, scope_type, scope_id, capability,
        source, status, expires_at, note, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
      `,
      [
        id,
        input.accountId,
        input.scopeType,
        nullable(input.scopeId),
        input.capability,
        input.source,
        input.status,
        nullable(input.expiresAt),
        nullable(input.note),
        input.createdAt,
        input.updatedAt,
      ]
    );

    return mapGrantRow(expectRow(result.rows[0], "createCapabilityGrant"));
  }

  async listActiveGrants(accountId: string, appSlug: AppSlug, at: string): Promise<StoredCapabilityGrant[]> {
    const result = await this.pool.query<GrantRow>(
      `
      SELECT *
      FROM capability_grants
      WHERE account_id = $1
        AND status = 'active'
        AND (expires_at IS NULL OR expires_at > $3)
        AND (
          scope_type = 'global'
          OR (scope_type = 'app' AND scope_id = $2)
        )
      ORDER BY created_at ASC
      `,
      [accountId, appSlug, at]
    );

    return result.rows.map(mapGrantRow);
  }

  async createSession(input: CreateSessionInput): Promise<StoredSession> {
    const result = await this.pool.query<SessionRow>(
      `
      INSERT INTO sessions (
        id, account_id, app_slug, created_at, last_seen_at,
        expires_at, claims_json, access_revision
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (id)
      DO UPDATE SET
        last_seen_at = EXCLUDED.last_seen_at,
        expires_at = EXCLUDED.expires_at,
        claims_json = EXCLUDED.claims_json,
        access_revision = EXCLUDED.access_revision
      WHERE sessions.account_id = EXCLUDED.account_id
        AND sessions.app_slug = EXCLUDED.app_slug
        AND sessions.access_revision <= EXCLUDED.access_revision
      RETURNING *
      `,
      [
        input.id,
        input.accountId,
        input.appSlug,
        input.createdAt,
        input.lastSeenAt,
        input.expiresAt,
        JSON.stringify(input.claimsJson),
        input.accessRevision,
      ]
    );

    return mapSessionRow(expectRow(result.rows[0], "createSession"));
  }

  async findSession(appSlug: AppSlug, sessionId: string): Promise<StoredSession | null> {
    const result = await this.pool.query<SessionRow>(
      "SELECT * FROM sessions WHERE app_slug = $1 AND id = $2",
      [appSlug, sessionId],
    );
    return result.rowCount ? mapSessionRow(expectRow(result.rows[0], "findSession")) : null;
  }

  async revokeSession(
    appSlug: AppSlug,
    sessionId: string,
    accountId: string,
    expectedAccessRevision: number,
    at: string,
  ): Promise<StoredSession | null> {
    const result = await this.pool.query<SessionRow>(
      `UPDATE sessions
       SET last_seen_at = $5, expires_at = $5, access_revision = access_revision + 1
       WHERE app_slug = $1 AND id = $2 AND account_id = $3 AND access_revision = $4
       RETURNING *`,
      [appSlug, sessionId, accountId, expectedAccessRevision, at],
    );
    return result.rowCount ? mapSessionRow(expectRow(result.rows[0], "revokeSession")) : null;
  }

  async createAuthAttempt(input: CreateAuthAttemptInput): Promise<StoredAuthAttempt> {
    const handle = input.handle ?? randomUUID();
    const result = await this.pool.query<AuthAttemptRow>(
      `INSERT INTO auth_attempts (
        handle, app_slug, provider, mode, return_to, status, created_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7) RETURNING *`,
      [handle, input.appSlug, input.provider, input.mode, input.returnTo, input.createdAt, input.expiresAt],
    );
    return mapAuthAttemptRow(expectRow(result.rows[0], "createAuthAttempt"));
  }

  async findAuthAttempt(appSlug: AppSlug, handle: string): Promise<StoredAuthAttempt | null> {
    const result = await this.pool.query<AuthAttemptRow>(
      "SELECT * FROM auth_attempts WHERE app_slug = $1 AND handle = $2",
      [appSlug, handle],
    );
    return result.rowCount ? mapAuthAttemptRow(expectRow(result.rows[0], "findAuthAttempt")) : null;
  }

  async updateAuthAttempt(
    appSlug: AppSlug,
    handle: string,
    update: { status: HeimdallAuthAttemptStatus; at: string; denialCode?: string },
  ): Promise<StoredAuthAttempt | null> {
    const result = await this.pool.query<AuthAttemptRow>(
      `UPDATE auth_attempts SET
        status = $3,
        completed_at = CASE WHEN $3 = 'completed' THEN $4 ELSE completed_at END,
        consumed_at = CASE WHEN $3 = 'consumed' THEN $4 ELSE consumed_at END,
        denial_code = COALESCE($5, denial_code)
      WHERE app_slug = $1 AND handle = $2
        AND (
          status = $3 OR
          (status = 'pending' AND $3 IN ('completed', 'denied', 'expired')) OR
          (status = 'completed' AND $3 = 'consumed')
        )
      RETURNING *`,
      [appSlug, handle, update.status, update.at, nullable(update.denialCode)],
    );
    if (result.rowCount) return mapAuthAttemptRow(expectRow(result.rows[0], "updateAuthAttempt"));
    return await this.findAuthAttempt(appSlug, handle);
  }

  async createPrivateCommandReceipt(input: CreatePrivateCommandReceiptInput): Promise<StoredPrivateCommandReceipt> {
    const result = await this.pool.query<PrivateCommandReceiptRow>(
      `INSERT INTO private_command_receipts (
        app_slug, idempotency_key, request_fingerprint, status,
        content_schema, envelope_base64, created_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (app_slug, idempotency_key) DO NOTHING
      RETURNING *`,
      [
        input.appSlug,
        input.idempotencyKey,
        input.requestFingerprint,
        input.status,
        input.contentSchema,
        input.envelopeBase64,
        input.createdAt,
        input.expiresAt,
      ],
    );
    const existing = result.rowCount
      ? mapPrivateCommandReceiptRow(expectRow(result.rows[0], "createPrivateCommandReceipt"))
      : await this.findPrivateCommandReceipt(input.appSlug, input.idempotencyKey);
    if (!existing) throw new Error("Private command receipt conflict returned no record.");
    if (existing.requestFingerprint !== input.requestFingerprint) {
      throw new Error("Idempotency key was reused with different command content.");
    }
    return existing;
  }

  async findPrivateCommandReceipt(appSlug: AppSlug, idempotencyKey: string): Promise<StoredPrivateCommandReceipt | null> {
    const result = await this.pool.query<PrivateCommandReceiptRow>(
      "SELECT * FROM private_command_receipts WHERE app_slug = $1 AND idempotency_key = $2",
      [appSlug, idempotencyKey],
    );
    return result.rowCount
      ? mapPrivateCommandReceiptRow(expectRow(result.rows[0], "findPrivateCommandReceipt"))
      : null;
  }

  async createAuthCompletion(input: CreateAuthCompletionInput): Promise<StoredAuthCompletion> {
    // The code is always minted here; nothing upstream may choose it.
    const code = randomUUID();
    const result = await this.pool.query<AuthCompletionRow>(
      `
      INSERT INTO auth_completions (
        code, attempt_id, app_slug, provider, mode, account_id, session_id,
        return_to, payload_json, created_at, expires_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
      `,
      [
        code,
        input.attemptId ?? null,
        input.appSlug,
        input.provider,
        input.mode,
        input.accountId,
        input.sessionId,
        input.returnTo,
        JSON.stringify(input.payloadJson),
        input.createdAt,
        input.expiresAt,
      ]
    );

    return mapAuthCompletionRow(expectRow(result.rows[0], "createAuthCompletion"));
  }

  async consumeAuthCompletion(appSlug: AppSlug, code: string, at: string): Promise<StoredAuthCompletion | null> {
    const result = await this.pool.query<AuthCompletionRow>(
      `
      UPDATE auth_completions
      SET consumed_at = $3
      WHERE code = $1
        AND app_slug = $2
        AND consumed_at IS NULL
        AND expires_at > $3
      RETURNING *
      `,
      [code, appSlug, at]
    );

    return result.rowCount ? mapAuthCompletionRow(expectRow(result.rows[0], "consumeAuthCompletion")) : null;
  }

  async consumeAuthCompletionByAttempt(appSlug: AppSlug, attemptId: string, at: string): Promise<StoredAuthCompletion | null> {
    const result = await this.pool.query<AuthCompletionRow>(
      `
      UPDATE auth_completions
      SET consumed_at = $3
      WHERE attempt_id = $1
        AND app_slug = $2
        AND consumed_at IS NULL
        AND expires_at > $3
      RETURNING *
      `,
      [attemptId, appSlug, at]
    );

    return result.rowCount ? mapAuthCompletionRow(expectRow(result.rows[0], "consumeAuthCompletionByAttempt")) : null;
  }

  async upsertEntitlementSnapshot(input: CreateEntitlementSnapshotInput): Promise<void> {
    await this.pool.query(
      `
      INSERT INTO entitlement_snapshots (
        id, account_id, provider, scope, evaluated_at,
        is_allowed, reason_code, reason_detail, raw_summary_json
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (account_id, provider, scope)
      DO UPDATE SET
        evaluated_at = EXCLUDED.evaluated_at,
        is_allowed = EXCLUDED.is_allowed,
        reason_code = EXCLUDED.reason_code,
        reason_detail = EXCLUDED.reason_detail,
        raw_summary_json = EXCLUDED.raw_summary_json
      `,
      [
        randomUUID(),
        input.accountId,
        input.provider,
        input.scope,
        input.evaluatedAt,
        input.isAllowed,
        input.reasonCode,
        nullable(input.reasonDetail),
        JSON.stringify(input.rawSummaryJson),
      ]
    );
  }

  async createAuditEvent(input: CreateAuditEventInput): Promise<void> {
    await this.pool.query(
      `
      INSERT INTO audit_events (
        id, account_id, session_id, app_slug, event_type,
        event_payload_json, created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
      [
        input.id ?? randomUUID(),
        nullable(input.accountId),
        nullable(input.sessionId),
        nullable(input.appSlug),
        input.eventType,
        JSON.stringify(input.eventPayloadJson),
        input.createdAt,
      ]
    );
  }
}

export function createPostgresStore(databaseUrl: string): PostgresStore {
  const pool = new Pool({
    connectionString: databaseUrl,
  });
  // An idle client whose connection ends (a database restart, an
  // administrator terminating the backend) is emitted here. Unheard, the
  // event kills the process and Node prints the pg Client, connection
  // parameters included. The pool has already dropped the dead client and
  // opens a new one on the next query, so this only says what happened, by
  // code.
  pool.on("error", (error) => {
    const code = (error as { code?: unknown }).code;
    console.error(
      `Heimdall lost an idle Postgres connection (${typeof code === "string" ? code : "error"}); the pool reconnects on the next query.`
    );
  });
  return new PostgresStore(pool);
}
