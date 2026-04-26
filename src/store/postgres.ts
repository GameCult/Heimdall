import { randomUUID } from "node:crypto";
import { Pool, type PoolClient, type QueryResultRow } from "pg";
import { type AppSlug, type LinkedIdentityInput, type Provider } from "../contracts.js";
import { CREATE_SCHEMA_SQL } from "./schema.js";
import {
  type CreateAccountInput,
  type CreateAuthCompletionInput,
  type CreateAuditEventInput,
  type CreateCapabilityGrantInput,
  type CreateEntitlementSnapshotInput,
  type CreateSessionInput,
  type HeimdallStore,
  type StoredAccount,
  type StoredAuthCompletion,
  type StoredCapabilityGrant,
  type StoredLinkedIdentity,
  type StoredSession,
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

  if (row.consumed_at) {
    completion.consumedAt = normalizeTimestamp(row.consumed_at);
  }

  return completion;
}

export class PostgresStore implements HeimdallStore {
  constructor(private readonly pool: Pick<Pool, "query" | "end">) {}

  async ensureSchema(): Promise<void> {
    await this.pool.query(CREATE_SCHEMA_SQL);
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

  async createAuthCompletion(input: CreateAuthCompletionInput): Promise<StoredAuthCompletion> {
    const code = input.code ?? randomUUID();
    const result = await this.pool.query<AuthCompletionRow>(
      `
      INSERT INTO auth_completions (
        code, app_slug, provider, mode, account_id, session_id,
        return_to, payload_json, created_at, expires_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
      `,
      [
        code,
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

export function createPostgresStore(databaseUrl: string): HeimdallStore {
  const pool = new Pool({
    connectionString: databaseUrl,
  });
  return new PostgresStore(pool);
}
