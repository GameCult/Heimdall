export const CREATE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  display_name TEXT,
  primary_email TEXT
);

CREATE TABLE IF NOT EXISTS linked_identities (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  username TEXT,
  display_name TEXT,
  primary_email TEXT,
  access_token_encrypted TEXT,
  refresh_token_encrypted TEXT,
  token_expires_at TIMESTAMPTZ,
  scopes TEXT NOT NULL DEFAULT '',
  profile_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE(provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS linked_identities_account_id_idx
  ON linked_identities(account_id);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  app_slug TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  claims_json JSONB NOT NULL,
  access_revision INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_account_id_idx
  ON sessions(account_id);

CREATE TABLE IF NOT EXISTS auth_completions (
  code TEXT PRIMARY KEY,
  app_slug TEXT NOT NULL,
  provider TEXT NOT NULL,
  mode TEXT NOT NULL,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  return_to TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS auth_completions_lookup_idx
  ON auth_completions(app_slug, expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS capability_grants (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  scope_type TEXT NOT NULL,
  scope_id TEXT,
  capability TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS capability_grants_lookup_idx
  ON capability_grants(account_id, scope_type, scope_id, status);

CREATE TABLE IF NOT EXISTS entitlement_snapshots (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  scope TEXT NOT NULL,
  evaluated_at TIMESTAMPTZ NOT NULL,
  is_allowed BOOLEAN NOT NULL,
  reason_code TEXT NOT NULL,
  reason_detail TEXT,
  raw_summary_json JSONB NOT NULL,
  UNIQUE(account_id, provider, scope)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  account_id TEXT,
  session_id TEXT,
  app_slug TEXT,
  event_type TEXT NOT NULL,
  event_payload_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_lookup_idx
  ON audit_events(account_id, session_id, app_slug, created_at);
`;
