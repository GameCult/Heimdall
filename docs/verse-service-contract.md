# Heimdall Verse Service Contract

Heimdall is the shared auth authority for GameCult-hosted experiments. It owns
auth/control-plane truth: provider OAuth, linked identities, grants,
entitlements, sessions, managed provider credential custody, app-facing claims,
and audit records.

Heimdall must not become the shared app-data swamp. App-domain state stays with
the app that owns the consequence. Heimdall owns authentication and authorization
evidence only.

## Owner Map

- Owner: Heimdall owns provider identity/linking, signed session and claim
  issuance, entitlement refresh, managed provider token custody, grants,
  auth-completion handoffs, refresh sessions, and audit events.
- Inputs: provider OAuth callbacks, app profile requests, caller-supplied
  entitlement policy, provider API responses, configured signing/encryption
  keys, app backend callback receipts, and local Postgres/in-memory store
  records.
- Outputs: signed access claims, refresh claims, JWKS, discovery documents,
  backend handoff payloads, managed credential projections, audit records, and
  app-local verification material.
- Derived state: health/discovery/JWKS responses, browser completion pages,
  app-profile docs, and public status checks are projections. They do not own
  auth truth.
- Forbidden writers: app backends, dashboards, browser callback pages, Eve/TUI
  renderers, and Odin probes must not mutate Heimdall auth truth except through
  explicit Heimdall API command boundaries.
- Shared paths: local dev memory store, deployed Postgres store, future
  CultCache `.cc` witness/export, Odin discovery, and Eve operator surface must
  describe the same auth/control-plane facts.
- Deletion line: any app-specific access rule that outgrows a thin app profile
  must move back to the app. Heimdall should not absorb product state to make a
  dashboard easier.

## CultCache Requirement

Heimdall currently has durable Postgres storage for deployed auth/control-plane
state. That is acceptable for live auth operations, but it is not enough for the
GameCult Verse service contract by itself.

The next state cut is a CultCache `.cc` witness/export path for Heimdall-owned
auth/control-plane documents:

- `heimdall.account.v0`
- `heimdall.linked_identity.v0`
- `heimdall.session.v0`
- `heimdall.grant.v0`
- `heimdall.entitlement_snapshot.v0`
- `heimdall.auth_completion.v0`
- `heimdall.audit_event.v0`
- `heimdall.app_profile.v0`
- `heimdall.managed_credential_projection.v0`

The `.cc` store does not need to replace Postgres in the first pass. The first
pass should export a typed, redacted, operator-safe witness of Heimdall state so
CultMesh/Odin/Eve can inspect service truth without receiving provider secrets.

Sensitive fields must be handled explicitly:

- provider access and refresh tokens stay sealed server-side;
- exported linked identity records carry provider, provider subject, scopes,
  expiry, and custody status, not raw tokens;
- audit payloads must redact provider tokens, secrets, callback codes, and
  private user data that is not needed for service operation;
- app-domain data stays out of Heimdall exports.

## Eve Surface Target

Heimdall should publish an Eve GUI/TUI DSL operator surface with these panels:

1. `Authority`: public base URL, service name, storage backend, signing key id,
   JWKS freshness, token custody source, deployment host.
2. `Providers`: configured providers, callback readiness, scope policy, refresh
   support, and last provider error without secrets.
3. `Apps`: app profiles, allowed providers, entitlement sources, handoff modes,
   claim audiences, and app-owned policy boundaries.
4. `Sessions And Grants`: counts and freshness for active sessions, grants,
   entitlement snapshots, refreshes, and completion handoffs.
5. `Audit`: recent redacted auth events, failed callback reasons, backend
   handoff failures, and stale provider-token custody.

Eve must send command intent only for explicit operator actions, such as
rotating a configured key, disabling a provider, revoking a session, or
refreshing an entitlement snapshot. Heimdall accepts or denies those actions.

## Migration Order

1. Define Heimdall CultCache document shapes for redacted auth/control-plane
   witness state.
2. Add a read-only export command from the current store into a `.cc` witness.
3. Publish the witness through CultMesh with secret-safe projections only.
4. Add an Eve DSL provider over the witness and existing health/discovery data.
5. Register Heimdall's provider surface with Odin.
6. Only after the witness path is stable, decide whether any live state should
   move from Postgres into a CultCache-backed primary store.

The invariant: Heimdall owns shared auth truth, not app-domain truth. CultCache
and CultMesh make Heimdall inspectable; they do not leak secrets or move product
state into the auth authority.
