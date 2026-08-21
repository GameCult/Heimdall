# Heimdall Verse Service Contract

Heimdall is the shared auth authority for GameCult-hosted experiments. It owns
auth/control-plane truth: provider OAuth, linked identities, grants,
entitlements, sessions, managed provider credential custody, app-facing claims,
and audit records.

Heimdall must not become the shared app-data swamp. App-domain state stays with
the app that owns the consequence. Heimdall owns authentication and authorization
evidence only.

## Owner Map

- Owner: Heimdall owns provider identity/linking, OAuth attempts, signed session and claim
  issuance, entitlement refresh, managed provider token custody, grants,
  auth-completion handoffs, refresh sessions, and audit events.
- Inputs: provider OAuth callbacks, app profile requests, caller-supplied
  entitlement policy, provider API responses, configured signing/encryption
  keys, app backend callback receipts, and local Postgres/in-memory store
  records.
- Outputs: signed access claims, refresh claims, typed private-command receipts, JWKS, discovery documents,
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

The next full state cut is a redacted CultCache `.cc` witness/export path for
Heimdall-owned auth/control-plane documents:

- `heimdall.account.v0`
- `heimdall.linked_identity.v0`
- `heimdall.session.v0`
- `heimdall.grant.v0`
- `heimdall.entitlement_snapshot.v0`
- `heimdall.auth_completion.v0`
- `heimdall.audit_event.v0`
- `heimdall.app_profile.v0`
- `heimdall.managed_credential_projection.v0`

The `.cc` store does not need to replace Postgres in the first pass. The live
first pass is narrower: it publishes a daemon-owned boundary store for Odin and
Idunn. That store carries the Heimdall provider advertisement, command
boundary, transport profile, and daemon-health summary without exporting
per-account auth truth. The next pass should extend that runtime-owned boundary
store into a typed, redacted, operator-safe witness of Heimdall auth state so
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
2. Publish a daemon-owned boundary `.cc` store plus Idunn daemon-health
   summary from the live runtime.
3. Extend the boundary store into redacted auth/document witness exports.
4. Publish the witness through CultMesh with secret-safe projections only.
5. Add an Eve DSL provider over the witness and existing health/discovery data.
6. Register Heimdall's provider surface with Odin.
7. Only after the witness path is stable, decide whether any live state should
   move from Postgres into a CultCache-backed primary store.

The invariant: Heimdall owns shared auth truth, not app-domain truth. CultCache
and CultMesh make Heimdall inspectable; they do not leak secrets or move product
state into the auth authority.

## Runtime Boundary First Cut

The current repo cut now publishes a daemon-owned boundary witness without
migrating live auth truth out of Postgres or the HTTP auth surface.

Authority map:

- Owner: Heimdall remains the only owner of auth/control-plane mutation.
- Inputs: static provider catalog, static app profiles, deployment/runtime
  config, and the redacted witness descriptor table in `src/verse-witness.ts`.
- Outputs: the existing read-only `pnpm export:provider-advertisement` JSON plus
  a runtime-owned `GC_ACCESS_CULTCACHE_PATH` store containing
  `gamecult.eve.provider_advertisement.v1`, `heimdall.command_boundary.v1`,
  `heimdall.transport_profile.v1`, and `idunn.daemon_health.v1` summary state.
  It also publishes the redacted `gamecult.heimdall.access` plugin
  advertisement and loopback command-route metadata. No claim, token, secret,
  nonce, or opaque attempt handle enters that store.
- Derived state: `/healthz`, JWKS, discovery, systemd, nginx routing, and the
  boundary store are projections. They must not mutate auth truth or replace
  explicit Heimdall API ownership.
- Forbidden writers: Odin probes, Eve renderers, dashboards, Idunn, and the
  boundary store cannot mutate accounts, linked identities, grants, sessions,
  tokens, completions, entitlements, audit events, or app profiles.
- Shared paths: the runtime boundary store, future redacted auth witness
  exports, CultMesh publication, and Eve lowering should reuse the same
  document IDs and redaction doctrine.
- Deletion line: if a future writer needs app-domain fields or provider tokens
  to make the surface useful, the design is wrong; keep those fields out or
  move the concern back to the owning app/service.

The boundary store currently names the daemon-owned publication seam. The next
redacted auth witness cut should add these `.cc` targets:

- `heimdall.account.v0` at `cultcache/heimdall/accounts/{accountId}.cc`
- `heimdall.linked_identity.v0` at
  `cultcache/heimdall/linked-identities/{provider}/{providerUserId}.cc`
- `heimdall.capability_grant.v0` at
  `cultcache/heimdall/grants/{grantId}.cc`
- `heimdall.session.v0` at `cultcache/heimdall/sessions/{sessionId}.cc`
- `heimdall.entitlement_snapshot.v0` at
  `cultcache/heimdall/entitlements/{accountId}/{provider}/{scope}.cc`
- `heimdall.auth_completion.v0` at
  `cultcache/heimdall/auth-completions/{completionCodeHash}.cc`
- `heimdall.auth_attempt.v1` at
  `cultcache/heimdall/auth-attempts/{attemptHandleHash}.cc`
- `heimdall.audit_event.v0` at `cultcache/heimdall/audit/{eventId}.cc`
- `heimdall.app_profile.v0` at
  `cultcache/heimdall/app-profiles/{appSlug}.cc`
- `heimdall.managed_credential_projection.v0` at
  `cultcache/heimdall/managed-credentials/{appSlug}/{accountId}/{provider}.cc`
