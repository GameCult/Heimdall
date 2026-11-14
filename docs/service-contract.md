# Heimdall Service Contract

This file describes the first landed Heimdall service slice.

It is the concrete HTTP/JWKS contract that now exists in the repo. It is not a
claim that every provider, consumer binding, or production-hardening concern is
done yet.

## Current stack

- runtime: Node.js `24+`
- service framework: Fastify
- language: TypeScript
- signing: Ed25519 JWTs with JWKS exposure

## Current routes

### `GET /healthz`

Purpose:

- basic liveness probe

Response:

```json
{
  "ok": true,
  "service": "heimdall",
  "issuer": "https://heimdall.gamecult.org",
  "storageBackend": "memory",
  "signingKeySource": "configured_file",
  "tokenCustodySource": "configured",
  "now": "2026-04-26T12:00:00.000Z"
}
```

### `GET /.well-known/jwks.json`

Purpose:

- publish the public signing key that app backends use to verify Heimdall JWTs

Notes:

- current skeleton signs with Ed25519
- `GC_ACCESS_SIGNING_PRIVATE_KEY_PATH` lets the service load a persisted key
  from disk
- if the path is missing and `GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP=1`, the
  service bootstraps a new key file on first start
- if no path is configured, the service still generates an
  ephemeral dev key at startup and deserves no sympathy when the `kid` changes

### `GET /.well-known/heimdall-configuration`

Purpose:

- publish discovery metadata for app backends and integration code

Current shape includes:

- `issuer`
- `jwksUri`
- `configurationUri`
- `oauthStartEndpoint`
- `oauthCallbackEndpoint`
- `supportedProviders`
- `apps`

### `GET /v1/apps`

Purpose:

- list known app profiles and their capability surfaces

### `GET /v1/apps/{appSlug}`

Purpose:

- return one app profile

Current app slugs:

- `repixelizer`
- `streampixels`
- `spotiverse`

Profile fields:

- `slug`
- `displayName`
- `profileVersion`
- `identityProviders`
- `entitlementSources`
- `managedConnectionProviders`
- `capabilities`

Capability modes:

- `shared`
  fully evaluated by Heimdall from signed facts/grants
- `hybrid`
  requires app-local state after claim verification

### `POST /v1/oauth/{provider}/start`

Purpose:

- begin a provider OAuth flow
- mint signed OAuth `state`
- return the provider authorization URL

Supported providers in the skeleton:

- `discord`
- `patreon`
- `github`
- `twitch`
- `youtube`
- `spotify`
- `joystick`
- `google`

Request body:

```json
{
  "appSlug": "repixelizer",
  "mode": "sign_in",
  "returnTo": "https://repixelizer.gamecult.org/app/",
  "handoff": {
    "kind": "backend_callback",
    "attemptId": "auth-attempt-123",
    "callbackUrl": "https://repixelizer.gamecult.org/api/auth/heimdall/callback"
  },
  "connection": {
    "kind": "creator",
    "targetId": "creator:alpha",
    "summary": "Optional app-local binding hint"
  },
  "requestedScopes": ["identify", "guilds"]
}
```

Response:

```json
{
  "provider": "discord",
  "appSlug": "repixelizer",
  "mode": "sign_in",
  "callbackUrl": "https://heimdall.gamecult.org/v1/oauth/discord/callback",
  "authorizationUrl": "https://heimdall.gamecult.org/v1/oauth/discord/launch?state=<signed-jwt>",
  "stateExpiresAt": "2026-04-26T12:10:00.000Z"
}
```

Send the user's browser to `authorizationUrl` unchanged. It is Heimdall's launch
hop, not the provider's URL.

### `GET /v1/oauth/{provider}/launch?state=<signed-jwt>`

The first thing the user's browser does with a state. Heimdall verifies the
state (signature, issuer, provider, `nbf`/`exp` with 30 s of skew), claims the
state's single launch, sets the binding cookie
`__Host-heimdall-oauth-<jti>` (`Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`,
`Max-Age` until the state expires; the value is a Heimdall-signed binding for
that state) and answers `302` to the provider's authorize URL, with
`Cache-Control: no-store` and `Referrer-Policy: no-referrer`. A second launch of
the same state is `400 state_already_launched` and sets no cookie. The state is
refused with `400 invalid_state`, `state_provider_mismatch` or `state_expired`.

The binding cookie needs an `https` public base URL (or `localhost`). A browser
must finish the flow in the browser that launched it.

Failure modes:

- `503 provider_not_configured` when the provider client id is missing
- `400 untrusted_backend_callback` when `handoff.kind=backend_callback` and
  `callbackUrl` is not in that app's `GC_ACCESS_APP_<SLUG>_BACKEND_CALLBACK_URLS`
- `400 return_to_not_allowed` when `returnTo`'s origin is not in that app's
  `allowedReturnOrigins` (`src/app-profiles.ts`) -- `returnTo` is where the
  browser handoff page postMessages the completion payload
  (`src/browser-handoff.ts`), so this check runs for every caller, not only an
  authenticated one
- `401 app_auth_required` when the request body carries `entitlementPolicy` and
  the caller did not authenticate as that app via `x-heimdall-app-secret`
  (`resolveAppCaller`, `src/app-caller.ts`) -- this applies regardless of
  `handoff.kind` or app slug; a caller with no policy to attach needs no secret,
  unless the app's profile sets `startRequiresAppCaller` (Bifrost only): then
  every start for that app, with or without a policy, needs that app's secret.
  Bifrost binds browser completion to a nonce that rides readable in the signed
  state's `return_to`, so only Bifrost may mint a Bifrost state; apps whose
  browser starts are public by design leave the flag unset
- `401 app_auth_required` also when `mode` is `connect` and the body carries a
  `connection` (a creator or account target): a connection target is app-backend
  authority, so only the authenticated app named by `appSlug` may start it. No
  secret, or another app's, is refused before any state is signed. `sign_in`
  starts carrying a `connection` are `400 connection_not_allowed_in_sign_in`

Step-up (`stepUp: true`, sign_in only, off by default):

- Asks the provider for a real re-authentication on the authorize URL, so a
  provider session already open in the browser is not enough to complete the
  sign-in. The start request field is `stepUp`; the signed state carries it as
  `step_up`, and the launch hop builds the provider URL from the state alone.
  Nothing on the callback or redeem side can set or clear it (a `stepUp` in a
  redeem body is ignored), and a completion reports it as `stepUpRequested: true`
  when the start asked.
- It is the authenticated app's request, like a connection target: no secret or
  another app's is `401 app_auth_required`; a `link` or `connect` start carrying
  it is `400 step_up_only_in_sign_in`; `stepUp: false` is the same as absent.
- Provider parameters (`stepUpAuthorizationParams`, `src/providers.ts`): Twitch
  `force_verify=true`, YouTube `prompt=login consent` (consent is kept; the
  provider always asks it), Google `prompt=login`. **The strengths differ.**
  Google `prompt=login` forces the person to re-authenticate. Twitch
  `force_verify` re-shows the authorize page: it proves a person at that browser
  chose to continue, not that they entered credentials. A consumer that needs
  credentials re-entered must not rely on Twitch step-up.
- A provider with no such parameter (Discord, Patreon, GitHub, Spotify,
  Joystick) is `400 step_up_not_supported`, with the provider named, before any
  state is signed. The URL builder throws rather than omit the step.
- A `backend_callback` handoff delivery does not carry `stepUpRequested`; only the redeemed completion does.
- A state signed by a build with step-up and launched by an older build loses the step
  silently (the older parser ignores `step_up`): deploy every Heimdall instance on one
  release, with no mixed window.
- Heimdall requests the step; it cannot observe that the provider honoured it.
  `stepUpRequested` says "asked", not "verified".

Launch note:

- Discord and Patreon are the implemented provider runtimes for Repixelizer
- Twitch, YouTube and Joystick have generic OAuth exchange and identity runtimes for
  StreamPixels viewer auth and managed creator connections
- GitHub is still catalogued for start URLs, but its callback runtime is not
  implemented yet
- Repixelizer launch can configure Discord and Patreon on its provider buttons

### Google (OpenID Connect, link-only)

`google` is an identity provider that never mints an account. It is a second
door into a person who already has one.

- Callback redirect URI (register exactly this in the Google Cloud OAuth
  client): `{GC_ACCESS_BASE_URL}/v1/oauth/google/callback`, which is
  `https://heimdall.gamecult.org/v1/oauth/google/callback` in production.
- Scopes `openid email profile`. The authorization request carries `state`
  (signed, Heimdall's), a `nonce`, and a PKCE `S256` challenge, all built at the
  launch hop, which is where the browser first meets the provider URL. The verifier
  and the nonce are derived from the state's `jti` and Heimdall's signing key,
  so nothing is stored between start and callback.
- The callback verifies the `id_token` (RS256 against Google's published
  keys; `iss` is Google, `aud` is this client, `exp`, `iat`, `nonce`) and
  requires a `sub` and a verified email. The account key is `sub`; the email
  is a display and contact field and never a lookup key.
- `mode: "link"` needs `Authorization: Bearer <Heimdall access token>` for the
  same app; the identity attaches to that token's account and to no other.
  `mode: "sign_in"` signs in an account the `sub` is already linked to.
- A `sub` no account holds, arriving with `sign_in`, is refused and mints
  nothing. A `sub` linked to another account is refused and never moved.
  Both audit as `oauth_callback_failed` with error class `LinkRefusal`
  and the code `identity_not_linked` or `link_initiator_mismatch`.
- Link is two-phase. The callback verifies the identity and records a pending
  link (TTL `completionTtlSeconds`), answering `status: "link_pending"` with a
  `pendingLinkId` and no session; it writes no linked identity. The app calls
  `POST /v1/apps/:appSlug/links/confirm` with `{ pendingLinkId }` and the
  Heimdall access token of the account that began the link; only that call
  attaches the identity. A different account, an expired, used or unknown id
  answers 410; a `sub` another account holds by then answers 409. A refused
  confirm does not consume the link.
- A sign-in callback evaluates every linked identity of the account with the
  start-time entitlement policy, so a member returning through Google keeps
  what Discord or Patreon grant.
- Configure with `GC_ACCESS_PROVIDER_GOOGLE_CLIENT_ID` and
  `GC_ACCESS_PROVIDER_GOOGLE_CLIENT_SECRET_FILE`. Admitted to the `bifrost`
  app profile only.

### `GET /v1/oauth/{provider}/callback`

Purpose:

- validate signed OAuth `state`
- complete the provider callback flow
- hand browser callers back to the app through a one-time completion exchange

Current status:

- validates signed `state` (signature, issuer, provider, expiry), requires the
  binding cookie the launch hop set, and consumes the state: a second callback
  is `400 state_already_used`, a missing or foreign cookie `400 state_not_bound`,
  an expired state `400 state_expired`; the binding is checked before the claim,
  so a browser without the cookie cannot burn the launching browser's state
- returns provider errors cleanly
- for Discord, exchanges the authorization code, resolves the provider
  identity, persists the local account/link/session/audit records, evaluates
  Repixelizer entitlement facts, and issues a signed Heimdall access claim
- when `handoff.kind=backend_callback`, delivers the auth result directly to
  the app backend and renders a tiny browser status page that can close itself
- when `handoff.kind=browser_completion` or handoff is omitted, keeps the older
  one-time completion-code flow as a fallback path
- if opener handoff is used and fails, the completion page still offers a
  fallback return link carrying only the one-time completion code, not the
  access token
- GitHub still returns "not implemented" at the runtime adapter layer until its
  callback path is added

Success response for backend-callback handoff now includes:

```json
{
  "delivery": {
    "kind": "backend_callback",
    "attemptId": "auth-attempt-123",
    "callbackUrl": "https://repixelizer.gamecult.org/api/auth/heimdall/callback",
    "status": "delivered"
  },
  "account": {
    "id": "acct_repixelizer_001",
    "displayName": "Meta"
  },
  "session": {
    "accountId": "acct_repixelizer_001",
    "sessionId": "uuid",
    "appSlug": "repixelizer",
    "accessRevision": 1,
    "expiresAt": "2026-05-26T12:00:00.000Z"
  },
  "accessToken": "<short-lived-signed-jwt>",
  "refreshToken": "<longer-lived-signed-jwt>",
  "refresh": {
    "expiresAt": "2026-05-26T12:00:00.000Z"
  }
}
```

Success response for browser-completion fallback still includes:

```json
{
  "completion": {
    "code": "<one-time-code>",
    "expiresAt": "2026-04-26T12:05:00.000Z",
    "redeemEndpoint": "https://heimdall.gamecult.org/v1/apps/repixelizer/auth-completions/redeem"
  }
}
```

### Backend callback delivery payload

Purpose:

- push the final auth result directly into the app backend without asking the
  browser to courier it

Current payload shape on success:

```json
{
  "source": "heimdall",
  "kind": "oauth_result",
  "handoffKind": "backend_callback",
  "attemptId": "auth-attempt-123",
  "status": "success",
  "provider": "discord",
  "appSlug": "repixelizer",
  "mode": "sign_in",
  "returnTo": "https://repixelizer.gamecult.org/app/",
  "connection": null,
  "account": {
    "id": "acct_repixelizer_001",
    "displayName": "Meta"
  },
  "session": {},
  "accessToken": "<signed-jwt>",
  "refreshToken": "<signed-refresh-jwt>",
  "refresh": {
    "expiresAt": "2026-05-26T12:00:00.000Z"
  },
  "claimSet": {},
  "verification": {},
  "sharedCapabilities": ["app_access", "queue_submit"],
  "hybridCapabilities": [],
  "entitlements": {
    "facts": ["entitlement.app_access"],
    "snapshots": []
  }
}
```

Current payload shape on failure:

```json
{
  "source": "heimdall",
  "kind": "oauth_result",
  "handoffKind": "backend_callback",
  "attemptId": "auth-attempt-123",
  "status": "error",
  "provider": "discord",
  "appSlug": "repixelizer",
  "mode": "sign_in",
  "returnTo": "https://repixelizer.gamecult.org/app/",
  "connection": null,
  "error": "oauth_callback_failed",
  "errorDescription": "..."
}
```

Important behavior:

- app backends should treat this as the preferred same-host or
  Yggdrasil-reachable integration path
- app backends should still verify the included Heimdall `accessToken` locally
- the browser only needs to learn attempt completion, not carry the final auth
  result

### `POST /v1/apps/{appSlug}/auth-completions/redeem`

Purpose:

- redeem a short-lived one-time browser completion code
- return the trusted Heimdall auth result to the app backend

Current role:

- fallback path for looser integrations, manual testing, or opener-based flows
- not the preferred same-host consumer path anymore

Request body:

```json
{
  "completionCode": "<one-time-code>"
}
```

Binding rules:

- A completion minted for a connection target (`connection.targetId` in the signed state) is redeemed only with `targetId` equal to it; absent or different answers `403 completion_target_mismatch` and leaves the code unconsumed.
- A `link` completion is redeemed only by the authenticated app backend (`x-heimdall-app-secret`); otherwise `401 app_auth_required`, code unconsumed. `link` start itself needs that authentication and `initiatingAccountId`; the callback refuses with `403 link_initiator_mismatch` when the provider identity belongs to a different account, and attaches an unlinked identity to the initiator.

Response:

```json
{
  "status": "success",
  "provider": "discord",
  "mode": "sign_in",
  "appSlug": "repixelizer",
  "account": {
    "id": "acct_repixelizer_001",
    "displayName": "Meta"
  },
  "session": {
    "accountId": "acct_repixelizer_001",
    "sessionId": "uuid",
    "appSlug": "repixelizer",
    "accessRevision": 1,
    "expiresAt": "2026-05-26T12:00:00.000Z"
  },
  "accessToken": "<signed-jwt>",
  "refreshToken": "<signed-refresh-jwt>",
  "refresh": {
    "expiresAt": "2026-05-26T12:00:00.000Z"
  },
  "claimSet": {},
  "verification": {
    "issuer": "https://heimdall.gamecult.org",
    "jwksUri": "https://heimdall.gamecult.org/.well-known/jwks.json",
    "alg": "EdDSA",
    "kid": "ed25519-..."
  },
  "sharedCapabilities": ["app_access", "queue_submit"],
  "hybridCapabilities": []
}
```

Important behavior:

- completion codes are one-time use
- completion codes are short-lived
- app backends should redeem them server-side
- the browser should not keep the final access token in callback URL fragments

### `POST /v1/apps/{appSlug}/sessions/refresh`

Purpose:

- reissue a short-lived app access claim from a longer-lived Heimdall refresh
  token
- let app backends recover from an expired local access cookie without sending
  the user through provider OAuth again
- keep provider access/refresh custody and entitlement refresh inside Heimdall

Request body for Repixelizer:

```json
{
  "refreshToken": "<signed-refresh-jwt>",
  "entitlementPolicies": [
    {
      "kind": "discord_role_access",
      "guildId": "gamecult-guild",
      "allowedRoleIds": ["role-repixelizer"]
    },
    {
      "kind": "patreon_membership_access",
      "requiredTierTitle": "Inner Sanctum"
    }
  ]
}
```

Response:

```json
{
  "session": {
    "accountId": "acct_repixelizer_001",
    "sessionId": "uuid",
    "appSlug": "repixelizer",
    "accessRevision": 1,
    "expiresAt": "2026-05-26T12:00:00.000Z"
  },
  "accessToken": "<fresh-signed-access-jwt>",
  "refreshToken": "<fresh-signed-refresh-jwt>",
  "refresh": {
    "expiresAt": "2026-05-26T12:00:00.000Z"
  },
  "sharedCapabilities": ["app_access", "queue_submit"],
  "hybridCapabilities": []
}
```

Important behavior:

- the refresh token is signed by Heimdall and scoped to one app session
- the access token remains short-lived; app backends still verify it locally
- if a stored provider access token is expired or near expiry, Heimdall takes
  a row lock on the linked identity, re-reads it, uses the stored provider
  refresh token and persists any rotation before evaluating entitlements; an
  identity whose grant the provider has revoked (no stored access token)
  contributes no entitlement
- any app authenticated via `x-heimdall-app-secret` (`resolveAppCaller`) may
  send `entitlementPolicies`; Heimdall matches each stored identity to the
  policy for that provider. Sending policy without authenticating is
  `401 app_auth_required` -- there is no per-slug allow-list for this anymore
- the endpoint is not a provider OAuth start path and should not produce a
  provider authorization URL

### `GET /v1/me/identities`

The identities the signed-in account holds, for a member's own view.

Authentication: a live Heimdall access token for any app as
`Authorization: Bearer` (the same check as `/v1/me/grants`). `401
sign_in_required` otherwise. The answer is `Cache-Control: no-store`.

```json
{
  "accountId": "uuid",
  "identities": [
    {
      "id": "uuid",
      "provider": "twitch",
      "providerUserId": "12345",
      "username": "name",
      "displayName": "Name",
      "linkedAt": "2026-11-13T12:00:00.000Z",
      "scopes": ["user:read:email"]
    }
  ]
}
```

`username` and `displayName` are present when the provider gave them. The
answer never carries a token column, the stored provider profile or the
account's email.

### `POST /v1/me/identities/{identityId}/unlink`

Takes one identity off the signed-in account. It is the only way a linked
identity is deleted, and it never takes the account's last one.

Authentication: a live Heimdall access token for any app, and fresh proof. The
body is empty or `null`.

- `401 sign_in_required`: no live bearer.
- `403 step_up_required`: the access token carries no `step_up_at` claim, or it
  is in the future, or it is older than 600 seconds
  (`STEP_UP_PROOF_TTL_SECONDS`, `src/claims.ts`). The remedy is a `sign_in`
  start with `stepUp: true` (see step-up above) through an identity on the
  account whose provider has re-authentication parameters, today twitch,
  youtube and google, then the access token that sign-in returns.
- `404 identity_not_found`: no such identity, or one that belongs to another
  account. The two are not distinguishable.
- `409 last_identity`: the account holds no other identity.
- `200`: `{"unlinked": {"id", "provider", "providerUserId"}, "identities": [...]}`
  with the remaining list in the shape above.

`step_up_at` (epoch seconds) is set on the access claim only when the callback's
signed state has `step_up` true and mode `sign_in`, or by an app's `POST
/v1/apps/{appSlug}/step-up` assertion (below). A refresh never carries it:
tokens a refresh issues cannot unlink, so proof is renewed only by a new step-up
sign-in. The unlink writes the audit event `identity_unlinked` (provider and
identity id only). When the account then holds no identity of that provider, the
revocation receipts for its live grants of that provider are written, as the
grants revoke route writes them.

A Twitch step-up proof is weaker than YouTube's or Google's: `force_verify` does
not force credential re-entry (see the step-up note under the OAuth start
section, "The strengths differ").

Limits that stay:

- Access tokens issued before the unlink keep the unlinked identity in their
  `identities` claim and its facts until they expire (`sessionTtlSeconds`).
- Discord and Patreon identities cannot give proof (no re-authentication
  parameter); an account holding only those cannot unlink.
- A stolen access token minted by a step-up sign-in can unlink more than one
  identity during its 600 second window.
- A sign-in through a provider whose identity is no longer linked mints a new
  account.

A link no longer moves an identity: `upsertLinkedIdentity` refuses an identity
another account holds (`links/confirm` answers `409 identity_linked_elsewhere`,
the callback `link_initiator_mismatch`). An unlinked identity belongs to no
account and can be linked by any account through the normal link flow.

### `POST /v1/apps/{appSlug}/step-up`

An app asserts that a member just passed a factor the app itself checked (for
Bifrost: a passkey assertion or an emailed code), and receives an access token
that carries that proof. The unlink route's step-up check then passes unchanged.

Authentication: both, always.

- the app's secret in `x-heimdall-app-secret`, as for every app route; and
- the member's live Heimdall access token for the same app as
  `Authorization: Bearer`.

Body (`additionalProperties` are dropped as on the sibling routes):

```json
{ "method": "bifrost-passkey", "nonce": "16 to 128 characters, fresh per assertion" }
```

Nonce: 16 to 128 characters of the base64url alphabet (`A-Za-z0-9_-`), so a
random token fits and spaces, controls and lone surrogates are a 400 schema
refusal. `method` is 1 to 64 characters and then must be in the profile's set.

Schema validation (body shape, `method` length, the nonce pattern and length,
the app slug) runs before the secret is checked and answers `400` with
Fastify's fixed schema error, the same for every caller whatever the secret and
never audited. Then the order of refusals, each a closed `error` code:

- `401 app_auth_required`: missing, wrong or another app's secret. The first
  check of the handler; nothing is written.
- `403 step_up_assertion_not_permitted`: the app's profile has no
  `stepUpAssertion` grant. Only `bifrost` has one; every other app is refused
  with its own secret. This branch has its own small budget (5 per 60 s per
  app); past it the answer is 429.
- `429 step_up_rate_limited` (`retryAfterSeconds`): the per-app budget (120 per
  60 s, spent by every attempt that passed the secret and the grant, including
  ones whose bearer then fails) is spent. In-process fixed windows: they reset
  when the process restarts and are not shared between instances.
- `401 sign_in_required`: the bearer is missing, malformed, expired, signed by
  another key, a refresh token, or rests on a session that is not live (no row,
  wrong account, revoked or expired, revision moved). One answer for all of
  them; it does not say whether an account exists.
- `403 bearer_app_mismatch`: a live bearer issued to another app. An app cannot
  assert for a token issued to another app. It tells only a holder of the
  secret and a valid bearer that the bearer is live and for another app, which
  that holder already knows.
- `429 step_up_rate_limited`: the per-account budget (10 per 600 s) is spent.
  It is checked after the bearer and its audience, before method and nonce.
- `400 unknown_step_up_method`: `method` is not in the profile's closed set
  (`methods` in the answer lists it). Bifrost: `bifrost-passkey`,
  `bifrost-email-code`. Provider labels (`provider:*`) cannot be asserted.
- `409 step_up_nonce_replayed`: that nonce was already spent for this session.
  The claim is the store's `oauth_state_uses` single-use primitive with phase
  `step_up_assert` and the key a SHA-256 of session id and nonce, so it holds
  across restarts and instances. **Retention is the session's expiry as of the
  claim plus 10.5 minutes (the 10 minute prune margin and 30 s clock skew), and
  pruning is lazy: each successful claim deletes at most 50 expired rows.** A refresh slides the session's expiry
  without bound, so a nonce can be pruned while its session is still live and
  then be accepted again. Replaying it still needs the secret and a live
  bearer, which is the power to assert with a fresh nonce; the nonce guards a
  captured request, not a compromised app. A refused method or a rate-limited
  attempt does not spend the nonce.
- `201`: `{"accessToken", "claimSet", "stepUp": {"at", "method", "validForSeconds"}}`,
  `Cache-Control: no-store`.

What the minted token is: a copy of the bearer's claims with a new `jti`,
`iat` and `nbf`, `step_up_at` = now and `step_up_method` = the asserted method.
It keeps the bearer's `exp`, same `sid` and account. Facts, capabilities and
identities are the bearer's and are not recomputed, so the route adds proof and
no capability. It mints no refresh token and writes no session row: it cannot
extend a lifetime or a session. A later refresh carries neither claim. The proof
is good for the usual 600 seconds (`STEP_UP_PROOF_TTL_SECONDS`) and only until
the token's own `exp`.

Receipts: each assertion writes the audit event `step_up_asserted`, and each
refusal after the secret verified writes `step_up_assertion_refused`, except
that two kinds are not recorded row by row: a rate-limited refusal is recorded
once per window per budget (its first; the row's `budget` names `app`,
`account` or `notPermitted`), and an app without the grant once per window.
Every other refusal under budget still writes a row each, up to about 121 a
minute for a holder of the secret, and `audit_events` has no retention: that is
an open follow-up. Rows carry the
app, the account and session when the bearer resolved, `method` (null when it
was not in the allowlist), `outcome`, `code`, `budget` (rate-limit rows) and `nonceDigest`. Never the
secret, the bearer, the minted token or the nonce. A request without the secret,
or failing schema validation, writes nothing.

Precondition: the route is usable only once the app holds the member's Heimdall
bearer. Bifrost deliberately does not hold it today. Putting the bearer in a
cookie ticket would turn cookie theft into bearer theft and, with
`bifrost-passkey` or `bifrost-email-code`, into unlink power; whether and how
Bifrost keeps the bearer is its own decision and is not made here.

Unlink accepts any method today. A `bifrost-email-code` proof unlinks an
identity a Google re-authentication would have guarded. Identity moves
(below) are the first route to require a method for whole-account coverage;
unlink is unchanged.

What this does not prove: Heimdall cannot see the passkey or the code. It trusts
the calling app's word, exactly as it trusts `stepUpRequested` (asked, not
verified). The word is bounded by the app secret, a live member bearer for that
app, the profile's method allowlist, a single-use nonce, the proof window and
the rate limits. A compromised Bifrost can assert proofs only for members whose
live bearer it holds. `identity_unlinked` records the proof's `stepUpMethod`
(`provider:<name>`, an app label, or null), and unlink does not yet require any
particular method.

### `POST /v1/apps/{appSlug}/identity-moves`

The one sanctioned way a login changes account (`moveIdentities` is the only
writer of `linked_identities.account_id`). Bifrost owns the merge: survivor
choice, preview, grace and undo timing. Heimdall receives the choice as which
proofs fill which side, renders no preview and picks nothing. Only a profile with
`identityMoves` may call it (today bifrost).

Credential: the app's secret. Body (closed; unknown properties are ignored, and
no account is ever named by the body):

- `moveId` (`^[A-Za-z0-9_-]{16,64}$`): the caller's idempotency key.
- `fromProofs`: 1 to 8 live Heimdall access tokens for this app, all of the
  source account.
- Forward move: `toProof` (a live token of the destination) and optionally
  `identityIds` (1 to 32; default every login the source holds).
- Reversal: `reversesMoveId` instead of `toProof`/`identityIds`. It moves back
  exactly the logins the forward move carried, once; `fromProofs` must be of the
  forward move's destination. A reversal is not itself reversible.

Each proof must be fresh: a step-up inside 600 s (`strong`) or a sign-in inside
300 s (`weak`), by `proofTier`, the same freshness rule the unlink route reads.
A token with neither claim (a refresh, a link) is stale.

Coverage: a proof through login X (`auth_identity_id`) moves X and nothing else
from that account. Only a strong proof asserted with a method in the profile's
`identityMoves.accountProofMethods` (`bifrost-passkey`; not `bifrost-email-code`,
which proves an inbox) speaks for the whole account. Moving several logins takes
one proof per login, or the passkey.

Order of refusals, each a fixed code: `401 app_auth_required`; `403
not_allowed_for_app`; a replayed `moveId` is answered next (below); `409
not_reversible` (reversal names a missing, foreign or reversal move); `403
proof_invalid` `{proof: "from"|"to"}` (not a live bearer of this app, or
`fromProofs` naming two accounts); `409 same_account`; `403 proof_stale`
`{proof}`; `403 identity_not_proved`; then the store: `403 proof_invalid` (a
proof session lapsed under the lock), `409 already_moved` (either side is an
alias), `409 provider_conflict` `{provider}`, `409 not_reversible`, `409
move_id_conflict`, `404 identity_not_found`, `403 identity_not_proved`. A refusal
body is `{error, detail?, proof?, provider?}` and never names an account id, an
identity the caller did not send, an email or a name.

On success, in one transaction: the logins move to the destination with their
stored credentials stripped; every live session of the source is revoked and its
pending links and unredeemed completions expire; one append-only `identity_moves`
row is written. Afterwards, for each moved provider the source no longer holds,
its live grants get revocation receipts under the source, and `identity_moved`
is audited. Answer `200`, `Cache-Control: no-store`:
`{moveId, accountId: <destination>, movedIdentityIds, proof: {from, to}, reversesMoveId?}`,
with `proof.from` `strong` if any from-proof was strong and `to` null on a
reversal.

Idempotency: the same `moveId` with the same app, accounts and `reversesMoveId`
answers the stored receipt byte for byte, even though the first success revoked
the source's sessions: the proofs are then checked for a valid Heimdall
signature, issuer, type and audience, and account, not for liveness. The replay
re-runs the revocation receipts, so a crash between commit and receipts heals on
the caller's retry. Anything else under a used `moveId` is `409 move_id_conflict`.

What a move leaves: an account holding no login with an unreversed move from it
is an alias of the move's destination (derived by `resolveAccount`, never
stored; one hop). A move into or out of an alias is `already_moved`. Bearers of
the destination keep their old identity list until they refresh. A sign-in
through a moved login lands on the destination because the row moved.

### `POST /v1/apps/{appSlug}/managed-credentials/resolve`

Purpose:

- let an app backend retrieve the current Heimdall-custodied access token for
  a managed provider connection
- keep refresh-token custody inside Heimdall instead of app persistence

Authentication:

- requires `x-heimdall-app-secret`
- the configured secret comes from the credential file named by
  `GC_ACCESS_APP_{APP_SLUG}_SHARED_SECRET_FILE`, per app; there is no generic
  fallback secret shared across apps

Request body:

```json
{
  "accountId": "acct_spotiverse_001",
  "provider": "spotify"
}
```

Response:

```json
{
  "accountId": "acct_spotiverse_001",
  "provider": "spotify",
  "providerUserId": "spotify-user-123",
  "accessToken": "<provider-access-token>",
  "tokenExpiresAt": "2026-06-02T13:00:00.000Z",
  "scopes": ["user-read-playback-state", "user-modify-playback-state"]
}
```

Important behavior:

- this endpoint only works for providers listed in the app profile's
  `managedConnectionProviders`
- it returns access tokens only; refresh tokens remain in Heimdall custody
- when a stored managed credential is expired or within the refresh window,
  Heimdall refreshes it before returning the access token and persists rotated
  access/refresh tokens. The refresh runs under a row lock on the linked
  identity (`SELECT ... FOR UPDATE`), so a given refresh token is presented to
  the provider once across concurrent requests and across two Heimdall
  processes sharing one database. Within one process, concurrent refreshes of
  one identity share a single attempt and its outcome (success or failure). A
  failed or timed-out attempt is recorded on the identity row
  (`refresh_failed_at`, written in the same transaction as the lock), and no
  process presents that row's refresh token again for 60 seconds: a process
  that takes the lock inside the backoff answers the same
  `managed_credential_refresh_failed` without calling the provider. A stamp
  more than 60 seconds in the future (a writer whose clock runs ahead) is skew,
  not a fresh failure, so the wait is capped at twice the backoff. A rotation,
  a revocation or a re-link clears the marker.
  The marker is a best-effort write on a second connection, made after the
  lock's transaction rolled back; it is not part of that transaction. When the
  rotation or the revocation the provider's answer called for cannot be
  committed, the fallback write leaves the marker and blanks the refresh token
  only when that token is spent: on a revoke (a rotating provider answered
  without a refresh token, or the grant was rejected), or when the provider
  rotates refresh tokens (Joystick) and so consumed it. A provider that keeps
  its refresh token valid (Twitch) keeps it, so a transient database failure
  does not strand the link: the next caller after the backoff presents it again.
  Residual risk: the provider may consume the refresh token as soon as the
  request is sent. If a Heimdall process dies after that and before the commit
  of the marker, the rotation or the revocation, or if the blanking fallback
  write fails too, nothing is recorded, and the
  next caller can present the refresh token the provider already consumed; for
  a provider that rotates (Joystick) that reads as token theft. The Heimdall
  steward ruled (#minds, 2026-11-08) that an intent log, written on its own
  connection before the provider call, replaces this marker; it is tracked in
  `joystick:follow_up:write-ahead-refresh-attempt-record`.
  The provider call is bounded at 10 seconds.
- a provider whose refresh tokens rotate (Joystick) fails closed: a refresh
  response without a new refresh token revokes the credential instead of
  keeping the old token
- `410 {"error":"managed_credential_revoked","provider":...}`: the provider
  rejected the grant (HTTP 400 whose OAuth `error` is exactly `invalid_grant`),
  or the identity holds no access token.
  The stored tokens are cleared and an audit event `managed_credential_revoked`
  is written; the owner must reconnect. `404 managed_credential_not_found`
  means no linked identity exists
- `502 {"error":"managed_credential_refresh_failed","provider":...}`: the
  refresh failed for any reason that is not a grant verdict (invalid client,
  a 401 or 5xx whatever its body says, timeout, a 2xx without a string
  `access_token` or carrying an `error`, a `refresh_token` that is present but
  not a string, an empty or non-JSON body). Stored tokens are untouched and a
  later request may succeed. An empty-string `refresh_token` counts as missing,
  so a rotating provider revokes (`rotation_missing`). A token answer without a
  usable `expires_in` (absent, non-numeric, or not a positive number or
  positive-integer string) stores the expiry as now plus the provider's default
  access-token lifetime (3600 seconds), so an expiry is never unknown and the
  credential always comes due for refresh
- app-local binding, diagnostics, subscription setup, and runtime behavior stay
  app-owned

### Reference local verifier seam

Purpose:

- give app backends a tiny local verification helper instead of encouraging
  per-request Heimdall callbacks

Current reference helper:

- `src/verifier.ts`

Current helper contract:

- build the verifier once from Heimdall `issuer`, app slug, and JWKS
- verify Ed25519 signature locally by `kid`
- reject wrong `iss`, wrong `aud`, malformed claim shape, `nbf` violations,
  and expired tokens
- accept a small clock-skew window for normal same-host reality

This is a reference seam, not a magical shared middleware product yet.

## Access claim shape

Current claim payload fields:

- `iss`
- `aud`
- `sub`
- `sid`
- `jti`
- `iat`
- `nbf`
- `exp`
- `typ`
- `account_id`
- `access_revision`
- `step_up_at` optional: epoch seconds of the proof; set only by a `sign_in` step-up callback or `POST /v1/apps/{appSlug}/step-up`, never by a refresh
- `step_up_method` optional: present exactly when `step_up_at` is; `provider:<name>` for a provider step-up sign-in, otherwise the method label the app asserted
- `auth_at` optional: epoch seconds of the sign-in this token was minted by; set only by a `sign_in` callback (never link, connect or refresh), always with `auth_identity_id`
- `auth_identity_id` optional: the `linked_identities.id` that sign-in came through; the only record of which login proved the session. An asserted step-up spreads the bearer's claims, so these pass through unchanged
- `display_name` optional
- `app.slug`
- `app.profile_version`
- `facts`
- `capabilities`
- `identities`

Important current rule:

- Heimdall only grants fully shared capabilities directly
- hybrid capabilities still require app-local checks after claim verification
- claim facts should prefer app-facing entitlement names over provider-branded
  trivia when a provider-specific detail is not actually needed by the
  consumer

Examples:

- Repixelizer `app_access` and `queue_submit` are shared
- Repixelizer `job_read_own` still needs local ownership
- StreamPixels `viewer_access` can be shared
- StreamPixels `creator_access` still needs app-local creator membership

## Current gaps

The following are not landed yet:

- admin/grant management surfaces
- GitHub callback runtime
- redacted per-account auth witness export and Odin/CultMesh consumption beyond
  the landed boundary/plugin advertisement store

## Private CultNet authentication commands

The live daemon also binds a loopback-only CultNet/RUDP operation service at
`127.0.0.1:4101` by default. Odin may advertise the route, but never proxies or
persists its payloads.

- service: `heimdall.private.commands`
- operations: `heimdall.auth.begin`, `heimdall.auth.complete`,
  `heimdall.auth.refresh`, `heimdall.auth.logout`
- request envelope: `heimdall.private_command_envelope.v1`
- begin result: `heimdall.auth_begin_receipt.v1`
- completion result: `heimdall.auth_completion_receipt.v1`
- refresh result: `heimdall.auth_refresh_receipt.v1`
- logout result: `heimdall.auth_logout_receipt.v1`

Requests are accepted only from a configured app runtime and use the existing
per-app shared secret. Expiry, nonce, operation, app, and idempotency identity
are authenticated. MessagePack payloads and sensitive completion results are
AES-256-GCM wrapped with a fresh nonce. A repeated idempotency key returns the
same result only for the exact same authenticated request; content changes are
denied. Completion consumption remains single-use in Heimdall's canonical
store.

Refresh claims are admitted only while their exact persisted session,
app/account custody, access revision, and refresh expiry still match. Logout
uses the refresh claim as custody proof and atomically advances the persisted
access revision while expiring the session. A stale or concurrently superseded
refresh cannot recreate the revoked session.

`gamecult.heimdall.access` exposes pure plugin ABI operations on the same
loopback listener. Those operations describe, validate, or project access UI;
they cannot create attempts, mint claims, or establish an app session.

## Odin/Eve provider advertisement

Purpose:

- advertise Heimdall's redacted provider, plugin, and command-boundary surfaces
  for Odin discovery
- name the redacted CultCache witness document schemas and future `.cc` paths
- avoid touching provider secrets, token custody, store migrations, or runtime
  mutation paths

Command:

```powershell
pnpm export:provider-advertisement
```

Current output shape:

- `schemaVersion`: `gamecult.eve.provider_advertisement.v1`
- `providerId`: `heimdall`
- `status`: `read_only_witness_planned`
- provider catalog entries for Discord, Patreon, GitHub, Twitch, YouTube, and
  Spotify
- app profile projections for Repixelizer, StreamPixels, and Spotiverse
- redacted witness descriptors for accounts, linked identities, grants,
  sessions, entitlement snapshots, auth completions, audit events, app profiles,
  and managed credential projections

Important behavior:

- this is a projection/export command, not a writer
- advertised witness paths are future CultCache targets, not proof that a live
  `.cc` exporter is already running
- exported descriptors forbid raw provider tokens, encrypted token blobs,
  completion codes, callback secrets, and app-domain state

## Next implementation move

Deploy and verify the hardened slice in the first real app binding:

- run Discord and Patreon Repixelizer auth with real provider credentials
- confirm direct backend callback delivery to Repixelizer
- confirm Repixelizer verifies the Heimdall access token locally and gates
  hosted routes from the adopted session
- configure Repixelizer access policy in Repixelizer's own runtime env:
  Discord should accept `KLTST` or the Patreon-synced `Inner Sanctum` role,
  and Patreon should accept the currently entitled tier title `Inner Sanctum`
