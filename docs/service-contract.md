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
- `GC_ACCESS_SIGNING_PRIVATE_KEY_PEM` still works for direct secret injection
- `GC_ACCESS_SIGNING_PRIVATE_KEY_PATH` lets the service load a persisted key
  from disk
- if the path is missing and `GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP=1`, the
  service bootstraps a new key file on first start
- if neither PEM nor path is configured, the service still generates an
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
- `claimIssueEndpoint`
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
  "authorizationUrl": "https://discord.com/oauth2/authorize?...",
  "stateToken": "<signed-jwt>",
  "stateExpiresAt": "2026-04-26T12:10:00.000Z"
}
```

Failure mode right now:

- `503 provider_not_configured` when the provider client id is missing

Launch note:

- Discord and Patreon are the implemented provider runtimes for Repixelizer
- Twitch and YouTube now have generic OAuth exchange and identity runtimes for
  StreamPixels viewer auth and managed creator connections
- GitHub is still catalogued for start URLs, but its callback runtime is not
  implemented yet
- Repixelizer launch can configure Discord and Patreon on its provider buttons

### `GET /v1/oauth/{provider}/callback`

Purpose:

- validate signed OAuth `state`
- complete the provider callback flow
- hand browser callers back to the app through a one-time completion exchange

Current status:

- validates signed `state`
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
- if a stored provider access token is expired or near expiry, Heimdall uses
  the stored provider refresh token and persists any rotation before
  evaluating entitlements
- Repixelizer may send all of its app-owned provider policies; Heimdall matches
  each stored identity to the policy for that provider
- the endpoint is not a provider OAuth start path and should not produce a
  provider authorization URL

### `POST /v1/apps/{appSlug}/managed-credentials/resolve`

Purpose:

- let an app backend retrieve the current Heimdall-custodied access token for
  a managed provider connection
- keep refresh-token custody inside Heimdall instead of app persistence

Authentication:

- requires `x-heimdall-app-secret`
- the configured secret comes from `GC_ACCESS_APP_{APP_SLUG}_SHARED_SECRET` or
  the generic `GC_ACCESS_APP_SHARED_SECRET`

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
  access/refresh tokens
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

### `POST /v1/apps/{appSlug}/claims/issue`

Purpose:

- issue a signed Heimdall access claim for one app after identity/grant facts
  have already been resolved

This is currently the concrete claim contract and integration seam for early app
binding work.

Request body:

```json
{
  "accountId": "acct_repixelizer_001",
  "displayName": "Meta",
  "facts": ["entitlement.app_access", "grant.operator"],
  "linkedIdentities": [
    {
      "provider": "discord",
      "providerUserId": "123456789",
      "username": "meta"
    }
  ],
  "accessRevision": 1,
  "ttlSeconds": 3600
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
  "sharedCapabilities": ["app_access", "queue_submit", "admin_access"],
  "hybridCapabilities": []
}
```

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

- revocation flows
- admin/grant management surfaces
- GitHub callback runtime

## Next implementation move

Deploy and verify the hardened slice in the first real app binding:

- run Discord and Patreon Repixelizer auth with real provider credentials
- confirm direct backend callback delivery to Repixelizer
- confirm Repixelizer verifies the Heimdall access token locally and gates
  hosted routes from the adopted session
- configure Repixelizer access policy in Repixelizer's own runtime env:
  Discord should accept `KLTST` or the Patreon-synced `Inner Sanctum` role,
  and Patreon should accept the currently entitled tier title `Inner Sanctum`
