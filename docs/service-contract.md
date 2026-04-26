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
  "now": "2026-04-26T12:00:00.000Z"
}
```

### `GET /.well-known/jwks.json`

Purpose:

- publish the public signing key that app backends use to verify Heimdall JWTs

Notes:

- current skeleton signs with Ed25519
- if `GC_ACCESS_SIGNING_PRIVATE_KEY_PEM` is absent, the service generates an
  ephemeral dev key at startup
- production should use a persisted private key and stable `kid`

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

Request body:

```json
{
  "appSlug": "repixelizer",
  "mode": "sign_in",
  "returnTo": "https://repixelizer.gamecult.org/app/",
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
- for browser-style callers, renders a Heimdall-hosted completion page that
  posts a one-time completion code back to the opener and tries to close
  itself
- if opener handoff fails, the completion page still offers a fallback return
  link carrying only the one-time completion code, not the access token
- for non-browser callers, returns JSON with the issued claim/session data plus
  completion metadata
- other configured providers still return "not implemented" at the runtime
  adapter layer until their callback paths are added

Success response for non-browser callers now includes:

```json
{
  "completion": {
    "code": "<one-time-code>",
    "expiresAt": "2026-04-26T12:05:00.000Z",
    "redeemEndpoint": "https://heimdall.gamecult.org/v1/apps/repixelizer/auth-completions/redeem"
  }
}
```

### `POST /v1/apps/{appSlug}/auth-completions/redeem`

Purpose:

- redeem a short-lived one-time browser completion code
- return the trusted Heimdall auth result to the app backend

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
    "expiresAt": "2026-04-26T13:00:00.000Z"
  },
  "accessToken": "<signed-jwt>",
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
    "expiresAt": "2026-04-26T13:00:00.000Z"
  },
  "accessToken": "<signed-jwt>",
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

- non-ephemeral signing key handling
- actual token encryption at rest and secret-management policy
- refresh/revocation flows
- app-facing middleware packages or reference verifiers
- admin/grant management surfaces

## Next implementation move

Build the first consumer seam and harden the custody story:

- persisted signing key material
- real token encryption at rest
- a reference verifier / middleware contract for app backends
- the first Repixelizer consumer binding that trusts Heimdall claims locally
