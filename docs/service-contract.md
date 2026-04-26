# Heimdall Service Contract

This file describes the first landed Heimdall service skeleton.

It is the concrete HTTP/JWKS contract that now exists in the repo. It is not a
claim that provider token exchange, persistence, or app bindings are fully
implemented yet.

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
- serve as the landing surface for future code/token exchange

Current status:

- validates signed `state`
- returns provider errors cleanly
- returns `501 token_exchange_not_implemented` after successful state/code
  validation

That is deliberate. The contract is landed; provider token exchange and account
persistence are next.

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
  "facts": ["discord.allowed_role", "grant.operator"],
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

Examples:

- Repixelizer `app_access` and `queue_submit` are shared
- Repixelizer `job_read_own` still needs local ownership
- StreamPixels `viewer_access` can be shared
- StreamPixels `creator_access` still needs app-local creator membership

## Current gaps

The following are not landed yet:

- provider token exchange on callback
- durable account/session/grant storage
- linked-identity persistence
- entitlement snapshot persistence
- refresh/revocation flows
- app-facing middleware packages or reference verifiers

## Next implementation move

Build durable storage plus the first real provider path on top of this
skeleton:

- persisted signing key material
- accounts and linked identities
- real callback exchange for one provider slice
- first end-to-end Repixelizer binding
