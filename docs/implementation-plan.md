# Heimdall Implementation Plan

## What this file is

This file is the forward plan and active hypothesis ledger for Heimdall.

It is not the canonical shared architecture note. That lives in
`docs/architecture.md`.

If the code or the architecture note disagrees with this plan, trust the code
and the architecture note first, then fix this file.

## Current machine

There is now a first landed Heimdall skeleton.

What exists right now is:

- the shared architecture note
- the concrete service contract in `docs/service-contract.md`
- app-binding notes for Repixelizer and StreamPixels
- a standalone TypeScript/Fastify service skeleton under `src/`
- Ed25519 JWT signing plus JWKS/discovery exposure
- OAuth start/callback contract surfaces with signed `state`
- app-profile-driven claim issuance for Repixelizer and StreamPixels
- in-memory/Postgres auth-control-plane storage
- persisted accounts, linked identities, sessions, grants, entitlement
  snapshots, and audit records
- a real Discord provider callback slice for Repixelizer access
- a direct backend callback handoff for same-host app integrations
- a one-time browser completion handoff so auth callback pages can post back to
  the opener instead of leaking final app auth in URL fragments, now retained
  as fallback rather than the preferred same-host path
- file-backed signing-key loading/bootstrap for stable service identity
- AES-256-GCM token sealing for managed provider credentials at rest
- a local verifier helper that app backends can use against Heimdall JWKS
- Repixelizer has consumed the direct backend callback flow in its hosted web
  layer and verifies Heimdall Ed25519 access tokens locally
- generic Twitch and YouTube OAuth callback runtimes for StreamPixels identity
  and managed creator connections
- an app-authenticated managed-credential resolve endpoint so StreamPixels can
  call provider APIs without storing refresh tokens locally
- managed Twitch/YouTube credentials refresh inside Heimdall before resolution
  when they are expired or near expiry
- StreamPixels now starts viewer and creator Twitch/YouTube OAuth through
  Heimdall, redeems one-time completion codes server-side, and keeps local
  profile/creator connector binding state in StreamPixels
- Heimdall is deployed on Yggdrasil at `https://heimdall.gamecult.org` with
  nginx/TLS, Postgres storage, stable file-backed signing, configured token
  custody, and public health/discovery/JWKS checks passing
- Repixelizer is deployed on Yggdrasil at
  `https://repixelizer.gamecult.org` with Heimdall mode enabled, Discord as the
  only public provider, required access, and queue protection
- explicit state/doctrine scaffolding so the plan does not immediately turn into
  soup

## Primary objective

Build Heimdall as a shared auth authority service that can:

- own provider OAuth and identity linking
- issue signed sessions and app-facing claims
- refresh Discord and Patreon entitlements
- evaluate per-app capability rules
- expose a clean contract to app backends without owning their domain data

## Current priorities

### 1. Lock the service boundary

Goals:

- keep Heimdall scoped to auth/control-plane machinery
- keep app-domain data in app-owned stores
- keep app profiles thin and explicit

### 2. Keep the contract tight while it goes live

Goals:

- define signed claim/session shapes
- define OAuth start/callback/link surfaces
- define grant and entitlement persistence boundaries
- define how app backends verify claims locally
  This now exists in reference form and Repixelizer has a Python consumer in
  its hosted web layer.

### 3. Launch Repixelizer with Discord first

Goals:

- deploy Heimdall on Yggdrasil with stable signing, encrypted token custody,
  and persistent Postgres storage
- configure the Discord OAuth app redirect URI to
  `https://heimdall.gamecult.org/v1/oauth/discord/callback`
- configure Heimdall's Discord client credentials for the Repixelizer-owned
  Discord OAuth app
- configure Repixelizer for `GC_ACCESS_MODE=heimdall` and
  `GC_ACCESS_ALLOWED_PROVIDERS=discord,patreon`
- configure Repixelizer's Discord access policy with its GameCult guild id and
  allowed role ids; Repixelizer sends that policy to Heimdall during the
  backend-callback OAuth start
- run the live browser OAuth flow and confirm Repixelizer receives the backend
  callback, verifies the claim locally, adopts a local session, gates hosted
  access, and stamps queued jobs with `account_id` / `session_id`

Deployment/configuration status:

- the deployment and service wiring are done
- public health/discovery/JWKS/config checks pass
- public Repixelizer auth-start returns Discord and Patreon authorization URLs
  using the Heimdall callback and Repixelizer backend handoff
- the Discord authorization URL requests only `identify guilds.members.read`
- the Patreon authorization URL requests only `identity identity[email]`
- the remaining launch check is the real interactive provider browser flow

Current Discord policy:

- Heimdall grants Repixelizer `entitlement.app_access` only when the Discord
  member has one of the role ids Repixelizer sent in its caller-owned
  entitlement policy
- launch policy is intentionally role-gated: the GameCult Discord can remain
  public, but Repixelizer access is limited to members with either `KLTST`
  or the Patreon-synced `Inner Sanctum` role

Current Patreon policy:

- Heimdall grants Repixelizer `entitlement.app_access` only when Patreon returns
  a currently entitled tier titled `Inner Sanctum`
- the policy is title-based, not amount-based

### 4. Migrate StreamPixels without flattening its good local seams

Goals:

- move provider/linking authority to Heimdall
- keep viewer profiles, creator memberships, connector bindings, diagnostics,
  runtime behavior, and audience data
  in StreamPixels
- keep creator/operator route authorization local to StreamPixels after claim
  verification

Landed:

- Heimdall handles Twitch/YouTube OAuth exchange and identity resolution
- Heimdall stores managed provider tokens and exposes current access-token
  resolution to app backends through an app shared secret
- StreamPixels delegates viewer claim/link and creator connector OAuth starts
  to Heimdall
- StreamPixels redeems completion codes through its service, then owns local
  viewer profile linking or creator connector binding

Still to verify:

- real browser StreamPixels viewer claim/link
- real creator connector attach for Twitch and YouTube
- runtime polling/subscription behavior using Heimdall-resolved credentials

### 5. Capture the Yggdrasil deployment shape early

Goals:

- treat Heimdall as a localhost service behind nginx on Yggdrasil
- support same-host callers first
- avoid per-request network chatter for routine app authorization

## Proposed phases

### Phase 1: Contract and schema scaffold

Landed in the first pass:

- signed claim/session payload shape
- Ed25519 JWKS verification surface
- OAuth `state` and callback contract surfaces
- app profile / capability rule inputs and outputs

Still to do in this phase:

- key rotation policy instead of just stable key loading
- token custody retrieval/refresh surfaces beyond initial storage

### Phase 2: Heimdall service skeleton

Landed in the first pass:

- provider OAuth start route scaffolding
- callback route scaffolding with signed-state validation
- session/claim issuance contract
- capability evaluation for shared app capabilities

Next in this phase:

- provider refresh/revocation flows
- connection lifecycle and token-rotation work

### Phase 3: Repixelizer binding

Landed in Repixelizer:

- Heimdall hosted auth mode
- direct backend callback receipt
- local Ed25519 JWT verification against Heimdall JWKS
- httpOnly local session adoption
- hosted landing-page provider buttons
- hosted route and queue/job ownership checks

Still to do for this phase:

- deploy and configure both services
- verify the real Discord OAuth path end to end

### Phase 4: StreamPixels authority migration

- replace provider/linking authority paths with Heimdall calls where they truly
  belong
- keep viewer/session expansion, creator memberships, and operator route
  enforcement local where they are app-domain concerns

### Phase 5: Ops and deploy

- define nginx/systemd/env/runbook surfaces for Heimdall on Yggdrasil
- keep callers and state stores localhost-first where practical

## Guardrails

- do not let auth reuse become data mixing
- do not turn Heimdall into a mandatory round-trip for every guarded app route
- do not fantasize about one shared cross-runtime embedded library; the apps can
  share contracts without sharing a runtime
- do not duplicate the shared architecture note into app profiles
- do not rip out app-local ownership and authorization logic that still belongs
  in the app
- keep one clear hypothesis per pass
- commit completed work before the planning notes start breeding
