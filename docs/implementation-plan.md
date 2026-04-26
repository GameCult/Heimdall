# Heimdall Implementation Plan

## What this file is

This file is the forward plan and active hypothesis ledger for Heimdall.

It is not the canonical shared architecture note. That lives in
`docs/architecture.md`.

If the code or the architecture note disagrees with this plan, trust the code
and the architecture note first, then fix this file.

## Current machine

There is no landed auth machine here yet.

What exists right now is:

- the shared architecture note
- app-binding notes for Repixelizer and StreamPixels
- explicit state/doctrine scaffolding so the plan does not immediately turn
  into soup

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

### 2. Define the contract before the service grows teeth

Goals:

- define signed claim/session shapes
- define OAuth start/callback/link surfaces
- define grant and entitlement persistence boundaries
- define how app backends verify claims locally

### 3. Make Repixelizer the first auth-blank consumer

Goals:

- gate hosted access and queue submission through Heimdall-issued claims
- attach queue ownership to `account_id` and `session_id`
- preserve the existing hosted GUI and queue runtime

### 4. Migrate StreamPixels without flattening its good local seams

Goals:

- move provider/linking authority toward Heimdall
- keep viewer profiles, creator memberships, connector creds, and audience data
  in StreamPixels
- keep creator/operator route authorization local to StreamPixels after claim
  verification

### 5. Capture the Yggdrasil deployment shape early

Goals:

- treat Heimdall as a localhost service behind nginx on Yggdrasil
- support same-host callers first
- avoid per-request network chatter for routine app authorization

## Proposed phases

### Phase 1: Contract and schema scaffold

- define:
  - signed claim/session payloads
  - JWKS or equivalent verification surface
  - OAuth `state` and callback contracts
  - grant / entitlement / audit record shapes
  - app profile / capability rule inputs and outputs

### Phase 2: Heimdall service skeleton

- create the first real service layout for:
  - provider OAuth start/callback routes
  - account / linked-identity persistence
  - session issuance and refresh
  - capability evaluation
  - audit logging

### Phase 3: Repixelizer binding

- integrate Heimdall into the hosted demo
- gate `POST /api/jobs`
- gate per-job read/cancel/event routes by local session ownership

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
