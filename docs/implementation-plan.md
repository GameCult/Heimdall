# GameCult Access Implementation Plan

## What this file is

This file is the forward plan and active hypothesis ledger for GameCult Access.

It is not the canonical shared architecture note. That lives in
`docs/architecture.md`.

If the code or the architecture note disagrees with this plan, trust the code
and the architecture note first, then fix this file.

## Current machine

There is no landed auth machine here yet.

What exists right now is:

- the extracted shared architecture note
- app-binding notes for Repixelizer and StreamPixels
- explicit state/doctrine scaffolding so the plan does not immediately turn into
  soup

## Primary objective

Build a reusable `gamecult_access` layer that can:

- own provider OAuth and identity linking
- issue signed local sessions
- refresh Discord and Patreon entitlements
- evaluate per-app capability rules
- stay separate from app-domain data

## Current priorities

### 1. Lock the shared boundary

Goals:

- keep the shared layer scoped to auth/control-plane machinery
- keep app-domain data in app-owned stores
- keep app profiles thin and explicit

### 2. Prefer embedded-package mode first

Goals:

- define the reusable package/module seam
- avoid a dedicated shared service until a second real app proves the need
- keep initial blast radius small

### 3. Make Repixelizer the first binding

Goals:

- gate hosted access and queue submission through local sessions
- attach queue ownership to `account_id` and `session_id`
- preserve the existing hosted GUI and queue runtime

### 4. Keep StreamPixels separate where it matters

Goals:

- let StreamPixels reuse auth/control-plane machinery
- keep viewer profiles, creator memberships, connector creds, and audience data
  in StreamPixels

## Proposed phases

### Phase 1: Shared package scaffold

- create package/module boundaries for:
  - provider adapters
  - signed session issuance/verification
  - linked identity persistence interfaces
  - entitlement refresh/evaluation
  - capability rule evaluation

### Phase 2: Repixelizer binding

- integrate the shared layer into the hosted demo
- gate `POST /api/jobs`
- gate per-job read/cancel/event routes by local session ownership

### Phase 3: StreamPixels control-plane fit check

- map the shared access layer onto StreamPixels creator/operator auth seams
- explicitly reject audience-data centralization

### Phase 4: Shared-store decision

- only after two real bindings exist, decide whether auth/control-plane state
  should stay embedded or move into a shared service/store

## Guardrails

- do not let auth reuse become data mixing
- do not build a central service first just because it sounds grand
- do not duplicate the shared architecture note into app profiles
- keep one clear hypothesis per pass
- commit completed work before the planning notes start breeding
