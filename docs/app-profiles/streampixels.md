# StreamPixels Access Profile

## What this file is

This file records how StreamPixels should fit onto Heimdall in
`docs/architecture.md` without turning streamer-audience data into shared auth
sludge.

It is a boundary note, not a command to rewrite StreamPixels around Repixelizer.

## Current repo boundary

The current StreamPixels architecture already makes useful splits:

- the web app owns the remembered viewer session
- the service owns provider OAuth exchange and identity resolution
- the overlay remains auth-free
- creator memberships and operator roles are separate from general viewer state

That is already compatible with the shared backbone idea.

## What StreamPixels can reuse

- signed local session mechanics
- linked-identity and signed OAuth-state patterns
- provider adapter structure
- creator/operator capability evaluation
- grant/invite primitives where they fit

In the service-first Heimdall version, the most likely reusable slice is:

- provider OAuth authority
- identity-linking authority
- managed Twitch/YouTube credential custody for creator connections
- entitlement refresh
- shared claim semantics

## What StreamPixels should keep separate

- viewer audience profiles
- creator memberships tied to streamer spaces
- creator connector bindings and feature semantics
- overlay/runtime state
- audience-facing app data in general

In plain language:

- Heimdall can authenticate and authorize the control plane
- Heimdall can also own OAuth flow and token custody for creator-side provider
  connections when that reduces auth duplication
- StreamPixels still owns which creator a connection belongs to, what
  subscriptions or sync flows it drives, and how failures are surfaced
- StreamPixels audience data stays StreamPixels data

## Capability direction

Likely capability families:

- `viewer_access`
- `creator_access`
- `creator_admin`
- `operator_access`

These should bind onto the existing StreamPixels creator/operator separation
instead of flattening it into one GameCult-member gate.

## Invariant

If a future shared access store exists, it must not become the canonical home
for streamer-audience identity and product data. That stays with StreamPixels.
