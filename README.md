# GameCult Access

GameCult Access is the planned shared auth and access-control backbone for
GameCult-hosted experiments.

The point is painfully simple:

- stop rebuilding Discord/Patreon login glue in every app
- keep signed local sessions, linked identities, and capability checks reusable
- keep app-domain data separate so "shared auth" does not become "shared swamp"

## Current Shape

This repo is planning and extraction work, not a landed auth service yet.

Canonical docs:

- `docs/architecture.md`
- `docs/implementation-plan.md`
- `docs/app-profiles/repixelizer.md`
- `docs/app-profiles/streampixels.md`
- `state/map.yaml`
- `notes/fresh-workspace-handoff.md`

## Working Loop

1. Rehydrate from canonical state.
2. Keep the shared backbone separate from app-domain data.
3. Prefer embedded shared-package mode before inventing a central auth service.
4. Move only one organ at a time.
5. Commit finished passes before the notes start breeding.
