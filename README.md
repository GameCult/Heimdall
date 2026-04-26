# Heimdall

Heimdall is the planned shared auth authority for GameCult-hosted experiments.

The point is painfully simple:

- stop rebuilding Discord/Patreon login glue in every app
- keep provider OAuth, linked identities, grants, entitlements, and session
  issuance in one place
- let app runtimes verify signed claims locally so "shared auth" does not
  become "everything phones home for every request"
- keep app-domain data separate so "shared auth" does not become "shared swamp"

## Current Shape

This repo now has an initial standalone service skeleton.

Landed right now:

- a TypeScript/Fastify service scaffold under `src/`
- Ed25519 JWT signing plus `/.well-known/jwks.json`
- signed OAuth start-state scaffolding for Discord, Patreon, GitHub, Twitch,
  and YouTube
- app profile surfaces for Repixelizer and StreamPixels
- signed claim issuance for app-local verification experiments

Still not landed:

- provider token exchange on callback
- durable account/session/grant storage
- end-to-end app integrations

Canonical docs:

- `docs/architecture.md`
- `docs/implementation-plan.md`
- `docs/service-contract.md`
- `docs/app-profiles/repixelizer.md`
- `docs/app-profiles/streampixels.md`
- `state/map.yaml`
- `notes/fresh-workspace-handoff.md`

## Dev Commands

```powershell
pnpm install
pnpm dev
pnpm test
pnpm build
```

## Working Loop

1. Rehydrate from canonical state.
2. Keep identity authority central and app-domain data local.
3. Prefer a Yggdrasil-hosted shared service over duplicated per-app provider
   stacks.
4. Let app backends verify signed claims locally instead of begging Heimdall on
   every guarded route.
5. Commit finished passes before the notes start breeding.
