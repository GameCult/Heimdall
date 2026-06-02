# Heimdall

Heimdall is the shared auth authority taking shape for GameCult-hosted
experiments.

The point is painfully simple:

- stop rebuilding Discord/Patreon login glue in every app
- keep provider OAuth, linked identities, grants, entitlements, and session
  issuance in one place
- let app runtimes verify signed claims locally so "shared auth" does not
  become "everything phones home for every request"
- keep app-domain data separate so "shared auth" does not become "shared swamp"

## Current Shape

This repo now has a stateful first slice instead of a decorative skeleton.

Landed right now:

- a TypeScript/Fastify service scaffold under `src/`
- Ed25519 JWT signing plus `/.well-known/jwks.json`
- file-backed signing-key loading/bootstrap so restart does not vaporize the
  service identity when you configure a real key path
- signed OAuth start-state scaffolding for Discord, Patreon, GitHub, Twitch,
  and YouTube
- durable auth/control-plane storage with in-memory and Postgres backends
- account, linked-identity, session, grant, entitlement snapshot, and audit
  persistence
- a real Discord OAuth callback path for the first Repixelizer access flow
- direct backend callback handoff for same-host or Yggdrasil-reachable app
  backends
- AES-256-GCM sealing for managed provider tokens at rest
- a one-time browser completion exchange kept as fallback for opener
  `postMessage` handoff
- app profile surfaces for Repixelizer and StreamPixels
- signed claim issuance for app-local verification experiments
- a local verifier helper in `src/verifier.ts` so app backends can validate
  Heimdall JWTs without phoning home on every guarded request

Still not landed:

- end-to-end app integrations in consumer repos
- refresh/revocation flows and admin surfaces

Canonical docs:

- `docs/architecture.md`
- `docs/implementation-plan.md`
- `docs/service-contract.md`
- `docs/verse-service-contract.md`
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
