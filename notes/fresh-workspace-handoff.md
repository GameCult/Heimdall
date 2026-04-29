# Fresh Workspace Handoff

This is the re-entry packet for `E:\Projects\Heimdall`.

It is intentionally short. Historical proof belongs in git history and the
distilled `state/evidence.jsonl` ledger; the shared architecture belongs in
`docs/architecture.md`; the forward build order belongs in
`docs/implementation-plan.md`.

## Rehydrate

From the repo root:

```powershell
# This repo has no dedicated venv yet. Use any working Python 3.11+.
E:\Projects\repixelizer\.venv\Scripts\python.exe .\tools\heimdall_state.py status
Get-Content '.\state\map.yaml'
Get-Content '.\notes\fresh-workspace-handoff.md'
Get-Content '.\docs\architecture.md'
Get-Content '.\docs\implementation-plan.md'
git status --short --branch
git log --oneline -5
Get-Content '.\state\evidence.jsonl' -Tail 8
```

Do not trust this file for the exact live HEAD. Always check git.

## Current Orientation

- this repo now has a first stateful Heimdall service slice
- the canonical shared architecture lives in `docs/architecture.md`
- the concrete HTTP/JWKS contract lives in `docs/service-contract.md`
- app profiles live under `docs/app-profiles/`
- the key boundary is explicit:
  - Heimdall owns OAuth, linking, managed provider credential custody, grants,
    entitlement refresh, and signed claim issuance
  - app-domain data stays app-owned by default
  - host apps verify signed claims locally for routine auth instead of calling
    Heimdall on every request
- the landed service now exposes:
  - `/.well-known/jwks.json`
  - `/.well-known/heimdall-configuration`
  - `/v1/oauth/{provider}/start`
  - `/v1/oauth/{provider}/callback`
  - `/v1/apps/{appSlug}/auth-completions/redeem`
  - `/v1/apps/{appSlug}/claims/issue`
- the Discord callback path now performs real code exchange, identity
  resolution, auth persistence, entitlement evaluation, audit logging, and
  claim issuance for the Repixelizer slice
- browser-style auth handoff now uses a one-time completion code posted back to
  the opener, with backend redemption instead of fragment-token handoff
- same-host or Yggdrasil-reachable app integrations can now ask Heimdall to
  deliver the auth result directly to an app backend callback endpoint, leaving
  the browser with only status/attempt signaling
- signing keys can now load from a persisted file path and bootstrap that file
  on first boot when explicitly enabled
- managed provider tokens are now sealed at rest with AES-256-GCM instead of
  being dumped into "encrypted" columns raw like an insult
- `src/verifier.ts` now provides a small local JWT verifier seam for app
  backends
- Repixelizer has consumed the backend-callback flow in its hosted web layer:
  it creates local auth attempts, asks Heimdall to start OAuth, receives the
  direct backend callback, verifies Heimdall Ed25519 access tokens locally, and
  adopts httpOnly local sessions
- Repixelizer is no longer blocking Heimdall on auth refactoring
- the first live launch should be Discord-only
- Patreon, GitHub, Twitch, and YouTube are catalogued providers, but their
  callback runtime adapters still return "not implemented"
- StreamPixels is the migration target with useful existing auth seams that
  should not be flattened into mush
- the intended first deployment shape is a Heimdall service on Yggdrasil behind
  nginx, not an embedded cross-runtime shared library fantasy

## Critical Doctrine

- Persistent state is the agent's mind.
- Cut stale architecture notes as ruthlessly as stale code.
- Do not mistake "shared auth" for "shared database."
- Do not mistake "shared auth service" for "every guarded route must call the
  mothership."
- If compaction hits before boundary findings are persisted, that work is gone.
  Re-gather it instead of pretending continuity happened.

## Next Real Move

Do not continue implementation automatically from a rehydrate-only request.

If the user asks to continue, the current next move is the live Discord-only
Repixelizer launch path:

- configure the Discord OAuth app redirect URI as
  `https://heimdall.gamecult.org/v1/oauth/discord/callback`
- configure Heimdall with Discord client id/secret, Repixelizer guild id,
  the Cultist role id in `GC_ACCESS_APP_REPIXELIZER_DISCORD_ALLOWED_ROLE_IDS`,
  Postgres storage, token encryption, and stable signing keys
- configure Repixelizer to use `GC_ACCESS_MODE=heimdall` and
  `GC_ACCESS_ALLOWED_PROVIDERS=discord`
- run the real browser OAuth flow end to end and confirm Repixelizer receives
  the backend callback, verifies the token, adopts a local session, and gates
  hosted routes

Launch policy is role-gated on purpose: the GameCult Discord can remain public,
but Repixelizer access is limited to members with the Cultist role.

## Immediate Re-entry Instruction

After compaction, first rehydrate and reorient from the listed files and git
state. Wait for the user's next instruction unless they explicitly say to
continue.
