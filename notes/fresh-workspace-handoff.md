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

- this repo now has an initial standalone Heimdall service skeleton
- the canonical shared architecture lives in `docs/architecture.md`
- the concrete HTTP/JWKS contract lives in `docs/service-contract.md`
- app profiles live under `docs/app-profiles/`
- the key boundary is explicit:
  - Heimdall owns OAuth, linking, managed provider credential custody, grants,
    entitlement refresh, and signed claim issuance
  - app-domain data stays app-owned by default
  - host apps verify signed claims locally for routine auth instead of calling
    Heimdall on every request
- the landed skeleton already exposes:
  - `/.well-known/jwks.json`
  - `/.well-known/heimdall-configuration`
  - `/v1/oauth/{provider}/start`
  - `/v1/oauth/{provider}/callback`
  - `/v1/apps/{appSlug}/claims/issue`
- Repixelizer is the first auth-blank binding target
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

If the user asks to continue, the current next move is to define the first
real provider/storage slice on top of the landed skeleton:

- durable account / linked-identity / grant persistence
- persisted signing key material
- first real provider callback/token exchange path
- first end-to-end Repixelizer binding

without dragging app-domain data into the shared layer and without forcing
per-request auth round-trips.

## Immediate Re-entry Instruction

After compaction, first rehydrate and reorient from the listed files and git
state. Wait for the user's next instruction unless they explicitly say to
continue.
