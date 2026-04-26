# Fresh Workspace Handoff

This is the re-entry packet for `E:\Projects\gamecult-access`.

It is intentionally short. Historical proof belongs in git history and the
distilled `state/evidence.jsonl` ledger; the shared architecture belongs in
`docs/architecture.md`; the forward build order belongs in
`docs/implementation-plan.md`.

## Rehydrate

From the repo root:

```powershell
# This repo has no dedicated venv yet. Use any working Python 3.11+.
E:\Projects\repixelizer\.venv\Scripts\python.exe .\tools\gamecult_access_state.py status
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

- this repo is planning and extraction work, not a landed auth service yet
- the canonical shared architecture lives in `docs/architecture.md`
- app profiles live under `docs/app-profiles/`
- the key boundary is explicit:
  - shared auth/control-plane mechanics are reusable
  - app-domain data stays app-owned by default
- Repixelizer is the first binding target
- StreamPixels is the boundary case that proves backbone reuse must not imply
  audience-data centralization
- the recommended first implementation mode is an embedded shared package, not a
  dedicated auth service

## Critical Doctrine

- Persistent state is the agent's mind.
- Cut stale architecture notes as ruthlessly as stale code.
- Do not mistake "shared auth" for "shared database."
- If compaction hits before boundary findings are persisted, that work is gone.
  Re-gather it instead of pretending continuity happened.

## Next Real Move

Do not continue implementation automatically from a rehydrate-only request.

If the user asks to continue, the current next move is to define the embedded
`gamecult_access` package seam:

- storage interfaces
- provider adapter interfaces
- signed-session claims
- capability rule evaluation boundaries

without central-service theatrics and without smearing app-domain data into the
shared layer.

## Immediate Re-entry Instruction

After compaction, first rehydrate and reorient from the listed files and git
state. Wait for the user's next instruction unless they explicitly say to
continue.
