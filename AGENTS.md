# Heimdall Instructions

## Project Purpose

Heimdall exists to hold the shared auth authority design for GameCult-hosted
experiments without letting that shared layer metastasize into a giant
mixed-data pit.

The planned shared authority owns:

- provider OAuth and linking
- signed session / claim issuance
- entitlement refresh
- capability evaluation
- app-facing access claims
- audit and grant surfaces

The planned non-shared-by-default layer is:

- app-domain user data
- audience data
- creator data
- queue/job payloads
- product-specific state
- app-local resource ownership checks

## Canonical State

- Treat `state/map.yaml` as the canonical current project map.
- Treat `state/scratch.md` as disposable working memory for one bounded subgoal.
- Treat `state/evidence.jsonl` as the distilled durable ledger of decisions,
  verified boundaries, and rejected paths.
- Treat `state/branches.json` as hypothesis tracking, not phase/status prose.
- Treat `notes/fresh-workspace-handoff.md` as the compact re-entry packet.
- Treat `docs/architecture.md` as the source-grounded shared architecture note.
- Treat `docs/implementation-plan.md` as the forward plan.
- Treat `docs/app-profiles/repixelizer.md` and
  `docs/app-profiles/streampixels.md` as thin app bindings, not the whole
  shared architecture. Add new app-profile notes when a new app binding needs
  durable context.

## Important Paths

Paths are relative to the repository root. Do not hard-code an absolute drive
path into this file; the repo has already been moved between drives once, and
every absolute path in here rotted the moment it happened.

- Shared architecture: `docs/architecture.md`
- Implementation plan: `docs/implementation-plan.md`
- Repixelizer profile: `docs/app-profiles/repixelizer.md`
- StreamPixels profile: `docs/app-profiles/streampixels.md`
- Spotiverse profile: `docs/app-profiles/spotiverse.md`
- Handoff summary: `notes/fresh-workspace-handoff.md`
- State CLI: `tools/heimdall_state.py`
- Pre-compaction helper: `tools/heimdall_prepare_compaction.py`

## Useful Commands

Both state tools are single-file, standard-library-only Python. They need no
virtualenv and no installed dependencies. Run them with `python` from the repo
root:

```powershell
python .\tools\heimdall_state.py status
python .\tools\heimdall_state.py add-evidence --type design --status accepted --note "..."
python .\tools\heimdall_prepare_compaction.py
```

Verified 2026-09-06 against Python 3.13.15 installed to the user scope; `py -3`
resolves the same interpreter.

If `python --version` prints an install prompt rather than a version, PATH is
resolving the Microsoft Store alias in `WindowsApps` instead of a real
interpreter, and it will still exit 0 while doing so. Install a real Python and
put it ahead of `WindowsApps` on PATH rather than hunting for some other
interpreter to hard-code here:

```powershell
winget install --id Python.Python.3.13 --scope user
```

## Session Bootstrap And Re-entry Protocol

On fresh session load:

1. read:
   - `state/map.yaml`
   - `notes/fresh-workspace-handoff.md`
   - `docs/architecture.md`
   - `docs/implementation-plan.md`
2. run:
   - `python .\tools\heimdall_state.py status`
   - `git status --short --branch`
   - `git log --oneline -5`
3. restate the current next action from persisted state before editing

After compaction or suspicious continuity loss:

1. rerun `heimdall_state.py status`
2. reread `state/map.yaml` and `notes/fresh-workspace-handoff.md`
3. treat the persisted next action as authoritative unless fresh evidence
   contradicts it

When the user says to prepare for imminent compaction:

1. run `tools/heimdall_prepare_compaction.py`
2. update only the state that actually changed
3. rerun the helper
4. commit the completed persistence pass unless the work is deliberately
   mid-surgery

After any major completed pass, assume compaction may be imminent even if the
user did not say so yet:

1. run `tools/heimdall_prepare_compaction.py`
2. sync only the persistent state that genuinely changed
3. rerun the helper
4. commit the persistence pass before moving on unless the work is
   deliberately mid-surgery
5. push the current branch to `origin` after the major pass unless the user
   explicitly says not to publish yet

## Operating Discipline

- Before substantial edits, restate the current mechanism and intended change.
- Keep identity authority central and app-domain data local unless there is a
  very deliberate, source-grounded reason to share something.
- Prefer the Yggdrasil-hosted Heimdall service over duplicated per-app provider
  stacks.
- Do not require a Heimdall round-trip for every guarded app route; host apps
  should verify signed claims locally and keep resource ownership checks local.
- Do not let app profiles turn into duplicate copies of the shared
  architecture.
- If the diff grows while the boundary gets blurrier, stop and simplify.
- Before handoff or compaction, sync `state/map.yaml`, refresh
  `notes/fresh-workspace-handoff.md`, add distilled evidence when future belief
  changed, and make the next action explicit.

## Build And Deploy Target

Heimdall runs as the auth authority behind Yggdrasil-hosted nginx at
`heimdall.gamecult.org`, on Linux. Idunn owns the deployment transaction. This
workstation is Windows and is where the shell is, not where the artifact runs:
a local compile is not evidence about the Linux release, because toolchain,
linker, filesystem semantics and path handling all differ. Build for the
target, or let the deploy path's own builder do it, and say which one you used.

## External Context

- For StreamPixels architecture/auth context, prefer the indexed `StreamPixels`
  repo through `voidbot` before filesystem spelunking.
- For GameCult deployment and host conventions, check the sibling `gamecult-ops`
  repo in the same projects root as this one before improvising infra claims.
