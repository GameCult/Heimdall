# Repixelizer Access Profile

## What this file is

This file binds Repixelizer onto the shared Heimdall design in
`docs/architecture.md`.

It is future design, not a claim that the hosted demo already has auth.

## Current repo boundary

Current live hosted-demo behavior is still just:

- hosted-demo runtime limits and UI flags in `E:\Projects\repixelizer\src\repixelizer\gui.py`
- the local single-process queue in that same module
- frontend runtime-config consumption in `E:\Projects\repixelizer\frontend\src\app.ts`

No Discord login, Patreon login, linked identities, local sessions, or access
gates are landed yet.

## App identity

- `app_slug`: `repixelizer`
- primary hostname: `repixelizer.gamecult.org`
- runtime shape: one hosted GUI plus one queue-backed worker loop inside the app

## Capabilities

- `app_access`
  - may load the protected hosted GUI
- `queue_submit`
  - may create a repixelizer job
- `job_read_own`
  - may read own job state, event stream, and final output
- `job_cancel_own`
  - may cancel own queued or running job
- `admin_access`
  - may inspect operational or grant/admin surfaces later

First-cut rule shape:

```text
queue_submit = app_access
job_read_own = app_access + resource ownership check
job_cancel_own = app_access + resource ownership check
```

## Access policy

```text
app_access =
  entitlement.app_access
  || grant.global_member
  || grant.app_access

queue_submit = app_access

admin_access =
  grant.operator
  || grant.admin_access
```

## Runtime binding

Suggested queue/job additions:

- `jobs.account_id`
- `jobs.session_id`
- `jobs.access_revision`
- `jobs.entitlement_checked_at`

Route policy:

- public:
  - `/api/health`
  - `/api/config`
- public or capability-gated by policy choice:
  - `/api/queue`
- requires `queue_submit`:
  - `POST /api/jobs`
- requires ownership:
  - `GET /api/jobs/{job_id}`
  - `GET /api/jobs/{job_id}/events`
  - `POST /api/jobs/{job_id}/heartbeat`
  - `DELETE /api/jobs/{job_id}`

Important invariant:

- job ownership resolves from the local session/account, not from Discord or
  Patreon ids

Heimdall should be involved in:

- login / link entry
- session and claim issuance
- entitlement refresh

Preferred browser handoff:

1. Repixelizer opens Heimdall auth in a script-opened new tab/window
2. Heimdall completes provider auth and upstream entitlement checks
3. Heimdall delivers the auth result directly to a Repixelizer backend callback
   endpoint keyed by a local auth attempt id
4. Repixelizer backend establishes local trusted auth state from that direct
   delivery
5. the callback context only needs to signal status, try to close itself, and
   offer a dead-simple return path
6. the main Repixelizer page learns completion from its own backend by polling,
   SSE, or websocket

Important rule:

- Repixelizer should not rely on a raw access token arriving in the callback
  URL
- the browser should not be the primary carrier of the final auth result
- the one-time completion-code redeem flow remains acceptable as a fallback,
  not the preferred same-host path

Repixelizer should still do locally:

- claim verification on guarded routes
- ownership checks on job reads, events, heartbeat, and cancel
- queue/runtime behavior

## Config mapping

- keep runtime/queue/limit env vars under `REPIXELIZER_*`
- move Heimdall integration under `GC_ACCESS_*`
- keep per-app role/tier/capability bindings small and app-scoped
