# Bifrost App Profile

Bifrost uses Heimdall for shared GameCult membership signals while keeping
Bifrost-domain state local.

## Ownership

Heimdall owns:

- Discord and Patreon OAuth
- provider token custody and refresh
- Discord role entitlement evaluation
- Patreon tier entitlement evaluation
- Patreon membership profile reads used for Bifrost support sync
- signed delivery of normalized patron support facts to Bifrost
- signed app claims and backend handoff delivery

Bifrost owns:

- local `UserAccount` and membership records
- work, motions, ledgers, patron support events, and governance weight
- the decision to turn a Heimdall member-access claim into active Bifrost
  membership
- provider-derived patron credit rules and receipt projection

## Current Access Policy

Bifrost accepts two Heimdall entitlement policies:

- Discord role access for the GameCult guild, with the deployment supplying the
  KTLST/cult-member role id as the allowed role.
- Patreon membership access for the configured support tier title, currently
  `Inner Sanctum` by default.

Both policies are caller-owned by Bifrost and must use `backend_callback`
handoff. Browser-completion handoffs must not carry app-owned entitlement
policies because a browser caller could forge the policy.

## Runtime Flow

1. Bifrost creates an auth attempt and asks Heimdall to start Discord or Patreon
   OAuth with a server-owned entitlement policy.
2. Heimdall completes provider OAuth, evaluates the entitlement, and delivers
   the result to `https://bifrost.gamecult.org/auth/heimdall/callback`.
3. Bifrost's browser waits at `/auth/heimdall/wait`.
4. When the callback arrives, Bifrost creates or updates its local user account,
   activates standard membership, and issues its own app cookie.

Heimdall does not own Bifrost ledgers, patron points, votes, payout proposals,
or work routing.

## Patron Support Sync

Bifrost patronage uses the same linked Patreon identity and membership reader as
the Repixelizer entitlement path. There is not a second Patreon parser in
Bifrost.

`POST /v1/apps/bifrost/patron-support/sync` is an app-authenticated Heimdall
backend route. Bifrost or an operator job calls it with:

- `accountId`: the Heimdall account already linked through Patreon OAuth
- `requiredTierTitle`: the Bifrost support tier title, usually `Inner Sanctum`
- optional `currencyCode` and `supportedAtUtc` fallback values

Heimdall refreshes the stored Patreon credential if needed, fetches the Patreon
identity profile with memberships and currently entitled tiers, finds an active
paid membership for the requested tier title, and POSTs a signed
`RecurringSupportSnapshot` fact to Bifrost's
`/heimdall/patron-support/events` endpoint.

The outbound fact uses `X-Heimdall-Signature-256` with the shared
`GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET`. Bifrost verifies that HMAC, resolves
the Heimdall account id to its local user account, deduplicates by provider
event id, records the support event, and derives patron points locally.

This route is a bridge from auth-owned Patreon evidence to Bifrost-owned
governance meaning. Heimdall still does not own points, votes, tiers, ledger
history, or payout policy.
