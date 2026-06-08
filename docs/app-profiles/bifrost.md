# Bifrost App Profile

Bifrost uses Heimdall for shared GameCult membership signals while keeping
Bifrost-domain state local.

## Ownership

Heimdall owns:

- Discord and Patreon OAuth
- provider token custody and refresh
- Discord role entitlement evaluation
- Patreon tier entitlement evaluation
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
