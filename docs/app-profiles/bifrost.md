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

The outbound fact uses `X-Heimdall-Signature-256` with the shared secret
Heimdall reads from `GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET_FILE`. Bifrost
verifies that HMAC, resolves the Heimdall account id to its local user account,
deduplicates by provider event id, records the support event, and derives
patron points locally.

This route is a bridge from auth-owned Patreon evidence to Bifrost-owned
governance meaning. Heimdall still does not own points, votes, tiers, ledger
history, or payout policy.

## App-asserted step-up

Bifrost's profile carries `stepUpAssertion: { methods: ["bifrost-passkey",
"bifrost-email-code"] }`, the only such grant. With its secret and a member's
live Heimdall bearer, Bifrost calls `POST /v1/apps/bifrost/step-up` with
`{method, nonce}` after it has checked the factor itself, and receives an access
token for the same session whose `step_up_at` and `step_up_method` satisfy
Heimdall's unlink check. Bifrost must send a fresh nonce per assertion, keep
the returned token only for the action it is for, and never send a method it did
not verify: Heimdall cannot tell. Contract, codes, limits and what it does not
prove are in `docs/service-contract.md`.

Precondition and limit: Bifrost can call this only while it holds the member's
Heimdall bearer, which it deliberately does not today. Holding it in a cookie
ticket would turn cookie theft into bearer theft and, with a passkey or email
code, into unlink power. And unlink accepts any method: a `bifrost-email-code`
proof can unlink an identity a Google re-authentication would have guarded.
Requiring a method per route is the later hardening (identity moves).

## Identity moves

Bifrost's profile carries `identityMoves: { accountProofMethods:
["bifrost-passkey"] }`, the only such grant (its methods are a subset of
`stepUpAssertion.methods`). With its secret, `POST /v1/apps/bifrost/identity-moves`
moves logins from one Heimdall account to another when it presents fresh proofs
of both: Bifrost's merge saga owns survivor choice, preview and undo timing;
Heimdall moves what the proofs cover. A proof through one login moves only that
login; an asserted `bifrost-passkey` proof covers the whole source account;
`bifrost-email-code` proves an inbox and does not. A multi-login source without a
passkey therefore needs one fresh sign-in per login. Until the Google client is
live, a member's strong proof is the asserted passkey only; Discord and Patreon
give weak (300 s) proofs. Contract, refusal order and idempotency are in
`docs/service-contract.md`.
