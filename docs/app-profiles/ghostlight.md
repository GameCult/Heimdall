# Ghostlight Dungeon Access Profile

Ghostlight Dungeon uses Heimdall's private CultNet authentication commands and
the `gamecult.heimdall.access` Eve plugin. Heimdall owns provider OAuth,
persistent attempts, local account identity, entitlement evaluation, signed
access claims, completion redemption, and refresh. Ghostlight verifies claims
locally and owns app sessions, campaigns, campaign membership, current campaign
selection, and every world mutation.

## App identity

- `app_slug`: `ghostlight`
- public URL: `https://yggdrasil.gamecult.org/ghostlight/`
- identity provider: Discord
- access rule: Ghostlight supplies its configured KLTST Discord-role policy on
  the app-authenticated private boundary; Heimdall evaluates the policy and
  grants `app_access` only when it succeeds

## Capabilities

- `app_access`: shared capability granting entry to the demo
- `campaign_play`: hybrid capability; Ghostlight must also prove that the
  authenticated account owns the selected campaign

The browser never carries provider tokens or a completion code. The access
plugin stores only an opaque attempt handle. Ghostlight redeems that handle over
the encrypted loopback command plane, verifies the resulting `aud=ghostlight`
claim against Heimdall JWKS, and establishes app-local campaign authority.
