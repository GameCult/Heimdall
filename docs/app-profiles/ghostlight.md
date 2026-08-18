# Ghostlight Dungeon Access Profile

Ghostlight Dungeon reuses Heimdall's browser-completion Discord sign-in path.
Heimdall owns provider OAuth, local account identity, signed access claims, and
refresh. Ghostlight verifies claims locally and owns campaigns, campaign
membership, current campaign selection, and every world mutation.

## App identity

- `app_slug`: `ghostlight`
- public URL: `https://yggdrasil.gamecult.org/ghostlight/`
- identity provider: Discord
- public-demo rule: any Heimdall-authenticated Discord identity receives
  `app_access`; no GameCult guild role is required

## Capabilities

- `app_access`: shared capability granting entry to the demo
- `campaign_play`: hybrid capability; Ghostlight must also prove that the
  authenticated account owns the selected campaign

The browser never carries provider tokens. It receives a one-time completion
code, Ghostlight redeems it server-to-server, verifies the resulting
`aud=ghostlight` claim against Heimdall JWKS, and establishes app-local campaign
authority.
