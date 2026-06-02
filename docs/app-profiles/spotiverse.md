# Spotiverse App Profile

Spotiverse consumes Heimdall as a managed Spotify credential authority.

## Boundary

- Heimdall owns Spotify OAuth, linked identity custody, refresh-token custody,
  and managed access-token projection.
- Spotiverse owns Spotify playback polling, queue command execution, command
  receipts, and its CultMesh/Eve provider surface.
- Odin, Eve, VoidBot Faces, and renderers consume the surface and command
  boundary; they do not receive Spotify tokens.

## Providers

- identity providers: `spotify`
- entitlement sources: none
- managed connection providers: `spotify`

## Capabilities

- `spotify_player_read`: shared capability after a linked Spotify identity.
- `spotify_queue_add`: shared capability after a linked Spotify identity;
  Spotiverse still owns URI validation and command receipts.

## Local Configuration

Heimdall needs:

```text
GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_ID=...
GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_SECRET=...
GC_ACCESS_APP_SPOTIVERSE_SHARED_SECRET=...
```

Spotiverse needs only the Heimdall base URL, matching app secret, and local
callback/return URLs.
