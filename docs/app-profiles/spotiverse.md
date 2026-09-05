# Spotiverse App Profile

> **RETIRED from the live registry 2026-09-06. This document is the restore
> spec — it is deliberately kept current, not archived.**
>
> Spotiverse was a small daemon exposing the Spotify API to agents. It was lost
> with the `E:` drive and has no repository in the swarm. The capability is
> wanted back — letting a Persona manage the queue during a stream is the
> motivating case — so this profile was removed in a way that is cheap to undo.
>
> **What was removed:** the `spotiverseProfile` object and its registry entry in
> `src/app-profiles.ts`, the `spotiverse` slug from `appSlugs` in
> `src/contracts.ts`, the hardcoded callback arm in `src/app.ts`, and three
> spotiverse-specific tests in `tests/app.test.ts`.
>
> **What was deliberately kept:** the whole `spotify` OAuth provider — the
> catalog entry in `src/providers.ts`, `spotifyRuntime` and its token/profile
> exchange in `src/oauth.ts`, and `"spotify"` in the `providers` union in
> `src/contracts.ts`. The provider is intact and unreferenced. Runtime health
> still reports `providers=2/6`, which counts it.
>
> **Why it was removed anyway:** `/v1/oauth/spotify/start` is gated by
> `supportsProvider(profile, provider)`, so a provider with no app behind it is
> unreachable. While the profile existed, that path was publicly reachable and
> would have run a real OAuth handshake against a real client secret, taking
> custody of a user's Spotify refresh token on behalf of a consumer that could
> not use it. Removing the profile closes the path; keeping the provider keeps
> the capability.

## Restoring

Everything below this line is still accurate. To bring Spotiverse back:

1. Re-add `spotiverseProfile` and its registry entry to `src/app-profiles.ts`,
   and `"spotiverse"` to `appSlugs` in `src/contracts.ts`. Both are recoverable
   verbatim from commit `5a15f71`, the last commit before removal.
2. Re-add the backend callback arm in `src/app.ts`. The daemon ran on
   **`http://127.0.0.1:8796/auth/heimdall/callback`**; that exact URL was the
   allowlisted value.
3. Configure `GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_ID` and
   `GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_SECRET` in the host service environment.
   They were removed from `/srv/heimdall/env/service.env` on retirement, so a
   fresh Spotify application registration may be needed.
4. Restore the three tests from `5a15f71` if the capabilities they covered
   (managed-credential resolve for spotify, portal backend callbacks) are not
   otherwise exercised. At retirement both were covered independently by the
   `streampixels` managed-credential tests and the generic
   `untrusted_backend_callback` test, so no coverage was lost by removing them.

No provider or protocol work is required. The retirement was a registry change.

---

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
GC_ACCESS_APP_SPOTIVERSE_BACKEND_CALLBACK_URLS=https://your-spotiverse-portal.example/auth/heimdall/callback
```

Spotiverse needs only the Heimdall base URL, matching app secret, and local
portal callback/return URLs. The callback URL Spotiverse sends in
`HEIMDALL_CALLBACK_URL` must exactly match one URL in Heimdall's
`GC_ACCESS_APP_SPOTIVERSE_BACKEND_CALLBACK_URLS` allowlist unless both services
are running on the same local host.
