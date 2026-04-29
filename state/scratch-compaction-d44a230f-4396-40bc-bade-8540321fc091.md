# Imminent Compaction Scratch

Live context from memory, written before inspection.

- User asked to prepare for imminent compaction after StreamPixels auth surgery.
- Heimdall repo: E:\Projects\Heimdall.
- StreamPixels repo: E:\Projects\StreamPixels.
- We migrated StreamPixels auth direction so Heimdall owns Twitch/YouTube OAuth, identity resolution, encrypted provider token custody, and app-authenticated managed access-token resolution.
- StreamPixels owns viewer profiles, local httpOnly viewer session, creator memberships, operator roles, connector binding, EventSub/live-chat runtime behavior, diagnostics, and audience data.
- Heimdall commit was created and pushed: f22db66 Add StreamPixels managed auth seams.
- StreamPixels commit was created locally but not pushed because the repo was already ahead by five commits before our work: 0183163 Delegate StreamPixels auth to Heimdall. After that, StreamPixels was ahead by 6.
- Verification completed before commits: Heimdall pnpm typecheck and pnpm test passed; StreamPixels pnpm typecheck and pnpm test passed.
- Twitch credentials were added from E:\Projects\Heimdall\secrets\streampixels_twitch_oauth.txt into E:\Projects\Heimdall\secrets\heimdall-service.env as GC_ACCESS_PROVIDER_TWITCH_CLIENT_ID and GC_ACCESS_PROVIDER_TWITCH_CLIENT_SECRET. Values were not printed.
- YouTube Google client secret JSON was added under E:\Projects\Heimdall\secrets\client_secret_*.json. I ignored its callback URI and copied client_id/client_secret into E:\Projects\Heimdall\secrets\heimdall-service.env as GC_ACCESS_PROVIDER_YOUTUBE_CLIENT_ID and GC_ACCESS_PROVIDER_YOUTUBE_CLIENT_SECRET. Values were not printed.
- Secrets folder is gitignored in Heimdall.
- Next action persisted in Heimdall state should be deploy/configure StreamPixels-Heimdall slice with Heimdall Twitch/YouTube provider credentials plus GC_ACCESS_APP_SHARED_SECRET on both sides, then real browser viewer claim/link and creator connector attach verification.
- Need now: run Heimdall compaction helper, update any state changed by credential setup if needed, rerun helper, commit persistence if changed. Do not commit secrets.
