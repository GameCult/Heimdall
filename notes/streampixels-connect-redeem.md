# For Kiko: what StreamPixels must do for a creator connect

Heimdall's side is done (this PR). A connect start that carries a `connection`
target is accepted only with StreamPixels' own `x-heimdall-app-secret`, so only
the StreamPixels backend can mint a state naming `{kind: "creator", targetId}`.
Heimdall cannot see StreamPixels' session; the secret proves the caller is the
backend, and the backend must have proved the creator-manage session itself
before it starts the connect.

What StreamPixels has to change (not done here; this repo does not touch it):

1. **Start the connect only after the creator-manage check.** The route that
   calls `POST /v1/oauth/:provider/start` with `mode: "connect"` must have
   verified, for the signed-in StreamPixels user, that they may manage creator
   `targetId`. Never take `targetId` from the browser unchecked.
2. **Remember what you started.** Store, server-side and bound to the attempt
   (the `attemptId` or browser session), the `targetId` StreamPixels asked
   Heimdall to bind.
3. **Redeem with that stored target, never one read back from the request or
   the completion.** `POST /v1/apps/streampixels/auth/redeem` takes `targetId`;
   Heimdall answers `403 completion_target_mismatch` (code left unconsumed) when
   it differs from the signed state's. That only protects you if the value you
   send is the one you stored at step 2. A redeem with no stored target for this
   attempt must be refused by StreamPixels before it calls Heimdall.
4. **Refuse a creator connect you did not start.** If a connect completion
   arrives for a `targetId` with no matching started attempt, do not rebind that
   creator's connector, whatever Heimdall's completion says.
5. **A connect completion with no creator target is not a creator connect and
   not a sign-in.** Joystick is managed-connection only: a non-creator Joystick
   completion is an error. (Twitch/YouTube `connect` without a `connection` is
   Heimdall's viewer-session path; treat it as that, never as a connector rebind.)
6. Blank targets (`"   "`, zero-width characters) are refused by Heimdall at
   start with `400 invalid_connection_target`; send real ids only.

Tracked as `joystick:follow_up:connect-start-needs-app-auth`.
