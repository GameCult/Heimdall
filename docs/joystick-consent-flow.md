# Joystick sign-in and consent: what exists, what is missing, a draft flow

Status: DRAFT design, no code. Source-grounded at `fefd2dd` (main). Follow-up
`heimdall-body:follow_up:chat-s3124-3129`. Not for merge until a Heimdall
steward rules on the open questions below.

## 1. What a viewer sees today

**Joystick viewer sign-in does not exist.** `streampixelsProfile`
(`src/app-profiles.ts:109-117`) lists Joystick only in
`managedConnectionProviders`. `admitsProviderForMode` (`:243`) admits `sign_in`
and `link` only for `identityProviders`, so
`POST /v1/oauth/joystick/start` with `mode: sign_in` returns
`400 provider_not_supported_for_app` as JSON before any redirect
(`startOAuthFlow`, `src/app.ts:598-603`). The viewer sees whatever the app does
with a failed start; Heimdall shows them nothing. The architecture doc records
this as deliberate until the public bot is registered
(`docs/architecture.md:461`, `joystick:follow_up:joystick-viewer-signin-public-bot`).

**The only live Joystick path is a creator `connect`.** Walking it as the
person in the browser:

1. The app backend starts the flow (authenticated by app secret, `connection`
   `{kind: creator, targetId}`). The person's browser is sent to
   `/v1/oauth/joystick/launch?state=...`.
2. `launch` (`src/app.ts:1130-1194`) claims the state, sets the binding cookie
   and answers `302` straight to `joystick.tv/api/oauth/authorize`. **Heimdall
   renders no page of its own.** Nothing says who is asking, for what, or what
   will be kept.
3. The only ask the person sees is Joystick's own screen, listing the scopes in
   `providerCatalog.joystick.defaultScopes` (`src/providers.ts:162`):
   `identity:read stream:read chat:read followers:read subscribers:read`.
   Joystick words that screen, not us.
4. The callback (`:1196`) exchanges the code, stores the credential encrypted
   (rotating refresh token, managed custody), and returns the generic handoff
   page (`src/browser-handoff.ts`): title "Authentication Complete", body "You
   can return to the app now." It does not name the app, the provider, the
   scopes granted, or that a long-lived refresh token is now held by Heimdall.
5. Refusal: if the person clicks Deny at Joystick, the callback gets
   `error=access_denied`, and the page says "Authentication Failed ... Return to
   the app to continue." The provider's own text is relayed only in
   `errorDescription` in the fallback URL fragment / postMessage payload, not
   shown on the page. Refusing *at Heimdall's step* is impossible: there is no
   Heimdall step.
6. After: the audit rows `oauth_callback_succeeded`, `auth_completion_created`,
   `managed_credential_revoked` etc. (`createAuditEvent` call sites, e.g.
   `app.ts:1582`) are written for operators. There is **no route a viewer can
   call to read them**, and no route a viewer can call to revoke a credential.
   Revocation exists only inside the app backend plane (`managed-credential.ts:172`).

## 2. What consent is missing

| Gap | Today | Why it matters |
| --- | --- | --- |
| Visible ask | None from Heimdall; provider screen only | The person cannot tell Heimdall custody (refresh token kept, rotated, used for stream/chat/follower reads) from a one-off login. |
| Who is asking | Not shown | Two parties act: the app (StreamPixels) and Heimdall as custodian. Neither is named. |
| Scope truth | Provider screen lists scopes; Heimdall's `requestedScopes` / `defaultScopes` are not shown or compared with what was granted | Granted scopes can differ from requested; the stored `scopes` (`app.ts:1406`) are never shown. |
| Typed refusal | A deny is an untyped `provider_error` | The app and the audit log cannot tell "viewer said no" from "provider broke". |
| Receipt | Operator audit rows only | The viewer cannot audit what was agreed, when, or revoke it. |
| Viewer vs creator | The `connect` binding proves a binding exists, not that the browser's owner is the creator (`joystick:follow_up:connect-start-needs-app-auth`) | Consent from the wrong person is not consent. |

## 3. Draft consent flow

Applies to any Joystick completion (creator connect now; viewer sign-in when
the public bot lands) and, if ruled, to every provider whose state carries
`managed_credential`.

### 3.1 The ask (visible, before the redirect)

`GET /v1/oauth/:provider/launch` stops answering `302`. It renders a Heimdall
page, **after** the state is verified but **before** the use is claimed, with:

- the app by display name and return origin;
- the provider and the exact scope list that will be requested;
- what Heimdall keeps (a refresh token, encrypted, rotating) versus what the
  app receives (no token; a claim) and for how long;
- two forms, both POST, CSRF-bound by the existing binding cookie:
  **Continue to Joystick** and **No, return to the app**;
- a link to the receipt of any earlier consent for this account and app.

Only Continue claims the launch use and answers `302`. The page is plain
server-rendered HTML with no script, matching the handoff page's escape rule.

### 3.2 Typed refusal

**No** (and a provider `access_denied` on return) produces a distinct result
`consent_refused` with `{provider, app, mode, by: "viewer" | "provider"}`:
delivered to the app by the same handoff channel as any result, written as an
audit event `consent_refused`, no credential stored, state consumed. A provider
failure stays `provider_error`. The app is told not to ask again in the same
session; whether it may ask later is the app's rule, not Heimdall's.

### 3.3 Receipt

On a granted completion Heimdall writes one `consent_receipt` row: receipt id
(random, non-guessable), account (or creator target), app, provider, scopes
asked, scopes granted, what Heimdall retains, `grantedAt`, `consentPageDigest`
(hash of the exact text shown, so a later wording change is visible), and a
`revokedAt` slot. The handoff page shows the receipt id and a "View receipt" link.

`GET /v1/receipts/:id` (viewer-bound by the same cookie or by the account's
access token) shows the row and offers **Revoke**, which calls the existing
managed-credential revocation and stamps `revokedAt`. Revoke is itself receipted.
Receipts are append-only; a revocation is a second row, not an edit.

## 4. Open questions for the steward

1. Who gets the ask: every provider, or only `managed_credential` ones? (Recommend: only managed custody, where Heimdall holds something beyond a login.)
2. Where does the receipt live: Heimdall store as a new document, or the existing audit table with a new `eventType`? (Recommend: new typed document; the audit table is operator-shaped and has no viewer read path.)
3. Viewer identity for the receipt page when the viewer has no Heimdall session yet (a first-time creator connect). Binding cookie only, or require sign-in first?
4. Does `consent_refused` need to reach a backend callback app, or only the browser handoff?
5. Wording ownership: the page text is legal-adjacent (CultCoin legal research is a sibling thread); who signs the copy?

## 5. Out of scope here

Enabling Joystick in `identityProviders`; fixing `connect-start-needs-app-auth`;
Postgres schema/migration for the receipt; any deploy. Each needs its own cut.

## 6. Test sketch

`tests/joystick-consent.test.ts` holds the behaviours above as skipped tests
(they cannot pass until the cut is built). Unrun: the author's workspace could
not install dependencies, so treat the file as a sketch to be typechecked.
