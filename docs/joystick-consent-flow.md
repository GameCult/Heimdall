# Joystick sign-in and consent: what was missing, and the flow that fills it

Status: built (sections 3-6 describe the code on this branch); sections 1-2 are
the state of `fefd2dd` (main) that motivated it. Follow-up
`heimdall-body:follow_up:chat-s3124-3129`, built under
`heimdall-body:follow_up:chat-mind-20261108T131253147Z-t1`. The steward's rulings
on the five open questions are in section 4.

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

## 3. The consent flow

Applies to every completion `callbackMint` calls `custody_only`: a managed
creator connection (Joystick today; Twitch and YouTube on StreamPixels when
they are connected rather than signed in). Viewer sign-in through an identity
provider is unchanged.

### 3.1 The ask

`GET /v1/oauth/:provider/launch` renders a Heimdall page (`src/consent.ts`)
instead of answering `302`, after the state verifies and before any use is
claimed. The page names the app and the origin the person returns to, the
provider and the exact scopes Heimdall will send (`authorizationScopes`, the
same function that builds the authorization URL), what Heimdall keeps (an
encrypted refresh token and access token, until the person takes it back or the
provider ends it), what the app receives, and how to take it back. It carries
two POST forms to `/v1/oauth/:provider/consent`, **Continue to Joystick** and
**No, return to the app**, and runs no script. It sets the ask's own
cookie (`__Host-heimdall-ask-<jti>`), which carries the exact text shown and is
accepted only by Continue and No; an answer without it is `state_not_bound` and
spends nothing. Viewing the ask claims nothing and binds nothing: the launch
binding cookie, which decides who may complete the state, is set only when
Continue claims the launch, and it carries the text shown on to the callback.
(An earlier cut set the binding on the ask, so anyone holding the launch URL
could become the state's owner; review of 2026-11-08 found it.)

What the app receives, stated as the code does it: not a claim. The app
backend can call `managed-credentials/resolve` and receive the current access
token; it never receives the refresh token. The earlier draft said the app
receives "no token"; that was wrong and the page does not say it.

### 3.2 Typed refusal

A decline, and a provider `error=access_denied` on any provider, produce the
result `consent_refused` with `by: "viewer" | "provider"`: an audit event
`consent_refused` (provider, mode, by; no account, no person), the browser
attempt denied with `denialCode consent_refused`, both uses of the state spent,
a `backend_callback` app told with the same payload, a "Not Connected" page in
the browser, and `400 {error: "consent_refused", by}` as JSON. No credential is
stored and no receipt is written. Every other provider error stays
`provider_error`. This changes the `access_denied` answer for every provider,
including Bifrost's and Repixelizer's sign-in; see the PR for the contract note.

### 3.3 Receipt

On a granted `custody_only` completion Heimdall writes one `consent_receipts`
row of kind `grant`: id (random), account, app, provider, scopes asked, scopes
granted (as the provider returned them), `consentText` (the lines and
button labels shown, taken from the ask and never rebuilt, so a deploy between
ask and callback cannot change what the receipt says), `consentPageDigest`
(sha-256 of that text), `createdAt`. A custody callback with no shown text
exchanges no code and stores no credential. The id
reaches the app (`consentReceiptId` in the completion and backend payloads) and
the person (the handoff page).

Receipts are append-only: the store role has `SELECT` and `INSERT` on the table
and nothing else. A revocation is a second row of kind `revocation` naming the
grant it takes back, unique per grant (a partial unique index); a grant is live
exactly when no revocation names it, and a concurrent second revoke reports
nothing and writes nothing. The
draft's `revokedAt` slot is gone for that reason.

### 3.4 My grants

Signed in means a live Heimdall access token for any app (`Authorization:
Bearer`), or a page link minted from one.

- `GET /v1/me/grants`: every grant and receipt of the account. `Accept:
  text/html` gets the page, one **Take this back** form per live grant; anything
  else gets `{grants, receipts}`.
- `POST /v1/me/grants/link` (bearer): `{url}` to the page, valid ten minutes.
  The token is signed, purpose-bound (`heimdall_grants_page`), stateless, and
  opens only this page and its revoke forms. The forms on a page opened by a link
  carry the link's own expiry, so using a link never renews it. This is how a browser that holds no
  session gets in; Heimdall sets no new cookie and stores nothing for it.
- `POST /v1/me/grants/:id/revoke` (bearer, or the page token in the form):
  strips the stored tokens from the credential, then writes a revocation row
  for every live grant on that credential. The credential is one row per account
  and provider, whichever app asked, so taking it back ends every grant resting
  on it. The next `managed-credentials/resolve` answers `410
  managed_credential_revoked`; nothing else needs to learn of it. Revoking a
  revoked grant changes nothing. Another account's grant id is `404`.

Heimdall can delete its copy; it cannot withdraw the permission at the
provider, and the page says so.

## 4. The steward's rulings

Each ruling picks the answer that gives the person the most agency and leaves
the least stored.

1. **Who gets the ask: managed custody only.** Where Heimdall holds a credential
   the person cannot see and an app can use, the person is asked and given a
   receipt. A login is already asked by the provider's own screen, and a receipt
   per login would store a row per sign-in for no agency the provider's screen
   does not give. The line is `callbackMint === "custody_only"`, so it needs no
   second list to keep in step with the profiles.
2. **The receipt is a new typed table, `consent_receipts`.** The audit table is
   operator-shaped and has no read path for the person; a viewer-readable
   record in it would make every audit row a potential disclosure. The table
   holds ids, scopes and a digest: no IP address, no user agent, no page text. A revocation names a
   receipt of its own account: a composite foreign key `(revokes_receipt_id,
   account_id)` to `(id, account_id)`, which is why `(id, account_id)` is also a
   unique key (`checkSchema` counts it). The in-memory store refuses the same. The table is created
   whole and first-created: no deployed database had an earlier shape, so there
   is no `ALTER` step.
   Refusals leave no receipt, only the anonymous audit row.
3. **Viewer identity: sign-in, not the cookie.** The binding cookie dies with
   the state and proves only that a browser launched a flow; it is not an
   account. The receipt page and revoke require a live access token or a
   ten-minute link minted from one. The cost is that a first-time creator must
   hold the session the completion returned to the app; the app mints the link.
   The alternative, a new long-lived Heimdall cookie, would store a session for
   every person who merely looked.
4. **`consent_refused` reaches a backend callback app.** An app that started the
   attempt and is waiting must be told, or it polls to expiry and cannot tell
   a person's no from a fault. The person's no is also not held against them:
   Heimdall stores nothing and sets no cooldown; whether and when to ask again
   is the app's rule.
5. **Wording: derived, not authored.** The text is generated from facts the code
   holds and states nothing the code does not do; it is a constant in
   `src/consent.ts` and its digest rides every receipt. Legal review of the
   wording (the CultCoin legal thread) may only narrow it, and any change moves
   the digest. Until that review lands the copy is Heimdall's, signed by the
   steward.
6. **Bounds on what rides the cookies.** The wording is read from a cookie
   only up to 16 KB inflated, so a compressed bomb is refused, not expanded. An
   app may request at most 32 scopes of 512 characters (`requested_scopes_too_large`
   at the ask). A custody callback whose binding carries no wording is refused
   with `consent_text_missing` before the state is claimed, so nothing is burned.

### Refusal return contract (for app authors)

A person's No at the ask, or a provider `access_denied`, is `consent_refused`.
No completion code is minted and the state is spent. What each side gets:

- **Browser.** A 200 HTML page titled "Not Connected" (a non-HTML caller gets a 400
  JSON `{error, by, provider, returnTo}`). The page does not redirect: by ruling
  it never navigates on its own. It posts the payload to `window.opener`
  (target origin = the origin of `returnTo`), tries `window.close()` after 50 ms,
  and offers a "Return to the app" link. In a plain tab the person clicks it.
- **The link** is `returnTo` with a fragment (read `location.hash`; it never
  reaches a server): `heimdall_status=error`, `heimdall_error=consent_refused`,
  `heimdall_refused_by=viewer|provider`, `heimdall_provider`,
  `heimdall_handoff_kind`, `heimdall_app_slug`, `heimdall_mode`, and
  `heimdall_attempt_id` when the flow carries an attempt. There is no
  `heimdall_completion_code`; a page with none, and `heimdall_error`, is a refusal.
  A fault is a different `heimdall_error` (`provider_error` and others).
- **postMessage** carries `{source: "heimdall", kind: "oauth_result",
  status: "error", error: "consent_refused", by, provider, appSlug, mode,
  returnTo, handoffKind, attemptId?}`.
- **Backend callback apps** get the same result POSTed to their callback URL
  (`status: "error"`, `error: "consent_refused"`, `by`, `attemptId`). An auth
  attempt is marked `denied` with `denialCode: "consent_refused"`, which
  `completeAuth` returns as `denied`.

`tests/joystick-consent.test.ts` ("the refusal return contract") pins the
fragment for both refusals and the attempt id.

## 5. Out of scope

Enabling Joystick in `identityProviders`; fixing
`joystick:follow_up:connect-start-needs-app-auth`; revoking at the provider
(Joystick offers no revocation call Heimdall uses); retention or deletion of
consent receipts and of the audit rows; consent for the creator's audience.

## 6. Tests

`tests/joystick-consent.test.ts` holds one behaviour per rule above. Rules were
checked by mutation, each mutant run on its own with a 300 s limit under an 8 GB
address-space cap (the PR lists them). The Postgres statements for
`consent_receipts` are exercised by `tests/store.test.ts` against the fake pool
and, when `HEIMDALL_TEST_PG_ADMIN_URL` is set, against a live database
(`scripts/test-live-pg.sh`); the live run was not possible where this was built.
