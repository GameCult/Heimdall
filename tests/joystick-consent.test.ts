import { createHash, randomBytes } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp, getHeimdallRuntimeContext, startOAuthFlow } from "../src/app.js";
import { resolveAppCaller } from "../src/app-caller.js";
import { consentDigest, consentText, digestOfText, type ConsentAsk } from "../src/consent.js";
import { decodeJwt, signJwt } from "../src/signing.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { providerCatalog } from "../src/providers.js";
import { InMemoryStore } from "../src/store/index.js";
import { createTestConfig, setCookieOf, stateOf } from "./oauth-flow.js";

// The consent cut for managed custody (docs/joystick-consent-flow.md): the ask,
// the typed refusal, the receipt, and the signed-in page that lists and revokes.

const apps: FastifyInstance[] = [];
afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  while (apps.length) await apps.pop()?.close();
});

const defaultScopes = providerCatalog.joystick.defaultScopes;
const secret = { "x-heimdall-app-secret": "streampixels-secret" };
const form = { "content-type": "application/x-www-form-urlencoded" };

/** A Joystick that returns whatever `code-<user>` names, granting only `granted`. */
function joystick(granted: string[] = ["identity:read", "stream:read"]): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode({ code }) {
      return { accessToken: `joy-access-${code}`, refreshToken: `joy-refresh-${code}`, tokenType: "Bearer", scope: granted, expiresAt: "2099-01-01T00:00:00.000Z", raw: {} };
    },
    async resolveIdentity({ accessToken }) {
      const id = accessToken.replace("joy-access-code-", "");
      return { provider: "joystick", providerUserId: `joy-${id}`, username: id, profile: { id } };
    },
    async evaluateEntitlements() {
      return { facts: [], snapshots: [] };
    },
  };
}

async function newApp(options: { granted?: string[]; callbacks?: string[] } = {}) {
  const store = new InMemoryStore();
  const config = createTestConfig();
  if (options.callbacks) config.appBackendCallbacks = { streampixels: options.callbacks };
  const app = await buildApp({ config, store, oauthRuntimes: { joystick: joystick(options.granted) } });
  apps.push(app);
  return { app, store };
}

async function startConnect(app: FastifyInstance, handoff: Record<string, unknown> = { kind: "browser_completion" }) {
  const response = await app.inject({
    method: "POST",
    url: "/v1/oauth/joystick/start",
    headers: secret,
    payload: {
      appSlug: "streampixels",
      mode: "connect",
      connection: { kind: "creator", targetId: "creator-1" },
      returnTo: "https://streampixels.gamecult.org/settings",
      handoff,
    },
  });
  expect(response.statusCode).toBe(201);
  return stateOf(response.json());
}

const launchUrl = (state: string) => `/v1/oauth/joystick/launch?state=${encodeURIComponent(state)}`;
const cookieNamed = (prefix: string) => (response: { headers: Record<string, unknown> }) =>
  setCookieOf(response).find((value) => value.startsWith(prefix))?.split(";")[0];
const askCookieOf = cookieNamed("__Host-heimdall-ask-");
const bindingCookieOf = cookieNamed("__Host-heimdall-oauth-");

/** The browser is shown the ask. The cookie it keeps is the ask's, which binds nothing. */
async function seeAsk(app: FastifyInstance, state: string) {
  const response = await app.inject({ method: "GET", url: launchUrl(state), headers: { accept: "text/html" } });
  expect(response.statusCode).toBe(200);
  expect(bindingCookieOf(response), "the ask must not set the launch binding").toBeUndefined();
  return { page: response, cookie: askCookieOf(response)! };
}

function answer(app: FastifyInstance, state: string, decision: "continue" | "decline", cookie?: string, accept = "text/html") {
  return app.inject({
    method: "POST",
    url: "/v1/oauth/joystick/consent",
    headers: { ...form, accept, ...(cookie ? { cookie } : {}) },
    payload: new URLSearchParams({ state, decision }).toString(),
  });
}

function callback(app: FastifyInstance, state: string, cookie: string, query: string, accept = "application/json") {
  return app.inject({
    method: "GET",
    url: `/v1/oauth/joystick/callback?state=${encodeURIComponent(state)}&${query}`,
    headers: { cookie, accept },
  });
}

/** Ask, accept, and complete as Joystick user `user`; returns the callback's JSON. */
async function grantAs(app: FastifyInstance, user: string) {
  const state = await startConnect(app);
  const asked = await seeAsk(app, state);
  const go = await answer(app, state, "continue", asked.cookie);
  expect(go.statusCode).toBe(302);
  const done = await callback(app, state, bindingCookieOf(go)!, `code=code-${user}`);
  expect(done.statusCode).toBe(201);
  return done.json() as { accessToken: string; consentReceiptId: string; account: { id: string }; session: { accountId: string } };
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const grantsOf = async (app: FastifyInstance, token: string) =>
  (await app.inject({ method: "GET", url: "/v1/me/grants", headers: bearer(token) })).json() as { grants: Array<Record<string, any>>; receipts: Array<Record<string, any>> };
const resolveCredential = (app: FastifyInstance, accountId: string) =>
  app.inject({ method: "POST", url: "/v1/apps/streampixels/managed-credentials/resolve", headers: secret, payload: { accountId, provider: "joystick" } });

describe("the ask", () => {
  it("launch shows a Heimdall page naming app, provider, scopes and custody, and does not redirect", async () => {
    const { app } = await newApp();
    const { page } = await seeAsk(app, await startConnect(app));
    expect(page.headers.location).toBeUndefined();
    for (const needle of ["StreamPixels", "Joystick", ...defaultScopes, "refresh token", "streampixels.gamecult.org", "Continue to Joystick", "No, return to the app"]) {
      expect(page.body).toContain(needle);
    }
    expect(page.body).not.toContain("<script");
    expect(page.headers["content-security-policy"]).toContain("form-action 'self' https://joystick.tv");
  });

  it("viewing the ask claims nothing: the launch is still spendable once after any number of views", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    await seeAsk(app, state);
    const { cookie } = await seeAsk(app, state);
    expect((await answer(app, state, "continue", cookie)).statusCode).toBe(302);
    const again = await answer(app, state, "continue", cookie, "application/json");
    expect(again.statusCode).toBe(400);
    expect(again.json()).toEqual({ error: "state_already_launched" });
  });

  it("Continue sends exactly the scopes the page listed", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    const go = await answer(app, state, "continue", cookie);
    expect(go.statusCode).toBe(302);
    const target = new URL(go.headers.location as string);
    expect(target.origin).toBe("https://joystick.tv");
    expect(target.searchParams.get("scope")).toBe(defaultScopes.join(" "));
  });

  it("a flow with no custody (sign-in through an identity provider) gets no ask and redirects as before", async () => {
    const { app } = await newApp();
    const start = await app.inject({
      method: "POST",
      url: "/v1/oauth/twitch/start",
      headers: secret,
      payload: { appSlug: "streampixels", mode: "sign_in", returnTo: "https://streampixels.gamecult.org/", handoff: { kind: "browser_completion" } },
    });
    expect(start.statusCode).toBe(201);
    const launch = await app.inject({ method: "GET", url: `/v1/oauth/twitch/launch?state=${encodeURIComponent(stateOf(start.json()))}`, headers: { accept: "text/html" } });
    expect(launch.statusCode).toBe(302);
  });

  it("an answer without the cookie the ask set is refused and spends nothing", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    for (const decision of ["continue", "decline"] as const) {
      const stranger = await answer(app, state, decision, undefined, "application/json");
      expect(stranger.statusCode, decision).toBe(400);
      expect(stranger.json(), decision).toEqual({ error: "state_not_bound" });
    }
    expect((await answer(app, state, "continue", cookie)).statusCode).toBe(302);
  });

  it("a stranger who only opens the launch URL is not bound to the state and cannot complete it", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const victim = await seeAsk(app, state);
    await answer(app, state, "continue", victim.cookie);
    // A fresh browser that holds the URL loads the ask and calls back with its own provider code.
    const stranger = await seeAsk(app, state);
    for (const cookie of [stranger.cookie, ""]) {
      const done = await callback(app, state, cookie, "code=code-attacker");
      expect(done.statusCode).toBe(400);
      expect(done.json()).toEqual({ error: "state_not_bound" });
    }
  });

  it("only Continue sets the launch binding, and the ask's cookie is no binding: it cannot complete a callback", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const asked = await seeAsk(app, state);
    const done = await callback(app, state, asked.cookie, "code=code-a");
    expect(done.json()).toEqual({ error: "state_not_bound" });
    const go = await answer(app, state, "continue", asked.cookie);
    expect(bindingCookieOf(go)).toBeDefined();
    expect(bindingCookieOf(go)!.length).toBeLessThan(3500);
  });

  it("a binding without the shown wording is refused with consent_text_missing before the state is spent", async () => {
    const { app, store } = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const state = await startConnect(app);
    const { jti, exp } = decodeJwt(state).payload as { jti: string; exp: number };
    // A binding that names this state but carries no wording: what a launch from before the ask would leave.
    const bare = signJwt({ typ: "heimdall_oauth_binding", iss: ctx.config.issuer, jti, iat: exp - 600, exp }, ctx.keys);
    const done = await callback(app, state, `__Host-heimdall-oauth-${jti}=${bare}`, "code=code-a");
    expect(done.statusCode).toBe(400);
    expect(done.json()).toEqual({ error: "consent_text_missing" });
    expect(await store.findStoredLinkedIdentity("joystick", "joy-a"), "no credential is kept").toBeNull();
    // Neither use of the state was spent by the refusal.
    const usedAt = new Date().toISOString();
    const expiresAt = new Date(exp * 1000).toISOString();
    expect(await store.claimOAuthStateUse({ jti, phase: "callback", appSlug: "streampixels", usedAt, expiresAt })).toBe(true);
  });

  describe("the wording a cookie may carry", () => {
    const signedAsk = (ctx: ReturnType<typeof getHeimdallRuntimeContext>, jti: string, exp: number, text: Buffer) =>
      signJwt({ typ: "heimdall_consent_ask", iss: ctx.config.issuer, jti, iat: exp - 600, exp, ct: deflateRawSync(text).toString("base64url") }, ctx.keys);

    it("is read up to 16 KB and no further: one byte over is refused, and a bomb is refused quickly", async () => {
      const { app } = await newApp();
      const ctx = getHeimdallRuntimeContext(app);
      const state = await startConnect(app);
      const { jti, exp } = decodeJwt(state).payload as { jti: string; exp: number };
      const answerWith = (text: Buffer, decision: "decline" | "continue" = "decline") =>
        answer(app, state, decision, `__Host-heimdall-ask-${jti}=${signedAsk(ctx, jti, exp, text)}`, "application/json");
      expect((await answerWith(Buffer.alloc(16 * 1024 + 1, 97))).json()).toEqual({ error: "state_not_bound" });
      const t0 = Date.now();
      expect((await answerWith(Buffer.alloc(300 * 1024 * 1024))).json()).toEqual({ error: "state_not_bound" });
      expect(Date.now() - t0).toBeLessThan(1500);
      // At the cap it is read.
      expect((await answerWith(Buffer.alloc(16 * 1024, 97))).json()).toMatchObject({ error: "consent_refused" });
    });

    it("requested scopes are capped at 32 of 512 characters, at start", async () => {
      const { app } = await newApp();
      const startWith = (requestedScopes: string[]) =>
        app.inject({
          method: "POST",
          url: "/v1/oauth/joystick/start",
          headers: secret,
          payload: { appSlug: "streampixels", mode: "connect", connection: { kind: "creator", targetId: "c" }, returnTo: "https://streampixels.gamecult.org/s", handoff: { kind: "browser_completion" }, requestedScopes },
        });
      const scopes = (n: number, len: number) => Array.from({ length: n }, (_, i) => `${i}`.padEnd(len, "x"));
      expect((await startWith(scopes(33, 10))).json()).toMatchObject({ error: "requested_scopes_too_large" });
      expect((await startWith(scopes(1, 513))).json()).toMatchObject({ error: "requested_scopes_too_large" });
      expect((await startWith(scopes(32, 512))).statusCode).toBe(201);
    });

    it("an ask the cookies could not carry is refused, not shown", async () => {
      const { app } = await newApp();
      const noise = Array.from({ length: 32 }, () => randomBytes(256).toString("hex")); // 32 x 512 incompressible
      const start = await app.inject({
        method: "POST",
        url: "/v1/oauth/joystick/start",
        headers: secret,
        payload: { appSlug: "streampixels", mode: "connect", connection: { kind: "creator", targetId: "c" }, returnTo: "https://streampixels.gamecult.org/s", handoff: { kind: "browser_completion" }, requestedScopes: noise },
      });
      expect(start.statusCode).toBe(201);
      const page = await app.inject({ method: "GET", url: launchUrl(stateOf(start.json())), headers: { accept: "text/html" } });
      expect(page.statusCode).toBe(400);
      expect(page.json()).toEqual({ error: "consent_ask_too_large" });
      expect(askCookieOf(page)).toBeUndefined();
    });
  });

  it("the consent route refuses a flow that has no ask", async () => {
    const { app } = await newApp();
    const start = await app.inject({
      method: "POST",
      url: "/v1/oauth/twitch/start",
      headers: secret,
      payload: { appSlug: "streampixels", mode: "sign_in", returnTo: "https://streampixels.gamecult.org/", handoff: { kind: "browser_completion" } },
    });
    const state = stateOf(start.json());
    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/twitch/consent",
      headers: form,
      payload: new URLSearchParams({ state, decision: "continue" }).toString(),
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "consent_not_required" });
  });
});

describe("the wording digest", () => {
  const ask: ConsentAsk = { appSlug: "streampixels", provider: "joystick", scopes: ["identity:read"], returnOrigin: "https://streampixels.gamecult.org" };
  it("is the sha-256 of the text shown, and moves with the app, provider, scopes and origin", () => {
    expect(consentDigest(ask)).toBe(createHash("sha256").update(consentText(ask), "utf8").digest("hex"));
    const variants: ConsentAsk[] = [
      { ...ask, appSlug: "bifrost" },
      { ...ask, provider: "twitch" },
      { ...ask, scopes: ["identity:read", "chat:read"] },
      { ...ask, returnOrigin: "https://elsewhere.example" },
    ];
    for (const variant of variants) expect(consentDigest(variant)).not.toBe(consentDigest(ask));
  });
});

describe("refusal", () => {
  it("declining yields consent_refused by the viewer, stores nothing, and spends the state", async () => {
    const { app, store } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    const no = await answer(app, state, "decline", cookie, "application/json");
    expect(no.statusCode).toBe(400);
    expect(no.json()).toMatchObject({ error: "consent_refused", by: "viewer", provider: "joystick" });

    // Nothing launches or completes afterwards, and nothing was kept.
    expect((await answer(app, state, "continue", cookie, "application/json")).json()).toEqual({ error: "state_already_launched" });
    expect((await callback(app, state, cookie, "code=code-a")).json()).toEqual({ error: "state_not_bound" });
    expect(await store.findStoredLinkedIdentity("joystick", "joy-a")).toBeNull();
    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string; eventPayloadJson: unknown }> }).auditEvents.values()];
    expect(events.filter((event) => event.eventType === "consent_refused").map((event) => event.eventPayloadJson)).toEqual([
      { provider: "joystick", mode: "connect", by: "viewer" },
    ]);
  });

  it("the browser sees a 'Not Connected' page, not an authentication failure", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    const no = await answer(app, state, "decline", cookie);
    expect(no.statusCode).toBe(200);
    expect(no.body).toContain("Not Connected");
    expect(no.body).toContain("consent_refused");
    expect(no.body).not.toContain("Authentication Failed");
  });

  it("an access_denied from the provider is consent_refused by the provider, distinct from provider_error", async () => {
    const { app, store } = await newApp();
    const denied = await newFlow(app);
    const response = await callback(app, denied.state, denied.cookie, "error=access_denied");
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: "consent_refused", by: "provider" });

    const faulty = await newFlow(app);
    expect((await callback(app, faulty.state, faulty.cookie, "error=server_error")).json().error).toBe("provider_error");
    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string }> }).auditEvents.values()];
    expect(events.filter((event) => event.eventType === "consent_refused")).toHaveLength(1);
  });

  it("a backend_callback app is told, with who refused", async () => {
    const callbackUrl = "https://streampixels.gamecult.org/api/heimdall/callback";
    const { app } = await newApp({ callbacks: [callbackUrl] });
    const delivered: Array<Record<string, unknown>> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      delivered.push(JSON.parse(String(init?.body)));
      return new Response("ok", { status: 200 });
    });
    const handoff = { kind: "backend_callback", callbackUrl, attemptId: "attempt-1" };

    const byViewer = await startConnect(app, handoff);
    const { cookie } = await seeAsk(app, byViewer);
    await answer(app, byViewer, "decline", cookie);
    const byProvider = await startConnect(app, handoff);
    const second = await seeAsk(app, byProvider);
    const proceeded = await answer(app, byProvider, "continue", second.cookie);
    await callback(app, byProvider, bindingCookieOf(proceeded)!, "error=access_denied");

    expect(delivered.map((payload) => [payload.status, payload.error, payload.by])).toEqual([
      ["error", "consent_refused", "viewer"],
      ["error", "consent_refused", "provider"],
    ]);
  });
});

/** What an app's landing page can read: the fragment on the page's "Return to the app" link. */
function returnFragment(page: { body: string }): URLSearchParams {
  const href = /id="return-link" href="([^"]+)"/.exec(page.body)?.[1];
  expect(href, "the page carries a return link").toBeDefined();
  const url = new URL(href!);
  expect(url.origin + url.pathname).toBe("https://streampixels.gamecult.org/settings");
  return new URLSearchParams(url.hash.slice(1));
}

describe("the refusal return contract", () => {
  const refusedFragment = (by: "viewer" | "provider") => ({
    heimdall_status: "error",
    heimdall_provider: "joystick",
    heimdall_handoff_kind: "browser_completion",
    heimdall_app_slug: "streampixels",
    heimdall_mode: "connect",
    heimdall_error: "consent_refused",
    heimdall_refused_by: by,
  });

  it("a decline returns a fragment that says the viewer refused, with no completion code", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    const fragment = returnFragment(await answer(app, state, "decline", cookie));
    expect(Object.fromEntries(fragment)).toEqual(refusedFragment("viewer"));
    expect(fragment.has("heimdall_completion_code")).toBe(false);
  });

  it("a provider access_denied returns a fragment that says the provider refused, with no completion code", async () => {
    const { app } = await newApp();
    const flow = await newFlow(app);
    const fragment = returnFragment(await callback(app, flow.state, flow.cookie, "error=access_denied", "text/html"));
    expect(Object.fromEntries(fragment)).toEqual(refusedFragment("provider"));
    expect(fragment.has("heimdall_completion_code")).toBe(false);
  });

  it.each(["viewer", "provider"] as const)("a browser_completion attempt refused by the %s is named in the fragment", async (by) => {
    const { app, store } = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const attempt = await store.createAuthAttempt({
      handle: "attempt-refused",
      appSlug: "streampixels",
      provider: "joystick",
      mode: "connect",
      returnTo: "https://streampixels.gamecult.org/settings",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });
    const caller = resolveAppCaller(ctx.config, "streampixels", secret);
    const started = await startOAuthFlow(
      ctx,
      "joystick",
      caller,
      { appSlug: "streampixels", mode: "connect", connection: { kind: "creator", targetId: "creator-1" }, returnTo: "https://streampixels.gamecult.org/settings", handoff: { kind: "browser_completion" } },
      { trustedBrowserAttemptId: attempt.handle }
    );
    expect(started.statusCode).toBe(201);
    const state = stateOf(started.body as Parameters<typeof stateOf>[0]);
    const { cookie } = await seeAsk(app, state);
    let page;
    if (by === "viewer") {
      page = await answer(app, state, "decline", cookie);
    } else {
      const go = await answer(app, state, "continue", cookie);
      page = await callback(app, state, bindingCookieOf(go)!, "error=access_denied", "text/html");
    }
    expect(Object.fromEntries(returnFragment(page))).toEqual({ ...refusedFragment(by), heimdall_attempt_id: "attempt-refused" });
  });
});

async function newFlow(app: FastifyInstance) {
  const state = await startConnect(app);
  const { cookie } = await seeAsk(app, state);
  const go = await answer(app, state, "continue", cookie);
  expect(go.statusCode).toBe(302);
  return { state, cookie: bindingCookieOf(go)! };
}

describe("the receipt", () => {
  it("a granted completion writes one receipt with asked and granted scopes and the digest of the wording shown", async () => {
    const { app, store } = await newApp({ granted: ["identity:read", "stream:read"] });
    const done = await grantAs(app, "a");
    const receipts = await store.listConsentReceipts(done.account.id);
    expect(receipts).toHaveLength(1);
    const ask: ConsentAsk = { appSlug: "streampixels", provider: "joystick", scopes: defaultScopes, returnOrigin: "https://streampixels.gamecult.org" };
    expect(receipts[0]).toMatchObject({
      id: done.consentReceiptId,
      kind: "grant",
      accountId: done.account.id,
      appSlug: "streampixels",
      provider: "joystick",
      scopesAsked: defaultScopes,
      scopesGranted: ["identity:read", "stream:read"],
      consentPageDigest: consentDigest(ask),
    });
  });

  it("the receipt holds the wording the person was shown, and its digest is that wording's hash", async () => {
    const { app, store } = await newApp();
    const state = await startConnect(app);
    const asked = await seeAsk(app, state);
    const go = await answer(app, state, "continue", asked.cookie);
    const done = await callback(app, state, bindingCookieOf(go)!, "code=code-a");
    const [receipt] = await store.listConsentReceipts(done.json().account.id);
    if (receipt?.kind !== "grant") throw new Error("no grant");
    expect(receipt.consentPageDigest).toBe(digestOfText(receipt.consentText));
    const shown = asked.page.body.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&gt;/g, ">").replace(/&lt;/g, "<").replace(/&amp;/g, "&");
    for (const line of receipt.consentText.split("\n")) expect(shown, line).toContain(line);
    expect(receipt.consentText).toContain("Continue to Joystick");
    expect(receipt.consentText).toContain("No, return to the app");
  });

  it("a refusal leaves no receipt", async () => {
    const { app, store } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    await answer(app, state, "decline", cookie);
    expect(await store.listConsentReceipts("anyone")).toEqual([]);
    expect((await store.findStoredLinkedIdentity("joystick", "joy-a"))).toBeNull();
  });

  it("the success page names the receipt", async () => {
    const { app } = await newApp();
    const state = await startConnect(app);
    const { cookie } = await seeAsk(app, state);
    const go = await answer(app, state, "continue", cookie);
    const page = await callback(app, state, bindingCookieOf(go)!, "code=code-a", "text/html");
    expect(page.statusCode).toBe(200);
    expect(page.body).toMatch(/receipt [0-9a-f-]{36}/);
  });
});

describe("my grants", () => {
  it("is closed to anyone without a live Heimdall access token", async () => {
    const { app } = await newApp();
    for (const headers of [{}, bearer("not-a-token")]) {
      const response = await app.inject({ method: "GET", url: "/v1/me/grants", headers });
      expect(response.statusCode).toBe(401);
      expect(response.json().error).toBe("sign_in_required");
    }
    const link = await app.inject({ method: "POST", url: "/v1/me/grants/link" });
    expect(link.statusCode).toBe(401);
    const revoke = await app.inject({ method: "POST", url: "/v1/me/grants/x/revoke" });
    expect(revoke.statusCode).toBe(401);
  });

  it("lists the signed-in account's grants and receipts, and no one else's", async () => {
    const { app } = await newApp();
    const a = await grantAs(app, "a");
    const b = await grantAs(app, "b");
    const mine = await grantsOf(app, a.accessToken);
    expect(mine.grants).toHaveLength(1);
    expect(mine.grants[0]).toMatchObject({ id: a.consentReceiptId, status: "active", provider: "joystick", appSlug: "streampixels", scopesGranted: ["identity:read", "stream:read"] });
    expect(JSON.stringify(mine)).not.toContain(b.consentReceiptId);
    expect(mine.receipts.map((receipt) => receipt.accountId)).toEqual([a.account.id]);
  });

  it("revoke takes effect on the next token use, edits no row, and receipts the revocation", async () => {
    const { app, store } = await newApp();
    const a = await grantAs(app, "a");
    expect((await resolveCredential(app, a.account.id)).statusCode).toBe(200);
    const before = await store.listConsentReceipts(a.account.id);

    const revoke = await app.inject({ method: "POST", url: `/v1/me/grants/${a.consentReceiptId}/revoke`, headers: bearer(a.accessToken) });
    expect(revoke.statusCode).toBe(200);
    expect(revoke.json().revoked).toEqual([a.consentReceiptId]);

    const next = await resolveCredential(app, a.account.id);
    expect(next.statusCode).toBe(410);
    expect(next.json().error).toBe("managed_credential_revoked");

    const after = await store.listConsentReceipts(a.account.id);
    expect(after).toHaveLength(2);
    expect(after[0]).toEqual(before[0]);
    expect(after[1]).toMatchObject({ kind: "revocation", revokesReceiptId: a.consentReceiptId, accountId: a.account.id });
    const view = (await grantsOf(app, a.accessToken)).grants[0]!;
    expect(view).toMatchObject({ status: "revoked", revocationReceiptId: after[1]!.id });
    expect(view.revokedAt).toBe(after[1]!.createdAt);
  });

  it("revoke is the owner's alone: another account's grant id is not found and its credential is untouched", async () => {
    const { app } = await newApp();
    const a = await grantAs(app, "a");
    const b = await grantAs(app, "b");
    const attempt = await app.inject({ method: "POST", url: `/v1/me/grants/${a.consentReceiptId}/revoke`, headers: bearer(b.accessToken) });
    expect(attempt.statusCode).toBe(404);
    expect((await resolveCredential(app, a.account.id)).statusCode).toBe(200);
    expect((await resolveCredential(app, b.account.id)).statusCode).toBe(200);
  });

  it("revoking twice changes nothing the second time", async () => {
    const { app, store } = await newApp();
    const a = await grantAs(app, "a");
    const url = `/v1/me/grants/${a.consentReceiptId}/revoke`;
    await app.inject({ method: "POST", url, headers: bearer(a.accessToken) });
    const second = await app.inject({ method: "POST", url, headers: bearer(a.accessToken) });
    expect(second.statusCode).toBe(200);
    expect(second.json().revoked).toEqual([]);
    expect(await store.listConsentReceipts(a.account.id)).toHaveLength(2);
    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string }> }).auditEvents.values()];
    expect(events.filter((event) => event.eventType === "consent_revoked")).toHaveLength(1);
  });

  it("a fresh connection after a revoke is a new grant, live again, and the old one stays revoked", async () => {
    const { app } = await newApp();
    const first = await grantAs(app, "a");
    await app.inject({ method: "POST", url: `/v1/me/grants/${first.consentReceiptId}/revoke`, headers: bearer(first.accessToken) });
    const second = await grantAs(app, "a");
    expect(second.consentReceiptId).not.toBe(first.consentReceiptId);
    expect((await resolveCredential(app, second.account.id)).statusCode).toBe(200);
    const grants = (await grantsOf(app, second.accessToken)).grants;
    expect(grants.map((grant) => [grant.id, grant.status])).toEqual([
      [first.consentReceiptId, "revoked"],
      [second.consentReceiptId, "active"],
    ]);
  });

  it("a browser with no session opens the page from a minted link and revokes with one form post", async () => {
    const { app } = await newApp();
    const a = await grantAs(app, "a");
    const link = await app.inject({ method: "POST", url: "/v1/me/grants/link", headers: bearer(a.accessToken) });
    expect(link.statusCode).toBe(201);
    const url = new URL(link.json().url as string);
    const page = await app.inject({ method: "GET", url: `${url.pathname}${url.search}`, headers: { accept: "text/html" } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain(a.consentReceiptId);
    expect(page.body).toContain("Take this back");
    expect(page.body).not.toContain("<script");

    const token = url.searchParams.get("t")!;
    const post = await app.inject({
      method: "POST",
      url: `/v1/me/grants/${a.consentReceiptId}/revoke`,
      headers: { ...form, accept: "text/html" },
      payload: new URLSearchParams({ t: token }).toString(),
    });
    expect(post.statusCode).toBe(200);
    expect(post.body).toContain("Taken back.");
    expect((await resolveCredential(app, a.account.id)).statusCode).toBe(410);
  });

  it("a page link is never renewed by being used: the forms on its page expire when the link does", async () => {
    const { app } = await newApp();
    const a = await grantAs(app, "a");
    const link = await app.inject({ method: "POST", url: "/v1/me/grants/link", headers: bearer(a.accessToken) });
    const url = new URL(link.json().url as string);
    const linkToken = url.searchParams.get("t")!;
    // Two minutes on, so a form token minted afresh would differ from the link's.
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 120_000 });
    const page = await app.inject({ method: "GET", url: `${url.pathname}${url.search}`, headers: { accept: "text/html" } });
    const formToken = /name="t" value="([^"]+)"/.exec(page.body)![1]!;
    expect(decodeJwt(formToken).payload.exp).toBe(decodeJwt(linkToken).payload.exp);
    // The same holds one hop on: the page a form post answers with.
    const post = await app.inject({
      method: "POST",
      url: "/v1/me/grants/nope/revoke",
      headers: { ...form, accept: "text/html" },
      payload: new URLSearchParams({ t: formToken }).toString(),
    });
    expect(post.statusCode).toBe(404);
    // A bearer, by contrast, opens a fresh window.
    const fresh = await app.inject({ method: "GET", url: "/v1/me/grants", headers: { ...bearer(a.accessToken), accept: "text/html" } });
    const freshToken = /name="t" value="([^"]+)"/.exec(fresh.body)![1]!;
    expect(decodeJwt(freshToken).payload.exp).toBeGreaterThanOrEqual(decodeJwt(linkToken).payload.exp as number);
  });

  it("two revokes at once take the grant back once: one revocation row, one audit event, one reporter", async () => {
    const { app, store } = await newApp();
    const a = await grantAs(app, "a");
    const url = `/v1/me/grants/${a.consentReceiptId}/revoke`;
    const [one, two] = await Promise.all([
      app.inject({ method: "POST", url, headers: bearer(a.accessToken) }),
      app.inject({ method: "POST", url, headers: bearer(a.accessToken) }),
    ]);
    expect([one.json().revoked.length, two.json().revoked.length].sort()).toEqual([0, 1]);
    expect((await store.listConsentReceipts(a.account.id)).filter((r) => r.kind === "revocation")).toHaveLength(1);
    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string }> }).auditEvents.values()];
    expect(events.filter((event) => event.eventType === "consent_revoked")).toHaveLength(1);
  });

  it("a page link proves only what it was minted for: an access token, a foreign token or none opens nothing", async () => {
    const { app } = await newApp();
    const a = await grantAs(app, "a");
    for (const t of [a.accessToken, "garbage", ""]) {
      const response = await app.inject({ method: "GET", url: `/v1/me/grants?t=${encodeURIComponent(t)}` });
      expect(response.statusCode, t).toBe(401);
      const revoke = await app.inject({
        method: "POST",
        url: `/v1/me/grants/${a.consentReceiptId}/revoke`,
        headers: form,
        payload: new URLSearchParams({ t }).toString(),
      });
      expect(revoke.statusCode, t).toBe(401);
    }
    expect((await resolveCredential(app, a.account.id)).statusCode).toBe(200);
  });
});
