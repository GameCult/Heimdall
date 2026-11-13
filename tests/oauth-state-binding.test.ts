import { generateKeyPairSync, randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp, getHeimdallRuntimeContext, startOAuthFlow } from "../src/app.js";
import { resolveAppCaller } from "../src/app-caller.js";
import { decodeJwt, signJwt } from "../src/signing.js";
import { OAUTH_STATE_PRUNE_BATCH, OAUTH_STATE_PRUNE_MARGIN_MS, OAUTH_STATE_SKEW_MS } from "../src/store/types.js";
import { createMockDiscordRuntime, createTestConfig, launchFlow, setCookieOf, stateOf } from "./oauth-flow.js";

// Heimdall's OAuth states complete once, only in the browser that launched
// them (finding state-replay). Soul's attack: a Bifrost state is readable in
// the URL the victim's browser is sent to, so an attacker who sees it opens it
// in their own browser, finishes the provider login as themselves, and hands
// the victim the resulting completion code.

const apps: FastifyInstance[] = [];
afterEach(async () => {
  vi.useRealTimers();
  while (apps.length) {
    await apps.pop()?.close();
  }
});

const victimAttempt = "VICTIM-ATTEMPT-NONCE";
const bifrostReturn = `https://bifrost.gamecult.org/auth/heimdall/complete?attempt=${victimAttempt}`;

async function newApp() {
  const app = await buildApp({ config: createTestConfig(), oauthRuntimes: { discord: createMockDiscordRuntime() } });
  apps.push(app);
  return app;
}

async function bifrostStart(app: FastifyInstance, extra: Record<string, unknown> = {}) {
  const response = await app.inject({
    method: "POST",
    url: "/v1/oauth/discord/start",
    headers: { "x-heimdall-app-secret": "bifrost-secret" },
    payload: { appSlug: "bifrost", mode: "sign_in", returnTo: bifrostReturn, handoff: { kind: "browser_completion" }, ...extra },
  });
  expect(response.statusCode).toBe(201);
  return response.json() as { authorizationUrl: string };
}

function launchUrl(start: { authorizationUrl: string }): string {
  const url = new URL(start.authorizationUrl);
  return `${url.pathname}${url.search}`;
}

function callback(app: FastifyInstance, state: string, cookie?: string, query = "code=attacker-code") {
  return app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?${query}&state=${encodeURIComponent(state)}`,
    ...(cookie ? { headers: { cookie } } : {}),
  });
}

describe("OAuth state binding", () => {
  it("Soul's replay fails: one state, at most one completion code, and only for the browser that launched it", async () => {
    const app = await newApp();
    const start = await bifrostStart(app);
    const state = stateOf(start);

    const victim = await launchFlow(app, start);

    // The attacker holds the same state. A second launch yields no cookie and no redirect.
    const attackerLaunch = await app.inject({ method: "GET", url: launchUrl(start) });
    expect(attackerLaunch.statusCode).toBe(400);
    expect(attackerLaunch.json()).toEqual({ error: "state_already_launched" });
    expect(setCookieOf(attackerLaunch)).toEqual([]);
    expect(attackerLaunch.headers.location).toBeUndefined();

    // Without the cookie the callback refuses and mints nothing.
    const attackerCallback = await callback(app, state);
    expect(attackerCallback.statusCode).toBe(400);
    expect(attackerCallback.json()).toEqual({ error: "state_not_bound" });
    expect(attackerCallback.body).not.toContain("completion");

    // The victim's callback still completes, once.
    const victimCallback = await callback(app, state, victim.cookie, "code=victim-code");
    expect(victimCallback.statusCode).toBe(201);
    const completionCode = victimCallback.json().completion.code as string;
    const redeem = await app.inject({
      method: "POST",
      url: "/v1/apps/bifrost/auth-completions/redeem",
      payload: { completionCode },
    });
    expect(redeem.statusCode).toBe(201);
    expect(redeem.json()).toEqual(expect.objectContaining({ status: "success", appSlug: "bifrost" }));

    const second = await callback(app, state, victim.cookie, "code=victim-code");
    expect(second.statusCode).toBe(400);
    expect(second.json()).toEqual({ error: "state_already_used" });
    expect(second.body).not.toContain("completion");
  });

  it("a stranger's callback needs no launch to be refused: no cookie, no completion code", async () => {
    const app = await newApp();
    const start = await bifrostStart(app);

    const response = await callback(app, stateOf(start));
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "state_not_bound" });
    expect(response.body).not.toContain("completion");
  });

  it("a cookie for another flow, another key, another type, or the wrong lifetime does not bind", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const own = await bifrostStart(app);
    const attackerFlow = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" },
    });
    const attackerStart = attackerFlow.json() as { authorizationUrl: string };
    const attackerCookie = (await launchFlow(app, attackerStart)).cookie;
    const ownState = stateOf(own);
    const ownJti = decodeJwt(ownState).payload.jti as string;
    const name = `__Host-heimdall-oauth-${ownJti}`;
    const now = Math.floor(Date.now() / 1000);
    const binding = (overrides: Record<string, unknown>, keys = ctx.keys) =>
      signJwt({ typ: "heimdall_oauth_binding", iss: ctx.config.issuer, jti: ownJti, iat: now, exp: now + 300, ...overrides }, keys);
    const foreignKeys = (() => {
      const pair = generateKeyPairSync("ed25519");
      return { ...ctx.keys, privateKey: pair.privateKey, publicKey: pair.publicKey };
    })();

    const forged: Record<string, string> = {
      "another flow's binding under this flow's cookie name": `${name}=${attackerCookie.split("=")[1]}`,
      "a binding signed with a different key": `${name}=${binding({}, foreignKeys)}`,
      "a binding for a different jti": `${name}=${binding({ jti: "someone-else" })}`,
      "a binding of another type": `${name}=${binding({ typ: "heimdall_oauth_state" })}`,
      "a binding from another issuer": `${name}=${binding({ iss: "https://elsewhere.example" })}`,
      "an expired binding": `${name}=${binding({ exp: now - 5 })}`,
      "the state token used as the cookie": `${name}=${ownState}`,
      "a binding whose exp is a string": `${name}=${binding({ exp: String(now + 300) })}`,
      "an empty cookie": `${name}=`,
    };
    for (const [label, cookie] of Object.entries(forged)) {
      const response = await callback(app, ownState, cookie);
      expect(response.statusCode, label).toBe(400);
      expect(response.json(), label).toEqual({ error: "state_not_bound" });
    }

    // A correctly signed binding for this jti is the one thing that binds.
    const good = await callback(app, ownState, `${name}=${binding({})}`);
    expect(good.statusCode).toBe(201);
  });

  it("the cookie is checked before the state is consumed: a stranger cannot burn or deny the victim's flow", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const attempt = await ctx.store.createAuthAttempt({
      handle: "attempt-1",
      appSlug: "repixelizer",
      provider: "discord",
      mode: "sign_in",
      returnTo: "https://repixelizer.gamecult.org/app/",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });
    const caller = resolveAppCaller(ctx.config, "repixelizer", { "x-heimdall-app-secret": "repixelizer-secret" });
    const started = await startOAuthFlow(
      ctx,
      "discord",
      caller,
      { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/", handoff: { kind: "browser_completion" } },
      { trustedBrowserAttemptId: attempt.handle }
    );
    expect(started.statusCode).toBe(201);
    const start = started.body as unknown as { authorizationUrl: string };
    const victim = await launchFlow(app, start);

    // A cookieless provider error, which would deny the attempt, and a cookieless code: both refused.
    for (const query of ["error=access_denied", "code=attacker-code", ""]) {
      const stranger = await callback(app, victim.state, undefined, query);
      expect(stranger.statusCode, query).toBe(400);
      expect(stranger.json(), query).toEqual({ error: "state_not_bound" });
    }

    // The state is still unclaimed, so the launcher's cookie still completes it...
    const response = await callback(app, victim.state, victim.cookie, "code=victim-code");
    expect(response.statusCode).toBe(201);
  });

  it("a callback with no binding denies the attempt its state names, once, and never a completed one", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const make = async (handle: string) => {
      await ctx.store.createAuthAttempt({
        handle,
        appSlug: "repixelizer",
        provider: "discord",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600_000).toISOString(),
      });
      const caller = resolveAppCaller(ctx.config, "repixelizer", { "x-heimdall-app-secret": "repixelizer-secret" });
      const started = await startOAuthFlow(
        ctx,
        "discord",
        caller,
        { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/", handoff: { kind: "browser_completion" } },
        { trustedBrowserAttemptId: handle }
      );
      return started.body as unknown as { authorizationUrl: string };
    };

    // Lapsed cookie: the launcher launched, then its cookie is gone at the callback.
    const lapsed = await make("lapsed");
    await launchFlow(app, lapsed);
    const refused = await callback(app, stateOf(lapsed), undefined, "code=c");
    expect(refused.json()).toEqual({ error: "state_not_bound" });
    const denied = await ctx.store.findAuthAttempt("repixelizer", "lapsed");
    expect(denied?.status).toBe("denied");
    expect(denied?.denialCode).toBe("state_not_bound");

    // A completed attempt stays completed under a later cookieless callback.
    const done = await make("done");
    const launched = await launchFlow(app, done);
    expect((await callback(app, launched.state, launched.cookie, "code=c")).statusCode).toBe(201);
    await callback(app, launched.state, undefined, "code=c");
    expect(["completed", "consumed"]).toContain((await ctx.store.findAuthAttempt("repixelizer", "done"))?.status);
  });

  it("a state with no jti is refused as invalid and names no attempt to deny", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const original = decodeJwt(stateOf(await bifrostStart(app))).payload;
    const { jti: _jti, ...rest } = original;
    const token = signJwt(rest, ctx.keys);
    const response = await callback(app, token, undefined, "code=c");
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "invalid_state" });
  });

  describe("a browser refused for its binding gets a page back to the app, not bare JSON", () => {
    const html = { accept: "text/html" };
    const get = (app: FastifyInstance, url: string, cookie?: string) =>
      app.inject({ method: "GET", url, headers: { ...html, ...(cookie ? { cookie } : {}) } });

    it("on a cookieless callback, a lapsed cookie and a reloaded launch", async () => {
      const app = await newApp();
      const start = await bifrostStart(app);
      const state = stateOf(start);

      const reloadBeforeLaunch = await get(app, `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(state)}`);
      expect(reloadBeforeLaunch.statusCode).toBe(400);
      expect(reloadBeforeLaunch.headers["content-type"]).toContain("text/html");
      expect(reloadBeforeLaunch.body).toContain("state_not_bound");
      expect(reloadBeforeLaunch.body).toContain("https://bifrost.gamecult.org/auth/heimdall/complete");

      const victim = await launchFlow(app, start);
      const reloaded = await get(app, launchUrl(start));
      expect(reloaded.statusCode).toBe(400);
      expect(reloaded.headers["content-type"]).toContain("text/html");
      expect(reloaded.body).toContain("state_already_launched");
      expect(setCookieOf(reloaded)).toEqual([]);

      // Handoff reload: the page after a completed callback, loaded again.
      expect((await get(app, `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(victim.state)}`, victim.cookie)).statusCode).toBeLessThan(300);
      const reload = await get(app, `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(victim.state)}`, victim.cookie);
      expect(reload.statusCode).toBe(400);
      expect(reload.headers["content-type"]).toContain("text/html");
      expect(reload.body).toContain("state_already_used");
    });

    it("never links to an origin the app does not own, and JSON stays JSON without Accept", async () => {
      const app = await newApp();
      const ctx = getHeimdallRuntimeContext(app);
      const original = decodeJwt(stateOf(await bifrostStart(app))).payload;
      const token = signJwt({ ...original, return_to: "https://evil.example/steal" }, ctx.keys);
      const evil = await get(app, `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(token)}`);
      expect(evil.statusCode).toBe(400);
      expect(evil.json()).toEqual({ error: "state_not_bound" });
      expect(evil.body).not.toContain("evil.example");

      const plain = await callback(app, stateOf(await bifrostStart(app)));
      expect(plain.json()).toEqual({ error: "state_not_bound" });
    });
  });

  describe("use-record retention", () => {
    // Only Date is faked: the routes stamp each claim with the clock, and the rest of the event loop stays real.
    const clockAt = (ms: number) => vi.useFakeTimers({ toFake: ["Date"], now: ms });
    const seedStale = async (app: FastifyInstance, count: number, beforeMs: number) => {
      const ctx = getHeimdallRuntimeContext(app);
      for (let i = 0; i < count; i += 1) {
        const expiresAt = new Date(beforeMs - i).toISOString();
        await ctx.store.claimOAuthStateUse({ jti: `stale-${i}`, phase: "launch", appSlug: "bifrost", usedAt: expiresAt, expiresAt });
      }
    };

    it("later claims never prune a live state: its launch and callback replays stay refused", async () => {
      const app = await newApp();
      const start = await bifrostStart(app);
      const victim = await launchFlow(app, start);
      const exp = decodeJwt(victim.state).payload.exp as number;

      // More stale records than one batch, then another user's flow, whose claims do the pruning.
      const staleBefore = Date.now() - OAUTH_STATE_SKEW_MS - OAUTH_STATE_PRUNE_MARGIN_MS;
      await seedStale(app, OAUTH_STATE_PRUNE_BATCH + 10, staleBefore);
      await launchFlow(app, await bifrostStart(app));

      const launchReplay = await app.inject({ method: "GET", url: launchUrl(start) });
      expect(launchReplay.json()).toEqual({ error: "state_already_launched" });

      // The callback is not pruned either: it completes once, and its replay is refused.
      expect((await callback(app, victim.state, victim.cookie, "code=victim-code")).statusCode).toBe(201);
      expect((await callback(app, victim.state, victim.cookie, "code=victim-code")).json()).toEqual({ error: "state_already_used" });

      // Inside exp + skew the state still verifies, and the record still refuses it.
      clockAt((exp + OAUTH_STATE_SKEW_MS / 1000 - 1) * 1000);
      await launchFlow(app, await bifrostStart(app));
      const lateReplay = await app.inject({ method: "GET", url: launchUrl(start) });
      expect(lateReplay.json()).toEqual({ error: "state_already_launched" });

    });

    it("once its records are pruned, an expired state is refused as state_expired, by the state and not the record", async () => {
      const app = await newApp();
      const ctx = getHeimdallRuntimeContext(app);
      const start = await bifrostStart(app);
      const victim = await launchFlow(app, start);
      const exp = decodeJwt(victim.state).payload.exp as number;

      // Past exp + skew + margin the victim's launch record is prunable; a new claim removes it.
      const pruneAt = (exp + (OAUTH_STATE_SKEW_MS + OAUTH_STATE_PRUNE_MARGIN_MS) / 1000 + 1) * 1000;
      clockAt(pruneAt);
      await launchFlow(app, await bifrostStart(app));
      const record = {
        jti: decodeJwt(victim.state).payload.jti as string,
        phase: "launch" as const,
        appSlug: "bifrost" as const,
        usedAt: new Date(pruneAt).toISOString(),
        expiresAt: new Date(exp * 1000).toISOString(),
      };
      // The record is gone, as the store (not the route) would now let the claim through ...
      expect(await ctx.store.claimOAuthStateUse(record)).toBe(true);
      // ... yet the routes refuse the state itself.
      const launchReplay = await app.inject({ method: "GET", url: launchUrl(start) });
      expect(launchReplay.statusCode).toBe(400);
      expect(launchReplay.json()).toEqual({ error: "state_expired" });
      expect((await callback(app, victim.state, victim.cookie)).json()).toEqual({ error: "state_expired" });
    });
  });

  it("a provider refusal from the launching browser still denies the attempt, once", async () => {
    const app = await newApp();
    const start = await bifrostStart(app);
    const victim = await launchFlow(app, start);

    const denied = await callback(app, victim.state, victim.cookie, "error=access_denied");
    expect(denied.statusCode).toBe(400);
    expect(denied.json().error).toBe("consent_refused");
    expect(denied.json().by).toBe("provider");
    const replay = await callback(app, victim.state, victim.cookie, "error=access_denied");
    expect(replay.json()).toEqual({ error: "state_already_used" });
  });

  // The private command plane's completeAuth answers a denied attempt with
  // attempt.denialCode as its error (private-command-plane.ts, completeAuth), so
  // these two codes are what Bifrost, Repixelizer and Ghostlight poll for.
  it.each([
    ["bifrost", "https://bifrost.gamecult.org/auth/heimdall/complete?attempt=a1", "access_denied", "consent_refused"],
    ["repixelizer", "https://repixelizer.gamecult.org/app/", "access_denied", "consent_refused"],
    ["repixelizer", "https://repixelizer.gamecult.org/app/", "server_error", "provider_error"],
  ] as const)("a %s attempt whose provider answers %s is denied with %s", async (appSlug, returnTo, providerError, denialCode) => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const attempt = await ctx.store.createAuthAttempt({
      handle: `attempt-${providerError}`,
      appSlug,
      provider: "discord",
      mode: "sign_in",
      returnTo,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });
    const caller = resolveAppCaller(ctx.config, appSlug, { "x-heimdall-app-secret": `${appSlug}-secret` });
    const started = await startOAuthFlow(
      ctx,
      "discord",
      caller,
      { appSlug, mode: "sign_in", returnTo, handoff: { kind: "browser_completion" } },
      { trustedBrowserAttemptId: attempt.handle }
    );
    const flow = await launchFlow(app, started.body as unknown as { authorizationUrl: string });
    await callback(app, flow.state, flow.cookie, `error=${providerError}`);
    expect(await ctx.store.findAuthAttempt(appSlug, attempt.handle)).toMatchObject({ status: "denied", denialCode });
  });

  describe("a state that is expired, foreign or tampered is refused at launch and at callback", () => {
    it.each([
      ["expired beyond the skew", { exp: Math.floor(Date.now() / 1000) - 100 }, "state_expired"],
      ["not yet valid", { nbf: Math.floor(Date.now() / 1000) + 100 }, "state_expired"],
      ["another issuer", { iss: "https://elsewhere.example" }, "invalid_state"],
      ["another provider in aud", { aud: "patreon" }, "state_provider_mismatch"],
      ["another provider in provider", { provider: "patreon", aud: "patreon" }, "state_provider_mismatch"],
      ["a wrong type", { typ: "heimdall_refresh" }, "invalid_state"],
    ])("%s", async (_label, change, error) => {
      const app = await newApp();
      const ctx = getHeimdallRuntimeContext(app);
      const start = await bifrostStart(app);
      const original = decodeJwt(stateOf(start)).payload;
      const token = signJwt({ ...original, ...change }, ctx.keys);
      const launch = await app.inject({ method: "GET", url: `/v1/oauth/discord/launch?state=${encodeURIComponent(token)}` });
      expect(launch.statusCode).toBe(400);
      expect(launch.json()).toEqual({ error });
      expect(setCookieOf(launch)).toEqual([]);

      const cookie = `__Host-heimdall-oauth-${original.jti as string}=${signJwt({ typ: "heimdall_oauth_binding", iss: ctx.config.issuer, jti: original.jti, iat: 0, exp: 4_000_000_000 }, ctx.keys)}`;
      const response = await callback(app, token, cookie);
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error });
      expect(response.body).not.toContain(token.slice(20, 60));
    });

    it("a state inside the 30 s skew still works, as a refresh token does", async () => {
      const app = await newApp();
      const ctx = getHeimdallRuntimeContext(app);
      const start = await bifrostStart(app);
      const original = decodeJwt(stateOf(start)).payload;
      const token = signJwt({ ...original, exp: Math.floor(Date.now() / 1000) - 10 }, ctx.keys);
      const launch = await app.inject({ method: "GET", url: `/v1/oauth/discord/launch?state=${encodeURIComponent(token)}` });
      expect(launch.statusCode).toBe(302);
    });

    it("a tampered signature, a malformed token and a provider that is not the route's", async () => {
      const app = await newApp();
      const start = await bifrostStart(app);
      const state = stateOf(start);
      const tampered = `${state.slice(0, -4)}AAAA`;
      for (const token of [tampered, "not-a-jwt", "a.b"]) {
        const launch = await app.inject({ method: "GET", url: `/v1/oauth/discord/launch?state=${encodeURIComponent(token)}` });
        expect(launch.statusCode).toBe(400);
        expect(launch.json()).toEqual({ error: "invalid_state" });
        expect(launch.body).not.toContain(token);
      }
      const wrongRoute = await app.inject({ method: "GET", url: `/v1/oauth/patreon/launch?state=${encodeURIComponent(state)}` });
      expect(wrongRoute.statusCode).toBe(400);
      expect(wrongRoute.json()).toEqual({ error: "state_provider_mismatch" });
    });
  });

  it("the launch response and the binding cookie carry the protections the binding relies on", async () => {
    const app = await newApp();
    const start = await bifrostStart(app, { requestedScopes: ["identify", "email"] });
    const jti = decodeJwt(stateOf(start)).payload.jti as string;

    const launch = await app.inject({ method: "GET", url: launchUrl(start) });
    expect(launch.statusCode).toBe(302);
    const cookies = setCookieOf(launch);
    expect(cookies).toHaveLength(1);
    const cookie = cookies[0] as string;
    expect(cookie.startsWith(`__Host-heimdall-oauth-${jti}=`)).toBe(true);
    const attributes = cookie.split(";").slice(1).map((part) => part.trim());
    expect(attributes).toEqual(expect.arrayContaining(["Path=/", "Secure", "HttpOnly", "SameSite=Lax"]));
    expect(attributes.some((attribute) => /^domain=/i.test(attribute))).toBe(false);
    const maxAge = Number(attributes.find((attribute) => attribute.startsWith("Max-Age="))?.slice("Max-Age=".length));
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(600);

    const location = new URL(launch.headers.location as string);
    expect(location.origin + location.pathname).toBe("https://discord.com/oauth2/authorize");
    expect(location.searchParams.get("state")).toBe(stateOf(start));
    expect(location.searchParams.get("scope")).toBe("identify email");
    expect(location.searchParams.get("client_id")).toBe("discord-client");
    expect(location.searchParams.get("redirect_uri")).toBe("https://heimdall.gamecult.org/v1/oauth/discord/callback");
    expect(launch.headers["cache-control"]).toBe("no-store");
    expect(launch.headers["referrer-policy"]).toBe("no-referrer");

    const done = await callback(app, stateOf(start), cookie.split(";")[0], "code=c");
    expect(done.statusCode).toBe(201);
    const cleared = setCookieOf(done).find((value) => value.startsWith(`__Host-heimdall-oauth-${jti}=`));
    expect(cleared).toBeDefined();
    expect(cleared).toMatch(/Max-Age=0/);
    expect(cleared?.startsWith(`__Host-heimdall-oauth-${jti}=;`)).toBe(true);
  });

  it("a launch for a provider with no client id is 503 and burns nothing", async () => {
    const config = { ...createTestConfig(), providers: { ...createTestConfig().providers } };
    const app = await buildApp({ config, oauthRuntimes: { discord: createMockDiscordRuntime() } });
    apps.push(app);
    const start = await bifrostStart(app);
    config.providers.discord = { clientId: undefined, clientSecret: undefined } as unknown as typeof config.providers.discord;
    const refused = await app.inject({ method: "GET", url: launchUrl(start) });
    expect(refused.statusCode).toBe(503);
    expect(refused.json().error).toBe("provider_not_configured");
    expect(setCookieOf(refused)).toEqual([]);
  });

  it("every start returns Heimdall's launch URL and no state token", async () => {
    const app = await newApp();
    for (const [headers, payload] of [
      [{}, { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" }],
      [
        { "x-heimdall-app-secret": "bifrost-secret" },
        { appSlug: "bifrost", mode: "sign_in", returnTo: bifrostReturn },
      ],
    ] as const) {
      const response = await app.inject({ method: "POST", url: "/v1/oauth/discord/start", headers, payload });
      expect(response.statusCode).toBe(201);
      const body = response.json();
      expect(body.stateToken).toBeUndefined();
      expect(new URL(body.authorizationUrl).origin + new URL(body.authorizationUrl).pathname).toBe(
        "https://heimdall.gamecult.org/v1/oauth/discord/launch"
      );
      expect(body.stateExpiresAt).toEqual(expect.any(String));
    }
  });

  it("claims the launch and the callback of a state under their own phases, until the state's expiry", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const spy = vi.spyOn(ctx.store, "claimOAuthStateUse");
    const start = await bifrostStart(app);
    const { jti, exp } = decodeJwt(stateOf(start)).payload as { jti: string; exp: number };

    const victim = await launchFlow(app, start);
    expect((await callback(app, victim.state, victim.cookie, "code=victim-code")).statusCode).toBe(201);

    const expiresAt = new Date(exp * 1000).toISOString();
    expect(spy.mock.calls.map(([claim]) => claim)).toEqual([
      { jti, phase: "launch", appSlug: "bifrost", usedAt: expect.any(String), expiresAt },
      { jti, phase: "callback", appSlug: "bifrost", usedAt: expect.any(String), expiresAt },
    ]);
  });

  it("the launch route validates its provider and its state parameter", async () => {
    const app = await newApp();
    for (const url of ["/v1/oauth/discord/launch", "/v1/oauth/discord/launch?state=", "/v1/oauth/bogus/launch?state=abc"]) {
      const response = await app.inject({ method: "GET", url });
      expect(response.statusCode, url).toBe(400);
      expect(response.json().error, url).toBe("invalid_request");
    }
  });

  it("a state's requested scopes are null, absent, or a list of strings, and nothing else", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const start = await bifrostStart(app);
    const original = decodeJwt(stateOf(start)).payload;
    const launchWith = async (change: Record<string, unknown>) => {
      const rest = { ...original };
      delete rest.requested_scopes;
      const token = signJwt({ ...rest, jti: randomUUID(), ...change }, ctx.keys);
      return app.inject({ method: "GET", url: `/v1/oauth/discord/launch?state=${encodeURIComponent(token)}` });
    };

    for (const [label, change] of [
      ["absent", {}],
      ["null", { requested_scopes: null }],
      ["a list", { requested_scopes: ["identify"] }],
    ] as const) {
      expect((await launchWith(change)).statusCode, label).toBe(302);
    }
    for (const [label, change] of [
      ["a string", { requested_scopes: "identify" }],
      ["a list with a number", { requested_scopes: ["identify", 7] }],
      ["a list of numbers", { requested_scopes: [1, 2] }],
      ["an object", { requested_scopes: { 0: "identify" } }],
    ] as const) {
      const response = await launchWith(change);
      expect(response.statusCode, label).toBe(400);
      expect(response.json(), label).toEqual({ error: "invalid_state" });
    }
  });

  it("the time windows hold to the second: a state from nbf - 30 s to exp + 30 s, a binding until its exp", async () => {
    const app = await newApp();
    const ctx = getHeimdallRuntimeContext(app);
    const start = await bifrostStart(app);
    const original = decodeJwt(stateOf(start)).payload;
    vi.useFakeTimers({ toFake: ["Date"] });
    const now = 1_900_000_000;
    vi.setSystemTime(now * 1000);
    const stateWith = (change: Record<string, unknown>) =>
      signJwt({ ...original, jti: randomUUID(), nbf: now - 1, exp: now + 600, ...change }, ctx.keys);
    const launch = (token: string) =>
      app.inject({ method: "GET", url: `/v1/oauth/discord/launch?state=${encodeURIComponent(token)}` });

    expect((await launch(stateWith({ exp: now - 30 }))).json()).toEqual({ error: "state_expired" });
    expect((await launch(stateWith({ exp: now - 29 }))).statusCode).toBe(302);
    expect((await launch(stateWith({ nbf: now + 31 }))).json()).toEqual({ error: "state_expired" });
    expect((await launch(stateWith({ nbf: now + 30 }))).statusCode).toBe(302);

    const token = stateWith({});
    const jti = decodeJwt(token).payload.jti as string;
    const bindingWith = (exp: number) =>
      `__Host-heimdall-oauth-${jti}=${signJwt({ typ: "heimdall_oauth_binding", iss: ctx.config.issuer, jti, iat: now - 5, exp }, ctx.keys)}`;
    expect((await callback(app, token, bindingWith(now))).json()).toEqual({ error: "state_not_bound" });
    expect((await callback(app, token, bindingWith(now + 1))).statusCode).toBe(201);
  });
});
