import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp, getHeimdallRuntimeContext, startOAuthFlow } from "../src/app.js";
import { resolveAppCaller } from "../src/app-caller.js";
import { decodeJwt, signJwt } from "../src/signing.js";
import { createMockDiscordRuntime, createTestConfig, launchFlow, setCookieOf, stateOf } from "./oauth-flow.js";

// Heimdall's OAuth states complete once, only in the browser that launched
// them (finding state-replay). Soul's attack: a Bifrost state is readable in
// the URL the victim's browser is sent to, so an attacker who sees it opens it
// in their own browser, finishes the provider login as themselves, and hands
// the victim the resulting completion code.

const apps: FastifyInstance[] = [];
afterEach(async () => {
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
    expect((await ctx.store.findAuthAttempt("repixelizer", attempt.handle))?.status).toBe("pending");

    // The victim's own callback is unharmed.
    const response = await callback(app, victim.state, victim.cookie, "code=victim-code");
    expect(response.statusCode).toBe(201);
  });

  it("a provider error from the launching browser still denies the attempt, once", async () => {
    const app = await newApp();
    const start = await bifrostStart(app);
    const victim = await launchFlow(app, start);

    const denied = await callback(app, victim.state, victim.cookie, "error=access_denied");
    expect(denied.statusCode).toBe(400);
    expect(denied.json().error).toBe("provider_error");
    const replay = await callback(app, victim.state, victim.cookie, "error=access_denied");
    expect(replay.json()).toEqual({ error: "state_already_used" });
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
});
