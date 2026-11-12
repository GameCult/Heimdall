import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { buildAuthorizationUrl, providerCatalog } from "../src/providers.js";
import { decodeJwt } from "../src/signing.js";
import { InMemoryStore } from "../src/store/index.js";
import { createTestConfig, launchFlow, launchWithRedirect } from "./oauth-flow.js";

// A sign_in step-up asks the provider for a real re-authentication. It is the
// authenticated app's request (never a browser's), it rides in the signed state
// only, it is off unless asked for, and a provider that has no such parameter is
// refused at start. These tests drive it as StreamPixels does: its own app
// secret, twitch and youtube sign_in starts, then the launch hop and redeem.

const returnTo = "https://streampixels.gamecult.org/signin/return";
const spAuth = { "x-heimdall-app-secret": "streampixels-secret" };

function runtime(provider: "twitch" | "youtube", providerUserId: string): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "at", refreshToken: "rt", tokenType: "Bearer", scope: ["user:read:email"], raw: {} };
    },
    async resolveIdentity() {
      return { provider, providerUserId, username: providerUserId, profile: { id: providerUserId } };
    },
    async evaluateEntitlements() {
      return { facts: [], snapshots: [] };
    },
  };
}

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function rig() {
  const app = await buildApp({
    config: createTestConfig(),
    store: new InMemoryStore(),
    oauthRuntimes: { twitch: runtime("twitch", "t-1"), youtube: runtime("youtube", "y-1") },
  });
  apps.push(app);
  return app;
}

type App = Awaited<ReturnType<typeof rig>>;

function start(
  app: App,
  provider: string,
  payload: Record<string, unknown> = {},
  headers: Record<string, string> = {},
  appSlug = "streampixels",
  url = returnTo
) {
  return app.inject({ method: "POST", url: `/v1/oauth/${provider}/start`, headers, payload: { appSlug, mode: "sign_in", returnTo: url, ...payload } });
}

describe("step-up on a sign_in start: the provider URL", () => {
  it("asks nothing extra without stepUp, for every provider StreamPixels signs in with", async () => {
    const app = await rig();
    for (const provider of ["twitch", "youtube"]) {
      for (const extra of [{}, { stepUp: false }]) {
        const started = await start(app, provider, extra);
        expect(started.statusCode).toBe(201);
        expect(decodeJwt(new URL(started.json().authorizationUrl).searchParams.get("state") ?? "").payload.step_up).toBeNull();
        const url = (await launchWithRedirect(app, started.json())).url;
        expect(url.searchParams.has("force_verify")).toBe(false);
        expect(url.searchParams.get("prompt")).toBe(provider === "youtube" ? "consent" : null);
      }
    }
  });

  it("with stepUp and the app secret: twitch force_verify=true, youtube prompt=login consent, state records it", async () => {
    const app = await rig();
    const twitch = await start(app, "twitch", { stepUp: true }, spAuth);
    expect(twitch.statusCode).toBe(201);
    expect(decodeJwt(new URL(twitch.json().authorizationUrl).searchParams.get("state") ?? "").payload.step_up).toBe(true);
    expect((await launchWithRedirect(app, twitch.json())).url.searchParams.get("force_verify")).toBe("true");

    const youtube = await start(app, "youtube", { stepUp: true }, spAuth);
    expect(youtube.statusCode).toBe(201);
    expect((await launchWithRedirect(app, youtube.json())).url.searchParams.get("prompt")).toBe("login consent");
  });

  it("Google (a Bifrost sign_in provider) gets prompt=login in place of select_account", async () => {
    const app = await rig();
    const bifrostReturn = "https://bifrost.gamecult.org/auth/heimdall/return";
    const plain = await start(app, "google", {}, { "x-heimdall-app-secret": "bifrost-secret" }, "bifrost", bifrostReturn);
    expect((await launchWithRedirect(app, plain.json())).url.searchParams.get("prompt")).toBe("select_account");
    const stepped = await start(app, "google", { stepUp: true }, { "x-heimdall-app-secret": "bifrost-secret" }, "bifrost", bifrostReturn);
    expect(stepped.statusCode).toBe(201);
    expect((await launchWithRedirect(app, stepped.json())).url.searchParams.get("prompt")).toBe("login");
  });
});

describe("step-up refusals", () => {
  it("is the app's request: no secret or a wrong secret is 401 app_auth_required, while the same start without stepUp stays open", async () => {
    const app = await rig();
    for (const headers of [{}, { "x-heimdall-app-secret": "wrong" }]) {
      const res = await start(app, "twitch", { stepUp: true }, headers);
      expect([res.statusCode, res.json().error]).toEqual([401, "app_auth_required"]);
    }
    expect((await start(app, "twitch", {}, {})).statusCode).toBe(201);
  });

  it("a provider with no re-authentication parameter is a typed refusal, with the secret, never a silent pass", async () => {
    const app = await rig();
    const bifrost = { "x-heimdall-app-secret": "bifrost-secret" };
    const res = await start(app, "discord", { stepUp: true }, bifrost, "bifrost", "https://bifrost.gamecult.org/auth/heimdall/return");
    expect([res.statusCode, res.json().error, res.json().provider]).toEqual([400, "step_up_not_supported", "discord"]);
    // The URL builder holds the same line: it throws rather than omit the step.
    for (const provider of ["discord", "patreon", "github", "spotify", "joystick"] as const) {
      expect(providerCatalog[provider].stepUpAuthorizationParams, provider).toBeUndefined();
      expect(() =>
        buildAuthorizationUrl({ provider, clientId: "c", redirectUri: "https://x/cb", state: "s", requestedScopes: undefined, stepUp: true })
      ).toThrow(/no re-authentication parameter/);
    }
    expect(Object.keys(providerCatalog).filter((p) => providerCatalog[p as keyof typeof providerCatalog].stepUpAuthorizationParams).sort()).toEqual(["google", "twitch", "youtube"]);
  });

  it("is sign_in only: link and connect starts carrying stepUp are 400 step_up_only_in_sign_in", async () => {
    const app = await rig();
    for (const mode of ["link", "connect"]) {
      const res = await start(app, "twitch", { mode, stepUp: true }, spAuth);
      expect([res.statusCode, res.json().error]).toEqual([400, "step_up_only_in_sign_in"]);
    }
  });
});

describe("the flag is the signed state's, not the redeem side's", () => {
  it("a completion reports stepUpRequested only when the start asked, and a stepUp handed to redeem changes nothing", async () => {
    const app = await rig();
    for (const asked of [true, false]) {
      const started = await start(app, "twitch", asked ? { stepUp: true } : {}, asked ? spAuth : {});
      const flow = await launchFlow(app, started.json());
      const called = await app.inject({
        method: "GET",
        url: `/v1/oauth/twitch/callback?code=c&state=${encodeURIComponent(flow.state)}`,
        headers: { cookie: flow.cookie, accept: "application/json" },
      });
      expect(called.statusCode).toBe(201);
      const code = called.json().completion.code as string;

      // A stepUp handed to redeem is not read: the answer reflects the start, whatever the body says.
      const redeemed = await app.inject({ method: "POST", url: "/v1/apps/streampixels/auth-completions/redeem", payload: { completionCode: code, stepUp: true } });
      expect(redeemed.statusCode).toBe(201);
      expect(redeemed.json().stepUpRequested).toBe(asked ? true : undefined);
    }
  });
});
