import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { buildAuthorizationUrl, providerCatalog } from "../src/providers.js";
import { createRuntimeKeyMaterial, decodeJwt, signJwt, verifyJwt } from "../src/signing.js";
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

async function rig(config = createTestConfig()) {
  const app = await buildApp({
    config,
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
      // The proof is the signed state's too: the claim carries step_up_at exactly when the start asked.
      expect(typeof redeemed.json().claimSet.step_up_at).toBe(asked ? "number" : "undefined");
    }
  });
});

describe("a forged or odd state cannot carry a step-up the start would not have signed", () => {
  // A real signing key on disk, so the test can re-sign a state as only Heimdall's key holder could.
  const dir = mkdtempSync(join(tmpdir(), "heimdall-stepup-"));
  const config = { ...createTestConfig(), signingPrivateKeyPath: join(dir, "signing.pem"), bootstrapSigningPrivateKeyOnMissing: true };
  // The app creates the key on first boot; read it only after the rig exists.
  const loadKeys = (c: typeof config) => createRuntimeKeyMaterial({ ...c, bootstrapSigningPrivateKeyOnMissing: false });

  async function forgedState(app: App, provider: string, headers: Record<string, string>, stepUp: unknown, appSlug = "streampixels", url = returnTo) {
    const started = await start(app, provider, {}, headers, appSlug, url);
    const real = new URL(started.json().authorizationUrl).searchParams.get("state") ?? "";
    const keys = loadKeys(config);
    const verified = verifyJwt(real, keys.publicKey) as { valid: boolean; payload: Record<string, unknown> };
    expect(verified.valid, "the test key signs what the app verifies").toBe(true);
    return { real, forged: signJwt({ ...verified.payload, step_up: stepUp }, keys) };
  }
  const launch = (app: App, provider: string, state: string) => app.inject({ method: "GET", url: `/v1/oauth/${provider}/launch?state=${encodeURIComponent(state)}` });

  it("rejects any step_up that is not null or true as invalid_state at the launch hop", async () => {
    const app = await rig(config);
    expect((await launch(app, "twitch", (await forgedState(app, "twitch", {}, true)).forged)).statusCode, "a well-formed true still launches").toBe(302);
    for (const odd of ["true", "yes", 1, 0, false, {}, []]) {
      const res = await launch(app, "twitch", (await forgedState(app, "twitch", {}, odd)).forged);
      expect([res.statusCode, res.json().error], JSON.stringify(odd)).toEqual([400, "invalid_state"]);
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it("a step-up state for a provider with no re-authentication parameter fails closed and does not burn the state", async () => {
    const dir2 = mkdtempSync(join(tmpdir(), "heimdall-stepup-"));
    const config2 = { ...createTestConfig(), signingPrivateKeyPath: join(dir2, "signing.pem"), bootstrapSigningPrivateKeyOnMissing: true };
    try {
      const app = await rig(config2);
      const bifrost = { "x-heimdall-app-secret": "bifrost-secret" };
      const started = await start(app, "discord", {}, bifrost, "bifrost", "https://bifrost.gamecult.org/auth/heimdall/return");
      const real = new URL(started.json().authorizationUrl).searchParams.get("state") ?? "";
      const keys2 = loadKeys(config2);
      const verified = verifyJwt(real, keys2.publicKey) as { valid: boolean; payload: Record<string, unknown> };
      expect(verified.valid).toBe(true);
      const forged = signJwt({ ...verified.payload, step_up: true }, keys2);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const res = await launch(app, "discord", forged);
        expect(res.statusCode, "never a redirect without the step").toBe(500);
        expect(res.headers.location).toBeUndefined();
      }
      // Not "state_already_launched": the refused launches did not claim the state.
      expect((await launch(app, "discord", real)).statusCode).toBe(302);
    } finally {
      rmSync(dir2, { recursive: true, force: true });
    }
  });
});
