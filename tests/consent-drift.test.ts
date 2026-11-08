import { afterEach, expect, it, vi } from "vitest";
import { type FastifyInstance } from "fastify";

// The receipt records the wording the person was shown. If the wording changes
// between the ask and the callback (a deploy inside the state's lifetime), the
// receipt must still hold what they saw.

const drift = vi.hoisted(() => ({ on: false }));
vi.mock("../src/consent.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/consent.js")>();
  return { ...real, consentText: (ask: Parameters<typeof real.consentText>[0]) => real.consentText(ask) + (drift.on ? "\nREWORDED AFTER THE ASK" : "") };
});

import { buildApp } from "../src/app.js";
import { InMemoryStore } from "../src/store/index.js";
import { createTestConfig, setCookieOf, stateOf } from "./oauth-flow.js";

const apps: FastifyInstance[] = [];
afterEach(async () => {
  drift.on = false;
  while (apps.length) await apps.pop()?.close();
});

it("a receipt holds the wording of the ask, not wording rebuilt at the callback", async () => {
  const store = new InMemoryStore();
  const app = await buildApp({
    config: createTestConfig(),
    store,
    oauthRuntimes: {
      joystick: {
        async exchangeAuthorizationCode() {
          return { accessToken: "joy-access-code-a", refreshToken: "r", tokenType: "Bearer", scope: ["identity:read"], expiresAt: "2099-01-01T00:00:00.000Z", raw: {} };
        },
        async resolveIdentity() {
          return { provider: "joystick", providerUserId: "joy-a", username: "a", profile: {} };
        },
        async evaluateEntitlements() {
          return { facts: [], snapshots: [] };
        },
      },
    },
  });
  apps.push(app);
  const start = await app.inject({
    method: "POST",
    url: "/v1/oauth/joystick/start",
    headers: { "x-heimdall-app-secret": "streampixels-secret" },
    payload: { appSlug: "streampixels", mode: "connect", connection: { kind: "creator", targetId: "c" }, returnTo: "https://streampixels.gamecult.org/s", handoff: { kind: "browser_completion" } },
  });
  const state = stateOf(start.json());
  const ask = await app.inject({ method: "GET", url: `/v1/oauth/joystick/launch?state=${encodeURIComponent(state)}`, headers: { accept: "text/html" } });
  const askCookie = setCookieOf(ask).find((c) => c.startsWith("__Host-heimdall-ask-"))!.split(";")[0]!;
  const go = await app.inject({
    method: "POST",
    url: "/v1/oauth/joystick/consent",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie: askCookie },
    payload: new URLSearchParams({ state, decision: "continue" }).toString(),
  });
  const binding = setCookieOf(go).find((c) => c.startsWith("__Host-heimdall-oauth-"))!.split(";")[0]!;
  drift.on = true; // the wording changes after the person has agreed
  const done = await app.inject({ method: "GET", url: `/v1/oauth/joystick/callback?state=${encodeURIComponent(state)}&code=code-a`, headers: { cookie: binding, accept: "application/json" } });
  expect(done.statusCode).toBe(201);
  const [receipt] = await store.listConsentReceipts(done.json().account.id);
  expect(receipt?.kind === "grant" && receipt.consentText).not.toContain("REWORDED");
});
