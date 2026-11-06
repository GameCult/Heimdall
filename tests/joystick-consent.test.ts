import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { createTestConfig } from "./oauth-flow.js";

// SKETCH for docs/joystick-consent-flow.md. Skipped: every test here names a
// behaviour the consent cut must build. Remove `.skip` as each one lands.

const apps: FastifyInstance[] = [];
afterEach(async () => {
  while (apps.length) await apps.pop()?.close();
});

async function creatorConnectStart(app: FastifyInstance) {
  const response = await app.inject({
    method: "POST",
    url: "/v1/oauth/joystick/start",
    headers: { "x-heimdall-app-secret": "streampixels-secret" },
    payload: {
      appSlug: "streampixels",
      mode: "connect",
      connection: { kind: "creator", targetId: "creator-1" },
      returnTo: "https://streampixels.gamecult.org/settings",
      handoff: { kind: "browser_completion" },
    },
  });
  expect(response.statusCode).toBe(201);
  const url = new URL(response.json().authorizationUrl as string);
  return `${url.pathname}${url.search}`;
}

describe.skip("Joystick consent flow (draft)", () => {
  it("launch shows a Heimdall ask naming app, provider and scopes, and does not redirect", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);
    const launch = await app.inject({ method: "GET", url: await creatorConnectStart(app), headers: { accept: "text/html" } });
    expect(launch.statusCode).toBe(200);
    expect(launch.headers.location).toBeUndefined();
    for (const needle of ["StreamPixels", "Joystick", "identity:read", "subscribers:read", "refresh token"]) {
      expect(launch.body).toContain(needle);
    }
  });

  it("a viewer who declines yields consent_refused by viewer, stores no credential, and consumes the state", async () => {
    // POST the decline form from the launch page with the binding cookie;
    // expect result {error: "consent_refused", by: "viewer"}, an audit event
    // "consent_refused", no managed credential row, and a second launch refused.
    expect.fail("not built");
  });

  it("a provider access_denied is consent_refused by provider, distinct from provider_error", async () => {
    expect.fail("not built");
  });

  it("a granted completion writes one receipt with asked and granted scopes and the page digest", async () => {
    expect.fail("not built");
  });

  it("the receipt page is readable only by the browser or account that consented, and revoke stamps revokedAt without editing the grant row", async () => {
    expect.fail("not built");
  });
});
