import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";

import { buildApp } from "../src/app.js";
import { type HeimdallConfig } from "../src/config.js";
import { identityFacts } from "../src/facts.js";

const REGISTRATION_SECRET = "operator-registration-secret";

function createTestConfig(overrides: Partial<HeimdallConfig> = {}): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    workspaceRoot: ".",
    dataRoot: "./.heimdall-data",
    cultCachePath: "./.heimdall-data/cultcache/heimdall.service.cc",
    publicBaseUrl: "https://heimdall.test",
    issuer: "https://heimdall.test",
    daemonId: "test-heimdall",
    idunnRudpHealth: undefined,
    idunnHealthContract: "heimdall.cultnet-rudp-provider-health",
    providerHealthIdentityPath: "./.heimdall-data/provider-health-identity.cc",
    sessionTtlSeconds: 3600,
    refreshTtlSeconds: 60 * 60 * 24 * 30,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    appSharedSecrets: {},
    appBackendCallbacks: {},
    storage: { backend: "memory", applySchemaOnStartup: true },
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: { clientId: "patreon-client", clientSecret: "patreon-secret" },
      github: { clientId: "github-client", clientSecret: "github-secret" },
      twitch: { clientId: "twitch-client", clientSecret: "twitch-secret" },
      youtube: { clientId: "youtube-client", clientSecret: "youtube-secret" },
      spotify: { clientId: "spotify-client", clientSecret: "spotify-secret" },
    },
    ...overrides,
  } as HeimdallConfig;
}

const registration = {
  slug: "erycina",
  displayName: "Erycina",
  identityProviders: ["discord"],
  redirectUris: ["https://erycina.test/auth/callback"],
  capabilities: [
    { key: "viewer_access", mode: "shared", summary: "Signed-in viewer.", anyOf: [identityFacts.authenticated] },
  ],
};

const apps: FastifyInstance[] = [];
afterEach(async () => {
  while (apps.length > 0) await apps.pop()!.close();
});

async function buildOpenInstance(): Promise<FastifyInstance> {
  const app = await buildApp({ config: createTestConfig({ appRegistrationSecret: REGISTRATION_SECRET }) });
  apps.push(app);
  return app;
}

describe("POST /v1/apps", () => {
  it("is closed on an instance with no registration secret configured", async () => {
    // A fresh instance must not be accidentally open. Heimdall is an OAuth
    // provider; an open registration endpoint lets anyone create a client that
    // starts provider flows under this instance's identity.
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({ method: "POST", url: "/v1/apps", payload: registration });

    expect(response.statusCode).toBe(404);
    expect(response.json().error).toBe("registration_closed");
  });

  it("refuses a request with no registration secret", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({ method: "POST", url: "/v1/apps", payload: registration });

    expect(response.statusCode).toBe(401);
  });

  it("refuses a request with the wrong registration secret", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({
      method: "POST",
      url: "/v1/apps",
      headers: { "x-heimdall-registration-secret": "not-it" },
      payload: registration,
    });

    expect(response.statusCode).toBe(401);
  });

  it("registers an app and returns an RFC 7591 shaped response", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({
      method: "POST",
      url: "/v1/apps",
      headers: { "x-heimdall-registration-secret": REGISTRATION_SECRET },
      payload: registration,
    });

    expect(response.statusCode).toBe(201);
    const body = response.json();
    expect(body.client_id).toBe("erycina");
    expect(body.client_secret).toBeTruthy();
    expect(body.client_name).toBe("Erycina");
    expect(body.redirect_uris).toEqual(["https://erycina.test/auth/callback"]);
    expect(typeof body.client_id_issued_at).toBe("number");
  });

  it("rejects an invalid registration with the problems that caused it", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({
      method: "POST",
      url: "/v1/apps",
      headers: { "x-heimdall-registration-secret": REGISTRATION_SECRET },
      payload: { ...registration, slug: "bifrost" },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe("invalid_client_metadata");
    expect(JSON.stringify(response.json().problems)).toMatch(/reserved by a built-in/);
  });

  it("rejects a capability rule naming a fact Heimdall does not produce", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({
      method: "POST",
      url: "/v1/apps",
      headers: { "x-heimdall-registration-secret": REGISTRATION_SECRET },
      payload: {
        ...registration,
        capabilities: [{ key: "admin", mode: "shared", summary: "x", anyOf: ["invented.superuser"] }],
      },
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.stringify(response.json().problems)).toMatch(/Unknown term/);
  });
});

describe("app discovery after registration", () => {
  it("lists a registered app alongside the built-ins", async () => {
    const app = await buildOpenInstance();
    await app.inject({
      method: "POST",
      url: "/v1/apps",
      headers: { "x-heimdall-registration-secret": REGISTRATION_SECRET },
      payload: registration,
    });

    const listed = (await app.inject({ method: "GET", url: "/v1/apps" })).json();
    const slugs = listed.apps.map((profile: { slug: string }) => profile.slug);

    expect(slugs).toContain("erycina");
    expect(slugs).toContain("bifrost");
  });

  it("serves a registered app's profile by slug", async () => {
    const app = await buildOpenInstance();
    await app.inject({
      method: "POST",
      url: "/v1/apps",
      headers: { "x-heimdall-registration-secret": REGISTRATION_SECRET },
      payload: registration,
    });

    const response = await app.inject({ method: "GET", url: "/v1/apps/erycina" });

    expect(response.statusCode).toBe(200);
    expect(response.json().displayName).toBe("Erycina");
  });

  it("404s an app nobody registered, rather than serving an empty profile", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({ method: "GET", url: "/v1/apps/nobody" });

    expect(response.statusCode).toBe(404);
    expect(response.json().error).toBe("unknown_app");
  });

  it("still serves the built-in profiles", async () => {
    const app = await buildOpenInstance();
    const response = await app.inject({ method: "GET", url: "/v1/apps/repixelizer" });

    expect(response.statusCode).toBe(200);
    expect(response.json().slug).toBe("repixelizer");
  });
});
