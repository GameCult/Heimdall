import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { type HeimdallConfig } from "../src/config.js";
import { decodeJwt, verifyJwt } from "../src/signing.js";

function createTestConfig(): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    sessionTtlSeconds: 3600,
    stateTtlSeconds: 600,
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: { clientId: "patreon-client", clientSecret: "patreon-secret" },
      github: { clientId: "github-client", clientSecret: "github-secret" },
      twitch: { clientId: "twitch-client", clientSecret: "twitch-secret" },
      youtube: { clientId: "youtube-client", clientSecret: "youtube-secret" },
    },
  };
}

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];

function getPublicKey(app: FastifyInstance) {
  return (
    app as FastifyInstance & {
      heimdallContext: {
        keys: {
          publicKey: Parameters<typeof verifyJwt>[1];
        };
      };
    }
  ).heimdallContext.keys.publicKey;
}

afterEach(async () => {
  while (apps.length) {
    await apps.pop()?.close();
  }
});

describe("Heimdall service skeleton", () => {
  it("serves discovery and JWKS metadata", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const discoveryResponse = await app.inject({
      method: "GET",
      url: "/.well-known/heimdall-configuration",
    });
    expect(discoveryResponse.statusCode).toBe(200);
    expect(discoveryResponse.json()).toEqual(
      expect.objectContaining({
        issuer: "https://heimdall.gamecult.org",
        jwksUri: "https://heimdall.gamecult.org/.well-known/jwks.json",
      })
    );

    const jwksResponse = await app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });
    expect(jwksResponse.statusCode).toBe(200);
    expect(jwksResponse.json()).toEqual(
      expect.objectContaining({
        keys: [
          expect.objectContaining({
            alg: "EdDSA",
            kid: expect.any(String),
            use: "sig",
          }),
        ],
      })
    );
  });

  it("builds signed OAuth start state for supported providers", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
      },
    });

    expect(response.statusCode).toBe(201);
    const payload = response.json();
    expect(payload.authorizationUrl).toContain("discord.com/oauth2/authorize");

    const decoded = decodeJwt(payload.stateToken);
    expect(decoded.payload).toEqual(
      expect.objectContaining({
        typ: "heimdall_oauth_state",
        provider: "discord",
        app_slug: "repixelizer",
      })
    );
  });

  it("issues signed claims and evaluates shared app capabilities", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/claims/issue",
      payload: {
        accountId: "acct_repixelizer_001",
        displayName: "Meta",
        facts: ["discord.allowed_role", "grant.operator"],
        linkedIdentities: [
          {
            provider: "discord",
            providerUserId: "123456789",
            username: "meta",
          },
        ],
      },
    });

    expect(response.statusCode).toBe(201);
    const payload = response.json();
    expect(payload.sharedCapabilities).toEqual(
      expect.arrayContaining(["app_access", "queue_submit", "admin_access"])
    );

    const verified = verifyJwt(payload.accessToken, getPublicKey(app));
    expect(verified.valid).toBe(true);

    const tokenDecoded = decodeJwt(payload.accessToken);
    expect(tokenDecoded.payload.capabilities).toEqual(
      expect.arrayContaining(["app_access", "queue_submit", "admin_access"])
    );
  });

  it("exposes StreamPixels hybrid capability seams without granting them blindly", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const profileResponse = await app.inject({
      method: "GET",
      url: "/v1/apps/streampixels",
    });

    expect(profileResponse.statusCode).toBe(200);
    expect(profileResponse.json()).toEqual(
      expect.objectContaining({
        slug: "streampixels",
        managedConnectionProviders: ["twitch", "youtube"],
      })
    );
  });
});
