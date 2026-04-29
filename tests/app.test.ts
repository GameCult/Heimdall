import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { type HeimdallConfig } from "../src/config.js";
import { entitlementFacts, grantFacts, identityFacts } from "../src/facts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { verifyJwt } from "../src/signing.js";
import { createHeimdallAccessTokenVerifier } from "../src/verifier.js";
import { InMemoryStore } from "../src/store/index.js";

function createTestConfig(): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    sessionTtlSeconds: 3600,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    storage: {
      backend: "memory",
      applySchemaOnStartup: true,
    },
    apps: {
      repixelizer: {
        discordGuildId: "gamecult-guild",
        discordAllowedRoleIds: ["role-repixelizer"],
      },
    },
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: { clientId: "patreon-client", clientSecret: "patreon-secret" },
      github: { clientId: "github-client", clientSecret: "github-secret" },
      twitch: { clientId: "twitch-client", clientSecret: "twitch-secret" },
      youtube: { clientId: "youtube-client", clientSecret: "youtube-secret" },
    },
  };
}

function createMockDiscordRuntime(): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return {
        accessToken: "discord-access-token",
        refreshToken: "discord-refresh-token",
        tokenType: "Bearer",
        scope: ["identify", "guilds.members.read"],
        expiresAt: "2026-04-26T13:00:00.000Z",
        raw: { source: "test" },
      };
    },
    async resolveIdentity() {
      return {
        provider: "discord",
        providerUserId: "discord-user-123",
        username: "meta",
        displayName: "Meta",
        primaryEmail: "meta@gamecult.org",
        profile: { id: "discord-user-123", username: "meta" },
      };
    },
    async evaluateEntitlements({ callback }) {
      return {
        facts: [entitlementFacts.appAccess],
        snapshots: [
          {
            accountId: callback.accountId,
            provider: "discord",
            scope: "repixelizer:discord_role_access:gamecult-guild",
            evaluatedAt: "2026-04-26T12:00:00.000Z",
            isAllowed: true,
            reasonCode: "matched_role",
            reasonDetail: "Matched Repixelizer access role.",
            rawSummaryJson: {
              guildId: "gamecult-guild",
              matchedRoles: ["role-repixelizer"],
            },
          },
        ],
      };
    },
  };
}

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
const originalFetch = globalThis.fetch;

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

function getHeimdallContext(app: FastifyInstance) {
  return (app as FastifyInstance & {
    heimdallContext: {
      keys: {
        publicKey: Parameters<typeof verifyJwt>[1];
        publicJwk: { alg: "EdDSA"; kid: string; use: "sig"; [key: string]: unknown };
      };
      tokenCustody: {
        decrypt(ciphertext: string): string;
      };
      store: InMemoryStore;
    };
  }).heimdallContext;
}

async function startDiscordSignIn(app: FastifyInstance): Promise<string> {
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
  return response.json().stateToken as string;
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  while (apps.length) {
    await apps.pop()?.close();
  }
});

describe("Heimdall service", () => {
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

    const verified = verifyJwt(payload.stateToken as string, getPublicKey(app));
    expect(verified.valid).toBe(true);
    if (verified.valid) {
      expect(verified.payload).toEqual(
        expect.objectContaining({
          typ: "heimdall_oauth_state",
          provider: "discord",
          app_slug: "repixelizer",
        })
      );
    }
  });

  it("completes a provider callback and issues a verified Repixelizer claim", async () => {
    const store = new InMemoryStore();
    const app = await buildApp({
      config: createTestConfig(),
      store,
      oauthRuntimes: {
        discord: createMockDiscordRuntime(),
      },
    });
    apps.push(app);

    const stateToken = await startDiscordSignIn(app);
    const response = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });

    expect(response.statusCode).toBe(201);
    const payload = response.json();
    expect(payload.completion).toEqual(
      expect.objectContaining({
        code: expect.any(String),
        redeemEndpoint: "https://heimdall.gamecult.org/v1/apps/repixelizer/auth-completions/redeem",
      })
    );
    expect(payload.sharedCapabilities).toEqual(expect.arrayContaining(["app_access", "queue_submit"]));
    expect(payload.account).toEqual(
      expect.objectContaining({
        displayName: "Meta",
        primaryEmail: "meta@gamecult.org",
      })
    );
    expect(payload.entitlements.facts).toEqual(expect.arrayContaining([entitlementFacts.appAccess]));

    const storedIdentity = await store.findStoredLinkedIdentity("discord", "discord-user-123");
    expect(storedIdentity).toEqual(expect.objectContaining({ provider: "discord" }));
    expect(storedIdentity?.accessTokenEncrypted).toMatch(/^gc_tok_v1:/);
    expect(storedIdentity?.accessTokenEncrypted).not.toBe("discord-access-token");
    expect(getHeimdallContext(app).tokenCustody.decrypt(storedIdentity?.accessTokenEncrypted ?? "")).toBe(
      "discord-access-token"
    );
    expect(getHeimdallContext(app).tokenCustody.decrypt(storedIdentity?.refreshTokenEncrypted ?? "")).toBe(
      "discord-refresh-token"
    );

    const verified = verifyJwt(payload.accessToken as string, getPublicKey(app));
    expect(verified.valid).toBe(true);
    if (verified.valid) {
      expect(verified.payload).toEqual(
        expect.objectContaining({
          typ: "heimdall_access",
          aud: "repixelizer",
          account_id: payload.account.id,
        })
      );
      expect(verified.payload.facts).toEqual(
        expect.arrayContaining([identityFacts.authenticated, entitlementFacts.appAccess])
      );
      expect(verified.payload.capabilities).toEqual(expect.arrayContaining(["app_access", "queue_submit"]));
    }
  });

  it("redeems a completion code exactly once", async () => {
    const app = await buildApp({
      config: createTestConfig(),
      oauthRuntimes: {
        discord: createMockDiscordRuntime(),
      },
    });
    apps.push(app);

    const stateToken = await startDiscordSignIn(app);
    const callbackResponse = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });
    const completionCode = callbackResponse.json().completion.code as string;

    const redeemResponse = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/auth-completions/redeem",
      payload: {
        completionCode,
      },
    });

    expect(redeemResponse.statusCode).toBe(201);
    expect(redeemResponse.json()).toEqual(
      expect.objectContaining({
        status: "success",
        provider: "discord",
        appSlug: "repixelizer",
      })
    );

    const secondRedeemResponse = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/auth-completions/redeem",
      payload: {
        completionCode,
      },
    });

    expect(secondRedeemResponse.statusCode).toBe(410);
  });

  it("renders a browser handoff page that posts a completion code instead of a token", async () => {
    const app = await buildApp({
      config: createTestConfig(),
      oauthRuntimes: {
        discord: createMockDiscordRuntime(),
      },
    });
    apps.push(app);

    const stateToken = await startDiscordSignIn(app);
    const response = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
      headers: {
        accept: "text/html",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.body).toContain("window.opener.postMessage");
    expect(response.body).toContain("heimdall_completion_code");
    expect(response.body).not.toContain("heimdall_access_token");
  });

  it("delivers auth results directly to app backends when backend callback handoff is requested", async () => {
    const deliveries: Array<Record<string, unknown>> = [];
    globalThis.fetch = async (input, init) => {
      if (String(input) !== "https://repixelizer.gamecult.org/api/auth/heimdall/callback") {
        throw new Error(`Unexpected fetch target in backend handoff test: ${String(input)}`);
      }

      deliveries.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(null, { status: 204 });
    };

    const app = await buildApp({
      config: createTestConfig(),
      oauthRuntimes: {
        discord: createMockDiscordRuntime(),
      },
    });
    apps.push(app);

    const startResponse = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        handoff: {
          kind: "backend_callback",
          attemptId: "attempt-123",
          callbackUrl: "https://repixelizer.gamecult.org/api/auth/heimdall/callback",
        },
      },
    });
    expect(startResponse.statusCode).toBe(201);
    const stateToken = startResponse.json().stateToken as string;

    const response = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
      headers: {
        accept: "text/html",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("heimdall_attempt_id");
    expect(response.body).not.toContain("heimdall_completion_code");
    expect(deliveries).toHaveLength(1);
    const delivery = deliveries[0];
    expect(delivery).toBeDefined();
    expect(delivery).toEqual(
      expect.objectContaining({
        source: "heimdall",
        kind: "oauth_result",
        handoffKind: "backend_callback",
        attemptId: "attempt-123",
        status: "success",
        provider: "discord",
        appSlug: "repixelizer",
      })
    );

    const deliveryAccessToken = delivery?.accessToken;
    expect(typeof deliveryAccessToken).toBe("string");
    const verified = verifyJwt(String(deliveryAccessToken), getPublicKey(app));
    expect(verified.valid).toBe(true);
  });

  it("issues direct claims from provider-agnostic entitlement facts", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/claims/issue",
      payload: {
        accountId: "acct_repixelizer_001",
        displayName: "Meta",
        facts: [entitlementFacts.appAccess, grantFacts.operator],
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

    const verifier = createHeimdallAccessTokenVerifier({
      issuer: "https://heimdall.gamecult.org",
      appSlug: "repixelizer",
      jwks: {
        keys: [getHeimdallContext(app).keys.publicJwk],
      },
    });
    expect(verifier.verify(payload.accessToken as string)).toEqual(
      expect.objectContaining({
        valid: true,
        claimSet: expect.objectContaining({
          aud: "repixelizer",
          app: expect.objectContaining({
            slug: "repixelizer",
          }),
        }),
      })
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
