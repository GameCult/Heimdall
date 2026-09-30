import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { type HeimdallConfig, loadConfig } from "../src/config.js";
import { entitlementFacts, identityFacts } from "../src/facts.js";
import { createOAuthRuntimeRegistry, type OAuthProviderRuntime } from "../src/oauth.js";
import { verifyJwt } from "../src/signing.js";
import { InMemoryStore } from "../src/store/index.js";

function createTestConfig(): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    workspaceRoot: "E:/Projects/Heimdall",
    dataRoot: "E:/Projects/Heimdall/.heimdall-data",
    cultCachePath: "E:/Projects/Heimdall/.heimdall-data/cultcache/heimdall.service.cc",
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    daemonId: "yggdrasil-heimdall",
    idunnRudpHealth: undefined,
    idunnHealthContract: "heimdall.cultnet-rudp-provider-health",
    providerHealthIdentityPath: "E:/Projects/Heimdall/.heimdall-data/provider-health-identity.cc",
    sessionTtlSeconds: 3600,
    refreshTtlSeconds: 60 * 60 * 24 * 30,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    appSharedSecrets: {
      streampixels: "streampixels-secret",
      repixelizer: "repixelizer-secret",
      bifrost: "bifrost-secret",
    },
    appBackendCallbacks: {
      bifrost: ["https://bifrost.gamecult.org/auth/heimdall/callback"],
      repixelizer: ["https://repixelizer.gamecult.org/api/auth/heimdall/callback"],
    },
    storage: {
      backend: "memory",
      applySchemaOnStartup: true,
    },
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: { clientId: "patreon-client", clientSecret: "patreon-secret" },
      github: { clientId: "github-client", clientSecret: "github-secret" },
      twitch: { clientId: "twitch-client", clientSecret: "twitch-secret" },
      youtube: { clientId: "youtube-client", clientSecret: "youtube-secret" },
      spotify: { clientId: "spotify-client", clientSecret: "spotify-secret" },
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
        encrypt(plaintext: string): string;
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
  }, 15_000);

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
          entitlement_policy: null,
        })
      );
    }
  });

  it("rejects caller-owned entitlement policy without a caller, regardless of handoff kind", async () => {
    // Policy trust is decided by resolveAppCaller alone now (R5, fork 1B):
    // handoff.kind no longer substitutes for identity, so the same 401 applies
    // to a browser-completion start as it would to a backend-callback one.
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        entitlementPolicy: {
          kind: "discord_role_access",
          guildId: "gamecult-guild",
          allowedRoleIds: ["role-repixelizer"],
        },
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(expect.objectContaining({ error: "app_auth_required" }));
  });

  it("accepts caller-owned entitlement policy for a browser completion handoff when the caller is trusted", async () => {
    // The other half of the same pin: a caller holding the secret may attach
    // policy even without a backend_callback handoff, because identity no
    // longer rides on handoff kind.
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      headers: { "x-heimdall-app-secret": "repixelizer-secret" },
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        entitlementPolicy: {
          kind: "discord_role_access",
          guildId: "gamecult-guild",
          allowedRoleIds: ["role-repixelizer"],
        },
      },
    });

    expect(response.statusCode).toBe(201);
  });

  it("accepts caller-owned entitlement policy for trusted backend handoffs", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      headers: { "x-heimdall-app-secret": "repixelizer-secret" },
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        handoff: {
          kind: "backend_callback",
          attemptId: "attempt-123",
          callbackUrl: "https://repixelizer.gamecult.org/api/auth/heimdall/callback",
        },
        entitlementPolicy: {
          kind: "discord_role_access",
          guildId: "gamecult-guild",
          allowedRoleIds: ["role-repixelizer"],
        },
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
          entitlement_policy: {
            kind: "discord_role_access",
            guildId: "gamecult-guild",
            allowedRoleIds: ["role-repixelizer"],
          },
        })
      );
    }
  });

  it("builds Patreon OAuth start state with caller-owned membership policy", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/patreon/start",
      headers: { "x-heimdall-app-secret": "repixelizer-secret" },
      payload: {
        appSlug: "repixelizer",
        mode: "sign_in",
        returnTo: "https://repixelizer.gamecult.org/app/",
        handoff: {
          kind: "backend_callback",
          attemptId: "attempt-123",
          callbackUrl: "https://repixelizer.gamecult.org/api/auth/heimdall/callback",
        },
        entitlementPolicy: {
          kind: "patreon_membership_access",
          requiredTierTitle: "Inner Sanctum",
        },
      },
    });

    expect(response.statusCode).toBe(201);
    const payload = response.json();
    const authorizationUrl = new URL(payload.authorizationUrl as string);
    expect(`${authorizationUrl.origin}${authorizationUrl.pathname}`).toBe("https://www.patreon.com/oauth2/authorize");
    expect(authorizationUrl.searchParams.get("scope")).toBe("identity identity[email]");

    const verified = verifyJwt(payload.stateToken as string, getPublicKey(app));
    expect(verified.valid).toBe(true);
    if (verified.valid) {
      expect(verified.payload).toEqual(
        expect.objectContaining({
          typ: "heimdall_oauth_state",
          provider: "patreon",
          app_slug: "repixelizer",
          entitlement_policy: {
            kind: "patreon_membership_access",
            requiredTierTitle: "Inner Sanctum",
          },
        })
      );
    }
  });

  it("builds Bifrost Discord OAuth start state with caller-owned cult member role policy", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      headers: { "x-heimdall-app-secret": "bifrost-secret" },
      payload: {
        appSlug: "bifrost",
        mode: "sign_in",
        returnTo: "https://bifrost.gamecult.org/auth/heimdall/wait?attemptId=bifrost-attempt-123&returnTo=%2FApp",
        handoff: {
          kind: "backend_callback",
          attemptId: "bifrost-attempt-123",
          callbackUrl: "https://bifrost.gamecult.org/auth/heimdall/callback",
        },
        entitlementPolicy: {
          kind: "discord_role_access",
          guildId: "gamecult-guild",
          allowedRoleIds: ["role-ktlst"],
        },
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
          app_slug: "bifrost",
          entitlement_policy: {
            kind: "discord_role_access",
            guildId: "gamecult-guild",
            allowedRoleIds: ["role-ktlst"],
          },
        })
      );
    }
  });

  it("builds Bifrost Patreon OAuth start state with caller-owned tier policy", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/patreon/start",
      headers: { "x-heimdall-app-secret": "bifrost-secret" },
      payload: {
        appSlug: "bifrost",
        mode: "sign_in",
        returnTo: "https://bifrost.gamecult.org/auth/heimdall/wait?attemptId=bifrost-attempt-123&returnTo=%2FApp",
        handoff: {
          kind: "backend_callback",
          attemptId: "bifrost-attempt-123",
          callbackUrl: "https://bifrost.gamecult.org/auth/heimdall/callback",
        },
        entitlementPolicy: {
          kind: "patreon_membership_access",
          requiredTierTitle: "Inner Sanctum",
        },
      },
    });

    expect(response.statusCode).toBe(201);
    const payload = response.json();
    const authorizationUrl = new URL(payload.authorizationUrl as string);
    expect(`${authorizationUrl.origin}${authorizationUrl.pathname}`).toBe("https://www.patreon.com/oauth2/authorize");

    const verified = verifyJwt(payload.stateToken as string, getPublicKey(app));
    expect(verified.valid).toBe(true);
    if (verified.valid) {
      expect(verified.payload).toEqual(
        expect.objectContaining({
          typ: "heimdall_oauth_state",
          provider: "patreon",
          app_slug: "bifrost",
          entitlement_policy: {
            kind: "patreon_membership_access",
            requiredTierTitle: "Inner Sanctum",
          },
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

  it("syncs a linked Patreon membership into a signed Bifrost support fact", async () => {
    const baseConfig = createTestConfig();
    const config = {
      ...baseConfig,
      appSharedSecrets: {
        ...baseConfig.appSharedSecrets,
        bifrost: "bifrost-secret",
      },
      bifrostPatronSupportEndpoint: "https://bifrost.gamecult.org/heimdall/patron-support/events",
      bifrostPatronSupportSecret: "bifrost-support-secret",
    };
    const store = new InMemoryStore();
    const app = await buildApp({ config, store });
    apps.push(app);

    const context = getHeimdallContext(app);
    const now = "2026-06-09T17:00:00.000Z";
    await store.createAccount({
      id: "heimdall-account-123",
      createdAt: now,
      lastSeenAt: now,
      displayName: "Patron",
    });
    await store.upsertLinkedIdentity({
      accountId: "heimdall-account-123",
      provider: "patreon",
      providerUserId: "patreon-user-456",
      accessTokenEncrypted: context.tokenCustody.encrypt("patreon-access-token"),
      refreshTokenEncrypted: context.tokenCustody.encrypt("patreon-refresh-token"),
      tokenExpiresAt: "2099-06-09T18:00:00.000Z",
      scopes: ["identity", "identity[email]"],
      profileJson: { id: "patreon-user-456" },
      createdAt: now,
      updatedAt: now,
    });

    let bifrostBody = "";
    let bifrostSignature = "";
    globalThis.fetch = async (input, init) => {
      const url = String(input);
      if (url.startsWith("https://www.patreon.com/api/oauth2/v2/identity")) {
        expect(init?.headers).toEqual(expect.objectContaining({ Authorization: "Bearer patreon-access-token" }));
        return new Response(
          JSON.stringify({
            data: { id: "patreon-user-456", type: "user", attributes: { full_name: "Patron" } },
            included: [
              {
                id: "member-789",
                type: "member",
                attributes: {
                  currently_entitled_amount_cents: 1500,
                  last_charge_status: "Paid",
                  patron_status: "active_patron",
                },
                relationships: {
                  currently_entitled_tiers: { data: [{ id: "tier-inner", type: "tier" }] },
                  campaign: { data: { id: "campaign-1", type: "campaign" } },
                },
              },
              { id: "tier-inner", type: "tier", attributes: { title: "Inner Sanctum" } },
              { id: "campaign-1", type: "campaign", attributes: { currency: "USD" } },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }

      if (url === "https://bifrost.gamecult.org/heimdall/patron-support/events") {
        bifrostBody = String(init?.body ?? "");
        const headers = init?.headers as Record<string, string>;
        bifrostSignature = headers["x-heimdall-signature-256"] ?? "";
        return new Response("processed", { status: 200 });
      }

      return new Response("unexpected request", { status: 500 });
    };

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/bifrost/patron-support/sync",
      headers: {
        "x-heimdall-app-secret": "bifrost-secret",
      },
      payload: {
        accountId: "heimdall-account-123",
        requiredTierTitle: "Inner Sanctum",
        supportedAtUtc: now,
      },
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(bifrostSignature).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(JSON.parse(bifrostBody)).toEqual({
      heimdallAccountId: "heimdall-account-123",
      provider: "Patreon",
      providerEventId: "patreon-membership-snapshot:patreon-user-456:member-789:2026-06-09:1500",
      kind: "RecurringSupportSnapshot",
      amount: 15,
      currencyCode: "USD",
      externalSupportId: "patreon-member:member-789",
      supportedAtUtc: now,
      isCurrentRecurringSupport: true,
      providerPayerId: "patreon-user-456",
      providerSubscriptionId: "member-789",
      notes: "Verified active Patreon membership for tier Inner Sanctum.",
    });
    expect(response.json()).toEqual(
      expect.objectContaining({
        status: "synced",
        bifrostResponse: "processed",
      })
    );
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

  it("refreshes a Repixelizer app claim from a Heimdall refresh token without provider OAuth", async () => {
    const store = new InMemoryStore();
    let exchangeCalls = 0;
    let refreshCalls = 0;
    const app = await buildApp({
      config: createTestConfig(),
      store,
      oauthRuntimes: {
        discord: {
          async exchangeAuthorizationCode() {
            exchangeCalls += 1;
            return {
              accessToken: "expired-discord-access-token",
              refreshToken: "discord-refresh-token",
              tokenType: "Bearer",
              scope: ["identify", "guilds.members.read"],
              expiresAt: "2026-04-26T13:00:00.000Z",
              raw: { source: "test" },
            };
          },
          async refreshAccessToken({ refreshToken }) {
            refreshCalls += 1;
            expect(refreshToken).toBe("discord-refresh-token");
            return {
              accessToken: "fresh-discord-access-token",
              refreshToken: "rotated-discord-refresh-token",
              tokenType: "Bearer",
              scope: ["identify", "guilds.members.read"],
              expiresAt: "2999-04-26T13:00:00.000Z",
              raw: { source: "refresh" },
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
          async evaluateEntitlements({ callback, tokenSet }) {
            expect(tokenSet.accessToken).toBe(refreshCalls ? "fresh-discord-access-token" : "expired-discord-access-token");
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
                  rawSummaryJson: {},
                },
              ],
            };
          },
        },
      },
    });
    apps.push(app);

    const stateToken = await startDiscordSignIn(app);
    const callbackResponse = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });
    expect(callbackResponse.statusCode).toBe(201);
    const refreshToken = callbackResponse.json().refreshToken as string;

    const refreshResponse = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/sessions/refresh",
      headers: { "x-heimdall-app-secret": "repixelizer-secret" },
      payload: {
        refreshToken,
        entitlementPolicies: [
          {
            kind: "discord_role_access",
            guildId: "gamecult-guild",
            allowedRoleIds: ["role-repixelizer"],
          },
        ],
      },
    });

    expect(refreshResponse.statusCode).toBe(201);
    expect(exchangeCalls).toBe(1);
    expect(refreshCalls).toBe(1);
    const payload = refreshResponse.json();
    expect(payload.sharedCapabilities).toEqual(expect.arrayContaining(["app_access", "queue_submit"]));
    expect(payload.refreshToken).toEqual(expect.any(String));
    const verified = verifyJwt(payload.accessToken as string, getPublicKey(app));
    expect(verified.valid).toBe(true);
    if (verified.valid) {
      expect(verified.payload.sid).toBe(callbackResponse.json().session.sessionId);
      expect(verified.payload.capabilities).toEqual(expect.arrayContaining(["app_access", "queue_submit"]));
    }
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

  it("no longer exposes a route to mint claims from caller-supplied facts", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/repixelizer/claims/issue",
      payload: { accountId: "probe" },
    });

    expect(response.statusCode).toBe(404);
    expect(app.printRoutes()).not.toContain("claims/issue");

    const discoveryResponse = await app.inject({
      method: "GET",
      url: "/.well-known/heimdall-configuration",
    });
    expect(discoveryResponse.json()).not.toHaveProperty("claimIssueEndpoint");
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

  it("rejects unconfigured backend callback URLs", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: {
        appSlug: "bifrost",
        mode: "connect",
        returnTo: "https://bifrost.gamecult.org/auth/complete",
        handoff: {
          kind: "backend_callback",
          attemptId: "bifrost-bad-attempt",
          callbackUrl: "https://not-bifrost.example/auth/heimdall/callback",
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(
      expect.objectContaining({
        error: "untrusted_backend_callback",
      })
    );
  });

  it("no longer trusts Repixelizer's callback URL by slug name alone", async () => {
    const baseConfig = createTestConfig();
    const config = {
      ...baseConfig,
      appBackendCallbacks: {},
    };
    const app = await buildApp({ config });
    apps.push(app);

    const response = await app.inject({
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

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(expect.objectContaining({ error: "untrusted_backend_callback" }));
  });

  it("requires the app secret uniformly, with no slug special-cased", async () => {
    // resolveAppCaller is the only identity decision left; it must behave
    // identically for every built-in slug rather than special-casing one.
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    for (const appSlug of ["repixelizer", "streampixels", "bifrost", "ghostlight"] as const) {
      const denied = await app.inject({
        method: "POST",
        url: `/v1/apps/${appSlug}/managed-credentials/resolve`,
        payload: { accountId: "acct-1", provider: "discord" },
      });
      expect(denied.statusCode, appSlug).toBe(401);
      expect(denied.json()).toEqual(expect.objectContaining({ error: "app_auth_required" }));
    }
  });

  it("uses only the timing-safe comparator: a near-miss secret is rejected, an exact one is accepted", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const nearMiss = await app.inject({
      method: "POST",
      url: "/v1/apps/streampixels/managed-credentials/resolve",
      headers: { "x-heimdall-app-secret": "streampixels-secretX" },
      payload: { accountId: "acct-1", provider: "twitch" },
    });
    expect(nearMiss.statusCode).toBe(401);

    const exact = await app.inject({
      method: "POST",
      url: "/v1/apps/streampixels/managed-credentials/resolve",
      headers: { "x-heimdall-app-secret": "streampixels-secret" },
      payload: { accountId: "acct-1", provider: "twitch" },
    });
    // Past the identity gate: the credential itself doesn't exist in this
    // fixture, but that is a 404, not a 401 -- proof the secret was accepted.
    expect(exact.statusCode).toBe(404);
  });

  it("resolves app-managed provider credentials without exposing refresh custody", async () => {
    const store = new InMemoryStore();
    const app = await buildApp({
      config: createTestConfig(),
      store,
      oauthRuntimes: {
        twitch: {
          async exchangeAuthorizationCode() {
            return {
              accessToken: "twitch-access-token",
              refreshToken: "twitch-refresh-token",
              tokenType: "Bearer",
              scope: ["user:read:email"],
              expiresAt: "2026-04-26T13:00:00.000Z",
              raw: { source: "test" },
            };
          },
          async resolveIdentity() {
            return {
              provider: "twitch",
              providerUserId: "twitch-user-123",
              username: "pixelpaladin",
              displayName: "PixelPaladin",
              profile: { id: "twitch-user-123" },
            };
          },
          async evaluateEntitlements() {
            return { facts: [], snapshots: [] };
          },
        },
      },
    });
    apps.push(app);

    const startResponse = await app.inject({
      method: "POST",
      url: "/v1/oauth/twitch/start",
      payload: {
        appSlug: "streampixels",
        mode: "connect",
        returnTo: "https://streampixels.gamecult.org/auth/connect",
      },
    });
    const stateToken = startResponse.json().stateToken as string;

    const callbackResponse = await app.inject({
      method: "GET",
      url: `/v1/oauth/twitch/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });
    const accountId = callbackResponse.json().account.id as string;

    const credentialResponse = await app.inject({
      method: "POST",
      url: "/v1/apps/streampixels/managed-credentials/resolve",
      headers: {
        "x-heimdall-app-secret": "streampixels-secret",
      },
      payload: {
        accountId,
        provider: "twitch",
      },
    });

    expect(credentialResponse.statusCode).toBe(200);
    expect(credentialResponse.json()).toEqual(
      expect.objectContaining({
        accountId,
        provider: "twitch",
        providerUserId: "twitch-user-123",
        accessToken: "twitch-access-token",
        scopes: ["user:read:email"],
      })
    );
    expect(credentialResponse.body).not.toContain("twitch-refresh-token");
  });

  it("refreshes expiring app-managed provider credentials before resolving them", async () => {
    const store = new InMemoryStore();
    const app = await buildApp({
      config: createTestConfig(),
      store,
      oauthRuntimes: {
        twitch: {
          async exchangeAuthorizationCode() {
            return {
              accessToken: "expired-twitch-access-token",
              refreshToken: "twitch-refresh-token",
              tokenType: "Bearer",
              scope: ["user:read:email"],
              expiresAt: "2026-04-26T13:00:00.000Z",
              raw: { source: "test" },
            };
          },
          async refreshAccessToken({ refreshToken }) {
            expect(refreshToken).toBe("twitch-refresh-token");
            return {
              accessToken: "fresh-twitch-access-token",
              refreshToken: "rotated-twitch-refresh-token",
              tokenType: "Bearer",
              scope: ["user:read:email", "user:read:chat"],
              expiresAt: "2999-04-26T13:00:00.000Z",
              raw: { source: "refresh" },
            };
          },
          async resolveIdentity() {
            return {
              provider: "twitch",
              providerUserId: "twitch-user-123",
              username: "pixelpaladin",
              displayName: "PixelPaladin",
              profile: { id: "twitch-user-123" },
            };
          },
          async evaluateEntitlements() {
            return { facts: [], snapshots: [] };
          },
        },
      },
    });
    apps.push(app);

    const startResponse = await app.inject({
      method: "POST",
      url: "/v1/oauth/twitch/start",
      payload: {
        appSlug: "streampixels",
        mode: "connect",
        returnTo: "https://streampixels.gamecult.org/auth/connect",
      },
    });
    const stateToken = startResponse.json().stateToken as string;

    const callbackResponse = await app.inject({
      method: "GET",
      url: `/v1/oauth/twitch/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });
    const accountId = callbackResponse.json().account.id as string;

    const credentialResponse = await app.inject({
      method: "POST",
      url: "/v1/apps/streampixels/managed-credentials/resolve",
      headers: {
        "x-heimdall-app-secret": "streampixels-secret",
      },
      payload: {
        accountId,
        provider: "twitch",
      },
    });

    expect(credentialResponse.statusCode).toBe(200);
    expect(credentialResponse.json()).toEqual(
      expect.objectContaining({
        accountId,
        provider: "twitch",
        providerUserId: "twitch-user-123",
        accessToken: "fresh-twitch-access-token",
        tokenExpiresAt: "2999-04-26T13:00:00.000Z",
        scopes: ["user:read:email", "user:read:chat"],
      })
    );
    expect(credentialResponse.body).not.toContain("rotated-twitch-refresh-token");
  });

  it("no longer honors a global shared secret across apps", async () => {
    // A per-app identity model with a global fallback is a two-app shared
    // secret in practice (R6, fork 2). GC_ACCESS_APP_SHARED_SECRET alone must
    // produce no usable secret for any app.
    const config = loadConfig({ GC_ACCESS_APP_SHARED_SECRET: "one-secret-for-everyone" });
    expect(config.appSharedSecrets).toEqual({});

    const app = await buildApp({
      config: {
        ...createTestConfig(),
        appSharedSecrets: {},
      },
    });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/streampixels/managed-credentials/resolve",
      headers: { "x-heimdall-app-secret": "one-secret-for-everyone" },
      payload: { accountId: "acct-1", provider: "twitch" },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(expect.objectContaining({ error: "app_auth_required" }));
  });

  it("accepts Twitch token scopes returned as an array", async () => {
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          access_token: "twitch-access-token",
          refresh_token: "twitch-refresh-token",
          token_type: "bearer",
          expires_in: 14124,
          scope: ["user:read:email"],
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        }
      );

    const runtimes = createOAuthRuntimeRegistry();
    const tokenSet = await runtimes.twitch.exchangeAuthorizationCode({
      config: createTestConfig(),
      code: "test-code",
      redirectUri: "https://heimdall.gamecult.org/v1/oauth/twitch/callback",
    });

    expect(tokenSet.scope).toEqual(["user:read:email"]);
  });
});

// An answer never carries an input value. The canary stands in for whatever a
// failure could quote: part of a misbound database URL in a pg or resolver
// error, a request body, a header, a path, or a 4xx error's own message.
describe("error answers never echo an input", () => {
  const CANARY = "CANARY";

  function failingStore(): InMemoryStore {
    const store = new InMemoryStore();
    store.consumeAuthCompletion = async () => {
      throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${CANARY}host.invalid`), {
        code: "ENOTFOUND",
        hostname: `${CANARY}host.invalid`,
      });
    };
    return store;
  }

  it("answers a store failure with a fixed 500 body and logs only the route and code", async () => {
    const app = await buildApp({ config: createTestConfig(), store: failingStore() });
    apps.push(app);
    const logged: string[] = [];
    const originalError = console.error;
    console.error = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
    try {
      const response = await app.inject({
        method: "POST",
        url: "/v1/apps/bifrost/auth-completions/redeem",
        payload: { completionCode: "x" },
      });

      expect(response.statusCode).toBe(500);
      expect(response.json()).toEqual({ error: "internal_error" });
    } finally {
      console.error = originalError;
    }
    expect(logged).toEqual(["Heimdall POST /v1/apps/:appSlug/auth-completions/redeem failed (ENOTFOUND)."]);
  });

  it("answers a body that is not JSON without quoting it", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/bifrost/auth-completions/redeem",
      headers: { "content-type": "application/json" },
      payload: `${CANARY}notjson`,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe("invalid_request");
    expect(response.body).not.toContain(CANARY);
  });

  it("answers any other 4xx error by its code, not its message", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);
    app.get("/v1/probe-4xx", async () => {
      throw Object.assign(new Error(`refused ${CANARY}input`), { statusCode: 409, code: "PROBE_REFUSED" });
    });

    const response = await app.inject({ method: "GET", url: "/v1/probe-4xx" });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({ error: "invalid_request", code: "PROBE_REFUSED" });
  });

  it("answers an unsupported media type without quoting the header", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/bifrost/auth-completions/redeem",
      headers: { "content-type": `application/${CANARY}` },
      payload: "x",
    });

    expect(response.statusCode).toBe(415);
    expect(response.body).not.toContain(CANARY);
  });

  it("names the failed schema rule without quoting the request", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/v1/apps/bifrost/auth-completions/redeem",
      payload: { [`${CANARY}extra`]: `${CANARY}value` },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe("invalid_request");
    expect(response.json().detail).toMatch(/^body: #\//);
    expect(response.body).not.toContain(CANARY);
  });

  it("answers an unknown route or app without quoting the path", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const route = await app.inject({ method: "GET", url: `/v1/${CANARY}route` });
    expect(route.statusCode).toBe(404);
    expect(route.json()).toEqual({ error: "not_found" });

    const unknownApp = await app.inject({ method: "GET", url: `/v1/apps/${CANARY}app` });
    expect(unknownApp.statusCode).toBe(404);
    expect(unknownApp.json().error).toBe("unknown_app");
    expect(unknownApp.body).not.toContain(CANARY);

    const start = await app.inject({
      method: "POST",
      url: "/v1/oauth/discord/start",
      payload: { appSlug: `${CANARY}app`, mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" },
    });
    expect(start.statusCode).toBe(400);
    expect(start.body).not.toContain(CANARY);
  });

  function failingDiscordRuntime(): OAuthProviderRuntime {
    return {
      ...createMockDiscordRuntime(),
      async exchangeAuthorizationCode() {
        throw new SyntaxError(`Unexpected token 'a', "access_token=${CANARY}token" is not valid JSON`);
      },
    };
  }

  it("renders a failed provider callback page without the failure's text", async () => {
    const app = await buildApp({ config: createTestConfig(), oauthRuntimes: { discord: failingDiscordRuntime() } });
    apps.push(app);

    const stateToken = await startDiscordSignIn(app);
    const response = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
      headers: { accept: "text/html" },
    });

    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.body).toContain("oauth_callback_failed");
    expect(response.body).not.toContain(CANARY);
  });

  it("delivers a failed provider callback to the app backend without the failure's text", async () => {
    const deliveries: string[] = [];
    globalThis.fetch = async (_input, init) => {
      deliveries.push(String(init?.body));
      return new Response(null, { status: 204 });
    };
    const app = await buildApp({ config: createTestConfig(), oauthRuntimes: { discord: failingDiscordRuntime() } });
    apps.push(app);

    const start = await app.inject({
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
    expect(start.statusCode).toBe(201);
    const response = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(start.json().stateToken as string)}`,
    });

    expect(response.statusCode).toBe(502);
    expect(response.body).not.toContain(CANARY);
    expect(deliveries).toHaveLength(1);
    expect(JSON.parse(deliveries[0]!)).toMatchObject({ status: "error", error: "oauth_callback_failed" });
    expect(deliveries[0]).not.toContain(CANARY);
  });
});

// The provider's error and error_description are relayed, but they arrive as
// query parameters anyone can write: only RFC 6749's characters survive, each
// is bounded, and the page cannot be made to run what they carry.
describe("the relayed provider error", () => {
  const injected = `<script>alert(1)</script>"\\\u0007é${"x".repeat(300)}`;
  const allowed = /^[\x20-\x21\x23-\x5b\x5d-\x7e]*$/;

  function providerErrorUrl(stateToken: string): string {
    const query = new URLSearchParams({ state: stateToken, error: `${"e".repeat(100)}\u0000`, error_description: injected });
    return `/v1/oauth/discord/callback?${query.toString()}`;
  }

  it("is printable and bounded in the JSON answer", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({ method: "GET", url: providerErrorUrl(await startDiscordSignIn(app)) });

    expect(response.statusCode).toBe(400);
    const { providerError, providerErrorDescription } = response.json() as Record<string, string>;
    expect(providerError).toBe("e".repeat(64));
    expect(providerErrorDescription).toHaveLength(256);
    expect(providerErrorDescription).toMatch(allowed);
    expect(String(providerErrorDescription).startsWith("<script>alert(1)</script>xxx")).toBe(true);
  });

  it("cannot inject markup into the browser page, and is bounded there", async () => {
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);

    const response = await app.inject({
      method: "GET",
      url: providerErrorUrl(await startDiscordSignIn(app)),
      headers: { accept: "text/html" },
    });

    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.body.match(/<script/gi)).toHaveLength(1);
    expect(response.body).not.toContain("<script>alert");
    expect(response.body).not.toContain("x".repeat(257));
  });

  it("is printable and bounded in the backend handoff", async () => {
    const deliveries: Array<Record<string, unknown>> = [];
    globalThis.fetch = async (_input, init) => {
      deliveries.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(null, { status: 204 });
    };
    const app = await buildApp({ config: createTestConfig() });
    apps.push(app);
    const start = await app.inject({
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
    expect(start.statusCode).toBe(201);

    await app.inject({ method: "GET", url: providerErrorUrl(start.json().stateToken as string) });

    expect(deliveries).toHaveLength(1);
    const description = String(deliveries[0]!.errorDescription);
    expect(description).toHaveLength(256);
    expect(description).toMatch(allowed);
  });
});

describe("the failed-callback audit event", () => {
  it("keeps the error's class and code, not its text", async () => {
    const store = new InMemoryStore();
    const app = await buildApp({
      config: createTestConfig(),
      store,
      oauthRuntimes: {
        discord: {
          ...createMockDiscordRuntime(),
          async exchangeAuthorizationCode() {
            throw Object.assign(new Error("getaddrinfo ENOTFOUND CANARYhost.invalid"), { code: "ENOTFOUND" });
          },
        },
      },
    });
    apps.push(app);

    const stateToken = await startDiscordSignIn(app);
    const response = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });
    expect(response.statusCode).toBe(502);

    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string; eventPayloadJson: unknown }> }).auditEvents.values()];
    const failed = events.filter((event) => event.eventType === "oauth_callback_failed");
    expect(failed).toHaveLength(1);
    expect(failed[0]!.eventPayloadJson).toEqual({
      provider: "discord",
      mode: "sign_in",
      errorClass: "Error",
      errorCode: "ENOTFOUND",
      providerStatus: null,
    });
    expect(JSON.stringify(events)).not.toContain("CANARY");
  });
});

describe("the failed-callback audit event for a provider's HTTP refusal", () => {
  async function auditAfterTokenExchangeAnswers(response: () => Response) {
    globalThis.fetch = async () => response();
    const store = new InMemoryStore();
    const app = await buildApp({ config: createTestConfig(), store, oauthRuntimes: createOAuthRuntimeRegistry() });
    apps.push(app);
    const stateToken = await startDiscordSignIn(app);
    const callback = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}`,
    });
    expect(callback.statusCode).toBe(502);
    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string; eventPayloadJson: unknown }> }).auditEvents.values()];
    return events.filter((event) => event.eventType === "oauth_callback_failed");
  }

  it("keeps the provider's status as a number and never its body", async () => {
    const failed = await auditAfterTokenExchangeAnswers(
      () => new Response('{"error":"invalid_grant","echo":"CANARYbody"}', { status: 401 })
    );

    expect(failed).toHaveLength(1);
    expect(failed[0]!.eventPayloadJson).toEqual({
      provider: "discord",
      mode: "sign_in",
      errorClass: "ProviderResponseError",
      errorCode: "provider_status",
      providerStatus: 401,
    });
    expect(JSON.stringify(failed)).not.toContain("CANARY");
  });

  it("keeps a 2xx body that is not JSON out of the event, by class and code alone", async () => {
    const failed = await auditAfterTokenExchangeAnswers(
      () => new Response('{"access_token":"CANARYaccess","refresh_token":CANARYrefresh}', { status: 200 })
    );

    expect(failed).toHaveLength(1);
    expect(failed[0]!.eventPayloadJson).toEqual({
      provider: "discord",
      mode: "sign_in",
      errorClass: "ProviderResponseError",
      errorCode: "provider_body_not_json",
      providerStatus: 200,
    });
    expect(JSON.stringify(failed)).not.toContain("CANARY");
  });

  it("keeps no status that is not an HTTP status", async () => {
    const store = new InMemoryStore();
    const app = await buildApp({
      config: createTestConfig(),
      store,
      oauthRuntimes: {
        discord: {
          ...createMockDiscordRuntime(),
          async exchangeAuthorizationCode() {
            throw Object.assign(new Error("refused"), { status: 9999 });
          },
        },
      },
    });
    apps.push(app);
    const stateToken = await startDiscordSignIn(app);
    await app.inject({ method: "GET", url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(stateToken)}` });

    const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string; eventPayloadJson: Record<string, unknown> }> }).auditEvents.values()];
    const failed = events.find((event) => event.eventType === "oauth_callback_failed");
    expect(failed?.eventPayloadJson.providerStatus).toBeNull();
  });
});
