import { expect } from "vitest";
import { type FastifyInstance } from "fastify";
import { type HeimdallConfig } from "../src/config.js";
import { entitlementFacts } from "../src/facts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";

export function createTestConfig(): HeimdallConfig {
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
      joystick: { clientId: "joystick-client", clientSecret: "joystick-secret" },
    },
  };
}

export function createMockDiscordRuntime(): OAuthProviderRuntime {
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

/** What a start returns that the browser needs: the launch URL, whose query carries the signed state. */
export interface StartBody {
  authorizationUrl: string;
}

export function stateOf(start: StartBody): string {
  return new URL(start.authorizationUrl).searchParams.get("state") ?? "";
}

export interface LaunchedFlow {
  state: string;
  /** The `name=value` pair a browser sends back to the callback. */
  cookie: string;
}

export function setCookieOf(response: { headers: Record<string, unknown> }): string[] {
  return [response.headers["set-cookie"]].flat().filter((value): value is string => typeof value === "string");
}

/** Drives what a user's browser does after a start: follow authorizationUrl to the launch hop and keep its cookie. */
export async function launchFlow(app: FastifyInstance, start: StartBody): Promise<LaunchedFlow> {
  const url = new URL(start.authorizationUrl);
  const response = await app.inject({ method: "GET", url: `${url.pathname}${url.search}` });
  expect(response.statusCode, "launch").toBe(302);
  const set = setCookieOf(response).find((value) => value.startsWith("__Host-heimdall-oauth-"));
  expect(set, "launch sets the binding cookie").toBeDefined();
  return { state: stateOf(start), cookie: (set as string).split(";")[0] as string };
}
