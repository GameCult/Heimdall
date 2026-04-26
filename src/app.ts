import { randomUUID } from "node:crypto";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import {
  appSlugs,
  connectionKinds,
  oauthModes,
  providers,
  type AccessClaimPayload,
  type AppSlug,
  type IssueClaimRequest,
  type OAuthConnectionBinding,
  type OAuthStartRequest,
  type Provider,
} from "./contracts.js";
import { getAppProfile, serializeAppProfile, supportsProvider } from "./app-profiles.js";
import { type HeimdallConfig, loadConfig } from "./config.js";
import { buildAuthorizationUrl, providerCatalog, providerExpectedEnv } from "./providers.js";
import { createRuntimeKeyMaterial, signJwt, verifyJwt } from "./signing.js";

interface BuildAppOptions {
  config?: HeimdallConfig;
}

function nowEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function clampTtlSeconds(value: number, fallback: number): number {
  if (!Number.isFinite(value)) {
    return fallback;
  }

  return Math.max(60, Math.min(86_400, Math.trunc(value)));
}

function normalizeFacts(request: IssueClaimRequest): string[] {
  const facts = new Set(request.facts ?? []);
  if (request.accountId.trim() || request.linkedIdentities?.length) {
    facts.add("identity.authenticated");
  }
  return [...facts].sort();
}

function buildDiscovery(config: HeimdallConfig) {
  return {
    issuer: config.issuer,
    jwksUri: `${config.publicBaseUrl}/.well-known/jwks.json`,
    configurationUri: `${config.publicBaseUrl}/.well-known/heimdall-configuration`,
    oauthStartEndpoint: `${config.publicBaseUrl}/v1/oauth/{provider}/start`,
    oauthCallbackEndpoint: `${config.publicBaseUrl}/v1/oauth/{provider}/callback`,
    claimIssueEndpoint: `${config.publicBaseUrl}/v1/apps/{appSlug}/claims/issue`,
    supportedProviders: providers.map((provider) => ({
      key: provider,
      displayName: providerCatalog[provider].displayName,
      roles: providerCatalog[provider].roles,
    })),
    apps: appSlugs.map((appSlug) => serializeAppProfile(getAppProfile(appSlug))),
  };
}

function buildOAuthStateToken(options: {
  config: HeimdallConfig;
  provider: Provider;
  appSlug: AppSlug;
  mode: OAuthStartRequest["mode"];
  returnTo: string;
  connection: OAuthConnectionBinding | undefined;
  keys: ReturnType<typeof createRuntimeKeyMaterial>;
}): { token: string; expiresAt: string } {
  const issuedAt = nowEpochSeconds();
  const expiresAtEpoch = issuedAt + options.config.stateTtlSeconds;

  const token = signJwt(
    {
      iss: options.config.issuer,
      sub: options.appSlug,
      aud: options.provider,
      jti: randomUUID(),
      iat: issuedAt,
      nbf: issuedAt,
      exp: expiresAtEpoch,
      typ: "heimdall_oauth_state",
      provider: options.provider,
      app_slug: options.appSlug,
      mode: options.mode,
      return_to: options.returnTo,
      connection: options.connection ?? null,
    },
    options.keys
  );

  return {
    token,
    expiresAt: new Date(expiresAtEpoch * 1000).toISOString(),
  };
}

export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();
  const keys = createRuntimeKeyMaterial(config);
  const app = Fastify({ logger: false });
  app.decorate("heimdallContext", { config, keys });

  await app.register(cors, {
    origin: true,
    credentials: true,
  });

  app.get("/healthz", async () => ({
    ok: true,
    service: config.serviceName,
    issuer: config.issuer,
    now: new Date().toISOString(),
  }));

  app.get("/.well-known/jwks.json", async () => ({
    keys: [keys.publicJwk],
  }));

  app.get("/.well-known/heimdall-configuration", async () => buildDiscovery(config));

  app.get("/v1/apps", async () => ({
    apps: appSlugs.map((appSlug) => serializeAppProfile(getAppProfile(appSlug))),
  }));

  app.get<{ Params: { appSlug: AppSlug } }>(
    "/v1/apps/:appSlug",
    {
      schema: {
        params: {
          type: "object",
          required: ["appSlug"],
          additionalProperties: false,
          properties: {
            appSlug: { type: "string", enum: [...appSlugs] },
          },
        },
      },
    },
    async (request) => serializeAppProfile(getAppProfile(request.params.appSlug))
  );

  app.post<{ Params: { provider: Provider }; Body: OAuthStartRequest }>(
    "/v1/oauth/:provider/start",
    {
      schema: {
        params: {
          type: "object",
          required: ["provider"],
          additionalProperties: false,
          properties: {
            provider: { type: "string", enum: [...providers] },
          },
        },
        body: {
          type: "object",
          required: ["appSlug", "mode", "returnTo"],
          additionalProperties: false,
          properties: {
            appSlug: { type: "string", enum: [...appSlugs] },
            mode: { type: "string", enum: [...oauthModes] },
            returnTo: { type: "string", format: "uri" },
            requestedScopes: {
              type: "array",
              items: { type: "string" },
              uniqueItems: true,
            },
            connection: {
              type: "object",
              required: ["kind", "targetId"],
              additionalProperties: false,
              properties: {
                kind: { type: "string", enum: [...connectionKinds] },
                targetId: { type: "string", minLength: 1 },
                summary: { type: "string" },
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const { provider } = request.params;
      const profile = getAppProfile(request.body.appSlug);

      if (!supportsProvider(profile, provider)) {
        reply.code(400);
        return {
          error: "provider_not_supported_for_app",
          provider,
          appSlug: profile.slug,
        };
      }

      const providerConfig = config.providers[provider];
      if (!providerConfig.clientId) {
        reply.code(503);
        return {
          error: "provider_not_configured",
          provider,
          expectedEnv: providerExpectedEnv(provider),
        };
      }

      const callbackUrl = `${config.publicBaseUrl}/v1/oauth/${provider}/callback`;
      const state = buildOAuthStateToken({
        config,
        provider,
        appSlug: profile.slug,
        mode: request.body.mode,
        returnTo: request.body.returnTo,
        connection: request.body.connection,
        keys,
      });

      reply.code(201);
      return {
        provider,
        appSlug: profile.slug,
        mode: request.body.mode,
        callbackUrl,
        authorizationUrl: buildAuthorizationUrl({
          provider,
          clientId: providerConfig.clientId,
          redirectUri: callbackUrl,
          state: state.token,
          requestedScopes: request.body.requestedScopes,
        }),
        stateToken: state.token,
        stateExpiresAt: state.expiresAt,
      };
    }
  );

  app.get<{
    Params: { provider: Provider };
    Querystring: { code?: string; state?: string; error?: string; error_description?: string };
  }>(
    "/v1/oauth/:provider/callback",
    {
      schema: {
        params: {
          type: "object",
          required: ["provider"],
          additionalProperties: false,
          properties: {
            provider: { type: "string", enum: [...providers] },
          },
        },
        querystring: {
          type: "object",
          additionalProperties: false,
          properties: {
            code: { type: "string" },
            state: { type: "string" },
            error: { type: "string" },
            error_description: { type: "string" },
          },
        },
      },
    },
    async (request, reply) => {
      if (!request.query.state) {
        reply.code(400);
        return { error: "missing_state" };
      }

      const verification = verifyJwt(request.query.state, keys.publicKey);
      if (!verification.valid) {
        reply.code(400);
        return { error: "invalid_state", detail: verification.error };
      }

      const statePayload = verification.payload;
      if (statePayload.typ !== "heimdall_oauth_state" || statePayload.provider !== request.params.provider) {
        reply.code(400);
        return { error: "state_provider_mismatch" };
      }

      if (request.query.error) {
        reply.code(400);
        return {
          error: "provider_error",
          provider: request.params.provider,
          providerError: request.query.error,
          providerErrorDescription: request.query.error_description,
        };
      }

      if (!request.query.code) {
        reply.code(400);
        return { error: "missing_code" };
      }

      reply.code(501);
      return {
        error: "token_exchange_not_implemented",
        provider: request.params.provider,
        appSlug: statePayload.app_slug,
        mode: statePayload.mode,
        returnTo: statePayload.return_to,
        connection: statePayload.connection,
        codeReceived: true,
      };
    }
  );

  app.post<{ Params: { appSlug: AppSlug }; Body: IssueClaimRequest }>(
    "/v1/apps/:appSlug/claims/issue",
    {
      schema: {
        params: {
          type: "object",
          required: ["appSlug"],
          additionalProperties: false,
          properties: {
            appSlug: { type: "string", enum: [...appSlugs] },
          },
        },
        body: {
          type: "object",
          required: ["accountId"],
          additionalProperties: false,
          properties: {
            accountId: { type: "string", minLength: 1 },
            sessionId: { type: "string", minLength: 1 },
            displayName: { type: "string", minLength: 1 },
            facts: {
              type: "array",
              items: { type: "string" },
              uniqueItems: true,
            },
            accessRevision: { type: "integer", minimum: 1 },
            ttlSeconds: { type: "integer", minimum: 60, maximum: 86400 },
            linkedIdentities: {
              type: "array",
              items: {
                type: "object",
                required: ["provider", "providerUserId"],
                additionalProperties: false,
                properties: {
                  provider: { type: "string", enum: [...providers] },
                  providerUserId: { type: "string", minLength: 1 },
                  username: { type: "string" },
                  displayName: { type: "string" },
                },
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const profile = getAppProfile(request.params.appSlug);
      const facts = normalizeFacts(request.body);
      const factSet = new Set(facts);
      const linkedIdentities = request.body.linkedIdentities ?? [];
      const sharedCapabilities = profile.evaluateSharedCapabilities({
        accountId: request.body.accountId,
        facts: factSet,
        identities: linkedIdentities,
      });

      const issuedAt = nowEpochSeconds();
      const ttlSeconds = clampTtlSeconds(request.body.ttlSeconds ?? config.sessionTtlSeconds, config.sessionTtlSeconds);
      const expiresAtEpoch = issuedAt + ttlSeconds;
      const sessionId = request.body.sessionId ?? randomUUID();
      const accessClaim: AccessClaimPayload = {
        iss: config.issuer,
        aud: profile.slug,
        sub: request.body.accountId,
        sid: sessionId,
        jti: randomUUID(),
        iat: issuedAt,
        nbf: issuedAt,
        exp: expiresAtEpoch,
        typ: "heimdall_access",
        account_id: request.body.accountId,
        access_revision: request.body.accessRevision ?? 1,
        app: {
          slug: profile.slug,
          profile_version: profile.profileVersion,
        },
        facts,
        capabilities: sharedCapabilities,
        identities: linkedIdentities,
      };

      if (request.body.displayName) {
        accessClaim.display_name = request.body.displayName;
      }

      reply.code(201);
      return {
        session: {
          accountId: request.body.accountId,
          sessionId,
          appSlug: profile.slug,
          accessRevision: accessClaim.access_revision,
          expiresAt: new Date(expiresAtEpoch * 1000).toISOString(),
        },
        accessToken: signJwt(accessClaim as unknown as Record<string, unknown>, keys),
        claimSet: accessClaim,
        verification: {
          issuer: config.issuer,
          jwksUri: `${config.publicBaseUrl}/.well-known/jwks.json`,
          alg: keys.alg,
          kid: keys.kid,
        },
        sharedCapabilities,
        hybridCapabilities: profile.capabilities.filter((capability) => capability.mode === "hybrid"),
      };
    }
  );

  return app;
}
