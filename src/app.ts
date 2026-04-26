import { randomUUID } from "node:crypto";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import {
  appSlugs,
  connectionKinds,
  oauthModes,
  providers,
  type AppSlug,
  type OAuthMode,
  type OAuthConnectionBinding,
  type RedeemAuthCompletionRequest,
  type OAuthStatePayload,
  type OAuthStartRequest,
  type Provider,
} from "./contracts.js";
import { mapIssueClaimRequest, issueAccessClaim, type IssueAccessClaimInput } from "./claims.js";
import { getAppProfile, serializeAppProfile, supportsProvider } from "./app-profiles.js";
import { renderBrowserHandoffPage } from "./browser-handoff.js";
import { type HeimdallConfig, loadConfig } from "./config.js";
import { createTokenCustody, type TokenCustody } from "./custody.js";
import { grantFact } from "./facts.js";
import { createOAuthRuntimeRegistry, type OAuthRuntimeRegistry } from "./oauth.js";
import { buildAuthorizationUrl, providerCatalog, providerExpectedEnv } from "./providers.js";
import { createRuntimeKeyMaterial, signJwt, verifyJwt } from "./signing.js";
import { createStore, type HeimdallStore } from "./store/index.js";
import { type CreateAccountInput, type StoredCapabilityGrant, type UpsertLinkedIdentityInput } from "./store/types.js";

interface BuildAppOptions {
  config?: HeimdallConfig;
  store?: HeimdallStore;
  oauthRuntimes?: Partial<OAuthRuntimeRegistry>;
  tokenCustody?: TokenCustody;
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

function nowEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function buildOAuthStateToken(options: {
  config: HeimdallConfig;
  provider: Provider;
  appSlug: AppSlug;
  mode: OAuthMode;
  returnTo: string;
  connection: OAuthConnectionBinding | undefined;
  keys: ReturnType<typeof createRuntimeKeyMaterial>;
}): { token: string; expiresAt: string } {
  const issuedAt = nowEpochSeconds();
  const expiresAtEpoch = issuedAt + options.config.stateTtlSeconds;
  const payload: OAuthStatePayload = {
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
  };
  const token = signJwt(payload as unknown as Record<string, unknown>, options.keys);

  return {
    token,
    expiresAt: new Date(expiresAtEpoch * 1000).toISOString(),
  };
}

function parseOAuthStatePayload(payload: Record<string, unknown>): OAuthStatePayload | null {
  if (
    payload.typ !== "heimdall_oauth_state" ||
    typeof payload.provider !== "string" ||
    !providers.includes(payload.provider as Provider) ||
    typeof payload.app_slug !== "string" ||
    !appSlugs.includes(payload.app_slug as AppSlug) ||
    typeof payload.mode !== "string" ||
    !oauthModes.includes(payload.mode as OAuthMode) ||
    typeof payload.return_to !== "string" ||
    typeof payload.iss !== "string" ||
    typeof payload.sub !== "string" ||
    typeof payload.aud !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.nbf !== "number" ||
    typeof payload.exp !== "number"
  ) {
    return null;
  }

  return payload as unknown as OAuthStatePayload;
}

function buildGrantFacts(grants: StoredCapabilityGrant[]): string[] {
  return grants.map((grant) => grantFact(grant.capability));
}

function prefersHtml(acceptHeader: string | undefined): boolean {
  if (!acceptHeader) {
    return false;
  }

  return acceptHeader.includes("text/html") || acceptHeader.includes("application/xhtml+xml");
}

export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();
  const store = options.store ?? (await createStore(config));
  const keys = createRuntimeKeyMaterial(config);
  const tokenCustody = options.tokenCustody ?? createTokenCustody(config);
  const oauthRuntimes: OAuthRuntimeRegistry = {
    ...createOAuthRuntimeRegistry(),
    ...(options.oauthRuntimes ?? {}),
  };
  const app = Fastify({ logger: false });
  app.decorate("heimdallContext", { config, keys, store, oauthRuntimes, tokenCustody });
  app.addHook("onClose", async () => {
    await store.close();
  });

  await app.register(cors, {
    origin: true,
    credentials: true,
  });

  app.get("/healthz", async () => ({
    ok: true,
    service: config.serviceName,
    issuer: config.issuer,
    storageBackend: config.storage.backend,
    signingKeySource: keys.source,
    tokenCustodySource: tokenCustody.source,
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

      const statePayload = parseOAuthStatePayload(verification.payload);
      if (!statePayload || statePayload.provider !== request.params.provider) {
        reply.code(400);
        return { error: "state_provider_mismatch" };
      }

      if (request.query.error) {
        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              error: "provider_error",
              errorDescription: request.query.error_description ?? request.query.error,
            })
          );
        }

        reply.code(400);
        return {
          error: "provider_error",
          provider: request.params.provider,
          providerError: request.query.error,
          providerErrorDescription: request.query.error_description,
          returnTo: statePayload.return_to,
        };
      }

      if (!request.query.code) {
        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              error: "missing_code",
            })
          );
        }

        reply.code(400);
        return { error: "missing_code", returnTo: statePayload.return_to };
      }

      const callbackUrl = `${config.publicBaseUrl}/v1/oauth/${request.params.provider}/callback`;
      const runtime = oauthRuntimes[request.params.provider];

      try {
        const tokenSet = await runtime.exchangeAuthorizationCode({
          config,
          code: request.query.code,
          redirectUri: callbackUrl,
        });
        const identity = await runtime.resolveIdentity({
          accessToken: tokenSet.accessToken,
        });
        const nowIso = new Date().toISOString();
        let account = await store.findAccountByLinkedIdentity(identity.provider, identity.providerUserId);

        if (!account) {
          const createAccountInput: CreateAccountInput = {
            createdAt: nowIso,
            lastSeenAt: nowIso,
          };
          const displayName = identity.displayName ?? identity.username;
          if (displayName !== undefined) {
            createAccountInput.displayName = displayName;
          }
          if (identity.primaryEmail !== undefined) {
            createAccountInput.primaryEmail = identity.primaryEmail;
          }
          account = await store.createAccount(createAccountInput);
        } else {
          const accountUpdates: { displayName?: string; primaryEmail?: string } = {};
          const displayName = identity.displayName ?? identity.username;
          if (displayName !== undefined) {
            accountUpdates.displayName = displayName;
          }
          if (identity.primaryEmail !== undefined) {
            accountUpdates.primaryEmail = identity.primaryEmail;
          }
          await store.touchAccount(account.id, nowIso, accountUpdates);
        }

        const linkedIdentityInput: UpsertLinkedIdentityInput = {
          accountId: account.id,
          provider: identity.provider,
          providerUserId: identity.providerUserId,
          scopes: tokenSet.scope,
          profileJson: identity.profile,
          createdAt: nowIso,
          updatedAt: nowIso,
        };
        if (identity.username !== undefined) {
          linkedIdentityInput.username = identity.username;
        }
        if (identity.displayName !== undefined) {
          linkedIdentityInput.displayName = identity.displayName;
        }
        if (identity.primaryEmail !== undefined) {
          linkedIdentityInput.primaryEmail = identity.primaryEmail;
        }
        linkedIdentityInput.accessTokenEncrypted = tokenCustody.encrypt(tokenSet.accessToken);
        if (tokenSet.refreshToken !== undefined) {
          linkedIdentityInput.refreshTokenEncrypted = tokenCustody.encrypt(tokenSet.refreshToken);
        }
        if (tokenSet.expiresAt !== undefined) {
          linkedIdentityInput.tokenExpiresAt = tokenSet.expiresAt;
        }
        await store.upsertLinkedIdentity(linkedIdentityInput);

        const entitlementEvaluation = await runtime.evaluateEntitlements({
          config,
          callback: {
            appSlug: statePayload.app_slug,
            accountId: account.id,
            connection: statePayload.connection,
          },
          identity,
          tokenSet,
        });
        for (const snapshot of entitlementEvaluation.snapshots) {
          await store.upsertEntitlementSnapshot(snapshot);
        }

        const grants = await store.listActiveGrants(account.id, statePayload.app_slug, nowIso);
        const issueInput: IssueAccessClaimInput = {
          appSlug: statePayload.app_slug,
          accountId: account.id,
          linkedIdentities: await store.listLinkedIdentitiesForAccount(account.id),
          facts: [...entitlementEvaluation.facts, ...buildGrantFacts(grants)],
        };
        if (account.displayName !== undefined) {
          issueInput.displayName = account.displayName;
        }

        const issued = await issueAccessClaim({
          config,
          keys,
          store,
          input: issueInput,
        });

        await store.createAuditEvent({
          accountId: account.id,
          sessionId: issued.session.sessionId,
          appSlug: statePayload.app_slug,
          eventType: "oauth_callback_succeeded",
          eventPayloadJson: {
            provider: request.params.provider,
            mode: statePayload.mode,
            returnTo: statePayload.return_to,
            grantedFacts: issued.claimSet.facts,
            sharedCapabilities: issued.sharedCapabilities,
          },
          createdAt: nowIso,
        });

        const accountSummary: {
          id: string;
          displayName?: string;
          primaryEmail?: string;
        } = {
          id: account.id,
        };
        if (account.displayName !== undefined) {
          accountSummary.displayName = account.displayName;
        }
        if (account.primaryEmail !== undefined) {
          accountSummary.primaryEmail = account.primaryEmail;
        }

        const completionPayload = {
          status: "success",
          provider: request.params.provider,
          mode: statePayload.mode,
          appSlug: statePayload.app_slug,
          account: accountSummary,
          entitlements: entitlementEvaluation,
          returnTo: statePayload.return_to,
          ...issued,
        };
        const completionExpiresAt = new Date(Date.now() + config.completionTtlSeconds * 1000).toISOString();
        const completion = await store.createAuthCompletion({
          appSlug: statePayload.app_slug,
          provider: request.params.provider,
          mode: statePayload.mode,
          accountId: account.id,
          sessionId: issued.session.sessionId,
          returnTo: statePayload.return_to,
          createdAt: nowIso,
          expiresAt: completionExpiresAt,
          payloadJson: completionPayload as unknown as Record<string, unknown>,
        });

        await store.createAuditEvent({
          accountId: account.id,
          sessionId: issued.session.sessionId,
          appSlug: statePayload.app_slug,
          eventType: "auth_completion_created",
          eventPayloadJson: {
            provider: request.params.provider,
            mode: statePayload.mode,
            completionCode: completion.code,
            expiresAt: completion.expiresAt,
          },
          createdAt: nowIso,
        });

        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              status: "success",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              completionCode: completion.code,
            })
          );
        }

        reply.code(201);
        return {
          completion: {
            code: completion.code,
            expiresAt: completion.expiresAt,
            redeemEndpoint: `${config.publicBaseUrl}/v1/apps/${statePayload.app_slug}/auth-completions/redeem`,
          },
          ...completionPayload,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : "OAuth callback failed.";
        const nowIso = new Date().toISOString();
        await store.createAuditEvent({
          appSlug: statePayload.app_slug,
          eventType: "oauth_callback_failed",
          eventPayloadJson: {
            provider: request.params.provider,
            mode: statePayload.mode,
            error: message,
          },
          createdAt: nowIso,
        });

        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              error: "oauth_callback_failed",
              errorDescription: message,
            })
          );
        }

        reply.code(502);
        return {
          error: "oauth_callback_failed",
          detail: message,
          provider: request.params.provider,
          appSlug: statePayload.app_slug,
          returnTo: statePayload.return_to,
        };
      }
    }
  );

  app.post<{ Params: { appSlug: AppSlug }; Body: RedeemAuthCompletionRequest }>(
    "/v1/apps/:appSlug/auth-completions/redeem",
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
          required: ["completionCode"],
          additionalProperties: false,
          properties: {
            completionCode: { type: "string", minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const nowIso = new Date().toISOString();
      const completion = await store.consumeAuthCompletion(request.params.appSlug, request.body.completionCode, nowIso);

      if (!completion) {
        reply.code(410);
        return { error: "invalid_or_expired_completion_code" };
      }

      await store.createAuditEvent({
        accountId: completion.accountId,
        sessionId: completion.sessionId,
        appSlug: completion.appSlug,
        eventType: "auth_completion_redeemed",
        eventPayloadJson: {
          provider: completion.provider,
          mode: completion.mode,
          completionCode: completion.code,
        },
        createdAt: nowIso,
      });

      reply.code(201);
      return completion.payloadJson;
    }
  );

  app.post<{ Params: { appSlug: AppSlug }; Body: import("./contracts.js").IssueClaimRequest }>(
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
      const issued = await issueAccessClaim({
        config,
        keys,
        store,
        input: mapIssueClaimRequest(request.params.appSlug, request.body),
      });
      reply.code(201);
      return issued;
    }
  );

  return app;
}
