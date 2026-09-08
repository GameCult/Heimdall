import { createHash, randomUUID } from "node:crypto";
import { decode, encode } from "@msgpack/msgpack";
import {
  startCultNetOperationServer,
  type CultNetOperationRequestMessage,
  type CultNetOperationResponseMessage,
  type CultNetOperationServer,
} from "cultnet-ts";
import { type FastifyInstance } from "fastify";
import { getHeimdallRuntimeContext, refreshAppSession, startOAuthFlow, verifyRefreshToken } from "./app.js";
import { callerFromOpenedEnvelope } from "./app-caller.js";
import { resolveAppProfile } from "./app-registry.js";
import { executeHeimdallAccessPlugin, HEIMDALL_ACCESS_PLUGIN_ID, type EvePluginAbiRequest } from "./access-plugin.js";
import { isAppSlug, oauthModes, providers, type AppSlug, type OAuthEntitlementPolicy, type OAuthMode, type Provider } from "./contracts.js";
import { type HeimdallConfig } from "./config.js";
import { openPrivateEnvelope, sealPrivateEnvelope, type HeimdallPrivateEnvelope } from "./private-command-security.js";
import { type HeimdallStore } from "./store/types.js";

export const HEIMDALL_PRIVATE_COMMAND_SERVICE = "heimdall.private.commands";
export const HEIMDALL_PRIVATE_ENVELOPE_SCHEMA = "heimdall.private_command_envelope.v1";

interface CachedResult {
  fingerprint: string;
  status: string;
  envelope: HeimdallPrivateEnvelope;
}

export async function startHeimdallPrivateCommandPlane(
  app: FastifyInstance,
  config: HeimdallConfig,
): Promise<CultNetOperationServer> {
  const seenNonces = new Map<string, number>();
  const inFlight = new Map<string, Promise<CachedResult>>();
  return await startCultNetOperationServer({
    runtimeId: config.daemonId,
    host: config.privateCommandHost ?? "127.0.0.1",
    port: config.privateCommandPort ?? 4101,
    handler: async (request) => {
      const now = Date.now();
      for (const [nonce, expiry] of seenNonces) if (expiry <= now) seenNonces.delete(nonce);
      try {
        if (request.serviceId === HEIMDALL_ACCESS_PLUGIN_ID) {
          if (request.payloadSchema !== "gamecult.eve.plugin_abi.request.v1" || request.payloadEncoding !== "messagepack-base64") {
            throw new Error("Heimdall access plugin requires the Eve plugin ABI request schema.");
          }
          const pluginRequest = decode(Buffer.from(request.payload, "base64")) as EvePluginAbiRequest;
          if (pluginRequest.operation !== request.operation) throw new Error("Plugin ABI operation disagrees with CultNet routing.");
          const pluginResponse = executeHeimdallAccessPlugin(pluginRequest);
          return {
            schemaVersion: "cultnet.operation_response.v0",
            messageId: request.messageId,
            serviceId: request.serviceId,
            operation: request.operation,
            status: pluginResponse.status,
            payloadSchema: "gamecult.eve.plugin_abi.response.v1",
            payloadEncoding: "messagepack-base64",
            payload: Buffer.from(encode(pluginResponse)).toString("base64"),
            diagnostics: [],
            sourceRuntimeId: config.daemonId,
          };
        }
        if (request.serviceId !== HEIMDALL_PRIVATE_COMMAND_SERVICE) throw new Error("Unknown Heimdall private command service.");
        if (request.payloadSchema !== HEIMDALL_PRIVATE_ENVELOPE_SCHEMA || request.payloadEncoding !== "messagepack-base64") {
          throw new Error("Heimdall private commands require the typed encrypted MessagePack envelope.");
        }
        const envelope = decode(Buffer.from(request.payload, "base64")) as HeimdallPrivateEnvelope;
        if (!isAppSlug(envelope.appSlug)) throw new Error("Unknown Heimdall app binding.");
        const appSlug = envelope.appSlug as AppSlug;
        const secret = config.appSharedSecrets[appSlug];
        if (!secret) throw new Error("Heimdall app binding has no private command secret.");
        if (envelope.operation !== request.operation) throw new Error("Private envelope operation disagrees with CultNet routing.");
        const expectedContentSchema = request.operation === "heimdall.auth.begin"
          ? "heimdall.auth_begin_command.v1"
          : request.operation === "heimdall.auth.complete"
            ? "heimdall.auth_complete_command.v1"
            : request.operation === "heimdall.auth.refresh"
              ? "heimdall.auth_refresh_command.v1"
              : request.operation === "heimdall.auth.logout"
                ? "heimdall.auth_logout_command.v1"
            : undefined;
        if (!expectedContentSchema || envelope.contentSchema !== expectedContentSchema) {
          throw new Error("Private command content schema does not match its operation.");
        }
        const allowedRuntimeIds = config.appRuntimeIds?.[appSlug] ?? [`yggdrasil-${appSlug}`];
        if (!request.sourceRuntimeId || !allowedRuntimeIds.includes(request.sourceRuntimeId)) {
          throw new Error("Private command caller is not the configured app runtime.");
        }
        const payload = openPrivateEnvelope(envelope, secret, now);
        const fingerprint = createHash("sha256").update(request.payload).digest("hex");
        const resultKey = `${appSlug}:${envelope.idempotencyKey}`;
        const store = getHeimdallRuntimeContext(app).store;
        const persisted = await store.findPrivateCommandReceipt(appSlug, envelope.idempotencyKey);
        if (persisted) {
          if (persisted.requestFingerprint !== fingerprint) throw new Error("Idempotency key was reused with different command content.");
          const cachedEnvelope = decode(Buffer.from(persisted.envelopeBase64, "base64")) as HeimdallPrivateEnvelope;
          return response(request, persisted.status, cachedEnvelope, config.daemonId);
        }
        const pending = inFlight.get(resultKey);
        if (pending) {
          const cached = await pending;
          if (cached.fingerprint !== fingerprint) throw new Error("Idempotency key was reused with different command content.");
          return response(request, cached.status, cached.envelope, config.daemonId);
        }
        if (seenNonces.has(`${appSlug}:${envelope.nonce}`)) throw new Error("Private command nonce was already used.");
        seenNonces.set(`${appSlug}:${envelope.nonce}`, Date.parse(envelope.expiresAt));

        const execution = (async (): Promise<CachedResult> => {
          const output = await executePrivateCommand(app, config, appSlug, request.operation, payload);
          const sealed = sealPrivateEnvelope({
            appSlug,
            operation: request.operation,
            contentSchema: output.payloadSchema,
            idempotencyKey: envelope.idempotencyKey,
            secret,
            payload: output.payload,
          });
          const stored = await store.createPrivateCommandReceipt({
            appSlug,
            idempotencyKey: envelope.idempotencyKey,
            requestFingerprint: fingerprint,
            status: output.status,
            contentSchema: output.payloadSchema,
            envelopeBase64: Buffer.from(encode(sealed)).toString("base64"),
            createdAt: sealed.issuedAt,
            expiresAt: sealed.expiresAt,
          });
          return {
            fingerprint: stored.requestFingerprint,
            status: stored.status,
            envelope: decode(Buffer.from(stored.envelopeBase64, "base64")) as HeimdallPrivateEnvelope,
          };
        })();
        inFlight.set(resultKey, execution);
        let cachedResult: CachedResult;
        try {
          cachedResult = await execution;
        } finally {
          if (inFlight.get(resultKey) === execution) inFlight.delete(resultKey);
        }
        return response(request, cachedResult.status, cachedResult.envelope, config.daemonId);
      } catch (error) {
        return {
          schemaVersion: "cultnet.operation_response.v0",
          messageId: request.messageId,
          serviceId: request.serviceId,
          operation: request.operation,
          status: "denied",
          payloadSchema: "gamecult.cultnet.operation_failure.v1",
          payloadEncoding: "messagepack-base64",
          payload: Buffer.from(encode({ code: "private-command-denied", message: "Heimdall denied the private command." })).toString("base64"),
          diagnostics: [error instanceof Error ? error.message : "Private command failed."],
          sourceRuntimeId: config.daemonId,
        };
      }
    },
  });
}

async function executePrivateCommand(
  app: FastifyInstance,
  config: HeimdallConfig,
  appSlug: AppSlug,
  operation: string,
  payload: Record<string, unknown>,
): Promise<{ status: string; payloadSchema: string; payload: Record<string, unknown> }> {
  if (operation === "heimdall.auth.begin") return await beginAuth(app, config, appSlug, payload);
  if (operation === "heimdall.auth.complete") return await completeAuth(app, appSlug, payload);
  if (operation === "heimdall.auth.refresh") return await refreshAuth(app, appSlug, payload);
  if (operation === "heimdall.auth.logout") return await logoutAuth(app, config, appSlug, payload);
  throw new Error(`Unsupported Heimdall private operation '${operation}'.`);
}

async function logoutAuth(
  app: FastifyInstance,
  config: HeimdallConfig,
  appSlug: AppSlug,
  payload: Record<string, unknown>,
): Promise<{ status: string; payloadSchema: string; payload: Record<string, unknown> }> {
  const refreshToken = String(payload.refreshToken ?? "");
  if (!refreshToken) throw new Error("Auth logout requires the app's encrypted refresh claim.");
  const context = getHeimdallRuntimeContext(app);
  const claim = verifyRefreshToken(refreshToken, appSlug, config, context.keys);
  if (!claim) throw new Error("Auth logout received an invalid or expired refresh claim.");
  const revokedAt = new Date().toISOString();
  const session = await context.store.revokeSession(
    appSlug,
    claim.sid,
    claim.account_id,
    claim.access_revision,
    revokedAt,
  );
  if (!session || session.accessRevision !== claim.access_revision + 1) {
    throw new Error("Auth logout could not revoke the exact session custody claim.");
  }
  await context.store.createAuditEvent({
    accountId: claim.account_id,
    sessionId: claim.sid,
    appSlug,
    eventType: "session_revoked",
    eventPayloadJson: { previousAccessRevision: claim.access_revision, accessRevision: session.accessRevision },
    createdAt: revokedAt,
  });
  return {
    status: "accepted",
    payloadSchema: "heimdall.auth_logout_receipt.v1",
    payload: {
      schema: "heimdall.auth_logout_receipt.v1",
      status: "revoked",
      sessionId: claim.sid,
      accessRevision: session.accessRevision,
      revokedAt,
    },
  };
}

async function refreshAuth(
  app: FastifyInstance,
  appSlug: AppSlug,
  payload: Record<string, unknown>,
): Promise<{ status: string; payloadSchema: string; payload: Record<string, unknown> }> {
  const refreshToken = String(payload.refreshToken ?? "");
  if (!refreshToken) throw new Error("Auth refresh requires the app's encrypted refresh claim.");
  const entitlementPolicy = parseEntitlementPolicy(payload.entitlementPolicy);
  // The plane already authenticated this call as `appSlug` by opening the
  // envelope with that app's shared secret and checking sourceRuntimeId; it
  // gets its AppCaller from the one other constructor that authority owns
  // (app-caller.ts) instead of writing the literal here, and calls the same
  // handler function the HTTP route uses rather than forging the HTTP header
  // back at itself.
  const context = getHeimdallRuntimeContext(app);
  await requireEntitlementPolicyIfProfileDemandsIt(context.store, appSlug, entitlementPolicy, "refresh");
  const result = await refreshAppSession(context, appSlug, callerFromOpenedEnvelope(appSlug), {
    refreshToken,
    ...(entitlementPolicy ? { entitlementPolicy } : {}),
  });
  const refreshedPayload = result.body as Record<string, unknown>;
  if (result.statusCode !== 201) {
    return {
      status: "accepted",
      payloadSchema: "heimdall.auth_refresh_receipt.v1",
      payload: {
        schema: "heimdall.auth_refresh_receipt.v1",
        status: "denied",
        error: String(refreshedPayload.error ?? "refresh_denied"),
      },
    };
  }
  return {
    status: "accepted",
    payloadSchema: "heimdall.auth_refresh_receipt.v1",
    payload: { ...refreshedPayload, schema: "heimdall.auth_refresh_receipt.v1", status: "authenticated" },
  };
}

async function beginAuth(
  app: FastifyInstance,
  config: HeimdallConfig,
  appSlug: AppSlug,
  payload: Record<string, unknown>,
): Promise<{ status: string; payloadSchema: string; payload: Record<string, unknown> }> {
  const provider = String(payload.provider ?? "discord") as Provider;
  const mode = String(payload.mode ?? "sign_in") as OAuthMode;
  const returnTo = String(payload.returnTo ?? "");
  if (!providers.includes(provider) || !oauthModes.includes(mode) || !returnTo) throw new Error("Auth begin payload is incomplete.");
  const entitlementPolicy = parseEntitlementPolicy(payload.entitlementPolicy);
  const store = getHeimdallRuntimeContext(app).store;
  await requireEntitlementPolicyIfProfileDemandsIt(store, appSlug, entitlementPolicy, "authentication");
  const now = new Date();
  const attempt = await store.createAuthAttempt({
    handle: randomUUID(),
    appSlug,
    provider,
    mode,
    returnTo,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.stateTtlSeconds * 1000).toISOString(),
  });
  // Same authority, same non-HTTP entry as refreshAuth above.
  const context = getHeimdallRuntimeContext(app);
  const start = await startOAuthFlow({ config: context.config, keys: context.keys, store: context.store }, provider, callerFromOpenedEnvelope(appSlug), {
    appSlug,
    mode,
    returnTo,
    handoff: { kind: "browser_completion", attemptId: attempt.handle },
    ...(entitlementPolicy ? { entitlementPolicy } : {}),
  });
  const startPayload = start.body as Record<string, unknown>;
  if (start.statusCode !== 201) {
    await context.store.updateAuthAttempt(appSlug, attempt.handle, {
      status: "denied",
      at: new Date().toISOString(),
      denialCode: String(startPayload.error ?? "oauth_start_denied"),
    });
    throw new Error(String(startPayload.detail ?? startPayload.error ?? "OAuth start was denied."));
  }
  const authorizationUrl = String(startPayload.authorizationUrl ?? "");
  const authorizationOrigin = new URL(authorizationUrl).origin;
  return {
    status: "accepted",
    payloadSchema: "heimdall.auth_begin_receipt.v1",
    payload: {
      schema: "heimdall.auth_begin_receipt.v1",
      status: "pending",
      handle: attempt.handle,
      expiresAt: attempt.expiresAt,
      navigation: {
        url: authorizationUrl,
        allowedOrigins: [authorizationOrigin, new URL(config.publicBaseUrl).origin],
      },
    },
  };
}

async function completeAuth(
  app: FastifyInstance,
  appSlug: AppSlug,
  payload: Record<string, unknown>,
): Promise<{ status: string; payloadSchema: string; payload: Record<string, unknown> }> {
  const handle = String(payload.handle ?? "");
  if (!handle) throw new Error("Auth completion requires an opaque attempt handle.");
  const store = getHeimdallRuntimeContext(app).store;
  const attempt = await store.findAuthAttempt(appSlug, handle);
  if (!attempt) throw new Error("Auth attempt is unknown for this app.");
  const now = new Date().toISOString();
  if (attempt.expiresAt <= now && attempt.status !== "completed") {
    await store.updateAuthAttempt(appSlug, handle, { status: "expired", at: now });
    return authCompletion("denied", { handle, error: "expired_attempt" });
  }
  if (attempt.status === "pending") return authCompletion("pending", { handle });
  if (attempt.status !== "completed") {
    return authCompletion("denied", { handle, error: attempt.denialCode ?? `attempt_${attempt.status}` });
  }
  // Consume by the attempt handle directly rather than forging an HTTP
  // self-call into the public redeem route: the plane already authenticated
  // `appSlug`, and the completion code is a secret this process never needs
  // to see, let alone pass back through its own front door.
  const completion = await store.consumeAuthCompletionByAttempt(appSlug, handle, now);
  if (!completion) {
    return authCompletion("denied", { handle, error: "invalid_or_expired_completion" });
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
    createdAt: now,
  });
  await store.updateAuthAttempt(appSlug, handle, { status: "consumed", at: now });
  return authCompletion("authenticated", { handle, ...completion.payloadJson });
}

function authCompletion(status: string, values: Record<string, unknown>) {
  return {
    // CultNet reports whether the private command executed. Authentication state
    // remains inside the typed receipt so callers can decode pending and denied
    // outcomes instead of mistaking them for transport failures.
    status: "accepted",
    payloadSchema: "heimdall.auth_completion_receipt.v1",
    payload: { ...values, schema: "heimdall.auth_completion_receipt.v1", status },
  };
}

function parseEntitlementPolicy(value: unknown): OAuthEntitlementPolicy | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (record.kind === "discord_role_access" && typeof record.guildId === "string" && Array.isArray(record.allowedRoleIds)) {
    const allowedRoleIds = record.allowedRoleIds.filter((item): item is string => typeof item === "string" && Boolean(item));
    return allowedRoleIds.length ? { kind: "discord_role_access", guildId: record.guildId, allowedRoleIds } : undefined;
  }
  if (record.kind === "patreon_membership_access" && typeof record.requiredTierTitle === "string") {
    return { kind: "patreon_membership_access", requiredTierTitle: record.requiredTierTitle };
  }
  return undefined;
}

/**
 * Ghostlight requires its caller-owned Discord role policy on every begin and
 * refresh; that used to be a literal `appSlug === "ghostlight"` branch here.
 * The requirement is now data on the app's profile
 * (AppProfile.requiredEntitlementPolicyKind), so a future app with the same
 * need declares it in its profile instead of adding another branch.
 */
async function requireEntitlementPolicyIfProfileDemandsIt(
  store: HeimdallStore,
  appSlug: AppSlug,
  entitlementPolicy: OAuthEntitlementPolicy | undefined,
  action: "authentication" | "refresh",
): Promise<void> {
  const profile = await resolveAppProfile(store, appSlug);
  const requiredKind = profile?.requiredEntitlementPolicyKind;
  if (requiredKind && entitlementPolicy?.kind !== requiredKind) {
    throw new Error(`${appSlug} ${action} requires its caller-owned ${requiredKind} policy.`);
  }
}

function response(
  request: CultNetOperationRequestMessage,
  status: string,
  envelope: HeimdallPrivateEnvelope,
  runtimeId: string,
): CultNetOperationResponseMessage {
  return {
    schemaVersion: "cultnet.operation_response.v0",
    messageId: request.messageId,
    serviceId: request.serviceId,
    operation: request.operation,
    status,
    payloadSchema: HEIMDALL_PRIVATE_ENVELOPE_SCHEMA,
    payloadEncoding: "messagepack-base64",
    payload: Buffer.from(encode(envelope)).toString("base64"),
    diagnostics: [],
    sourceRuntimeId: runtimeId,
  };
}
