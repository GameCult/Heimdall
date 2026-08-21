import { createHash, randomUUID } from "node:crypto";
import { decode, encode } from "@msgpack/msgpack";
import {
  startCultNetOperationServer,
  type CultNetOperationRequestMessage,
  type CultNetOperationResponseMessage,
  type CultNetOperationServer,
} from "cultnet-ts";
import { type FastifyInstance } from "fastify";
import { getHeimdallRuntimeContext } from "./app.js";
import { executeHeimdallAccessPlugin, HEIMDALL_ACCESS_PLUGIN_ID, type EvePluginAbiRequest } from "./access-plugin.js";
import { appSlugs, oauthModes, providers, type AppSlug, type OAuthEntitlementPolicy, type OAuthMode, type Provider } from "./contracts.js";
import { type HeimdallConfig } from "./config.js";
import { openPrivateEnvelope, sealPrivateEnvelope, type HeimdallPrivateEnvelope } from "./private-command-security.js";

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
        if (!appSlugs.includes(envelope.appSlug as AppSlug)) throw new Error("Unknown Heimdall app binding.");
        const appSlug = envelope.appSlug as AppSlug;
        const secret = config.appSharedSecrets[appSlug];
        if (!secret) throw new Error("Heimdall app binding has no private command secret.");
        if (envelope.operation !== request.operation) throw new Error("Private envelope operation disagrees with CultNet routing.");
        const expectedContentSchema = request.operation === "heimdall.auth.begin"
          ? "heimdall.auth_begin_command.v1"
          : request.operation === "heimdall.auth.complete"
            ? "heimdall.auth_complete_command.v1"
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
  throw new Error(`Unsupported Heimdall private operation '${operation}'.`);
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
  if (appSlug === "ghostlight" && (!entitlementPolicy || entitlementPolicy.kind !== "discord_role_access")) {
    throw new Error("Ghostlight authentication requires its caller-owned Discord role policy.");
  }
  const now = new Date();
  const attempt = await getHeimdallRuntimeContext(app).store.createAuthAttempt({
    handle: randomUUID(),
    appSlug,
    provider,
    mode,
    returnTo,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.stateTtlSeconds * 1000).toISOString(),
  });
  const start = await app.inject({
    method: "POST",
    url: `/v1/oauth/${provider}/start`,
    headers: { "x-heimdall-app-secret": config.appSharedSecrets[appSlug] ?? "" },
    payload: {
      appSlug,
      mode,
      returnTo,
      handoff: { kind: "browser_completion", attemptId: attempt.handle },
      ...(entitlementPolicy ? { entitlementPolicy } : {}),
    },
  });
  const startPayload = start.json<Record<string, unknown>>();
  if (start.statusCode !== 201) {
    await getHeimdallRuntimeContext(app).store.updateAuthAttempt(appSlug, attempt.handle, {
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
    return authCompletion("denied", { error: "expired_attempt" });
  }
  if (attempt.status === "pending") return authCompletion("pending", { handle });
  if (attempt.status !== "completed") return authCompletion("denied", { error: attempt.denialCode ?? `attempt_${attempt.status}` });
  const redemption = await app.inject({
    method: "POST",
    url: `/v1/apps/${appSlug}/auth-completions/redeem`,
    payload: { completionCode: handle },
  });
  if (redemption.statusCode !== 201) return authCompletion("denied", { error: "invalid_or_expired_completion" });
  return authCompletion("authenticated", redemption.json<Record<string, unknown>>());
}

function authCompletion(status: string, values: Record<string, unknown>) {
  return {
    status: status === "authenticated" ? "accepted" : status,
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
