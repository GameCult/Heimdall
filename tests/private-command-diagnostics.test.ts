// A private command's reply travels partly outside its sealed envelope: the
// status, the failure payload and the diagnostics are plaintext, and the
// calling app logs the diagnostics. Soul pass 4 found a provider's refresh
// token there: a 2xx refresh answer that is not JSON made JSON.parse quote the
// text around the fault, and the plane returned that message as a diagnostic.
// These tests drive the real Discord runtime with only fetch stubbed.
import { decode, encode } from "@msgpack/msgpack";
import { invokeCultNetOperation } from "cultnet-ts";
import { afterEach, expect, it, vi } from "vitest";
import { buildApp } from "../src/app.js";
import { type HeimdallConfig } from "../src/config.js";
import { startHeimdallPrivateCommandPlane } from "../src/private-command-plane.js";
import { openPrivateEnvelope, sealPrivateEnvelope, type HeimdallPrivateEnvelope } from "../src/private-command-security.js";
import { InMemoryStore } from "../src/store/index.js";

const secret = "ghostlight-private-command-secret";
const resources: Array<{ close(): Promise<unknown> }> = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(resources.splice(0).reverse().map((r) => r.close()));
});

function config(): HeimdallConfig {
  return {
    serviceName: "heimdall", host: "127.0.0.1", port: 4100, privateCommandHost: "127.0.0.1", privateCommandPort: 0,
    workspaceRoot: "/tmp", dataRoot: "/tmp/.hd", cultCachePath: "/tmp/.hd/t.cc",
    publicBaseUrl: "https://heimdall.gamecult.org", issuer: "https://heimdall.gamecult.org", daemonId: "yggdrasil-heimdall",
    idunnRudpHealth: undefined, idunnHealthContract: "heimdall.cultnet-rudp-provider-health", providerHealthIdentityPath: "/tmp/.hd/p.cc",
    sessionTtlSeconds: 3600, refreshTtlSeconds: 3600, stateTtlSeconds: 600, completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false, tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    appSharedSecrets: { ghostlight: secret }, appRuntimeIds: { ghostlight: ["yggdrasil-ghostlight"] }, appBackendCallbacks: {},
    storage: { backend: "memory", applySchemaOnStartup: true },
    providers: { discord: { clientId: "discord-client", clientSecret: "discord-secret" }, patreon: {}, github: {}, twitch: {}, youtube: {}, spotify: {} },
  } as HeimdallConfig;
}

async function command(endpoint: unknown, operation: string, contentSchema: string, key: string, payload: Record<string, unknown>) {
  const envelope = sealPrivateEnvelope({ appSlug: "ghostlight", operation, contentSchema, idempotencyKey: key, secret, payload });
  return invokeCultNetOperation(endpoint as never, {
    schemaVersion: "cultnet.operation_request.v0", messageId: `m-${key}`, serviceId: "heimdall.private.commands", operation,
    payloadSchema: "heimdall.private_command_envelope.v1", payloadEncoding: "messagepack-base64",
    payload: Buffer.from(encode(envelope)).toString("base64"), sourceRuntimeId: "yggdrasil-ghostlight",
  } as never, { runtimeId: "yggdrasil-ghostlight" });
}
const open = (reply: { payload: string }) =>
  openPrivateEnvelope(decode(Buffer.from(reply.payload, "base64")) as HeimdallPrivateEnvelope, secret);

/** A signed-in Ghostlight session, then a refresh whose provider answer is `refreshAnswer`. */
async function refreshAgainst(refreshAnswer: () => Response) {
  let refreshing = false;
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith("/oauth2/token")) {
      if (new URLSearchParams(String(init?.body)).get("grant_type") === "refresh_token") {
        refreshing = true;
        return refreshAnswer();
      }
      return new Response(
        JSON.stringify({ access_token: "first-access", refresh_token: "first-refresh", token_type: "Bearer", expires_in: 60, scope: "identify" }),
        { status: 200 }
      );
    }
    if (u.endsWith("/users/@me")) return new Response(JSON.stringify({ id: "u1", username: "u1" }), { status: 200 });
    if (u.includes("/member")) return new Response(JSON.stringify({ roles: ["r"] }), { status: 200 });
    return new Response("{}", { status: 404 });
  });
  const cfg = config();
  const app = await buildApp({ config: cfg, store: new InMemoryStore() });
  resources.push(app);
  const plane = await startHeimdallPrivateCommandPlane(app, cfg);
  resources.push(plane);
  const policy = { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] };
  const begin = open(await command(plane.endpoint, "heimdall.auth.begin", "heimdall.auth_begin_command.v1", "k1",
    { provider: "discord", mode: "sign_in", returnTo: "https://yggdrasil.gamecult.org/ghostlight/", entitlementPolicy: policy }));
  const state = new URL(String((begin.navigation as { url: string }).url)).searchParams.get("state")!;
  const callback = await app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?code=c1&state=${encodeURIComponent(state)}`,
    headers: { accept: "application/json" },
  });
  expect(callback.statusCode, callback.body).toBe(201);
  const done = open(await command(plane.endpoint, "heimdall.auth.complete", "heimdall.auth_complete_command.v1", "k2", { handle: begin.handle }));
  expect(done.status).toBe("authenticated");
  const reply = await command(plane.endpoint, "heimdall.auth.refresh", "heimdall.auth_refresh_command.v1", "k3",
    { refreshToken: done.refreshToken, entitlementPolicy: policy });
  expect(refreshing).toBe(true);
  return reply;
}

/** Every plaintext byte of a reply: the message itself and its decoded failure payload. */
function plaintext(reply: { payload: string }): string {
  return JSON.stringify(reply) + JSON.stringify(decode(Buffer.from(reply.payload, "base64")));
}

it("keeps a provider's malformed 2xx refresh body out of every plaintext part of the reply", async () => {
  const reply = await refreshAgainst(
    () => new Response('{"access_token":"CANARYaccess0123456789","refresh_token":CANARYrefresh0123456789,"token_type":"Bearer"}', { status: 200 })
  );

  expect(reply.status).toBe("denied");
  expect(reply.diagnostics).toEqual(["Heimdall denied the private command (ProviderResponseError, provider_body_not_json)."]);
  expect(plaintext(reply)).not.toContain("CANARY");
});

it("keeps a provider's refusal body out of every plaintext part of the reply", async () => {
  const reply = await refreshAgainst(() => new Response('{"error":"invalid_grant","echo":"CANARYrefused"}', { status: 400 }));

  expect(reply.status).toBe("denied");
  expect(reply.diagnostics).toEqual(["Heimdall denied the private command (ProviderResponseError, provider_status)."]);
  expect(plaintext(reply)).not.toContain("CANARY");
});

it("keeps the completion code out of the audit trail when the plane redeems by attempt", async () => {
  vi.stubGlobal("fetch", async (url: string | URL) => {
    const u = String(url);
    if (u.endsWith("/oauth2/token")) {
      return new Response(
        JSON.stringify({ access_token: "a", refresh_token: "r", token_type: "Bearer", expires_in: 60, scope: "identify" }),
        { status: 200 }
      );
    }
    if (u.endsWith("/users/@me")) return new Response(JSON.stringify({ id: "u1", username: "u1" }), { status: 200 });
    if (u.includes("/member")) return new Response(JSON.stringify({ roles: ["r"] }), { status: 200 });
    return new Response("{}", { status: 404 });
  });
  const cfg = config();
  const store = new InMemoryStore();
  const app = await buildApp({ config: cfg, store });
  resources.push(app);
  const plane = await startHeimdallPrivateCommandPlane(app, cfg);
  resources.push(plane);
  const policy = { kind: "discord_role_access", guildId: "g", allowedRoleIds: ["r"] };
  const begin = open(await command(plane.endpoint, "heimdall.auth.begin", "heimdall.auth_begin_command.v1", "k1",
    { provider: "discord", mode: "sign_in", returnTo: "https://yggdrasil.gamecult.org/ghostlight/", entitlementPolicy: policy }));
  const state = new URL(String((begin.navigation as { url: string }).url)).searchParams.get("state")!;
  const callback = await app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?code=c1&state=${encodeURIComponent(state)}`,
    headers: { accept: "application/json" },
  });
  const code = (callback.json().completion as { code: string }).code;
  const done = open(await command(plane.endpoint, "heimdall.auth.complete", "heimdall.auth_complete_command.v1", "k2", { handle: begin.handle }));
  expect(done.status).toBe("authenticated");

  const events = [...(store as unknown as { auditEvents: Map<string, { eventType: string; eventPayloadJson: unknown }> }).auditEvents.values()];
  expect(events.filter((event) => event.eventType === "auth_completion_redeemed").map((event) => event.eventPayloadJson)).toEqual([
    { provider: "discord", mode: "sign_in" },
  ]);
  expect(JSON.stringify(events)).not.toContain(code);
});
