import { decode, encode } from "@msgpack/msgpack";
import { invokeCultNetOperation } from "cultnet-ts";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { executeHeimdallAccessPlugin } from "../src/access-plugin.js";
import { type HeimdallConfig } from "../src/config.js";
import { entitlementFacts } from "../src/facts.js";
import { startHeimdallPrivateCommandPlane } from "../src/private-command-plane.js";
import { openPrivateEnvelope, sealPrivateEnvelope, type HeimdallPrivateEnvelope } from "../src/private-command-security.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";

const secret = "ghostlight-private-command-secret";
const resources: Array<{ close(): Promise<unknown> }> = [];

afterEach(async () => {
  await Promise.all(resources.splice(0).reverse().map(resource => resource.close()));
});

describe("Heimdall Eve access plugin", () => {
  it("describes, validates, and projects access state without granting access", () => {
    const description = executeHeimdallAccessPlugin({
      schema: "gamecult.eve.plugin_abi.request.v1",
      pluginId: "gamecult.heimdall.access",
      operation: "describe",
      requestId: "describe-1",
      input: {},
    });
    expect(description.status).toBe("ok");
    expect(description.output.authority).toContain("no-access-grant");

    const projection = executeHeimdallAccessPlugin({
      schema: "gamecult.eve.plugin_abi.request.v1",
      pluginId: "gamecult.heimdall.access",
      operation: "project",
      requestId: "project-1",
      input: {
        state: {
          schema: "heimdall.access_gate_state.v1",
          state: "anonymous",
          title: "Sign in",
          detail: "Discord access is required.",
          canBegin: true,
          canComplete: false,
        },
      },
    });
    expect(projection.status).toBe("ok");
    expect(projection.output.component).toEqual(expect.objectContaining({ kind: "heimdall.access_gate" }));
  });

  it("persists and redeems a private Ghostlight attempt exactly once behind encrypted CultNet envelopes", async () => {
    const config = testConfig();
    const app = await buildApp({
      config,
      oauthRuntimes: { discord: mockDiscordRuntime() },
    });
    resources.push(app);
    const plane = await startHeimdallPrivateCommandPlane(app, config);
    resources.push(plane);

    const pluginDescription = await invokeCultNetOperation(plane.endpoint, {
      schemaVersion: "cultnet.operation_request.v0",
      messageId: "plugin-describe-transport",
      serviceId: "gamecult.heimdall.access",
      operation: "describe",
      payloadSchema: "gamecult.eve.plugin_abi.request.v1",
      payloadEncoding: "messagepack-base64",
      payload: Buffer.from(encode({
        schema: "gamecult.eve.plugin_abi.request.v1",
        pluginId: "gamecult.heimdall.access",
        operation: "describe",
        requestId: "plugin-describe",
        input: {},
      })).toString("base64"),
      sourceRuntimeId: "odin-test",
    }, { runtimeId: "odin-test" });
    expect(pluginDescription.status).toBe("ok");
    expect(decode(Buffer.from(pluginDescription.payload, "base64"))).toMatchObject({
      pluginId: "gamecult.heimdall.access",
      operation: "describe",
      status: "ok",
    });

    const beginEnvelope = sealPrivateEnvelope({
      appSlug: "ghostlight",
      operation: "heimdall.auth.begin",
      contentSchema: "heimdall.auth_begin_command.v1",
      idempotencyKey: "begin-1",
      secret,
      payload: {
        provider: "discord",
        mode: "sign_in",
        returnTo: "https://yggdrasil.gamecult.org/ghostlight/",
        entitlementPolicy: {
          kind: "discord_role_access",
          guildId: "gamecult-guild",
          allowedRoleIds: ["role-ktlst"],
        },
      },
    });
    const beginResponse = await invoke(plane.endpoint, "heimdall.auth.begin", "transport-begin-1", beginEnvelope);
    expect(beginResponse.status).toBe("accepted");
    expect(beginResponse.payloadSchema).toBe("heimdall.private_command_envelope.v1");
    expect(beginResponse.payload).not.toContain("discord.com");
    const beginWire = decodeEnvelope(beginResponse.payload);
    expect(beginWire.contentSchema).toBe("heimdall.auth_begin_receipt.v1");
    const begin = openPrivateEnvelope(beginWire, secret);
    expect(begin.schema).toBe("heimdall.auth_begin_receipt.v1");
    const handle = String(begin.handle);
    const navigation = begin.navigation as { url: string };
    const state = new URL(navigation.url).searchParams.get("state");
    expect(state).toBeTruthy();

    const callback = await app.inject({
      method: "GET",
      url: `/v1/oauth/discord/callback?code=test-code&state=${encodeURIComponent(state ?? "")}`,
    });
    expect(callback.statusCode, callback.body).toBe(201);
    expect(callback.json().completion.code).toBe(handle);

    const completeEnvelope = sealPrivateEnvelope({
      appSlug: "ghostlight",
      operation: "heimdall.auth.complete",
      contentSchema: "heimdall.auth_complete_command.v1",
      idempotencyKey: "complete-1",
      secret,
      payload: { handle },
    });
    const completionResponse = await invoke(plane.endpoint, "heimdall.auth.complete", "transport-complete-1", completeEnvelope);
    expect(completionResponse.status).toBe("accepted");
    expect(completionResponse.payloadSchema).toBe("heimdall.private_command_envelope.v1");
    expect(completionResponse.payload).not.toContain("heimdall_access");
    const completionWire = decodeEnvelope(completionResponse.payload);
    expect(completionWire.contentSchema).toBe("heimdall.auth_completion_receipt.v1");
    const completion = openPrivateEnvelope(completionWire, secret);
    expect(completion.status).toBe("authenticated");
    expect(completion.accessToken).toEqual(expect.any(String));

    const retry = await invoke(plane.endpoint, "heimdall.auth.complete", "transport-complete-retry", completeEnvelope);
    expect(openPrivateEnvelope(decodeEnvelope(retry.payload), secret)).toEqual(completion);

    const wrongRuntime = await invokeCultNetOperation(plane.endpoint, request(
      "heimdall.auth.complete",
      "transport-wrong-runtime",
      completeEnvelope,
      "not-ghostlight",
    ), { runtimeId: "not-ghostlight" });
    expect(wrongRuntime.status).toBe("denied");
  }, 20_000);
});

async function invoke(endpoint: string, operation: string, messageId: string, envelope: HeimdallPrivateEnvelope) {
  return await invokeCultNetOperation(endpoint, request(operation, messageId, envelope, "yggdrasil-ghostlight"), {
    runtimeId: "yggdrasil-ghostlight",
  });
}

function request(operation: string, messageId: string, envelope: HeimdallPrivateEnvelope, sourceRuntimeId: string) {
  return {
    schemaVersion: "cultnet.operation_request.v0" as const,
    messageId,
    serviceId: "heimdall.private.commands",
    operation,
    payloadSchema: "heimdall.private_command_envelope.v1",
    payloadEncoding: "messagepack-base64" as const,
    payload: Buffer.from(encode(envelope)).toString("base64"),
    sourceRuntimeId,
  };
}

function decodeEnvelope(payload: string): HeimdallPrivateEnvelope {
  return decode(Buffer.from(payload, "base64")) as HeimdallPrivateEnvelope;
}

function testConfig(): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    privateCommandHost: "127.0.0.1",
    privateCommandPort: 0,
    workspaceRoot: "F:/Projects/Heimdall",
    dataRoot: "F:/Projects/Heimdall/.heimdall-data",
    cultCachePath: "F:/Projects/Heimdall/.heimdall-data/cultcache/test.cc",
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    daemonId: "yggdrasil-heimdall",
    idunnRudpHealth: undefined,
    idunnHealthContract: "heimdall.cultnet-rudp-provider-health",
    providerHealthIdentityPath: "F:/Projects/Heimdall/.heimdall-data/provider-health-test.cc",
    sessionTtlSeconds: 3600,
    refreshTtlSeconds: 3600,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    appSharedSecrets: { ghostlight: secret },
    appRuntimeIds: { ghostlight: ["yggdrasil-ghostlight"] },
    appBackendCallbacks: {},
    storage: { backend: "memory", applySchemaOnStartup: true },
    providers: {
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
      patreon: {}, github: {}, twitch: {}, youtube: {}, spotify: {},
    },
  };
}

function mockDiscordRuntime(): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "provider-access", tokenType: "Bearer", scope: ["identify", "guilds.members.read"], raw: {} };
    },
    async resolveIdentity() {
      return { provider: "discord", providerUserId: "discord-1", displayName: "Tester", profile: {} };
    },
    async evaluateEntitlements({ callback }) {
      return {
        facts: [entitlementFacts.appAccess],
        snapshots: [{
          accountId: callback.accountId,
          provider: "discord",
          scope: "ghostlight:discord_role_access:gamecult-guild",
          evaluatedAt: new Date().toISOString(),
          isAllowed: true,
          reasonCode: "matched_role",
          rawSummaryJson: { matchedRoles: ["role-ktlst"] },
        }],
      };
    },
  };
}
