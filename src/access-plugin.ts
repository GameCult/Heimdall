export const HEIMDALL_ACCESS_PLUGIN_ID = "gamecult.heimdall.access";

export interface EvePluginAbiRequest {
  schema: "gamecult.eve.plugin_abi.request.v1";
  pluginId: string;
  operation: string;
  requestId: string;
  input: Record<string, unknown>;
}

export interface EvePluginAbiResponse {
  schema: "gamecult.eve.plugin_abi.response.v1";
  pluginId: string;
  operation: string;
  requestId: string;
  status: "ok" | "invalid" | "unsupported";
  output: Record<string, unknown>;
  diagnostics?: Array<Record<string, unknown>>;
}

const accessStates = new Set(["anonymous", "pending", "denied", "authenticated", "expired", "unavailable"]);

export function buildHeimdallAccessPluginAdvertisement() {
  return {
    schema: "gamecult.eve.plugin_advertisement.v1",
    pluginId: HEIMDALL_ACCESS_PLUGIN_ID,
    ownerService: "asgard.heimdall",
    version: "0.1.0",
    manifestAddress: "cultmesh://gamecult/heimdall/plugins/access/manifest",
    runtime: {
      invocationModel: "executable-sidecar",
      contract: "gamecult.eve.plugin_abi.v1",
      transports: ["cultnet.operation.v0", "in-process-reference"],
      authority: ["renderer-independent", "no-access-grant", "no-provider-state-mutation"],
      sidecar: {
        processKind: "heimdall-daemon-plugin-organ",
        protocol: "cultnet.operation.v0",
        requestSchema: "gamecult.eve.plugin_abi.request.v1",
        responseSchema: "gamecult.eve.plugin_abi.response.v1",
        operations: ["describe", "validate", "project"],
        commandEnvelope: "gamecult.eve.command_invocation.v1",
        receiptSchema: "gamecult.eve.command_result.v1",
        stateAuthority: "Heimdall projects access state; the plugin cannot grant access.",
        endpoint: "rudp://127.0.0.1:4101",
      },
    },
    schemas: [
      "heimdall.access_gate_state.v1",
      "heimdall.auth_attempt.v1",
      "heimdall.auth_begin_receipt.v1",
      "heimdall.auth_completion_receipt.v1",
      "heimdall.auth_navigation_receipt.v1",
      "heimdall.auth_completion_status.v1",
    ],
    componentKinds: ["heimdall.access_gate", "heimdall.identity", "heimdall.access_status"],
    commands: ["heimdall.auth.begin", "heimdall.auth.complete", "app.auth.logout"],
    fixtures: ["anonymous", "pending", "denied", "authenticated", "expired", "unavailable"],
    navigationOrigins: ["https://discord.com", "https://heimdall.gamecult.org"],
  };
}

export function executeHeimdallAccessPlugin(request: EvePluginAbiRequest): EvePluginAbiResponse {
  if (request.schema !== "gamecult.eve.plugin_abi.request.v1" || request.pluginId !== HEIMDALL_ACCESS_PLUGIN_ID) {
    return response(request, "invalid", {}, "Request does not target the Heimdall access plugin.");
  }
  if (request.operation === "describe") {
    return response(request, "ok", {
      pluginId: HEIMDALL_ACCESS_PLUGIN_ID,
      version: "0.1.0",
      operations: ["describe", "validate", "project"],
      componentKinds: ["heimdall.access_gate", "heimdall.identity", "heimdall.access_status"],
      commands: ["heimdall.auth.begin", "heimdall.auth.complete", "app.auth.logout"],
      capabilities: ["auth.gate", "auth.begin", "auth.complete", "auth.logout"],
      authority: ["no-access-grant", "no-provider-state-mutation"],
    });
  }
  const state = record(request.input.state);
  const diagnostic = validateState(state);
  if (request.operation === "validate") {
    return diagnostic ? response(request, "invalid", { valid: false }, diagnostic) : response(request, "ok", { valid: true });
  }
  if (request.operation === "project") {
    if (diagnostic) return response(request, "invalid", {}, diagnostic);
    return response(request, "ok", {
      component: {
        kind: "heimdall.access_gate",
        props: {
          state: state.state,
          title: state.title,
          detail: state.detail,
          displayName: state.displayName ?? "",
        },
      },
    });
  }
  return response(request, "unsupported", {}, `Unsupported operation '${request.operation}'.`);
}

function validateState(state: Record<string, unknown>): string | undefined {
  if (state.schema !== "heimdall.access_gate_state.v1") return "Access projection requires heimdall.access_gate_state.v1.";
  if (typeof state.state !== "string" || !accessStates.has(state.state)) return "Access state is invalid.";
  if (typeof state.title !== "string" || !state.title) return "Access title is required.";
  if (typeof state.detail !== "string") return "Access detail is required.";
  if (typeof state.canBegin !== "boolean" || typeof state.canComplete !== "boolean") return "Access command availability is required.";
  return undefined;
}

function response(
  request: EvePluginAbiRequest,
  status: EvePluginAbiResponse["status"],
  output: Record<string, unknown>,
  diagnostic?: string,
): EvePluginAbiResponse {
  return {
    schema: "gamecult.eve.plugin_abi.response.v1",
    pluginId: HEIMDALL_ACCESS_PLUGIN_ID,
    operation: request.operation,
    requestId: request.requestId,
    status,
    output,
    ...(diagnostic ? { diagnostics: [{ code: status, message: diagnostic }] } : {}),
  };
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
