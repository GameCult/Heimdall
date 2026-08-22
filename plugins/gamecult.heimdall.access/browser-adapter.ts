const ATTEMPT_KEY = "gamecult.heimdall.access.attempt";

export interface HeimdallAccessResumeTarget {
  complete(handle: string): Promise<void>;
}

export interface HeimdallAccessResumeOptions {
  appSlug: string;
}

export function createHeimdallAccessBrowserAdapter(options: { advertisedOrigins: readonly string[] }) {
  const advertisedOrigins = new Set(options.advertisedOrigins.map(value => new URL(value).origin));
  return {
  pluginId: "gamecult.heimdall.access",
  capabilities: ["auth.gate", "auth.begin", "auth.complete", "auth.logout"],
  componentKinds: ["heimdall.access_gate", "heimdall.identity", "heimdall.access_status"],
  schemas: ["heimdall.access_gate_state.v1"],
  normalizeDocument(_schemaId: string | undefined, value: unknown): unknown {
    return value;
  },
  renderComponent(
    component: { id?: string },
    props: Record<string, unknown>,
  ): HTMLElement {
    const view = document.createElement("section");
    view.className = `heimdall-access heimdall-access-${String(props.state || "unknown")}`;
    if (component.id) view.id = component.id;
    view.setAttribute("role", "status");
    view.setAttribute("aria-live", "polite");
    const title = document.createElement("h2");
    title.textContent = String(props.title || "Access");
    const detail = document.createElement("p");
    detail.textContent = String(props.detail || "");
    view.append(title, detail);
    const displayName = String(props.displayName || "");
    if (displayName) {
      const identity = document.createElement("p");
      identity.className = "heimdall-identity";
      identity.textContent = displayName;
      view.append(identity);
    }
    return view;
  },
  async consumeCommandResult(
    pluginPayload: { schemaId: string; payload: Record<string, unknown> },
  ): Promise<void> {
    if (pluginPayload.schemaId === "heimdall.auth_navigation_receipt.v1") {
      const handle = String(pluginPayload.payload.handle || "");
      const navigation = object(pluginPayload.payload.navigation);
      const url = new URL(String(navigation.url || ""));
      const allowedOrigins = Array.isArray(navigation.allowedOrigins)
        ? navigation.allowedOrigins.filter((value): value is string => typeof value === "string")
        : [];
      if (!handle || url.protocol !== "https:" || !advertisedOrigins.has(url.origin) || !allowedOrigins.includes(url.origin)) {
        throw new Error("Heimdall returned an unsafe authentication navigation receipt.");
      }
      sessionStorage.setItem(ATTEMPT_KEY, handle);
      window.location.assign(url.toString());
      return;
    }
    if (pluginPayload.schemaId === "heimdall.auth_completion_status.v1") {
      const status = String(pluginPayload.payload.status || "");
      if (status === "authenticated" || status === "denied" || status === "expired") {
        sessionStorage.removeItem(ATTEMPT_KEY);
      }
    }
    },
  };
}

export const heimdallAccessBrowserAdapter = createHeimdallAccessBrowserAdapter({
  advertisedOrigins: ["https://discord.com", "https://heimdall.gamecult.org"],
});

export async function resumeHeimdallAccess(
  target: HeimdallAccessResumeTarget,
  options: HeimdallAccessResumeOptions,
): Promise<boolean> {
  const returned = readHeimdallBrowserReturn(window.location.href, options.appSlug);
  const storedHandle = sessionStorage.getItem(ATTEMPT_KEY);
  if (returned) {
    clearHeimdallBrowserReturn();
    if (returned.status === "error") {
      sessionStorage.removeItem(ATTEMPT_KEY);
      throw new Error(returned.message);
    }
    if (storedHandle && storedHandle !== returned.handle) {
      sessionStorage.removeItem(ATTEMPT_KEY);
      throw new Error("Heimdall returned an authentication attempt other than the one this browser started.");
    }
    sessionStorage.setItem(ATTEMPT_KEY, returned.handle);
  }
  const handle = returned?.status === "success" ? returned.handle : storedHandle;
  if (!handle) return false;
  await target.complete(handle);
  return true;
}

export function readHeimdallBrowserReturn(
  href: string,
  appSlug: string,
): { status: "success"; handle: string } | { status: "error"; message: string } | undefined {
  const url = new URL(href);
  const parameters = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  const status = parameters.get("heimdall_status");
  if (!status) return undefined;
  if (parameters.get("heimdall_handoff_kind") !== "browser_completion"
    || parameters.get("heimdall_app_slug") !== appSlug) {
    return { status: "error", message: "Heimdall returned an authentication result for another application or handoff mode." };
  }
  if (status !== "success") {
    return {
      status: "error",
      message: parameters.get("heimdall_error_description")
        || parameters.get("heimdall_error")
        || "Heimdall authentication failed.",
    };
  }
  const attemptId = parameters.get("heimdall_attempt_id") || "";
  const completionCode = parameters.get("heimdall_completion_code") || "";
  if (!attemptId || !completionCode || attemptId !== completionCode) {
    return { status: "error", message: "Heimdall returned a malformed authentication completion witness." };
  }
  return { status: "success", handle: completionCode };
}

function clearHeimdallBrowserReturn(): void {
  history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
}

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
