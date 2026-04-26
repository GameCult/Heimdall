import { type AppSlug, type OAuthHandoffKind, type OAuthMode, type Provider } from "./contracts.js";

interface BrowserHandoffBase {
  handoffKind: OAuthHandoffKind;
  provider: Provider;
  appSlug: AppSlug;
  mode?: OAuthMode;
  returnTo: string;
}

export interface BrowserHandoffSuccess extends BrowserHandoffBase {
  status: "success";
  mode: OAuthMode;
  completionCode?: string;
  attemptId?: string;
}

export interface BrowserHandoffError extends BrowserHandoffBase {
  status: "error";
  error: string;
  errorDescription?: string;
  attemptId?: string;
}

export type BrowserHandoffPayload = BrowserHandoffSuccess | BrowserHandoffError;

function serializeForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function buildBrowserFallbackUrl(payload: BrowserHandoffPayload): string {
  const url = new URL(payload.returnTo);
  const fragment = new URLSearchParams({
    heimdall_status: payload.status,
    heimdall_provider: payload.provider,
    heimdall_handoff_kind: payload.handoffKind,
  });
  fragment.set("heimdall_app_slug", payload.appSlug);

  if ("mode" in payload && payload.mode) {
    fragment.set("heimdall_mode", payload.mode);
  }

  if (payload.attemptId) {
    fragment.set("heimdall_attempt_id", payload.attemptId);
  }

  if (payload.status === "success" && payload.completionCode) {
    fragment.set("heimdall_completion_code", payload.completionCode);
  } else {
    if (payload.status === "error") {
      fragment.set("heimdall_error", payload.error);
      if (payload.errorDescription) {
        fragment.set("heimdall_error_description", payload.errorDescription);
      }
    }
  }

  url.hash = fragment.toString();
  return url.toString();
}

export function renderBrowserHandoffPage(payload: BrowserHandoffPayload): string {
  const targetOrigin = new URL(payload.returnTo).origin;
  const fallbackUrl = buildBrowserFallbackUrl(payload);
  const scriptPayload = serializeForScript({
    source: "heimdall",
    kind: "oauth_result",
    ...payload,
  });
  const scriptOrigin = serializeForScript(targetOrigin);
  const scriptFallbackUrl = serializeForScript(fallbackUrl);
  const scriptTitle = serializeForScript(
    payload.status === "success" ? "Authentication Complete" : "Authentication Failed"
  );
  const scriptBody = serializeForScript(
    payload.status === "success"
      ? payload.handoffKind === "backend_callback"
        ? "The app backend has the auth result already. You can return to the app now."
        : "You can return to the app now."
      : "The authentication flow failed. Return to the app to continue."
  );

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${payload.status === "success" ? "Authentication Complete" : "Authentication Failed"}</title>
    <style>
      :root {
        color-scheme: light dark;
        font-family: ui-sans-serif, system-ui, sans-serif;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: #11161d;
        color: #f4f7fb;
      }
      main {
        width: min(32rem, calc(100vw - 2rem));
        border-radius: 1rem;
        padding: 1.5rem;
        background: rgba(20, 27, 36, 0.96);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.3);
      }
      h1 {
        margin: 0 0 0.75rem;
        font-size: 1.35rem;
      }
      p {
        margin: 0 0 1rem;
        line-height: 1.5;
        color: #d5dce6;
      }
      a {
        display: inline-block;
        margin-top: 0.5rem;
        color: #11161d;
        background: #d8eefe;
        text-decoration: none;
        border-radius: 999px;
        padding: 0.75rem 1rem;
        font-weight: 600;
      }
      small {
        display: block;
        margin-top: 0.9rem;
        color: #9aacbe;
      }
    </style>
  </head>
  <body>
    <main>
      <h1 id="title"></h1>
      <p id="body"></p>
      <a id="return-link" href="${fallbackUrl}">Return to the app</a>
      <small>If this tab does not close on its own, you can close it manually.</small>
    </main>
    <script>
      const payload = ${scriptPayload};
      const targetOrigin = ${scriptOrigin};
      const fallbackUrl = ${scriptFallbackUrl};
      const title = ${scriptTitle};
      const body = ${scriptBody};

      document.getElementById("title").textContent = title;
      document.getElementById("body").textContent = body;
      document.getElementById("return-link").setAttribute("href", fallbackUrl);

      try {
        if (window.opener && !window.opener.closed) {
          window.opener.postMessage(payload, targetOrigin);
        }
      } catch {}

      setTimeout(() => {
        try {
          window.close();
        } catch {}
      }, 50);
    </script>
  </body>
</html>`;
}
