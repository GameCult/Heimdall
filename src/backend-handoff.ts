import { type IssuedAccessClaimResult } from "./claims.js";
import { type AppSlug, type OAuthConnectionBinding, type OAuthMode, type Provider } from "./contracts.js";
import { type EntitlementEvaluation } from "./oauth.js";

interface AccountSummary {
  id: string;
  displayName?: string;
  primaryEmail?: string;
}

interface BackendHandoffBase {
  source: "heimdall";
  kind: "oauth_result";
  handoffKind: "backend_callback";
  attemptId: string;
  provider: Provider;
  appSlug: AppSlug;
  returnTo: string;
  connection: OAuthConnectionBinding | null;
}

export interface BackendHandoffSuccessPayload extends BackendHandoffBase, IssuedAccessClaimResult {
  status: "success";
  mode: OAuthMode;
  account: AccountSummary;
  entitlements: EntitlementEvaluation;
}

export interface BackendHandoffErrorPayload extends BackendHandoffBase {
  status: "error";
  mode?: OAuthMode;
  error: string;
  errorDescription?: string;
}

export type BackendHandoffPayload = BackendHandoffSuccessPayload | BackendHandoffErrorPayload;

export async function deliverBackendHandoff(callbackUrl: string, payload: BackendHandoffPayload): Promise<void> {
  const response = await fetch(callbackUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `Backend handoff delivery failed (status ${response.status}): ${body || "empty response"}`
    );
  }
}
