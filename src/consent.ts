import { createHash } from "node:crypto";
import { type AppSlug, type Provider } from "./contracts.js";
import { getAppProfile } from "./app-profiles.js";
import { providerCatalog } from "./providers.js";
import { type StoredConsentReceipt } from "./store/index.js";

/**
 * What Heimdall tells a person before it holds a provider credential for an
 * app, and the page that lists what they agreed to. The wording is built from
 * the facts the code holds (the app, the provider, the scopes sent), never
 * from a promise the code does not keep. Any change to a line changes the
 * digest every later receipt carries, so a reader can tell which wording a
 * person saw.
 */

export interface ConsentAsk {
  appSlug: AppSlug;
  provider: Provider;
  /** The scopes Heimdall will send the provider. */
  scopes: readonly string[];
  /** The origin the person returns to afterwards. */
  returnOrigin: string;
}

export const GRANTS_PATH = "/v1/me/grants";

function appName(slug: AppSlug): string {
  return getAppProfile(slug)?.displayName ?? slug;
}

/** The exact lines shown on the ask, apart from the two buttons. The digest is over these. */
export function consentLines(ask: ConsentAsk): string[] {
  const app = appName(ask.appSlug);
  const provider = providerCatalog[ask.provider].displayName;
  return [
    `${app} asks Heimdall to hold a connection to your ${provider} account.`,
    `Heimdall will ask ${provider} for these permissions: ${ask.scopes.join(", ")}.`,
    `Heimdall keeps an encrypted refresh token and access token for this connection until you take it back or ${provider} ends it.`,
    `${app}'s server can ask Heimdall for a current access token and use it for those permissions. It never receives the refresh token.`,
    `If you say no, nothing is kept.`,
    `You can take this back at any time. Heimdall then deletes its copy of the tokens and stops handing out access tokens. The permission stays with ${provider} until you remove it in your ${provider} settings.`,
    `Afterwards you are returned to ${ask.returnOrigin}.`,
  ];
}

/** The labels on the two buttons. They are wording the person agrees to, so they are part of the text. */
export function consentButtons(ask: ConsentAsk): { go: string; no: string } {
  return { go: `Continue to ${providerCatalog[ask.provider].displayName}`, no: "No, return to the app" };
}

/**
 * Everything the person reads before answering, as one text: the lines and the
 * button labels. It is built once, when the ask is rendered, and that exact
 * text travels with the flow to the receipt; nothing rebuilds it later.
 */
export function consentText(ask: ConsentAsk): string {
  const { go, no } = consentButtons(ask);
  return [...consentLines(ask), go, no].join("\n");
}

export function digestOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function consentDigest(ask: ConsentAsk): string {
  return digestOfText(consentText(ask));
}

export function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const pageStyle = `
      :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #11161d; color: #f4f7fb; }
      main { width: min(38rem, calc(100vw - 2rem)); border-radius: 1rem; padding: 1.5rem; background: rgba(20, 27, 36, 0.96); box-shadow: 0 24px 60px rgba(0, 0, 0, 0.3); }
      h1 { margin: 0 0 0.75rem; font-size: 1.35rem; }
      p, li { line-height: 1.5; color: #d5dce6; }
      ul { padding-left: 1.2rem; }
      code { color: #d8eefe; }
      button { font: inherit; font-weight: 600; border: 0; border-radius: 999px; padding: 0.75rem 1rem; margin: 0.25rem 0.5rem 0.25rem 0; cursor: pointer; }
      button.go { color: #11161d; background: #d8eefe; }
      button.no { color: #f4f7fb; background: #2c3745; }
      section { border-top: 1px solid #2c3745; padding: 0.75rem 0; }
      small { color: #9aacbe; }`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>${pageStyle}
    </style>
  </head>
  <body>
    <main>
${body}
    </main>
  </body>
</html>`;
}

/** The ask. Two POST forms carry the signed state; the page runs no script. */
export function renderConsentPage(ask: ConsentAsk, state: string): string {
  const lines = consentLines(ask);
  const provider = providerCatalog[ask.provider].displayName;
  const [headline, ...rest] = lines;
  const form = (decision: "continue" | "decline", label: string) =>
    `<button class="${decision === "continue" ? "go" : "no"}" type="submit" name="decision" value="${decision}">${escapeHtml(label)}</button>`;
  return page(
    `${appName(ask.appSlug)} wants to connect ${provider}`,
    `      <h1>${escapeHtml(headline!)}</h1>
      <ul>
${rest.map((line) => `        <li>${escapeHtml(line)}</li>`).join("\n")}
      </ul>
      <form method="post" action="/v1/oauth/${ask.provider}/consent">
        <input type="hidden" name="state" value="${escapeHtml(state)}">
        ${form("continue", consentButtons(ask).go)}
        ${form("decline", consentButtons(ask).no)}
      </form>`
  );
}

export interface GrantView {
  consentText: string;
  id: string;
  appSlug: AppSlug;
  provider: Provider;
  scopesAsked: string[];
  scopesGranted: string[];
  grantedAt: string;
  consentPageDigest: string;
  status: "active" | "revoked";
  revokedAt?: string;
  revocationReceiptId?: string;
}

/** Every grant the receipts hold, each live unless a revocation names it. */
export function grantViews(receipts: readonly StoredConsentReceipt[]): GrantView[] {
  const revocations = new Map<string, StoredConsentReceipt & { kind: "revocation" }>();
  for (const receipt of receipts) {
    if (receipt.kind === "revocation") revocations.set(receipt.revokesReceiptId, receipt);
  }
  const views: GrantView[] = [];
  for (const receipt of receipts) {
    if (receipt.kind !== "grant") continue;
    const revocation = revocations.get(receipt.id);
    views.push({
      id: receipt.id,
      appSlug: receipt.appSlug,
      provider: receipt.provider,
      scopesAsked: receipt.scopesAsked,
      scopesGranted: receipt.scopesGranted,
      grantedAt: receipt.createdAt,
      consentPageDigest: receipt.consentPageDigest,
      consentText: receipt.consentText,
      status: revocation ? "revoked" : "active",
      ...(revocation ? { revokedAt: revocation.createdAt, revocationReceiptId: revocation.id } : {}),
    });
  }
  return views;
}

/** The signed-in page: every grant with its receipt, one button each to take it back. */
export function renderGrantsPage(grants: readonly GrantView[], pageToken: string, notice?: string): string {
  const cards = grants.length
    ? grants
        .map((grant) => {
          const provider = providerCatalog[grant.provider].displayName;
          const header = `${escapeHtml(appName(grant.appSlug))} → ${escapeHtml(provider)}`;
          const detail = `granted ${escapeHtml(grant.grantedAt)}; permissions ${escapeHtml(grant.scopesGranted.join(", ") || "none returned")}; receipt <code>${escapeHtml(grant.id)}</code>; wording <code>${escapeHtml(grant.consentPageDigest.slice(0, 12))}</code>`;
          if (grant.status === "revoked") {
            return `      <section><strong>${header}</strong> <small>taken back ${escapeHtml(grant.revokedAt ?? "")}; receipt <code>${escapeHtml(grant.revocationReceiptId ?? "")}</code></small><br><small>${detail}</small></section>`;
          }
          return `      <section><strong>${header}</strong> <small>active</small><br><small>${detail}</small>
        <form method="post" action="${GRANTS_PATH}/${escapeHtml(grant.id)}/revoke">
          <input type="hidden" name="t" value="${escapeHtml(pageToken)}">
          <button class="no" type="submit">Take this back</button>
        </form></section>`;
        })
        .join("\n")
    : `      <p>You have not connected anything through Heimdall.</p>`;
  return page(
    "Your connections",
    `      <h1>Your connections</h1>
${notice ? `      <p><strong>${escapeHtml(notice)}</strong></p>\n` : ""}${cards}
      <p><small>Taking a connection back deletes Heimdall's copy of the tokens. The app's next request for a token is refused. The permission stays with the provider until you remove it in the provider's settings.</small></p>`
  );
}
