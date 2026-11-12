import { createHmac, randomUUID } from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { type AppCaller, isAppCaller, resolveAppCaller } from "./app-caller.js";
import { deliverBackendHandoff, type BackendHandoffPayload } from "./backend-handoff.js";
import {
  appSlugs,
  connectionKinds,
  oauthHandoffKinds,
  oauthModes,
  providers,
  isAppSlug,
  type AppSlug,
  type OAuthHandoff,
  type OAuthEntitlementPolicy,
  type OAuthMode,
  type OAuthConnectionBinding,
  type RedeemAuthCompletionRequest,
  type RefreshSessionRequest,
  type RefreshTokenPayload,
  type OAuthStatePayload,
  type OAuthStartRequest,
  type Provider,
} from "./contracts.js";
import { issueAccessClaim, type IssueAccessClaimInput } from "./claims.js";
import { builtInAppProfiles, getAppProfile, isAllowedReturnOrigin, serializeAppProfile, admitsProviderForMode, callbackMint, isUsableConnectionTarget } from "./app-profiles.js";
import { renderBrowserHandoffPage } from "./browser-handoff.js";
import { consentText, digestOfText, grantViews, GRANTS_PATH, renderConsentPage, renderGrantsPage, type ConsentAsk } from "./consent.js";
import { type HeimdallConfig, loadConfig } from "./config.js";
import { createTokenCustody, type TokenCustody } from "./custody.js";
import { grantFact } from "./facts.js";
import { deriveOidcSecrets } from "./google-oidc.js";
import {
  createOAuthRuntimeRegistry,
  fetchPatreonIdentity,
  summarizePatreonMemberships,
  type OAuthRuntimeRegistry,
} from "./oauth.js";
import { ManagedCredentialRefreshFailed, refreshManagedCredential } from "./managed-credential.js";
import { authorizationScopes, buildAuthorizationUrl, providerCatalog, providerExpectedEnv } from "./providers.js";
import { createRuntimeKeyMaterial, signJwt, verifyJwt } from "./signing.js";
import { createStore, type HeimdallStore } from "./store/index.js";
import {
  type CreateAccountInput,
  type StoredCapabilityGrant,
  type StoredLinkedIdentity,
  type UpsertLinkedIdentityInput,
} from "./store/types.js";

export interface BuildAppOptions {
  config?: HeimdallConfig;
  store?: HeimdallStore;
  oauthRuntimes?: Partial<OAuthRuntimeRegistry>;
  tokenCustody?: TokenCustody;
}

export interface HeimdallRuntimeContext {
  config: HeimdallConfig;
  keys: ReturnType<typeof createRuntimeKeyMaterial>;
  store: HeimdallStore;
  oauthRuntimes: OAuthRuntimeRegistry;
  tokenCustody: TokenCustody;
}

export function getHeimdallRuntimeContext(app: FastifyInstance): HeimdallRuntimeContext {
  return (app as FastifyInstance & { heimdallContext: HeimdallRuntimeContext }).heimdallContext;
}

function buildDiscovery(config: HeimdallConfig) {
  return {
    issuer: config.issuer,
    jwksUri: `${config.publicBaseUrl}/.well-known/jwks.json`,
    configurationUri: `${config.publicBaseUrl}/.well-known/heimdall-configuration`,
    oauthStartEndpoint: `${config.publicBaseUrl}/v1/oauth/{provider}/start`,
    oauthCallbackEndpoint: `${config.publicBaseUrl}/v1/oauth/{provider}/callback`,
    supportedProviders: providers.map((provider) => ({
      key: provider,
      displayName: providerCatalog[provider].displayName,
      roles: providerCatalog[provider].roles,
    })),
    apps: Object.values(builtInAppProfiles).map(serializeAppProfile),
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
  initiatorAccountId: string | undefined;
  handoff: OAuthHandoff;
  entitlementPolicy: OAuthEntitlementPolicy | undefined;
  requestedScopes: string[] | undefined;
  stepUp: boolean | undefined;
  keys: ReturnType<typeof createRuntimeKeyMaterial>;
}): { token: string; jti: string; expiresAt: string } {
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
    initiator_account_id: options.initiatorAccountId ?? null,
    handoff: options.handoff,
    entitlement_policy: options.entitlementPolicy ?? null,
    requested_scopes: options.requestedScopes ?? null,
    step_up: options.stepUp ? true : null,
  };
  const token = signJwt(payload as unknown as Record<string, unknown>, options.keys);

  return {
    token,
    jti: payload.jti,
    expiresAt: new Date(expiresAtEpoch * 1000).toISOString(),
  };
}

function parseOAuthStatePayload(payload: Record<string, unknown>): OAuthStatePayload | null {
  const handoff = payload.handoff;
  const handoffIsValid =
    handoff === null ||
    handoff === undefined ||
    (typeof handoff === "object" &&
      handoff !== null &&
      (((handoff as Record<string, unknown>).kind === "browser_completion" &&
          ((handoff as Record<string, unknown>).attemptId === undefined ||
            typeof (handoff as Record<string, unknown>).attemptId === "string")) ||
        ((handoff as Record<string, unknown>).kind === "backend_callback" &&
          typeof (handoff as Record<string, unknown>).attemptId === "string" &&
          typeof (handoff as Record<string, unknown>).callbackUrl === "string")));
  const entitlementPolicy = payload.entitlement_policy;
  const entitlementPolicyIsValid =
    entitlementPolicy === null ||
    entitlementPolicy === undefined ||
    ((typeof entitlementPolicy === "object" &&
      entitlementPolicy !== null &&
      (entitlementPolicy as Record<string, unknown>).kind === "discord_role_access" &&
      typeof (entitlementPolicy as Record<string, unknown>).guildId === "string" &&
      Array.isArray((entitlementPolicy as Record<string, unknown>).allowedRoleIds) &&
      ((entitlementPolicy as Record<string, unknown>).allowedRoleIds as unknown[]).every(
        (roleId) => typeof roleId === "string"
      )) ||
      (typeof entitlementPolicy === "object" &&
        entitlementPolicy !== null &&
        (entitlementPolicy as Record<string, unknown>).kind === "patreon_membership_access" &&
        typeof (entitlementPolicy as Record<string, unknown>).requiredTierTitle === "string"));
  const requestedScopes = payload.requested_scopes;
  const requestedScopesAreValid =
    requestedScopes === null ||
    requestedScopes === undefined ||
    (Array.isArray(requestedScopes) && requestedScopes.every((scope) => typeof scope === "string"));
  if (
    payload.typ !== "heimdall_oauth_state" ||
    typeof payload.provider !== "string" ||
    !providers.includes(payload.provider as Provider) ||
    typeof payload.app_slug !== "string" ||
    !isAppSlug(payload.app_slug) ||
    typeof payload.mode !== "string" ||
    !oauthModes.includes(payload.mode as OAuthMode) ||
    typeof payload.return_to !== "string" ||
    typeof payload.iss !== "string" ||
    typeof payload.sub !== "string" ||
    typeof payload.aud !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.nbf !== "number" ||
    typeof payload.exp !== "number" ||
    !handoffIsValid ||
    !entitlementPolicyIsValid ||
    !(payload.initiator_account_id === undefined || payload.initiator_account_id === null || typeof payload.initiator_account_id === "string") ||
    !requestedScopesAreValid ||
    !(payload.step_up === undefined || payload.step_up === null || payload.step_up === true)
  ) {
    return null;
  }

  const normalizedPayload = payload as unknown as OAuthStatePayload;
  if (!normalizedPayload.handoff) {
    normalizedPayload.handoff = { kind: "browser_completion" };
  }
  if (!normalizedPayload.initiator_account_id) {
    normalizedPayload.initiator_account_id = null;
  }
  if (!normalizedPayload.entitlement_policy) {
    normalizedPayload.entitlement_policy = null;
  }
  if (!normalizedPayload.requested_scopes) {
    normalizedPayload.requested_scopes = null;
  }
  if (!normalizedPayload.step_up) {
    normalizedPayload.step_up = null;
  }

  return normalizedPayload;
}

type OAuthStateVerdict =
  | { ok: true; payload: OAuthStatePayload }
  | { ok: false; error: "invalid_state" | "state_provider_mismatch" | "state_expired" };

/**
 * The one place a signed OAuth state becomes trusted: signature, shape, issuer,
 * audience and provider, and the time window with the same 30 s skew refresh
 * tokens use. Every route that turns a state into navigation or a completion
 * runs this first; the refusals are fixed codes and never echo the token.
 */
function verifyOAuthState(
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>,
  token: string,
  provider: Provider
): OAuthStateVerdict {
  const verification = verifyJwt(token, keys.publicKey);
  if (!verification.valid) {
    return { ok: false, error: "invalid_state" };
  }

  const payload = parseOAuthStatePayload(verification.payload);
  if (!payload || payload.iss !== config.issuer) {
    return { ok: false, error: "invalid_state" };
  }
  if (payload.aud !== payload.provider || payload.provider !== provider) {
    return { ok: false, error: "state_provider_mismatch" };
  }

  const now = nowEpochSeconds();
  if (payload.nbf > now + 30 || payload.exp <= now - 30) {
    return { ok: false, error: "state_expired" };
  }

  return { ok: true, payload };
}

const oauthBindingType = "heimdall_oauth_binding";

function oauthBindingCookieName(jti: string): string {
  return `__Host-heimdall-oauth-${jti}`;
}

/** The signed claim that this browser launched this state: it is the cookie's value, and needs no store read to check. */
function signOAuthBinding(
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>,
  state: OAuthStatePayload,
  shownText?: string
): string {
  return signJwt(
    {
      typ: oauthBindingType,
      iss: config.issuer,
      jti: state.jti,
      iat: nowEpochSeconds(),
      exp: state.exp,
      // The wording the person agreed to, carried from the ask to the receipt.
      ...(shownText === undefined ? {} : { ct: deflateRawSync(shownText).toString("base64url") }),
    },
    keys
  );
}

const consentAskType = "heimdall_consent_ask";

/** The most wording a cookie may carry, before and after compression. The ask refuses what exceeds it; the readers never inflate past it. */
const maxConsentTextBytes = 16 * 1024;
/** Browsers drop a cookie above 4096 bytes; the ask refuses one it could not keep. */
const maxConsentCookieChars = 3800;
/** What an app may request: more is not a scope list a person can read. */
const maxRequestedScopes = 32;
const maxRequestedScopeChars = 512;

function consentAskCookieName(jti: string): string {
  return `__Host-heimdall-ask-${jti}`;
}

/**
 * The ask's own cookie. It proves a browser was shown the ask and carries the
 * exact text shown; only Continue and No accept it. It is not the launch
 * binding: that is set when Continue claims the launch, so that merely opening
 * the launch URL never makes a browser the state's owner.
 */
function signConsentAsk(config: HeimdallConfig, keys: ReturnType<typeof createRuntimeKeyMaterial>, state: OAuthStatePayload, shownText: string): string {
  return signJwt(
    { typ: consentAskType, iss: config.issuer, jti: state.jti, iat: nowEpochSeconds(), exp: state.exp, ct: deflateRawSync(shownText).toString("base64url") },
    keys
  );
}

/** The text a held cookie of the given type carries, or null when the cookie is absent, foreign, expired or carries none. */
function cookieConsentText(
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>,
  token: string | undefined,
  type: string,
  state: OAuthStatePayload
): string | null {
  if (!token) return null;
  const verification = verifyJwt(token, keys.publicKey);
  if (!verification.valid) return null;
  const { typ, iss, jti, exp, ct } = verification.payload;
  if (typ !== type || iss !== config.issuer || jti !== state.jti || typeof exp !== "number" || exp <= nowEpochSeconds() || typeof ct !== "string") {
    return null;
  }
  try {
    return inflateRawSync(Buffer.from(ct, "base64url"), { maxOutputLength: maxConsentTextBytes }).toString("utf8");
  } catch {
    return null;
  }
}

function setConsentAskCookie(reply: FastifyReply, state: OAuthStatePayload, value: string, maxAgeSeconds: number): void {
  reply.setCookie(consentAskCookieName(state.jti), value, {
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    maxAge: Math.max(0, maxAgeSeconds),
  });
}

function oauthBindingHolds(
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>,
  token: string | undefined,
  state: OAuthStatePayload
): boolean {
  if (!token) {
    return false;
  }
  const verification = verifyJwt(token, keys.publicKey);
  if (!verification.valid) {
    return false;
  }
  const { typ, iss, jti, exp } = verification.payload;
  return typ === oauthBindingType && iss === config.issuer && jti === state.jti && typeof exp === "number" && exp > nowEpochSeconds();
}

function setOAuthBindingCookie(reply: FastifyReply, state: OAuthStatePayload, value: string, maxAgeSeconds: number): void {
  reply.setCookie(oauthBindingCookieName(state.jti), value, {
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    maxAge: Math.max(0, maxAgeSeconds),
  });
}

function oauthCallbackUrl(config: HeimdallConfig, provider: Provider): string {
  return `${config.publicBaseUrl}/v1/oauth/${provider}/callback`;
}

function buildGrantFacts(grants: StoredCapabilityGrant[]): string[] {
  return grants.map((grant) => grantFact(grant.capability));
}

function parseRefreshTokenPayload(payload: Record<string, unknown>): RefreshTokenPayload | null {
  if (
    payload.typ !== "heimdall_refresh" ||
    typeof payload.iss !== "string" ||
    typeof payload.aud !== "string" ||
    !isAppSlug(payload.aud) ||
    typeof payload.sub !== "string" ||
    typeof payload.sid !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.nbf !== "number" ||
    typeof payload.exp !== "number" ||
    typeof payload.account_id !== "string" ||
    typeof payload.access_revision !== "number" ||
    !payload.app ||
    typeof payload.app !== "object" ||
    (payload.app as Record<string, unknown>).slug !== payload.aud ||
    typeof (payload.app as Record<string, unknown>).profile_version !== "string"
  ) {
    return null;
  }

  return payload as unknown as RefreshTokenPayload;
}

export function verifyRefreshToken(
  token: string,
  appSlug: AppSlug,
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>
): RefreshTokenPayload | null {
  const verification = verifyJwt(token, keys.publicKey);
  if (!verification.valid) {
    return null;
  }

  const payload = parseRefreshTokenPayload(verification.payload);
  if (!payload || payload.iss !== config.issuer || payload.aud !== appSlug || payload.app.slug !== appSlug) {
    return null;
  }

  const now = nowEpochSeconds();
  if (payload.nbf > now + 30 || payload.exp <= now - 30) {
    return null;
  }

  return payload;
}

/**
 * A provider's `error` and `error_description` as Heimdall relays them. They
 * arrive as query parameters anyone can write, so only the characters RFC 6749
 * (4.1.2.1) allows in them survive, and each is cut to a bound. The browser
 * page escapes what is left for its own contexts.
 */
function relayedProviderText(value: string | undefined, bound: number): string | undefined {
  const printable = value?.replace(/[^\x20-\x21\x23-\x5b\x5d-\x7e]/g, "").slice(0, bound);
  return printable ? printable : undefined;
}

/** A link callback the signed state's initiator does not license. Its message is static and safe to relay. */
export class LinkRefusal extends Error {
  constructor(
    readonly code: "link_initiator_missing" | "link_initiator_mismatch" | "link_initiator_unknown" | "identity_not_linked",
    message: string
  ) {
    super(message);
    this.name = "LinkRefusal";
  }
}

export function errorIdentity(error: unknown): { errorClass: string; errorCode: string | null } {
  const code = (error as { code?: unknown } | null)?.code;
  return {
    errorClass: error instanceof Error && /^[A-Za-z]{1,64}$/.test(error.name) ? error.name : "Error",
    errorCode: typeof code === "string" && /^[A-Za-z0-9_]{1,64}$/.test(code) ? code : null,
  };
}

function prefersHtml(acceptHeader: string | undefined): boolean {
  if (!acceptHeader) {
    return false;
  }

  return acceptHeader.includes("text/html") || acceptHeader.includes("application/xhtml+xml");
}

/**
 * `browser_completion.attemptId` is never accepted from a request body. It
 * exists only to correlate a completion with the attempt the private command
 * plane's `beginAuth` created server-side (see `startOAuthFlow`'s
 * `trustedBrowserAttemptId` parameter) — a handle a public caller could name
 * here would let it complete someone else's pending attempt (R21.1). A public
 * `browser_completion` caller has no attempt to correlate: it gets the
 * completion code directly in the callback response or handoff page.
 */
function normalizeOAuthHandoff(value: OAuthStartRequest["handoff"]): OAuthHandoff {
  if (!value) {
    return { kind: "browser_completion" };
  }

  if (value.kind === "browser_completion") {
    return { kind: "browser_completion" };
  }

  if (
    value.kind === "backend_callback" &&
    typeof value.attemptId === "string" &&
    value.attemptId.trim() &&
    typeof value.callbackUrl === "string" &&
    value.callbackUrl.trim()
  ) {
    return {
      kind: "backend_callback",
      attemptId: value.attemptId.trim(),
      callbackUrl: value.callbackUrl.trim(),
    };
  }

  throw new Error("Invalid OAuth handoff definition.");
}

function normalizeEntitlementPolicy(value: OAuthStartRequest["entitlementPolicy"]): OAuthEntitlementPolicy | undefined {
  if (!value) {
    return undefined;
  }

  if (
    value.kind === "discord_role_access" &&
    typeof value.guildId === "string" &&
    value.guildId.trim() &&
    Array.isArray(value.allowedRoleIds)
  ) {
    const allowedRoleIds = value.allowedRoleIds.map((roleId) => roleId.trim()).filter(Boolean);
    if (allowedRoleIds.length) {
      return {
        kind: "discord_role_access",
        guildId: value.guildId.trim(),
        allowedRoleIds,
      };
    }
  }

  if (
    value.kind === "patreon_membership_access" &&
    typeof value.requiredTierTitle === "string" &&
    value.requiredTierTitle.trim()
  ) {
    return {
      kind: "patreon_membership_access",
      requiredTierTitle: value.requiredTierTitle.trim(),
    };
  }

  throw new Error("Invalid entitlement policy definition.");
}

function normalizeEntitlementPolicies(value: RefreshSessionRequest["entitlementPolicies"]): OAuthEntitlementPolicy[] {
  if (!value) {
    return [];
  }

  return value.map((entry) => {
    const policy = normalizeEntitlementPolicy(entry);
    if (!policy) {
      throw new Error("Invalid entitlement policy definition.");
    }
    return policy;
  });
}

function entitlementPolicyProvider(policy: OAuthEntitlementPolicy): Provider {
  return policy.kind === "discord_role_access" ? "discord" : "patreon";
}

function signBifrostPatronSupportPayload(secret: string, body: string): string {
  const signature = createHmac("sha256", secret).update(body).digest("hex");
  return `sha256=${signature}`;
}

function centsToDecimalString(cents: number): string {
  return (cents / 100).toFixed(2);
}

function storedIdentityToResolvedIdentity(identity: StoredLinkedIdentity) {
  const resolved = {
    provider: identity.provider,
    providerUserId: identity.providerUserId,
    profile: identity.profileJson,
  };
  if (identity.username !== undefined) {
    Object.assign(resolved, { username: identity.username });
  }
  if (identity.displayName !== undefined) {
    Object.assign(resolved, { displayName: identity.displayName });
  }
  if (identity.primaryEmail !== undefined) {
    Object.assign(resolved, { primaryEmail: identity.primaryEmail });
  }
  return resolved;
}

async function evaluateStoredEntitlements(options: {
  config: HeimdallConfig;
  store: HeimdallStore;
  tokenCustody: TokenCustody;
  oauthRuntimes: OAuthRuntimeRegistry;
  appSlug: AppSlug;
  accountId: string;
  entitlementPolicies: OAuthEntitlementPolicy[];
  /** A provider the caller has already evaluated with fresh tokens. */
  skipProvider?: Provider;
}): Promise<string[]> {
  const profile = getAppProfile(options.appSlug);
  if (!profile) {
    throw new Error(`Unknown app '${options.appSlug}'.`);
  }
  const linkedIdentities = await options.store.listStoredLinkedIdentitiesForAccount(options.accountId);
  const facts: string[] = [];

  for (const storedIdentity of linkedIdentities) {
    if (!profile.entitlementSources.includes(storedIdentity.provider) || storedIdentity.provider === options.skipProvider) {
      continue;
    }

    const refreshed = await refreshManagedCredential(options, storedIdentity);
    const linkedIdentity = refreshed.identity;
    if (refreshed.kind === "revoked" || !linkedIdentity.accessTokenEncrypted) {
      continue;
    }

    const runtime = options.oauthRuntimes[linkedIdentity.provider];
    const entitlementPolicy =
      options.entitlementPolicies.find((policy) => entitlementPolicyProvider(policy) === linkedIdentity.provider) ?? null;
    const tokenSet = {
      accessToken: options.tokenCustody.decrypt(linkedIdentity.accessTokenEncrypted),
      tokenType: "Bearer",
      scope: linkedIdentity.scopes,
      raw: {},
    };
    if (linkedIdentity.tokenExpiresAt !== undefined) {
      Object.assign(tokenSet, { expiresAt: linkedIdentity.tokenExpiresAt });
    }
    const evaluation = await runtime.evaluateEntitlements({
      config: options.config,
      callback: {
        appSlug: options.appSlug,
        accountId: options.accountId,
        connection: null,
        entitlementPolicy,
      },
      identity: storedIdentityToResolvedIdentity(linkedIdentity),
      tokenSet,
    });
    for (const snapshot of evaluation.snapshots) {
      await options.store.upsertEntitlementSnapshot(snapshot);
    }
    facts.push(...evaluation.facts);
  }

  return [...new Set(facts)];
}

function acceptsBackendCallback(config: HeimdallConfig, appSlug: AppSlug, handoff: OAuthHandoff): boolean {
  if (handoff.kind !== "backend_callback") {
    return false;
  }

  return (config.appBackendCallbacks[appSlug] ?? []).includes(handoff.callbackUrl);
}

async function maybeDeliverBackendHandoff(handoff: OAuthHandoff, payload: BackendHandoffPayload): Promise<void> {
  if (handoff.kind !== "backend_callback") {
    return;
  }

  await deliverBackendHandoff(handoff.callbackUrl, payload);
}

export interface HandlerResult {
  statusCode: number;
  body: unknown;
}

/**
 * OAuth start, extracted so the HTTP route and the private command plane's
 * `beginAuth` reach the same authority through the same function instead of
 * the plane forging an HTTP self-call with a header only it can set.
 */
export async function startOAuthFlow(
  ctx: Pick<HeimdallRuntimeContext, "config" | "keys" | "store">,
  provider: Provider,
  caller: AppCaller | null,
  input: OAuthStartRequest,
  options?: {
    /**
     * The attempt handle to bind into the state token's `browser_completion`
     * handoff. Set only by `beginAuth` (private-command-plane.ts), which
     * mints the handle itself via `store.createAuthAttempt` before calling
     * here — it is a TypeScript function argument, never a value parsed out
     * of `input`/the request body, so a public HTTP caller has no way to
     * populate it (R21.1). `normalizeOAuthHandoff` already strips any
     * body-supplied `attemptId` for this reason; this is the only path by
     * which one reaches the signed state token.
     */
    trustedBrowserAttemptId?: string;
    /**
     * The account an explicit link binds to. Like `trustedBrowserAttemptId`
     * it is a function argument, never a value parsed out of the request:
     * the HTTP route sets it only from a verified Heimdall access token for
     * this app (`resolveLinkAccount`), so a caller cannot name an account.
     */
    linkAccountId?: string;
  }
): Promise<HandlerResult> {
  const { config, keys } = ctx;
  const profile = getAppProfile(input.appSlug);
  if (!profile) {
    return { statusCode: 404, body: { error: "unknown_app", detail: "No app is registered under that slug." } };
  }

  if (!admitsProviderForMode(profile, provider, input.mode)) {
    return {
      statusCode: 400,
      body: { error: "provider_not_supported_for_app", provider, mode: input.mode, appSlug: profile.slug },
    };
  }

  // A connection target is app-backend authority: it rides only on connect
  // starts that carry the app's own secret (gated below), and never on a
  // sign_in start, which is open to any browser.
  if (input.mode === "sign_in" && input.connection !== undefined) {
    return {
      statusCode: 400,
      body: { error: "connection_not_allowed_in_sign_in", detail: "sign_in start must not carry a connection target." },
    };
  }

  if (input.stepUp && input.mode !== "sign_in") {
    return { statusCode: 400, body: { error: "step_up_only_in_sign_in", detail: "stepUp applies to sign_in starts only." } };
  }

  const descriptor = providerCatalog[provider];
  // A provider that never mints an account attaches an identity only through
  // a bound link: the user's own access token, since the app's word does not
  // name this person to Google. A link start without a verified Heimdall session would end
  // in a refusal at the callback, so it is refused before the redirect.
  // `sign_in` stays open: it signs in an identity already linked, and the
  // callback refuses one that is not.
  if (descriptor.firstLogin === "requires_link" && input.mode === "link" && !options?.linkAccountId) {
    return {
      statusCode: 401,
      body: {
        error: "link_session_required",
        detail: `Linking ${descriptor.displayName} needs a Heimdall access token for ${profile.slug}: send it as a Bearer token.`,
      },
    };
  }

  // Link mode binds an identity to an existing account, so the account must
  // be named by someone Heimdall can believe: the authenticated app backend.
  // The name rides in the signed state and the callback holds the provider's
  // identity to it. No other mode carries an initiator.
  if (input.mode === "link") {
    if (options?.linkAccountId) {
      // The user's own access token for this app names the account.
      if (input.initiatingAccountId !== undefined && input.initiatingAccountId !== options.linkAccountId) {
        return { statusCode: 400, body: { error: "link_initiator_conflict", detail: "initiatingAccountId differs from the bearer's account." } };
      }
    } else {
      if (!isAppCaller(caller) || caller.appSlug !== profile.slug) {
        return { statusCode: 401, body: { error: "app_auth_required" } };
      }
      if (!input.initiatingAccountId) {
        return { statusCode: 400, body: { error: "link_initiator_required", detail: "link mode needs initiatingAccountId." } };
      }
      if (!(await ctx.store.findAccountById(input.initiatingAccountId))) {
        return { statusCode: 400, body: { error: "link_initiator_unknown", detail: "initiatingAccountId names no account." } };
      }
    }
  } else if (input.initiatingAccountId !== undefined) {
    return { statusCode: 400, body: { error: "initiator_only_in_link_mode" } };
  }

  // A step-up is app-backend authority, like a connection target: it is
  // asked for by the authenticated app, never by a browser, and only on
  // sign_in. A provider with no re-authentication parameter is refused here,
  // at start, so no step-up ever reaches the person without its step.
  if (input.stepUp) {
    if (!isAppCaller(caller) || caller.appSlug !== profile.slug) {
      return { statusCode: 401, body: { error: "app_auth_required" } };
    }
    if (!providerCatalog[provider].stepUpAuthorizationParams) {
      return { statusCode: 400, body: { error: "step_up_not_supported", provider, detail: `${providerCatalog[provider].displayName} has no re-authentication parameter.` } };
    }
  }

  if (
    input.requestedScopes !== undefined &&
    (input.requestedScopes.length > maxRequestedScopes || input.requestedScopes.some((scope) => scope.length > maxRequestedScopeChars))
  ) {
    return {
      statusCode: 400,
      body: { error: "requested_scopes_too_large", detail: `At most ${maxRequestedScopes} scopes of ${maxRequestedScopeChars} characters each.` },
    };
  }

  if (!isAllowedReturnOrigin(profile, input.returnTo)) {
    return {
      statusCode: 400,
      body: { error: "return_to_not_allowed", detail: `returnTo must land on an origin ${profile.slug} owns.` },
    };
  }

  let handoff: OAuthHandoff;
  try {
    handoff = normalizeOAuthHandoff(input.handoff);
  } catch (error) {
    return {
      statusCode: 400,
      body: {
        error: "invalid_handoff",
        detail: error instanceof Error ? error.message : "Invalid OAuth handoff definition.",
      },
    };
  }
  let entitlementPolicy: OAuthEntitlementPolicy | undefined;
  try {
    entitlementPolicy = normalizeEntitlementPolicy(input.entitlementPolicy);
  } catch (error) {
    return {
      statusCode: 400,
      body: {
        error: "invalid_entitlement_policy",
        detail: error instanceof Error ? error.message : "Invalid entitlement policy definition.",
      },
    };
  }
  if (handoff.kind === "backend_callback" && !acceptsBackendCallback(config, profile.slug, handoff)) {
    return {
      statusCode: 400,
      body: {
        error: "untrusted_backend_callback",
        detail: "Backend callback handoffs are only accepted for configured app callback URLs.",
      },
    };
  }
  if (options?.trustedBrowserAttemptId && handoff.kind === "browser_completion") {
    handoff = { kind: "browser_completion", attemptId: options.trustedBrowserAttemptId };
  }
  if ((entitlementPolicy || profile.startRequiresAppCaller || (input.mode === "connect" && input.connection !== undefined)) && (!isAppCaller(caller) || caller.appSlug !== profile.slug)) {
    return { statusCode: 401, body: { error: "app_auth_required" } };
  }

  // After the app-secret gate, so a caller without the secret learns nothing about what a target must look like.
  if (input.connection !== undefined && !isUsableConnectionTarget(input.connection.targetId)) {
    return {
      statusCode: 400,
      body: { error: "invalid_connection_target", detail: "connection.targetId must name a target." },
    };
  }

  if (callbackMint(profile, provider, input.mode, input.connection) === "refused") {
    return {
      statusCode: 400,
      body: {
        error: "creator_connection_required",
        detail: `${provider} on ${profile.slug} is a managed creator connection: connect needs connection.kind creator and a targetId.`,
      },
    };
  }

  const providerConfig = config.providers[provider];
  if (!providerConfig.clientId) {
    return {
      statusCode: 503,
      body: { error: "provider_not_configured", provider, expectedEnv: providerExpectedEnv(provider) },
    };
  }

  const state = buildOAuthStateToken({
    config,
    provider,
    appSlug: profile.slug,
    mode: input.mode,
    returnTo: input.returnTo,
    connection: input.connection,
    initiatorAccountId: options?.linkAccountId ?? input.initiatingAccountId,
    handoff,
    entitlementPolicy,
    requestedScopes: input.requestedScopes,
    stepUp: input.stepUp,
    keys,
  });
  return {
    statusCode: 201,
    body: {
      provider,
      appSlug: profile.slug,
      mode: input.mode,
      callbackUrl: oauthCallbackUrl(config, provider),
      authorizationUrl: `${config.publicBaseUrl}/v1/oauth/${provider}/launch?state=${encodeURIComponent(state.token)}`,
      handoff,
      stateExpiresAt: state.expiresAt,
    },
  };
}

/**
 * The account a link start binds to: the one a live Heimdall access token for
 * this app names. The token must verify under Heimdall's own key, be an access
 * token for `appSlug`, be inside its validity window, and belong to a session
 * the store still holds for that account at that revision. A bearer that fails
 * any of these binds nothing: a link is explicit or it does not happen.
 */
async function resolveLinkAccount(
  ctx: Pick<HeimdallRuntimeContext, "config" | "keys" | "store">,
  appSlug: AppSlug,
  authorization: string | undefined
): Promise<string | null> {
  const token = /^Bearer\s+(\S+)$/i.exec(authorization ?? "")?.[1];
  if (!token) return null;
  const verification = verifyJwt(token, ctx.keys.publicKey);
  if (!verification.valid) return null;
  const claims = verification.payload;
  const now = nowEpochSeconds();
  if (
    claims.typ !== "heimdall_access" ||
    claims.iss !== ctx.config.issuer ||
    claims.aud !== appSlug ||
    typeof claims.account_id !== "string" ||
    typeof claims.sid !== "string" ||
    typeof claims.access_revision !== "number" ||
    typeof claims.exp !== "number" ||
    claims.exp <= now ||
    (typeof claims.nbf === "number" && claims.nbf > now)
  ) {
    return null;
  }
  const session = await ctx.store.findSession(appSlug, claims.sid);
  if (
    !session ||
    session.accountId !== claims.account_id ||
    session.accessRevision !== claims.access_revision ||
    Date.parse(session.expiresAt) <= Date.now()
  ) {
    return null;
  }
  return claims.account_id;
}

/** The account a Heimdall access token for any app names, when the token and its session are live. */
async function resolveAccessAccount(
  ctx: Pick<HeimdallRuntimeContext, "config" | "keys" | "store">,
  authorization: string | undefined
): Promise<string | null> {
  const token = /^Bearer\s+(\S+)$/i.exec(authorization ?? "")?.[1];
  if (!token) return null;
  const verification = verifyJwt(token, ctx.keys.publicKey);
  if (!verification.valid) return null;
  const audience = verification.payload.aud;
  return isAppSlug(audience) ? resolveLinkAccount(ctx, audience, authorization) : null;
}

const grantsPageTokenType = "heimdall_grants_page";
const grantsPageTokenTtlSeconds = 600;

/** A short, purpose-bound proof of a signed-in account, so the grants page can be opened and its forms posted by a browser that holds no session. */
function signGrantsPageToken(
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>,
  accountId: string,
  exp: number = nowEpochSeconds() + grantsPageTokenTtlSeconds
): string {
  return signJwt({ typ: grantsPageTokenType, iss: config.issuer, account_id: accountId, iat: nowEpochSeconds(), exp }, keys);
}

/** The account and expiry a page token proves. A page's own forms are signed to this same expiry, so a link is never renewed by being used. */
function grantsPageTokenAccount(
  config: HeimdallConfig,
  keys: ReturnType<typeof createRuntimeKeyMaterial>,
  token: unknown
): { accountId: string; exp: number } | null {
  if (typeof token !== "string") return null;
  const verification = verifyJwt(token, keys.publicKey);
  if (!verification.valid) return null;
  const { typ, iss, account_id: accountId, exp } = verification.payload;
  return typ === grantsPageTokenType && iss === config.issuer && typeof accountId === "string" && typeof exp === "number" && exp > nowEpochSeconds()
    ? { accountId, exp }
    : null;
}

function consentAskFor(state: OAuthStatePayload): ConsentAsk {
  return {
    appSlug: state.app_slug,
    provider: state.provider,
    scopes: authorizationScopes(state.provider, state.requested_scopes ?? undefined),
    returnOrigin: new URL(state.return_to).origin,
  };
}

/**
 * Session refresh, extracted for the same reason as startOAuthFlow: the HTTP
 * route and the plane's `refreshAuth` (which owns Ghostlight identity) call
 * this directly with an envelope-derived AppCaller instead of the plane
 * forging an HTTP self-call.
 */
export async function refreshAppSession(
  ctx: HeimdallRuntimeContext,
  appSlug: AppSlug,
  caller: AppCaller | null,
  input: RefreshSessionRequest
): Promise<HandlerResult> {
  const { config, keys, store, tokenCustody, oauthRuntimes } = ctx;
  let entitlementPolicies: OAuthEntitlementPolicy[];
  try {
    entitlementPolicies = normalizeEntitlementPolicies(input.entitlementPolicies);
    const legacyPolicy = normalizeEntitlementPolicy(input.entitlementPolicy);
    if (legacyPolicy) {
      entitlementPolicies.push(legacyPolicy);
    }
  } catch (error) {
    return {
      statusCode: 400,
      body: {
        error: "invalid_entitlement_policy",
        detail: error instanceof Error ? error.message : "Invalid entitlement policy definition.",
      },
    };
  }
  if (entitlementPolicies.length > 0 && (!isAppCaller(caller) || caller.appSlug !== appSlug)) {
    return { statusCode: 401, body: { error: "app_auth_required" } };
  }

  const refreshClaim = verifyRefreshToken(input.refreshToken, appSlug, config, keys);
  if (!refreshClaim) {
    return { statusCode: 401, body: { error: "invalid_or_expired_refresh_token" } };
  }

  const nowIso = new Date().toISOString();
  const persistedSession = await store.findSession(appSlug, refreshClaim.sid);
  if (
    !persistedSession ||
    persistedSession.accountId !== refreshClaim.account_id ||
    persistedSession.accessRevision !== refreshClaim.access_revision ||
    Date.parse(persistedSession.expiresAt) <= Date.parse(nowIso)
  ) {
    return { statusCode: 401, body: { error: "revoked_or_stale_refresh_token" } };
  }
  const account = await store.findAccountById(refreshClaim.account_id);
  const linkedIdentities = await store.listLinkedIdentitiesForAccount(refreshClaim.account_id);
  const grants = await store.listActiveGrants(refreshClaim.account_id, appSlug, nowIso);
  const entitlementFactList = await evaluateStoredEntitlements({
    config,
    store,
    tokenCustody,
    oauthRuntimes,
    appSlug,
    accountId: refreshClaim.account_id,
    entitlementPolicies,
  });
  const issueInput: IssueAccessClaimInput = {
    appSlug,
    accountId: refreshClaim.account_id,
    sessionId: refreshClaim.sid,
    accessRevision: refreshClaim.access_revision,
    linkedIdentities,
    facts: [...entitlementFactList, ...buildGrantFacts(grants)],
  };
  if (account?.displayName !== undefined) {
    issueInput.displayName = account.displayName;
  }

  const issued = await issueAccessClaim({
    config,
    keys,
    store,
    input: issueInput,
  });

  await store.createAuditEvent({
    accountId: refreshClaim.account_id,
    sessionId: refreshClaim.sid,
    appSlug,
    eventType: "session_refreshed",
    eventPayloadJson: {
      grantedFacts: issued.claimSet.facts,
      sharedCapabilities: issued.sharedCapabilities,
    },
    createdAt: nowIso,
  });

  return { statusCode: 201, body: issued };
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
  // Fastify's default handlers answer with the error's message, and messages
  // carry input: pg and Node name the database host or the database (which a
  // misbound URL fills with part of a secret), the default not-found answer
  // quotes the path, and any error thrown with a 4xx status says whatever its
  // thrower wrote. So every framework answer here is built from fixed text,
  // the error code and the route's own schema, never from the message.
  app.setErrorHandler((error: FastifyError, request, reply) => {
    const status = error.statusCode !== undefined && error.statusCode >= 400 && error.statusCode < 600 ? error.statusCode : 500;
    const code = typeof error.code === "string" ? error.code : "error";
    reply.code(status);
    if (status >= 500) {
      console.error(`Heimdall ${request.method} ${request.routeOptions.url ?? "(no route)"} failed (${code}).`);
      return { error: "internal_error" };
    }
    if (error.validation) {
      // Ajv's messages and schema paths come from the route's schema, not the request.
      const failures = error.validation.map((failure) => `${failure.schemaPath} ${failure.message ?? failure.keyword}`);
      return { error: "invalid_request", detail: `${error.validationContext ?? "request"}: ${failures.join("; ")}` };
    }
    return { error: "invalid_request", code };
  });
  app.setNotFoundHandler((_request, reply) => {
    reply.code(404);
    return { error: "not_found" };
  });
  app.decorate("heimdallContext", { config, keys, store, oauthRuntimes, tokenCustody });
  app.addHook("onClose", async () => {
    await store.close();
  });

  await app.register(cors, {
    origin: true,
    credentials: true,
  });
  await app.register(cookie);
  // The consent and grants pages are plain HTML forms.
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_request, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });

  app.get("/healthz", async () => ({
    ok: true,
    service: config.serviceName,
    issuer: config.issuer,
    storageBackend: config.storage.backend,
    cultCachePath: config.cultCachePath,
    idunnDaemon: config.daemonId,
    idunnHealthContract: config.idunnHealthContract,
    idunnRudpHealth: config.idunnRudpHealth ?? null,
    signingKeySource: keys.source,
    tokenCustodySource: tokenCustody.source,
    now: new Date().toISOString(),
  }));

  app.get("/.well-known/jwks.json", async () => ({
    keys: [keys.publicJwk],
  }));

  app.get("/.well-known/heimdall-configuration", async () => buildDiscovery(config));

  app.get("/v1/apps", async () => ({
    apps: Object.values(builtInAppProfiles).map(serializeAppProfile),
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
            appSlug: { type: "string" },
          },
        },
      },
    },
    async (request, reply) => {
      const profile = getAppProfile(request.params.appSlug);
      if (!profile) {
        reply.code(404);
        return { error: "unknown_app", detail: "No app is registered under that slug." };
      }
      return serializeAppProfile(profile);
    }
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
            initiatingAccountId: { type: "string", minLength: 1 },
            stepUp: { type: "boolean" },
            handoff: {
              type: "object",
              required: ["kind"],
              additionalProperties: false,
              properties: {
                kind: { type: "string", enum: [...oauthHandoffKinds] },
                attemptId: { type: "string", minLength: 1 },
                callbackUrl: { type: "string", format: "uri" },
              },
            },
            entitlementPolicy: {
              anyOf: [
                {
                  type: "object",
                  required: ["kind", "guildId", "allowedRoleIds"],
                  additionalProperties: false,
                  properties: {
                    kind: { type: "string", const: "discord_role_access" },
                    guildId: { type: "string", minLength: 1 },
                    allowedRoleIds: {
                      type: "array",
                      minItems: 1,
                      items: { type: "string", minLength: 1 },
                      uniqueItems: true,
                    },
                  },
                },
                {
                  type: "object",
                  required: ["kind", "requiredTierTitle"],
                  additionalProperties: false,
                  properties: {
                    kind: { type: "string", const: "patreon_membership_access" },
                    requiredTierTitle: { type: "string", minLength: 1 },
                  },
                },
              ],
            },
          },
        },
      },
    },
    async (request, reply) => {
      const caller = resolveAppCaller(config, request.body.appSlug, request.headers);
      let linkAccountId: string | undefined;
      if (request.body.mode === "link") {
        const bound = await resolveLinkAccount({ config, keys, store }, request.body.appSlug, request.headers.authorization);
        if (bound === null && request.headers.authorization !== undefined) {
          reply.code(401);
          return { error: "invalid_link_session", detail: "The bearer is not a live Heimdall access token for this app." };
        }
        linkAccountId = bound ?? undefined;
      }
      const result = await startOAuthFlow({ config, keys, store }, request.params.provider, caller, request.body, {
        ...(linkAccountId !== undefined ? { linkAccountId } : {}),
      });
      reply.code(result.statusCode);
      return result.body;
    }
  );

  /**
   * A refusal of a verified state. A browser (Accept: text/html) gets the
   * handoff page linking back to the state's return_to, so the person is not
   * left on a bare JSON body; the origin is re-checked against the app's
   * allowlist here rather than trusting the signed value. Anything else gets
   * the fixed JSON code.
   */
  const refuseVerifiedState = (
    request: FastifyRequest,
    reply: FastifyReply,
    state: OAuthStatePayload,
    error: "state_not_bound" | "state_already_launched" | "state_already_used" | "consent_text_missing"
  ) => {
    reply.code(400);
    const profile = getAppProfile(state.app_slug);
    if (prefersHtml(request.headers.accept) && profile && isAllowedReturnOrigin(profile, state.return_to)) {
      reply.type("text/html; charset=utf-8");
      return reply.send(
        renderBrowserHandoffPage({
          handoffKind: (state.handoff ?? { kind: "browser_completion" }).kind,
          status: "error",
          provider: state.provider,
          appSlug: state.app_slug,
          mode: state.mode,
          returnTo: state.return_to,
          error,
        })
      );
    }
    return { error };
  };

  const denyAttempt = async (state: OAuthStatePayload, denialCode: string): Promise<void> => {
    const handoff = state.handoff ?? { kind: "browser_completion" };
    if (handoff.kind !== "browser_completion" || !handoff.attemptId) return;
    await store.updateAuthAttempt(state.app_slug, handoff.attemptId, {
      status: "denied",
      at: new Date().toISOString(),
      denialCode,
    });
  };

  /**
   * The person said no, at Heimdall's ask (`viewer`) or at the provider
   * (`provider`, a returned access_denied). It is its own result, never a
   * provider_error: the app and the audit log can tell a refusal from a fault.
   * Nothing is stored beyond an audit row that names no one.
   */
  const refuseConsent = async (request: FastifyRequest, reply: FastifyReply, state: OAuthStatePayload, by: "viewer" | "provider") => {
    const handoff = state.handoff ?? { kind: "browser_completion" };
    await denyAttempt(state, "consent_refused");
    await store.createAuditEvent({
      appSlug: state.app_slug,
      eventType: "consent_refused",
      eventPayloadJson: { provider: state.provider, mode: state.mode, by },
      createdAt: new Date().toISOString(),
    });
    if (handoff.kind === "backend_callback") {
      await maybeDeliverBackendHandoff(handoff, {
        source: "heimdall",
        kind: "oauth_result",
        handoffKind: "backend_callback",
        attemptId: handoff.attemptId,
        status: "error",
        provider: state.provider,
        appSlug: state.app_slug,
        mode: state.mode,
        returnTo: state.return_to,
        connection: state.connection,
        error: "consent_refused",
        by,
      });
    }
    if (prefersHtml(request.headers.accept)) {
      reply.type("text/html; charset=utf-8");
      return reply.send(
        renderBrowserHandoffPage({
          handoffKind: handoff.kind,
          status: "error",
          provider: state.provider,
          appSlug: state.app_slug,
          mode: state.mode,
          returnTo: state.return_to,
          ...(handoff.attemptId ? { attemptId: handoff.attemptId } : {}),
          error: "consent_refused",
          by,
        })
      );
    }
    reply.code(400);
    return { error: "consent_refused", by, provider: state.provider, returnTo: state.return_to };
  };

  const providerNotConfigured = (reply: FastifyReply, state: OAuthStatePayload) => {
    reply.code(503);
    return { error: "provider_not_configured", provider: state.provider, expectedEnv: providerExpectedEnv(state.provider) };
  };

  /** Claim the launch use, bind the browser, and send it to the provider. */
  const beginProviderRedirect = async (request: FastifyRequest, reply: FastifyReply, state: OAuthStatePayload, rawState: string, shownText?: string) => {
    const clientId = config.providers[state.provider].clientId;
    if (!clientId) {
      return providerNotConfigured(reply, state);
    }
    const first = await store.claimOAuthStateUse({
      jti: state.jti,
      phase: "launch",
      appSlug: state.app_slug,
      usedAt: new Date().toISOString(),
      expiresAt: new Date(state.exp * 1000).toISOString(),
    });
    if (!first) {
      return refuseVerifiedState(request, reply, state, "state_already_launched");
    }

    const oidc = providerCatalog[state.provider].oidc ? deriveOidcSecrets(state.jti, keys.privateKey) : undefined;
    setOAuthBindingCookie(reply, state, signOAuthBinding(config, keys, state, shownText), state.exp - nowEpochSeconds());
    reply.header("Cache-Control", "no-store");
    reply.header("Referrer-Policy", "no-referrer");
    return reply.redirect(
      buildAuthorizationUrl({
        provider: state.provider,
        clientId,
        redirectUri: oauthCallbackUrl(config, state.provider),
        state: rawState,
        requestedScopes: state.requested_scopes ?? undefined,
        ...(state.step_up ? { stepUp: true } : {}),
        ...(oidc ? { oidc: { nonce: oidc.nonce, codeChallenge: oidc.codeChallenge } } : {}),
      }),
      302
    );
  };

  app.get<{
    Params: { provider: Provider };
    Querystring: { state: string };
  }>(
    "/v1/oauth/:provider/launch",
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
          required: ["state"],
          additionalProperties: false,
          properties: {
            state: { type: "string", minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const verified = verifyOAuthState(config, keys, request.query.state, request.params.provider);
      if (!verified.ok) {
        reply.code(400);
        return { error: verified.error };
      }
      const state = verified.payload;
      const askProfile = getAppProfile(state.app_slug);
      if (askProfile && callbackMint(askProfile, state.provider, state.mode, state.connection) === "custody_only") {
        if (!config.providers[state.provider].clientId) {
          return providerNotConfigured(reply, state);
        }
        // Heimdall is about to hold a credential for the app: ask first. Viewing
        // the ask claims nothing and binds nothing; only Continue spends the
        // launch use and sets the launch binding. The ask's own cookie rides on
        // the page so that the form's answer can only come from the browser
        // that was shown it, and carries the text it was shown.
        const ask = consentAskFor(state);
        const shown = consentText(ask);
        const askCookie = signConsentAsk(config, keys, state, shown);
        // An ask the cookies cannot carry is refused, not shown: the person
        // could press Continue and nothing would bind.
        if (Buffer.byteLength(shown, "utf8") > maxConsentTextBytes || askCookie.length > maxConsentCookieChars) {
          reply.code(400);
          return { error: "consent_ask_too_large" };
        }
        setConsentAskCookie(reply, state, askCookie, state.exp - nowEpochSeconds());
        reply.header("Cache-Control", "no-store");
        reply.header("Referrer-Policy", "no-referrer");
        reply.header("X-Frame-Options", "DENY");
        reply.header(
          "Content-Security-Policy",
          `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' ${new URL(providerCatalog[state.provider].authorizationEndpoint).origin}`
        );
        reply.type("text/html; charset=utf-8");
        return reply.send(renderConsentPage(ask, request.query.state));
      }
      return beginProviderRedirect(request, reply, state, request.query.state);
    }
  );

  app.post<{
    Params: { provider: Provider };
    Body: { state: string; decision: "continue" | "decline" };
  }>(
    "/v1/oauth/:provider/consent",
    {
      schema: {
        params: {
          type: "object",
          required: ["provider"],
          additionalProperties: false,
          properties: { provider: { type: "string", enum: [...providers] } },
        },
        body: {
          type: "object",
          required: ["state", "decision"],
          additionalProperties: false,
          properties: {
            state: { type: "string", minLength: 1 },
            decision: { type: "string", enum: ["continue", "decline"] },
          },
        },
      },
    },
    async (request, reply) => {
      const verified = verifyOAuthState(config, keys, request.body.state, request.params.provider);
      if (!verified.ok) {
        reply.code(400);
        return { error: verified.error };
      }
      const state = verified.payload;
      const profile = getAppProfile(state.app_slug);
      if (!profile || callbackMint(profile, state.provider, state.mode, state.connection) !== "custody_only") {
        reply.code(400);
        return { error: "consent_not_required" };
      }
      // Either answer must come from the browser the ask was shown to.
      const shownText = cookieConsentText(config, keys, request.cookies[consentAskCookieName(state.jti)], consentAskType, state);
      if (shownText === null) {
        return refuseVerifiedState(request, reply, state, "state_not_bound");
      }
      setConsentAskCookie(reply, state, "", 0);
      if (request.body.decision === "continue") {
        return beginProviderRedirect(request, reply, state, request.body.state, shownText);
      }
      // A decline spends both uses of the state: it can neither launch nor complete afterwards.
      const usedAt = new Date().toISOString();
      const expiresAt = new Date(state.exp * 1000).toISOString();
      if (!(await store.claimOAuthStateUse({ jti: state.jti, phase: "launch", appSlug: state.app_slug, usedAt, expiresAt }))) {
        return refuseVerifiedState(request, reply, state, "state_already_launched");
      }
      await store.claimOAuthStateUse({ jti: state.jti, phase: "callback", appSlug: state.app_slug, usedAt, expiresAt });
      setOAuthBindingCookie(reply, state, "", 0);
      return refuseConsent(request, reply, state, "viewer");
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

      const verified = verifyOAuthState(config, keys, request.query.state, request.params.provider);
      if (!verified.ok) {
        reply.code(400);
        return { error: verified.error };
      }
      const statePayload = verified.payload;
      const handoff = statePayload.handoff ?? { kind: "browser_completion" };
      const denyBrowserAttempt = (denialCode: string): Promise<void> => denyAttempt(statePayload, denialCode);
      // The cookie is checked before the claim: a stranger without it must not be
      // able to burn the state that the browser that launched it still needs.
      // The attempt is denied, though: a launcher whose cookie lapsed can never
      // complete this state, and its page polls an attempt that would otherwise
      // sit pending until it expires.
      if (!oauthBindingHolds(config, keys, request.cookies[oauthBindingCookieName(statePayload.jti)], statePayload)) {
        await denyBrowserAttempt("state_not_bound");
        return refuseVerifiedState(request, reply, statePayload, "state_not_bound");
      }
      // A custody flow carries the wording its person was shown in the launch
      // binding. A binding without it did not pass through the ask (a launch
      // from before it existed): refuse here, before the state is spent and
      // before any code is exchanged, so nothing is kept and nothing is burned.
      const shownText = cookieConsentText(config, keys, request.cookies[oauthBindingCookieName(statePayload.jti)], oauthBindingType, statePayload);
      const callbackProfile = getAppProfile(statePayload.app_slug);
      const mint = callbackProfile ? callbackMint(callbackProfile, request.params.provider, statePayload.mode, statePayload.connection) : "refused";
      if (mint === "custody_only" && shownText === null) {
        await denyBrowserAttempt("consent_text_missing");
        return refuseVerifiedState(request, reply, statePayload, "consent_text_missing");
      }
      setOAuthBindingCookie(reply, statePayload, "", 0);
      const firstCallback = await store.claimOAuthStateUse({
        jti: statePayload.jti,
        phase: "callback",
        appSlug: statePayload.app_slug,
        usedAt: new Date().toISOString(),
        expiresAt: new Date(statePayload.exp * 1000).toISOString(),
      });
      if (!firstCallback) {
        return refuseVerifiedState(request, reply, statePayload, "state_already_used");
      }

      if (request.query.error === "access_denied") {
        return refuseConsent(request, reply, statePayload, "provider");
      }
      if (request.query.error) {
        const providerError = relayedProviderText(request.query.error, 64);
        const providerErrorDescription = relayedProviderText(request.query.error_description, 256);
        const relayedDescription = providerErrorDescription ?? providerError;
        const relayedDescriptionField = relayedDescription ? { errorDescription: relayedDescription } : {};
        await denyBrowserAttempt("provider_error");
        if (handoff.kind === "backend_callback") {
          await maybeDeliverBackendHandoff(handoff, {
            source: "heimdall",
            kind: "oauth_result",
            handoffKind: "backend_callback",
            attemptId: handoff.attemptId,
            status: "error",
            provider: request.params.provider,
            appSlug: statePayload.app_slug,
            mode: statePayload.mode,
            returnTo: statePayload.return_to,
            connection: statePayload.connection,
            error: "provider_error",
            ...relayedDescriptionField,
          });
        }

        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              handoffKind: handoff.kind,
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              ...(handoff.kind === "backend_callback" ? { attemptId: handoff.attemptId } : {}),
              error: "provider_error",
              ...relayedDescriptionField,
            })
          );
        }

        reply.code(400);
        return {
          error: "provider_error",
          provider: request.params.provider,
          providerError,
          providerErrorDescription,
          returnTo: statePayload.return_to,
        };
      }

      if (!request.query.code) {
        await denyBrowserAttempt("missing_code");
        if (handoff.kind === "backend_callback") {
          await maybeDeliverBackendHandoff(handoff, {
            source: "heimdall",
            kind: "oauth_result",
            handoffKind: "backend_callback",
            attemptId: handoff.attemptId,
            status: "error",
            provider: request.params.provider,
            appSlug: statePayload.app_slug,
            mode: statePayload.mode,
            returnTo: statePayload.return_to,
            connection: statePayload.connection,
            error: "missing_code",
          });
        }

        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              handoffKind: handoff.kind,
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              ...(handoff.kind === "backend_callback" ? { attemptId: handoff.attemptId } : {}),
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
        if (mint === "refused") {
          throw new Error("The signed state names a mode the provider has no role for in this app.");
        }
        const callbackDescriptor = providerCatalog[request.params.provider];
        const oidc = callbackDescriptor.oidc ? deriveOidcSecrets(statePayload.jti, keys.privateKey) : undefined;
        const tokenSet = await runtime.exchangeAuthorizationCode({
          config,
          code: request.query.code,
          redirectUri: callbackUrl,
          ...(oidc ? { codeVerifier: oidc.codeVerifier } : {}),
        });
        const identity = await runtime.resolveIdentity({
          config,
          accessToken: tokenSet.accessToken,
          tokenSet,
          ...(oidc ? { oidcNonce: oidc.nonce } : {}),
        });
        const nowIso = new Date().toISOString();
        let account = await store.findAccountByLinkedIdentity(identity.provider, identity.providerUserId);
        // One person, one account. A link attaches the provider identity to the
        // account the signed state names, and to no other: an identity another
        // account holds is a refusal, never a quiet sign-in as that account or a
        // move. A provider that never mints an account refuses an identity no
        // account holds.
        const boundAccountId = statePayload.mode === "link" ? statePayload.initiator_account_id : null;
        if (statePayload.mode === "link") {
          if (!boundAccountId) {
            throw new LinkRefusal("link_initiator_missing", "The signed link state names no initiating account.");
          }
          if (account && account.id !== boundAccountId) {
            throw new LinkRefusal("link_initiator_mismatch", "This identity belongs to a different account than the one that started the link.");
          }
          if (!account) {
            account = await store.findAccountById(boundAccountId);
            if (!account) {
              throw new LinkRefusal("link_initiator_unknown", "The initiating account no longer exists.");
            }
          }
        } else if (!account && callbackDescriptor.firstLogin === "requires_link") {
          throw new LinkRefusal("identity_not_linked", "No account holds this identity; sign in another way and link it first.");
        }

        const buildLinkedIdentityInput = (accountId: string): UpsertLinkedIdentityInput => {
        const linkedIdentityInput: UpsertLinkedIdentityInput = {
          accountId,
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
        return linkedIdentityInput;
        };

        // A link is two-phase. The callback cannot tie itself to the browser
        // that began the link (start is a server-to-server POST), so whoever
        // completes the Google login here may be someone the initiator sent
        // the URL to. Nothing is written to the account: the verified identity
        // waits as a pending link, and only a confirm bearing the access token
        // of the account that began the link attaches it.
        if (boundAccountId && callbackDescriptor.firstLogin === "requires_link") {
          const pendingLink = await store.createPendingLink({
            appSlug: statePayload.app_slug,
            accountId: boundAccountId,
            provider: identity.provider,
            providerUserId: identity.providerUserId,
            identity: buildLinkedIdentityInput(boundAccountId),
            returnTo: statePayload.return_to,
            createdAt: nowIso,
            expiresAt: new Date(Date.now() + config.completionTtlSeconds * 1000).toISOString(),
          });
          await store.createAuditEvent({
            accountId: boundAccountId,
            appSlug: statePayload.app_slug,
            eventType: "link_pending",
            // Never the pending link's id: it is the confirm secret.
            eventPayloadJson: { provider: identity.provider, expiresAt: pendingLink.expiresAt },
            createdAt: nowIso,
          });
          const pendingBody = {
            status: "link_pending" as const,
            provider: request.params.provider,
            mode: statePayload.mode,
            appSlug: statePayload.app_slug,
            returnTo: statePayload.return_to,
            pendingLinkId: pendingLink.id,
            expiresAt: pendingLink.expiresAt,
            confirmEndpoint: `${config.publicBaseUrl}/v1/apps/${statePayload.app_slug}/links/confirm`,
          };
          if (handoff.kind === "backend_callback") {
            await maybeDeliverBackendHandoff(handoff, {
              source: "heimdall",
              kind: "oauth_result",
              handoffKind: "backend_callback",
              attemptId: handoff.attemptId,
              connection: statePayload.connection,
              ...pendingBody,
            });
          }
          if (prefersHtml(request.headers.accept)) {
            reply.type("text/html; charset=utf-8");
            return reply.send(
              renderBrowserHandoffPage({
                handoffKind: handoff.kind,
                status: "success",
                provider: request.params.provider,
                appSlug: statePayload.app_slug,
                mode: statePayload.mode,
                returnTo: statePayload.return_to,
                pendingLinkId: pendingLink.id,
                ...(handoff.attemptId ? { attemptId: handoff.attemptId } : {}),
              })
            );
          }
          reply.code(201);
          return pendingBody;
        }

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
          // A link adds an identity; it does not rewrite the account's profile.
          if (displayName !== undefined && statePayload.mode !== "link") {
            accountUpdates.displayName = displayName;
          }
          if (identity.primaryEmail !== undefined && statePayload.mode !== "link") {
            accountUpdates.primaryEmail = identity.primaryEmail;
          }
          await store.touchAccount(account.id, nowIso, accountUpdates);
        }

        await store.upsertLinkedIdentity(buildLinkedIdentityInput(account.id));

        // Heimdall now holds a credential the person was asked about: the
        // receipt is the record of that agreement, written with the credential.
        let consentReceiptId: string | undefined;
        if (mint === "custody_only" && shownText !== null) {
          const ask = consentAskFor(statePayload);
          const { receipt } = await store.createConsentReceipt({
            kind: "grant",
            accountId: account.id,
            appSlug: statePayload.app_slug,
            provider: identity.provider,
            createdAt: nowIso,
            scopesAsked: [...ask.scopes],
            scopesGranted: tokenSet.scope,
            consentPageDigest: digestOfText(shownText),
            consentText: shownText,
          });
          consentReceiptId = receipt.id;
        }

        const entitlementEvaluation = await runtime.evaluateEntitlements({
          config,
          callback: {
            appSlug: statePayload.app_slug,
            accountId: account.id,
            connection: statePayload.connection,
            entitlementPolicy: statePayload.entitlement_policy,
          },
          identity,
          tokenSet,
        });
        for (const snapshot of entitlementEvaluation.snapshots) {
          await store.upsertEntitlementSnapshot(snapshot);
        }
        // The account's other linked identities count too: a member who
        // returns through a provider that grants nothing (Google) keeps what
        // Discord or Patreon grant. They are evaluated with the app's
        // start-time policy, the same call the refresh route makes.
        const linkedFacts = await evaluateStoredEntitlements({
          config,
          store,
          tokenCustody,
          oauthRuntimes,
          appSlug: statePayload.app_slug,
          accountId: account.id,
          entitlementPolicies: statePayload.entitlement_policy ? [statePayload.entitlement_policy] : [],
          skipProvider: identity.provider,
        });

        const grants = await store.listActiveGrants(account.id, statePayload.app_slug, nowIso);
        const issueInput: IssueAccessClaimInput = {
          appSlug: statePayload.app_slug,
          accountId: account.id,
          linkedIdentities: await store.listLinkedIdentitiesForAccount(account.id),
          facts: [...new Set([...entitlementEvaluation.facts, ...linkedFacts]), ...buildGrantFacts(grants)],
          ...(mint === "custody_only" ? { withoutCapabilities: true } : {}),
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
        // A custody-only completion carries no refresh token: the refresh
        // route recomputes capabilities from the account's facts, so one
        // would turn the capability-free session into a viewer session.
        const { refreshToken: issuedRefreshToken, refresh: issuedRefresh, ...issuedWithoutRefresh } = issued;
        const delivered =
          mint === "custody_only"
            ? issuedWithoutRefresh
            : { ...issuedWithoutRefresh, refreshToken: issuedRefreshToken, refresh: issuedRefresh };

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
          connection: statePayload.connection,
          ...(statePayload.step_up ? { stepUpRequested: true } : {}),
          ...(consentReceiptId ? { consentReceiptId } : {}),
          ...delivered,
        };
        if (handoff.kind === "backend_callback") {
          await maybeDeliverBackendHandoff(handoff, {
            source: "heimdall",
            kind: "oauth_result",
            handoffKind: "backend_callback",
            attemptId: handoff.attemptId,
            status: "success",
            provider: request.params.provider,
            appSlug: statePayload.app_slug,
            mode: statePayload.mode,
            returnTo: statePayload.return_to,
            connection: statePayload.connection,
            account: accountSummary,
            entitlements: entitlementEvaluation,
            ...(consentReceiptId ? { consentReceiptId } : {}),
            ...delivered,
          });

          await store.createAuditEvent({
            accountId: account.id,
            sessionId: issued.session.sessionId,
            appSlug: statePayload.app_slug,
            eventType: "backend_handoff_delivered",
            eventPayloadJson: {
              provider: request.params.provider,
              mode: statePayload.mode,
              attemptId: handoff.attemptId,
              connection: statePayload.connection,
              callbackUrl: handoff.callbackUrl,
            },
            createdAt: nowIso,
          });

          if (prefersHtml(request.headers.accept)) {
            reply.type("text/html; charset=utf-8");
            return reply.send(
              renderBrowserHandoffPage({
                handoffKind: "backend_callback",
                status: "success",
                provider: request.params.provider,
                appSlug: statePayload.app_slug,
                mode: statePayload.mode,
                returnTo: statePayload.return_to,
                attemptId: handoff.attemptId,
                ...(consentReceiptId ? { consentReceiptId } : {}),
              })
            );
          }

          reply.code(201);
          return {
            delivery: {
              kind: "backend_callback",
              attemptId: handoff.attemptId,
              callbackUrl: handoff.callbackUrl,
              status: "delivered",
            },
            account: accountSummary,
            session: issued.session,
            verification: issued.verification,
          };
        }

        const completionExpiresAt = new Date(Date.now() + config.completionTtlSeconds * 1000).toISOString();
        // The completion code is always minted here, never taken from the
        // caller. handoff.attemptId is a browser-carried correlation handle,
        // not a secret: before this cut it was assigned verbatim as the code
        // (createAuthCompletion({ code: handoff.attemptId })), so anyone who
        // started the flow could fix the redemption code in advance and
        // redeem a victim's signed tokens without ever touching the app
        // secret. It is stored on `attemptId` below purely for correlation.
        const completion = await store.createAuthCompletion({
          ...(handoff.kind === "browser_completion" && handoff.attemptId ? { attemptId: handoff.attemptId } : {}),
          appSlug: statePayload.app_slug,
          provider: request.params.provider,
          mode: statePayload.mode,
          accountId: account.id,
          sessionId: issued.session.sessionId,
          returnTo: statePayload.return_to,
          ...(statePayload.connection ? { targetId: statePayload.connection.targetId } : {}),
          createdAt: nowIso,
          expiresAt: completionExpiresAt,
          payloadJson: completionPayload as unknown as Record<string, unknown>,
        });
        if (handoff.kind === "browser_completion" && handoff.attemptId) {
          await store.updateAuthAttempt(statePayload.app_slug, handoff.attemptId, {
            status: "completed",
            at: nowIso,
          });
        }

        await store.createAuditEvent({
          accountId: account.id,
          sessionId: issued.session.sessionId,
          appSlug: statePayload.app_slug,
          eventType: "auth_completion_created",
          // Never the completion code: until it expires, the unauthenticated
          // redeem route turns it into the session. The event's sessionId
          // already names the completion, one per callback.
          eventPayloadJson: {
            provider: request.params.provider,
            mode: statePayload.mode,
            expiresAt: completion.expiresAt,
          },
          createdAt: nowIso,
        });

        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              handoffKind: "browser_completion",
              status: "success",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              completionCode: completion.code,
              ...(consentReceiptId ? { consentReceiptId } : {}),
              ...(handoff.kind === "browser_completion" && handoff.attemptId
                ? { attemptId: handoff.attemptId }
                : {}),
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
        // Neither the answer nor the audit event carries the error's text.
        // This path catches store and provider failures: a Postgres or
        // resolver error names a constraint, the host or the database, and
        // JSON.parse quotes the provider's response body. The audit event
        // keeps the error's class, its code, and a provider's HTTP status.
        const status = (error as { status?: unknown }).status;
        // A link refusal is a typed decision with a static message; every
        // other failure keeps the opaque answer above.
        const refusal = error instanceof LinkRefusal ? error : null;
        const failureCode = refusal?.code ?? "oauth_callback_failed";
        const failure = refusal?.message ?? "The provider callback could not be completed.";
        const nowIso = new Date().toISOString();
        await denyBrowserAttempt(failureCode);
        await store.createAuditEvent({
          appSlug: statePayload.app_slug,
          eventType: refusal ? "oauth_link_refused" : "oauth_callback_failed",
          eventPayloadJson: {
            provider: request.params.provider,
            mode: statePayload.mode,
            ...errorIdentity(error),
            providerStatus: typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
          },
          createdAt: nowIso,
        });

        if (handoff.kind === "backend_callback") {
          try {
            await maybeDeliverBackendHandoff(handoff, {
              source: "heimdall",
              kind: "oauth_result",
              handoffKind: "backend_callback",
              attemptId: handoff.attemptId,
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              connection: statePayload.connection,
              error: failureCode,
              errorDescription: failure,
            });
          } catch {}
        }

        if (prefersHtml(request.headers.accept)) {
          reply.type("text/html; charset=utf-8");
          return reply.send(
            renderBrowserHandoffPage({
              handoffKind: handoff.kind,
              status: "error",
              provider: request.params.provider,
              appSlug: statePayload.app_slug,
              mode: statePayload.mode,
              returnTo: statePayload.return_to,
              ...(handoff.kind === "backend_callback" ? { attemptId: handoff.attemptId } : {}),
              error: failureCode,
              errorDescription: failure,
            })
          );
        }

        reply.code(refusal ? 403 : 502);
        return {
          error: failureCode,
          detail: failure,
          provider: request.params.provider,
          appSlug: statePayload.app_slug,
          returnTo: statePayload.return_to,
        };
      }
    }
  );

  // Second phase of a link. The callback only recorded the verified identity;
  // this writes it, and only for the account whose access token began the
  // link. The bearer is the same proof start demanded, so a stranger who
  // completed the provider login (or holds the id) attaches nothing.
  app.post<{ Params: { appSlug: AppSlug }; Body: { pendingLinkId: string } }>(
    "/v1/apps/:appSlug/links/confirm",
    {
      schema: {
        params: {
          type: "object",
          required: ["appSlug"],
          additionalProperties: false,
          properties: { appSlug: { type: "string", enum: [...appSlugs] } },
        },
        body: {
          type: "object",
          required: ["pendingLinkId"],
          additionalProperties: false,
          properties: { pendingLinkId: { type: "string", minLength: 1 } },
        },
      },
    },
    async (request, reply) => {
      const accountId = await resolveLinkAccount({ config, keys, store }, request.params.appSlug, request.headers.authorization);
      if (!accountId) {
        reply.code(401);
        return { error: "invalid_link_session", detail: "The bearer is not a live Heimdall access token for this app." };
      }
      const nowIso = new Date().toISOString();
      const pending = await store.consumePendingLink(request.params.appSlug, request.body.pendingLinkId, accountId, nowIso);
      if (!pending) {
        reply.code(410);
        return { error: "invalid_or_expired_pending_link" };
      }
      const holder = await store.findAccountByLinkedIdentity(pending.provider, pending.providerUserId);
      if (holder && holder.id !== accountId) {
        reply.code(409);
        return { error: "identity_linked_elsewhere" };
      }
      await store.upsertLinkedIdentity({ ...pending.identity, accountId, updatedAt: nowIso });
      await store.createAuditEvent({
        accountId,
        appSlug: pending.appSlug,
        eventType: "link_confirmed",
        eventPayloadJson: { provider: pending.provider },
        createdAt: nowIso,
      });
      reply.code(201);
      return { status: "linked", provider: pending.provider, accountId, returnTo: pending.returnTo };
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
            targetId: { type: "string", minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const nowIso = new Date().toISOString();
      // Sign-in and connect completions are redeemed by the browser flow, so
      // the route stays open to it. A link completion was minted for an
      // initiator the authenticated app named at start; only that app's
      // backend redeems it. Redeem is also where the connection target is
      // held to what the signed state named, both ways: a target the state never named is refused too. Both refusals read the row
      // without consuming it, so a wrong caller or target cannot burn the code.
      const pending = await store.findAuthCompletion(request.params.appSlug, request.body.completionCode);
      if (pending && !pending.consumedAt && pending.expiresAt > nowIso) {
        if (pending.mode === "link" && !resolveAppCaller(config, request.params.appSlug, request.headers)) {
          reply.code(401);
          return { error: "app_auth_required" };
        }
        if (pending.targetId !== request.body.targetId) {
          await store.createAuditEvent({
            accountId: pending.accountId,
            sessionId: pending.sessionId,
            appSlug: pending.appSlug,
            eventType: "auth_completion_target_refused",
            eventPayloadJson: { provider: pending.provider, mode: pending.mode },
            createdAt: nowIso,
          });
          reply.code(403);
          return { error: "completion_target_mismatch" };
        }
      }
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
        },
        createdAt: nowIso,
      });
      // completion.attemptId is the browser-carried correlation handle, kept
      // separate from the redemption code itself (see createAuthCompletion
      // above); this used to key off the completion code, which only ever
      // matched an attempt by the coincidence of the pre-fix bug where the
      // code *was* the caller-chosen attemptId.
      if (completion.attemptId) {
        await store.updateAuthAttempt(request.params.appSlug, completion.attemptId, {
          status: "consumed",
          at: nowIso,
        });
      }

      reply.code(201);
      return completion.payloadJson;
    }
  );

  app.post<{ Params: { appSlug: AppSlug }; Body: RefreshSessionRequest }>(
    "/v1/apps/:appSlug/sessions/refresh",
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
          required: ["refreshToken"],
          additionalProperties: false,
          properties: {
            refreshToken: { type: "string", minLength: 1 },
            entitlementPolicy: {
              anyOf: [
                {
                  type: "object",
                  required: ["kind", "guildId", "allowedRoleIds"],
                  additionalProperties: false,
                  properties: {
                    kind: { type: "string", const: "discord_role_access" },
                    guildId: { type: "string", minLength: 1 },
                    allowedRoleIds: {
                      type: "array",
                      minItems: 1,
                      items: { type: "string", minLength: 1 },
                      uniqueItems: true,
                    },
                  },
                },
                {
                  type: "object",
                  required: ["kind", "requiredTierTitle"],
                  additionalProperties: false,
                  properties: {
                    kind: { type: "string", const: "patreon_membership_access" },
                    requiredTierTitle: { type: "string", minLength: 1 },
                  },
                },
              ],
            },
            entitlementPolicies: {
              type: "array",
              items: {
                anyOf: [
                  {
                    type: "object",
                    required: ["kind", "guildId", "allowedRoleIds"],
                    additionalProperties: false,
                    properties: {
                      kind: { type: "string", const: "discord_role_access" },
                      guildId: { type: "string", minLength: 1 },
                      allowedRoleIds: {
                        type: "array",
                        minItems: 1,
                        items: { type: "string", minLength: 1 },
                        uniqueItems: true,
                      },
                    },
                  },
                  {
                    type: "object",
                    required: ["kind", "requiredTierTitle"],
                    additionalProperties: false,
                    properties: {
                      kind: { type: "string", const: "patreon_membership_access" },
                      requiredTierTitle: { type: "string", minLength: 1 },
                    },
                  },
                ],
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const caller = resolveAppCaller(config, request.params.appSlug, request.headers);
      const result = await refreshAppSession(
        { config, keys, store, tokenCustody, oauthRuntimes },
        request.params.appSlug,
        caller,
        request.body
      );
      reply.code(result.statusCode);
      return result.body;
    }
  );

  app.post<{
    Params: { appSlug: AppSlug };
    Body: {
      accountId: string;
      requiredTierTitle: string;
      currencyCode?: string;
      supportedAtUtc?: string;
    };
  }>(
    "/v1/apps/:appSlug/patron-support/sync",
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
          required: ["accountId", "requiredTierTitle"],
          additionalProperties: false,
          properties: {
            accountId: { type: "string", minLength: 1 },
            requiredTierTitle: { type: "string", minLength: 1 },
            currencyCode: { type: "string", minLength: 3, maxLength: 3 },
            supportedAtUtc: { type: "string", minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const profile = getAppProfile(request.params.appSlug);
      if (!profile) {
        reply.code(404);
        return { error: "unknown_app", detail: "No app is registered under that slug." };
      }
      if (!resolveAppCaller(config, profile.slug, request.headers)) {
        reply.code(401);
        return { error: "app_auth_required" };
      }

      if (profile.slug !== "bifrost") {
        reply.code(400);
        return { error: "patron_support_sync_only_available_for_bifrost", appSlug: profile.slug };
      }

      if (!config.bifrostPatronSupportEndpoint || !config.bifrostPatronSupportSecret) {
        reply.code(503);
        return { error: "bifrost_patron_support_not_configured" };
      }

      const storedLinkedIdentity = await store.findStoredLinkedIdentityForAccount(request.body.accountId, "patreon");
      if (!storedLinkedIdentity) {
        reply.code(404);
        return { error: "patreon_identity_not_linked" };
      }

      const now = new Date().toISOString();
      const refreshed = await refreshManagedCredential({ config, store, tokenCustody, oauthRuntimes }, storedLinkedIdentity);
      const linkedIdentity = refreshed.identity;
      if (refreshed.kind === "revoked" || !linkedIdentity.accessTokenEncrypted) {
        reply.code(404);
        return { error: "patreon_identity_not_linked" };
      }

      const patreonProfile = await fetchPatreonIdentity(tokenCustody.decrypt(linkedIdentity.accessTokenEncrypted));
      const memberships = summarizePatreonMemberships(patreonProfile);
      const activeMembership = memberships.find(
        (membership) =>
          membership.isActivePaid &&
          membership.currentlyEntitledAmountCents > 0 &&
          membership.tierTitles.includes(request.body.requiredTierTitle)
      );

      if (!activeMembership) {
        reply.code(404);
        return {
          error: "active_patreon_membership_not_found",
          accountId: request.body.accountId,
          requiredTierTitle: request.body.requiredTierTitle,
          membershipCount: memberships.length,
        };
      }

      const supportedAtUtc = request.body.supportedAtUtc ?? now;
      const supportedDay = supportedAtUtc.slice(0, 10);
      const currencyCode = activeMembership.campaignCurrency ?? request.body.currencyCode ?? "USD";
      const supportFact = {
        heimdallAccountId: request.body.accountId,
        provider: "Patreon",
        providerEventId: [
          "patreon-membership-snapshot",
          linkedIdentity.providerUserId,
          activeMembership.memberId,
          supportedDay,
          activeMembership.currentlyEntitledAmountCents,
        ].join(":"),
        kind: "RecurringSupportSnapshot",
        amount: Number(centsToDecimalString(activeMembership.currentlyEntitledAmountCents)),
        currencyCode,
        externalSupportId: `patreon-member:${activeMembership.memberId}`,
        supportedAtUtc,
        isCurrentRecurringSupport: true,
        providerPayerId: linkedIdentity.providerUserId,
        providerSubscriptionId: activeMembership.memberId,
        notes: `Verified active Patreon membership for tier ${request.body.requiredTierTitle}.`,
      };
      const body = JSON.stringify(supportFact);
      const bifrostResponse = await fetch(config.bifrostPatronSupportEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-heimdall-signature-256": signBifrostPatronSupportPayload(config.bifrostPatronSupportSecret, body),
        },
        body,
      });
      // Bifrost's answer is kept by its status alone, in the audit event and
      // in the reply: another service's body can quote the signed fact or
      // its own configuration, and both of those are stored and relayed.
      await bifrostResponse.body?.cancel();

      await store.createAuditEvent({
        accountId: request.body.accountId,
        appSlug: "bifrost",
        eventType: bifrostResponse.ok ? "bifrost_patron_support_synced" : "bifrost_patron_support_sync_failed",
        eventPayloadJson: {
          provider: "patreon",
          requiredTierTitle: request.body.requiredTierTitle,
          providerEventId: supportFact.providerEventId,
          bifrostStatus: bifrostResponse.status,
        },
        createdAt: now,
      });

      if (!bifrostResponse.ok) {
        reply.code(502);
        return {
          error: "bifrost_patron_support_rejected",
          statusCode: bifrostResponse.status,
          detail: "Bifrost refused the patron support fact.",
        };
      }

      return {
        status: "synced",
        supportFact,
        bifrostStatus: bifrostResponse.status,
      };
    }
  );

  app.post<{
    Params: { appSlug: AppSlug };
    Body: { accountId: string; provider: Provider };
  }>(
    "/v1/apps/:appSlug/managed-credentials/resolve",
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
          required: ["accountId", "provider"],
          additionalProperties: false,
          properties: {
            accountId: { type: "string", minLength: 1 },
            provider: { type: "string", enum: [...providers] },
          },
        },
      },
    },
    async (request, reply) => {
      const profile = getAppProfile(request.params.appSlug);
      if (!profile) {
        reply.code(404);
        return { error: "unknown_app", detail: "No app is registered under that slug." };
      }
      if (!resolveAppCaller(config, profile.slug, request.headers)) {
        reply.code(401);
        return { error: "app_auth_required" };
      }

      if (!profile.managedConnectionProviders.includes(request.body.provider)) {
        reply.code(400);
        return {
          error: "provider_not_managed_for_app",
          provider: request.body.provider,
          appSlug: profile.slug,
        };
      }

      const storedLinkedIdentity = await store.findStoredLinkedIdentityForAccount(request.body.accountId, request.body.provider);
      if (!storedLinkedIdentity) {
        reply.code(404);
        return { error: "managed_credential_not_found" };
      }
      let refreshed;
      try {
        refreshed = await refreshManagedCredential({ config, store, tokenCustody, oauthRuntimes }, storedLinkedIdentity);
      } catch (error) {
        if (error instanceof ManagedCredentialRefreshFailed) {
          reply.code(502);
          return { error: error.code, provider: error.provider };
        }
        throw error;
      }
      const linkedIdentity = refreshed.identity;
      if (refreshed.kind === "revoked" || !linkedIdentity.accessTokenEncrypted) {
        reply.code(410);
        return { error: "managed_credential_revoked", provider: linkedIdentity.provider };
      }

      const response: {
        accountId: string;
        provider: Provider;
        providerUserId: string;
        accessToken: string;
        tokenExpiresAt?: string;
        scopes: string[];
      } = {
        accountId: linkedIdentity.accountId,
        provider: linkedIdentity.provider,
        providerUserId: linkedIdentity.providerUserId,
        accessToken: tokenCustody.decrypt(linkedIdentity.accessTokenEncrypted),
        scopes: linkedIdentity.scopes,
      };

      if (linkedIdentity.tokenExpiresAt) {
        response.tokenExpiresAt = linkedIdentity.tokenExpiresAt;
      }

      return response;
    }
  );

  /** The signed-in account, and the expiry the page's own forms get: a bearer starts a fresh window, a page link only passes on the one it has. */
  const grantsAccount = async (request: FastifyRequest, pageToken?: unknown): Promise<{ accountId: string; exp: number } | null> => {
    const bearerAccount = await resolveAccessAccount({ config, keys, store }, request.headers.authorization);
    if (bearerAccount) return { accountId: bearerAccount, exp: nowEpochSeconds() + grantsPageTokenTtlSeconds };
    return grantsPageTokenAccount(config, keys, pageToken);
  };

  const grantsReply = (reply: FastifyReply) => {
    reply.header("Cache-Control", "no-store");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  };

  const signInRequired = (reply: FastifyReply) => {
    reply.code(401);
    return { error: "sign_in_required", detail: "Send a Heimdall access token as a Bearer token, or open a link from POST /v1/me/grants/link." };
  };

  // The signed-in surface for consent: every grant and receipt the account
  // holds, and the one-click way to take each back.
  app.get<{ Querystring: { t?: string } }>(
    GRANTS_PATH,
    { schema: { querystring: { type: "object", additionalProperties: false, properties: { t: { type: "string" } } } } },
    async (request, reply) => {
      const caller = await grantsAccount(request, request.query.t);
      if (!caller) return signInRequired(reply);
      const { accountId } = caller;
      grantsReply(reply);
      const receipts = await store.listConsentReceipts(accountId);
      if (prefersHtml(request.headers.accept)) {
        reply.type("text/html; charset=utf-8");
        return reply.send(renderGrantsPage(grantViews(receipts), signGrantsPageToken(config, keys, accountId, caller.exp)));
      }
      return { grants: grantViews(receipts), receipts };
    }
  );

  // A link a browser can open: short-lived, opens the grants page and nothing else.
  app.post(`${GRANTS_PATH}/link`, async (request, reply) => {
    const accountId = await resolveAccessAccount({ config, keys, store }, request.headers.authorization);
    if (!accountId) return signInRequired(reply);
    grantsReply(reply);
    reply.code(201);
    return {
      url: `${config.publicBaseUrl}${GRANTS_PATH}?t=${encodeURIComponent(signGrantsPageToken(config, keys, accountId))}`,
      expiresInSeconds: grantsPageTokenTtlSeconds,
    };
  });

  app.post<{ Params: { grantId: string }; Body?: { t?: string } }>(
    `${GRANTS_PATH}/:grantId/revoke`,
    {
      schema: {
        params: { type: "object", required: ["grantId"], additionalProperties: false, properties: { grantId: { type: "string", minLength: 1 } } },
        body: { type: ["object", "null"], additionalProperties: false, properties: { t: { type: "string" } } },
      },
    },
    async (request, reply) => {
      const caller = await grantsAccount(request, request.body?.t);
      if (!caller) return signInRequired(reply);
      const { accountId } = caller;
      grantsReply(reply);
      const receipts = await store.listConsentReceipts(accountId);
      const grant = grantViews(receipts).find((view) => view.id === request.params.grantId);
      if (!grant) {
        reply.code(404);
        return { error: "grant_not_found" };
      }
      const revoked: string[] = [];
      if (grant.status === "active") {
        // The credential is one row per account and provider, whichever app
        // asked, so taking it back ends every live grant that rests on it.
        // It is stripped first: a failure after that leaves a receipt that
        // still reads active over a credential that is gone, never the reverse.
        const identity = await store.findStoredLinkedIdentityForAccount(accountId, grant.provider);
        const at = new Date().toISOString();
        if (identity) {
          await store.updateLinkedIdentityCredential(identity.id, async () => ({ kind: "revoke", updatedAt: at }));
        }
        for (const live of grantViews(receipts).filter((view) => view.provider === grant.provider && view.status === "active")) {
          const { created } = await store.createConsentReceipt({
            kind: "revocation",
            accountId,
            appSlug: live.appSlug,
            provider: live.provider,
            createdAt: at,
            revokesReceiptId: live.id,
          });
          // A concurrent revoke may have written it first; only the writer reports it.
          if (created) revoked.push(live.id);
        }
        if (revoked.length) {
          await store.createAuditEvent({
            accountId,
            eventType: "consent_revoked",
            eventPayloadJson: { provider: grant.provider, grantIds: revoked },
            createdAt: at,
          });
        }
      }
      if (prefersHtml(request.headers.accept) || request.headers["content-type"]?.startsWith("application/x-www-form-urlencoded")) {
        reply.type("text/html; charset=utf-8");
        const views = grantViews(await store.listConsentReceipts(accountId));
        return reply.send(renderGrantsPage(views, signGrantsPageToken(config, keys, accountId, caller.exp), revoked.length ? "Taken back." : "Already taken back."));
      }
      return { revoked, grants: grantViews(await store.listConsentReceipts(accountId)) };
    }
  );

  return app;
}
