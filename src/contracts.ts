export const providers = ["discord", "patreon", "github", "twitch", "youtube", "spotify", "joystick", "google"] as const;

export type Provider = (typeof providers)[number];

/** Apps shipped with Heimdall. Seed data, not the set of permissible apps. */
export const appSlugs = ["repixelizer", "streampixels", "bifrost", "ghostlight"] as const;

export type BuiltInAppSlug = (typeof appSlugs)[number];

/**
 * An app identifier. Always a string on the wire; it was narrowed to a union
 * only because every app was known at build time. Validity is decided by the
 * app registry, not the type system.
 */
export type AppSlug = string;

/**
 * Shape check only. Whether an app exists is a registry question, and callers
 * without a store — the offline token verifier, for one — can only check that
 * an identifier is well formed. A host app verifying its own tokens should
 * compare aud against its own slug rather than trusting a shape.
 */
export function isAppSlug(value: unknown): value is AppSlug {
  return typeof value === "string" && /^[a-z][a-z0-9_-]{1,62}$/.test(value);
}

export const oauthModes = ["sign_in", "link", "connect"] as const;

export type OAuthMode = (typeof oauthModes)[number];

export const connectionKinds = ["account", "creator", "workspace", "project", "channel"] as const;

export type ConnectionKind = (typeof connectionKinds)[number];

export const oauthHandoffKinds = ["browser_completion", "backend_callback"] as const;

export type OAuthHandoffKind = (typeof oauthHandoffKinds)[number];

export interface OAuthConnectionBinding {
  kind: ConnectionKind;
  targetId: string;
  summary?: string;
}

export interface OAuthBrowserCompletionHandoff {
  kind: "browser_completion";
  attemptId?: string;
}

export interface OAuthBackendCallbackHandoff {
  kind: "backend_callback";
  attemptId: string;
  callbackUrl: string;
}

export type OAuthHandoff = OAuthBrowserCompletionHandoff | OAuthBackendCallbackHandoff;

export interface DiscordRoleEntitlementPolicy {
  kind: "discord_role_access";
  guildId: string;
  allowedRoleIds: string[];
}

export interface PatreonMembershipEntitlementPolicy {
  kind: "patreon_membership_access";
  requiredTierTitle: string;
}

export type OAuthEntitlementPolicy = DiscordRoleEntitlementPolicy | PatreonMembershipEntitlementPolicy;

export interface OAuthStartRequest {
  appSlug: AppSlug;
  mode: OAuthMode;
  returnTo: string;
  connection?: OAuthConnectionBinding;
  /** Link mode only: the account the authenticated app says is linking. Carried in the signed state. */
  initiatingAccountId?: string;
  handoff?: OAuthHandoff;
  requestedScopes?: string[];
  entitlementPolicy?: OAuthEntitlementPolicy;
  /** Sign_in only, app-authenticated: ask the provider for a real re-authentication. Off when absent. */
  stepUp?: boolean;
}

export interface OAuthStatePayload {
  iss: string;
  sub: AppSlug;
  aud: Provider;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  typ: "heimdall_oauth_state";
  provider: Provider;
  app_slug: AppSlug;
  mode: OAuthMode;
  return_to: string;
  connection: OAuthConnectionBinding | null;
  initiator_account_id: string | null;
  handoff: OAuthHandoff | null;
  entitlement_policy: OAuthEntitlementPolicy | null;
  /** The start's requestedScopes, carried so the launch hop can build the provider URL from the signed state alone. */
  requested_scopes: string[] | null;
  /** The start's step-up request. Signed, so the launch hop reads it here and nowhere else; null when not asked. */
  step_up: true | null;
}

export interface LinkedIdentityInput {
  provider: Provider;
  providerUserId: string;
  username?: string;
  displayName?: string;
}

export interface RedeemAuthCompletionRequest {
  completionCode: string;
  /** Required when the completion was minted for a connection target; must equal it. */
  targetId?: string;
}

export type HeimdallAuthAttemptStatus = "pending" | "completed" | "denied" | "consumed" | "expired";

export interface HeimdallAuthAttempt {
  schema: "heimdall.auth_attempt.v1";
  handle: string;
  appSlug: AppSlug;
  provider: Provider;
  mode: OAuthMode;
  returnTo: string;
  status: HeimdallAuthAttemptStatus;
  createdAt: string;
  expiresAt: string;
  completedAt?: string;
  consumedAt?: string;
  denialCode?: string;
}

export interface RefreshSessionRequest {
  refreshToken: string;
  entitlementPolicy?: OAuthEntitlementPolicy;
  entitlementPolicies?: OAuthEntitlementPolicy[];
}

export interface AccessClaimPayload {
  iss: string;
  aud: AppSlug;
  sub: string;
  sid: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  typ: "heimdall_access";
  account_id: string;
  access_revision: number;
  /** Epoch seconds of the step-up sign-in this access token was minted by; absent on every other token, and never carried by a refresh. */
  step_up_at?: number;
  /**
   * How the proof in step_up_at was made: `provider:<name>` for a step-up
   * sign-in Heimdall ran, or one of the calling app's allowlisted method
   * labels when the app asserted it (POST /v1/apps/{app}/step-up). Present
   * exactly when step_up_at is; never carried by a refresh.
   */
  step_up_method?: string;
  display_name?: string;
  app: {
    slug: AppSlug;
    profile_version: string;
  };
  facts: string[];
  capabilities: string[];
  identities: LinkedIdentityInput[];
}

export interface RefreshTokenPayload {
  iss: string;
  aud: AppSlug;
  sub: string;
  sid: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  typ: "heimdall_refresh";
  account_id: string;
  access_revision: number;
  app: {
    slug: AppSlug;
    profile_version: string;
  };
}
