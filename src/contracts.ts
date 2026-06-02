export const providers = ["discord", "patreon", "github", "twitch", "youtube", "spotify"] as const;

export type Provider = (typeof providers)[number];

export const appSlugs = ["repixelizer", "streampixels", "spotiverse"] as const;

export type AppSlug = (typeof appSlugs)[number];

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
  handoff?: OAuthHandoff;
  requestedScopes?: string[];
  entitlementPolicy?: OAuthEntitlementPolicy;
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
  handoff: OAuthHandoff | null;
  entitlement_policy: OAuthEntitlementPolicy | null;
}

export interface LinkedIdentityInput {
  provider: Provider;
  providerUserId: string;
  username?: string;
  displayName?: string;
}

export interface IssueClaimRequest {
  accountId: string;
  sessionId?: string;
  displayName?: string;
  facts?: string[];
  linkedIdentities?: LinkedIdentityInput[];
  accessRevision?: number;
  ttlSeconds?: number;
}

export interface RedeemAuthCompletionRequest {
  completionCode: string;
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
