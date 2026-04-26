export const providers = ["discord", "patreon", "github", "twitch", "youtube"] as const;

export type Provider = (typeof providers)[number];

export const appSlugs = ["repixelizer", "streampixels"] as const;

export type AppSlug = (typeof appSlugs)[number];

export const oauthModes = ["sign_in", "link", "connect"] as const;

export type OAuthMode = (typeof oauthModes)[number];

export const connectionKinds = ["account", "creator", "workspace", "project", "channel"] as const;

export type ConnectionKind = (typeof connectionKinds)[number];

export interface OAuthConnectionBinding {
  kind: ConnectionKind;
  targetId: string;
  summary?: string;
}

export interface OAuthStartRequest {
  appSlug: AppSlug;
  mode: OAuthMode;
  returnTo: string;
  connection?: OAuthConnectionBinding;
  requestedScopes?: string[];
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
