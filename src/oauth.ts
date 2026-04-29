import { Buffer } from "node:buffer";
import {
  type AppSlug,
  type OAuthConnectionBinding,
  type OAuthEntitlementPolicy,
  type Provider,
} from "./contracts.js";
import { type HeimdallConfig } from "./config.js";
import { entitlementFacts } from "./facts.js";
import { type CreateEntitlementSnapshotInput } from "./store/types.js";

export interface OAuthTokenSet {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  scope: string[];
  expiresAt?: string;
  raw: Record<string, unknown>;
}

export interface ResolvedIdentity {
  provider: Provider;
  providerUserId: string;
  username?: string;
  displayName?: string;
  primaryEmail?: string;
  avatarUrl?: string;
  profile: Record<string, unknown>;
}

export interface EntitlementEvaluation {
  facts: string[];
  snapshots: CreateEntitlementSnapshotInput[];
}

export interface OAuthCallbackContext {
  appSlug: AppSlug;
  accountId: string;
  connection: OAuthConnectionBinding | null;
  entitlementPolicy: OAuthEntitlementPolicy | null;
}

export interface OAuthProviderRuntime {
  exchangeAuthorizationCode(options: {
    config: HeimdallConfig;
    code: string;
    redirectUri: string;
  }): Promise<OAuthTokenSet>;
  resolveIdentity(options: { accessToken: string }): Promise<ResolvedIdentity>;
  evaluateEntitlements(options: {
    config: HeimdallConfig;
    callback: OAuthCallbackContext;
    identity: ResolvedIdentity;
    tokenSet: OAuthTokenSet;
  }): Promise<EntitlementEvaluation>;
}

function buildErrorMessage(status: number, body: string, fallback: string): string {
  return `${fallback} (status ${status}): ${body || "empty response"}`;
}

async function fetchJson<T>(input: string | URL, init: RequestInit, fallbackError: string): Promise<T> {
  const response = await fetch(input, init);
  const text = await response.text();

  if (!response.ok) {
    throw new Error(buildErrorMessage(response.status, text, fallbackError));
  }

  return (text ? JSON.parse(text) : {}) as T;
}

async function exchangeDiscordAuthorizationCode(options: {
  config: HeimdallConfig;
  code: string;
  redirectUri: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.discord;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Discord OAuth is not fully configured.");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: options.code,
    redirect_uri: options.redirectUri,
  });
  const basicAuth = Buffer.from(`${providerConfig.clientId}:${providerConfig.clientSecret}`).toString("base64");
  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in: number;
    scope: string;
  }>(
    "https://discord.com/api/v10/oauth2/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    },
    "Discord token exchange failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: tokenResponse.scope.split(/\s+/).filter(Boolean),
    expiresAt: new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString(),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  return tokenSet;
}

async function resolveDiscordIdentity(options: { accessToken: string }): Promise<ResolvedIdentity> {
  const user = await fetchJson<{
    id: string;
    username?: string;
    global_name?: string;
    email?: string;
    avatar?: string | null;
  }>(
    "https://discord.com/api/v10/users/@me",
    {
      headers: {
        Authorization: `Bearer ${options.accessToken}`,
      },
    },
    "Discord identity lookup failed"
  );

  const identity: ResolvedIdentity = {
    provider: "discord",
    providerUserId: user.id,
    profile: user as unknown as Record<string, unknown>,
  };

  if (user.username) {
    identity.username = user.username;
  }

  const displayName = user.global_name ?? user.username;
  if (displayName) {
    identity.displayName = displayName;
  }

  if (user.email) {
    identity.primaryEmail = user.email;
  }

  if (user.avatar) {
    identity.avatarUrl = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`;
  }

  return identity;
}

async function evaluateDiscordEntitlements(options: {
  config: HeimdallConfig;
  callback: OAuthCallbackContext;
  tokenSet: OAuthTokenSet;
}): Promise<EntitlementEvaluation> {
  if (options.callback.appSlug !== "repixelizer") {
    return { facts: [], snapshots: [] };
  }

  const policy = options.callback.entitlementPolicy;
  if (!policy || policy.kind !== "discord_role_access") {
    return { facts: [], snapshots: [] };
  }
  const guildId = policy.guildId;
  const allowedRoleIds = policy.allowedRoleIds;

  const response = await fetch(
    `https://discord.com/api/v10/users/@me/guilds/${guildId}/member`,
    {
      headers: {
        Authorization: `Bearer ${options.tokenSet.accessToken}`,
      },
    }
  );

  if (response.status === 404) {
    return {
      facts: [],
      snapshots: [
        {
          accountId: options.callback.accountId,
          provider: "discord",
          scope: `repixelizer:discord_member:${guildId}`,
          evaluatedAt: new Date().toISOString(),
          isAllowed: false,
          reasonCode: "not_in_guild",
          reasonDetail: "Current user is not a member of the configured GameCult guild.",
          rawSummaryJson: { guildId },
        },
      ],
    };
  }

  const text = await response.text();
  if (!response.ok) {
    throw new Error(buildErrorMessage(response.status, text, "Discord guild member lookup failed"));
  }

  const member = (text ? JSON.parse(text) : {}) as {
    nick?: string;
    roles?: string[];
    joined_at?: string;
  };
  const roles = member.roles ?? [];
  const matchedRoles = allowedRoleIds.filter((roleId) => roles.includes(roleId));
  const facts: string[] = [];

  if (matchedRoles.length > 0) {
    facts.push(entitlementFacts.appAccess);
  }

  return {
    facts,
    snapshots: [
      {
        accountId: options.callback.accountId,
        provider: "discord",
        scope: `repixelizer:discord_role_access:${guildId}`,
        evaluatedAt: new Date().toISOString(),
        isAllowed: matchedRoles.length > 0,
        reasonCode: matchedRoles.length > 0 ? "matched_role" : "missing_role",
        reasonDetail:
          matchedRoles.length > 0
            ? "Matched a configured Repixelizer access role."
            : allowedRoleIds.length
              ? "User is in the guild but lacks the configured Repixelizer access role."
              : "Repixelizer did not supply any Discord role ids in its entitlement policy.",
        rawSummaryJson: {
          guildId,
          roles,
          matchedRoles,
          nick: member.nick,
          joinedAt: member.joined_at,
        },
      },
    ],
  };
}

const discordRuntime: OAuthProviderRuntime = {
  exchangeAuthorizationCode: exchangeDiscordAuthorizationCode,
  resolveIdentity: resolveDiscordIdentity,
  evaluateEntitlements: evaluateDiscordEntitlements,
};

const notImplementedRuntime: OAuthProviderRuntime = {
  async exchangeAuthorizationCode() {
    throw new Error("Provider callback exchange is not implemented yet.");
  },
  async resolveIdentity() {
    throw new Error("Provider identity resolution is not implemented yet.");
  },
  async evaluateEntitlements() {
    return { facts: [], snapshots: [] };
  },
};

export type OAuthRuntimeRegistry = Record<Provider, OAuthProviderRuntime>;

export function createOAuthRuntimeRegistry(): OAuthRuntimeRegistry {
  return {
    discord: discordRuntime,
    patreon: notImplementedRuntime,
    github: notImplementedRuntime,
    twitch: notImplementedRuntime,
    youtube: notImplementedRuntime,
  };
}
