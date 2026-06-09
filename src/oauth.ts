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
  refreshAccessToken?(options: {
    config: HeimdallConfig;
    refreshToken: string;
  }): Promise<OAuthTokenSet>;
  resolveIdentity(options: { config: HeimdallConfig; accessToken: string }): Promise<ResolvedIdentity>;
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

function normalizeScopes(scope: string | string[] | undefined): string[] {
  if (Array.isArray(scope)) {
    return scope.map((value) => value.trim()).filter(Boolean);
  }

  return scope?.split(/\s+/).filter(Boolean) ?? [];
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
    scope?: string | string[];
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
    scope: normalizeScopes(tokenResponse.scope),
    expiresAt: new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString(),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  return tokenSet;
}

async function refreshDiscordAccessToken(options: {
  config: HeimdallConfig;
  refreshToken: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.discord;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Discord OAuth is not fully configured.");
  }

  const basicAuth = Buffer.from(`${providerConfig.clientId}:${providerConfig.clientSecret}`).toString("base64");
  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in: number;
    scope?: string | string[];
  }>(
    "https://discord.com/api/v10/oauth2/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: options.refreshToken,
      }),
    },
    "Discord token refresh failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    expiresAt: new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString(),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  return tokenSet;
}

async function exchangePatreonAuthorizationCode(options: {
  config: HeimdallConfig;
  code: string;
  redirectUri: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.patreon;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Patreon OAuth is not fully configured.");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: options.code,
    client_id: providerConfig.clientId,
    client_secret: providerConfig.clientSecret,
    redirect_uri: options.redirectUri,
  });
  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://www.patreon.com/api/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    },
    "Patreon token exchange failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function refreshPatreonAccessToken(options: {
  config: HeimdallConfig;
  refreshToken: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.patreon;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Patreon OAuth is not fully configured.");
  }

  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://www.patreon.com/api/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: options.refreshToken,
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
      }),
    },
    "Patreon token refresh failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function exchangeTwitchAuthorizationCode(options: {
  config: HeimdallConfig;
  code: string;
  redirectUri: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.twitch;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Twitch OAuth is not fully configured.");
  }

  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://id.twitch.tv/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
        code: options.code,
        grant_type: "authorization_code",
        redirect_uri: options.redirectUri,
      }),
    },
    "Twitch token exchange failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function refreshTwitchAccessToken(options: {
  config: HeimdallConfig;
  refreshToken: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.twitch;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Twitch OAuth is not fully configured.");
  }

  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://id.twitch.tv/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
        grant_type: "refresh_token",
        refresh_token: options.refreshToken,
      }),
    },
    "Twitch token refresh failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function exchangeYouTubeAuthorizationCode(options: {
  config: HeimdallConfig;
  code: string;
  redirectUri: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.youtube;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("YouTube OAuth is not fully configured.");
  }

  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
    id_token?: string;
  }>(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
        code: options.code,
        grant_type: "authorization_code",
        redirect_uri: options.redirectUri,
      }),
    },
    "YouTube token exchange failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function refreshYouTubeAccessToken(options: {
  config: HeimdallConfig;
  refreshToken: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.youtube;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("YouTube OAuth is not fully configured.");
  }

  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
        grant_type: "refresh_token",
        refresh_token: options.refreshToken,
      }),
    },
    "YouTube token refresh failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function exchangeSpotifyAuthorizationCode(options: {
  config: HeimdallConfig;
  code: string;
  redirectUri: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.spotify;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Spotify OAuth is not fully configured.");
  }

  const basicAuth = Buffer.from(`${providerConfig.clientId}:${providerConfig.clientSecret}`).toString("base64");
  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://accounts.spotify.com/api/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: options.code,
        redirect_uri: options.redirectUri,
      }),
    },
    "Spotify token exchange failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
  }

  return tokenSet;
}

async function refreshSpotifyAccessToken(options: {
  config: HeimdallConfig;
  refreshToken: string;
}): Promise<OAuthTokenSet> {
  const providerConfig = options.config.providers.spotify;
  if (!providerConfig.clientId || !providerConfig.clientSecret) {
    throw new Error("Spotify OAuth is not fully configured.");
  }

  const basicAuth = Buffer.from(`${providerConfig.clientId}:${providerConfig.clientSecret}`).toString("base64");
  const tokenResponse = await fetchJson<{
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string | string[];
  }>(
    "https://accounts.spotify.com/api/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: options.refreshToken,
      }),
    },
    "Spotify token refresh failed"
  );

  const tokenSet: OAuthTokenSet = {
    accessToken: tokenResponse.access_token,
    tokenType: tokenResponse.token_type,
    scope: normalizeScopes(tokenResponse.scope),
    raw: tokenResponse as unknown as Record<string, unknown>,
  };

  if (tokenResponse.refresh_token) {
    tokenSet.refreshToken = tokenResponse.refresh_token;
  }

  if (tokenResponse.expires_in) {
    tokenSet.expiresAt = new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString();
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

export async function fetchPatreonIdentity(accessToken: string): Promise<Record<string, unknown>> {
  const url = new URL("https://www.patreon.com/api/oauth2/v2/identity");
  url.searchParams.set("include", "memberships.currently_entitled_tiers,memberships.campaign");
  url.searchParams.set("fields[user]", "email,full_name,image_url,thumb_url,url,vanity");
  url.searchParams.set(
    "fields[member]",
    "currently_entitled_amount_cents,last_charge_date,last_charge_status,patron_status,pledge_relationship_start"
  );
  url.searchParams.set("fields[tier]", "title");
  url.searchParams.set("fields[campaign]", "creation_name,currency,url");

  return fetchJson<Record<string, unknown>>(
    url,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
    "Patreon identity lookup failed"
  );
}

function patreonUserAttributes(payload: Record<string, unknown>): Record<string, unknown> {
  const data = payload.data;
  if (typeof data !== "object" || data === null) {
    return {};
  }

  const attributes = (data as Record<string, unknown>).attributes;
  return typeof attributes === "object" && attributes !== null ? attributes as Record<string, unknown> : {};
}

async function resolvePatreonIdentity(options: { accessToken: string }): Promise<ResolvedIdentity> {
  const profile = await fetchPatreonIdentity(options.accessToken);
  const data = profile.data;
  if (typeof data !== "object" || data === null || typeof (data as Record<string, unknown>).id !== "string") {
    throw new Error("Patreon identity response did not include a user id.");
  }

  const attributes = patreonUserAttributes(profile);
  const displayName = typeof attributes.full_name === "string" ? attributes.full_name : undefined;
  const vanity = typeof attributes.vanity === "string" ? attributes.vanity : undefined;
  const email = typeof attributes.email === "string" ? attributes.email : undefined;
  const imageUrl =
    typeof attributes.image_url === "string"
      ? attributes.image_url
      : typeof attributes.thumb_url === "string"
        ? attributes.thumb_url
        : undefined;

  const identity: ResolvedIdentity = {
    provider: "patreon",
    providerUserId: (data as Record<string, unknown>).id as string,
    profile,
  };

  if (vanity) {
    identity.username = vanity;
  }

  if (displayName) {
    identity.displayName = displayName;
  }

  if (email) {
    identity.primaryEmail = email;
  }

  if (imageUrl) {
    identity.avatarUrl = imageUrl;
  }

  return identity;
}

async function resolveTwitchIdentity(options: {
  config: HeimdallConfig;
  accessToken: string;
}): Promise<ResolvedIdentity> {
  const providerConfig = options.config.providers.twitch;
  const payload = await fetchJson<{
    data?: Array<{
      id: string;
      login?: string;
      display_name?: string;
      profile_image_url?: string;
      email?: string;
    }>;
  }>(
    "https://api.twitch.tv/helix/users",
    {
      headers: {
        Authorization: `Bearer ${options.accessToken}`,
        "Client-Id": providerConfig.clientId ?? "",
      },
    },
    "Twitch identity lookup failed"
  );
  const user = payload.data?.[0];

  if (!user?.id) {
    throw new Error("Twitch identity response did not include a user id.");
  }

  const identity: ResolvedIdentity = {
    provider: "twitch",
    providerUserId: user.id,
    profile: user as unknown as Record<string, unknown>,
  };

  if (user.login) {
    identity.username = user.login;
  }

  if (user.display_name) {
    identity.displayName = user.display_name;
  }

  if (user.email) {
    identity.primaryEmail = user.email;
  }

  if (user.profile_image_url) {
    identity.avatarUrl = user.profile_image_url;
  }

  return identity;
}

async function resolveYouTubeIdentity(options: { accessToken: string }): Promise<ResolvedIdentity> {
  const channelUrl = new URL("https://www.googleapis.com/youtube/v3/channels");
  channelUrl.searchParams.set("part", "snippet");
  channelUrl.searchParams.set("mine", "true");
  const channelResponse = await fetch(channelUrl, {
    headers: {
      Authorization: `Bearer ${options.accessToken}`,
    },
  });

  if (channelResponse.ok) {
    const payload = (await channelResponse.json()) as {
      items?: Array<{
        id: string;
        snippet?: {
          title?: string;
          customUrl?: string;
          thumbnails?: {
            default?: { url?: string };
            medium?: { url?: string };
            high?: { url?: string };
          };
        };
      }>;
    };
    const channel = payload.items?.[0];

    if (channel?.id) {
      const identity: ResolvedIdentity = {
        provider: "youtube",
        providerUserId: channel.id,
        username: channel.snippet?.customUrl ?? channel.snippet?.title ?? channel.id,
        displayName: channel.snippet?.title ?? channel.id,
        profile: channel as unknown as Record<string, unknown>,
      };
      const avatarUrl =
        channel.snippet?.thumbnails?.high?.url ??
        channel.snippet?.thumbnails?.medium?.url ??
        channel.snippet?.thumbnails?.default?.url;
      if (avatarUrl) {
        identity.avatarUrl = avatarUrl;
      }
      return identity;
    }
  }

  const userInfo = await fetchJson<{
    sub?: string;
    name?: string;
    picture?: string;
    email?: string;
  }>(
    "https://openidconnect.googleapis.com/v1/userinfo",
    {
      headers: {
        Authorization: `Bearer ${options.accessToken}`,
      },
    },
    "Google identity lookup failed"
  );

  if (!userInfo.sub) {
    throw new Error("Google identity response did not include a subject.");
  }

  const identity: ResolvedIdentity = {
    provider: "youtube",
    providerUserId: userInfo.sub,
    username: userInfo.email ?? userInfo.name ?? userInfo.sub,
    displayName: userInfo.name ?? userInfo.email ?? userInfo.sub,
    profile: userInfo as unknown as Record<string, unknown>,
  };

  if (userInfo.email) {
    identity.primaryEmail = userInfo.email;
  }

  if (userInfo.picture) {
    identity.avatarUrl = userInfo.picture;
  }

  return identity;
}

async function resolveSpotifyIdentity(options: { accessToken: string }): Promise<ResolvedIdentity> {
  const profile = await fetchJson<{
    id?: string;
    display_name?: string;
    email?: string;
    images?: Array<{ url?: string }>;
    uri?: string;
  }>(
    "https://api.spotify.com/v1/me",
    {
      headers: {
        Authorization: `Bearer ${options.accessToken}`,
      },
    },
    "Spotify identity lookup failed"
  );

  if (!profile.id) {
    throw new Error("Spotify identity response did not include a user id.");
  }

  const identity: ResolvedIdentity = {
    provider: "spotify",
    providerUserId: profile.id,
    username: profile.id,
    displayName: profile.display_name ?? profile.id,
    profile: profile as unknown as Record<string, unknown>,
  };

  if (profile.email) {
    identity.primaryEmail = profile.email;
  }

  const avatarUrl = profile.images?.find((image) => image.url)?.url;
  if (avatarUrl) {
    identity.avatarUrl = avatarUrl;
  }

  return identity;
}

async function evaluateDiscordEntitlements(options: {
  config: HeimdallConfig;
  callback: OAuthCallbackContext;
  tokenSet: OAuthTokenSet;
}): Promise<EntitlementEvaluation> {
  const policy = options.callback.entitlementPolicy;
  if (!policy || policy.kind !== "discord_role_access") {
    return { facts: [], snapshots: [] };
  }
  const appSlug = options.callback.appSlug;
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
          scope: `${appSlug}:discord_member:${guildId}`,
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
        scope: `${appSlug}:discord_role_access:${guildId}`,
        evaluatedAt: new Date().toISOString(),
        isAllowed: matchedRoles.length > 0,
        reasonCode: matchedRoles.length > 0 ? "matched_role" : "missing_role",
        reasonDetail:
          matchedRoles.length > 0
            ? `Matched a configured ${appSlug} access role.`
            : allowedRoleIds.length
              ? `User is in the guild but lacks the configured ${appSlug} access role.`
              : `${appSlug} did not supply any Discord role ids in its entitlement policy.`,
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

function includedPatreonMembers(profile: Record<string, unknown>): Array<Record<string, unknown>> {
  const included = profile.included;
  if (!Array.isArray(included)) {
    return [];
  }

  return included.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === "object" &&
      entry !== null &&
      (entry as Record<string, unknown>).type === "member"
  );
}

function includedPatreonTierById(profile: Record<string, unknown>): Map<string, Record<string, unknown>> {
  const included = profile.included;
  const tiers = new Map<string, Record<string, unknown>>();
  if (!Array.isArray(included)) {
    return tiers;
  }

  for (const entry of included) {
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const record = entry as Record<string, unknown>;
    if (record.type === "tier" && typeof record.id === "string") {
      tiers.set(record.id, record);
    }
  }

  return tiers;
}

function relatedPatreonTierIds(member: Record<string, unknown>): string[] {
  const relationships = member.relationships;
  if (typeof relationships !== "object" || relationships === null) {
    return [];
  }

  const tiers = (relationships as Record<string, unknown>).currently_entitled_tiers;
  if (typeof tiers !== "object" || tiers === null) {
    return [];
  }

  const data = (tiers as Record<string, unknown>).data;
  if (!Array.isArray(data)) {
    return [];
  }

  return data
    .map((entry) => {
      if (typeof entry !== "object" || entry === null) {
        return undefined;
      }
      const record = entry as Record<string, unknown>;
      return record.type === "tier" && typeof record.id === "string" ? record.id : undefined;
    })
    .filter((id): id is string => id !== undefined);
}

function relatedPatreonCampaignId(member: Record<string, unknown>): string | undefined {
  const relationships = member.relationships;
  if (typeof relationships !== "object" || relationships === null) {
    return undefined;
  }

  const campaign = (relationships as Record<string, unknown>).campaign;
  if (typeof campaign !== "object" || campaign === null) {
    return undefined;
  }

  const data = (campaign as Record<string, unknown>).data;
  if (typeof data !== "object" || data === null) {
    return undefined;
  }

  const record = data as Record<string, unknown>;
  return record.type === "campaign" && typeof record.id === "string" ? record.id : undefined;
}

function includedPatreonCampaignById(profile: Record<string, unknown>): Map<string, Record<string, unknown>> {
  const included = profile.included;
  const campaigns = new Map<string, Record<string, unknown>>();
  if (!Array.isArray(included)) {
    return campaigns;
  }

  for (const entry of included) {
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const record = entry as Record<string, unknown>;
    if (record.type === "campaign" && typeof record.id === "string") {
      campaigns.set(record.id, record);
    }
  }

  return campaigns;
}

function patreonTierTitle(tier: Record<string, unknown>): string | undefined {
  const attributes = tier.attributes;
  if (typeof attributes !== "object" || attributes === null) {
    return undefined;
  }

  const title = (attributes as Record<string, unknown>).title;
  return typeof title === "string" ? title : undefined;
}

function patreonMemberAttributes(member: Record<string, unknown>): Record<string, unknown> {
  const attributes = member.attributes;
  return typeof attributes === "object" && attributes !== null ? attributes as Record<string, unknown> : {};
}

function patreonMemberIsActivePaid(attributes: Record<string, unknown>): boolean {
  const patronStatus = attributes.patron_status;
  const lastChargeStatus = attributes.last_charge_status;
  return patronStatus === "active_patron" && (lastChargeStatus === undefined || lastChargeStatus === null || lastChargeStatus === "Paid");
}

export interface PatreonMembershipSummary {
  memberId: string;
  campaignId?: string;
  campaignCurrency?: string;
  tierTitles: string[];
  patronStatus?: string;
  lastChargeStatus?: string;
  currentlyEntitledAmountCents: number;
  lastChargeDate?: string;
  pledgeRelationshipStart?: string;
  isActivePaid: boolean;
}

export function summarizePatreonMemberships(profile: Record<string, unknown>): PatreonMembershipSummary[] {
  const tiersById = includedPatreonTierById(profile);
  const campaignsById = includedPatreonCampaignById(profile);

  return includedPatreonMembers(profile)
    .filter((member) => typeof member.id === "string")
    .map((member) => {
      const attributes = patreonMemberAttributes(member);
      const campaignId = relatedPatreonCampaignId(member);
      const campaign = campaignId ? campaignsById.get(campaignId) : undefined;
      const campaignAttributes =
        campaign && typeof campaign.attributes === "object" && campaign.attributes !== null
          ? campaign.attributes as Record<string, unknown>
          : {};
      const campaignCurrency =
        typeof campaignAttributes.currency === "string"
          ? campaignAttributes.currency
          : undefined;
      const currentlyEntitledAmountCents =
        typeof attributes.currently_entitled_amount_cents === "number" ? attributes.currently_entitled_amount_cents : 0;
      const patronStatus = typeof attributes.patron_status === "string" ? attributes.patron_status : undefined;
      const lastChargeStatus =
        typeof attributes.last_charge_status === "string" ? attributes.last_charge_status : undefined;
      const lastChargeDate = typeof attributes.last_charge_date === "string" ? attributes.last_charge_date : undefined;
      const pledgeRelationshipStart =
        typeof attributes.pledge_relationship_start === "string" ? attributes.pledge_relationship_start : undefined;
      const tierTitles = relatedPatreonTierIds(member)
        .map((tierId) => tiersById.get(tierId))
        .filter((tier): tier is Record<string, unknown> => tier !== undefined)
        .map((tier) => patreonTierTitle(tier))
        .filter((title): title is string => title !== undefined);

      return {
        memberId: member.id as string,
        ...(campaignId !== undefined ? { campaignId } : {}),
        ...(campaignCurrency !== undefined ? { campaignCurrency } : {}),
        tierTitles,
        ...(patronStatus !== undefined ? { patronStatus } : {}),
        ...(lastChargeStatus !== undefined ? { lastChargeStatus } : {}),
        currentlyEntitledAmountCents,
        ...(lastChargeDate !== undefined ? { lastChargeDate } : {}),
        ...(pledgeRelationshipStart !== undefined ? { pledgeRelationshipStart } : {}),
        isActivePaid: patreonMemberIsActivePaid(attributes),
      };
    });
}

async function evaluatePatreonEntitlements(options: {
  callback: OAuthCallbackContext;
  tokenSet: OAuthTokenSet;
}): Promise<EntitlementEvaluation> {
  const policy = options.callback.entitlementPolicy;
  if (!policy || policy.kind !== "patreon_membership_access") {
    return { facts: [], snapshots: [] };
  }
  const appSlug = options.callback.appSlug;

  const profile = await fetchPatreonIdentity(options.tokenSet.accessToken);
  const members = summarizePatreonMemberships(profile);
  const activeMembers = members.filter(
    (member) => member.isActivePaid && member.tierTitles.includes(policy.requiredTierTitle)
  );
  const isAllowed = activeMembers.length > 0;

  return {
    facts: isAllowed ? [entitlementFacts.appAccess] : [],
    snapshots: [
      {
        accountId: options.callback.accountId,
        provider: "patreon",
        scope: `${appSlug}:patreon_membership_access`,
        evaluatedAt: new Date().toISOString(),
        isAllowed,
        reasonCode: isAllowed ? "active_membership" : members.length ? "inactive_membership" : "missing_membership",
        reasonDetail: isAllowed
          ? `Matched an active Patreon membership for ${appSlug} access.`
          : members.length
            ? "Patreon membership data was present but did not meet the active access policy."
            : `Patreon did not return a membership matching the ${appSlug} access policy.`,
        rawSummaryJson: {
          requiredTierTitle: policy.requiredTierTitle,
          memberCount: members.length,
          entitledTierCount: new Set(members.flatMap((member) => member.tierTitles)).size,
          matchingMemberCount: activeMembers.length,
        },
      },
    ],
  };
}

const discordRuntime: OAuthProviderRuntime = {
  exchangeAuthorizationCode: exchangeDiscordAuthorizationCode,
  refreshAccessToken: refreshDiscordAccessToken,
  resolveIdentity: resolveDiscordIdentity,
  evaluateEntitlements: evaluateDiscordEntitlements,
};

const patreonRuntime: OAuthProviderRuntime = {
  exchangeAuthorizationCode: exchangePatreonAuthorizationCode,
  refreshAccessToken: refreshPatreonAccessToken,
  resolveIdentity: resolvePatreonIdentity,
  evaluateEntitlements: evaluatePatreonEntitlements,
};

const twitchRuntime: OAuthProviderRuntime = {
  exchangeAuthorizationCode: exchangeTwitchAuthorizationCode,
  refreshAccessToken: refreshTwitchAccessToken,
  resolveIdentity: resolveTwitchIdentity,
  async evaluateEntitlements() {
    return { facts: [], snapshots: [] };
  },
};

const youtubeRuntime: OAuthProviderRuntime = {
  exchangeAuthorizationCode: exchangeYouTubeAuthorizationCode,
  refreshAccessToken: refreshYouTubeAccessToken,
  resolveIdentity: resolveYouTubeIdentity,
  async evaluateEntitlements() {
    return { facts: [], snapshots: [] };
  },
};

const spotifyRuntime: OAuthProviderRuntime = {
  exchangeAuthorizationCode: exchangeSpotifyAuthorizationCode,
  refreshAccessToken: refreshSpotifyAccessToken,
  resolveIdentity: resolveSpotifyIdentity,
  async evaluateEntitlements() {
    return { facts: [], snapshots: [] };
  },
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
    patreon: patreonRuntime,
    github: notImplementedRuntime,
    twitch: twitchRuntime,
    youtube: youtubeRuntime,
    spotify: spotifyRuntime,
  };
}
