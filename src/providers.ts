import { type Provider } from "./contracts.js";

export type ProviderRole = "identity" | "entitlement" | "managed_credential";

export interface ProviderDescriptor {
  key: Provider;
  displayName: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  /** RFC 7591 names: how the client authenticates at the token endpoint. */
  tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post";
  /** True when a refresh response replaces the refresh token and the old one dies. */
  rotatesRefreshTokens: boolean;
  defaultScopes: string[];
  roles: ProviderRole[];
  clientIdEnv: string;
  clientSecretEnv: string;
  additionalAuthorizationParams?: Record<string, string>;
}

export const providerCatalog: Record<Provider, ProviderDescriptor> = {
  discord: {
    key: "discord",
    displayName: "Discord",
    authorizationEndpoint: "https://discord.com/oauth2/authorize",
    tokenEndpoint: "https://discord.com/api/v10/oauth2/token",
    tokenEndpointAuthMethod: "client_secret_basic",
    rotatesRefreshTokens: false,
    defaultScopes: ["identify", "guilds.members.read"],
    roles: ["identity", "entitlement"],
    clientIdEnv: "GC_ACCESS_PROVIDER_DISCORD_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET_FILE",
  },
  patreon: {
    key: "patreon",
    displayName: "Patreon",
    authorizationEndpoint: "https://www.patreon.com/oauth2/authorize",
    tokenEndpoint: "https://www.patreon.com/api/oauth2/token",
    tokenEndpointAuthMethod: "client_secret_post",
    rotatesRefreshTokens: false,
    defaultScopes: ["identity", "identity[email]"],
    roles: ["identity", "entitlement"],
    clientIdEnv: "GC_ACCESS_PROVIDER_PATREON_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_PATREON_CLIENT_SECRET_FILE",
  },
  github: {
    key: "github",
    displayName: "GitHub",
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    tokenEndpointAuthMethod: "client_secret_post",
    rotatesRefreshTokens: false,
    defaultScopes: ["read:user", "user:email"],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_GITHUB_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_GITHUB_CLIENT_SECRET_FILE",
  },
  twitch: {
    key: "twitch",
    displayName: "Twitch",
    authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
    tokenEndpoint: "https://id.twitch.tv/oauth2/token",
    tokenEndpointAuthMethod: "client_secret_post",
    rotatesRefreshTokens: false,
    defaultScopes: ["user:read:email"],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_TWITCH_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_TWITCH_CLIENT_SECRET_FILE",
  },
  youtube: {
    key: "youtube",
    displayName: "YouTube",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    tokenEndpointAuthMethod: "client_secret_post",
    rotatesRefreshTokens: false,
    defaultScopes: [
      "openid",
      "email",
      "profile",
      "https://www.googleapis.com/auth/youtube.readonly",
    ],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_YOUTUBE_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_YOUTUBE_CLIENT_SECRET_FILE",
    additionalAuthorizationParams: {
      access_type: "offline",
      include_granted_scopes: "true",
      prompt: "consent",
    },
  },
  spotify: {
    key: "spotify",
    displayName: "Spotify",
    authorizationEndpoint: "https://accounts.spotify.com/authorize",
    tokenEndpoint: "https://accounts.spotify.com/api/token",
    tokenEndpointAuthMethod: "client_secret_basic",
    rotatesRefreshTokens: false,
    defaultScopes: [
      "user-read-currently-playing",
      "user-read-playback-state",
      "user-modify-playback-state",
    ],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_SECRET_FILE",
  },
  joystick: {
    key: "joystick",
    displayName: "Joystick",
    authorizationEndpoint: "https://joystick.tv/api/oauth/authorize",
    tokenEndpoint: "https://api.joystick.tv/api/oauth/token",
    tokenEndpointAuthMethod: "client_secret_basic",
    rotatesRefreshTokens: true,
    defaultScopes: ["identity:read", "stream:read", "chat:read", "followers:read", "subscribers:read"],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_JOYSTICK_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_JOYSTICK_CLIENT_SECRET_FILE",
  },
};

export function buildAuthorizationUrl(options: {
  provider: Provider;
  clientId: string;
  redirectUri: string;
  state: string;
  requestedScopes: string[] | undefined;
}): string {
  const descriptor = providerCatalog[options.provider];
  const url = new URL(descriptor.authorizationEndpoint);
  const scopes = options.requestedScopes?.length ? options.requestedScopes : descriptor.defaultScopes;

  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", options.state);

  for (const [key, value] of Object.entries(descriptor.additionalAuthorizationParams ?? {})) {
    url.searchParams.set(key, value);
  }

  return url.toString();
}

export function providerExpectedEnv(provider: Provider): string[] {
  const descriptor = providerCatalog[provider];
  return [descriptor.clientIdEnv, descriptor.clientSecretEnv];
}
