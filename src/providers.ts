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
  /**
   * Seconds an access token lives when a token answer carries no usable
   * `expires_in` (RFC 6749 5.1 makes it RECOMMENDED, not required). An unknown
   * expiry is never stored: the credential would never come due for refresh.
   */
  defaultAccessTokenLifetimeSeconds: number;
  defaultScopes: string[];
  roles: ProviderRole[];
  clientIdEnv: string;
  clientSecretEnv: string;
  additionalAuthorizationParams?: Record<string, string>;
  /**
   * What a callback does with a (provider, subject) no account holds yet.
   * `mints_account` is every provider's behaviour before Google: the first
   * login makes an account. `requires_link` never mints: the identity
   * attaches only to the account a verified link start bound
   * (`link_account_id`), otherwise the callback refuses. Google is a second
   * door into a person who already has an account, so a first Google login
   * must not make a stranger of them.
   */
  firstLogin: "mints_account" | "requires_link";
  /** OpenID Connect: the callback verifies an id_token and uses PKCE (S256) and a nonce. */
  oidc?: true;
}

export const providerCatalog: Record<Provider, ProviderDescriptor> = {
  discord: {
    key: "discord",
    displayName: "Discord",
    authorizationEndpoint: "https://discord.com/oauth2/authorize",
    tokenEndpoint: "https://discord.com/api/v10/oauth2/token",
    tokenEndpointAuthMethod: "client_secret_basic",
    rotatesRefreshTokens: false,
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: ["identify", "guilds.members.read"],
    roles: ["identity", "entitlement"],
    firstLogin: "mints_account",
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
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: ["identity", "identity[email]"],
    roles: ["identity", "entitlement"],
    firstLogin: "mints_account",
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
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: ["read:user", "user:email"],
    roles: ["identity", "managed_credential"],
    firstLogin: "mints_account",
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
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: ["user:read:email"],
    roles: ["identity", "managed_credential"],
    firstLogin: "mints_account",
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
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: [
      "openid",
      "email",
      "profile",
      "https://www.googleapis.com/auth/youtube.readonly",
    ],
    roles: ["identity", "managed_credential"],
    firstLogin: "mints_account",
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
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: [
      "user-read-currently-playing",
      "user-read-playback-state",
      "user-modify-playback-state",
    ],
    roles: ["identity", "managed_credential"],
    firstLogin: "mints_account",
    clientIdEnv: "GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_SPOTIFY_CLIENT_SECRET_FILE",
  },
  google: {
    key: "google",
    displayName: "Google",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    tokenEndpointAuthMethod: "client_secret_post",
    rotatesRefreshTokens: false,
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: ["openid", "email", "profile"],
    roles: ["identity"],
    firstLogin: "requires_link",
    oidc: true,
    clientIdEnv: "GC_ACCESS_PROVIDER_GOOGLE_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_GOOGLE_CLIENT_SECRET_FILE",
    additionalAuthorizationParams: { prompt: "select_account" },
  },
  joystick: {
    key: "joystick",
    displayName: "Joystick",
    authorizationEndpoint: "https://joystick.tv/api/oauth/authorize",
    tokenEndpoint: "https://api.joystick.tv/api/oauth/token",
    tokenEndpointAuthMethod: "client_secret_basic",
    rotatesRefreshTokens: true,
    defaultAccessTokenLifetimeSeconds: 3600,
    defaultScopes: ["identity:read", "stream:read", "chat:read", "followers:read", "subscribers:read"],
    roles: ["identity", "managed_credential"],
    firstLogin: "mints_account",
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
  /** For an OIDC provider: the nonce, and the S256 challenge of the PKCE verifier. */
  oidc?: { nonce: string; codeChallenge: string };
}): string {
  const descriptor = providerCatalog[options.provider];
  const url = new URL(descriptor.authorizationEndpoint);
  const scopes = options.requestedScopes?.length ? options.requestedScopes : descriptor.defaultScopes;

  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", options.state);
  if (descriptor.oidc) {
    if (!options.oidc) {
      throw new Error(`${descriptor.displayName} is an OIDC provider: its authorization URL needs a nonce and a PKCE challenge.`);
    }
    url.searchParams.set("nonce", options.oidc.nonce);
    url.searchParams.set("code_challenge", options.oidc.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
  }

  for (const [key, value] of Object.entries(descriptor.additionalAuthorizationParams ?? {})) {
    url.searchParams.set(key, value);
  }

  return url.toString();
}

export function providerExpectedEnv(provider: Provider): string[] {
  const descriptor = providerCatalog[provider];
  return [descriptor.clientIdEnv, descriptor.clientSecretEnv];
}
