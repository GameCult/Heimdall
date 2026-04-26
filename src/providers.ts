import { type Provider } from "./contracts.js";

export type ProviderRole = "identity" | "entitlement" | "managed_credential";

export interface ProviderDescriptor {
  key: Provider;
  displayName: string;
  authorizationEndpoint: string;
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
    defaultScopes: ["identify", "email", "guilds.members.read"],
    roles: ["identity", "entitlement"],
    clientIdEnv: "GC_ACCESS_PROVIDER_DISCORD_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET",
  },
  patreon: {
    key: "patreon",
    displayName: "Patreon",
    authorizationEndpoint: "https://www.patreon.com/oauth2/authorize",
    defaultScopes: ["identity", "identity[email]", "campaigns.members"],
    roles: ["identity", "entitlement"],
    clientIdEnv: "GC_ACCESS_PROVIDER_PATREON_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_PATREON_CLIENT_SECRET",
  },
  github: {
    key: "github",
    displayName: "GitHub",
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    defaultScopes: ["read:user", "user:email"],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_GITHUB_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_GITHUB_CLIENT_SECRET",
  },
  twitch: {
    key: "twitch",
    displayName: "Twitch",
    authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
    defaultScopes: ["user:read:email"],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_TWITCH_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_TWITCH_CLIENT_SECRET",
  },
  youtube: {
    key: "youtube",
    displayName: "YouTube",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    defaultScopes: [
      "openid",
      "email",
      "profile",
      "https://www.googleapis.com/auth/youtube.readonly",
    ],
    roles: ["identity", "managed_credential"],
    clientIdEnv: "GC_ACCESS_PROVIDER_YOUTUBE_CLIENT_ID",
    clientSecretEnv: "GC_ACCESS_PROVIDER_YOUTUBE_CLIENT_SECRET",
    additionalAuthorizationParams: {
      access_type: "offline",
      include_granted_scopes: "true",
      prompt: "consent",
    },
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
