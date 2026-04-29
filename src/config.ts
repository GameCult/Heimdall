import { providers, type Provider } from "./contracts.js";

export interface ProviderClientConfig {
  clientId?: string;
  clientSecret?: string;
}

export interface StorageConfig {
  backend: "memory" | "postgres";
  databaseUrl?: string;
  applySchemaOnStartup: boolean;
}

export interface HeimdallConfig {
  serviceName: string;
  host: string;
  port: number;
  publicBaseUrl: string;
  issuer: string;
  sessionTtlSeconds: number;
  stateTtlSeconds: number;
  completionTtlSeconds: number;
  signingPrivateKeyPem?: string;
  signingPrivateKeyPath?: string;
  bootstrapSigningPrivateKeyOnMissing: boolean;
  signingKeyId?: string;
  tokenEncryptionKeyBase64?: string;
  storage: StorageConfig;
  providers: Record<Provider, ProviderClientConfig>;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function readInt(envValue: string | undefined, fallback: number): number {
  if (!envValue) {
    return fallback;
  }

  const parsed = Number.parseInt(envValue, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function readBoolean(envValue: string | undefined, fallback: boolean): boolean {
  if (!envValue) {
    return fallback;
  }

  const normalized = envValue.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return fallback;
}

function readProviderConfig(env: NodeJS.ProcessEnv, provider: Provider): ProviderClientConfig {
  const prefix = `GC_ACCESS_PROVIDER_${provider.toUpperCase()}`;
  const config: ProviderClientConfig = {};
  const clientId = env[`${prefix}_CLIENT_ID`];
  const clientSecret = env[`${prefix}_CLIENT_SECRET`];

  if (clientId) {
    config.clientId = clientId;
  }

  if (clientSecret) {
    config.clientSecret = clientSecret;
  }

  return config;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): HeimdallConfig {
  const host = env.HOST ?? "127.0.0.1";
  const port = readInt(env.PORT, 4100);
  const publicBaseUrl = trimTrailingSlash(env.GC_ACCESS_BASE_URL ?? `http://${host}:${port}`);
  const issuer = trimTrailingSlash(env.GC_ACCESS_ISSUER ?? publicBaseUrl);
  const storageBackend =
    env.GC_ACCESS_STORAGE_BACKEND === "postgres" || env.GC_ACCESS_DATABASE_URL ? "postgres" : "memory";
  const providersConfig = Object.fromEntries(
    providers.map((provider) => [provider, readProviderConfig(env, provider)])
  ) as Record<Provider, ProviderClientConfig>;

  const config: HeimdallConfig = {
    serviceName: "heimdall",
    host,
    port,
    publicBaseUrl,
    issuer,
    sessionTtlSeconds: readInt(env.GC_ACCESS_SESSION_TTL_SECONDS, 3600),
    stateTtlSeconds: readInt(env.GC_ACCESS_STATE_TTL_SECONDS, 600),
    completionTtlSeconds: readInt(env.GC_ACCESS_COMPLETION_TTL_SECONDS, 300),
    bootstrapSigningPrivateKeyOnMissing: readBoolean(env.GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP, false),
    storage: {
      backend: storageBackend,
      applySchemaOnStartup: readBoolean(env.GC_ACCESS_APPLY_SCHEMA_ON_STARTUP, true),
    },
    providers: providersConfig,
  };

  const signingPrivateKeyPem = env.GC_ACCESS_SIGNING_PRIVATE_KEY_PEM?.replace(/\\n/g, "\n");
  if (signingPrivateKeyPem) {
    config.signingPrivateKeyPem = signingPrivateKeyPem;
  }

  if (env.GC_ACCESS_SIGNING_PRIVATE_KEY_PATH) {
    config.signingPrivateKeyPath = env.GC_ACCESS_SIGNING_PRIVATE_KEY_PATH;
  }

  if (env.GC_ACCESS_SIGNING_KEY_ID) {
    config.signingKeyId = env.GC_ACCESS_SIGNING_KEY_ID;
  }

  if (env.GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64) {
    config.tokenEncryptionKeyBase64 = env.GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64;
  }

  if (env.GC_ACCESS_DATABASE_URL) {
    config.storage.databaseUrl = env.GC_ACCESS_DATABASE_URL;
  }

  return config;
}
