import path from "node:path";
import { fileURLToPath } from "node:url";
import { appSlugs, providers, type AppSlug, type Provider } from "./contracts.js";

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
  privateCommandHost?: string;
  privateCommandPort?: number;
  workspaceRoot: string;
  dataRoot: string;
  cultCachePath: string;
  idunnWriteLeasePath?: string | undefined;
  idunnRuntimeBundlePath?: string | undefined;
  publicBaseUrl: string;
  issuer: string;
  daemonId: string;
  idunnRudpHealth: string | undefined;
  idunnHealthContract: string;
  odinCultMeshUri?: string;
  providerHealthIdentityPath: string;
  sessionTtlSeconds: number;
  refreshTtlSeconds: number;
  stateTtlSeconds: number;
  completionTtlSeconds: number;
  signingPrivateKeyPem?: string;
  signingPrivateKeyPath?: string;
  bootstrapSigningPrivateKeyOnMissing: boolean;
  signingKeyId?: string;
  tokenEncryptionKeyBase64?: string;
  appSharedSecrets: Partial<Record<AppSlug, string>>;
  appRuntimeIds?: Partial<Record<AppSlug, string[]>>;
  appBackendCallbacks: Partial<Record<AppSlug, string[]>>;
  bifrostPatronSupportEndpoint?: string;
  /** Operator secret gating runtime app registration. Unset means registration is closed. */
  appRegistrationSecret?: string;
  bifrostPatronSupportSecret?: string;
  storage: StorageConfig;
  providers: Record<Provider, ProviderClientConfig>;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

/**
 * Distance from a candidate's assigned HTTP port to its private command port.
 * Large enough that the derived ports cannot land inside the route's candidate
 * range and collide with another generation's HTTP listener.
 */
const PRIVATE_COMMAND_PORT_OFFSET = 1000;

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

/**
 * Parse `GAMECULT_IDUNN_CANDIDATE_BIND`, the loopback socket Idunn assigns to
 * a candidate incarnation. Returns undefined when unset, so a developer run
 * and a plain systemd unit keep using HOST/PORT.
 *
 * Loopback is required: the candidate is reached through Idunn's route, never
 * directly. A non-loopback or zero-port value means the launch inputs are
 * wrong, and starting anyway would expose an unrouted generation.
 */
function readIdunnCandidateBind(
  value: string | undefined
): { host: string; port: number } | undefined {
  if (!value) {
    return undefined;
  }

  const separator = value.lastIndexOf(":");
  if (separator <= 0) {
    throw new Error(`GAMECULT_IDUNN_CANDIDATE_BIND is not host:port: ${value}`);
  }

  const host = value.slice(0, separator).replace(/^\[|\]$/g, "");
  const port = Number(value.slice(separator + 1));

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`GAMECULT_IDUNN_CANDIDATE_BIND has no usable port: ${value}`);
  }

  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    throw new Error(`GAMECULT_IDUNN_CANDIDATE_BIND must be loopback: ${value}`);
  }

  return { host, port };
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

function readList(envValue: string | undefined): string[] {
  return envValue?.split(",").map((entry) => entry.trim()).filter(Boolean) ?? [];
}

function readOptionalString(envValue: string | undefined): string | undefined {
  const value = envValue?.trim();
  return value ? value : undefined;
}

/**
 * `--state-root PATH`, the directory Idunn assigns for this target's persistent
 * state. Idunn owns that location: the recipe declares state slots relative to
 * it and the operator binding supplies the absolute path, so the service is
 * told rather than choosing. Absent outside Idunn, where GC_ACCESS_DATA_ROOT
 * and the repo-local default still apply.
 */
function readStateRootArgument(argv: readonly string[]): string | undefined {
  const index = argv.indexOf("--state-root");
  if (index === -1) {
    return undefined;
  }

  const value = argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error("--state-root requires a path");
  }

  if (!path.isAbsolute(value)) {
    throw new Error(`--state-root must be absolute: ${value}`);
  }

  return value;
}

export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  argv: readonly string[] = process.argv.slice(2)
): HeimdallConfig {
  const sourceRoot = fileURLToPath(new URL("../", import.meta.url));
  const workspaceRoot = path.resolve(sourceRoot, "..");
  const stateRootArgument = readStateRootArgument(argv);
  // Where Heimdall listens and what Heimdall advertises are two different
  // authorities, and Idunn is the reason they must not be conflated. Under
  // Idunn a candidate and the incumbent run at once, so the candidate is told
  // which loopback socket to take; that address is ephemeral by design. The
  // advertised base URL builds the OAuth callback registered with each
  // provider, and cannot move.
  const candidateBind = readIdunnCandidateBind(env.GAMECULT_IDUNN_CANDIDATE_BIND);
  const host = candidateBind?.host ?? env.HOST ?? "127.0.0.1";
  const port = candidateBind?.port ?? readInt(env.PORT, 4100);

  if (candidateBind && !env.GC_ACCESS_BASE_URL) {
    throw new Error(
      "GC_ACCESS_BASE_URL is required when GAMECULT_IDUNN_CANDIDATE_BIND is set: " +
        "deriving the public base URL from an Idunn candidate socket would advertise " +
        "an ephemeral port as the provider-registered OAuth callback."
    );
  }

  const publicBaseUrl = trimTrailingSlash(env.GC_ACCESS_BASE_URL ?? `http://${host}:${port}`);
  const issuer = trimTrailingSlash(env.GC_ACCESS_ISSUER ?? publicBaseUrl);
  const dataRoot =
    stateRootArgument ?? env.GC_ACCESS_DATA_ROOT ?? path.join(workspaceRoot, ".heimdall-data");
  const storageBackend =
    env.GC_ACCESS_STORAGE_BACKEND === "postgres" || env.GC_ACCESS_DATABASE_URL ? "postgres" : "memory";
  const providersConfig = Object.fromEntries(
    providers.map((provider) => [provider, readProviderConfig(env, provider)])
  ) as Record<Provider, ProviderClientConfig>;
  const appSharedSecrets = Object.fromEntries(
    appSlugs
      .map((appSlug) => {
        const envKey = `GC_ACCESS_APP_${appSlug.toUpperCase()}_SHARED_SECRET`;
        return [appSlug, env[envKey]];
      })
      .filter(([, value]) => Boolean(value))
  ) as Partial<Record<AppSlug, string>>;
  const appBackendCallbacks = Object.fromEntries(
    appSlugs
      .map((appSlug) => {
        const envKey = `GC_ACCESS_APP_${appSlug.toUpperCase()}_BACKEND_CALLBACK_URLS`;
        return [appSlug, readList(env[envKey])];
      })
      .filter(([, value]) => Array.isArray(value) && value.length > 0)
  ) as Partial<Record<AppSlug, string[]>>;
  const appRuntimeIds = Object.fromEntries(
    appSlugs
      .map((appSlug) => {
        const envKey = `GC_ACCESS_APP_${appSlug.toUpperCase()}_RUNTIME_IDS`;
        return [appSlug, readList(env[envKey])];
      })
      .filter(([, value]) => Array.isArray(value) && value.length > 0)
  ) as Partial<Record<AppSlug, string[]>>;

  const config: HeimdallConfig = {
    serviceName: "heimdall",
    host,
    port,
    privateCommandHost: env.GC_ACCESS_PRIVATE_COMMAND_HOST ?? "127.0.0.1",
    // The private command plane is a second listener belonging to the same
    // generation as the HTTP one, so under Idunn its port has to move with the
    // candidate too. A fixed port makes two generations impossible: the
    // candidate collides with the incumbent on bind and the deployment dies
    // before it can warm. Offsetting from the assigned candidate port keeps
    // each generation's pair together and keeps the published command-boundary
    // endpoint truthful, since it reads this same value.
    privateCommandPort: candidateBind
      ? candidateBind.port + PRIVATE_COMMAND_PORT_OFFSET
      : readInt(env.GC_ACCESS_PRIVATE_COMMAND_PORT, 4101),
    workspaceRoot,
    dataRoot,
    idunnWriteLeasePath: env.GAMECULT_IDUNN_PROCESS_WRITE_LEASE,
    idunnRuntimeBundlePath: env.GAMECULT_IDUNN_RUNTIME_BUNDLE,
    cultCachePath: env.GC_ACCESS_CULTCACHE_PATH ?? path.join(dataRoot, "cultcache", "heimdall.service.cc"),
    publicBaseUrl,
    issuer,
    daemonId: env.GC_ACCESS_IDUNN_DAEMON ?? "yggdrasil-heimdall",
    idunnRudpHealth: readOptionalString(env.GC_ACCESS_IDUNN_RUDP_HEALTH),
    idunnHealthContract: env.GC_ACCESS_IDUNN_HEALTH_CONTRACT ?? "heimdall.cultnet-rudp-provider-health",
    providerHealthIdentityPath:
      env.GC_ACCESS_PROVIDER_HEALTH_IDENTITY_PATH ?? path.join(dataRoot, "provider-health-identity.cc"),
    sessionTtlSeconds: readInt(env.GC_ACCESS_SESSION_TTL_SECONDS, 3600),
    refreshTtlSeconds: readInt(env.GC_ACCESS_REFRESH_TTL_SECONDS, 60 * 60 * 24 * 30),
    stateTtlSeconds: readInt(env.GC_ACCESS_STATE_TTL_SECONDS, 600),
    completionTtlSeconds: readInt(env.GC_ACCESS_COMPLETION_TTL_SECONDS, 300),
    bootstrapSigningPrivateKeyOnMissing: readBoolean(env.GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP, false),
    appSharedSecrets,
    appRuntimeIds,
    appBackendCallbacks,
    storage: {
      backend: storageBackend,
      applySchemaOnStartup: readBoolean(env.GC_ACCESS_APPLY_SCHEMA_ON_STARTUP, true),
    },
    providers: providersConfig,
  };

  const odinCultMeshUri = readOptionalString(env.GC_ACCESS_ODIN_CULTMESH_URI);
  if (odinCultMeshUri) {
    config.odinCultMeshUri = odinCultMeshUri;
  }

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

  if (env.GC_ACCESS_BIFROST_PATRON_SUPPORT_ENDPOINT) {
    config.bifrostPatronSupportEndpoint = env.GC_ACCESS_BIFROST_PATRON_SUPPORT_ENDPOINT;
  }

  if (env.GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET) {
    if (env.GC_ACCESS_APP_REGISTRATION_SECRET) {
      config.appRegistrationSecret = env.GC_ACCESS_APP_REGISTRATION_SECRET;
    }
    config.bifrostPatronSupportSecret = env.GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET;
  }

  if (env.GC_ACCESS_DATABASE_URL) {
    config.storage.databaseUrl = env.GC_ACCESS_DATABASE_URL;
  }

  return config;
}
