import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { encode } from "@msgpack/msgpack";
import { appSlugs, providers } from "./contracts.js";
import type { HeimdallConfig } from "./config.js";
import { buildHeimdallProviderAdvertisement } from "./verse-witness.js";

const STORE_FORMAT_VERSION = "cultcache.store.v1";

type CultCacheRecord = {
  key: string;
  schemaId: string;
  schemaName: string;
  schemaVersion: string;
  payload: unknown;
  storedAt: string;
};

export type HeimdallRuntimePulse = {
  updatedAt: string;
  configuredProviders: string[];
  storageBackend: string;
  appProfileCount: number;
  cultCachePath: string;
};

export function createHeimdallRuntimePulse(config: HeimdallConfig, updatedAt = new Date().toISOString()): HeimdallRuntimePulse {
  return {
    updatedAt,
    configuredProviders: providers.filter((provider) => {
      const entry = config.providers[provider];
      return Boolean(entry?.clientId && entry.clientSecret);
    }),
    storageBackend: config.storage.backend,
    appProfileCount: appSlugs.length,
    cultCachePath: config.cultCachePath,
  };
}

export async function publishHeimdallVerseState(config: HeimdallConfig, pulse: HeimdallRuntimePulse): Promise<void> {
  const records: CultCacheRecord[] = [
    {
      key: "heimdall",
      schemaId: "gamecult.eve.provider_advertisement.v1",
      schemaName: "gamecult.eve.provider_advertisement",
      schemaVersion: "gamecult.eve.provider_advertisement.v1",
      payload: buildRuntimeProviderAdvertisement(config, pulse),
      storedAt: pulse.updatedAt,
    },
    {
      key: "heimdall",
      schemaId: "heimdall.command_boundary.v1",
      schemaName: "heimdall.command_boundary",
      schemaVersion: "heimdall.command_boundary.v1",
      payload: buildCommandBoundary(config, pulse),
      storedAt: pulse.updatedAt,
    },
    {
      key: "heimdall",
      schemaId: "heimdall.transport_profile.v1",
      schemaName: "heimdall.transport_profile",
      schemaVersion: "heimdall.transport_profile.v1",
      payload: buildTransportProfile(config, pulse),
      storedAt: pulse.updatedAt,
    },
    {
      key: config.daemonId,
      schemaId: "idunn.daemon_health",
      schemaName: "idunn.daemon_health",
      schemaVersion: "idunn.daemon_health.v1",
      payload: buildDaemonHealthRecord(config, pulse),
      storedAt: pulse.updatedAt,
    },
  ];

  await writeCultCacheSnapshot(config.cultCachePath, records);
}

export function buildHeimdallHealthDetail(config: HeimdallConfig, pulse: HeimdallRuntimePulse): string {
  const healthTransport = config.idunnRudpHealth ? "CultNet/RUDP" : "CultCache witness only";
  return `Heimdall auth runtime active; storage=${pulse.storageBackend}; providers=${pulse.configuredProviders.length}/${providers.length}; apps=${pulse.appProfileCount}; healthTransport=${healthTransport}`;
}

function buildRuntimeProviderAdvertisement(config: HeimdallConfig, pulse: HeimdallRuntimePulse) {
  const advertisement = buildHeimdallProviderAdvertisement({ updatedAt: pulse.updatedAt });
  const witnessPath = path.relative(config.workspaceRoot, config.cultCachePath).replace(/\\/g, "/");
  return {
    ...advertisement,
    status: "daemon_live" as const,
    version: "daemon-live-v1",
    provider: {
      ...advertisement.provider,
      transport: config.idunnRudpHealth
        ? "CultCache witness store + daemon-published Idunn health over CultNet/RUDP."
        : "CultCache witness store; Idunn health still falls back to local witness publication.",
    },
    controlSurface: {
      ...advertisement.controlSurface,
      controls: {
        ...advertisement.controlSurface.controls,
        reason: "This runtime publication advertises provider shape and lifecycle boundaries. Auth mutation remains behind explicit Heimdall HTTP APIs.",
      },
    },
    runtime: {
      storageBackend: pulse.storageBackend,
      configuredProviders: pulse.configuredProviders,
      appProfileCount: pulse.appProfileCount,
      cultCachePath: witnessPath,
      idunnHealthContract: config.idunnHealthContract,
      idunnRudpHealth: config.idunnRudpHealth ?? null,
    },
  };
}

function buildCommandBoundary(config: HeimdallConfig, pulse: HeimdallRuntimePulse) {
  return {
    schema: "heimdall.command_boundary.v1",
    boundaryId: "heimdall",
    daemonId: config.daemonId,
    providerId: "heimdall",
    updatedAt: pulse.updatedAt,
    owner: "Heimdall auth runtime",
    lifecycleAuthority: "idunn.yggdrasil-source-app.deploy",
    healthPublication: {
      contract: config.idunnHealthContract,
      transport: config.idunnRudpHealth ? "cultnet.transport.rudp.v0" : "cultcache-store",
      publicationSource: config.idunnRudpHealth ? "daemon-published" : "daemon-published-cultcache",
      stateOwner: "Heimdall auth runtime",
    },
    commands: [],
    forbiddenWriters: [
      "Odin and Idunn may observe Heimdall boundary state but do not mutate auth/control-plane truth.",
      "HTTP /healthz, JWKS, discovery, systemd, and nginx routing are compatibility witnesses, not daemon truth.",
    ],
    compatibility: {
      httpHealth: "/healthz",
      jwks: "/.well-known/jwks.json",
      discovery: "/.well-known/heimdall-configuration",
      yggdrasilDeployLane: "E:/Projects/Odin/scripts/deploy-yggdrasil-heimdall.cmd",
      status: "fallback-witness-only",
    },
  };
}

function buildTransportProfile(config: HeimdallConfig, pulse: HeimdallRuntimePulse) {
  return {
    schema: "heimdall.transport_profile.v1",
    profileId: "heimdall",
    daemonId: config.daemonId,
    providerId: "heimdall",
    updatedAt: pulse.updatedAt,
    targetTransport: "cultnet.transport.rudp.v0",
    currentTransport: config.idunnRudpHealth
      ? "cultcache-redacted-witness + daemon-published-rudp-health + compatibility-http"
      : "cultcache-redacted-witness + compatibility.ssh-systemd-http",
    healthTransport: config.idunnRudpHealth ? "cultnet.transport.rudp.v0" : "cultcache-store",
    stateTransport: "cultcache-store",
    rendererTransport: "browser-http-jwks-discovery-lowering",
    storageBackend: pulse.storageBackend,
    cutLine: config.idunnRudpHealth
      ? "Heimdall now publishes daemon-owned witness state and Idunn health; systemd, /healthz, JWKS, discovery, and nginx routing can be demoted to deployment/debug witnesses once Odin consumes the typed store."
      : "Heimdall now publishes a daemon-owned witness store; the remaining transport debt is Idunn health publication over CultNet/RUDP and Odin ingestion of the typed witness surface.",
  };
}

function buildDaemonHealthRecord(config: HeimdallConfig, pulse: HeimdallRuntimePulse) {
  return [
    config.daemonId,
    "active",
    buildHeimdallHealthDetail(config, pulse),
    pulse.updatedAt,
    config.idunnHealthContract,
    config.idunnRudpHealth ? "daemon-published" : "daemon-published-cultcache",
    config.idunnRudpHealth ? "cultnet.transport.rudp.v0" : "cultcache-store",
  ];
}

async function writeCultCacheSnapshot(filePath: string, records: CultCacheRecord[]): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  const catalog = records.map((record) => [
    record.schemaId,
    record.schemaName,
    record.schemaVersion,
    record.schemaId,
    JSON.stringify({
      schemaName: record.schemaName,
      schemaVersion: record.schemaVersion,
      members: [],
    }),
    [record.schemaId],
    [],
  ]);
  const entries = records.map((record) => [record.key, record.schemaId, record.storedAt, encode(record.payload)]);
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;

  try {
    await writeFile(tempPath, encode([STORE_FORMAT_VERSION, catalog, entries]));
    await rename(tempPath, filePath);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => undefined);
    throw error;
  }
}
