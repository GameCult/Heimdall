/**
 * What Idunn hands a generation for runtime presence: a parent-only identity
 * store and an activation seed, passed as descriptors named in LISTEN_FDNAMES.
 * Every key here is generated for the test or a canary byte pattern.
 */
import { closeSync, openSync } from "node:fs";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { encode } from "@msgpack/msgpack";
import { SingleFileMessagePackBackingStore } from "@gamecult/cultcache-ts";
import { IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME } from "cultnet-ts";

import { openOrEnrollProviderHealthIdentity } from "../../src/provider-health-identity.js";
import type { RuntimeBundleFacts } from "../../src/runtime-presence.js";

export const bundleFacts: RuntimeBundleFacts = {
  target: "heimdall",
  planId: "plan-1",
  incarnationId: "incarnation-1",
  sealedReleaseId: "release-1",
  runtimeId: "runtime-1",
  runtimeInstanceId: "instance-1",
  expectedProjectionSha256: "sha256-projection",
  activationWitnessSha256: "sha256-witness",
  activationSignerIdentityId: "activation-signer",
  stateSchemaGeneration: null,
  stateContractSha256: null,
  capabilities: [],
  healthContract: "health-contract",
};

/** Write both stores into `dir`, readable by any uid (the children run as others). */
export async function writePresenceFixtures(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  await chmod(dir, 0o755);
  const enrolled = path.join(dir, "enrolled.cc");
  await openOrEnrollProviderHealthIdentity(enrolled);
  const [record] = await new SingleFileMessagePackBackingStore(enrolled).pullAll();
  // Re-wrapped the way cultcache-rs writes a store, which is how Idunn writes it.
  await writeFile(
    path.join(dir, "runtime-presence-identity.cc"),
    encode([
      [
        "gamecult-provider-health-identity",
        "gamecult.provider_health_identity.private.v1",
        record!.payload,
        "2026-09-06T00:00:00.000Z",
        "gamecult.provider_health_identity.private.v1",
      ],
    ]),
    { mode: 0o644 }
  );
  await writeFile(path.join(dir, "activation-seed"), Buffer.alloc(32, 7), { mode: 0o644 });
}

/** Open both descriptors and name them the way systemd's LISTEN_FDNAMES does. */
export function openPresenceDescriptors(dir: string): { env: NodeJS.ProcessEnv; close: () => void } {
  const fds = [
    [openSync(path.join(dir, "runtime-presence-identity.cc"), "r"), "gamecult-runtime-presence-identity"],
    [openSync(path.join(dir, "activation-seed"), "r"), IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME],
  ] as const;
  const names: string[] = [];
  for (const [fd, name] of fds) {
    while (names.length < fd - 3) names.push(`pad-${names.length}`);
    names[fd - 3] = name;
  }
  return {
    env: { LISTEN_FDNAMES: names.join(":") },
    close: () => fds.forEach(([fd]) => closeSync(fd)),
  };
}
