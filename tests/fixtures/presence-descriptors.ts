/**
 * What Idunn hands a generation for runtime presence: the bundle directory, a
 * parent-only identity store and an activation seed, the last two passed as
 * descriptors named in LISTEN_FDNAMES. The bytes are the Rust owner's, copied
 * from CultLib (see idunn-runtime/README.md); every key in them is a test key.
 */
import { closeSync, openSync } from "node:fs";
import { chmod, copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";

import { IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME } from "cultnet-ts";

export const idunnRuntimeFixtures = path.join(import.meta.dirname, "idunn-runtime");

const FIXTURE_FILES = [
  "expected.cc",
  "activation.cc",
  "activation-key.seed",
  "provider-identity.credential",
  "machine-id",
] as const;

/** The machine id the fixture identity is bound to, in place of /etc/machine-id. */
export const fixtureMachineId = async (dir: string = idunnRuntimeFixtures): Promise<string> =>
  (await readFile(path.join(dir, "machine-id"), "utf8")).trim();

/** Copy the fixtures into `dir`, readable by any uid (the children run as others). */
export async function writePresenceFixtures(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  await chmod(dir, 0o755);
  for (const name of FIXTURE_FILES) {
    const target = path.join(dir, name);
    await copyFile(path.join(idunnRuntimeFixtures, name), target);
    await chmod(target, 0o644);
  }
}

/** Open both descriptors and name them the way systemd's LISTEN_FDNAMES does. */
export function openPresenceDescriptors(dir: string): { env: NodeJS.ProcessEnv; close: () => void } {
  const fds = [
    [openSync(path.join(dir, "provider-identity.credential"), "r"), "gamecult-runtime-presence-identity"],
    [openSync(path.join(dir, "activation-key.seed"), "r"), IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME],
  ] as const;
  const names: string[] = [];
  for (const [fd, name] of fds) {
    while (names.length < fd - 3) names.push(`pad-${names.length}`);
    names[fd - 3] = name;
  }
  return {
    env: { LISTEN_FDNAMES: names.join(":") },
    // The authority closes each descriptor it reads; this releases only what it did not.
    close: () =>
      fds.forEach(([fd]) => {
        try {
          closeSync(fd);
        } catch {
          // already closed by the reader
        }
      }),
  };
}
