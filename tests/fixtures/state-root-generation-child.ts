/**
 * One Idunn generation, as a process: it runs as the uid and gid its parent
 * gave it, under UMask=0007, and does what Heimdall does to a state root on a
 * pulse. The parent test spawns two of these under different uids that share
 * a group.
 *
 * argv: <role: first|next> <stateRoot> <fixtureDir>
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { loadConfig } from "../../src/config.js";
import { PublisherSequence, buildPresenceStatement } from "../../src/runtime-presence.js";
import { bundleFacts, openPresenceDescriptors } from "./presence-descriptors.js";
import { createHeimdallRuntimePulse, publishHeimdallVerseState } from "../../src/verse-state.js";

const [role, stateRoot, fixtureDir] = process.argv.slice(2) as [string, string, string];
process.umask(0o007);

const config = loadConfig({
  GC_ACCESS_BASE_URL: "https://heimdall.example.test",
  GC_ACCESS_DATA_ROOT: stateRoot,
});

async function publishPresence(): Promise<void> {
  const descriptors = openPresenceDescriptors(fixtureDir);
  try {
    const observedAtUnixMillis = Date.now();
    await buildPresenceStatement({
      bundle: bundleFacts,
      state: "warming",
      detail: "generation probe",
      boundEndpoint: null,
      writeLeaseSha256: null,
      observedAtUnixMillis,
      publisherSequence: new PublisherSequence().next(observedAtUnixMillis),
      providerHealthIdentityPath: path.join(stateRoot, "provider-health-identity.cc"),
      env: descriptors.env,
    });
  } finally {
    descriptors.close();
  }
}

if (role === "next") {
  // Generation N+1 reads what N left before it replaces it.
  const previous = await readFile(config.cultCachePath);
  if (previous.length === 0) throw new Error("previous generation's snapshot is empty");
}

await publishHeimdallVerseState(config, createHeimdallRuntimePulse(config));
await publishPresence();

if (role === "first") {
  // The 0600 counter the 2026-09-07 generation left behind. Nothing reads it
  // now; it stays as the stale fixture the next generation must live beside.
  await writeFile(path.join(stateRoot, "runtime-presence-sequence"), "41\n", { mode: 0o600 });
}
