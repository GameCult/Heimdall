import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { PublisherSequence, buildPresenceStatement } from "../src/runtime-presence.js";
import { bundleFacts, openPresenceDescriptors, writePresenceFixtures } from "./fixtures/presence-descriptors.js";

const machineIdAvailable = await readFile("/etc/machine-id", "utf8").then(
  () => true,
  () => false
);

describe("PublisherSequence", () => {
  it("starts at the observed millis", () => {
    expect(new PublisherSequence().next(1_700_000_000_000)).toBe(1_700_000_000_000);
  });

  it("strictly increases for equal, earlier and later observations", () => {
    const sequence = new PublisherSequence();
    const first = sequence.next(1_700_000_000_000);
    const equal = sequence.next(1_700_000_000_000);
    const earlier = sequence.next(1_699_999_990_000);
    const later = sequence.next(1_700_000_050_000);
    expect([first, equal, earlier, later]).toEqual([
      1_700_000_000_000,
      1_700_000_000_001,
      1_700_000_000_002,
      1_700_000_050_000,
    ]);
  });

  it("never falls below the observed millis once the clock moves ahead", () => {
    const sequence = new PublisherSequence();
    sequence.next(1_700_000_000_000);
    sequence.next(1_700_000_000_000);
    sequence.next(1_700_000_000_000);
    expect(sequence.next(1_700_000_000_002)).toBe(1_700_000_000_003);
    expect(sequence.next(1_700_000_000_010)).toBe(1_700_000_000_010);
  });

  it("refuses a value that is not a safe integer and keeps its place", () => {
    const sequence = new PublisherSequence();
    expect(sequence.next(10)).toBe(10);
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 1.5, 2 ** 60]) {
      expect(() => sequence.next(bad)).toThrow("observedAtUnixMillis");
    }
    expect(sequence.next(5)).toBe(11);
  });
});

describe.skipIf(!machineIdAvailable)("presence publication and the state root", () => {
  it("touches no path under dataRoot", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-nodataroot-"));
    await writePresenceFixtures(path.join(dir, "fixtures"));
    // A regular file as dataRoot: opening anything beneath it fails with
    // ENOTDIR for every uid, root included.
    const dataRoot = path.join(dir, "not-a-directory");
    await writeFile(dataRoot, "");
    const config = loadConfig({
      GC_ACCESS_BASE_URL: "https://heimdall.example.test",
      GC_ACCESS_DATA_ROOT: dataRoot,
    });

    const descriptors = openPresenceDescriptors(path.join(dir, "fixtures"));
    try {
      const observedAtUnixMillis = Date.parse("2026-10-23T12:00:00.000Z");
      const statement = await buildPresenceStatement({
        bundle: bundleFacts,
        state: "warming",
        detail: "probe",
        boundEndpoint: null,
        writeLeaseSha256: null,
        observedAtUnixMillis,
        publisherSequence: new PublisherSequence().next(observedAtUnixMillis),
        providerHealthIdentityPath: config.providerHealthIdentityPath,
        env: descriptors.env,
      });
      expect(statement.target).toBe("heimdall");
    } finally {
      descriptors.close();
    }
    expect((await readdir(dir)).sort()).toEqual(["fixtures", "not-a-directory"]);
  });
});
