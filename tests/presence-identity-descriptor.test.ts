import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { encode } from "@msgpack/msgpack";
import { SingleFileMessagePackBackingStore } from "cultcache-ts";
import { describe, expect, it } from "vitest";

import {
  openOrEnrollProviderHealthIdentity,
  openProviderHealthIdentity,
  providerHealthPublicIdentity,
} from "../src/provider-health-identity.js";

const machineIdAvailable = await readFile("/etc/machine-id", "utf8").then(
  () => true,
  () => false
);

/**
 * The identity is machine-id bound, so enrolment only works where a machine-id
 * exists. These run on Linux and are skipped elsewhere.
 */
describe.skipIf(!machineIdAvailable)("presence identity from a passed descriptor", () => {
  it("reads an Idunn-written store, not a cultcache-ts one", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-presence-"));

    // Enrol with the TypeScript client to get a genuine machine-bound payload,
    // then re-wrap that payload the way cultcache-rs writes a store: a bare
    // array of positional [key, type, payload, stored_at, schema_id] envelopes.
    // Idunn writes with the Rust client, and cultcache-ts cannot read that
    // layout, so wrapping it here is what makes this test resemble reality.
    const tsStore = path.join(dir, "ts-enrolled.cc");
    const enrolled = await openOrEnrollProviderHealthIdentity(tsStore);
    const records = await new SingleFileMessagePackBackingStore(tsStore).pullAll();
    expect(records).toHaveLength(1);

    const idunnStore = path.join(dir, "runtime-presence-identity.cc");
    await writeFile(
      idunnStore,
      encode([
        [
          "gamecult-provider-health-identity",
          "gamecult.provider_health_identity.private.v1",
          records[0]!.payload,
          "2026-09-06T00:00:00.000Z",
          "gamecult.provider_health_identity.private.v1",
        ],
      ])
    );

    const fd = openSync(idunnStore, "r");
    try {
      // The lookup maps a name index onto 3 + index, so the name list is padded
      // until the presence entry lands on whatever descriptor open() actually
      // returned. Assuming it is 3 is how this passes on one machine and reads
      // the wrong descriptor on another.
      const names = [
        ...Array.from({ length: fd - 3 }, (_, i) => `pad-${i}`),
        "gamecult-runtime-presence-identity",
      ].join(":");

      const opened = await openProviderHealthIdentity(
        path.join(dir, "would-be-self-enrolled.cc"),
        { LISTEN_FDNAMES: names, LISTEN_PID: String(process.pid) }
      );

      // Same key means it came from the descriptor. A fresh self-enrolment
      // would produce a different key -- which is exactly the failure that
      // makes Idunn refuse this daemon's health and stall promotion.
      expect(providerHealthPublicIdentity(opened).publicKeyHex).toBe(
        providerHealthPublicIdentity(enrolled).publicKeyHex
      );
    } finally {
      closeSync(fd);
    }
  });
});

describe("presence identity descriptor selection", () => {
  const dir = os.tmpdir();

  it("takes the named descriptor even when LISTEN_PID is another namespace's pid", async () => {
    // Idunn launches candidates with PrivatePIDs=yes, so systemd sets
    // LISTEN_PID to the pid it knows in the outer namespace while this process
    // sees a namespace-local one. They never match. Refusing the descriptor on
    // that basis sent Heimdall down the self-enrolling path, where it signed
    // health with a key nothing trusts and warmed forever -- so the descriptor
    // must still be taken, and the attempt to read it is the proof.
    await expect(
      openProviderHealthIdentity(path.join(dir, `heimdall-outer-pid-${process.pid}.cc`), {
        LISTEN_FDNAMES: "gamecult-runtime-presence-identity",
        LISTEN_PID: String(process.pid + 1),
      })
    ).rejects.toThrow();
  });

  it("ignores a descriptor set that does not name the presence identity", async () => {
    await openProviderHealthIdentity(
      path.join(dir, `heimdall-other-fd-${process.pid}.cc`),
      { LISTEN_FDNAMES: "some-other-credential", LISTEN_PID: String(process.pid) }
    ).catch((error) => {
      expect(String(error)).not.toContain("Idunn runtime presence identity");
    });
  });
});
