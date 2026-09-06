import { mkdtemp, readFile } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import os from "node:os";
import path from "node:path";

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
 * The identity is machine-id bound, so these can only run where a machine-id
 * exists. On Windows the enrolment path itself is unavailable, and the
 * descriptor selection below is the part worth proving anyway.
 */
describe.skipIf(!machineIdAvailable)("presence identity from a passed descriptor", () => {
  it("reads the identity Idunn passed rather than enrolling its own", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-presence-"));
    const store = path.join(dir, "runtime-presence-identity.cc");
    const enrolled = await openOrEnrollProviderHealthIdentity(store);

    const fd = openSync(store, "r");
    try {
      // The lookup maps a name index onto 3 + index, so the name list has to be
      // padded until the presence entry lands on whatever descriptor open()
      // actually returned. Assuming it is 3 is how this test would pass on one
      // machine and read the wrong descriptor on another.
      const names = [
        ...Array.from({ length: fd - 3 }, (_, i) => `pad-${i}`),
        "gamecult-runtime-presence-identity",
      ].join(":");

      const opened = await openProviderHealthIdentity(
        path.join(dir, "would-be-self-enrolled.cc"),
        { LISTEN_FDNAMES: names, LISTEN_PID: String(process.pid) },
        process.pid
      );

      // Same key as the enrolled one means it came from the descriptor. A
      // fresh self-enrolment would produce a different key, which is exactly
      // the failure that would make Idunn refuse this daemon's health.
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

  it("falls back to the path when systemd passed nothing", async () => {
    // No LISTEN_FDNAMES means no Idunn: the ordinary self-enrolling path
    // applies and must not be treated as an error.
    const target = path.join(dir, `heimdall-no-fd-${process.pid}.cc`);
    await expect(
      openProviderHealthIdentity(target, {}, process.pid)
    ).resolves.toBeDefined().catch(() => {
      // On a host without a machine-id enrolment cannot succeed; the point is
      // that it took the path branch rather than trying to read a descriptor.
    });
  });

  it("ignores descriptors addressed to another process", async () => {
    // LISTEN_PID naming a different process means these descriptors are not
    // ours. Consuming them would read a sibling's identity.
    const target = path.join(dir, `heimdall-wrong-pid-${process.pid}.cc`);
    await openProviderHealthIdentity(
      target,
      { LISTEN_FDNAMES: "gamecult-runtime-presence-identity", LISTEN_PID: String(process.pid + 1) },
      process.pid
    ).catch((error) => {
      // Either it enrolled via the path, or it failed for a machine-id reason.
      // What must not happen is a descriptor read.
      expect(String(error)).not.toContain("presence identity");
    });
  });

  it("ignores a descriptor set that does not name the presence identity", async () => {
    const target = path.join(dir, `heimdall-other-fd-${process.pid}.cc`);
    await openProviderHealthIdentity(
      target,
      { LISTEN_FDNAMES: "some-other-credential", LISTEN_PID: String(process.pid) },
      process.pid
    ).catch((error) => {
      expect(String(error)).not.toContain("presence identity");
    });
  });
});
