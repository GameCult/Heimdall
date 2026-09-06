import { mkdtemp, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { encode } from "@msgpack/msgpack";
import { SingleFileMessagePackBackingStore } from "cultcache-ts";
import { describe, expect, it } from "vitest";

import { resolveWriteLease } from "../src/process-write-lease.js";

/**
 * Idunn writes CultCache envelopes whose payload is the canonical positional
 * MessagePack encoding of the record. These helpers reproduce that shape, so
 * the tests exercise the same bytes the daemon will actually be handed rather
 * than a convenient object.
 */
async function writeStore(file: string, type: string, payload: Uint8Array): Promise<void> {
  // Written with the CultCache client, the same way Idunn writes these. A
  // hand-built fixture only proves the reader agrees with the fixture.
  await new SingleFileMessagePackBackingStore(file).push({
    key: "heimdall",
    type,
    schemaId: type,
    storedAt: "2026-09-06T00:00:00.000Z",
    payload,
  });
}

function expectedIncarnation(target: string, incarnationId: string): Uint8Array {
  const fields = new Array(12).fill("x");
  fields[0] = "idunn.expected_incarnation.v2";
  fields[1] = target;
  fields[3] = incarnationId;
  return encode(fields);
}

function writeLease(target: string, incarnationId: string, epoch = 3): Uint8Array {
  const fields: unknown[] = new Array(14).fill("x");
  fields[0] = "idunn.process_write_lease.v1";
  fields[1] = target;
  fields[4] = incarnationId;
  fields[10] = "runtime-instance-1";
  fields[12] = epoch;
  fields[13] = 1757116800000;
  return encode(fields);
}

async function bundleWith(
  expectedBytes: Uint8Array | undefined,
  leaseBytes: Uint8Array | undefined
): Promise<{ bundle: string; lease: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), "heimdall-lease-"));
  const bundle = path.join(root, "runtime-instance-1");
  await mkdir(bundle, { recursive: true });

  if (expectedBytes) {
    await writeStore(path.join(bundle, "expected.cc"), "idunn.expected_incarnation", expectedBytes);
  }

  const lease = path.join(root, "process-write-lease.cc");
  if (leaseBytes) {
    await writeStore(lease, "idunn.process_write_lease", leaseBytes);
  }

  return { bundle, lease };
}

describe("Idunn process write lease", () => {
  it("permits writes when not launched by Idunn", async () => {
    // A developer run and the current plain systemd unit have no second
    // generation to collide with.
    await expect(resolveWriteLease({})).resolves.toMatchObject({
      mayWrite: true,
      reason: "not-under-idunn",
    });
  });

  it("permits writes when the lease names this incarnation", async () => {
    const { bundle, lease } = await bundleWith(
      expectedIncarnation("heimdall", "incarnation-a"),
      writeLease("heimdall", "incarnation-a", 7)
    );

    await expect(
      resolveWriteLease({ leasePath: lease, runtimeBundlePath: bundle })
    ).resolves.toMatchObject({ mayWrite: true, reason: "held", incarnationId: "incarnation-a", leaseEpoch: 7 });
  });

  it("refuses writes when the lease names the other generation", async () => {
    // The case the lease exists for: a warming candidate while the incumbent
    // still holds the store.
    const { bundle, lease } = await bundleWith(
      expectedIncarnation("heimdall", "incarnation-candidate"),
      writeLease("heimdall", "incarnation-incumbent")
    );

    const decision = await resolveWriteLease({ leasePath: lease, runtimeBundlePath: bundle });
    expect(decision.mayWrite).toBe(false);
    expect(decision.reason).toContain("incarnation-incumbent");
  });

  it("refuses writes when no lease has been granted yet", async () => {
    const { bundle, lease } = await bundleWith(
      expectedIncarnation("heimdall", "incarnation-a"),
      undefined
    );

    const decision = await resolveWriteLease({ leasePath: lease, runtimeBundlePath: bundle });
    expect(decision.mayWrite).toBe(false);
    expect(decision.reason).toContain("no readable write lease");
  });

  it("refuses writes when the lease belongs to another target", async () => {
    const { bundle, lease } = await bundleWith(
      expectedIncarnation("heimdall", "incarnation-a"),
      writeLease("ghostlight", "incarnation-a")
    );

    const decision = await resolveWriteLease({ leasePath: lease, runtimeBundlePath: bundle });
    expect(decision.mayWrite).toBe(false);
    expect(decision.reason).toContain("ghostlight");
  });

  it("refuses writes on a wrong-length or wrong-schema lease", async () => {
    const short = encode(new Array(9).fill("x"));
    const wrongSchema = encode(
      Object.assign(new Array(14).fill("x"), { 0: "idunn.process_write_lease.v0", 12: 1 })
    );

    for (const bytes of [short, wrongSchema]) {
      const { bundle, lease } = await bundleWith(
        expectedIncarnation("heimdall", "incarnation-a"),
        bytes
      );
      const decision = await resolveWriteLease({ leasePath: lease, runtimeBundlePath: bundle });
      expect(decision.mayWrite).toBe(false);
    }
  });

  it("refuses writes when a lease path is set without a runtime bundle", async () => {
    // Launch inputs are incoherent; declining is the safe reading.
    const decision = await resolveWriteLease({ leasePath: "/nonexistent/lease.cc" });
    expect(decision.mayWrite).toBe(false);
    expect(decision.reason).toContain("GAMECULT_IDUNN_RUNTIME_BUNDLE");
  });

  it("refuses writes when the runtime bundle is unreadable", async () => {
    const { lease } = await bundleWith(undefined, writeLease("heimdall", "incarnation-a"));
    const decision = await resolveWriteLease({
      leasePath: lease,
      runtimeBundlePath: "/nonexistent/bundle",
    });
    expect(decision.mayWrite).toBe(false);
    expect(decision.reason).toContain("unreadable runtime bundle");
  });
});
