import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { openSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { decode, encode } from "@msgpack/msgpack";
import { describe, expect, it } from "vitest";

import {
  openProviderHealthIdentity,
  passedDescriptor,
  providerHealthPublicIdentity,
} from "../src/provider-health-identity.js";
import { fixtureMachineId, idunnRuntimeFixtures } from "./fixtures/presence-descriptors.js";

const machineIdAvailable = await readFile("/etc/machine-id", "utf8").then(
  () => true,
  () => false
);

/**
 * The identity is machine-id bound, so enrolment only works where a machine-id
 * exists. These run on Linux and are skipped elsewhere.
 */
/** Name the presence descriptor so it lands on whatever fd open() returned. */
function presenceEnv(fd: number): NodeJS.ProcessEnv {
  // The lookup maps a name index onto 3 + index, so the name list is padded
  // until the presence entry lands on the descriptor open() actually returned.
  // Assuming it is 3 is how this passes on one machine and reads the wrong
  // descriptor on another.
  const names = [
    ...Array.from({ length: fd - 3 }, (_, i) => `pad-${i}`),
    "gamecult-runtime-presence-identity",
  ].join(":");
  return { LISTEN_FDNAMES: names, LISTEN_PID: String(process.pid) };
}

describe("presence identity from a passed descriptor", () => {
  it("decodes the Rust owner's record, whose key fields are integer arrays", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-presence-"));
    const fd = openSync(path.join(idunnRuntimeFixtures, "provider-identity.credential"), "r");

    const opened = await openProviderHealthIdentity(
      path.join(dir, "would-be-self-enrolled.cc"),
      presenceEnv(fd),
      fixtureMachineId
    );

    // The fixture's own public key means it came from the descriptor. A fresh
    // self-enrolment would produce a different key, which is exactly the failure
    // that makes Idunn refuse this daemon's health and stall promotion.
    const store = decode(await readFile(path.join(idunnRuntimeFixtures, "provider-identity.credential"))) as unknown[][];
    const record = decode(store[0]![2] as Uint8Array) as unknown[];
    expect(providerHealthPublicIdentity(opened).publicKeyHex).toBe(
      Buffer.from(record[2] as number[]).toString("hex")
    );
    await expect(access(path.join(dir, "would-be-self-enrolled.cc"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("refuses a bin-shaped record on the descriptor path, naming the key-shape check and no value", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-presence-bin-"));
    const store = decode(await readFile(path.join(idunnRuntimeFixtures, "provider-identity.credential"))) as unknown[][];
    const record = decode(store[0]![2] as Uint8Array) as unknown[];
    // What this process's own enroller writes: the same record with bin key fields.
    const binRecord = record.map((field, index) =>
      index === 2 || index === 3 ? Uint8Array.from(field as number[]) : field
    );
    const binStore = path.join(dir, "bin-shaped.cc");
    await writeFile(binStore, encode([[store[0]![0], store[0]![1], encode(binRecord), store[0]![3], store[0]![4]]]));
    const fd = openSync(binStore, "r");

    const failure = await openProviderHealthIdentity(path.join(dir, "x.cc"), presenceEnv(fd), fixtureMachineId).then(
      () => undefined,
      (error: Error) => error
    );

    expect(failure?.message).toContain("key shape check");
    expect(failure?.message).not.toContain((record[1] as string).slice(0, 16));
  });

  it.each([
    ["schema", 0, "bogus", "schema check"],
    ["protector", 4, "bogus", "protector check"],
    ["binding", 5, "bogus", "binding check"],
    ["version", 6, "v9", "version check"],
  ])("a record failing only the %s check is refused by that check", async (_name, index, replacement, check) => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-presence-check-"));
    const store = decode(await readFile(path.join(idunnRuntimeFixtures, "provider-identity.credential"))) as unknown[][];
    const record = decode(store[0]![2] as Uint8Array) as unknown[];
    record[index] = replacement;
    const damaged = path.join(dir, "damaged.cc");
    await writeFile(damaged, encode([[store[0]![0], store[0]![1], encode(record), store[0]![3], store[0]![4]]]));
    const fd = openSync(damaged, "r");

    await expect(
      openProviderHealthIdentity(path.join(dir, "x.cc"), presenceEnv(fd), fixtureMachineId)
    ).rejects.toThrow(check);
  });
});

describe("presence identity descriptor selection", () => {
  const dir = os.tmpdir();

  it("takes the named descriptor even when LISTEN_PID is another namespace's pid", () => {
    // Idunn launches candidates with PrivatePIDs=yes, so systemd sets
    // LISTEN_PID to the pid it knows in the outer namespace while this process
    // sees a namespace-local one. They never match. Refusing the descriptor on
    // that basis sent Heimdall down the self-enrolling path, where it signed
    // health with a key nothing trusts and warmed forever.
    //
    // This asserts the *selection*, not a read. An earlier version of this test
    // called openProviderHealthIdentity, which then did readFileSync on fd 3 --
    // a live handle inside the vitest worker. On Windows that blocks instead of
    // throwing, which hung the worker and took the whole suite with it. The
    // decision under test is which descriptor gets chosen; reading a real one
    // is not part of it.
    expect(
      passedDescriptor("gamecult-runtime-presence-identity", {
        LISTEN_FDNAMES: "gamecult-runtime-presence-identity",
        LISTEN_PID: String(process.pid + 1),
      })
    ).toBe(3);
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

describe("an Idunn generation without the presence identity descriptor", () => {
  it("refuses, naming the descriptor, and enrolls nothing", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-nodescriptor-"));
    const identityPath = path.join(dir, "provider-health-identity.cc");

    await expect(
      openProviderHealthIdentity(identityPath, {
        GAMECULT_IDUNN_RUNTIME_BUNDLE: "/run/idunn/bundle",
        LISTEN_FDNAMES: "some-other-descriptor",
      })
    ).rejects.toThrow("gamecult-runtime-presence-identity");

    await expect(access(identityPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("still self-enrolls outside Idunn", async () => {
    if (!machineIdAvailable) return;
    const dir = await mkdtemp(path.join(os.tmpdir(), "heimdall-outside-idunn-"));
    const identityPath = path.join(dir, "provider-health-identity.cc");

    await openProviderHealthIdentity(identityPath, {});

    await expect(access(identityPath)).resolves.toBeUndefined();
  });
});
