import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createPublicKey, createPrivateKey, verify } from "node:crypto";
import dgram from "node:dgram";
import { chmod, copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { closeSync, openSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { decode, encode } from "@msgpack/msgpack";
import {
  RUNTIME_PRESENCE_SLOT,
  parseCultNetMessage,
  runtimePresenceActivationSigningMessage,
  runtimePresenceProviderSigningMessage,
} from "cultnet-ts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { startFakeIdunnRudp, type FakeIdunnRudp } from "./fixtures/fake-idunn-rudp.js";
import { idunnRuntimeFixtures } from "./fixtures/presence-descriptors.js";

const run = promisify(execFile);

const GENERATION_UID = 61184;
const STATE_GID = 4242;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_ED25519_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// The launch needs root (to pick the uid and bind a machine-id) and a mount
// namespace (so the fixture machine-id does not replace the host's). The
// stopgap's node container has both; anywhere else the test steps aside.
const canLaunch =
  process.getuid?.() === 0 &&
  (await run("unshare", ["--mount", "--", "true"]).then(
    () => true,
    () => false
  ));

/**
 * The artifact under test. By default the esbuild bundle `pnpm bundle` makes,
 * run by this process's node; a runbook proves a sealed release by naming its
 * bundle and node here instead.
 */
const bundleOverride = process.env.HEIMDALL_BOOT_BUNDLE;
const nodeOverride = process.env.HEIMDALL_BOOT_NODE;

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as net.AddressInfo;
      probe.close(() => resolve(port));
    });
  });
}

interface Launch {
  child: ChildProcess;
  stderr: () => string;
  exited: Promise<number | null>;
  candidatePort: number;
}

describe.skipIf(!canLaunch)("the bundle booted as Idunn launches it", () => {
  let base: string;
  let bundle: string;
  let node: string;
  let idunn: FakeIdunnRudp;
  let odin: dgram.Socket;
  let odinPort: number;
  const launched: ChildProcess[] = [];

  beforeAll(async () => {
    base = await mkdtemp(path.join(os.tmpdir(), "heimdall-boot-"));
    await chmod(base, 0o755);
    if (bundleOverride) {
      bundle = bundleOverride;
    } else {
      await run("corepack", ["pnpm", "bundle"], { cwd: path.join(import.meta.dirname, "..") });
      bundle = path.join(base, "heimdall.mjs");
      await copyFile(path.join(import.meta.dirname, "..", "dist", "heimdall"), bundle);
      await chmod(bundle, 0o644);
    }
    node = nodeOverride ?? process.execPath;
    idunn = await startFakeIdunnRudp();
    odin = dgram.createSocket("udp4");
    await new Promise<void>((resolve) => odin.bind(0, "127.0.0.1", resolve));
    odinPort = odin.address().port;
  }, 120_000);

  afterAll(() => {
    for (const child of launched) child.kill("SIGKILL");
    idunn?.close();
    odin?.close();
  });

  /** Credential files as Idunn holds them: readable only by the parent. */
  async function credentials(dir: string, identity: Buffer | undefined) {
    await mkdir(dir, { recursive: true });
    const seed = path.join(dir, "activation-key.seed");
    await copyFile(path.join(idunnRuntimeFixtures, "activation-key.seed"), seed);
    await chmod(seed, 0o400);
    let identityFile: string | undefined;
    if (identity) {
      identityFile = path.join(dir, "provider-identity.credential");
      await writeFile(identityFile, identity, { mode: 0o400 });
    }
    return { seed, identityFile };
  }

  /** Start the bundle as the generation unit does, with the fixture machine-id bound over the host's. */
  async function launch(label: string, identity: Buffer | undefined): Promise<Launch> {
    const dir = path.join(base, label);
    await mkdir(dir, { recursive: true });
    await chmod(dir, 0o755);

    // Idunn's runtime bundle: the two records, read-only.
    const bundleDir = path.join(dir, "bundle");
    await mkdir(bundleDir);
    for (const name of ["expected.cc", "activation.cc"]) {
      await copyFile(path.join(idunnRuntimeFixtures, name), path.join(bundleDir, name));
      await chmod(path.join(bundleDir, name), 0o444);
    }
    await chmod(bundleDir, 0o555);

    const machineId = path.join(dir, "machine-id");
    await copyFile(path.join(idunnRuntimeFixtures, "machine-id"), machineId);
    await chmod(machineId, 0o444);

    const stateRoot = path.join(dir, "state");
    await mkdir(stateRoot);
    await run("chown", [`0:${STATE_GID}`, stateRoot]);
    await chmod(stateRoot, 0o2770);

    const heimdall = path.join(dir, "heimdall.mjs");
    await copyFile(bundle, heimdall);
    await chmod(heimdall, 0o444);

    const files = await credentials(path.join(dir, "credentials"), identity);
    const candidatePort = await freePort();

    const fds = [openSync(files.seed, "r")];
    const names = ["gamecult-idunn-runtime-activation-key"];
    if (files.identityFile) {
      fds.push(openSync(files.identityFile, "r"));
      names.push("gamecult-runtime-presence-identity");
    }

    const env = {
      PATH: process.env.PATH ?? "",
      LISTEN_FDS: String(fds.length),
      LISTEN_FDNAMES: names.join(":"),
      GAMECULT_IDUNN_CANDIDATE_BIND: `127.0.0.1:${candidatePort}`,
      GAMECULT_IDUNN_RUNTIME_BUNDLE: bundleDir,
      GAMECULT_IDUNN_PROCESS_WRITE_LEASE: path.join(dir, "process-write-lease.cc"),
      GC_ACCESS_BASE_URL: "https://heimdall.test",
      GC_ACCESS_ISSUER: "https://heimdall.test",
      GC_ACCESS_STORAGE_BACKEND: "memory",
      GC_ACCESS_IDUNN_RUDP_HEALTH: `127.0.0.1:${idunn.port}`,
      GC_ACCESS_IDUNN_HEALTH_CONTRACT: "heimdall.cultnet-rudp-provider-health",
      GC_ACCESS_ODIN_CULTMESH_URI: `rudp://127.0.0.1:${odinPort}`,
      CULTMESH_URI_ODIN_RUDP: `rudp://127.0.0.1:${odinPort}`,
      GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP: "1",
      GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: path.join(stateRoot, "signing.pem"),
      GC_ACCESS_SIGNING_KEY_ID: "boot-test",
    };

    // uid, gid and umask as Idunn's DynamicUser unit gives them. The fixture
    // machine-id is bound only inside this mount namespace.
    const script =
      `mount --bind ${machineId} /etc/machine-id && ` +
      `exec setpriv --reuid ${GENERATION_UID} --regid ${STATE_GID} --clear-groups ` +
      `sh -c 'umask 0007; cd ${dir}; exec ${node} heimdall.mjs --state-root ${stateRoot}'`;
    const child = spawn("unshare", ["--mount", "--", "sh", "-c", script], {
      env,
      stdio: ["ignore", "ignore", "pipe", ...fds],
    });
    launched.push(child);
    fds.forEach((fd) => closeSync(fd));

    let stderr = "";
    child.stderr!.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    const exited = new Promise<number | null>((resolve) => child.once("exit", (code) => resolve(code)));
    return { child, stderr: () => stderr, exited, candidatePort };
  }

  async function answers(port: number): Promise<number | undefined> {
    return fetch(`http://127.0.0.1:${port}/.well-known/jwks.json`).then(
      (response) => response.status,
      () => undefined
    );
  }

  it("signs warming presence on every pulse and answers HTTP", async () => {
    const credential = await readFile(path.join(idunnRuntimeFixtures, "provider-identity.credential"));
    const generation = await launch("signs", credential);

    // Startup publication, then one per 10 s pulse. A publication fault is
    // reported as it is logged rather than after the frames never arrive.
    const publicationFault = new Promise<never>((_resolve, reject) => {
      const watch = setInterval(() => {
        if (generation.stderr().includes(" failed on ")) {
          clearInterval(watch);
          reject(new Error(`publication failed; stderr: ${generation.stderr()}`));
        }
      }, 200);
      void idunn.frame(2).then(() => clearInterval(watch));
    });
    const exitedEarly = generation.exited.then((code) => {
      throw new Error(`bundle exited ${code}; stderr: ${generation.stderr()}`);
    });
    // The first statement is the startup publication, which follows the listen
    // directly; the 10 s pulse loop has not yet fired.
    await Promise.race([
      idunn.frame(0),
      publicationFault,
      exitedEarly,
      new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error(`no presence at startup; stderr: ${generation.stderr()}`)), 8_000)
      ),
    ]);
    await Promise.race([idunn.frame(2), publicationFault, exitedEarly]);

    expect(await answers(generation.candidatePort)).toBe(200);

    // Public keys of the two proofs, from the fixtures' test keys.
    const store = decode(credential) as unknown[][];
    const record = decode(store[0]![2] as Uint8Array) as unknown[];
    const providerKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(record[2] as number[])]),
      format: "der",
      type: "spki",
    });
    const activationKey = createPublicKey(
      createPrivateKey({
        key: Buffer.concat([
          PKCS8_ED25519_SEED_PREFIX,
          await readFile(path.join(idunnRuntimeFixtures, "activation-key.seed")),
        ]),
        format: "der",
        type: "pkcs8",
      })
    );

    let previousSequence = 0;
    for (const frame of idunn.frames.slice(0, 3)) {
      const message = parseCultNetMessage(decode(frame.payload), "cultnet.schema.v0");
      if (message.schemaVersion !== "cultnet.document_put_raw.v0") throw new Error("not a raw document put");
      const fields = decode(message.document.payload) as unknown[];
      expect(fields[RUNTIME_PRESENCE_SLOT.state]).toBe("warming");

      const unsigned = [...fields];
      unsigned[RUNTIME_PRESENCE_SLOT.signature] = new Uint8Array();
      unsigned[RUNTIME_PRESENCE_SLOT.activationSignature] = new Uint8Array();
      const proof = encode(unsigned);
      expect(
        verify(
          null,
          runtimePresenceProviderSigningMessage(proof),
          providerKey,
          fields[RUNTIME_PRESENCE_SLOT.signature] as Uint8Array
        )
      ).toBe(true);
      expect(
        verify(
          null,
          runtimePresenceActivationSigningMessage(proof),
          activationKey,
          fields[RUNTIME_PRESENCE_SLOT.activationSignature] as Uint8Array
        )
      ).toBe(true);

      const sequence = fields[RUNTIME_PRESENCE_SLOT.publisherSequence] as number;
      expect(sequence).toBeGreaterThan(previousSequence);
      previousSequence = sequence;
    }

    expect(generation.stderr()).not.toContain("failed on startup");
    expect(generation.stderr()).not.toContain("failed on interval");
    generation.child.kill("SIGKILL");
  }, 90_000);

  it.each([
    ["the identity descriptor is not passed", undefined, "gamecult-runtime-presence-identity"],
    ["the identity is damaged", "damaged", "identity id check"],
  ])("exits before listening when %s", async (_name, damage, expected) => {
    const credential = await readFile(path.join(idunnRuntimeFixtures, "provider-identity.credential"));
    const store = decode(credential) as unknown[][];
    const record = decode(store[0]![2] as Uint8Array) as unknown[];
    const publicKey = [...(record[2] as number[])];
    const original = { publicKeyHex: Buffer.from(publicKey).toString("hex"), id: record[1] as string, binding: record[5] as string };
    let identity: Buffer | undefined;
    if (damage) {
      publicKey[0] = publicKey[0]! ^ 1;
      record[2] = publicKey;
      identity = Buffer.from(encode([[store[0]![0], store[0]![1], encode(record), store[0]![3], store[0]![4]]]));
    }
    const started = Date.now();
    const generation = await launch(damage ? "damaged" : "no-identity", identity);

    const code = await Promise.race([
      generation.exited,
      new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 5_000)),
    ]);

    expect(code, generation.stderr()).not.toBe("timeout");
    expect(code).not.toBe(0);
    expect(Date.now() - started).toBeLessThan(6_000);
    expect(await answers(generation.candidatePort)).toBeUndefined();
    expect(generation.stderr()).toContain(expected);
    // No byte of the credential: not the key bytes, not the id, not the binding.
    expect(generation.stderr()).not.toContain(original.publicKeyHex);
    expect(generation.stderr()).not.toContain(original.id.slice(0, 16));
    expect(generation.stderr()).not.toContain(original.binding.slice(-16));
  }, 30_000);
});
