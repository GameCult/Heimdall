import { execFile } from "node:child_process";
import { chmod, chown, mkdir, mkdtemp, readdir, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { build } from "esbuild";
import { describe, expect, it } from "vitest";

import { writePresenceFixtures } from "./fixtures/presence-descriptors.js";

const run = promisify(execFile);

const STATE_GID = 4242;
const GENERATION_N = 61184;
const GENERATION_N_PLUS_1 = 61185;

// Creating uids and groups needs root; the stopgap's node container runs as root.
const isRoot = process.getuid?.() === 0;

async function walk(dir: string): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    found.push(full);
    if (entry.isDirectory()) found.push(...(await walk(full)));
  }
  return found;
}

/**
 * Idunn gives every generation a fresh DynamicUser uid and one shared group,
 * UMask=0007, and a 2770 setgid state root. Generation N+1 runs beside or after
 * N and must be able to read and replace everything N left there.
 */
describe.skipIf(!isRoot)("Idunn state root across generations", () => {
  it("generation N+1, a different uid in the same group, reads and replaces generation N's state", async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), "heimdall-generations-"));
    await chmod(base, 0o755);

    // The fixtures stand in for what Idunn passes as descriptors.
    const fixtures = path.join(base, "fixtures");
    await writePresenceFixtures(fixtures);

    const stateRoot = path.join(base, "state");
    await mkdir(stateRoot);
    await chown(stateRoot, 0, STATE_GID);
    await chmod(stateRoot, 0o2770);

    // The generations run as uids that cannot read the checkout, so each runs
    // one self-contained bundle built into the world-readable scratch root.
    const child = path.join(base, "generation.mjs");
    await build({
      entryPoints: [path.join(import.meta.dirname, "fixtures", "state-root-generation-child.ts")],
      bundle: true,
      platform: "node",
      format: "esm",
      target: "node24",
      outfile: child,
      external: ["pg-native"],
      banner: {
        js: "import{createRequire}from'node:module';const require=createRequire(import.meta.url);",
      },
      logLevel: "silent",
    });
    await chmod(child, 0o644);
    const generation = (role: "first" | "next", uid: number) =>
      run(process.execPath, [child, role, stateRoot, fixtures], {
        uid,
        gid: STATE_GID,
        cwd: base,
        env: { PATH: process.env.PATH ?? "", HOME: fixtures },
      });

    await generation("first", GENERATION_N);

    const left = await walk(stateRoot);
    expect(left.map((entry) => path.relative(stateRoot, entry)).sort()).toEqual([
      "cultcache",
      path.join("cultcache", "heimdall.service.cc"),
      "runtime-presence-sequence",
    ]);

    await generation("next", GENERATION_N_PLUS_1);

    // Generation N+1 replaced the snapshot, and no owner-only file is left
    // behind for generation N+2: everything but the stale 0600 fixture is
    // readable and writable by the state group.
    const snapshot = await stat(path.join(stateRoot, "cultcache", "heimdall.service.cc"));
    expect(snapshot.uid).toBe(GENERATION_N_PLUS_1);
    expect(snapshot.gid).toBe(STATE_GID);
    for (const entry of await walk(stateRoot)) {
      if (path.basename(entry) === "runtime-presence-sequence") continue;
      expect((await stat(entry)).mode & 0o060, path.relative(stateRoot, entry)).toBe(0o060);
    }
    expect((await readdir(stateRoot)).sort()).toEqual(["cultcache", "runtime-presence-sequence"]);
  }, 60_000);
});
