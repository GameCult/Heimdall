import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// A secret must never reach a terminal. Under Idunn, Heimdall's stderr goes to
// the journal and the install script tails the journal to the operator's
// terminal, so the layer that matters is the process's own output, not an
// error's message. These cases run the real entrypoint with canary values in
// the places a misbinding puts secrets, and fail on any byte of the canary
// anywhere on stdout or stderr: in a message, an error cause, an error
// property, or anything else Node chooses to print.

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");
const scratch = mkdtempSync(join(tmpdir(), "heimdall-entrypoint-"));
const CANARY = "CANARY";

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

function file(name: string, contents: string): string {
  const path = join(scratch, name);
  writeFileSync(path, contents);
  return path;
}

interface Run {
  code: number | null;
  signal: NodeJS.Signals | null;
  output: string;
}

interface Identity {
  uid: number;
  gid: number;
}

/**
 * Who can be denied a read. Root reads a mode-000 file, so a read failure is
 * only reachable as another user: the process itself when it is not root, or
 * else the checkout's owner, who can still load the entrypoint. A string is
 * the reason no such user exists here.
 */
function nonRootReader(): Identity | "self" | string {
  if (process.platform === "win32") return "file modes do not deny reads on Windows";
  if (process.getuid?.() !== 0) return "self";
  const owner = statSync(repoRoot);
  if (owner.uid === 0) return "running as root in a root-owned checkout, so no other user can load the entrypoint";
  return { uid: owner.uid, gid: owner.gid };
}

/** Runs `tsx src/index.ts` with only the given environment, merging stdout and stderr. */
function runEntrypoint(name: string, env: Record<string, string>, identity?: Identity): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [tsxCli, "src/index.ts"], {
      cwd: repoRoot,
      ...identity,
      env: {
        PATH: process.env.PATH ?? "",
        HOME: scratch,
        GC_ACCESS_DATA_ROOT: join(scratch, `data-${name}`),
        PORT: "0",
        GC_ACCESS_PRIVATE_COMMAND_PORT: "0",
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString("utf8")));
    child.stderr.on("data", (chunk: Buffer) => (output += chunk.toString("utf8")));
    // A case that fails to fail would start serving; stop it rather than hang.
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    child.on("error", reject);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, output });
    });
  });
}

/** A base64 value that decodes to exactly 32 bytes and still carries the canary. */
function canaryTokenKey(tag: string): string {
  return `${CANARY}${tag}`.padEnd(43, "A") + "=";
}

interface Case {
  name: string;
  env: () => Record<string, string>;
  /** Something the failure must say, so a case cannot pass by never reaching its path. */
  expect: RegExp;
  /** Run the entrypoint as a user a file mode can refuse. */
  nonRoot?: true;
}

const cases: Case[] = [
  {
    name: "a URL bound into an absolute _FILE slot",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: `/postgres://heimdall:${CANARY}url@db/heimdall` }),
    expect: /GC_ACCESS_DATABASE_URL_FILE could not be read \(ENOENT\)/,
  },
  {
    name: "a _FILE path under a regular file",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: join(file("plain", "x"), `${CANARY}notdir`) }),
    expect: /GC_ACCESS_DATABASE_URL_FILE could not be read \(ENOTDIR\)/,
  },
  {
    name: "a secret bound into a relative _FILE slot",
    env: () => ({ GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET_FILE: `${CANARY}relative-secret` }),
    expect: /GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET_FILE is not an absolute path/,
  },
  {
    name: "a secret bound both ways",
    env: () => ({
      GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET: `${CANARY}plain`,
      GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET_FILE: file("both", `${CANARY}file\n`),
    }),
    expect: /GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET and GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET_FILE are both set/,
  },
  {
    name: "a blank secret file",
    env: () => ({ GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET_FILE: join(scratch, "blank") }),
    expect: /GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET_FILE is empty/,
  },
  {
    name: "a token key that decodes short",
    env: () => ({ GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64_FILE: file("short-key", `${CANARY}shortkey\n`) }),
    expect: /GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64_FILE must decode to exactly 32 bytes/,
  },
  {
    name: "a database URL with an unusable port",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: file("db-port", `postgres://heimdall:${CANARY}port@db:notaport/heimdall\n`) }),
    expect: /Postgres storage could not be prepared \(ERR_INVALID_URL\)/,
  },
  {
    name: "a database URL that does not parse",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: file("db-parse", `postgres://heimdall:${CANARY} parse@[bad/heimdall\n`) }),
    expect: /Postgres storage could not be prepared \(E[A-Z_]+\)/,
  },
  {
    name: "a database URL with a broken percent escape",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: file("db-percent", `postgres://heimdall:${CANARY}%zz@127.0.0.1:1/heimdall\n`) }),
    expect: /Postgres storage could not be prepared \(ECONNREFUSED\)/,
  },
  {
    name: "a database that refuses the connection",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: file("db-refused", `postgres://heimdall:${CANARY}refused@127.0.0.1:1/heimdall\n`) }),
    expect: /Postgres storage could not be prepared \(ECONNREFUSED\)/,
  },
  {
    // A password holding an unescaped delimiter moves part of it into the
    // host, and the resolver's error names the host.
    name: "a database host that does not resolve",
    env: () => ({ GC_ACCESS_DATABASE_URL_FILE: file("db-host", `postgres://heimdall:pw@${CANARY}host.invalid/heimdall\n`) }),
    expect: /Postgres storage could not be prepared \(E[A-Z_]+\)/,
  },
  {
    // A start that does not apply the schema still connects, so a misbound URL
    // fails at startup rather than in a request's error answer.
    name: "a database host that does not resolve, on a start that does not apply the schema",
    env: () => ({
      GC_ACCESS_APPLY_SCHEMA_ON_STARTUP: "0",
      GC_ACCESS_DATABASE_URL_FILE: file("db-host-noapply", `postgres://heimdall:pw@${CANARY}host.invalid/heimdall\n`),
    }),
    expect: /Postgres storage could not be prepared \(E[A-Z_]+\)/,
  },
  {
    name: "private key text bound to the signing key path",
    env: () => ({
      GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: `-----BEGIN PRIVATE KEY-----\n${CANARY}pem\n-----END PRIVATE KEY-----\n`,
    }),
    expect: /GC_ACCESS_SIGNING_PRIVATE_KEY_PATH is not an absolute path/,
  },
  {
    name: "a signing key path that names no file",
    env: () => ({ GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: join(scratch, `${CANARY}missing-key`) }),
    expect: /GC_ACCESS_SIGNING_PRIVATE_KEY_PATH names no file \(ENOENT\)/,
  },
  {
    name: "a signing key file that is not a key",
    env: () => ({ GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: file("not-a-key", `${CANARY}notakey\n`) }),
    expect: /GC_ACCESS_SIGNING_PRIVATE_KEY_PATH does not hold a usable private key/,
  },
  {
    name: "a signing key file its reader may not read",
    env: () => {
      const key = file(`${CANARY}locked-key`, `${CANARY}pem\n`);
      chmodSync(key, 0o000);
      const dataRoot = join(scratch, "locked-key-data");
      mkdirSync(dataRoot, { recursive: true });
      chmodSync(dataRoot, 0o777);
      return { GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: key, GC_ACCESS_DATA_ROOT: dataRoot };
    },
    expect: /GC_ACCESS_SIGNING_PRIVATE_KEY_PATH could not be read \(EACCES\)/,
    nonRoot: true,
  },
  {
    name: "a signing key path that is a directory",
    env: () => {
      const dir = join(scratch, "key-dir");
      mkdirSync(dir, { recursive: true });
      return { GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: dir };
    },
    expect: /GC_ACCESS_SIGNING_PRIVATE_KEY_PATH could not be read \(EISDIR\)/,
  },
  {
    name: "a bootstrapped signing key whose directory cannot be created",
    env: () => ({
      GC_ACCESS_SIGNING_PRIVATE_KEY_PATH: join(file("key-parent", "x"), `${CANARY}dir`, "key.pem"),
      GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP: "1",
    }),
    expect: /GC_ACCESS_SIGNING_PRIVATE_KEY_PATH could not be created \(ENOTDIR\)/,
  },
  {
    // Every secret is configured and valid, and startup fails afterwards, in
    // the entrypoint's own catch: the one place that holds the whole config.
    name: "a listen failure with every secret configured",
    env: () => ({
      HOST: "203.0.113.1",
      GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64_FILE: file("listen-key", `${canaryTokenKey("key")}\n`),
      GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET_FILE: file("listen-patron", `${CANARY}patron\n`),
      GC_ACCESS_PROVIDER_GITHUB_CLIENT_SECRET_FILE: file("listen-github", `${CANARY}github\n`),
      GC_ACCESS_APP_BIFROST_SHARED_SECRET_FILE: file("listen-bifrost", `${CANARY}bifrost\n`),
    }),
    expect: /Heimdall failed to start/,
  },
];

describe("the entrypoint never prints a secret", () => {
  writeFileSync(join(scratch, "blank"), " \n");
  // mkdtemp makes the scratch directory private to its creator; a non-root
  // reader must still reach the files a case names inside it.
  chmodSync(scratch, 0o755);
  const reader = nonRootReader();

  for (const testCase of cases) {
    const skipReason = testCase.nonRoot && typeof reader === "string" && reader !== "self" ? reader : undefined;
    const title = `refuses ${testCase.name} without printing the canary${skipReason ? ` (skipped: ${skipReason})` : ""}`;
    it.skipIf(skipReason !== undefined)(title, async () => {
      const identity = testCase.nonRoot && typeof reader === "object" ? reader : undefined;
      const run = await runEntrypoint(testCase.name.replace(/\W+/g, "-"), testCase.env(), identity);

      expect(run.signal, "the process must stop by itself").toBeNull();
      expect(run.code, "startup must fail").not.toBe(0);
      expect(run.output).toMatch(testCase.expect);
      expect(run.output.includes(CANARY), "no byte of the canary may reach the terminal").toBe(false);
    }, 45_000);
  }
});
