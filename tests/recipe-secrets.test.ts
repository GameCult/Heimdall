import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { appProfiles } from "../src/app-profiles.js";
import { appSlugs, providers } from "../src/contracts.js";
import { providerCatalog } from "../src/providers.js";

// The Idunn recipe decides which environment names a binding may set, and
// Idunn refuses any other. So the recipe is where "a secret is only ever a
// file" is enforced for a deployment: a plaintext secret name declared here
// can carry the secret into the binding, the unit and every plan.

const recipe = readFileSync(new URL("../deployment/idunn/recipe.toml", import.meta.url), "utf8");

/** The names in one `KEY = [ "A", "B" ]` array of the given TOML text. */
function stringArray(text: string, key: string): string[] {
  const match = new RegExp(`^${key}\\s*=\\s*\\[([^\\]]*)\\]`, "m").exec(text);
  return match ? [...match[1]!.matchAll(/"([^"]+)"/g)].map((name) => name[1]!) : [];
}

const serviceSection = /^\[service\]\n([\s\S]*?)(?=^\[)/m.exec(recipe.replace(/\r\n/g, "\n"))?.[1] ?? "";
const serviceNames = [
  ...stringArray(serviceSection, "optional_environment"),
  ...stringArray(serviceSection, "required_environment"),
];
const everyDeclaredName = [...recipe.replace(/\r\n/g, "\n").matchAll(/^\w+_environment\s*=\s*\[([^\]]*)\]/gm)].flatMap(
  (match) => [...match[1]!.matchAll(/"([^"]+)"/g)].map((name) => name[1]!)
);

// The secrets Heimdall reads are observed, not read from the source: the real
// loadConfig runs against an environment that records every name it looks
// up. readSecretInput looks up `NAME_FILE` for each secret, so every `_FILE`
// lookup names one, however the call is spelled and whatever list computes
// the name. The recorder also stands in for process.env, both while config.ts
// is imported (freshly, so a copy of process.env taken at module load is the
// recorder too) and during every call.
//
// A read made from a copy of the environment ({ ...env }, Object.entries)
// cannot be seen, so copying or enumerating it is recorded and fails below.
//
// A secret read only on a branch some value opens is reached by running
// loadConfig over many environments, until no run reads a new name: every
// secret found so far set in plaintext; then each name read so far set to
// each probe value (a few shapes, plus every string literal in config.ts);
// then every name at once, each set to a value loadConfig accepted for it
// alone; and every combined run again as Idunn starts Heimdall, with the
// recipe's service arguments and a candidate socket with its base URL, a
// pair loadConfig refuses one name at a time. A run that throws still counts
// the reads it made first.
//
// Known limit: a read gated on a value that is none of the probe values and
// not accepted alone in combination with the others stays unseen.
const configSource = readFileSync(new URL("../src/config.ts", import.meta.url), "utf8");
const probeValues = [
  ...new Set(["1", "true", "/probe/path", "127.0.0.1:4100", "https://probe.test", ...[...configSource.matchAll(/"([^"\\\r\n]+)"/g)].map((m) => m[1]!)]),
];

const recorder = { values: {} as Record<string, string>, names: new Set<string>(), enumerated: false };
const recordingEnv = new Proxy({} as NodeJS.ProcessEnv, {
  get(_target, name) {
    if (typeof name !== "string") return undefined;
    recorder.names.add(name);
    return recorder.values[name];
  },
  has(_target, name) {
    if (typeof name !== "string") return false;
    recorder.names.add(name);
    return name in recorder.values;
  },
  ownKeys() {
    recorder.enumerated = true;
    return [];
  },
  getOwnPropertyDescriptor() {
    recorder.enumerated = true;
    return undefined;
  },
});

async function withRecordingProcessEnv<T>(run: () => T | Promise<T>): Promise<T> {
  const processEnv = process.env;
  process.env = recordingEnv;
  try {
    return await run();
  } finally {
    process.env = processEnv;
  }
}

/**
 * How Idunn starts Heimdall: the recipe's [service] arguments after the
 * entry script, each binding given a probe value, and the environment an
 * Idunn candidate always has (a loopback socket, which requires the base URL).
 */
const recipeArguments = [...(/^\[service\][\s\S]*?^arguments = \[([\s\S]*?)^\]/m.exec(recipe.replace(/\r\n/g, "\n"))?.[1] ?? "").matchAll(
  /\{ kind = "(literal|binding)", (?:value|name) = "([^"]+)" \}/g
)].map((match) => (match[1] === "literal" ? match[2]! : "/probe/idunn-binding"));
const idunnArgv = recipeArguments.slice(1);
const idunnEnv = { GAMECULT_IDUNN_CANDIDATE_BIND: "127.0.0.1:4100", GC_ACCESS_BASE_URL: "https://probe.test" };

vi.resetModules();
const { loadConfig } = await withRecordingProcessEnv(() => import("../src/config.js"));

/** The names one loadConfig run reads under `values`, and whether it accepted them. */
async function readsOf(
  values: Readonly<Record<string, string>>,
  argv: readonly string[] = []
): Promise<{ names: Set<string>; accepted: boolean }> {
  recorder.values = { ...values };
  recorder.names = new Set();
  let accepted = true;
  await withRecordingProcessEnv(() => {
    try {
      loadConfig(recordingEnv, argv);
    } catch {
      accepted = false; // the reads before the refusal still count
    }
  });
  return { names: recorder.names, accepted };
}

async function exploreLoadConfig(): Promise<{ names: Set<string>; enumerated: boolean }> {
  const names = new Set<string>();
  recorder.enumerated = false;
  const secretsOf = () => [...names].filter((name) => name.endsWith("_FILE")).map((name) => name.slice(0, -"_FILE".length));
  for (let grew = true; grew; ) {
    const before = names.size;
    const secrets = Object.fromEntries(secretsOf().map((name) => [name, "probe-secret"]));
    const settable = [...names].filter((name) => !name.endsWith("_FILE") && !(name in secrets));
    const accepted = new Map<string, string[]>();
    const keep = (run: { names: Set<string> }) => run.names.forEach((name) => names.add(name));
    keep(await readsOf({}));
    keep(await readsOf(secrets));
    keep(await readsOf({ ...secrets, ...idunnEnv }, idunnArgv));
    for (const name of settable) {
      for (const value of probeValues) {
        const run = await readsOf({ ...secrets, [name]: value });
        keep(run);
        if (run.accepted) accepted.set(name, [...(accepted.get(name) ?? []), value]);
      }
    }
    const widest = Math.max(0, ...[...accepted.values()].map((values) => values.length));
    for (let round = 0; round < widest; round += 1) {
      const together = Object.fromEntries([...accepted].map(([name, values]) => [name, values[round % values.length]!]));
      keep(await readsOf({ ...secrets, ...together }));
      keep(await readsOf({ ...secrets, ...together, ...idunnEnv }, idunnArgv));
    }
    grew = names.size > before;
  }
  return { names, enumerated: recorder.enumerated };
}

const explored = await exploreLoadConfig();

/** Secrets Heimdall reads through readSecretInput, by their plaintext name. */
const secretNames = [...explored.names]
  .filter((name) => name.endsWith("_FILE"))
  .map((name) => name.slice(0, -"_FILE".length));

const secretShaped =
  /SECRET|PASSWORD|PASSPHRASE|TOKEN|API_KEY|PRIVATE_KEY|ENCRYPTION_KEY|SALT|CREDENTIAL|DATABASE_URL|_DSN|_PEM|HMAC/;

/** Secret-shaped names that hold no secret, each for its own reason. */
const notSecrets = new Set([
  // A path to the signing key file, which Heimdall reads (or creates) itself.
  "GC_ACCESS_SIGNING_PRIVATE_KEY_PATH",
  // A flag: create that file on first boot.
  "GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP",
]);

describe("Idunn recipe secret declarations", () => {
  it("reads the service's declared environment", () => {
    expect(serviceNames).toContain("GC_ACCESS_DATABASE_URL_FILE");
    expect(serviceNames).toContain("GC_ACCESS_BASE_URL");
  });

  it("declares no secret-shaped name except as a _FILE credential path", () => {
    const plaintext = everyDeclaredName.filter(
      (name) => secretShaped.test(name) && !name.endsWith("_FILE") && !notSecrets.has(name)
    );
    expect(plaintext).toEqual([]);
  });

  it("starts the exploration the way the recipe starts Heimdall", async () => {
    expect(idunnArgv).toEqual(["--state-root", "/probe/idunn-binding"]);
    expect(serviceNames).toEqual(expect.arrayContaining(Object.keys(idunnEnv)));
    expect((await readsOf({ ...idunnEnv }, idunnArgv)).accepted).toBe(true);
  });

  it("reads the environment only by name, never by copying or enumerating it", () => {
    expect(explored.enumerated).toBe(false);
  });

  it("sees every secret loadConfig reads, across the provider and app lists", () => {
    expect(secretNames).toEqual(
      expect.arrayContaining([
        "GC_ACCESS_DATABASE_URL",
        "GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64",
        "GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET",
        ...providers.map((provider) => `GC_ACCESS_PROVIDER_${provider.toUpperCase()}_CLIENT_SECRET`),
        ...appSlugs.map((appSlug) => `GC_ACCESS_APP_${appSlug.toUpperCase()}_SHARED_SECRET`),
      ])
    );
  });

  it("declares none of the secrets Heimdall reads under its plaintext name", () => {
    for (const name of secretNames) {
      expect(everyDeclaredName).not.toContain(name);
    }
  });

  it("declares every provider client-secret file the witness publishes", () => {
    for (const provider of providers) {
      expect(serviceNames).toContain(providerCatalog[provider].clientSecretEnv);
    }
  });

  it("declares the shared-secret file of every app profile the witness publishes", () => {
    for (const profile of Object.values(appProfiles)) {
      expect(serviceNames).toContain(`GC_ACCESS_APP_${profile.slug.toUpperCase()}_SHARED_SECRET_FILE`);
    }
  });

  it("declares the _FILE of every secret Heimdall reads", () => {
    for (const name of secretNames) {
      expect(serviceNames).toContain(`${name}_FILE`);
    }
  });
});
