import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { appProfiles } from "../src/app-profiles.js";
import { appSlugs, providers } from "../src/contracts.js";
import { loadConfig } from "../src/config.js";
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
// the name. The same recorder stands in for process.env during the call, so a
// read that bypasses the env argument is seen too.
//
// A read made from a copy of the environment ({ ...env }, Object.entries)
// cannot be seen, so copying or enumerating it is recorded and fails below.
//
// A secret read only on a branch that some value opens is reached by running
// loadConfig over many environments: every secret found so far set in
// plaintext, then each name read so far set to each probe value in turn, then
// every such name set to one probe value at once, until no run reads a new
// name. A run that throws still counts the reads it made first.
const probeValues = ["1", "true", "/probe/path", "127.0.0.1:4100", "https://probe.test"];

function readsOf(values: Readonly<Record<string, string>>): { names: Set<string>; enumerated: boolean } {
  const names = new Set<string>();
  let enumerated = false;
  const record = (name: string | symbol) => {
    if (typeof name === "string") names.add(name);
  };
  const env = new Proxy({} as NodeJS.ProcessEnv, {
    get(_target, name) {
      record(name);
      return typeof name === "string" ? values[name] : undefined;
    },
    has(_target, name) {
      record(name);
      return typeof name === "string" && name in values;
    },
    ownKeys() {
      enumerated = true;
      return [];
    },
    getOwnPropertyDescriptor() {
      enumerated = true;
      return undefined;
    },
  });
  const processEnv = process.env;
  process.env = env;
  try {
    loadConfig(env, []);
  } catch {
    // The reads before the refusal still count.
  } finally {
    process.env = processEnv;
  }
  return { names, enumerated };
}

function exploreLoadConfig(): { names: Set<string>; enumerated: boolean } {
  const names = new Set<string>();
  let enumerated = false;
  const secretsOf = () => [...names].filter((name) => name.endsWith("_FILE")).map((name) => name.slice(0, -"_FILE".length));
  for (let grew = true; grew; ) {
    const before = names.size;
    const secrets = Object.fromEntries(secretsOf().map((name) => [name, "probe-secret"]));
    const settable = [...names].filter((name) => !name.endsWith("_FILE") && !(name in secrets));
    const runs: Array<Record<string, string>> = [
      {},
      secrets,
      ...settable.flatMap((name) => probeValues.map((value) => ({ ...secrets, [name]: value }))),
      ...probeValues.map((value) => ({ ...secrets, ...Object.fromEntries(settable.map((name) => [name, value])) })),
    ];
    for (const values of runs) {
      const run = readsOf(values);
      run.names.forEach((name) => names.add(name));
      enumerated ||= run.enumerated;
    }
    grew = names.size > before;
  }
  return { names, enumerated };
}

const explored = exploreLoadConfig();

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
