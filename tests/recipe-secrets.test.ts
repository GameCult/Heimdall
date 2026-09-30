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
// read that bypasses the env argument is seen too. The environment is empty,
// so this sees the reads loadConfig makes when nothing is set; a secret read
// only on a branch some other variable opens would not be seen.
function namesLoadConfigReads(): Set<string> {
  const names = new Set<string>();
  const env = new Proxy({} as NodeJS.ProcessEnv, {
    get(_target, name) {
      if (typeof name === "string") names.add(name);
      return undefined;
    },
    has(_target, name) {
      if (typeof name === "string") names.add(name);
      return false;
    },
  });
  const processEnv = process.env;
  process.env = env;
  try {
    loadConfig(env, []);
  } finally {
    process.env = processEnv;
  }
  return names;
}

/** Secrets Heimdall reads through readSecretInput, by their plaintext name. */
const secretNames = [...namesLoadConfigReads()]
  .filter((name) => name.endsWith("_FILE"))
  .map((name) => name.slice(0, -"_FILE".length));

const secretShaped =
  /SECRET|PASSWORD|PASSPHRASE|TOKEN|API_KEY|PRIVATE_KEY|ENCRYPTION_KEY|SALT|CREDENTIAL|DATABASE_URL|_DSN|_PEM/;

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
