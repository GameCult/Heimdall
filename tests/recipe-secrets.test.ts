import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
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

// The secrets Heimdall reads are whatever its source passes to
// readSecretInput, so the set is read from the source: a secret added there
// cannot be declared in plaintext here without failing. A literal name is
// taken as written; the two computed names expand over the lists that compute
// them; any other argument fails, because this test cannot know its names.
const srcRoot = new URL("../src/", import.meta.url);
const secretArguments = readdirSync(srcRoot, { recursive: true })
  .map(String)
  .filter((file) => file.endsWith(".ts"))
  .flatMap((file) =>
    [...readFileSync(new URL(file.replace(/\\/g, "/"), srcRoot), "utf8").matchAll(/(?<!function )readSecretInput\(\s*[^,()]+,\s*([^)]+?)\s*\)/g)].map(
      (call) => call[1]!
    )
  );

const computedSecretNames: Record<string, string[]> = {
  "`${prefix}_CLIENT_SECRET`": providers.map((provider) => `GC_ACCESS_PROVIDER_${provider.toUpperCase()}_CLIENT_SECRET`),
  envKey: appSlugs.map((appSlug) => `GC_ACCESS_APP_${appSlug.toUpperCase()}_SHARED_SECRET`),
};

/** Secrets Heimdall reads through readSecretInput, by their plaintext name. */
const secretNames = secretArguments.flatMap((argument) => {
  const literal = /^"([A-Z0-9_]+)"$/.exec(argument);
  if (literal) return [literal[1]!];
  const computed = computedSecretNames[argument];
  if (computed) return computed;
  throw new Error(`recipe-secrets cannot derive the names read by readSecretInput(env, ${argument}); teach it.`);
});

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

  it("finds every readSecretInput call in the source", () => {
    expect(secretNames).toEqual(
      expect.arrayContaining([
        "GC_ACCESS_DATABASE_URL",
        "GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64",
        "GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET",
        "GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET",
        "GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET",
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
