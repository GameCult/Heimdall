import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { appProfiles } from "../src/app-profiles.js";
import { providers } from "../src/contracts.js";
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

const serviceSecretNames = [
  "GC_ACCESS_DATABASE_URL",
  "GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64",
  "GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET",
];

/** Secrets Heimdall reads through readSecretInput, by their plaintext name. */
const secretNames = [
  ...serviceSecretNames,
  ...providers.map((provider) => `GC_ACCESS_PROVIDER_${provider.toUpperCase()}_CLIENT_SECRET`),
  ...Object.values(appProfiles).map((profile) => `GC_ACCESS_APP_${profile.slug.toUpperCase()}_SHARED_SECRET`),
];

const secretShaped = /SECRET|PASSWORD|DATABASE_URL|ENCRYPTION_KEY|_PEM$/;

describe("Idunn recipe secret declarations", () => {
  it("reads the service's declared environment", () => {
    expect(serviceNames).toContain("GC_ACCESS_DATABASE_URL_FILE");
    expect(serviceNames).toContain("GC_ACCESS_BASE_URL");
  });

  it("declares no secret-shaped name except as a _FILE credential path", () => {
    const plaintext = everyDeclaredName.filter((name) => secretShaped.test(name) && !name.endsWith("_FILE"));
    expect(plaintext).toEqual([]);
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

  it("declares the database URL, token key and patron secret files", () => {
    for (const name of serviceSecretNames) {
      expect(serviceNames).toContain(`${name}_FILE`);
    }
  });
});
