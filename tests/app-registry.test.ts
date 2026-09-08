import { beforeEach, describe, expect, it } from "vitest";

import { isBuiltInApp, listAppProfiles, resolveAppProfile } from "../src/app-registry.js";
import { evaluateCapabilityRules } from "../src/capability-rules.js";
import { type CapabilityDefinition } from "../src/capability-rules.js";
import { entitlementFacts, grantFacts, identityFacts } from "../src/facts.js";
import { InMemoryStore } from "../src/store/in-memory.js";
import { type StoredRegisteredApp } from "../src/store/types.js";

const registeredApp = (overrides: Partial<StoredRegisteredApp> = {}): StoredRegisteredApp => ({
  slug: "erycina",
  displayName: "Erycina",
  profileVersion: "2026-01-01",
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
  identityProviders: ["discord"],
  entitlementSources: [],
  managedConnectionProviders: [],
  capabilities: [
    { key: "viewer_access", mode: "shared", summary: "Signed-in viewer.", anyOf: [identityFacts.authenticated] },
  ] as CapabilityDefinition[],
  redirectUris: ["https://erycina.example/auth/callback"],
  ...overrides,
});

let store: InMemoryStore;
beforeEach(() => {
  store = new InMemoryStore();
});

/**
 * There is no runtime registration authority anymore (deleted with the
 * caller-identity cut: registerApp minted a client_secret nobody verified,
 * and validateAppRegistration/AppRegistrationRequest/RegistrationProblem/
 * AppRegistrationError went with it). `registered_apps` remains a profile
 * store consulted below the built-in profiles; a real deployment provisions
 * a row directly against Postgres, and `seedRegisteredApp` is the equivalent
 * test/ops seam on the in-memory store.
 */
describe("resolveAppProfile", () => {
  it("resolves a registered app", async () => {
    store.seedRegisteredApp(registeredApp());
    const profile = await resolveAppProfile(store, "erycina");

    expect(profile?.displayName).toBe("Erycina");
  });

  it("resolves a built-in app without touching storage", async () => {
    expect((await resolveAppProfile(store, "bifrost"))?.displayName).toBe("Bifrost");
  });

  it("returns null for an app nobody registered", async () => {
    expect(await resolveAppProfile(store, "nope")).toBeNull();
  });

  it("a built-in cannot be shadowed even if a row exists for it", async () => {
    // The built-in lookup runs first; a row written by some other path
    // cannot hijack a shipped audience.
    store.seedRegisteredApp(registeredApp({ slug: "bifrost", displayName: "Impostor" }));

    expect((await resolveAppProfile(store, "bifrost"))?.displayName).toBe("Bifrost");
  });
});

describe("a registered profile evaluates like a built-in", () => {
  it("grants capabilities through the same evaluator", async () => {
    store.seedRegisteredApp(
      registeredApp({
        capabilities: [
          { key: "member_access", mode: "shared", summary: "member", anyOf: [entitlementFacts.appAccess, grantFacts.globalMember] },
          { key: "post_create", mode: "shared", summary: "post", anyOf: ["member_access"] },
        ] as CapabilityDefinition[],
      }),
    );
    const profile = await resolveAppProfile(store, "erycina");

    expect(evaluateCapabilityRules(profile!.capabilities, new Set([grantFacts.globalMember]))).toEqual([
      "member_access",
      "post_create",
    ]);
    expect(evaluateCapabilityRules(profile!.capabilities, new Set([identityFacts.authenticated]))).toEqual([]);
  });
});

describe("listAppProfiles", () => {
  it("lists built-ins alongside registered apps", async () => {
    store.seedRegisteredApp(registeredApp());
    const slugs = (await listAppProfiles(store)).map((profile) => profile.slug);

    expect(slugs).toContain("bifrost");
    expect(slugs).toContain("erycina");
  });

  it("lists each app once", async () => {
    store.seedRegisteredApp(registeredApp());
    const slugs = (await listAppProfiles(store)).map((profile) => profile.slug);

    expect(new Set(slugs).size).toBe(slugs.length);
  });
});

describe("isBuiltInApp", () => {
  it("knows the shipped profiles", () => {
    expect(isBuiltInApp("repixelizer")).toBe(true);
    expect(isBuiltInApp("erycina")).toBe(false);
  });
});
