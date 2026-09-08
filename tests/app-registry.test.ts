import { beforeEach, describe, expect, it } from "vitest";

import {
  isBuiltInApp,
  listAppProfiles,
  resolveAppProfile,
  validateAppRegistration,
  type AppRegistrationRequest,
} from "../src/app-registry.js";
import { evaluateCapabilityRules } from "../src/capability-rules.js";
import { type Provider } from "../src/contracts.js";
import { entitlementFacts, grantFacts, identityFacts } from "../src/facts.js";
import { InMemoryStore } from "../src/store/in-memory.js";

const request = (overrides: Partial<AppRegistrationRequest> = {}): AppRegistrationRequest => ({
  slug: "erycina",
  displayName: "Erycina",
  identityProviders: ["discord"],
  redirectUris: ["https://erycina.example/auth/callback"],
  capabilities: [
    { key: "viewer_access", mode: "shared", summary: "Signed-in viewer.", anyOf: [identityFacts.authenticated] },
  ],
  ...overrides,
});

let store: InMemoryStore;
beforeEach(() => {
  store = new InMemoryStore();
});

/**
 * There is no runtime registration authority anymore (deleted with the
 * caller-identity cut: registerApp minted a client_secret nobody verified).
 * `registered_apps` remains a profile store, so tests that need a resolvable
 * profile write the row directly through the store primitive, the same way
 * production code would seed one outside the deleted HTTP surface.
 */
async function seedRegisteredApp(overrides: Partial<AppRegistrationRequest> = {}, registeredAt = "2026-01-01T00:00:00.000Z") {
  const req = request(overrides);
  return store.registerApp({
    slug: req.slug,
    displayName: req.displayName.trim(),
    profileVersion: req.profileVersion?.trim() || registeredAt.slice(0, 10),
    registeredAt,
    identityProviders: req.identityProviders as Provider[],
    entitlementSources: (req.entitlementSources ?? []) as Provider[],
    managedConnectionProviders: (req.managedConnectionProviders ?? []) as Provider[],
    capabilities: req.capabilities,
    redirectUris: req.redirectUris,
  });
}

describe("validateAppRegistration", () => {
  it("accepts a well-formed registration", () => {
    expect(validateAppRegistration(request())).toEqual([]);
  });

  it("refuses a slug that shadows a built-in app", () => {
    // Otherwise a registration inherits a shipped app's audience, which is
    // impersonation rather than registration.
    const problems = validateAppRegistration(request({ slug: "bifrost" }));
    expect(problems[0]!.reason).toMatch(/reserved by a built-in/);
  });

  it("refuses slugs that would be awkward as a JWT audience or storage key", () => {
    for (const slug of ["A", "1app", "has space", "has/slash", ""]) {
      expect(validateAppRegistration(request({ slug })).some((p) => p.field === "slug")).toBe(true);
    }
  });

  it("refuses an unknown provider", () => {
    const problems = validateAppRegistration(request({ identityProviders: ["myspace"] }));
    expect(problems.some((p) => p.reason.includes("myspace"))).toBe(true);
  });

  it("requires at least one identity provider", () => {
    expect(validateAppRegistration(request({ identityProviders: [] })).some((p) => p.field === "identityProviders")).toBe(true);
  });

  it("refuses a capability rule naming a fact Heimdall does not produce", () => {
    // The registration gate. An app selects from Heimdall's vocabulary; it
    // cannot invent a fact to grant itself something.
    const problems = validateAppRegistration(
      request({
        capabilities: [{ key: "admin", mode: "shared", summary: "x", anyOf: ["invented.superuser"] }],
      }),
    );
    expect(problems.some((p) => p.reason.includes("Unknown term"))).toBe(true);
  });

  describe("redirect URIs", () => {
    it("requires at least one", () => {
      expect(validateAppRegistration(request({ redirectUris: [] })).some((p) => p.field === "redirectUris")).toBe(true);
    });

    it("refuses a relative URI", () => {
      expect(validateAppRegistration(request({ redirectUris: ["/callback"] }))[0]!.reason).toMatch(/absolute/);
    });

    it("refuses plain http off loopback, because that is where a code would leak", () => {
      expect(
        validateAppRegistration(request({ redirectUris: ["http://erycina.example/cb"] }))[0]!.reason,
      ).toMatch(/https/);
    });

    it("allows http on loopback, for local development", () => {
      expect(validateAppRegistration(request({ redirectUris: ["http://127.0.0.1:8080/cb"] }))).toEqual([]);
      expect(validateAppRegistration(request({ redirectUris: ["http://localhost:8080/cb"] }))).toEqual([]);
    });

    it("refuses a fragment", () => {
      expect(validateAppRegistration(request({ redirectUris: ["https://a.example/cb#x"] }))[0]!.reason).toMatch(/fragment/);
    });
  });

  it("reports every problem rather than stopping at the first", () => {
    const problems = validateAppRegistration(request({ slug: "!!", displayName: "", identityProviders: [] }));
    expect(problems.length).toBeGreaterThan(2);
  });
});

describe("resolveAppProfile", () => {
  it("resolves a registered app", async () => {
    await seedRegisteredApp();
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
    // Registration refuses built-in slugs; this is the second place that holds,
    // so a row written by some other path cannot hijack a shipped audience.
    await store.registerApp({
      slug: "bifrost",
      displayName: "Impostor",
      profileVersion: "x",
      registeredAt: "2026-01-01T00:00:00.000Z",
      identityProviders: ["discord"],
      entitlementSources: [],
      managedConnectionProviders: [],
      capabilities: [],
      redirectUris: [],
    });

    expect((await resolveAppProfile(store, "bifrost"))?.displayName).toBe("Bifrost");
  });
});

describe("a registered profile evaluates like a built-in", () => {
  it("grants capabilities through the same evaluator", async () => {
    await seedRegisteredApp({
      capabilities: [
        { key: "member_access", mode: "shared", summary: "member", anyOf: [entitlementFacts.appAccess, grantFacts.globalMember] },
        { key: "post_create", mode: "shared", summary: "post", anyOf: ["member_access"] },
      ],
    });
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
    await seedRegisteredApp();
    const slugs = (await listAppProfiles(store)).map((profile) => profile.slug);

    expect(slugs).toContain("bifrost");
    expect(slugs).toContain("erycina");
  });

  it("lists each app once", async () => {
    await seedRegisteredApp();
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
