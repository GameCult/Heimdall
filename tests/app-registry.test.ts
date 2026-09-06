import { beforeEach, describe, expect, it } from "vitest";

import {
  AppRegistrationError,
  hashClientSecret,
  isBuiltInApp,
  listAppProfiles,
  registerApp,
  resolveAppProfile,
  validateAppRegistration,
  verifyClientSecret,
  type AppRegistrationRequest,
} from "../src/app-registry.js";
import { evaluateCapabilityRules } from "../src/capability-rules.js";
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

describe("registerApp", () => {
  it("stores the app and returns a secret exactly once", async () => {
    const { app, clientSecret } = await registerApp(store, request());

    expect(app.slug).toBe("erycina");
    expect(clientSecret).toBeTruthy();
    // The secret is returned, never stored.
    expect(app).not.toHaveProperty("clientSecret");
    expect(app.clientSecretHash).toBe(hashClientSecret(clientSecret));
  });

  it("refuses an invalid registration rather than storing a broken profile", async () => {
    await expect(registerApp(store, request({ slug: "bifrost" }))).rejects.toBeInstanceOf(AppRegistrationError);
    expect(await store.findRegisteredApp("bifrost")).toBeNull();
  });

  it("keeps the original creation time when an app re-registers", async () => {
    const first = await registerApp(store, request(), "2026-01-01T00:00:00.000Z");
    const second = await registerApp(store, request({ displayName: "Erycina v2" }), "2026-06-01T00:00:00.000Z");

    expect(second.app.createdAt).toBe(first.app.createdAt);
    expect(second.app.updatedAt).toBe("2026-06-01T00:00:00.000Z");
    expect(second.app.displayName).toBe("Erycina v2");
  });
});

describe("verifyClientSecret", () => {
  it("accepts the issued secret and rejects anything else", async () => {
    const { app, clientSecret } = await registerApp(store, request());

    expect(verifyClientSecret(clientSecret, app.clientSecretHash)).toBe(true);
    expect(verifyClientSecret("not-the-secret", app.clientSecretHash)).toBe(false);
    expect(verifyClientSecret(clientSecret, null)).toBe(false);
  });
});

describe("resolveAppProfile", () => {
  it("resolves a registered app", async () => {
    await registerApp(store, request());
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
      clientSecretHash: null,
    });

    expect((await resolveAppProfile(store, "bifrost"))?.displayName).toBe("Bifrost");
  });
});

describe("a registered profile evaluates like a built-in", () => {
  it("grants capabilities through the same evaluator", async () => {
    await registerApp(
      store,
      request({
        capabilities: [
          { key: "member_access", mode: "shared", summary: "member", anyOf: [entitlementFacts.appAccess, grantFacts.globalMember] },
          { key: "post_create", mode: "shared", summary: "post", anyOf: ["member_access"] },
        ],
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
    await registerApp(store, request());
    const slugs = (await listAppProfiles(store)).map((profile) => profile.slug);

    expect(slugs).toContain("bifrost");
    expect(slugs).toContain("erycina");
  });

  it("lists each app once", async () => {
    await registerApp(store, request());
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
