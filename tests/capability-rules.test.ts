import { describe, expect, it } from "vitest";

import {
  describeCapabilityRule,
  evaluateCapabilityRules,
  isFactTerm,
  validateCapabilityRules,
  type CapabilityDefinition,
} from "../src/capability-rules.js";
import { entitlementFacts, grantFacts, identityFacts } from "../src/facts.js";

const shared = (key: string, anyOf: string[]): CapabilityDefinition => ({
  key,
  mode: "shared",
  summary: key,
  anyOf,
});

const hybrid = (key: string): CapabilityDefinition => ({
  key,
  mode: "hybrid",
  summary: key,
  localRequirement: "Host app resolves this.",
});

describe("evaluateCapabilityRules", () => {
  it("grants a capability when any one term holds", () => {
    const rules = [shared("app_access", [entitlementFacts.appAccess, grantFacts.globalMember])];

    expect(evaluateCapabilityRules(rules, new Set([grantFacts.globalMember]))).toEqual(["app_access"]);
    expect(evaluateCapabilityRules(rules, new Set([entitlementFacts.appAccess]))).toEqual(["app_access"]);
  });

  it("grants nothing when no term holds", () => {
    const rules = [shared("app_access", [entitlementFacts.appAccess])];
    expect(evaluateCapabilityRules(rules, new Set([identityFacts.authenticated]))).toEqual([]);
  });

  it("resolves a capability that depends on another capability", () => {
    // queue_submit derives from app_access in the real repixelizer profile, so
    // one pass is not enough.
    const rules = [
      shared("app_access", [grantFacts.globalMember]),
      shared("queue_submit", ["app_access"]),
    ];

    expect(evaluateCapabilityRules(rules, new Set([grantFacts.globalMember]))).toEqual([
      "app_access",
      "queue_submit",
    ]);
  });

  it("resolves a dependency declared before the capability it depends on", () => {
    const rules = [
      shared("queue_submit", ["app_access"]),
      shared("app_access", [grantFacts.globalMember]),
    ];

    expect(evaluateCapabilityRules(rules, new Set([grantFacts.globalMember]))).toEqual([
      "queue_submit",
      "app_access",
    ]);
  });

  it("does not grant a derived capability when its dependency fails", () => {
    const rules = [
      shared("app_access", [grantFacts.globalMember]),
      shared("queue_submit", ["app_access"]),
    ];

    expect(evaluateCapabilityRules(rules, new Set([identityFacts.authenticated]))).toEqual([]);
  });

  it("never grants a hybrid capability, which the host app owns", () => {
    const rules = [shared("app_access", [grantFacts.globalMember]), hybrid("job_read_own")];

    expect(evaluateCapabilityRules(rules, new Set([grantFacts.globalMember]))).toEqual(["app_access"]);
  });

  it("returns capabilities in declaration order so a profile reads as it evaluates", () => {
    const rules = [
      shared("alpha", [grantFacts.operator]),
      shared("beta", [grantFacts.operator]),
      shared("gamma", [grantFacts.operator]),
    ];

    expect(evaluateCapabilityRules(rules, new Set([grantFacts.operator]))).toEqual(["alpha", "beta", "gamma"]);
  });
});

describe("validateCapabilityRules", () => {
  it("accepts facts from Heimdall's own vocabulary", () => {
    const rules = [
      shared("app_access", [entitlementFacts.appAccess, grantFacts.globalMember, identityFacts.authenticated]),
    ];
    expect(validateCapabilityRules(rules)).toEqual([]);
  });

  it("accepts a reference to another capability in the same profile", () => {
    const rules = [shared("app_access", [grantFacts.globalMember]), shared("queue_submit", ["app_access"])];
    expect(validateCapabilityRules(rules)).toEqual([]);
  });

  it("refuses a term that is neither a fact nor a capability here", () => {
    // The registration gate: an app selects from what Heimdall vouches for and
    // cannot invent a fact to grant itself something.
    const rules = [shared("app_access", ["invented.fact"])];
    const problems = validateCapabilityRules(rules);

    expect(problems).toHaveLength(1);
    expect(problems[0]!.term).toBe("invented.fact");
    expect(problems[0]!.reason).toMatch(/Unknown term/);
  });

  it("refuses another app's capability key", () => {
    const rules = [shared("member_access", ["someone_elses_capability"])];
    expect(validateCapabilityRules(rules)[0]!.reason).toMatch(/Unknown term/);
  });

  it("refuses a self-referential capability", () => {
    const rules = [shared("app_access", ["app_access"])];
    expect(validateCapabilityRules(rules)[0]!.reason).toMatch(/cannot depend on itself/);
  });

  it("refuses a shared capability with no terms, which could never be granted", () => {
    const rules: CapabilityDefinition[] = [{ key: "app_access", mode: "shared", summary: "x" }];
    expect(validateCapabilityRules(rules)[0]!.reason).toMatch(/at least one term/);
  });

  it("refuses shared rules on a hybrid capability", () => {
    const rules: CapabilityDefinition[] = [
      { key: "job_read_own", mode: "hybrid", summary: "x", anyOf: [grantFacts.operator] },
    ];
    expect(validateCapabilityRules(rules)[0]!.reason).toMatch(/resolved by the host app/i);
  });

  it("reports every problem rather than stopping at the first", () => {
    const rules = [shared("a", ["nope.one"]), shared("b", ["nope.two"])];
    expect(validateCapabilityRules(rules)).toHaveLength(2);
  });
});

describe("isFactTerm", () => {
  it("recognises Heimdall's namespaces and nothing else", () => {
    expect(isFactTerm("identity.authenticated")).toBe(true);
    expect(isFactTerm("entitlement.app_access")).toBe(true);
    expect(isFactTerm("grant.operator")).toBe(true);
    expect(isFactTerm("app_access")).toBe(false);
    expect(isFactTerm("custom.thing")).toBe(false);
  });
});

describe("describeCapabilityRule", () => {
  it("derives the readable form rather than storing a second copy", () => {
    expect(describeCapabilityRule(shared("app_access", ["entitlement.app_access", "grant.global_member"]))).toBe(
      "entitlement.app_access || grant.global_member",
    );
  });

  it("describes a hybrid capability by its local requirement", () => {
    expect(describeCapabilityRule(hybrid("job_read_own"))).toBe("Host app resolves this.");
  });
});
