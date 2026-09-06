// Capability rules as data.
//
// App profiles used to carry an evaluateSharedCapabilities function alongside a
// sharedRule string describing what that function did. Two representations of
// one rule, free to drift, and the function is the reason an app profile could
// not be registered at runtime: you cannot accept code from a stranger and run
// it inside the auth authority.
//
// The rules were never more than a disjunction. Every sharedRule in the built-in
// profiles is "a || b || c" over a closed vocabulary, so the executable form is
// a list, not an expression language. anyOf is now the only representation.
//
// The safety property that makes runtime registration acceptable: a term must
// name either a fact Heimdall itself produces, or another capability in the
// same profile. A registered app selects from what Heimdall has already decided
// is true about an account. It cannot invent a fact, and it cannot reach into
// another app's capabilities.

export type CapabilityMode = "shared" | "hybrid";

/** Prefixes of facts Heimdall produces. A rule term outside these must name a capability in the same profile. */
export const FACT_NAMESPACES = ["identity.", "entitlement.", "grant."] as const;

export interface CapabilityDefinition {
  key: string;
  mode: CapabilityMode;
  summary: string;
  /**
   * Granted when the account holds any of these terms. A term is a fact
   * (identity.*, entitlement.*, grant.*) or another capability key in this
   * profile. Omitted for hybrid capabilities, which the host app resolves.
   */
  anyOf?: string[];
  /** For hybrid capabilities: what the host app must combine with the shared claim. */
  localRequirement?: string;
}

export interface CapabilityRuleProblem {
  capability: string;
  term: string;
  reason: string;
}

export function isFactTerm(term: string): boolean {
  return FACT_NAMESPACES.some((namespace) => term.startsWith(namespace));
}

/**
 * Rejects a rule set that reaches outside what Heimdall can vouch for.
 *
 * This is the gate on runtime registration. An unknown term is refused rather
 * than treated as false, because a rule that silently never fires is a
 * capability an app believes it has and never receives, and that failure
 * surfaces as a support ticket rather than an error.
 */
export function validateCapabilityRules(capabilities: readonly CapabilityDefinition[]): CapabilityRuleProblem[] {
  const problems: CapabilityRuleProblem[] = [];
  const known = new Set(capabilities.map((capability) => capability.key));

  for (const capability of capabilities) {
    if (capability.mode === "hybrid") {
      if (capability.anyOf?.length) {
        problems.push({
          capability: capability.key,
          term: capability.anyOf.join(" || "),
          reason: "A hybrid capability is resolved by the host app and must not carry shared rules.",
        });
      }
      continue;
    }

    if (!capability.anyOf?.length) {
      problems.push({
        capability: capability.key,
        term: "",
        reason: "A shared capability needs at least one term, or it can never be granted.",
      });
      continue;
    }

    for (const term of capability.anyOf) {
      if (isFactTerm(term)) continue;
      if (known.has(term)) {
        if (term === capability.key) {
          problems.push({ capability: capability.key, term, reason: "A capability cannot depend on itself." });
        }
        continue;
      }
      problems.push({
        capability: capability.key,
        term,
        reason: "Unknown term. Use a Heimdall fact (identity./entitlement./grant.) or a capability in this profile.",
      });
    }
  }

  return problems;
}

/**
 * Grants every shared capability whose terms are satisfied.
 *
 * Capabilities may reference each other, so this runs to a fixed point rather
 * than in one pass. It terminates because the granted set only grows and is
 * bounded by the rule count; a self-reference is refused by validation rather
 * than looped on here.
 */
export function evaluateCapabilityRules(
  capabilities: readonly CapabilityDefinition[],
  facts: ReadonlySet<string>,
): string[] {
  const shared = capabilities.filter((capability) => capability.mode === "shared" && capability.anyOf?.length);
  const granted = new Set<string>();

  let changed = true;
  while (changed) {
    changed = false;
    for (const capability of shared) {
      if (granted.has(capability.key)) continue;
      const satisfied = capability.anyOf!.some((term) => (isFactTerm(term) ? facts.has(term) : granted.has(term)));
      if (satisfied) {
        granted.add(capability.key);
        changed = true;
      }
    }
  }

  // Declaration order, so a profile reads the way it evaluates.
  return capabilities.filter((capability) => granted.has(capability.key)).map((capability) => capability.key);
}

/** Human-readable form of a rule, derived rather than stored, so it cannot drift from what runs. */
export function describeCapabilityRule(capability: CapabilityDefinition): string {
  if (capability.mode === "hybrid") return capability.localRequirement ?? "Resolved by the host app.";
  return (capability.anyOf ?? []).join(" || ");
}
