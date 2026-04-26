// Shared claim facts should describe app-facing auth state.
// Provider-specific detail belongs in linked identities and entitlement snapshots.

export function grantFact(capability: string): string {
  return `grant.${capability}`;
}

export const identityFacts = {
  authenticated: "identity.authenticated",
} as const;

export const entitlementFacts = {
  appAccess: "entitlement.app_access",
} as const;

export const grantFacts = {
  globalMember: grantFact("global_member"),
  appAccess: grantFact("app_access"),
  adminAccess: grantFact("admin_access"),
  operator: grantFact("operator"),
} as const;
