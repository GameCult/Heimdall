import {
  evaluateCapabilityRules,
  type CapabilityDefinition,
  type CapabilityMode,
} from "./capability-rules.js";
import { type AppSlug, type LinkedIdentityInput, type Provider } from "./contracts.js";
import { entitlementFacts, grantFacts, identityFacts } from "./facts.js";

export type { CapabilityDefinition, CapabilityMode };

export interface ClaimEvaluationContext {
  accountId: string;
  facts: Set<string>;
  identities: LinkedIdentityInput[];
}

/**
 * An app's auth profile. Entirely data.
 *
 * It used to carry an evaluateSharedCapabilities function beside a sharedRule
 * string that described what the function did — two representations of one rule,
 * free to drift, and the reason a profile could not arrive at runtime. Every
 * rule was a disjunction over a closed vocabulary, so anyOf now carries it and
 * evaluation is a free function over the data.
 */
export interface AppProfile {
  slug: AppSlug;
  displayName: string;
  profileVersion: string;
  identityProviders: Provider[];
  entitlementSources: Provider[];
  managedConnectionProviders: Provider[];
  capabilities: CapabilityDefinition[];
}

/** The membership signal shared by every app that gates on GameCult membership. */
const gameCultMembership = [
  entitlementFacts.appAccess,
  grantFacts.globalMember,
  grantFacts.appAccess,
];

const repixelizerProfile: AppProfile = {
  slug: "repixelizer",
  displayName: "Repixelizer",
  profileVersion: "2026-04-26.1",
  identityProviders: ["discord", "patreon"],
  entitlementSources: ["discord", "patreon"],
  managedConnectionProviders: [],
  capabilities: [
    {
      key: "app_access",
      mode: "shared",
      summary: "May load the protected hosted GUI.",
      anyOf: gameCultMembership,
    },
    {
      key: "queue_submit",
      mode: "shared",
      summary: "May create a repixelizer job.",
      anyOf: ["app_access"],
    },
    {
      key: "job_read_own",
      mode: "hybrid",
      summary: "May read own job state, event stream, and final output.",
      localRequirement: "Host app must combine app_access with job ownership.",
    },
    {
      key: "job_cancel_own",
      mode: "hybrid",
      summary: "May cancel own queued or running job.",
      localRequirement: "Host app must combine app_access with job ownership.",
    },
    {
      key: "admin_access",
      mode: "shared",
      summary: "May inspect grant/admin surfaces.",
      anyOf: [grantFacts.operator, grantFacts.adminAccess],
    },
  ],
};

const streampixelsProfile: AppProfile = {
  slug: "streampixels",
  displayName: "StreamPixels",
  profileVersion: "2026-04-26",
  identityProviders: ["twitch", "youtube"],
  entitlementSources: [],
  managedConnectionProviders: ["twitch", "youtube"],
  capabilities: [
    {
      key: "viewer_access",
      mode: "shared",
      summary: "Authenticated viewer session for control-plane surfaces.",
      anyOf: [identityFacts.authenticated],
    },
    {
      key: "creator_access",
      mode: "hybrid",
      summary: "Creator-scoped route access.",
      localRequirement:
        "Host app must combine authenticated session claims with local creator membership.",
    },
    {
      key: "creator_admin",
      mode: "hybrid",
      summary: "Creator-scoped write/admin access.",
      localRequirement:
        "Host app must combine authenticated session claims with local creator admin membership.",
    },
    {
      key: "operator_access",
      mode: "shared",
      summary: "Global operator access.",
      anyOf: [grantFacts.operator],
    },
  ],
};

const bifrostProfile: AppProfile = {
  slug: "bifrost",
  displayName: "Bifrost",
  profileVersion: "2026-06-08",
  identityProviders: ["discord", "patreon"],
  entitlementSources: ["discord", "patreon"],
  managedConnectionProviders: [],
  capabilities: [
    {
      key: "member_access",
      mode: "shared",
      summary: "May enter the Bifrost member alpha through a Heimdall-verified GameCult membership signal.",
      anyOf: gameCultMembership,
    },
  ],
};

const ghostlightProfile: AppProfile = {
  slug: "ghostlight",
  displayName: "Ghostlight Dungeon",
  profileVersion: "2026-08-22",
  identityProviders: ["discord"],
  entitlementSources: ["discord"],
  managedConnectionProviders: [],
  capabilities: [
    {
      key: "app_access",
      mode: "shared",
      summary: "May enter Ghostlight Dungeon after Heimdall verifies the app-supplied GameCult Discord role policy.",
      anyOf: gameCultMembership,
    },
    {
      key: "campaign_play",
      mode: "hybrid",
      summary: "May play campaigns owned by the authenticated Ghostlight account.",
      localRequirement: "Ghostlight must combine app_access with local campaign ownership.",
    },
  ],
};

/**
 * Profiles that ship with Heimdall. These are seed data, not special cases:
 * a registered app produces the same shape and is evaluated by the same code.
 */
export const builtInAppProfiles: Record<AppSlug, AppProfile> = {
  repixelizer: repixelizerProfile,
  streampixels: streampixelsProfile,
  bifrost: bifrostProfile,
  ghostlight: ghostlightProfile,
};

export const appProfiles = builtInAppProfiles;

export function getAppProfile(appSlug: AppSlug): AppProfile {
  return appProfiles[appSlug];
}

/** Shared capabilities the account holds for this app, from the profile's rules. */
export function evaluateSharedCapabilities(profile: AppProfile, context: ClaimEvaluationContext): string[] {
  return evaluateCapabilityRules(profile.capabilities, context.facts);
}

export function serializeAppProfile(profile: AppProfile): Record<string, unknown> {
  return {
    slug: profile.slug,
    displayName: profile.displayName,
    profileVersion: profile.profileVersion,
    identityProviders: profile.identityProviders,
    entitlementSources: profile.entitlementSources,
    managedConnectionProviders: profile.managedConnectionProviders,
    capabilities: profile.capabilities,
  };
}

export function supportsProvider(profile: AppProfile, provider: Provider): boolean {
  return (
    profile.identityProviders.includes(provider) ||
    profile.managedConnectionProviders.includes(provider) ||
    profile.entitlementSources.includes(provider)
  );
}
