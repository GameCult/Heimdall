import { type AppSlug, type LinkedIdentityInput, type Provider } from "./contracts.js";

export type CapabilityMode = "shared" | "hybrid";

export interface CapabilityDefinition {
  key: string;
  mode: CapabilityMode;
  summary: string;
  sharedRule?: string;
  localRequirement?: string;
}

export interface ClaimEvaluationContext {
  accountId: string;
  facts: Set<string>;
  identities: LinkedIdentityInput[];
}

export interface AppProfile {
  slug: AppSlug;
  displayName: string;
  profileVersion: string;
  identityProviders: Provider[];
  entitlementSources: Provider[];
  managedConnectionProviders: Provider[];
  capabilities: CapabilityDefinition[];
  evaluateSharedCapabilities(context: ClaimEvaluationContext): string[];
}

function hasAnyFact(facts: Set<string>, values: readonly string[]): boolean {
  return values.some((value) => facts.has(value));
}

const repixelizerProfile: AppProfile = {
  slug: "repixelizer",
  displayName: "Repixelizer",
  profileVersion: "2026-04-26",
  identityProviders: ["discord", "patreon"],
  entitlementSources: ["discord", "patreon"],
  managedConnectionProviders: [],
  capabilities: [
    {
      key: "app_access",
      mode: "shared",
      summary: "May load the protected hosted GUI.",
      sharedRule:
        "discord.allowed_role || patreon.allowed_tier || grant.global_member || grant.app_access",
    },
    {
      key: "queue_submit",
      mode: "shared",
      summary: "May create a repixelizer job.",
      sharedRule: "app_access",
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
      sharedRule: "grant.operator || grant.admin_access",
    },
  ],
  evaluateSharedCapabilities(context) {
    const capabilities: string[] = [];
    const appAccess = hasAnyFact(context.facts, [
      "discord.allowed_role",
      "patreon.allowed_tier",
      "grant.global_member",
      "grant.app_access",
    ]);

    if (appAccess) {
      capabilities.push("app_access", "queue_submit");
    }

    if (hasAnyFact(context.facts, ["grant.operator", "grant.admin_access"])) {
      capabilities.push("admin_access");
    }

    return capabilities;
  },
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
      sharedRule: "identity.authenticated",
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
      sharedRule: "grant.operator",
    },
  ],
  evaluateSharedCapabilities(context) {
    const capabilities: string[] = [];

    if (context.facts.has("identity.authenticated")) {
      capabilities.push("viewer_access");
    }

    if (context.facts.has("grant.operator")) {
      capabilities.push("operator_access");
    }

    return capabilities;
  },
};

export const appProfiles: Record<AppSlug, AppProfile> = {
  repixelizer: repixelizerProfile,
  streampixels: streampixelsProfile,
};

export function getAppProfile(appSlug: AppSlug): AppProfile {
  return appProfiles[appSlug];
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
