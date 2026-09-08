import {
  evaluateCapabilityRules,
  type CapabilityDefinition,
  type CapabilityMode,
} from "./capability-rules.js";
import { type AppSlug, type LinkedIdentityInput, type OAuthEntitlementPolicy, type Provider } from "./contracts.js";
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
  /**
   * Origins `returnTo` may land on for this app. A caller-chosen returnTo is
   * where the browser handoff page postMessages the completion payload
   * (src/browser-handoff.ts), so an unlisted origin is an exfiltration
   * primitive, not a convenience. Compared by URL origin, not prefix.
   */
  allowedReturnOrigins: readonly string[];
  /**
   * Some apps require the caller to supply an entitlement policy of a
   * specific kind on every begin/refresh (ghostlight's caller-owned Discord
   * role gate). Data instead of a per-slug branch in the private command
   * plane; absent for apps with no such requirement.
   */
  requiredEntitlementPolicyKind?: OAuthEntitlementPolicy["kind"];
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
  allowedReturnOrigins: ["https://repixelizer.gamecult.org"],
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
  allowedReturnOrigins: ["https://streampixels.gamecult.org"],
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
  allowedReturnOrigins: ["https://bifrost.gamecult.org"],
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
  allowedReturnOrigins: ["https://yggdrasil.gamecult.org"],
  requiredEntitlementPolicyKind: "discord_role_access",
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
 * Profiles that ship with Heimdall. This is the whole set: runtime app
 * registration (POST /v1/apps, and the `registered_apps` table it fed) was
 * deleted with the caller-identity cut (R21.3) after Soul showed it was
 * unreachable dead code — every HTTP route already enumerates these four
 * slugs in its own JSON schema, so a registered row could never be resolved
 * from a request. A future app with a genuine dynamic-registration need adds
 * that back as a designed, authenticated feature, not by resurrecting this.
 */
export const builtInAppProfiles: Record<AppSlug, AppProfile> = {
  repixelizer: repixelizerProfile,
  streampixels: streampixelsProfile,
  bifrost: bifrostProfile,
  ghostlight: ghostlightProfile,
};

export const appProfiles = builtInAppProfiles;

export function getAppProfile(appSlug: AppSlug): AppProfile | undefined {
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

/**
 * Whether `returnTo` may be handed back to the browser for this app. Origin
 * comparison only (scheme + host + port) — the allowlist names an app's
 * origin once rather than every path it might redirect to. An unparseable
 * URL is refused rather than throwing.
 */
export function isAllowedReturnOrigin(profile: AppProfile, returnTo: string): boolean {
  try {
    return profile.allowedReturnOrigins.includes(new URL(returnTo).origin);
  } catch {
    return false;
  }
}
