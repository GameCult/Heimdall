// Runtime app registration.
//
// App slugs used to be a compile-time union. That was tolerable while every app
// was ours, and it blocks the thing Heimdall is for: an app it has never heard
// of, running on someone else's machine, needs to register against a
// self-hosted instance without forking and rebuilding the auth authority.
//
// A registration is entirely data. It is accepted only if every capability rule
// names a fact Heimdall itself produces or another capability in the same
// profile, which is what stops a registration from granting itself something
// Heimdall never decided was true.

import { builtInAppProfiles, type AppProfile } from "./app-profiles.js";
import { validateCapabilityRules, type CapabilityDefinition } from "./capability-rules.js";
import { providers, type Provider } from "./contracts.js";
import { type HeimdallStore, type StoredRegisteredApp } from "./store/types.js";

/** Slugs are used as JWT audiences and storage keys; keep them boring. */
const SLUG_PATTERN = /^[a-z][a-z0-9_-]{1,62}$/;

export interface AppRegistrationRequest {
  slug: string;
  displayName: string;
  profileVersion?: string;
  identityProviders: string[];
  entitlementSources?: string[];
  managedConnectionProviders?: string[];
  capabilities: CapabilityDefinition[];
  redirectUris: string[];
}

export interface RegistrationProblem {
  field: string;
  reason: string;
}

export function isBuiltInApp(slug: string): boolean {
  return Object.hasOwn(builtInAppProfiles, slug);
}

function isKnownProvider(value: string): value is Provider {
  return (providers as readonly string[]).includes(value);
}

/**
 * A redirect URI is where an authorization code is delivered, so a permissive
 * one is a token-theft primitive rather than a convenience. Absolute, no
 * fragment, and TLS unless it is loopback.
 */
function redirectUriProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "Redirect URI must be an absolute URL.";
  }
  if (url.hash) return "Redirect URI must not carry a fragment.";
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    return "Redirect URI must use https, except on loopback.";
  }
  return null;
}

export function validateAppRegistration(request: AppRegistrationRequest): RegistrationProblem[] {
  const problems: RegistrationProblem[] = [];

  if (!SLUG_PATTERN.test(request.slug ?? "")) {
    problems.push({
      field: "slug",
      reason: "Slug must be 2-63 characters, lowercase, starting with a letter, using only a-z 0-9 _ and -.",
    });
  } else if (isBuiltInApp(request.slug)) {
    // Otherwise a registration could shadow a shipped app and inherit its
    // audience, which is impersonation rather than registration.
    problems.push({ field: "slug", reason: `Slug '${request.slug}' is reserved by a built-in app profile.` });
  }

  if (!request.displayName?.trim()) {
    problems.push({ field: "displayName", reason: "A display name is required." });
  }

  for (const [field, values] of [
    ["identityProviders", request.identityProviders],
    ["entitlementSources", request.entitlementSources ?? []],
    ["managedConnectionProviders", request.managedConnectionProviders ?? []],
  ] as const) {
    for (const value of values ?? []) {
      if (!isKnownProvider(value)) {
        problems.push({ field, reason: `Unknown provider '${value}'.` });
      }
    }
  }

  if (!request.identityProviders?.length) {
    problems.push({ field: "identityProviders", reason: "At least one identity provider is required." });
  }

  if (!request.redirectUris?.length) {
    problems.push({ field: "redirectUris", reason: "At least one redirect URI is required." });
  }
  for (const uri of request.redirectUris ?? []) {
    const problem = redirectUriProblem(uri);
    if (problem) problems.push({ field: "redirectUris", reason: `${problem} (${uri})` });
  }

  if (!request.capabilities?.length) {
    problems.push({ field: "capabilities", reason: "At least one capability is required." });
  }
  for (const problem of validateCapabilityRules(request.capabilities ?? [])) {
    problems.push({ field: `capabilities.${problem.capability}`, reason: problem.reason });
  }

  return problems;
}

export class AppRegistrationError extends Error {
  constructor(readonly problems: RegistrationProblem[]) {
    super(`App registration rejected: ${problems.map((problem) => problem.reason).join(" ")}`);
    this.name = "AppRegistrationError";
  }
}

export function registeredAppToProfile(app: StoredRegisteredApp): AppProfile {
  return {
    slug: app.slug,
    displayName: app.displayName,
    profileVersion: app.profileVersion,
    identityProviders: app.identityProviders,
    entitlementSources: app.entitlementSources,
    managedConnectionProviders: app.managedConnectionProviders,
    capabilities: app.capabilities,
  };
}

/**
 * Built-ins first, so a shipped app cannot be shadowed even if a row for it
 * somehow exists. Registration refuses those slugs, and this is the second
 * place that holds.
 */
export async function resolveAppProfile(store: HeimdallStore, slug: string): Promise<AppProfile | null> {
  const builtIn = builtInAppProfiles[slug as keyof typeof builtInAppProfiles];
  if (builtIn) return builtIn;
  const registered = await store.findRegisteredApp(slug);
  return registered ? registeredAppToProfile(registered) : null;
}

export async function listAppProfiles(store: HeimdallStore): Promise<AppProfile[]> {
  const registered = await store.listRegisteredApps();
  return [
    ...Object.values(builtInAppProfiles),
    ...registered.filter((app) => !isBuiltInApp(app.slug)).map(registeredAppToProfile),
  ];
}
