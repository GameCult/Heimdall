// App profile resolution: built-in profiles plus whatever is provisioned
// directly in the `registered_apps` table.
//
// This used to also own runtime registration (POST /v1/apps): a caller
// self-registered a profile and got back a client_secret nobody ever
// verified. That HTTP surface, its validation, and the minted secret are
// gone (the caller-identity cut). `registered_apps` remains a profile store
// beneath the built-in profiles; a row is now provisioned by direct SQL
// against Postgres (or InMemoryStore.seedRegisteredApp for tests), not by an
// app calling Heimdall.

import { builtInAppProfiles, type AppProfile } from "./app-profiles.js";
import { type HeimdallStore, type StoredRegisteredApp } from "./store/types.js";

export function isBuiltInApp(slug: string): boolean {
  return Object.hasOwn(builtInAppProfiles, slug);
}

/**
 * A registered app's `redirectUris` is the same "where may this app send a
 * browser back to" data a runtime registration used to validate; it becomes
 * the profile's return-origin allowlist. An unparseable entry is dropped
 * rather than widening the allowlist with garbage.
 */
function returnOriginsFromRedirectUris(redirectUris: string[]): string[] {
  const origins = new Set<string>();
  for (const uri of redirectUris) {
    try {
      origins.add(new URL(uri).origin);
    } catch {
      // Dropped: an unparseable redirect URI cannot name a trustworthy origin.
    }
  }
  return [...origins];
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
    allowedReturnOrigins: returnOriginsFromRedirectUris(app.redirectUris),
  };
}

/**
 * Built-ins first, so a shipped app cannot be shadowed even if a row for it
 * somehow exists.
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
