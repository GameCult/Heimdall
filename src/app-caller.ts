// The single caller-identity authority for app-backend HTTP requests.
//
// Before this module existed, "is this caller app X" was decided ad hoc in
// five places: three inline secret reads in app.ts, a slug-name trust
// (`appSlug === "repixelizer"`), and a handoff-kind trust
// (`handoff.kind === "backend_callback"`) that let a caller assert its own
// identity by choosing a request shape. A handler now receives an AppCaller
// value or nothing; it never reads the header or the secret table itself.
//
// The loopback private command plane is the second, non-HTTP entry to this
// same authority: it opens its envelope with the same per-app secret and
// checks sourceRuntimeId, then constructs an AppCaller directly and calls the
// same handler functions app.ts uses — it does not re-enter HTTP.

import { timingSafeEqual } from "node:crypto";
import { type AppSlug } from "./contracts.js";
import { type HeimdallConfig } from "./config.js";

// `{ appSlug }` used to satisfy this type structurally, so any module could
// construct a caller by writing the literal — nothing but grep discipline
// stopped an importer from forging one. The symbol brand stops that at
// compile time, but a cast (`as unknown as AppCaller`) or a JSON round-trip
// defeats a type-level check trivially; nothing enforced it at runtime. The
// module-private WeakSet below is the enforcement: brandCaller registers
// every value it mints, and isAppCaller is the only way a consumer may trust
// one. A forged literal — even one carrying the symbol key by hand — was
// never added to the set and is rejected.
const callerBrand = Symbol("AppCaller");

export interface AppCaller {
  readonly appSlug: AppSlug;
  readonly [callerBrand]: true;
}

const mintedCallers = new WeakSet<object>();

function brandCaller(appSlug: AppSlug): AppCaller {
  const caller: AppCaller = { appSlug, [callerBrand]: true };
  mintedCallers.add(caller);
  return caller;
}

/**
 * The runtime half of the brand. `startOAuthFlow` and `refreshAppSession`
 * call this instead of trusting the `AppCaller | null` type alone — a value
 * that is not exactly the object `resolveAppCaller` or
 * `callerFromOpenedEnvelope` returned is never in the set, regardless of
 * shape or cast.
 */
export function isAppCaller(value: unknown): value is AppCaller {
  return typeof value === "object" && value !== null && mintedCallers.has(value);
}

/**
 * The private command plane already authenticated `appSlug` by opening its
 * envelope with the app's shared secret and checking sourceRuntimeId before
 * ever calling this. It has no header to read, so it cannot go through
 * resolveAppCaller; this is the only other place an AppCaller may be minted.
 */
export function callerFromOpenedEnvelope(appSlug: AppSlug): AppCaller {
  return brandCaller(appSlug);
}

/** Timing-safe comparator. The only comparator anywhere a shared secret is checked. */
export function secretMatches(expected: string | undefined, provided: string | undefined): boolean {
  if (!expected || !provided) {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(provided);
  return expectedBuffer.length === providedBuffer.length && timingSafeEqual(expectedBuffer, providedBuffer);
}

function getSharedSecretHeader(headers: Record<string, string | string[] | undefined>): string | undefined {
  const header = headers["x-heimdall-app-secret"];
  return Array.isArray(header) ? header[0] : header;
}

/**
 * Decide whether an HTTP request is authenticated as `appSlug`. Reads exactly
 * one header (`x-heimdall-app-secret`) and one table
 * (`config.appSharedSecrets[appSlug]`, per-app only — there is no global
 * fallback). Returns null rather than throwing: callers turn null into the
 * one 401 `app_auth_required` shape.
 */
export function resolveAppCaller(
  config: HeimdallConfig,
  appSlug: AppSlug,
  headers: Record<string, string | string[] | undefined>
): AppCaller | null {
  return secretMatches(config.appSharedSecrets[appSlug], getSharedSecretHeader(headers)) ? brandCaller(appSlug) : null;
}
