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

export interface AppCaller {
  appSlug: AppSlug;
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
  return secretMatches(config.appSharedSecrets[appSlug], getSharedSecretHeader(headers)) ? { appSlug } : null;
}
