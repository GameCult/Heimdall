import { randomUUID } from "node:crypto";
import {
  type AccessClaimPayload,
  type AppSlug,
  type LinkedIdentityInput,
  type RefreshTokenPayload,
} from "./contracts.js";
import { evaluateSharedCapabilities, getAppProfile, type AppProfile } from "./app-profiles.js";
import { type HeimdallConfig } from "./config.js";
import { identityFacts } from "./facts.js";
import { signJwt, type RuntimeKeyMaterial } from "./signing.js";
import { type CreateSessionInput, type HeimdallStore } from "./store/types.js";

/** How long a step-up sign-in's proof stays good for an action that demands it (identity unlink). */
export const STEP_UP_PROOF_TTL_SECONDS = 600;

/** How long a plain sign-in's proof stays good for an action that accepts a weak proof (an identity move). */
export const AUTH_PROOF_TTL_SECONDS = 300;

function nowEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function clampTtlSeconds(value: number, fallback: number): number {
  if (!Number.isFinite(value)) {
    return fallback;
  }

  return Math.max(60, Math.min(86_400, Math.trunc(value)));
}

function normalizeFacts(accountId: string, linkedIdentities: LinkedIdentityInput[], facts: string[]): string[] {
  const normalized = new Set(facts);

  if (accountId.trim() || linkedIdentities.length) {
    normalized.add(identityFacts.authenticated);
  }

  return [...normalized].sort();
}

export interface IssueAccessClaimInput {
  appSlug: AppSlug;
  accountId: string;
  displayName?: string;
  linkedIdentities: LinkedIdentityInput[];
  facts: string[];
  /**
   * The claim names the account and its identities and carries no facts and
   * no capabilities (a managed-credential connect for a provider that is not
   * an identity provider). The facts are not even `identity.authenticated`.
   */
  withoutCapabilities?: boolean;
  sessionId?: string;
  accessRevision?: number;
  ttlSeconds?: number;
  /** Epoch seconds of a step-up sign-in completing; only that callback sets it, a refresh never does. */
  stepUpAt?: number;
  /** Required with stepUpAt (`provider:<name>`); the claim never carries one without the other. */
  stepUpMethod?: string;
  /** Epoch seconds of the sign-in that minted this token, with authIdentityId (both or neither). Only a sign_in callback sets them; a refresh, link or connect never does. */
  authAt?: number;
  /** The linked_identities.id the sign-in came through. */
  authIdentityId?: string;
}

export interface IssuedAccessClaimResult {
  session: {
    accountId: string;
    sessionId: string;
    appSlug: AppSlug;
    accessRevision: number;
    expiresAt: string;
  };
  accessToken: string;
  refreshToken: string;
  refresh: {
    expiresAt: string;
  };
  claimSet: AccessClaimPayload;
  verification: {
    issuer: string;
    jwksUri: string;
    alg: string;
    kid: string;
  };
  sharedCapabilities: string[];
  hybridCapabilities: AppProfile["capabilities"];
}

export async function issueAccessClaim(options: {
  config: HeimdallConfig;
  keys: RuntimeKeyMaterial;
  store: HeimdallStore;
  input: IssueAccessClaimInput;
}): Promise<IssuedAccessClaimResult> {
  const profile = getAppProfile(options.input.appSlug);
  if (!profile) {
    // An unregistered audience must not receive a signed claim: the token
    // would name an app no verifier can resolve a profile for.
    throw new Error(`Cannot issue an access claim for unknown app '${options.input.appSlug}'.`);
  }
  const withoutCapabilities = options.input.withoutCapabilities === true;
  const facts = withoutCapabilities
    ? []
    : normalizeFacts(options.input.accountId, options.input.linkedIdentities, options.input.facts);
  // Every shared capability needs a non-empty anyOf (capability-rules), so an
  // empty fact set yields no capabilities: facts are the one owner of that.
  const sharedCapabilities = evaluateSharedCapabilities(profile, {
    accountId: options.input.accountId,
    facts: new Set(facts),
    identities: options.input.linkedIdentities,
  });

  const issuedAt = nowEpochSeconds();
  const ttlSeconds = clampTtlSeconds(
    options.input.ttlSeconds ?? options.config.sessionTtlSeconds,
    options.config.sessionTtlSeconds
  );
  const expiresAtEpoch = issuedAt + ttlSeconds;
  const refreshTtlSeconds = Math.max(ttlSeconds, Math.trunc(options.config.refreshTtlSeconds));
  const refreshExpiresAtEpoch = issuedAt + refreshTtlSeconds;
  const sessionId = options.input.sessionId ?? randomUUID();
  const accessRevision = options.input.accessRevision ?? 1;

  const claimSet: AccessClaimPayload = {
    iss: options.config.issuer,
    aud: profile.slug,
    sub: options.input.accountId,
    sid: sessionId,
    jti: randomUUID(),
    iat: issuedAt,
    nbf: issuedAt,
    exp: expiresAtEpoch,
    typ: "heimdall_access",
    account_id: options.input.accountId,
    access_revision: accessRevision,
    app: {
      slug: profile.slug,
      profile_version: profile.profileVersion,
    },
    facts,
    capabilities: sharedCapabilities,
    identities: options.input.linkedIdentities,
  };

  if (options.input.stepUpAt !== undefined) {
    claimSet.step_up_at = options.input.stepUpAt;
    if (options.input.stepUpMethod !== undefined) {
      claimSet.step_up_method = options.input.stepUpMethod;
    }
  }

  if (options.input.authAt !== undefined && options.input.authIdentityId !== undefined) {
    claimSet.auth_at = options.input.authAt;
    claimSet.auth_identity_id = options.input.authIdentityId;
  }

  if (options.input.displayName) {
    claimSet.display_name = options.input.displayName;
  }

  const accessToken = signJwt(claimSet as unknown as Record<string, unknown>, options.keys);
  const refreshClaimSet: RefreshTokenPayload = {
    iss: options.config.issuer,
    aud: profile.slug,
    sub: options.input.accountId,
    sid: sessionId,
    jti: randomUUID(),
    iat: issuedAt,
    nbf: issuedAt,
    exp: refreshExpiresAtEpoch,
    typ: "heimdall_refresh",
    account_id: options.input.accountId,
    access_revision: accessRevision,
    app: {
      slug: profile.slug,
      profile_version: profile.profileVersion,
    },
  };
  const refreshToken = signJwt(refreshClaimSet as unknown as Record<string, unknown>, options.keys);
  const sessionRecord: CreateSessionInput = {
    id: sessionId,
    accountId: options.input.accountId,
    appSlug: profile.slug,
    createdAt: new Date(issuedAt * 1000).toISOString(),
    lastSeenAt: new Date(issuedAt * 1000).toISOString(),
    expiresAt: new Date(refreshExpiresAtEpoch * 1000).toISOString(),
    accessRevision,
    claimsJson: claimSet as unknown as Record<string, unknown>,
  };
  await options.store.createSession(sessionRecord);

  return {
    session: {
      accountId: options.input.accountId,
      sessionId,
      appSlug: profile.slug,
      accessRevision,
      expiresAt: sessionRecord.expiresAt,
    },
    accessToken,
    refreshToken,
    refresh: {
      expiresAt: sessionRecord.expiresAt,
    },
    claimSet,
    verification: {
      issuer: options.config.issuer,
      jwksUri: `${options.config.publicBaseUrl}/.well-known/jwks.json`,
      alg: options.keys.alg,
      kid: options.keys.kid,
    },
    sharedCapabilities,
    hybridCapabilities: withoutCapabilities
      ? []
      : profile.capabilities.filter((capability) => capability.mode === "hybrid"),
  };
}

/**
 * A new access token for the session the bearer already holds, carrying proof
 * the calling app asserted. Everything the bearer claimed is copied and
 * nothing is recomputed, so the route can add proof and no capability; `exp`
 * stays the bearer's, so it cannot extend a lifetime; no refresh token is
 * minted and no session row is written, so it cannot extend the session.
 */
export function signAssertedStepUpClaim(options: {
  keys: RuntimeKeyMaterial;
  bearerClaims: Record<string, unknown>;
  method: string;
}): { accessToken: string; claimSet: Record<string, unknown>; stepUpAt: number } {
  const stepUpAt = nowEpochSeconds();
  const claimSet = {
    ...options.bearerClaims,
    jti: randomUUID(),
    iat: stepUpAt,
    nbf: stepUpAt,
    step_up_at: stepUpAt,
    step_up_method: options.method,
  };
  return { accessToken: signJwt(claimSet, options.keys), claimSet, stepUpAt };
}

/**
 * How fresh a bearer's proof of the member is, from its claims alone:
 * `strong` when a step-up (Heimdall's or the app's asserted one) happened in
 * the last STEP_UP_PROOF_TTL_SECONDS, else `weak` when the sign-in did in the
 * last AUTH_PROOF_TTL_SECONDS, else null. The one freshness rule: identity
 * unlink and identity moves both read it.
 */
export function proofTier(claims: Record<string, unknown>, nowS: number): "strong" | "weak" | null {
  const within = (at: unknown, window: number) => typeof at === "number" && at <= nowS && nowS - at <= window;
  if (within(claims.step_up_at, STEP_UP_PROOF_TTL_SECONDS)) return "strong";
  if (within(claims.auth_at, AUTH_PROOF_TTL_SECONDS)) return "weak";
  return null;
}

/**
 * What a fresh proof covers of its account: `account` (every login) only for a
 * strong proof whose step_up_method the app's profile lists as an account
 * proof; otherwise the one login the sign-in came through (its id); otherwise
 * nothing. A proof through login X never speaks for the account's other logins.
 */
export function proofCovers(
  claims: Record<string, unknown>,
  accountProofMethods: readonly string[],
  nowS: number
): "account" | string | null {
  if (
    proofTier(claims, nowS) === "strong" &&
    typeof claims.step_up_method === "string" &&
    accountProofMethods.includes(claims.step_up_method)
  ) {
    return "account";
  }
  return typeof claims.auth_identity_id === "string" ? claims.auth_identity_id : null;
}
