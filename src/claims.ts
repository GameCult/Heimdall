import { randomUUID } from "node:crypto";
import {
  type AccessClaimPayload,
  type AppSlug,
  type IssueClaimRequest,
  type LinkedIdentityInput,
} from "./contracts.js";
import { getAppProfile } from "./app-profiles.js";
import { type HeimdallConfig } from "./config.js";
import { signJwt, type RuntimeKeyMaterial } from "./signing.js";
import { type CreateSessionInput, type HeimdallStore } from "./store/types.js";

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
    normalized.add("identity.authenticated");
  }

  return [...normalized].sort();
}

export interface IssueAccessClaimInput {
  appSlug: AppSlug;
  accountId: string;
  displayName?: string;
  linkedIdentities: LinkedIdentityInput[];
  facts: string[];
  sessionId?: string;
  accessRevision?: number;
  ttlSeconds?: number;
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
  claimSet: AccessClaimPayload;
  verification: {
    issuer: string;
    jwksUri: string;
    alg: string;
    kid: string;
  };
  sharedCapabilities: string[];
  hybridCapabilities: ReturnType<typeof getAppProfile>["capabilities"];
}

export async function issueAccessClaim(options: {
  config: HeimdallConfig;
  keys: RuntimeKeyMaterial;
  store: HeimdallStore;
  input: IssueAccessClaimInput;
}): Promise<IssuedAccessClaimResult> {
  const profile = getAppProfile(options.input.appSlug);
  const facts = normalizeFacts(options.input.accountId, options.input.linkedIdentities, options.input.facts);
  const factSet = new Set(facts);
  const sharedCapabilities = profile.evaluateSharedCapabilities({
    accountId: options.input.accountId,
    facts: factSet,
    identities: options.input.linkedIdentities,
  });

  const issuedAt = nowEpochSeconds();
  const ttlSeconds = clampTtlSeconds(
    options.input.ttlSeconds ?? options.config.sessionTtlSeconds,
    options.config.sessionTtlSeconds
  );
  const expiresAtEpoch = issuedAt + ttlSeconds;
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

  if (options.input.displayName) {
    claimSet.display_name = options.input.displayName;
  }

  const accessToken = signJwt(claimSet as unknown as Record<string, unknown>, options.keys);
  const sessionRecord: CreateSessionInput = {
    id: sessionId,
    accountId: options.input.accountId,
    appSlug: profile.slug,
    createdAt: new Date(issuedAt * 1000).toISOString(),
    lastSeenAt: new Date(issuedAt * 1000).toISOString(),
    expiresAt: new Date(expiresAtEpoch * 1000).toISOString(),
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
    claimSet,
    verification: {
      issuer: options.config.issuer,
      jwksUri: `${options.config.publicBaseUrl}/.well-known/jwks.json`,
      alg: options.keys.alg,
      kid: options.keys.kid,
    },
    sharedCapabilities,
    hybridCapabilities: profile.capabilities.filter((capability) => capability.mode === "hybrid"),
  };
}

export function mapIssueClaimRequest(appSlug: AppSlug, request: IssueClaimRequest): IssueAccessClaimInput {
  const input: IssueAccessClaimInput = {
    appSlug,
    accountId: request.accountId,
    linkedIdentities: request.linkedIdentities ?? [],
    facts: request.facts ?? [],
  };

  if (request.displayName !== undefined) {
    input.displayName = request.displayName;
  }

  if (request.sessionId !== undefined) {
    input.sessionId = request.sessionId;
  }

  if (request.accessRevision !== undefined) {
    input.accessRevision = request.accessRevision;
  }

  if (request.ttlSeconds !== undefined) {
    input.ttlSeconds = request.ttlSeconds;
  }

  return input;
}
