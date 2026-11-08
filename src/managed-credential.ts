import { type HeimdallConfig } from "./config.js";
import { type Provider } from "./contracts.js";
import { type TokenCustody } from "./custody.js";
import { type ExpiringTokenSet, type OAuthProviderRuntime, type OAuthRuntimeRegistry, ProviderResponseError } from "./oauth.js";
import { providerCatalog } from "./providers.js";
import { type HeimdallStore } from "./store/index.js";
import { type CredentialDecision, type StoredLinkedIdentity } from "./store/types.js";

/** A stored access token this close to expiry (or past it) is refreshed before use. */
export const MANAGED_CREDENTIAL_REFRESH_SKEW_MS = 5 * 60 * 1000;

/**
 * The longest a refresh may hold the row lock: the provider call is aborted
 * at this bound, and every waiter holds a pooled connection for at most this
 * long behind the holder.
 */
export const MANAGED_CREDENTIAL_REFRESH_TIMEOUT_MS = 10_000;

/**
 * After a refresh attempt fails or times out, no process presents the row's
 * refresh token again until this long has passed (the failure is recorded on
 * the row, read under the lock). A provider that rotates may have consumed the
 * token before the attempt was aborted, and presenting it again reads as theft.
 */
export const MANAGED_CREDENTIAL_REFRESH_BACKOFF_MS = 60 * 1000;

export interface ManagedCredentialContext {
  config: HeimdallConfig;
  store: HeimdallStore;
  tokenCustody: TokenCustody;
  oauthRuntimes: OAuthRuntimeRegistry;
  clock?: () => number;
  timeoutMs?: number;
}

export type ManagedCredentialRevocationReason = "provider_revoked" | "rotation_missing";

/** `revoked` means the identity holds no access token: the provider took the grant back, or it was never held. */
export type ManagedCredentialOutcome =
  | { kind: "current"; identity: StoredLinkedIdentity }
  | { kind: "revoked"; identity: StoredLinkedIdentity };

/**
 * The provider could not be asked, or answered with something that is not a
 * grant verdict (invalid_client, 5xx, timeout, malformed body). The stored
 * tokens are untouched. Carries the provider and nothing the provider said.
 */
export class ManagedCredentialRefreshFailed extends Error {
  readonly code = "managed_credential_refresh_failed";
  readonly provider: Provider;

  constructor(provider: Provider) {
    super(`${providerCatalog[provider].displayName} managed credential refresh failed.`);
    this.name = "ManagedCredentialRefreshFailed";
    this.provider = provider;
  }
}

function dueForRefresh(identity: StoredLinkedIdentity, runtime: OAuthProviderRuntime, now: number): boolean {
  if (!identity.tokenExpiresAt || !identity.refreshTokenEncrypted || !runtime.refreshAccessToken) {
    return false;
  }
  return Date.parse(identity.tokenExpiresAt) - now <= MANAGED_CREDENTIAL_REFRESH_SKEW_MS;
}

/**
 * Whether a failure stamped `failedAt` still holds this clock off. A stamp from
 * a writer whose clock runs ahead reads as the future; one this far ahead or
 * more is skew, not a fresh failure, so the wait stays bounded at twice the
 * backoff.
 */
function withinBackoff(failedAt: string, now: number): boolean {
  const elapsed = now - Date.parse(failedAt);
  return elapsed > -MANAGED_CREDENTIAL_REFRESH_BACKOFF_MS && elapsed < MANAGED_CREDENTIAL_REFRESH_BACKOFF_MS;
}

function withoutTokens(identity: StoredLinkedIdentity): StoredLinkedIdentity {
  const { accessTokenEncrypted: _a, refreshTokenEncrypted: _r, tokenExpiresAt: _e, ...rest } = identity;
  return rest;
}

/**
 * Refreshes in flight in this process, per store and linked identity. The row
 * lock serialises processes; it cannot tell a waiter that queued behind a
 * failed holder from a caller that arrived after the failure, so each waiter
 * would present the same refresh token again. Callers that arrive while an
 * attempt is in flight join it and receive its outcome, success or failure.
 * The entry lives exactly as long as the attempt: a later request retries.
 *
 * Across processes the row owns it: a failed attempt leaves a marker on the
 * row, and a process that takes the lock inside the backoff presents nothing.
 */
const refreshesInFlight = new WeakMap<HeimdallStore, Map<string, Promise<ManagedCredentialOutcome>>>();

/**
 * The one refresh policy. `snapshot` is a hint: it may skip the lock when no
 * refresh is due and never decides one. The row's lock owns when a refresh
 * token is presented across processes; this process makes one attempt per
 * identity at a time; the decision is made on the row as read under the lock.
 */
export async function refreshManagedCredential(
  ctx: ManagedCredentialContext,
  snapshot: StoredLinkedIdentity
): Promise<ManagedCredentialOutcome> {
  const clock = ctx.clock ?? Date.now;
  const runtime = ctx.oauthRuntimes[snapshot.provider];

  if (!snapshot.accessTokenEncrypted) {
    return { kind: "revoked", identity: snapshot };
  }
  if (!dueForRefresh(snapshot, runtime, clock())) {
    return { kind: "current", identity: snapshot };
  }

  let inFlight = refreshesInFlight.get(ctx.store);
  if (!inFlight) {
    inFlight = new Map();
    refreshesInFlight.set(ctx.store, inFlight);
  }
  const joined = inFlight.get(snapshot.id);
  if (joined) {
    return joined;
  }
  const attempt = refreshUnderLock(ctx, snapshot).finally(() => {
    inFlight.delete(snapshot.id);
  });
  inFlight.set(snapshot.id, attempt);
  return attempt;
}

async function refreshUnderLock(
  ctx: ManagedCredentialContext,
  snapshot: StoredLinkedIdentity
): Promise<ManagedCredentialOutcome> {
  const clock = ctx.clock ?? Date.now;
  const provider = snapshot.provider;
  const runtime = ctx.oauthRuntimes[provider];

  let revocation: ManagedCredentialRevocationReason | undefined;
  let failed = false;
  const rotation = (locked: StoredLinkedIdentity, refreshed: ExpiringTokenSet, updatedAt: string): CredentialDecision => {
    let refreshTokenEncrypted: string;
    if (refreshed.refreshToken) {
      refreshTokenEncrypted = ctx.tokenCustody.encrypt(refreshed.refreshToken);
    } else if (providerCatalog[provider].rotatesRefreshTokens) {
      revocation = "rotation_missing";
      return { kind: "revoke", updatedAt };
    } else {
      refreshTokenEncrypted = locked.refreshTokenEncrypted!;
    }

    // The refreshed set always carries an expiry (the provider's, or the
    // descriptor's default lifetime): the old one is already due, and an
    // unknown one would never come due (dueForRefresh).
    return {
      kind: "rotate",
      accessTokenEncrypted: ctx.tokenCustody.encrypt(refreshed.accessToken),
      refreshTokenEncrypted,
      tokenExpiresAt: refreshed.expiresAt,
      scopes: refreshed.scope.length ? refreshed.scope : locked.scopes,
      updatedAt,
    };
  };

  const decide = async (locked: StoredLinkedIdentity): Promise<CredentialDecision> => {
    if (!locked.accessTokenEncrypted || !dueForRefresh(locked, runtime, clock())) {
      return { kind: "keep" };
    }
    if (locked.refreshFailedAt && withinBackoff(locked.refreshFailedAt, clock())) {
      failed = true;
      return { kind: "keep" };
    }
    const refreshToken = ctx.tokenCustody.decrypt(locked.refreshTokenEncrypted!);

    let refreshed;
    try {
      refreshed = await runtime.refreshAccessToken!({
        config: ctx.config,
        refreshToken,
        signal: AbortSignal.timeout(ctx.timeoutMs ?? MANAGED_CREDENTIAL_REFRESH_TIMEOUT_MS),
      });
    } catch (error) {
      if (error instanceof ProviderResponseError && error.oauthError === "invalid_grant") {
        revocation = "provider_revoked";
        return { kind: "revoke", updatedAt: new Date(clock()).toISOString() };
      }
      failed = true;
      return { kind: "failed", failedAt: new Date(clock()).toISOString() };
    }

    // The provider has answered, and may have consumed the token: from here a throw must still leave the marker, which
    // a rolled-back transaction would not (the store writes it on its own for a rotation it could not commit).
    const answeredAt = new Date(clock()).toISOString();
    try {
      return rotation(locked, refreshed, answeredAt);
    } catch {
      failed = true;
      return { kind: "failed", failedAt: new Date(clock()).toISOString() };
    }
  };

  const committed = await ctx.store.updateLinkedIdentityCredential(snapshot.id, decide);
  if (revocation) {
    await ctx.store.createAuditEvent({
      accountId: snapshot.accountId,
      eventType: "managed_credential_revoked",
      eventPayloadJson: { provider, reason: revocation },
      createdAt: new Date(clock()).toISOString(),
    });
  }
  if (failed) {
    throw new ManagedCredentialRefreshFailed(provider);
  }
  if (!committed) {
    return { kind: "revoked", identity: withoutTokens(snapshot) };
  }
  return { kind: committed.accessTokenEncrypted ? "current" : "revoked", identity: committed };
}
