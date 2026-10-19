import { type HeimdallConfig } from "./config.js";
import { type Provider } from "./contracts.js";
import { type TokenCustody } from "./custody.js";
import { type OAuthProviderRuntime, type OAuthRuntimeRegistry, ProviderResponseError } from "./oauth.js";
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
 * Accepted residual risk (docs/service-contract.md): one presentation per
 * process per burst, so N processes may present one token N times.
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
  const decide = async (locked: StoredLinkedIdentity): Promise<CredentialDecision> => {
    if (!locked.accessTokenEncrypted || !dueForRefresh(locked, runtime, clock())) {
      return { kind: "keep" };
    }
    const updatedAt = new Date(clock()).toISOString();
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
        return { kind: "revoke", updatedAt };
      }
      throw new ManagedCredentialRefreshFailed(provider);
    }

    let refreshTokenEncrypted: string;
    if (refreshed.refreshToken) {
      refreshTokenEncrypted = ctx.tokenCustody.encrypt(refreshed.refreshToken);
    } else if (providerCatalog[provider].rotatesRefreshTokens) {
      revocation = "rotation_missing";
      return { kind: "revoke", updatedAt };
    } else {
      refreshTokenEncrypted = locked.refreshTokenEncrypted!;
    }

    // The token set always carries an expiry (the provider's, or the
    // descriptor's default lifetime): the old one is already due, and an
    // unknown one would never come due (dueForRefresh).
    const tokenExpiresAt = refreshed.expiresAt;
    return {
      kind: "rotate",
      accessTokenEncrypted: ctx.tokenCustody.encrypt(refreshed.accessToken),
      refreshTokenEncrypted,
      ...(tokenExpiresAt !== undefined ? { tokenExpiresAt } : {}),
      scopes: refreshed.scope.length ? refreshed.scope : locked.scopes,
      updatedAt,
    };
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
  if (!committed) {
    return { kind: "revoked", identity: withoutTokens(snapshot) };
  }
  return { kind: committed.accessTokenEncrypted ? "current" : "revoked", identity: committed };
}
