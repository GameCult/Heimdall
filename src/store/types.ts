import {
  type AppSlug,
  type HeimdallAuthAttemptStatus,
  type LinkedIdentityInput,
  type OAuthMode,
  type Provider,
} from "../contracts.js";

export interface StoredAccount {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  displayName?: string;
  primaryEmail?: string;
}

export interface CreateAccountInput {
  id?: string;
  createdAt: string;
  lastSeenAt: string;
  displayName?: string;
  primaryEmail?: string;
}

export interface StoredLinkedIdentity {
  id: string;
  accountId: string;
  provider: Provider;
  providerUserId: string;
  username?: string;
  displayName?: string;
  primaryEmail?: string;
  accessTokenEncrypted?: string;
  refreshTokenEncrypted?: string;
  tokenExpiresAt?: string;
  /** When a refresh attempt last failed; cleared by the next rotation, revocation or re-link. */
  refreshFailedAt?: string;
  scopes: string[];
  profileJson: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLinkedIdentityInput {
  id?: string;
  accountId: string;
  provider: Provider;
  providerUserId: string;
  username?: string;
  displayName?: string;
  primaryEmail?: string;
  accessTokenEncrypted?: string;
  refreshTokenEncrypted?: string;
  tokenExpiresAt?: string;
  scopes: string[];
  profileJson: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

/**
 * What the owner of a refresh decides after reading the row under its lock.
 * `rotate` and `revoke` write token columns, scopes, updated_at and clear the
 * failed-refresh marker; `failed` writes the marker alone. None touches
 * account, profile or identity fields.
 */
export type CredentialDecision =
  | { kind: "keep" }
  | {
      kind: "rotate";
      accessTokenEncrypted: string;
      refreshTokenEncrypted: string;
      tokenExpiresAt: string;
      scopes: string[];
      updatedAt: string;
      /** The provider rotates refresh tokens, so the one presented is spent whether or not this decision commits. */
      consumedRefreshToken: boolean;
    }
  | { kind: "revoke"; updatedAt: string }
  | { kind: "failed"; failedAt: string };

export interface StoredSession {
  id: string;
  accountId: string;
  appSlug: AppSlug;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  accessRevision: number;
  claimsJson: Record<string, unknown>;
}

export interface CreateSessionInput {
  id: string;
  accountId: string;
  appSlug: AppSlug;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  accessRevision: number;
  claimsJson: Record<string, unknown>;
}

export interface StoredCapabilityGrant {
  id: string;
  accountId: string;
  scopeType: "global" | "app";
  scopeId?: AppSlug;
  capability: string;
  source: string;
  status: "active" | "revoked";
  expiresAt?: string;
  note?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateCapabilityGrantInput {
  id?: string;
  accountId: string;
  scopeType: "global" | "app";
  scopeId?: AppSlug;
  capability: string;
  source: string;
  status: "active" | "revoked";
  expiresAt?: string;
  note?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateEntitlementSnapshotInput {
  accountId: string;
  provider: Provider;
  scope: string;
  evaluatedAt: string;
  isAllowed: boolean;
  reasonCode: string;
  reasonDetail?: string;
  rawSummaryJson: Record<string, unknown>;
}

export interface CreateAuditEventInput {
  id?: string;
  accountId?: string;
  sessionId?: string;
  appSlug?: AppSlug;
  eventType: string;
  eventPayloadJson: Record<string, unknown>;
  createdAt: string;
}

export interface StoredAuthCompletion {
  code: string;
  /**
   * The browser-carried attempt handle this completion correlates to, if the
   * handoff supplied one. Correlation only: it is never the redemption
   * secret, and never used to look up a completion by anyone but the
   * envelope-authenticated private command plane.
   */
  attemptId?: string;
  appSlug: AppSlug;
  provider: Provider;
  mode: OAuthMode;
  accountId: string;
  sessionId: string;
  returnTo: string;
  /** The connection target the signed state named, if any; compared at redeem. */
  targetId?: string;
  createdAt: string;
  expiresAt: string;
  consumedAt?: string;
  payloadJson: Record<string, unknown>;
}

export interface ClaimOAuthStateUseInput {
  jti: string;
  phase: "launch" | "callback";
  appSlug: AppSlug;
  usedAt: string;
  expiresAt: string;
}

export interface CreateAuthCompletionInput {
  /**
   * Correlation handle only (see StoredAuthCompletion.attemptId). The store
   * always mints `code` itself; a caller cannot choose it.
   */
  attemptId?: string;
  targetId?: string;
  appSlug: AppSlug;
  provider: Provider;
  mode: OAuthMode;
  accountId: string;
  sessionId: string;
  returnTo: string;
  createdAt: string;
  expiresAt: string;
  payloadJson: Record<string, unknown>;
}

/**
 * A link the callback has verified but not written. The identity attaches to
 * `accountId` (the account whose Heimdall access token began the link) only
 * when that same account confirms it; until then no linked-identity row
 * exists. `identity` holds the already-encrypted row to write.
 */
export interface StoredPendingLink {
  id: string;
  appSlug: AppSlug;
  accountId: string;
  provider: Provider;
  providerUserId: string;
  identity: UpsertLinkedIdentityInput;
  returnTo: string;
  createdAt: string;
  expiresAt: string;
  consumedAt?: string;
}

/** The store mints `id`; a caller cannot choose it. */
export type CreatePendingLinkInput = Omit<StoredPendingLink, "id" | "consumedAt">;

export interface StoredAuthAttempt {
  handle: string;
  appSlug: AppSlug;
  provider: Provider;
  mode: OAuthMode;
  returnTo: string;
  status: HeimdallAuthAttemptStatus;
  createdAt: string;
  expiresAt: string;
  completedAt?: string;
  consumedAt?: string;
  denialCode?: string;
}

export interface CreateAuthAttemptInput {
  handle?: string;
  appSlug: AppSlug;
  provider: Provider;
  mode: OAuthMode;
  returnTo: string;
  createdAt: string;
  expiresAt: string;
}

export interface StoredPrivateCommandReceipt {
  appSlug: AppSlug;
  idempotencyKey: string;
  requestFingerprint: string;
  status: string;
  contentSchema: string;
  envelopeBase64: string;
  createdAt: string;
  expiresAt: string;
}

export type CreatePrivateCommandReceiptInput = StoredPrivateCommandReceipt;

/**
 * What a person agreed to, or took back. Append-only: a grant row is never
 * edited, and a revocation is a second row naming it, so a grant is live
 * exactly when no revocation names it. `scopesAsked` is what Heimdall sent the
 * provider, `scopesGranted` what the provider returned, `consentPageDigest`
 * the hash of the wording the person was shown and `consentText` that wording
 * itself. A grant is revoked at most once: a second revocation naming the same
 * grant is not written, and the store answers with the first.
 */
export type StoredConsentReceipt = {
  id: string;
  accountId: string;
  appSlug: AppSlug;
  provider: Provider;
  createdAt: string;
} & (
  | { kind: "grant"; scopesAsked: string[]; scopesGranted: string[]; consentPageDigest: string; consentText: string }
  | { kind: "revocation"; revokesReceiptId: string }
);

/** The store mints `id`; a caller cannot choose it. */
export type CreateConsentReceiptInput = StoredConsentReceipt extends infer R
  ? R extends StoredConsentReceipt
    ? Omit<R, "id">
    : never
  : never;

export interface HeimdallStore {
  ensureSchema(): Promise<void>;
  close(): Promise<void>;
  createAccount(input: CreateAccountInput): Promise<StoredAccount>;
  touchAccount(accountId: string, at: string, updates?: { displayName?: string; primaryEmail?: string }): Promise<void>;
  findAccountById(accountId: string): Promise<StoredAccount | null>;
  findAccountByLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredAccount | null>;
  findStoredLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredLinkedIdentity | null>;
  findStoredLinkedIdentityForAccount(accountId: string, provider: Provider): Promise<StoredLinkedIdentity | null>;
  listStoredLinkedIdentitiesForAccount(accountId: string): Promise<StoredLinkedIdentity[]>;
  upsertLinkedIdentity(input: UpsertLinkedIdentityInput): Promise<StoredLinkedIdentity>;
  /**
   * Serialise decisions about one row's credential. `decide` receives the row
   * as read under the lock (never a caller's snapshot) and the decision is
   * committed before this resolves, so a rotated pair is persisted before any
   * caller sees the new access token. Returns the committed row, or null when
   * no row has that id. A throw from `decide` writes nothing.
   */
  updateLinkedIdentityCredential(
    id: string,
    decide: (locked: StoredLinkedIdentity) => Promise<CredentialDecision>,
  ): Promise<StoredLinkedIdentity | null>;
  listLinkedIdentitiesForAccount(accountId: string): Promise<LinkedIdentityInput[]>;
  createCapabilityGrant(input: CreateCapabilityGrantInput): Promise<StoredCapabilityGrant>;
  listActiveGrants(accountId: string, appSlug: AppSlug, at: string): Promise<StoredCapabilityGrant[]>;
  createSession(input: CreateSessionInput): Promise<StoredSession>;
  findSession(appSlug: AppSlug, sessionId: string): Promise<StoredSession | null>;
  revokeSession(
    appSlug: AppSlug,
    sessionId: string,
    accountId: string,
    expectedAccessRevision: number,
    at: string,
  ): Promise<StoredSession | null>;
  createAuthAttempt(input: CreateAuthAttemptInput): Promise<StoredAuthAttempt>;
  findAuthAttempt(appSlug: AppSlug, handle: string): Promise<StoredAuthAttempt | null>;
  updateAuthAttempt(
    appSlug: AppSlug,
    handle: string,
    update: { status: HeimdallAuthAttemptStatus; at: string; denialCode?: string },
  ): Promise<StoredAuthAttempt | null>;
  createPrivateCommandReceipt(input: CreatePrivateCommandReceiptInput): Promise<StoredPrivateCommandReceipt>;
  findPrivateCommandReceipt(appSlug: AppSlug, idempotencyKey: string): Promise<StoredPrivateCommandReceipt | null>;
  createAuthCompletion(input: CreateAuthCompletionInput): Promise<StoredAuthCompletion>;
  /** Read a completion without consuming it, so redeem can refuse a mismatch without burning the code. */
  findAuthCompletion(appSlug: AppSlug, code: string): Promise<StoredAuthCompletion | null>;
  consumeAuthCompletion(appSlug: AppSlug, code: string, at: string): Promise<StoredAuthCompletion | null>;
  /**
   * Consume a completion by its correlated attempt handle instead of its
   * code. The private command plane already authenticated `appSlug` by
   * opening the envelope; this lets its `completeAuth` redeem the completion
   * it created without ever needing to know (or forge) the code.
   */
  consumeAuthCompletionByAttempt(appSlug: AppSlug, attemptId: string, at: string): Promise<StoredAuthCompletion | null>;
  createPendingLink(input: CreatePendingLinkInput): Promise<StoredPendingLink>;
  /**
   * Single-use redemption: returns the link only for the app and the account
   * it was begun by, before it expires and once. A mismatch returns null and
   * leaves the link unconsumed.
   */
  consumePendingLink(appSlug: AppSlug, id: string, accountId: string, at: string): Promise<StoredPendingLink | null>;
  upsertEntitlementSnapshot(input: CreateEntitlementSnapshotInput): Promise<void>;
  /**
   * Claim one use of a signed OAuth state: true only for the first claim of
   * (jti, phase), false for every later one. Without it a state is a bearer
   * token any number of browsers can complete, so an attacker who learns a
   * victim's state completes it as themselves and hands the victim a code
   * for the attacker's account. `expiresAt` is the state's own expiry; the
   * state is refused at that time before any claim, so the record is dead
   * after it and a store may drop it.
   */
  claimOAuthStateUse(input: ClaimOAuthStateUseInput): Promise<boolean>;
  createAuditEvent(input: CreateAuditEventInput): Promise<void>;
  /** `created` is false when a revocation for that grant already existed and is what comes back. */
  createConsentReceipt(input: CreateConsentReceiptInput): Promise<{ receipt: StoredConsentReceipt; created: boolean }>;
  /** Every receipt the account holds, oldest first. */
  listConsentReceipts(accountId: string): Promise<StoredConsentReceipt[]>;
}
