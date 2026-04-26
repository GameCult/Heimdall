import { type AppSlug, type LinkedIdentityInput, type OAuthMode, type Provider } from "../contracts.js";

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
  appSlug: AppSlug;
  provider: Provider;
  mode: OAuthMode;
  accountId: string;
  sessionId: string;
  returnTo: string;
  createdAt: string;
  expiresAt: string;
  consumedAt?: string;
  payloadJson: Record<string, unknown>;
}

export interface CreateAuthCompletionInput {
  code?: string;
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

export interface HeimdallStore {
  ensureSchema(): Promise<void>;
  close(): Promise<void>;
  createAccount(input: CreateAccountInput): Promise<StoredAccount>;
  touchAccount(accountId: string, at: string, updates?: { displayName?: string; primaryEmail?: string }): Promise<void>;
  findAccountByLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredAccount | null>;
  upsertLinkedIdentity(input: UpsertLinkedIdentityInput): Promise<StoredLinkedIdentity>;
  listLinkedIdentitiesForAccount(accountId: string): Promise<LinkedIdentityInput[]>;
  createCapabilityGrant(input: CreateCapabilityGrantInput): Promise<StoredCapabilityGrant>;
  listActiveGrants(accountId: string, appSlug: AppSlug, at: string): Promise<StoredCapabilityGrant[]>;
  createSession(input: CreateSessionInput): Promise<StoredSession>;
  createAuthCompletion(input: CreateAuthCompletionInput): Promise<StoredAuthCompletion>;
  consumeAuthCompletion(appSlug: AppSlug, code: string, at: string): Promise<StoredAuthCompletion | null>;
  upsertEntitlementSnapshot(input: CreateEntitlementSnapshotInput): Promise<void>;
  createAuditEvent(input: CreateAuditEventInput): Promise<void>;
}
