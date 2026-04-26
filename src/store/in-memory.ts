import { randomUUID } from "node:crypto";
import { type AppSlug, type LinkedIdentityInput, type Provider } from "../contracts.js";
import {
  type CreateAccountInput,
  type CreateAuthCompletionInput,
  type CreateAuditEventInput,
  type CreateCapabilityGrantInput,
  type CreateEntitlementSnapshotInput,
  type CreateSessionInput,
  type HeimdallStore,
  type StoredAccount,
  type StoredAuthCompletion,
  type StoredCapabilityGrant,
  type StoredLinkedIdentity,
  type StoredSession,
  type UpsertLinkedIdentityInput,
} from "./types.js";

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function isGrantActive(grant: StoredCapabilityGrant, appSlug: AppSlug, at: string): boolean {
  if (grant.status !== "active") {
    return false;
  }

  if (grant.expiresAt && grant.expiresAt <= at) {
    return false;
  }

  return grant.scopeType === "global" || grant.scopeId === appSlug;
}

export class InMemoryStore implements HeimdallStore {
  private readonly accounts = new Map<string, StoredAccount>();
  private readonly linkedIdentities = new Map<string, StoredLinkedIdentity>();
  private readonly grants = new Map<string, StoredCapabilityGrant>();
  private readonly sessions = new Map<string, StoredSession>();
  private readonly authCompletions = new Map<string, StoredAuthCompletion>();
  private readonly entitlementSnapshots = new Map<string, CreateEntitlementSnapshotInput>();
  private readonly auditEvents = new Map<string, CreateAuditEventInput>();

  async ensureSchema(): Promise<void> {
    return;
  }

  async close(): Promise<void> {
    return;
  }

  async createAccount(input: CreateAccountInput): Promise<StoredAccount> {
    const account: StoredAccount = {
      id: input.id ?? randomUUID(),
      createdAt: input.createdAt,
      lastSeenAt: input.lastSeenAt,
    };

    if (input.displayName !== undefined) {
      account.displayName = input.displayName;
    }

    if (input.primaryEmail !== undefined) {
      account.primaryEmail = input.primaryEmail;
    }

    this.accounts.set(account.id, clone(account));
    return clone(account);
  }

  async touchAccount(accountId: string, at: string, updates?: { displayName?: string; primaryEmail?: string }): Promise<void> {
    const account = this.accounts.get(accountId);
    if (!account) {
      throw new Error(`Account '${accountId}' was not found.`);
    }

    account.lastSeenAt = at;
    if (updates?.displayName) {
      account.displayName = updates.displayName;
    }
    if (updates?.primaryEmail) {
      account.primaryEmail = updates.primaryEmail;
    }
  }

  async findAccountByLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredAccount | null> {
    for (const linkedIdentity of this.linkedIdentities.values()) {
      if (linkedIdentity.provider === provider && linkedIdentity.providerUserId === providerUserId) {
        return clone(this.accounts.get(linkedIdentity.accountId) ?? null);
      }
    }

    return null;
  }

  async upsertLinkedIdentity(input: UpsertLinkedIdentityInput): Promise<StoredLinkedIdentity> {
    const existing = [...this.linkedIdentities.values()].find(
      (identity) => identity.provider === input.provider && identity.providerUserId === input.providerUserId
    );
    const id = existing?.id ?? input.id ?? randomUUID();
    const linkedIdentity: StoredLinkedIdentity = {
      id,
      accountId: input.accountId,
      provider: input.provider,
      providerUserId: input.providerUserId,
      scopes: [...input.scopes],
      profileJson: clone(input.profileJson),
      createdAt: existing?.createdAt ?? input.createdAt,
      updatedAt: input.updatedAt,
    };

    if (input.username !== undefined) {
      linkedIdentity.username = input.username;
    }

    if (input.displayName !== undefined) {
      linkedIdentity.displayName = input.displayName;
    }

    if (input.primaryEmail !== undefined) {
      linkedIdentity.primaryEmail = input.primaryEmail;
    }

    if (input.accessTokenEncrypted !== undefined) {
      linkedIdentity.accessTokenEncrypted = input.accessTokenEncrypted;
    }

    if (input.refreshTokenEncrypted !== undefined) {
      linkedIdentity.refreshTokenEncrypted = input.refreshTokenEncrypted;
    }

    if (input.tokenExpiresAt !== undefined) {
      linkedIdentity.tokenExpiresAt = input.tokenExpiresAt;
    }

    this.linkedIdentities.set(id, clone(linkedIdentity));
    return clone(linkedIdentity);
  }

  async listLinkedIdentitiesForAccount(accountId: string): Promise<LinkedIdentityInput[]> {
    return [...this.linkedIdentities.values()]
      .filter((identity) => identity.accountId === accountId)
      .map((identity) => {
        const linkedIdentity: LinkedIdentityInput = {
          provider: identity.provider,
          providerUserId: identity.providerUserId,
        };

        if (identity.username !== undefined) {
          linkedIdentity.username = identity.username;
        }

        if (identity.displayName !== undefined) {
          linkedIdentity.displayName = identity.displayName;
        }

        return linkedIdentity;
      });
  }

  async createCapabilityGrant(input: CreateCapabilityGrantInput): Promise<StoredCapabilityGrant> {
    const grant: StoredCapabilityGrant = {
      id: input.id ?? randomUUID(),
      accountId: input.accountId,
      scopeType: input.scopeType,
      capability: input.capability,
      source: input.source,
      status: input.status,
      createdAt: input.createdAt,
      updatedAt: input.updatedAt,
    };

    if (input.scopeId !== undefined) {
      grant.scopeId = input.scopeId;
    }

    if (input.expiresAt !== undefined) {
      grant.expiresAt = input.expiresAt;
    }

    if (input.note !== undefined) {
      grant.note = input.note;
    }

    this.grants.set(grant.id, clone(grant));
    return clone(grant);
  }

  async listActiveGrants(accountId: string, appSlug: AppSlug, at: string): Promise<StoredCapabilityGrant[]> {
    return [...this.grants.values()]
      .filter((grant) => grant.accountId === accountId && isGrantActive(grant, appSlug, at))
      .map((grant) => clone(grant));
  }

  async createSession(input: CreateSessionInput): Promise<StoredSession> {
    const session: StoredSession = clone(input);
    this.sessions.set(session.id, session);
    return clone(session);
  }

  async createAuthCompletion(input: CreateAuthCompletionInput): Promise<StoredAuthCompletion> {
    const completion: StoredAuthCompletion = {
      code: input.code ?? randomUUID(),
      appSlug: input.appSlug,
      provider: input.provider,
      mode: input.mode,
      accountId: input.accountId,
      sessionId: input.sessionId,
      returnTo: input.returnTo,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      payloadJson: clone(input.payloadJson),
    };

    this.authCompletions.set(completion.code, clone(completion));
    return clone(completion);
  }

  async consumeAuthCompletion(appSlug: AppSlug, code: string, at: string): Promise<StoredAuthCompletion | null> {
    const completion = this.authCompletions.get(code);
    if (!completion) {
      return null;
    }

    if (completion.appSlug !== appSlug || completion.expiresAt <= at || completion.consumedAt) {
      return null;
    }

    completion.consumedAt = at;
    return clone(completion);
  }

  async upsertEntitlementSnapshot(input: CreateEntitlementSnapshotInput): Promise<void> {
    const key = `${input.accountId}:${input.provider}:${input.scope}`;
    this.entitlementSnapshots.set(key, clone(input));
  }

  async createAuditEvent(input: CreateAuditEventInput): Promise<void> {
    const event: CreateAuditEventInput = clone({
      ...input,
      id: input.id ?? randomUUID(),
    });
    this.auditEvents.set(event.id ?? randomUUID(), event);
  }
}
