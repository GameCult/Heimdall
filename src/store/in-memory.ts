import { randomUUID } from "node:crypto";
import { type AppSlug, type LinkedIdentityInput, type Provider } from "../contracts.js";
import {
  type CreateAccountInput,
  type CreateAuthAttemptInput,
  type CreateAuthCompletionInput,
  type CreateAuditEventInput,
  type CreateCapabilityGrantInput,
  type CreateEntitlementSnapshotInput,
  type CreateSessionInput,
  type CreatePrivateCommandReceiptInput,
  type HeimdallStore,
  type StoredAccount,
  type StoredAuthAttempt,
  type StoredAuthCompletion,
  type StoredCapabilityGrant,
  type StoredLinkedIdentity,
  type StoredRegisteredApp,
  type StoredSession,
  type StoredPrivateCommandReceipt,
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
  private readonly registeredApps = new Map<string, StoredRegisteredApp>();
  private readonly accounts = new Map<string, StoredAccount>();
  private readonly linkedIdentities = new Map<string, StoredLinkedIdentity>();
  private readonly grants = new Map<string, StoredCapabilityGrant>();
  private readonly sessions = new Map<string, StoredSession>();
  private readonly authAttempts = new Map<string, StoredAuthAttempt>();
  private readonly privateCommandReceipts = new Map<string, StoredPrivateCommandReceipt>();
  private readonly authCompletions = new Map<string, StoredAuthCompletion>();
  private readonly authCompletionsByAttempt = new Map<string, string>();
  private readonly entitlementSnapshots = new Map<string, CreateEntitlementSnapshotInput>();
  private readonly auditEvents = new Map<string, CreateAuditEventInput>();

  /**
   * Test/ops seam only — not part of HeimdallStore. There is no production
   * writer for `registered_apps` anymore; a real deployment provisions a row
   * directly against Postgres. This lets fixtures exercise resolveAppProfile's
   * non-built-in branch the same way.
   */
  seedRegisteredApp(record: StoredRegisteredApp): void {
    this.registeredApps.set(record.slug, structuredClone(record));
  }

  async findRegisteredApp(slug: string): Promise<StoredRegisteredApp | null> {
    const record = this.registeredApps.get(slug);
    return record ? structuredClone(record) : null;
  }

  async listRegisteredApps(): Promise<StoredRegisteredApp[]> {
    return [...this.registeredApps.values()]
      .sort((left, right) => left.slug.localeCompare(right.slug))
      .map((record) => structuredClone(record));
  }

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

  async findAccountById(accountId: string): Promise<StoredAccount | null> {
    return clone(this.accounts.get(accountId) ?? null);
  }

  async findAccountByLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredAccount | null> {
    for (const linkedIdentity of this.linkedIdentities.values()) {
      if (linkedIdentity.provider === provider && linkedIdentity.providerUserId === providerUserId) {
        return clone(this.accounts.get(linkedIdentity.accountId) ?? null);
      }
    }

    return null;
  }

  async findStoredLinkedIdentity(provider: Provider, providerUserId: string): Promise<StoredLinkedIdentity | null> {
    for (const linkedIdentity of this.linkedIdentities.values()) {
      if (linkedIdentity.provider === provider && linkedIdentity.providerUserId === providerUserId) {
        return clone(linkedIdentity);
      }
    }

    return null;
  }

  async findStoredLinkedIdentityForAccount(accountId: string, provider: Provider): Promise<StoredLinkedIdentity | null> {
    for (const linkedIdentity of this.linkedIdentities.values()) {
      if (linkedIdentity.accountId === accountId && linkedIdentity.provider === provider) {
        return clone(linkedIdentity);
      }
    }

    return null;
  }

  async listStoredLinkedIdentitiesForAccount(accountId: string): Promise<StoredLinkedIdentity[]> {
    return [...this.linkedIdentities.values()]
      .filter((identity) => identity.accountId === accountId)
      .map((identity) => clone(identity));
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
    const existing = this.sessions.get(input.id);
    if (existing && (existing.appSlug !== input.appSlug || existing.accountId !== input.accountId)) {
      throw new Error("Session custody cannot move between accounts or apps.");
    }
    if (existing && existing.accessRevision > input.accessRevision) {
      throw new Error("Session access revision cannot move backward.");
    }
    const session: StoredSession = clone(input);
    this.sessions.set(session.id, session);
    return clone(session);
  }

  async findSession(appSlug: AppSlug, sessionId: string): Promise<StoredSession | null> {
    const session = this.sessions.get(sessionId);
    return session?.appSlug === appSlug ? structuredClone(session) : null;
  }

  async revokeSession(
    appSlug: AppSlug,
    sessionId: string,
    accountId: string,
    expectedAccessRevision: number,
    at: string,
  ): Promise<StoredSession | null> {
    const session = this.sessions.get(sessionId);
    if (!session
      || session.appSlug !== appSlug
      || session.accountId !== accountId
      || session.accessRevision !== expectedAccessRevision) return null;
    const revoked = {
      ...session,
      lastSeenAt: at,
      expiresAt: at,
      accessRevision: expectedAccessRevision + 1,
    };
    this.sessions.set(sessionId, revoked);
    return structuredClone(revoked);
  }

  async createAuthAttempt(input: CreateAuthAttemptInput): Promise<StoredAuthAttempt> {
    const attempt: StoredAuthAttempt = {
      handle: input.handle ?? randomUUID(),
      appSlug: input.appSlug,
      provider: input.provider,
      mode: input.mode,
      returnTo: input.returnTo,
      status: "pending",
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
    };
    if (this.authAttempts.has(attempt.handle)) throw new Error("Auth attempt handle already exists.");
    this.authAttempts.set(attempt.handle, clone(attempt));
    return clone(attempt);
  }

  async findAuthAttempt(appSlug: AppSlug, handle: string): Promise<StoredAuthAttempt | null> {
    const attempt = this.authAttempts.get(handle);
    return attempt?.appSlug === appSlug ? clone(attempt) : null;
  }

  async updateAuthAttempt(
    appSlug: AppSlug,
    handle: string,
    update: { status: import("../contracts.js").HeimdallAuthAttemptStatus; at: string; denialCode?: string },
  ): Promise<StoredAuthAttempt | null> {
    const attempt = this.authAttempts.get(handle);
    if (!attempt || attempt.appSlug !== appSlug) return null;
    const allowed = attempt.status === update.status ||
      (attempt.status === "pending" && ["completed", "denied", "expired"].includes(update.status)) ||
      (attempt.status === "completed" && update.status === "consumed");
    if (!allowed) return clone(attempt);
    attempt.status = update.status;
    if (update.status === "completed") attempt.completedAt = update.at;
    if (update.status === "consumed") attempt.consumedAt = update.at;
    if (update.denialCode !== undefined) attempt.denialCode = update.denialCode;
    this.authAttempts.set(handle, clone(attempt));
    return clone(attempt);
  }

  async createPrivateCommandReceipt(input: CreatePrivateCommandReceiptInput): Promise<StoredPrivateCommandReceipt> {
    const key = `${input.appSlug}:${input.idempotencyKey}`;
    const existing = this.privateCommandReceipts.get(key);
    if (existing) {
      if (existing.requestFingerprint !== input.requestFingerprint) {
        throw new Error("Idempotency key was reused with different command content.");
      }
      return clone(existing);
    }
    this.privateCommandReceipts.set(key, clone(input));
    return clone(input);
  }

  async findPrivateCommandReceipt(appSlug: AppSlug, idempotencyKey: string): Promise<StoredPrivateCommandReceipt | null> {
    const receipt = this.privateCommandReceipts.get(`${appSlug}:${idempotencyKey}`);
    return receipt ? clone(receipt) : null;
  }

  async createAuthCompletion(input: CreateAuthCompletionInput): Promise<StoredAuthCompletion> {
    // The code is always minted here; nothing upstream may choose it (see
    // src/app.ts createAuthCompletion call site for why that mattered).
    // Mirrors the partial unique index on (app_slug, attempt_id) WHERE
    // consumed_at IS NULL (schema.ts): one attempt handle binds at most one
    // unconsumed completion, so consumeAuthCompletionByAttempt never has more
    // than one live row to choose between.
    if (input.attemptId) {
      const existingCode = this.authCompletionsByAttempt.get(`${input.appSlug}:${input.attemptId}`);
      const existing = existingCode ? this.authCompletions.get(existingCode) : undefined;
      if (existing && !existing.consumedAt) {
        throw new Error("Attempt handle already has an unconsumed completion.");
      }
    }
    const completion: StoredAuthCompletion = {
      code: randomUUID(),
      ...(input.attemptId ? { attemptId: input.attemptId } : {}),
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
    if (input.attemptId) {
      this.authCompletionsByAttempt.set(`${input.appSlug}:${input.attemptId}`, completion.code);
    }
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

  async consumeAuthCompletionByAttempt(appSlug: AppSlug, attemptId: string, at: string): Promise<StoredAuthCompletion | null> {
    const code = this.authCompletionsByAttempt.get(`${appSlug}:${attemptId}`);
    if (!code) {
      return null;
    }
    return this.consumeAuthCompletion(appSlug, code, at);
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
