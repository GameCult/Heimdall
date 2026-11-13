import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { buildApp } from "../src/app.js";
import { issueAccessClaim } from "../src/claims.js";
import { type Provider } from "../src/contracts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { createRuntimeKeyMaterial, decodeJwt, signJwt, verifyJwt } from "../src/signing.js";
import { IdentityHeldElsewhereError, InMemoryStore } from "../src/store/index.js";
import { createTestConfig, launchFlow, launchState, stateOf } from "./oauth-flow.js";

// The member's identity surface: list what an account holds, and take one
// identity off it. Taking one off is the account's own decision made with
// fresh proof (a step-up sign-in inside the proof window), never the
// bearer's alone. These tests drive both routes over HTTP as an app would.

const returnTo = "https://streampixels.gamecult.org/signin/return";
const spAuth = { "x-heimdall-app-secret": "streampixels-secret" };
const now = "2026-11-13T12:00:00.000Z";

function runtime(provider: "twitch" | "youtube", providerUserId: string): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "at", refreshToken: "rt", tokenType: "Bearer", scope: ["user:read:email"], raw: {} };
    },
    async resolveIdentity() {
      return { provider, providerUserId, username: providerUserId, profile: { id: providerUserId } };
    },
    async evaluateEntitlements() {
      return { facts: [], snapshots: [] };
    },
  };
}

const dir = mkdtempSync(join(tmpdir(), "heimdall-unlink-"));
const config = { ...createTestConfig(), signingPrivateKeyPath: join(dir, "signing.pem"), bootstrapSigningPrivateKeyOnMissing: true };
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function rig() {
  const store = new InMemoryStore();
  const app = await buildApp({
    config,
    store,
    oauthRuntimes: { twitch: runtime("twitch", "t-1"), youtube: runtime("youtube", "y-1") },
  });
  apps.push(app);
  const keys = createRuntimeKeyMaterial({ ...config, bootstrapSigningPrivateKeyOnMissing: false });
  return { app, store, keys };
}
type Rig = Awaited<ReturnType<typeof rig>>;

async function seedAccount(r: Rig, held: Array<[Provider, string]>) {
  const account = await r.store.createAccount({ createdAt: now, lastSeenAt: now });
  const rows = [];
  for (const [provider, providerUserId] of held) {
    rows.push(
      await r.store.upsertLinkedIdentity({
        accountId: account.id,
        provider,
        providerUserId,
        username: `${provider}-name`,
        displayName: `${provider} display`,
        primaryEmail: "secret@example.test",
        accessTokenEncrypted: "ACCESS-CIPHERTEXT",
        refreshTokenEncrypted: "REFRESH-CIPHERTEXT",
        scopes: ["identify"],
        profileJson: { raw: "PROFILE-CANARY" },
        createdAt: now,
        updatedAt: now,
      })
    );
  }
  return { account, rows };
}

/** A real sign_in through twitch, as StreamPixels runs it, redeemed for the tokens. */
async function signIn(r: Rig, stepUp: boolean) {
  const started = await r.app.inject({
    method: "POST",
    url: "/v1/oauth/twitch/start",
    headers: stepUp ? spAuth : {},
    payload: { appSlug: "streampixels", mode: "sign_in", returnTo, ...(stepUp ? { stepUp: true } : {}) },
  });
  expect(started.statusCode).toBe(201);
  const flow = await launchFlow(r.app, started.json());
  const called = await r.app.inject({
    method: "GET",
    url: `/v1/oauth/twitch/callback?code=c&state=${encodeURIComponent(flow.state)}`,
    headers: { cookie: flow.cookie, accept: "application/json" },
  });
  expect(called.statusCode).toBe(201);
  const redeemed = await r.app.inject({
    method: "POST",
    url: "/v1/apps/streampixels/auth-completions/redeem",
    payload: { completionCode: called.json().completion.code },
  });
  expect(redeemed.statusCode).toBe(201);
  return redeemed.json() as { accessToken: string; refreshToken: string; claimSet: Record<string, unknown> };
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const list = (r: Rig, token?: string) => r.app.inject({ method: "GET", url: "/v1/me/identities", headers: token ? bearer(token) : {} });
const unlink = (r: Rig, id: string, token?: string, payload?: unknown) =>
  r.app.inject({ method: "POST", url: `/v1/me/identities/${encodeURIComponent(id)}/unlink`, headers: token ? bearer(token) : {}, ...(payload !== undefined ? { payload: payload as object } : {}) });

describe("step_up_at on the access claim", () => {
  it("a step-up sign-in's claim carries it; an ordinary sign-in and a refresh do not", async () => {
    const r = await rig();
    await seedAccount(r, [["twitch", "t-1"], ["youtube", "y-1"]]);
    const before = Math.floor(Date.now() / 1000);
    const stepped = await signIn(r, true);
    expect(stepped.claimSet.step_up_at).toBeGreaterThanOrEqual(before);
    expect(stepped.claimSet.step_up_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
    expect(stepped.claimSet.step_up_method).toBe("provider:twitch");
    const plain = (await signIn(r, false)).claimSet;
    expect(plain.step_up_at).toBeUndefined();
    expect(plain.step_up_method).toBeUndefined();

    const refreshed = await r.app.inject({ method: "POST", url: "/v1/apps/streampixels/sessions/refresh", payload: { refreshToken: stepped.refreshToken } });
    expect(refreshed.statusCode).toBe(201);
    expect(refreshed.json().claimSet.step_up_at, "a refresh never renews proof").toBeUndefined();
    expect(refreshed.json().claimSet.step_up_method).toBeUndefined();
  });
});

describe("GET /v1/me/identities", () => {
  it("is 401 sign_in_required without a live bearer", async () => {
    const r = await rig();
    for (const token of [undefined, "not-a-token"]) {
      const res = await list(r, token);
      expect([res.statusCode, res.json().error]).toEqual([401, "sign_in_required"]);
    }
  });

  it("lists the caller's identities and nothing that is a credential, a profile or an email", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"], ["discord", "d-9"]]);
    await seedAccount(r, [["youtube", "y-other"]]);
    const { accessToken } = await signIn(r, false);
    const res = await list(r, accessToken);
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    const body = res.json();
    expect(body.accountId).toBe(account.id);
    expect(body.identities).toEqual([
      // The sign-in above refreshed the twitch row from what the provider returned.
      { id: rows[0]!.id, provider: "twitch", providerUserId: "t-1", username: "t-1", linkedAt: now, scopes: ["user:read:email"] },
      { id: rows[1]!.id, provider: "discord", providerUserId: "d-9", username: "discord-name", displayName: "discord display", linkedAt: now, scopes: ["identify"] },
    ]);
    expect(res.body).not.toMatch(/CIPHERTEXT|PROFILE-CANARY|secret@example|primary_email|primaryEmail/);
  });
});

describe("POST /v1/me/identities/:identityId/unlink", () => {
  it("is 401 without a live bearer", async () => {
    const r = await rig();
    const { rows } = await seedAccount(r, [["twitch", "t-1"], ["youtube", "y-1"]]);
    expect((await unlink(r, rows[1]!.id)).statusCode).toBe(401);
    expect((await unlink(r, rows[1]!.id, "garbage")).statusCode).toBe(401);
  });

  it("is 403 step_up_required for a bearer with no proof, and for a refresh-issued one, and removes nothing", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"], ["youtube", "y-1"]]);
    const plain = await signIn(r, false);
    const denied = await unlink(r, rows[1]!.id, plain.accessToken);
    expect([denied.statusCode, denied.json().error]).toEqual([403, "step_up_required"]);
    expect(denied.json().detail).toMatch(/twitch, youtube and google/);

    const stepped = await signIn(r, true);
    const refreshed = await r.app.inject({ method: "POST", url: "/v1/apps/streampixels/sessions/refresh", payload: { refreshToken: stepped.refreshToken } });
    const viaRefresh = await unlink(r, rows[1]!.id, refreshed.json().accessToken);
    expect([viaRefresh.statusCode, viaRefresh.json().error]).toEqual([403, "step_up_required"]);
    expect(await r.store.listStoredLinkedIdentitiesForAccount(account.id)).toHaveLength(2);
  });

  it("is 403 for proof older than the window and for proof dated in the future; 599 s old still passes", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"], ["youtube", "y-1"], ["discord", "d-1"]]);
    const issueWith = async (stepUpAt: number) =>
      (await issueAccessClaim({
        config,
        keys: r.keys,
        store: r.store,
        input: { appSlug: "streampixels", accountId: account.id, linkedIdentities: [], facts: [], stepUpAt },
      })).accessToken;
    const nowS = Math.floor(Date.now() / 1000);
    for (const at of [nowS - 601, nowS + 120]) {
      const res = await unlink(r, rows[1]!.id, await issueWith(at));
      expect([res.statusCode, res.json().error], String(at - nowS)).toEqual([403, "step_up_required"]);
    }
    expect(await r.store.listStoredLinkedIdentitiesForAccount(account.id)).toHaveLength(3);
    const edge = await unlink(r, rows[1]!.id, await issueWith(nowS - 599));
    expect(edge.statusCode).toBe(200);
  });

  it("a step-up sign-in's bearer unlinks: 200 with the remaining list, an audit event without credentials", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"], ["discord", "d-9"]]);
    const audit = vi.spyOn(r.store, "createAuditEvent");
    const { accessToken } = await signIn(r, true);
    const res = await unlink(r, rows[1]!.id, accessToken, null);
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.json().unlinked).toEqual({ id: rows[1]!.id, provider: "discord", providerUserId: "d-9" });
    expect(res.json().identities.map((i: { id: string }) => i.id)).toEqual([rows[0]!.id]);
    expect(res.body).not.toMatch(/CIPHERTEXT|PROFILE-CANARY|secret@example/);
    expect(await r.store.listStoredLinkedIdentitiesForAccount(account.id)).toHaveLength(1);
    const event = audit.mock.calls.map(([e]) => e).find((e) => e.eventType === "identity_unlinked");
    expect(event?.accountId).toBe(account.id);
    expect(event?.eventPayloadJson).toEqual({ provider: "discord", identityId: rows[1]!.id, stepUpMethod: "provider:twitch" });
  });

  it("the account's only identity is 409 last_identity and the row stays", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"]]);
    const { accessToken } = await signIn(r, true);
    const res = await unlink(r, rows[0]!.id, accessToken);
    expect([res.statusCode, res.json().error]).toEqual([409, "last_identity"]);
    expect(await r.store.listStoredLinkedIdentitiesForAccount(account.id)).toHaveLength(1);
  });

  it("another account's identity and a nonexistent one are the same 404", async () => {
    const r = await rig();
    await seedAccount(r, [["twitch", "t-1"], ["discord", "d-9"]]);
    const other = await seedAccount(r, [["youtube", "y-other"], ["github", "g-other"]]);
    const { accessToken } = await signIn(r, true);
    const foreign = await unlink(r, other.rows[0]!.id, accessToken);
    const missing = await unlink(r, "no-such-id", accessToken);
    expect([foreign.statusCode, foreign.json().error]).toEqual([404, "identity_not_found"]);
    expect([missing.statusCode, missing.body]).toEqual([404, foreign.body]);
    expect(await r.store.listStoredLinkedIdentitiesForAccount(other.account.id)).toHaveLength(2);
  });

  it("an unlinked identity belongs to no one, and another account can then link it, but not before", async () => {
    const r = await rig();
    const mine = await seedAccount(r, [["twitch", "t-1"], ["discord", "d-9"]]);
    const theirs = await seedAccount(r, [["youtube", "y-other"]]);
    const input = { accountId: theirs.account.id, provider: "discord" as const, providerUserId: "d-9", scopes: [], profileJson: {}, createdAt: now, updatedAt: now };
    await expect(r.store.upsertLinkedIdentity(input)).rejects.toBeInstanceOf(IdentityHeldElsewhereError);
    const { accessToken } = await signIn(r, true);
    expect((await unlink(r, mine.rows[1]!.id, accessToken)).statusCode).toBe(200);
    await expect(r.store.upsertLinkedIdentity(input)).resolves.toMatchObject({ accountId: theirs.account.id });
  });

  it("writes revocation receipts for the provider's live grants when its last identity goes, and not before", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"], ["youtube", "y-1"], ["youtube", "y-2"]]);
    const grant = async (provider: Provider) =>
      (await r.store.createConsentReceipt({ kind: "grant", accountId: account.id, appSlug: "streampixels", provider, createdAt: now, scopesAsked: ["a"], scopesGranted: ["a"], consentPageDigest: "d", consentText: "t" })).receipt;
    const ytGrant = await grant("youtube");
    const twGrant = await grant("twitch");
    const { accessToken } = await signIn(r, true);

    // A second youtube identity remains: the grant's provider still holds a credential.
    expect((await unlink(r, rows[1]!.id, accessToken)).statusCode).toBe(200);
    expect((await r.store.listConsentReceipts(account.id)).filter((x) => x.kind === "revocation")).toHaveLength(0);

    // The last youtube identity goes (twitch stays as the sign-in identity): youtube's grant is revoked, twitch's is not.
    const audit = vi.spyOn(r.store, "createAuditEvent");
    expect((await unlink(r, rows[2]!.id, accessToken)).statusCode).toBe(200);
    const revocations = (await r.store.listConsentReceipts(account.id)).filter((x) => x.kind === "revocation");
    expect(revocations.map((x) => x.kind === "revocation" && x.revokesReceiptId)).toEqual([ytGrant.id]);
    expect(revocations.map((x) => x.provider)).toEqual(["youtube"]);
    expect(twGrant.id).not.toBe(ytGrant.id);
    expect(audit.mock.calls.map(([e]) => e.eventType)).toEqual(expect.arrayContaining(["identity_unlinked", "consent_revoked"]));
  });

  it("proof past the window refuses even a bearer that was fresh when issued", async () => {
    const r = await rig();
    const { rows } = await seedAccount(r, [["twitch", "t-1"], ["discord", "d-9"]]);
    vi.useFakeTimers({ toFake: ["Date"] });
    const { accessToken } = await signIn(r, true);
    vi.setSystemTime(Date.now() + 601_000);
    const res = await unlink(r, rows[1]!.id, accessToken);
    expect([res.statusCode, res.json().error]).toEqual([403, "step_up_required"]);
  });

  it("the proof window's edge: exactly 600 s old still passes, 601 s does not (frozen clock)", async () => {
    const r = await rig();
    const { account, rows } = await seedAccount(r, [["twitch", "t-1"], ["youtube", "y-1"], ["discord", "d-1"]]);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-13T12:00:00.000Z"));
    const nowS = Math.floor(Date.now() / 1000);
    const issueWith = async (stepUpAt: number) =>
      (await issueAccessClaim({ config, keys: r.keys, store: r.store, input: { appSlug: "streampixels", accountId: account.id, linkedIdentities: [], facts: [], stepUpAt } })).accessToken;
    const tooOld = await unlink(r, rows[1]!.id, await issueWith(nowS - 601));
    expect([tooOld.statusCode, tooOld.json().error]).toEqual([403, "step_up_required"]);
    const edge = await unlink(r, rows[1]!.id, await issueWith(nowS - 600));
    expect(edge.statusCode).toBe(200);
  });

  it("a one-identity bearer naming another account's identity gets 404, not 409", async () => {
    const r = await rig();
    await seedAccount(r, [["twitch", "t-1"]]);
    const other = await seedAccount(r, [["youtube", "y-other"], ["github", "g-other"]]);
    const { accessToken } = await signIn(r, true);
    const res = await unlink(r, other.rows[0]!.id, accessToken);
    expect([res.statusCode, res.json().error]).toEqual([404, "identity_not_found"]);
  });

  it("a step_up state in a non-sign_in mode (forged, signed) yields no step_up_at", async () => {
    const r = await rig();
    const { account } = await seedAccount(r, [["twitch", "t-1"]]);
    const started = await r.app.inject({
      method: "POST",
      url: "/v1/oauth/twitch/start",
      headers: spAuth,
      payload: { appSlug: "streampixels", mode: "link", initiatingAccountId: account.id, returnTo },
    });
    expect(started.statusCode).toBe(201);
    const verified = verifyJwt(stateOf(started.json()), r.keys.publicKey) as { valid: boolean; payload: Record<string, unknown> };
    expect(verified.valid).toBe(true);
    expect(verified.payload.mode).toBe("link");
    const flow = await launchState(r.app, signJwt({ ...verified.payload, step_up: true }, r.keys));
    const called = await r.app.inject({
      method: "GET",
      url: `/v1/oauth/twitch/callback?code=c&state=${encodeURIComponent(flow.state)}`,
      headers: { cookie: flow.cookie, accept: "application/json" },
    });
    expect(called.statusCode).toBe(201);
    expect(called.json().stepUpRequested, "the forged flag was read").toBe(true);
    const token = called.json().accessToken as string;
    expect(token, "the link completion minted an access token to inspect").toBeTruthy();
    expect(decodeJwt(token).payload.step_up_at).toBeUndefined();
  });
});
