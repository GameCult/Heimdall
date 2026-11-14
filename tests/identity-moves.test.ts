import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { buildApp } from "../src/app.js";
import { builtInAppProfiles } from "../src/app-profiles.js";
import { AUTH_PROOF_TTL_SECONDS, issueAccessClaim, proofTier } from "../src/claims.js";
import { type AppSlug, type Provider } from "../src/contracts.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { createRuntimeKeyMaterial } from "../src/signing.js";
import { InMemoryStore } from "../src/store/index.js";
import { type CreateAuditEventInput } from "../src/store/types.js";
import { createTestConfig, launchFlow } from "./oauth-flow.js";

// POST /v1/apps/{app}/identity-moves, driven over HTTP the way Bifrost would
// call it: the proofs are real access tokens whose claims say how and through
// which login the member signed in; the answers are what a caller can see.

const now = "2026-11-14T12:00:00.000Z";
const appAuth = { "x-heimdall-app-secret": "bifrost-secret" };
const moveId = (tag: string) => `move-${tag}`.padEnd(20, "x");
const nowS = () => Math.floor(Date.now() / 1000);

const dir = mkdtempSync(join(tmpdir(), "heimdall-identity-moves-"));
const config = { ...createTestConfig(), signingPrivateKeyPath: join(dir, "signing.pem"), bootstrapSigningPrivateKeyOnMissing: true };
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

function twitchRuntime(providerUserId: string): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "at", refreshToken: "rt", tokenType: "Bearer", scope: ["user:read:email"], raw: {} };
    },
    async resolveIdentity() {
      return { provider: "twitch", providerUserId, username: providerUserId, profile: { id: providerUserId } };
    },
    async evaluateEntitlements() {
      return { facts: [], snapshots: [] };
    },
  };
}

function discordRuntime(providerUserId: string): OAuthProviderRuntime {
  return { ...twitchRuntime(providerUserId), async resolveIdentity() { return { provider: "discord", providerUserId, username: providerUserId, profile: { id: providerUserId } }; } };
}

async function rig(twitchUser = "t-signin") {
  const store = new InMemoryStore();
  const audit: CreateAuditEventInput[] = [];
  const realAudit = store.createAuditEvent.bind(store);
  store.createAuditEvent = async (input) => {
    audit.push(structuredClone(input));
    return realAudit(input);
  };
  const app = await buildApp({ config, store, oauthRuntimes: { twitch: twitchRuntime(twitchUser), discord: discordRuntime("d-linked") } });
  apps.push(app);
  const keys = createRuntimeKeyMaterial({ ...config, bootstrapSigningPrivateKeyOnMissing: false });
  return { app, store, keys, audit };
}
type Rig = Awaited<ReturnType<typeof rig>>;

let seq = 0;
/** An account holding the given logins, each with a credential, and one live-session proof factory. */
async function acct(r: Rig, held: Array<[Provider, string?]>) {
  seq += 1;
  const account = await r.store.createAccount({ createdAt: now, lastSeenAt: now, displayName: "DISPLAY-CANARY", primaryEmail: "canary@example.test" });
  const rows = [];
  for (const [provider, user] of held) {
    rows.push(
      await r.store.upsertLinkedIdentity({
        accountId: account.id,
        provider,
        providerUserId: user ?? `${provider}-${seq}`,
        scopes: ["identify"],
        accessTokenEncrypted: "ACCESS-CIPHERTEXT",
        refreshTokenEncrypted: "REFRESH-CIPHERTEXT",
        profileJson: {},
        createdAt: now,
        updatedAt: now,
      })
    );
  }
  return { account, rows };
}
type Acct = Awaited<ReturnType<typeof acct>>;

interface ProofOptions {
  app?: AppSlug;
  /** Seconds since the sign-in; null mints a token with no sign-in claim (a refresh or link would). */
  signedInAgo?: number | null;
  via?: number;
  stepUp?: { agoS?: number; method: string };
}
/** A live session for the account and the access token it would hold. */
async function proof(r: Rig, a: Acct, o: ProofOptions = {}) {
  const ago = o.signedInAgo === undefined ? 0 : o.signedInAgo;
  const issued = await issueAccessClaim({
    config,
    keys: r.keys,
    store: r.store,
    input: {
      appSlug: o.app ?? "bifrost",
      accountId: a.account.id,
      linkedIdentities: a.rows.map((row) => ({ provider: row.provider, providerUserId: row.providerUserId })),
      facts: [],
      ...(ago === null ? {} : { authAt: nowS() - ago, authIdentityId: a.rows[o.via ?? 0]!.id }),
      ...(o.stepUp ? { stepUpAt: nowS() - (o.stepUp.agoS ?? 0), stepUpMethod: o.stepUp.method } : {}),
    },
  });
  return { token: issued.accessToken, sid: issued.session.sessionId };
}
const passkey = { method: "bifrost-passkey" };

const move = (r: Rig, body: object, headers: Record<string, string> = appAuth, app = "bifrost") =>
  r.app.inject({ method: "POST", url: `/v1/apps/${app}/identity-moves`, headers, payload: body });
const held = async (r: Rig, a: Acct) => (await r.store.listStoredLinkedIdentitiesForAccount(a.account.id)).map((i) => i.id).sort();
const err = (res: { statusCode: number; json(): { error?: string } }) => [res.statusCode, res.json().error];

/** Source with discord+google, destination with patreon: a passkey on the source and any fresh proof on the destination. */
async function scene(r: Rig) {
  const from = await acct(r, [["discord"], ["google"]]);
  const to = await acct(r, [["patreon"]]);
  return {
    from,
    to,
    fromProof: await proof(r, from, { stepUp: passkey }),
    toProof: await proof(r, to),
  };
}

describe("a sanctioned move", () => {
  it("two fresh proofs move every login of the source and answer the receipt, with no token, email or name", async () => {
    const r = await rig();
    const s = await scene(r);
    const sourceIds = await held(r, s.from);
    const res = await move(r, { moveId: moveId("a"), fromProofs: [s.fromProof.token], toProof: s.toProof.token });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.json()).toEqual({
      moveId: moveId("a"),
      accountId: s.to.account.id,
      movedIdentityIds: expect.arrayContaining(sourceIds),
      proof: { from: "strong", to: "weak" },
    });
    expect(res.json().movedIdentityIds).toHaveLength(2);
    expect(res.body).not.toMatch(/CIPHERTEXT|canary|DISPLAY|ey[A-Za-z0-9_-]{20,}\./);
    expect(await held(r, s.from)).toEqual([]);
    expect(await held(r, s.to)).toEqual(expect.arrayContaining(sourceIds));
    expect(await held(r, s.to)).toHaveLength(3);
    expect(r.audit.find((e) => e.eventType === "identity_moved")).toMatchObject({
      accountId: s.from.account.id,
      eventPayloadJson: { moveId: moveId("a"), toAccountId: s.to.account.id, providers: ["discord", "google"], reversesMoveId: null },
    });
  });

  it("answers the identical body for the same moveId after the source's sessions are revoked, and changes nothing twice", async () => {
    const r = await rig();
    const s = await scene(r);
    const body = { moveId: moveId("b"), fromProofs: [s.fromProof.token], toProof: s.toProof.token };
    const first = await move(r, body);
    expect(first.statusCode).toBe(200);
    const session = await r.store.findSession("bifrost", s.fromProof.sid);
    expect(Date.parse(session!.expiresAt), "the source's session is already dead").toBeLessThanOrEqual(Date.now());
    const again = await move(r, body);
    expect([again.statusCode, again.body]).toEqual([200, first.body]);
    expect(r.audit.filter((e) => e.eventType === "identity_moved")).toHaveLength(1);
  });

  it("a moveId reused for another account pair, another proof owner or another reversesMoveId is 409 move_id_conflict and changes nothing", async () => {
    const r = await rig();
    const s = await scene(r);
    const other = await acct(r, [["twitch"]]);
    await move(r, { moveId: moveId("c"), fromProofs: [s.fromProof.token], toProof: s.toProof.token });
    const otherProof = await proof(r, other);
    const toStranger = await move(r, { moveId: moveId("c"), fromProofs: [s.fromProof.token], toProof: otherProof.token });
    expect(err(toStranger)).toEqual([409, "move_id_conflict"]);
    const fromStranger = await move(r, { moveId: moveId("c"), fromProofs: [otherProof.token], toProof: s.toProof.token });
    expect(err(fromStranger)).toEqual([409, "move_id_conflict"]);
    const asReversal = await move(r, { moveId: moveId("c"), fromProofs: [s.toProof.token], reversesMoveId: moveId("zz") });
    expect(err(asReversal)).toEqual([409, "move_id_conflict"]);
    expect(await held(r, other)).toHaveLength(1);
    expect(await held(r, s.to)).toHaveLength(3);
  });

  it("a replay whose proofs are another app's tokens, or another account's, is 409 move_id_conflict, not the stored receipt", async () => {
    const r = await rig();
    const s = await scene(r);
    const body = { moveId: moveId("rp"), fromProofs: [s.fromProof.token], toProof: s.toProof.token };
    expect((await move(r, body)).statusCode).toBe(200);
    const foreign = await proof(r, s.from, { app: "streampixels", stepUp: passkey });
    expect(err(await move(r, { ...body, fromProofs: [foreign.token] }))).toEqual([409, "move_id_conflict"]);
    const foreignTo = await proof(r, s.to, { app: "streampixels" });
    expect(err(await move(r, { ...body, toProof: foreignTo.token }))).toEqual([409, "move_id_conflict"]);
    expect((await move(r, body)).statusCode, "the genuine proofs still replay").toBe(200);
  });

  it("an app without the secret is 401; streampixels with its own secret is 403 not_allowed_for_app", async () => {
    const r = await rig();
    const s = await scene(r);
    const body = { moveId: moveId("d"), fromProofs: [s.fromProof.token], toProof: s.toProof.token };
    expect(err(await move(r, body, {}))).toEqual([401, "app_auth_required"]);
    expect(err(await move(r, body, { "x-heimdall-app-secret": "nope" }))).toEqual([401, "app_auth_required"]);
    expect(err(await move(r, body, { "x-heimdall-app-secret": "streampixels-secret" }, "streampixels"))).toEqual([403, "not_allowed_for_app"]);
    expect(await held(r, s.from)).toHaveLength(2);
  });

  it("only bifrost is granted moves, and its account proofs are methods it may assert", () => {
    const granted = Object.values(builtInAppProfiles).filter((p) => p.identityMoves !== undefined);
    expect(granted.map((p) => p.slug)).toEqual(["bifrost"]);
    const bifrost = granted[0]!;
    expect(bifrost.identityMoves!.accountProofMethods.every((m) => bifrost.stepUpAssertion!.methods.includes(m))).toBe(true);
    expect(bifrost.identityMoves!.accountProofMethods).not.toContain("bifrost-email-code");
  });
});

describe("what a proof must be", () => {
  it("another app's token, a revoked session and a forged signature are 403 proof_invalid and nothing moves", async () => {
    const r = await rig();
    const s = await scene(r);
    const foreign = await proof(r, s.from, { app: "streampixels", stepUp: passkey });
    const revoked = await proof(r, s.from, { stepUp: passkey });
    await r.store.revokeSession("bifrost", revoked.sid, s.from.account.id, 1, new Date().toISOString());
    const forged = s.fromProof.token.slice(0, -6) + "AAAAAA";
    for (const [fromProofs, toProof, who] of [
      [[foreign.token], s.toProof.token, "from"],
      [[revoked.token], s.toProof.token, "from"],
      [[forged], s.toProof.token, "from"],
      [[s.fromProof.token], forged, "to"],
    ] as const) {
      const res = await move(r, { moveId: moveId("e"), fromProofs, toProof });
      expect([res.statusCode, res.json()]).toEqual([403, { error: "proof_invalid", proof: who }]);
    }
    expect(await held(r, s.from)).toHaveLength(2);
  });

  it("a sign-in 300 s old passes and 301 s is proof_stale; a token with no sign-in claim (refresh, link) is proof_stale; a step-up inside 600 s reports strong", async () => {
    const r = await rig();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(now));
    const to = await acct(r, [["patreon"]]);
    const toProof = await proof(r, to);
    const providers: Provider[] = ["discord", "google", "twitch", "github", "spotify", "youtube"];
    const attempt = async (tag: string, o: ProofOptions) => {
      const from = await acct(r, [[providers.shift()!]]);
      const p = await proof(r, from, o);
      return move(r, { moveId: moveId(tag), fromProofs: [p.token], toProof: toProof.token });
    };
    const edge = await attempt("edge", { signedInAgo: AUTH_PROOF_TTL_SECONDS });
    expect([edge.statusCode, edge.json().proof]).toEqual([200, { from: "weak", to: "weak" }]);
    const late = await attempt("late", { signedInAgo: AUTH_PROOF_TTL_SECONDS + 1 });
    expect([late.statusCode, late.json()]).toEqual([403, { error: "proof_stale", proof: "from" }]);
    const none = await attempt("none", { signedInAgo: null });
    expect(err(none)).toEqual([403, "proof_stale"]);
    const strong = await attempt("strong", { signedInAgo: 5_000, stepUp: { agoS: 600, method: "provider:twitch" } });
    expect([strong.statusCode, strong.json().proof.from]).toEqual([200, "strong"]);
    const stale = await attempt("stale", { signedInAgo: 5_000, stepUp: { agoS: 601, method: "bifrost-passkey" } });
    expect(err(stale)).toEqual([403, "proof_stale"]);
    // The destination's proof is held to the same rule.
    const from = await acct(r, [["google"]]);
    const fresh = await proof(r, from);
    const staleTo = await proof(r, to, { signedInAgo: AUTH_PROOF_TTL_SECONDS + 1 });
    const res = await move(r, { moveId: moveId("sto"), fromProofs: [fresh.token], toProof: staleTo.token });
    expect([res.statusCode, res.json()]).toEqual([403, { error: "proof_stale", proof: "to" }]);
  });

  it("fromProofs naming two accounts is 403 proof_invalid; one account on both sides is 409 same_account", async () => {
    const r = await rig();
    const s = await scene(r);
    const split = await move(r, { moveId: moveId("f"), fromProofs: [s.fromProof.token, s.toProof.token], toProof: s.toProof.token });
    expect([split.statusCode, split.json()]).toEqual([403, { error: "proof_invalid", proof: "from" }]);
    const twice = await proof(r, s.from, { stepUp: passkey });
    const same = await move(r, { moveId: moveId("g"), fromProofs: [s.fromProof.token], toProof: twice.token });
    expect(err(same)).toEqual([409, "same_account"]);
    expect(await held(r, s.from)).toHaveLength(2);
  });

  it("the body is closed: a forward move needs toProof, a reversal takes no toProof or identityIds, ids are patterned", async () => {
    const r = await rig();
    const s = await scene(r);
    const t = s.fromProof.token;
    for (const body of [
      { moveId: moveId("h"), fromProofs: [t] },
      { moveId: "short", fromProofs: [t], toProof: t },
      { moveId: moveId("h"), fromProofs: [], toProof: t },
      { moveId: moveId("h"), fromProofs: [t], toProof: t, reversesMoveId: moveId("i") },
      { moveId: moveId("h"), fromProofs: [t], reversesMoveId: moveId("i"), identityIds: ["x"] },
    ]) {
      expect((await move(r, body)).statusCode, JSON.stringify(Object.keys(body))).toBe(400);
    }
  });
});

describe("accounts come only from proofs", () => {
  it("a stray accountId in the body steers nothing", async () => {
    const r = await rig();
    const s = await scene(r);
    const stranger = await acct(r, [["twitch"]]);
    const res = await move(r, { moveId: moveId("y"), fromProofs: [s.fromProof.token], toProof: s.toProof.token, accountId: stranger.account.id, toAccountId: stranger.account.id });
    expect([res.statusCode, res.json().accountId]).toEqual([200, s.to.account.id]);
    expect(await held(r, stranger)).toHaveLength(1);
  });
});

describe("which logins a proof moves", () => {
  async function multi(r: Rig) {
    const from = await acct(r, [["discord"], ["google"], ["twitch"]]);
    const to = await acct(r, [["patreon"]]);
    return { from, to, toProof: await proof(r, to) };
  }

  it("a sign-in through login X moves X and cannot move the source's other logins", async () => {
    const r = await rig();
    const s = await multi(r);
    const [discord, google] = s.from.rows;
    const viaDiscord = await proof(r, s.from, { via: 0 });
    const all = await move(r, { moveId: moveId("j"), fromProofs: [viaDiscord.token], toProof: s.toProof.token });
    expect(err(all)).toEqual([403, "identity_not_proved"]);
    const other = await move(r, { moveId: moveId("j"), fromProofs: [viaDiscord.token], toProof: s.toProof.token, identityIds: [google!.id] });
    expect(err(other)).toEqual([403, "identity_not_proved"]);
    expect(await held(r, s.from)).toHaveLength(3);
    const only = await move(r, { moveId: moveId("j"), fromProofs: [viaDiscord.token], toProof: s.toProof.token, identityIds: [discord!.id] });
    expect([only.statusCode, only.json().movedIdentityIds]).toEqual([200, [discord!.id]]);
    expect((await held(r, s.from)).sort()).toEqual([google!.id, s.from.rows[2]!.id].sort());
  });

  it("one proof per login moves them all; an asserted passkey covers the whole account; an email code covers only its own login", async () => {
    const r = await rig();
    let s = await multi(r);
    const perLogin = await Promise.all(s.from.rows.map((_, via) => proof(r, s.from, { via })));
    const res = await move(r, { moveId: moveId("k"), fromProofs: perLogin.map((p) => p.token), toProof: s.toProof.token });
    expect([res.statusCode, res.json().movedIdentityIds]).toHaveLength(2);
    expect(res.json().proof.from).toBe("weak");
    expect(await held(r, s.from)).toEqual([]);

    s = await multi(r);
    const byPasskey = await proof(r, s.from, { stepUp: passkey });
    expect((await move(r, { moveId: moveId("l"), fromProofs: [byPasskey.token], toProof: s.toProof.token })).statusCode).toBe(200);

    s = await multi(r);
    const byEmail = await proof(r, s.from, { stepUp: { method: "bifrost-email-code" } });
    const refused = await move(r, { moveId: moveId("m"), fromProofs: [byEmail.token], toProof: s.toProof.token });
    expect(err(refused)).toEqual([403, "identity_not_proved"]);
    expect(await held(r, s.from)).toHaveLength(3);
  });

  it("a provider held on both sides is 409 provider_conflict naming only the provider, and nothing moves", async () => {
    const r = await rig();
    const from = await acct(r, [["discord"], ["google"]]);
    const to = await acct(r, [["discord"]]);
    const res = await move(r, { moveId: moveId("n"), fromProofs: [(await proof(r, from, { stepUp: passkey })).token], toProof: (await proof(r, to)).token });
    expect([res.statusCode, res.json()]).toEqual([409, { error: "provider_conflict", provider: "discord" }]);
    expect(res.body).not.toContain(from.account.id);
    expect(await held(r, from)).toHaveLength(2);
    expect(await held(r, to)).toHaveLength(1);
  });

  it("naming an identity the source does not hold is 404 identity_not_found", async () => {
    const r = await rig();
    const s = await scene(r);
    const res = await move(r, { moveId: moveId("o"), fromProofs: [s.fromProof.token], toProof: s.toProof.token, identityIds: [s.to.rows[0]!.id] });
    expect(err(res)).toEqual([404, "identity_not_found"]);
  });
});

describe("what a move leaves behind", () => {
  it("strips the moved credentials, expires the source's sessions, pending links and unredeemed completions, and leaves the destination live", async () => {
    const r = await rig();
    const s = await scene(r);
    const linkInput = { appSlug: "bifrost" as const, provider: "discord" as const, providerUserId: "d-x", identity: { accountId: "x", provider: "discord" as const, providerUserId: "d-x", scopes: [], profileJson: {}, createdAt: now, updatedAt: now }, returnTo: "https://bifrost.gamecult.org/x", createdAt: now, expiresAt: "2099-01-01T00:00:00.000Z" };
    const srcLink = await r.store.createPendingLink({ ...linkInput, accountId: s.from.account.id });
    const dstLink = await r.store.createPendingLink({ ...linkInput, accountId: s.to.account.id });
    const completion = (accountId: string) =>
      r.store.createAuthCompletion({ appSlug: "bifrost", provider: "discord", mode: "sign_in", accountId, sessionId: "sess", returnTo: "https://bifrost.gamecult.org/x", createdAt: now, expiresAt: "2099-01-01T00:00:00.000Z", payloadJson: {} });
    const srcCompletion = await completion(s.from.account.id);
    const dstCompletion = await completion(s.to.account.id);
    const res = await move(r, { moveId: moveId("p"), fromProofs: [s.fromProof.token], toProof: s.toProof.token });
    expect(res.statusCode).toBe(200);
    const movedIds = new Set(s.from.rows.map((row) => row.id));
    for (const row of (await r.store.listStoredLinkedIdentitiesForAccount(s.to.account.id)).filter((row) => movedIds.has(row.id))) {
      expect(row.accessTokenEncrypted).toBeUndefined();
      expect(row.refreshTokenEncrypted).toBeUndefined();
    }
    const record = await r.store.findIdentityMove(moveId("p"));
    expect(record?.moved.map((m) => m.credentialStripped)).toEqual([true, true]);
    expect((await r.store.findSession("bifrost", s.fromProof.sid))!.accessRevision).toBe(2);
    expect((await r.store.findSession("bifrost", s.toProof.sid))!.accessRevision).toBe(1);
    expect(Date.parse((await r.store.findSession("bifrost", s.toProof.sid))!.expiresAt)).toBeGreaterThan(Date.now());
    expect(await r.store.consumePendingLink("bifrost", srcLink.id, s.from.account.id, new Date().toISOString())).toBeNull();
    expect(await r.store.consumePendingLink("bifrost", dstLink.id, s.to.account.id, new Date().toISOString())).not.toBeNull();
    expect(await r.store.consumeAuthCompletion("bifrost", srcCompletion.code, new Date().toISOString())).toBeNull();
    expect(await r.store.consumeAuthCompletion("bifrost", dstCompletion.code, new Date().toISOString())).not.toBeNull();
  });

  it("revokes the source's live grants for the providers it no longer holds, leaves the destination's receipts, and a replay heals a crash after commit", async () => {
    const r = await rig();
    const s = await scene(r);
    const grant = (accountId: string, provider: Provider) =>
      r.store.createConsentReceipt({ kind: "grant", accountId, appSlug: "bifrost", provider, createdAt: now, scopesAsked: ["identify"], scopesGranted: ["identify"], consentPageDigest: "d", consentText: "t" });
    await grant(s.from.account.id, "discord");
    await grant(s.to.account.id, "patreon");
    const receiptsOf = async (a: Acct) => (await r.store.listConsentReceipts(a.account.id)).map((x) => `${x.kind}:${x.provider}`);
    const body = { moveId: moveId("q"), fromProofs: [s.fromProof.token], toProof: s.toProof.token };
    vi.spyOn(r.store, "createConsentReceipt").mockRejectedValueOnce(new Error("crash after commit"));
    expect((await move(r, body)).statusCode).toBe(500);
    expect(await held(r, s.from), "the move itself committed").toEqual([]);
    expect(await receiptsOf(s.from)).toEqual(["grant:discord"]);
    const healed = await move(r, body);
    expect(healed.statusCode).toBe(200);
    expect(await receiptsOf(s.from)).toEqual(["grant:discord", "revocation:discord"]);
    expect(await receiptsOf(s.to)).toEqual(["grant:patreon"]);
    expect((await move(r, body)).body, "and it is idempotent").toBe(healed.body);
    expect(await receiptsOf(s.from)).toHaveLength(2);
  });

  it("the destination never loses an identity, whatever is refused", async () => {
    const r = await rig();
    const s = await scene(r);
    const before = (await held(r, s.to)).length;
    const refusals = [
      { moveId: moveId("r1"), fromProofs: [s.fromProof.token], toProof: s.toProof.token, identityIds: ["nope"] },
      { moveId: moveId("r2"), fromProofs: [s.fromProof.token], toProof: s.fromProof.token },
      { moveId: moveId("r3"), fromProofs: [s.toProof.token], toProof: s.toProof.token },
    ];
    for (const body of refusals) {
      await move(r, body);
      expect((await held(r, s.to)).length).toBeGreaterThanOrEqual(before);
    }
    expect((await move(r, { moveId: moveId("r4"), fromProofs: [s.fromProof.token], toProof: s.toProof.token })).statusCode).toBe(200);
    expect((await held(r, s.to)).length).toBeGreaterThanOrEqual(before);
  });

  it("a sign-in through a moved login lands on the destination, with no alias lookup", async () => {
    const r = await rig("t-moved");
    const from = await acct(r, [["twitch", "t-moved"]]);
    const to = await acct(r, [["patreon"]]);
    const mv = await move(r, { moveId: moveId("s"), fromProofs: [(await proof(r, from, { stepUp: passkey })).token], toProof: (await proof(r, to)).token });
    expect(mv.statusCode).toBe(200);
    const started = await r.app.inject({ method: "POST", url: "/v1/oauth/twitch/start", payload: { appSlug: "streampixels", mode: "sign_in", returnTo: "https://streampixels.gamecult.org/signin/return" } });
    const flow = await launchFlow(r.app, started.json());
    const called = await r.app.inject({ method: "GET", url: `/v1/oauth/twitch/callback?code=c&state=${encodeURIComponent(flow.state)}`, headers: { cookie: flow.cookie, accept: "application/json" } });
    expect(called.statusCode).toBe(201);
    expect(called.json().account.id).toBe(to.account.id);
  });
});

describe("aliases and reversal", () => {
  it("an emptied source is an alias; moving into or out of it is 409 already_moved", async () => {
    const r = await rig();
    const s = await scene(r);
    expect((await move(r, { moveId: moveId("t"), fromProofs: [s.fromProof.token], toProof: s.toProof.token })).statusCode).toBe(200);
    // A session can outlive its logins only by being minted for an account that holds none, which is how a stale caller would look.
    const aliasProof = await proof(r, { account: s.from.account, rows: [s.to.rows[0]!] }, { stepUp: passkey });
    const third = await acct(r, [["github"]]);
    const out = await move(r, { moveId: moveId("u"), fromProofs: [aliasProof.token], toProof: (await proof(r, third)).token });
    expect(err(out)).toEqual([409, "already_moved"]);
    const aliasTo = await proof(r, { account: s.from.account, rows: [s.to.rows[0]!] });
    const into = await move(r, { moveId: moveId("u2"), fromProofs: [(await proof(r, third, { stepUp: passkey })).token], toProof: aliasTo.token });
    expect(err(into)).toEqual([409, "already_moved"]);
    expect(await held(r, third)).toHaveLength(1);
  });

  it("a reversal through a moved login moves exactly those logins back; a second reversal is not_reversible; credentials stay stripped", async () => {
    const r = await rig();
    const s = await scene(r);
    const sourceIds = await held(r, s.from);
    await move(r, { moveId: moveId("v"), fromProofs: [s.fromProof.token], toProof: s.toProof.token });
    const [discord, google] = s.from.rows;
    // The destination now holds the moved logins: a sign-in through one of them is a proof of the destination.
    const viaMoved = await proof(r, { account: s.to.account, rows: [discord!, google!] }, { via: 0 });
    const own = await proof(r, s.to, { via: 0 });
    const denied = await move(r, { moveId: moveId("w"), fromProofs: [own.token], reversesMoveId: moveId("v") });
    expect(err(denied), "the destination's own login does not speak for the moved ones").toEqual([403, "identity_not_proved"]);
    const viaBoth = [viaMoved, await proof(r, { account: s.to.account, rows: [discord!, google!] }, { via: 1 })];
    const back = await move(r, { moveId: moveId("w"), fromProofs: viaBoth.map((p) => p.token), reversesMoveId: moveId("v") });
    expect(back.statusCode, back.body).toBe(200);
    expect(back.json()).toEqual({ moveId: moveId("w"), accountId: s.from.account.id, movedIdentityIds: expect.arrayContaining(sourceIds), proof: { from: "weak", to: null }, reversesMoveId: moveId("v") });
    expect(await held(r, s.from)).toEqual(sourceIds);
    expect(await held(r, s.to)).toHaveLength(1);
    expect((await r.store.listStoredLinkedIdentitiesForAccount(s.from.account.id)).every((i) => i.accessTokenEncrypted === undefined)).toBe(true);
    const own2 = await proof(r, s.to, { via: 0 });
    const again = await move(r, { moveId: moveId("w2"), fromProofs: [own2.token], reversesMoveId: moveId("v") });
    expect(err(again)).toEqual([409, "not_reversible"]);
    const reverseTheReversal = await move(r, { moveId: moveId("w3"), fromProofs: [(await proof(r, s.from)).token], reversesMoveId: moveId("w") });
    expect(err(reverseTheReversal)).toEqual([409, "not_reversible"]);
    const unknown = await move(r, { moveId: moveId("w4"), fromProofs: [(await proof(r, s.from)).token], reversesMoveId: moveId("nothere") });
    expect(err(unknown)).toEqual([409, "not_reversible"]);
  });
});

describe("proofTier", () => {
  it("a proof dated in the future proves nothing, whichever claim carries it", () => {
    const n = nowS();
    expect(proofTier({ auth_at: n + 5 }, n)).toBeNull();
    expect(proofTier({ step_up_at: n + 5 }, n)).toBeNull();
    expect(proofTier({ step_up_at: n + 5, auth_at: n }, n), "a future step-up does not hide a valid sign-in").toBe("weak");
    expect(proofTier({ step_up_at: n, auth_at: n - 9_999 }, n)).toBe("strong");
  });
});

describe("the reversal's source must be the forward move's destination", () => {
  it("is refused as not_reversible before the proofs are judged, even for a stale proof", async () => {
    const r = await rig();
    const s = await scene(r);
    expect((await move(r, { moveId: moveId("fw"), fromProofs: [s.fromProof.token], toProof: s.toProof.token })).statusCode).toBe(200);
    const third = await acct(r, [["github"]]);
    const onward = await proof(r, s.to, { stepUp: passkey });
    expect((await move(r, { moveId: moveId("on"), fromProofs: [onward.token], toProof: (await proof(r, third)).token })).statusCode).toBe(200);
    const stale = await proof(r, third, { signedInAgo: 9_999 });
    const res = await move(r, { moveId: moveId("rv"), fromProofs: [stale.token], reversesMoveId: moveId("fw") });
    expect(err(res)).toEqual([409, "not_reversible"]);
  });
});

describe("idempotency is by moveId", () => {
  it("a replayed reversal under another reversesMoveId is 409 move_id_conflict, not the stored receipt", async () => {
    const r = await rig();
    const s = await scene(r);
    await move(r, { moveId: moveId("fw2"), fromProofs: [s.fromProof.token], toProof: s.toProof.token });
    const [discord, google] = s.from.rows;
    const viaMoved = async (via: number) => (await proof(r, { account: s.to.account, rows: [discord!, google!] }, { via })).token;
    const body = { moveId: moveId("rv2"), fromProofs: [await viaMoved(0), await viaMoved(1)], reversesMoveId: moveId("fw2") };
    const back = await move(r, body);
    expect(back.statusCode, back.body).toBe(200);
    expect((await move(r, body)).body, "the same body replays").toBe(back.body);
    expect(err(await move(r, { ...body, reversesMoveId: moveId("other") }))).toEqual([409, "move_id_conflict"]);
    expect(await held(r, s.from)).toHaveLength(2);
  });

  it("a replay with the same moveId and different identityIds returns the first receipt (steward ruling: the key is the moveId, a retry carries the same body)", async () => {
    const r = await rig();
    const from = await acct(r, [["discord"], ["google"]]);
    const to = await acct(r, [["patreon"]]);
    const fromProof = await proof(r, from, { stepUp: passkey });
    const toProof = await proof(r, to);
    const first = await move(r, { moveId: moveId("ids"), fromProofs: [fromProof.token], toProof: toProof.token, identityIds: [from.rows[0]!.id] });
    expect(first.json().movedIdentityIds).toEqual([from.rows[0]!.id]);
    const again = await move(r, { moveId: moveId("ids"), fromProofs: [fromProof.token], toProof: toProof.token, identityIds: [from.rows[1]!.id] });
    expect([again.statusCode, again.body]).toEqual([200, first.body]);
    expect(await held(r, from), "and the second selection did not move").toEqual([from.rows[1]!.id]);
  });
});

describe("what a refusal says", () => {
  it("no refusal body names an account id, an email, a name or an identity the caller did not send", async () => {
    const r = await rig();
    const s = await scene(r);
    const stranger = await acct(r, [["discord", "d-stranger"]]);
    const bodies = [
      await move(r, { moveId: moveId("x1"), fromProofs: [s.fromProof.token], toProof: "garbage" }),
      await move(r, { moveId: moveId("x2"), fromProofs: [(await proof(r, s.from, { via: 0 })).token], toProof: s.toProof.token }),
      await move(r, { moveId: moveId("x3"), fromProofs: [s.fromProof.token], toProof: s.toProof.token, identityIds: [stranger.rows[0]!.id] }),
      await move(r, { moveId: moveId("x4"), fromProofs: [s.toProof.token], toProof: s.toProof.token }),
      await move(r, { moveId: moveId("x5"), fromProofs: [s.fromProof.token], reversesMoveId: moveId("nothere") }),
      await move(r, { moveId: moveId("x6"), fromProofs: [(await proof(r, s.from, { signedInAgo: 9_999 })).token], toProof: s.toProof.token }),
    ];
    const ids = [s.from, s.to, stranger].flatMap((a) => [a.account.id, ...a.rows.map((row) => row.id), ...a.rows.map((row) => row.providerUserId)]);
    for (const res of bodies) {
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      for (const id of ids) expect(res.body).not.toContain(id);
      expect(res.body).not.toMatch(/canary|DISPLAY/);
      expect(Object.keys(res.json()).every((k) => ["error", "detail", "proof", "provider"].includes(k))).toBe(true);
    }
  });
});

describe("claims: which sign-in a token came from", () => {
  const returnTo = "https://streampixels.gamecult.org/signin/return";
  async function twitchSignIn(r: Rig) {
    const started = await r.app.inject({ method: "POST", url: "/v1/oauth/twitch/start", payload: { appSlug: "streampixels", mode: "sign_in", returnTo } });
    const flow = await launchFlow(r.app, started.json());
    const called = await r.app.inject({ method: "GET", url: `/v1/oauth/twitch/callback?code=c&state=${encodeURIComponent(flow.state)}`, headers: { cookie: flow.cookie, accept: "application/json" } });
    expect(called.statusCode).toBe(201);
    const redeemed = await r.app.inject({ method: "POST", url: "/v1/apps/streampixels/auth-completions/redeem", payload: { completionCode: called.json().completion.code } });
    expect(redeemed.statusCode).toBe(201);
    return redeemed.json() as { refreshToken: string; claimSet: Record<string, unknown> };
  }

  it("a sign_in stamps auth_at and the login it came through; a refresh does not renew them", async () => {
    const r = await rig("t-claims");
    const before = nowS();
    const signed = await twitchSignIn(r);
    const row = await r.store.findStoredLinkedIdentity("twitch", "t-claims");
    expect(signed.claimSet.auth_identity_id).toBe(row!.id);
    expect(signed.claimSet.auth_at).toBeGreaterThanOrEqual(before);
    expect(signed.claimSet.auth_at).toBeLessThanOrEqual(nowS());
    expect(signed.claimSet.step_up_at).toBeUndefined();
    const refreshed = await r.app.inject({ method: "POST", url: "/v1/apps/streampixels/sessions/refresh", payload: { refreshToken: signed.refreshToken } });
    expect(refreshed.statusCode).toBe(201);
    expect(refreshed.json().claimSet.auth_at).toBeUndefined();
    expect(refreshed.json().claimSet.auth_identity_id).toBeUndefined();
  });

  it("a link callback mints no sign-in proof: no auth_at, no auth_identity_id", async () => {
    const r = await rig();
    const holder = await acct(r, [["twitch"]]);
    const started = await r.app.inject({ method: "POST", url: "/v1/oauth/discord/start", headers: appAuth, payload: { appSlug: "bifrost", mode: "link", initiatingAccountId: holder.account.id, returnTo: "https://bifrost.gamecult.org/x" } });
    expect(started.statusCode).toBe(201);
    const flow = await launchFlow(r.app, started.json());
    const called = await r.app.inject({ method: "GET", url: `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(flow.state)}`, headers: { cookie: flow.cookie, accept: "application/json" } });
    expect(called.statusCode).toBe(201);
    expect(called.json().claimSet.identities).toHaveLength(2);
    expect(called.json().claimSet.auth_at).toBeUndefined();
    expect(called.json().claimSet.auth_identity_id).toBeUndefined();
    expect(called.body).not.toMatch(/auth_at|auth_identity_id/);
  });

  it("a connect callback mints no sign-in proof either", async () => {
    const r = await rig("t-connect");
    const started = await r.app.inject({ method: "POST", url: "/v1/oauth/twitch/start", headers: { "x-heimdall-app-secret": "streampixels-secret" }, payload: { appSlug: "streampixels", mode: "connect", returnTo: "https://streampixels.gamecult.org/signin/return", connection: { kind: "creator", targetId: "creator-1" } } });
    expect(started.statusCode, started.body).toBe(201);
    const flow = await launchFlow(r.app, started.json());
    const called = await r.app.inject({ method: "GET", url: `/v1/oauth/twitch/callback?code=c&state=${encodeURIComponent(flow.state)}`, headers: { cookie: flow.cookie, accept: "application/json" } });
    expect(called.statusCode, called.body).toBe(201);
    expect(called.body).toContain("claimSet");
    expect(called.body).not.toMatch(/auth_at|auth_identity_id/);
  });

  it("an asserted step-up carries the bearer's auth claims through unchanged", async () => {
    const r = await rig();
    const a = await acct(r, [["discord"], ["google"]]);
    const p = await proof(r, a, { via: 1, signedInAgo: 30 });
    const res = await r.app.inject({ method: "POST", url: "/v1/apps/bifrost/step-up", headers: { ...appAuth, authorization: `Bearer ${p.token}` }, payload: { method: "bifrost-passkey", nonce: "n".repeat(32) } });
    expect(res.statusCode).toBe(201);
    expect(res.json().claimSet).toMatchObject({ auth_identity_id: a.rows[1]!.id, auth_at: nowS() - 30, step_up_method: "bifrost-passkey" });
  });
});
