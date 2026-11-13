import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { buildApp, STEP_UP_ASSERT_LIMITS } from "../src/app.js";
import { builtInAppProfiles } from "../src/app-profiles.js";
import { issueAccessClaim } from "../src/claims.js";
import { type Provider } from "../src/contracts.js";
import { createRuntimeKeyMaterial, signJwt, verifyJwt } from "../src/signing.js";
import { InMemoryStore } from "../src/store/index.js";
import { type CreateAuditEventInput } from "../src/store/types.js";
import { createTestConfig } from "./oauth-flow.js";

// An app asserting a step-up proof for its member: POST /v1/apps/{app}/step-up.
// Driven over HTTP through the real Fastify app, the way Bifrost would call it,
// with the unlink route as the consumer of the proof it mints.

const now = "2026-11-13T12:00:00.000Z";
const secret = "bifrost-secret";
const appAuth = { "x-heimdall-app-secret": secret };
const nonce = (tag: string) => `nonce-${tag.replace(/[^A-Za-z0-9_-]/g, "_")}-`.padEnd(32, "x");

const dir = mkdtempSync(join(tmpdir(), "heimdall-stepup-assert-"));
const config = { ...createTestConfig(), signingPrivateKeyPath: join(dir, "signing.pem"), bootstrapSigningPrivateKeyOnMissing: true };
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function rig() {
  const store = new InMemoryStore();
  const audit: CreateAuditEventInput[] = [];
  const realAudit = store.createAuditEvent.bind(store);
  store.createAuditEvent = async (input) => {
    audit.push(structuredClone(input));
    return realAudit(input);
  };
  const app = await buildApp({ config, store });
  apps.push(app);
  const keys = createRuntimeKeyMaterial({ ...config, bootstrapSigningPrivateKeyOnMissing: false });
  return { app, store, keys, audit };
}
type Rig = Awaited<ReturnType<typeof rig>>;

/** A member with the given identities and a live Heimdall session for `appSlug`, as a sign-in would have left them. */
let seq = 0;
async function member(r: Rig, appSlug = "bifrost", held?: Array<[Provider, string]>, accountId?: string) {
  seq += 1;
  held ??= [["discord", `d-${seq}`], ["google", `g-${seq}`]];
  const account = accountId ? { id: accountId } : await r.store.createAccount({ createdAt: now, lastSeenAt: now });
  const rows = [];
  if (!accountId) {
    for (const [provider, providerUserId] of held) {
      rows.push(await r.store.upsertLinkedIdentity({ accountId: account.id, provider, providerUserId, scopes: [], profileJson: {}, createdAt: now, updatedAt: now }));
    }
  }
  const issued = await issueAccessClaim({
    config,
    keys: r.keys,
    store: r.store,
    input: { appSlug, accountId: account.id, linkedIdentities: held.map(([provider, providerUserId]) => ({ provider, providerUserId })), facts: [] },
  });
  return { account, rows, issued, token: issued.accessToken, sid: issued.session.sessionId };
}

const bearer = (token?: string) => (token ? { authorization: `Bearer ${token}` } : {});
const assertStepUp = (r: Rig, o: { app?: string; headers?: Record<string, string>; token?: string | undefined; method?: string; nonce?: string; payload?: object } = {}) =>
  r.app.inject({
    method: "POST",
    url: `/v1/apps/${o.app ?? "bifrost"}/step-up`,
    headers: { ...(o.headers ?? appAuth), ...bearer(o.token) },
    payload: o.payload ?? { method: o.method ?? "bifrost-passkey", nonce: o.nonce ?? nonce("a") },
  });
const unlink = (r: Rig, id: string, token: string) =>
  r.app.inject({ method: "POST", url: `/v1/me/identities/${encodeURIComponent(id)}/unlink`, headers: bearer(token) });
const refused = (res: { statusCode: number; json(): { error?: string } }) => [res.statusCode, res.json().error];
const claimsOf = (token: string, r: Rig) => {
  const v = verifyJwt(token, r.keys.publicKey);
  expect(v.valid).toBe(true);
  return v.valid ? v.payload : {};
};
const nowS = () => Math.floor(Date.now() / 1000);
const auditOf = (r: Rig, type: string) => r.audit.filter((e) => e.eventType === type);

describe("the proof it mints", () => {
  it("returns a new access token for the same session and account, with step_up_at now and the method, and no refresh token", async () => {
    const r = await rig();
    const m = await member(r);
    const before = nowS();
    const res = await assertStepUp(r, { token: m.token });
    expect(res.statusCode).toBe(201);
    expect(res.headers["cache-control"]).toBe("no-store");
    const body = res.json();
    expect(Object.keys(body).sort()).toEqual(["accessToken", "claimSet", "stepUp"]);
    expect(res.body).not.toContain(m.issued.refreshToken);
    const original = claimsOf(m.token, r);
    const minted = claimsOf(body.accessToken, r);
    expect(minted.step_up_method).toBe("bifrost-passkey");
    expect(minted.step_up_at).toBeGreaterThanOrEqual(before);
    expect(minted.step_up_at).toBeLessThanOrEqual(nowS());
    expect(body.claimSet).toEqual(minted);
    expect(body.stepUp).toEqual({ at: minted.step_up_at, method: "bifrost-passkey", validForSeconds: 600 });
    expect(minted.jti).not.toBe(original.jti);
    // Everything else is the bearer's own: it adds proof, not capability, and does not move the session.
    const { jti, iat, nbf, step_up_at, step_up_method, ...rest } = minted;
    const { jti: _j, iat: _i, nbf: _n, ...originalRest } = original;
    expect(rest).toEqual(originalRest);
    expect([jti, iat, nbf, step_up_at, step_up_method].every((v) => v !== undefined)).toBe(true);
    expect(minted.sid).toBe(m.sid);
    expect(minted.account_id).toBe(m.account.id);
    expect(minted.aud).toBe("bifrost");
  });

  it("the unlink check passes with the returned bearer and fails 403 step_up_required with the original", async () => {
    const r = await rig();
    const m = await member(r);
    expect(refused(await unlink(r, m.rows[1]!.id, m.token))).toEqual([403, "step_up_required"]);
    const minted = (await assertStepUp(r, { token: m.token })).json().accessToken;
    expect((await unlink(r, m.rows[1]!.id, m.token)).statusCode, "the original bearer gains nothing").toBe(403);
    const done = await unlink(r, m.rows[1]!.id, minted);
    expect(done.statusCode).toBe(200);
    expect(done.json().unlinked.id).toBe(m.rows[1]!.id);
    const unlinkEvent = auditOf(r, "identity_unlinked")[0]!;
    expect(unlinkEvent.eventPayloadJson).toMatchObject({ provider: "google", stepUpMethod: "bifrost-passkey" });
  });

  it("does not extend the lifetime: exp stays the bearer's, the session row is untouched, no refresh is minted", async () => {
    const r = await rig();
    const m = await member(r);
    const sessionBefore = await r.store.findSession("bifrost", m.sid);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 1_500_000);
    const res = await assertStepUp(r, { token: m.token });
    expect(res.statusCode).toBe(201);
    const original = claimsOf(m.token, r);
    const minted = claimsOf(res.json().accessToken, r);
    expect(minted.exp).toBe(original.exp);
    expect(minted.iat).toBeGreaterThan(original.iat as number);
    expect(await r.store.findSession("bifrost", m.sid)).toEqual(sessionBefore);
  });

  it("a refresh after an assertion carries neither step_up_at nor step_up_method", async () => {
    const r = await rig();
    const m = await member(r);
    expect((await assertStepUp(r, { token: m.token })).statusCode).toBe(201);
    const refreshed = await r.app.inject({ method: "POST", url: "/v1/apps/bifrost/sessions/refresh", payload: { refreshToken: m.issued.refreshToken } });
    expect(refreshed.statusCode).toBe(201);
    const claims = claimsOf(refreshed.json().accessToken, r);
    expect(claims).not.toHaveProperty("step_up_at");
    expect(claims).not.toHaveProperty("step_up_method");
    expect(refreshed.json().claimSet).not.toHaveProperty("step_up_at");
    expect(refreshed.json().claimSet).not.toHaveProperty("step_up_method");
  });

  it("the proof is good for 599 s and not for 601 s, as for any step-up", async () => {
    const r = await rig();
    const m = await member(r, "bifrost", [["discord", "d-w"], ["google", "g-w"], ["patreon", "p-w"]]);
    vi.useFakeTimers({ toFake: ["Date"] });
    const minted = (await assertStepUp(r, { token: m.token })).json().accessToken;
    vi.setSystemTime(Date.now() + 601_000);
    expect(refused(await unlink(r, m.rows[1]!.id, minted))).toEqual([403, "step_up_required"]);
    vi.setSystemTime(Date.now() - 2_000);
    expect((await unlink(r, m.rows[1]!.id, minted)).statusCode).toBe(200);
  });

  it("the provider step-up callback labels its proof provider:<name>", async () => {
    // The sign_in path itself is proved in identity-unlink.test.ts; here the claim input is the contract.
    const r = await rig();
    const m = await member(r);
    const issued = await issueAccessClaim({
      config, keys: r.keys, store: r.store,
      input: { appSlug: "bifrost", accountId: m.account.id, linkedIdentities: [], facts: [], stepUpAt: nowS(), stepUpMethod: "provider:google" },
    });
    expect(issued.claimSet.step_up_method).toBe("provider:google");
  });
});

describe("it is never issuable without both credentials", () => {
  it("401 app_auth_required for a missing, wrong, or another app's secret, even with a good bearer; nothing is written", async () => {
    const r = await rig();
    const m = await member(r);
    for (const headers of [{}, { "x-heimdall-app-secret": "wrong" }, { "x-heimdall-app-secret": "streampixels-secret" }, { "x-heimdall-app-secret": "" }]) {
      const res = await assertStepUp(r, { headers, token: m.token });
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual({ error: "app_auth_required" });
    }
    expect(r.audit.filter((e) => e.eventType.startsWith("step_up"))).toEqual([]);
  });

  it("401 sign_in_required for a missing, garbage, expired, foreign-signed, revoked-session or unknown-session bearer; the same answer for each", async () => {
    const r = await rig();
    const m = await member(r);
    const claims = claimsOf(m.token, r);
    const past = nowS() - 10;
    const other = createRuntimeKeyMaterial({ ...config, signingPrivateKeyPath: join(dir, "other.pem"), bootstrapSigningPrivateKeyOnMissing: true });
    const bad: Array<[string, string | undefined]> = [
      ["missing", undefined],
      ["garbage", "not-a-token"],
      ["expired", signJwt({ ...claims, iat: past - 100, nbf: past - 100, exp: past }, r.keys)],
      ["foreign key", signJwt(claims, other)],
      ["unknown session", signJwt({ ...claims, sid: "no-such-session" }, r.keys)],
      ["wrong account for the session", signJwt({ ...claims, account_id: "someone-else" }, r.keys)],
      ["refresh token as bearer", m.issued.refreshToken],
    ];
    for (const [label, token] of bad) {
      const res = await assertStepUp(r, { token, nonce: nonce(label) });
      expect([label, ...refused(res)]).toEqual([label, 401, "sign_in_required"]);
      expect(res.body).not.toContain("account");
    }
    // A revoked session: the row is closed and its revision moved on.
    expect(await r.store.revokeSession("bifrost", m.sid, m.account.id, 1, now)).not.toBeNull();
    const revoked = await assertStepUp(r, { token: m.token, nonce: nonce("revoked") });
    expect(refused(revoked)).toEqual([401, "sign_in_required"]);
    expect(r.audit.some((e) => e.eventType === "step_up_asserted")).toBe(false);
  });

  it("a bearer issued to another app is 403 bearer_app_mismatch, never a proof, and says nothing about the account", async () => {
    const r = await rig();
    const sp = await member(r, "streampixels");
    const res = await assertStepUp(r, { token: sp.token });
    expect(refused(res)).toEqual([403, "bearer_app_mismatch"]);
    expect(res.body).not.toContain(sp.account.id);
    // A token for a session that does not exist is indistinguishable from garbage, whatever app it names.
    const ghost = signJwt({ ...claimsOf(sp.token, r), sid: "ghost" }, r.keys);
    expect(refused(await assertStepUp(r, { token: ghost }))).toEqual([401, "sign_in_required"]);
  });

  it("only a profile that grants it may assert: every other app is 403 with its own secret and a live bearer", async () => {
    expect(Object.values(builtInAppProfiles).filter((p) => p.stepUpAssertion).map((p) => p.slug)).toEqual(["bifrost"]);
    const r = await rig();
    for (const [slug, appSecret] of [["streampixels", "streampixels-secret"], ["repixelizer", "repixelizer-secret"]] as const) {
      const m = await member(r, slug);
      const res = await assertStepUp(r, { app: slug, headers: { "x-heimdall-app-secret": appSecret }, token: m.token });
      expect([slug, ...refused(res)]).toEqual([slug, 403, "step_up_assertion_not_permitted"]);
      expect(res.json()).not.toHaveProperty("accessToken");
    }
    // Another app's secret on bifrost's route is still app_auth_required, not the flag.
    const b = await member(r);
    expect(refused(await assertStepUp(r, { headers: { "x-heimdall-app-secret": "streampixels-secret" }, token: b.token }))).toEqual([401, "app_auth_required"]);
  });
});

describe("the method and the nonce", () => {
  it("rejects a method outside the profile's closed set with 400, names the set, and does not spend the nonce", async () => {
    const r = await rig();
    const m = await member(r);
    for (const method of ["passkey", "provider:google", "streampixels-passkey", "BIFROST-PASSKEY", "bifrost-passkey "]) {
      const res = await assertStepUp(r, { token: m.token, method, nonce: nonce("m") });
      expect([method, ...refused(res)]).toEqual([method, 400, "unknown_step_up_method"]);
      expect(res.json().methods).toEqual(["bifrost-passkey", "bifrost-email-code"]);
    }
    expect((await assertStepUp(r, { token: m.token, method: "bifrost-email-code", nonce: nonce("m") })).statusCode).toBe(201);
  });

  it("malformed bodies are 400 before anything is minted", async () => {
    const r = await rig();
    const m = await member(r);
    for (const payload of [{}, { method: "bifrost-passkey" }, { nonce: nonce("a") }, { method: "bifrost-passkey", nonce: "short" }, { method: "bifrost-passkey", nonce: "has a space in it, 16+ chars" }, { method: "bifrost-passkey", nonce: `${"a".repeat(20)}\ud800` }, { method: "bifrost-passkey", nonce: "a".repeat(129) }, { method: "bifrost-passkey", nonce: "ok-looking-nonce-é-ünï" }, { method: 7, nonce: nonce("a") }]) {
      expect((await assertStepUp(r, { token: m.token, payload })).statusCode, JSON.stringify(payload)).toBe(400);
    }
    expect(auditOf(r, "step_up_asserted")).toEqual([]);
  });

  it("a nonce is single-use per session: the second try is 409, another session may use the same value", async () => {
    const r = await rig();
    const m = await member(r);
    const second = await member(r, "bifrost", [], m.account.id);
    expect((await assertStepUp(r, { token: m.token })).statusCode).toBe(201);
    const replay = await assertStepUp(r, { token: m.token });
    expect(refused(replay)).toEqual([409, "step_up_nonce_replayed"]);
    expect(replay.json()).not.toHaveProperty("accessToken");
    // The replay does not depend on which method rides with it.
    expect(refused(await assertStepUp(r, { token: m.token, method: "bifrost-email-code" }))).toEqual([409, "step_up_nonce_replayed"]);
    expect((await assertStepUp(r, { token: second.token })).statusCode).toBe(201);
  });

  it("a nonce is retained to the session's expiry as of the claim: a refresh slides the session past it, and then the nonce can be reused (documented limit)", async () => {
    const r = await rig();
    const m = await member(r);
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    const R = config.refreshTtlSeconds * 1000;
    expect((await assertStepUp(r, { token: m.token, nonce: nonce("N") })).statusCode).toBe(201);
    vi.setSystemTime(t0 + R - 60_000);
    const refreshed = await r.app.inject({ method: "POST", url: "/v1/apps/bifrost/sessions/refresh", payload: { refreshToken: m.issued.refreshToken } });
    expect(refreshed.statusCode).toBe(201);
    const token = refreshed.json().accessToken as string;
    // Inside the retained horizon the replay is still refused, refreshed session or not.
    expect(refused(await assertStepUp(r, { token, nonce: nonce("N") }))).toEqual([409, "step_up_nonce_replayed"]);
    // Past the old expiry plus the store's prune margin, the next claim prunes N while the session lives on.
    vi.setSystemTime(t0 + R + 11 * 60_000);
    expect((await assertStepUp(r, { token, nonce: nonce("M") })).statusCode).toBe(201);
    expect((await assertStepUp(r, { token, nonce: nonce("N") })).statusCode).toBe(201);
  });

  it("a nonce stays spent for the session's life, past the access token's own expiry, and across a restart of the process", async () => {
    const r = await rig();
    const m = await member(r);
    expect((await assertStepUp(r, { token: m.token })).statusCode).toBe(201);
    // A second app instance over the same store has no memory of the first: the store carries the claim.
    const again = await buildApp({ config, store: r.store });
    apps.push(again);
    const res = await again.inject({ method: "POST", url: "/v1/apps/bifrost/step-up", headers: { ...appAuth, ...bearer(m.token) }, payload: { method: "bifrost-passkey", nonce: nonce("a") } });
    expect(refused(res)).toEqual([409, "step_up_nonce_replayed"]);
  });
});

describe("rate limits", () => {
  it("trips per account, leaves other accounts alone, and turns over with the window", async () => {
    const r = await rig();
    const m = await member(r);
    const other = await member(r);
    vi.useFakeTimers({ toFake: ["Date"] });
    for (let i = 0; i < STEP_UP_ASSERT_LIMITS.account.max; i += 1) {
      expect((await assertStepUp(r, { token: m.token, nonce: nonce(`r${i}`) })).statusCode, `attempt ${i}`).toBe(201);
    }
    const tripped = await assertStepUp(r, { token: m.token, nonce: nonce("over") });
    expect(refused(tripped)).toEqual([429, "step_up_rate_limited"]);
    expect(tripped.json().retryAfterSeconds).toBeGreaterThan(0);
    expect(tripped.json()).not.toHaveProperty("accessToken");
    expect((await assertStepUp(r, { token: other.token })).statusCode).toBe(201);
    vi.setSystemTime(Date.now() + STEP_UP_ASSERT_LIMITS.account.windowMs + 1000);
    expect((await assertStepUp(r, { token: m.token, nonce: nonce("after") })).statusCode).toBe(201);
    // The tripped attempt did not spend its nonce.
    expect((await assertStepUp(r, { token: m.token, nonce: nonce("over") })).statusCode).toBe(201);
  });

  it("trips per app across accounts, counting attempts that failed their bearer", async () => {
    const r = await rig();
    const m = await member(r);
    vi.useFakeTimers({ toFake: ["Date"] });
    for (let i = 0; i < STEP_UP_ASSERT_LIMITS.app.max; i += 1) {
      expect((await assertStepUp(r, { token: "garbage", nonce: nonce(`g${i}`) })).statusCode).toBe(401);
    }
    expect(refused(await assertStepUp(r, { token: m.token }))).toEqual([429, "step_up_rate_limited"]);
    vi.setSystemTime(Date.now() + STEP_UP_ASSERT_LIMITS.app.windowMs + 1000);
    expect((await assertStepUp(r, { token: m.token })).statusCode).toBe(201);
  });
});

describe("flood handling", () => {
  it("a flood is not an audit flood: an app without the grant is audited once per window, a tripped budget once per window", async () => {
    const r = await rig();
    const sp = await member(r, "streampixels");
    vi.useFakeTimers({ toFake: ["Date"] });
    const codes: Record<number, number> = {};
    for (let i = 0; i < 500; i += 1) {
      const res = await assertStepUp(r, { app: "streampixels", headers: { "x-heimdall-app-secret": "streampixels-secret" }, token: sp.token, nonce: nonce(`f${i}`) });
      codes[res.statusCode] = (codes[res.statusCode] ?? 0) + 1;
    }
    expect(codes).toEqual({ 403: STEP_UP_ASSERT_LIMITS.notPermitted.max, 429: 500 - STEP_UP_ASSERT_LIMITS.notPermitted.max });
    const rows = (code: string) => auditOf(r, "step_up_assertion_refused").filter((e) => e.eventPayloadJson.code === code);
    expect(rows("step_up_assertion_not_permitted")).toHaveLength(1);
    expect(rows("step_up_rate_limited")).toHaveLength(1);
    vi.setSystemTime(Date.now() + STEP_UP_ASSERT_LIMITS.notPermitted.windowMs + 1000);
    await assertStepUp(r, { app: "streampixels", headers: { "x-heimdall-app-secret": "streampixels-secret" }, token: sp.token });
    expect(rows("step_up_assertion_not_permitted")).toHaveLength(2);

    // The same for the granted app's per-app and per-account budgets.
    const m = await member(r);
    const before = r.audit.length;
    for (let i = 0; i < 300; i += 1) await assertStepUp(r, { token: "garbage", nonce: nonce(`g${i}`) });
    expect(r.audit.length - before, "garbage-bearer refusals up to the budget, then one row for the trip").toBe(STEP_UP_ASSERT_LIMITS.app.max + 1);
    vi.setSystemTime(Date.now() + STEP_UP_ASSERT_LIMITS.app.windowMs + 1000);
    const mark = r.audit.length;
    for (let i = 0; i < 30; i += 1) await assertStepUp(r, { token: m.token, nonce: nonce(`a${i}`) });
    const accountRows = r.audit.slice(mark);
    expect(accountRows.filter((e) => e.eventType === "step_up_asserted")).toHaveLength(STEP_UP_ASSERT_LIMITS.account.max);
    expect(accountRows.filter((e) => e.eventPayloadJson.code === "step_up_rate_limited")).toHaveLength(1);
  });
});

describe("receipts", () => {
  it("records every assertion and every post-secret refusal with account, app, session, method, outcome and time, and nothing secret", async () => {
    const r = await rig();
    const m = await member(r);
    const sp = await member(r, "streampixels");
    const printed: string[] = [];
    for (const channel of ["log", "info", "warn", "error", "debug"] as const) vi.spyOn(console, channel).mockImplementation((...a) => void printed.push(a.join(" ")));
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => (printed.push(String(chunk)), true));
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => (printed.push(String(chunk)), true));

    const nonceOk = nonce("ok-CANARY");
    const nonceBadMethod = nonce("bad-CANARY");
    const responses = [
      await assertStepUp(r, { token: m.token, nonce: nonceOk }),
      await assertStepUp(r, { token: m.token, nonce: nonceOk }),
      await assertStepUp(r, { token: m.token, method: "evil-CANARY-method", nonce: nonceBadMethod }),
      await assertStepUp(r, { token: sp.token, nonce: nonce("mismatch-CANARY") }),
      await assertStepUp(r, { token: "garbage-CANARY", nonce: nonce("anon-CANARY") }),
    ];
    expect(responses.map((x) => x.statusCode)).toEqual([201, 409, 400, 403, 401]);

    const ok = auditOf(r, "step_up_asserted");
    expect(ok).toHaveLength(1);
    expect(ok[0]).toMatchObject({ accountId: m.account.id, sessionId: m.sid, appSlug: "bifrost", eventPayloadJson: { outcome: "asserted", method: "bifrost-passkey" } });
    expect(Date.parse(ok[0]!.createdAt)).not.toBeNaN();
    const refusals = auditOf(r, "step_up_assertion_refused");
    expect(refusals.map((e) => e.eventPayloadJson.code)).toEqual(["step_up_nonce_replayed", "unknown_step_up_method", "bearer_app_mismatch", "sign_in_required"]);
    expect(refusals.map((e) => e.accountId)).toEqual([m.account.id, m.account.id, sp.account.id, undefined]);
    expect(refusals[1]!.eventPayloadJson.method).toBeNull();
    expect(refusals.every((e) => e.appSlug === "bifrost" && e.eventPayloadJson.outcome === "refused")).toBe(true);
    for (const e of [...ok, ...refusals.slice(0, 2)]) expect(e.eventPayloadJson.nonceDigest).toMatch(/^[0-9a-f]{64}$/);

    const everything = JSON.stringify([r.audit, printed, responses.map((x) => x.body.replace(/"accessToken":"[^"]+"/, ""))]);
    const minted = responses[0]!.json().accessToken as string;
    const secrets = [secret, m.token, sp.token, m.issued.refreshToken, "CANARY"];
    for (const needle of secrets) expect(everything, needle).not.toContain(needle);
    expect(JSON.stringify(r.audit)).not.toContain(minted);
    expect(printed.join("")).not.toContain(minted);
    // A stored session row holds nothing the minted token adds.
    expect(JSON.stringify(await r.store.findSession("bifrost", m.sid))).not.toContain("step_up");
  });
});
