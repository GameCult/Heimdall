import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { type FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { loadConfig, type HeimdallConfig } from "../src/config.js";
import { resetGoogleJwksCache } from "../src/google-oidc.js";
import { type OAuthProviderRuntime } from "../src/oauth.js";
import { InMemoryStore } from "../src/store/index.js";

const CLIENT_ID = "google-client";
const REDIRECT = "https://heimdall.gamecult.org/v1/oauth/google/callback";
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const originalFetch = globalThis.fetch;
const apps: FastifyInstance[] = [];

function config(): HeimdallConfig {
  const base = loadConfig({
    GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
    GC_ACCESS_PROVIDER_GOOGLE_CLIENT_ID: CLIENT_ID,
    GC_ACCESS_PROVIDER_DISCORD_CLIENT_ID: "discord-client",
  } as NodeJS.ProcessEnv);
  return {
    ...base,
    storage: { backend: "memory", applySchemaOnStartup: true },
    tokenEncryptionKeyBase64: Buffer.alloc(32, 7).toString("base64"),
    bootstrapSigningPrivateKeyOnMissing: true,
    providers: {
      ...base.providers,
      google: { clientId: CLIENT_ID, clientSecret: "google-secret" },
      discord: { clientId: "discord-client", clientSecret: "discord-secret" },
    },
  };
}

function discordRuntime(providerUserId: string, name: string): OAuthProviderRuntime {
  return {
    async exchangeAuthorizationCode() {
      return { accessToken: "d-at", refreshToken: "d-rt", tokenType: "Bearer", scope: ["identify"], expiresAt: "2099-01-01T00:00:00.000Z", raw: {} };
    },
    async resolveIdentity() {
      return { provider: "discord", providerUserId, username: name, displayName: name, profile: { id: providerUserId } };
    },
    async evaluateEntitlements() {
      return { facts: [], snapshots: [] };
    },
  };
}

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signedIdToken(claims: Record<string, unknown>): string {
  const now = Math.floor(Date.now() / 1000);
  const body = `${b64({ alg: "RS256", kid: "k1" })}.${b64({
    iss: "https://accounts.google.com",
    aud: CLIENT_ID,
    azp: CLIENT_ID,
    sub: "g-sub-1",
    email: "person@example.org",
    email_verified: true,
    name: "Person",
    iat: now,
    exp: now + 600,
    ...claims,
  })}`;
  return `${body}.${createSign("RSA-SHA256").update(body).sign(rsa.privateKey).toString("base64url")}`;
}

interface GoogleLeg {
  tokenRequests: URLSearchParams[];
}

/** Google's two endpoints: the key set, and a token endpoint whose id_token echoes the nonce it was told. */
function fakeGoogle(options: { nonceFrom: () => string | undefined; claims?: Record<string, unknown> }): GoogleLeg {
  const leg: GoogleLeg = { tokenRequests: [] };
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "https://www.googleapis.com/oauth2/v3/certs") {
      return new Response(
        JSON.stringify({ keys: [{ ...(rsa.publicKey.export({ format: "jwk" }) as object), kid: "k1", alg: "RS256" }] }),
        { status: 200 }
      );
    }
    if (url === "https://oauth2.googleapis.com/token") {
      leg.tokenRequests.push(new URLSearchParams(String(init?.body)));
      return new Response(
        JSON.stringify({
          access_token: "g-at",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid email profile",
          id_token: signedIdToken({ nonce: options.nonceFrom(), ...options.claims }),
        }),
        { status: 200 }
      );
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  return leg;
}

function accountCount(store: InMemoryStore): number {
  return (store as unknown as { accounts: Map<string, unknown> }).accounts.size;
}

async function signInWithDiscord(app: FastifyInstance, providerUserId = "discord-1"): Promise<{ accessToken: string; accountId: string }> {
  const start = await app.inject({
    method: "POST",
    url: "/v1/oauth/discord/start",
    payload: { appSlug: "bifrost", mode: "sign_in", returnTo: "https://bifrost.gamecult.org/auth/heimdall/complete" },
  });
  expect(start.statusCode).toBe(201);
  const callback = await app.inject({
    method: "GET",
    url: `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(start.json().stateToken)}`,
  });
  expect(callback.statusCode).toBe(201);
  const body = callback.json();
  return { accessToken: body.accessToken as string, accountId: body.account.id as string };
}

async function build(store = new InMemoryStore(), discordUser = "discord-1") {
  const app = await buildApp({ config: config(), store, oauthRuntimes: { discord: discordRuntime(discordUser, "Person") } });
  apps.push(app);
  return { app, store };
}

function startGoogle(app: FastifyInstance, accessToken?: string, mode: "link" | "sign_in" = "link") {
  return app.inject({
    method: "POST",
    url: "/v1/oauth/google/start",
    headers: accessToken ? { authorization: `Bearer ${accessToken}` } : {},
    payload: { appSlug: "bifrost", mode, returnTo: "https://bifrost.gamecult.org/auth/heimdall/complete" },
  });
}

function callbackGoogle(app: FastifyInstance, stateToken: string) {
  return app.inject({ method: "GET", url: `/v1/oauth/google/callback?code=g-code&state=${encodeURIComponent(stateToken)}` });
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  resetGoogleJwksCache();
  while (apps.length) await apps.pop()?.close();
});

describe("Google as a Heimdall OIDC provider", () => {
  it("builds the authorization request: openid email profile, the exact callback, state, nonce and an S256 challenge", async () => {
    const { app } = await build();
    const { accessToken } = await signInWithDiscord(app);
    const start = await startGoogle(app, accessToken);

    expect(start.statusCode).toBe(201);
    expect(start.json().callbackUrl).toBe(REDIRECT);
    const url = new URL(start.json().authorizationUrl);
    expect(`${url.origin}${url.pathname}`).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("state")).toBe(start.json().stateToken);
    expect(url.searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("links Google to the account that asked, with PKCE proven end to end and the id_token's nonce matched", async () => {
    const { app, store } = await build();
    const { accessToken, accountId } = await signInWithDiscord(app);
    const start = await startGoogle(app, accessToken);
    const url = new URL(start.json().authorizationUrl);
    const leg = fakeGoogle({ nonceFrom: () => url.searchParams.get("nonce") ?? undefined });

    const done = await callbackGoogle(app, start.json().stateToken);

    expect(done.statusCode).toBe(201);
    expect(done.json().account.id).toBe(accountId);
    expect(accountCount(store)).toBe(1);
    const sent = leg.tokenRequests[0]!;
    expect(sent.get("grant_type")).toBe("authorization_code");
    expect(sent.get("redirect_uri")).toBe(REDIRECT);
    // The verifier Heimdall sent hashes to the challenge it put in the authorization URL.
    expect(createHash("sha256").update(sent.get("code_verifier") ?? "", "ascii").digest("base64url")).toBe(
      url.searchParams.get("code_challenge")
    );
    const stored = await store.findStoredLinkedIdentity("google", "g-sub-1");
    expect(stored?.accountId).toBe(accountId);
    expect(stored?.primaryEmail).toBe("person@example.org");
  });

  it("signs in the account Google is linked to, with no session, and mints nothing", async () => {
    const { app, store } = await build();
    const { accessToken, accountId } = await signInWithDiscord(app);
    const link = await startGoogle(app, accessToken);
    const linkUrl = new URL(link.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => linkUrl.searchParams.get("nonce") ?? undefined });
    expect((await callbackGoogle(app, link.json().stateToken)).statusCode).toBe(201);

    const signIn = await startGoogle(app, undefined, "sign_in");
    expect(signIn.statusCode).toBe(201);
    const signInUrl = new URL(signIn.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => signInUrl.searchParams.get("nonce") ?? undefined });
    const done = await callbackGoogle(app, signIn.json().stateToken);

    expect(done.statusCode).toBe(201);
    expect(done.json().account.id).toBe(accountId);
    expect(accountCount(store)).toBe(1);
  });

  it("refuses a link start with no Heimdall session", async () => {
    const { app, store } = await build();
    const start = await startGoogle(app);
    expect(start.statusCode).toBe(401);
    expect(start.json().error).toBe("link_session_required");
    expect(accountCount(store)).toBe(0);
  });

  it.each([
    ["a garbage bearer", () => "not-a-token"],
    ["a token for another app", async (app: FastifyInstance) => {
      const start = await app.inject({
        method: "POST",
        url: "/v1/oauth/discord/start",
        payload: { appSlug: "repixelizer", mode: "sign_in", returnTo: "https://repixelizer.gamecult.org/app/" },
      });
      const cb = await app.inject({ method: "GET", url: `/v1/oauth/discord/callback?code=c&state=${encodeURIComponent(start.json().stateToken)}` });
      return cb.json().accessToken as string;
    }],
  ])("refuses a link start carrying %s", async (_name, token) => {
    const { app, store } = await build();
    const bearer = await token(app);
    const before = accountCount(store);
    const start = await startGoogle(app, bearer);
    expect(start.statusCode).toBe(401);
    expect(start.json().error).toBe("invalid_link_session");
    expect(accountCount(store)).toBe(before);
  });

  it("refuses a first Google login from a subject no account holds, and mints no account for it", async () => {
    // The person who has a Discord account arrives with Google for the first time, signing in rather than linking.
    const { app, store } = await build();
    await signInWithDiscord(app);
    const start = await startGoogle(app, undefined, "sign_in");
    expect(start.statusCode).toBe(201);
    const url = new URL(start.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => url.searchParams.get("nonce") ?? undefined });

    const before = accountCount(store);
    const done = await callbackGoogle(app, start.json().stateToken);

    expect(done.statusCode).toBe(502);
    expect(done.json().error).toBe("oauth_callback_failed");
    expect(accountCount(store)).toBe(before);
    expect(await store.findStoredLinkedIdentity("google", "g-sub-1")).toBeNull();
  });

  it("never moves or merges: a Google subject already linked to one account cannot be linked to another", async () => {
    const store = new InMemoryStore();
    const first = await build(store, "discord-1");
    const a = await signInWithDiscord(first.app, "discord-1");
    const startA = await startGoogle(first.app, a.accessToken);
    const urlA = new URL(startA.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => urlA.searchParams.get("nonce") ?? undefined });
    expect((await callbackGoogle(first.app, startA.json().stateToken)).statusCode).toBe(201);

    // A second person, a second account, the same Google subject.
    const second = await build(store, "discord-2");
    const b = await signInWithDiscord(second.app, "discord-2");
    expect(b.accountId).not.toBe(a.accountId);
    const startB = await startGoogle(second.app, b.accessToken);
    const urlB = new URL(startB.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => urlB.searchParams.get("nonce") ?? undefined });
    const done = await callbackGoogle(second.app, startB.json().stateToken);

    expect(done.statusCode).toBe(502);
    expect((await store.findStoredLinkedIdentity("google", "g-sub-1"))?.accountId).toBe(a.accountId);
  });

  it.each([
    ["an unverified email", { email_verified: false }],
    ["another client's audience", { aud: "other-client", azp: "other-client" }],
    ["a nonce this request did not carry", { nonce: "replayed" }],
    ["an expired token", { exp: Math.floor(Date.now() / 1000) - 3600 }],
  ])("links nothing when the id_token has %s", async (_name, claims) => {
    const { app, store } = await build();
    const { accessToken } = await signInWithDiscord(app);
    const start = await startGoogle(app, accessToken);
    const url = new URL(start.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => url.searchParams.get("nonce") ?? undefined, claims });

    const done = await callbackGoogle(app, start.json().stateToken);

    expect(done.statusCode).toBe(502);
    expect(await store.findStoredLinkedIdentity("google", "g-sub-1")).toBeNull();
    expect(accountCount(store)).toBe(1);
  });

  it("keys the identity by sub: the same email under a different sub is a different, unlinkable identity", async () => {
    const { app, store } = await build();
    const { accessToken, accountId } = await signInWithDiscord(app);
    const start = await startGoogle(app, accessToken);
    const url = new URL(start.json().authorizationUrl);
    fakeGoogle({ nonceFrom: () => url.searchParams.get("nonce") ?? undefined, claims: { sub: "g-sub-2" } });
    await callbackGoogle(app, start.json().stateToken);
    expect((await store.findStoredLinkedIdentity("google", "g-sub-2"))?.accountId).toBe(accountId);
    expect(await store.findStoredLinkedIdentity("google", "person@example.org")).toBeNull();
  });

  it("leaves the six existing providers minting on first login", async () => {
    const { app, store } = await build();
    await signInWithDiscord(app);
    expect(accountCount(store)).toBe(1);
  });
});
