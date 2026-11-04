import { createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  deriveOidcSecrets,
  GoogleIdTokenError,
  resetGoogleJwksCache,
  verifyGoogleIdToken,
  type GoogleIdTokenFailure,
} from "../src/google-oidc.js";

const CLIENT_ID = "google-client.apps.googleusercontent.com";
const NONCE = "the-nonce";
const NOW_MS = Date.parse("2026-11-04T12:00:00.000Z");
const NOW_S = Math.floor(NOW_MS / 1000);

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const otherRsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const originalFetch = globalThis.fetch;
let jwksFetches = 0;

function jwks(kidKeys: Record<string, KeyObject>) {
  return {
    keys: Object.entries(kidKeys).map(([kid, key]) => ({
      ...(key.export({ format: "jwk" }) as Record<string, string>),
      kid,
      alg: "RS256",
      use: "sig",
    })),
  };
}

function serveJwks(kidKeys: Record<string, KeyObject>) {
  globalThis.fetch = (async (input: string | URL) => {
    expect(String(input)).toBe("https://www.googleapis.com/oauth2/v3/certs");
    jwksFetches += 1;
    return new Response(JSON.stringify(jwks(kidKeys)), { status: 200, headers: { "cache-control": "public, max-age=3600" } });
  }) as typeof fetch;
}

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function idToken(
  claims: Record<string, unknown> = {},
  options: { kid?: string; alg?: string; key?: KeyObject; omit?: string[] } = {}
): string {
  const payload: Record<string, unknown> = {
    iss: "https://accounts.google.com",
    aud: CLIENT_ID,
    azp: CLIENT_ID,
    sub: "110169484474386276334",
    email: "meta@example.org",
    email_verified: true,
    name: "Meta",
    picture: "https://lh3.googleusercontent.com/a/x",
    nonce: NONCE,
    iat: NOW_S - 10,
    exp: NOW_S + 3000,
    ...claims,
  };
  for (const key of options.omit ?? []) delete payload[key];
  const header = b64({ alg: options.alg ?? "RS256", typ: "JWT", kid: options.kid ?? "k1" });
  const body = `${header}.${b64(payload)}`;
  const signature = createSign("RSA-SHA256").update(body).sign(options.key ?? rsa.privateKey).toString("base64url");
  return `${body}.${signature}`;
}

async function refusal(token: string, nonce = NONCE): Promise<GoogleIdTokenFailure> {
  try {
    await verifyGoogleIdToken(token, { clientId: CLIENT_ID, nonce }, NOW_MS);
  } catch (error) {
    expect(error).toBeInstanceOf(GoogleIdTokenError);
    return (error as GoogleIdTokenError).code;
  }
  throw new Error("the token was accepted");
}

beforeEach(() => {
  resetGoogleJwksCache();
  jwksFetches = 0;
  serveJwks({ k1: rsa.publicKey });
});
afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("verifyGoogleIdToken", () => {
  it("accepts a good token and returns the subject as the identity", async () => {
    const claims = await verifyGoogleIdToken(idToken(), { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS);
    expect(claims).toEqual({
      sub: "110169484474386276334",
      email: "meta@example.org",
      name: "Meta",
      picture: "https://lh3.googleusercontent.com/a/x",
    });
  });

  it("accepts the bare-host issuer Google also uses", async () => {
    await expect(verifyGoogleIdToken(idToken({ iss: "accounts.google.com" }), { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS)).resolves.toMatchObject({
      sub: "110169484474386276334",
    });
  });

  it.each<[string, () => string, GoogleIdTokenFailure]>([
    ["a foreign issuer", () => idToken({ iss: "https://evil.example" }), "bad_issuer"],
    ["an issuer that merely contains Google's", () => idToken({ iss: "https://accounts.google.com.evil.example" }), "bad_issuer"],
    ["another client's audience", () => idToken({ aud: "other-client", azp: "other-client" }), "bad_audience"],
    ["an array audience whose azp is not this client", () => idToken({ aud: [CLIENT_ID, "other"], azp: "other" }), "bad_audience"],
    ["an array audience with no azp", () => idToken({ aud: [CLIENT_ID], azp: undefined }), "bad_audience"],
    ["an expired token", () => idToken({ exp: NOW_S - 61 }), "expired"],
    ["a token with no exp", () => idToken({}, { omit: ["exp"] }), "expired"],
    ["a token issued in the future", () => idToken({ iat: NOW_S + 3600 }), "not_yet_valid"],
    ["a token with no iat", () => idToken({}, { omit: ["iat"] }), "not_yet_valid"],
    ["a nonce this request did not carry", () => idToken({ nonce: "someone-elses" }), "bad_nonce"],
    ["a token with no nonce", () => idToken({}, { omit: ["nonce"] }), "bad_nonce"],
    ["no subject", () => idToken({}, { omit: ["sub"] }), "missing_subject"],
    ["an empty subject", () => idToken({ sub: "" }), "missing_subject"],
    ["no email", () => idToken({}, { omit: ["email"] }), "email_missing"],
    ["an unverified email", () => idToken({ email_verified: false }), "email_not_verified"],
    ["no email_verified claim", () => idToken({}, { omit: ["email_verified"] }), "email_not_verified"],
    ["a string email_verified other than true", () => idToken({ email_verified: "yes" }), "email_not_verified"],
    ["alg none", () => idToken({}, { alg: "none" }), "unsupported_algorithm"],
    ["alg HS256", () => idToken({}, { alg: "HS256" }), "unsupported_algorithm"],
    ["a key Google does not publish", () => idToken({}, { kid: "unknown" }), "unknown_key"],
    ["a signature by another key under Google's kid", () => idToken({}, { key: otherRsa.privateKey }), "bad_signature"],
    ["three empty parts", () => "..", "malformed"],
    ["two parts", () => "a.b", "malformed"],
  ])("refuses %s", async (_name, make, code) => {
    expect(await refusal(make())).toBe(code);
  });

  it("checks the signature before it believes any claim", async () => {
    // A forged payload with every claim right is still refused as a bad signature.
    const forged = idToken({}, { key: otherRsa.privateKey });
    expect(await refusal(forged)).toBe("bad_signature");
  });

  it("takes email_verified string 'true' as Google's older tokens spell it", async () => {
    await expect(verifyGoogleIdToken(idToken({ email_verified: "true" }), { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS)).resolves.toMatchObject({
      email: "meta@example.org",
    });
  });

  it("caches Google's keys and refetches once for a rotated kid, not for every bad token", async () => {
    await verifyGoogleIdToken(idToken(), { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS);
    await verifyGoogleIdToken(idToken(), { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS + 1000);
    expect(jwksFetches).toBe(1);
    serveJwks({ k1: rsa.publicKey, k2: otherRsa.publicKey });
    const rotated = idToken({}, { kid: "k2", key: otherRsa.privateKey });
    // Inside the refetch floor the unknown kid is refused without a fetch.
    await expect(verifyGoogleIdToken(rotated, { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS + 2000)).rejects.toMatchObject({ code: "unknown_key" });
    expect(jwksFetches).toBe(1);
    await expect(verifyGoogleIdToken(rotated, { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS + 120_000)).resolves.toMatchObject({ sub: "110169484474386276334" });
    expect(jwksFetches).toBe(2);
  });

  it("refuses with jwks_unavailable when Google's key endpoint fails", async () => {
    resetGoogleJwksCache();
    globalThis.fetch = (async () => new Response("down", { status: 503 })) as typeof fetch;
    expect(await refusal(idToken())).toBe("jwks_unavailable");
  });

  it("never quotes the token in its refusal", async () => {
    const token = idToken({ email: "secret-person@example.org", nonce: "wrong" });
    try {
      await verifyGoogleIdToken(token, { clientId: CLIENT_ID, nonce: NONCE }, NOW_MS);
    } catch (error) {
      expect(String((error as Error).message)).not.toContain("secret-person");
      expect(String((error as Error).message)).not.toContain(token.slice(0, 20));
    }
  });
});

describe("deriveOidcSecrets", () => {
  const key = generateKeyPairSync("ed25519").privateKey;
  const otherKey = generateKeyPairSync("ed25519").privateKey;

  it("is the same pair for the same state and Heimdall key, so nothing is stored between start and callback", () => {
    expect(deriveOidcSecrets("jti-1", key)).toEqual(deriveOidcSecrets("jti-1", key));
  });

  it("differs per state, per Heimdall key, and between verifier and nonce", () => {
    const a = deriveOidcSecrets("jti-1", key);
    expect(deriveOidcSecrets("jti-2", key).codeVerifier).not.toBe(a.codeVerifier);
    expect(deriveOidcSecrets("jti-2", key).nonce).not.toBe(a.nonce);
    expect(deriveOidcSecrets("jti-1", otherKey).codeVerifier).not.toBe(a.codeVerifier);
    expect(a.codeVerifier).not.toBe(a.nonce);
  });

  it("yields an RFC 7636 verifier (43-128 unreserved characters) and its S256 challenge", () => {
    const { codeVerifier, codeChallenge } = deriveOidcSecrets("jti-1", key);
    expect(codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(codeChallenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(codeChallenge).not.toBe(codeVerifier);
  });
});
