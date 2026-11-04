import { createHash, createPublicKey, sign, verify, type KeyObject } from "node:crypto";

/**
 * Google sign-in as OpenID Connect: the id_token is the identity, and this
 * file is the one place that decides whether to believe it. The subject
 * (`sub`) is the account key; the email is a claim about the subject, never
 * its key.
 */

export const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"] as const;
export const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

const CLOCK_LEEWAY_SECONDS = 60;
const DEFAULT_JWKS_TTL_SECONDS = 3600;
const MAX_JWKS_TTL_SECONDS = 24 * 3600;
/** An unknown `kid` refetches the key set at most this often. */
const MIN_JWKS_REFETCH_MS = 60_000;

export type GoogleIdTokenFailure =
  | "malformed"
  | "unsupported_algorithm"
  | "unknown_key"
  | "bad_signature"
  | "bad_issuer"
  | "bad_audience"
  | "expired"
  | "not_yet_valid"
  | "bad_nonce"
  | "missing_subject"
  | "email_missing"
  | "email_not_verified"
  | "jwks_unavailable";

/** A refusal that names the rule that failed and quotes nothing from the token. */
export class GoogleIdTokenError extends Error {
  readonly code: GoogleIdTokenFailure;

  constructor(code: GoogleIdTokenFailure) {
    super(`Google id_token refused (${code}).`);
    this.name = "GoogleIdTokenError";
    this.code = code;
  }
}

export interface GoogleIdentityClaims {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
  hd?: string;
}

interface Jwk {
  kid?: string;
  kty?: string;
  alg?: string;
  n?: string;
  e?: string;
}

let cachedKeys: { keys: Map<string, KeyObject>; expiresAt: number; fetchedAt: number } | null = null;

export function resetGoogleJwksCache(): void {
  cachedKeys = null;
}

async function fetchGoogleKeys(now: number): Promise<{ keys: Map<string, KeyObject>; expiresAt: number; fetchedAt: number }> {
  let response: Response;
  try {
    response = await fetch(GOOGLE_JWKS_URI, { headers: { Accept: "application/json" } });
  } catch {
    throw new GoogleIdTokenError("jwks_unavailable");
  }
  if (!response.ok) {
    throw new GoogleIdTokenError("jwks_unavailable");
  }
  let body: { keys?: Jwk[] };
  try {
    body = (await response.json()) as { keys?: Jwk[] };
  } catch {
    throw new GoogleIdTokenError("jwks_unavailable");
  }
  const keys = new Map<string, KeyObject>();
  for (const jwk of body.keys ?? []) {
    if (jwk.kty !== "RSA" || !jwk.kid || (jwk.alg !== undefined && jwk.alg !== "RS256")) continue;
    try {
      keys.set(jwk.kid, createPublicKey({ key: jwk as never, format: "jwk" }));
    } catch {
      // A key Node cannot read verifies nothing; the others stand.
    }
  }
  const maxAge = /max-age=(\d+)/.exec(response.headers.get("cache-control") ?? "");
  const ttl = Math.min(maxAge ? Number(maxAge[1]) : DEFAULT_JWKS_TTL_SECONDS, MAX_JWKS_TTL_SECONDS);
  return { keys, expiresAt: now + ttl * 1000, fetchedAt: now };
}

async function keyForKid(kid: string, now: number): Promise<KeyObject> {
  if (cachedKeys && cachedKeys.expiresAt > now) {
    const hit = cachedKeys.keys.get(kid);
    if (hit) return hit;
    // Unknown kid in a live cache: Google may have rotated. Refetch, but not on every bad token.
    if (now - cachedKeys.fetchedAt < MIN_JWKS_REFETCH_MS) {
      throw new GoogleIdTokenError("unknown_key");
    }
  }
  cachedKeys = await fetchGoogleKeys(now);
  const key = cachedKeys.keys.get(kid);
  if (!key) throw new GoogleIdTokenError("unknown_key");
  return key;
}

function decodeSegment(segment: string): Record<string, unknown> {
  try {
    const value = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as unknown;
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch {
    // fallthrough
  }
  throw new GoogleIdTokenError("malformed");
}

/**
 * Verifies a Google id_token for this client. Order is signature first, then
 * claims, so no claim of an unauthenticated token decides anything. Refuses
 * on: algorithm other than RS256, unknown key, bad signature, `iss` not
 * Google, `aud` not this client (an array `aud` also needs `azp` to be this
 * client), `exp` passed, `iat` or `nbf` in the future, `nonce` not the one
 * this authorization request carried, no `sub`, no `email`, and an email
 * Google has not verified.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  expected: { clientId: string; nonce: string },
  nowMs: number = Date.now()
): Promise<GoogleIdentityClaims> {
  const parts = idToken.split(".");
  if (parts.length !== 3 || parts.some((part) => part === "")) {
    throw new GoogleIdTokenError("malformed");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  const header = decodeSegment(encodedHeader);
  if (header.alg !== "RS256") {
    throw new GoogleIdTokenError("unsupported_algorithm");
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new GoogleIdTokenError("unknown_key");
  }

  const key = await keyForKid(header.kid, nowMs);
  const signatureValid = verify(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`, "utf8"),
    key,
    Buffer.from(encodedSignature, "base64url")
  );
  if (!signatureValid) {
    throw new GoogleIdTokenError("bad_signature");
  }

  const claims = decodeSegment(encodedPayload);
  const nowSeconds = Math.floor(nowMs / 1000);

  if (typeof claims.iss !== "string" || !(GOOGLE_ISSUERS as readonly string[]).includes(claims.iss)) {
    throw new GoogleIdTokenError("bad_issuer");
  }
  const aud = claims.aud;
  const audienceOk =
    typeof aud === "string"
      ? aud === expected.clientId
      : Array.isArray(aud) && aud.includes(expected.clientId) && claims.azp === expected.clientId;
  if (!audienceOk) {
    throw new GoogleIdTokenError("bad_audience");
  }
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_LEEWAY_SECONDS <= nowSeconds) {
    throw new GoogleIdTokenError("expired");
  }
  if (typeof claims.iat !== "number" || claims.iat - CLOCK_LEEWAY_SECONDS > nowSeconds) {
    throw new GoogleIdTokenError("not_yet_valid");
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf - CLOCK_LEEWAY_SECONDS > nowSeconds)) {
    throw new GoogleIdTokenError("not_yet_valid");
  }
  if (typeof claims.nonce !== "string" || claims.nonce !== expected.nonce) {
    throw new GoogleIdTokenError("bad_nonce");
  }
  if (typeof claims.sub !== "string" || claims.sub === "" || claims.sub.length > 255) {
    throw new GoogleIdTokenError("missing_subject");
  }
  if (typeof claims.email !== "string" || claims.email === "") {
    throw new GoogleIdTokenError("email_missing");
  }
  if (claims.email_verified !== true && claims.email_verified !== "true") {
    throw new GoogleIdTokenError("email_not_verified");
  }

  const identity: GoogleIdentityClaims = { sub: claims.sub, email: claims.email };
  if (typeof claims.name === "string" && claims.name !== "") identity.name = claims.name;
  if (typeof claims.picture === "string" && claims.picture !== "") identity.picture = claims.picture;
  if (typeof claims.hd === "string" && claims.hd !== "") identity.hd = claims.hd;
  return identity;
}

/**
 * The PKCE verifier and the nonce of one authorization request, derived from
 * the request's state `jti` and Heimdall's signing key instead of stored. The
 * state token travels through the browser and carries the `jti`, so whoever
 * can read the redirect can read the `jti`; they cannot compute an Ed25519
 * signature over it. The signature is deterministic, so start and callback
 * derive the same pair, and nothing is persisted between them.
 */
export function deriveOidcSecrets(stateJti: string, signingKey: KeyObject): {
  codeVerifier: string;
  codeChallenge: string;
  nonce: string;
} {
  const derive = (label: string): string =>
    createHash("sha256")
      .update(sign(null, Buffer.from(`heimdall:oidc:${label}:${stateJti}`, "utf8"), signingKey))
      .digest("base64url");
  const codeVerifier = derive("pkce-verifier");
  return {
    codeVerifier,
    codeChallenge: createHash("sha256").update(codeVerifier, "ascii").digest("base64url"),
    nonce: derive("nonce"),
  };
}
