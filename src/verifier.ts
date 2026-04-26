import { createPublicKey, type KeyObject } from "node:crypto";
import { appSlugs, providers, type AccessClaimPayload, type AppSlug, type LinkedIdentityInput, type Provider } from "./contracts.js";
import { type PublicSigningJwk, verifyJwt } from "./signing.js";

export interface HeimdallVerifierOptions {
  issuer: string;
  appSlug: AppSlug;
  jwks: {
    keys: PublicSigningJwk[];
  };
  allowedClockSkewSeconds?: number;
}

export type VerifyAccessTokenResult =
  | {
      valid: true;
      header: Record<string, unknown>;
      claimSet: AccessClaimPayload;
    }
  | {
      valid: false;
      error: string;
    };

function isLinkedIdentity(value: unknown): value is LinkedIdentityInput {
  if (!value || typeof value !== "object") {
    return false;
  }

  const record = value as Record<string, unknown>;
  if (
    typeof record.provider !== "string" ||
    !providers.includes(record.provider as Provider) ||
    typeof record.providerUserId !== "string"
  ) {
    return false;
  }

  if (record.username !== undefined && typeof record.username !== "string") {
    return false;
  }

  if (record.displayName !== undefined && typeof record.displayName !== "string") {
    return false;
  }

  return true;
}

function parseAccessClaimPayload(payload: Record<string, unknown>): AccessClaimPayload | null {
  if (
    payload.typ !== "heimdall_access" ||
    typeof payload.iss !== "string" ||
    typeof payload.aud !== "string" ||
    !appSlugs.includes(payload.aud as AppSlug) ||
    typeof payload.sub !== "string" ||
    typeof payload.sid !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.nbf !== "number" ||
    typeof payload.exp !== "number" ||
    typeof payload.account_id !== "string" ||
    typeof payload.access_revision !== "number" ||
    !payload.app ||
    typeof payload.app !== "object" ||
    typeof (payload.app as Record<string, unknown>).slug !== "string" ||
    !appSlugs.includes((payload.app as Record<string, unknown>).slug as AppSlug) ||
    typeof (payload.app as Record<string, unknown>).profile_version !== "string" ||
    !Array.isArray(payload.facts) ||
    !payload.facts.every((fact) => typeof fact === "string") ||
    !Array.isArray(payload.capabilities) ||
    !payload.capabilities.every((capability) => typeof capability === "string") ||
    !Array.isArray(payload.identities) ||
    !payload.identities.every(isLinkedIdentity)
  ) {
    return null;
  }

  if (payload.display_name !== undefined && typeof payload.display_name !== "string") {
    return null;
  }

  return payload as unknown as AccessClaimPayload;
}

function buildKeyIndex(jwks: { keys: PublicSigningJwk[] }): Map<string, KeyObject> {
  return new Map(
    jwks.keys.map((jwk) => [
      jwk.kid,
      createPublicKey({
        key: jwk,
        format: "jwk",
      }),
    ])
  );
}

export function createHeimdallAccessTokenVerifier(options: HeimdallVerifierOptions): {
  verify(token: string, now?: Date): VerifyAccessTokenResult;
} {
  const keyIndex = buildKeyIndex(options.jwks);
  const allowedClockSkewSeconds = Math.max(0, Math.trunc(options.allowedClockSkewSeconds ?? 30));

  return {
    verify(token: string, now = new Date()): VerifyAccessTokenResult {
      const [encodedHeader] = token.split(".");
      if (!encodedHeader) {
        return { valid: false, error: "Malformed JWT." };
      }

      let header: Record<string, unknown>;
      try {
        header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as Record<string, unknown>;
      } catch {
        return { valid: false, error: "Malformed JWT header." };
      }

      if (header.alg !== "EdDSA" || typeof header.kid !== "string") {
        return { valid: false, error: "Unsupported JWT signing header." };
      }

      const publicKey = keyIndex.get(header.kid);
      if (!publicKey) {
        return { valid: false, error: `Unknown signing key id '${header.kid}'.` };
      }

      const verified = verifyJwt(token, publicKey);
      if (!verified.valid) {
        return verified;
      }

      const claimSet = parseAccessClaimPayload(verified.payload);
      if (!claimSet) {
        return { valid: false, error: "JWT payload is not a valid Heimdall access claim." };
      }

      if (claimSet.iss !== options.issuer) {
        return { valid: false, error: "JWT issuer does not match the configured Heimdall issuer." };
      }

      if (claimSet.aud !== options.appSlug || claimSet.app.slug !== options.appSlug) {
        return { valid: false, error: "JWT audience does not match the expected app slug." };
      }

      const nowEpochSeconds = Math.floor(now.getTime() / 1000);
      if (claimSet.nbf > nowEpochSeconds + allowedClockSkewSeconds) {
        return { valid: false, error: "JWT is not valid yet." };
      }

      if (claimSet.exp <= nowEpochSeconds - allowedClockSkewSeconds) {
        return { valid: false, error: "JWT has expired." };
      }

      return {
        valid: true,
        header: verified.header,
        claimSet,
      };
    },
  };
}
