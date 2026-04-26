import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { type HeimdallConfig } from "./config.js";

type Jwk = {
  crv?: string;
  kty?: string;
  x?: string;
  [key: string]: unknown;
};

export interface RuntimeKeyMaterial {
  alg: "EdDSA";
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicJwk: Jwk & { alg: "EdDSA"; kid: string; use: "sig" };
}

function encodeBase64Url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64url");
}

function decodeBase64Url(input: string): string {
  return Buffer.from(input, "base64url").toString("utf8");
}

function buildKeyId(publicJwk: Jwk, explicitKeyId?: string): string {
  if (explicitKeyId) {
    return explicitKeyId;
  }

  const thumbprint = createHash("sha256")
    .update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x }))
    .digest("hex");
  return `ed25519-${thumbprint.slice(0, 12)}`;
}

export function createRuntimeKeyMaterial(config: HeimdallConfig): RuntimeKeyMaterial {
  const privateKey = config.signingPrivateKeyPem
    ? createPrivateKey(config.signingPrivateKeyPem)
    : generateKeyPairSync("ed25519").privateKey;
  const publicKey = createPublicKey(privateKey);
  const exportedJwk = publicKey.export({ format: "jwk" }) as Jwk;
  const kid = buildKeyId(exportedJwk, config.signingKeyId);

  return {
    alg: "EdDSA",
    kid,
    privateKey,
    publicKey,
    publicJwk: {
      ...exportedJwk,
      alg: "EdDSA",
      kid,
      use: "sig",
    },
  };
}

export function signJwt(payload: Record<string, unknown>, keys: RuntimeKeyMaterial): string {
  const header = {
    alg: keys.alg,
    kid: keys.kid,
    typ: "JWT",
  };

  const encodedHeader = encodeBase64Url(JSON.stringify(header));
  const encodedPayload = encodeBase64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), keys.privateKey);

  return `${signingInput}.${encodeBase64Url(signature)}`;
}

export function decodeJwt(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const [encodedHeader, encodedPayload] = token.split(".");
  if (!encodedHeader || !encodedPayload) {
    throw new Error("Malformed JWT.");
  }

  return {
    header: JSON.parse(decodeBase64Url(encodedHeader)) as Record<string, unknown>,
    payload: JSON.parse(decodeBase64Url(encodedPayload)) as Record<string, unknown>,
  };
}

export function verifyJwt(
  token: string,
  publicKey: KeyObject
): { valid: true; header: Record<string, unknown>; payload: Record<string, unknown> } | {
  valid: false;
  error: string;
} {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    return { valid: false, error: "Malformed JWT." };
  }

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = Buffer.from(encodedSignature, "base64url");
  const valid = verify(null, Buffer.from(signingInput, "utf8"), publicKey, signature);

  if (!valid) {
    return { valid: false, error: "Invalid JWT signature." };
  }

  const { header, payload } = decodeJwt(token);
  return { valid: true, header, payload };
}
