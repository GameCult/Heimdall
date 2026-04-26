import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { type HeimdallConfig } from "./config.js";

type Jwk = {
  crv?: string;
  kty?: string;
  x?: string;
  [key: string]: unknown;
};

export type PublicSigningJwk = Jwk & { alg: "EdDSA"; kid: string; use: "sig" };

export interface RuntimeKeyMaterial {
  alg: "EdDSA";
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicJwk: PublicSigningJwk;
  source: "configured_pem" | "configured_file" | "bootstrapped_file" | "ephemeral_dev";
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

function exportPrivateKeyPem(privateKey: KeyObject): string {
  const exported = privateKey.export({
    format: "pem",
    type: "pkcs8",
  }) as string | Buffer;
  return typeof exported === "string" ? exported : exported.toString("utf8");
}

function loadPrivateKeyFromPath(path: string): KeyObject {
  return createPrivateKey(readFileSync(path, "utf8"));
}

function createOrLoadPrivateKeyFromPath(config: HeimdallConfig): {
  privateKey: KeyObject;
  source: RuntimeKeyMaterial["source"];
} {
  const path = config.signingPrivateKeyPath;
  if (!path) {
    return {
      privateKey: generateKeyPairSync("ed25519").privateKey,
      source: "ephemeral_dev",
    };
  }

  if (existsSync(path)) {
    return {
      privateKey: loadPrivateKeyFromPath(path),
      source: "configured_file",
    };
  }

  if (!config.bootstrapSigningPrivateKeyOnMissing) {
    throw new Error(
      `Signing key file '${path}' does not exist. Set GC_ACCESS_SIGNING_PRIVATE_KEY_BOOTSTRAP=1 to create it on first boot.`
    );
  }

  const privateKey = generateKeyPairSync("ed25519").privateKey;
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(path, exportPrivateKeyPem(privateKey), {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    return {
      privateKey,
      source: "bootstrapped_file",
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw error;
    }

    return {
      privateKey: loadPrivateKeyFromPath(path),
      source: "configured_file",
    };
  }
}

export function createRuntimeKeyMaterial(config: HeimdallConfig): RuntimeKeyMaterial {
  const loaded = config.signingPrivateKeyPem
    ? {
        privateKey: createPrivateKey(config.signingPrivateKeyPem),
        source: "configured_pem" as const,
      }
    : createOrLoadPrivateKeyFromPath(config);
  const privateKey = loaded.privateKey;
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
    source: loaded.source,
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
