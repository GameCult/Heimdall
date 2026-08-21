import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { decode, encode } from "@msgpack/msgpack";

export interface HeimdallPrivateEnvelope {
  schema: "heimdall.private_command_envelope.v1";
  appSlug: string;
  operation: string;
  contentSchema: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  idempotencyKey: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  signature: string;
}

function keyFor(secret: string): Buffer {
  return createHash("sha256").update("heimdall.private-command.v1\0").update(secret).digest();
}

function authenticatedFields(envelope: Omit<HeimdallPrivateEnvelope, "signature">): string {
  return [
    envelope.schema,
    envelope.appSlug,
    envelope.operation,
    envelope.contentSchema,
    envelope.issuedAt,
    envelope.expiresAt,
    envelope.nonce,
    envelope.idempotencyKey,
    envelope.iv,
    envelope.ciphertext,
    envelope.authTag,
  ].join("\n");
}

function aad(envelope: Pick<HeimdallPrivateEnvelope, "schema" | "appSlug" | "operation" | "contentSchema" | "issuedAt" | "expiresAt" | "nonce" | "idempotencyKey">): Buffer {
  return Buffer.from([
    envelope.schema,
    envelope.appSlug,
    envelope.operation,
    envelope.contentSchema,
    envelope.issuedAt,
    envelope.expiresAt,
    envelope.nonce,
    envelope.idempotencyKey,
  ].join("\n"), "utf8");
}

export function sealPrivateEnvelope(options: {
  appSlug: string;
  operation: string;
  contentSchema: string;
  idempotencyKey: string;
  secret: string;
  payload: Record<string, unknown>;
  issuedAt?: string;
  expiresAt?: string;
  nonce?: string;
}): HeimdallPrivateEnvelope {
  const issuedAt = options.issuedAt ?? new Date().toISOString();
  const expiresAt = options.expiresAt ?? new Date(Date.parse(issuedAt) + 30_000).toISOString();
  const nonce = options.nonce ?? randomBytes(16).toString("base64url");
  const iv = randomBytes(12);
  const partial = {
    schema: "heimdall.private_command_envelope.v1" as const,
    appSlug: options.appSlug,
    operation: options.operation,
    contentSchema: options.contentSchema,
    issuedAt,
    expiresAt,
    nonce,
    idempotencyKey: options.idempotencyKey,
    iv: iv.toString("base64url"),
    ciphertext: "",
    authTag: "",
  };
  const cipher = createCipheriv("aes-256-gcm", keyFor(options.secret), iv);
  cipher.setAAD(aad(partial));
  const ciphertext = Buffer.concat([
    cipher.update(encode(options.payload)),
    cipher.final(),
  ]);
  partial.ciphertext = ciphertext.toString("base64url");
  partial.authTag = cipher.getAuthTag().toString("base64url");
  const signature = createHmac("sha256", options.secret).update(authenticatedFields(partial)).digest("base64url");
  return { ...partial, signature };
}

export function openPrivateEnvelope(
  envelope: HeimdallPrivateEnvelope,
  secret: string,
  now = Date.now(),
): Record<string, unknown> {
  if (envelope.schema !== "heimdall.private_command_envelope.v1") throw new Error("Unsupported private command envelope.");
  const issuedAt = Date.parse(envelope.issuedAt);
  const expiresAt = Date.parse(envelope.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    throw new Error("Private command has invalid time bounds.");
  }
  if (issuedAt > now + 30_000 || expiresAt <= now || expiresAt - issuedAt > 120_000) {
    throw new Error("Private command is expired or outside the accepted clock window.");
  }
  const { signature, ...unsigned } = envelope;
  const expected = createHmac("sha256", secret).update(authenticatedFields(unsigned)).digest();
  const provided = Buffer.from(signature, "base64url");
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    throw new Error("Private command signature is invalid.");
  }
  const decipher = createDecipheriv("aes-256-gcm", keyFor(secret), Buffer.from(envelope.iv, "base64url"));
  decipher.setAAD(aad(envelope));
  decipher.setAuthTag(Buffer.from(envelope.authTag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]);
  const payload = decode(plaintext) as unknown;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Private command payload is not an object.");
  return payload as Record<string, unknown>;
}
