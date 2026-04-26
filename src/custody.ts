import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { type HeimdallConfig } from "./config.js";

const TOKEN_ENVELOPE_PREFIX = "gc_tok_v1";
const TOKEN_KEY_BYTES = 32;
const TOKEN_IV_BYTES = 12;

export interface TokenCustody {
  source: "configured" | "ephemeral_dev";
  encrypt(plaintext: string): string;
  decrypt(ciphertext: string): string;
}

function decodeConfiguredKey(base64Value: string): Buffer {
  const normalized = base64Value.trim();
  if (!normalized) {
    throw new Error("GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64 is set but empty.");
  }

  const key = Buffer.from(normalized, "base64");
  if (key.byteLength !== TOKEN_KEY_BYTES) {
    throw new Error(
      `GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64 must decode to exactly ${TOKEN_KEY_BYTES} bytes for AES-256-GCM.`
    );
  }

  return key;
}

function decodeEnvelope(ciphertext: string): { iv: Buffer; sealed: Buffer; authTag: Buffer } {
  const [prefix, payload] = ciphertext.split(":", 2);
  if (prefix !== TOKEN_ENVELOPE_PREFIX || !payload) {
    throw new Error("Managed provider credential is not in a supported encrypted format.");
  }

  const [ivEncoded, sealedEncoded, authTagEncoded] = payload.split(".");
  if (!ivEncoded || !sealedEncoded || !authTagEncoded) {
    throw new Error("Managed provider credential envelope is malformed.");
  }

  return {
    iv: Buffer.from(ivEncoded, "base64url"),
    sealed: Buffer.from(sealedEncoded, "base64url"),
    authTag: Buffer.from(authTagEncoded, "base64url"),
  };
}

export function createTokenCustody(config: HeimdallConfig): TokenCustody {
  const key = config.tokenEncryptionKeyBase64
    ? decodeConfiguredKey(config.tokenEncryptionKeyBase64)
    : (() => {
        if (config.storage.backend === "postgres") {
          throw new Error(
            "GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64 is required when Heimdall uses persistent postgres storage."
          );
        }

        return randomBytes(TOKEN_KEY_BYTES);
      })();
  const source: TokenCustody["source"] = config.tokenEncryptionKeyBase64 ? "configured" : "ephemeral_dev";

  return {
    source,
    encrypt(plaintext: string): string {
      const iv = randomBytes(TOKEN_IV_BYTES);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const sealed = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      const authTag = cipher.getAuthTag();

      return `${TOKEN_ENVELOPE_PREFIX}:${iv.toString("base64url")}.${sealed.toString("base64url")}.${authTag.toString("base64url")}`;
    },
    decrypt(ciphertext: string): string {
      const envelope = decodeEnvelope(ciphertext);
      const decipher = createDecipheriv("aes-256-gcm", key, envelope.iv);
      decipher.setAuthTag(envelope.authTag);
      const plaintext = Buffer.concat([decipher.update(envelope.sealed), decipher.final()]);
      return plaintext.toString("utf8");
    },
  };
}
