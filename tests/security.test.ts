import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { type HeimdallConfig } from "../src/config.js";
import { createTokenCustody } from "../src/custody.js";
import { createRuntimeKeyMaterial } from "../src/signing.js";

function createTestConfig(overrides: Partial<HeimdallConfig> = {}): HeimdallConfig {
  return {
    serviceName: "heimdall",
    host: "127.0.0.1",
    port: 4100,
    publicBaseUrl: "https://heimdall.gamecult.org",
    issuer: "https://heimdall.gamecult.org",
    sessionTtlSeconds: 3600,
    stateTtlSeconds: 600,
    completionTtlSeconds: 300,
    bootstrapSigningPrivateKeyOnMissing: false,
    appSharedSecrets: {},
    storage: {
      backend: "memory",
      applySchemaOnStartup: true,
    },
    providers: {
      discord: {},
      patreon: {},
      github: {},
      twitch: {},
      youtube: {},
    },
    ...overrides,
  };
}

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    rmSync(tempDirs.pop() ?? "", { force: true, recursive: true });
  }
});

describe("Heimdall security helpers", () => {
  it("round-trips provider tokens through AES-GCM custody", () => {
    const custody = createTokenCustody({
      ...createTestConfig(),
      tokenEncryptionKeyBase64: Buffer.alloc(32, 23).toString("base64"),
    });

    const encrypted = custody.encrypt("discord-access-token");
    expect(encrypted).toMatch(/^gc_tok_v1:/);
    expect(encrypted).not.toBe("discord-access-token");
    expect(custody.decrypt(encrypted)).toBe("discord-access-token");
  });

  it("refuses persistent provider-token storage without a stable encryption key", () => {
    expect(() =>
      createTokenCustody(
        createTestConfig({
          storage: {
            backend: "postgres",
            applySchemaOnStartup: true,
            databaseUrl: "postgres://127.0.0.1/heimdall",
          },
        })
      )
    ).toThrow(/GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64/);
  });

  it("bootstraps and then reuses a file-backed signing key", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "heimdall-signing-"));
    tempDirs.push(tempDir);
    const signingKeyPath = join(tempDir, "keys", "heimdall-signing-key.pem");

    const first = createRuntimeKeyMaterial(
      createTestConfig({
        signingPrivateKeyPath: signingKeyPath,
        bootstrapSigningPrivateKeyOnMissing: true,
      })
    );
    const second = createRuntimeKeyMaterial(
      createTestConfig({
        signingPrivateKeyPath: signingKeyPath,
        bootstrapSigningPrivateKeyOnMissing: false,
      })
    );

    expect(first.source).toBe("bootstrapped_file");
    expect(second.source).toBe("configured_file");
    expect(first.kid).toBe(second.kid);
    expect(existsSync(signingKeyPath)).toBe(true);
    expect(readFileSync(signingKeyPath, "utf8")).toContain("BEGIN PRIVATE KEY");
  });
});
