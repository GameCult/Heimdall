import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig, readSecretInput } from "../src/config.js";
import { appSlugs, providers } from "../src/contracts.js";
import { providerCatalog, providerExpectedEnv } from "../src/providers.js";

// Secret inputs arrive as files named by `NAME_FILE` (systemd credentials under
// Idunn). These tests pin the reader's rules and that every secret Heimdall
// consumes goes through it.

const tempDirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "heimdall-secret-input-"));
  tempDirs.push(dir);
  return dir;
}

function secretFile(contents: string, name = "secret"): string {
  const path = join(tempDir(), name);
  writeFileSync(path, contents);
  return path;
}

function thrownMessage(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error("expected the action to throw");
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("readSecretInput", () => {
  it("reads the value from the file named by NAME_FILE and strips exactly one trailing newline", () => {
    const cases: Array<[string, string]> = [
      ["from-the-file\n", "from-the-file"],
      ["from-the-file\r\n", "from-the-file"],
      ["two-newlines\n\n", "two-newlines\n"],
      ["line-one\nline-two\n", "line-one\nline-two"],
      ["  inner spaces kept  \n", "  inner spaces kept  "],
      ["no-newline", "no-newline"],
    ];

    for (const [contents, expected] of cases) {
      const env = { EXAMPLE_SECRET_FILE: secretFile(contents) };
      expect(readSecretInput(env, "EXAMPLE_SECRET")).toBe(expected);
    }
  });

  it("returns undefined when neither form is set", () => {
    expect(readSecretInput({}, "EXAMPLE_SECRET")).toBeUndefined();
  });

  it("falls back to the plaintext name only while NAME_FILE is absent (legacy shim)", () => {
    expect(readSecretInput({ EXAMPLE_SECRET: "legacy-plaintext" }, "EXAMPLE_SECRET")).toBe("legacy-plaintext");
  });

  it("refuses both forms at once, and the refusal carries neither value", () => {
    const fileCanary = "canary-file-7c1e0f";
    const plainCanary = "canary-plain-93ab2d";
    const env = {
      EXAMPLE_SECRET: plainCanary,
      EXAMPLE_SECRET_FILE: secretFile(fileCanary),
    };

    const message = thrownMessage(() => readSecretInput(env, "EXAMPLE_SECRET"));
    expect(message).toContain("EXAMPLE_SECRET_FILE");
    expect(message).toMatch(/both set/);
    expect(message).not.toContain(fileCanary);
    expect(message).not.toContain(plainCanary);
    expect(message).not.toContain("canary");
  });

  it("refuses both forms even when the plaintext form is empty", () => {
    const env = { EXAMPLE_SECRET: "", EXAMPLE_SECRET_FILE: secretFile("value") };
    expect(() => readSecretInput(env, "EXAMPLE_SECRET")).toThrow(/both set/);
  });

  it("refuses an unreadable path naming only the variable and the code, not the path", () => {
    // A secret bound into a _FILE slot by mistake must not be printed back.
    const canaryPath = join(tempDir(), "canary-path-3b7e1d");
    const message = thrownMessage(() => readSecretInput({ EXAMPLE_SECRET_FILE: canaryPath }, "EXAMPLE_SECRET"));
    expect(message).toContain("EXAMPLE_SECRET_FILE");
    expect(message).toContain("ENOENT");
    expect(message).not.toContain("canary");
  });

  it("refuses a _FILE value that is not an absolute path, without echoing it", () => {
    for (const value of ["postgres://heimdall:canary-pw-6f02aa@db/heimdall", "relative/canary-rel-0c9d", ""]) {
      const message = thrownMessage(() => readSecretInput({ EXAMPLE_SECRET_FILE: value }, "EXAMPLE_SECRET"));
      expect(message).toBe("EXAMPLE_SECRET_FILE is not an absolute path.");
    }
  });

  it("does not treat an empty _FILE as unset, even with no plaintext form", () => {
    expect(() => readSecretInput({ EXAMPLE_SECRET_FILE: "" }, "EXAMPLE_SECRET")).toThrow(/EXAMPLE_SECRET_FILE/);
  });

  it("refuses an unreadable file, and carries no byte of what sits in or beside it", () => {
    const dir = tempDir();
    const canary = "canary-sibling-5d2f88";
    writeFileSync(join(dir, "sibling"), canary);
    const notAFile = join(dir, "credential");
    mkdirSync(notAFile);
    writeFileSync(join(notAFile, "inside"), canary);

    const message = thrownMessage(() => readSecretInput({ EXAMPLE_SECRET_FILE: notAFile }, "EXAMPLE_SECRET"));
    expect(message).toBe("EXAMPLE_SECRET_FILE could not be read (EISDIR).");
  });

  it("refuses a blank secret file rather than treating it as unset", () => {
    for (const contents of ["", "\n", " \n", "\t\r\n", "   "]) {
      const env = { EXAMPLE_SECRET_FILE: secretFile(contents) };
      expect(thrownMessage(() => readSecretInput(env, "EXAMPLE_SECRET"))).toBe("EXAMPLE_SECRET_FILE is empty.");
    }
  });

  it("refuses a blank plaintext secret too", () => {
    for (const value of ["", "  ", "\n"]) {
      expect(thrownMessage(() => readSecretInput({ EXAMPLE_SECRET: value }, "EXAMPLE_SECRET"))).toBe(
        "EXAMPLE_SECRET is empty."
      );
    }
  });

  it("keeps a value whose only whitespace is inside or around real content", () => {
    const env = { EXAMPLE_SECRET_FILE: secretFile(" padded value \n") };
    expect(readSecretInput(env, "EXAMPLE_SECRET")).toBe(" padded value ");
  });
});

describe("loadConfig secret inputs", () => {
  it("configures every secret Heimdall consumes from its _FILE twin alone", () => {
    const env: Record<string, string> = {};
    const expected = new Map<string, string>();
    function bind(name: string): string {
      const value = `value-of-${name.toLowerCase()}`;
      env[`${name}_FILE`] = secretFile(`${value}\n`, name);
      expected.set(name, value);
      return value;
    }

    const databaseUrl = bind("GC_ACCESS_DATABASE_URL");
    const tokenKey = bind("GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64");
    const patronSecret = bind("GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET");
    const providerSecrets = Object.fromEntries(
      providers.map((provider) => [provider, bind(`GC_ACCESS_PROVIDER_${provider.toUpperCase()}_CLIENT_SECRET`)])
    );
    const appSecrets = Object.fromEntries(
      appSlugs.map((slug) => [slug, bind(`GC_ACCESS_APP_${slug.toUpperCase()}_SHARED_SECRET`)])
    );

    const config = loadConfig(env, []);

    expect(config.storage.databaseUrl).toBe(databaseUrl);
    expect(config.tokenEncryptionKeyBase64).toBe(tokenKey);
    expect(config.bifrostPatronSupportSecret).toBe(patronSecret);
    for (const provider of providers) {
      expect(config.providers[provider].clientSecret).toBe(providerSecrets[provider]);
    }
    expect(config.appSharedSecrets).toEqual(appSecrets);
  });

  it("selects postgres storage from a database URL given only as a file", () => {
    const config = loadConfig(
      { GC_ACCESS_DATABASE_URL_FILE: secretFile("postgres://heimdall@localhost/heimdall\n") },
      []
    );
    expect(config.storage.backend).toBe("postgres");
  });

  it("keeps memory storage when no database URL is bound, and postgres when it is asked for", () => {
    expect(loadConfig({}, []).storage.backend).toBe("memory");
    expect(loadConfig({ GC_ACCESS_STORAGE_BACKEND: "memory" }, []).storage.backend).toBe("memory");
    expect(loadConfig({ GC_ACCESS_STORAGE_BACKEND: "postgres" }, []).storage.backend).toBe("postgres");
  });

  it("refuses to start when the database URL file is absent", () => {
    const missing = join(tempDir(), "database-url");
    const message = thrownMessage(() => loadConfig({ GC_ACCESS_DATABASE_URL_FILE: missing }, []));
    expect(message).toBe("GC_ACCESS_DATABASE_URL_FILE could not be read (ENOENT).");
  });

  it("refuses to start on a blank database URL file instead of falling back to memory storage", () => {
    for (const contents of ["", "\n", " \n"]) {
      const env = { GC_ACCESS_DATABASE_URL_FILE: secretFile(contents) };
      expect(() => loadConfig(env, [])).toThrow("GC_ACCESS_DATABASE_URL_FILE is empty.");
    }
  });

  // One per call site: a site that reads the plaintext name itself before the
  // reader would let the plaintext win silently instead of refusing.
  const bothSetSites: Array<[string, string]> = [
    ["token encryption key", "GC_ACCESS_TOKEN_ENCRYPTION_KEY_BASE64"],
    ["provider client secret", "GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET"],
    ["app shared secret", "GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET"],
    ["database URL", "GC_ACCESS_DATABASE_URL"],
    ["patron support secret", "GC_ACCESS_BIFROST_PATRON_SUPPORT_SECRET"],
  ];
  for (const [site, name] of bothSetSites) {
    it(`refuses the ${site} bound both ways at startup`, () => {
      const env = { [name]: "plain", [`${name}_FILE`]: secretFile("file") };
      expect(() => loadConfig(env, [])).toThrow(`${name} and ${name}_FILE are both set`);
    });
  }

  it("publishes provider secret variable names that actually configure the secret", () => {
    for (const provider of providers) {
      const secretVariable = providerCatalog[provider].clientSecretEnv;
      expect(providerExpectedEnv(provider)).toContain(secretVariable);

      const config = loadConfig({ [secretVariable]: secretFile(`${provider}-secret\n`) }, []);
      expect(config.providers[provider].clientSecret).toBe(`${provider}-secret`);
    }
  });
});
