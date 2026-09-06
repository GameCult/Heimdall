import path from "node:path";
import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";

describe("Idunn candidate bind", () => {
  it("falls back to HOST/PORT when Idunn is not the launcher", () => {
    const config = loadConfig({ HOST: "127.0.0.1", PORT: "4100" });

    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(4100);
  });

  it("takes the candidate socket over HOST/PORT", () => {
    // Idunn owns the listen address for a candidate incarnation, because the
    // incumbent still holds the ordinary one. HOST/PORT are not consulted.
    const config = loadConfig({
      HOST: "127.0.0.1",
      PORT: "4100",
      GAMECULT_IDUNN_CANDIDATE_BIND: "127.0.0.1:18833",
      GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
    });

    expect(config.port).toBe(18833);
    expect(config.host).toBe("127.0.0.1");
  });

  it("never advertises the candidate socket as the public base URL", () => {
    // The regression this guards: publicBaseUrl defaults to host:port, and it
    // builds the OAuth callback registered with each provider. Deriving it
    // from an ephemeral candidate port would hand providers a URL that stops
    // resolving the moment the candidate is promoted or discarded.
    const config = loadConfig({
      GAMECULT_IDUNN_CANDIDATE_BIND: "127.0.0.1:18833",
      GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
    });

    expect(config.publicBaseUrl).toBe("https://heimdall.gamecult.org");
    expect(config.publicBaseUrl).not.toContain("18833");
  });

  it("refuses to start under Idunn without an explicit public base URL", () => {
    expect(() =>
      loadConfig({ GAMECULT_IDUNN_CANDIDATE_BIND: "127.0.0.1:18833" })
    ).toThrow(/GC_ACCESS_BASE_URL is required/);
  });

  it("rejects a non-loopback or unusable candidate socket", () => {
    for (const value of ["0.0.0.0:18833", "10.77.0.1:18833", "127.0.0.1:0", "127.0.0.1", "127.0.0.1:not-a-port"]) {
      expect(() =>
        loadConfig({
          GAMECULT_IDUNN_CANDIDATE_BIND: value,
          GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
        })
      ).toThrow(/GAMECULT_IDUNN_CANDIDATE_BIND/);
    }
  });

  it("accepts a bracketed IPv6 loopback", () => {
    const config = loadConfig({
      GAMECULT_IDUNN_CANDIDATE_BIND: "[::1]:18833",
      GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
    });

    expect(config.host).toBe("::1");
    expect(config.port).toBe(18833);
  });
});

describe("Idunn state root argument", () => {
  it("takes --state-root over GC_ACCESS_DATA_ROOT", () => {
    // Idunn owns where state lives: the recipe declares slots relative to
    // state_root and the binding supplies the absolute path as a launch
    // argument. The env var remains for runs outside Idunn.
    const config = loadConfig({ GC_ACCESS_DATA_ROOT: "/tmp/ignored" }, [
      "--state-root",
      "/var/lib/gamecult/heimdall",
    ]);

    expect(config.dataRoot).toBe("/var/lib/gamecult/heimdall");
    expect(config.cultCachePath).toContain("heimdall.service.cc");
    expect(config.cultCachePath).toBe(
      path.join(config.dataRoot, "cultcache", "heimdall.service.cc")
    );
  });

  it("falls back to GC_ACCESS_DATA_ROOT when the argument is absent", () => {
    expect(loadConfig({ GC_ACCESS_DATA_ROOT: "/srv/heimdall/state" }, []).dataRoot).toBe(
      "/srv/heimdall/state"
    );
  });

  it("rejects a missing or relative --state-root", () => {
    expect(() => loadConfig({}, ["--state-root"])).toThrow(/requires a path/);
    expect(() => loadConfig({}, ["--state-root", "--other"])).toThrow(/requires a path/);
    expect(() => loadConfig({}, ["--state-root", "relative/path"])).toThrow(/must be absolute/);
  });
});

describe("private command plane port", () => {
  it("moves with the candidate so two generations can coexist", () => {
    // The incumbent holds the configured port. A candidate that reuses it dies
    // on bind before it can warm, which is how the first sealed release failed.
    const config = loadConfig(
      {
        GAMECULT_IDUNN_CANDIDATE_BIND: "127.0.0.1:14103",
        GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
        GC_ACCESS_PRIVATE_COMMAND_PORT: "4101",
      },
      []
    );

    expect(config.port).toBe(14103);
    expect(config.privateCommandPort).toBe(15103);
  });

  it("keeps the configured port when not launched by Idunn", () => {
    expect(
      loadConfig({ GC_ACCESS_PRIVATE_COMMAND_PORT: "4101" }, []).privateCommandPort
    ).toBe(4101);
  });
});
