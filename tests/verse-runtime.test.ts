import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { decode } from "@msgpack/msgpack";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createHeimdallRuntimePulse, publishHeimdallVerseState } from "../src/verse-state.js";

describe("Heimdall verse runtime publication", () => {
  it("writes provider advertisement, command boundary, transport profile, and daemon health to the witness store", async () => {
    const tmp = await mkdtemp(path.join(os.tmpdir(), "heimdall-verse-runtime-"));
    const config = loadConfig({
      GC_ACCESS_BASE_URL: "https://heimdall.gamecult.org",
      GC_ACCESS_CULTCACHE_PATH: path.join(tmp, "cultcache", "heimdall.service.cc"),
      GC_ACCESS_DATABASE_URL: "postgres://heimdall:test@localhost/heimdall",
      GC_ACCESS_IDUNN_RUDP_HEALTH: "10.77.0.2:17870",
      GC_ACCESS_PROVIDER_DISCORD_CLIENT_ID: "discord-client",
      GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET: "discord-secret",
      GC_ACCESS_PROVIDER_TWITCH_CLIENT_ID: "twitch-client",
      GC_ACCESS_PROVIDER_TWITCH_CLIENT_SECRET: "twitch-secret",
    });
    const pulse = createHeimdallRuntimePulse(config, "2026-06-16T17:10:00.000Z");

    await publishHeimdallVerseState(config, pulse);

    const contents = await readFile(config.cultCachePath);
    const decoded = decode(contents) as [string, unknown[], Array<[string, string, string, Uint8Array]>];

    expect(decoded[0]).toBe("cultcache.store.v1");
    const entries = decoded[2];
    const bySchema = new Map(entries.map((entry) => [entry[1], decode(entry[3])]));

    expect(bySchema.get("gamecult.eve.provider_advertisement.v1")).toMatchObject({
      providerId: "heimdall",
      status: "daemon_live",
      locatedService: "asgard.yggdrasil.heimdall",
      runtime: {
        storageBackend: "postgres",
        configuredProviders: ["discord", "twitch"],
        appProfileCount: 5,
      },
    });
    expect(bySchema.get("heimdall.command_boundary.v1")).toMatchObject({
      boundaryId: "heimdall",
      daemonId: "yggdrasil-heimdall",
      healthPublication: {
        contract: "heimdall.cultnet-rudp-provider-health",
        transport: "cultnet.transport.rudp.v0",
      },
      commands: [
        { operation: "heimdall.auth.begin" },
        { operation: "heimdall.auth.complete" },
        { operation: "heimdall.auth.refresh" },
      ],
      privateRoute: {
        endpoint: "rudp://127.0.0.1:4101",
        exposure: "loopback-only",
      },
    });
    expect(bySchema.get("gamecult.eve.plugin_advertisement.v1")).toMatchObject({
      pluginId: "gamecult.heimdall.access",
      ownerService: "asgard.heimdall",
      commands: ["heimdall.auth.begin", "heimdall.auth.complete", "app.auth.logout"],
    });
    expect(bySchema.get("heimdall.transport_profile.v1")).toMatchObject({
      daemonId: "yggdrasil-heimdall",
      targetTransport: "cultnet.transport.rudp.v0",
      healthTransport: "cultnet.transport.rudp.v0",
    });
    expect(bySchema.get("idunn.daemon_health")).toEqual([
      "yggdrasil-heimdall",
      "active",
      "Heimdall auth runtime active; storage=postgres; providers=2/6; apps=5; healthTransport=CultNet/RUDP",
      "2026-06-16T17:10:00.000Z",
      "heimdall.cultnet-rudp-provider-health",
      "daemon-published",
      "cultnet.transport.rudp.v0",
    ]);
  });
});
