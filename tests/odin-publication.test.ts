import { describe, expect, it } from "vitest";
import { CultMesh } from "cultmesh-ts";
import { CultNetDocumentRegistry } from "cultnet-ts";

import { loadConfig } from "../src/config.js";
import { publishHeimdallOdinState } from "../src/odin-publication.js";
import { createHeimdallRuntimePulse, type CultCacheRecord } from "../src/verse-state.js";

describe("Heimdall Odin publication", () => {
  it("publishes the exact redacted provider, command, plugin, and transport records", async () => {
    const config = loadConfig({
      GC_ACCESS_ODIN_CULTMESH_URI: "cultmesh://odin/rendezvous/provider-catalog",
      GC_ACCESS_PROVIDER_DISCORD_CLIENT_ID: "public-client-id",
      GC_ACCESS_PROVIDER_DISCORD_CLIENT_SECRET: "must-never-publish",
      GC_ACCESS_APP_GHOSTLIGHT_SHARED_SECRET: "must-never-publish-either",
    });
    const pulse = createHeimdallRuntimePulse(config, "2026-08-22T12:00:00.000Z");
    const published: CultCacheRecord[] = [];
    let inFlight = 0;
    let maximumInFlight = 0;

    await publishHeimdallOdinState(config, pulse, {
      environment: { CULTMESH_URI_ODIN_RUDP: "10.77.0.1:17871" },
      publish: async (record, endpoint) => {
        inFlight += 1;
        maximumInFlight = Math.max(maximumInFlight, inFlight);
        expect(endpoint).toEqual({
          host: "10.77.0.1",
          port: 17871,
          uri: "rudp://10.77.0.1:17871",
        });
        published.push(record);
        await Promise.resolve();
        inFlight -= 1;
      },
    });

    expect(published.map((record) => [record.schemaId, record.key])).toEqual([
      ["gamecult.eve.provider_advertisement.v1", "eve:provider:heimdall"],
      ["heimdall.command_boundary.v1", "heimdall:command-boundary"],
      ["gamecult.eve.plugin_advertisement.v1", "eve:plugin:gamecult.heimdall.access"],
      ["heimdall.transport_profile.v1", "heimdall:transport-profile"],
    ]);
    const serialized = JSON.stringify(published);
    expect(serialized).not.toContain("must-never-publish");
    expect(serialized).not.toContain("must-never-publish-either");
    expect(serialized).not.toContain("access_token");
    expect(serialized).not.toContain("refresh_token");
    expect(maximumInFlight).toBe(1);
  });

  it("does not invent an Odin route when publication is not configured", async () => {
    const config = loadConfig({});
    let calls = 0;
    await publishHeimdallOdinState(config, createHeimdallRuntimePulse(config), {
      publish: async () => {
        calls += 1;
      },
    });
    expect(calls).toBe(0);
  });

  it("publishes all four documents over Odin's RUDP catalog contract", async () => {
    const received = new Set<string>();
    const server = CultMesh.createRudpDocumentServer(
      "odin-heimdall-test-catalog",
      0x0d1d0002,
      {
        documents: new CultNetDocumentRegistry(),
        bindHost: "127.0.0.1",
        bindPort: 0,
        resendPollMs: 5,
        onDocumentPutRaw: (document) => {
          received.add(`${document.schemaId}:${document.recordKey}`);
        },
      },
    );

    try {
      await server.start();
      const config = loadConfig({
        GC_ACCESS_ODIN_CULTMESH_URI: "cultmesh://odin/rendezvous/provider-catalog",
      });
      await publishHeimdallOdinState(config, createHeimdallRuntimePulse(config), {
        environment: { CULTMESH_URI_ODIN_RUDP: `127.0.0.1:${server.bind.port}` },
      });
      expect([...received].sort()).toEqual([
        "gamecult.eve.plugin_advertisement.v1:eve:plugin:gamecult.heimdall.access",
        "gamecult.eve.provider_advertisement.v1:eve:provider:heimdall",
        "heimdall.command_boundary.v1:heimdall:command-boundary",
        "heimdall.transport_profile.v1:heimdall:transport-profile",
      ]);
    } finally {
      server.close();
    }
  });
});
