import dgram from "node:dgram";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { decode } from "@msgpack/msgpack";
import {
  CultNetRudpSession,
  decodeRudpPacket,
  encodeRudpPacket,
  parseCultNetMessage,
  type CultNetTransportFrame,
} from "cultnet-ts";
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import { publishIdunnRudpHealth } from "../src/idunn-rudp-health.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...original,
    readFile: async (file: Parameters<typeof original.readFile>[0], ...args: unknown[]) => {
      if (file === "/etc/machine-id") return "heimdall-rudp-test-machine\n";
      return (original.readFile as (...values: unknown[]) => Promise<unknown>)(file, ...args);
    },
  };
});

describe("Heimdall Idunn health publication", () => {
  it("completes the canonical RUDP handshake before publishing its signed frame", async () => {
    const server = dgram.createSocket("udp4");
    const session = new CultNetRudpSession({
      connectionId: 0x1d0d0001,
      initialSequence: 1,
      resendDelayMs: 100,
    });
    let resolveFrame!: (frame: CultNetTransportFrame) => void;
    const frameReceived = new Promise<CultNetTransportFrame>((resolve) => {
      resolveFrame = resolve;
    });

    server.on("message", (wire, remote) => {
      const packet = decodeRudpPacket(wire);
      if (packet.packetType === "connect") {
        server.send(encodeRudpPacket(session.acceptConnect(packet, Date.now())), remote.port, remote.address);
        return;
      }
      const result = session.receive(packet, Date.now());
      if (result.reply) server.send(encodeRudpPacket(result.reply), remote.port, remote.address);
      for (const frame of result.delivered) resolveFrame(frame);
      if (result.delivered.length > 0) {
        server.send(encodeRudpPacket(session.createAck()), remote.port, remote.address);
      }
    });
    await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", resolve));

    try {
      const tmp = await mkdtemp(path.join(os.tmpdir(), "heimdall-idunn-rudp-"));
      const address = server.address();
      const config = loadConfig({
        GC_ACCESS_IDUNN_RUDP_HEALTH: `127.0.0.1:${address.port}`,
        GC_ACCESS_PROVIDER_HEALTH_IDENTITY_PATH: path.join(tmp, "provider-health-identity.cc"),
      });
      const observedAt = "2026-08-22T00:45:00.000Z";

      // The transport is handed an already-signed statement; building one is
      // the presence module's job and is covered against the Rust vectors in
      // cultnet-ts. What this asserts is that the envelope keys the document by
      // the signed target, which is the pairing Odin refuses when it differs.
      const presence = {
        target: "heimdall",
        payload: new Uint8Array([0x01, 0x02, 0x03]),
      };

      await publishIdunnRudpHealth(config, {
        daemonId: "yggdrasil-heimdall",
        state: "active",
        detail: "private-command-plane-ready",
        observedAt,
        presence,
      });
      const frame = await frameReceived;
      const message = parseCultNetMessage(decode(frame.payload), "cultnet.schema.v0");

      expect(frame.channelId).toBe("schema");
      expect(message.schemaVersion).toBe("cultnet.document_put_raw.v0");
      if (message.schemaVersion !== "cultnet.document_put_raw.v0") {
        throw new Error("Expected raw document publication.");
      }
      expect(message.document.schemaId).toBe("gamecult.runtime_presence_health.v2");
      expect(message.document.recordKey).toBe(presence.target);
      expect(message.document.sourceRole).toBe("runtime-presence-publisher");
      expect(Buffer.from(message.document.payload)).toEqual(Buffer.from(presence.payload));
    } finally {
      server.close();
    }
  });
});
