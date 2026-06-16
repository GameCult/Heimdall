import dgram from "node:dgram";
import { encode } from "@msgpack/msgpack";
import {
  encodeCultNetMessageForWire,
  encodeRudpPacket,
  type CultNetDocumentPutRawMessage,
  type CultNetRudpPacket,
} from "cultnet-ts";
import type { HeimdallConfig } from "./config.js";

const CULTNET_RUDP_PROTOCOL_ID = "cultnet.transport.rudp.v0";
const IDUNN_HEALTH_RUDP_CONNECTION_ID = 0x1d0d0001;
const RUDP_HEALTH_CONNECT_ATTEMPTS = 3;
const RUDP_PULSE_POST_SEND_GRACE_MS = 1000;
const RUDP_CONNECT_TO_DATA_GRACE_MS = 300;

type Endpoint = {
  host: string;
  port: number;
};

type IdunnHealthInput = {
  daemonId: string;
  state: string;
  detail: string;
  observedAt: string;
};

export async function publishIdunnRudpHealth(config: HeimdallConfig, health: IdunnHealthInput): Promise<void> {
  if (!config.idunnRudpHealth) {
    return;
  }

  const endpoint = parseEndpoint(config.idunnRudpHealth);
  let lastError: unknown;
  for (let attempt = 1; attempt <= RUDP_HEALTH_CONNECT_ATTEMPTS; attempt += 1) {
    try {
      await publishIdunnRudpHealthOnce(endpoint, config, health);
      return;
    } catch (error) {
      lastError = error;
      if ((error as Error & { code?: string }).code !== "ETIMEDOUT") {
        throw error;
      }
    }
  }
  throw lastError;
}

async function publishIdunnRudpHealthOnce(
  endpoint: Endpoint,
  config: HeimdallConfig,
  health: IdunnHealthInput,
): Promise<void> {
  const socket = dgram.createSocket(endpointFamily(endpoint.host));

  try {
    await bindSocket(socket, endpoint);
    const connect = buildConnectPacket();
    await sendPacket(socket, endpoint, connect);
    await sleep(RUDP_CONNECT_TO_DATA_GRACE_MS);
    const payload = buildDocumentPutPayload(config, health);
    await sendPacket(socket, endpoint, buildSchemaDataPacket(payload));
    await sleep(RUDP_PULSE_POST_SEND_GRACE_MS);
  } finally {
    socket.close();
  }
}

function buildDocumentPutPayload(config: HeimdallConfig, health: IdunnHealthInput): Uint8Array {
  const recordPayload = encode([
    health.daemonId,
    health.state,
    health.detail,
    health.observedAt,
    config.idunnHealthContract,
    "daemon-published",
    CULTNET_RUDP_PROTOCOL_ID,
  ]);
  const message: CultNetDocumentPutRawMessage = {
    schemaVersion: "cultnet.document_put_raw.v0",
    messageId: `heimdall-health:${health.daemonId}:${health.observedAt.replace(/[:.]/g, "-")}`,
    document: {
      schemaId: "idunn.daemon_health",
      recordKey: health.daemonId,
      storedAt: health.observedAt,
      payloadEncoding: "messagepack",
      payload: recordPayload,
      sourceRuntimeId: "heimdall-service",
      sourceRole: "daemon-health-publisher",
      tags: [CULTNET_RUDP_PROTOCOL_ID],
    },
  };
  return encode(encodeCultNetMessageForWire(message, "cultnet.schema.v0"));
}

function buildConnectPacket(): CultNetRudpPacket {
  return {
    packetType: "connect",
    connectionId: IDUNN_HEALTH_RUDP_CONNECTION_ID,
    sequence: 1,
    ack: 0,
    ackMask: 0,
    channelId: "control",
    reliable: true,
    ordered: true,
    sequenced: false,
    payload: new Uint8Array(),
  };
}

function buildSchemaDataPacket(payload: Uint8Array): CultNetRudpPacket {
  return {
    packetType: "data",
    connectionId: IDUNN_HEALTH_RUDP_CONNECTION_ID,
    sequence: 2,
    ack: 0,
    ackMask: 0,
    channelId: "schema",
    reliable: true,
    ordered: true,
    sequenced: false,
    payload,
  };
}

async function bindSocket(socket: dgram.Socket, endpoint: Endpoint): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, localBindHost(endpoint.host), () => {
      socket.off("error", reject);
      resolve();
    });
  });
}

function localBindHost(remoteHost: string): string {
  if (remoteHost === "localhost" || remoteHost.startsWith("127.")) {
    return "127.0.0.1";
  }
  if (remoteHost === "::1") {
    return "::1";
  }
  return remoteHost.includes(":") ? "::" : "0.0.0.0";
}

async function sendPacket(socket: dgram.Socket, endpoint: Endpoint, input: CultNetRudpPacket): Promise<void> {
  const wire = encodeRudpPacket(input);
  await new Promise<void>((resolve, reject) => {
    socket.send(wire, endpoint.port, endpoint.host, (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function endpointFamily(host: string): "udp4" | "udp6" {
  return host.includes(":") ? "udp6" : "udp4";
}

function parseEndpoint(value: string): Endpoint {
  const text = value.trim();
  const ipv6 = text.match(/^\[([^\]]+)\]:(\d+)$/);
  if (ipv6) {
    return { host: ipv6[1]!, port: parsePort(ipv6[2]!) };
  }
  const index = text.lastIndexOf(":");
  if (index <= 0) {
    throw new Error(`Idunn RUDP endpoint must be host:port, got "${value}".`);
  }
  return {
    host: text.slice(0, index),
    port: parsePort(text.slice(index + 1)),
  };
}

function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Idunn RUDP endpoint port is invalid: ${value}`);
  }
  return port;
}
