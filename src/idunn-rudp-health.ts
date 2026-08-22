import dgram from "node:dgram";
import { randomUUID } from "node:crypto";
import { encode } from "@msgpack/msgpack";
import {
  CultNetRudpSession,
  decodeRudpPacket,
  encodeCultNetMessageForWire,
  encodeRudpPacket,
  type CultNetDocumentPutRawMessage,
  type CultNetRudpPacket,
} from "cultnet-ts";
import type { HeimdallConfig } from "./config.js";
import {
  openOrEnrollProviderHealthIdentity,
  signProviderHealthPayload,
} from "./provider-health-identity.js";

const CULTNET_RUDP_PROTOCOL_ID = "cultnet.transport.rudp.v0";
const IDUNN_HEALTH_RUDP_CONNECTION_ID = 0x1d0d0001;
const RUDP_HEALTH_CONNECT_ATTEMPTS = 3;
const RUDP_ACCEPT_TIMEOUT_MS = 2_000;
const RUDP_ACK_TIMEOUT_MS = 1_000;
const SIGNED_DAEMON_HEALTH_SCHEMA = "idunn.signed_daemon_health.v1";
const publisherIncarnationId = randomUUID();
let publisherSequence = 0;

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
  const receiver = createPacketReceiver(socket);
  const session = new CultNetRudpSession({
    connectionId: IDUNN_HEALTH_RUDP_CONNECTION_ID,
    initialSequence: 1,
    resendDelayMs: 100,
  });

  try {
    await bindSocket(socket, endpoint);
    await sendPacket(socket, endpoint, session.createConnect(Date.now(), new Uint8Array()));
    await receiveUntil(receiver, session, endpoint, "accept", RUDP_ACCEPT_TIMEOUT_MS);

    const payload = await buildSignedDocumentPutPayload(config, health);
    const ack = receiveUntil(receiver, session, endpoint, "ack", RUDP_ACK_TIMEOUT_MS);
    for (const packet of session.sendMany("schema", payload, {
      reliable: true,
      ordered: true,
      nowMs: Date.now(),
    })) {
      await sendPacket(socket, endpoint, packet);
    }
    await ack;
  } finally {
    receiver.close();
    socket.close();
  }
}

async function buildSignedDocumentPutPayload(config: HeimdallConfig, health: IdunnHealthInput): Promise<Uint8Array> {
  const identity = await openOrEnrollProviderHealthIdentity(config.providerHealthIdentityPath);
  publisherSequence += 1;
  const unsigned = [
    SIGNED_DAEMON_HEALTH_SCHEMA,
    health.daemonId,
    config.idunnHealthContract,
    "heimdall-service",
    health.state,
    health.detail,
    identity.identityId,
    publisherIncarnationId,
    publisherSequence,
    Date.parse(health.observedAt),
    null,
    null,
    null,
    null,
    "ed25519",
    new Uint8Array(),
    false,
  ];
  const signature = signProviderHealthPayload(identity, encode(unsigned));
  const recordPayload = encode([...unsigned.slice(0, 15), signature, false]);
  const message: CultNetDocumentPutRawMessage = {
    schemaVersion: "cultnet.document_put_raw.v0",
    messageId: `heimdall-health:${health.daemonId}:${health.observedAt.replace(/[:.]/g, "-")}`,
    document: {
      schemaId: "idunn.signed_daemon_health",
      recordKey: health.daemonId,
      storedAt: health.observedAt,
      payloadEncoding: "messagepack",
      payload: recordPayload,
      sourceRuntimeId: "heimdall-service",
      sourceAgentId: identity.identityId,
      sourceRole: "daemon-health-publisher",
      tags: [CULTNET_RUDP_PROTOCOL_ID],
    },
  };
  return encode(encodeCultNetMessageForWire(message, "cultnet.schema.v0"));
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

type PacketReceiver = {
  socket: dgram.Socket;
  next(timeoutMs: number, label: string): Promise<CultNetRudpPacket>;
  close(): void;
};

function createPacketReceiver(socket: dgram.Socket): PacketReceiver {
  const packets: CultNetRudpPacket[] = [];
  const errors: Error[] = [];
  const waiters: Array<{
    resolve: (packet: CultNetRudpPacket) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];

  const resolveNext = (): void => {
    while (waiters.length > 0 && (packets.length > 0 || errors.length > 0)) {
      const waiter = waiters.shift()!;
      clearTimeout(waiter.timer);
      const error = errors.shift();
      if (error) waiter.reject(error);
      else waiter.resolve(packets.shift()!);
    }
  };
  const onMessage = (wire: Buffer): void => {
    try {
      packets.push(decodeRudpPacket(wire));
    } catch (error) {
      errors.push(asError(error));
    }
    resolveNext();
  };
  const onError = (error: Error): void => {
    errors.push(error);
    resolveNext();
  };
  socket.on("message", onMessage);
  socket.on("error", onError);

  return {
    socket,
    next(timeoutMs, label) {
      const packet = packets.shift();
      if (packet) return Promise.resolve(packet);
      const error = errors.shift();
      if (error) return Promise.reject(error);
      return new Promise((resolve, reject) => {
        const waiter = {
          resolve,
          reject,
          timer: setTimeout(() => {
            const index = waiters.indexOf(waiter);
            if (index >= 0) waiters.splice(index, 1);
            const timeout = new Error(`timed out waiting for Idunn RUDP ${label}`) as Error & { code?: string };
            timeout.code = "ETIMEDOUT";
            reject(timeout);
          }, Math.max(1, timeoutMs)),
        };
        waiters.push(waiter);
      });
    },
    close() {
      socket.off("message", onMessage);
      socket.off("error", onError);
      while (waiters.length > 0) {
        const waiter = waiters.shift()!;
        clearTimeout(waiter.timer);
        const error = new Error("Idunn RUDP packet receiver closed") as Error & { code?: string };
        error.code = "ECLOSED";
        waiter.reject(error);
      }
    },
  };
}

async function receiveUntil(
  receiver: PacketReceiver,
  session: CultNetRudpSession,
  endpoint: Endpoint,
  packetType: "accept" | "ack",
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const packet = await receiver.next(Math.min(100, deadline - Date.now()), packetType);
      const result = session.receive(packet, Date.now());
      if (result.reply) await sendPacket(receiver.socket, endpoint, result.reply);
      if (packet.packetType === packetType) return;
    } catch (error) {
      if ((error as Error & { code?: string }).code !== "ETIMEDOUT") throw error;
    }
    for (const packet of session.dueResends(Date.now())) {
      await sendPacket(receiver.socket, endpoint, packet);
    }
  }
  const error = new Error(`timed out waiting for Idunn RUDP ${packetType}`) as Error & { code?: string };
  error.code = "ETIMEDOUT";
  throw error;
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
