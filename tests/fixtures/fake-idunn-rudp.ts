/**
 * A stand-in for Idunn's health endpoint: it accepts each RUDP connect, acks
 * the frame that follows and keeps every delivered frame. Heimdall opens a
 * fresh socket and session per publication, so sessions are kept per remote.
 */
import dgram from "node:dgram";
import {
  CultNetRudpSession,
  decodeRudpPacket,
  encodeRudpPacket,
  type CultNetTransportFrame,
} from "cultnet-ts";

export interface FakeIdunnRudp {
  port: number;
  frames: CultNetTransportFrame[];
  /** Resolves with the nth delivered frame (0-based) once it has arrived. */
  frame(index: number): Promise<CultNetTransportFrame>;
  close(): void;
}

export async function startFakeIdunnRudp(): Promise<FakeIdunnRudp> {
  const server = dgram.createSocket("udp4");
  const sessions = new Map<string, CultNetRudpSession>();
  const frames: CultNetTransportFrame[] = [];
  const waiting: Array<{ index: number; resolve: (frame: CultNetTransportFrame) => void }> = [];

  server.on("message", (wire, remote) => {
    const packet = decodeRudpPacket(wire);
    const key = `${remote.address}:${remote.port}`;
    if (packet.packetType === "connect") {
      const session = new CultNetRudpSession({
        connectionId: 0x1d0d0001,
        initialSequence: 1,
        resendDelayMs: 100,
      });
      sessions.set(key, session);
      server.send(encodeRudpPacket(session.acceptConnect(packet, Date.now())), remote.port, remote.address);
      return;
    }
    const session = sessions.get(key);
    if (!session) return;
    const result = session.receive(packet, Date.now());
    if (result.reply) server.send(encodeRudpPacket(result.reply), remote.port, remote.address);
    for (const frame of result.delivered) {
      frames.push(frame);
      for (const waiter of waiting.filter((entry) => entry.index === frames.length - 1)) waiter.resolve(frame);
    }
    if (result.delivered.length > 0) {
      server.send(encodeRudpPacket(session.createAck()), remote.port, remote.address);
    }
  });
  await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", resolve));

  return {
    port: server.address().port,
    frames,
    frame: (index) =>
      frames[index]
        ? Promise.resolve(frames[index]!)
        : new Promise((resolve) => waiting.push({ index, resolve })),
    close: () => server.close(),
  };
}
