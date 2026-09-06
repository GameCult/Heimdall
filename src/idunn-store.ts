/**
 * Reading the `.cc` stores Idunn writes.
 *
 * Idunn writes with `cultcache-rs`, which lays a single-file store out as a
 * bare MessagePack array of positional envelopes:
 *
 *     [ [key, type, payload, stored_at, schema_id], ... ]
 *
 * `cultcache-ts` writes a different shape — `[formatVersion, catalog, records]`
 * with envelopes as named objects — and **cannot read the Rust layout at all**;
 * its schema rejects it with "expected object, received array". So Heimdall
 * cannot use its own CultCache client to read an Idunn-written store, and this
 * module exists to read exactly that one layout.
 *
 * That divergence is a defect in CultLib, not a property of the format, and
 * this module is a consumer-side reader for as long as it stands. If the two
 * forks are reconciled, delete this and use the client.
 */
import { decode } from "@msgpack/msgpack";

const ENVELOPE_FIELD_COUNT = 5;
const ENVELOPE_PAYLOAD = 2;

/**
 * Decode the payloads of every envelope in an Idunn-written store, in order.
 *
 * Accepts bytes rather than a path so callers can read from a file, or from a
 * file descriptor systemd passed them.
 */
export function readIdunnStorePayloads(bytes: Uint8Array, label: string): Uint8Array[] {
  const store = decode(bytes);
  if (!Array.isArray(store)) {
    throw new Error(`${label} is not a cultcache-rs single-file store`);
  }

  return store.map((envelope, index) => {
    if (!Array.isArray(envelope) || envelope.length !== ENVELOPE_FIELD_COUNT) {
      throw new Error(
        `${label} envelope ${index} is not the ${ENVELOPE_FIELD_COUNT}-field positional contract`
      );
    }

    const payload = envelope[ENVELOPE_PAYLOAD];
    if (!(payload instanceof Uint8Array)) {
      throw new Error(`${label} envelope ${index} has no binary payload`);
    }

    return payload;
  });
}

/** The single record an Idunn-written store is expected to hold. */
export function readIdunnStoreRecord(bytes: Uint8Array, label: string): Uint8Array {
  const payloads = readIdunnStorePayloads(bytes, label);
  if (payloads.length !== 1) {
    throw new Error(`${label} must contain exactly one record, found ${payloads.length}`);
  }
  return payloads[0]!;
}
