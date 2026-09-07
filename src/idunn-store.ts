/**
 * Reading the two `.cc` shapes Idunn hands a target.
 *
 * Most Idunn-written stores — the control store, the runtime bundle's
 * `expected.cc`, the process write lease — are ordinary CultCache stores in the
 * standard framing, and `cultcache-ts` reads them directly. Verified against
 * Idunn's live control store on yggdrasil: 36 records, no complaint.
 *
 * Service identity *private* stores are the exception. `cultnet-rs` writes
 * those with `atomic_create_private_store`, a deliberately minimal container
 * holding one bare positional envelope:
 *
 *     [ [key, type, payload, stored_at, schema_id] ]
 *
 * That is not a fork divergence, it is a different writer for a different job —
 * a private key container rather than a record store — and `cultcache-ts`
 * cannot parse it. `readPrivateStoreRecord` exists for that one shape.
 */
import { decode } from "@msgpack/msgpack";
import { SingleFileMessagePackBackingStore } from "@gamecult/cultcache-ts";

const ENVELOPE_FIELD_COUNT = 5;
const ENVELOPE_PAYLOAD = 2;

/**
 * Read the single record from a service identity private store, given its
 * bytes. Takes bytes rather than a path because this store is handed over as
 * an open file descriptor, not a filename.
 */
export function readPrivateStoreRecord(bytes: Uint8Array, label: string): Uint8Array {
  const store = decode(bytes);
  if (!Array.isArray(store) || store.length !== 1) {
    throw new Error(`${label} is not a single-record private store`);
  }

  const envelope = store[0];
  if (!Array.isArray(envelope) || envelope.length !== ENVELOPE_FIELD_COUNT) {
    throw new Error(
      `${label} envelope is not the ${ENVELOPE_FIELD_COUNT}-field positional contract`
    );
  }

  const payload = envelope[ENVELOPE_PAYLOAD];
  if (!(payload instanceof Uint8Array)) {
    throw new Error(`${label} envelope has no binary payload`);
  }

  return payload;
}

/**
 * Read the single record from an ordinary Idunn-written CultCache store.
 *
 * Uses the CultCache client rather than decoding by hand: this is the standard
 * framing, and hand-decoding it is how a reader ends up agreeing with its own
 * fixtures instead of with the writer.
 */
export async function readIdunnStoreRecord(file: string, label: string): Promise<Uint8Array> {
  const records = await new SingleFileMessagePackBackingStore(file).pullAll();
  if (records.length !== 1) {
    throw new Error(`${label} must contain exactly one record, found ${records.length}`);
  }
  return records[0]!.payload;
}
