/**
 * Idunn process write lease.
 *
 * During a deployment Idunn runs a candidate incarnation alongside the
 * incumbent, under a distinct UID and distinct PID/mount namespaces, so for a
 * while two Heimdall processes exist at once. Exactly one of them may write the
 * CultCache service store. Idunn decides which, by publishing a lease record
 * naming an incarnation; a process that is not that incarnation must not write.
 *
 * This module answers one question — may this process write state right now —
 * and answers it by reading, never by asserting. It grants nothing. Absence of
 * a lease is a "no", not an error: a warming candidate legitimately has not been
 * granted one yet and is expected to keep asking.
 *
 * Outside Idunn (developer runs, the plain systemd unit) no lease path is
 * configured and the answer is an unconditional yes, because there is no second
 * generation to collide with.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";

import { decode } from "@msgpack/msgpack";
import { readIdunnStoreRecord } from "./idunn-store.js";

const WRITE_LEASE_SCHEMA = "idunn.process_write_lease.v1";
const EXPECTED_INCARNATION_SCHEMA = "idunn.expected_incarnation.v2";

/** Positional field indexes in the canonical contracts. */
const LEASE_SCHEMA_VERSION = 0;
const LEASE_TARGET = 1;
const LEASE_INCARNATION_ID = 4;
const LEASE_RUNTIME_INSTANCE_ID = 10;
const LEASE_EPOCH = 12;
const LEASE_FIELD_COUNT = 14;

const EXPECTED_SCHEMA_VERSION = 0;
const EXPECTED_TARGET = 1;
const EXPECTED_INCARNATION_ID = 3;

export interface WriteLeaseInputs {
  /** GAMECULT_IDUNN_PROCESS_WRITE_LEASE — path to the lease record. */
  leasePath?: string | undefined;
  /** GAMECULT_IDUNN_RUNTIME_BUNDLE — directory holding expected.cc. */
  runtimeBundlePath?: string | undefined;
}

/**
 * Thrown when a state write is declined for want of the lease. Distinct from an
 * ordinary failure on purpose: for a warming candidate this is the expected
 * condition, not an incident, and callers should log it accordingly rather than
 * reporting a broken daemon every pulse.
 */
export class WriteLeaseNotHeldError extends Error {
  constructor(reason: string) {
    super(`Idunn process write lease not held: ${reason}`);
    this.name = "WriteLeaseNotHeldError";
  }
}

export type WriteLeaseDecision =
  | { mayWrite: true; reason: "not-under-idunn" }
  | { mayWrite: true; reason: "held"; incarnationId: string; leaseEpoch: number }
  | { mayWrite: false; reason: string };

function positionalFields(payload: Uint8Array, label: string): unknown[] {
  const decoded = decode(payload);
  if (!Array.isArray(decoded)) {
    throw new Error(`${label} is not positional MessagePack`);
  }
  return decoded;
}

function stringField(fields: unknown[], index: number, label: string): string {
  const value = fields[index];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} field ${index} is not a non-empty string`);
  }
  return value;
}

/**
 * Read the record out of an Idunn-written store. Reads the file directly
 * rather than through the CultCache client: this must work on a store owned by
 * another UID, it must never create the file it is inspecting, and
 * `cultcache-ts` cannot parse the layout `cultcache-rs` writes anyway — see
 * `idunn-store.ts`.
 */
async function readEnvelopePayload(file: string, label: string): Promise<Uint8Array> {
  return readIdunnStoreRecord(await readFile(file), label);
}

/**
 * Resolve whether this process holds the write lease.
 *
 * Every failure path returns `mayWrite: false` with a reason rather than
 * throwing. A candidate that cannot prove it holds the lease must decline to
 * write, and it must keep running so it can publish warming health and be
 * promoted — crashing would turn "not yet my turn" into a failed deployment.
 */
export async function resolveWriteLease(inputs: WriteLeaseInputs): Promise<WriteLeaseDecision> {
  if (!inputs.leasePath) {
    return { mayWrite: true, reason: "not-under-idunn" };
  }

  if (!inputs.runtimeBundlePath) {
    return {
      mayWrite: false,
      reason:
        "GAMECULT_IDUNN_PROCESS_WRITE_LEASE is set without GAMECULT_IDUNN_RUNTIME_BUNDLE, " +
        "so this process cannot identify which incarnation it is",
    };
  }

  let expectedTarget: string;
  let expectedIncarnationId: string;
  try {
    const payload = await readEnvelopePayload(
      path.join(inputs.runtimeBundlePath, "expected.cc"),
      "expected incarnation"
    );
    const fields = positionalFields(payload, "expected incarnation");
    const schema = stringField(fields, EXPECTED_SCHEMA_VERSION, "expected incarnation");
    if (schema !== EXPECTED_INCARNATION_SCHEMA) {
      return { mayWrite: false, reason: `expected incarnation schema is ${schema}` };
    }
    expectedTarget = stringField(fields, EXPECTED_TARGET, "expected incarnation");
    expectedIncarnationId = stringField(fields, EXPECTED_INCARNATION_ID, "expected incarnation");
  } catch (error) {
    return { mayWrite: false, reason: `unreadable runtime bundle: ${String(error)}` };
  }

  let fields: unknown[];
  try {
    fields = positionalFields(
      await readEnvelopePayload(inputs.leasePath, "process write lease"),
      "process write lease"
    );
  } catch (error) {
    // No lease yet is the ordinary state of a warming candidate.
    return { mayWrite: false, reason: `no readable write lease: ${String(error)}` };
  }

  if (fields.length !== LEASE_FIELD_COUNT) {
    return {
      mayWrite: false,
      reason: `write lease is not the ${LEASE_FIELD_COUNT}-field positional contract`,
    };
  }

  try {
    const schema = stringField(fields, LEASE_SCHEMA_VERSION, "process write lease");
    if (schema !== WRITE_LEASE_SCHEMA) {
      return { mayWrite: false, reason: `write lease schema is ${schema}` };
    }

    const target = stringField(fields, LEASE_TARGET, "process write lease");
    if (target !== expectedTarget) {
      return { mayWrite: false, reason: `write lease belongs to target ${target}` };
    }

    const incarnationId = stringField(fields, LEASE_INCARNATION_ID, "process write lease");
    if (incarnationId !== expectedIncarnationId) {
      return {
        mayWrite: false,
        reason: `write lease is held by incarnation ${incarnationId}, not this one`,
      };
    }

    stringField(fields, LEASE_RUNTIME_INSTANCE_ID, "process write lease");

    const leaseEpoch = fields[LEASE_EPOCH];
    if (typeof leaseEpoch !== "number" || !Number.isInteger(leaseEpoch) || leaseEpoch < 0) {
      return { mayWrite: false, reason: "write lease has no usable epoch" };
    }

    return { mayWrite: true, reason: "held", incarnationId, leaseEpoch };
  } catch (error) {
    return { mayWrite: false, reason: `malformed write lease: ${String(error)}` };
  }
}
