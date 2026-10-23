/**
 * Heimdall's runtime presence statement.
 *
 * Odin admits a document as runtime presence only when it carries the
 * `gamecult.runtime_presence_health.v2` schema and its record key equals the
 * signed target. Anything else it stores as an ordinary document and never
 * correlates, so a candidate publishing the wrong contract warms forever
 * without ever being promoted — healthy from every angle except the one that
 * decides.
 *
 * The statement is dual-proved. The stable provider-health key says "Heimdall
 * made this statement"; the activation key Idunn passed at launch says "and it
 * is the incarnation Idunn started". Both cover one payload, and neither
 * establishes admission alone. Every field describing the launch is read from
 * the runtime bundle rather than from configuration: the bundle is Idunn's own
 * immutable record of what it started, and a statement assembled from anything
 * else would be describing a launch nobody authorised.
 */

import path from "node:path";
import { createHash, createPrivateKey, type KeyObject } from "node:crypto";

import { decode } from "@msgpack/msgpack";
import {
  IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME,
  encodeRuntimePresenceHealth,
  runtimePresenceActivationSigningMessage,
  runtimePresenceProofPayload,
  runtimePresenceProviderSigningMessage,
  type GameCultRuntimeCapability,
  type RuntimePresenceHealth,
  type RuntimePresenceState,
} from "cultnet-ts";

import type { HeimdallConfig } from "./config.js";
import { readIdunnStoreRecord } from "./idunn-store.js";
import {
  openProviderHealthIdentity,
  passedDescriptor,
  readPassedDescriptor,
  signWithIdentity,
  type PrivateIdentity,
} from "./provider-health-identity.js";

const PKCS8_ED25519_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Positional slots in `idunn.expected_incarnation.v2`. */
const EXPECTED = {
  target: 1,
  planId: 2,
  incarnationId: 3,
  sealedReleaseId: 4,
  runtimeId: 8,
  healthContract: 10,
  stateSchemaGeneration: 12,
  stateContractSha256: 13,
  capabilities: 16,
} as const;

/** Positional slots in `idunn.runtime_activation.v2`. */
const ACTIVATION = {
  expectedProjectionSha256: 1,
  runtimeInstanceId: 3,
  activationSignerIdentityId: 4,
} as const;

export interface RuntimeBundleFacts {
  target: string;
  planId: string;
  incarnationId: string;
  sealedReleaseId: string;
  runtimeId: string;
  runtimeInstanceId: string;
  expectedProjectionSha256: string;
  activationWitnessSha256: string;
  activationSignerIdentityId: string;
  stateSchemaGeneration: string | null;
  stateContractSha256: string | null;
  capabilities: GameCultRuntimeCapability[];
  healthContract: string;
}

function fields(payload: Uint8Array, label: string): unknown[] {
  const decoded = decode(payload);
  if (!Array.isArray(decoded)) {
    throw new Error(`${label} is not positional MessagePack`);
  }
  return decoded;
}

function text(values: unknown[], index: number, label: string): string {
  const value = values[index];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} field ${index} is not a non-empty string`);
  }
  return value;
}

function optionalText(values: unknown[], index: number): string | null {
  const value = values[index];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function capabilities(values: unknown[], index: number): GameCultRuntimeCapability[] {
  const claims = values[index];
  if (claims === undefined || claims === null) {
    return [];
  }
  if (!Array.isArray(claims)) {
    throw new Error("expected incarnation capabilities are not a list");
  }
  return claims.map((claim) => {
    if (!Array.isArray(claim) || claim.length < 4) {
      throw new Error("expected incarnation capability is not a positional tuple");
    }
    const [capability, schema, compatibility, capacity] = claim as unknown[];
    if (
      typeof capability !== "string" ||
      typeof schema !== "string" ||
      typeof compatibility !== "string" ||
      typeof capacity !== "number"
    ) {
      throw new Error("expected incarnation capability has an unexpected shape");
    }
    return { capability, schema, compatibility, capacity };
  });
}

/**
 * Read what Idunn recorded about this launch.
 *
 * `expected.cc` describes the incarnation Idunn intends; `activation.cc` names
 * the process it actually started and the activation signer whose proof this
 * statement must carry.
 */
export async function readRuntimeBundleFacts(bundlePath: string): Promise<RuntimeBundleFacts> {
  const expected = fields(
    await readIdunnStoreRecord(path.join(bundlePath, "expected.cc"), "expected incarnation"),
    "expected incarnation",
  );
  const activationPayload = await readIdunnStoreRecord(
    path.join(bundlePath, "activation.cc"),
    "runtime activation",
  );
  const activation = fields(activationPayload, "runtime activation");

  const generation = optionalText(expected, EXPECTED.stateSchemaGeneration);
  const contract = optionalText(expected, EXPECTED.stateContractSha256);
  if ((generation === null) !== (contract === null)) {
    throw new Error("expected incarnation state lineage is partial");
  }

  return {
    target: text(expected, EXPECTED.target, "expected incarnation"),
    planId: text(expected, EXPECTED.planId, "expected incarnation"),
    incarnationId: text(expected, EXPECTED.incarnationId, "expected incarnation"),
    sealedReleaseId: text(expected, EXPECTED.sealedReleaseId, "expected incarnation"),
    runtimeId: text(expected, EXPECTED.runtimeId, "expected incarnation"),
    runtimeInstanceId: text(activation, ACTIVATION.runtimeInstanceId, "runtime activation"),
    expectedProjectionSha256: text(
      activation,
      ACTIVATION.expectedProjectionSha256,
      "runtime activation",
    ),
    // The witness is the digest of the activation record itself, not a field
    // inside it: it is what binds this statement to the exact launch Idunn
    // recorded, so it is computed over the bytes actually delivered.
    activationWitnessSha256: `sha256-${createHash("sha256").update(activationPayload).digest("hex")}`,
    activationSignerIdentityId: text(
      activation,
      ACTIVATION.activationSignerIdentityId,
      "runtime activation",
    ),
    stateSchemaGeneration: generation,
    stateContractSha256: contract,
    capabilities: capabilities(expected, EXPECTED.capabilities),
    healthContract: text(expected, EXPECTED.healthContract, "expected incarnation"),
  };
}

/**
 * The publisher sequence a process stamps on its presence statements.
 *
 * Odin compares `publisher_sequence` only against stored presence of the same
 * activation, and Idunn mints a fresh activation for every start, continuity
 * restarts included. So the sequence need only strictly increase within this
 * process; nothing has to survive a restart, and nothing is written to the
 * state root. Muninn derives its sequence the same way: the observation clock,
 * never below the previous value plus one.
 */
export class PublisherSequence {
  private last = 0;

  next(observedAtUnixMillis: number): number {
    if (!Number.isSafeInteger(observedAtUnixMillis)) {
      throw new Error("observedAtUnixMillis is not a safe integer");
    }
    this.last = Math.max(observedAtUnixMillis, this.last + 1);
    return this.last;
  }
}

export interface PresenceStatementInputs {
  bundle: RuntimeBundleFacts;
  identity: PrivateIdentity;
  activationKey: KeyObject;
  state: RuntimePresenceState;
  detail: string;
  boundEndpoint: string | null;
  writeLeaseSha256: string | null;
  observedAtUnixMillis: number;
  publisherSequence: number;
}

export interface PresenceStatement {
  target: string;
  payload: Uint8Array;
}

/**
 * Build and dual-sign one presence statement from keys and facts already open.
 *
 * Returns the target alongside the bytes because the document key must equal
 * the signed target; Odin refuses the pair when they differ, and that is the
 * one part of the envelope the transport cannot infer.
 */
export function buildPresenceStatement(inputs: PresenceStatementInputs): PresenceStatement {
  const { identity } = inputs;

  const presence: RuntimePresenceHealth = {
    target: inputs.bundle.target,
    expectedProjectionSha256: inputs.bundle.expectedProjectionSha256,
    planId: inputs.bundle.planId,
    incarnationId: inputs.bundle.incarnationId,
    sealedReleaseId: inputs.bundle.sealedReleaseId,
    activationWitnessSha256: inputs.bundle.activationWitnessSha256,
    stateSchemaGeneration: inputs.bundle.stateSchemaGeneration,
    stateContractSha256: inputs.bundle.stateContractSha256,
    runtimeId: inputs.bundle.runtimeId,
    runtimeInstanceId: inputs.bundle.runtimeInstanceId,
    boundEndpoint: inputs.boundEndpoint,
    capabilities: inputs.bundle.capabilities,
    healthContract: inputs.bundle.healthContract,
    state: inputs.state,
    detail: inputs.detail,
    writeLeaseSha256: inputs.writeLeaseSha256,
    signerIdentityId: identity.identityId,
    publisherSequence: inputs.publisherSequence,
    observedAtUnixMillis: inputs.observedAtUnixMillis,
    activationSignerIdentityId: inputs.bundle.activationSignerIdentityId,
  };

  const proof = runtimePresenceProofPayload(presence);
  const signature = signWithIdentity(identity, runtimePresenceProviderSigningMessage(proof));
  const activationSignature = signWithIdentity(
    { ...identity, privateKey: inputs.activationKey },
    runtimePresenceActivationSigningMessage(proof),
  );

  return {
    target: presence.target,
    payload: encodeRuntimePresenceHealth(presence, signature, activationSignature),
  };
}

export interface PresenceAuthority {
  sign(
    state: RuntimePresenceState,
    detail: string,
    observedAtUnixMillis: number,
  ): PresenceStatement;
}

/**
 * Open everything this launch's presence statements stand on, once, before the
 * process listens: Idunn's bundle facts, the activation seed and the presence
 * identity (each descriptor is read whole and closed), and the one publisher
 * sequence. It owns them for the life of the process; a pulse supplies only its
 * state, detail and observation time.
 *
 * A launch-contract fault (a missing or malformed bundle, descriptor or
 * identity) throws here, so the process exits before it accepts a request and
 * Idunn fails Warming at once, instead of a listener that can never sign.
 */
export async function openPresenceAuthority(
  config: Pick<HeimdallConfig, "idunnRuntimeBundlePath" | "host" | "port" | "providerHealthIdentityPath">,
  env: NodeJS.ProcessEnv = process.env,
  machineId?: () => Promise<string>,
): Promise<PresenceAuthority> {
  if (!config.idunnRuntimeBundlePath) {
    throw new Error("no Idunn runtime bundle path: presence has no launch to attest");
  }
  const bundle = await readRuntimeBundleFacts(config.idunnRuntimeBundlePath);

  const activationDescriptor = passedDescriptor(IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME, env);
  if (activationDescriptor === undefined) {
    throw new Error(
      "Idunn passed no runtime activation credential, so this process cannot prove it is the " +
        "incarnation Idunn started",
    );
  }
  const seed = readPassedDescriptor(activationDescriptor);
  if (seed.length !== 32) {
    throw new Error("Idunn runtime activation credential is not a 32-byte seed");
  }
  const activationKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });

  const identity = await openProviderHealthIdentity(config.providerHealthIdentityPath, env, machineId);
  const boundEndpoint = `http://${config.host}:${config.port}`;
  const sequence = new PublisherSequence();

  return {
    sign: (state, detail, observedAtUnixMillis) =>
      buildPresenceStatement({
        bundle,
        identity,
        activationKey,
        state,
        detail,
        boundEndpoint,
        // A warming candidate holds no lease and must not claim one; the
        // contract refuses the pair, and Idunn needs the warming statement to
        // promote it.
        writeLeaseSha256: null,
        observedAtUnixMillis,
        publisherSequence: sequence.next(observedAtUnixMillis),
      }),
  };
}
