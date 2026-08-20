import { decode, encode } from "@msgpack/msgpack";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { chmod, readFile } from "node:fs/promises";
import { SingleFileMessagePackBackingStore, type CultCacheEnvelope } from "cultcache-ts";

const PRIVATE_SCHEMA = "gamecult.provider_health_identity.private.v1";
const PRIVATE_KEY = "gamecult-provider-health-identity";
const ID_DOMAIN = Buffer.from("gamecult.provider-health.identity.v1\0");
const SIGNATURE_DOMAIN = Buffer.from("gamecult.provider-health.signature.v1\0");
const SIGNING_PURPOSE = Buffer.from("idunn.signed_daemon_health.v1");
const PROTECTOR_CONTEXT = "gamecult-provider-health-identity-v1";
const PKCS8_ED25519_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

type PrivateIdentity = {
  identityId: string;
  publicKey: Uint8Array;
  privateKey: KeyObject;
};

export async function openOrEnrollProviderHealthIdentity(path: string): Promise<PrivateIdentity> {
  const store = new SingleFileMessagePackBackingStore(path);
  const existing = await store.pullAll();
  if (existing.length === 0) {
    const seed = randomBytes(32);
    const privateKey = privateKeyFromSeed(seed);
    const publicKey = rawPublicKey(privateKey);
    const identityId = deriveIdentityId(publicKey);
    const machineId = await readMachineId();
    const binding = protectorBinding(machineId);
    const protectedSeed = xorSeed(seed, binding);
    const createdAt = new Date().toISOString();
    const payload = encode([
      PRIVATE_SCHEMA,
      identityId,
      publicKey,
      protectedSeed,
      "linux_file_mode_machine_id_binding",
      binding,
      "v1",
      "os_installation_file_bound_cloneable_baseline",
      createdAt,
      randomBytes(32),
    ]);
    const envelope: CultCacheEnvelope = {
      key: PRIVATE_KEY,
      type: PRIVATE_SCHEMA,
      schemaId: PRIVATE_SCHEMA,
      storedAt: createdAt,
      payload,
      catalogEntry: {
        schemaId: PRIVATE_SCHEMA,
        schemaName: PRIVATE_SCHEMA,
        schemaVersion: "1",
        contentHash: createHash("sha256").update(PRIVATE_SCHEMA).digest("hex"),
        canonicalSchemaJson: JSON.stringify({ title: PRIVATE_SCHEMA, type: "array" }),
      },
    };
    await store.push(envelope);
    await chmod(path, 0o600);
    return { identityId, publicKey, privateKey };
  }
  if (existing.length !== 1) {
    throw new Error("Provider-health identity store must contain exactly one record.");
  }
  return decodePrivateIdentity(existing[0]!.payload, await readMachineId());
}

export function signProviderHealthPayload(identity: PrivateIdentity, payload: Uint8Array): Uint8Array {
  const message = Buffer.concat([
    SIGNATURE_DOMAIN,
    u64be(SIGNING_PURPOSE.length),
    SIGNING_PURPOSE,
    u64be(payload.length),
    payload,
  ]);
  return sign(null, message, identity.privateKey);
}

export function providerHealthPublicIdentity(identity: PrivateIdentity): {
  identityId: string;
  publicKeyHex: string;
} {
  return { identityId: identity.identityId, publicKeyHex: Buffer.from(identity.publicKey).toString("hex") };
}

function decodePrivateIdentity(payload: Uint8Array, machineId: string): PrivateIdentity {
  const value = decode(payload);
  if (!Array.isArray(value) || value.length !== 10) {
    throw new Error("Provider-health identity payload is malformed.");
  }
  const [schema, identityId, publicKey, protectedSeed, protector, binding, version] = value;
  if (
    schema !== PRIVATE_SCHEMA ||
    typeof identityId !== "string" ||
    !(publicKey instanceof Uint8Array) || publicKey.length !== 32 ||
    !(protectedSeed instanceof Uint8Array) || protectedSeed.length !== 32 ||
    protector !== "linux_file_mode_machine_id_binding" ||
    binding !== protectorBinding(machineId) ||
    version !== "v1" ||
    identityId !== deriveIdentityId(publicKey)
  ) {
    throw new Error("Provider-health identity does not belong to this host or profile.");
  }
  const seed = xorSeed(protectedSeed, binding);
  const privateKey = privateKeyFromSeed(seed);
  if (!rawPublicKey(privateKey).equals(Buffer.from(publicKey))) {
    throw new Error("Provider-health private seed does not match its public key.");
  }
  return { identityId, publicKey, privateKey };
}

async function readMachineId(): Promise<string> {
  for (const path of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
    try {
      const value = (await readFile(path, "utf8")).trim();
      if (value) return value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  throw new Error("Linux machine-id is unavailable.");
}

function protectorBinding(machineId: string): string {
  return `${PROTECTOR_CONTEXT}:machine-id-sha256:${createHash("sha256").update(machineId).digest("hex")}`;
}

function xorSeed(seed: Uint8Array, binding: string): Buffer {
  const mask = createHash("sha256")
    .update(Buffer.from("gamecult-linux-service-seed-v1\0"))
    .update(PROTECTOR_CONTEXT)
    .update(binding)
    .digest();
  return Buffer.from(seed.map((byte, index) => byte ^ mask[index]!));
}

function deriveIdentityId(publicKey: Uint8Array): string {
  return createHash("sha256").update(ID_DOMAIN).update(publicKey).digest("hex");
}

function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]), format: "der", type: "pkcs8" });
}

function rawPublicKey(privateKey: KeyObject): Buffer {
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}

function u64be(value: number): Buffer {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}
