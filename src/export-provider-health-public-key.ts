import {
  openOrEnrollProviderHealthIdentity,
  providerHealthPublicIdentity,
} from "./provider-health-identity.js";

const identityPath = process.argv[2];
if (!identityPath) {
  throw new Error("Usage: export-provider-health-public-key <provider-health-identity.cc>");
}

const identity = await openOrEnrollProviderHealthIdentity(identityPath);
process.stdout.write(`${providerHealthPublicIdentity(identity).publicKeyHex}\n`);
