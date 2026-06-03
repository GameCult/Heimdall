import { buildHeimdallProviderAdvertisement } from "./verse-witness.js";

function readUpdatedAt(args: string[]): string {
  const index = args.indexOf("--updated-at");
  const value = index >= 0 ? args[index + 1] : undefined;

  if (!value) {
    return new Date().toISOString();
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid --updated-at value: ${value}`);
  }

  return parsed.toISOString();
}

const pretty = process.argv.includes("--pretty");
const updatedAt = readUpdatedAt(process.argv.slice(2));
const advertisement = buildHeimdallProviderAdvertisement({ updatedAt });

process.stdout.write(`${JSON.stringify(advertisement, null, pretty ? 2 : 0)}\n`);
