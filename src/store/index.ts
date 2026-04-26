import { type HeimdallConfig } from "../config.js";
import { InMemoryStore } from "./in-memory.js";
import { createPostgresStore } from "./postgres.js";
import { type HeimdallStore } from "./types.js";

export * from "./types.js";
export { InMemoryStore } from "./in-memory.js";
export { PostgresStore, createPostgresStore } from "./postgres.js";

export async function createStore(config: HeimdallConfig): Promise<HeimdallStore> {
  const store =
    config.storage.backend === "postgres"
      ? createPostgresStore(config.storage.databaseUrl ?? "postgres://127.0.0.1/heimdall")
      : new InMemoryStore();

  if (config.storage.applySchemaOnStartup) {
    await store.ensureSchema();
  }

  return store;
}
