import { type HeimdallConfig } from "../config.js";
import { InMemoryStore } from "./in-memory.js";
import { createPostgresStore } from "./postgres.js";
import { type HeimdallStore } from "./types.js";

export * from "./types.js";
export { InMemoryStore } from "./in-memory.js";
export { PostgresStore, createPostgresStore } from "./postgres.js";

export async function createStore(config: HeimdallConfig): Promise<HeimdallStore> {
  if (config.storage.backend !== "postgres") {
    return new InMemoryStore();
  }

  const store = createPostgresStore(config.storage.databaseUrl ?? "postgres://127.0.0.1/heimdall");
  try {
    // Every start connects and proves the database can take its requests,
    // whether or not it applied the schema first (CREATE ... IF NOT EXISTS
    // leaves a damaged table as it is), so a misbound URL, an empty or
    // damaged database, or a role that may not write fails here rather than
    // in the first request.
    if (config.storage.applySchemaOnStartup) {
      await store.ensureSchema();
    }
    await store.checkSchema();
  } catch (error) {
    // pg's and Node's errors name the host, the database or the URL itself,
    // and any of those can hold part of a secret that was bound or escaped
    // wrongly. Startup prints this error, so it names only the input and a
    // code, and carries no cause.
    const code = (error as { code?: unknown }).code;
    throw new Error(
      `Postgres storage could not be prepared (${typeof code === "string" ? code : "error"}); check GC_ACCESS_DATABASE_URL_FILE.`
    );
  }

  return store;
}
