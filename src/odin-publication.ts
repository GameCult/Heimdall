import { defineDocumentType } from "cultcache-ts";
import { defineCultNetDocumentBinding } from "cultnet-ts";
import { CultMesh, type CultMeshRudpEndpoint } from "cultmesh-ts";
import { z } from "zod";

import type { HeimdallConfig } from "./config.js";
import {
  buildHeimdallVerseRecords,
  type CultCacheRecord,
  type HeimdallRuntimePulse,
} from "./verse-state.js";

const ODIN_DOCUMENT_CATALOG_CONNECTION_ID = 0x0d1d0002;
const HEIMDALL_ODIN_RUNTIME_ID = "yggdrasil-heimdall";

export type HeimdallOdinDocumentPublisher = (
  record: CultCacheRecord,
  endpoint: CultMeshRudpEndpoint,
) => Promise<void>;

export async function publishHeimdallOdinState(
  config: HeimdallConfig,
  pulse: HeimdallRuntimePulse,
  options: {
    environment?: Record<string, string | undefined>;
    publish?: HeimdallOdinDocumentPublisher;
  } = {},
): Promise<void> {
  if (!config.odinCultMeshUri) {
    return;
  }

  const endpoint = CultMesh.resolveRudpEndpoint(
    config.odinCultMeshUri,
    options.environment ?? process.env,
  );
  const publish = options.publish ?? publishRecord;
  for (const record of buildHeimdallVerseRecords(config, pulse)) {
    await publish(record, endpoint);
  }
}

async function publishRecord(
  record: CultCacheRecord,
  endpoint: CultMeshRudpEndpoint,
): Promise<void> {
  const definition = defineDocumentType({
    type: record.schemaName,
    schemaId: record.schemaId,
    schemaName: record.schemaName,
    schemaVersion: record.schemaVersion,
    schema: z.record(z.unknown()),
  });
  const payload = definition.schema.parse(record.payload);
  await CultMesh.publishRudpDocumentOnce(
    HEIMDALL_ODIN_RUNTIME_ID,
    ODIN_DOCUMENT_CATALOG_CONNECTION_ID,
    endpoint,
    defineCultNetDocumentBinding({ definition }),
    record.key,
    payload,
    {
      flushTimeoutMs: 500,
      resendPollMs: 10,
      sourceRole: "heimdall-auth-authority",
      tags: ["heimdall", "redacted", "discovery"],
    },
  );
}
