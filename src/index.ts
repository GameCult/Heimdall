import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { publishIdunnRudpHealth } from "./idunn-rudp-health.js";
import { createHeimdallRuntimePulse, buildHeimdallHealthDetail, publishHeimdallVerseState } from "./verse-state.js";

const config = loadConfig();
const app = await buildApp({ config });
const versePulseIntervalMs = 60_000;
const healthPulseIntervalMs = 10_000;

try {
  await app.listen({ host: config.host, port: config.port });
  app.log.info(`Heimdall listening on ${config.host}:${config.port}`);
  await publishVerseState().catch((error) => {
    console.error("Heimdall verse publication failed on startup:", error);
  });
  await publishHealthState().catch((error) => {
    console.error("Heimdall signed health publication failed on startup:", error);
  });
  const verseTimer = setInterval(() => {
    void publishVerseState().catch((error) => {
      console.error("Heimdall verse publication failed on interval:", error);
    });
  }, versePulseIntervalMs);
  const healthTimer = setInterval(() => {
    void publishHealthState().catch((error) => {
      console.error("Heimdall signed health publication failed on interval:", error);
    });
  }, healthPulseIntervalMs);
  verseTimer.unref?.();
} catch (error) {
  app.log.error(error);
  process.exitCode = 1;
}

async function publishVerseState(): Promise<void> {
  const pulse = createHeimdallRuntimePulse(config);
  await publishHeimdallVerseState(config, pulse);
}

async function publishHealthState(): Promise<void> {
  const pulse = createHeimdallRuntimePulse(config);
  await publishIdunnRudpHealth(config, {
    daemonId: config.daemonId,
    state: "active",
    detail: buildHeimdallHealthDetail(config, pulse),
    observedAt: pulse.updatedAt,
  });
}
