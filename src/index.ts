import { resolveWriteLease, WriteLeaseNotHeldError } from "./process-write-lease.js";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { publishIdunnRudpHealth } from "./idunn-rudp-health.js";
import { publishHeimdallOdinState } from "./odin-publication.js";
import { startHeimdallPrivateCommandPlane } from "./private-command-plane.js";
import type { CultNetOperationServer } from "cultnet-ts";
import { createHeimdallRuntimePulse, buildHeimdallHealthDetail, publishHeimdallVerseState } from "./verse-state.js";

const config = loadConfig();
const app = await buildApp({ config });
const versePulseIntervalMs = 60_000;
const healthPulseIntervalMs = 10_000;
let privateCommands: CultNetOperationServer | undefined;

try {
  privateCommands = await startHeimdallPrivateCommandPlane(app, config);
  app.addHook("onClose", async () => privateCommands?.close());
  await app.listen({ host: config.host, port: config.port });
  app.log.info(`Heimdall listening on ${config.host}:${config.port}`);
  app.log.info(`Heimdall private CultNet commands listening at ${privateCommands.endpoint}`);
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
  void runHealthPulseLoop();
  verseTimer.unref?.();
} catch (error) {
  await privateCommands?.close().catch(() => undefined);
  // Write to stderr directly as well as through the logger. Pino buffers, and
  // setting exitCode lets the process exit before that buffer flushes, so a
  // startup failure logged only through app.log disappears entirely. Under a
  // supervisor that is the worst possible failure: the unit dies, the journal
  // holds nothing, and the operator is told only that it is not running.
  console.error("Heimdall failed to start:", error);
  app.log.error(error);
  process.exitCode = 1;
}

async function publishVerseState(): Promise<void> {
  const pulse = createHeimdallRuntimePulse(config);
  try {
    await publishHeimdallVerseState(config, pulse);
  } catch (error) {
    // A warming candidate does not hold the write lease, and will not until
    // Idunn fences the incumbent. That is the expected state for most of a
    // deployment, not a fault: decline the write, say so once per pulse at
    // info, and keep serving. Health publication continues either way, which
    // is what lets Idunn observe the candidate and promote it.
    if (error instanceof WriteLeaseNotHeldError) {
      app.log.info(error.message);
      return;
    }
    throw error;
  }
  await publishHeimdallOdinState(config, pulse);
}

async function publishHealthState(): Promise<void> {
  const pulse = createHeimdallRuntimePulse(config);

  // "active" is a claim about owning the target's state, not about having
  // started. A candidate that has not been granted the write lease is serving
  // but is not the owner, and Idunn must observe `warming` before it fences the
  // incumbent — a candidate that reports active from its first pulse cannot be
  // promoted correctly, because the warming evidence the transaction needs
  // never appears.
  const lease = await resolveWriteLease({
    leasePath: config.idunnWriteLeasePath,
    runtimeBundlePath: config.idunnRuntimeBundlePath,
  });
  const detail = lease.mayWrite
    ? buildHeimdallHealthDetail(config, pulse)
    : `Heimdall candidate warming; ${lease.reason}`;

  await publishIdunnRudpHealth(config, {
    daemonId: config.daemonId,
    state: lease.mayWrite ? "active" : "warming",
    detail,
    observedAt: pulse.updatedAt,
  });
}

async function runHealthPulseLoop(): Promise<void> {
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, healthPulseIntervalMs));
    await publishHealthState().catch((error) => {
      console.error("Heimdall signed health publication failed on interval:", error);
    });
  }
}
