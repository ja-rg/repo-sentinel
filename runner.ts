import { hostname } from "node:os";
import { processDockerfile } from "./src/runner/process-dockerfile";
import { processImage } from "./src/runner/process-image";
import { processManifest } from "./src/runner/process-manifest";
import { processRepoOrArchive } from "./src/runner/process-repo-or-archive";
import {
  claimNextPendingRun,
  markRunDone,
  markRunFailed,
} from "./src/runner/update-runs";
import { heartbeatWorker } from "./src/api/worker-manager";

const workerId = `${hostname()}-${process.pid}`;
const startedAt = new Date().toISOString();

async function beat(
  status: "idle" | "running" | "error",
  currentRunId?: number | null,
  details?: unknown,
) {
  heartbeatWorker({
    workerId,
    pid: process.pid,
    status,
    currentRunId,
    startedAt,
    details,
  });
}

await beat("idle", null, { phase: "boot" });

while (true) {
  const run = claimNextPendingRun();

  if (!run) {
    await beat("idle", null, { phase: "polling" });
    await Bun.sleep(1000);
    continue;
  }

  let findings = {};
  let decision: Record<string, unknown> = {};

  await beat("running", run.id, { kind: run.kind });

  try {
    switch (run.kind) {
      case "dockerfile":
        findings = await processDockerfile(run);
        break;
      case "image":
        findings = await processImage(run);
        break;
      case "repo":
      case "archive":
        findings = await processRepoOrArchive(run);
        break;
      case "k8s_manifest":
        [findings, decision] = await processManifest(run);
        break;
      default:
        throw new Error(`Unknown run kind: ${run.kind}`);
    }

    markRunDone(run.id, JSON.stringify(findings), JSON.stringify(decision));
    await beat("idle", null, { last_completed_run_id: run.id });
  } catch (error) {
    markRunFailed(run.id, String(error));
    await beat("error", run.id, { error: String(error) });
  }
}
