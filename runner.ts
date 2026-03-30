import { hostname } from "node:os";
import { processDockerfile } from "./src/runner/process-dockerfile";
import { processImage } from "./src/runner/process-image";
import { processManifest } from "./src/runner/process-manifest";
import { processRepoOrArchive } from "./src/runner/process-repo-or-archive";
import { processService } from "./src/runner/process-service";
import {
  claimNextPendingRun,
  markRunDone,
  markRunFailed,
} from "./src/runner/update-runs";
import { heartbeatWorker } from "./src/api/worker-manager";

const workerId = `${hostname()}-${process.pid}`;
const startedAt = new Date().toISOString();
const HEARTBEAT_INTERVAL_MS = 10000;

type BeatStatus = "idle" | "running" | "error" | "terminated";

const heartbeatState: {
  status: BeatStatus;
  currentRunId: number | null;
  details?: unknown;
} = {
  status: "idle",
  currentRunId: null,
  details: { phase: "boot" },
};

async function beat(
  status: BeatStatus,
  currentRunId?: number | null,
  details?: unknown,
) {
  heartbeatState.status = status;
  heartbeatState.currentRunId = currentRunId ?? null;
  heartbeatState.details = details;

  heartbeatWorker({
    workerId,
    pid: status === "terminated" ? null : process.pid,
    status,
    currentRunId,
    startedAt,
    details,
  });
}

const heartbeatTimer = setInterval(() => {
  void beat(
    heartbeatState.status,
    heartbeatState.currentRunId,
    heartbeatState.details,
  );
}, HEARTBEAT_INTERVAL_MS);

function markTerminated(reason: string) {
  clearInterval(heartbeatTimer);
  try {
    heartbeatWorker({
      workerId,
      pid: null,
      status: "terminated",
      currentRunId: null,
      startedAt,
      details: {
        reason,
        previous_status: heartbeatState.status,
        previous_run_id: heartbeatState.currentRunId,
      },
    });
  } catch {
    // best effort only during shutdown
  }
}

process.once("SIGINT", () => {
  markTerminated("sigint");
  process.exit(0);
});

process.once("SIGTERM", () => {
  markTerminated("sigterm");
  process.exit(0);
});

process.once("beforeExit", () => {
  markTerminated("before_exit");
});

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
      case "k8s_service":
        [findings, decision] = await processService(run);
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
