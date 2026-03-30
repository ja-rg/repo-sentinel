import { hostname } from "node:os";
import {
  insertRunLog,
  upsertWorkerHeartbeat,
  type WorkerStatus,
} from "./db-actions";

export type WorkerHeartbeatStatus = WorkerStatus;

export function heartbeatWorker(params: {
  workerId: string;
  pid: number | null;
  status: WorkerHeartbeatStatus;
  currentRunId?: number | null;
  startedAt?: string;
  details?: unknown;
}) {
  upsertWorkerHeartbeat.run(
    params.workerId,
    params.pid,
    params.status,
    params.currentRunId ?? null,
    hostname(),
    params.startedAt ?? null,
    params.details ? JSON.stringify(params.details) : null,
  );
}

export function logRun(
  runId: number,
  level: "debug" | "info" | "warn" | "error",
  message: string,
  opts?: { stage?: string; details?: unknown },
) {
  insertRunLog.get(
    runId,
    level,
    opts?.stage ?? null,
    message,
    opts?.details ? JSON.stringify(opts.details) : null,
  );
}
