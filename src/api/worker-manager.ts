import { hostname } from "node:os";
import {
  upsertWorkerHeartbeat,
  type WorkerStatus,
} from "./db-actions";

export type WorkerHeartbeatStatus = WorkerStatus;

export function heartbeatWorker(params: {
  workerId: string;
  pid: number;
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