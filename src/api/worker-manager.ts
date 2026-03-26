import { db } from "../db";

export type WorkerHeartbeatStatus = "idle" | "running" | "error";

export function initWorkerHeartbeatTable() {
  db.run(`
    CREATE TABLE IF NOT EXISTS worker_heartbeats (
      worker_id TEXT PRIMARY KEY,
      pid INTEGER,
      status TEXT NOT NULL,
      current_run_id INTEGER,
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
      details_json TEXT
    )
  `);
}

const upsertHeartbeatQuery = db.query(`
  INSERT INTO worker_heartbeats (
    worker_id,
    pid,
    status,
    current_run_id,
    started_at,
    last_seen_at,
    details_json
  )
  VALUES (?1, ?2, ?3, ?4, COALESCE(?5, datetime('now')), datetime('now'), ?6)
  ON CONFLICT(worker_id) DO UPDATE SET
    pid = excluded.pid,
    status = excluded.status,
    current_run_id = excluded.current_run_id,
    last_seen_at = datetime('now'),
    details_json = excluded.details_json
`);

export function heartbeatWorker(params: {
  workerId: string;
  pid: number;
  status: WorkerHeartbeatStatus;
  currentRunId?: number | null;
  startedAt?: string;
  details?: unknown;
}) {
  initWorkerHeartbeatTable();
  upsertHeartbeatQuery.run(
    params.workerId,
    params.pid,
    params.status,
    params.currentRunId ?? null,
    params.startedAt ?? null,
    params.details ? JSON.stringify(params.details) : null,
  );
}
