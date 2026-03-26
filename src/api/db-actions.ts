import { db } from "../db";

export const RUN_KINDS = [
  "repo",
  "archive",
  "dockerfile",
  "image",
  "k8s_manifest",
] as const;
export type RunKind = typeof RUN_KINDS[number];

export const RUN_STATUS = [
  "pending",
  "running",
  "done",
  "failed",
  "rejected",
] as const;
export type RunStatus = typeof RUN_STATUS[number];

export const WORKER_STATUS = [
  "idle",
  "running",
  "error",
] as const;
export type WorkerStatus = typeof WORKER_STATUS[number];

/**
 * Bun SQLite is much safer here if schema creation is done
 * statement-by-statement instead of one huge db.run(`...; ...; ...`)
 */
db.run(`
  CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN (${RUN_KINDS.map(k => `'${k}'`).join(",")})),
    input_ref TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (${RUN_STATUS.map(k => `'${k}'`).join(",")})) DEFAULT 'pending',
    stage TEXT,
    findings_json TEXT,
    decision_json TEXT,
    error_text TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    started_at TEXT,
    finished_at TEXT
  )
`);

db.run(`
  CREATE INDEX IF NOT EXISTS idx_analysis_runs_status_created_at
  ON analysis_runs(status, created_at)
`);

db.run(`
  CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    pid INTEGER,
    status TEXT NOT NULL CHECK (status IN (${WORKER_STATUS.map(s => `'${s}'`).join(",")})),
    current_run_id INTEGER,
    hostname TEXT,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    details_json TEXT,
    FOREIGN KEY (current_run_id) REFERENCES analysis_runs(id)
  )
`);

db.run(`
  CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_last_seen
  ON worker_heartbeats(last_seen_at)
`);

export const insertRun = db.query(`
  INSERT INTO analysis_runs (kind, input_ref, status)
  VALUES (?1, ?2, 'pending')
  RETURNING
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export const getRun = db.query(`
  SELECT
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
  FROM analysis_runs
  WHERE id = ?1
`);

export const listRuns = db.query(`
  SELECT
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
  FROM analysis_runs
  ORDER BY id DESC
  LIMIT ?1
`);

export const claimNextPendingRun = db.query(`
  UPDATE analysis_runs
  SET
    status = 'running',
    stage = 'claimed',
    started_at = datetime('now')
  WHERE id = (
    SELECT id
    FROM analysis_runs
    WHERE status = 'pending'
    ORDER BY id ASC
    LIMIT 1
  )
  RETURNING
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export const markRunStage = db.query(`
  UPDATE analysis_runs
  SET stage = ?2
  WHERE id = ?1
  RETURNING
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export const markRunDone = db.query(`
  UPDATE analysis_runs
  SET
    status = 'done',
    stage = 'done',
    findings_json = ?2,
    decision_json = ?3,
    error_text = NULL,
    finished_at = datetime('now')
  WHERE id = ?1
  RETURNING
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export const markRunFailed = db.query(`
  UPDATE analysis_runs
  SET
    status = 'failed',
    stage = 'failed',
    error_text = ?2,
    finished_at = datetime('now')
  WHERE id = ?1
  RETURNING
    id, kind, input_ref, status, stage,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export const upsertWorkerHeartbeat = db.query(`
  INSERT INTO worker_heartbeats (
    worker_id,
    pid,
    status,
    current_run_id,
    hostname,
    started_at,
    last_seen_at,
    details_json
  )
  VALUES (
    ?1,
    ?2,
    ?3,
    ?4,
    ?5,
    COALESCE(?6, datetime('now')),
    datetime('now'),
    ?7
  )
  ON CONFLICT(worker_id) DO UPDATE SET
    pid = excluded.pid,
    status = excluded.status,
    current_run_id = excluded.current_run_id,
    hostname = excluded.hostname,
    last_seen_at = datetime('now'),
    details_json = excluded.details_json
`);

export const listWorkerHeartbeats = db.query(`
  SELECT
    worker_id,
    pid,
    status,
    current_run_id,
    hostname,
    started_at,
    last_seen_at,
    details_json
  FROM worker_heartbeats
  ORDER BY last_seen_at DESC
`);

export const getWorkerHeartbeat = db.query(`
  SELECT
    worker_id,
    pid,
    status,
    current_run_id,
    hostname,
    started_at,
    last_seen_at,
    details_json
  FROM worker_heartbeats
  WHERE worker_id = ?1
`);

export const deleteStaleWorkerHeartbeats = db.query(`
  DELETE FROM worker_heartbeats
  WHERE last_seen_at < datetime('now', ?1)
`);