import { rowToApi } from "../api/request-utilities";
import { logRun } from "../api/worker-manager";
import { db } from "../db";

const claimNextPendingRunQuery = db.query(`
  UPDATE analysis_runs
  SET
    status = 'running',
    started_at = datetime('now')
  WHERE id = (
    SELECT id
    FROM analysis_runs
    WHERE status = 'pending'
    ORDER BY created_at
    LIMIT 1
  )
  RETURNING
    id, kind, input_ref, status, stage, tool_options_json,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

const markRunFailedQuery = db.query(`
  UPDATE analysis_runs
  SET
    status = 'failed',
    error_text = ?2,
    finished_at = datetime('now')
  WHERE id = ?1
  RETURNING
    id, kind, input_ref, status, stage, tool_options_json,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

const markRunStageQuery = db.query(`
  UPDATE analysis_runs
  SET
    stage = ?2
  WHERE id = ?1
  RETURNING
    id, kind, input_ref, status, stage, tool_options_json,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export const markRunDoneQuery = db.query(`
  UPDATE analysis_runs
  SET
    status = 'done',
    findings_json = ?2,
    decision_json = ?3,
    finished_at = datetime('now')
  WHERE id = ?1
  RETURNING
    id, kind, input_ref, status, stage, tool_options_json,
    findings_json, decision_json, error_text,
    created_at, started_at, finished_at
`);

export type Run = {
  id: number;
  kind: string;
  input_ref: string;
  status: string;
  stage: string | null;
  tool_options_json?: unknown;
  findings_json: string | null;
  decision_json: string | null;
  error_text: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export function claimNextPendingRun(): Run | null {
  const row = claimNextPendingRunQuery.get();
  return row ? rowToApi(row) : null;
}

export function markRunFailed(runId: number, errorText: string): Run | null {
  const row = markRunFailedQuery.get(runId, errorText);
  return row ? rowToApi(row) : null;
}

export function markRunStage(runId: number, stage: string): Run | null {
  const row = markRunStageQuery.get(runId, stage);
  return row ? rowToApi(row) : null;
}

export function markRunDone(
  runId: number,
  findings?: unknown,
  decision?: unknown,
): Run | null {
  const findingsJson = findings == null ? null : JSON.stringify(findings);
  const decisionJson = decision == null ? null : JSON.stringify(decision);

  const row = markRunDoneQuery.get(runId, findingsJson, decisionJson);
  return row ? rowToApi(row) : null;
}

export function setRunStage(runId: number, stage: string, message?: string) {
  markRunStage(runId, stage);

  if (message) {
    logRun(runId, "info", message, { stage });
  }
}
