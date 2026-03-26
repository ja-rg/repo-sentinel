import type { WorkerStatus } from "./utilities/format";

export type RunKind =
  | "repo"
  | "archive"
  | "dockerfile"
  | "image"
  | "k8s_manifest";
export type RunStatus = "pending" | "running" | "done" | "failed" | "rejected";
export type CheckState = "pass" | "warn" | "fail" | "unknown";
export type AnalysisRun = {
  id: number;
  kind: RunKind;
  input_ref: string;
  status: RunStatus;
  stage?: string | null;
  findings_json?: unknown;
  decision_json?: unknown;
  error_text?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  upload?: {
    name: string;
    size: number;
    type: string;
    path: string;
  };
};
export type HealthCheck = {
  key: string;
  label: string;
  status: CheckState;
  summary: string;
  error?: string;
  details?: unknown;
  missing?: string[];
};
export type HealthReport = {
  ok: boolean;
  status?: CheckState;
  service?: string;
  database?: unknown;
  worker?: {
    status: WorkerStatus
    summary: string;
    active_workers?: number;
    stale_workers?: number;
    workers?: Array<{
      worker_id: string;
      pid?: number;
      status?: string;
      current_run_id?: number | null;
      last_seen_at?: string;
    }>;
  };
  checks?: HealthCheck[];
  [key: string]: unknown;
};
export type FindingsSection = {
  key: string;
  title: string;
  kind: "semgrep" | "trivy" | "syft" | "gitleaks" | "generic";
  items: unknown[];
  raw: unknown;
};
