import type { RunStatus, CheckState } from "../types";

export function formatDateTime(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}
export function toneForRunStatus(status: RunStatus) {
  switch (status) {
    case "done":
      return "text-emerald-300 border-emerald-500/40 bg-emerald-500/10";
    case "running":
      return "text-sky-300 border-sky-500/40 bg-sky-500/10";
    case "failed":
      return "text-rose-300 border-rose-500/40 bg-rose-500/10";
    case "rejected":
      return "text-amber-300 border-amber-500/40 bg-amber-500/10";
    default:
      return "text-zinc-300 border-zinc-700 bg-zinc-900";
  }
}
export function toneForCheck(status?: CheckState) {
  switch (status) {
    case "pass":
      return "text-emerald-300 border-emerald-500/40 bg-emerald-500/10";
    case "warn":
      return "text-amber-300 border-amber-500/40 bg-amber-500/10";
    case "fail":
      return "text-rose-300 border-rose-500/40 bg-rose-500/10";
    default:
      return "text-zinc-300 border-zinc-700 bg-zinc-900";
  }
}
export const WORKER_STATUS = ["idle", "running", "stale", "error"] as const;
export type WorkerStatus = (typeof WORKER_STATUS)[number];

export function toneForWorkerStatus(status: WorkerStatus) {
  switch (status) {
    case "running":
      return "text-sky-300 border-sky-500/40 bg-sky-500/10";
    case "idle":
      return "text-emerald-300 border-emerald-500/40 bg-emerald-500/10";
    case "error":
      return "text-rose-300 border-rose-500/40 bg-rose-500/10";
    case "stale":
      return "text-zinc-300 border-zinc-700 bg-zinc-900/50";
    default:
      return "text-zinc-300 border-zinc-700 bg-zinc-900";
  }
}
