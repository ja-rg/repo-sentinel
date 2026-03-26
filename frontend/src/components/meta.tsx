import type { HealthReport } from "../types";
import { toneForCheck } from "../utilities/format";
import { cn } from "../utilities/json";

export function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-[0.16em] text-zinc-500">
        {label}
      </dt>
      <dd className="mt-1 text-lg font-semibold text-white">{value}</dd>
    </div>
  );
}
export function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-[0.16em] text-zinc-500">
        {label}
      </dt>
      <dd className="mt-1 wrap-break-words text-sm text-zinc-200">{value}</dd>
    </div>
  );
}
export function EmptyState({
  message,
  compact = false,
}: {
  message: string;
  compact?: boolean;
}) {
  return (
    <div className={cn("text-sm text-zinc-500", compact ? "p-0" : "p-4")}>
      {message}
    </div>
  );
}
export function InlineNotice({
  tone,
  message,
}: {
  tone: "success" | "error" | "neutral";
  message: string;
}) {
  const styles =
    tone === "success"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
      : tone === "error"
        ? "border-rose-500/30 bg-rose-500/10 text-rose-200"
        : "border-zinc-700 bg-zinc-900 text-zinc-300";

  return <div className={cn("border p-3 text-sm", styles)}>{message}</div>;
}
export function HealthPanel({
  report,
  loading,
}: {
  report: HealthReport | null;
  loading: boolean;
}) {
  if (loading && !report) {
    return <p className="text-sm text-zinc-500">Loading health...</p>;
  }

  if (!report) {
    return <p className="text-sm text-zinc-500">No health data.</p>;
  }

  const checks = report.checks ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-sm">
        <span
          className={cn(
            "inline-flex border px-2 py-1 text-xs uppercase tracking-wide",
            toneForCheck(report.status || (report.ok ? "pass" : "fail")),
          )}
        >
          {report.ok ? "healthy" : "degraded"}
        </span>
        {report.service && (
          <span className="text-zinc-400">{report.service}</span>
        )}
      </div>

      {report.worker && (
        <div className="border border-zinc-800 p-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-white">Worker</p>
              <p className="text-sm text-zinc-400">{report.worker.summary}</p>
            </div>
            <span
              className={cn(
                "inline-flex border px-2 py-1 text-xs uppercase tracking-wide",
                toneForCheck(report.worker.status),
              )}
            >
              {report.worker.status}
            </span>
          </div>
          {Array.isArray(report.worker.workers) &&
            report.worker.workers.length > 0 && (
              <div className="mt-3 space-y-2">
                {report.worker.workers.map((worker) => (
                  <div
                    key={worker.worker_id}
                    className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800 pt-2 text-xs text-zinc-500 first:border-t-0 first:pt-0"
                  >
                    <span>{worker.worker_id}</span>
                    <span>pid {worker.pid ?? "?"}</span>
                    <span>{worker.status ?? "unknown"}</span>
                    <span>
                      {worker.current_run_id
                        ? `run #${worker.current_run_id}`
                        : "idle"}
                    </span>
                    <span>{worker.last_seen_at ?? "no heartbeat"}</span>
                  </div>
                ))}
              </div>
            )}
        </div>
      )}

      <div className="space-y-2">
        {checks.map((check) => (
          <div key={check.key} className="border border-zinc-800 p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-white">{check.label}</p>
                <p className="mt-1 text-sm text-zinc-400">
                  {check.error || check.summary}
                </p>
              </div>
              <span
                className={cn(
                  "inline-flex border px-2 py-1 text-xs uppercase tracking-wide",
                  toneForCheck(check.status),
                )}
              >
                {check.status}
              </span>
            </div>
            {Array.isArray(check.missing) && check.missing.length > 0 && (
              <div className="mt-2 text-xs text-amber-300">
                Missing: {check.missing.join(", ")}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
