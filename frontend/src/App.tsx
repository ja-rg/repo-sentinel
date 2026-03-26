import React, { useEffect, useMemo, useRef, useState } from "react";

type RunKind = "repo" | "archive" | "dockerfile" | "image" | "k8s_manifest";
type RunStatus = "pending" | "running" | "done" | "failed" | "rejected";
type CheckState = "pass" | "warn" | "fail" | "unknown";

type AnalysisRun = {
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

type HealthCheck = {
  key: string;
  label: string;
  status: CheckState;
  summary: string;
  error?: string;
  details?: unknown;
  missing?: string[];
};

type HealthReport = {
  ok: boolean;
  status?: CheckState;
  service?: string;
  database?: unknown;
  worker?: {
    status: CheckState;
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

type FindingsSection = {
  key: string;
  title: string;
  kind: "semgrep" | "trivy" | "generic";
  items: unknown[];
  raw: unknown;
};

const API_BASE = "http://localhost:3000";
const POLL_MS = 5000;

const kindMeta: Record<
  RunKind,
  {
    label: string;
    mode: "text" | "file";
    placeholder?: string;
    accept?: string;
  }
> = {
  repo: {
    label: "Repository",
    mode: "text",
    placeholder: "https://github.com/org/repo.git",
  },
  archive: {
    label: "Archive",
    mode: "file",
    accept: ".zip,.tar,.tgz,.tar.gz",
  },
  dockerfile: {
    label: "Dockerfile",
    mode: "file",
    accept: ".dockerfile,Dockerfile,text/plain",
  },
  image: {
    label: "Image",
    mode: "text",
    placeholder: "ghcr.io/acme/app:1.2.0",
  },
  k8s_manifest: {
    label: "K8s manifest",
    mode: "file",
    accept: ".yaml,.yml,.json",
  },
};

function cn(...values: Array<string | undefined | false | null>) {
  return values.filter(Boolean).join(" ");
}

function parseJson<T = unknown>(value: unknown): T | unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as T;
  } catch {
    return value;
  }
}

function prettyJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatDateTime(value?: string | null) {
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

function getRunCounts(runs: AnalysisRun[]) {
  return runs.reduce(
    (acc, run) => {
      acc.total += 1;
      acc[run.status] += 1;
      return acc;
    },
    {
      total: 0,
      pending: 0,
      running: 0,
      done: 0,
      failed: 0,
      rejected: 0,
    },
  );
}

function toneForRunStatus(status: RunStatus) {
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

function toneForCheck(status?: CheckState) {
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

function normalizeHealth(raw: unknown): HealthReport | null {
  if (!raw || typeof raw !== "object") return null;
  const data = raw as Record<string, unknown>;

  if (Array.isArray(data.checks)) {
    return data as unknown as HealthReport;
  }

  const legacyChecks = data.checks;
  if (!legacyChecks || typeof legacyChecks !== "object") {
    return data as HealthReport;
  }

  const normalizedChecks = Object.entries(legacyChecks as Record<string, any>).map(
    ([key, value]) => ({
      key,
      label: key.replace(/_/g, " "),
      status:
        value?.status === "ok"
          ? "pass"
          : value?.status === "fail"
            ? "fail"
            : "unknown",
      summary: value?.error || value?.details || key,
      error: value?.error,
      details: value?.details,
      missing: Array.isArray(value?.details)
        ? value.details.filter((item: any) => item && item.found === false).map((item: any) => item.image)
        : undefined,
    }),
  );

  return {
    ok: Boolean(data.ok),
    service: typeof data.service === "string" ? data.service : undefined,
    database: data.database,
    checks: normalizedChecks,
  };
}

function normalizeFindings(raw: unknown): FindingsSection[] {
  const parsed = parseJson(raw);

  if (Array.isArray(parsed)) {
    return [{ key: "findings", title: "Findings", kind: "generic", items: parsed, raw: parsed }];
  }

  if (!parsed || typeof parsed !== "object") {
    return [];
  }

  return Object.entries(parsed as Record<string, unknown>).map(([key, value]) => ({
    key,
    title: key,
    kind: key === "semgrep" ? "semgrep" : key === "trivy" ? "trivy" : "generic",
    items: Array.isArray(value) ? value : value == null ? [] : [value],
    raw: value,
  }));
}

function flattenTrivy(results: unknown[]) {
  const items: Array<Record<string, unknown>> = [];

  for (const result of results) {
    if (!result || typeof result !== "object") continue;
    const source = result as Record<string, any>;
    const target = source.Target ?? source.target;
    const misconfigurations = Array.isArray(source.Misconfigurations)
      ? source.Misconfigurations
      : Array.isArray(source.misconfigurations)
        ? source.misconfigurations
        : [];

    for (const misconfiguration of misconfigurations) {
      items.push({
        target,
        type: source.Type ?? source.type,
        class: source.Class ?? source.class,
        ...misconfiguration,
      });
    }
  }

  return items;
}

function App() {
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);

  const [runs, setRuns] = useState<AnalysisRun[]>([]);
  const [runsLoading, setRunsLoading] = useState(false);

  const [selectedRun, setSelectedRun] = useState<AnalysisRun | null>(null);
  const [selectedRunLoading, setSelectedRunLoading] = useState(false);
  const selectedRunIdRef = useRef<number | null>(null);

  const [kind, setKind] = useState<RunKind>("repo");
  const [inputRef, setInputRef] = useState("");
  const [file, setFile] = useState<File | null>(null);

  const [submitting, setSubmitting] = useState(false);
  const [submitMessage, setSubmitMessage] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [ensuringWorker, setEnsuringWorker] = useState(false);
  const [workerMessage, setWorkerMessage] = useState<string | null>(null);

  const currentMeta = kindMeta[kind];

  useEffect(() => {
    selectedRunIdRef.current = selectedRun?.id ?? null;
  }, [selectedRun]);

  async function loadHealth() {
    setHealthLoading(true);
    try {
      const res = await fetch(`${API_BASE}/health`);
      const data = await res.json();
      setHealth(normalizeHealth(data));
    } catch {
      setHealth({
        ok: false,
        status: "fail",
        checks: [
          {
            key: "backend",
            label: "backend",
            status: "fail",
            summary: "Could not reach backend",
          },
        ],
      });
    } finally {
      setHealthLoading(false);
    }
  }

  async function loadRuns() {
    setRunsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/analysis-runs?limit=50`);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("Invalid runs payload");
      setRuns(data);

      const selectedRunId = selectedRunIdRef.current;
      const nextSelected =
        data.find((run) => run.id === selectedRunId) ??
        data[0] ??
        null;

      if (nextSelected && nextSelected.id !== selectedRunId) {
        setSelectedRun(nextSelected);
      }
    } catch {
      setRuns([]);
    } finally {
      setRunsLoading(false);
    }
  }

  async function loadRunById(id: number) {
    setSelectedRunLoading(true);
    try {
      const res = await fetch(`${API_BASE}/analysis-runs/${id}`);
      const data = await res.json();
      setSelectedRun(data);
    } finally {
      setSelectedRunLoading(false);
    }
  }

  async function ensureWorker() {
    setEnsuringWorker(true);
    setWorkerMessage(null);
    try {
      const res = await fetch(`${API_BASE}/workers/ensure`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error || "Could not ensure worker");
      }
      setWorkerMessage(data.message || "Worker ensured.");
      await loadHealth();
    } catch (error) {
      setWorkerMessage(error instanceof Error ? error.message : "Could not ensure worker");
    } finally {
      setEnsuringWorker(false);
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setSubmitMessage(null);
    setSubmitError(null);

    try {
      let res: Response;

      if (currentMeta.mode === "text") {
        if (!inputRef.trim()) {
          throw new Error("Reference is required.");
        }

        res = await fetch(`${API_BASE}/analysis-runs`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind, input_ref: inputRef.trim() }),
        });
      } else {
        if (!file) {
          throw new Error("File is required.");
        }

        const formData = new FormData();
        formData.append("kind", kind);
        formData.append("file", file);
        formData.append("input_ref", inputRef.trim() || file.name);

        res = await fetch(`${API_BASE}/analysis-runs`, {
          method: "POST",
          body: formData,
        });
      }

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error || "Request failed.");
      }

      setSubmitMessage(`Run #${data.id} created.`);
      setInputRef("");
      setFile(null);
      await loadRuns();
      await loadRunById(data.id);
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Unknown error.");
    } finally {
      setSubmitting(false);
    }
  }

  useEffect(() => {
    loadHealth();
    loadRuns();

    const interval = window.setInterval(() => {
      loadHealth();
      loadRuns();
      if (selectedRunIdRef.current) {
        loadRunById(selectedRunIdRef.current);
      }
    }, POLL_MS);

    return () => window.clearInterval(interval);
  }, []);

  const counts = useMemo(() => getRunCounts(runs), [runs]);
  const findingsSections = useMemo(() => normalizeFindings(selectedRun?.findings_json), [selectedRun]);
  const decision = useMemo(() => parseJson(selectedRun?.decision_json), [selectedRun]);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <main className="mx-auto max-w-7xl px-4 py-4 sm:px-6 lg:px-8">
        <header className="border border-zinc-800 bg-zinc-950">
          <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
            <div>
              <p className="text-xs uppercase tracking-[0.24em] text-zinc-500">RepoSentinel</p>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">Security console</h1>
              <p className="mt-1 max-w-3xl text-sm text-zinc-400">
                One page, one queue, one selected run. No marketing blocks. No oversized cards. Findings stay structured.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  loadHealth();
                  loadRuns();
                  if (selectedRun?.id) loadRunById(selectedRun.id);
                }}
                className="inline-flex h-10 items-center justify-center border border-zinc-700 px-3 text-sm text-zinc-200 hover:border-zinc-500"
              >
                Refresh
              </button>
              <button
                type="button"
                onClick={ensureWorker}
                disabled={ensuringWorker}
                className="inline-flex h-10 items-center justify-center border border-sky-500/40 bg-sky-500/10 px-3 text-sm text-sky-200 hover:bg-sky-500/15 disabled:opacity-60"
              >
                {ensuringWorker ? "Ensuring worker..." : "Ensure worker"}
              </button>
            </div>
          </div>
        </header>

        <section className="mt-4 grid gap-4 xl:grid-cols-[320px_360px_minmax(0,1fr)]">
          <aside className="border border-zinc-800">
            <SectionTitle title="New run" subtitle="Submit a source to the queue" />
            <form onSubmit={handleSubmit} className="space-y-4 p-4">
              <div className="grid grid-cols-2 gap-2">
                {(Object.keys(kindMeta) as RunKind[]).map((item) => (
                  <button
                    key={item}
                    type="button"
                    onClick={() => {
                      setKind(item);
                      setInputRef("");
                      setFile(null);
                      setSubmitMessage(null);
                      setSubmitError(null);
                    }}
                    className={cn(
                      "border px-3 py-2 text-left text-sm",
                      kind === item ? "border-sky-500 bg-sky-500/10 text-sky-100" : "border-zinc-800 text-zinc-300 hover:border-zinc-600",
                    )}
                  >
                    {kindMeta[item].label}
                  </button>
                ))}
              </div>

              {currentMeta.mode === "text" ? (
                <Field label="Reference">
                  <input
                    value={inputRef}
                    onChange={(event) => setInputRef(event.target.value)}
                    placeholder={currentMeta.placeholder}
                    className="h-11 w-full border border-zinc-800 bg-zinc-950 px-3 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-sky-500"
                  />
                </Field>
              ) : (
                <>
                  <Field label="File">
                    <input
                      type="file"
                      accept={currentMeta.accept}
                      onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                      className="block w-full border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-300 file:mr-3 file:border-0 file:bg-zinc-800 file:px-3 file:py-2 file:text-sm file:text-zinc-100"
                    />
                  </Field>

                  <Field label="Display name">
                    <input
                      value={inputRef}
                      onChange={(event) => setInputRef(event.target.value)}
                      placeholder="Optional"
                      className="h-11 w-full border border-zinc-800 bg-zinc-950 px-3 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-sky-500"
                    />
                  </Field>
                </>
              )}

              {submitMessage && <InlineNotice tone="success" message={submitMessage} />}
              {submitError && <InlineNotice tone="error" message={submitError} />}
              {workerMessage && <InlineNotice tone="neutral" message={workerMessage} />}

              <button
                type="submit"
                disabled={submitting}
                className="inline-flex h-11 w-full items-center justify-center bg-white px-4 text-sm font-medium text-black disabled:opacity-60"
              >
                {submitting ? "Creating..." : "Create run"}
              </button>
            </form>

            <div className="border-t border-zinc-800 p-4 text-sm">
              <dl className="grid grid-cols-2 gap-3">
                <Stat label="total" value={String(counts.total)} />
                <Stat label="active" value={String(counts.pending + counts.running)} />
                <Stat label="done" value={String(counts.done)} />
                <Stat label="failed" value={String(counts.failed + counts.rejected)} />
              </dl>
            </div>
          </aside>

          <section className="border border-zinc-800">
            <SectionTitle title="Queue" subtitle="Recent runs" action={runsLoading ? "Loading..." : `${runs.length} loaded`} />
            <div className="max-h-[calc(100vh-12rem)] overflow-auto">
              {runs.length === 0 ? (
                <EmptyState message="No runs yet." />
              ) : (
                runs.map((run) => (
                  <button
                    key={run.id}
                    type="button"
                    onClick={() => loadRunById(run.id)}
                    className={cn(
                      "grid w-full gap-2 border-b border-zinc-800 px-4 py-3 text-left hover:bg-zinc-900",
                      selectedRun?.id === run.id && "bg-zinc-900",
                    )}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-white">#{run.id}</span>
                          <span className={cn("border px-2 py-0.5 text-[11px] uppercase tracking-wide", toneForRunStatus(run.status))}>
                            {run.status}
                          </span>
                        </div>
                        <p className="mt-1 truncate text-sm text-zinc-300">{run.input_ref}</p>
                      </div>
                      <span className="text-xs text-zinc-500">{run.kind}</span>
                    </div>
                    <div className="flex items-center justify-between gap-3 text-xs text-zinc-500">
                      <span>{run.stage || "No stage"}</span>
                      <span>{formatDateTime(run.created_at)}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </section>

          <section className="border border-zinc-800">
            <SectionTitle
              title={selectedRun ? `Run #${selectedRun.id}` : "Run detail"}
              subtitle={selectedRun ? selectedRun.input_ref : "Select a run"}
              action={selectedRunLoading ? "Refreshing..." : selectedRun?.kind}
            />

            {!selectedRun ? (
              <EmptyState message="Select a run from the queue." />
            ) : (
              <div className="grid gap-0">
                <Subsection title="Health">
                  <HealthPanel report={health} loading={healthLoading} />
                </Subsection>

                <Subsection title="Run metadata">
                  <dl className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
                    <Meta label="status" value={selectedRun.status} />
                    <Meta label="stage" value={selectedRun.stage || "—"} />
                    <Meta label="kind" value={selectedRun.kind} />
                    <Meta label="created" value={formatDateTime(selectedRun.created_at)} />
                    <Meta label="started" value={formatDateTime(selectedRun.started_at)} />
                    <Meta label="finished" value={formatDateTime(selectedRun.finished_at)} />
                  </dl>
                  {selectedRun.error_text && (
                    <div className="mt-4 border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
                      {selectedRun.error_text}
                    </div>
                  )}
                </Subsection>

                {selectedRun.kind === "k8s_manifest" && (
                  <Subsection title="Decision">
                    <JsonBlock value={decision} />
                  </Subsection>
                )}

                <Subsection title="Findings">
                  {findingsSections.length === 0 ? (
                    <EmptyState message="No findings yet." compact />
                  ) : (
                    <div className="space-y-5">
                      {findingsSections.map((section) => (
                        <FindingsSectionView key={section.key} section={section} />
                      ))}
                    </div>
                  )}
                </Subsection>
              </div>
            )}
          </section>
        </section>
      </main>
    </div>
  );
}

function SectionTitle({ title, subtitle, action }: { title: string; subtitle: string; action?: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-zinc-800 p-4">
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-zinc-300">{title}</h2>
        <p className="mt-1 text-sm text-zinc-500">{subtitle}</p>
      </div>
      {action && <div className="shrink-0 text-xs text-zinc-500">{action}</div>}
    </div>
  );
}

function Subsection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-zinc-800 last:border-b-0">
      <div className="border-b border-zinc-800 px-4 py-3 text-xs uppercase tracking-[0.18em] text-zinc-500">{title}</div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="mb-2 text-xs uppercase tracking-[0.18em] text-zinc-500">{label}</div>
      {children}
    </label>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</dt>
      <dd className="mt-1 text-lg font-semibold text-white">{value}</dd>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</dt>
      <dd className="mt-1 break-words text-sm text-zinc-200">{value}</dd>
    </div>
  );
}

function EmptyState({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={cn("text-sm text-zinc-500", compact ? "p-0" : "p-4")}>{message}</div>;
}

function InlineNotice({ tone, message }: { tone: "success" | "error" | "neutral"; message: string }) {
  const styles =
    tone === "success"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
      : tone === "error"
        ? "border-rose-500/30 bg-rose-500/10 text-rose-200"
        : "border-zinc-700 bg-zinc-900 text-zinc-300";

  return <div className={cn("border p-3 text-sm", styles)}>{message}</div>;
}

function HealthPanel({ report, loading }: { report: HealthReport | null; loading: boolean }) {
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
        <span className={cn("inline-flex border px-2 py-1 text-xs uppercase tracking-wide", toneForCheck(report.status || (report.ok ? "pass" : "fail")))}>
          {report.ok ? "healthy" : "degraded"}
        </span>
        {report.service && <span className="text-zinc-400">{report.service}</span>}
      </div>

      {report.worker && (
        <div className="border border-zinc-800 p-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-white">Worker</p>
              <p className="text-sm text-zinc-400">{report.worker.summary}</p>
            </div>
            <span className={cn("inline-flex border px-2 py-1 text-xs uppercase tracking-wide", toneForCheck(report.worker.status))}>
              {report.worker.status}
            </span>
          </div>
          {Array.isArray(report.worker.workers) && report.worker.workers.length > 0 && (
            <div className="mt-3 space-y-2">
              {report.worker.workers.map((worker) => (
                <div key={worker.worker_id} className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800 pt-2 text-xs text-zinc-500 first:border-t-0 first:pt-0">
                  <span>{worker.worker_id}</span>
                  <span>pid {worker.pid ?? "?"}</span>
                  <span>{worker.status ?? "unknown"}</span>
                  <span>{worker.current_run_id ? `run #${worker.current_run_id}` : "idle"}</span>
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
                <p className="mt-1 text-sm text-zinc-400">{check.error || check.summary}</p>
              </div>
              <span className={cn("inline-flex border px-2 py-1 text-xs uppercase tracking-wide", toneForCheck(check.status))}>
                {check.status}
              </span>
            </div>
            {Array.isArray(check.missing) && check.missing.length > 0 && (
              <div className="mt-2 text-xs text-amber-300">Missing: {check.missing.join(", ")}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsSectionView({ section }: { section: FindingsSection }) {
  if (section.kind === "semgrep") {
    return <SemgrepFindings title={section.title} items={section.items} raw={section.raw} />;
  }

  if (section.kind === "trivy") {
    return <TrivyFindings title={section.title} items={section.items} raw={section.raw} />;
  }

  return <GenericFindings title={section.title} raw={section.raw} count={section.items.length} />;
}

function SemgrepFindings({ title, items, raw }: { title: string; items: unknown[]; raw: unknown }) {
  const rows = Array.isArray(items) ? items : [];

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">{rows.length} results</span>
      </div>

      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {rows.map((entry, index) => {
            const item = (entry ?? {}) as Record<string, any>;
            const severity = item.extra?.severity ?? item.severity ?? "unknown";
            const message = item.extra?.message ?? item.message ?? item.check_id ?? "Semgrep finding";
            const path = item.path ?? item.location?.path ?? "unknown";
            const line = item.start?.line ?? item.line ?? "?";

            return (
              <div key={`${item.check_id || "semgrep"}-${index}`} className="border border-zinc-800 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">{severity}</span>
                  <span className="text-xs text-zinc-500">{item.check_id || "rule"}</span>
                </div>
                <p className="mt-2 text-sm text-white">{message}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span>{path}</span>
                  <span>line {line}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function TrivyFindings({ title, items, raw }: { title: string; items: unknown[]; raw: unknown }) {
  const rows = flattenTrivy(items);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">{rows.length} misconfigurations</span>
      </div>

      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {rows.map((entry, index) => {
            const item = entry as Record<string, any>;
            const severity = item.Severity ?? item.severity ?? "unknown";
            const titleText = item.Title ?? item.title ?? item.Message ?? item.message ?? item.ID ?? item.id ?? "Trivy finding";
            const id = item.ID ?? item.AVDID ?? item.id ?? "rule";
            const target = item.target ?? item.Target ?? "unknown";

            return (
              <div key={`${id}-${index}`} className="border border-zinc-800 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">{severity}</span>
                  <span className="text-xs text-zinc-500">{id}</span>
                </div>
                <p className="mt-2 text-sm text-white">{titleText}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span>{target}</span>
                  {item.Resolution && <span>{item.Resolution}</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function GenericFindings({ title, raw, count }: { title: string; raw: unknown; count: number }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">{count} items</span>
      </div>
      <JsonBlock value={raw} />
    </div>
  );
}

function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="overflow-auto border border-zinc-800 bg-black p-3 text-xs leading-6 text-emerald-200">
      <code>{prettyJson(value)}</code>
    </pre>
  );
}

export default App;
