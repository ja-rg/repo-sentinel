import React, { useEffect, useMemo, useRef, useState } from "react";

type RunKind = "repo" | "archive" | "dockerfile" | "image" | "k8s_manifest";
type RunStatus = "pending" | "running" | "done" | "failed" | "rejected";

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

type HealthReport = {
  ok: boolean;
  [key: string]: unknown;
};

const API_BASE = "http://localhost:3000";

const kindMeta: Record<
  RunKind,
  {
    label: string;
    description: string;
    mode: "text" | "file";
    placeholder?: string;
    accept?: string;
  }
> = {
  repo: {
    label: "Git Repository",
    description:
      "Clone and analyze a remote repository with Semgrep, Trivy, and Gitleaks-style workflows.",
    mode: "text",
    placeholder: "https://github.com/org/repo.git",
  },
  archive: {
    label: "Archived Project",
    description:
      "Upload a project archive and process it as a static codebase snapshot.",
    mode: "file",
    accept: ".zip,.tar,.tgz,.tar.gz",
  },
  dockerfile: {
    label: "Dockerfile",
    description:
      "Upload a Dockerfile and inspect build-time security posture and container risk indicators.",
    mode: "file",
    accept: "Dockerfile",
  },
  image: {
    label: "Container Image",
    description:
      "Scan a container image reference directly, such as nginx:latest or ghcr.io/acme/app:1.2.0.",
    mode: "text",
    placeholder: "nginx:latest",
  },
  k8s_manifest: {
    label: "Kubernetes Manifest",
    description:
      "Upload a manifest, evaluate it before deployment, optionally expose it, then probe dynamically.",
    mode: "file",
    accept: ".yaml,.yml,.json",
  },
};

function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? "";
  } catch {
    return String(value);
  }
}
function parsePossiblyJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function statusTone(status: RunStatus) {
  switch (status) {
    case "done":
      return "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30";
    case "running":
      return "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30";
    case "failed":
      return "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30";
    case "rejected":
      return "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30";
    case "pending":
    default:
      return "bg-zinc-500/15 text-zinc-300 ring-1 ring-zinc-500/30";
  }
}

function kindBadgeTone(kind: RunKind) {
  switch (kind) {
    case "repo":
      return "bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30";
    case "archive":
      return "bg-fuchsia-500/15 text-fuchsia-300 ring-1 ring-fuchsia-500/30";
    case "dockerfile":
      return "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30";
    case "image":
      return "bg-indigo-500/15 text-indigo-300 ring-1 ring-indigo-500/30";
    case "k8s_manifest":
      return "bg-teal-500/15 text-teal-300 ring-1 ring-teal-500/30";
    default:
      return "bg-zinc-500/15 text-zinc-300 ring-1 ring-zinc-500/30";
  }
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

  const currentMeta = kindMeta[kind];

  useEffect(() => {
    selectedRunIdRef.current = selectedRun?.id ?? null;
  }, [selectedRun]);

  async function loadHealth() {
    setHealthLoading(true);
    try {
      const res = await fetch(`${API_BASE}/health`);
      const data = await res.json();
      setHealth(data);
    } catch {
      setHealth({ ok: false, error: "Could not reach backend" });
    } finally {
      setHealthLoading(false);
    }
  }

  async function loadRuns() {
    setRunsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/analysis-runs?limit=20`);
      const data = await res.json();
      setRuns(data);
      const selectedRunId = selectedRunIdRef.current;
      const hasSelectedRun =
        Array.isArray(data) &&
        selectedRunId !== null &&
        data.some((run: AnalysisRun) => run.id === selectedRunId);

      if (selectedRunId === null && Array.isArray(data) && data.length > 0) {
        setSelectedRun(data[0]);
      } else if (!hasSelectedRun && Array.isArray(data) && data.length > 0) {
        setSelectedRun(data[0]);
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
    } catch {
      // keep current selection if fetch fails
    } finally {
      setSelectedRunLoading(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setSubmitMessage(null);
    setSubmitError(null);

    try {
      let res: Response;

      if (currentMeta.mode === "text") {
        if (!inputRef.trim()) {
          throw new Error("A reference is required for this analysis type.");
        }

        res = await fetch(`${API_BASE}/analysis-runs`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            kind,
            input_ref: inputRef.trim(),
          }),
        });
      } else {
        if (!file) {
          throw new Error("A file is required for this analysis type.");
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

      setSubmitMessage(`Run #${data.id} created successfully.`);
      setInputRef("");
      setFile(null);

      await loadRuns();
      await loadRunById(data.id);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Unknown error.");
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
    }, 5000);

    return () => window.clearInterval(interval);
  }, []);

  const selectedFindings = useMemo(
    () => parsePossiblyJson(selectedRun?.findings_json),
    [selectedRun]
  );

  const selectedDecision = useMemo(
    () => parsePossiblyJson(selectedRun?.decision_json),
    [selectedRun]
  );

  const runCounts = useMemo(() => {
    const counts: Record<RunStatus, number> = {
      pending: 0,
      running: 0,
      done: 0,
      failed: 0,
      rejected: 0,
    };

    for (const run of runs) {
      counts[run.status] += 1;
    }

    return counts;
  }, [runs]);

  return (
    <div className="min-h-screen bg-[#050816] text-zinc-100">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.18),transparent_28%),radial-gradient(circle_at_top_right,rgba(139,92,246,0.18),transparent_24%),radial-gradient(circle_at_bottom,rgba(16,185,129,0.12),transparent_35%)]" />

      <main className="mx-auto max-w-7xl px-6 py-8 lg:px-10">
        <section className="overflow-hidden rounded-3xl border border-white/10 bg-white/5 shadow-2xl shadow-black/30 backdrop-blur">
          <div className="grid gap-8 px-6 py-8 lg:grid-cols-[1.2fr_0.8fr] lg:px-10 lg:py-10">
            <div>
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-sky-400/20 bg-sky-400/10 px-3 py-1 text-xs font-medium uppercase tracking-[0.24em] text-sky-300">
                Sentinel
                <span className="h-1.5 w-1.5 rounded-full bg-sky-300" />
                Security orchestration
              </div>

              <h1 className="max-w-3xl text-4xl font-semibold tracking-tight text-white md:text-5xl">
                Unified static and deployment-aware analysis for repositories,
                images, Dockerfiles, and Kubernetes manifests.
              </h1>

              <p className="mt-4 max-w-2xl text-base leading-7 text-zinc-300 md:text-lg">
                Sentinel submits analysis jobs to your backend, lets workers
                process them asynchronously, and surfaces findings, execution
                state, and decisions in a single operator-facing console.
              </p>

              <div className="mt-8 grid gap-4 sm:grid-cols-3">
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <p className="text-sm text-zinc-400">Backend health</p>
                  <div className="mt-2 flex items-center gap-3">
                    <span
                      className={cn(
                        "h-3 w-3 rounded-full",
                        health?.ok ? "bg-emerald-400" : "bg-rose-400"
                      )}
                    />
                    <span className="text-lg font-semibold">
                      {healthLoading
                        ? "Checking..."
                        : health?.ok
                          ? "Operational"
                          : "Unavailable"}
                    </span>
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <p className="text-sm text-zinc-400">Queued and active</p>
                  <p className="mt-2 text-3xl font-semibold text-white">
                    {runCounts.pending + runCounts.running}
                  </p>
                  <p className="mt-1 text-sm text-zinc-400">
                    pending {runCounts.pending} · running {runCounts.running}
                  </p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <p className="text-sm text-zinc-400">Completed</p>
                  <p className="mt-2 text-3xl font-semibold text-white">
                    {runCounts.done}
                  </p>
                  <p className="mt-1 text-sm text-zinc-400">
                    failed {runCounts.failed} · rejected {runCounts.rejected}
                  </p>
                </div>
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-black/25 p-5">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-white">
                  Pipeline coverage
                </h2>
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-zinc-300">
                  worker-driven
                </span>
              </div>

              <div className="mt-5 space-y-3">
                {[
                  "Repository and archive ingestion",
                  "Semgrep, Trivy, secrets, and code hygiene checks",
                  "Dockerfile and image analysis",
                  "Pre-apply manifest gating for Kubernetes",
                  "Dynamic exposure and Nuclei validation",
                  "Decision persistence and findings retrieval",
                ].map((item) => (
                  <div
                    key={item}
                    className="flex items-start gap-3 rounded-2xl border border-white/10 bg-white/5 p-3"
                  >
                    <div className="mt-1 h-2.5 w-2.5 rounded-full bg-sky-300" />
                    <p className="text-sm leading-6 text-zinc-200">{item}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="mt-8 grid gap-8 xl:grid-cols-[420px_minmax(0,1fr)]">
          <div className="space-y-8">
            <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur">
              <div className="mb-5">
                <h2 className="text-xl font-semibold text-white">
                  Start a new analysis run
                </h2>
                <p className="mt-1 text-sm text-zinc-400">
                  Submit source material to the backend and let workers pick it
                  up from the queue.
                </p>
              </div>

              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label className="mb-2 block text-sm font-medium text-zinc-300">
                    Analysis type
                  </label>
                  <div className="grid grid-cols-1 gap-2">
                    {(Object.keys(kindMeta) as RunKind[]).map((item) => (
                      <button
                        key={item}
                        type="button"
                        onClick={() => {
                          setKind(item);
                          setInputRef("");
                          setFile(null);
                          setSubmitError(null);
                          setSubmitMessage(null);
                        }}
                        className={cn(
                          "rounded-2xl border p-3 text-left transition",
                          kind === item
                            ? "border-sky-400/40 bg-sky-400/10"
                            : "border-white/10 bg-black/20 hover:border-white/20 hover:bg-white/5"
                        )}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-medium text-white">
                            {kindMeta[item].label}
                          </span>
                          <span
                            className={cn(
                              "rounded-full px-2.5 py-1 text-xs capitalize",
                              kindBadgeTone(item)
                            )}
                          >
                            {item.replace("_", " ")}
                          </span>
                        </div>
                        <p className="mt-2 text-sm leading-6 text-zinc-400">
                          {kindMeta[item].description}
                        </p>
                      </button>
                    ))}
                  </div>
                </div>

                {currentMeta.mode === "text" ? (
                  <div>
                    <label className="mb-2 block text-sm font-medium text-zinc-300">
                      Reference
                    </label>
                    <input
                      value={inputRef}
                      onChange={(e) => setInputRef(e.target.value)}
                      placeholder={currentMeta.placeholder}
                      className="w-full rounded-2xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none ring-0 placeholder:text-zinc-500 focus:border-sky-400/40"
                    />
                  </div>
                ) : (
                  <>
                    <div>
                      <label className="mb-2 block text-sm font-medium text-zinc-300">
                        File upload
                      </label>
                      <input
                        type="file"
                        accept={currentMeta.accept}
                        onChange={(e) =>
                          setFile(e.target.files?.[0] ?? null)
                        }
                        className="block w-full rounded-2xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-zinc-300 file:mr-4 file:rounded-xl file:border-0 file:bg-sky-400/15 file:px-3 file:py-2 file:text-sm file:font-medium file:text-sky-300"
                      />
                    </div>

                    <div>
                      <label className="mb-2 block text-sm font-medium text-zinc-300">
                        Display reference
                      </label>
                      <input
                        value={inputRef}
                        onChange={(e) => setInputRef(e.target.value)}
                        placeholder="Optional name shown as input_ref"
                        className="w-full rounded-2xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-sky-400/40"
                      />
                    </div>
                  </>
                )}

                {submitMessage && (
                  <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
                    {submitMessage}
                  </div>
                )}

                {submitError && (
                  <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
                    {submitError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={submitting}
                  className="inline-flex w-full items-center justify-center rounded-2xl bg-sky-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-sky-300 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {submitting ? "Submitting run..." : "Create analysis run"}
                </button>
              </form>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold text-white">
                  Execution model
                </h2>
                <button
                  onClick={() => {
                    loadHealth();
                    loadRuns();
                    if (selectedRun?.id) loadRunById(selectedRun.id);
                  }}
                  className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-zinc-300 hover:bg-white/10"
                >
                  Refresh
                </button>
              </div>

              <div className="mt-5 space-y-3 text-sm text-zinc-300">
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <p className="font-medium text-white">1. Ingestion</p>
                  <p className="mt-1 text-zinc-400">
                    The API accepts a repo reference or uploaded artifact and
                    inserts a pending run into SQLite.
                  </p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <p className="font-medium text-white">2. Polling worker</p>
                  <p className="mt-1 text-zinc-400">
                    Workers claim the next pending run and execute the proper
                    processor by run kind.
                  </p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <p className="font-medium text-white">3. Result materialization</p>
                  <p className="mt-1 text-zinc-400">
                    Findings, decisions, stage progression, and terminal state
                    are written back for operator review.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-8">
            <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-white">
                    Recent analysis runs
                  </h2>
                  <p className="mt-1 text-sm text-zinc-400">
                    Live view of the queue and completed jobs.
                  </p>
                </div>
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-zinc-300">
                  {runs.length} loaded
                </span>
              </div>

              <div className="mt-5 overflow-hidden rounded-2xl border border-white/10">
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-white/10 text-sm">
                    <thead className="bg-black/20 text-zinc-400">
                      <tr>
                        <th className="px-4 py-3 text-left font-medium">Run</th>
                        <th className="px-4 py-3 text-left font-medium">Kind</th>
                        <th className="px-4 py-3 text-left font-medium">Input</th>
                        <th className="px-4 py-3 text-left font-medium">Status</th>
                        <th className="px-4 py-3 text-left font-medium">Stage</th>
                        <th className="px-4 py-3 text-left font-medium">Created</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/10 bg-white/[0.02]">
                      {runsLoading ? (
                        <tr>
                          <td
                            colSpan={6}
                            className="px-4 py-6 text-center text-zinc-400"
                          >
                            Loading runs...
                          </td>
                        </tr>
                      ) : runs.length === 0 ? (
                        <tr>
                          <td
                            colSpan={6}
                            className="px-4 py-6 text-center text-zinc-400"
                          >
                            No runs yet.
                          </td>
                        </tr>
                      ) : (
                        runs.map((run) => (
                          <tr
                            key={run.id}
                            onClick={() => loadRunById(run.id)}
                            className={cn(
                              "cursor-pointer transition hover:bg-white/[0.04]",
                              selectedRun?.id === run.id && "bg-sky-400/5"
                            )}
                          >
                            <td className="px-4 py-3 font-medium text-white">
                              #{run.id}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={cn(
                                  "rounded-full px-2.5 py-1 text-xs capitalize",
                                  kindBadgeTone(run.kind)
                                )}
                              >
                                {run.kind.replace("_", " ")}
                              </span>
                            </td>
                            <td className="max-w-[240px] truncate px-4 py-3 text-zinc-300">
                              {run.input_ref}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={cn(
                                  "rounded-full px-2.5 py-1 text-xs capitalize",
                                  statusTone(run.status)
                                )}
                              >
                                {run.status}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-zinc-300">
                              {run.stage || "—"}
                            </td>
                            <td className="px-4 py-3 text-zinc-400">
                              {run.created_at}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="grid gap-8">
              <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-semibold text-white">
                      Run details
                    </h2>
                    <p className="mt-1 text-sm text-zinc-400">
                      Selected analysis record and terminal metadata.
                    </p>
                  </div>
                  {selectedRunLoading && (
                    <span className="text-sm text-zinc-400">Refreshing...</span>
                  )}
                </div>

                {selectedRun ? (
                  <div className="mt-5 space-y-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Run id
                        </p>
                        <p className="mt-2 text-lg font-semibold text-white">
                          #{selectedRun.id}
                        </p>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Status
                        </p>
                        <div className="mt-2">
                          <span
                            className={cn(
                              "rounded-full px-2.5 py-1 text-xs capitalize",
                              statusTone(selectedRun.status)
                            )}
                          >
                            {selectedRun.status}
                          </span>
                        </div>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4 sm:col-span-2">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Input reference
                        </p>
                        <p className="mt-2 break-all text-sm text-zinc-200">
                          {selectedRun.input_ref}
                        </p>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Stage
                        </p>
                        <p className="mt-2 text-sm text-zinc-200">
                          {selectedRun.stage || "—"}
                        </p>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Kind
                        </p>
                        <p className="mt-2 text-sm text-zinc-200">
                          {selectedRun.kind}
                        </p>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Started
                        </p>
                        <p className="mt-2 text-sm text-zinc-200">
                          {selectedRun.started_at || "—"}
                        </p>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-wide text-zinc-500">
                          Finished
                        </p>
                        <p className="mt-2 text-sm text-zinc-200">
                          {selectedRun.finished_at || "—"}
                        </p>
                      </div>
                    </div>

                    {selectedRun.error_text && (
                      <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 p-4">
                        <p className="text-sm font-medium text-rose-300">
                          Error
                        </p>
                        <p className="mt-2 whitespace-pre-wrap text-sm text-rose-200">
                          {selectedRun.error_text}
                        </p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-6 text-sm text-zinc-400">
                    Select a run to inspect findings and decisions.
                  </div>
                )}
              </div>

              <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur">
                <div>
                  <h2 className="text-xl font-semibold text-white">
                    Findings and decision payloads
                  </h2>
                  <p className="mt-1 text-sm text-zinc-400">
                    Raw backend material for rendering scanners, evidence, and
                    allow-or-block decisions.
                  </p>
                </div>

                <div className="mt-5 grid gap-5">
                  {selectedRun?.kind === "k8s_manifest" && (
                    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                      <div className="mb-3 flex items-center justify-between">
                        <h3 className="font-medium text-white">Decision JSON</h3>
                        <span className="text-xs text-zinc-500">
                          execution verdict
                        </span>
                      </div>
                      <div className="max-h-[260px] overflow-auto rounded-xl bg-[#02040b] p-4 text-xs leading-6 text-emerald-200">
                        <code className="block whitespace-pre-wrap break-words font-mono">
                          {prettyJson(selectedDecision)}
                        </code>
                      </div>
                    </div>
                  )}

                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <h3 className="font-medium text-white">Findings JSON</h3>
                      <span className="text-xs text-zinc-500">
                        scanner outputs
                      </span>
                    </div>
                    <div className="space-y-4">
                      {selectedFindings !== null &&
                        selectedFindings !== undefined &&
                        typeof selectedFindings === "object" &&
                        !Array.isArray(selectedFindings) &&
                        Object.entries(selectedFindings as Record<string, unknown>).map(
                          ([key, value]) => (
                            <div key={key}>
                              <div className="mb-2 flex items-center justify-between">
                                <h4 className="text-sm font-medium text-white">{key}</h4>
                                <span className="text-xs text-zinc-500">
                                  {Array.isArray(value)
                                    ? `${value.length} items`
                                    : value !== null && typeof value === "object"
                                      ? "object"
                                      : typeof value}
                                </span>
                              </div>
                              <div className="max-h-[200px] overflow-auto rounded-xl bg-[#02040b] p-4 text-xs leading-6 text-emerald-200">
                                <code className="block whitespace-pre-wrap break-words font-mono">
                                  {prettyJson(value)}
                                </code>
                              </div>
                            </div>
                          )
                        )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;