import React, { useEffect, useMemo, useRef, useState } from "react";
import type {
  RunKind,
  AnalysisRun,
  HealthReport,
  ToolName,
  ToolOptions,
  RunCommand,
} from "./types";

interface RunLog {
  id: number;
  run_id: number;
  created_at: string;
  level: "debug" | "info" | "warn" | "error";
  stage: string | null;
  message: string;
  details_json: unknown;
}

import { cn, parseJson } from "./utilities/json";
import { formatDateTime, toneForRunStatus } from "./utilities/format";
import { FindingsSectionView, DecisionView } from "./components/findings";
import { normalizeHealth, normalizeFindings } from "./utilities/normalization";
import {
  HealthPanel,
  InlineNotice,
  Stat,
  EmptyState,
  Meta,
} from "./components/meta";
import { Subsection, SectionTitle, Field } from "./components/sections";

const API_BASE = "http://localhost:2002";
const POLL_MS = 5000;
const TOOL_DEFAULTS: Record<
  ToolName,
  { image: string; command: string[] }
> = {
  semgrep: { image: "semgrep/semgrep:latest", command: ["semgrep", "--config", "auto", "--json", "--no-git-ignore"] },
  trivy: { image: "aquasec/trivy:canary", command: ["--quiet", "--format", "json"] },
  gitleaks: { image: "zricethezav/gitleaks:latest", command: ["detect", "--report-format", "json", "--report-path", "-", "--no-banner", "--no-git"] },
  syft: { image: "anchore/syft:latest", command: ["-o", "cyclonedx-json"] },
  grype: { image: "anchore/grype:latest", command: ["-o", "json"] },
  nuclei: { image: "projectdiscovery/nuclei:latest", command: ["-jsonl", "-silent"] },
};
const TOOLS_BY_KIND: Record<RunKind, ToolName[]> = {
  repo: ["semgrep", "trivy", "gitleaks", "syft"],
  archive: ["semgrep", "trivy", "gitleaks", "syft"],
  dockerfile: ["semgrep", "trivy"],
  image: ["trivy", "syft", "grype"],
  k8s_manifest: ["semgrep", "trivy", "nuclei"],
  k8s_service: ["nuclei"],
};

const kindMeta: Record<
  RunKind,
  {
    mode: "text" | "file";
    placeholder?: string;
    accept?: string;
    label: string;
  }
> = {
  repo: {
    mode: "text",
    placeholder: "github.com/owner/repo",
    label: "Repository",
  },
  k8s_manifest: {
    mode: "file",
    accept: ".yaml,.yml,.json",
    label: "K8s Manifest",
  },
  k8s_service: {
    mode: "text",
    placeholder: "http://service.namespace.svc.cluster.local:80",
    label: "K8s Service URL",
  },
  archive: {
    mode: "file",
    accept: ".zip,.tar,.tar.gz",
    label: "Archive",
  },
  dockerfile: {
    mode: "file",
    accept: ".dockerfile",
    label: "Dockerfile",
  },
  image: {
    mode: "text",
    placeholder: "image:tag",
    label: "Image",
  },
};

function getRunCounts(runs: AnalysisRun[]) {
  return {
    total: runs.length,
    pending: runs.filter((r) => r.status === "pending").length,
    running: runs.filter((r) => r.status === "running").length,
    done: runs.filter((r) => r.status === "done").length,
    failed: runs.filter((r) => r.status === "failed").length,
    rejected: runs.filter((r) => r.status === "rejected").length,
  };
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

  const [runLogs, setRunLogs] = useState<RunLog[]>([]);
  const [runCommands, setRunCommands] = useState<RunCommand[]>([]);
  const [verboseCommands, setVerboseCommands] = useState(false);
  const [enabledTools, setEnabledTools] = useState<Partial<Record<ToolName, boolean>>>({});
  const [extraArgsByTool, setExtraArgsByTool] = useState<Partial<Record<ToolName, string>>>({});
  const [customCommandByTool, setCustomCommandByTool] = useState<Partial<Record<ToolName, string>>>({});
  const [imageByTool, setImageByTool] = useState<Partial<Record<ToolName, string>>>({});

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
        data.find((run) => run.id === selectedRunId) ?? data[0] ?? null;

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
      const [runRes, logsRes, commandsRes] = await Promise.all([
        fetch(`${API_BASE}/analysis-runs/${id}`),
        fetch(`${API_BASE}/analysis-runs/${id}/logs`),
        fetch(`${API_BASE}/analysis-runs/${id}/commands`),
      ]);
      const runData = await runRes.json();
      const logsData = await logsRes.json();
      const commandsData = await commandsRes.json();
      setSelectedRun(runData);
      setRunLogs(Array.isArray(logsData) ? logsData : []);
      setRunCommands(Array.isArray(commandsData) ? commandsData : []);
    } finally {
      setSelectedRunLoading(false);
    }
  }

  async function loadRunLogs(id: number) {
    const res = await fetch(`${API_BASE}/analysis-runs/${id}/logs`);
    const data = await res.json();
    setRunLogs(Array.isArray(data) ? data : []);
  }

  async function loadRunCommands(id: number) {
    const res = await fetch(`${API_BASE}/analysis-runs/${id}/commands`);
    const data = await res.json();
    setRunCommands(Array.isArray(data) ? data : []);
  }

  function buildToolOptionsPayload(): ToolOptions {
    const tools = TOOLS_BY_KIND[kind];
    const enabled = tools.filter((tool) => enabledTools[tool] !== false);
    const overrides: NonNullable<ToolOptions["overrides"]> = {};

    for (const tool of tools) {
      const image = imageByTool[tool]?.trim();
      const extraArgsRaw = extraArgsByTool[tool]?.trim();
      const customRaw = customCommandByTool[tool]?.trim();

      const extraArgs = extraArgsRaw ? extraArgsRaw.split(/\s+/).filter(Boolean) : undefined;
      const command = customRaw ? customRaw.split(/\s+/).filter(Boolean) : undefined;

      if (image || (extraArgs && extraArgs.length > 0) || (command && command.length > 0)) {
        overrides[tool] = {
          image,
          extra_args: extraArgs,
          command,
        };
      }
    }

    return {
      enabled_tools: enabled,
      overrides: Object.keys(overrides).length ? overrides : undefined,
      verbose_commands: verboseCommands,
    };
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
      setWorkerMessage(
        error instanceof Error ? error.message : "Could not ensure worker",
      );
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
      const toolOptions = buildToolOptionsPayload();

      if (currentMeta.mode === "text") {
        if (!inputRef.trim()) {
          throw new Error("Reference is required.");
        }

        res = await fetch(`${API_BASE}/analysis-runs`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind, input_ref: inputRef.trim(), tool_options: toolOptions }),
        });
      } else {
        if (!file) {
          throw new Error("File is required.");
        }

        const formData = new FormData();
        formData.append("kind", kind);
        formData.append("file", file);
        formData.append("input_ref", inputRef.trim() || file.name);
        formData.append("tool_options", JSON.stringify(toolOptions));

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
      await loadRunCommands(data.id);
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
        loadRunLogs(selectedRunIdRef.current);
        loadRunCommands(selectedRunIdRef.current);
      }
    }, POLL_MS);

    return () => window.clearInterval(interval);
  }, []);

  const counts = useMemo(() => getRunCounts(runs), [runs]);
  const findingsSections = useMemo(
    () => normalizeFindings(selectedRun?.findings_json),
    [selectedRun],
  );
  const decision = useMemo(
    () => parseJson(selectedRun?.decision_json),
    [selectedRun],
  );
  const commandPreview = useMemo(() => {
    const options = buildToolOptionsPayload();
    return TOOLS_BY_KIND[kind]
      .filter((tool) => options.enabled_tools?.includes(tool) ?? true)
      .map((tool) => {
        const defaults = TOOL_DEFAULTS[tool];
        const override = options.overrides?.[tool];
        const image = override?.image || defaults.image;
        const cmd = override?.command?.length
          ? override.command
          : [...defaults.command, ...(override?.extra_args ?? [])];
        return `${tool}: docker run --rm ${image} ${cmd.join(" ")}`;
      });
  }, [kind, enabledTools, extraArgsByTool, customCommandByTool, imageByTool, verboseCommands]);
  const manifestFindingsJson = useMemo(
    () => parseJson(selectedRun?.findings_json),
    [selectedRun?.findings_json],
  );

  function downloadManifestFindings() {
    if (!selectedRun || selectedRun.kind !== "k8s_manifest") return;

    const pretty = JSON.stringify(manifestFindingsJson ?? null, null, 2);
    const blob = new Blob([pretty], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `run-${selectedRun.id}-k8s-manifest-findings.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  function downloadRunCommandLogs() {
    if (!selectedRun) return;
    const pretty = JSON.stringify(runCommands, null, 2);
    const blob = new Blob([pretty], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `run-${selectedRun.id}-command-logs.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <main className="mx-auto max-w-7xl px-4 py-4 sm:px-6 lg:px-8">
        <header className="border border-zinc-800 bg-zinc-950">
          <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
            <div>
              <p className="text-xs uppercase tracking-[0.24em] text-zinc-500">
                RepoSentinel
              </p>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                Security console
              </h1>
              <p className="mt-1 max-w-3xl text-sm text-zinc-400">
                One page, one queue, one selected run. No marketing blocks. No
                oversized cards. Findings stay structured.
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
          <Subsection title="Health">
            <HealthPanel report={health} loading={healthLoading} />
          </Subsection>
        </header>

        <section className="mt-4 grid gap-4 xl:grid-cols-[320px_360px_minmax(0,1fr)]">
          <aside className="border border-zinc-800">
            <SectionTitle
              title="New run"
              subtitle="Submit a source to the queue"
            />
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
                      setEnabledTools({});
                      setExtraArgsByTool({});
                      setCustomCommandByTool({});
                      setImageByTool({});
                    }}
                    className={cn(
                      "border px-3 py-2 text-left text-sm",
                      kind === item
                        ? "border-sky-500 bg-sky-500/10 text-sky-100"
                        : "border-zinc-800 text-zinc-300 hover:border-zinc-600",
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
                      onChange={(event) =>
                        setFile(event.target.files?.[0] ?? null)
                      }
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

              <div className="border border-zinc-800 p-3">
                <p className="text-xs uppercase tracking-[0.14em] text-zinc-500">
                  Advanced tool options
                </p>
                <label className="mt-3 flex items-center gap-2 text-sm text-zinc-300">
                  <input
                    type="checkbox"
                    checked={verboseCommands}
                    onChange={(event) => setVerboseCommands(event.target.checked)}
                    className="h-4 w-4"
                  />
                  Verbose command logging (store stdout/stderr)
                </label>

                <div className="mt-3 space-y-3">
                  {TOOLS_BY_KIND[kind].map((tool) => {
                    const enabled = enabledTools[tool] !== false;
                    return (
                      <div key={tool} className="border border-zinc-800 p-2">
                        <label className="flex items-center gap-2 text-sm text-zinc-200">
                          <input
                            type="checkbox"
                            checked={enabled}
                            onChange={(event) =>
                              setEnabledTools((prev) => ({
                                ...prev,
                                [tool]: event.target.checked,
                              }))
                            }
                            className="h-4 w-4"
                          />
                          Enable {tool}
                        </label>
                        <div className="mt-2 grid gap-2">
                          <input
                            value={imageByTool[tool] ?? ""}
                            onChange={(event) =>
                              setImageByTool((prev) => ({ ...prev, [tool]: event.target.value }))
                            }
                            placeholder="Image override (optional)"
                            className="h-9 w-full border border-zinc-800 bg-zinc-950 px-2 text-xs text-white outline-none placeholder:text-zinc-600 focus:border-sky-500"
                          />
                          <input
                            value={extraArgsByTool[tool] ?? ""}
                            onChange={(event) =>
                              setExtraArgsByTool((prev) => ({ ...prev, [tool]: event.target.value }))
                            }
                            placeholder="Extra args (space-separated)"
                            className="h-9 w-full border border-zinc-800 bg-zinc-950 px-2 text-xs text-white outline-none placeholder:text-zinc-600 focus:border-sky-500"
                          />
                          <input
                            value={customCommandByTool[tool] ?? ""}
                            onChange={(event) =>
                              setCustomCommandByTool((prev) => ({ ...prev, [tool]: event.target.value }))
                            }
                            placeholder="Custom command (space-separated, optional)"
                            className="h-9 w-full border border-zinc-800 bg-zinc-950 px-2 text-xs text-white outline-none placeholder:text-zinc-600 focus:border-sky-500"
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="mt-3">
                  <p className="text-xs uppercase tracking-[0.14em] text-zinc-500">Command preview</p>
                  <pre className="mt-2 overflow-x-auto border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-400">
                    {commandPreview.length === 0 ? "No enabled tools." : commandPreview.join("\n")}
                  </pre>
                </div>
              </div>

              {submitMessage && (
                <InlineNotice tone="success" message={submitMessage} />
              )}
              {submitError && (
                <InlineNotice tone="error" message={submitError} />
              )}
              {workerMessage && (
                <InlineNotice tone="neutral" message={workerMessage} />
              )}

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
                <Stat
                  label="active"
                  value={String(counts.pending + counts.running)}
                />
                <Stat label="done" value={String(counts.done)} />
                <Stat
                  label="failed"
                  value={String(counts.failed + counts.rejected)}
                />
              </dl>
            </div>
          </aside>

          <section className="border border-zinc-800">
            <SectionTitle
              title="Queue"
              subtitle="Recent runs"
              action={runsLoading ? "Loading..." : `${runs.length} loaded`}
            />
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
                          <span className="font-medium text-white">
                            #{run.id}
                          </span>
                          <span
                            className={cn(
                              "border px-2 py-0.5 text-[11px] uppercase tracking-wide",
                              toneForRunStatus(run.status),
                            )}
                          >
                            {run.status}
                          </span>
                        </div>
                        <p className="mt-1 truncate text-sm text-zinc-300">
                          {run.input_ref}
                        </p>
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
                <Subsection title="Run metadata">
                  <dl className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
                    <Meta label="status" value={selectedRun.status} />
                    <Meta label="stage" value={selectedRun.stage || "—"} />
                    <Meta label="kind" value={selectedRun.kind} />
                    <Meta
                      label="created"
                      value={formatDateTime(selectedRun.created_at)}
                    />
                    <Meta
                      label="started"
                      value={formatDateTime(selectedRun.started_at)}
                    />
                    <Meta
                      label="finished"
                      value={formatDateTime(selectedRun.finished_at)}
                    />
                  </dl>
                  {selectedRun.error_text && (
                    <div className="mt-4 border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
                      {selectedRun.error_text}
                    </div>
                  )}
                </Subsection>

                <Subsection title="Execution log">
                  <details className="group">
                    <summary className="cursor-pointer select-none p-3 text-sm font-medium hover:bg-zinc-900">
                      {runLogs.length === 0
                        ? "No logs yet"
                        : `${runLogs.length} log entries`}
                    </summary>
                    <div className="space-y-2 p-3">
                      {runLogs.length === 0 ? (
                        <EmptyState message="No logs yet." compact />
                      ) : (
                        runLogs.map((log) => (
                          <div
                            key={log.id}
                            className="border border-zinc-800 p-3 text-sm"
                          >
                            <div className="flex items-center justify-between gap-3 text-xs text-zinc-500">
                              <span>{log.created_at}</span>
                              <span>{log.level}</span>
                              <span>{log.stage || "—"}</span>
                            </div>
                            <p className="mt-2 text-zinc-200">{log.message}</p>
                            {log.details_json ? (
                              <pre className="mt-2 overflow-x-auto border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-400">
                                {JSON.stringify(log.details_json, null, 2)}
                              </pre>
                            ) : null}
                          </div>
                        ))
                      )}
                    </div>
                  </details>
                </Subsection>

                <Subsection title="Command executions">
                  <div className="flex justify-end pb-2">
                    <button
                      type="button"
                      onClick={downloadRunCommandLogs}
                      className="inline-flex items-center justify-center border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs uppercase tracking-[0.14em] text-zinc-200 hover:border-zinc-500 hover:bg-zinc-800"
                    >
                      Download command logs
                    </button>
                  </div>
                  {runCommands.length === 0 ? (
                    <EmptyState message="No command executions yet." compact />
                  ) : (
                    <div className="space-y-3">
                      {runCommands.map((cmd) => (
                        <details key={cmd.id} className="border border-zinc-800 p-3">
                          <summary className="cursor-pointer select-none text-sm text-zinc-200">
                            [{cmd.tool}] {cmd.status} {cmd.duration_ms ? `(${cmd.duration_ms}ms)` : ""}
                          </summary>
                          <div className="mt-2 space-y-2">
                            <p className="text-xs text-zinc-400">{cmd.stage || "—"}</p>
                            <p className="text-xs text-zinc-400">Image: {cmd.image}</p>
                            <pre className="overflow-x-auto border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-300">
                              {cmd.command_text}
                            </pre>
                            <div>
                              <p className="text-xs uppercase tracking-[0.12em] text-zinc-500">stdout</p>
                              <pre className="overflow-x-auto border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-400">
                                {cmd.stdout_text || "(empty)"}
                              </pre>
                            </div>
                            <div>
                              <p className="text-xs uppercase tracking-[0.12em] text-zinc-500">stderr</p>
                              <pre className="overflow-x-auto border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-400">
                                {cmd.stderr_text || "(empty)"}
                              </pre>
                            </div>
                          </div>
                        </details>
                      ))}
                    </div>
                  )}
                </Subsection>

                {(selectedRun.kind === "k8s_manifest" ||
                  selectedRun.kind === "k8s_service") && (
                  <Subsection title="Decision">
                    <DecisionView decision={decision} />
                  </Subsection>
                )}

                <Subsection title="Findings">
                  {findingsSections.length === 0 ? (
                    <EmptyState message="No findings yet." compact />
                  ) : (
                    <div className="space-y-5">
                      {selectedRun.kind === "k8s_manifest" && (
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={downloadManifestFindings}
                            className="inline-flex items-center justify-center border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs uppercase tracking-[0.14em] text-zinc-200 hover:border-zinc-500 hover:bg-zinc-800"
                          >
                            Download findings JSON
                          </button>
                        </div>
                      )}
                      {findingsSections.map((section) => (
                        <FindingsSectionView
                          key={section.key}
                          section={section}
                        />
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

export default App;
