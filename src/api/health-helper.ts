import { existsSync } from "node:fs";
import { delimiter } from "node:path";
import { db } from "../db";

type CheckState = "pass" | "warn" | "fail";

type HealthCheck = {
  key: string;
  label: string;
  status: CheckState;
  summary: string;
  error?: string;
  details?: unknown;
  missing?: string[];
};

type WorkerSnapshot = {
  worker_id: string;
  pid: number | null;
  status: string;
  current_run_id: number | null;
  last_seen_at: string;
  started_at: string;
};

type HealthReport = {
  ok: boolean;
  status: CheckState;
  service: string;
  database: {
    path: string;
    exists: boolean;
  };
  checks: HealthCheck[];
  worker: {
    status: CheckState;
    summary: string;
    active_workers: number;
    stale_workers: number;
    workers: WorkerSnapshot[];
  };
};

const REQUIRED_IMAGES = ["semgrep", "trivy", "grype", "nuclei", "syft"] as const;
const WORKER_FRESHNESS_SECONDS = 15;
const WORKER_STALE_SECONDS = 60;

async function runCommand(
  cmd: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string; exitCode: number | null }> {
  try {
    const proc = Bun.spawn(cmd, {
      stdout: "pipe",
      stderr: "pipe",
    });

    const [stdoutBuf, stderrBuf, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);

    return {
      ok: exitCode === 0,
      stdout: stdoutBuf.trim(),
      stderr: stderrBuf.trim(),
      exitCode,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
      exitCode: null,
    };
  }
}

function commandExists(command: string): boolean {
  const pathValue = process.env.PATH ?? "";
  const paths = pathValue.split(delimiter);

  for (const dir of paths) {
    if (!dir) continue;

    const candidate = `${dir}/${command}`;
    if (existsSync(candidate)) return true;

    const exeCandidate = `${dir}/${command}.exe`;
    if (existsSync(exeCandidate)) return true;
  }

  return false;
}

async function checkDocker(): Promise<HealthCheck> {
  if (!commandExists("docker")) {
    return {
      key: "docker",
      label: "Docker",
      status: "fail",
      summary: "docker binary not found",
      error: "docker binary not found in PATH",
    };
  }

  const result = await runCommand(["docker", "info", "--format", "json"]);
  if (!result.ok) {
    return {
      key: "docker",
      label: "Docker",
      status: "fail",
      summary: "docker daemon not reachable",
      error: result.stderr || "docker daemon not reachable",
    };
  }

  let details: unknown = result.stdout;
  try {
    details = JSON.parse(result.stdout);
  } catch {
    // keep stdout when not json
  }

  return {
    key: "docker",
    label: "Docker",
    status: "pass",
    summary: "docker daemon reachable",
    details,
  };
}

async function checkDockerImages(): Promise<HealthCheck> {
  if (!commandExists("docker")) {
    return {
      key: "docker_images",
      label: "Docker images",
      status: "fail",
      summary: "docker unavailable, cannot inspect images",
      error: "docker binary not found in PATH",
    };
  }

  const result = await runCommand(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]) ;

  if (!result.ok) {
    return {
      key: "docker_images",
      label: "Docker images",
      status: "fail",
      summary: "unable to list docker images",
      error: result.stderr || "unable to list docker images",
    };
  }

  const installed = new Set(
    result.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  );

  const imageMatches = REQUIRED_IMAGES.map((required) => {
    const found = [...installed].some((image) => {
      const repo = image.split(":")[0] ?? "";
      const shortRepo = repo.split("/").pop() ?? repo;
      return repo === required || shortRepo === required;
    });

    return { image: required, found };
  });

  const missing = imageMatches.filter((item) => !item.found).map((item) => item.image);

  if (missing.length > 0) {
    return {
      key: "docker_images",
      label: "Docker images",
      status: "fail",
      summary: `missing required images: ${missing.join(", ")}`,
      error: `missing required images: ${missing.join(", ")}`,
      details: imageMatches,
      missing,
    };
  }

  return {
    key: "docker_images",
    label: "Docker images",
    status: "pass",
    summary: "all required images are present",
    details: imageMatches,
  };
}

async function checkKubectl(): Promise<HealthCheck> {
  if (!commandExists("kubectl")) {
    return {
      key: "kubectl",
      label: "kubectl",
      status: "warn",
      summary: "kubectl binary not found",
      error: "kubectl binary not found in PATH",
    };
  }

  const result = await runCommand(["kubectl", "version", "--client", "--output=json"]);
  if (!result.ok) {
    return {
      key: "kubectl",
      label: "kubectl",
      status: "warn",
      summary: "kubectl installed but not usable",
      error: result.stderr || "kubectl not usable",
    };
  }

  let details: unknown = result.stdout;
  try {
    details = JSON.parse(result.stdout);
  } catch {
    // keep stdout when not json
  }

  return {
    key: "kubectl",
    label: "kubectl",
    status: "pass",
    summary: "kubectl client usable",
    details,
  };
}

async function checkKubernetes(): Promise<HealthCheck> {
  if (!commandExists("kubectl")) {
    return {
      key: "kubernetes",
      label: "Kubernetes cluster",
      status: "warn",
      summary: "kubectl unavailable, cluster status unknown",
      error: "kubectl binary not found in PATH",
    };
  }

  const result = await runCommand(["kubectl", "cluster-info"]);
  if (!result.ok) {
    return {
      key: "kubernetes",
      label: "Kubernetes cluster",
      status: "warn",
      summary: "kubectl present but cluster not reachable",
      error: result.stderr || "kubernetes cluster not reachable",
    };
  }

  return {
    key: "kubernetes",
    label: "Kubernetes cluster",
    status: "pass",
    summary: "cluster reachable",
    details: result.stdout,
  };
}

function buildWorkerHealth() {
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

  const workers = db.query(`
    SELECT worker_id, pid, status, current_run_id, started_at, last_seen_at
    FROM worker_heartbeats
    ORDER BY last_seen_at DESC
  `).all() as WorkerSnapshot[];

  const freshnessExpr = `(strftime('%s','now') - strftime('%s', last_seen_at))`;
  const active_workers = Number(
    (db.query(`SELECT COUNT(*) as count FROM worker_heartbeats WHERE ${freshnessExpr} <= ?1`).get(WORKER_FRESHNESS_SECONDS) as { count: number } | undefined)?.count ?? 0,
  );
  const stale_workers = Number(
    (db.query(`SELECT COUNT(*) as count FROM worker_heartbeats WHERE ${freshnessExpr} > ?1 AND ${freshnessExpr} <= ?2`).get(WORKER_FRESHNESS_SECONDS, WORKER_STALE_SECONDS) as { count: number } | undefined)?.count ?? 0,
  );

  if (active_workers > 0) {
    return {
      status: "pass" as const,
      summary: `${active_workers} active worker${active_workers === 1 ? "" : "s"}`,
      active_workers,
      stale_workers,
      workers,
    };
  }

  if (stale_workers > 0) {
    return {
      status: "warn" as const,
      summary: "no active worker heartbeat, but stale worker records exist",
      active_workers,
      stale_workers,
      workers,
    };
  }

  return {
    status: "fail" as const,
    summary: "no workers available",
    active_workers,
    stale_workers,
    workers,
  };
}

function overallStatus(checks: HealthCheck[], workerStatus: CheckState): CheckState {
  const states = [...checks.map((check) => check.status), workerStatus];
  if (states.includes("fail")) return "fail";
  if (states.includes("warn")) return "warn";
  return "pass";
}

export async function buildHealthReport(dbPath: string): Promise<HealthReport> {
  const [docker, dockerImages, kubectl, kubernetes] = await Promise.all([
    checkDocker(),
    checkDockerImages(),
    checkKubectl(),
    checkKubernetes(),
  ]);

  const checks = [docker, dockerImages, kubectl, kubernetes];
  const worker = buildWorkerHealth();
  const status = overallStatus(checks, worker.status);

  return {
    ok: status !== "fail",
    status,
    service: "reposentinel-api",
    database: {
      path: dbPath,
      exists: existsSync(dbPath),
    },
    checks,
    worker,
  };
}
