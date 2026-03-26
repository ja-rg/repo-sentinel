import { existsSync } from "node:fs";
import { delimiter } from "node:path";

type CheckStatus = "ok" | "fail";

type DependencyCheck = {
  status: CheckStatus;
  details?: unknown;
  error?: string;
};

type HealthReport = {
  ok: boolean;
  service: string;
  database: string;
  checks: {
    docker: DependencyCheck;
    docker_images: DependencyCheck;
    kubectl: DependencyCheck;
    kubernetes: DependencyCheck;
  };
};

const REQUIRED_IMAGES = ["semgrep", "trivy", "grype", "nuclei", "syft"] as const;

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
    if (existsSync(candidate)) {
      return true;
    }

    // por compatibilidad si alguna vez corre en entorno con sufijos
    const exeCandidate = `${dir}/${command}.exe`;
    if (existsSync(exeCandidate)) {
      return true;
    }
  }

  return false;
}

async function checkDocker(): Promise<DependencyCheck> {
  if (!commandExists("docker")) {
    return {
      status: "fail",
      error: "docker binary not found in PATH",
    };
  }

  const result = await runCommand(["docker", "info", "--format", "json"]);
  if (!result.ok) {
    return {
      status: "fail",
      error: result.stderr || "docker daemon not reachable",
    };
  }

  return {
    status: "ok",
    details: "docker daemon reachable",
  };
}

async function checkDockerImages(): Promise<DependencyCheck> {
  if (!commandExists("docker")) {
    return {
      status: "fail",
      error: "docker binary not found in PATH",
    };
  }

  const result = await runCommand([
    "docker",
    "images",
    "--format",
    "{{.Repository}}:{{.Tag}}",
  ]);

  if (!result.ok) {
    return {
      status: "fail",
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
    const found = [...installed].some((img) => {
      const repo = img.split(":")[0] ?? "";
      const shortRepo = repo.split("/").pop() ?? repo;
      return repo === required || shortRepo === required;
    });

    return { image: required, found };
  });

  const missing = imageMatches.filter((x) => !x.found).map((x) => x.image);

  if (missing.length > 0) {
    return {
      status: "fail",
      error: `missing images: ${missing.join(", ")}`,
      details: imageMatches,
    };
  }

  return {
    status: "ok",
    details: imageMatches,
  };
}

async function checkKubectl(): Promise<DependencyCheck> {
  if (!commandExists("kubectl")) {
    return {
      status: "fail",
      error: "kubectl binary not found in PATH",
    };
  }

  const result = await runCommand(["kubectl", "version", "--client", "--output=json"]);
  if (!result.ok) {
    return {
      status: "fail",
      error: result.stderr || "kubectl not usable",
    };
  }

  let parsed: unknown = result.stdout;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    // dejamos texto plano si no parsea
  }

  return {
    status: "ok",
    details: parsed,
  };
}

async function checkKubernetes(): Promise<DependencyCheck> {
  if (!commandExists("kubectl")) {
    return {
      status: "fail",
      error: "kubectl binary not found in PATH",
    };
  }

  const result = await runCommand(["kubectl", "cluster-info"]);
  if (!result.ok) {
    return {
      status: "fail",
      error: result.stderr || "kubernetes cluster not reachable",
    };
  }

  return {
    status: "ok",
    details: result.stdout,
  };
}

export async function buildHealthReport(dbPath: string): Promise<HealthReport> {
  const [docker, dockerImages, kubectl, kubernetes] = await Promise.all([
    checkDocker(),
    checkDockerImages(),
    checkKubectl(),
    checkKubernetes(),
  ]);

  const ok =
    docker.status === "ok" &&
    dockerImages.status === "ok" &&
    kubectl.status === "ok" &&
    kubernetes.status === "ok";

  return {
    ok,
    service: "reposentinel-api",
    database: dbPath,
    checks: {
      docker,
      docker_images: dockerImages,
      kubectl,
      kubernetes,
    },
  };
}