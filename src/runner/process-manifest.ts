import { readdir, rm } from "node:fs/promises";
import { join, extname } from "node:path";
import { spawn } from "bun";
import { dockerRun } from "./docker";
import { type Run, setRunStage } from "./update-runs";
import { DATA_DIR } from "../db";
import { logRun } from "../api/worker-manager";

type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

type Finding = {
    tool: string;
    category: "manifest" | "runtime" | "deployment";
    severity: FindingSeverity;
    title: string;
    description: string;
    resource?: string;
    raw?: unknown;
};

type Decision = {
    action: "allow" | "reject" | "teardown" | "failed";
    reason: string;
    stage: string;
    applied: boolean;
    exposed_url?: string | null;
};

export async function processManifest(
    run: Run
): Promise<[Finding[], Decision]> {
    const runDir = join(DATA_DIR, "runs", String(run.id));

    let findings: Finding[] = [];
    let applied = false;
    let exposedUrl: string | null = null;
    let manifestPath: string | null = null;

    try {
        setRunStage(run.id, "validating-manifest", "Validating uploaded manifest");
        // 1. Find uploaded manifest
        manifestPath = await findSingleUploadedFile(runDir);
        // 2. Validate manifest file
        if (!manifestPath) {
            throw new Error(`No manifest file found for run ${run.id}`);
        }

        await validateManifestFile(manifestPath, run.id);

        // 2. Static analysis
        setRunStage(run.id, "static-analysis", "Running manifest static analysis");
        logRun(run.id, "info", "Manifest static analysis started", {
            stage: "static-analysis",
        });
        const staticFindings = await runStaticManifestAnalysis(manifestPath, run.id);
        findings.push(...staticFindings);
        logRun(run.id, "info", "Manifest static analysis finished", {
            stage: "static-analysis",
            details: { resultCount: staticFindings.length },
        });

        if (hasBlockingManifestFindings(staticFindings)) {
            setRunStage(run.id, "completed", "Manifest rejected after static analysis");
            return [
                findings,
                {
                    action: "reject",
                    reason: "Manifest security analysis produced blocking findings.",
                    stage: "static-analysis",
                    applied: false,
                    exposed_url: null,
                },
            ];
        }

        // 3. Apply to cluster
        setRunStage(run.id, "applying", "Applying manifest to cluster");
        await kubectlApply(manifestPath, run.id);
        applied = true;

        // 4. Wait for workload/service readiness
        setRunStage(run.id, "waiting-readiness", "Waiting for workload readiness");
        await waitForManifestResources(manifestPath, run.id);

        // 5. Resolve service URL
        setRunStage(run.id, "resolving-service", "Resolving service URL");
        exposedUrl = await resolveManifestServiceUrl(manifestPath, run.id);
        if (!exposedUrl) {
            findings.push({
                tool: "deployment",
                category: "deployment",
                severity: "medium",
                title: "Service URL not resolved",
                description:
                    "Manifest was applied, but no reachable service URL could be resolved through Minikube.",
            });

                    setRunStage(run.id, "teardown", "Tearing down deployment after unresolved service URL");
            await kubectlDelete(manifestPath, run.id).catch(() => { });
                    setRunStage(run.id, "completed", "Manifest processing completed with teardown");
            return [
                findings,
                {
                    action: "teardown",
                    reason: "Deployment succeeded but service exposure could not be resolved safely.",
                    stage: "service-resolution",
                    applied: false,
                    exposed_url: null,
                },
            ];
        }

        // 6. Runtime scan with Nuclei
        setRunStage(run.id, "runtime-scan", "Running runtime scan");
        logRun(run.id, "info", "Nuclei runtime scan started", {
            stage: "runtime-scan",
            details: { target: exposedUrl },
        });
        const runtimeFindings = await runNucleiScan(exposedUrl, run.id);
        findings.push(...runtimeFindings);
        logRun(run.id, "info", "Nuclei runtime scan finished", {
            stage: "runtime-scan",
            details: { resultCount: runtimeFindings.length, target: exposedUrl },
        });

        if (hasBlockingRuntimeFindings(runtimeFindings)) {
            setRunStage(run.id, "teardown", "Tearing down deployment after runtime findings");
            await kubectlDelete(manifestPath, run.id).catch(() => { });
            setRunStage(run.id, "completed", "Manifest processing completed with teardown");
            return [
                findings,
                {
                    action: "teardown",
                    reason: "Runtime scan found blocking issues after deployment.",
                    stage: "runtime-scan",
                    applied: false,
                    exposed_url: exposedUrl,
                },
            ];
        }

        // 7. Safe enough to keep
        setRunStage(run.id, "completed", "Manifest processing completed");
        return [
            findings,
            {
                action: "allow",
                reason: "Manifest passed static checks and runtime probing.",
                stage: "completed",
                applied: true,
                exposed_url: exposedUrl,
            },
        ];
    } catch (err) {
        setRunStage(run.id, "error", "Manifest processing failed");
        logRun(run.id, "error", "Manifest processing failed", {
            stage: "error",
            details: { error: String(err) },
        });

        if (applied) {
            try {
                if (manifestPath) {
                    setRunStage(run.id, "teardown", "Tearing down deployment after failure");
                    await kubectlDelete(manifestPath, run.id);
                }
            } catch {
                // best effort cleanup
            }
        }

        findings.push({
            tool: "pipeline",
            category: "deployment",
            severity: "high",
            title: "Manifest processing failed",
            description: String(err),
            raw: { error: String(err) },
        });

        return [
            findings,
            {
                action: "failed",
                reason: String(err),
                stage: "error",
                applied: false,
                exposed_url: exposedUrl,
            },
        ];
    } finally {
        try {
            await rm(runDir, { recursive: true, force: true });
        } catch (err) {
            console.warn(`Failed to clean up manifest data for run ${run.id}:`, err);
        }
    }
}

async function findSingleUploadedFile(runDir: string): Promise<string> {
    const entries = await readdir(runDir, { withFileTypes: true });
    const files = entries
        .filter((entry) => entry.isFile())
        .map((entry) => join(runDir, entry.name));

    if (files.length === 0) {
        throw new Error(`No uploaded manifest found in ${runDir}`);
    }

    if (files.length > 1) {
        throw new Error(`Expected exactly one uploaded manifest in ${runDir}, found ${files.length}`);
    }

    const single = files[0];
    if (!single) {
        throw new Error(`No uploaded manifest found in ${runDir}`);
    }

    return single;
}

async function validateManifestFile(manifestPath: string, runId: number) {
    const file = Bun.file(manifestPath);
    const exists = await file.exists();
    if (!exists) {
        throw new Error(`Manifest file not found for run ${runId}`);
    }

    const text = await file.text();
    const trimmed = text.trim();

    if (!trimmed) {
        throw new Error(`Manifest file is empty for run ${runId}`);
    }

    const ext = extname(manifestPath).toLowerCase();
    const looksLikeYaml =
        trimmed.startsWith("---") ||
        /^[A-Za-z0-9_.-]+\s*:/m.test(trimmed);

    const looksLikeJson =
        trimmed.startsWith("{") || trimmed.startsWith("[");

    if (![".yaml", ".yml", ".json", ""].includes(ext) && !looksLikeYaml && !looksLikeJson) {
        throw new Error(`Manifest file does not look like YAML or JSON for run ${runId}`);
    }
}

async function runStaticManifestAnalysis(manifestPath: string, runId: number): Promise<Finding[]> {
    const findings: Finding[] = [];

    const hostDir = manifestPath.substring(0, manifestPath.lastIndexOf("/")).replaceAll("\\", "/");
    const filename = manifestPath.split(/[\\/]/).pop()!;

    const volumes = [
        {
            hostPath: hostDir.startsWith("./") ? hostDir : `./${hostDir}`,
            containerPath: "/data",
        },
    ];

    // Trivy config
    try {
        const trivyProc = dockerRun(
            ["config", "--quiet", "--format", "json", `/data/${filename}`],
            "aquasec/trivy:latest",
            volumes
        );

        const output = await trivyProc.stdout.text();
        const exitCode = await trivyProc.exited;

        if (exitCode !== 0) {
            throw new Error(`Trivy config failed with exit code ${exitCode}`);
        }

        const parsed = JSON.parse(output);
        const results = parsed.Results || [];

        for (const result of results) {
            const misconfigs = result.Misconfigurations || [];
            for (const item of misconfigs) {
                findings.push({
                    tool: "trivy",
                    category: "manifest",
                    severity: normalizeSeverity(item.Severity),
                    title: item.Title || item.ID || "Manifest misconfiguration",
                    description: item.Message || item.Description || "Trivy detected a manifest issue.",
                    resource: result.Target,
                    raw: item,
                });
            }
        }
    } catch (err) {
        findings.push({
            tool: "trivy",
            category: "manifest",
            severity: "high",
            title: "Trivy manifest scan failed",
            description: String(err),
            raw: { error: String(err) },
        });
    }

    // Semgrep on manifest
    try {
        const semgrepProc = dockerRun(
            ["semgrep", "--config", "auto", "--json", `/data/${filename}`],
            "semgrep/semgrep:latest",
            volumes
        );

        const output = await semgrepProc.stdout.text();
        const exitCode = await semgrepProc.exited;

        if (exitCode !== 0) {
            throw new Error(`Semgrep failed with exit code ${exitCode}`);
        }

        const parsed = JSON.parse(output);
        const results = parsed.results || [];

        for (const item of results) {
            findings.push({
                tool: "semgrep",
                category: "manifest",
                severity: normalizeSeverity(item?.extra?.severity),
                title: item?.check_id || "Semgrep manifest finding",
                description: item?.extra?.message || "Semgrep detected a manifest issue.",
                resource: item?.path,
                raw: item,
            });
        }
    } catch (err) {
        findings.push({
            tool: "semgrep",
            category: "manifest",
            severity: "medium",
            title: "Semgrep manifest scan failed",
            description: String(err),
            raw: { error: String(err) },
        });
    }

    return findings;
}

function hasBlockingManifestFindings(findings: Finding[]) {
    return findings.some(
        (f) =>
            f.category === "manifest" &&
            (f.severity === "critical" || f.severity === "high")
    );
}

function hasBlockingRuntimeFindings(findings: Finding[]) {
    return findings.some(
        (f) =>
            f.category === "runtime" &&
            (f.severity === "critical" || f.severity === "high")
    );
}

async function kubectlApply(manifestPath: string, runId: number) {
    const proc = spawn({
        cmd: ["kubectl", "apply", "-f", manifestPath],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        throw new Error(`kubectl apply failed for run ${runId}: ${stderr || stdout || "unknown error"}`);
    }
}

async function kubectlDelete(manifestPath: string, runId: number) {
    const proc = spawn({
        cmd: ["kubectl", "delete", "-f", manifestPath],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        throw new Error(`kubectl delete failed for run ${runId}: ${stderr || stdout || "unknown error"}`);
    }
}

async function waitForManifestResources(manifestPath: string, runId: number) {
    // Best-effort simple wait.
    // You can later replace this with resource-aware rollout logic.
    const proc = spawn({
        cmd: ["kubectl", "wait", "--for=condition=available", "--timeout=120s", "-f", manifestPath],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    // Some manifests do not define "available" resources, so do not always hard-fail here.
    if (exitCode !== 0) {
        console.warn(`kubectl wait warning for run ${runId}: ${stderr || stdout || "unknown wait issue"}`);
    }
}

async function resolveManifestServiceUrl(manifestPath: string, runId: number): Promise<string | null> {
    const serviceNames = await getServiceNamesFromManifest(manifestPath);

    for (const serviceName of serviceNames) {
        const proc = spawn({
            cmd: ["minikube", "service", serviceName, "--url"],
            stdout: "pipe",
            stderr: "pipe",
        });

        const stdout = await new Response(proc.stdout).text();
        const stderr = await new Response(proc.stderr).text();
        const exitCode = await proc.exited;

        if (exitCode === 0) {
            const url = stdout.trim().split(/\r?\n/)[0]?.trim();
            if (url) return url;
        } else {
            console.warn(`minikube service failed for ${serviceName} on run ${runId}: ${stderr || stdout}`);
        }
    }

    return null;
}

async function getServiceNamesFromManifest(manifestPath: string): Promise<string[]> {
    const text = await Bun.file(manifestPath).text();

    // Very light heuristic parser.
    // Better than nothing, but not a full YAML parser.
    const docs = text.split(/^---\s*$/m);
    const names: string[] = [];

    for (const doc of docs) {
        const kindMatch = doc.match(/^\s*kind:\s*Service\s*$/im);
        if (!kindMatch) continue;

        const nameMatch = doc.match(/^\s*name:\s*([^\s]+)\s*$/im);
        if (nameMatch && nameMatch[1]) {
            names.push(nameMatch[1]);
        }
    }

    return [...new Set(names)];
}

async function runNucleiScan(targetUrl: string, runId: number): Promise<Finding[]> {
    const findings: Finding[] = [];

    const proc = dockerRun(
        ["-u", targetUrl, "-jsonl", "-silent"],
        "projectdiscovery/nuclei:latest",
        []
    );

    const output = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0 && !output.trim()) {
        throw new Error(`Nuclei failed for run ${runId} with exit code ${exitCode}`);
    }

    const lines = output
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

    for (const line of lines) {
        try {
            const item = JSON.parse(line);
            findings.push({
                tool: "nuclei",
                category: "runtime",
                severity: normalizeSeverity(item.info?.severity),
                title: item.info?.name || item.templateID || "Runtime finding",
                description:
                    item.info?.description ||
                    `Nuclei detected a runtime issue at ${item.matchedAt || targetUrl}.`,
                resource: item.matchedAt || targetUrl,
                raw: item,
            });
        } catch {
            // ignore malformed line
        }
    }

    return findings;
}

function normalizeSeverity(input: unknown): FindingSeverity {
    const value = String(input || "").toLowerCase();

    if (value === "critical") return "critical";
    if (value === "high") return "high";
    if (value === "medium") return "medium";
    if (value === "low") return "low";
    return "info";
}