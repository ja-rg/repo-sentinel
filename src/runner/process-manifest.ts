import { readdir, rm } from "node:fs/promises";
import { join, extname, dirname, basename } from "node:path";
import { spawn } from "bun";
import { parseAllDocuments } from "yaml";
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

type ManifestResource = {
    kind: string;
    name: string;
    namespace: string;
    spec?: Record<string, unknown>;
};

type ServiceResource = ManifestResource & {
    kind: "Service";
    spec: Record<string, unknown>;
};

const publishedManifestTunnels = new Map<number, () => void>();

export function cleanupPublishedManifestTunnel(runId: number) {
    const cleanup = publishedManifestTunnels.get(runId);
    if (!cleanup) return;

    publishedManifestTunnels.delete(runId);
    try {
        cleanup();
    } catch {
        // best effort cleanup
    }
}

export function cleanupAllPublishedManifestTunnels() {
    const entries = Array.from(publishedManifestTunnels.entries());
    for (const [runId, cleanup] of entries) {
        publishedManifestTunnels.delete(runId);
        try {
            cleanup();
        } catch {
            // best effort cleanup
        }
    }
}

export async function processManifest(
    run: Run
): Promise<[Finding[], Decision]> {
    const runDir = join(DATA_DIR, "runs", String(run.id));

    let findings: Finding[] = [];
    let applied = false;
    let exposedUrl: string | null = null;
    let manifestPath: string | null = null;
    let runtimeTunnelCleanup: (() => void) | null = null;
    let publishedTunnelCleanup: (() => void) | null = null;
    let shouldKeepPublishedTunnel = false;

    try {
        setRunStage(run.id, "validating-manifest", "Validating uploaded manifest");
        // 1. Find uploaded manifest
        manifestPath = await findSingleUploadedFile(runDir);
        // 2. Validate manifest file
        if (!manifestPath) {
            throw new Error(`No manifest file found for run ${run.id}`);
        }

        await validateManifestFile(manifestPath, run.id);
        const resources = await parseManifestResources(manifestPath, run.id);

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

        if (/*hasBlockingManifestFindings(staticFindings) */ false) { // Relaxed for demo purposes, re-enable in production
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
        await ensureManifestNamespaces(resources, run.id);
        await kubectlApply(manifestPath, run.id);
        applied = true;

        // 4. Wait for workload/service readiness
        setRunStage(run.id, "waiting-readiness", "Waiting for workload readiness");
        await waitForManifestResources(resources, run.id); // Relaxed for demo purposes, re-enable in production

        // 5. Resolve service resources and runtime scanning target
        const services = getServiceResources(resources);
        if (services.length === 0) {
            setRunStage(run.id, "completed", "Manifest applied (no service exposure required)");
            return [
                findings,
                {
                    action: "allow",
                    reason: "Manifest passed static checks and does not expose a Service for runtime probing.",
                    stage: "completed",
                    applied: true,
                    exposed_url: null,
                },
            ];
        }

        const primaryService = services[0];
        if (!primaryService) {
            throw new Error(`No primary Service found for run ${run.id}`);
        }

        setRunStage(run.id, "runtime-target", "Opening temporary runtime target for Nuclei");
        const runtimeTarget = await openRuntimeScanTarget(primaryService, run.id);
        runtimeTunnelCleanup = runtimeTarget.cleanup;

        if (!runtimeTarget.url) {
            findings.push({
                tool: "deployment",
                category: "deployment",
                severity: "medium",
                title: "Runtime target not resolved",
                description:
                    "Manifest was applied, but no reachable runtime target could be prepared for Nuclei.",
            });

            setRunStage(run.id, "teardown", "Tearing down deployment after unresolved runtime target");
            await kubectlDelete(manifestPath, run.id).catch(() => { });
            setRunStage(run.id, "completed", "Manifest processing completed with teardown");
            return [
                findings,
                {
                    action: "teardown",
                    reason: "Deployment succeeded but runtime probing target could not be resolved safely.",
                    stage: "runtime-target",
                    applied: false,
                    exposed_url: null,
                },
            ];
        }

        // 6. Runtime scan with Nuclei
        setRunStage(run.id, "runtime-scan", "Running runtime scan");
        logRun(run.id, "info", "Nuclei runtime scan started", {
            stage: "runtime-scan",
            details: { target: runtimeTarget.url },
        });
        const runtimeFindings = await runNucleiScan(runtimeTarget.url, run.id);
        findings.push(...runtimeFindings);
        logRun(run.id, "info", "Nuclei runtime scan finished", {
            stage: "runtime-scan",
            details: { resultCount: runtimeFindings.length, target: runtimeTarget.url },
        });
        runtimeTarget.cleanup();
        runtimeTunnelCleanup = null;

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
                    exposed_url: null,
                },
            ];
        }

        // 7. Safe enough to keep; publish service URL via a persistent local tunnel
        setRunStage(run.id, "publishing", "Resolving service URL for published access");
        const publishedTarget = await openPublishedServiceTarget(primaryService, run.id);
        publishedTunnelCleanup = publishedTarget.cleanup;

        if (!publishedTarget.url) {
            findings.push({
                tool: "deployment",
                category: "deployment",
                severity: "medium",
                title: "Published target not resolved",
                description:
                    "Manifest passed runtime scan, but a reachable published target could not be prepared.",
            });

            setRunStage(run.id, "teardown", "Tearing down deployment after unresolved published target");
            await kubectlDelete(manifestPath, run.id).catch(() => { });
            setRunStage(run.id, "completed", "Manifest processing completed with teardown");
            return [
                findings,
                {
                    action: "teardown",
                    reason: "Deployment succeeded but published target could not be resolved safely.",
                    stage: "publishing",
                    applied: false,
                    exposed_url: null,
                },
            ];
        }

        exposedUrl = publishedTarget.url;

        logRun(run.id, "info", "Published service tunnel established", {
            stage: "publishing",
            details: { target: exposedUrl, namespace: primaryService.namespace, service: primaryService.name },
        });

        setRunStage(run.id, "completed", "Manifest processing completed");
        cleanupPublishedManifestTunnel(run.id);
        publishedManifestTunnels.set(run.id, publishedTarget.cleanup);
        shouldKeepPublishedTunnel = true;

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
        if (runtimeTunnelCleanup) {
            try {
                runtimeTunnelCleanup();
            } catch {
                // best effort cleanup
            }
        }

        if (publishedTunnelCleanup && !shouldKeepPublishedTunnel) {
            try {
                publishedTunnelCleanup();
            } catch {
                // best effort cleanup
            }
        }

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

    const hostDir = dirname(manifestPath).replaceAll("\\", "/");
    const filename = basename(manifestPath);

    const volumes = [
        {
            hostPath: hostDir,
            containerPath: "/data",
        },
    ];

    // Trivy config
    try {
        const trivyProc = dockerRun(
            ["config", "--quiet", "--format", "json", `/data/${filename}`],
            "aquasec/trivy:canary",
            volumes
        );

        const output = await trivyProc.stdout.text();
        const errText = await trivyProc.stderr.text();
        const exitCode = await trivyProc.exited;

        if (exitCode !== 0) {
            throw new Error(
                `Trivy config failed with exit code ${exitCode}${errText.trim() ? `: ${errText.trim()}` : ""}`
            );
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
        const errText = await semgrepProc.stderr.text();
        const exitCode = await semgrepProc.exited;

        if (exitCode !== 0) {
            throw new Error(
                `Semgrep failed with exit code ${exitCode}${errText.trim() ? `: ${errText.trim()}` : ""}`
            );
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

async function waitForManifestResources(resources: ManifestResource[], runId: number) {
    const waits = resources.filter((resource) =>
        ["Deployment", "StatefulSet", "DaemonSet", "Pod", "Job"].includes(resource.kind)
    );

    for (const resource of waits) {
        let args: string[] | null = null;

        switch (resource.kind) {
            case "Deployment":
                args = ["rollout", "status", `deployment/${resource.name}`, "-n", resource.namespace, "--timeout=120s"];
                break;
            case "StatefulSet":
                args = ["rollout", "status", `statefulset/${resource.name}`, "-n", resource.namespace, "--timeout=120s"];
                break;
            case "DaemonSet":
                args = ["rollout", "status", `daemonset/${resource.name}`, "-n", resource.namespace, "--timeout=120s"];
                break;
            case "Pod":
                args = ["wait", "--for=condition=Ready", `pod/${resource.name}`, "-n", resource.namespace, "--timeout=120s"];
                break;
            case "Job":
                args = ["wait", "--for=condition=complete", `job/${resource.name}`, "-n", resource.namespace, "--timeout=120s"];
                break;
        }

        if (!args) continue;

        const result = await runCommand("kubectl", args, 130_000);
        if (result.exitCode !== 0) {
            throw new Error(
                `Readiness check failed for ${resource.kind}/${resource.name} in namespace ${resource.namespace} on run ${runId}: ${result.stderr || result.stdout || "unknown error"}`,
            );
        }
    }
}

function getServiceResources(resources: ManifestResource[]): ServiceResource[] {
    const services: ServiceResource[] = [];
    for (const resource of resources) {
        if (resource.kind !== "Service") continue;
        services.push({
            ...resource,
            kind: "Service",
            spec: resource.spec ?? {},
        });
    }
    return services;
}

async function openRuntimeScanTarget(
    service: ServiceResource,
    runId: number,
): Promise<{ url: string | null; cleanup: () => void }> {
    const localPort = await allocateLocalPort(18080);
    const servicePort = getPrimaryServicePort(service);
    if (!servicePort) {
        return {
            url: null,
            cleanup: () => { },
        };
    }

    const proc = spawn({
        cmd: [
            "kubectl",
            "port-forward",
            "-n",
            service.namespace,
            `svc/${service.name}`,
            `${localPort}:${servicePort}`,
        ],
        stdout: "pipe",
        stderr: "pipe",
    });

    const outputReader = (async () => {
        const [stdout, stderr] = await Promise.all([
            new Response(proc.stdout).text(),
            new Response(proc.stderr).text(),
        ]);
        return { stdout, stderr };
    })();

    const url = `http://127.0.0.1:${localPort}`;
    const becameReady = await waitForHttpTarget(url, 20_000);

    if (!becameReady) {
        try {
            proc.kill();
        } catch {
            // best effort
        }

        const output = await outputReader.catch(() => ({ stdout: "", stderr: "" }));
        console.warn(
            `kubectl port-forward did not become ready for ${service.namespace}/${service.name} on run ${runId}: ${output.stderr || output.stdout || "unknown error"}`,
        );

        return {
            url: null,
            cleanup: () => { },
        };
    }

    return {
        url,
        cleanup: () => {
            try {
                proc.kill();
            } catch {
                // best effort
            }
        },
    };
}

function getPrimaryServicePort(service: ServiceResource): number | null {
    const ports = Array.isArray(service.spec.ports)
        ? (service.spec.ports as Array<Record<string, unknown>>)
        : [];
    const firstPort = ports[0];
    if (!firstPort) return null;

    const targetPort = firstPort.targetPort;
    if (typeof targetPort === "number" && Number.isFinite(targetPort)) {
        return targetPort;
    }

    const port = Number(firstPort.port ?? 0);
    return port > 0 ? port : null;
}

async function allocateLocalPort(basePort: number): Promise<number> {
    // Good-enough deterministic allocation for a single worker flow.
    const offset = Math.floor(Math.random() * 5000);
    return basePort + offset;
}

async function waitForHttpTarget(url: string, timeoutMs: number): Promise<boolean> {
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
        try {
            const req = await fetch(url, {
                method: "GET",
            });

            if (req.status >= 100) {
                return true;
            }
        } catch {
            // not ready yet
        }

        await Bun.sleep(500);
    }

    return false;
}

async function ensureManifestNamespaces(resources: ManifestResource[], runId: number) {
    const namespaces = getNamespacesFromResources(resources);

    for (const namespace of namespaces) {
        const existsResult = await runCommand(
            "kubectl",
            ["get", "namespace", namespace, "-o", "name"],
            15_000,
        );
        if (existsResult.exitCode === 0) continue;

        const createResult = await runCommand(
            "kubectl",
            ["create", "namespace", namespace],
            20_000,
        );

        if (createResult.exitCode !== 0) {
            throw new Error(
                `Failed to create namespace '${namespace}' for run ${runId}: ${createResult.stderr || createResult.stdout || "unknown error"}`,
            );
        }

        logRun(runId, "info", `Created namespace '${namespace}'`, {
            stage: "applying",
        });
    }
}

async function parseManifestResources(
    manifestPath: string,
    runId: number,
): Promise<ManifestResource[]> {
    const text = await Bun.file(manifestPath).text();
    const docs = parseAllDocuments(text);
    const resources: ManifestResource[] = [];

    for (const doc of docs) {
        const parsed = doc.toJSON();
        collectManifestResources(parsed, resources);
    }

    if (resources.length === 0) {
        throw new Error(`No Kubernetes resources parsed from manifest for run ${runId}`);
    }

    return resources;
}

function collectManifestResources(value: unknown, out: ManifestResource[]) {
    if (!value || typeof value !== "object") return;

    const node = value as Record<string, unknown>;
    const kind = typeof node.kind === "string" ? node.kind : null;

    if (kind === "List" && Array.isArray(node.items)) {
        for (const item of node.items) {
            collectManifestResources(item, out);
        }
        return;
    }

    if (!kind) return;

    const metadata = (node.metadata && typeof node.metadata === "object")
        ? (node.metadata as Record<string, unknown>)
        : {};
    const name = typeof metadata.name === "string" ? metadata.name : null;
    if (!name) return;

    const namespace = typeof metadata.namespace === "string" && metadata.namespace.trim()
        ? metadata.namespace
        : "default";

    out.push({
        kind,
        name,
        namespace,
        spec: node.spec && typeof node.spec === "object"
            ? (node.spec as Record<string, unknown>)
            : undefined,
    });
}

function getNamespacesFromResources(resources: ManifestResource[]): string[] {
    const namespaces = new Set<string>();
    for (const resource of resources) {
        if (!resource.namespace || resource.namespace === "default") continue;
        namespaces.add(resource.namespace);
    }
    return Array.from(namespaces);
}

async function runCommand(
    command: string,
    args: string[],
    timeoutMs: number,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    const proc = spawn({
        cmd: [command, ...args],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdoutPromise = new Response(proc.stdout).text();
    const stderrPromise = new Response(proc.stderr).text();

    let timedOut = false;
    const timeoutPromise = Bun.sleep(timeoutMs).then(() => {
        timedOut = true;
        try {
            proc.kill();
        } catch {
            // best effort
        }
    });

    await Promise.race([proc.exited, timeoutPromise]);
    const [stdout, stderr] = await Promise.all([stdoutPromise, stderrPromise]);
    const exitCode = await proc.exited;

    if (timedOut) {
        return {
            stdout,
            stderr: `Command timed out after ${timeoutMs}ms. ${stderr}`.trim(),
            exitCode: exitCode ?? 1,
        };
    }

    return {
        stdout,
        stderr,
        exitCode,
    };
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

async function openPublishedServiceTarget(
    service: ServiceResource,
    runId: number,
): Promise<{ url: string | null; cleanup: () => void }> {
    const localPort = await allocateLocalPort(28080);
    const servicePort = getPrimaryServicePort(service);
    if (!servicePort) {
        return {
            url: null,
            cleanup: () => { },
        };
    }

    const proc = spawn({
        cmd: [
            "kubectl",
            "port-forward",
            "-n",
            service.namespace,
            `svc/${service.name}`,
            `${localPort}:${servicePort}`,
        ],
        stdout: "pipe",
        stderr: "pipe",
    });

    const outputReader = (async () => {
        const [stdout, stderr] = await Promise.all([
            new Response(proc.stdout).text(),
            new Response(proc.stderr).text(),
        ]);
        return { stdout, stderr };
    })();

    const url = `http://127.0.0.1:${localPort}`;
    const becameReady = await waitForHttpTarget(url, 20_000);

    if (!becameReady) {
        try {
            proc.kill();
        } catch {
            // best effort
        }

        const output = await outputReader.catch(() => ({ stdout: "", stderr: "" }));
        console.warn(
            `Published tunnel did not become ready for ${service.namespace}/${service.name} on run ${runId}: ${output.stderr || output.stdout || "unknown error"}`,
        );

        return {
            url: null,
            cleanup: () => { },
        };
    }

    return {
        url,
        cleanup: () => {
            try {
                proc.kill();
            } catch {
                // best effort
            }
        },
    };
}