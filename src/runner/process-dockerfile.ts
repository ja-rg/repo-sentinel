import { dockerRun } from "./docker";
import { type Run, setRunStage } from "./update-runs";
import { DATA_DIR } from "../db";
import { rm } from "node:fs/promises";
import { logRun } from "../api/worker-manager";


export async function processDockerfile(run: Run) {
    const dockerfilePath = `${DATA_DIR}/runs/${run.id}/Dockerfile`;
    const findings: Record<string, unknown> = {};

    try {
        setRunStage(run.id, "validating-dockerfile", "Validating Dockerfile");

        // 1. Locate the Dockerfile
        const exists = await Bun.file(dockerfilePath).exists();
        if (!exists) {
            throw new Error(`Dockerfile not found for run ${run.id}`);
        }

        const volumes = [{
            hostPath: `${DATA_DIR}/runs/${run.id}`,
            containerPath: "/data"
        }];

        // 2. Basic validity checks
        const dockerfileContent = await Bun.file(dockerfilePath).text();
        const trimmed = dockerfileContent.trim();

        const redflags = [
            !/\bFROM\b/i.test(dockerfileContent) && "Missing FROM instruction",
            (trimmed.startsWith("{") || trimmed.startsWith("[")) && "Looks like JSON, not a Dockerfile",
            (trimmed.startsWith("---") || /^[\w-]+\s*:/m.test(dockerfileContent)) && "Looks like YAML, not a Dockerfile",
            /[\x00-\x08\x0E-\x1F\x7F]/.test(dockerfileContent) && "Contains binary/control data, not a valid Dockerfile",
        ].filter(Boolean) as string[];

        if (redflags.length > 0) {
            throw new Error(`Invalid Dockerfile for run ${run.id}: ${redflags.join(", ")} `);
        }

        // 3. Analyze with Semgrep
        setRunStage(run.id, "running-semgrep", "Running Semgrep");
        logRun(run.id, "info", "Semgrep started", { stage: "running-semgrep" });

        const proc = dockerRun(
            ["semgrep", "--config", "p/dockerfile", "--json", "--no-git-ignore", "/data"],
            "semgrep/semgrep:latest",
            volumes
        );

        const outputText = await proc.stdout.text();

        // optional: inspect exit code
        const exitCode = await proc.exited;
        if (exitCode !== 0) {
            const errText = proc.stderr ?? "";
            throw new Error(`Semgrep failed with exit code ${exitCode}: ${errText} `);
        }

        const semgrep = JSON.parse(outputText);
        findings["semgrep"] = semgrep.results || [];
        logRun(run.id, "info", "Semgrep finished", {
            stage: "running-semgrep",
            details: {
                resultCount: Array.isArray(findings["semgrep"]) ? findings["semgrep"].length : 0,
            },
        });


        // Trivy
        // docker run --rm -v ./data/runs/1/:/project aquasec/trivy:canary --format json config /project --file-patterns "dockerfile:Dockerfile*
        setRunStage(run.id, "running-trivy", "Running Trivy");
        logRun(run.id, "info", "Trivy started", { stage: "running-trivy" });
        const trivyProc = dockerRun(
            ["--quiet", "--format", "json", "config", "/data", "--file-patterns", "dockerfile:Dockerfile*"],
            "aquasec/trivy:canary",
            volumes
        );

        const trivyOutputText = await trivyProc.stdout.text();

        const trivyExitCode = await trivyProc.exited;
        if (trivyExitCode !== 0) {
            const errText = trivyProc.stderr ?? "";
            throw new Error(`Trivy failed with exit code ${trivyExitCode}: ${errText} `);
        }
        const trivyResults = JSON.parse(trivyOutputText);
        findings["trivy"] = trivyResults.Results || [];
        logRun(run.id, "info", "Trivy finished", {
            stage: "running-trivy",
            details: {
                resultCount: Array.isArray(findings["trivy"]) ? findings["trivy"].length : 0,
            },
        });

        setRunStage(run.id, "completed", "Dockerfile processing completed");
        return findings;
    } catch (err) {
        setRunStage(run.id, "error", "Dockerfile processing failed");
        logRun(run.id, "error", "Dockerfile processing failed", {
            stage: "error",
            details: { error: String(err) },
        });
        console.error(`Error analyzing Dockerfile for run ${run.id}: `, err);
        throw new Error(`Error analyzing Dockerfile for run ${run.id}: ${err}`);
    } finally {
        setRunStage(run.id, "cleanup", "Cleaning up Dockerfile workspace");

        // Remove the folder with the Dockerfile to save space
        try {
            await rm(`${DATA_DIR}/runs/${run.id}`, { recursive: true, force: true });
            logRun(run.id, "info", "Dockerfile workspace cleanup completed", {
                stage: "cleanup",
            });
        } catch (err) {
            console.warn(`Failed to clean up Dockerfile data for run ${run.id}: `, err);
            logRun(run.id, "warn", "Dockerfile workspace cleanup failed", {
                stage: "cleanup",
                details: { error: String(err) },
            });
        }
    }
}