import { dockerRun } from "./docker";
import { type Run } from "./update-runs";
import { DATA_DIR } from "../db";
import { rm } from "node:fs/promises";


export async function processDockerfile(run: Run) {
    const dockerfilePath = `${DATA_DIR}/runs/${run.id}/Dockerfile`;

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
    const findings: Record<string, unknown> = {};

    try {
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


        // Trivy
        // docker run --rm -v ./data/runs/1/:/project aquasec/trivy:latest --format json config /project --file-patterns "dockerfile:Dockerfile*
        const trivyProc = dockerRun(
            ["--quiet", "--format", "json", "config", "/data", "--file-patterns", "dockerfile:Dockerfile*"],
            "aquasec/trivy:latest",
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
    } catch (err) {
        console.error(`Error running Semgrep for run ${run.id}: `, err);
        throw new Error(`Error analyzing Dockerfile for run ${run.id}: ${err}`);
    }

    // Remove the folder with the Dockerfile to save space
    try {
        await rm(`${DATA_DIR}/runs/${run.id}`, { recursive: true, force: true });
    } catch (err) {
        console.warn(`Failed to clean up Dockerfile data for run ${run.id}: `, err);
    }

    return findings;
}