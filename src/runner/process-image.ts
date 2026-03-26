import { spawn } from "bun";
import type { Run } from "./update-runs";
import { dockerRun } from "./docker";

type Findings = Record<string, unknown>;

export async function processImage(run: Run) {
    const imageRef = run.input_ref?.trim();

    if (!imageRef) {
        throw new Error(`Image reference is required for run ${run.id}`);
    }

    await ensureImageAvailable(imageRef, run.id);

    const findings: Findings = {};

    findings["image_ref"] = imageRef;
    findings["docker_inspect"] = await runDockerInspect(imageRef, run.id);
    findings["trivy"] = await runTrivyImage(imageRef, run.id);
    findings["syft"] = await runSyftImage(imageRef, run.id);
    findings["grype"] = await runGrypeImage(imageRef, run.id);

    await removeImage(imageRef, run.id);

    return findings;
}

async function ensureImageAvailable(imageRef: string, runId: number) {
    const inspectProc = spawn({
        cmd: ["docker", "image", "inspect", imageRef],
        stdout: "pipe",
        stderr: "pipe",
    });

    const inspectStdout = await new Response(inspectProc.stdout).text();
    const inspectStderr = await new Response(inspectProc.stderr).text();
    const inspectExit = await inspectProc.exited;

    if (inspectExit === 0) {
        return;
    }

    const pullProc = spawn({
        cmd: ["docker", "pull", imageRef],
        stdout: "pipe",
        stderr: "pipe",
    });

    const pullStdout = await new Response(pullProc.stdout).text();
    const pullStderr = await new Response(pullProc.stderr).text();
    const pullExit = await pullProc.exited;

    if (pullExit !== 0) {
        throw new Error(
            `Image "${imageRef}" is not available locally and docker pull failed for run ${runId}: ${pullStderr || pullStdout || inspectStderr || inspectStdout || "unknown error"}`
        );
    }
}

async function removeImage(imageRef: string, runId: number) {
    const proc = spawn({
        cmd: ["docker", "rmi", "-f", imageRef],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;
    if (exitCode !== 0) {
        throw new Error(
            `Failed to remove image "${imageRef}" for run ${runId} with exit code ${exitCode}: ${stderr || stdout || "unknown error"}`
        );
    }
}

async function runDockerInspect(imageRef: string, runId: number) {
    const proc = spawn({
        cmd: ["docker", "image", "inspect", imageRef],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        throw new Error(
            `docker image inspect failed for run ${runId} with exit code ${exitCode}: ${stderr || stdout || "unknown error"}`
        );
    }

    const parsed = JSON.parse(stdout);
    return Array.isArray(parsed) ? parsed[0] ?? null : parsed;
}

async function runTrivyImage(imageRef: string, runId: number) {
    const proc = dockerRun(
        ["image", "--quiet", "--format", "json", imageRef],
        "aquasec/trivy:latest",
        [{ containerPath: "/var/run/docker.sock", hostPath: "/var/run/docker.sock" }]
    );

    const outputText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        const errText =
            typeof proc.stderr === "string" ? proc.stderr : "Trivy image execution failed";
        throw new Error(`Trivy image scan failed for run ${runId} with exit code ${exitCode}: ${errText}`);
    }

    const parsed = JSON.parse(outputText);
    return parsed.Results || parsed;
}

async function runSyftImage(imageRef: string, runId: number) {
    const proc = dockerRun(
        ["-o", "cyclonedx-json", `docker:${imageRef}`],
        "anchore/syft:latest",
        [{ containerPath: "/var/run/docker.sock", hostPath: "/var/run/docker.sock" }]
    );

    const outputText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        const errText =
            typeof proc.stderr === "string" ? proc.stderr : "Syft image execution failed";
        throw new Error(`Syft image SBOM failed for run ${runId} with exit code ${exitCode}: ${errText}`);
    }

    return JSON.parse(outputText);
}

async function runGrypeImage(imageRef: string, runId: number) {
    const proc = dockerRun(
        ["-o", "json", `docker:${imageRef}`],
        "anchore/grype:latest",
        [{ containerPath: "/var/run/docker.sock", hostPath: "/var/run/docker.sock" }],
    );

    const outputText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        const errText =
            typeof proc.stderr === "string" ? proc.stderr : "Grype image execution failed";
        throw new Error(`Grype image scan failed for run ${runId} with exit code ${exitCode}: ${errText}`);
    }

    const parsed = JSON.parse(outputText);
    return parsed.matches || parsed;
}