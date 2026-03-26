import { mkdir, readdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, extname } from "node:path";
import { spawn } from "bun";

import { dockerRun } from "./docker";
import type { Run } from "./update-runs";
import { DATA_DIR } from "../db";

type Findings = Record<string, unknown>;

export async function processRepoOrArchive(run: Run) {
    const runDir = join(DATA_DIR, "runs", String(run.id));
    const workspaceDir = join(runDir, "workspace");

    await mkdir(workspaceDir, { recursive: true });

    let scanTarget = "";

    try {
        if (run.kind === "repo") {
            scanTarget = join(workspaceDir, "repo");
            await cloneRepo(run.input_ref, scanTarget);
        } else if (run.kind === "archive") {
            const archivePath = await findSingleUploadedFile(runDir);
            if (!archivePath) {
                throw new Error(`No archive file found for run ${run.id}`);
            }

            scanTarget = join(workspaceDir, "archive");
            await mkdir(scanTarget, { recursive: true });
            await extractArchive(archivePath, scanTarget);
        } else {
            throw new Error(`processRepoOrArchive received unsupported kind: ${run.kind}`);
        }

        // prefix ./ and replace all backslashes with forward slashes to ensure Docker compatibility on Windows
        scanTarget = "./" + scanTarget.split(join("")).join("/");

        await assertDirectoryHasFiles(scanTarget);

        const findings: Findings = {};

        findings["semgrep"] = await runSemgrep(scanTarget, run.id);
        findings["trivy"] = await runTrivyFs(scanTarget, run.id);
        findings["gitleaks"] = await runGitleaks(scanTarget, run.id);
        findings["syft"] = await runSyft(scanTarget, run.id);
        return findings;
    } finally {
        try {
            await rm(runDir, { recursive: true, force: true });
        } catch (err) {
            console.warn(`Failed to clean up run directory for run ${run.id}:`, err);
        }
    }
}

async function cloneRepo(repoUrl: string, destination: string) {
    if (!repoUrl || !repoUrl.trim()) {
        throw new Error("Repository URL is required");
    }

    const proc = spawn({
        cmd: ["git", "clone", "--depth", "1", repoUrl, destination],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        throw new Error(
            `git clone failed with exit code ${exitCode}: ${stderr || stdout || "unknown error"}`
        );
    }
}

async function findSingleUploadedFile(runDir: string) {
    const entries = await readdir(runDir, { withFileTypes: true });

    const files = entries
        .filter((entry) => entry.isFile())
        .map((entry) => join(runDir, entry.name));

    if (files.length === 0) {
        throw new Error(`No uploaded archive found in ${runDir}`);
    }

    if (files.length > 1) {
        throw new Error(
            `Expected exactly one uploaded archive in ${runDir}, found ${files.length}`
        );
    }

    return files[0];
}

async function extractArchive(archivePath: string, destination: string) {
    const lower = archivePath.toLowerCase();

    if (lower.endsWith(".zip")) {
        const proc = spawn({
            cmd: ["unzip", "-q", archivePath, "-d", destination],
            stdout: "pipe",
            stderr: "pipe",
        });

        const stdout = await new Response(proc.stdout).text();
        const stderr = await new Response(proc.stderr).text();
        const exitCode = await proc.exited;

        if (exitCode !== 0) {
            throw new Error(
                `unzip failed with exit code ${exitCode}: ${stderr || stdout || "unknown error"}`
            );
        }

        return;
    }

    if (
        lower.endsWith(".tar") ||
        lower.endsWith(".tgz") ||
        lower.endsWith(".tar.gz") ||
        lower.endsWith(".tar.bz2") ||
        lower.endsWith(".tbz2") ||
        lower.endsWith(".tar.xz") ||
        lower.endsWith(".txz")
    ) {
        const proc = spawn({
            cmd: ["tar", "-xf", archivePath, "-C", destination],
            stdout: "pipe",
            stderr: "pipe",
        });

        const stdout = await new Response(proc.stdout).text();
        const stderr = await new Response(proc.stderr).text();
        const exitCode = await proc.exited;

        if (exitCode !== 0) {
            throw new Error(
                `tar extraction failed with exit code ${exitCode}: ${stderr || stdout || "unknown error"}`
            );
        }

        return;
    }

    throw new Error(
        `Unsupported archive type: ${extname(archivePath) || archivePath}`
    );
}

async function assertDirectoryHasFiles(dir: string) {
    if (!existsSync(dir)) {
        throw new Error(`Scan target does not exist: ${dir}`);
    }

    const entries = await readdir(dir, { withFileTypes: true });
    if (entries.length === 0) {
        throw new Error(`Scan target is empty: ${dir}`);
    }
}

async function runSemgrep(scanTarget: string, runId: number) {
    const volumes = [
        {
            hostPath: scanTarget,
            containerPath: "/src",
        },
    ];

    const proc = dockerRun(
        ["semgrep", "--config", "auto", "--json", "--no-git-ignore", "/src"],
        "semgrep/semgrep:latest",
        volumes
    );

    const outputText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        const errText =
            typeof proc.stderr === "string" ? proc.stderr : "Semgrep execution failed";
        throw new Error(`Semgrep failed with exit code ${exitCode}: ${errText}`);
    }

    const parsed = JSON.parse(outputText);
    return parsed.results || [];
}

async function runTrivyFs(scanTarget: string, runId: number) {
    const volumes = [
        {
            hostPath: scanTarget,
            containerPath: "/project",
        },
    ];

    const proc = dockerRun(
        ["fs", "--quiet", "--format", "json", "/project"],
        "aquasec/trivy:latest",
        volumes
    );

    const outputText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        const errText =
            typeof proc.stderr === "string" ? proc.stderr : "Trivy execution failed";
        throw new Error(`Trivy failed with exit code ${exitCode}: ${errText}`);
    }

    const parsed = JSON.parse(outputText);
    return parsed.Results || [];
}

async function runGitleaks(scanTarget: string, runId: number) {
    const volumes = [
        {
            hostPath: scanTarget,
            containerPath: "/path",
        },
    ];

    const proc = dockerRun(
        [
            "detect",
            "--source=/path",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--no-git", // disable built-in git scanning since we're mounting the filesystem directly
        ],
        "zricethezav/gitleaks:latest",
        volumes
    );

    const stdoutText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        /**
         * Gitleaks often exits non-zero when leaks are found.
         * We should try to interpret stdout first before failing hard.
         */
        try {
            if (stdoutText.trim()) {
                const parsed = JSON.parse(stdoutText);
                return Array.isArray(parsed) ? parsed : [];
            }
        } catch {
            // fall through
        }

        /**
         * Conservative fallback:
         * if the tool exits non-zero and does not provide parseable JSON on stdout,
         * treat it as a tool failure rather than "findings".
         */
        throw new Error(`Gitleaks failed with exit code ${exitCode}: ${stdoutText || "unknown error"}`);
    }

    try {
        if (!stdoutText.trim()) return [];
        const parsed = JSON.parse(stdoutText);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

// Run syft to get the sbom
async function runSyft(scanTarget: string, runId: number) {
    const volumes = [
        {
            hostPath: scanTarget,
            containerPath: "/project",
        },
    ];

    const proc = dockerRun(
        ["-o", "cyclonedx-json", "/project"],
        "anchore/syft:latest",
        volumes
    );
    // docker run --rm -v ./:/project anchore/syft:latest -o cyclonedx-json /project

    const outputText = await proc.stdout.text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
        const errText =
            typeof proc.stderr === "string" ? proc.stderr : "Syft execution failed";
        throw new Error(`Syft failed with exit code ${exitCode}: ${errText}`);
    }

    const parsed = JSON.parse(outputText);
    return parsed;
}