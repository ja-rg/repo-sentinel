type Volume = {
    hostPath: string;
    containerPath: string;
};

import { isAbsolute, resolve } from "node:path";
import { finishRunCommand, insertRunCommand } from "../api/db-actions";

type ExecuteDockerToolInput = {
    runId: number;
    tool: string;
    stage: string;
    command: string[];
    image: string;
    volumes: Volume[];
    network?: string;
    verbose?: boolean;
};

type ExecuteDockerToolResult = {
    command: string[];
    stdout: string;
    stderr: string;
    exitCode: number;
    durationMs: number;
};

const MAX_OUTPUT_BYTES = 64 * 1024;

function truncateOutput(text: string) {
    if (text.length <= MAX_OUTPUT_BYTES) return text;
    return `${text.slice(0, MAX_OUTPUT_BYTES)}\n...[truncated]`;
}

const buildDockerRunCommand = (cmd: string[], image: string, volumes: Volume[], network?: string) => {
    const volumeArgs = volumes.flatMap(({ hostPath, containerPath }) => {
        const absoluteHostPath = isAbsolute(hostPath)
            ? hostPath
            : resolve(hostPath);

        return [
            "-v",
            `${absoluteHostPath}:${containerPath}`,
        ];
    });

    const fullCmd = !network ?
        ["docker", "run", "--rm", ...volumeArgs, image, ...cmd] :
        ["docker", "run", "--rm", "--network", network, ...volumeArgs, image, ...cmd];

    return fullCmd;
};

const dockerRun = (cmd: string[], image: string, volumes: Volume[], network?: string) => {
    const fullCmd = buildDockerRunCommand(cmd, image, volumes, network);

    console.log(`Running command: ${fullCmd.join(" ")}`);
    return Bun.spawn(fullCmd, {
        stdout: "pipe",
        stderr: "pipe",
    });
};

async function executeDockerTool(input: ExecuteDockerToolInput): Promise<ExecuteDockerToolResult> {
    const fullCmd = buildDockerRunCommand(input.command, input.image, input.volumes, input.network);
    const startedAt = Date.now();
    const commandText = fullCmd.join(" ");

    const commandRow = insertRunCommand.get(
        input.runId,
        input.tool,
        input.stage,
        input.image,
        commandText,
        JSON.stringify(fullCmd),
    ) as { id: number };

    const proc = Bun.spawn(fullCmd, {
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;
    const durationMs = Date.now() - startedAt;

    finishRunCommand.get(
        commandRow.id,
        truncateOutput(stdout),
        truncateOutput(stderr),
        exitCode,
        durationMs,
    );

    if (input.verbose) {
        console.log(`Command(${input.tool}): ${commandText}`);
        if (stdout.trim()) {
            console.log(`stdout(${input.tool}): ${truncateOutput(stdout)}`);
        }
        if (stderr.trim()) {
            console.log(`stderr(${input.tool}): ${truncateOutput(stderr)}`);
        }
    }

    return {
        command: fullCmd,
        stdout,
        stderr,
        exitCode,
        durationMs,
    };
}

export { dockerRun, executeDockerTool };