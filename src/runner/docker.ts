type Volume = {
    hostPath: string;
    containerPath: string;
};

import { isAbsolute, resolve } from "node:path";

const dockerRun = (cmd: string[], image: string, volumes: Volume[], network?: string) => {
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

    console.log(`Running command: ${fullCmd.join(" ")}`);
    return Bun.spawn(fullCmd, {
        stdout: "pipe",
        stderr: "pipe",
    });
};

export { dockerRun };