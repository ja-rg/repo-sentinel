type Volume = {
    hostPath: string;
    containerPath: string;
};

const dockerRun = (cmd: string[], image: string, volumes: Volume[]) => {
    const volumeArgs = volumes.flatMap(({ hostPath, containerPath }) => [
        "-v",
        `${hostPath}:${containerPath}`,
    ]);

    const fullCmd = ["docker", "run", "--rm", ...volumeArgs, image, ...cmd];

    console.log(`Running command: ${fullCmd.join(" ")}`);
    return Bun.spawn(fullCmd);
};

export { dockerRun };