const children = [
  // Add a cd frontend/ && bun run build step for the frontend if you have one
  Bun.spawn(["cd", "frontend/", "&&", "bun", "run", "build"], {
    stdout: "inherit",
    stderr: "inherit",
  }),
  Bun.spawn(["bun", "run", "api-server.ts"], {
    stdout: "inherit",
    stderr: "inherit",
  }),
  Bun.spawn(["bun", "run", "runner.ts"], {
    stdout: "inherit",
    stderr: "inherit",
  }),
  Bun.spawn(["bun", "run", "workers.ts"], {
    stdout: "inherit",
    stderr: "inherit",
  }),
];

function shutdown() {
  for (const child of children) {
    try {
      child.kill();
    } catch {
      // ignore
    }
  }
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await Promise.all(children.map((child) => child.exited));
