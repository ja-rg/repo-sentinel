import { Hono } from "hono";
import { cors } from "hono/cors";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { getRun, insertRun, listRuns } from "./src/api/db-actions";
import { buildHealthReport } from "./src/api/health-helper";
import {
  isValidKind,
  parseCreateRunRequest,
  rowToApi,
} from "./src/api/request-utilities";
import { DATA_DIR, DB_PATH } from "./src/db";
import { serveStatic } from "hono/bun";

const app = new Hono();
let workerProcess: Bun.Subprocess | null = null;
let workerProcessAlive = false;

function hasLiveWorkerProcess() {
  return workerProcessAlive;
}

function ensureWorkerProcess() {
  if (hasLiveWorkerProcess()) {
    return { started: false, pid: workerProcess?.pid ?? null };
  }

  workerProcess = Bun.spawn(["bun", "run", "runner.ts"], {
    stdout: "inherit",
    stderr: "inherit",
  });

  workerProcessAlive = true;
  workerProcess.exited.finally(() => {
    workerProcessAlive = false;
    workerProcess = null;
  });

  return { started: true, pid: workerProcess.pid };
}

app.use("*", cors());

app.get("/health", async (c) => {
  const report = await buildHealthReport(DB_PATH);
  const status = report.status === "fail" ? 503 : 200;
  return c.json(report, status);
});

app.post("/workers/ensure", async (c) => {
  const report = await buildHealthReport(DB_PATH);

  if (report.worker.active_workers > 0) {
    return c.json({
      ok: true,
      started: false,
      message: "At least one worker is already active.",
      worker: report.worker,
    });
  }

  const spawned = ensureWorkerProcess();
  return c.json({
    ok: true,
    started: spawned.started,
    pid: spawned.pid,
    message: spawned.started
      ? "Worker started."
      : "Worker already managed by API process.",
  });
});

app.post("/analysis-runs", async (c) => {
  try {
    const parsed = await parseCreateRunRequest(c);
    if (parsed instanceof Response) return parsed;

    const { kind, input_ref, file } = parsed;

    if (!isValidKind(kind)) {
      return c.json({
        error:
          "Invalid kind. Use one of: repo, archive, dockerfile, image, k8s_manifest",
      }, 400);
    }

    const isJsonKind = kind === "repo" || kind === "image";
    const isUploadKind = kind === "archive" || kind === "dockerfile" ||
      kind === "k8s_manifest";

    if (isJsonKind) {
      if (typeof input_ref !== "string" || input_ref.trim() === "") {
        return c.json({ error: "input_ref must be a non-empty string" }, 400);
      }

      const row = insertRun.get(kind, input_ref.trim());
      return c.json(rowToApi(row), 201);
    }

    if (!(file instanceof File)) {
      return c.json({ error: "file is required" }, 400);
    }

    if (!isUploadKind) {
      return c.json({ error: "Unsupported kind" }, 400);
    }

    const normalizedInputRef =
      typeof input_ref === "string" && input_ref.trim() !== ""
        ? input_ref.trim()
        : file.name || `${kind}-upload`;

    const row = insertRun.get(kind, normalizedInputRef);
    const apiRow = rowToApi(row);

    const runDir = join(DATA_DIR, "runs", String(apiRow.id));
    mkdirSync(runDir, { recursive: true });

    const filename = file.name || `${kind}-upload`;
    const filepath = join(runDir, filename);

    await Bun.write(filepath, file);

    return c.json(
      {
        ...apiRow,
        upload: {
          name: filename,
          size: file.size,
          type: file.type,
          path: filepath,
        },
      },
      201,
    );
  } catch (error) {
    console.error("[analysis-runs] request parse failed:", error);
    return c.json({ error: "Failed to parse request body" }, 400);
  }
});

app.get("/analysis-runs", (c) => {
  const limitRaw = Number(c.req.query("limit") ?? 20);
  const limit = Number.isFinite(limitRaw)
    ? Math.max(1, Math.min(100, Math.trunc(limitRaw)))
    : 20;
  const rows = listRuns.all(limit).map(rowToApi);
  return c.json(rows);
});

app.get("/analysis-runs/:id", (c) => {
  const idRaw = c.req.param("id");
  const id = Number(idRaw);

  if (!Number.isInteger(id) || id <= 0) {
    return c.json({ error: "Invalid analysis run id" }, 400);
  }

  const row = getRun.get(id);
  if (!row) {
    return c.json({ error: "Analysis run not found" }, 404);
  }

  return c.json(rowToApi(row));
});

app.use("/assets/*", serveStatic({ root: "./dist" }));
app.get("*", async (c) => {
  try {
    const html = await Bun.file("./dist/index.html").text();
    return c.html(html);
  } catch {
    return c.json({ message: "API running" });
  }
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

const port = Number(process.env.PORT ?? 3000);
const server = Bun.serve({ port, fetch: app.fetch });

console.log(
  `RepoSentinel API listening on http://${server.hostname}:${server.port}`,
);
console.log(`SQLite DB: ${DB_PATH}`);
