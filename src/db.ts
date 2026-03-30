import { Database } from "bun:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";


export const DATA_DIR = "./data";
export const DB_PATH = join(DATA_DIR, "reposentinel.sqlite");

if (!existsSync(DATA_DIR)) {
    mkdirSync(DATA_DIR, { recursive: true });
}

export const db = new Database(DB_PATH);

// Concurrency/availability tuning for multi-process access.
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA synchronous = NORMAL;");
db.exec("PRAGMA busy_timeout = 5000;");
db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA temp_store = MEMORY;");
db.exec("PRAGMA wal_autocheckpoint = 1000;");

let dbClosed = false;

export function closeDatabase() {
    if (dbClosed) return;
    dbClosed = true;
    try {
        db.close();
    } catch {
        // best effort close
    }
}

function registerDbShutdownHandlers() {
    const close = () => closeDatabase();

    process.once("SIGINT", close);
    process.once("SIGTERM", close);
    process.once("beforeExit", close);
    process.once("exit", close);
}

registerDbShutdownHandlers();