import { WORKER_HEARTBEAT_TIMEOUT_SECONDS } from "./src/api/health-helper";
import { db } from "./src/db";

setInterval(() => {
  reconcileWorkerHeartbeats();
}, 10000); // cada 10s

function isPidAlive(pid: number) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function reconcileWorkerHeartbeats() {
  const candidates = db.query(`
    SELECT worker_id, pid, status
    FROM worker_heartbeats
    WHERE (strftime('%s','now') - strftime('%s', last_seen_at)) > ?1
      AND status != 'terminated'
  `).all(WORKER_HEARTBEAT_TIMEOUT_SECONDS) as {
    worker_id: string;
    pid: number | null;
    status: string;
  }[];

  const terminatedWorkerIds: string[] = [];

  for (const worker of candidates) {
    if (typeof worker.pid !== "number") {
      terminatedWorkerIds.push(worker.worker_id);
      continue;
    }

    if (!isPidAlive(worker.pid)) {
      terminatedWorkerIds.push(worker.worker_id);
    }
  }

  if (terminatedWorkerIds.length === 0) {
    return;
  }

  const markTerminated = db.query(`
    UPDATE worker_heartbeats
    SET status = 'terminated', pid = NULL, current_run_id = NULL
    WHERE worker_id = ?1
  `);

  const applyTerminationUpdates = db.transaction((workerIds: string[]) => {
    for (const workerId of workerIds) {
      markTerminated.run(workerId);
    }
  });

  applyTerminationUpdates(terminatedWorkerIds);
}
