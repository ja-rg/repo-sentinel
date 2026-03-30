import { WORKER_STALE_SECONDS } from "./src/api/health-helper";
import { db } from "./src/db";

setInterval(() => {
  cleanupStaleWorkers();
}, 10000); // cada 10s

function cleanupStaleWorkers() {
  const stale = db.query(`
    SELECT worker_id, pid
    FROM worker_heartbeats
    WHERE (strftime('%s','now') - strftime('%s', last_seen_at)) > ?1
  `).all(WORKER_STALE_SECONDS) as { worker_id: string; pid: number | null }[];

  for (const worker of stale) {
    if (worker.pid) {
      try {
        process.kill(worker.pid);
      } catch {}
    }
  }

  const markStale = db.query(`
    UPDATE worker_heartbeats
    SET status = 'stale', pid = NULL
    WHERE worker_id = ?1
  `);

  const applyStaleUpdates = db.transaction((workerIds: string[]) => {
    for (const workerId of workerIds) {
      markStale.run(workerId);
    }
  });

  applyStaleUpdates(stale.map((worker) => worker.worker_id));
}
