import { processDockerfile } from "./runner/process-dockerfile";
import { processImage } from "./runner/process-image";
import { processManifest } from "./runner/process-manifest";
import { processRepoOrArchive } from "./runner/process-repo-or-archive";
import { claimNextPendingRun, markRunDone, markRunFailed } from "./runner/update-runs";

while (true) {
  const run = claimNextPendingRun();
  if (!run) {
    await Bun.sleep(1000);
    continue;
  }

  let findings = {}, decision: Record<string, unknown> = {};

  try {
    switch (run.kind) {
      case "dockerfile":
        findings = await processDockerfile(run);
        break;
      case "image":
        findings = await processImage(run);
        break;
      case "repo":
      case "archive":
        findings = await processRepoOrArchive(run);
        break;
      case "k8s_manifest":
        [findings, decision] = await processManifest(run);
        break;
      default:
        throw new Error(`Unknown run kind: ${run.kind}`);
    }
    markRunDone(run.id, JSON.stringify(findings), JSON.stringify(decision));

  } catch (err) {
    markRunFailed(run.id, String(err));
  }
}