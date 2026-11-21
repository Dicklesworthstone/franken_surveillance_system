import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const digest = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");

// The edited timeline and held-out calibration counts are produced by the native
// replay in scripts/check_residential_class_fusion.py. The native report alone
// cannot reconstruct which frames of the original films were used in the cut.
const qualifiedReplay = "sha256:26ccb9d4ecf0f711a1d68e3134084a8a162107b35b5601d55d1764983e4833d7";

export function readFusionExcerpt(directory, sceneBytes) {
  const file = join(directory, "fusion-replay.json");
  if (!existsSync(file)) return null;
  const bytes = readFileSync(file);
  assert.equal(digest(bytes), qualifiedReplay, "Edited fusion replay differs from qualified output");
  const replay = JSON.parse(bytes);
  assert.equal(digest(sceneBytes), replay.scene_sha256, "Fusion replay scene differs");
  const scene = JSON.parse(sceneBytes);
  for (const source of replay.cameras) {
    const camera = scene.cameras.find((c) => c.id === source.camera);
    assert.equal("sha256:" + camera?.video_sha256, source.source_film_sha256, "Fusion replay film differs");
  }
  const report = readFileSync(join(directory, replay.report.path));
  assert.equal(digest(report), replay.report.sha256, "Native fusion report differs");
  assert.equal(JSON.parse(report).calibrated_class_advice.report_digest, replay.report.advice_digest);
  return replay;
}
