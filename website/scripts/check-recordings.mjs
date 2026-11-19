// Validate the media/evidence relationships before preparing a public export.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { imageToGround } from "../lib/cameras.js";
import {
  cases,
  cameras,
  cameraAsset,
  DURATION,
  recording,
} from "../lib/scenarios.js";

const root = new URL("../public/", import.meta.url);
const read = (path) => readFile(new URL(path, root));
const json = async (path) => JSON.parse(await read(path));
async function verified(path, digest) {
  const bytes = await read(path);
  assert.equal(
    "sha256:" + createHash("sha256").update(bytes).digest("hex"),
    digest,
    path + " differs from the indexed analysis",
  );
  return bytes;
}
const rig = await json("films/rig.json");
const index = await json("evidence/index.json");
assert.deepEqual(rig.recording, recording);
assert.equal(rig.duration, DURATION);
for (const camera of cameras) {
  const actual = rig.cameras[camera.id].imageToGround;
  const expected = imageToGround(
    camera,
    recording.nativeWidth,
    recording.nativeHeight,
  );
  assert.equal(actual.length, expected.length);
  assert.ok(
    expected.every((x, i) => Math.abs(x - actual[i]) < 1e-10),
    camera.id + " ground projection has changed",
  );
}
for (const s of cases) {
  const { views, pairs } = index[s.id];
  const rigCase = rig.cases[s.id];
  const [x, x1, z, z1] = s.zoneBounds;
  assert.deepEqual(rigCase.zone.rect, [x, z, x1 - x, z1 - z]);
  for (const c of cameras) {
    const view = views[c.id],
      stem = cameraAsset(s, c.id);
    assert.equal(view.asset, stem);
    assert.deepEqual(rigCase.views[c.id], {
      asset: stem,
      visibility: view.visibility,
    });
    await verified("films/" + stem + ".mp4", view.filmDigest);
    await verified("evidence/" + stem + ".mjpeg", view.inputDigest);
    const report = JSON.parse(
      await verified("evidence/" + stem + ".json", view.reportDigest),
    );
    assert.equal(report.import_identity, view.importId);
    assert.equal(report.frames_decoded, DURATION * recording.nativeFps);
    assert.deepEqual(
      [report.width, report.height],
      [recording.nativeWidth, recording.nativeHeight],
    );
    assert.equal(view.candidates, report.candidates.length);
    assert.equal(view.frames, report.frames_decoded);
    assert.deepEqual(
      view.entries,
      report.candidates.map((c) => ({
        time: c.entry_segment / recording.nativeFps,
        track: c.track_id,
        kind: c.event_kind,
      })),
    );
  }
  for (let i = 0; i < cameras.length; i++) {
    for (const other of cameras.slice(i + 1)) {
      const ids = [cameras[i].id, other.id].sort();
      const pair = pairs[ids.join("-")];
      assert.equal(pair.report, s.id + "-" + ids.join("-") + ".json");
      const report = JSON.parse(
        await verified("evidence/" + pair.report, pair.reportDigest),
      );
      assert.deepEqual(report.cameras.map((c) => c.camera).sort(), ids);
      for (const c of report.cameras)
        assert.equal(c.import_identity, views[c.camera].importId);
      assert.deepEqual(report.zones, [
        { zone_id: rigCase.zone.id, x, y: z, width: x1 - x, height: z1 - z },
      ]);
      assert.equal(report.dependencies.dependency_cluster_count, 1);
      assert.equal(report.dependencies.independence_certified, false);
      assert.equal(report.effects_authorized, false);
    }
  }
}
console.log(
  "Verified the films, native inputs, camera reports and pair reports for every encounter.",
);
