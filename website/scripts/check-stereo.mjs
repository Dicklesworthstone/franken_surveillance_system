import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  imageSize,
  moments,
  cameraRig,
  referenceFrame,
  reconstruct,
} from "../lib/stereo.js";
const read = (f) => readFileSync(new URL("../public/" + f, import.meta.url));
const digest = (b) => "sha256:" + createHash("sha256").update(b).digest("hex");
const json = (f) => JSON.parse(read("stereo/" + f));
const capture = json("capture.json"),
  rig = json("rig.json");
assert.deepEqual(imageSize, capture.imageSize);
assert.equal(rig.twin_digest, digest(read("stereo/floor.fsstwin")));
assert.equal(rig.source_scene_digest, digest(read("stereo/capture.json")));
for (const [f, pin] of Object.entries(capture.files))
  assert.equal(digest(read("stereo/" + f)), pin, f);
for (const [id, c] of Object.entries(capture.cameras))
  assert.equal(c.digest, digest(read("court/" + id + ".mp4")));
for (const { frame } of moments) {
  const { marks, point } = referenceFrame(frame),
    fit = reconstruct(marks);
  assert.equal(fit.status, "fit");
  assert.ok(fit.residual < 1e-8);
  assert.ok(Math.hypot(...point.map((v, i) => v - fit.point[i])) < 1e-8);
  assert.equal(reconstruct({ ...marks, patio: null }).status, "waiting");
  assert.equal(reconstruct({ ...marks, patio: [20, 15] }).status, "disagrees");
  const fixture = capture.moments.find((v) => v.frame === frame);
  assert.deepEqual(fixture.marks, marks);
  assert.deepEqual(fixture.point, point);
  const query = json("query-" + frame + ".json"),
    r = json("report-" + frame + ".json").report;
  assert.equal(query.camera_rig_digest, digest(read("stereo/rig.json")));
  assert.equal(
    r.reference_time_ns,
    String(Math.round((frame * 1e9) / capture.fps)),
  );
  const h = r.hypotheses[0];
  assert.equal(h.knowledge, "estimated");
  const [x, y, z] = h.estimate.position;
  assert.ok(Math.hypot(x - point[0], z - point[1], -y - point[2]) < 1e-8);
  assert.ok(h.estimate.rms_reprojection_pixels < 1e-8);
  for (const [i, id] of Object.keys(cameraRig).entries()) {
    const o = query.hypotheses[0].observations[i];
    assert.deepEqual(o.pixel_min, marks[id]);
    assert.equal(o.source_digest, capture.files[id + "-" + frame + ".png"]);
    assert.equal(
      o.evidence_digest,
      digest(read("stereo/" + id + "-" + frame + "-mark.json")),
    );
    assert.equal(h.observations[i].evidence_digest, o.evidence_digest);
  }
}
console.log(
  "Stereo passed at three instants, including exact source frames, mark custody, native 3D estimates, disagreement and single-view depth.",
);
