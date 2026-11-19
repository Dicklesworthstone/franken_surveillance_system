// Check exact-frame custody and the physical constraints exposed by the motion controls.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  G,
  controls,
  duration,
  fps,
  milestones,
  motionAt,
  motionPath,
  parcelAt,
  presets,
} from "../lib/motion.js";

const read = (name) =>
  readFileSync(new URL("../public/motion/" + name, import.meta.url));
const json = (name) => JSON.parse(read(name));
const digest = (name) => createHash("sha256").update(read(name)).digest("hex");
const near = (a, b, tolerance = 1e-8) =>
  assert.ok(Math.abs(a - b) < tolerance, a + " versus " + b);
const capture = json("capture.json"),
  analysis = json("analysis.json");
assert.deepEqual(capture.parameters, presets[0]);
assert.equal(capture.fps, fps);
assert.equal(capture.seconds, duration);
assert.equal(analysis.capture, "sha256:" + digest("capture.json"));
for (const [file, hash] of Object.entries(capture.files))
  assert.equal(digest(file), hash, file);
for (const cam of ["porch", "drive"]) {
  const v = analysis.views[cam],
    r = json(cam + ".json");
  for (const [name, hash] of [
    [".mp4", v.filmDigest],
    [".mjpeg", v.inputDigest],
    [".json", v.reportDigest],
    ["-sample.jpg", v.sampleDigest],
  ])
    assert.equal("sha256:" + digest(cam + name), hash);
  assert.equal(v.importId, r.import_identity);
  assert.equal(v.candidates, r.candidate_count);
  const cap = r.detector_cascade;
  assert.equal(analysis.model, cap.package_digest);
  assert.equal(v.frames, r.frames_decoded);
  assert.equal(v.frames, duration * analysis.sampleFps);
  assert.equal(v.plateSegment, analysis.sampleFps);
  const input = read(cam + ".mjpeg"),
    plate = read(cam + "-sample.jpg"),
    soi = Buffer.from([255, 216, 255]);
  let start = -1;
  for (let frame = 0; frame <= v.plateSegment; frame++) {
    start = input.indexOf(soi, start + 1);
    assert.notEqual(start, -1);
  }
  assert.deepEqual(input.subarray(start, start + plate.length), plate);
  assert.deepEqual(
    v.samples,
    cap.frames.map((f) => {
      const detections = (f.detections ?? []).map(
        ({ label, score, bounds_subpixel }) => ({
          label,
          score,
          bounds_subpixel,
        }),
      );
      return {
        segment: f.segment,
        status: f.status,
        classes: [...new Set(detections.map((d) => d.label))].sort(),
        detections,
      };
    }),
  );
}

const extremes = controls.reduce(
  (all, c) =>
    all.flatMap((p) =>
      [c.min, c.max].map((value) => ({ ...p, [c.key]: value })),
    ),
  [{}],
);
for (const p of [...presets, ...extremes]) {
  const m = milestones(p);
  assert.ok(m.release < m.contact && m.settle < duration);
  near(motionAt(p, duration).advance, motionPath.distance);
  near(parcelAt(p, m.release).clearance, p.drop);
  near(parcelAt(p, m.contact).clearance, 0);
  const speed = Math.sqrt(2 * G * p.drop);
  near(parcelAt(p, m.contact - 1e-7).speed, -speed, 2e-6);
  near(parcelAt(p, m.contact).speed, speed * p.bounce);
  near(
    parcelAt(p, m.contact + (speed * p.bounce) / G).clearance,
    p.drop * p.bounce ** 2,
  );
  assert.equal(parcelAt(p, m.settle).phase, "At rest");
  let prev = motionAt(p, 0);
  for (let n = 1; n <= duration * fps; n++) {
    const q = motionAt(p, n / fps);
    assert.ok(q.clearance >= 0 && q.advance >= prev.advance - 1e-12);
    for (let side = 0; side < 2; side++) {
      const l = q.legs[side],
        old = prev.legs[side];
      if (l.placed && old.placed) {
        near(q.z - p.height * l.ankle[2], prev.z - p.height * old.ankle[2]);
        near(l.ankle[1], 0.042);
      }
      for (const joint of [l.knee, ...Object.values(q.arms[side])])
        assert.ok(joint.every(Number.isFinite));
    }
    prev = q;
  }
}
console.log(
  "Motion passed 19 gait and drop configurations, reference-film custody and native frame/overlay checks.",
);
