import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { G } from "../lib/motion.js";
import {
  clipSeconds,
  conditions,
  drag,
  flight,
  frameRate,
  freeBall,
  parameters,
  passAt,
  radius,
} from "../lib/pass.js";
const bytes = (f) =>
  readFileSync(new URL("../public/court/" + f, import.meta.url));
const json = (f) => JSON.parse(bytes(f)),
  hash = (f) => "sha256:" + createHash("sha256").update(bytes(f)).digest("hex");
const cap = json("capture.json"),
  idx = json("analysis.json");
assert.equal(idx.capture, hash("capture.json"));
assert.deepEqual(cap.parameters, conditions[0]);
assert.equal(cap.fps, frameRate);
assert.equal(cap.seconds, clipSeconds);
for (const [f, h] of Object.entries(cap.files))
  assert.equal(hash(f), "sha256:" + h, f);
for (const [f, h] of Object.entries(cap.assets))
  assert.equal(hash(f), "sha256:" + h, f);
const close = (a, b, tol = 1e-7) =>
  assert.ok(Math.abs(a - b) < tol, a + " vs " + b);
const combos = parameters.reduce(
  (cs, c) =>
    cs.flatMap((p) => [c.min, c.max].map((v) => ({ ...p, [c.key]: v }))),
  [{ style: "bounce" }, { style: "chest" }],
);
for (const p of [...conditions, ...combos]) {
  const f = flight(p),
    q = passAt(p, 0),
    h = 1e-5;
  assert.ok(q.arrival < clipSeconds);
  close(freeBall(p, f, f.travel).x, f.catchX);
  close(freeBall(p, f, f.first).y, radius);
  const down = (freeBall(p, f, f.first - h).y - radius) / h,
    up = (freeBall(p, f, f.first + h).y - radius) / h;
  close(up / down, p.rebound, 0.0001);
  const t = 0.11,
    moving = freeBall(p, f, t);
  close(
    (freeBall(p, f, t + h).x - moving.x) / h,
    p.speed * Math.exp(-drag * t),
    0.0001,
  );
  close(moving.y, f.y0 + f.vy * t - (G * t * t) / 2);
  assert.equal(
    passAt(p, q.arrival).phase,
    q.caught ? "Caught" : "Missed catch",
  );
  for (let n = 0; n <= clipSeconds * frameRate; n++)
    assert.ok(passAt(p, n / frameRate).ball.y >= radius);
}
assert.equal(passAt(conditions[0], clipSeconds).phase, "Caught");
assert.equal(passAt(conditions[2], clipSeconds).phase, "Missed catch");
for (const [id, v] of Object.entries(idx.views)) {
  const watch = json(id + ".json"),
    inspection = json(id + "-inspection.json");
  for (const [suffix, h] of [
    [".mp4", v.filmDigest],
    [".mjpeg", v.inputDigest],
    [".json", v.reportDigest],
    ["-inspection.json", v.inspectionDigest],
    ["-sample.jpg", v.sampleDigest],
  ])
    assert.equal(hash(id + suffix), h);
  assert.equal(v.importId, watch.import_identity);
  assert.equal(inspection.source_import, v.importId);
  assert.equal(
    inspection.package_digest,
    watch.detector_cascade.package_digest,
  );
  assert.equal(inspection.package_digest, idx.model);
  assert.equal(inspection.frames.length, 1);
  assert.equal(inspection.frames[0].segment, 4);
  assert.deepEqual(inspection.frames[0].dimensions, [160, 90]);
  assert.equal(watch.frames_decoded, idx.sampleFps * clipSeconds);
  const stream = bytes(id + ".mjpeg"),
    starts = [],
    soi = Buffer.from([255, 216, 255]);
  for (
    let offset = stream.indexOf(soi);
    offset >= 0;
    offset = stream.indexOf(soi, offset + 1)
  )
    starts.push(offset);
  assert.equal(starts.length, watch.frames_decoded);
  starts.push(stream.length);
  for (const [n, digest] of Object.entries(v.frameDigests)) {
    const i = Number(n),
      file = id + "-" + n + ".jpg";
    assert.equal(hash(file), digest);
    assert.deepEqual(bytes(file), stream.subarray(starts[i], starts[i + 1]));
  }
  assert.deepEqual(
    v.samples,
    watch.detector_cascade.frames.map((f) => {
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
const earlier = json("earlier/source.json"),
  earlierWatch = json("earlier/garden.json");
for (const [f, h] of [
  ["garden.mp4", earlier.filmDigest],
  ["garden.mjpeg", earlier.inputDigest],
  ["garden.json", earlier.reportDigest],
  ["frame.jpg", earlier.frameDigest],
])
  assert.equal(hash("earlier/" + f), h);
assert.equal(earlier.importId, earlierWatch.import_identity);
assert.notEqual(earlier.importId, idx.views.garden.importId);
const frames = bytes("earlier/garden.mjpeg"),
  start = Buffer.from([255, 216, 255]);
let a = -1;
for (let n = 0; n <= earlier.segment; n++) a = frames.indexOf(start, a + 1);
assert.deepEqual(
  frames.subarray(a, frames.indexOf(start, a + 1)),
  bytes("earlier/frame.jpg"),
);
assert.ok(
  earlierWatch.detector_cascade.frames
    .find((f) => f.segment === earlier.segment)
    .detections.some((d) => d.label === "bicycle"),
);
console.log(
  "Courtyard verified across both pass styles, all 32 parameter corners, three authored passes, two exact-frame native inspections and the earlier false positive.",
);
