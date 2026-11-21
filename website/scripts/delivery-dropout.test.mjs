import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { readDeliveryDropout } from "../lib/watch/delivery-dropout.mjs";

const source = fileURLToPath(new URL("../public/watch/delivery-dropout/", import.meta.url));
const scene = fileURLToPath(new URL("../public/watch/intrusion/scene.json", import.meta.url));
test("surviving frames retain the shared movie clock on both sides of the real gap", () => {
  const replay = readDeliveryDropout(source, scene);
  assert.deepEqual(replay.complete.frames, Array.from({ length: 64 }, (_, i) => i));
  assert.deepEqual(replay.dropout.frames.slice(23, 41), [23, ...Array(16).fill(null), 24]);
  assert.ok(replay.dropout.witnesses.some(([a, b]) => a < 3 && b <= 3));
  assert.ok(replay.dropout.witnesses.some(([a, b]) => a >= 5 && b > 5));
  assert.ok(replay.dropout.witnesses.every(([a, b]) => b <= 3 || a >= 5));
});

test("each displayed tile reproduces its own retained camera picture and source film frame", () => {
  const replay = readDeliveryDropout(source, scene);
  const width = 64, height = 36, size = width * height;
  function decode(file, filter = "") {
    const bytes = execFileSync("ffmpeg", ["-v", "error", "-i", join(source, file), "-vf",
      filter + "scale=64:36,format=gray", "-fps_mode", "passthrough", "-f", "rawvideo",
      "-threads", "1", "pipe:1"]);
    assert.equal(bytes.length % size, 0);
    return Array.from({ length: bytes.length / size }, (_, i) => bytes.subarray(i * size, (i + 1) * size));
  }
  function checkPicture(a, b, context) {
    let error = 0;
    for (let i = 0; i < size; i++) error += Math.abs(a[i] - b[i]);
    assert.ok(error / size < 0.8, context + " mean luma difference " + error / size);
  }
  const original = decode("source.mp4");
  assert.equal(original.length, 192);
  for (const name of ["complete", "dropout"]) {
    const side = replay[name];
    const recording = decode(name + ".mkv");
    const tiles = decode(name + ".webp", `untile=8x${side.samples / 8},`);
    assert.deepEqual([recording.length, tiles.length], [side.samples, side.samples]);
    side.frames.forEach((segment, i) => {
      if (segment === null) return;
      checkPicture(recording[segment], original[i * 3], name + " source frame " + i * 3);
      checkPicture(tiles[segment], recording[segment], name + " camera frame " + segment);
    });
  }
});

test("a cross-gap native claim and a substituted sample both fail release verification", t => {
  const copy = mkdtempSync(join(tmpdir(), "fss-dropout-test-"));
  t.after(() => rmSync(copy, { recursive: true, force: true }));
  cpSync(source, copy, { recursive: true });
  // Update the fixture manifest too. The gate must catch contradictory content, even with a matching digest.
  function replace(file, content) {
    writeFileSync(join(copy, file), content);
    const manifest = JSON.parse(readFileSync(join(copy, "replay.json")));
    manifest.files[file] = createHash("sha256").update(content).digest("hex");
    writeFileSync(join(copy, "replay.json"), JSON.stringify(manifest));
  }
  const name = "dropout-watch-0.json";
  const bytes = readFileSync(join(copy, name));
  const report = JSON.parse(bytes);
  const record = report.coverage.records[0];
  assert.ok(record.presentation_timing_checked);
  delete record.presentation_timing_checked;
  replace(name, JSON.stringify(report));
  assert.throws(() => readDeliveryDropout(copy, scene), /did not verify movie presentation timing/);
  record.presentation_timing_checked = true;
  const gap = record.zones[0].uncovered.find(g => g.reason === "presentation_continuity_unproven");
  assert.ok(gap);
  gap.reason = "background_warmup";
  replace(name, JSON.stringify(report));
  assert.throws(() => readDeliveryDropout(copy, scene), /Watch continuity gaps differ/);
  gap.reason = "presentation_continuity_unproven";
  const originalBounds = gap.capture_ns;
  gap.capture_ns = [103_000_000_000, 104_000_000_000];
  replace(name, JSON.stringify(report));
  assert.throws(() => readDeliveryDropout(copy, scene), /does not cover the missing pictures/);
  gap.capture_ns = originalBounds;
  assert.ok(report.coverage.records[0].zones[0].witnesses.length);
  report.coverage.records[0].zones[0].witnesses[0].covered_ns[1] = 104_000_000_000;
  replace(name, JSON.stringify(report));
  assert.throws(() => readDeliveryDropout(copy, scene), /witness crosses source dropout/);
  // A closed native witness ending on the very first missing tick is also unsafe.
  report.coverage.records[0].zones[0].witnesses[0].covered_ns[1] = 103_000_000_000;
  replace(name, JSON.stringify(report));
  assert.throws(() => readDeliveryDropout(copy, scene), /witness crosses source dropout/);
  replace(name, bytes);
  const movie = "dropout-movie.txt";
  const rows = readFileSync(join(copy, movie), "utf8");
  const mutated = rows.replace(/(movie_sample=24 [^\n]*?source_offset=)(\d+)/, (_, prefix, n) => prefix + (Number(n) + 1));
  assert.notEqual(mutated, rows);
  replace(movie, mutated);
  assert.throws(() => readDeliveryDropout(copy, scene), /Surviving camera packet differs/);
});
