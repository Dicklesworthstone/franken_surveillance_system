// Check the exported bytes that supply the five-camera replay and its detector overlays.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fromReports, objectReader, renderIdentity, sha256 as hash } from "../lib/watch/retained.mjs";
import { readRelayReplay } from "../lib/watch/relay-replay.mjs";
import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { readFusionExcerpt } from "../lib/watch/fusion-excerpt.mjs";

function verifyMovie(path, custody, format, id) {
  const { streams: [stream] } = JSON.parse(execFileSync("ffprobe", [
    "-v", "error", "-protocol_whitelist", "file", "-select_streams", "v:0", "-count_packets", "-show_entries",
    "stream=codec_name,profile,width,height,r_frame_rate,nb_read_packets,duration", "-of", "json", path,
  ], { encoding: "utf8" }));
  assert.ok(stream, id + " missing video stream");
  const [num, den] = stream.r_frame_rate.split("/").map(Number);
  assert.ok(num > 0 && den > 0 && Number.isFinite(num / den), id + " movie time base");
  assert.equal(custody.fps, num / den, id + " film frame rate");
  assert.equal(custody.codec, stream.codec_name + " " + (stream.profile ?? "None"), id + " film codec");
  assert.ok((format === "mp4avc" && stream.codec_name === "h264") ||
    (format === "mp4hevc" && stream.codec_name === "hevc"), id + " retained movie format");
  assert.equal(custody.frames, Number(stream.nb_read_packets), id + " film frames");
  assert.deepEqual([custody.width, custody.height], [stream.width, stream.height], id + " encoded dimensions");
  const displayedSeconds = custody.duration_seconds ?? custody.frames / custody.fps;
  assert.ok(Math.abs(displayedSeconds - Number(stream.duration)) <= 0.000001, id + " film duration");
}

function checkReferences(value, read) {
  if (typeof value === "string" && value.startsWith("native/")) read(value);
  else if (value && typeof value === "object")
    for (const child of Object.values(value)) checkReferences(child, read);
}

// The authoring code rounds coordinates twice: to five decimals in the native
// summary and to three in the small browser file. Check each rounding boundary.
function rounded(actual, source, digits, context) {
  assert.ok(Number.isFinite(actual) && Number.isFinite(source) &&
    actual === Number(actual.toFixed(digits)) &&
    Math.abs(actual - source) <= 0.5 * 10 ** -digits + Number.EPSILON, context);
}

function verifyDetections(camera, clock, native, overlay, read) {
  const detection = native.detections;
  const summaries = new Map((detection?.frames ?? []).map(row => [row.segment, row]));
  assert.equal(summaries.size, detection?.frames?.length ?? 0, "Duplicate detector segment");
  const seen = new Set();
  const positiveFrames = [];
  const epoch = BigInt(Date.parse(clock.start)) * 1_000_000n;
  for (const range of detection?.reports ?? []) {
    const outer = JSON.parse(read(range.report));
    for (const child of outer.reports ?? outer.bursts ?? [outer]) {
      const report = child.report ?? child;
      assert.equal(report.source_import, native.custody.import_id, camera.id + " detector source");
      assert.equal(report.box_subpixels, 256);
      for (const frame of report.frames) {
        assert.equal(frame.sensor_id, "sensor:" + camera.id);
        assert.deepEqual(frame.dimensions, [camera.width, camera.height]);
        const summary = summaries.get(frame.segment);
        assert.ok(summary && !seen.has(summary.frame), "Repeated or unlisted detector frame");
        const { earliest_ns, latest_ns } = frame.capture;
        const time = Number(BigInt(earliest_ns) + BigInt(latest_ns) - 2n * epoch) / 2e9;
        rounded(summary.t, time, 4, "Detector capture time");
        assert.equal(summary.frame, Math.round(time * clock.fps), "Detector overlay frame");
        assert.ok(summary.frame >= 0 && summary.frame < clock.frames);
        assert.equal(summary.capsule, frame.capsule_digest);
        seen.add(summary.frame);
        assert.equal(summary.detections.length, frame.detections.length);
        const people = [];
        for (const [i, raw] of frame.detections.entries()) {
          const row = summary.detections[i];
          assert.equal(row.label, raw.label);
          rounded(row.score, raw.score, 4, "Detector score");
          assert.equal(row.box.length, 4);
          for (const [axis, coordinate] of row.box.entries()) {
            const pixels = frame.dimensions[axis % 2];
            rounded(coordinate, raw.bounds_subpixel[axis] / (pixels * 256), 5, "Detector box");
          }
          if (row.label === "person") people.push(row);
        }
        if (people.length && overlay) {
          positiveFrames.push(String(summary.frame));
          const boxes = overlay.person[summary.frame];
          assert.equal(boxes?.length, people.length, "Missing person box");
          for (const [i, row] of people.entries()) {
            assert.equal(boxes[i].length, 5);
            row.box.forEach((v, axis) => rounded(boxes[i][axis], v, 3, "Browser box"));
            rounded(boxes[i][4], row.score, 2, "Browser score");
          }
        }
      }
    }
  }
  assert.equal(seen.size, summaries.size, "Missing native detector frames");
  if (detection?.frames_inferred !== undefined) assert.equal(detection.frames_inferred, seen.size);
  if (overlay) {
    assert.deepEqual(overlay.inferred, [...seen].sort((a, b) => a - b));
    assert.deepEqual(Object.keys(overlay.person).sort(), positiveFrames.sort());
  }
  return seen.size;
}

export function verifyWatchTake(directory) {
  const sceneBytes = readFileSync(join(directory, "scene.json"));
  const scene = JSON.parse(sceneBytes);
  const fusion = readFusionExcerpt(directory, sceneBytes);
  const relay = readRelayReplay(directory, sceneBytes);
  const name = basename(directory);
  assert.equal(scene.take, name);
  const nativeFile = join(directory, "native.json");
  const boxesFile = join(directory, "native-boxes.json");
  const nativeBytes = existsSync(nativeFile) ? readFileSync(nativeFile) : null;
  const native = nativeBytes ? JSON.parse(nativeBytes) : null;
  const retained = native?.retained_objects ? new Set(native.retained_objects) : null;
  const read = objectReader(directory, retained);
  if (retained) assert.equal(retained.size, native.retained_objects.length, "Duplicate retained object");
  const boxesBytes = native && Object.hasOwn(native, "detector_boxes") ? read(native.detector_boxes)
    : existsSync(boxesFile) ? readFileSync(boxesFile) : null;
  const boxes = boxesBytes ? JSON.parse(boxesBytes) : null;
  const ids = scene.cameras.map(c => c.id).sort();
  assert.equal(new Set(ids).size, ids.length);
  if (native) {
    assert.equal(native.schema, "fss.website.watch_native.v1");
    assert.equal(native.take, name);
    if (native.scene_sha256 !== undefined) assert.equal(native.scene_sha256, "sha256:" + hash(sceneBytes));
    assert.deepEqual(Object.keys(native.cameras).sort(), ids);
    checkReferences(native, read);
    fromReports(native, read);
  }
  if (boxes) {
    assert.ok(native, "Detector overlays require native evidence");
    assert.equal(boxes.schema, "fss.website.watch_native_boxes.v1");
    assert.equal(boxes.take, name);
    assert.equal(boxes.fps, scene.clock.fps);
    assert.equal(boxes.frames, scene.clock.frames);
    assert.deepEqual(Object.keys(boxes.cameras).sort(), ids);
    for (const id of ids) {
      const row = boxes.cameras[id];
      assert.ok(row && Array.isArray(row.inferred) && row.person &&
        typeof row.person === "object" && !Array.isArray(row.person), "Invalid detector overlay for " + id);
    }
  }
  let frames = 0;
  for (const camera of scene.cameras) {
    assert.match(camera.id, /^[a-z0-9_-]+$/);
    if (camera.video) {
      assert.equal(camera.video, `/watch/${name}/${camera.id}.mp4`);
      const film = readFileSync(join(directory, camera.id + ".mp4"));
      assert.equal(hash(film), camera.video_sha256, camera.id + " film digest");
      assert.equal(film.length, camera.video_bytes);
    }
    if (!native) continue;
    const record = native.cameras[camera.id];
    const custody = record.custody;
    if (custody?.outcome === "ok") {
      assert.equal(record.film, camera.video);
      assert.equal(custody.sha256, "sha256:" + camera.video_sha256);
      assert.equal(custody.bytes, camera.video_bytes);
      const fields = Object.fromEntries(read(custody.receipt).toString().trim().split("\n").map(line => {
        const pos = line.indexOf("=");
        return [line.slice(0, pos), line.slice(pos + 1)];
      }));
      assert.equal(fields.verified_source_sha256, custody.sha256);
      assert.equal(fields.input_sha256, custody.sha256);
      assert.equal(fields.input_bytes, String(custody.bytes));
      assert.equal(fields.import_identity, custody.import_id);
      assert.equal(fields.import_root, custody.import_root);
      assert.equal(fields.segment_count, String(custody.segments), camera.id + " import segment count");
      assert.equal(fields.omission_count, "0", camera.id + " source omissions");
      assert.equal(fields.capture_time_class, custody.capture_time_class);
      // Each retained MP4 video sample is one segment. The author counts that
      // film's video packets even when another camera has a different duration.
      assert.equal(custody.frames, custody.segments, camera.id + " film frames");
      verifyMovie(join(directory, camera.id + ".mp4"), custody, fields.media_format, camera.id);
      assert.deepEqual([custody.width, custody.height], [camera.width, camera.height], camera.id + " film dimensions");
    } else {
      assert.equal(record.detections?.reports?.length ?? 0, 0, "Detector report without an import");
    }
    frames += verifyDetections(camera, scene.clock, record, boxes?.cameras[camera.id], read);
  }
  const twinFile = join(directory, "twin/twin.json");
  const twinBytes = existsSync(twinFile) ? readFileSync(twinFile) : null;
  const renderDigest = renderIdentity(sceneBytes, nativeBytes, boxesBytes && hash(boxesBytes), twinBytes, fusion, relay);
  return { cameras: ids.length, frames, renderDigest, retainedObjects: retained, detectorBoxes: native?.detector_boxes };
}
