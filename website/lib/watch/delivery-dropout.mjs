import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const NS = 1_000_000_000;
const fieldMap = lines => Object.fromEntries(lines.map(line => {
  const at = line.indexOf("=");
  return [line.slice(0, at), line.slice(at + 1)];
}));

// Selection receipts express movie ticks as exact rationals, including for Matroska nanoseconds.
function interval(text) {
  return text.split(",").map(item => {
    const [n, d] = item.split("/").map(BigInt);
    assert.ok(d > 0n && n >= 0n && n % d === 0n && n / d <= BigInt(Number.MAX_SAFE_INTEGER));
    return Number(n / d);
  });
}

export function readDeliveryDropout(directory, sceneFile) {
  const read = name => readFileSync(join(directory, name));
  const bytes = read("replay.json");
  const manifest = JSON.parse(bytes);
  assert.equal(manifest.schema, "fss.website.delivery_dropout.v1");
  assert.deepEqual([manifest.fps, manifest.sourceFps, manifest.seconds], [8, 24, 8]);
  assert.ok(Number.isSafeInteger(manifest.epochNs));
  const checked = name => {
    const data = read(name);
    assert.equal(sha(data), manifest.files[name], name + " generation digest");
    return data;
  };
  const capture = JSON.parse(checked("capture.json"));
  const mesh = JSON.parse(checked("mesh-receipt.json"));
  const scene = JSON.parse(readFileSync(sceneFile));
  assert.equal(manifest.model, scene.source_blend_sha256, "House used by the night film");
  assert.equal(mesh.authoringBlendSha256, manifest.model, "House used by the delivery film");
  assert.equal(mesh.packedGlbSha256, capture.inputs["/estate/estate.glb"].sha256);
  const views = capture.captures.filter(c => c.caseId === "delivery" && c.camera === "porch");
  assert.equal(views.length, 1);
  assert.equal(views[0].videoSha256, sha(checked("source.mp4")));
  assert.deepEqual([views[0].frames, views[0].fps], [192, 24]);
  const count = manifest.seconds * manifest.fps;
  const tick = NS / manifest.fps;
  const sourcePackets = new Map();
  const data = {};
  for (const name of ["complete", "dropout"]) {
    const movie = checked(name + ".mkv");
    const movieSha = "sha256:" + sha(movie);
    const imp = fieldMap(checked(name + "-import.txt").toString().trim().split("\n"));
    for (const field of ["verified_source_sha256", "input_sha256"]) assert.equal(imp[field], movieSha);
    assert.equal(imp.input_bytes, String(movie.length));
    assert.equal(imp.media_format, "mkvavc");
    assert.equal(imp.capture_time_class, "operator_assumption");
    assert.equal(imp.omission_count, "0");
    assert.equal(imp.absence_certifiable, "false");
    const lines = checked(name + "-movie.txt").toString().trim().split("\n");
    const movieFields = fieldMap(lines);
    assert.equal(movieFields.import_identity, imp.import_identity);
    assert.equal(movieFields.import_root, imp.import_root);
    assert.equal(movieFields.selection_verified_source_sha256, movieSha);
    assert.equal(movieFields.selection_movie_tick_unit, "nanosecond");
    assert.equal(movieFields.selection_interval, "half_open");
    assert.equal(movieFields.selection_complete, "true");
    assert.equal(movieFields.selection_source_bytes_read, String(movie.length));
    assert.equal(movieFields.query_start_movie_tick, "0");
    assert.equal(movieFields.query_end_movie_tick, String(count * tick));
    const frames = Array(count).fill(null);
    const segments = [];
    for (const line of lines.filter(l => l.startsWith("movie_sample="))) {
      const m = /^movie_sample=(\d+) segment=(\d+) edit_index=implicit movie_interval=(\S+) source_offset=(\d+) source_bytes=(\d+)$/.exec(line);
      assert.ok(m, "Malformed native presentation sample");
      const [start, end] = interval(m[3]);
      const frame = start / tick, segment = Number(m[2]), at = Number(m[4]), len = Number(m[5]);
      assert.ok(Number.isInteger(frame) && frame >= 0 && frame < count && frames[frame] === null);
      assert.equal(end, start + tick);
      assert.equal(Number(m[1]), segments.length);
      assert.equal(segment, segments.length);
      assert.ok(at >= 0 && len > 0 && at + len <= movie.length);
      const packet = sha(movie.subarray(at, at + len));
      if (name === "complete") sourcePackets.set(frame, packet);
      else assert.equal(packet, sourcePackets.get(frame), "Surviving camera packet differs at frame " + frame);
      segments.push(frame);
      frames[frame] = segment;
    }
    assert.equal(Number(imp.segment_count), segments.length);
    assert.equal(Number(movieFields.selected_presentation_count), segments.length);
    const gaps = lines.filter(l => l.startsWith("movie_gap=")).map((line, i) => {
      const match = /^movie_gap=(\d+) kind=unrepresented movie_interval=(\S+)$/.exec(line);
      assert.ok(match && Number(match[1]) === i);
      return interval(match[2]);
    });
    assert.equal(Number(movieFields.movie_gap_count), gaps.length);
    assert.deepEqual(gaps, name === "complete" ? [] : [[3 * NS, 5 * NS]], "Native dropout bounds");
    for (const [i, frame] of frames.entries())
      assert.equal(frame === null, gaps.some(([a,b]) => a <= i * tick && i * tick < b));
    const breaks = segments.flatMap((frame, i) => i && frame !== segments[i - 1] + 1 ? [i] : []);
    const starts = [0, ...breaks];
    const witnesses = [];
    for (const start of starts) {
      const file = name + "-watch-" + start + ".json";
      const r = JSON.parse(checked(file));
      assert.equal(r.format, "fss.recorded_watch_report.v1");
      assert.deepEqual([r.import_identity, r.import_root], [imp.import_identity, imp.import_root]);
      const sampleCount = segments.length - start;
      assert.deepEqual([r.first_segment, r.segment_count, r.frames_decoded], [start, sampleCount, sampleCount]);
      assert.ok(["retained","already_retained"].includes(r.coverage.coverage_status));
      assert.equal(r.coverage.absence_certified_for_witness_domains, true);
      assert.equal(r.coverage.records.length, 1);
      for (const record of r.coverage.records) {
        assert.deepEqual([record.sensor_id, record.import_identity, record.first_segment, record.last_segment],
          ["sensor:porch", imp.import_identity, start, segments.length - 1]);
        assert.equal(record.presentation_timing_checked, true, "Watch did not verify movie presentation timing");
        assert.equal(record.presentation_confirmation_checked, true,
          "Watch did not bound confirmation to continuous decoded frames");
        assert.deepEqual(record.zones.map(zone => zone.zone_id), ["porch"]);
        for (const zone of record.zones) {
          const cuts = zone.uncovered.filter(gap => gap.reason === "presentation_continuity_unproven");
          assert.deepEqual(cuts.map(cut => [cut.first_segment, cut.last_segment]),
            breaks.filter(i => i > start).map(i => [i - 1, i]), "Watch continuity gaps differ from the recorded movie");
          for (const cut of cuts) {
            const firstMissing = (segments[cut.first_segment] + 1) * tick;
            const nextPicture = segments[cut.last_segment] * tick;
            const [begin, end] = cut.capture_ns;
            assert.ok(Number.isSafeInteger(begin) && Number.isSafeInteger(end)
              && begin <= manifest.epochNs + firstMissing && end >= manifest.epochNs + nextPicture,
              "Watch gap does not cover the missing pictures");
          }
          assert.equal(zone.witnesses.length, r.coverage.witness_count);
          for (const w of zone.witnesses) {
            assert.ok(Number.isInteger(w.first_segment) && Number.isInteger(w.last_segment)
              && start <= w.first_segment && w.first_segment <= w.last_segment && w.last_segment < segments.length);
            const [a, b] = w.covered_ns.map(n => n - manifest.epochNs);
            assert.ok(Number.isSafeInteger(a) && Number.isSafeInteger(b) && a < b);
            // Core CaptureInterval includes both endpoints; the movie's missing interval excludes its end.
            assert.ok(!gaps.some(([lo, hi]) => a < hi && b >= lo), "Negative witness crosses source dropout");
            assert.ok(a >= segments[w.first_segment] * tick && b <= (segments[w.last_segment] + 1) * tick);
            assert.match(w.witness.negativePredicate, /no confirmed foreground-track entry into zone:porch/);
            assert.match(w.witness.witnessDigest, /^sha256:[0-9a-f]{64}$/);
            if (start === 0) witnesses.push([a / NS, b / NS]);
          }
        }
      }
    }
    assert.ok(witnesses.length > 0);
    checked(name + ".webp");
    data[name] = { frames, gaps: gaps.map(pair => pair.map(n => n / NS)), witnesses, reports: [name + "-watch-0.json"],
      samples: segments.length, sheetDigest: manifest.files[name + ".webp"] };
  }
  assert.notEqual(manifest.files["complete.mkv"], manifest.files["dropout.mkv"]);
  return { ...data, fps: manifest.fps, seconds: manifest.seconds, digest: sha(bytes) };
}
