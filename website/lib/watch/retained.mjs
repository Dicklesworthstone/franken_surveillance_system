import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function objectReader(directory, retained) {
  const cache = new Map();
  return (path) => {
    const match = /^native\/objects\/([0-9a-f]{64})\.(?:json|txt)$/.exec(path);
    assert.ok(match, `Invalid evidence object path: ${path}`);
    if (retained) assert.ok(retained.has(path), "Object outside this generation: " + path);
    if (!cache.has(path)) {
      const bytes = readFileSync(join(directory, path));
      assert.equal(sha256(bytes), match[1], `Evidence object digest: ${path}`);
      cache.set(path, bytes);
    }
    return cache.get(path);
  };
}

// Film and report links are content addressed in these inputs. Include the
// verified excerpt projections so a newly qualified capture changes the page identity.
export function renderIdentity(sceneBytes, nativeBytes, boxesDigest, twinBytes, fusion, relay) {
  return sha256(JSON.stringify([
    sha256(sceneBytes), nativeBytes && sha256(nativeBytes), boxesDigest,
    twinBytes && sha256(twinBytes),
    fusion && sha256(JSON.stringify(fusion)), relay && sha256(JSON.stringify(relay)),
  ]));
}

export function verifyRenderedTake(html, identity) {
  const main = html.match(/<main\b[^>]*>/g) ?? [];
  const rendered = main.length === 1 && /\sdata-take-digest="([0-9a-f]{64})"/.exec(main[0])?.[1];
  assert.equal(rendered, identity, "Rendered page and exported replay evidence belong to different generations");
}

// Derive the camera and ledger claims from the linked native records. Older
// summaries omit the derived fields; newer ones must agree with those records.
export function fromReports(raw, read) {
  for (const variant of raw.fusion?.variants ?? []) {
    if (variant.outcome !== "ok") {
      assert.ok(variant.report == null && variant.probability_ppm == null && variant.decision == null,
        "Unsuccessful fusion query with a decision or probability");
      continue;
    }
    const report = JSON.parse(read(variant.report));
    assert.equal(report.schema, "fss.fusion_outcome.v1", "Fusion report schema");
    assert.equal(variant.decision, report.decision.kind, "Fusion decision");
    for (const key of ["probability_ppm", "knowledge_state", "posterior_log_odds_millibans", "supporting_clusters", "reasons"])
      assert.deepEqual(variant[key], report[key], "Fusion " + key);
  }
  for (const [id, camera] of Object.entries(raw.cameras)) {
    const cv = camera.coverage;
    if (!cv) continue;
    const flags = [];
    const intervals = [];
    const reports = cv.reports ?? [];
    const failures = cv.windows_failed ?? [];
    const windows = [];
    let newlyRetained = 0;
    for (const link of reports) {
      const report = JSON.parse(read(link));
      assert.equal(report.format, "fss.recorded_watch_report.v1");
      assert.equal(camera.custody.outcome, "ok", id + " coverage without custody");
      assert.equal(report.import_identity, camera.custody.import_id, id + " coverage source");
      assert.equal(report.import_root, camera.custody.import_root, id + " coverage root");
      windows.push([report.first_segment, report.segment_count]);
      const coverage = report.coverage;
      assert.equal(coverage.format, "fss.recorded_watch_coverage.v1");
      assert.ok(["retained", "already_retained"].includes(coverage.coverage_status), id + " unretained coverage");
      if (coverage.coverage_status === "retained") newlyRetained++;
      flags.push(coverage.absence_certified_for_witness_domains);
      const before = intervals.length;
      for (const record of coverage.records) {
        assert.equal(record.sensor_id, "sensor:" + id, id + " coverage sensor");
        assert.equal(record.import_identity, report.import_identity);
        for (const zone of record.zones) {
          for (const w of zone.witnesses) {
            const times = w.covered_ns.map(ns => Number(BigInt(ns) - BigInt(raw.fss.capture_epoch_ns)) / 1e9);
            intervals.push({ t0: times[0], t1: times[1], frames: w.frames });
          }
        }
      }
      assert.equal(coverage.witness_count, intervals.length - before, id + " native witness count");
    }
    for (const failure of failures) windows.push([failure.first_segment, failure.frames]);
    windows.sort((a, b) => a[0] - b[0]);
    let end = 0;
    for (const [start, length] of windows) {
      assert.ok(Number.isSafeInteger(start) && start >= end && Number.isSafeInteger(length) &&
        length > 0 && start + length <= camera.custody.segments, id + " overlapping or invalid coverage window");
      end = start + length;
    }
    if (cv.reports || cv.windows_failed) {
      const outcome = failures.length ? (reports.length ? "partial" : "refused") : "ok";
      assert.equal(cv.outcome, outcome, id + " coverage outcome");
    }
    intervals.sort((a, b) => a.t0 - b.t0);
    if (cv.witnesses) {
      assert.equal(cv.witnesses.length, intervals.length, id + " coverage intervals");
      for (const [i, w] of intervals.entries()) {
        const row = cv.witnesses[i];
        // Python rounds the two epoch-relative endpoints to milliseconds.
        assert.ok(Math.abs(row.t0 - w.t0) <= 0.000501 && Math.abs(row.t1 - w.t1) <= 0.000501, id + " coverage interval");
        assert.equal(row.frames, w.frames, id + " coverage frames");
      }
      const seconds = cv.witnesses.reduce((n, w) => n + w.t1 - w.t0, 0);
      if (cv.covered_seconds != null) assert.ok(Math.abs(seconds - cv.covered_seconds) <= 0.005001, id + " coverage seconds");
    } else {
      assert.ok(cv.covered_seconds == null, id + " coverage seconds without witnesses");
    }
    if (cv.witness_count != null) assert.equal(cv.witness_count, intervals.length, id + " witness count");
    // Early drivers counted only windows newly appended in this invocation.
    if (cv.windows_retained != null) assert.ok([reports.length, newlyRetained].includes(cv.windows_retained), id + " retained windows");
    if (cv.windows != null) assert.equal(cv.windows, windows.length, id + " coverage windows");
    const flag = flags.length && typeof flags[0] === "boolean" && flags.every(f => f === flags[0]) ? flags[0] : null;
    if (Object.hasOwn(cv, "absence_certified_for_witness_domains")) {
      assert.equal(cv.absence_certified_for_witness_domains, flag, id + " coverage certification");
    }
    cv.absence_certified_for_witness_domains = flag;
  }
  if (raw.ledger) {
    const link = raw.ledger.status;
    const bytes = link ? read(link) : null;
    const status = link?.endsWith(".json") ? JSON.parse(bytes) : null;
    const anchor = status?.anchor;
    let final = null;
    if (anchor?.commit_sequence != null) {
      assert.equal(status.schema, "fss.status.v1");
      assert.equal(anchor.site_lineage, raw.fss.site, "Ledger site lineage");
      assert.ok(Number.isSafeInteger(anchor.commit_sequence) && anchor.commit_sequence >= 0, "Ledger sequence");
      if (anchor.ledger_root != null) assert.match(anchor.ledger_root, /^sha256:[0-9a-f]{64}$/);
      final = { sequence: anchor.commit_sequence, root: anchor.ledger_root ?? null };
    }
    if (raw.ledger.final != null) assert.deepEqual(raw.ledger.final, final, "Final ledger anchor");
    raw.ledger.final = final;
  }
  return raw;
}
