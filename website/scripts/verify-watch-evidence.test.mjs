import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { verifyWatchTake } from "./verify-watch-evidence.mjs";
import { verifyRenderedTake } from "../lib/watch/retained.mjs";
import { checkMatches } from "../lib/watch/load.js";

test("gaps in staged positions cannot establish a match or exclude an unobserved actor", () => {
  const take = {
    fps: 1, frames: 2, start: 0, zone: "+00:00", effects: [],
    actors: [{ id: "a", track: "A" }, { id: "b", track: "B" }],
    tracks: { a: { x: [0, null], z: [0, null] }, b: { x: [5, 5], z: [0, 0] } },
  };
  const judge = () => checkMatches({
    gate: 1, pairs: [], events: [{ t: 0, times: [0, 1], ground: [0, 0] }],
  }, take).events[0];
  assert.equal(judge().near, null);
  take.tracks.b.x = [0.5, 0.75];
  assert.equal(judge().onPerson, true);
  assert.equal(judge().near.track, "B");
  take.tracks.a.x = [3, 3];
  take.tracks.a.z = [0, 0];
  take.tracks.b.x = [5, 5];
  assert.equal(judge().near.distance, 3);
  assert.equal(judge().onPerson, false);
});

test("export binds camera footage, raw imports, detector samples and browser boxes", async (t) => {
  const folder = await mkdtemp(join(tmpdir(), "fss-export-"));
  t.after(() => rm(folder, { recursive: true, force: true }));
  const take = join(folder, "intrusion");
  await cp(new URL("../public/watch/intrusion/", import.meta.url), take, { recursive: true });
  const nativePath = join(take, "native.json");
  const boxesPath = join(take, "native-boxes.json");
  const source = await readFile(nativePath);
  const compact = await readFile(boxesPath);
  const cameras = Object.values(JSON.parse(source).cameras);
  const frames = cameras.reduce((sum, c) => sum + c.detections.frames.length, 0);
  const baseline = verifyWatchTake(take);
  assert.ok(frames > 0);
  assert.equal(baseline.cameras, cameras.length);
  assert.equal(baseline.frames, frames);
  const html = `<main id="top" data-take-digest="${baseline.renderDigest}">`;
  verifyRenderedTake(html, baseline.renderDigest);
  const replacement = JSON.parse(source);
  replacement.seconds += 60;
  await writeFile(nativePath, JSON.stringify(replacement));
  const second = verifyWatchTake(take);
  assert.throws(() => verifyRenderedTake(html, second.renderDigest), /different generations/);
  await writeFile(nativePath, source);

  const excerptFile = join(take, "fusion-replay.json");
  const excerptBytes = await readFile(excerptFile);
  const excerpt = JSON.parse(excerptBytes);
  excerpt.cameras[0].source_frame += 1;
  await writeFile(excerptFile, JSON.stringify(excerpt));
  assert.throws(() => verifyWatchTake(take), /differs from qualified output/);
  await writeFile(excerptFile, excerptBytes);
  const report = join(take, excerpt.report.path);
  const reportBytes = await readFile(report);
  await writeFile(report, "{}");
  assert.throws(() => verifyWatchTake(take), /Native fusion report differs/);
  await writeFile(report, reportBytes);

  async function refuseSwap(swap, error) {
    const native = JSON.parse(source);
    swap(native.cameras.gate, native.cameras.porch);
    await writeFile(nativePath, JSON.stringify(native));
    assert.throws(() => verifyWatchTake(take), error);
  }
  await refuseSwap((gate, porch) => { gate.custody.receipt = porch.custody.receipt; }, assert.AssertionError);
  await refuseSwap((gate) => { gate.custody.frames--; }, /film frames/);
  await refuseSwap((gate) => { gate.custody.fps = 1; }, /film frame rate/);
  await refuseSwap((gate) => { gate.custody.codec = "hevc Main"; }, /film codec/);
  await refuseSwap((gate) => { gate.custody.duration_seconds = 732; }, /film duration/);
  await refuseSwap((gate, porch) => { gate.detections.reports[0] = porch.detections.reports[0]; }, /detector source/);
  await refuseSwap((gate, porch) => {
    gate.coverage.absence_certified_for_witness_domains = true;
    gate.coverage.reports[0] = porch.coverage.reports[0];
  }, /coverage source/);
  await refuseSwap((gate) => { gate.coverage.absence_certified_for_witness_domains = false; }, /coverage certification/);
  await refuseSwap((gate) => { gate.coverage.outcome = "refused"; }, /coverage outcome/);
  const overlap = JSON.parse(source);
  overlap.cameras.doorbell.coverage.windows_failed[0].first_segment = 0;
  await writeFile(nativePath, JSON.stringify(overlap));
  assert.throws(() => verifyWatchTake(take), /overlapping or invalid coverage window/);
  await refuseSwap((gate) => { gate.coverage.witnesses[0].t1 += 1; }, /coverage interval/);
  const stale = JSON.parse(source);
  const changedFusion = JSON.parse(source);
  changedFusion.fusion.variants[0].probability_ppm = [1000000, 1000000];
  await writeFile(nativePath, JSON.stringify(changedFusion));
  assert.throws(() => verifyWatchTake(take), /Fusion probability_ppm/);
  stale.ledger.final = { sequence: stale.ledger.sequence, root: stale.ledger.root };
  await writeFile(nativePath, JSON.stringify(stale));
  assert.throws(() => verifyWatchTake(take), /Final ledger anchor/);
  // A failed CLI status retained as text supplies no final ledger position.
  delete stale.ledger.final;
  stale.ledger.status = stale.cameras.gate.custody.receipt;
  await writeFile(nativePath, JSON.stringify(stale));
  assert.equal(verifyWatchTake(take).frames, frames);
  await writeFile(nativePath, source);
  const wrong = JSON.parse(compact);
  const [firstDetection] = Object.values(wrong.cameras.gate.person);
  firstDetection[0][0] += 0.1;
  await writeFile(boxesPath, JSON.stringify(wrong));
  assert.throws(() => verifyWatchTake(take), /Browser box/);
  const missingCamera = JSON.parse(compact);
  missingCamera.cameras.gate = null;
  await writeFile(boxesPath, JSON.stringify(missingCamera));
  assert.throws(() => verifyWatchTake(take), /Invalid detector overlay for gate/);

  // In a new generation, the immutable object wins over an out-of-date compatibility alias.
  const native = JSON.parse(source);
  const digest = createHash("sha256").update(compact).digest("hex");
  native.detector_boxes = `native/objects/${digest}.json`;
  await writeFile(join(take, native.detector_boxes), compact);
  await writeFile(nativePath, JSON.stringify(native));
  assert.equal(verifyWatchTake(take).frames, frames);
  await writeFile(join(take, native.detector_boxes), JSON.stringify(wrong));
  assert.throws(() => verifyWatchTake(take), /Evidence object digest/);
  await rm(nativePath);
  await rm(boxesPath);
  const stagedOnly = verifyWatchTake(take);
  assert.equal(stagedOnly.frames, 0);
  assert.equal(stagedOnly.cameras, baseline.cameras);
  assert.throws(() => verifyRenderedTake(html, stagedOnly.renderDigest), /different generations/);
});
