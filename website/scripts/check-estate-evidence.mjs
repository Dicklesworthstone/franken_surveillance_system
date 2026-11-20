// Pass --verify-film-frames to reproduce the full native input and each
// scheduled inspection plate from its original H.264 film on the capture host.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { imageToGround } from "../lib/cameras.js";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { "verify-film-frames": { type: "boolean" } },
});
assert.ok(positionals.length <= 1, "Expected at most one public directory");
const root = positionals[0] || fileURLToPath(new URL("../public/", import.meta.url));
const sha = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");

// GroundHomography::digest uses canonical length-prefixed UTF-8 and nine
// big-endian IEEE-754 coefficients, in CLI row order.
function homographyDigest(matrix) {
  const fields = [];
  for (const label of ["fss.recorded_corroboration_plan.v1", "ground-homography"]) {
    const text = Buffer.from(label), length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(text.length));
    fields.push(length, text);
  }
  const coefficients = Buffer.alloc(72);
  matrix.forEach((value, i) => coefficients.writeDoubleBE(value, 8 * i));
  return sha(Buffer.concat([...fields, coefficients]));
}

async function bytes(url, digest) {
  assert.match(url, /^\/(night-media|night-evidence)\/[\w/.-]+$/);
  assert.ok(!url.includes(".."));
  const data = await readFile(resolve(root, "." + url));
  if (url.startsWith("/night-evidence/") && url !== "/night-evidence/index.json") {
    assert.match(url, /^\/night-evidence\/objects\/[0-9a-f]{64}\.(json|txt|jpg|mjpeg|bin)$/);
    assert.equal(sha(data), "sha256:" + url.split("/").pop().split(".")[0], url);
  }
  if (digest) assert.equal(sha(data), digest, url);
  return data;
}
const json = async (url) => JSON.parse(await bytes(url));
const index = await json("/night-evidence/index.json");
assert.equal(index.schema, "fss.web.alder_evidence.v1");
assert.equal(index.modelDigest, "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74");
assert.deepEqual(Object.keys(index.cases).sort(), ["after-hours", "delivery", "wildlife"]);
assert.equal(index.capture, "/night-media/capture.json");
assert.match(index.captureDigest, /^sha256:[a-f0-9]{64}$/);
const {captures} = JSON.parse(await bytes(index.capture, index.captureDigest));
let lenses = 0, frames = 0, packages = 0, verifiedEvents = 0;
for (const [caseId, record] of Object.entries(index.cases)) {
  const captureViews = captures.filter(c => c.caseId === caseId && c.camera !== "overview");
  assert.deepEqual(Object.keys(record.views).sort(), captureViews.map(c => c.camera).sort());
  assert.ok(captureViews.length >= 2);
  const candidates = new Map();
  for (const capture of captureViews) {
    const view = record.views[capture.camera];
    assert.equal(view.film, "/night-media/" + caseId + "-" + capture.camera + ".mp4");
    assert.equal(view.filmDigest, "sha256:" + capture.videoSha256);
    await bytes(view.film, view.filmDigest);
    assert.equal(view.filmFps, capture.fps);
    assert.equal(view.filmFrames, capture.frames);
    const input = await bytes(view.input, view.inputDigest);
    const film = resolve(root, "." + view.film);
    const scale = `scale=${index.bounds.width}:${index.bounds.height}`;
    const encode = ["-c:v", "mjpeg", "-q:v", "4", "-threads", "1", "-pix_fmt", "yuvj420p"];
    if (values["verify-film-frames"]) {
      const stride = view.filmFps / view.nativeFps;
      assert.ok(Number.isInteger(stride) && stride >= 1);
      const reference = execFileSync("ffmpeg", [
        "-nostdin", "-v", "error", "-i", film,
        "-vf", `select=not(mod(n\\,${stride})),${scale}`, "-fps_mode", "passthrough",
        ...encode, "-f", "mjpeg", "pipe:1",
      ], {maxBuffer: input.length + 1024 * 1024});
      assert.ok(reference.equals(input), `${view.film} did not reproduce its complete native input`);
    }
    const receipt = (await bytes(view.importReceipt)).toString();
    const fields = Object.fromEntries(receipt.trim().split("\n").map(line => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }));
    assert.equal(fields.import_identity, view.importId);
    assert.equal(fields.verified_source_sha256, view.inputDigest);
    assert.equal(fields.input_sha256, view.inputDigest);
    assert.equal(fields.input_bytes, String(input.length));
    assert.equal(fields.segment_count, String(view.frames));
    assert.equal(fields.omission_count, "0");
    const watch = await json(view.watch);
    assert.equal(watch.import_identity, view.importId);
    assert.equal(watch.candidate_count, view.candidateCount);
    assert.equal(watch.candidates.length, view.candidateCount);
    candidates.set(capture.camera, watch.candidates);
    assert.equal(watch.frames_decoded, view.frames);
    assert.equal(watch.absence_certifiable, false);
    assert.equal(watch.effects_authorized, false);
    assert.equal(watch.alert_authorized, false);
    assert.equal(watch.detector_cascade.package_digest, index.modelDigest);
    assert.ok(watch.detector_cascade.inference_count <= 1);
    const trackLabels = watch.candidates.flatMap(c => c.class_evidence.filter(e => e.outcome === "associated").map(e => ({
      candidate:c.candidate_id, frame:e.segment, time:e.segment/view.nativeFps,
      label:e.label, score:e.score, supports:e.supports, overlapPpm:e.iou_ppm, evidenceDigest:e.evidence_digest,
      capsule:c.evidence.find(f => f.segment === e.segment).capsule_digest,
    })));
    assert.deepEqual(view.trackLabels, trackLabels);
    if (caseId === "after-hours") {
      const time = await json(view.dwell.report);
      assert.equal(time.event_rule, "sampled_dwell");
      assert.equal(time.import_identity, view.importId);
      assert.equal(time.frames_decoded, view.frames);
      assert.equal(time.continuous_occupancy_certified, false);
      assert.equal(time.absence_certifiable, false);
      assert.equal(time.alert_authorized, false);
      assert.equal(Number(time.minimum_duration_ns), 1e9);
      assert.equal(time.minimum_observations, 5);
      assert.equal(time.candidate_count, view.dwell.count);
      assert.equal(view.dwell.longestSeconds, time.candidates.length
        ? Math.max(...time.candidates.map(c => Number(c.minimum_duration_ns))) / 1e9 : null);
    }
    assert.equal(view.frames, Math.ceil(view.filmFrames * view.nativeFps / view.filmFps));
    assert.deepEqual(view.samples.map(s => s.frame), [...new Set([1,2].map(n =>
      Math.min(view.frames - 1, Math.floor(view.frames * n / 3))))]);
    for (const sample of view.samples) {
      const [jpeg, report] = await Promise.all([bytes(sample.image), json(sample.report)]);
      assert.equal(jpeg.length, sample.inputBytes);
      assert.ok(input.subarray(sample.inputOffset, sample.inputOffset + sample.inputBytes).equals(jpeg));
      assert.equal(sample.time, sample.frame / view.nativeFps);
      assert.equal(sample.filmFrame, sample.frame * view.filmFps / view.nativeFps);
      if (values["verify-film-frames"]) {
        const reference = execFileSync("ffmpeg", [
          "-nostdin", "-v", "error", "-i", film,
          "-vf", `select=eq(n\\,${sample.filmFrame}),${scale}`, "-frames:v", "1",
          ...encode, "-f", "image2pipe", "pipe:1",
        ]);
        assert.ok(reference.equals(jpeg),
          `${view.film} frame ${sample.filmFrame} did not reproduce the retained inspection JPEG`);
      }
      assert.equal(report.source_import, view.importId);
      assert.equal(report.package_digest, index.modelDigest);
      assert.equal(report.generation, view.modelGeneration);
      assert.equal(report.minimum_score_ppm, view.minimumScorePpm);
      assert.equal(report.box_subpixels, index.bounds.subpixels);
      assert.equal(report.frames.length, 1);
      assert.equal(report.complete, true);
      assert.equal(report.effects_authorized, false);
      assert.equal(report.absence_certifiable, false);
      const frame = report.frames[0];
      assert.equal(frame.segment, sample.frame);
      assert.deepEqual(frame.dimensions, [index.bounds.width,index.bounds.height]);
      assert.equal(frame.capsule_digest, sample.capsule);
      assert.deepEqual(sample.detections, frame.detections.map(({label,score,bounds_subpixel}) => ({label,score,bounds_subpixel})));
      packages++;
    }
    const projection = imageToGround({position:capture.sample.eye,target:capture.sample.target,
      fov:capture.sample.verticalFovDegrees}, 160, 90);
    assert.deepEqual(record.associations.projections[capture.camera], projection);
    lenses++;
    frames += view.frames;
  }
  const cameraNames = Object.keys(record.views).sort();
  const pairNames = cameraNames.flatMap((a, i) => cameraNames.slice(i + 1).map(b => a + "+" + b));
  assert.deepEqual(Object.keys(record.associations.pairs).sort(), [...pairNames].sort());
  const reference = captureViews.find(c => c.camera === cameraNames[0]);
  const [x, , z] = reference.sample.subjectFoot;
  const zone = [x - 2, z - 2, 4, 4];
  assert.equal(record.associations.referenceCamera, reference.camera);
  assert.equal(record.associations.referenceSeconds, reference.stillSeconds);
  assert.deepEqual(record.associations.zone, zone);
  for (const [pair, {report:link,cameras,count}] of Object.entries(record.associations.pairs)) {
    const report = await json(link);
    assert.deepEqual(cameras, pair.split("+"));
    assert.deepEqual(report.cameras.map(c => c.camera).sort(), [...cameras].sort());
    for (const c of report.cameras) {
      assert.equal(c.import_identity, record.views[c.camera].importId);
      assert.equal(c.ground_homography_digest, homographyDigest(record.associations.projections[c.camera]));
    }
    assert.deepEqual(report.zones, [{ zone_id: "review", x: zone[0], y: zone[1], width: zone[2], height: zone[3] }]);
    assert.equal(report.time_gate_ns, 250000000);
    assert.equal(report.distance_gate, 1);
    assert.equal(report.candidate_count, count);
    assert.equal(report.candidates.length, count);
    candidates.set(pair, report.candidates);
    assert.equal(report.dependencies.independence_certified, false);
    assert.equal(report.dependencies.dependency_cluster_count, 1);
    assert.equal(report.effects_authorized, false);
    assert.ok(report.candidates.every(c => c.policy_action === "hold" && !c.alert_prepared));
  }
  assert.equal(record.decision.effectsAuthorized, false);
  assert.equal(record.decision.absenceCertified, false);
  assert.equal(record.decision.independentConfirmation, false);
  const labels = new Set(Object.values(record.views).flatMap(v =>
    v.samples.flatMap(s => s.detections.map(d => d.label))));
  assert.deepEqual(record.decision.observedLabels, [...labels].sort());
  const lab = record.belief;
  const positives = Object.entries(record.views).flatMap(([camera,view]) => {
    const rows = view.samples.flatMap(s => s.detections.filter(d => d.label === "person")
      .map(d => ({camera, frame:s.frame, time:s.time, report:s.report, score:d.score, capsule:s.capsule})));
    rows.push(...view.trackLabels.filter(e => e.label === "person" && e.supports).map(e => ({
      camera, frame:e.frame, time:e.time, report:view.watch, score:e.score, capsule:e.capsule,
    })));
    return rows.sort((a,b) => b.score - a.score).slice(0,1);
  }).sort((a,b) => b.score - a.score || a.camera.localeCompare(b.camera));
  assert.deepEqual(lab.observations, positives);
  assert.equal(lab.status, positives.length ? "illustrative" : "no_person_label");
  assert.deepEqual(lab.variants.map(v => v.id), positives.length >= 2 ? ["single","shared","independent"]
    : positives.length ? ["single"] : []);
  for (const variant of lab.variants) {
    const [input,result] = await Promise.all([json(variant.input), json(variant.report)]);
    assert.deepEqual(input.prior, [-602,-602]);
    assert.deepEqual(input.evidence.map(e => e.id), (variant.id === "single" ? positives.slice(0,1) : positives).map(o => o.capsule));
    assert.ok(input.evidence.every(e => e.calibration.llr[0] === 600 && e.calibration.llr[1] === 800));
    assert.equal(result.effect_authority, false);
    assert.equal(variant.decision, result.decision.kind);
    assert.deepEqual(variant.probabilityPpm, result.probability_ppm);
    assert.equal(result.supporting_clusters, variant.supportingClusters);
    assert.equal(result.supporting_clusters, variant.id === "independent" ? positives.length : 1);
  }
  const sessions = await Promise.all(["open","orient","handoff","resume"].map(k => json(record.agent[k])));
  assert.ok(sessions.every(s => s.schema === "fss.agent_response_envelope.v1" &&
    s.sessionId === sessions[0].sessionId && s.missionId === sessions[0].missionId && s.outcome === "ok"));
  assert.deepEqual(sessions.map(s => s.operationId), ["AOP-001","AOP-003","AOP-012","AOP-002"]);
  assert.equal(sessions[1].inputAnchor.deploymentId, "site:alder-house-replay");
  const ledger = record.ledger;
  if (ledger.status === "no_candidate") {
    assert.ok(Object.values(record.views).every(v => v.candidateCount === 0));
    assert.ok(Object.values(record.associations.pairs).every(p => p.count === 0));
    continue;
  }
  assert.equal(ledger.status, "verified");
  const source = [...pairNames, ...cameraNames].find(key => candidates.get(key)?.length);
  assert.equal(ledger.source, source);
  const selected = candidates.get(source)[0];
  assert.equal(ledger.eventId, selected.event_id);
  const [first, retry, audit, explain] = await Promise.all(
    [ledger.publication,ledger.repeat,ledger.custody,ledger.explain].map(json));
  assert.equal(first.published_count, 1);
  assert.equal(retry.already_published_count, 1);
  assert.equal(first.authority_sequence, ledger.sequence);
  assert.equal(retry.authority_sequence, ledger.sequence);
  for (const [publication, status] of [[first,"published"],[retry,"already_published"]]) {
    const rows = publication.candidates.filter(c => c.status === status);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].event_id, selected.event_id);
    assert.equal(rows[0].proposal_digest, selected.proposal_digest);
    assert.equal(rows[0].provenance_root, selected.provenance_root);
  }
  assert.equal(audit.event_id, ledger.eventId);
  assert.equal(audit.ledger_root, ledger.root);
  assert.equal(audit.all_verified, true);
  assert.equal(audit.site, sessions[1].inputAnchor.deploymentId);
  assert.equal(audit.anchor.authorityRoot, sessions[1].inputAnchor.authorityRoot);
  assert.equal(audit.anchor.capsuleSequence, ledger.sequence);
  assert.equal(explain.outcome, "ok");
  assert.ok(explain.payload.evidenceHandles.some(h => h.kind === "event_revision" &&
    h.handleId.startsWith("fss://event/" + ledger.eventId + "/revision/") && h.objectDigest === audit.revision_digest));
  const alertPlan = await json(record.agent.notification);
  assert.equal(alertPlan.errorId, "ERR-ALERT-NOT-ELIGIBLE-001");
  assert.equal(alertPlan.outcome, "refused");
  assert.equal(alertPlan.inputAnchor.authorityRoot, audit.anchor.authorityRoot);
  assert.deepEqual(ledger.objects.map(o => o.digest), audit.objects.map(o => o.digest));
  for (const obj of ledger.objects) await bytes(obj.file, obj.digest);
  verifiedEvents++;
}
console.log("Verified " + lenses + " camera imports, " + frames + " native frames, " + packages +
  " scheduled package inspections and " + verifiedEvents + " audited event publications.");
