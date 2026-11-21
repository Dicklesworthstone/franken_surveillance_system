import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readFusionExcerpt } from "./fusion-excerpt.mjs";

const digest = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
// The listener is an observer outside the native CLI. Pin the captured observations
// from check_residential_relay.py, including per-phase request counts and replies.
const qualifiedReplay = "sha256:886f2d102c32a150e2cce3d069794e74facea8483196f2bc536593599e30e48f";

export function readRelayReplay(directory, sceneBytes) {
  const path = join(directory, "relay-replay.json");
  if (!existsSync(path)) return null;
  const bytes = readFileSync(path);
  const replay = JSON.parse(bytes);
  assert.equal(replay.schema, "fss.website.residential_relay.v1", "Relay comparison schema");
  const fusion = readFusionExcerpt(directory, sceneBytes);
  assert.ok(fusion, "Relay comparison needs its source camera replay");
  assert.equal(replay.source.fusion_replay_sha256, digest(readFileSync(join(directory, "fusion-replay.json"))), "Relay source replay digest");
  assert.equal(replay.source.report_sha256, fusion.report.sha256, "Relay source fusion report");
  assert.deepEqual(replay.source.source_frames, fusion.source_frames, "Relay source frame sequence");
  assert.deepEqual(replay.source.cameras, fusion.cameras.map(({ camera, source_frame, frame, source_film_sha256, fixture_sha256 }) =>
    ({ camera, source_frame, frame, source_film_sha256, fixture_sha256 })), "Relay source films and frames");
  const objects = new Map();
  const readObject = (reference) => {
    const match = /^relay-replay\/([0-9a-f]{64})\.json$/.exec(reference.path);
    assert.ok(match && reference.sha256 === "sha256:" + match[1], "Invalid relay evidence object reference");
    if (!objects.has(reference.path)) {
      const bytes = readFileSync(join(directory, reference.path));
      assert.equal(digest(bytes), reference.sha256, "Relay evidence object differs from its recorded digest");
      objects.set(reference.path, { json: JSON.parse(bytes), length: bytes.length });
    }
    return objects.get(reference.path);
  };
  assert.deepEqual(replay.branches.map((branch) => branch.id).sort(), ["accepted", "held", "lost-ack"], "Relay comparison branches");
  const sourceReport = JSON.parse(readFileSync(join(directory, fusion.report.path), "utf8"));
  const [sourceEvent] = sourceReport.candidates;
  const held = replay.branches.find((branch) => branch.id === "held");
  assert.equal(held.event.id, sourceEvent.event_id, "Held event differs from the source camera replay");
  const accepted = replay.branches.find((branch) => branch.id === "accepted");
  const lost = replay.branches.find((branch) => branch.id === "lost-ack");
  assert.deepEqual(lost.event, accepted.event, "The two dispatch tests must use the same eligible event");
  const idempotencyKeys = new Set();
  for (const branch of replay.branches) {
    const publication = readObject(branch.event.publication).json;
    const event = publication.candidates.find((candidate) => candidate.event_id === branch.event.id);
    assert.ok(event && publication.published_count === 1, "Missing published relay event");
    assert.equal(event.event_state, branch.event.state, "Relay event state");
    assert.equal(event.policy_action, branch.event.policy_action, "Relay event policy");
    assert.equal(event.event_revision_digest, branch.event.revision_digest, "Relay event revision");
    assert.equal(event.proposal_digest, branch.event.proposal_digest, "Relay proposal digest");
    const listener = readObject(branch.listener).json;
    assert.equal(listener.schema, "fss.website.relay_listener.v1");
    assert.equal(listener.branch, branch.id, "Relay listener branch");
    assert.deepEqual(branch.steps.map((step) => step.phase), listener.observations.map((row) => row.phase), "Relay listener phases");
    let total = 0;
    let first;
    let dispatched;
    for (const [index, step] of branch.steps.entries()) {
      const recorded = listener.observations[index];
      const envelope = readObject(step.native).json;
      assert.equal(envelope.outcome, step.outcome, "Relay native outcome");
      assert.equal(envelope.errorId ?? null, step.error_id, "Relay native error");
      assert.equal(envelope.payload?.state ?? null, step.effect_state, "Relay native effect state");
      if (step.phase === "dispatch") dispatched = envelope.payload;
      if (dispatched && (step.phase === "repeat" || step.phase === "inspect")) {
        assert.equal(envelope.payload?.operationId, dispatched.operationId, "Repeated alert operation identity");
        assert.equal(envelope.payload?.idempotencyKey, dispatched.idempotencyKey, "Repeated alert idempotency key");
      }
      assert.equal(recorded.native_sha256, step.native.sha256, "Listener observed a different native call");
      assert.equal(recorded.requests_before, total, "Listener request count before call");
      assert.equal(recorded.received.length, step.requests_received, "Listener requests observed during call");
      for (const request of recorded.received) {
        const body = readObject(request.body);
        assert.equal(request.body.sha256, request.body_sha256, "Received request body digest");
        assert.equal(body.length, request.body_bytes, "Received request body length");
        assert.equal(request.path, "/fss/alert", "Received request destination");
        assert.equal(body.json.schema, "fss.webhook-alert.v1", "Received webhook schema");
        assert.equal("sha256:" + body.json.operation_sha256, digest(envelope.payload.operationId), "Received webhook operation");
        assert.equal("sha256:" + request.idempotency_key, digest(envelope.payload.idempotencyKey), "Received webhook idempotency key");
        assert.equal("sha256:" + body.json.precondition_sha256, envelope.payload.preconditionDigest, "Received webhook precondition");
        assert.equal("sha256:" + body.json.request_sha256, envelope.payload.requestDigest, "Received webhook request");
        assert.equal("sha256:" + body.json.event_revision_sha256, branch.event.revision_digest, "Received webhook event revision");
        idempotencyKeys.add(request.idempotency_key);
        first ??= request;
      }
      total += recorded.received.length;
      assert.equal(recorded.requests_after, total, "Listener request count after call");
    }
    assert.equal(branch.relay.requests_received, total, "Relay total");
    for (const field of ["response_disposition", "response_status", "body_sha256"])
      assert.equal(branch.relay[field], first?.[field] ?? null, "Relay " + field);
    branch.receivedBody = first?.body ?? null;
    branch.receivedBytes = first?.body_bytes ?? null;
  }
  assert.ok(accepted.receivedBody && lost.receivedBody, "Missing observed request for the acknowledgement comparison");
  assert.equal(accepted.relay.body_sha256, lost.relay.body_sha256, "Different POST bodies in the acknowledgement comparison");
  assert.equal(idempotencyKeys.size, 1, "Different Idempotency-Key headers in the acknowledgement comparison");
  assert.equal(digest(bytes), qualifiedReplay, "Relay comparison differs from its qualified capture");
  return replay;
}
