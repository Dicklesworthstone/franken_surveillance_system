import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { cameras, cameraAsset, cases } from "./scenarios.js";
const read = (file) => readFileSync(join(process.cwd(), "public", file));
const json = (file) => JSON.parse(read(file));
// Export small projections for the page and keep the complete native receipts downloadable.
export function fieldData() {
  const index = json("field/index.json");
  const report = (name) => {
    const file = name + ".json";
    assert.ok(Object.hasOwn(index, file), "Missing " + file);
    return json("field/" + file);
  };
  for (const [file, hash] of Object.entries(index)) {
    assert.match(file, /^[a-z\d-]+\.(json|bin|jpg|mp4)$/);
    assert.equal(
      "sha256:" +
        createHash("sha256")
          .update(read("field/" + file))
          .digest("hex"),
      hash,
      file,
    );
  }
  const pair = report("association"),
    narrow = json("evidence/delivery-drive-porch.json");
  const publication = report("publication"),
    repeat = report("repeat"),
    custody = report("custody");
  const event = pair.candidates[0];
  assert.equal(pair.candidate_count, 1);
  assert.equal(narrow.candidate_count, 0);
  assert.deepEqual(
    pair.cameras.map((c) => c.import_identity),
    narrow.cameras.map((c) => c.import_identity),
  );
  assert.deepEqual(pair.zones, narrow.zones);
  assert.equal(pair.distance_gate, narrow.distance_gate);
  assert.equal(custody.event_id, event.event_id);
  assert.equal(custody.revision_digest, event.event_revision_digest);
  assert.equal(custody.all_verified, true);
  assert.equal(custody.event_record.state, event.event_state);
  assert.equal(publication.candidates[0].status, "published");
  assert.equal(repeat.candidates[0].status, "already_published");
  assert.equal(repeat.authority_sequence, custody.anchor.capsuleSequence);
  const root = custody.objects.find((o) => o.digest === custody.event_root);
  assert.ok(
    root.declared_manifest &&
      root.children.length === 1 &&
      custody.manifest_expansion_complete,
  );
  for (const obj of custody.objects) {
    const file = obj.digest.slice(7) + ".bin";
    assert.equal(index[file], obj.digest);
    assert.equal(read("field/" + file).length, obj.verified_payload_bytes);
  }
  const survey = Object.fromEntries(
    cases.map((s) => [
      s.id,
      json("evidence/" + s.id + "-drive-porch.json").entries.map((e) => ({
        camera: e.camera,
        segment: e.segment,
        ground: e.ground,
      })),
    ]),
  );
  const agent = {};
  for (const op of ["orient", "explain", "alert", "handoff", "resume"]) {
    const r = report(op);
    assert.equal(r.schema, "fss.agent_response_envelope.v1");
    assert.equal(r.outcome, op === "alert" ? "refused" : "ok");
    agent[op] = {
      operation: r.operationId,
      view: r.effectiveViewId,
      outcome: r.outcome,
      capabilities: r.effectiveCapabilities,
      payload: r.payloadSchema,
      proofs: r.proofPointers.length,
      error: r.errorId,
      session: r.sessionId,
      affordances: r.affordances.map((a) =>
        a.purpose.trim().replace(/\s+/g, " "),
      ),
      unknowns: r.payload?.situationFrame?.unknowns ?? [],
      handoff: r.payload?.handoffId ?? null,
      receipt: r.compressionReceiptId,
    };
  }
  assert.equal(agent.resume.session, agent.handoff.session);
  assert.equal(agent.alert.error, "ERR-ALERT-NOT-ELIGIBLE-001");
  const belief = {};
  for (const mode of ["single", "shared", "independent"]) {
    const r = report("belief-" + mode);
    assert.equal(r.effect_authority, false);
    belief[mode] = {
      interval: r.probability_ppm,
      clusters: r.supporting_clusters,
      decision: r.decision.kind,
    };
  }
  const wall = Object.fromEntries(
    cases.map((s) => [
      s.id,
      Object.fromEntries(
        cameras.map((c) => {
          const cascade = json(
            "evidence/" + cameraAsset(s, c.id) + ".json",
          ).detector_cascade;
          return [
            c.id,
            Object.fromEntries(
              cascade.frames.map((f) => [
                f.segment,
                {
                  status: f.status,
                  classes: [
                    ...new Set((f.detections ?? []).map((d) => d.label)),
                  ],
                },
              ]),
            ),
          ];
        }),
      ),
    ]),
  );
  return {
    wall,
    survey,
    agent,
    belief,
    association: {
      range: pair.distance_gate,
      zone: pair.zones[0],
      distance: event.ground_distance,
      delta: event.worst_case_separation_ns / 1e6,
      marks: event.entries.map((i) => {
        const e = pair.entries[i];
        return {
          camera: e.camera,
          ground: e.ground,
          segment: e.segment,
          track: e.track_id,
          box: e.track_box_cxcywh,
        };
      }),
      shared: pair.dependencies.dependency_cluster_count,
      gates: [narrow.time_gate_ns / 1e6, pair.time_gate_ns / 1e6],
      eventId: event.event_id,
      state: event.event_state,
      action: event.policy_action,
    },
    ledger: {
      before: pair.authority_sequence,
      after: publication.authority_sequence,
      repeat: repeat.authority_sequence,
      root: custody.event_root,
      revision: custody.revision_digest,
      ledgerRoot: custody.ledger_root,
      objects: custody.objects.map((o) => ({
        digest: o.digest,
        bytes: o.verified_payload_bytes,
        manifest: o.declared_manifest,
      })),
    },
  };
}
