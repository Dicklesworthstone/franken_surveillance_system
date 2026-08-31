# Data formats, identities, and publication contracts

**Status:** normative architecture input
**As of:** 2026-08-31
**Machine schema registry:** [`registries/SCHEMAS.md`](registries/SCHEMAS.md)

## 1. Format constitution

FSS does not let an implementation library accidentally become the data model. Every durable or
cross-process object has:

- a stable schema or format ID;
- a version and explicit compatibility policy;
- bounded fields and allocation formulas;
- canonical identity bytes distinct from human JSON rendering;
- an exact producer generation and input root;
- explicit unknown-field, unknown-enum, and unknown-version behavior;
- deterministic fixtures, round trips, malformed-input campaigns, and migration tests;
- a publication state and a root-last commit point.

Serde may encode bounded control-plane JSON and reports. **Serde-derived layout is never the
canonical durable byte format.** Durable binary bytes are written and parsed by a versioned,
hand-audited first-party codec. A schema can define a canonical JSON projection for interchange,
but object identity is taken only over the schema’s declared canonical projection, never over an
arbitrary serializer’s map order, whitespace, float spelling, or enum representation.

Unknown mandatory semantics fail closed. Forward-compatible extensions are accepted only in a
schema-declared extension map whose bytes and taint are preserved. Canonical records are immutable;
correction creates a superseding revision.

## 2. Identity layers

FSS distinguishes identities that conventional media systems often collapse:

| Identity | Meaning |
|---|---|
| source object | exact bytes received or imported |
| packet span | exact transport packets and continuity interval |
| access unit | one compressed video/audio decoding unit |
| decoded surface | pixel/sample values under exact codec and numeric policy |
| derivative | an explicit transform of one or more source ranges |
| semantic observation | typed facts tied to source/decoded evidence |
| model result | derived output tied to model package and invocation receipt |
| graph/search generation | derived projection through one authority high-water mark |
| event revision | immutable semantic hypothesis/adjudication state |
| effect operation | prepared/committed external mutation with idempotency identity |
| publication root | visible root whose complete child closure has verified |

Equality at one layer does not imply equality at another. Two remuxed objects can carry identical
access units and have different container bytes. Two model runs can produce identical tensors while
having different package or numeric-policy identities. Deduplication policy names the layer at
which equality is asserted.

## 3. Evidence anchor

[`schemas/evidence_anchor.v1.json`](schemas/evidence_anchor.v1.json) names one coherent authority
cut. It binds at least:

- property/installation lineage;
- chronicle epoch and ordered batch sequence;
- ledger root and object-publication root;
- adapter, schema, policy, calibration, coverage, and clock generations;
- optional derived high-water marks;
- canonical digest and production build identity.

A request pins an anchor. It does not read “latest” repeatedly while assembling a response. A
cross-generation answer is legal only as an explicit temporal query whose component anchors are
reported.

## 4. Evidence delta batch

[`schemas/evidence_delta_batch.v1.json`](schemas/evidence_delta_batch.v1.json) is the one ordered
version universe consumed by canonical history, graph/search maintenance, subscriptions, replicas,
checkpoints, and speculative branches.

A batch contains ordered retract/add facts, object/publication references, predecessor identity,
producer and schema epochs, and a high-water sequence. A consumer publishes its own root only after
applying an unbroken prefix and records the exact consumed high-water mark. Gaps, duplicate batches,
predecessor mismatches, and incompatible epochs are typed outcomes, not eventual-consistency
footnotes.

## 5. Sensor capsule

[`schemas/sensor_capsule.v1.json`](schemas/sensor_capsule.v1.json) describes one bounded
media/metadata segment. It binds:

- sensor, adapter, firmware/app/region, and stream generations;
- sequence range, conservative capture-time interval, receive time, and clock basis;
- transport continuity, packet/access-unit map, codec profile, container, dimensions, and frame
  count;
- exact source object, intentionally omitted source, and any live/analysis derivative roots;
- decode/concealment, quality, tamper, and compatibility evidence;
- privacy mask, retention class, consent, legal hold, and deletion scope;
- publication root and ledger revision.

A capsule may represent intentionally omitted source bytes, but the omission reason and policy are
explicit. A decoded frame without a source capsule is transient cognition, not canonical media
evidence. “No person appeared” is never inferred from a capsule whose coverage or decodability is
uncertified.

## 6. Event hypothesis and revision chain

[`schemas/event_hypothesis.v1.json`](schemas/event_hypothesis.v1.json) is one immutable event
revision. It includes:

- event ID, parent revision, state, semantic kind, and policy disposition;
- time, zone, track, and protected-volume scope;
- calibrated probability or conformal/set-valued result with assumptions;
- positive evidence, negative-domain witnesses, contradictions, and failure-domain partition;
- exact model execution receipts, graph witnesses, calibration/coverage anchors, and policy epoch;
- abstention, missing-view request, counterfactual explanation, and deterministic decision
  fingerprint.

An event ID can have many revisions. Corroboration, rejection, resolution, relabeling, and human
feedback create new revisions and preserve the causal chain. A model output never rewrites an old
event record.

## 7. Operation receipt

[`schemas/operation_receipt.v1.json`](schemas/operation_receipt.v1.json) captures effect truth:

```text
prepared -> revalidated -> committed -> adapter_accepted -> observed -> verified
```

Terminal or durable nonterminal branches include cancelled, failed, expired, compensated, and
indeterminate. The receipt binds principal, capability, scope, lease fence, idempotency key,
request/precondition/result digests, policy anchor, timestamps, provider/adapter identity, and
stable error class.

A retry with the same idempotency key and same semantic request returns the prior result. The same
key with different content fails. An indeterminate operation is reconciled before any retry that
could duplicate an effect. Provider acceptance is never represented as delivery or physical
outcome.

## 8. Calibration certificate and coverage witness

[`schemas/calibration_certificate.v1.json`](schemas/calibration_certificate.v1.json) binds:

- metric/world coordinate frame and scale evidence;
- sensor intrinsics, distortion, extrinsics, time offset/skew, rolling-shutter terms, and
  covariance;
- moving-camera trajectory and reconstruction roots;
- protected volumes, zones, occluders, blind spots, and validity region;
- reprojection, temporal, loop-closure, and held-out residuals;
- issue/expiry, invalidators, and source evidence root.

[`schemas/coverage_witness.v1.json`](schemas/coverage_witness.v1.json) is a query-specific proof of
what could actually have been observed. It names the calibration generation, active/healthy sensor
set, occlusion and quality masks, time interval, spatial domain, lower-bound observed fraction,
and every uncovered or uncertain region. A rendering or point cloud can be a child; it is not the
certificate itself.

## 9. Graph algorithm witness

[`schemas/graph_algorithm_witness.v1.json`](schemas/graph_algorithm_witness.v1.json) accompanies
every decision-relevant graph computation. It binds:

- registered algorithm and implementation generation;
- authorized immutable projection and authority anchor;
- directedness, multiedge, weight, numeric, and tie-break policy;
- input `n`, `m`, temporal extent, and dominant complexity formula;
- observed operation counts, memory/budget use, stop reason, and approximation envelope;
- canonical output and decision-path digests;
- differential/reference and incremental/full-equivalence evidence where required.

A graph answer without this witness may be useful exploratory output. It cannot silently become an
authoritative association, coverage, deletion, or alert-policy premise.

## 10. Decision card

[`schemas/decision_card.v1.json`](schemas/decision_card.v1.json) records a bounded adaptive or
engineering choice: alternatives, hard clamps, prior evidence, utility/cost terms, uncertainty,
selected arm, safe fallback, observation window, promotion criterion, and result. Decision cards
may tune candidate budgets, cache sizes, transfer redundancy, or model routing. They may not weaken
privacy, capability, witness, freshness, retention, corroboration, or release invariants.

## 11. Canonical model package and execution receipt

[`schemas/model_package_manifest.v1.json`](schemas/model_package_manifest.v1.json) is the immutable
model root. It binds:

- original acquisition/import evidence and exact license text/digest;
- canonical tensors and packed weight variants;
- frozen first-party operator IR and operator-registry generation;
- preprocessing, frame/audio sampling, postprocessing, label/prompt vocabulary, and calibration;
- shape, dtype, layout, alias, numeric, quantization, and resource policy;
- scalar/oracle comparison, tensor error envelopes, task/event quality evidence, and adversarial
  slices;
- CPU/optional accelerator compatibility, repair symbols, and removal/rebuild rules.

[`schemas/model_execution_receipt.v1.json`](schemas/model_execution_receipt.v1.json) binds one
invocation to input roots, package root, execution/memory plan, kernel choices, numeric envelope,
resource and cancellation outcomes, output tensor root, warnings, and canonical result digest. A
model output may enter cognition only with a valid receipt. Quantization, operator lowering,
preprocessing, or calibration changes create a new package generation.

## 12. Transfer manifest and receipt

[`schemas/transfer_manifest.v1.json`](schemas/transfer_manifest.v1.json) describes an immutable ATP
object graph: root, typed children, chunk/symbol geometry, digest domains, generation, privacy and
retention class, destination constraints, and required closure/retrievability policy.

[`schemas/transfer_receipt.v1.json`](schemas/transfer_receipt.v1.json) records reserve, path
selection, chunk/symbol progress, resume journal, repair, post-repair digest verification, child
closure, root publication, replica and retrievability state, bytes/cost/latency, cancellation drain,
and final outcome. ATP moves evidence and state. It does not carry camera, alert, deletion, or drone
mutation authority.

## 13. Adapter compatibility certificate

[`schemas/adapter_compatibility_certificate.v1.json`](schemas/adapter_compatibility_certificate.v1.json)
binds support to an exact device model, hardware revision, firmware, vendor-app/API/region tuple,
protocol transcript generation, credential method, capabilities, observed negative cases,
continuity/decode/clock campaigns, resource bounds, and expiry/invalidators. “Works with Wyze” or
“supports ONVIF” is not a certificate.

## 14. Cancellation drain certificate

[`schemas/cancellation_drain_certificate.v1.json`](schemas/cancellation_drain_certificate.v1.json)
records cancellation request, owned region tree, unresolved obligations, nonnegative potential
samples, active progress regime, finalizers, external effects, quarantined staging, last durable
anchor, and terminal outcome. When an effect may have happened but cannot be reconciled, the result
is `indeterminate`, not `cancelled`.

## 15. Release qualification receipt

[`schemas/release_qualification_receipt.v1.json`](schemas/release_qualification_receipt.v1.json)
binds one local DSR lane/target result to clean source identity, exact sibling closure, pinned
nightly, Cargo.lock and metadata closure, host/toolchain, feature set, commands, artifacts,
measurements, failures, and proof roots. A complete release root is published only when all required
native targets and cross-target invariants pass. Retained partial artifacts are never promoted by
being present.

## 16. Evidence bundle

[`schemas/evidence_bundle.v1.json`](schemas/evidence_bundle.v1.json) is the support/replay envelope.
It contains event and authority roots, object inventory and retention state, build/config/device/
model registries, replay command, expected semantic and decision fingerprints, optional schedule
seed, and explicit omissions.

A default support bundle omits private media and replaces it with hashes, structural metadata,
small explicitly approved crops, or synthetic reproductions. A forensic export is a separate
capability, retention event, and audit root.

## 17. Object namespace

Target logical layout:

```text
objects/<algorithm>/<prefix>/<digest>
roots/sensor/<sensor-id>/<stream-generation>/<sequence>.fssroot
roots/event/<event-id>/<revision>.fssroot
roots/calibration/<generation>.fssroot
roots/model/<package-root>.fssroot
roots/transfer/<transfer-id>.fssroot
roots/export/<export-id>.fssroot
proofs/<gate>/<proof-root>.fssroot
```

Object-store keys are placement hints, not identities. The canonical digest and manifest define
identity. Backends may map keys differently without changing semantics.

## 18. Media derivative receipt

Each derivative names:

- source capsule/object ranges and packet/access-unit map;
- exact transform plan and media-kernel generation;
- codec profile, color space, transfer function, range, rotation, crop, scale, and audio layout;
- frame/sample selection and timestamp mapping;
- output digest and byte/frame/sample counts;
- concealment, truncation, unsupported syntax, and quality warnings;
- resource measurements and cancellation outcome.

A thumbnail, live proxy, VLM frame sequence, redacted export, and operator clip are distinct
derivatives even when generated in one process.

## 19. Decision fingerprint

The decision fingerprint is a digest over the canonical ordered projection of:

- event revision inputs;
- positive and negative witnesses;
- evidence identities and independent failure-domain classes;
- sensor health, continuity, observability, calibration, and coverage state;
- model, graph, search, memory, and policy generations;
- calibrated intervals/set-valued outputs;
- canonical tie breaks, rule path, and selected effect/abstention.

It excludes incidental wall-clock logging, addresses, thread/task IDs not in semantic policy,
unordered-map iteration, and free-form prose. Replay may regenerate different explanatory wording
while preserving the semantic fingerprint.

## 20. Deletion closure

Deletion is an effect over a reachability graph. A completion proof covers:

- canonical roots and every child object;
- local spool and unpublished staging;
- remote replicas, repair symbols, multipart remnants, and provider versions;
- thumbnails, live proxies, redacted/unredacted exports, and analysis caches;
- lexical, vector, graph, standing-query, and operational-memory projections;
- model-executor tensor/result caches whose evidence no longer exists;
- journals, support bundles, releases, and backups subject to explicit retention/legal hold.

Where immediate physical deletion is impossible, the record states cryptographic erasure,
provider retention expiry, legal hold, or a blocked reason and next obligation. “Database row
deleted” is not closure.
