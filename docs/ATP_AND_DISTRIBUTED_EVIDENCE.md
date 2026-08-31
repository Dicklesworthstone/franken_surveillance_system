# ATP and distributed evidence movement for FSS

**Document class:** normative immutable-transfer and edge/distributed architecture
**Revision:** 1
**Date:** 2026-08-31
**Primary source DNA:** Asupersync ATP, FrankenFS publication/repair, FrankenSQLite MVCC, Dwarf Fortress MCP effect separation

---

## 0. Thesis

FSS has two very different networking problems:

1. **Move immutable evidence and derived artifacts reliably across unreliable paths.**
2. **Perform non-idempotent or externally observable effects such as camera control and alerts.**

Conventional systems often use one RPC/message layer for both. FSS must not. Asupersync’s ATP
architecture is most valuable precisely because it treats a transfer as a verified object-graph
operation with identity, staging, repair, resumability, path policy, quotas, journals, and a
root-last commit. That is the right substrate for sensor capsules, model jobs, checkpoint bundles,
calibration assets, archive objects, replay corpora, and proof bundles.

ATP is explicitly **not** the transport for PTZ, sirens, camera configuration, privacy deletion,
alert dispatch, or drone flight. Those cross a separately fenced effect protocol with idempotency,
preconditions, lookup/reconciliation, and terminal observation.

## 1. Transfer invariants

### `XFER-INV-001` — immutable roots only

An ATP transfer moves an immutable named object graph. Mutable session state, credential handles,
effect authority, and live in-memory objects never ride inside the graph.

### `XFER-INV-002` — deterministic transfer identity

`TransferId` is domain-separated and derived from sender/receiver identities, session nonces,
manifest identity, transfer-policy digest, and protocol generation. Retrying the same transfer does
not create a new semantic object; changing any critical input does.

### `XFER-INV-003` — offered, verified, and committed are distinct

A sender may offer bytes that the receiver has not verified. The receiver may verify children whose
root has not committed. The root may commit only after graph closure, policy, durability, and
publication checks pass. Metrics and receipts keep these counters separate.

### `XFER-INV-004` — root last

A visible transfer root cannot reference missing, unverified, unpublished, or unauthorized
children. Children may exist as staged/unreachable objects after failure; they are not a committed
transfer.

### `XFER-INV-005` — path delivery is not semantic completion

A transport ACK, object upload, or remote write return value is not proof that the receiving FSS
node activated, indexed, archived, or retained the graph. Completion is defined by the transfer
contract and receipt.

### `XFER-INV-006` — repair cannot invent authority

RaptorQ or other repair reconstructs bytes for a known object identity. It does not repair a stale
policy, missing capability, invalid signature, unknown critical field, or semantic mismatch.

### `XFER-INV-007` — adaptive transport fails closed

When path telemetry, repair estimates, congestion state, or cost data is missing, stale, or
contradictory, ATP uses a safe bounded baseline. It never silently reduces integrity, authorization,
retention, or redundancy.

### `XFER-INV-008` — cancellation owns staged work

Cancellation requests stop new offers, drain in-flight paths, seal the resumable journal, and
classify every staged child as reusable, quarantined, or collectable. No child task/path is orphaned.

### `XFER-INV-009` — retention and deletion are not transfer shortcuts

ATP may move or replicate immutable objects under a retention capability. Deletion, legal hold,
privacy erasure, and retention changes remain explicit effects over the canonical object graph.

### `XFER-INV-010` — receipts are canonical evidence

Transfer receipts, journals, path decisions, verification failures, repair events, and root commits
are authoritative ledger facts. The bytes themselves live in content-addressed storage; search and
UI status are derived.

## 2. FSS object-graph families

### 2.1 Sensor capsule graph

```text
SensorCapsuleRoot
├── CapsuleManifest
│   ├── sensor/device/firmware/adapter generations
│   ├── capture and receive time intervals
│   ├── stream profile and codec/container identity
│   ├── continuity/loss/reorder evidence
│   ├── privacy/retention class
│   └── child identities and policy digests
├── SourceMediaRun(s)
│   ├── GOP/container-aware chunk(s)
│   ├── packet index
│   └── checksum/Merkle data
├── OptionalAudioRun(s)
├── TimingEvidence
├── AdapterReceipt
├── HealthSnapshot
├── OptionalRepairSymbols
└── OptionalDerivedReferenceSet
```

Derived frames, thumbnails, embeddings, and model outputs normally form sibling roots that point
back to the capsule rather than mutating it.

### 2.2 Model job graph

```text
ModelJobRoot
├── exact input capsule/window references
├── preprocessing manifest
├── weights/operator/runtime generation
├── resource/deadline policy
├── requested output schema
└── capability scope
```

The result is a new immutable graph containing structured outputs, uncertainty, execution receipt,
operator/kernel choices, timings, and failure/abstention. The model executor never receives alert or
camera-control authority.

### 2.3 Calibration graph

Contains source observations, marker/feature correspondences, intrinsics, transforms, uncertainty,
solver policy, residuals, held-out validation, invalidators, digital-twin geometry roots, and the
certificate. Large dense geometry can be transferred separately and referenced from the certificate.

### 2.4 Incident/evidence bundle graph

Contains exact event revisions, source capsule subsets, redacted derivatives, model and policy
receipts, graph witnesses, alert receipts, operator adjudication, deterministic report, signatures,
and chain-of-custody metadata. Export creates a new redaction/custody generation; it does not expose
internal roots without authorization.

### 2.5 Replay and qualification graph

Contains source snapshot identity, sibling closure, toolchain, configs, model/adapters, deterministic
seeds, fault schedule, inputs, outputs, logs, measurements, negative evidence, and signatures. These
bundles are first-class ATP objects and can be repaired/audited like other evidence.

## 3. Manifest design

The ATP manifest is versioned, canonical, self-describing, and rejects unknown critical fields.
It names:

- manifest/protocol generation;
- domain-separated object and root IDs;
- canonical child ordering;
- sizes, chunking policy, and content digests;
- graph closure expectations;
- compression/encryption parameters;
- RaptorQ/source/repair symbol parameters where used;
- capability and privacy/retention class;
- allowed destinations/peers;
- durability and publication requirement;
- expiry and resume policy;
- delta/base identities;
- required receipt schema;
- extension fields with critical/noncritical classification.

Durable manifests never use unversioned serde-derived layout as their byte contract. Canonical JSON
may be an interchange/debug representation; binary durable bytes are explicitly specified and
round-trip tested.

## 4. Chunking and deduplication

Generic content-defined chunking can perform poorly on compressed video because tiny changes alter
large entropy-coded regions. FSS uses media-aware chunking:

1. preserve original container/packet custody;
2. cut primarily at container fragments, keyframes, GOP boundaries, or bounded time/size limits;
3. create a deterministic packet/sample index;
4. optionally subchunk large stable regions for retransmission and repair;
5. deduplicate by content identity across overlapping pre/post-event windows;
6. avoid transcoding solely for dedupe;
7. store thumbnails/proxies as separate derived roots.

For model weights and graph/index artifacts, fixed or content-defined chunking may be superior. The
manifest declares the policy and version. A policy change creates new manifests but can reuse
identical child content.

## 5. Transfer lifecycle

The normative lifecycle is:

```text
Proposed
  -> Reserved
  -> Offered
  -> Receiving
  -> ChildrenVerified
  -> GraphClosed
  -> DurabilitySatisfied
  -> RootCommitted
  -> ReceiptSealed
```

Terminal alternatives:

```text
Rejected       policy/capability/manifest refusal before receipt
Aborted        safely stopped; no semantic root committed
Quarantined    bytes retained for diagnosis but not eligible for publication
Indeterminate  remote semantic commit may have occurred and lookup cannot resolve
Superseded     transfer completed but a later generation is active
```

### 5.1 Proposal

The sender presents root/manifest identity, estimated bytes, policy, priority, deadline, and path
capabilities. No large data moves yet.

### 5.2 Reservation

The receiver reserves quota, journal space, object-store authority, and child tasks. The reservation
is cancellable and has an expiry/fence.

### 5.3 Offer and receive

Paths offer chunks/symbols. The receiver records offered bytes separately from verified bytes.
Duplicate chunks are acknowledged by identity without re-materialization.

### 5.4 Child verification

Each child is decrypted/authenticated, length/digest checked, format-bounded where applicable, and
staged under an unpublished generation. Invalid bytes never count as verified throughput.

### 5.5 Graph closure

The receiver proves all required children and manifest relationships exist, critical extensions are
understood, and no unauthorized/revoked object was smuggled through a reference.

### 5.6 Durability

The destination-specific policy is satisfied: memory-only live handoff, local fsync, replica count,
remote object verification, or proof-of-retrievability registration. The receipt states which.

### 5.7 Root commit

The root pointer/ledger revision publishes atomically. Only this step makes the graph visible as a
committed transfer.

### 5.8 Receipt sealing

The receiver returns a signed/domain-separated receipt containing the exact root, transfer ID,
source/destination, counters, path/repair decisions, durability class, times, and commit anchor.

## 6. Resumable journal

A transfer journal is an append-only, checksummed state machine containing:

- transfer/reservation identities and fence;
- manifest digest;
- destination generation;
- chunk/symbol offered/verified bitmap or compact set;
- staged object locations;
- path attempts and terminal reasons;
- repair decoder state sufficient for deterministic resume;
- quota consumption;
- cancellation reason and drain progress;
- last durable transition;
- root commit/receipt state.

Recovery rules:

1. replay only complete valid journal records;
2. revalidate reservation, capability, manifest, and destination generation;
3. verify staged bytes rather than trusting journal claims;
4. resume only missing useful data;
5. refuse a stale worker’s root publication after a newer lease/fence;
6. reconcile a potentially committed remote root before retransmitting;
7. quarantine contradictory state and emit a doctor finding.

The journal itself can be part of a FrankenFS/FrankenSQLite recovery protocol, but the semantic state
machine is implementation-independent and has an in-memory reference model.

## 7. Multi-path transfer and the path graph

Possible paths include:

- local shared memory between sibling processes;
- Unix domain socket/named pipe;
- local TCP/QUIC-like native transport;
- trusted LAN direct path;
- store-and-forward mailbox on an edge node;
- relay through another authorized FSS node;
- remote object store staging;
- removable/imported media in an offline workflow.

ATP models paths as a graph with properties:

```text
availability
observed loss/reorder/latency distribution
cost/energy
bandwidth and congestion window
privacy/trust domain
maximum object class
repair support
metered-egress policy
last verified observation
```

Path candidates may race, but losing paths are cancelled and drained. Data received from any path
contributes only after content verification. Path choice is deterministic given the same telemetry
snapshot and policy tie-break.

FSS uses path diversity to improve delivery, not to count correlated copies as independent durable
replicas. Failure-domain identity is part of the path/replica model.

## 8. Adaptive RaptorQ and repair economics

RaptorQ is valuable for intermittent wireless/edge paths and long-lived object durability, but it is
not free. FSS chooses repair overhead from an expected-loss/expected-completion model:

```text
expected_cost(r) =
    transfer_bytes(r) * bandwidth_cost
  + encode_decode_cpu(r) * energy_cost
  + completion_latency_penalty(r)
  + P(incomplete_or_unrecoverable | r, observed_regime) * failure_cost
```

Constraints may impose a minimum repair floor for high-value evidence. The decision record names:

- loss/reorder/availability regime;
- source symbol count/size;
- proposed repair symbol count;
- posterior/confidence bounds;
- cost weights and policy clamps;
- selected code parameters;
- fallback if telemetry is stale;
- decoder work budget.

Use cases:

- opportunistic drone/edge upload during a weak link;
- pre-event spool evacuation when a node is failing;
- remote archive replication across interruption-prone paths;
- repairable proof/replay corpora;
- mailbox dissemination to intermittently connected trusted nodes.

Non-use cases:

- every tiny control message;
- live preview latency where loss is intentionally tolerated;
- non-idempotent effects;
- replacing cryptographic integrity;
- pretending repair symbols compensate for only one failure domain.

Repair decoding emits a proof event naming source/repair symbols used and verifies the reconstructed
content identity before publication.

## 9. Delta transfer

When sender and receiver share a verified base root, the sender may transfer a delta manifest. Delta
semantics are object-level, not mutable byte patches without context. The delta names:

- base root and required generation;
- additions/removals/replacements by stable object key;
- unchanged child references;
- canonical resulting root;
- merge/conflict policy;
- proof that applying the delta yields the target graph.

If the base is missing, stale, or contradictory, the receiver requests the full graph or a new
compatible base. A delta cannot delete a held object or weaken privacy/retention; those changes need
separate authority/effect workflows.

For live streams, overlap between rolling event windows is handled by manifest reuse of immutable
media chunks rather than transferring duplicate clips.

## 10. Store-and-forward mailbox semantics

Battery cameras and edge nodes may be intermittently reachable. FSS supports an ATP mailbox:

- sender deposits immutable offered roots/symbols under quota;
- mailbox cannot inspect secrets beyond its capability;
- recipient later verifies and commits;
- expiration, priority, retention class, and backpressure are explicit;
- mailbox ACK means custody of an offer, not final recipient commit;
- end-to-end receipt remains pending until the destination commits;
- duplicate delivery is safe by transfer/root identity;
- a mailbox loss or corruption is diagnosable and repairable where redundancy exists.

This is useful for edge→GPU jobs, offline property nodes, and delayed archive replication. It is not
a general command queue for physical effects.

## 11. Edge/GPU/archive topology

### 11.1 Edge acquisition node

Owns device adapters, source custody, packet/clock evidence, local spool, cheap candidate generation,
privacy masking, and emergency local policy. It can continue limited security operation without the
GPU or cloud.

### 11.2 Pure-Rust model executor

Receives exact model job graphs, runs qualified FrankenTorch/FSS kernels, and emits result graphs.
It has no device credentials, alert provider secrets, or canonical-write authority beyond result
submission.

### 11.3 Archive publisher

Receives evidence roots under a retention capability, uploads/stages children, verifies remote
objects, commits the remote root, and returns a custody receipt. It cannot alter event semantics.

### 11.4 Read replica/search node

Consumes ordered canonical capsules/checkpoints, verifies root closure, and publishes derived graph/
search generations. It does not become an effect coordinator.

## 12. Backpressure and admission

Each transfer reserves:

- bytes in memory and disk spool;
- chunk/symbol count;
- file descriptors/connections;
- CPU encode/decode budget;
- network bandwidth/egress budget;
- remote operations budget;
- deadline and priority;
- retention/quota class.

When capacity is exhausted, policy chooses among explicit actions:

- refuse low-priority transfer;
- retain source while dropping a derived rendition;
- reduce preview quality;
- postpone semantic enrichment;
- spill to an authorized tier;
- evict only objects whose retention/dependency graph permits it;
- alert the operator to a growing durability backlog.

FSS never silently drops source evidence while reporting the stream as fully protected.

## 13. Transfer security

- Mutual peer identity and capability negotiation precede manifest acceptance.
- Content identity and authenticated encryption are independent: ciphertext can rotate without
  changing plaintext object identity only under an explicit envelope scheme.
- The manifest binds encryption context and destination authorization.
- Replay is harmless by transfer/root identity and fence.
- Decompression, parser, and object-count bombs are bounded before allocation.
- Unknown critical fields fail closed.
- Path/relay/mailbox nodes receive minimum authority and cannot convert custody into effect rights.
- Secret-bearing objects use stricter destinations/retention and are never model inputs by default.
- Logs/receipts avoid plaintext secrets and sensitive raw media.

## 14. Deterministic laboratory and fault matrix

The reference transfer state machine runs under Asupersync LabRuntime. The matrix explores:

- cancellation before/after reservation, offer, child verify, graph closure, durability, root commit,
  and receipt;
- duplicate, delayed, reordered, corrupted, truncated, and replayed chunks/symbols;
- path failure and racing winners;
- journal torn writes and stale records;
- sender/receiver/mailbox/relay/archive process death;
- stale lease/fence after restart;
- remote object visibility lag;
- multipart upload ambiguity;
- wrong base for delta;
- RaptorQ decoder budget exhaustion and malicious symbol sets;
- quota exhaustion during repair;
- contradictory path telemetry;
- clock discontinuity in deadlines/expiry;
- privacy/capability revocation during transfer;
- deletion or legal-hold race;
- root commit with missing/unverified child attempt;
- receipt loss after commit.

Required metamorphic properties include:

- path permutation does not change committed root;
- duplicate offers do not change semantic result;
- transfer interruption/resume equals uninterrupted transfer;
- repair reconstruction equals original content digest;
- incremental/delta transfer equals full target graph;
- losing raced paths leave no owned work;
- insufficient repair increases failure/latency, never creates corrupt success;
- root visibility implies graph closure.

## 15. Transfer receipt

The versioned receipt includes:

```text
schema
transfer_id
root_id and manifest digest
sender/receiver identities
policy/capability digests
source and destination generations
started/committed/sealed time intervals
offered/verified/committed bytes and objects
reused/deduplicated bytes
source/repair symbols and decode events
path attempts, winner, and decision fingerprint
quota/cost/energy observations
durability class and replica/failure domains
root commit anchor
terminal state and reason
journal identity
signatures/authentication context
```

The schema lives at `schemas/transfer_receipt.v1.json`.

## 16. Performance objectives

The transfer engine measures distributions for:

- first useful verified byte;
- root commit latency;
- useful verified throughput;
- CPU cycles/byte and peak memory;
- dedupe ratio;
- repair overhead and decode tail;
- resume waste after interruption;
- remote operation count and cost;
- spool age/backlog;
- time to drain on cancellation;
- journal write amplification;
- retrieval/repair success.

Benchmarks use identical semantic roots and receipts across arms. A fast path that commits a
different root or omits evidence is not faster—it is a different operation.

## 17. Integration sequence

1. Freeze object/manifest/transfer/receipt identities and state machine.
2. Build a single-process in-memory sender/receiver oracle.
3. Add deterministic chunk verification, dedupe, and root-last commit.
4. Add crash-safe journal and restart reconciliation.
5. Add local file/socket path and cancellation gauntlet.
6. Add packet/path fault simulation and deterministic racing.
7. Add media-aware capsule chunking.
8. Add delta/base reuse.
9. Add adaptive RaptorQ with fixed safe baseline first.
10. Add mailbox/store-and-forward.
11. Add edge→model and edge→archive end-to-end paths.
12. Add remote object-store path with multipart reconciliation.
13. Add retrievability/repair and deletion/hold interaction.
14. Optimize only after same-root same-receipt benchmark evidence.

## 18. Rejected designs

- sending camera commands or alerts through ATP;
- mutable shared objects replicated between workers;
- counting uploaded children as a published archive;
- one “bytes transferred” counter;
- accepting transport checksum as content/semantic verification;
- unbounded content-defined chunking over compressed media;
- a message broker as the canonical state store;
- eventual delivery without idempotent root identity;
- silent path fallback that changes privacy or cost class;
- coding overhead selected from a magic constant with no regime evidence;
- remote inference that cannot name exact source/model/preprocessing roots;
- background transfer tasks outside a region;
- cleanup by deleting all staged data without checking reuse/hold/reconciliation;
- treating an archive provider success response as retrieval proof.

ATP gives FSS an information-moving plane whose correctness survives unreliable networks and
processes. Its greatest architectural contribution is the refusal to confuse movement, verification,
publication, and external effects.
