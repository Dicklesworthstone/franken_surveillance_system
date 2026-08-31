# Franken-stack second-pass deep dive for `franken_surveillance_system`

**Document class:** normative architecture input
**Revision:** 2
**Date:** 2026-08-31
**Status:** second-pass substrate constitution
**Audience:** implementers, reviewers, autonomous coding agents, systems researchers, camera-protocol specialists, computer-vision researchers, and release engineers

> This document is deliberately not a feature survey. It asks, project by project, which mechanisms are genuinely load-bearing for a world-class heterogeneous surveillance system, which invariant each mechanism establishes, where it belongs in FSS, what a superficial imitation would get wrong, and what evidence is required before the import may be called integrated.

The first architectural pass correctly identified the major Franken projects. It did not go far enough. The deeper reading shows that the valuable inheritance is not a list of crates; it is a set of **semantic contracts** that compose into a new systems architecture:

```text
owned work + explicit authority + cancellation to quiescence
  + one version universe + semantic MVCC witnesses
  + verified object-graph movement + root-last publication
  + temperature-tiered derived state + incremental maintenance
  + deterministic graph choices + complexity witnesses
  + progressive cognition + immutable model generations
  + capability-scoped agent surfaces + durable operational memory
  + local, receipt-bearing qualification
= an evidence fabric rather than an NVR with models bolted on
```

Every import therefore has seven required fields:

1. **Mechanism.** The exact idea or implementation surface being imported.
2. **Invariant.** The safety, correctness, determinism, or performance property it establishes.
3. **Semantic owner.** The FSS crate or process that owns the behavior.
4. **Substitute prohibition.** The weaker design that must not silently replace it.
5. **Reference model.** The deterministic or simple oracle against which optimized implementations are checked.
6. **Failure boundary.** What remains true when the imported implementation is absent, degraded, cancelled, or crashes.
7. **Admission gate.** The retained evidence required before the mechanism may enter an authoritative path.

The machine-readable companion is [`architecture/franken_imports.json`](architecture/franken_imports.json). The dependency rules are in [`DEPENDENCY_CONSTITUTION.md`](docs/DEPENDENCY_CONSTITUTION.md), and the complete import gates are in [`docs/FRANKEN_IMPORT_ADMISSION_GATES.md`](docs/FRANKEN_IMPORT_ADMISSION_GATES.md).

---

# 1. Constitutional conclusions of the second pass

The deeper repository audit changes the first design in twenty-eight material ways.

1. **`asupersync` is the only runtime and concurrency model.** No Tokio, async-std, smol, Rayon-owned task pool, detached thread, foreign cancellation tree, or ambient executor may enter the FSS process.
2. **FSS is a semantic subject fabric, not a tangle of channels.** Internal traffic uses typed subject families, declared service classes, capability-compiled routing, and explicit packet/authority/reasoning planes.
3. **ATP is the canonical bulk movement plane.** Archive, replication, model artifacts, calibration evidence, digital-twin generations, replay corpora, and support bundles move as verified object graphs, not anonymous files or multipart uploads.
4. **The live world is multi-version.** Every query, event decision, calibration solve, model invocation, graph execution, and effect plan pins an `EvidenceAnchor`; “latest” may not mix generations.
5. **Every negative read is witnessed.** “No person is present,” “the gate remained empty,” or “no relevant event exists” is a predicate over an observed domain and interval with a coverage certificate, not the absence of a row.
6. **Event decisions are optimistic semantic transactions.** They carry positive and negative read witnesses, intended policy effects, model/policy/calibration epochs, and revalidate before consequential dispatch.
7. **Last-writer-wins is forbidden for semantic state.** Reconciliation follows intent replay → stable-key structural merge → registered commutative composition → reconcile/replan → reject.
8. **Narrow publication points use deterministic flat combining where measurement justifies it.** Contending producers prepare complete work independently; a combiner performs only sequencing, fence validation, and root publication.
9. **Adaptive policies are advisory and clamped.** BOCPD, e-processes, conformal predictors, bandits, or learned schedulers may tune inspection depth, batch size, candidate count, and path allocation; they may not weaken authority, freshness, coverage, integrity, or verification requirements.
10. **Original media custody is a state machine.** Received, staged, verified, published, exposed, replicated, durable, and deleted are distinct states with monotone transitions and receipts.
11. **All coherent multi-artifact state is child-first, root-last.** A visible root may never name incomplete children, whether the root represents a media segment, incident bundle, index generation, calibration certificate, model activation, or release.
12. **Repair is doctor → immutable plan → sealed apply.** No generic “fix” operation mutates canonical evidence or archives.
13. **The commit/event stream is the version universe.** History, time travel, subscriptions, derived graph/search updates, replication, and speculative branches consume one ordered capsule stream.
14. **Graph storage is temperature-tiered.** Hot tiny relations remain inline, mutable recent deltas live in bounded sorted blocks, cold stable relations live in sealed compressed runs, and historical anchors cool under retention policy.
15. **Standing relations are incrementally maintained.** Active tracks, reachability, sensor health, coverage, likely cross-camera transitions, and attention candidates update from signed deltas rather than full recomputation.
16. **Graph execution is deterministic by contract.** Every non-unique answer declares a CGSE-style tie-break policy, output order, numeric policy, stale-result rule, and decision-path digest.
17. **Graph algorithms emit complexity witnesses.** The system records `n`, `m`, dominant operation counts, budget use, policy identity, output digest, and decision-path digest so complexity and determinism regressions are visible.
18. **The cognition path is progressively refined.** Cheap deterministic filters produce useful early answers; expensive multimodal reasoning refines a pinned candidate set and cannot erase provenance.
19. **Search visibility is decoupled from durability.** A searchable in-memory delta may serve bounded provisional results, but durable generation activation remains seal → verify → continuity check → root publish.
20. **Media and feature ingest is columnar and share-nothing by default.** Per-stream workers write flat timestamp/object/feature columns into bounded arenas; consolidation is deterministic and avoids shared per-frame hash maps.
21. **Safe SIMD is an implementation strategy, not an unsafe exception.** Scalar semantics are canonical; safe portable vector kernels must be bit-identical or tolerance-certified and selected through same-binary dispatch.
22. **The graph database is never placed in the camera effect path merely because graphs are useful.** Canonical evidence and effect truth remain in the authoritative ledger; graph/search engines are projections with high-water marks and certificates.
23. **The agent interface is capability-scoped and read-first.** No arbitrary shell, SQL, vendor method, codec command, model prompt, or drone-control escape hatch is exposed.
24. **Operational memory is advisory.** False-alarm lessons, device quirks, household routines, and runbooks carry provenance, confidence, decay, and harmful-feedback weight; they may rank attention but cannot rewrite evidence or grant authority.
25. **The dependency universe is closed.** Direct production dependencies are FSS crates, `asupersync`, admitted Franken crates, and a tiny ledgered set of foundational crates. Convenience is not a reason for an exception.
26. **Every production semantic path is first-party Rust.** Python, FFmpeg, vendor SDKs/applications, ONNX/CUDA framework stacks, and other foreign executables are sealed laboratory or migration oracles only; they are absent from the release closure and cannot be invoked by production.
27. **GitHub Actions YAML is an executable portability specification, not release authority.** Local qualification and Doodlestein Self-Releaser receipts are authoritative.
28. **No readiness claim is aggregate.** Contract, reference, conformance, cancellation, crash recovery, security, privacy, performance, quality, compatibility, operability, and documentation are separately earned dimensions.

These decisions are constitutional. Later code may improve their implementations, but it may not silently replace their semantics.

---

# 2. `asupersync`: execution, authority, messaging, cancellation, and transfer

**Primary inspected sources**

- [`README.md`](https://github.com/Dicklesworthstone/asupersync/blob/19d0ae479549d279866c407a7ee5b5b61f654cbe/README.md)
- [`asupersync_plan_v4.md`](https://github.com/Dicklesworthstone/asupersync/blob/19d0ae479549d279866c407a7ee5b5b61f654cbe/asupersync_plan_v4.md)
- [`asupersync_v4_formal_semantics.md`](https://github.com/Dicklesworthstone/asupersync/blob/19d0ae479549d279866c407a7ee5b5b61f654cbe/asupersync_v4_formal_semantics.md)
- [`docs/atp_architecture.md`](https://github.com/Dicklesworthstone/asupersync/blob/19d0ae479549d279866c407a7ee5b5b61f654cbe/docs/atp_architecture.md)
- [`src/atp/diagnostics/mod.rs`](https://github.com/Dicklesworthstone/asupersync/blob/19d0ae479549d279866c407a7ee5b5b61f654cbe/src/atp/diagnostics/mod.rs)
- [`docs/plans/proposal_to_integrate_ideas_from_nats_into_asupersync__after_feedback.md`](https://github.com/Dicklesworthstone/asupersync/blob/19d0ae479549d279866c407a7ee5b5b61f654cbe/docs/plans/proposal_to_integrate_ideas_from_nats_into_asupersync__after_feedback.md)

The superficial import would be “use Asupersync instead of Tokio.” The real import is a programming model in which every live computation, effect, lease, transfer, and cleanup obligation has an owner and a terminal protocol.

## 2.1 Region ownership becomes the physical topology of FSS

The process tree is not decorative observability. It defines who owns every camera session, packet, model request, transfer, and incident obligation:

```text
process
├── authority-root
├── subject-fabric
│   ├── route-registry
│   ├── capability-compiler
│   └── durable-consumer-supervisor
├── site
│   ├── clock-discipline
│   ├── sensor
│   │   ├── adapter-session
│   │   │   ├── credential-lease
│   │   │   ├── control-pump
│   │   │   ├── packet-pump
│   │   │   └── health-probe
│   │   ├── source-custody
│   │   ├── live-proxy
│   │   └── analysis-cascade
│   ├── digital-twin-generation
│   ├── graph/search-projectors
│   └── incident
│       ├── evidence-freeze
│       ├── verifier-fanout
│       ├── policy-adjudication
│       ├── alert-obligation
│       └── archive-obligation
├── transfer-supervisor
│   ├── local-spool
│   ├── cloud-replication
│   ├── model-distribution
│   └── retrievability-scrub
└── operations
    ├── doctor
    ├── repair
    ├── support-bundle
    └── release-qualification
```

A site cannot report clean shutdown while a child still owns unsealed source bytes, an unresolved alert delivery, a live credential lease, a staged archive root, or an indeterminate vendor effect. Region close produces a **drain receipt**, not a boolean.

### FSS invariant established

`INV-006`: every child is owned, and terminal closure reports unresolved external effects explicitly.

### Superficial imitation failure

Wrapping arbitrary detached tasks in a top-level cancellation token leaves the same orphan, cleanup, and retry ambiguities. Ownership must be structural at spawn time and preserved across adapters and any explicitly owned Rust process supervisors.

## 2.2 `Cx` is both execution context and authority carrier

Every FSS function that can block, allocate shared budget, read time, access a secret, touch a device, publish state, invoke a model, create child work, or dispatch an effect accepts a context or a narrower capability derived from it. The context carries:

- deployment, site, principal, request, trace, and replay identities;
- `EvidenceAnchor` and declared freshness horizon;
- deadline, virtual/physical clock source, and cancellation reason chain;
- CPU, memory, decoded-pixel, encoded-byte, GPU, network, object-operation, token, and retry budgets;
- capability mask and spatial/device/object scope;
- device, adapter, firmware, schema, model, calibration, graph, search, and policy epochs;
- privacy class and redaction obligations;
- service class and QoS lane;
- deterministic seed and decision-card identity.

Authority is narrowed twice: Rust types remove impossible operations from an interface, and runtime capability masks prevent a child from recovering ambient authority through a service locator. A pure-Rust model executor receives immutable input objects and a model-generation capability, not camera credentials or an alert sender.

## 2.3 Four-valued outcomes prevent epistemic flattening

FSS preserves `Ok`, expected `Err`, `Cancelled`, and `Panicked` at task and region boundaries. At external effect boundaries it adds an explicit semantic outcome lattice:

```text
NotPrepared
Prepared
Dispatched
AcceptedByBoundary
ObservedPartial
VerifiedComplete
VerifiedFailed
CancelledBeforeDispatch
CancelledAfterDispatch
Indeterminate
```

A lost vendor response after dispatch cannot become `Cancelled`. An archive upload whose child objects exist but whose root was never published is not `Complete`. An alert accepted by an HTTP endpoint is not `Delivered` unless its registered delivery predicate is observed.

## 2.4 Reserve/commit and obligations apply everywhere

Asupersync’s two-phase primitives imply a general FSS discipline:

- reserve packet-buffer capacity before accepting ownership;
- reserve a ledger sequence before exposing a capsule;
- reserve model capacity before materializing decoded tensors;
- reserve archive object identities before multipart upload;
- reserve an alert idempotency outcome before delivery;
- reserve a calibration generation before expensive solve work;
- reserve a release version before native target builds.

The reservation records exact inputs, authority, budget, generation, and destination. Commit is a bounded, non-cancellable publication step. Dropping an unresolved reservation has defined abort semantics and emits evidence in lab mode.

Obligation kinds include packet acknowledgement, decoder-frame release, model-host reply, evidence-root seal, archive verification, alert receipt, credential lease release, privacy deletion closure, transfer drain, and release-target completion.

## 2.5 Cancellation requires progress certificates

Long cancellation paths define a nonnegative potential function rather than waiting an arbitrary timeout. Examples:

- unacknowledged packet batches + decoder frames + pending model windows;
- bytes under unpublished object roots;
- archive parts not yet verified or abandoned;
- incident children not terminal;
- outstanding alert deliveries;
- leases not released;
- transfer paths not drained;
- deletion graph edges not yet closed.

A cancellation progress certificate records potential samples, active regime, expected descent, rebounds, masked sections, external blockers, and the final reason the region reached `Cancelled`, `Failed`, or `Indeterminate`. Statistical diagnostics may predict drain time; they never authorize discarding an obligation.

## 2.6 Deterministic LabRuntime is the default reference environment

All time, jitter, backoff, queue arbitration, lease expiry, retry, packet loss, boundary crash, and fault injection flows through runtime abstractions. The same semantic code runs under production and laboratory contexts. The lab explores:

- cancellation at every registered yield point;
- duplicate, delayed, reordered, truncated, and corrupted packets;
- boundary death between reserve, dispatch, receipt, observation, and proof;
- clock jumps, drift, and uncertainty growth;
- stale model/search/graph/calibration generations;
- concurrent incident revisions and policy updates;
- archive path failure and resume;
- deletion concurrent with query and replication;
- device firmware migration during acquisition;
- alert retry after ambiguous delivery;
- region closure around a non-cooperative, sealed laboratory-oracle process without importing it into production authority.

Mazurkiewicz-trace equivalence, DPOR-style exploration, Foata/geodesic normalization, and deterministic decision-path hashing make schedule exploration comparable across builds. Optional topology or homology heuristics may prioritize interesting schedules but cannot reduce the oracle set without proof.

## 2.7 ATP is the object-graph movement plane

ATP’s load-bearing abstraction is a verified object graph:

```text
TransferRoot
└── Manifest
    ├── SourceSegment objects
    │   ├── packet chunks
    │   ├── timestamp sidecars
    │   └── repair symbols
    ├── DerivedProxy objects
    ├── FeatureColumn objects
    ├── EventEvidence objects
    ├── Model/Calibration/Policy receipts
    └── graph-closure metadata
```

FSS imports the following ATP mechanisms directly:

- domain-separated root identities;
- manifest-described DAGs rather than implicit directories;
- object length/hash/sparse-range/repair metadata;
- path lifecycle `Discover → Candidate → Probing → Active → Suspect → Draining → Closed`;
- verifier stages `PreFlight`, `InFlight`, `PostFlight`, `Exposure`, and `Recovery`;
- quarantine before exposure on integrity failure;
- crash-resumable, versioned, checksummed journals;
- child verification and graph-closure verification before root publication;
- repair symbols as first-class objects;
- multipath racing with loser drain rather than abrupt abandonment;
- transfer diagnostics and scheduler feedback bounded by hard integrity rules.

ATP is **not** the command plane for PTZ, sirens, credential mutation, retention deletion, or drone flight. Bulk object transfer is resumable and eventually delivered; consequential effects require idempotency, fencing, lookup, and reconciliation.

The full FSS design is in [`docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md`](docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md).

## 2.8 A semantic subject fabric replaces ad hoc internal RPC

The NATS-inspired Asupersync proposal contributes a second major idea: subjects, account/import-export trust graphs, edge-to-core topology, and service classes compose naturally with FSS.

FSS defines typed subjects such as:

```text
fss.site.<site>.sensor.<sensor>.packet.<generation>
fss.site.<site>.sensor.<sensor>.health
fss.site.<site>.event.<event>.revision
fss.site.<site>.incident.<incident>.obligation
fss.site.<site>.archive.<root>.state
fss.site.<site>.calibration.<generation>.state
fss.control.adapter.<adapter>.request
fss.control.effect.<effect-kind>.prepare
fss.evidence.decision.<decision-id>
```

The public mental model remains small, but internal service classes are explicit:

| Service class | Semantics | Example |
|---|---|---|
| `EphemeralLatest` | bounded loss permitted; newest state dominates | UI thumbnails, thermal gauges |
| `OrderedTelemetry` | per-source ordering and gap receipts | packet health, clock samples |
| `DurableAtLeastOnce` | acknowledged durable consumer with idempotent handler | observation capsules, graph deltas |
| `ObligatedExactlyEffectOnce` | effect identity + lease + lookup + reconciliation; not magical exactly-once transport | alert dispatch, retention change |
| `VerifiedObjectGraph` | ATP manifest, integrity, resume, root-last exposure | archive, model, calibration, release |

The packet plane stays small and fast. The authority plane owns leases, fencing, durability, and cutover. The reasoning plane owns evidence, replay, certified cuts, and counterfactual explanations. Not every frame pays for every invariant.

## 2.9 Asupersync admission gate `INT-AS-001`

Integration is admitted only when:

1. the same end-to-end scenario passes under production and lab time;
2. no owned work survives region close;
3. every nontrivial drain emits a progress certificate;
4. every obligation reaches a terminal or explicit indeterminate state;
5. capability narrowing is tested statically and dynamically;
6. subject routing cannot cross unauthorized site/device/privacy scopes;
7. ATP corruption, truncation, reordering, path failure, resume, and repair campaigns preserve root integrity;
8. scheduler/diagnostic adaptation cannot alter authoritative results;
9. no second runtime, detached worker, or ambient timer appears in the dependency closure.

---

# 3. `frankensqlite`: semantic MVCC, witnesses, commit combining, and recovery

**Primary inspected sources**

- [`README.md`](https://github.com/Dicklesworthstone/frankensqlite/blob/2d8a68b9ad82d685f8bacd9d5fe3c8fe5304a0e4/README.md)
- [`crates/fsqlite-mvcc/src/begin_concurrent.rs`](https://github.com/Dicklesworthstone/frankensqlite/blob/2d8a68b9ad82d685f8bacd9d5fe3c8fe5304a0e4/crates/fsqlite-mvcc/src/begin_concurrent.rs)
- [`crates/fsqlite-mvcc/src/commit_combiner.rs`](https://github.com/Dicklesworthstone/frankensqlite/blob/2d8a68b9ad82d685f8bacd9d5fe3c8fe5304a0e4/crates/fsqlite-mvcc/src/commit_combiner.rs)
- [`crates/fsqlite-mvcc/src/bocpd.rs`](https://github.com/Dicklesworthstone/frankensqlite/blob/2d8a68b9ad82d685f8bacd9d5fe3c8fe5304a0e4/crates/fsqlite-mvcc/src/bocpd.rs)

The superficial import would be “store events in SQLite.” The real import is that concurrent semantic decisions require immutable versions, explicit read/write witnesses, deterministic sequencing, safe conflict refinement, and crash-recoverable publication.

## 3.1 One `EvidenceAnchor`, never a mutable global present

Each authoritative publication creates an immutable anchor:

```text
EvidenceAnchor {
    deployment_lineage,
    site_epoch,
    observation_seq,
    ledger_commit_seq,
    source_root,
    clock_epoch,
    adapter_epoch_set,
    model_epoch_set,
    calibration_epoch,
    graph_high_water,
    search_high_water,
    policy_epoch,
    privacy_epoch,
    schema_epoch
}
```

A query pins one anchor. A temporal query explicitly names multiple anchors. A model request cannot combine frames, tracks, geometry, or embeddings from incompatible anchors without a declared reconciliation operation.

## 3.2 Positive and negative read witnesses

An event or effect plan records what it relied on:

- sensor identity, generation, firmware, adapter, and stream revision;
- packet interval and continuity bitmap;
- source object identity and byte range;
- frame/tensor preprocessing identity;
- entity/track revision and identity hypothesis;
- spatial cell or frustum occupancy;
- graph edge existence or nonexistence;
- path or temporal reachability result and certificate;
- aggregate count and contributing source set;
- calibration transform and covariance bound;
- model, policy, privacy, schema, and capability epochs;
- negative-domain predicate such as “no authorized resident track intersects zone Z during interval I”;
- coverage witness proving which sensors and occlusion model make the negative predicate meaningful.

Write witnesses describe intended semantic consequences: event revision, alert obligation, retention hold, archive promotion, PTZ lease, policy activation, or privacy deletion graph.

## 3.3 Hierarchical witnesses and conservative refinement

Witnesses form a hierarchy:

```text
deployment
└── site
    └── domain: sensor | space | time | identity | policy | archive
        └── sensor / zone / interval / entity / root
            └── packet range / frustum cell / field / edge / object child
```

The coarse witness is mandatory and sound. Fine witnesses are optional accelerators. When two plans appear to conflict at a coarse level, FSS estimates whether refinement is worth the cost. Exhausting the refinement budget yields a conservative conflict or replan. It can never yield permission to commit.

## 3.4 SSI-style dangerous structures apply to event decisions

Prepared event/effect decisions and recent commits form a dependency graph from read/write conflicts. A plan that depends on “no resident is present” conflicts with an observation that introduces a resident track before commit. A policy activation that changes the alert threshold conflicts with an event decision prepared under the old policy. A camera move conflicts with any decision relying on the prior calibration.

Serializable ledger semantics do not make the physical world transactional. Passing the gate proves that the decision was valid at its revalidation anchor. The boundary operation still performs a final scoped precondition check and later reconciliation.

## 3.5 Semantic merge ladder

FSS never merges raw serialized event bytes or accepts last-writer-wins for semantic state. It attempts:

1. **Exact intent replay.** Recompute the original event/effect intent at the new anchor.
2. **Stable-key structural merge.** Merge disjoint evidence links, annotation fields, graph edges, or object children in canonical order.
3. **Registered commutative composition.** Apply only when the operation registry proves the changes commute, such as adding independent corroborating evidence or monotone counters.
4. **Reconcile and replan.** Resolve any external effect first, then create a new plan.
5. **Reject.** Ambiguous semantics remain conflicted.

An accepted merge emits a certificate with basis anchors, intent identities, conflict domains, refinement path, canonical normal form, and output digest.

## 3.6 Deterministic flat combining at narrow publication points

FrankenSQLite’s commit combiner demonstrates an important mechanical-sympathy pattern: under contention, producers publish complete requests to cache-line-separated slots; one combiner assigns a sequence range with one atomic operation and signals results. Sequential L1 work can beat parallel cache-line ping-pong.

FSS applies this only to small, deterministic publication points:

- allocating observation sequences;
- publishing event revisions;
- advancing graph/search high-water marks;
- assigning archive-root generations;
- sealing idempotency outcomes;
- ordering policy/calibration/model activations.

Decoding, inference, feature extraction, graph computation, and object upload never run under the combiner lock. The combiner drains, drops the lock, and only then invokes callbacks or expensive work.

## 3.7 BOCPD and workload regime monitors

FrankenSQLite’s Bayesian online change-point detector motivates FSS monitors for:

- motion-candidate rate;
- detector-positive rate;
- false-alarm feedback rate;
- decoder latency and drop rate;
- cross-camera association entropy;
- archive backlog and path throughput;
- camera clock drift;
- witness-conflict and replan rate;
- model-host latency or memory pressure.

A detected regime change may reset adaptive estimates, change batching, increase inspection, lower nonessential sampling, or schedule recalibration. It may not lower evidence requirements, privacy masks, capability checks, or alert-verification rules.

## 3.8 Cache alignment, sharding, and version reclamation

FSS imports the mechanical discipline, not necessarily exact data structures:

- shard write-hot tables by stable identity to avoid one global lock;
- cache-line-separate contended atomics and per-worker slots;
- keep read-mostly generations immutable and share them by reference;
- use epoch/hazard-style reclamation only behind a safe facade and deterministic oracle;
- place small hot metadata inline and large cold payloads out of line;
- use S3-FIFO/ARC-like policies only after same-binary workload evidence;
- expose version-chain pressure and old-anchor retention as first-class metrics.

## 3.9 Ledger and object store split

The ledger owns identity, order, witnesses, manifests, effect state, policy, and small metadata. The object graph owns media, feature columns, model artifacts, twin geometry, replay corpora, and proof bundles. Neither is a cache for the other. Database rows name immutable object roots; object roots never imply a committed ledger decision without a marker.

The detailed design is in [`docs/MVCC_EVIDENCE_LEDGER.md`](docs/MVCC_EVIDENCE_LEDGER.md).

## 3.10 FrankenSQLite admission gate `INT-FSQL-001`

Admission requires:

1. a single-threaded reference ledger;
2. schedule exploration over concurrent reads, event revisions, and effect commits;
3. crash injection at every reserve/materialize/publish boundary;
4. positive and negative-read phantom tests;
5. deterministic semantic-rebase equivalence;
6. commit-combiner sequence and active-registration proofs;
7. stale-anchor refusal and historical `AS OF` replay;
8. recovery that distinguishes published, staged, aborted, and indeterminate external effects;
9. demonstrated rule that witness-refinement exhaustion creates false conflicts only;
10. no direct use of lower-level APIs that bypass the connection/semantic witness pipeline.

---

# 4. `frankenfs`: custody, publication lattices, repair, and evidence

**Primary inspected sources**

- [`README.md`](https://github.com/Dicklesworthstone/frankenfs/blob/151ea2dabb37c26d4f21e1369e409b1a348ca00b/README.md)
- [`COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`](https://github.com/Dicklesworthstone/frankenfs/blob/151ea2dabb37c26d4f21e1369e409b1a348ca00b/COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md)
- [`crates/ffs-mvcc/src/store.rs`](https://github.com/Dicklesworthstone/frankenfs/blob/151ea2dabb37c26d4f21e1369e409b1a348ca00b/crates/ffs-mvcc/src/store.rs)

The superficial import would be “use content hashes and RaptorQ.” The deeper import is a custody model: staged data is not visible data, visible data is not necessarily durable data, and repair is a separately authorized semantic effect.

## 4.1 The FSS publication lattice

FSS defines these states for every durable object graph:

```text
Reserved
  → Materializing
  → Staged
  → ChildVerified
  → GraphClosed
  → RootPublished
  → Exposed
  → Replicated(k)
  → DurabilityQualified(policy)
  → Retired
  → DeletionPending
  → DeletionClosed
```

Transitions are monotone except through an explicit repair or rollback generation. `Exposed` means authorized readers may discover the root. `DurabilityQualified` means the registered replica, repair-symbol, and retrievability policy has been met. A root can be published locally while cloud durability is degraded; the two claims remain distinct.

## 4.2 Filesystem and object paths are capabilities

Every local path operation occurs under a rooted capability describing:

- allowed roots and path classes;
- symlink and reparse-point policy;
- maximum bytes, files, depth, and lifetime;
- read/write/rename/delete/fsync authority;
- publication generation and lease fence;
- privacy class and secure-erasure requirements.

No adapter, model executor, or MCP handler receives ambient access to the repository, credential directory, media spool, or archive keys.

## 4.3 Child-first, root-last multi-output publication

Incident exports, calibration results, support bundles, index generations, and releases are sibling sets. Publication follows:

1. enumerate exact intended outputs;
2. preflight names, authority, quota, and identities;
3. stage every child under an unpublished generation;
4. verify checksums, schemas, privacy transforms, and durability barriers;
5. compute manifest and graph root;
6. atomically publish the root pointer;
7. retain or retire the prior root;
8. emit a publication receipt.

A human report, machine JSON, source-span map, signature, SBOM, and repair sidecar are one publication transaction when they describe the same logical artifact.

## 4.4 Copy-on-write and immutable evidence

Original source objects are immutable. Corrections produce new metadata/event generations that cite the original and supersede earlier interpretations. Redaction creates a separately identified derivative and policy edge; it does not mutate source bytes. Retention and deletion operate on the object graph with explicit legal/privacy holds.

## 4.5 Doctor, sealed repair plan, apply

`fss doctor` only diagnoses and proposes. A repair plan contains:

- current root and ledger anchor;
- findings and evidence;
- exact intended mutations;
- required capabilities;
- estimated bytes/operations/time;
- replacement and rollback roots;
- stale-root refusal rule;
- postconditions and verification steps.

`repair apply` revalidates the root, lease, policy, and free-space budget immediately before mutation. A plan prepared for an old root fails closed.

## 4.6 RaptorQ and retrievability

Repair symbols are useful for media chunks, manifests, model packages, calibration corpora, and proof bundles, but “RaptorQ enabled” is not itself a durability claim. Each protection policy names source symbol size, repair ratio, failure model, refresh trigger, decode budget, key context, and drill cadence.

Retrievability audits sample manifest closure, object availability, key recovery, decryption, decode, and semantic reassembly. A provider `HEAD` success is not proof that an incident clip can be reconstructed.

## 4.7 Staged/visible/durable epochs for media

The writeback-cache lesson generalizes:

- **staged epoch:** bytes accepted into an owned local buffer;
- **visible epoch:** a published root allows authorized reads;
- **durable epoch:** fsync/replication policy is satisfied;
- **protected epoch:** repair-symbol and retrievability policy is satisfied.

Every reader declares which epoch it requires. Live preview may consume staged/visible data. Evidence export requires durable and usually protected data. Incident adjudication may use visible data but must disclose durability status.

## 4.8 Same-binary experiments and negative evidence

Performance experiments select arms at runtime in one binary, use identical input roots, emit semantic output digests, run an A/A null, and retain distributional results. An optimization that only rejects malformed input has earned negative evidence, not success-path readiness.

## 4.9 FrankenFS admission gate `INT-FFS-001`

Admission requires:

- complete crash matrices for every publication state;
- path traversal, symlink, alias, and generation-fence tests;
- stale repair-plan refusal;
- independent reconstruction of every advertised root;
- restore into a new observation epoch with old readers remaining coherent;
- repair/deletion concurrency tests;
- same-binary semantic-equivalence receipts;
- retrievability drills that include keys and semantic assembly;
- explicit separation of staged, visible, durable, and protected claims.

---

# 5. `frankensearch`: progressive cognition, Quill, immutable generations, and oracles

**Primary inspected sources**

- [`README.md`](https://github.com/Dicklesworthstone/frankensearch/blob/2fbb36f13b44248365448ee1192f2411a9bd5486/README.md)
- [`COMPREHENSIVE_PLAN_FOR_THE_QUILL_LEXICAL_ENGINE.md`](https://github.com/Dicklesworthstone/frankensearch/blob/2fbb36f13b44248365448ee1192f2411a9bd5486/COMPREHENSIVE_PLAN_FOR_THE_QUILL_LEXICAL_ENGINE.md)

The superficial import would be “add BM25 and vector search.” The deeper import is a progressive, generation-pinned cognition engine whose ingest, visibility, durability, model identity, and conformance are independently explicit.

## 5.1 Progressive results are the default agent contract

FSS queries return useful stages:

1. exact IDs, typed filters, time/space predicates, and policy-visible facts;
2. lexical candidates over canonical event text, adapter diagnostics, and runbooks;
3. graph expansion from high-confidence seeds;
4. cheap feature/vector candidates;
5. structured reranking by urgency, causal proximity, coverage, novelty, and actionability;
6. optional multimodal reranking under a model budget;
7. evidence shaping and explanation under a token budget.

Every stage pins the same anchor and records candidate counts, pruning, score components, freshness, and stop reason. Budget exhaustion returns a useful partial result labeled with its coverage; it does not fabricate completeness.

## 5.2 Quill’s “merge = concat” changes FSS index design

Globally ordered, disjoint ID/time intervals allow sealed posting or feature blocks to merge by ordered concatenation rather than decode/rebase/re-encode. FSS adopts interval discipline for:

- observation sequence blocks;
- event revision postings;
- track/time postings;
- sensor/zone inverted lists;
- feature-column shards;
- archive object indexes.

Holes are legal. Compaction rewrites only tombstone- or correction-dense runs. This lowers write amplification and makes sealing scale with cores.

## 5.3 Columnar sort-based ingest

Instead of shared maps keyed by every object/frame, workers produce flat columns such as:

```text
(sensor_id, observation_seq, capture_lo, capture_hi, packet_offset)
(term_id, event_ordinal, position)
(track_id, time_bucket, zone_id, confidence)
(feature_space_id, entity_id, quantized_vector)
```

Workers own disjoint ranges and bounded arenas. Flush uses radix/partition/sort passes over contiguous memory. Shared mutable state is limited to deterministic range assignment and root publication.

## 5.4 Searchable delta, durable seal

A bounded in-memory delta can be searchable immediately. It carries an unpublished/provisional generation identity and cannot support strong absence claims. Durable activation is:

```text
freeze delta
→ write sealed segment
→ verify format/checksums/model identity
→ build generation manifest
→ continuity-check source high-water mark
→ publish root
→ retire old generation after readers drain
```

This decouples low-latency visibility from durable publication without conflating them.

## 5.5 Schema-specialized safe SIMD

FSS knows its hot schemas: timestamps, bounding boxes, track features, zone bitsets, quantized embeddings, posting blocks, and pixel-quality metrics. It can build monomorphic safe-Rust kernels rather than a generic dynamic-value engine. Every vector path retains a scalar oracle, exact/tolerance policy, forced-arm test, architecture matrix, and same-binary dispatch receipt.

## 5.6 Immutable model and embedding spaces

A feature vector is meaningless without producer identity. Every index generation declares model weights digest, code/preprocess digest, dimension, quantization, numeric policy, device class, and calibration. Vectors from different spaces never share an index merely because dimensions match. Model upgrade requires full backfill or a separately certified alignment transform followed by root-last activation.

## 5.7 Absence claims require coverage certificates

Top-k ranking and “no relevant event exists” are different queries. The latter requires a certified scan domain, generation, filter policy, continuity/coverage witness, and recall qualification. Without them the result is `uncertified_absence`, not “nothing happened.”

## 5.8 Pinned oracle and differential gauntlet

FSS may replace generic engines with focused in-house implementations only while retaining a pinned oracle behind a non-production feature. Promotion requires:

- result-set/score/tie-order classification;
- malformed-input and resource-bound campaigns;
- incremental/full equivalence;
- crash and generation-activation matrices;
- held-out quality evaluation;
- same-binary performance receipts;
- negative-evidence and divergence ledgers.

## 5.9 Frankensearch admission gate `INT-FSEARCH-001`

Admission requires immutable generation activation/rollback, deterministic top-k, source-span reconstruction, stale invalidation, bounded deltas, fallback without embeddings, model-space isolation, score-ledger replay, progressive stop receipts, and fail-closed absence certificates.

---

# 6. `franken_markdown`: exact knowledge, bounded parsing, taint, and deterministic publication

**Primary inspected source:** [`README.md`](https://github.com/Dicklesworthstone/franken_markdown/blob/main/README.md)

FSS consumes manuals, adapter notes, household policies, incident narratives, model cards, source code, protocol captures, and agent-authored runbooks. These are useful and untrusted.

## 6.1 Span-preserving typed knowledge

Documents are parsed into an arena with exact byte spans and stable source identities. Every chunk or extracted fact retains document digest, byte range, parser policy, normalization steps, and corpus generation. Retrieval can quote or summarize while preserving provenance.

Text can influence attention or propose a plan; it cannot grant capabilities. Prompt-like instructions in camera metadata, OCR, subtitles, vendor responses, or incident notes retain taint through parsing, retrieval, summarization, and MCP output.

## 6.2 Explicit stacks and bounded structures

Protocol JSON, adapter descriptors, query predicates, Markdown, OCR text, and model structured output use explicit stacks/arenas rather than recursion over attacker-controlled depth. Limits cover bytes, nesting, members, strings, nodes, diagnostics, recovery attempts, and output.

Strict mode rejects malformed input. Hardened recovery is separately selected, bounded, deterministic, and emits a decision record.

## 6.3 One source, multiple deterministic projections

Incident evidence can publish Markdown, HTML, PDF, machine JSON, source-span maps, and signatures as one sibling set. The same canonical report model drives all outputs. Rendering cannot invoke an ambient browser or network fetch in the authoritative path.

## 6.4 Incremental equivalence

Large runbooks and event journals update incrementally, but an incremental parse must be equivalent to a clean full parse under the same policy. Stable span identities allow search generations and citations to update without silent drift.

## 6.5 Franken Markdown admission gate `INT-FMD-001`

Admission requires byte/span round trips, incremental/full equivalence, deterministic output bytes, bounded malicious-input campaigns, taint preservation, staged sibling publication, and no hidden filesystem/network/runtime dependency in the pure core.

---

# 7. `frankengraphdb`: one version universe, Strata, Loom, Ripple, and certificates

**Primary inspected source:** [`README.md`](https://github.com/Dicklesworthstone/frankengraphdb/blob/e9103117295730cc53dc2d5c9428a5af7aeb8338/README.md)

The superficial import would be “put tracks and sensors in a graph database.” The real import is the composition of one version universe, temperature-tiered relations, factorized/worst-case-optimal execution, incremental Z-set maintenance, deterministic certificates, capability-compiled planning, and branch-per-agent speculation.

## 7.1 One version universe

Observation capsules are the ordered delta stream for:

- authoritative history;
- current projections;
- graph and search updates;
- subscriptions and standing alerts;
- replay;
- branch creation;
- archive and replica high-water marks;
- dataset and qualification extraction.

Each derived generation publishes a root naming the exact source high-water mark it consumed. There is no “eventually updated graph” with unknowable provenance.

## 7.2 Temperature-tiered heterogeneous relations

FSS has power-law and temporal relation patterns: most entities have tiny neighborhoods, while sites, zones, active incidents, and popular identities become hubs. One representation is wasteful.

The target relation store uses:

- inline micro-adjacency for tiny hot relations;
- bounded sorted mutable delta blocks for recent changes;
- sealed compressed CSR/columnar runs for cold stable relations;
- archive anchors for history;
- immutable snapshot views shared by reference.

Movement between tiers is policy- and workload-driven but cannot change graph semantics.

## 7.3 Factorized and worst-case-optimal execution

Queries such as “find all tracks that could have moved from any blind spot through any camera-overlap sequence to the rear door while avoiding observed resident paths” can explode if every intermediate path tuple is materialized. The planner keeps factorized sets and uses FreeJoin/WCO-style execution when hypergraph shape warrants it. Binary joins remain valid for simple shapes.

Every plan records cardinality estimates, chosen variable order, factorization boundaries, capability projection, cost model epoch, and deterministic tie policies.

## 7.4 Incremental Z-set maintenance

Standing relations update from signed deltas:

- active tracks;
- zone occupancy intervals;
- sensor coverage/effective health;
- cross-camera transition likelihoods;
- identity hypothesis components;
- incident causal graphs;
- blind spots and minimum sensor cuts;
- attention and novelty candidates;
- retention/deletion reachability.

A full recomputation oracle remains available. Incremental outputs must be exactly or tolerance-equivalent at every high-water mark.

## 7.5 Branch-per-agent and counterfactual planning

An agent can fork a cheap logical branch at a pinned anchor, add hypothetical sensor placements, camera moves, privacy masks, retention policies, or event interpretations, run algorithms, and compare outcomes. Merge never copies fabricated state into reality. It produces a candidate intent and conflict report, then compiles and validates against the live anchor.

## 7.6 Planner-enforced capability scope

Authorization applies before expansion. A capability restricted to one site, zone, time range, privacy class, or relation family cannot infer hidden data through degree, count, reachability, absence, timing, or plan-cost side channels. Certificates name the authorized projection, not the global graph.

## 7.7 Plan certificates and decision cards

Strict deterministic queries emit a plan certificate. Adaptive choices emit a decision card containing inputs, policy, alternatives, evidence, clamp state, selected action, and replay identity. Instrumentation failure may reduce observability; it cannot alter the selected authoritative result.

## 7.8 Why FSS does not place graph storage in the effect path

The initial authoritative implementation remains a simple append-only ledger plus deterministic projections. Optimized graph storage enters only after reference equivalence and workload evidence. Alerts, PTZ, retention, and privacy deletion never depend on an uncertified graph result without a fallback verification path.

## 7.9 FrankengraphDB admission gate `INT-FGDB-001`

Admission requires one-high-water-mark provenance, reference graph equivalence, immutable snapshots, incremental/full equivalence, factorized output determinism, capability noninterference, branch isolation, plan-certificate replay, and measured benefit over simpler ordered maps.

---

# 8. `franken_networkx`: CGSE, complexity witnesses, and the FSS graph algorithm atlas

**Primary inspected source:** [`README.md`](https://github.com/Dicklesworthstone/franken_networkx/blob/f3b2a3872dcebcc29155c483543aa6e4ef6b6663/README.md)

FrankenNetworkX contributes two things. First, a large Rust graph-algorithm substrate. Second, and more importantly, the doctrine that observable iteration order, tie-breaks, error classes, numeric policy, and complexity are contracts rather than incidental implementation details.

## 8.1 CGSE-style deterministic choices

Every FSS graph execution declares:

```text
algorithm_id
projection_id
anchor
node/edge identity policy
multiedge and direction semantics
weight/numeric/overflow policy
tie_break_policy
output_order
resource budget
stale_result_policy
```

Hash-map iteration is never a tie-break policy. Equivalent mathematical answers can lead an agent or operator to different actions, so FSS treats chosen representatives as observable behavior.

## 8.2 Complexity witnesses

Planning-relevant executions emit:

```text
GraphAlgorithmWitness {
  algorithm_id,
  implementation_id,
  projection_id,
  anchor,
  n, m,
  dominant_operation_counts,
  allocation_bytes,
  budget_consumed,
  tie_break_policy,
  decision_path_digest,
  output_digest,
  exact_or_approximate,
  error_bound,
  stop_reason
}
```

The witness catches accidental complexity regressions, hidden fallback to quadratic behavior, and nondeterministic ordering drift.

## 8.3 Load-bearing algorithm families for FSS

The detailed registry is [`docs/GRAPH_ALGORITHM_ATLAS.md`](docs/GRAPH_ALGORITHM_ATLAS.md) and [`architecture/graph_algorithms.json`](architecture/graph_algorithms.json). The most important families are:

| Algorithm family | FSS decision supported |
|---|---|
| Dynamic connectivity | Which sensors, tracks, zones, archives, and evidence roots remain connected after failures or moves? |
| Articulation points and bridges | Which camera, access path, network link, clock source, or archive replica is a single point of failure? |
| Strongly connected components and condensation DAG | Where do effect, retry, identity, or dataflow cycles threaten deadlock or circular reasoning? |
| Dominators | Which sensor or gateway lies on every evidentiary path to a claim? |
| Shortest and k-shortest paths | What are plausible cross-camera trajectories and robust alternatives? |
| Temporal reachability | Could an entity physically traverse between observations within uncertain time intervals? |
| Multi-source distance | Which camera, drone position, or verifier can reduce uncertainty fastest? |
| Max flow / min cut | What is sensing or network capacity, and what minimum failure set destroys observability? |
| Gomory-Hu tree | What are all-pairs minimum sensor/communication cuts for resilience planning? |
| Min-cost flow and assignment | How should bounded model/GPU/network capacity serve candidate windows? |
| Bipartite/weighted matching | Which detections correspond across cameras, and which tasks go to which workers? |
| Set cover / submodular selection | Which minimum camera or frame set covers a zone or explains an incident? |
| Spanning forest / Steiner approximations | What low-cost sensor/network layout connects required areas? |
| PageRank, HITS, PPR | Which entities, sensors, or evidence nodes deserve attention? Advisory only. |
| Community detection | Which tracks/events/sensors form coherent episodes or failure domains? |
| Spectral anomaly and graph change | Did topology or behavior shift enough to schedule inspection or recalibration? |
| Critical path on plan DAGs | Which obligation controls incident or shutdown latency? |
| Minimum feedback vertex/edge approximations | Which dependency cycles should be broken to make an effect plan safe? |
| Graph alignment / assignment | How do reconstructed maps, camera views, and historical twins correspond? |

## 8.4 Exact, approximate, and advisory separation

Exact algorithms may authorize a deterministic internal choice when their projection and anchor are valid. Approximate algorithms carry error bounds and can rank candidates, never prove absence or authorize a consequential effect alone. Centrality/community scores are advisory even when computed exactly.

## 8.5 FrankenNetworkX admission gate `INT-FNX-001`

Algorithms are admitted only after differential tests against the reference implementation, adversarial graph families, CGSE tie fixtures, budget cancellation, snapshot invalidation, complexity-witness regression locks, and no Python/PyO3 dependency in the production server.

---

# 9. `frankentorch`: typed model execution, static specialization, and conformance

The second pass makes `frankentorch` load-bearing. The earlier architecture correctly isolated
models from canonical truth but still left room for a Python, ONNX Runtime, or CUDA framework
service to become the production implementation. That would preserve a Rust supervisor while
outsourcing tensor semantics, preprocessing, allocation, scheduling, operator dispatch, model
interpretation, and most failure behavior to a second ecosystem.

The production rule is stronger: FSS imports open-weight models offline into an immutable,
versioned, pure-Rust package and executes them through admitted FrankenTorch/FSS kernels. Foreign
frameworks remain sealed laboratory oracles only.

## 9.1 Canonical model package

A package is an immutable object graph containing:

```text
source model and license identities
canonical tensor objects and semantic axes
operator graph and shape constraints
preprocess/postprocess graph
numeric and determinism policy
quantization/calibration generation
operator/runtime compatibility requirements
oracle and held-out-quality receipts
repair and activation manifests
```

Production never downloads weights, executes `trust_remote_code`, or performs ambient plugin
lookup. Unsupported operators fail import rather than selecting a foreign runtime.

## 9.2 Typed tensor and alias semantics

FSS imports FrankenTorch's explicit dtype, shape, stride/layout, storage identity, view/alias,
device, quantization, and version-counter model. Immutable weights are shared structurally;
invocation scratch is region-owned. In-place operations are admitted only when alias/version
semantics are explicit and differential tests prove them. This prevents a zero-copy optimization
from silently turning an evidence input or intermediate into mutable shared state.

## 9.3 Static dispatch and shape specialization

Kernel selection is a registered function of:

```text
operator × dtype × layout × shape class × device class × numeric policy
```

Every specialization names its valid domain, scalar reference, complexity/scratch bound,
determinism class, and exact/tolerance oracle. Frozen camera profiles and model dimensions permit
monomorphic safe-Rust paths, cache-shaped tiling, packed weights, portable SIMD, and fusion without
paying a general framework's dynamic-dispatch and conversion taxes.

## 9.4 Deterministic memory planning

The compiled model plan computes activation liveness, deterministic buffer reuse, persistent versus
ephemeral storage, scratch reservations, and peak bytes before execution. The plan fingerprint and
peak memory appear in the execution receipt. Resource failure occurs before unbounded partial work;
a host-wide OOM is not a model outcome.

## 9.5 Quantization is a new semantic generation

Weight packing, scales, zero points, group size, accumulator dtype, clipping, calibration corpus,
and kernel family are part of model identity. Quantized and floating generations do not share a
score/embedding space or thresholds without a qualified mapping. Promotion requires both numeric
parity evidence and held-out event quality, especially rare-threat recall and hard negatives.

## 9.6 Model execution is a receipt-producing computation

An invocation pins source windows, model/preprocessing/runtime generations, reserves memory/work,
selects a deterministic plan, executes through bounded kernel regions, validates structured output,
publishes the result root, and seals a `ModelExecutionReceipt`. Cancellation before publication
leaves no visible result; accelerator/model failure cannot mutate canonical event state.

## 9.7 CPU-first and accelerator frontier

The universal production path is safe scalar plus portable-SIMD/tiled/fused CPU execution. An
accelerator is admitted only as a separately supervised Rust host with exact OS/driver/device
identity, bounded buffers, no effect authority, CPU differential replay, reset/OOM/hang tests, and a
measured tail/energy/quality benefit. Foreign CUDA/ONNX/Metal frameworks are not hidden fallback.

## 9.8 Differential and forensic gauntlet

Each operator/model family is compared against pinned laboratory oracles over generated and real
media. Divergence artifacts localize the first differing tensor/operator and preserve exact input,
weights, platform, kernel, numeric policy, and reproduction command. Source presence or one
successful sample is never model support.

## 9.9 FrankenTorch admission gate `INT-FT-001`

Admission requires:

- reproducible canonical package bytes from pinned inputs;
- bounded pure-Rust import with no arbitrary code;
- scalar reference semantics for every required operator;
- optimized/reference same-binary equivalence and complexity witnesses;
- deterministic or tolerance-certified cross-platform execution;
- hard memory/work/output budgets and cancellation at registered boundaries;
- held-out event-level quality and calibration;
- immutable score-space/quantization identity;
- package ATP transfer, repair, corruption, rollback, and root-closure tests;
- a qualified CPU path for every advertised production model;
- no production Python, ONNX Runtime, libtorch, OpenCV, or vendor model server.

The complete mechanism contract is in
[`docs/deep-dives/FRANKENTORCH.md`](docs/deep-dives/FRANKENTORCH.md) and
[`PURE_RUST_MODEL_RUNTIME.md`](docs/PURE_RUST_MODEL_RUNTIME.md).

# 10. `dwarf_fortress_mcp`: semantic control over a partially observed world

**Primary inspected sources**

- [`FRANKENSTACK_DEEP_DIVE.md`](https://github.com/Dicklesworthstone/dwarf_fortress_mcp/blob/main/FRANKENSTACK_DEEP_DIVE.md)
- [`COMPREHENSIVE_PLAN_FOR_DWARF_FORTRESS_MCP.md`](https://github.com/Dicklesworthstone/dwarf_fortress_mcp/blob/main/COMPREHENSIVE_PLAN_FOR_DWARF_FORTRESS_MCP.md)

This is the closest architectural analogy. A camera deployment, like a fortress, is a live world changing independently of the server. Observations are partial and delayed. Actions may be accepted now and take effect later. Retry can duplicate effects. A raw tool catalog hides rather than solves the hard problem.

## 10.1 Observation anchors and resumable deltas

Agents receive compact deltas from a named anchor, not repeated world dumps. A delta states its predecessor/root identities, high-water marks, omitted domains, coverage, and resumption token. If the chain breaks, the server reports the gap and offers a bounded rebase rather than silently mixing state.

## 10.2 Plans are semantic transactions

An agent proposes intent: “inspect the rear path,” “retain evidence,” “move PTZ to reduce uncertainty,” or “acknowledge alert.” FSS compiles intent into a plan with witnesses, capabilities, leases, expected cost, reversible/irreversible boundaries, preconditions, and verification predicates.

## 10.3 Completion is observed, not inferred from dispatch

The protocol distinguishes request durability, boundary acceptance, observed mutation, and verified terminal outcome. A PTZ request accepted by a camera is not complete until the resulting pose/visual field is observed. A retention hold is not complete until the object graph and replicas report the hold generation.

## 10.4 Negative evidence and token economy

“No event” answers require coverage witnesses. Agent responses spend tokens on the smallest sufficient evidence: typed summaries first, progressive detail, exact source references, and explanations only when requested or decision-relevant.

## 10.5 Explicit rejections inherited from DFMCP

FSS rejects:

- one giant tool per vendor command;
- arbitrary shell or vendor-RPC execution;
- screenshot-only state;
- a mutable global world cache;
- accepted request = completed physical work;
- raw-byte merge or last-writer-wins semantic state;
- detached observers and retry loops;
- adaptive safety thresholds;
- latest-state reads that mix generations.

## 10.6 DFMCP admission gate `INT-DFMCP-001`

The semantic control-plane import is admitted when every consequential tool names its anchor, witnesses, authority, costs, effect phases, idempotency, cancellation behavior, and terminal proof; replay reproduces its decision; and token-bounded views never misstate coverage.

---

# 11. `fastmcp_rust`: bounded, capability-scoped agent presentation

**Primary inspected source:** [`README.md`](https://github.com/Dicklesworthstone/fastmcp_rust/blob/main/README.md)

FastMCP Rust is the presentation boundary, not the semantic core. The framework’s strongest lesson is its qualification honesty: local handler cancellation does not automatically prove wire interruption, and source presence does not prove protocol conformance.

## 11.1 Request-owned work

Each request owns a region. Streaming results, model calls, graph queries, and evidence shaping are children. Cancellation drains them and preserves four-valued outcomes. Long-lived subscriptions are explicit resources with leases, not detached request leftovers.

## 11.2 Bounded protocol surfaces

JSON and framing limits cover request bytes, nesting, members, strings, output items, evidence bytes, and progress notifications. Stable error codes distinguish stale anchor, coverage uncertified, capability denied, budget exhausted, adapter degraded, effect indeterminate, and output truncated.

## 11.3 Capability-derived tools

Tool registration is not authority. The request context must carry a capability narrowed to site, sensor, zone, time, privacy class, effect kind, and budget. Read-only contexts cannot manufacture alert, camera-control, archive-delete, or credential capabilities.

## 11.4 No generic escape hatches

The MCP surface never exposes arbitrary SQL, shell, FFmpeg arguments, model prompts, vendor methods, file paths, or drone commands. It exposes semantic FSS operations whose schemas are generated from the authoritative registry.

## 11.5 FastMCP admission gate `INT-FMCP-001`

Admission requires bounded framing, request-region quiescence, cancellation over every enabled transport, stable schemas/errors, capability non-escalation, output redaction, replayable receipts, and explicit per-transport qualification rather than aggregate claims.

---

# 12. `eidetic_engine_cli`: operational memory without authority corruption

**Primary inspected sources**

- [`README.md`](https://github.com/Dicklesworthstone/eidetic_engine_cli/blob/main/README.md)
- [`COMPREHENSIVE_PLAN.md`](https://github.com/Dicklesworthstone/eidetic_engine_cli/blob/main/COMPREHENSIVE_PLAN.md)

FSS needs to learn from deployments, but learning must not rewrite history or silently turn household routine into truth.

## 12.1 Memory classes

FSS operational memory stores:

- adapter and firmware quirks;
- decoder/model failure modes;
- false alarms, misses, and near misses;
- operator-confirmed routines;
- calibration drift patterns;
- provider cost and outage lessons;
- repair and release runbooks;
- security/privacy anti-patterns;
- evidence-supported policy proposals.

Each memory has provenance, confidence, maturity, decay, privacy scope, evidence pointers, supersession, and feedback history.

## 12.2 Trauma guard and anti-pattern inversion

Harmful feedback counts more strongly than helpful feedback. A rule that repeatedly causes false dismissal, privacy leakage, missed alerts, or unsafe effects is demoted and can invert into an explicit `AVOID` anti-pattern. This is especially important for household-routine learning: one historically common behavior must not suppress a novel true threat.

## 12.3 Deterministic context packs

Agent context packing combines lexical, semantic, graph, recency, confidence, risk, and diversity objectives under a token budget. Every selected item explains its score and evidence. Pack hashes are reproducible. A memory can suggest an investigation or rank a candidate; it cannot alter source evidence, event state, or capability.

## 12.4 Explicit curation

The system proposes consolidation, promotion, retirement, and policy changes. Apply is separate, audited, and capability-scoped. Background workers never silently rewrite procedural memory during an active decision.

## 12.5 Eidetic admission gate `INT-EE-001`

Admission requires provenance-complete records, deterministic packs, feedback traceability, decay and trauma-guard tests, immutable supersession, privacy scoping, and proof that memory scores cannot enter authoritative evidence or effect authorization fields.

---

# 13. `doodlestein_self_releaser`: local qualification is part of the architecture

**Primary inspected source:** [`README.md`](https://github.com/Dicklesworthstone/doodlestein_self_releaser/blob/main/README.md)

Release is not clerical work outside the trust model. FSS depends on exact nightly behavior, pinned sibling revisions, native OS/media/device behavior, model packages, and reproducible evidence. A hosted badge cannot be the trust root.

## 13.1 One workflow specification, local execution

Workflow YAML remains a portable job graph. DSR/`act` and controlled native Linux, macOS, and Windows hosts execute it locally. The direct `scripts/qualify.sh` contract remains the semantic source of truth; workflow jobs call it rather than duplicating checks.

## 13.2 Clean source and sibling closure

A release starts from a clean commit in an isolated snapshot. Every path/git Franken dependency is copied or resolved at an exact clean revision and named in a source manifest. Cargo resolution is locked and offline. Uncommitted sibling code cannot hide inside a binary attributed to the FSS commit.

## 13.3 Partial builds are retained but never blessed

Completed target artifacts can survive interruption and resume. The authoritative release manifest is withheld until every required target and cross-target invariant passes. This is root-last publication applied to releases.

## 13.4 Exact asset and custody contract

Each target maps to one exact primary asset and required checksum/signature/SBOM/receipt siblings. Upload is followed by download-and-verify. Publication means the bytes users retrieve equal the locally qualified bytes.

## 13.5 FSS local lanes

FSS defines local qualification lanes:

- `policy-and-registry`;
- `reference-semantics`;
- `rust-static`;
- `lab-schedules`;
- `media-fixtures`;
- `adapter-hardware`;
- `model-quality`;
- `archive-recovery`;
- `security-privacy`;
- `performance-energy`;
- `native-target-build`;
- `release-custody`.

No GitHub-hosted lane is required to build, test, qualify, or publish. The detailed contract is [`docs/LOCAL_QUALIFICATION_WITH_DSR.md`](docs/LOCAL_QUALIFICATION_WITH_DSR.md).

## 13.6 DSR admission gate `INT-DSR-001`

Admission requires clean source/sibling closure, exact nightly identity, locked/offline resolution, native host manifests, resumable target receipts, complete asset enumeration, signatures/SBOMs, withheld partial manifests, upload/download verification, and no hosted-runner dependency.

---

# 14. Cross-stack composition

The imports compose into four planes, not a monolith.

## 14.1 Packet plane

Owns high-rate bounded work: packets, frames, thumbnails, telemetry, feature columns, and ephemeral latest-state views. It is Asupersync-owned, subject-routed, budgeted, and backpressured. It avoids per-item heavyweight proofs while retaining sequence/gap identities.

## 14.2 Authority plane

Owns source custody, anchors, versions, witnesses, policies, identities, manifests, effect state, privacy, and publication. FrankenSQLite/FrankenFS semantics and ATP roots live here.

## 14.3 Cognition plane

Owns decoded media, models, tracks, graph/search projections, digital twins, attention, and operational memory. Everything cites an authority anchor and can be rebuilt.

## 14.4 Effect plane

Owns alerts, camera settings, PTZ, retention, export, deletion, model/calibration activation, and any future flight plan. It is narrow, fenced, idempotent, and reconciliation-first.

```text
Packet plane ──capsules──▶ Authority plane ──deltas──▶ Cognition plane
      ▲                         │                           │
      │                         └────plans/witnesses────────┘
      │                                      │
      └────────observed outcomes──────── Effect plane
```

No plane can silently redefine another plane’s semantics.

---

# 15. Target crate and process ownership

The target topology is intentionally fine-grained so semantic ownership is visible in Cargo and in the process tree.

| Layer | Crates | Semantic owner |
|---|---|---|
| Foundation | `fss-types`, `fss-error`, `fss-schema`, `fss-numeric`, `fss-identity` | canonical types, stable IDs, numeric policy |
| Runtime/fabric | `fss-runtime`, `fss-capability`, `fss-subject`, `fss-obligation`, `fss-lab` | Asupersync integration, routing, service classes, replay |
| Device | `fss-device-core`, `fss-device-uvc`, `fss-device-rtsp`, `fss-device-onvif`, `fss-device-vendor-wire`, `fss-drone-capture` | discovery, auth, first-party protocol capture, controls, exact compatibility |
| Media | `fss-packet`, `fss-container`, `fss-codec-bitstream`, `fss-codec-kernel`, `fss-live`, `fss-audio` | packet truth, pure-Rust parse/decode/encode kernels, proxies |
| Authority | `fss-ledger`, `fss-witness`, `fss-object`, `fss-publication`, `fss-archive`, `fss-repair`, `fss-privacy` | version universe, custody, retention, deletion |
| Geometry | `fss-time`, `fss-calibration`, `fss-geometry`, `fss-twin`, `fss-coverage` | coordinate/time uncertainty and observability |
| Cognition | `fss-model-registry`, `fss-model-runtime`, `fss-model-kernels`, `fss-quality`, `fss-detect`, `fss-track`, `fss-associate`, `fss-temporal`, `fss-fusion` | pure-Rust model execution, derived results, and event candidates |
| Knowledge | `fss-search`, `fss-graph`, `fss-graph-algorithms`, `fss-memory`, `fss-explain` | derived retrieval, graph, context packs |
| Effects | `fss-event`, `fss-policy`, `fss-plan`, `fss-effect`, `fss-alert` | semantic plans and external outcomes |
| Presentation | `fss-api`, `fss-cli`, `fss-mcp`, `fss-report`, `fss-ops` | bounded human/agent surfaces |
| Qualification | `fss-reference`, `fss-gauntlet`, `fss-fixtures`, `fss-bench`, `fss-release` | oracles, evidence, DSR receipts |

The checked-in skeleton remains smaller until contracts and dependency directions are frozen. Empty crate theater is not progress.

---

# 16. Closed dependency universe

The strict policy is:

```text
std/core/alloc
+ FSS workspace crates
+ asupersync
+ explicitly admitted Franken crates
+ tiny Rust-only foundational exceptions with stable DEP IDs
```

Foundational exceptions are not a generic “common crate” category. Each exception names purpose, owning crate, enabled features, transitive closure, security/reproducibility review, replacement trigger, and review date. `serde`/`serde_json` may encode control and report schemas; they do not define durable canonical bytes. Cryptography, hashing, TLS, zeroization, and platform integration prefer already-owned Franken/Asupersync surfaces; any direct exception is separately gate-blocking.

Forbidden production dependencies include alternate runtimes, broad web frameworks, ORM/database clients, generic graph/search engines, Python/PyO3, FFmpeg/OpenCV/ONNX/CUDA frameworks or executables, vendor SDKs/applications/helpers, opaque telemetry agents, C/C++ FFI, dynamic loading, and dependencies that start threads or read ambient configuration without an FSS capability.

Foreign incumbents may run only in sealed laboratory or one-time migration lanes to produce tainted fixtures and differential evidence. The production runtime has no invocation path to those lanes. A device, codec, model, or accelerator capability is not production-admitted until its pure-Rust path and safe first-party substrate pass the applicable gate.

See [`DEPENDENCY_CONSTITUTION.md`](docs/DEPENDENCY_CONSTITUTION.md).

---

# 17. Import admission and replacement doctrine

An import progresses through:

```text
Censused
→ Contracted
→ ReferenceImplemented
→ AdapterImplemented
→ DifferentiallyVerified
→ FaultVerified
→ PerformanceMeasured
→ ProductionAdmitted
```

No source code presence, dependency declaration, or passing happy-path test skips a state. If an imported Franken crate is not ready for FSS’s exact use, FSS retains the contract and runs a simple reference adapter. The import is semantic before it is physical.

A replacement is permitted only when it preserves the contract, passes the same oracle and fault matrix, and updates the dependency/import registries. “Smaller,” “popular,” or “easier” is not evidence of semantic equivalence.

---

# 18. Integration sequence

The correct sequence is:

1. freeze stable IDs, anchors, effect outcomes, service classes, and publication states;
2. build a dependency-free single-threaded reference world and object graph;
3. build deterministic replay and fixture generation;
4. introduce Asupersync ownership, subject fabric, and LabRuntime execution;
5. add the multi-version ledger, positive/negative witnesses, and semantic merge oracle;
6. add source custody, root-last publication, repair-plan/apply, and local spool;
7. add UVC/file replay and packet/container truth before proprietary adapters;
8. add ATP transfer and cloud-object adapters behind the local object oracle;
9. add immutable graph/search generations and algorithm witnesses;
10. add one detector/tracker cascade with pinned model identity and replay corpus;
11. add event transactions and one non-physical alert effect with full reconciliation;
12. add time/calibration/coverage and witnessed absence claims;
13. add proprietary camera adapters one device/firmware/app tuple at a time;
14. add manually piloted drone capture and digital-twin qualification;
15. add MCP and operational memory after authority boundaries are proven;
16. optimize only where receipts identify a wall;
17. qualify locally through DSR and publish the release root last.

This sequence builds the semantic oracle before the optimized substrate. Otherwise FSS risks becoming extraordinarily fast at making ungrounded claims.

---

# 19. Research agenda created by the second pass

The architecture exposes several high-value research programs:

1. **Coverage-witness algebra.** Compose uncertain camera frusta, temporal intervals, occlusion, health, and detector recall into conservative absence certificates.
2. **Semantic SSI for physical-world events.** Determine minimal witness domains that preserve serializable event decisions without pathological false conflicts.
3. **Object-graph erasure policy.** Jointly optimize chunking, repair-symbol allocation, cloud operations, retrievability cadence, and incident value.
4. **Temporal graph reachability under interval uncertainty.** Efficiently reject impossible cross-camera associations while preserving true paths.
5. **Submodular active perception.** Select the next camera/PTZ/drone observation that maximally reduces incident uncertainty per unit risk and cost.
6. **Anytime-valid rare-event calibration.** Maintain alarm-quality evidence under distribution shift without turning statistical adaptation into authority.
7. **Digital-twin drift localization.** Separate camera movement, firmware crop change, seasonal geometry change, and clock drift from residual patterns.
8. **Schedule-space risk prioritization.** Use Asupersync trace topology to find incident/transfer/cancellation schedules most likely to violate obligations.
9. **Factorized incident explanation.** Produce compact proofs over many alternative trajectories without materializing combinatorial path sets.
10. **Privacy-preserving cross-camera association.** Preserve continuity without permanent biometric identity or globally linkable embeddings.
11. **Semantic subject service classes.** Prove that packet-plane optimization cannot leak into authority-plane guarantees.
12. **Energy-aware progressive cognition.** Optimize detector/model scheduling under thermal and battery constraints while preserving a fixed miss-risk envelope.

Each program has a safe baseline. Failure to improve performance or quality cannot weaken the core contract.

---

# 20. Agent cognitive operating-system synthesis

The deepest consequence of the repository-by-repository study is that the agent surface must not
be a final thin API pasted over finished subsystems. The agent operating layer is the place where
the stack's guarantees become one usable cognitive instrument. Each sibling contributes a
different necessary dimension:

| Source | Agent-system inheritance | What becomes impossible |
|---|---|---|
| Asupersync | region-owned sessions, capability/budget context, durable work, cancellation drain, obligations, continuations | mission work living only for one request; orphan investigations; cancellation reported before cleanup/reconciliation |
| FrankenSQLite | multi-version workspace/case/finding/plan revisions, witnesses, deterministic publication, time travel and rebase | mutable shared scratchpads, last-writer-wins agent state, silent stale handoff continuation |
| FrankenFS | root-last context/handoff/experience publication, custody states, doctor/repair, deletion closure | half-published handoffs, context roots pointing at missing children, deleted evidence surviving in derived agent artifacts |
| Frankensearch/Quill | progressive minimum-sufficient context, immutable generation, searchable delta, score/stop/absence receipts | raw world dumps as the default interface; silent recall gaps; context assembled from mixed generations |
| Franken Markdown | exact spans, taint, one semantic source and deterministic robot/human documentation | prose/tool/schema drift; prompt text acquiring authority; examples diverging across CLI/MCP/reports |
| FrankenGraphDB | one delta universe, branches, task/decision graphs, factorized explanation, capability-before-expansion | private speculation merged as truth; agent graphs leaking hidden neighbors/counts; combinatorial explanation materialization |
| FrankenNetworkX | canonical choices, minimal evidence subgraphs, dominators/cuts/submodularity, complexity witnesses | hash-order recommendations; opaque evidence selection; unpriced graph reasoning |
| FrankenTorch | typed frozen computation and receipt-bearing model execution | model prose or embeddings becoming unaudited cognition; mixed numeric/model generations inside one decision |
| Dwarf Fortress MCP | semantic situation views, prepared plans, delayed completion, indeterminate outcomes, obligation cockpit | one-tool-per-command interfaces; dispatch ACK treated as physical success; screenshot-first world reconstruction |
| FastMCP Rust | request-owned bounded presentation and transport-specific qualification | MCP handler semantics becoming architecture; unqualified cancellation/bidirectional claims; generic privileged escape hatches |
| Eidetic Engine | resumable orientation, deterministic packs, evidence-linked memory, feedback provenance, decay/trauma guard | prior experience becoming current truth; silent autonomous memory rewrite; harmful procedural transfer persisting unchallenged |
| DSR | task-level local qualification and root-last release evidence | an agent-facing API being declared usable because schemas compile or hosted CI is green |

## 20.1 The synthetic abstraction tower

The composition yields one tower, not parallel product areas:

```text
L0 runtime authority, identity, budgets, object custody
  ↓
L1 source evidence and continuity
  ↓
L2 canonical world facts and coverage at one EvidenceAnchor
  ↓
L3 derived beliefs: detections, tracks, events, graph/search results, uncertainty
  ↓
L4 SituationCapsule: SituationFrame + WorldEnvelope + delta + context proof + control envelope
  ↓
L5 InvestigationCase: competing hypotheses, contradictions, predictions, falsifiers, probes
  ↓
L6 Affordance frontier: valid read/wait/explain/repair/control options under hard clamps
  ↓
L7 ObjectiveContract + witnessed contingent ControlPlan
  ↓
L8 effects and obligations: prepare, commit, observe, verify/reconcile
  ↓
L9 ExecutionEpisode and outcome attribution
  ↓
L10 Experience/learning proposal and root-last handoff/resume
```

Every layer has a semantic owner, exact basis root, validity/invalidators, downward evidence handles,
upward mission relevance, bounded resource cost, deterministic decision fingerprint, and failure
mode. Higher layers may summarize lower layers but cannot redefine them. Lower layers cannot infer
mission preference or effect authority.

### 20.1.1 The evidence–possibility–control membrane

The most important addition to the tower is the `WorldEnvelope` carried by every
`SituationFrame`. A single ranked interpretation is insufficient in a safety system because the
world that matters most may be the one that is merely still possible. The envelope therefore
separates three linked projections:

1. **Evidence envelope:** positively supported facts, certified absences, coverage boundaries,
   continuity, provenance, and the exact assumptions under which those statements hold.
2. **Possibility envelope:** material alternative and adversarial worlds that remain consistent
   with the evidence, including low-probability/high-loss residuals protected from ordinary
   ranking and compression.
3. **Control envelope:** robust actions valid across the protected world set, conditional branches
   whose validity is world-specific, information-gathering probes that collapse the frontier,
   wait/watch choices, and actions that are blocked or unavailable.

This is a belief-space control contract rather than a classifier leaderboard. A model result can
add or reweight a possible world; graph reasoning can expose shared failure domains; search can
retrieve analogous evidence; memory can suggest a prior case. None of those may erase a protected
world without an evidence-linked collapse witness. Every `ControlPlan` binds the exact
`WorldEnvelope` digest and records the worlds in which each step is valid or unsafe. Revalidation
must fail closed when the envelope expands, splits, loses certified coverage, or changes in a way
that invalidates the plan's robustness class.

## 20.2 The universal driver loop

```text
session.open/resume
  → session.orient
  → session.follow/query/investigate/explain
  → plan
  → commit
  → wait/cancel
  → verify/reconcile
  → feedback/learning proposal
  → handoff
```

This small grammar is more powerful than a large command catalog because each operation receives
and returns the same session, anchor, epistemic, evidence-handle, budget, obligation, continuation,
and error/recovery vocabulary. Domain-specific camera, graph, model, archive, calibration, privacy,
and effect behavior is typed data inside the grammar rather than a new cognitive universe.

Every call is carried by one `AgentRequestEnvelope` and one `AgentResponseEnvelope`. The request
pins a `ContractBasis` containing the `fss/1` semantic protocol, schema catalog, ontology,
operation/view/capability/error/cost registry digests, producer release, and accepted nightly.
It also binds principal, session, mission, input anchor, workspace revision, view, target handles,
typed operation payload, budgets, requested capabilities/privacy transforms, idempotency,
continuation, hydration/compression policy, and taint. The operation registry is the sole mapping
from a public verb to its request and response payload schemas. This prevents CLI, MCP, TUI, Rust
API, and reports from acquiring rival hidden semantics and makes transcript equivalence a
mechanical release property rather than a documentation promise.

## 20.3 Cognitive economy as a system property

The resource objective is not minimum tokens in isolation. It is maximum evidence-grounded decision
quality per complete cost vector:

```text
(tokens, bytes, rows, graph operations, model work, latency, energy, network, storage,
 privacy exposure, operator burden, effect risk)
```

A compact result is valid only with a `SemanticCompressionReceipt`; an empty result is valid only
with coverage/completeness; a recommendation is valid only as a hard-clamped decomposed affordance;
a handoff is valid only if a new agent can rebase it and recover critical state without hidden
conversation. `QL-AGENT-001` measures all of these at task level.

## 20.4 Accretion without epistemic corruption

Resolved work produces immutable episodes and candidate lessons, not silent policy mutation. A
learning proposal names applicability, evidence, counterexamples, harmful outcomes, expiry,
validation plan, and promotion authority. Memory remains advisory and must be revalidated against
live anchors. The trauma guard can demote, retire, or invert harmful procedures into anti-patterns.
This turns past work into cheaper future decisions without turning accumulated confidence into
ambient authority.

---

# 21. Final synthesis

FSS should not be understood as a Rust NVR, a camera integration hub, a drone mapper, a graph database, or a multimodal agent. It is a **proof-carrying evidence fabric for a partially observed physical world**.

The Franken stack makes that possible because its strongest ideas line up:

- Asupersync owns work, authority, cancellation, messaging, and transfer.
- FrankenSQLite supplies multi-version semantic concurrency and narrow commit sequencing.
- FrankenFS supplies custody, publication, repair, and evidence discipline.
- Frankensearch supplies progressive cognition, focused in-house indexing, and oracle-driven replacement.
- Franken Markdown supplies exact, taint-preserving knowledge and deterministic reports.
- FrankengraphDB supplies one version universe, tiered relations, factorization, incremental maintenance, and certificates.
- FrankenNetworkX supplies deterministic algorithm choices and complexity witnesses.
- Dwarf Fortress MCP supplies the honest control-plane model for delayed, partial, externally changing worlds.
- FastMCP Rust supplies the bounded agent presentation layer.
- Eidetic Engine supplies cautious operational learning.
- DSR supplies local, root-last release qualification.

The alien-artifact quality does not come from maximizing novelty. It comes from making every important semantic boundary explicit, composable, testable, and difficult to bypass accidentally—then using focused algorithms and mechanical sympathy to make the resulting system faster, cheaper, and more reliable than architectures that take shortcuts.
