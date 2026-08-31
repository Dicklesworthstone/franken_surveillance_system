# MVCC evidence ledger and semantic transaction protocol

**Status:** normative design
**Revision:** 1
**Date:** 2026-08-31

FSS cannot make the physical world transactional. It can make its observations, decisions, plans, publications, and effect reconciliation serializable and replayable. This document defines that boundary.

## 1. One version universe

The canonical append-only stream consists of `ObservationCapsule`, `AuthorityDelta`, `EffectRecord`, and `PublicationMarker` entries ordered by `LedgerCommitSeq`. Derived graph, search, feature, and memory systems consume the same stream and publish high-water marks.

The stream supports:

- current views;
- historical `AS OF` reads;
- subscriptions;
- deterministic replay;
- graph/search/index updates;
- replica transfer;
- branch creation;
- dataset extraction;
- incident reconstruction.

There is no separate mutable “current truth” whose history is inferred later.

## 2. Evidence anchor

```text
EvidenceAnchor {
  deployment_lineage,
  site_epoch,
  ledger_commit_seq,
  observation_seq,
  source_root,
  clock_epoch,
  adapter_epochs,
  model_epochs,
  calibration_epoch,
  graph_generation,
  search_generation,
  policy_epoch,
  privacy_epoch,
  schema_epoch
}
```

Readers pin an anchor. Derived generations may lag but must declare the consumed high-water mark and allowed staleness. A strict query refuses a projection newer or older than its contract permits.

## 3. Canonical record families

- deployment/site/principal/capability generations;
- device, credential reference, adapter, firmware, and stream generations;
- packet/source segment capsules and clock evidence;
- object manifests and publication markers;
- model, calibration, graph, search, and policy activations;
- event hypotheses and immutable revisions;
- effect plans, dispatches, observations, and terminal reconciliation;
- privacy masks, holds, retention, deletion plans, and closure receipts;
- qualification and readiness roots.

Large media and derived arrays live in the object store. Ledger records name their roots.

## 4. Transaction classes

| Class | Examples | External effect? |
|---|---|---|
| `ObservationCommit` | source capsule, health sample, clock sample | no |
| `DerivedGenerationCommit` | graph/search/model-result generation | no, rebuildable |
| `EventRevisionCommit` | corroboration, rejection, severity change | no external effect |
| `EffectPrepareCommit` | alert/PTZ/retention/export plan | not yet |
| `EffectDispatchCommit` | request durably recorded before boundary call | yes/possible |
| `EffectObservationCommit` | boundary accepted, physical change observed | reports external state |
| `EffectTerminalCommit` | verified complete/failed/indeterminate | terminal classification |
| `PublicationCommit` | object/calibration/model/release root | exposes immutable state |
| `PrivacyCommit` | mask/hold/deletion generation | may create external mutations |

## 5. Read witnesses

A transaction records predicates, not only row versions. Witness forms include:

- exact record revision;
- field value or absence;
- object/child existence and integrity;
- stream continuity over a packet/time range;
- clock interval and uncertainty bound;
- spatial occupancy over cells/frusta/zones;
- track/entity revision;
- graph edge/path/reachability result;
- aggregate with contributing source set;
- policy/model/calibration/privacy/schema generation;
- negative-domain predicate;
- coverage witness;
- lease/capability fence;
- external operation lookup state.

## 6. Negative witnesses

A negative claim contains:

```text
NegativeWitness {
  predicate,
  spatial_domain,
  temporal_interval,
  authorized_projection,
  sensor_set,
  continuity_evidence,
  calibration_generation,
  occlusion_model,
  detector/coverage qualification,
  unobservable_subdomains,
  expiry,
  digest
}
```

The claim is invalidated by new observations in the domain, health/clock/calibration drift, policy/model change, or an expanded authorized projection. Missing coverage yields `Unknown`, never `False`.

## 7. Write witnesses

Write witnesses name semantic conflict domains:

- event identity/revision;
- alert/incident obligation;
- sensor control lease and pose domain;
- retention/hold/deletion graph;
- policy/model/calibration activation namespace;
- archive root/generation;
- identity/track hypothesis component;
- graph/search generation root;
- release version and asset set.

They begin conservative and may be refined under budget.

## 8. Hierarchical refinement

Conflict domains form a tree. Example:

```text
site
└── spatial
    └── zone rear-yard
        └── frustum intersection
            └── voxel/time mask
```

A coarse collision triggers optional value-of-information refinement. If refinement cannot prove disjointness within budget, the transaction conflicts. Performance degradation may reduce concurrency; it cannot admit a race.

## 9. Dangerous structures

FSS tracks rw-antidependencies among prepared/recent transactions. Examples:

- event E reads “no resident in zone”; new observation writes resident occupancy; E prepares alert;
- retention deletion reads “no hold”; incident creation writes hold; deletion writes object removal;
- PTZ plan reads old camera pose/coverage; calibration activation changes transform; PTZ writes pose;
- model promotion reads quality corpus generation; feedback commit changes labels; promotion writes active model.

The coordinator aborts/replans a pivot that would violate the selected serializability profile.

## 10. Commit coordinator

Producers prepare complete candidates in parallel. A narrow deterministic coordinator:

1. orders candidates by stable policy;
2. validates anchor, epochs, capability, lease, and idempotency;
3. checks read/write witnesses;
4. performs bounded refinement;
5. detects dangerous structures;
6. allocates a gap-free commit sequence, optionally with flat combining;
7. reserves external-effect/publication records;
8. emits commit/replan/conflict receipts;
9. releases the lock before callbacks or expensive I/O.

No decode, inference, graph traversal, object upload, or vendor call runs in the sequencing critical section.

## 11. Semantic merge

### Exact intent replay

Recompile the original semantic intent at the new anchor. This is preferred because it reuses current policy, calibration, and observations.

### Stable-key structural merge

Allowed for disjoint evidence edges, independent annotations, distinct object children, or non-overlapping spatial/time masks with canonical ordering.

### Registered commutative operations

Examples include monotone corroboration sets, counters with deduplication identity, and union of independent source references. The operation registry contains an algebraic law and differential tests.

### Reconcile and replan

Any transaction that may have dispatched an external effect first looks up and observes the operation. It never blindly retries from the old branch.

### Reject

Unknown semantics, conflicting identity hypotheses, incompatible policies, or unbounded merge cost fail closed.

## 12. External effect protocol

```text
Prepare
→ Revalidate
→ PersistDispatchIntent
→ Dispatch
→ PersistBoundaryReceipt
→ ObservePhysicalOrRemoteState
→ VerifyPostcondition
→ Terminalize
```

Cancellation before `PersistDispatchIntent` is clean. Cancellation after dispatch must reconcile. Terminal states are `VerifiedComplete`, `VerifiedFailed`, or `Indeterminate`; local cancellation is not a substitute.

## 13. Idempotency

An idempotency key is scoped by operation family, principal, target, and generation. The ledger stores request digest and outcome. Reuse with identical content returns the prior outcome or reconciliation handle. Reuse with different content is a conflict.

Vendor APIs lacking native idempotency use a fencing/lookup/observation protocol and may remain `Indeterminate`.

## 14. Branches

Branches are immutable overlays rooted at an anchor. They support hypothetical camera placements, policy changes, sensor failures, retention choices, and event interpretations. They can consume graph/search/model projections rebuilt from branch deltas.

Merging a branch produces a live candidate intent and conflict certificate. Fabricated branch observations never become canonical evidence.

## 15. Recovery

On startup FSS:

1. validates ledger and object publication roots;
2. reconstructs prepared, dispatched, observed, and terminal effect sets;
3. resumes or aborts unpublished local transactions;
4. queries external operation states where possible;
5. marks unknowable effects `Indeterminate`;
6. starts a new process/site observation epoch;
7. invalidates stale leases and prepared plans;
8. rebuilds or verifies derived generations from high-water marks.

## 16. Reference implementation

The oracle uses ordered maps, one writer, no background threads, explicit deterministic clocks, and whole-domain witnesses. Optimizations may add sharding, fine witnesses, lock-free snapshots, flat combining, and incremental projections only behind equivalence tests.

## 17. Admission evidence

- reference/optimized differential execution;
- schedule exploration;
- negative phantom corpus;
- crash at every publication/effect point;
- stale-anchor and epoch invalidation;
- semantic rebase certificate replay;
- branch isolation;
- idempotency conflict tests;
- external ambiguity recovery;
- bounded-refinement false-conflict proof;
- historical query and derived high-water correctness.
