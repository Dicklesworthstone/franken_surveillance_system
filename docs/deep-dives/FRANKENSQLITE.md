# Deep dive: `frankensqlite` as the multi-version evidence and semantic-transaction substrate

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-FSQL-001`
**Status:** design import; persistence adapter remains unqualified
**Audit basis:** repository architecture, concurrency contract, critical invariants, recovery and benchmark methodology inspected 2026-08-31

## 1. The non-obvious import

The shallow transplant would be “store FSS metadata in SQLite.” The valuable import is a much stronger model:

```text
immutable versions
+ coherent snapshot anchors
+ witnessed reads, including negative predicates
+ deterministic commit publication
+ SSI-style dangerous-structure detection
+ conservative conflict refinement
+ semantic merge proofs
+ crash-first recovery
= concurrent reasoning without mixing worlds
```

FSS observes a world that changes independently of it. The ledger cannot make the physical world transactional, but it can make the *observation history, derived-generation boundaries, prepared effects, and reconciliation protocol* serializable and auditable.

## 2. One canonical version axis for authoritative facts

Every committed authority-plane change receives a monotonically ordered `CommitSeq`. A query pins a `WorldAnchor`:

```text
deployment_lineage
commit_seq
observation_epoch
object_root
adapter_registry_epoch
model_registry_epoch
calibration_epoch
policy_epoch
privacy_epoch
schema_epoch
```

A reader never combines event revision from one anchor, camera health from another, and calibration from a third unless it explicitly performs a temporal join. Derived graph/search/model generations publish the exact high-water mark they consumed and cannot claim freshness beyond it.

The ledger stores compact authority facts and manifests. Large media, model weights, geometry, and proof artifacts remain content-addressed objects whose roots are referenced transactionally.

## 3. Read witnesses: a plan records what it relied on

A prepared alert, camera control, deletion, export, or activation records semantic read witnesses, not one coarse state hash. FSS witness classes include:

- identity generation and revision;
- field value, field absence, or presence state;
- stream continuity interval and packet-sequence domain;
- source-object existence and custody state;
- event revision and evidence-root membership;
- calibration transform, covariance, and validity region;
- coverage cell/zone version and visibility mask;
- track/association membership and alternative hypotheses;
- policy, privacy, model, adapter, schema, and capability epochs;
- archive publication and retrievability state;
- resource reservation, lease, and fence;
- aggregate quantity plus contributing set;
- graph edge existence/nonexistence and bounded reachability;
- negative predicate over an explicitly covered spatial-temporal domain.

A write witness identifies the semantic domains an effect or publication intends to change. Conflict is defined over semantics, not serialized row bytes.

## 4. Negative reads are first-class predicates

“No person is in the protected yard” is not absence of a detector row. It depends on:

```text
zone geometry
camera coverage generation
effective sensor health
capture interval and continuity
model/detector generation
minimum observable size/contrast
occlusion and privacy masks
queried time range
```

The witness therefore names a bounded domain and coverage certificate. New evidence that introduces a person, invalidates calibration, degrades a camera, or changes the policy conflicts with the negative read. Cache miss is never evidence of absence.

## 5. Hierarchical witnesses permit safe refinement

Witnesses form a hierarchy:

```text
deployment
└── domain (sensor / event / archive / policy / geometry)
    └── sensor-set / zone / time-bucket / entity family
        └── stream generation / spatial cell / event / object root
            └── field / packet range / pixel mask / edge / object child
```

Coarse witnesses are mandatory and sound. Fine witnesses are optional performance accelerators. If two prepared operations conflict coarsely, the coordinator may spend a bounded value-of-information budget to refine. Exhaustion yields a conservative conflict or replan; it never grants permission.

This asymmetry is essential: performance failure may reduce concurrency, but cannot create an undetected race.

## 6. SSI-style dangerous structures for multi-agent and external-world plans

Prepared and recently committed semantic transactions form a dependency graph from read/write antidependencies. The coordinator detects dangerous structures that could create write skew, including phantoms from negative reads.

Examples:

- Agent A reads “rear camera healthy” and prepares suppressing a redundant alert; Agent B concurrently disables that camera for maintenance.
- Two agents each see one free archive budget and both prepare expensive exports.
- A retention change reads “no legal hold” while another operation creates the hold.
- A camera-control plan reads an old calibration/coverage generation while a calibration activation changes the field of view.
- An alert policy reads “no prior alert in cooldown window” while another alert commits into that window.

Passing the ledger gate proves validity at the selected anchor. It does not prove the camera/provider/physical world stayed unchanged forever. The boundary operation still performs a final bounded precondition check and later reconciliation.

## 7. Deterministic commit combining

Planning, decoding, inference, and graph work remain parallel. Completed commit candidates enter one brief deterministic sequencing point. The combiner:

1. orders candidates by registered stable policy;
2. validates transaction, lease, fence, and epoch identity;
3. checks read/write witnesses against the chosen anchor;
4. performs bounded refinement;
5. detects dangerous structures;
6. reserves durable IDs and idempotency rows;
7. stages object/publication references;
8. commits one authority delta batch or returns a precise conflict/replan result.

Callbacks and expensive work happen after releasing the sequencing lock. Drain-then-drop-then-process prevents reentrant deadlocks. Failed speculative workers publish no visible side effects.

## 8. Semantic merge ladder

FSS never resolves semantic conflict with last-writer-wins. The merge ladder is:

1. **Exact intent replay.** Recompile the immutable intent against the new anchor.
2. **Stable-key structural merge.** Merge disjoint fields, object children, spatial masks, annotation edges, or time ranges using canonical order.
3. **Registered commutative composition.** Append-only adjudications, evidence edges, and counters may compose when the registry proves commutativity and identity.
4. **Domain compensation and replan.** Reconcile an external effect before generating a replacement plan.
5. **Reject.** Unknown, ambiguous, or privacy-sensitive semantics do not merge.

An accepted merge emits a certificate naming basis anchors, intents, conflict domains, mechanism, canonical normal form, decision path, and post-merge digest.

Potential safe merge families:

- append-only evidence/adjudication records;
- nonoverlapping media packet ranges in one stream generation;
- nonoverlapping privacy-mask tiles under the same coordinate frame;
- independent archive manifest children before root publication;
- track annotations that target distinct registered fields;
- resource counters with algebraically registered operations.

Threat belief, identity association, effect status, policy priority, and deletion scope never use blind field merges.

## 9. Savepoints map to staged semantic work

Savepoints are useful for bounded batches and agent plans. Rolling back to a savepoint restores transaction-local rows, object references, witness sets, and publication reservations while preserving the outer transaction’s ownership and lock semantics. Release merges child state into its parent deterministically.

FSS uses savepoint-like scopes for:

- one sensor capsule inside a larger ingest batch;
- one model result inside an event revision;
- one provider part inside a multipart archive upload;
- one candidate association inside a k-best hypothesis batch;
- one evidence export rendition inside an all-or-nothing sibling publication.

A savepoint cannot roll back an already dispatched external effect; that belongs to reconciliation/compensation.

## 10. Exact numeric ordering is a correctness surface

Time, sequence numbers, costs, IDs, and model scores cannot rely on lossy or platform-variable comparison. FSS imports the exact-order discipline:

- integer timestamps and sequence values compare exactly in widened integer space;
- floating values have a registered total order, NaN policy, signed-zero policy, and overflow behavior;
- mixed integer/real comparisons never silently cast large integers to imprecise floats;
- score-space identity is part of the key, so values from different model generations are incomparable by default;
- deterministic tie-breaks are explicit stable IDs or insertion sequence, never hash iteration.

This is crucial for replay, top-k alert selection, temporal windows, and archive expiry.

## 11. Recovery is part of the transaction contract

Crash testing covers each publication cut:

```text
before ID reservation
after reservation / before row materialization
after ledger rows / before object staging
after object children / before root seal
after root seal / before root pointer commit
after commit / before client response
after effect intent commit / before dispatch
after dispatch / before provider receipt
after receipt / before observation/reconciliation
```

Recovery distinguishes:

- definitely not committed;
- committed and visible;
- staged but unreachable and eligible for quarantine/GC;
- effect dispatched but outcome unknown;
- object root published but remote retrievability unproven;
- derived generation stale and rebuildable;
- canonical evidence requiring operator repair.

Recovery never infers a successful external effect solely from an intent row.

## 12. Compact conflict summaries must preserve safety history

Pruning old transactions or event history must retain enough summary state to preserve SSI reasoning. Approximate read fingerprints may create false conflicts but cannot create false negatives. Any compact structure used for witness membership has a declared one-sided error contract and reference fallback.

For FSS, summaries retain at least:

- read/write conflict epochs;
- negative-domain coverage roots;
- effect and lease fences;
- event lineage high-water marks;
- archive/deletion obligations;
- dangerous-structure in/out history needed by the selected SSI profile.

## 13. Canonical versus derived data

### Canonical ledger families

- deployment, principal, capability, policy, and privacy generations;
- device/adapter/stream identities and compatibility tuples;
- observation/capsule manifests and time/continuity evidence;
- immutable event revisions and adjudications;
- calibration and coverage certificates;
- model job/result identities and admitted summaries;
- prepared effects, receipts, reconciliation, and obligations;
- archive roots, retention, holds, deletion plans, and proof bundles;
- the ordered `EvidenceDeltaBatch` log.

### Derived/rebuildable families

- decoded frame caches and proxies;
- track acceleration indexes;
- search segments and embeddings;
- graph adjacency representations and centrality scores;
- thumbnails, summaries, context packs, and TUI projections;
- materialized standing queries;
- optimization statistics not required to explain a committed decision.

Derived generations still have identities and high-water marks; rebuildable does not mean untracked.

## 14. FSS semantic owners

| Imported mechanism | FSS owner | Replacement prohibition |
|---|---|---|
| `CommitSeq`, snapshot anchors | `fss-ledger`, `fss-types` | No mutable “latest world” singleton |
| Read/write/negative witnesses | `fss-transaction` | No state-hash-only validation |
| SSI dependency graph | `fss-transaction` | No optimistic commit without phantom handling |
| Deterministic commit combiner | `fss-ledger` | No callback under publication lock |
| Semantic merge certificates | Domain crate + `fss-transaction` | No generic last-writer-wins |
| Crash recovery | `fss-ledger`, `fss-evidence` | No log scraping as source of truth |
| Exact ordering | `fss-types` | No hash order or lossy mixed numeric compare |

## 15. Superficial imitations that would fail

1. Storing rows in FrankenSQLite but letting every subsystem maintain its own mutable epoch.
2. Snapshotting tables without pinning model, calibration, policy, and object roots.
3. Recording a plan state hash rather than the facts and negative predicates it relied on.
4. Using the low-level transaction manager and assuming it provides full SSI semantics automatically.
5. Treating cache misses or no detector row as negative evidence.
6. Refining conflicts with a probabilistic structure that can false-negative.
7. Letting a callback or model run inside the commit critical section.
8. Merging threat belief or effect state by field timestamp.
9. Pruning dependency history needed to detect later dangerous structures.
10. Reporting crash recovery from happy-path database reopen tests only.

## 16. Admission evidence for `INT-FSQL-001`

1. Differential execution against a single-threaded in-memory reference ledger.
2. Snapshot tests prove no query mixes authority epochs or derived high-water marks.
3. Negative-read phantom corpus covers space, time, coverage, continuity, policy, and object domains.
4. Multi-agent dangerous-structure schedules are explored deterministically.
5. Conflict refinement exhaustion produces conservative aborts only.
6. Semantic merge certificates replay byte-for-byte and reject unknown operations.
7. Savepoint rollback/release preserves outer ownership and witness semantics.
8. Exact numeric and tie-order fixtures cover large integers, NaNs, signed zero, time intervals, and model-generation separation.
9. Crash injection at every reserve/materialize/publish/effect boundary yields the registered recovery state.
10. Backup/restore enters a new observation epoch and rejects stale prepared effects.
11. Pruning/compaction preserves SSI summaries and negative-domain roots.
12. Concurrency/performance claims include raw samples, environment, contention shape, aborts, tail latency, and same-binary A/A controls.
13. No persistence readiness claim is made from parser/source presence or rejection-only tests.

## 17. Deliberately rejected imports

- Treating the entire physical world as ACID. Only the observation/effect protocol is transactional.
- Using database triggers or SQL as hidden policy authority.
- Exposing arbitrary SQL to agents.
- Making large media blobs the primary relational payload.
- Requiring advanced native-mode features before a deterministic adapter proves semantics.
- Equating database commit with camera/provider effect completion.

## 18. Resulting architectural leap

The ledger does more than remember events. It lets an agent or operator ask:

> “At exactly which coherent world anchor was this decision valid, what positive and negative facts did it rely on, which concurrent changes could invalidate it, what external effect crossed the boundary, and what can be proven after a crash?”

That is the transaction model FSS actually needs.
