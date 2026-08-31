# Deep dive: `frankengraphdb` as the one-version-universe, incremental graph, branch, policy, and decision architecture

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-FGDB-001`
**Status:** design import; persistent graph engine remains optional until admitted
**Audit basis:** comprehensive design plan and current repository architecture inspected 2026-08-31

## 1. Why this is the richest architectural source

The shallow transplant would be “store event relationships in a graph database.” That would place too much authority in one derived representation and miss the plan’s real contribution: a composition of versioning, temperature-tiered storage, factorized queries, incremental views, subscriptions, policy, branches, migration, learning, and negative-space verification.

FSS imports the architecture while keeping canonical evidence in its authority ledger/object graph. The graph engine is a snapshot-pinned projection and query substrate, not the sole source of truth.

## 2. The central transplant: one version universe

`GraphDeltaBatch` becomes `EvidenceDeltaBatch`, the ordered change unit consumed by every projection:

```text
canonical observation history
current sensor/device state
track and association projections
event evidence graph
calibration/coverage graph
search and vector generations
standing predicates and subscriptions
agent branches and counterfactuals
remote read replicas
replay and proof bundles
```

Each consumer publishes a root naming the exact batch high-water mark. There is no independent “event bus state,” “graph state,” or “search state” with untraceable lag. Lag is explicit as `(consumed_seq, available_seq, source_root)`.

A batch may include:

- inserted/superseded authority records;
- object-root references;
- effect state transitions;
- invalidation/tombstone records;
- derived-generation invalidations;
- negative-domain coverage changes;
- schema/policy/model/calibration epoch changes.

The batch is canonical, bounded, ordered, and replayable. Derived computations do not write fabricated facts back into it.

## 3. CopperCore: narrow graph primitives before database ambition

FSS starts with a small deterministic graph kernel:

- stable external keys separate from compact generational handles;
- directed, undirected, multiedge, temporal, and hyperedge projections as explicit types;
- immutable snapshot views shared by reference;
- canonical iteration and tie-breaks;
- append-only delta application with validation;
- simple ordered maps/vectors as reference representation;
- algorithm traits independent of storage layout.

Optimized storage or a full graph database is admitted only behind these semantics. The effect path never waits on an ambitious general graph query engine when a small reference operator suffices.

## 4. Strata: temperature-tiered representation

Sensor/evidence graphs have extreme skew. A camera has a tiny stable neighborhood; a busy event or time bucket may connect thousands of observations; old history is cold. One representation wastes memory or update cost.

FSS representation ladder:

```text
TinyInline        very small immutable adjacency in entity record
HotDelta          recent sorted bounded additions/tombstones
WarmBlock         sealed contiguous adjacency blocks
ColdCompressed    time-partitioned compressed runs
RemoteManifest    archived adjacency/object manifests loaded on demand
```

Promotions/demotions use clone -> apply delta -> validate -> atomic swap. Hysteresis prevents flapping. Old readers retain coherent immutable views. Representation choice is a decision-card arm with measured workloads; it cannot alter result ordering or claim class.

## 5. Loom: factorized and worst-case-aware joins

Multi-camera correlation can explode if every intermediate combination materializes. Queries such as:

> “Find an unknown entity observed near a protected boundary, then absent from cameras that should see it, later matched to a track near a door, while a sensor-health degradation shares a common cause.”

join tracks, intervals, zones, visibility, sensor health, object attributes, policy, and events. FSS uses factorized relations and worst-case-optimal join planning where appropriate. Intermediate sets remain represented as products/unions rather than enumerated Cartesian paths.

The reference engine may use straightforward ordered joins first. The optimized Loom path is admitted only after output equivalence, cardinality estimates, memory bounds, and adversarial join shapes.

## 6. Ripple: incremental Z-set maintenance

Standing predicates update from `EvidenceDeltaBatch` rather than rescanning all history:

- active unknown presence by protected zone;
- tracks whose expected next camera observation is overdue;
- calibration/coverage holes affecting an active event;
- unresolved alert/provider indeterminacy;
- cameras with correlated degradation;
- events awaiting independent failure-domain corroboration;
- retention/deletion obligations becoming due;
- model/adapter drift affecting live evidence.

Relations use signed multiplicities so insertions, retractions, supersession, and correction compose. Every incremental view has a full-recompute oracle and exact consumed high-water mark. Incremental failure never silently freezes a stale alert predicate; it degrades or recomputes under policy.

## 7. Sentinel: serializable multi-version graph state

The graph projection is multi-version and snapshot-pinned. Prepared graph-informed effects carry read witnesses over nodes, edges, absence predicates, paths, coverage domains, and policy epochs. SSI reasoning remains owned by the authority transaction layer, but Sentinel-inspired graph witnesses allow precise conflict detection.

A graph algorithm cannot authorize an effect from a stale projection without explicit freshness policy and revalidation against canonical state.

## 8. Chronicle: deterministic protocol and replay

Every graph update/query/algorithm request can be represented as a canonical protocol operation with:

- input root and anchor;
- projection/schema/algorithm/policy generations;
- capability scope;
- deterministic parameters and seed;
- budget;
- output digest and decision path;
- complexity witness;
- stale/approximation status.

Chronicle replay reproduces graph construction and answers. It detects tie-break drift, storage-layout leakage, and nondeterministic parallel reductions.

## 9. Beacon: graph rank and vector retrieval as attention aids

Beacon-like graph rank, personalized PageRank, ANN, and hybrid retrieval can improve investigation and attention. They remain cognition:

- rank sensors/events/evidence likely relevant to a task;
- identify central failure domains or causal evidence;
- retrieve similar prior events or routines;
- seed graph expansion from semantic candidates.

Rank scores never become physical facts or direct alert authority. Approximation class and generation accompany every result.

## 10. Prism: subscriptions over explicit predicates

Alerts and operator streams are not arbitrary callbacks. A subscription binds:

```text
principal/capability
predicate generation
projection and authority high-water mark
freshness and completeness contract
delivery budget/backpressure policy
resume cursor
privacy/redaction scope
```

Prism-like incremental subscriptions produce resumable deltas with sequence identities and gap detection. A slow subscriber cannot block canonical ingestion. Dropped/coalesced updates follow registered semantics; mandatory effect obligations are not discarded as UI noise.

## 11. Warden: policy compiled before expansion

Authorization is applied before graph traversal, not after results are found. A principal limited to specific cameras/zones/events cannot infer hidden neighbors through degree, counts, reachability, centrality, or “no result.” Query planning operates over an authorized projection.

Warden-style audit records:

- grant and policy epoch;
- projection transformation;
- filters applied before expansion;
- result/absence claim scope;
- privacy/redaction generation;
- query cost and denied domains.

## 12. Colony: branch-per-agent speculation

Each investigator or agent may create a cheap logical branch rooted at a pinned anchor. Hypothetical operations add semantic deltas on the branch:

- alternative cross-camera associations;
- candidate calibration adjustments;
- possible benign/threat explanations;
- proposed camera placements or observation paths;
- retention/export plans;
- policy threshold changes.

Algorithms and cost/coverage analysis run over the branch. “Merge” means produce a candidate intent, evidence comparison, and conflict report for live recompilation. Fabricated branch state is never copied into authority history.

Branches have quotas, TTLs, owner capabilities, and content-addressed roots. They are ideal for parallel agents because comparison is cheap and interference is absent.

## 13. Cautery: self-profiling without semantic self-modification

The engine measures cardinalities, cache behavior, update skew, query shapes, model routing, and pressure. It may propose representation, index, batch, or plan changes. Any self-tuning decision is bounded by:

- registered arms and hard invariants;
- shadow execution or same-binary experiment;
- decision card and evidence threshold;
- rollback and hysteresis;
- deterministic safe baseline.

The database does not silently rewrite semantics or safety thresholds in pursuit of speed.

## 14. DNA: compatibility is a differential contract

The DNA harness compares:

- reference versus optimized graph representations;
- full recompute versus incremental views;
- exact versus certified approximation;
- prior versus candidate persistent formats;
- prior versus candidate query plans;
- local versus remote/read-replica results;
- migration before/after roots.

Every divergence has a canonical reproducer, classification, and consumer impact. Error-only agreement and unexercised surface are reported separately from successful conformance.

## 15. Fossil: a semantics manifest prevents accidental drift

FSS creates a graph semantics manifest defining:

- identity and generation rules;
- directedness/multiedge/hyperedge semantics;
- insertion/iteration/tie ordering;
- temporal interval and uncertainty semantics;
- missing/unknown/null distinctions;
- numeric/overflow/NaN policy;
- mutation and invalidation rules;
- exact/approximate claim classes;
- capability projection behavior;
- durable format versions.

The manifest is executable through fixtures and registries. A storage optimization may not redefine it.

## 16. Sextant: live migration is dual-run, compare, cut over, revert

Persistent graph/search/model/ledger formats evolve through migration passports:

1. identify source and target generations;
2. create a shadow target from a pinned source root;
3. dual-apply ordered deltas;
4. compare reference queries, counts, roots, and invariants;
5. seal a cutover checkpoint;
6. atomically publish target root;
7. retain source for rollback until expiry;
8. monitor drift and revert on violation.

No in-place schema rewrite is trusted without a reproducible source root and rollback.

## 17. Gradient: failures update engineering priors, not truth

Failed queries, false alerts, missed associations, bad plans, and performance regressions feed a structured failure ledger. The system learns which strategies are brittle under which regimes and may adjust experiment priority or routing. It does not automatically rewrite event labels, household whitelists, or hard safety policy.

Failure learning records conditions, mechanism, observed evidence, counterfactual, confidence, and revival conditions.

## 18. Mirror: invariants can be synthesized, but promotion is reviewed

Repeated traces and schemas can suggest candidate invariants—for example, an event state never moving backward, a published root always naming verified children, or a privacy transform always preceding remote upload. Mirror-like tooling proposes mechanical checks and counterexamples. Human/agent review assigns stable IDs and scope before an invariant becomes normative.

Observed regularity alone is not a law.

## 19. Wormhole: speculative precomputation under strict discard rules

FSS may precompute likely next work:

- decode the next GOP while a candidate is active;
- prefetch likely adjacent-camera segments;
- evaluate alternate association hypotheses;
- warm a model generation;
- compute likely evidence crops;
- stage graph/search candidates.

Speculation receives a child budget and no mutation authority. Outputs are content-addressed and admitted only if their input root/preconditions still match. Cancellation/discard is cheap and leaves no canonical side effect.

## 20. Cambium: learned planning remains an optional cognition arm

Learned cardinality, cost, or query-plan models may improve routing. They are shadowed against deterministic plans, constrained by resource/safety bounds, and produce decision cards. If the model is absent, stale, OOD, or uncertain, the reference planner remains correct.

No learned plan can remove a mandatory witness, authorization filter, or evidence stage.

## 21. Immune: negative-space verification searches for missing claims

The most important test may be what the system fails to test. Immune-style checks ask:

- Which registered algorithms lack adversarial graph families?
- Which device/firmware tuples have only rejection tests?
- Which alert paths lack lost-ACK recovery?
- Which absence claims lack coverage certificates?
- Which formats lack corrupt/truncated fixtures?
- Which privacy data families are not reached by deletion tests?
- Which performance claims lack A/A nulls or raw samples?
- Which code paths escape Asupersync time/ownership?
- Which README statements have no machine-readable proof source?

Release gates consume this negative-space report. Unknown coverage is visible rather than inferred complete.

## 22. Typed claim classes

Every graph/query output declares one of:

- `Exact`: complete under the named projection and budget;
- `CertifiedApproximate`: bounded error/recall or proof certificate under named assumptions;
- `NonCertifiedApproximate`: heuristic approximation with measured behavior but no bound;
- `Heuristic`: attention/recommendation only.

Claim class is part of the type/receipt and cannot be upgraded by prose. An approximate path is never silently returned from an exact API.

## 23. Decision cards and operation-cost registry

Every meaningful adaptive or alternative design decision has:

```text
decision_id and owner
allowed arms
hard constraints
input features and regime
reference arm
primary/guardrail metrics
evidence threshold and expiry
rollout/shadow protocol
rollback and hysteresis
negative evidence
```

The operation-cost registry rejects impossible SLOs before implementation. It records asymptotic and workload variables for adjacency, temporal lookup, witness validation, incremental views, branch clone/merge, association, coverage, and retrieval.

## 24. FSS semantic owners

| Mechanism | FSS owner | Replacement prohibition |
|---|---|---|
| `EvidenceDeltaBatch` | `fss-ledger`, `fss-delta` | No independent unordered event bus as truth |
| Snapshot graph kernel | `fss-graph-core` | No storage-layout-defined semantics |
| Strata representations | `fss-graph-store` | No representation switch without validation |
| Loom factorized joins | `fss-query` | No unbounded Cartesian materialization |
| Ripple views | `fss-incremental` | No stale standing predicate without lag status |
| Prism subscriptions | `fss-subscription` | No callback with hidden cursor/gap semantics |
| Warden projection | `fss-policy`, planner | No post-query filtering as authorization |
| Colony branches | `fss-branch` | No branch bytes merged into authority |
| Sextant migration | format owner | No destructive in-place migration |
| Immune verification | `fss-gauntlet` | No coverage inferred from source presence |

## 25. Superficial imitations that would fail

1. Putting all evidence into a graph and calling it authoritative.
2. Letting graph/search/subscription consumers maintain unrelated version clocks.
3. Materializing every multiway path before filtering.
4. Updating standing alerts by periodic full scans with no high-water mark.
5. Applying authorization after traversal and leaking degree/absence.
6. Copying speculative branch state into the live world.
7. Switching storage representations in place while readers hold views.
8. Calling a heuristic centrality result exact.
9. Letting a learned planner skip witnesses or safety filters.
10. Migrating formats without dual-run equivalence and rollback.
11. Reporting tested code paths while ignoring unexercised/negative-only surfaces.
12. Adopting all named subsystems at once before a small reference kernel exists.

## 26. Admission evidence for `INT-FGDB-001`

1. One ordered `EvidenceDeltaBatch` stream drives all admitted projections with explicit high-water marks.
2. Reference graph oracle and immutable snapshot views pass generation/invalidation tests.
3. Stable external keys, generational internal handles, and ABA fixtures.
4. Canonical ordering and decision-path digests survive representation changes.
5. Full recompute equals incremental Z-set views over insert/retract/supersede histories.
6. Factorized query results equal reference joins and remain within memory budgets on adversarial shapes.
7. Capability projections demonstrate noninterference for values, counts, paths, degree, and absence.
8. Branch isolation, quota, TTL, comparison, and live-intent recompilation.
9. Representation promotion/demotion clone-validate-swap with old-reader coherence.
10. Exact/approximate claim classes are mechanically enforced.
11. Migration passports prove dual-apply, cutover, rollback, and root equivalence.
12. Decision cards and operation-cost rows exist before adaptive/learned strategies activate.
13. Negative-space report blocks readiness claims with missing success/adversarial evidence.
14. Persistent FrankenGraphDB is adopted only after demonstrating benefit over the simpler reference projection.

## 27. Deliberately rejected imports

- A graph database in the live device/effect critical path before reference semantics.
- Automatic active-active merge for noncommutative policy/effect state.
- JIT or learned planning as an early dependency.
- Graph rank as threat truth.
- Unbounded general graph-query language exposed to agents.
- A single representation for every adjacency family.

## 28. Resulting architectural leap

FSS gains a common temporal change kernel and a family of certified projections. It can update standing security predicates incrementally, run sophisticated multi-camera joins without combinatorial explosion, give each agent an isolated hypothesis branch, migrate live generations safely, and expose exactly how complete or approximate every graph answer is.
