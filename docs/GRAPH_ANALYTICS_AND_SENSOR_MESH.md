# Graph analytics and sensor-mesh constitution

**Document class:** normative graph semantics, algorithms, and qualification plan
**Revision:** 1
**Date:** 2026-08-31
**Primary source DNA:** `franken_networkx`, `frankengraphdb`, `dwarf_fortress_mcp`, `eidetic_engine_cli`

---

## 0. Why graph theory is central rather than decorative

A multi-camera security system is not simply a collection of independent classifiers. It is a set
of partially overlapping, failure-prone observers embedded in a physical topology. Threats move
through space and time; visibility is directional and occlusion-dependent; track identities cross
sensor boundaries; evidence supports or contradicts other evidence; alert workflows have causal
and delivery dependencies; archives are immutable object graphs; and failures create cuts through
the system.

The first FSS draft treated “the graph” as a useful derived projection. That remains true but is too
weak. FSS needs several distinct graph universes, each with explicit semantics, canonical tie-breaks,
version anchors, uncertainty, complexity witnesses, and validity intervals. Graph algorithms are
part of the decision kernel, not an analytics dashboard.

The governing rule is:

> **Every operational graph answer is a snapshot-pinned projection with a declared mathematical
> model, deterministic choice policy, resource budget, decision-path digest, and certificate of
> what the answer does and does not establish.**

## 1. Constitutional graph rules

### `GRAPH-INV-001` — one anchor per execution

Every graph execution pins one canonical observation anchor and one projection generation. It may
explicitly query a temporal interval, but it never silently mixes camera health from one anchor,
calibration from another, and tracks from a third.

### `GRAPH-INV-002` — graph type is semantic

Directedness, multiedges, self-loops, edge identity, node identity, weight interpretation, missing
weight behavior, numeric domain, and temporal semantics are part of the algorithm contract. A
simple undirected graph is not a harmless substitute for a temporal directed multigraph.

### `GRAPH-INV-003` — canonical choices

When several mathematically valid answers exist, FSS declares a tie-break policy. Hash iteration,
thread completion order, allocator address, and platform-dependent floating-point reduction order
are never tie-break policies.

### `GRAPH-INV-004` — graph projections cannot authorize effects

A cut, path, matching, PageRank score, community, anomaly, or predicted edge may propose attention
or evidence. It cannot directly trigger an alert, PTZ move, retention change, person-identification
claim, or drone action. Policy evaluates graph evidence together with canonical observations and
capabilities.

### `GRAPH-INV-005` — absence is certified or unknown

“No route exists,” “no camera covers this region,” “no associated track appears,” and “no evidence
supports this hypothesis” require an exact-domain coverage certificate. Budget exhaustion,
staleness, sampling, or approximate search produces `UncertifiedAbsence`, not false certainty.

### `GRAPH-INV-006` — approximation is one-sided where safety matters

An approximation may overstate conflict, risk, required coverage, or uncertainty. It may not
silently understate a blind spot, cut vulnerability, path possibility, or identity ambiguity. Any
algorithm with possible false negatives must be restricted to candidate generation followed by an
exact verifier.

### `GRAPH-INV-007` — derived maintenance is reproducible

Incremental maintenance from observation capsules must be equivalent to a full rebuild at the same
anchor. Every projection names its source high-water mark and deterministic update order.

### `GRAPH-INV-008` — witnesses travel with answers

Every planning-relevant execution emits a `GraphAlgorithmWitness` naming inputs, policy, observed
work, stop reason, output digest, and decision-path digest. An answer without a witness is advisory
at most.

## 2. Graph universes

FSS does not use one giant property graph for everything. It publishes typed projections over the
same version universe.

### 2.1 Physical topology graph `G_phys`

**Nodes:** doors, windows, gates, walkways, rooms, yards, roof zones, fences, stairs, driveways,
likely entry surfaces, shelters, choke points, and surveyed landmarks.
**Edges:** traversable transitions with direction, width, slope, visibility, access state, expected
transit-time interval, and uncertainty.
**Uses:** adversarial routes, resident routine routes, choke points, evacuation/approach analysis,
camera placement, and observation planning.

A single physical connection may have parallel edges: ordinary walking, crawling under an
obstacle, climbing, or a door-open versus door-closed transition. Collapsing those edges would erase
exactly the stealth behavior the system must reason about.

### 2.2 Visibility and coverage hypergraph `H_vis`

Visibility is not naturally pairwise. A camera can observe a target cell only under a joint set of
conditions: pose, field of view, occluder state, illumination, weather, lens health, target height,
motion direction, codec quality, and detector profile. FSS therefore models a coverage relation as
a hyperedge or factor:

```text
(camera_generation, calibration_generation, target_cell, target_class,
 environment_regime, sensor_health) -> detection-opportunity distribution
```

The ordinary bipartite camera↔cell projection is a derived view used for placement algorithms. It
must retain a link to the richer factor and uncertainty.

### 2.3 Sensor dependency graph `G_sensor`

**Nodes:** sensors, access points, switches, power circuits, edge hosts, clock sources, model executors,
archive paths, and alert providers.
**Edges:** depends-on, shares-failure-domain, synchronizes-with, transfers-through, powered-by,
corroborates, and can-fallback-to.
**Uses:** articulation points, bridges, dominators, cuts, correlated failure analysis, and degraded
mode selection.

### 2.4 Time-expanded transit graph `G_time`

A node is `(zone, time_bucket_or_interval)`. Edges represent physically plausible movement under a
speed/behavior model and uncertain clock alignment. It supports:

- cross-camera tracklet association;
- route hypotheses through unobserved space;
- earliest/latest possible arrival;
- explanation of why two sightings can or cannot be the same entity;
- observability-aware negative evidence.

Clock uncertainty widens edge intervals. A path that exists only because timestamps were treated as
exact is invalid.

### 2.5 Track association graph `G_assoc`

**Nodes:** within-camera tracklets and observations.
**Edges:** candidate identity transitions with decomposed cost/evidence:

- temporal feasibility;
- calibrated spatial transition;
- appearance similarity with model generation;
- size/gait/motion constraints;
- occlusion and blind-route plausibility;
- contradictory simultaneous visibility;
- source quality and health;
- household routine context.

Assignments are hypotheses, not identity facts. Competing paths and ambiguity margins are retained.

### 2.6 Causal evidence graph `G_evidence`

**Nodes:** source capsules, decoded windows, detections, tracks, geometry facts, model receipts,
hypothesis revisions, policy decisions, alert intents, provider receipts, operator adjudications,
and memories.
**Edges:** derived-from, supports, contradicts, invalidates, supersedes, observed-after,
required-by, and explains.
**Uses:** explanations, invalidation, deletion closure, reproducibility, evidence-minimality,
dominator analysis, and counterfactuals.

This graph is the spine of every alert explanation. It is append-only at the canonical layer;
current views select the active revision set.

### 2.7 Effect and obligation graph `G_effect`

**Nodes:** prepared intents, capability grants, leases, dispatch attempts, callbacks, observations,
verification predicates, compensations, and cleanup obligations.
**Edges:** must-precede, owns, fences, waits-for, compensates, verifies, and blocks.
**Uses:** cycle/deadlock detection, critical path, cancellation potential, and honest completion.

### 2.8 Archive object graph `G_object`

**Nodes:** evidence roots, manifests, source media chunks, repair symbols, indexes, reports, model
receipts, signatures, and replicas.
**Edges:** contains, references, repairs, supersedes, replica-of, and retained-by-hold.
**Uses:** graph closure verification, root-last publication, deletion reachability, retrieval audits,
and repair planning.

### 2.9 Trust and authority graph `G_auth`

**Nodes:** principals, capabilities, scoped resources, adapters, model executors, effects, and policies.
**Edges:** may-read, may-derive, may-prepare, may-commit, delegated-from, narrowed-by, and expires-at.
**Uses:** capability noninterference, least-authority review, cache partitioning, and proof that a
query result does not leak hidden neighbors or counts.

### 2.10 Operational memory graph `G_memory`

**Nodes:** evidence-linked lessons, benign routines, failure modes, anti-patterns, operator feedback,
and runbooks.
**Edges:** supported-by, contradicted-by, applies-to, supersedes, harmed, helped, and revived-by.
**Uses:** retrieval and attention only. Memory cannot mutate authority, policy, or identity.

## 3. Algorithm execution contract

Every registered graph algorithm declares:

```text
algorithm_id
semantic_version
projection_kind
source_anchor
projection_generation
node/edge identity policy
directedness and multiedge semantics
weight and missing-value policy
numeric type, precision, NaN/overflow policy
tie_break_policy_id
exact/approximate/reference status
soundness direction
resource budget and cancellation points
complexity model
staleness/expiry policy
output ordering
certificate schema
reference oracle
differential corpus
```

The execution witness adds:

```text
n, m, hyperedge/factor counts
input digest
policy digest
observed operation counts
allocations/peak bytes
budget consumed
stop reason
recovery decisions
output digest
decision_path_digest
certificate digest
```

The machine registry is `architecture/graph_algorithms.json`; the schema is
`schemas/graph_algorithm_witness.v1.json`.

## 4. Canonical graph semantics from FrankenNetworkX

FSS imports the following deeper mechanism, not merely a list of algorithms:

1. **Observable behavior is contractual.** Iteration order, selected equal-cost path, matching
   choice, output order, error class, and failure reason are regression-locked.
2. **CGSE-style tie breaks.** A `TieBreakPolicy` is named at the call site or inherited from a
   projection policy epoch. The decision path is hashed so replay detects nondeterministic drift.
3. **Strict versus hardened modes.** Strict mode rejects malformed or semantically incomplete
   graph input. Hardened mode performs only registered bounded recovery and emits a decision record.
4. **Complexity witnesses.** Performance regressions and adversarial graph blowups are visible in
   operation counts, not inferred only from wall time.
5. **Differential oracles.** Small/medium fixtures compare against a pinned reference; optimized
   implementations remain behind semantic equivalence gates.
6. **Repairable long-lived artifacts.** Critical graph/proof corpora and baseline ledgers are
   content-addressed and may carry repair symbols.

FSS uses the native Rust crates and owned semantics. It does not embed Python or depend on the
NetworkX compatibility layer in production.

## 5. Algorithm families and exact FSS uses

### 5.1 Dynamic connectivity

**Question:** Which regions remain connected to a monitored boundary after a sensor, access point,
light, or path becomes unavailable?
**Projection:** `G_phys`, `G_sensor`, and the camera↔cell projection.
**Operational use:** incrementally update coverage components under device failure, door/gate
state, foliage/vehicle occlusion, or calibration invalidation.

The reference implementation may rebuild with union-find/BFS. An optimized fully dynamic
structure is admitted only when update/query workload justifies it and its answer is differential-
checked under deletion-heavy adversarial sequences.

### 5.2 Articulation points, bridges, and biconnected components

These reveal single points whose failure disconnects physical routes, observation coverage, clock
synchronization, network delivery, or evidence custody.

Examples:

- one rear camera is the only observer connecting two coverage regions;
- one Wi-Fi access point dominates all outdoor streams;
- one doorway is the only observed transition between yard and interior;
- one archive relay is the only path to remote durability.

A cut finding is not merely a dashboard warning. It creates a registered resilience obligation and
feeds placement/repair planning.

### 5.3 Dominators and dominance frontiers

In a directed flow graph, node `d` dominates `n` when every path to `n` passes through `d`. FSS uses
this for:

- sensors that dominate evidence for a zone or route;
- model stages that dominate every alert proof;
- clock/calibration facts that dominate cross-camera identity;
- effects/receipts that dominate a terminal outcome;
- archive objects that dominate restorability.

Dominator results are especially useful for explanations: “this alert depends critically on camera
3 because every feasible observation path crosses it.” Dominance frontiers identify where evidence
from alternative branches reconverges.

### 5.4 Minimum cuts and Gomory–Hu trees

For undirected capacity models, a Gomory–Hu tree compactly represents all-pairs minimum-cut values.
FSS uses it to identify:

- pairs of zones separated by weak observation capacity;
- small correlated sensor-failure sets that create blind corridors;
- network/evidence-transfer bottlenecks;
- which additional camera or link most improves the worst cut.

Capacities are not arbitrary “confidence” numbers. They must have a registered interpretation, such
as lower-bounded independent observation opportunity or throughput. Correlated sensors cannot be
summed as independent capacity without a failure-domain factor.

### 5.5 Effective resistance, algebraic connectivity, and Fiedler structure

Effective resistance provides a global redundancy measure: two nodes joined by many independent
paths have lower resistance than two nodes connected by one fragile bridge. FSS applies resistance
and Laplacian spectral quantities to:

- redundancy of zone coverage;
- resilience of sensor/network topology;
- candidate placement that reduces fragile long-range dependence;
- drift detection when the operational graph loses connectivity quality;
- prioritizing tests at structurally weak seams.

These metrics are advisory and numerically sensitive. The contract states solver tolerance,
conditioning, disconnected behavior, and deterministic reduction order. Small graphs use an exact
or high-precision oracle. A spectral score can rank candidates but cannot certify threat absence.

### 5.6 Shortest, k-shortest, and constrained paths

FSS needs more than one shortest path:

- shortest plausible unobserved route between two sightings;
- k alternative routes to measure ambiguity;
- lexicographically constrained paths respecting speed, zone, and visibility;
- resident/raccoon/vehicle route hypotheses;
- archive/network fallback routes;
- explanation path through evidence.

Equal-cost paths use a declared stable identity/insertion tie-break. A path witness includes the
edge sequence and decomposed cost; a scalar score alone is insufficient.

### 5.7 Temporal reachability and interval paths

A cross-camera hypothesis is valid only when a path exists within uncertain capture intervals and
motion constraints. The temporal solver propagates earliest/latest arrival intervals and rejects
causally impossible transitions. It can return:

- reachable with witness path;
- unreachable with complete-domain certificate;
- ambiguous because time/geometry bounds overlap;
- unknown because the expansion budget or projection coverage is incomplete.

This four-way result prevents “timestamps are close” from masquerading as identity evidence.

### 5.8 Maximum flow and minimum-cost flow

**Maximum flow/min-cut:** quantify evidence transport capacity, simultaneous stream admission, or
observation opportunity under capacity constraints.
**Minimum-cost flow:** allocate bounded model/compute/archive capacity across candidate events,
streams, and destinations while meeting deadlines and minimum-service constraints.

Cross-camera track association can also be represented as a time-expanded min-cost-flow problem,
where each tracklet has entry/exit nodes, transition edges encode plausibility, and capacities
prevent one tracklet from being assigned to multiple identities. The solver emits the selected flow,
alternatives within a margin, and sensitivity to each cost family.

A heuristic/greedy scheduler may be the hot path, but small exact min-cost flow is the reference
oracle and counterexample generator.

### 5.9 Bipartite and general matching

Matching supports:

- calibration feature/correspondence assignment;
- tracklet association across adjacent cameras;
- assigning model executors to jobs under capability constraints;
- assigning camera placements to coverage obligations;
- matching operator feedback to event revisions.

The contract declares whether cardinality, total weight, bottleneck, stable matching, or a
lexicographic objective is intended. Equal-weight matching is canonicalized. Approximate nearest
neighbor retrieval may propose candidate edges but the final matching uses exact registered costs.

### 5.10 SCCs, condensation DAGs, and cycle analysis

Strongly connected components reveal feedback loops in:

- effect/obligation waits;
- archive replication/retention dependencies;
- policy rules that recursively support each other;
- event/memory derivation mistakes;
- model pipeline dependencies.

The condensation DAG provides a canonical acyclic order for recomputation, invalidation, recovery,
and publication. An unexpected SCC in a graph class declared acyclic is a hard invariant failure.

### 5.11 Topological order and critical path

Every complex operation—alert delivery, evidence publication, calibration, model activation,
release qualification—is represented as an obligation DAG. Critical-path analysis identifies:

- which step controls latency;
- where parallelism is safe;
- which cancellation obligations remain;
- whether a reported deadline is even feasible;
- which proof lane blocks a release root.

Observed step durations are intervals/distributions, not eternal constants. Scheduling adaptation
may improve parallelism but cannot reorder semantic dependencies.

### 5.12 Centrality, PageRank, HITS, and personalized PageRank

These are attention tools, never authority. Examples:

- prioritize evidence nodes influential to many current hypotheses;
- rank sensors whose degradation affects many zones;
- retrieve memories near a current event;
- identify operational hubs requiring resilience review.

Centrality can be self-reinforcing and biased by graph construction. Every score names the
projection and normalization; it is not called “importance” without qualification.

### 5.13 Community, motif, triadic census, and routine structure

Community and motif analysis can find repeated household/animal/vehicle routines, co-failure
clusters, and recurring event subgraphs. They generate candidates for memory curation or hard-
negative datasets. They do not autonomously whitelist behavior.

A “known routine” remains an evidence-linked probabilistic pattern with scope, recency, confidence,
and invalidators. A novel deviation can increase inspection priority but cannot become a threat
fact by graph anomaly alone.

### 5.14 Link prediction

Link prediction proposes missing association, causal, or memory edges. It is explicitly
non-authoritative. Suggested edges enter a verifier that checks source evidence, temporal/geometry
constraints, capability visibility, and contradiction.

### 5.15 Isomorphism and subgraph matching

VF2/VF2++-class methods and canonical fingerprints can compare:

- event/evidence structures to known incidents;
- route/trajectory shapes independent of exact coordinates;
- scene graphs after calibration changes;
- adapter state-machine traces against qualified normal forms;
- attack/failure motifs in red-team corpora.

Because subgraph isomorphism can explode exponentially, every call has size, degree, label, and time
budgets. Failure to finish is `Unknown`, not “no match.”

### 5.16 k-core, k-truss, and robust support

Core/truss decompositions identify subgraphs supported by multiple mutually reinforcing links.
FSS can use them to distinguish:

- a track identity supported by several consistent observations from one fragile edge;
- a zone covered by multiple independent sensors from a superficial degree count;
- a memory cluster with corroborated evidence from a chain of copies.

Independence/failure-domain semantics remain necessary; dense correlated evidence is not
corroboration.

### 5.17 Spanning forests, Steiner approximations, and connected dominating sets

These support economical deployment:

- minimum infrastructure connecting required sensors/edge nodes;
- a small connected observer/control backbone;
- candidate relay placement;
- selecting survey waypoints for calibration.

A minimum spanning tree deliberately removes redundancy, so it is a cost baseline—not the final
security topology. Resilience constraints add extra edges or require k-connectivity.

### 5.18 Planarity and geometric consistency

Planarity and embedding checks help validate simplified property topology, but a real 3D property
is not globally planar. FSS uses these algorithms only on declared 2D layers such as a floor,
walkway map, or fence graph. A planar embedding cannot replace metric calibration.

### 5.19 Submodular sensor placement

Candidate camera placement is formulated as robust constrained set selection. Let `S` be selected
camera poses and `ω` an environment/failure scenario. A basic objective is:

```text
F(S) = E_ω [ Σ_target w(target) * U(P_detect(target | S, ω)) ]
       - installation_cost(S)
       - privacy_cost(S)
       - correlated_failure_penalty(S)
```

Subject to:

- budget/port/power/network constraints;
- privacy-exclusion constraints;
- minimum per-zone and per-route coverage;
- failure-domain diversity;
- mounting feasibility;
- bandwidth/compute/archive capacity;
- no forbidden field of view.

Where the utility is monotone submodular, lazy greedy provides a strong approximation baseline.
FSS also uses exchange/local-search and exact branch-and-bound on small candidate sets as an oracle.
For non-submodular occlusion/correlation terms, the plan reports the heuristic nature rather than
claiming a guarantee.

Robust variants optimize worst-case or lower-tail performance across weather, night, foliage,
vehicle occlusion, device failures, and adversarial route classes. Placement output includes
counterfactuals: what blind region or cut remains if each selected camera fails?

## 6. Cross-camera association as a proof-carrying graph problem

The association pipeline is:

1. Pin tracklets, time intervals, calibration, and model generations.
2. Generate candidate edges using cheap temporal/spatial gates.
3. Add exact evidence components and contradiction edges.
4. Build a time-expanded capacity graph.
5. Solve deterministic min-cost flow/matching.
6. Compute near-optimal alternatives and assignment margin.
7. Validate against simultaneous-visibility and route constraints.
8. Publish an association hypothesis revision and witness.

The result records:

- selected tracklet sequence;
- transition witnesses;
- cost decomposition;
- alternative assignments within policy margin;
- unobserved intervals and routes;
- model/geometry/time uncertainty;
- evidence that would most reduce ambiguity.

It never emits a permanent biometric identity by default.

## 7. Sensor-mesh resilience analysis

For every qualified deployment, FSS produces a resilience certificate containing:

- connected components by operational regime;
- articulation sensors/links and bridges;
- zone-pair min cuts and Gomory–Hu summary where applicable;
- dominators for each critical zone/effect/archive objective;
- effective resistance/algebraic connectivity trends;
- one- and two-failure scenario coverage loss;
- correlated failure-domain cuts;
- unreachable/blind cells with coverage-certification status;
- proposed placements ranked by marginal robust gain;
- operation counts and projection digest.

The certificate expires on camera movement, firmware/stream profile change, significant foliage or
scene change, clock/calibration invalidation, network topology change, or policy epoch change.

## 8. Incremental graph maintenance

Observation capsules form the one ordered update stream. Each graph projector:

1. consumes capsules from a named high-water mark;
2. applies changes to an unpublished generation;
3. maintains incremental deltas/Z-set-like signed changes where useful;
4. runs consistency checks and selected full-rebuild comparisons;
5. publishes the new root last;
6. retains the old root for pinned readers;
7. emits a projection certificate.

Hot tiny adjacency can remain inline; recent mutable deltas use bounded sorted blocks; cold stable
adjacency uses sealed compressed runs. Representation is temperature-driven, but semantics remain
identical. A graph database is admitted only where measured workloads justify it; simple ordered
maps remain the reference.

## 9. Factorization and query execution

Queries such as “which entrances have a feasible unobserved route to the house under any two-sensor
failure while remaining temporally compatible with event E?” can explode if every intermediate
path/scenario is materialized. The query layer therefore preserves factorized sets and uses
worst-case-aware joins where applicable.

Rules:

- capabilities filter nodes/edges before expansion;
- intermediate cardinality budgets are explicit;
- factorized answers retain provenance and can be lazily enumerated;
- exact absence requires complete expansion or a mathematical certificate;
- approximate candidate generation is followed by exact verification;
- query plans and tie-breaks are fingerprinted;
- incremental standing queries update from the capsule stream rather than full rescans.

## 10. Capability noninterference

A principal authorized for one zone or camera must not infer hidden topology through:

- node degree;
- result counts;
- reachability;
- shortest-path length;
- cut size;
- absence witnesses;
- centrality;
- timing side channels.

Authorization creates an induced, policy-defined projection before algorithm execution. The witness
names that projection. Cache keys include principal/capability facts and anchor. Global graph
results are never computed and then redacted after the fact when that would leak structure.

## 11. Strict and hardened graph modes

### Strict mode

Used for canonical qualification and safety-relevant decisions. It rejects:

- unknown node/edge types;
- missing required weights;
- NaN/infinite values outside policy;
- stale or mixed anchors;
- malformed temporal intervals;
- noncanonical duplicate identities;
- unsupported graph sizes/algorithm modes;
- uncertain recovery.

### Hardened mode

Used for diagnostics and hostile imported data. It may, under bounded registered rules:

- skip a malformed optional attribute;
- quarantine an invalid component;
- clamp a diagnostic-only value;
- fall back from optimized to reference algorithm;
- truncate an advisory enumeration with continuation.

Every recovery emits a `DecisionRecord`; hardened output cannot silently enter a strict policy path.

## 12. Differential and adversarial qualification

Each algorithm family has:

- small exact fixtures;
- differential tests against native FrankenNetworkX/reference implementations;
- insertion-order and tie-break fixtures;
- graph isomorphism/metamorphic relations;
- dynamic-update versus full-rebuild equivalence;
- cancellation at registered checkpoints;
- malformed and adversarial graph families;
- complexity-witness ceilings;
- numeric edge cases;
- capability noninterference tests;
- snapshot invalidation tests;
- cross-platform deterministic digest checks.

Adversarial families include paths, stars, cliques, grids, lollipops, barbell graphs, dense
bipartite graphs, near-disconnected spectral graphs, multigraph parallel-edge storms, temporal
interval ambiguity, and exponential subgraph-matching cases.

## 13. Performance and adaptive policy

Adaptive policy may choose:

- whether to refine a coarse witness;
- exact versus registered approximate candidate generator;
- batch size;
- parallel decomposition;
- hot/cold representation;
- update versus rebuild;
- which advisory analytics to compute.

It may not change:

- projection/anchor;
- tie-break policy;
- soundness direction;
- absence-certificate requirement;
- capability scope;
- numeric overflow policy;
- effect authority.

Every adaptive decision has priors, clamps, minimum sample counts, reset semantics, and a safe
baseline. Missing or contradictory telemetry selects the safe/reference path.

## 14. Admission sequence

1. Define typed graph identities, projections, anchors, and witness schema.
2. Implement ordered-map reference graphs and canonical iteration.
3. Add BFS/DFS, components, shortest paths, DAG/SCC, and exact matching/flow references.
4. Add complexity and decision-path witnesses.
5. Build dynamic-update/full-rebuild and capability noninterference gauntlets.
6. Integrate native FrankenNetworkX algorithms behind equivalent contracts.
7. Add physical, sensor-dependency, evidence, and effect graph projections.
8. Add time-expanded association and alternative-assignment analysis.
9. Add cuts/dominators/resistance/spectral resilience certificates.
10. Add robust placement and exact small-instance oracle.
11. Admit FrankenGraphDB incremental/factorized storage only after workload receipts show benefit.
12. Add graph-aware retrieval/memory after canonical graph semantics are stable.

## 15. What this doctrine rejects

- one mutable global graph;
- “latest” graph reads that mix generations;
- hash-order tie breaks;
- a centrality score called threat probability;
- link prediction presented as identity;
- degree count presented as independent corroboration;
- approximate no-path/no-match claims;
- cloning the entire graph per agent or query;
- graph storage in the live effect path before reference semantics;
- Python/NetworkX/PyO3 in production;
- an optimization without a complexity witness and semantic digest;
- camera-placement claims based only on geometric field-of-view area;
- a pretty digital-twin graph without held-out visibility validation.

Graph theory earns its place in FSS by making blind spots, ambiguity, causality, resilience, and
resource tradeoffs more explicit and more verifiable—not by making the architecture sound more
sophisticated.
