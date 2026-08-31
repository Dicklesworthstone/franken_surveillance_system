# Certified graph intelligence architecture

**Document class:** normative graph design
**Revision:** 1
**Date:** 2026-08-31
**Machine registry:** [`../architecture/graph_algorithms.json`](../architecture/graph_algorithms.json)

## 1. Graphs are operational, not decorative

FSS contains several different graphs whose algorithms directly affect observability, association, investigation, resilience, and cost. Putting data in a graph database is not the insight. The insight is to define exact projections, snapshot semantics, deterministic choices, complexity bounds, and proof/witness artifacts for each decision.

## 2. Projection families

### Sensor topology graph

Nodes: cameras, microphones, drones, network links, power sources, gateways, archive endpoints.
Edges: connectivity, shared failure domain, power dependency, bandwidth route, credential/account dependency.

### Spatial visibility graph

Nodes: cameras, poses, zones, surfaces, portals, occluders, coverage cells.
Edges: sees, overlaps, can-transition, occludes, bounded-by, adjacent-to.

### Track and association graph

Nodes: detections, tracklets, tracks, appearance/pose observations, event candidates.
Edges: temporal continuation, cross-camera candidate, mutual exclusion, corroboration, contradiction.

### Event/evidence causal graph

Nodes: source capsules, observations, hypotheses, events, policy decisions, alerts, operator outcomes.
Edges: supports, contradicts, derived-from, caused-by, supersedes, verified-by.

### Object/custody graph

Nodes: media chunks, manifests, archive roots, repair symbols, replicas, deletion tombstones.
Edges: contains, repairs, replicates, supersedes, reachable-from.

### Runtime/obligation graph

Nodes: regions, tasks, waits, leases, permits, transfers, external effects.
Edges: owns, waits-for, blocks, must-drain-before.

Each projection has an ID, source high-water mark, authority scope, schema epoch, directedness/multiedge/weight semantics, and stale-result policy.

## 3. Storage tiers

- tiny hot adjacency inline with the entity projection;
- recent mutable deltas in bounded sorted blocks;
- cold stable adjacency in sealed compressed runs;
- immutable historical generations retained by policy;
- specialized columnar relations for common joins;
- factorized representations where path expansion would explode.

No one representation is required to serve all degree distributions and workloads. Optimized storage sits behind a reference ordered-map graph oracle.

## 4. Stable identities and views

External identities are stable and never recycled. Internal handles are generational so stale references fail. Algorithms operate over immutable `Arc`-shared snapshot views; cloning a view is O(1), not a deep graph copy.

A view pins its backing generation. Any live iterator that promises fail-fast mutation behavior carries a revision and returns the registered invalidation error. An exported numeric view freezes/version-pins its storage; growable backing allocations cannot be exposed.

## 5. Canonical graph semantics

Every algorithm declares:

```text
algorithm_id
projection_id
anchor
directedness_and_multiedge_policy
weight_and_numeric_policy
tie_break_policy
output_order
complexity_bound
resource_budget
stale_result_policy
reference_implementation
```

Equal-cost/equal-score answers are operationally meaningful. Tie-breaking can use stable insertion sequence, external identity, edge identity, or an explicit lexicographic key. Hash iteration is never a policy.

Every planning-relevant run emits a `GraphAlgorithmWitness` containing `n`, `m`, observed operation counts, budget, selected decision path, output digest, and generation identities.

## 6. Algorithm families

### Dynamic connectivity and reachability

Use for current zone reachability, network partition detection, archive route availability, and whether an approaching subject can move from one observed portal to another.

### Articulation points, bridges, dominators, cuts

Identify camera/network/power single points of failure; zones whose observation depends on one sensor; portals dominating all approach paths; minimal sensor sets whose loss creates a blind corridor.

### Shortest, k-shortest, and temporal paths

Generate physically plausible cross-camera transition hypotheses, alternate routes, and incident reconstructions. Temporal paths use interval travel bounds and reject impossible ordering.

### Bipartite matching, min-cost flow, and k-best assignments

Associate tracklets across cameras while respecting mutual exclusion, travel time, appearance, pose, and uncertainty. Retain k-best/Murty-style alternatives when ambiguity matters instead of collapsing immediately to one identity.

### Max-flow/min-cut and Gomory-Hu structures

Quantify observation redundancy, network/archive capacity, and minimal cuts. Gomory-Hu-style all-pairs cut summaries can support rapid “what failures separate this zone?” queries on stable undirected projections.

### SCCs, cycles, condensation DAGs, and topological order

Detect dependency loops in jobs/effects/replication, reason about strongly coupled failure domains, and schedule plan DAGs.

### Spanning forests and Steiner-like design

Propose low-cost connectivity/coverage infrastructure while preserving explicit approximation bounds. A recommendation never becomes installation truth without geometry and site constraints.

### Facility location, set cover, and submodular selection

Choose camera placements, active observations, thumbnails, model invocations, or evidence items that maximize marginal coverage/information under cost. Greedy/submodular methods emit approximation and stopping witnesses.

### PPR, centrality, communities, and attention

Rank evidence or sensors for investigation. These are advisory and can never authorize an effect. Centrality results are especially sensitive to projection and normalization and must state both.

### d-separation and causal graph queries

Test whether purported independent evidence shares a modeled causal path, whether a confounder can explain corroboration, and which observations could resolve ambiguity. The graph is a declared model, not proof of real-world causality.

### Graph hashing/isomorphism

Detect repeated topology/configuration shapes, cache specialized kernels, and compare deployment structures. Hash collision or heuristic isomorphism cannot establish identity without verification.

### Hypergraph/factor graph reasoning

Some evidence relations involve many participants: one archive root contains many chunks; one calibration factor connects many poses; one policy rule covers many zones. FSS preserves such factorization rather than exploding every relation into pairwise edges when that changes cost or semantics.

## 7. Incremental standing predicates

Important predicates update from `EvidenceDeltaBatch` rather than full scans:

- active tracks per zone;
- plausible cross-camera continuation edges;
- uncovered/undercovered cells;
- sensor failure cuts;
- archive objects below replication/retrievability policy;
- event hypotheses with new contradiction/support;
- unresolved obligations and wait cycles;
- privacy deletion reachability.

Incremental results are periodically checked against full reference recomputation.

## 8. Authorization before expansion

Capability scope is compiled into the projection before traversal. An agent authorized for one site/zone cannot infer hidden nodes through degree, counts, path existence, cut size, or absence. The witness names the authorized projection root.

## 9. Factorized query execution

Queries such as “all plausible routes from any perimeter detection to any door supported by any camera overlap” can create enormous intermediates. The planner uses worst-case-aware join ordering and factorized sets; it materializes only when the output contract requires it. Every optimization has a simple relational/graph reference oracle.

## 10. Adversarial graph corpus

Qualification includes:

- empty/singleton/disconnected graphs;
- paths, cycles, stars, grids, cliques, lollipops, barbells;
- power-law hubs and high parallel-edge multiplicity;
- equal-weight diamonds and massive tie sets;
- zero/negative/overflow/NaN weights as allowed by policy;
- temporal interval boundary cases;
- dense bipartite ambiguous matching;
- graph mutation/invalidation schedules;
- capability boundary and side-channel fixtures;
- malformed serialized graphs and repair damage;
- incremental retraction storms;
- factorized-query worst cases.

## 11. Forge-style specialization

Frequently executed projections with stable schema/shape may compile to generated, monomorphic Rust kernels. The generator input, source output, toolchain, and reference digest are deterministic. Generated code remains safe Rust and is never produced at runtime. Specialization is selected only inside its proven shape region and compared against the generic oracle.

## 12. Admission rule

No graph algorithm enters a decision path until:

- semantics and tie-breaks are registered;
- differential tests pass against the reference/oracle;
- adversarial families and budget cancellation pass;
- snapshot/view invalidation is correct;
- complexity witnesses are stable and within registered bounds;
- capability noninterference passes;
- incremental/full equivalence passes where applicable;
- output serialization and repair round-trip;
- performance benefit is demonstrated before replacing the simple path.
