# FSS graph algorithm atlas

**Status:** normative algorithm-selection plan
**Revision:** 1
**Date:** 2026-08-31

FSS is graph-shaped in several distinct senses: sensors cover zones; observations support claims; tracks move through space-time; devices and archives fail together; plans contain obligations; identities branch and merge; privacy and authority restrict traversal. The graph layer is a derived projection over a pinned authority anchor. It is never the sole source of truth.

## 1. Graph projections

FSS does not expose one universal graph. Each projection has explicit node/edge types, anchor, authorization, update policy, and numeric semantics.

| Projection | Nodes | Edges |
|---|---|---|
| `SensorCoverageGraph` | sensors, frusta, zones, occluders | observes, overlaps, occludes, depends-on |
| `SpatioTemporalTrackGraph` | detections, tracklets, tracks, zones, time buckets | follows, may-correspond, can-reach, conflicts |
| `EvidenceClaimGraph` | source ranges, observations, model results, witnesses, claims | supports, contradicts, derived-from, invalidates |
| `IncidentCausalGraph` | events, conditions, effects, outcomes | precedes, enables, blocks, caused-by |
| `DeviceFailureGraph` | devices, gateways, power/network/clock domains | depends-on, shares-failure-domain |
| `ArchiveObjectGraph` | roots, manifests, objects, repair groups, replicas | contains, protects, replicated-at, held-by |
| `AuthorityGraph` | principals, capabilities, sites, zones, resources | grants, narrows, imports, denies |
| `PlanObligationGraph` | plan steps, leases, effects, verification predicates | depends-on, conflicts, compensates |
| `OperationalMemoryGraph` | memories, evidence spans, rules, anti-patterns | supported-by, supersedes, contradicted-by |
| `DigitalTwinGraph` | poses, landmarks, surfaces, zones, portals | adjacent, visible-from, occludes, aligned-with |

## 2. Determinism contract

Every execution declares:

- `algorithm_id` and implementation version;
- projection/root and `EvidenceAnchor`;
- directedness, multiedge, self-loop, attribute, and missing-value semantics;
- numeric type, tolerance, overflow, NaN, infinity, and negative-weight policy;
- CGSE-style tie-break policy;
- output ordering;
- resource budget and cancellation checkpoints;
- exact/approximate/advisory classification;
- stale-result and partial-result policy.

A mathematically valid but differently ordered answer is a behavioral change if it can steer an agent or effect plan differently.

## 3. Complexity witness

Every planning-relevant execution emits:

```text
GraphAlgorithmWitness {
  schema,
  algorithm_id,
  implementation_id,
  projection_id,
  anchor,
  node_count,
  edge_count,
  input_digest,
  policy_id,
  dominant_operation_counts,
  peak_working_bytes,
  budget_consumed,
  exactness,
  error_bound,
  stop_reason,
  decision_path_digest,
  output_digest
}
```

Dominant counts are algorithm-specific: heap operations, relaxations, union/find operations, residual-edge scans, augmentations, join probes, matrix-vector products, or branch-and-bound nodes. They make accidental complexity regressions testable.

## 4. Core algorithms

### `ALG-DYNCONN-001` — dynamic connectivity

**Decision:** whether required observability, network, evidence, or obligation components remain connected as sensors/gateways/objects appear and disappear.

**Projection:** coverage, failure, archive, or plan graph.
**Exactness:** exact within pinned projection.
**Updates:** edge insert/delete batches from observation capsules.
**Candidate methods:** union-find for insertion epochs; offline rollback/segment-tree; dynamic forest structures only after proof.
**Safety role:** identifies disconnected or unobservable domains; never infers safety from connectivity alone.

### `ALG-BRIDGE-001` — articulation points and bridges

**Decision:** single points of failure in sensing, network, power, archive, and evidence support.

A camera can be an articulation point in a coverage graph; a gateway in a device graph; a source segment in a claim graph. Results include the separated components and affected zone/time/value, not only IDs.

### `ALG-SCC-001` — strongly connected components and condensation

**Decision:** collapse cycles in retry/effect, identity-hypothesis, dataflow, and obligation graphs. The condensation DAG becomes the safe planning substrate.

Cycles are not automatically bugs: reciprocal identity evidence may be legitimate. The algorithm classifies cycle type and checks registered invariants.

### `ALG-TOPO-001` — topological order and critical path

**Decision:** executable order, parallel frontier, and latency-controlling obligations for incident verification, archive publication, calibration, shutdown, repair, and release.

Tie order is stable by plan-step identity. The witness records earliest/latest times and slack under the declared cost model.

### `ALG-DOM-001` — dominators and post-dominators

**Decision:** identify a sensor, gateway, evidence object, verifier, or plan step that lies on every path from source to claim or from prepare to completion.

A claim dominated by one failure domain is less robust than one supported through independent paths. Dominator results feed corroboration explanations and resilience planning.

### `ALG-SP-001` — shortest path

**Decision:** minimum-cost plausible movement, data route, repair path, or plan route.

Weights are typed: physical time interval, negative-log likelihood, bytes, latency, monetary cost, energy, or risk cannot be mixed without an explicit composite policy.

### `ALG-KSP-001` — k-shortest/simple alternative paths

**Decision:** maintain alternative cross-camera trajectories and network/archive routes rather than overcommitting to one explanation.

Diversity constraints prevent near-duplicate paths from wasting verifier/model budget.

### `ALG-TREACH-001` — temporal reachability

**Decision:** whether a track/entity could move between observations under uncertain capture intervals, geometry, speed priors, portals, and occlusion.

Edges carry valid time intervals and travel-time bounds. A path is valid only if temporal constraints compose. The result returns feasible interval sets and invalidation reasons.

### `ALG-MSD-001` — multi-source distance

**Decision:** nearest effective sensor/verifier/archive replica/refuge of observability from many sources. Used for active perception and resilience.

### `ALG-FLOW-001` — max flow / min cut

**Decision:** sensing/network/processing capacity and the minimum failure set that breaks a required service.

Capacities are typed and may be intervals. Approximate capacities cannot produce an exact safety claim.

### `ALG-GH-001` — Gomory-Hu tree

**Decision:** summarize all-pairs minimum cuts in undirected resilience projections. Useful for camera/gateway/network placement and identifying weakly connected zone pairs.

### `ALG-MCF-001` — min-cost flow

**Decision:** allocate bounded GPU/model/network/archive capacity to candidate windows while satisfying urgency/coverage constraints at minimum cost.

The exact solver remains off the packet path; fast heuristics produce candidates verified against constraints.

### `ALG-MATCH-001` — bipartite/weighted matching

**Decision:** cross-camera detection association, task-to-worker placement, observation-to-landmark matching, and device-to-zone assignment.

Weights combine calibrated components with a versioned policy. Forbidden pairs are absent, not merely high-cost. Ties use stable entity IDs and source order.

### `ALG-MULTIMATCH-001` — multi-hypothesis assignment

**Decision:** retain several globally coherent association hypotheses when local pairwise matching is ambiguous. Candidate methods include Murty-style k-best assignments and factor-graph search under strict budgets.

### `ALG-SETCOVER-001` — set cover

**Decision:** minimum camera/frame/evidence subset that covers a zone, time interval, claim support set, or review task.

Greedy approximations carry ratio/error class and cannot certify a true minimum. For small incident graphs, exact branch-and-bound provides an oracle.

### `ALG-SUBMOD-001` — submodular selection

**Decision:** choose the next camera, PTZ pose, drone observation, frame window, or verifier call that maximizes expected uncertainty reduction under cost/risk budget.

The objective and monotonicity/submodularity assumptions are explicit. Violations fall back to a conservative heuristic.

### `ALG-MST-001` — spanning forest

**Decision:** low-cost network/sensor/replica layout connecting required components; also baseline topology for incremental reasoning.

### `ALG-STEINER-001` — Steiner approximation

**Decision:** connect required zones/sensors/gateways using optional intermediate nodes at lower cost than a terminal-only tree.

Approximation status is explicit and used for planning, not authoritative event truth.

### `ALG-PPR-001` — personalized PageRank

**Decision:** rank nearby evidence, entities, failures, and memories from an incident seed while damping hub domination.

Advisory only. Capability projection is applied before walk construction.

### `ALG-HITS-001` — HITS

**Decision:** distinguish hub-like sensors/aggregators from authority-like evidence or runbook nodes. Advisory and explanation-oriented.

### `ALG-CENTRAL-001` — betweenness/closeness/harmonic centrality

**Decision:** maintenance and attention prioritization, not effect authorization. Exact/approximate variants have separate IDs and error policies.

### `ALG-COMM-001` — community detection

**Decision:** group recurrent event episodes, correlated failure domains, traffic patterns, or identity hypotheses. Communities are hypotheses with stability scores, not identities.

### `ALG-SPECTRAL-001` — spectral graph change/anomaly

**Decision:** detect topology or transition-distribution changes that may indicate camera movement, environment change, tampering, or behavior shift.

Outputs schedule inspection/recalibration; they do not declare an intrusion.

### `ALG-ALIGN-001` — graph/landmark alignment

**Decision:** align reconstructed digital twins, floor/site maps, camera landmark graphs, and prior geometry generations. Uses typed correspondences, outlier rejection, and transform uncertainty.

### `ALG-BICONN-001` — biconnected components

**Decision:** identify portions of coverage/network graphs with redundant paths and isolate weak articulation boundaries.

### `ALG-CUTTREE-001` — cut hierarchy

**Decision:** produce a multiscale decomposition of site observability/resilience for placement planning and explanation.

### `ALG-CYCLE-001` — cycle basis and feedback-set approximation

**Decision:** explain retry/obligation/control cycles and propose edges or vertices whose removal makes a plan acyclic. Any mutation remains a separately reviewed plan.

### `ALG-CAUSALPATH-001` — constrained causal path

**Decision:** retrieve evidence paths that support or contradict an event while respecting temporal order, provenance class, and independence constraints.

### `ALG-FACTOR-001` — factorized multiway join

**Decision:** answer pattern queries without materializing combinatorial intermediate paths. Used for incident explanations and multi-sensor correlation.

### `ALG-ZSET-001` — incremental Z-set maintenance

**Decision:** update standing graph relations from signed capsule deltas and produce exactly the same result as full recomputation at a high-water mark.

### `ALG-SKYLINE-001` — Pareto skyline

**Decision:** present non-dominated camera placements, verifier plans, archive policies, or event hypotheses across cost, latency, coverage, privacy, and risk rather than hiding tradeoffs in one scalar.

### `ALG-MINCOST-CORR-001` — minimum-cost corroboration

**Decision:** find the cheapest set of independent evidence paths satisfying a policy’s corroboration constraints. This is a registered constrained optimization problem, not “two models agree.”

## 5. Cross-camera association graph

Nodes are tracklets with time intervals, appearance/motion features, zones, and source failure domains. Candidate edges exist only when:

- temporal reachability is feasible;
- geometry/portal constraints permit movement;
- identity policy allows comparison;
- feature-space generations are compatible;
- source health meets the minimum;
- the edge probability/error bound passes candidate threshold.

The solver retains multiple hypotheses and emits conflict/exclusion reasons. An embedding nearest neighbor alone never creates an identity.

## 6. Coverage and observability graph

Coverage is a hypergraph: one sensor observation covers a set of spatial cells over time under pose, occlusion, image quality, and detector qualification. FSS may use a bipartite expansion for algorithms but records the transformation.

Key outputs:

- uncovered and weakly covered cells;
- minimum sensor cuts;
- articulation sensors;
- redundancy by independent failure domain;
- expected view diversity;
- active perception candidates;
- coverage witness roots for negative claims.

## 7. Evidence independence graph

Corroboration requires distinct failure domains. Nodes/edges encode shared sensor, clock, model family, preprocessing, training data, network path, power, and human annotation. A policy may require evidence paths whose lowest common shared ancestor is above a declared independence threshold.

Two models on the same frames with the same backbone are not automatically independent.

## 8. Snapshot and zero-copy rules

Algorithms operate over immutable views pinned to a projection generation and authority anchor. Cloning a view shares storage. Mutation publishes a new generation. Iterators either remain snapshot-coherent or explicitly fail-fast on revision; “live but silently changing” is forbidden.

## 9. Resource and adversarial bounds

Every algorithm family declares worst-case complexity and hard caps. Inputs from vendor metadata, OCR, model output, or agent query are attacker-controlled. Bounded expansion, cancellation checkpoints, depth/width limits, and partial-result semantics are mandatory.

## 10. Differential qualification

For each algorithm:

- small exhaustive oracle;
- pinned FrankenNetworkX/NetworkX reference where applicable;
- adversarial families (paths, stars, cliques, grids, lollipops, dense bipartite, multigraphs, negative weights, temporal traps);
- permutation/tie-order metamorphic tests;
- snapshot invalidation;
- budget cancellation;
- complexity witness thresholds;
- incremental/full equivalence where applicable;
- architecture-specific safe-SIMD equivalence.

## 11. Admission rule

No algorithm enters an authoritative decision because it exists in a sibling crate. It must have an FSS projection contract, exactness class, tie policy, numeric policy, oracle, fault/resource campaign, and decision-specific gate.
