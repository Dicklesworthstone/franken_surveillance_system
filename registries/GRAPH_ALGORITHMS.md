# Graph algorithm registry

Machine source: `architecture/graph_algorithms.json`. Full motivation, numeric policy, and failure semantics live in [`docs/GRAPH_ALGORITHM_ATLAS.md`](../docs/GRAPH_ALGORITHM_ATLAS.md). All outputs are derived, anchor-pinned, capability-filtered, deterministically ordered, and witness-carrying.

| ID | Algorithm | Projections | Exactness class | Admission gate |
|---|---|---|---|---|
| `ALG-DYNCONN-001` | `dynamic_connectivity` | `SensorCoverageGraph`, `DeviceFailureGraph`, `ArchiveObjectGraph`, `PlanObligationGraph` | `exact` | `INT-FNX-001` |
| `ALG-BRIDGE-001` | `articulation_points_and_bridges` | `SensorCoverageGraph`, `DeviceFailureGraph`, `EvidenceClaimGraph` | `exact` | `INT-FNX-001` |
| `ALG-SCC-001` | `strongly_connected_components` | `PlanObligationGraph`, `EvidenceClaimGraph`, `IncidentCausalGraph` | `exact` | `INT-FNX-001` |
| `ALG-TOPO-001` | `topological_order_and_critical_path` | `PlanObligationGraph`, `IncidentCausalGraph` | `exact` | `INT-FNX-001` |
| `ALG-DOM-001` | `dominators_and_postdominators` | `EvidenceClaimGraph`, `PlanObligationGraph`, `DeviceFailureGraph` | `exact` | `INT-FNX-001` |
| `ALG-SP-001` | `shortest_path` | `SpatioTemporalTrackGraph`, `DeviceFailureGraph`, `ArchiveObjectGraph` | `exact` | `INT-FNX-001` |
| `ALG-KSP-001` | `k_shortest_diverse_paths` | `SpatioTemporalTrackGraph`, `ArchiveObjectGraph` | `exact_or_bounded` | `INT-FNX-001` |
| `ALG-TREACH-001` | `temporal_reachability` | `SpatioTemporalTrackGraph`, `DigitalTwinGraph` | `exact` | `INT-FNX-001` |
| `ALG-MSD-001` | `multi_source_distance` | `SensorCoverageGraph`, `ArchiveObjectGraph` | `exact` | `INT-FNX-001` |
| `ALG-FLOW-001` | `max_flow_min_cut` | `DeviceFailureGraph`, `SensorCoverageGraph`, `PlanObligationGraph` | `exact` | `INT-FNX-001` |
| `ALG-GH-001` | `gomory_hu_tree` | `DeviceFailureGraph`, `SensorCoverageGraph` | `exact` | `INT-FNX-001` |
| `ALG-MCF-001` | `min_cost_flow` | `PlanObligationGraph`, `DeviceFailureGraph` | `exact_or_verified_candidate` | `INT-FNX-001` |
| `ALG-MATCH-001` | `weighted_bipartite_matching` | `SpatioTemporalTrackGraph`, `DigitalTwinGraph`, `PlanObligationGraph` | `exact` | `INT-FNX-001` |
| `ALG-MULTIMATCH-001` | `k_best_global_assignment` | `SpatioTemporalTrackGraph` | `bounded_exact` | `INT-FNX-001` |
| `ALG-SETCOVER-001` | `set_cover` | `SensorCoverageGraph`, `EvidenceClaimGraph` | `approximate_or_exact_small` | `INT-FNX-001` |
| `ALG-SUBMOD-001` | `submodular_selection` | `SensorCoverageGraph`, `EvidenceClaimGraph` | `approximate` | `INT-FNX-001` |
| `ALG-MST-001` | `minimum_spanning_forest` | `DeviceFailureGraph`, `SensorCoverageGraph`, `ArchiveObjectGraph` | `exact` | `INT-FNX-001` |
| `ALG-STEINER-001` | `steiner_tree_approximation` | `DeviceFailureGraph`, `SensorCoverageGraph` | `approximate` | `INT-FNX-001` |
| `ALG-PPR-001` | `personalized_pagerank` | `EvidenceClaimGraph`, `OperationalMemoryGraph` | `approximate_advisory` | `INT-FNX-001` |
| `ALG-HITS-001` | `hits` | `EvidenceClaimGraph`, `OperationalMemoryGraph` | `approximate_advisory` | `INT-FNX-001` |
| `ALG-CENTRAL-001` | `centrality_family` | `DeviceFailureGraph`, `SensorCoverageGraph`, `OperationalMemoryGraph` | `exact_or_approximate_advisory` | `INT-FNX-001` |
| `ALG-COMM-001` | `community_detection` | `IncidentCausalGraph`, `OperationalMemoryGraph` | `approximate_advisory` | `INT-FNX-001` |
| `ALG-SPECTRAL-001` | `spectral_change_detection` | `SpatioTemporalTrackGraph`, `DeviceFailureGraph` | `approximate_advisory` | `INT-FNX-001` |
| `ALG-INTERDICT-001` | `network_interdiction_and_robust_placement` | `SensorCoverageGraph`, `DeviceFailureGraph` | `bounded_exact_or_approximate` | `INT-FNX-001` |
| `ALG-RELIABILITY-001` | `reliability_bounds` | `DeviceFailureGraph`, `ArchiveObjectGraph` | `bounded_statistical` | `INT-FNX-001` |
| `ALG-FACTOR-001` | `factorized_free_join` | `EvidenceClaimGraph`, `SpatioTemporalTrackGraph` | `exact` | `INT-FNX-001` |
| `ALG-ZSET-001` | `zset_incremental_maintenance` | `SensorCoverageGraph`, `SpatioTemporalTrackGraph`, `EvidenceClaimGraph`, `IncidentCausalGraph`, `DeviceFailureGraph`, `ArchiveObjectGraph`, `AuthorityGraph`, `PlanObligationGraph`, `OperationalMemoryGraph`, `DigitalTwinGraph` | `exact` | `INT-FNX-001` |

## Implementation status

`ALG-BRIDGE-001` is implemented over the `SensorCoverageGraph` projection (iterative Tarjan,
certified against a brute-force removal oracle and metamorphic tests).

The weighted/directed families below are implemented (`status: implemented` in the machine
source, with implementation, tie-break, policy and complexity-bound identities and evidence) on
the canonical `WeightedGraph` substrate (`crates/fss-graph-algorithms/src/weighted.rs`: stable
identities, one declared weight unit bound into the digest, exact checked `u64` arithmetic) and
the shared certification machinery (`certified.rs`: fail-closed budgets, the registered bound
checked on every run and re-checkable from a stored witness, domain-separated output and
decision-path digests):

- `ALG-SCC-001`: iterative Tarjan + Kahn condensation order by smallest member; certified against mutual reachability.
- `ALG-TOPO-001`: Kahn min-heap order, frontiers, CPM schedule with node durations and arc lags, canonical critical path; certified against smallest-available selection + n-round relaxation.
- `ALG-DOM-001`: Cooper–Harvey–Kennedy dominators and post-dominators with dominated counts; certified against single-node removal.
- `ALG-SP-001`: lexicographic `(distance, hops)` Dijkstra, smallest tight parent arc; certified against Bellman–Ford.
- `ALG-MSD-001`: multi-source `(distance, source, hops)` Dijkstra; certified against per-source Bellman–Ford minimum.
- `ALG-FLOW-001`: certified Edmonds–Karp: arc cut (inclusion-minimal source side) or minimum-weight node failure set by node splitting; certified against source-side subset enumeration; failure-set enumeration.
- `ALG-MST-001`: Kruskal over the strict `(weight, edge index)` order, counted merge sort, union by size; certified against exhaustive spanning-forest enumeration.
- `ALG-GH-001`: Gusfield flow-equivalent tree over `n - 1` certified flow runs; certified against all-pairs subset cuts.
- `ALG-MCF-001`: successive shortest paths with potentials; certified optimal (no negative residual cycle); exact shortfall; certified against unit-step Bellman–Ford augmentation.
- `ALG-MATCH-001`: Hungarian (128-bit, self-certified by duality) with exact lexicographic tie-break over the tight subgraph; maximum-cardinality or priced non-assignment; certified against exhaustive assignment enumeration.
- `ALG-MULTIMATCH-001`: Murty best-first over `(objective, assignment tuple)` with lexicographically minimal subproblems; certified against exhaustive enumeration, first `k` in order.
- `ALG-KSP-001`: Yen with lexicographic spur searches, a minimum-distinct-arcs diversity filter, an explicit enumeration cap and a typed stop reason; certified against exhaustive loopless-path enumeration.
- `ALG-TREACH-001`: exact integer-interval least fixpoint (departure windows, travel bounds, per-node linger) with `reachable` / `temporally_infeasible` / `no_path`; certified against integer-time set fixpoint.
- `ALG-DYNCONN-001`: offline segment tree over edge lifetimes with rollback union-find; strict insert/delete batches; certified against per-state BFS recomputation.
- `ALG-RELIABILITY-001`: per-zone blindness probability bounds under independent interval-probability failure domains (outward 10^-18 fixed point) with minimal blinding domain sets; certified against a direct scenario sum over admissible probability vectors and exhaustive minimal cuts.
- `ALG-INTERDICT-001`: minimum-cost sensor set whose loss opens an unobserved entry-to-target walk (exact up to 20 relevant sensors; explicitly approximate upper bound beyond), or an existing blind path; robust placement not implemented; certified against brute-force subsets.

Each is certified on seeded directed and undirected graphs (random, DAG, cycle, clique, star,
path, layered, joined cycles, empty) or seeded assignment problems, insertion-order metamorphic
tests, budget-one-short refusals and tampered-witness refusals
(`crates/fss-graph-algorithms/tests/weighted_certification.rs`,
`crates/fss-graph-algorithms/tests/optimization_certification.rs`,
`crates/fss-graph-algorithms/tests/path_time_certification.rs`,
`crates/fss-graph-algorithms/tests/resilience_certification.rs`). The projections are caller-built:
no retained-record projection builder exists yet for `PlanObligationGraph`, `EvidenceClaimGraph`,
`IncidentCausalGraph`, `DeviceFailureGraph`, `SpatioTemporalTrackGraph` or `ArchiveObjectGraph`.
None is qualified: the `INT-FNX-001` differential and the atlas's snapshot-invalidation,
capability-noninterference and incremental/full lanes do not exist. Every other row is
`specified`.

## Registry drifts

- Algorithm: `ALG-ZSET-001`
  - Field: `projection`
  - Original snapshot: "All derived projections"
  - Reconciled value: 10 canonical projections (`SensorCoverageGraph`, `SpatioTemporalTrackGraph`, `EvidenceClaimGraph`, `IncidentCausalGraph`, `DeviceFailureGraph`, `ArchiveObjectGraph`, `AuthorityGraph`, `PlanObligationGraph`, `OperationalMemoryGraph`, `DigitalTwinGraph`)
  - Status: `reconciled_pending_owner_decision`
  - Reason: The 2026-08-31 snapshot informally declared 'All derived projections'. Reconciled to the 10 canonical projections pending owner decision on wildcard vs explicit enumeration.

