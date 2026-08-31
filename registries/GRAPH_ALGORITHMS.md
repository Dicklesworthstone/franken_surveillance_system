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
| `ALG-ZSET-001` | `zset_incremental_maintenance` | `All derived projections` | `exact` | `INT-FNX-001` |
