#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Complete 8-remaining-universe + 12-universe crosswalk contract, differential, fault,
//! incremental-vs-full equivalence, and `v1 -> v2` migration suite (`GRAPH-PROJECTION-SEMANTICS-001`,
//! `fss-x4a.23.69`):
//! - `G_phys`     (`PROJ-PHYSICAL-001`,  `fss-x4a.23.69.1`)
//! - `G_sensor`   (`PROJ-SENSOR-001`,    `fss-x4a.23.69.3`)
//! - `G_time`     (`PROJ-TIME-001`,      `fss-x4a.23.69.4`)
//! - `G_assoc`    (`PROJ-ASSOC-001`,     `fss-x4a.23.69.5`)
//! - `G_evidence` (`PROJ-EVIDENCE-001`,  `fss-x4a.23.69.6`)
//! - `G_object`   (`PROJ-OBJECT-001`,    `fss-x4a.23.69.8`)
//! - `G_memory`   (`PROJ-MEMORY-001`,    `fss-x4a.23.69.10`)
//! - `G_agent`    (`PROJ-AGENT-001`,     `fss-x4a.23.69.11`)
//! - Exhaustive 12-universe `CANONICAL_PROJECTION_CROSSWALK` verification (`fss-x4a.23.69`).

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{ContentDigest, Generation, LedgerAnchor, Plane, TimestampNs};
use fss_graph_algorithms::projection::{AbsenceBoundary, GraphUniverse, ProjectionAuthorityScope};
use fss_graph_algorithms::typed_universes::g_agent::{
    AgentControlEdge, AgentControlGraph, AgentControlNode, AgentEdgeKind, AgentGraphDelta,
    AgentNodeKind,
};
use fss_graph_algorithms::typed_universes::g_assoc::{
    AssocCandidateEdge, AssocComponentCosts, AssocDelta, TrackAssociationGraph, TrackletNodeSpec,
};
use fss_graph_algorithms::typed_universes::g_evidence::{
    CausalEvidenceGraph, EvidenceEdgeKind, EvidenceEffectOutcome, EvidenceGraphDelta,
    EvidenceGraphEdge, EvidenceGraphNode, EvidenceGraphNodeKind,
};
use fss_graph_algorithms::typed_universes::g_memory::{
    MemoryDelta, MemoryEdgeKind, MemoryEdgeSpec, MemoryNodeKind, MemoryNodeSpec,
    MemoryPromotionState, OperationalMemoryGraph,
};
use fss_graph_algorithms::typed_universes::g_object::{
    ArchiveObjectEdge, ArchiveObjectGraph, ArchiveObjectKind, ArchiveObjectNode,
    ObjectClosureVerdict, ObjectCustodyState, ObjectEdgeKind, ObjectGraphDelta,
};
use fss_graph_algorithms::typed_universes::g_phys::{
    PhysicalAccessState, PhysicalDelta, PhysicalEdgeSpec, PhysicalNodeKind, PhysicalNodeSpec,
    PhysicalTopologyGraph, TraversalBehaviorMode,
};
use fss_graph_algorithms::typed_universes::g_sensor::{
    FailureDomainCategory, SensorDelta, SensorDepEdge, SensorDepEdgeKind, SensorDependencyGraph,
    SensorInfraKind, SensorInfraNode,
};
use fss_graph_algorithms::typed_universes::g_time::{
    TimeDelta, TimeExpandedNodeSpec, TimeExpandedTransitGraph, TimeFeasibilityVerdict,
    TimeNodeObservability, TimeTransitEdgeSpec,
};
use fss_graph_algorithms::typed_universes::g_world::{
    WorldHypothesisDisposition, WorldKnowledgeState, WorldProvenanceClass,
};
use fss_graph_algorithms::typed_universes::{
    CANONICAL_PROJECTION_CROSSWALK, CURRENT_UNIVERSE_WIRE_VERSION, LEGACY_UNIVERSE_WIRE_VERSION,
    TypedUniverseError, TypedUniverseGuidance,
};

type TestResult = Result<(), Box<dyn Error>>;

fn anchor(seq: u64) -> LedgerAnchor {
    LedgerAnchor {
        site_lineage: "site-alpha".to_owned(),
        ledger_epoch: 1,
        commit_sequence: seq,
        adapter_registry_epoch: 1,
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        state_root: ContentDigest::sha256(&seq.to_be_bytes()),
    }
}

fn full_scope(universe: GraphUniverse) -> ProjectionAuthorityScope {
    ProjectionAuthorityScope::active_for(universe, 1, 1)
}

fn complete_absence() -> AbsenceBoundary {
    AbsenceBoundary::CertifiedComplete {
        coverage_witness_digest: ContentDigest::sha256(b"cov-witness:complete-v1"),
    }
}

fn patch_wire_version(bytes: &[u8], bad_version: u32) -> Vec<u8> {
    let mut patched = bytes.to_vec();
    patched[8..12].copy_from_slice(&bad_version.to_be_bytes());
    patched
}

#[test]
fn proj_physical_001_parallel_stealth_edges_crosswalk_deltas_and_migration() -> TestResult {
    let scope = full_scope(GraphUniverse::GPhys);
    let nodes = vec![
        PhysicalNodeSpec {
            node_id: "yard:north".to_owned(),
            kind: PhysicalNodeKind::Yard,
            survey_generation: Generation(2),
            survey_valid_until_ns: TimestampNs(50_000),
            plane: Plane::Cognition,
        },
        PhysicalNodeSpec {
            node_id: "fence:side".to_owned(),
            kind: PhysicalNodeKind::Fence,
            survey_generation: Generation(2),
            survey_valid_until_ns: TimestampNs(50_000),
            plane: Plane::Cognition,
        },
        PhysicalNodeSpec {
            node_id: "door:back".to_owned(),
            kind: PhysicalNodeKind::Door,
            survey_generation: Generation(2),
            survey_valid_until_ns: TimestampNs(50_000),
            plane: Plane::Cognition,
        },
        PhysicalNodeSpec {
            node_id: "landmark:stale-shed".to_owned(),
            kind: PhysicalNodeKind::SurveyedLandmark,
            survey_generation: Generation(1),
            survey_valid_until_ns: TimestampNs(5_000),
            plane: Plane::Cognition,
        },
    ];
    let edges = vec![
        // Open high-visibility walk directly to door
        PhysicalEdgeSpec {
            edge_id: "e:walk-open".to_owned(),
            source_id: "yard:north".to_owned(),
            target_id: "door:back".to_owned(),
            mode: TraversalBehaviorMode::OrdinaryWalk,
            width_cm: 120,
            slope_permille: 0,
            visibility_bps: 9_200,
            access_state: PhysicalAccessState::Open,
            min_transit_ms: 4_000,
            max_transit_ms: 6_000,
            uncertainty_ms: 500,
            survey_generation: Generation(2),
            valid_until_ns: TimestampNs(50_000),
        },
        // Parallel stealth crawl under hedge between the SAME endpoints (low visibility!)
        PhysicalEdgeSpec {
            edge_id: "e:crawl-stealth".to_owned(),
            source_id: "yard:north".to_owned(),
            target_id: "door:back".to_owned(),
            mode: TraversalBehaviorMode::CrawlUnderObstacle,
            width_cm: 65,
            slope_permille: -30,
            visibility_bps: 800,
            access_state: PhysicalAccessState::Open,
            min_transit_ms: 11_000,
            max_transit_ms: 16_000,
            uncertainty_ms: 2_000,
            survey_generation: Generation(2),
            valid_until_ns: TimestampNs(50_000),
        },
        // Closed door edge (must not be used as open walk)
        PhysicalEdgeSpec {
            edge_id: "e:door-locked".to_owned(),
            source_id: "yard:north".to_owned(),
            target_id: "fence:side".to_owned(),
            mode: TraversalBehaviorMode::DoorClosed,
            width_cm: 90,
            slope_permille: 0,
            visibility_bps: 5_000,
            access_state: PhysicalAccessState::LockedOrClosed,
            min_transit_ms: 2_000,
            max_transit_ms: 3_000,
            uncertainty_ms: 300,
            survey_generation: Generation(2),
            valid_until_ns: TimestampNs(50_000),
        },
        // Stale survey edge (expired at now_ns = 10_000)
        PhysicalEdgeSpec {
            edge_id: "e:stale-shortcut".to_owned(),
            source_id: "yard:north".to_owned(),
            target_id: "landmark:stale-shed".to_owned(),
            mode: TraversalBehaviorMode::OrdinaryWalk,
            width_cm: 100,
            slope_permille: 0,
            visibility_bps: 100,
            access_state: PhysicalAccessState::Open,
            min_transit_ms: 500,
            max_transit_ms: 1_000,
            uncertainty_ms: 100,
            survey_generation: Generation(1),
            valid_until_ns: TimestampNs(5_000),
        },
    ];

    let gphys = PhysicalTopologyGraph::build(
        "proj:phys-home",
        Generation(1),
        anchor(101),
        ContentDigest::sha256(b"hist:101"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert!(!gphys.grants_effect_authority());

    // DigitalTwinGraph lossless crosswalk preserves parallel edges.
    let xwalk = gphys.digital_twin_crosswalk();
    assert_eq!(xwalk.source_universe, GraphUniverse::GPhys);
    assert_eq!(xwalk.registry_projection_name, "DigitalTwinGraph");
    assert_eq!(xwalk.mapped_nodes, 4);
    assert_eq!(xwalk.preserved_parallel_edges, 4);
    assert!(xwalk.lossless_verified);

    // Compare nominal vs stealth routes: pairwise nominal collapse MUST be proven lossy!
    let cmp = gphys.compare_nominal_and_stealth_routes(
        "yard:north",
        "door:back",
        TimestampNs(10_000),
        Some(Generation(2)),
        10_000,
        || false,
    )?;
    assert!(!cmp.infers_metric_calibration);
    assert!(!cmp.grants_effect_authority);
    assert!(cmp.stealth_route_lost_under_pairwise_collapse);
    let nom = cmp.nominal_route.as_ref().ok_or("missing nominal route")?;
    let stl = cmp.stealth_route.as_ref().ok_or("missing stealth route")?;
    assert_eq!(nom.edge_ids, vec!["e:walk-open".to_owned()]);
    assert_eq!(stl.edge_ids, vec!["e:crawl-stealth".to_owned()]);
    assert!(stl.max_visibility_bps < nom.max_visibility_bps);
    assert!(
        cmp.stale_survey_ids
            .contains(&"landmark:stale-shed".to_owned())
    );
    assert!(
        cmp.stale_survey_ids
            .contains(&"e:stale-shortcut".to_owned())
    );

    // Incremental delta vs full rebuild parity.
    let climb_edge = PhysicalEdgeSpec {
        edge_id: "e:climb-fence".to_owned(),
        source_id: "yard:north".to_owned(),
        target_id: "fence:side".to_owned(),
        mode: TraversalBehaviorMode::Climb,
        width_cm: 80,
        slope_permille: 450,
        visibility_bps: 1_200,
        access_state: PhysicalAccessState::Open,
        min_transit_ms: 7_000,
        max_transit_ms: 10_000,
        uncertainty_ms: 1_000,
        survey_generation: Generation(2),
        valid_until_ns: TimestampNs(50_000),
    };
    let inc = gphys.apply_deltas(
        anchor(102),
        ContentDigest::sha256(b"hist:102"),
        Generation(1),
        &scope,
        &[PhysicalDelta::UpsertEdge(Box::new(climb_edge.clone()))],
        complete_absence(),
        || false,
    )?;
    let mut full_edges = edges;
    full_edges.push(climb_edge);
    let full = PhysicalTopologyGraph::build(
        "proj:phys-home",
        Generation(1),
        anchor(102),
        ContentDigest::sha256(b"hist:102"),
        &scope,
        nodes,
        full_edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(inc.universe_digest(), full.universe_digest());

    // v1 -> v2 tombstone migration & unknown-version quarantine.
    let v1_bytes = inc.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, report) = PhysicalTopologyGraph::from_canonical_bytes(&v1_bytes)?;
    assert_eq!(report.source_version, LEGACY_UNIVERSE_WIRE_VERSION);
    assert_eq!(report.target_version, CURRENT_UNIVERSE_WIRE_VERSION);
    assert!(report.migrated);
    assert_eq!(report.tombstoned_fields.len(), 1);
    assert_eq!(migrated.universe_digest(), inc.universe_digest());
    let v2_bytes = migrated.to_canonical_bytes()?;
    let (v2_loaded, v2_rep) = PhysicalTopologyGraph::from_canonical_bytes(&v2_bytes)?;
    assert!(!v2_rep.migrated);
    assert_eq!(v2_loaded.universe_digest(), inc.universe_digest());
    let err = PhysicalTopologyGraph::from_canonical_bytes(&patch_wire_version(&v2_bytes, 99))
        .err()
        .ok_or("expected unsupported version error")?;
    assert_eq!(
        err.guidance(),
        TypedUniverseGuidance::QuarantineAndRebuildFromLedger
    );

    println!(
        "CAPLOG {{\"universe\":\"G_phys\",\"req\":\"PROJ-PHYSICAL-001\",\"stealth_lost_if_collapsed\":{},\"stale_excluded\":{},\"witness_ops\":{}}}",
        cmp.stealth_route_lost_under_pairwise_collapse,
        cmp.stale_survey_ids.len(),
        cmp.witness
            .dominant_operation_counts()
            .get("universe_ops")
            .copied()
            .unwrap_or(0)
    );
    Ok(())
}

#[test]
fn proj_sensor_001_common_cause_cut_fallback_invalidation_and_noninterference() -> TestResult {
    let scope = full_scope(GraphUniverse::GSensor);
    let mk_node = |id: &str,
                   kind: SensorInfraKind,
                   valid_until: i128,
                   doms: &[(FailureDomainCategory, &str)]| SensorInfraNode {
        node_id: id.to_owned(),
        kind,
        component_generation: Generation(1),
        telemetry_valid_until_ns: TimestampNs(valid_until),
        intrinsic_domains: doms.iter().map(|(c, n)| (*c, (*n).to_owned())).collect(),
        plane: Plane::Cognition,
    };
    let nodes = vec![
        mk_node(
            "cam:front",
            SensorInfraKind::Sensor,
            50_000,
            &[(FailureDomainCategory::Vendor, "vendor:acme")],
        ),
        mk_node(
            "cam:porch-fb",
            SensorInfraKind::Sensor,
            50_000,
            &[(FailureDomainCategory::Vendor, "vendor:acme")],
        ),
        mk_node(
            "cam:cellular-indep",
            SensorInfraKind::Sensor,
            50_000,
            &[(FailureDomainCategory::Vendor, "vendor:beta")],
        ),
        mk_node("sw:poe-main", SensorInfraKind::Switch, 50_000, &[]),
        mk_node("pwr:circuit-a", SensorInfraKind::PowerCircuit, 50_000, &[]),
        mk_node("clk:ntp-local", SensorInfraKind::ClockSource, 50_000, &[]),
    ];
    let mk_edge =
        |src: &str, dst: &str, kind: SensorDepEdgeKind, cat: FailureDomainCategory| SensorDepEdge {
            source_id: src.to_owned(),
            target_id: dst.to_owned(),
            kind,
            category: cat,
            provenance: "observed_lldp".to_owned(),
            generation: Generation(1),
            valid_until_ns: TimestampNs(50_000),
        };
    let edges = vec![
        mk_edge(
            "cam:front",
            "sw:poe-main",
            SensorDepEdgeKind::TransfersThrough,
            FailureDomainCategory::Network,
        ),
        mk_edge(
            "cam:porch-fb",
            "sw:poe-main",
            SensorDepEdgeKind::TransfersThrough,
            FailureDomainCategory::Network,
        ),
        mk_edge(
            "sw:poe-main",
            "pwr:circuit-a",
            SensorDepEdgeKind::PoweredBy,
            FailureDomainCategory::Power,
        ),
        mk_edge(
            "cam:front",
            "clk:ntp-local",
            SensorDepEdgeKind::SynchronizesWith,
            FailureDomainCategory::Clock,
        ),
        mk_edge(
            "cam:porch-fb",
            "clk:ntp-local",
            SensorDepEdgeKind::SynchronizesWith,
            FailureDomainCategory::Clock,
        ),
        // Corroboration pair that secretly shares switch, power, clock, AND vendor!
        mk_edge(
            "cam:front",
            "cam:porch-fb",
            SensorDepEdgeKind::Corroborates,
            FailureDomainCategory::Network,
        ),
        // Fallback 1 shares sw:poe-main -> INVALIDATED on switch cut!
        mk_edge(
            "cam:front",
            "cam:porch-fb",
            SensorDepEdgeKind::CanFallbackTo,
            FailureDomainCategory::Network,
        ),
        // Fallback 2 is independent of sw:poe-main -> SURVIVES switch cut!
        mk_edge(
            "cam:front",
            "cam:cellular-indep",
            SensorDepEdgeKind::CanFallbackTo,
            FailureDomainCategory::Network,
        ),
    ];

    let gsensor = SensorDependencyGraph::build(
        "proj:sensor-site",
        Generation(1),
        anchor(201),
        ContentDigest::sha256(b"hist:201"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert!(!gsensor.grants_effect_authority());

    // Single switch failure cut loses BOTH cam:front and cam:porch-fb, invalidates porch-fb fallback,
    // keeps cellular-indep fallback valid, and exposes hidden common causes!
    let report =
        gsensor.assess_component_failure("sw:poe-main", TimestampNs(10_000), 10_000, || false)?;
    assert!(!report.certifies_physical_independence);
    assert!(!report.grants_effect_authority);
    assert_eq!(
        report.lost_sensors,
        vec!["cam:front".to_owned(), "cam:porch-fb".to_owned()]
    );
    assert_eq!(
        report.invalidated_fallbacks,
        vec![("cam:front".to_owned(), "cam:porch-fb".to_owned())]
    );
    assert_eq!(
        report.valid_fallbacks,
        vec![("cam:front".to_owned(), "cam:cellular-indep".to_owned())]
    );
    assert_eq!(report.degraded_mode, "degraded_fallback_invalidated");
    let shared = report
        .shared_corroboration_domains
        .get(&("cam:front".to_owned(), "cam:porch-fb".to_owned()))
        .ok_or("missing corroboration pair")?;
    assert!(shared.contains(&(FailureDomainCategory::Network, "sw:poe-main".to_owned())));
    assert!(shared.contains(&(FailureDomainCategory::Power, "pwr:circuit-a".to_owned())));
    assert!(shared.contains(&(FailureDomainCategory::Clock, "clk:ntp-local".to_owned())));
    assert!(shared.contains(&(FailureDomainCategory::Vendor, "vendor:acme".to_owned())));

    // Capability-projected visible_out_degree hides redacted neighbor without leaking degree!
    let mut redacted_scope = full_scope(GraphUniverse::GSensor);
    redacted_scope
        .redacted_node_ids
        .insert("cam:cellular-indep".to_owned());
    let gsensor_redacted = SensorDependencyGraph::build(
        "proj:sensor-site",
        Generation(1),
        anchor(201),
        ContentDigest::sha256(b"hist:201"),
        &redacted_scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert_eq!(
        gsensor.visible_out_degree("cam:front"),
        gsensor_redacted.visible_out_degree("cam:front") + 1
    );
    assert_eq!(gsensor_redacted.visible_out_degree("cam:cellular-indep"), 0);

    // Incremental delta parity & v1 -> v2 tombstone migration.
    let edge_host = mk_node("host:edge-1", SensorInfraKind::EdgeHost, 50_000, &[]);
    let inc = gsensor.apply_deltas(
        anchor(202),
        ContentDigest::sha256(b"hist:202"),
        Generation(1),
        &scope,
        &[SensorDelta::UpsertNode(edge_host.clone())],
        complete_absence(),
        || false,
    )?;
    let mut full_nodes = nodes;
    full_nodes.push(edge_host);
    let full = SensorDependencyGraph::build(
        "proj:sensor-site",
        Generation(1),
        anchor(202),
        ContentDigest::sha256(b"hist:202"),
        &scope,
        full_nodes,
        edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(inc.universe_digest(), full.universe_digest());

    let v1_bytes = inc.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = SensorDependencyGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), inc.universe_digest());
    assert_eq!(mig.tombstoned_fields.len(), 1);

    println!(
        "CAPLOG {{\"universe\":\"G_sensor\",\"req\":\"PROJ-SENSOR-001\",\"lost_sensors\":{},\"invalidated_fallbacks\":{},\"shared_domains\":{}}}",
        report.lost_sensors.len(),
        report.invalidated_fallbacks.len(),
        shared.len()
    );
    Ok(())
}

#[test]
fn proj_time_001_interval_widening_counterexample_abstain_and_unknown_never_impossible()
-> TestResult {
    let scope = full_scope(GraphUniverse::GTime);
    let mk_node =
        |id: &str, zone: &str, start: i128, end: i128, unc: u64, obs: TimeNodeObservability| {
            TimeExpandedNodeSpec {
                node_id: id.to_owned(),
                zone_id: zone.to_owned(),
                interval_start_ns: TimestampNs(start),
                interval_end_ns: TimestampNs(end),
                clock_uncertainty_ns: unc,
                clock_generation: Generation(3),
                geometry_generation: Generation(2),
                behavior_generation: Generation(1),
                observability: obs,
                plane: Plane::Cognition,
            }
        };
    // Exact midpoint of z1 = 10_000, travel = [4_000, 5_000] -> exact midpoint arrival [14_000, 15_000]
    // Target z3 midpoint = 13_400 (window [13_300, 13_500]): exact midpoint says IMPOSSIBLE!
    // But clock uncertainty (500 + 500 = 1_000ns) widens earliest arrival to 10_000 + 4_000 - 1_000 = 13_000 <= 13_500 -> FEASIBLE!
    let nodes = vec![
        mk_node(
            "t:camA-0",
            "zone:driveway",
            9_900,
            10_100,
            500,
            TimeNodeObservability::Observed,
        ),
        mk_node(
            "t:blind-1",
            "zone:hedge",
            11_000,
            13_000,
            200,
            TimeNodeObservability::UnobservedSpace,
        ),
        mk_node(
            "t:camB-2",
            "zone:porch",
            13_300,
            13_500,
            500,
            TimeNodeObservability::Observed,
        ),
        mk_node(
            "t:drifted",
            "zone:back",
            20_000,
            20_500,
            9_000,
            TimeNodeObservability::Observed,
        ),
        mk_node(
            "t:recon",
            "zone:side",
            12_000,
            13_000,
            100,
            TimeNodeObservability::ReconnectBoundary,
        ),
        mk_node(
            "t:after-recon",
            "zone:garage",
            15_000,
            16_000,
            100,
            TimeNodeObservability::Observed,
        ),
    ];
    let edges = vec![
        TimeTransitEdgeSpec {
            edge_id: "e:direct-widened".to_owned(),
            source_id: "t:camA-0".to_owned(),
            target_id: "t:camB-2".to_owned(),
            behavior_model: "walk_1_4mps".to_owned(),
            min_travel_ns: 4_000,
            max_travel_ns: 5_000,
            max_allowed_clock_uncertainty_ns: 2_000,
        },
        TimeTransitEdgeSpec {
            edge_id: "e:to-blind".to_owned(),
            source_id: "t:camA-0".to_owned(),
            target_id: "t:blind-1".to_owned(),
            behavior_model: "walk_1_4mps".to_owned(),
            min_travel_ns: 1_500,
            max_travel_ns: 2_000,
            max_allowed_clock_uncertainty_ns: 2_000,
        },
        TimeTransitEdgeSpec {
            edge_id: "e:to-drifted".to_owned(),
            source_id: "t:camA-0".to_owned(),
            target_id: "t:drifted".to_owned(),
            behavior_model: "walk_1_4mps".to_owned(),
            min_travel_ns: 8_000,
            max_travel_ns: 10_000,
            max_allowed_clock_uncertainty_ns: 2_000,
        },
        TimeTransitEdgeSpec {
            edge_id: "e:via-recon-1".to_owned(),
            source_id: "t:camA-0".to_owned(),
            target_id: "t:recon".to_owned(),
            behavior_model: "walk_1_4mps".to_owned(),
            min_travel_ns: 1_500,
            max_travel_ns: 2_500,
            max_allowed_clock_uncertainty_ns: 2_000,
        },
        TimeTransitEdgeSpec {
            edge_id: "e:via-recon-2".to_owned(),
            source_id: "t:recon".to_owned(),
            target_id: "t:after-recon".to_owned(),
            behavior_model: "walk_1_4mps".to_owned(),
            min_travel_ns: 2_000,
            max_travel_ns: 3_000,
            max_allowed_clock_uncertainty_ns: 2_000,
        },
    ];

    let gtime = TimeExpandedTransitGraph::build(
        "proj:time-site",
        Generation(1),
        anchor(301),
        ContentDigest::sha256(b"hist:301"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert!(!gtime.grants_effect_authority());

    // 1. Exact-vs-interval counterexample proven!
    let res = gtime.assess_same_entity_feasibility(
        "t:camA-0",
        "t:camB-2",
        Some(Generation(3)),
        Some(Generation(2)),
        10_000,
        || false,
    )?;
    match res.verdict {
        TimeFeasibilityVerdict::Feasible {
            exact_midpoint_would_have_erred,
            ..
        } => assert!(exact_midpoint_would_have_erred),
        other => return Err(format!("expected Feasible counterexample, got {other:?}").into()),
    }

    // 2. Temporal tolerance violation -> AbstainToleranceExceeded with exact invalidating interval!
    let drift_res = gtime.assess_same_entity_feasibility(
        "t:camA-0",
        "t:drifted",
        Some(Generation(3)),
        Some(Generation(2)),
        10_000,
        || false,
    )?;
    assert!(matches!(
        drift_res.verdict,
        TimeFeasibilityVerdict::AbstainToleranceExceeded {
            observed_uncertainty_ns: 9_500,
            max_tolerance_ns: 2_000,
            ..
        }
    ));

    // 3. Stale clock gen, budget exhaustion, and intermediate ReconnectBoundary -> Unknown (NEVER Infeasible!)
    let stale_res = gtime.assess_same_entity_feasibility(
        "t:camA-0",
        "t:camB-2",
        Some(Generation(99)),
        Some(Generation(2)),
        10_000,
        || false,
    )?;
    assert!(matches!(
        stale_res.verdict,
        TimeFeasibilityVerdict::Unknown { .. }
    ));

    let budget_res = gtime.assess_same_entity_feasibility(
        "t:camA-0",
        "t:camB-2",
        Some(Generation(3)),
        Some(Generation(2)),
        1,
        || false,
    )?;
    assert!(matches!(
        budget_res.verdict,
        TimeFeasibilityVerdict::Unknown { ref reason } if reason == "budget_exhausted"
    ));

    let recon_res = gtime.assess_same_entity_feasibility(
        "t:camA-0",
        "t:after-recon",
        Some(Generation(3)),
        Some(Generation(2)),
        10_000,
        || false,
    )?;
    assert!(matches!(
        recon_res.verdict,
        TimeFeasibilityVerdict::Unknown { ref reason } if reason == "reconnect_boundary_clock_discontinuity"
    ));

    // 4. Incremental parity & v1 -> v2 migration.
    let inc = gtime.apply_deltas(
        anchor(302),
        ContentDigest::sha256(b"hist:302"),
        Generation(1),
        &scope,
        &[TimeDelta::RemoveEdge("e:to-blind".to_owned())],
        complete_absence(),
        || false,
    )?;
    let full_edges: Vec<_> = edges
        .into_iter()
        .filter(|e| e.edge_id != "e:to-blind")
        .collect();
    let full = TimeExpandedTransitGraph::build(
        "proj:time-site",
        Generation(1),
        anchor(302),
        ContentDigest::sha256(b"hist:302"),
        &scope,
        nodes,
        full_edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(inc.universe_digest(), full.universe_digest());

    let v1_bytes = inc.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = TimeExpandedTransitGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), inc.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_time\",\"req\":\"PROJ-TIME-001\",\"exact_counterexample_caught\":true,\"abstain_logged\":true,\"unknown_on_budget_and_reconnect\":true}}"
    );
    Ok(())
}

#[test]
fn proj_assoc_001_k_best_ambiguity_no_mixed_embeddings_and_no_person_identity() -> TestResult {
    let scope = full_scope(GraphUniverse::GAssoc);
    let mk_t =
        |id: &str, cam: &str, zone: &str, start: i128, end: i128, emb_gen: u64, cls: &str| {
            TrackletNodeSpec {
                tracklet_id: id.to_owned(),
                camera_id: cam.to_owned(),
                zone_id: zone.to_owned(),
                start_ns: TimestampNs(start),
                end_ns: TimestampNs(end),
                embedding_generation: Generation(emb_gen),
                geometry_generation: Generation(1),
                source_quality_bps: 8_500,
                hypothesis_class: cls.to_owned(),
                failure_domains: ["sw:poe-main".to_owned()].into_iter().collect(),
                asserts_person_identity: false,
                plane: Plane::Cognition,
            }
        };

    // 1. Tracklet attempting biometric person identity assertion fails closed!
    let mut bad_id = mk_t("trk:bad", "cam:1", "yard", 100, 200, 2, "person");
    bad_id.asserts_person_identity = true;
    assert!(matches!(
        TrackAssociationGraph::build(
            "proj:bad-id",
            Generation(1),
            anchor(401),
            ContentDigest::sha256(b"h"),
            &scope,
            vec![bad_id],
            vec![],
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 2. Mixing embedding generations across a candidate edge fails closed!
    let mix_nodes = vec![
        mk_t("trk:g1", "cam:1", "yard", 100, 200, 1, "person"),
        mk_t("trk:g2", "cam:2", "porch", 300, 400, 2, "person"),
    ];
    let mix_edge = AssocCandidateEdge {
        edge_id: "e:mix".to_owned(),
        source_id: "trk:g1".to_owned(),
        target_id: "trk:g2".to_owned(),
        hypothesis_label: "illegal_mixed_gen".to_owned(),
        components: AssocComponentCosts {
            temporal_cost: 10,
            spatial_cost: 10,
            appearance_cost: 10,
            size_gait_motion_cost: 10,
            occlusion_route_cost: 10,
            source_health_penalty: 0,
            household_routine_cost: 0,
        },
        assumptions: vec![],
        contradictions: vec![],
        protected_alternative: false,
        discriminating_probe: None,
    };
    assert!(matches!(
        TrackAssociationGraph::build(
            "proj:mix",
            Generation(1),
            anchor(401),
            ContentDigest::sha256(b"h"),
            &scope,
            mix_nodes,
            vec![mix_edge],
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::MixedAnchorOrGeneration(_))
    ));

    // 3. Person-vs-raccoon/crawling ambiguity retains BOTH hypotheses even at k=1, flags
    //    simultaneous disjoint visibility contradiction, surfaces shared camera failure domains,
    //    and picks the cheapest discriminating probe!
    let nodes = vec![
        mk_t(
            "trk:yard-1",
            "cam:1",
            "yard",
            1_000,
            2_000,
            2,
            "low_profile",
        ),
        mk_t(
            "trk:porch-2",
            "cam:2",
            "porch",
            3_000,
            4_000,
            2,
            "low_profile",
        ),
        mk_t(
            "trk:garage-simul",
            "cam:3",
            "garage",
            1_500,
            2_500,
            2,
            "person",
        ),
    ];
    let edges = vec![
        AssocCandidateEdge {
            edge_id: "hyp:raccoon-benign".to_owned(),
            source_id: "trk:yard-1".to_owned(),
            target_id: "trk:porch-2".to_owned(),
            hypothesis_label: "benign_raccoon_routine".to_owned(),
            components: AssocComponentCosts {
                temporal_cost: 10,
                spatial_cost: 15,
                appearance_cost: 20,
                size_gait_motion_cost: 15,
                occlusion_route_cost: 10,
                source_health_penalty: 5,
                household_routine_cost: 5,
            },
            assumptions: vec!["low_height_small_animal".to_owned()],
            contradictions: vec![],
            protected_alternative: false,
            discriminating_probe: Some(("probe:pan-ptz-high".to_owned(), 50)),
        },
        AssocCandidateEdge {
            edge_id: "hyp:crawling-intruder".to_owned(),
            source_id: "trk:yard-1".to_owned(),
            target_id: "trk:porch-2".to_owned(),
            hypothesis_label: "crawling_person_intruder".to_owned(),
            components: AssocComponentCosts {
                temporal_cost: 10,
                spatial_cost: 15,
                appearance_cost: 25,
                size_gait_motion_cost: 25,
                occlusion_route_cost: 10,
                source_health_penalty: 5,
                household_routine_cost: 15,
            },
            assumptions: vec!["human_crawling_posture".to_owned()],
            contradictions: vec![],
            protected_alternative: true,
            discriminating_probe: Some(("probe:ir-illuminator-burst".to_owned(), 12)),
        },
        AssocCandidateEdge {
            edge_id: "hyp:impossible-simul".to_owned(),
            source_id: "trk:yard-1".to_owned(),
            target_id: "trk:garage-simul".to_owned(),
            hypothesis_label: "same_actor_two_places".to_owned(),
            components: AssocComponentCosts {
                temporal_cost: 1,
                spatial_cost: 1,
                appearance_cost: 1,
                size_gait_motion_cost: 1,
                occlusion_route_cost: 1,
                source_health_penalty: 0,
                household_routine_cost: 0,
            },
            assumptions: vec![],
            contradictions: vec![],
            protected_alternative: false,
            discriminating_probe: None,
        },
    ];

    let gassoc = TrackAssociationGraph::build(
        "proj:assoc-site",
        Generation(1),
        anchor(401),
        ContentDigest::sha256(b"hist:401"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert!(!gassoc.grants_effect_authority());

    // Even with k = 1, the protected crawling-intruder hypothesis MUST survive!
    let k1 = gassoc.evaluate_k_best_hypotheses(1, 10_000, || false)?;
    assert_eq!(k1.retained_hypotheses.len(), 2);
    assert_eq!(k1.retained_hypotheses[0].edge_id, "hyp:raccoon-benign");
    assert_eq!(k1.retained_hypotheses[1].edge_id, "hyp:crawling-intruder");
    assert!(
        k1.retained_hypotheses
            .iter()
            .all(|h| !h.asserts_person_identity)
    );
    assert_eq!(
        k1.retained_hypotheses[0].shared_camera_failure_domains,
        vec!["sw:poe-main".to_owned()]
    );
    assert!(k1.unresolved_ambiguity);
    assert_eq!(k1.ambiguity_margin, Some(25));
    assert_eq!(
        k1.cheapest_discriminating_probe,
        Some(("probe:ir-illuminator-burst".to_owned(), 12))
    );

    // With k = 3, simultaneous disjoint visibility contradiction is ranked last and explicitly flagged!
    let k3 = gassoc.evaluate_k_best_hypotheses(3, 10_000, || false)?;
    let simul = k3
        .retained_hypotheses
        .iter()
        .find(|h| h.edge_id == "hyp:impossible-simul")
        .ok_or("missing simultaneous hypothesis")?;
    assert!(simul.simultaneous_visibility_contradiction);

    // Incremental parity & v1 -> v2 migration.
    let inc = gassoc.apply_deltas(
        anchor(402),
        ContentDigest::sha256(b"hist:402"),
        Generation(1),
        &scope,
        &[AssocDelta::RemoveEdge("hyp:impossible-simul".to_owned())],
        complete_absence(),
        || false,
    )?;
    let full_edges: Vec<_> = edges
        .into_iter()
        .filter(|e| e.edge_id != "hyp:impossible-simul")
        .collect();
    let full = TrackAssociationGraph::build(
        "proj:assoc-site",
        Generation(1),
        anchor(402),
        ContentDigest::sha256(b"hist:402"),
        &scope,
        nodes,
        full_edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(inc.universe_digest(), full.universe_digest());

    let v1_bytes = inc.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = TrackAssociationGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), inc.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_assoc\",\"req\":\"PROJ-ASSOC-001\",\"k1_retained\":{},\"unresolved_ambiguity\":{},\"probe\":\"probe:ir-illuminator-burst\"}}",
        k1.retained_hypotheses.len(),
        k1.unresolved_ambiguity
    );
    Ok(())
}

#[test]
fn proj_evidence_001_append_only_supersession_invalidation_and_counterfactuals() -> TestResult {
    let scope = full_scope(GraphUniverse::GEvidence);
    let mk_node = |id: &str,
                   kind: EvidenceGraphNodeKind,
                   ks: WorldKnowledgeState,
                   prov: WorldProvenanceClass,
                   disp: WorldHypothesisDisposition,
                   eff: EvidenceEffectOutcome,
                   gen_n: u64| EvidenceGraphNode {
        node_id: id.to_owned(),
        kind,
        knowledge_state: ks,
        provenance_class: prov,
        disposition: disp,
        effect_outcome: eff,
        artifact_generation: Generation(gen_n),
        plane: Plane::Cognition,
    };

    let nodes = vec![
        mk_node(
            "cap:cam1-seg1",
            EvidenceGraphNodeKind::SourceCapsule,
            WorldKnowledgeState::Certified,
            WorldProvenanceClass::SourceRetained,
            WorldHypothesisDisposition::Supported,
            EvidenceEffectOutcome::NotAnEffect,
            2,
        ),
        mk_node(
            "det:v1-old",
            EvidenceGraphNodeKind::Detection,
            WorldKnowledgeState::Observed,
            WorldProvenanceClass::DerivedCognition,
            WorldHypothesisDisposition::ActiveAlternative,
            EvidenceEffectOutcome::NotAnEffect,
            1,
        ),
        mk_node(
            "det:v2-new",
            EvidenceGraphNodeKind::Detection,
            WorldKnowledgeState::Observed,
            WorldProvenanceClass::DerivedCognition,
            WorldHypothesisDisposition::Supported,
            EvidenceEffectOutcome::NotAnEffect,
            2,
        ),
        mk_node(
            "dec:alert-1",
            EvidenceGraphNodeKind::PolicyDecision,
            WorldKnowledgeState::Hypothesized,
            WorldProvenanceClass::DerivedCognition,
            WorldHypothesisDisposition::Supported,
            EvidenceEffectOutcome::Prepared,
            2,
        ),
    ];
    let edges = vec![
        EvidenceGraphEdge {
            source_id: "det:v1-old".to_owned(),
            target_id: "cap:cam1-seg1".to_owned(),
            kind: EvidenceEdgeKind::DerivedFrom,
        },
        EvidenceGraphEdge {
            source_id: "det:v2-new".to_owned(),
            target_id: "cap:cam1-seg1".to_owned(),
            kind: EvidenceEdgeKind::DerivedFrom,
        },
        EvidenceGraphEdge {
            source_id: "det:v2-new".to_owned(),
            target_id: "det:v1-old".to_owned(),
            kind: EvidenceEdgeKind::Supersedes,
        },
        EvidenceGraphEdge {
            source_id: "det:v2-new".to_owned(),
            target_id: "dec:alert-1".to_owned(),
            kind: EvidenceEdgeKind::Supports,
        },
    ];

    let gev = CausalEvidenceGraph::build(
        "proj:ev-site",
        Generation(1),
        anchor(501),
        ContentDigest::sha256(b"hist:501"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert!(!gev.grants_effect_authority());

    // 1. Recomputed explanation retains superseded history and identifies exact counterfactual flippers!
    let rep = gev.explain_decision_and_counterfactuals("dec:alert-1", None, 10_000, || false)?;
    assert!(rep.decision_currently_supported);
    assert!(!rep.grants_effect_authority);
    assert_eq!(rep.superseded_history_nodes, vec!["det:v1-old".to_owned()]);
    assert_eq!(rep.minimal_source_roots, vec!["cap:cam1-seg1".to_owned()]);
    assert!(
        rep.counterfactual_decision_flippers
            .contains(&"cap:cam1-seg1".to_owned())
    );
    assert!(
        rep.counterfactual_decision_flippers
            .contains(&"det:v2-new".to_owned())
    );
    assert!(
        rep.deletion_impact_nodes
            .contains(&"dec:alert-1".to_owned())
    );

    // 2. Append-only enforcement: mutating an existing node fails closed!
    assert!(matches!(
        gev.apply_deltas(
            anchor(502),
            ContentDigest::sha256(b"hist:502"),
            Generation(1),
            &scope,
            &[EvidenceGraphDelta::AppendNode(nodes[0].clone())],
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::InvalidInput(_))
    ));

    // 3. Appending an Invalidates edge propagates without deleting history and flips decision!
    let inv_node = mk_node(
        "adj:lens-smudge",
        EvidenceGraphNodeKind::OperatorAdjudication,
        WorldKnowledgeState::Certified,
        WorldProvenanceClass::OperatorAsserted,
        WorldHypothesisDisposition::Refuted,
        EvidenceEffectOutcome::NotAnEffect,
        2,
    );
    let inv_edge = EvidenceGraphEdge {
        source_id: "adj:lens-smudge".to_owned(),
        target_id: "det:v2-new".to_owned(),
        kind: EvidenceEdgeKind::Invalidates,
    };
    let gev2 = gev.apply_deltas(
        anchor(502),
        ContentDigest::sha256(b"hist:502"),
        Generation(1),
        &scope,
        &[
            EvidenceGraphDelta::AppendNode(inv_node.clone()),
            EvidenceGraphDelta::AppendEdge(inv_edge.clone()),
        ],
        complete_absence(),
        || false,
    )?;
    let mut full_nodes = nodes;
    full_nodes.push(inv_node);
    let mut full_edges = edges;
    full_edges.push(inv_edge);
    let full = CausalEvidenceGraph::build(
        "proj:ev-site",
        Generation(1),
        anchor(502),
        ContentDigest::sha256(b"hist:502"),
        &scope,
        full_nodes,
        full_edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(gev2.universe_digest(), full.universe_digest());

    let rep2 = gev2.explain_decision_and_counterfactuals("dec:alert-1", None, 10_000, || false)?;
    assert!(!rep2.decision_currently_supported);
    assert!(rep2.invalidated_nodes.contains(&"det:v2-new".to_owned()));
    assert!(rep2.invalidated_nodes.contains(&"dec:alert-1".to_owned()));
    assert_eq!(rep2.superseded_history_nodes, vec!["det:v1-old".to_owned()]);

    // 4. v1 -> v2 tombstone migration.
    let v1_bytes = gev2.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = CausalEvidenceGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), gev2.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_evidence\",\"req\":\"PROJ-EVIDENCE-001\",\"flippers\":{},\"invalidated_after_adj\":{}}}",
        rep.counterfactual_decision_flippers.len(),
        rep2.invalidated_nodes.len()
    );
    Ok(())
}

#[test]
fn proj_object_001_root_last_custody_holds_and_graph_complete_deletion() -> TestResult {
    let scope = full_scope(GraphUniverse::GObject);
    let mk_obj = |id: &str,
                  kind: ArchiveObjectKind,
                  gen_n: u64,
                  custody: ObjectCustodyState,
                  missing: bool| ArchiveObjectNode {
        object_id: id.to_owned(),
        kind,
        content_digest: ContentDigest::sha256(id.as_bytes()),
        byte_len: 4096,
        object_generation: Generation(gen_n),
        custody_state: custody,
        missing_on_challenge: missing,
        plane: Plane::Authority,
    };

    // Scenario A: defective closure (staged child under published root, stale repair symbol,
    // lagging replica) + deletion blocked by legal hold AND shared alternate EvidenceRoot!
    let nodes = vec![
        mk_obj(
            "root:ev-1",
            ArchiveObjectKind::EvidenceRoot,
            2,
            ObjectCustodyState::Published,
            false,
        ),
        mk_obj(
            "root:ev-alt",
            ArchiveObjectKind::EvidenceRoot,
            2,
            ObjectCustodyState::Retrievable,
            false,
        ),
        mk_obj(
            "man:m1",
            ArchiveObjectKind::Manifest,
            2,
            ObjectCustodyState::Durable,
            false,
        ),
        mk_obj(
            "chk:staged-bad",
            ArchiveObjectKind::SourceChunk,
            2,
            ObjectCustodyState::Staged,
            false,
        ),
        mk_obj(
            "chk:shared",
            ArchiveObjectKind::SourceChunk,
            2,
            ObjectCustodyState::Retrievable,
            false,
        ),
        mk_obj(
            "rep:stale-sym",
            ArchiveObjectKind::RepairSymbol,
            1,
            ObjectCustodyState::Published,
            false,
        ),
        mk_obj(
            "mir:lagging",
            ArchiveObjectKind::Replica,
            2,
            ObjectCustodyState::Durable,
            false,
        ),
        mk_obj(
            "idx:sec-1",
            ArchiveObjectKind::Index,
            2,
            ObjectCustodyState::Published,
            false,
        ),
        mk_obj(
            "cache:hot-1",
            ArchiveObjectKind::CacheEntry,
            2,
            ObjectCustodyState::Published,
            false,
        ),
        mk_obj(
            "hold:legal-1",
            ArchiveObjectKind::Hold,
            2,
            ObjectCustodyState::Protected,
            false,
        ),
    ];
    let edges = vec![
        ArchiveObjectEdge {
            source_id: "root:ev-1".to_owned(),
            target_id: "man:m1".to_owned(),
            kind: ObjectEdgeKind::Contains,
        },
        ArchiveObjectEdge {
            source_id: "man:m1".to_owned(),
            target_id: "chk:staged-bad".to_owned(),
            kind: ObjectEdgeKind::Contains,
        },
        ArchiveObjectEdge {
            source_id: "man:m1".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::Contains,
        },
        ArchiveObjectEdge {
            source_id: "root:ev-alt".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::References,
        },
        ArchiveObjectEdge {
            source_id: "rep:stale-sym".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::Repairs,
        },
        ArchiveObjectEdge {
            source_id: "mir:lagging".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::ReplicaOf,
        },
        ArchiveObjectEdge {
            source_id: "idx:sec-1".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::References,
        },
        ArchiveObjectEdge {
            source_id: "cache:hot-1".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::References,
        },
        ArchiveObjectEdge {
            source_id: "chk:shared".to_owned(),
            target_id: "hold:legal-1".to_owned(),
            kind: ObjectEdgeKind::RetainedByHold,
        },
        // Hold cycle to verify cycle-safe traversal!
        ArchiveObjectEdge {
            source_id: "hold:legal-1".to_owned(),
            target_id: "chk:shared".to_owned(),
            kind: ObjectEdgeKind::RetainedByHold,
        },
    ];

    let gobj = ArchiveObjectGraph::build(
        "proj:obj-site",
        Generation(1),
        anchor(601),
        ContentDigest::sha256(b"hist:601"),
        &scope,
        nodes,
        edges,
        complete_absence(),
        || false,
    )?;
    assert!(!gobj.grants_effect_authority());

    let audit = gobj.audit_root_closure_and_deletion(
        "root:ev-1",
        ObjectCustodyState::Published,
        10_000,
        || false,
    )?;
    assert_eq!(
        audit.closure_verdict,
        ObjectClosureVerdict::ClosureDefective
    );
    assert_eq!(
        audit.deletion_verdict,
        ObjectClosureVerdict::DeletionBlocked
    );
    assert_eq!(
        audit.root_before_child_violations,
        vec!["chk:staged-bad".to_owned()]
    );
    assert_eq!(audit.stale_repair_symbols, vec!["rep:stale-sym".to_owned()]);
    assert_eq!(audit.lagging_replicas, vec!["mir:lagging".to_owned()]);
    assert!(
        audit
            .deletion_blockers
            .iter()
            .any(|b| b.starts_with("hold:chk:shared:hold:legal-1"))
    );
    assert!(
        audit
            .deletion_blockers
            .iter()
            .any(|b| b.starts_with("shared_alternate_root:root:ev-alt:chk:shared"))
    );
    assert!(
        audit
            .deletion_closure_members
            .contains(&"idx:sec-1".to_owned())
    );
    assert!(
        audit
            .deletion_closure_members
            .contains(&"cache:hot-1".to_owned())
    );
    assert!(
        audit
            .deletion_closure_members
            .contains(&"rep:stale-sym".to_owned())
    );
    assert!(
        audit
            .deletion_closure_members
            .contains(&"mir:lagging".to_owned())
    );

    // Scenario B: repair custody + remove hold & alternate root via apply_deltas -> both ClosureVerified & DeletionClosureAdmitted!
    let repaired = gobj.apply_deltas(
        anchor(602),
        ContentDigest::sha256(b"hist:602"),
        Generation(1),
        &scope,
        &[
            ObjectGraphDelta::UpsertNode(mk_obj(
                "man:m1",
                ArchiveObjectKind::Manifest,
                2,
                ObjectCustodyState::Retrievable,
                false,
            )),
            ObjectGraphDelta::UpsertNode(mk_obj(
                "chk:staged-bad",
                ArchiveObjectKind::SourceChunk,
                2,
                ObjectCustodyState::Retrievable,
                false,
            )),
            ObjectGraphDelta::UpsertNode(mk_obj(
                "rep:stale-sym",
                ArchiveObjectKind::RepairSymbol,
                2,
                ObjectCustodyState::Retrievable,
                false,
            )),
            ObjectGraphDelta::UpsertNode(mk_obj(
                "mir:lagging",
                ArchiveObjectKind::Replica,
                2,
                ObjectCustodyState::Replicated,
                false,
            )),
            ObjectGraphDelta::RemoveNode("hold:legal-1".to_owned()),
            ObjectGraphDelta::RemoveNode("root:ev-alt".to_owned()),
        ],
        complete_absence(),
        || false,
    )?;
    let audit_ok = repaired.audit_root_closure_and_deletion(
        "root:ev-1",
        ObjectCustodyState::Published,
        10_000,
        || false,
    )?;
    assert_eq!(
        audit_ok.closure_verdict,
        ObjectClosureVerdict::ClosureVerified
    );
    assert_eq!(
        audit_ok.deletion_verdict,
        ObjectClosureVerdict::DeletionClosureAdmitted
    );

    let v1_bytes = repaired.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = ArchiveObjectGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), repaired.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_object\",\"req\":\"PROJ-OBJECT-001\",\"root_before_child_caught\":{},\"blockers\":{},\"closure_members\":{}}}",
        audit.root_before_child_violations.len(),
        audit.deletion_blockers.len(),
        audit.deletion_closure_members.len()
    );
    Ok(())
}

#[test]
fn proj_memory_001_promotion_gate_counterexample_retention_ttl_drift_and_isolation() -> TestResult {
    let scope = full_scope(GraphUniverse::GMemory);
    let root_a = ContentDigest::sha256(b"ev-root:a");
    let val_a = ContentDigest::sha256(b"val-path:a");

    // 1. Promotion without evidence_roots or validation_path_digest fails closed!
    let bad_promo = MemoryNodeSpec {
        memory_id: "mem:unproven".to_owned(),
        kind: MemoryNodeKind::BenignRoutine,
        property_id: "prop-alpha".to_owned(),
        scope_tags: ["zone:driveway".to_owned()].into_iter().collect(),
        recorded_at_ns: TimestampNs(1_000),
        privacy_ttl_until_ns: TimestampNs(50_000),
        confidence_bps: 9_000,
        validated_firmware_gen: Generation(4),
        evidence_roots: vec![],
        validation_path_digest: None,
        promotion_state: MemoryPromotionState::PromotedAdvisory,
        suggested_probe_id: None,
        mutates_authority_or_truth: false,
        plane: Plane::Cognition,
    };
    assert!(matches!(
        OperationalMemoryGraph::build(
            "proj:mem-bad",
            Generation(1),
            anchor(701),
            ContentDigest::sha256(b"h"),
            &scope,
            vec![bad_promo],
            vec![],
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 2. Full operational memory scenario:
    //    - Benign routine ("usually a raccoon") + always-retrievable counterexample
    //    - Firmware-drifted old lesson
    //    - Privacy-TTL expired note
    //    - Conflicting operator feedback pair
    //    - Other property memory isolated strictly (and cross-property edge rejected!)
    let mk_mem = |id: &str,
                  kind: MemoryNodeKind,
                  prop: &str,
                  ttl: i128,
                  fw: u64,
                  promo: MemoryPromotionState,
                  probe: Option<&str>| MemoryNodeSpec {
        memory_id: id.to_owned(),
        kind,
        property_id: prop.to_owned(),
        scope_tags: ["zone:driveway".to_owned()].into_iter().collect(),
        recorded_at_ns: TimestampNs(1_000),
        privacy_ttl_until_ns: TimestampNs(ttl),
        confidence_bps: 8_000,
        validated_firmware_gen: Generation(fw),
        evidence_roots: vec![root_a],
        validation_path_digest: Some(val_a),
        promotion_state: promo,
        suggested_probe_id: probe.map(str::to_owned),
        mutates_authority_or_truth: false,
        plane: Plane::Cognition,
    };
    let nodes = vec![
        mk_mem(
            "mem:usually-raccoon",
            MemoryNodeKind::BenignRoutine,
            "prop-alpha",
            50_000,
            4,
            MemoryPromotionState::PromotedAdvisory,
            Some("probe:low-ir-check"),
        ),
        mk_mem(
            "mem:counter-intruder",
            MemoryNodeKind::Counterexample,
            "prop-alpha",
            50_000,
            4,
            MemoryPromotionState::RetainedNegativeLesson,
            Some("probe:verify-perimeter-gate"),
        ),
        mk_mem(
            "mem:old-fw-lesson",
            MemoryNodeKind::EvidenceLinkedLesson,
            "prop-alpha",
            50_000,
            2,
            MemoryPromotionState::PromotedAdvisory,
            None,
        ),
        mk_mem(
            "mem:ttl-expired",
            MemoryNodeKind::EvidenceLinkedLesson,
            "prop-alpha",
            5_000,
            4,
            MemoryPromotionState::PromotedAdvisory,
            None,
        ),
        mk_mem(
            "mem:op-fb-1",
            MemoryNodeKind::OperatorFeedback,
            "prop-alpha",
            50_000,
            4,
            MemoryPromotionState::PromotedAdvisory,
            None,
        ),
        mk_mem(
            "mem:op-fb-2",
            MemoryNodeKind::OperatorFeedback,
            "prop-alpha",
            50_000,
            4,
            MemoryPromotionState::PromotedAdvisory,
            None,
        ),
        mk_mem(
            "mem:other-property",
            MemoryNodeKind::BenignRoutine,
            "prop-beta",
            50_000,
            4,
            MemoryPromotionState::PromotedAdvisory,
            Some("probe:secret-beta-probe"),
        ),
    ];
    let edges = vec![
        MemoryEdgeSpec {
            source_id: "mem:usually-raccoon".to_owned(),
            target_id: "mem:counter-intruder".to_owned(),
            kind: MemoryEdgeKind::ContradictedBy,
        },
        MemoryEdgeSpec {
            source_id: "mem:op-fb-1".to_owned(),
            target_id: "mem:op-fb-2".to_owned(),
            kind: MemoryEdgeKind::ContradictedBy,
        },
    ];

    // Cross-property edge fails closed!
    let mut cross_edges = edges.clone();
    cross_edges.push(MemoryEdgeSpec {
        source_id: "mem:usually-raccoon".to_owned(),
        target_id: "mem:other-property".to_owned(),
        kind: MemoryEdgeKind::SupportedBy,
    });
    assert!(matches!(
        OperationalMemoryGraph::build(
            "proj:mem-cross",
            Generation(1),
            anchor(701),
            ContentDigest::sha256(b"h"),
            &scope,
            nodes.clone(),
            cross_edges,
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    let gmem = OperationalMemoryGraph::build(
        "proj:mem-site",
        Generation(1),
        anchor(701),
        ContentDigest::sha256(b"hist:701"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    assert!(!gmem.grants_effect_authority());

    let ret = gmem.retrieve_advisory_context(
        "prop-alpha",
        "zone:driveway",
        TimestampNs(10_000),
        Generation(4),
        10_000,
        || false,
    )?;
    assert!(ret.current_event_truth_remains_anchor_pinned);
    assert!(!ret.grants_effect_authority);
    assert!(
        ret.active_advisory_ids
            .contains(&"mem:usually-raccoon".to_owned())
    );
    assert!(
        ret.counterexample_and_negative_ids
            .contains(&"mem:counter-intruder".to_owned())
    );
    assert_eq!(
        ret.firmware_drifted_ids,
        vec!["mem:old-fw-lesson".to_owned()]
    );
    assert_eq!(ret.privacy_ttl_expired_count, 1);
    assert_eq!(
        ret.conflicting_feedback_pairs,
        vec![("mem:op-fb-1".to_owned(), "mem:op-fb-2".to_owned())]
    );
    assert!(
        ret.suggested_probe_ids
            .contains(&"probe:verify-perimeter-gate".to_owned())
    );
    // Strict property isolation: zero leakage from prop-beta!
    assert!(
        !ret.active_advisory_ids
            .contains(&"mem:other-property".to_owned())
    );
    assert!(
        !ret.suggested_probe_ids
            .contains(&"probe:secret-beta-probe".to_owned())
    );

    // Incremental delta parity & v1 -> v2 migration.
    let runbook = mk_mem(
        "mem:runbook-1",
        MemoryNodeKind::Runbook,
        "prop-alpha",
        50_000,
        4,
        MemoryPromotionState::PromotedAdvisory,
        None,
    );
    let inc = gmem.apply_deltas(
        anchor(702),
        ContentDigest::sha256(b"hist:702"),
        Generation(1),
        &scope,
        &[MemoryDelta::UpsertNode(Box::new(runbook.clone()))],
        complete_absence(),
        || false,
    )?;
    let mut full_nodes = nodes;
    full_nodes.push(runbook);
    let full = OperationalMemoryGraph::build(
        "proj:mem-site",
        Generation(1),
        anchor(702),
        ContentDigest::sha256(b"hist:702"),
        &scope,
        full_nodes,
        edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(inc.universe_digest(), full.universe_digest());

    let v1_bytes = inc.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = OperationalMemoryGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), inc.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_memory\",\"req\":\"PROJ-MEMORY-001\",\"counterexamples\":{},\"drifted\":{},\"ttl_expired\":{}}}",
        ret.counterexample_and_negative_ids.len(),
        ret.firmware_drifted_ids.len(),
        ret.privacy_ttl_expired_count
    );
    Ok(())
}

#[test]
fn proj_agent_001_handoff_closure_guards_stale_claims_and_dropped_worlds() -> TestResult {
    let scope = full_scope(GraphUniverse::GAgent);
    let mk_node = |id: &str,
                   kind: AgentNodeKind,
                   auth_hwm: u64,
                   claim_target: Option<&str>,
                   protects_world: bool| AgentControlNode {
        node_id: id.to_owned(),
        kind,
        mission_id: "mission:night-watch".to_owned(),
        workspace_id: "ws:agent-1".to_owned(),
        authority_hwm: auth_hwm,
        cognition_hwm: auth_hwm,
        claim_target_id: claim_target.map(str::to_owned),
        protects_high_loss_world: protects_world,
        grants_effect_authority: false,
        claims_occurrence: false,
        asserts_current_fact: false,
        plane: Plane::Cognition,
    };

    // 1. Non-authority / non-occurrence / non-current-fact guards fail closed!
    let mut bad_claim = mk_node(
        "claim:1",
        AgentNodeKind::WorkClaim,
        10,
        Some("zone:a"),
        false,
    );
    bad_claim.grants_effect_authority = true;
    assert!(matches!(
        bad_claim.validate(),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));
    let mut bad_plan = mk_node("plan:1", AgentNodeKind::Plan, 10, None, false);
    bad_plan.claims_occurrence = true;
    assert!(matches!(
        bad_plan.validate(),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));
    let mut bad_ep = mk_node("ep:1", AgentNodeKind::Episode, 10, None, false);
    bad_ep.asserts_current_fact = true;
    assert!(matches!(
        bad_ep.validate(),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 2. Healthy full orient -> investigate -> plan -> handoff -> resume closure!
    let nodes = vec![
        mk_node("mis:rev-1", AgentNodeKind::MissionRevision, 10, None, false),
        mk_node("ws:s1", AgentNodeKind::SessionWorkspace, 10, None, false),
        mk_node(
            "cap:sit-1",
            AgentNodeKind::SituationCapsule,
            10,
            None,
            false,
        ),
        mk_node(
            "w:high-loss-intruder",
            AgentNodeKind::WorldEnvelope,
            10,
            None,
            true,
        ),
        mk_node("inv:case-1", AgentNodeKind::Investigation, 10, None, false),
        mk_node("plan:p1", AgentNodeKind::Plan, 12, None, false),
        mk_node(
            "obl:verify-door",
            AgentNodeKind::Obligation,
            12,
            None,
            false,
        ),
        mk_node(
            "claim:c1",
            AgentNodeKind::WorkClaim,
            12,
            Some("target:door-back"),
            false,
        ),
        mk_node("ho:h1", AgentNodeKind::Handoff, 12, None, false),
        mk_node(
            "ws:s2-resumed",
            AgentNodeKind::SessionWorkspace,
            12,
            None,
            false,
        ),
    ];
    let edges = vec![
        AgentControlEdge {
            source_id: "mis:rev-1".to_owned(),
            target_id: "inv:case-1".to_owned(),
            kind: AgentEdgeKind::Controls,
        },
        AgentControlEdge {
            source_id: "ho:h1".to_owned(),
            target_id: "w:high-loss-intruder".to_owned(),
            kind: AgentEdgeKind::WorldSafety,
        },
        AgentControlEdge {
            source_id: "ho:h1".to_owned(),
            target_id: "obl:verify-door".to_owned(),
            kind: AgentEdgeKind::Delegates,
        },
        AgentControlEdge {
            source_id: "ws:s2-resumed".to_owned(),
            target_id: "ho:h1".to_owned(),
            kind: AgentEdgeKind::Resumes,
        },
    ];

    let gagent = AgentControlGraph::build(
        "proj:agent-site",
        Generation(1),
        anchor(801),
        ContentDigest::sha256(b"hist:801"),
        &scope,
        nodes,
        edges,
        complete_absence(),
        || false,
    )?;
    assert!(!gagent.grants_effect_authority());

    let ok_rep = gagent.verify_handoff_closure("mission:night-watch", 12, 10, 10_000, || false)?;
    assert!(ok_rep.closure_intact);
    assert!(!ok_rep.grants_effect_authority);
    assert_eq!(
        ok_rep.persisted_obligations,
        vec!["obl:verify-door".to_owned()]
    );
    assert_eq!(
        ok_rep.preserved_protected_worlds,
        vec!["w:high-loss-intruder".to_owned()]
    );
    assert!(ok_rep.dropped_protected_worlds.is_empty());
    assert!(ok_rep.stale_handoff_ids.is_empty());
    assert!(ok_rep.conflicting_work_claims.is_empty());
    assert!(
        ok_rep
            .decision_impact_delta_ids
            .contains(&"plan:p1".to_owned())
    );

    // 3. Faults: stale handoff (expected HWM 15 > 12), conflicting WorkClaim on same target,
    //    dropped protected world (removing WorldSafety edge), AND invalidated plan!
    let faulted = gagent.apply_deltas(
        anchor(802),
        ContentDigest::sha256(b"hist:802"),
        Generation(1),
        &scope,
        &[
            AgentGraphDelta::UpsertNode(Box::new(mk_node(
                "claim:c2-conflict",
                AgentNodeKind::WorkClaim,
                15,
                Some("target:door-back"),
                false,
            ))),
            AgentGraphDelta::RemoveEdge(AgentControlEdge {
                source_id: "ho:h1".to_owned(),
                target_id: "w:high-loss-intruder".to_owned(),
                kind: AgentEdgeKind::WorldSafety,
            }),
            AgentGraphDelta::AddEdge(AgentControlEdge {
                source_id: "inv:case-1".to_owned(),
                target_id: "plan:p1".to_owned(),
                kind: AgentEdgeKind::Invalidates,
            }),
        ],
        complete_absence(),
        || false,
    )?;
    let bad_rep =
        faulted.verify_handoff_closure("mission:night-watch", 15, 10, 10_000, || false)?;
    assert!(!bad_rep.closure_intact);
    assert_eq!(bad_rep.stale_handoff_ids, vec!["ho:h1".to_owned()]);
    assert_eq!(
        bad_rep.dropped_protected_worlds,
        vec!["w:high-loss-intruder".to_owned()]
    );
    assert_eq!(bad_rep.invalidated_plan_ids, vec!["plan:p1".to_owned()]);
    assert_eq!(
        bad_rep.conflicting_work_claims.get("target:door-back"),
        Some(&vec!["claim:c1".to_owned(), "claim:c2-conflict".to_owned()])
    );

    // 4. v1 -> v2 tombstone migration.
    let v1_bytes = faulted.to_legacy_v1_fixture_bytes(true)?;
    let (migrated, mig) = AgentControlGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(mig.migrated);
    assert_eq!(migrated.universe_digest(), faulted.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_agent\",\"req\":\"PROJ-AGENT-001\",\"healthy_closure\":{},\"faulted_stale\":{},\"faulted_conflicts\":{},\"faulted_dropped_worlds\":{}}}",
        ok_rep.closure_intact,
        bad_rep.stale_handoff_ids.len(),
        bad_rep.conflicting_work_claims.len(),
        bad_rep.dropped_protected_worlds.len()
    );
    Ok(())
}

#[test]
fn graph_projection_semantics_001_exhaustive_12_universe_crosswalk_no_lossy_collapse() -> TestResult
{
    assert_eq!(CANONICAL_PROJECTION_CROSSWALK.len(), 12);
    let mut universes = BTreeSet::new();
    let mut reqs = BTreeSet::new();
    let mut registry_names = BTreeSet::new();
    for entry in CANONICAL_PROJECTION_CROSSWALK {
        assert!(
            universes.insert(entry.universe),
            "duplicate universe in CANONICAL_PROJECTION_CROSSWALK: {:?}",
            entry.universe
        );
        assert!(
            reqs.insert(entry.projection_ref),
            "duplicate projection_ref in CANONICAL_PROJECTION_CROSSWALK: {}",
            entry.projection_ref
        );
        assert!(!entry.registry_projection_name.is_empty());
        assert!(!entry.preserved_distinction.is_empty());
        registry_names.insert(entry.registry_projection_name);
    }

    // All 12 normative typed graph universes MUST be present without collapse!
    let expected_universes = [
        GraphUniverse::GPhys,
        GraphUniverse::HVis,
        GraphUniverse::GSensor,
        GraphUniverse::GTime,
        GraphUniverse::GAssoc,
        GraphUniverse::GEvidence,
        GraphUniverse::GEffect,
        GraphUniverse::GObject,
        GraphUniverse::GAuth,
        GraphUniverse::GMemory,
        GraphUniverse::GAgent,
        GraphUniverse::GWorld,
    ];
    for u in expected_universes {
        assert!(universes.contains(&u), "missing universe {u:?}");
    }
    // Exactly the 10 machine-readable registry projections are covered cleanly (with 2 explicit
    // composed views: SpatioTemporalTrackGraph = G_time + G_assoc, IncidentCausalGraph = G_agent + G_world).
    assert_eq!(registry_names.len(), 10);

    // Cross-check against `architecture/graph_algorithms.json` so registry projection names never drift!
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let reg_path = manifest_dir.join("../../architecture/graph_algorithms.json");
    let reg_text = std::fs::read_to_string(&reg_path)?;
    for name in &registry_names {
        let quoted = format!("\"{name}\"");
        assert!(
            reg_text.contains(&quoted),
            "crosswalk registry projection {name} missing from architecture/graph_algorithms.json"
        );
    }

    println!(
        "CAPLOG {{\"epic\":\"GRAPH-PROJECTION-SEMANTICS-001\",\"typed_universes\":{},\"registry_projections\":{},\"lossless_crosswalk\":true}}",
        universes.len(),
        registry_names.len()
    );
    Ok(())
}
