#![forbid(unsafe_code)]
//! Contract, differential (incremental vs full rebuild), fault, compatibility/migration (`v1 -> v2`),
//! and realistic E2E proof suite for the four typed FSS graph projection universes:
//! - `H_vis` (`PROJ-VISIBILITY-001`, `fss-x4a.23.69.2`)
//! - `G_effect` (`PROJ-EFFECT-001`, `fss-x4a.23.69.7`)
//! - `G_auth` (`PROJ-AUTH-001`, `fss-x4a.23.69.9`)
//! - `G_world` (`PROJ-WORLD-001`, `fss-x4a.23.69.12`)

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{ContentDigest, Generation, LedgerAnchor, Plane, TimestampNs};
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, ProjectionAuthorityScope, ProjectionError,
};
use fss_graph_algorithms::typed_universes::g_auth::{
    AuthDelta, AuthEdgeKind, AuthEdgeSpec, AuthNodeKind, AuthNodeSpec, AuthorityGraph,
};
use fss_graph_algorithms::typed_universes::g_effect::{
    EffectCompletionVerdict, EffectDelta, EffectEdgeKind, EffectEdgeSpec, EffectNodeKind,
    EffectNodeSpec, EffectObligationGraph, EffectObligationState,
};
use fss_graph_algorithms::typed_universes::g_world::{
    AffordanceClass, CandidateWorldAction, PlanRevalidationOutcome, ProtectedWorldSpec, WorldDelta,
    WorldFactorEdge, WorldFactorGraph, WorldFactorKind, WorldFactorSpec,
    WorldHypothesisDisposition, WorldKnowledgeState, WorldProvenanceClass,
};
use fss_graph_algorithms::typed_universes::h_vis::{
    CodecQualityState, IlluminationWeather, LensHealthState, OccluderState, PoseFovStatus,
    SensorHealthPosture, VisibilityCoverageVerdict, VisibilityDelta, VisibilityFactor,
    VisibilityHypergraph,
};
use fss_graph_algorithms::typed_universes::{
    CURRENT_UNIVERSE_WIRE_VERSION, LEGACY_UNIVERSE_WIRE_VERSION, TypedUniverseError,
};

type TestResult = Result<(), Box<dyn Error>>;

fn anchor(seq: u64) -> LedgerAnchor {
    LedgerAnchor {
        site_lineage: "site:north-perimeter".to_owned(),
        ledger_epoch: 1,
        commit_sequence: seq,
        adapter_registry_epoch: 1,
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        state_root: ContentDigest::sha256(&seq.to_be_bytes()),
    }
}

fn complete_absence() -> AbsenceBoundary {
    AbsenceBoundary::CertifiedComplete {
        coverage_witness_digest: ContentDigest::sha256(b"cov-witness:complete-v1"),
    }
}

fn nominal_factor(id: &str, cam: &str, cell: &str, cal_gen: u64) -> VisibilityFactor {
    VisibilityFactor {
        factor_id: id.to_owned(),
        camera_id: cam.to_owned(),
        camera_generation: Generation(1),
        calibration_generation: Generation(cal_gen),
        target_cell_id: cell.to_owned(),
        target_class: "person".to_owned(),
        environment_regime: "driveway_day".to_owned(),
        sensor_health: SensorHealthPosture::Nominal,
        pose_fov: PoseFovStatus::InFrustumVerified,
        occluder_state: OccluderState::Clear,
        illumination_weather: IlluminationWeather::DayClear,
        lens_health: LensHealthState::Clean,
        target_height_cm: 175,
        target_direction: "inbound_north".to_owned(),
        codec_quality: CodecQualityState::High,
        detector_model_generation: Generation(3),
        detector_profile_id: "detector:yolox-s-v3".to_owned(),
        detector_degraded: false,
        detection_probability_bps: 9_200,
        uncertainty_bps: 350,
        valid_from_ns: TimestampNs(1_000),
        valid_until_ns: TimestampNs(10_000),
        failure_domains: ["power:poe-sw-1".to_owned(), "net:vlan-cam".to_owned()]
            .into_iter()
            .collect(),
        plane: Plane::Cognition,
    }
}

#[test]
fn h_vis_12d_factors_linked_bipartite_coverage_loss_incremental_parity_and_v1_migration()
-> TestResult {
    let scope = ProjectionAuthorityScope::active_for(GraphUniverse::HVis, 1, 1);
    let f_clear = nominal_factor("f-cam1-driveway", "cam-1", "cell-driveway", 2);
    let mut f_occluded = nominal_factor("f-cam2-gate-occluded", "cam-2", "cell-gate", 2);
    f_occluded.occluder_state = OccluderState::Occluded;
    let mut f_weather = nominal_factor("f-cam3-yard-fog", "cam-3", "cell-yard", 2);
    f_weather.illumination_weather = IlluminationWeather::SevereWeather;
    f_weather.lens_health = LensHealthState::SmudgedOrWet;
    f_weather.codec_quality = CodecQualityState::DroppedFrames;
    f_weather.detector_degraded = true;

    let hvis = VisibilityHypergraph::build(
        "proj:h-vis-site",
        Generation(1),
        anchor(10),
        ContentDigest::sha256(b"hist:10"),
        &scope,
        vec![f_clear.clone(), f_occluded.clone(), f_weather.clone()],
        complete_absence(),
        || false,
    )?;
    assert!(!hvis.grants_effect_authority());

    // 1. Nominal cell is CertifiedObservable; occluded/weather/degraded/missing/stale cells are
    //    UnknownUncertified — NEVER evidence of absence!
    let clear_cov = hvis.assess_cell_coverage(
        "cell-driveway",
        "person",
        TimestampNs(5_000),
        Some(Generation(2)),
        1_000,
        || false,
    )?;
    assert!(clear_cov.verdict.certifies_absence());
    assert!(!clear_cov.grants_effect_authority);
    assert!(!clear_cov.witness.grants_effect_authority());

    // Calibration invalidation turns clear cell into UnknownUncertified immediately!
    let stale_cal = hvis.assess_cell_coverage(
        "cell-driveway",
        "person",
        TimestampNs(5_000),
        Some(Generation(3)),
        1_000,
        || false,
    )?;
    assert!(!stale_cal.verdict.certifies_absence());
    assert!(matches!(
        stale_cal.verdict,
        VisibilityCoverageVerdict::UnknownUncertified { ref reasons, .. }
            if reasons.iter().any(|r| r == "calibration_generation_stale")
    ));

    // Occluded, degraded weather/lens/codec/detector, and missing target class NEVER certify absence!
    for (cell, cls, expected_reason) in [
        ("cell-gate", "person", "occluder_present_or_unknown"),
        ("cell-yard", "person", "illumination_weather_degraded"),
        ("cell-driveway", "vehicle", "missing_visibility_factor"),
    ] {
        let res = hvis.assess_cell_coverage(
            cell,
            cls,
            TimestampNs(5_000),
            Some(Generation(2)),
            1_000,
            || false,
        )?;
        assert!(!res.verdict.certifies_absence());
        assert!(matches!(
            res.verdict,
            VisibilityCoverageVerdict::UnknownUncertified { ref reasons, .. }
                if reasons.iter().any(|r| r == expected_reason)
        ));
    }

    // 2. Derived lossy camera<->cell bipartite projection retains links to native 12D factors!
    let bip =
        hvis.derive_camera_cell_bipartite(TimestampNs(5_000), Some(Generation(2)), 1_000, || {
            false
        })?;
    assert_eq!(bip.edges.len(), 3);
    assert!(bip.edges.iter().all(|e| e.is_lossy_bipartite_projection));
    assert!(bip.edges.iter().all(|e| !e.source_factor_ids.is_empty()));
    assert_eq!(bip.parent_h_vis_digest, hvis.universe_digest());

    // 3. Differential test: incremental delta update == full rebuild byte-for-byte!
    let mut f_clear_night = f_clear.clone();
    f_clear_night.illumination_weather = IlluminationWeather::NightIr;
    f_clear_night.target_height_cm = 120;
    let inc = hvis.apply_deltas(
        anchor(11),
        ContentDigest::sha256(b"hist:11"),
        Generation(1),
        &scope,
        &[
            VisibilityDelta::UpsertFactor(Box::new(f_clear_night.clone())),
            VisibilityDelta::RemoveFactor("f-cam3-yard-fog".to_owned()),
        ],
        complete_absence(),
        || false,
    )?;
    let full = VisibilityHypergraph::build(
        "proj:h-vis-site",
        Generation(1),
        anchor(11),
        ContentDigest::sha256(b"hist:11"),
        &scope,
        vec![f_occluded, f_clear_night],
        complete_absence(),
        || false,
    )?;
    assert_eq!(inc.universe_digest(), full.universe_digest());
    assert_eq!(
        inc.projection().generation(),
        full.projection().generation()
    );

    // 4. Compatibility & migration: v1 fixture migrates cleanly to v2 with tombstones; v99 quarantined!
    let v1_bytes = inc.to_legacy_v1_fixture_bytes(8_500)?;
    let (migrated, report) = VisibilityHypergraph::from_canonical_bytes(&v1_bytes)?;
    assert_eq!(report.source_version, LEGACY_UNIVERSE_WIRE_VERSION);
    assert_eq!(report.target_version, CURRENT_UNIVERSE_WIRE_VERSION);
    assert!(report.migrated);
    assert!(!report.tombstoned_fields.is_empty());
    assert_eq!(migrated.universe_digest(), inc.universe_digest());
    let mut v99 = inc.to_canonical_bytes()?;
    v99[8..12].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(
        VisibilityHypergraph::from_canonical_bytes(&v99).err(),
        Some(TypedUniverseError::UnsupportedVersion { version: 99 })
    );

    // 5. Faults: budget exhaustion, cancellation, privacy redaction downgrading absence boundary!
    assert!(matches!(
        inc.assess_cell_coverage(
            "cell-driveway",
            "person",
            TimestampNs(5_000),
            None,
            1,
            || false
        ),
        Err(TypedUniverseError::BudgetExhausted { .. })
    ));
    assert_eq!(
        inc.assess_cell_coverage(
            "cell-driveway",
            "person",
            TimestampNs(5_000),
            None,
            100,
            || true
        ),
        Err(TypedUniverseError::Cancelled)
    );
    let mut redacted_scope = scope;
    redacted_scope
        .redacted_node_ids
        .insert("factor/f-cam1-driveway".to_owned());
    let redacted_hvis = VisibilityHypergraph::build(
        "proj:h-vis-redacted",
        Generation(1),
        anchor(12),
        ContentDigest::sha256(b"hist:12"),
        &redacted_scope,
        vec![f_clear],
        complete_absence(),
        || false,
    )?;
    assert!(
        !redacted_hvis
            .projection()
            .absence_boundary()
            .certifies_absence()
    );
    let red_cov = redacted_hvis.assess_cell_coverage(
        "cell-driveway",
        "person",
        TimestampNs(5_000),
        Some(Generation(2)),
        100,
        || false,
    )?;
    assert!(!red_cov.verdict.certifies_absence());

    println!(
        "CAPLOG {{\"universe\":\"H_vis\",\"ref\":\"PROJ-VISIBILITY-001\",\"factors\":{},\"migrated_v1_to_v2\":true,\"witness_digest\":\"{}\",\"verdict\":\"ok\"}}",
        inc.visible_factors().len(),
        clear_cov.witness.digest().to_text()
    );
    Ok(())
}

fn eff_node(
    id: &str,
    kind: EffectNodeKind,
    key: &str,
    fence: u64,
    expected_fence: u64,
    dur: u64,
    state: EffectObligationState,
) -> EffectNodeSpec {
    EffectNodeSpec {
        node_id: id.to_owned(),
        kind,
        idempotency_key: key.to_owned(),
        lease_fence: fence,
        expected_lease_fence: expected_fence,
        authority_anchor: anchor(20),
        owner_principal: "agent:responder-1".to_owned(),
        duration_ms: dur,
        state,
        plane: if kind == EffectNodeKind::RecommendationPlan {
            Plane::Cognition
        } else {
            Plane::Effect
        },
    }
}

#[test]
fn g_effect_closed_loop_honest_completion_wait_cycles_stale_fences_and_v1_migration() -> TestResult
{
    let scope = ProjectionAuthorityScope::active_for(GraphUniverse::GEffect, 1, 1);

    // 1. E2E closed-loop prepare -> commit -> observe -> verify succeeds ONLY when verified!
    let nodes = vec![
        eff_node(
            "rec-1",
            EffectNodeKind::RecommendationPlan,
            "k-rec",
            1,
            1,
            5,
            EffectObligationState::NonAuthoritativeRecommendation,
        ),
        eff_node(
            "intent-1",
            EffectNodeKind::PreparedIntent,
            "k-alert-1",
            7,
            7,
            10,
            EffectObligationState::Verified,
        ),
        eff_node(
            "dispatch-1",
            EffectNodeKind::DispatchAttempt,
            "k-alert-1",
            7,
            7,
            40,
            EffectObligationState::Verified,
        ),
        eff_node(
            "obs-1",
            EffectNodeKind::Observation,
            "k-alert-1",
            7,
            7,
            15,
            EffectObligationState::Verified,
        ),
        eff_node(
            "verify-1",
            EffectNodeKind::VerificationPredicate,
            "k-alert-1",
            7,
            7,
            10,
            EffectObligationState::Verified,
        ),
    ];
    let edges = vec![
        EffectEdgeSpec {
            source_id: "rec-1".to_owned(),
            target_id: "intent-1".to_owned(),
            kind: EffectEdgeKind::Recommends,
        },
        EffectEdgeSpec {
            source_id: "intent-1".to_owned(),
            target_id: "dispatch-1".to_owned(),
            kind: EffectEdgeKind::MustPrecede,
        },
        EffectEdgeSpec {
            source_id: "dispatch-1".to_owned(),
            target_id: "obs-1".to_owned(),
            kind: EffectEdgeKind::MustPrecede,
        },
        EffectEdgeSpec {
            source_id: "obs-1".to_owned(),
            target_id: "verify-1".to_owned(),
            kind: EffectEdgeKind::MustPrecede,
        },
        EffectEdgeSpec {
            source_id: "verify-1".to_owned(),
            target_id: "dispatch-1".to_owned(),
            kind: EffectEdgeKind::Verifies,
        },
    ];
    let geff = EffectObligationGraph::build(
        "proj:g-effect-closed-loop",
        Generation(1),
        anchor(20),
        ContentDigest::sha256(b"hist:20"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    let ok = geff.analyze_obligations(1_000, || false)?;
    assert_eq!(ok.verdict, EffectCompletionVerdict::CompleteVerified);
    assert!(ok.deadlock_cycles.is_empty());
    assert_eq!(ok.critical_path_duration_ms, Some(75));
    assert!(!ok.grants_effect_authority);

    // A high-duration RecommendationPlan MUST NOT hijack the executable critical path!
    let mut rec_heavy = nodes.clone();
    rec_heavy[0].duration_ms = 99_999;
    let geff_rec_heavy = EffectObligationGraph::build(
        "proj:g-effect-rec-heavy",
        Generation(1),
        anchor(20),
        ContentDigest::sha256(b"hist:20"),
        &scope,
        rec_heavy,
        edges.clone(),
        complete_absence(),
        || false,
    )?;
    let ok_rec = geff_rec_heavy.analyze_obligations(1_000, || false)?;
    assert_eq!(ok_rec.critical_path_duration_ms, Some(75));
    assert_eq!(
        ok_rec.critical_path.as_deref(),
        Some(
            &[
                "intent-1".to_owned(),
                "dispatch-1".to_owned(),
                "obs-1".to_owned(),
                "verify-1".to_owned()
            ][..]
        )
    );

    // Recommendation trying to emit `Verifies` or `Fences` edge MUST fail closed!
    let bad_rec = EffectObligationGraph::build(
        "proj:bad-rec",
        Generation(1),
        anchor(20),
        ContentDigest::sha256(b"hist:20"),
        &scope,
        nodes.clone(),
        vec![EffectEdgeSpec {
            source_id: "rec-1".to_owned(),
            target_id: "dispatch-1".to_owned(),
            kind: EffectEdgeKind::Verifies,
        }],
        complete_absence(),
        || false,
    );
    assert!(matches!(
        bad_rec,
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 2. Open-loop dispatch (Dispatched / Lost ACK -> Indeterminate) CANNOT be reported complete!
    let lost_ack = geff.apply_deltas(
        anchor(21),
        ContentDigest::sha256(b"hist:21"),
        Generation(1),
        &scope,
        &[EffectDelta::UpsertNode(eff_node(
            "dispatch-1",
            EffectNodeKind::DispatchAttempt,
            "k-alert-1",
            7,
            7,
            40,
            EffectObligationState::Indeterminate,
        ))],
        complete_absence(),
        || false,
    )?;
    let indet = lost_ack.analyze_obligations(1_000, || false)?;
    assert_eq!(
        indet.verdict,
        EffectCompletionVerdict::IndeterminateRequiresReconciliation
    );
    assert_eq!(indet.indeterminate_nodes, vec!["dispatch-1".to_owned()]);

    // 3. Wait cycle, stale fence, duplicate commit key, compensation failure, & clean cancel potential!
    let fault_nodes = vec![
        eff_node(
            "a",
            EffectNodeKind::CleanupObligation,
            "k-a",
            1,
            2,
            10,
            EffectObligationState::Prepared,
        ), // stale fence
        eff_node(
            "b",
            EffectNodeKind::CleanupObligation,
            "k-b",
            2,
            2,
            10,
            EffectObligationState::Prepared,
        ), // cleanly cancellable
        eff_node(
            "d1",
            EffectNodeKind::DispatchAttempt,
            "k-dup",
            3,
            3,
            10,
            EffectObligationState::Dispatched,
        ),
        eff_node(
            "d2",
            EffectNodeKind::DispatchAttempt,
            "k-dup",
            3,
            3,
            10,
            EffectObligationState::Failed,
        ),
    ];
    let fault_edges = vec![
        EffectEdgeSpec {
            source_id: "a".to_owned(),
            target_id: "b".to_owned(),
            kind: EffectEdgeKind::WaitsFor,
        },
        EffectEdgeSpec {
            source_id: "b".to_owned(),
            target_id: "a".to_owned(),
            kind: EffectEdgeKind::WaitsFor,
        },
    ];
    let fault_g = EffectObligationGraph::build(
        "proj:g-effect-faults",
        Generation(1),
        anchor(22),
        ContentDigest::sha256(b"hist:22"),
        &scope,
        fault_nodes,
        fault_edges,
        complete_absence(),
        || false,
    )?;
    let fa = fault_g.analyze_obligations(1_000, || false)?;
    assert_eq!(fa.verdict, EffectCompletionVerdict::IncompleteOrBlocked);
    assert_eq!(
        fa.deadlock_cycles,
        vec![vec!["a".to_owned(), "b".to_owned()]]
    );
    assert_eq!(fa.stale_fence_nodes, vec!["a".to_owned()]);
    assert_eq!(fa.cleanly_cancellable_nodes, vec!["b".to_owned()]);
    assert_eq!(fa.duplicate_commit_keys, vec!["k-dup".to_owned()]);
    assert_eq!(fa.uncompensated_failures, vec!["d2".to_owned()]);
    assert!(fa.critical_path.is_none());

    // 4. Incremental vs full-rebuild parity + v1->v2 migration + unknown-version quarantine!
    let full_lost = EffectObligationGraph::build(
        "proj:g-effect-closed-loop",
        Generation(1),
        anchor(21),
        ContentDigest::sha256(b"hist:21"),
        &scope,
        vec![
            nodes[0].clone(),
            nodes[1].clone(),
            eff_node(
                "dispatch-1",
                EffectNodeKind::DispatchAttempt,
                "k-alert-1",
                7,
                7,
                40,
                EffectObligationState::Indeterminate,
            ),
            nodes[3].clone(),
            nodes[4].clone(),
        ],
        edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(lost_ack.universe_digest(), full_lost.universe_digest());

    let v1_bytes = geff.to_legacy_v1_fixture_bytes(true)?;
    let (mig, rep) = EffectObligationGraph::from_canonical_bytes(&v1_bytes)?;
    assert!(rep.migrated);
    assert_eq!(mig.universe_digest(), geff.universe_digest());

    println!(
        "CAPLOG {{\"universe\":\"G_effect\",\"ref\":\"PROJ-EFFECT-001\",\"deadlocks\":{},\"witness_digest\":\"{}\",\"verdict\":\"ok\"}}",
        fa.deadlock_cycles.len(),
        ok.witness.digest().to_text()
    );
    Ok(())
}

fn auth_node(
    id: &str,
    kind: AuthNodeKind,
    prop: &str,
    scopes: &[&str],
    exp: i128,
    revoked: bool,
) -> AuthNodeSpec {
    AuthNodeSpec {
        node_id: id.to_owned(),
        kind,
        property_id: prop.to_owned(),
        scope_tags: scopes.iter().map(|s| (*s).to_owned()).collect(),
        expires_at_ns: TimestampNs(exp),
        revoked,
        plane: Plane::Authority,
    }
}

#[test]
fn g_auth_monotone_narrowing_noninterference_cache_partitioning_and_v1_migration() -> TestResult {
    let scope = ProjectionAuthorityScope::active_for(GraphUniverse::GAuth, 1, 7);

    let nodes = vec![
        auth_node(
            "p:owner",
            AuthNodeKind::Principal,
            "prop-alpha",
            &["cam:front", "cam:back", "alert:send"],
            100_000,
            false,
        ),
        auth_node(
            "p:guest",
            AuthNodeKind::Principal,
            "prop-alpha",
            &["cam:front"],
            50_000,
            false,
        ),
        auth_node(
            "pol:front-only",
            AuthNodeKind::Policy,
            "prop-alpha",
            &["cam:front"],
            100_000,
            false,
        ),
        auth_node(
            "res:front-cam",
            AuthNodeKind::ScopedResource,
            "prop-alpha",
            &["cam:front"],
            100_000,
            false,
        ),
        auth_node(
            "res:back-cam",
            AuthNodeKind::ScopedResource,
            "prop-alpha",
            &["cam:back"],
            100_000,
            false,
        ),
        auth_node(
            "eff:send-alert",
            AuthNodeKind::Effect,
            "prop-alpha",
            &["alert:send"],
            100_000,
            false,
        ),
        auth_node(
            "claim:work-1",
            AuthNodeKind::WorkClaim,
            "prop-alpha",
            &["alert:send"],
            100_000,
            false,
        ),
    ];
    let edges = vec![
        AuthEdgeSpec {
            source_id: "p:guest".to_owned(),
            target_id: "p:owner".to_owned(),
            kind: AuthEdgeKind::DelegatedFrom,
            expires_at_ns: TimestampNs(50_000),
            revoked: false,
        },
        AuthEdgeSpec {
            source_id: "p:guest".to_owned(),
            target_id: "pol:front-only".to_owned(),
            kind: AuthEdgeKind::NarrowedBy,
            expires_at_ns: TimestampNs(50_000),
            revoked: false,
        },
        AuthEdgeSpec {
            source_id: "p:owner".to_owned(),
            target_id: "res:front-cam".to_owned(),
            kind: AuthEdgeKind::MayRead,
            expires_at_ns: TimestampNs(100_000),
            revoked: false,
        },
        AuthEdgeSpec {
            source_id: "p:owner".to_owned(),
            target_id: "res:back-cam".to_owned(),
            kind: AuthEdgeKind::MayRead,
            expires_at_ns: TimestampNs(100_000),
            revoked: false,
        },
        AuthEdgeSpec {
            source_id: "p:owner".to_owned(),
            target_id: "eff:send-alert".to_owned(),
            kind: AuthEdgeKind::MayCommit,
            expires_at_ns: TimestampNs(100_000),
            revoked: false,
        },
        AuthEdgeSpec {
            source_id: "p:guest".to_owned(),
            target_id: "res:front-cam".to_owned(),
            kind: AuthEdgeKind::MayRead,
            expires_at_ns: TimestampNs(50_000),
            revoked: false,
        },
        // Confused-deputy attempt: guest has edge to back-cam, but guest's narrowed scope lacks `cam:back`!
        AuthEdgeSpec {
            source_id: "p:guest".to_owned(),
            target_id: "res:back-cam".to_owned(),
            kind: AuthEdgeKind::MayRead,
            expires_at_ns: TimestampNs(50_000),
            revoked: false,
        },
    ];

    let gauth = AuthorityGraph::build(
        "proj:g-auth-alpha",
        Generation(1),
        anchor(30),
        ContentDigest::sha256(b"hist:30"),
        &scope,
        nodes.clone(),
        edges.clone(),
        complete_absence(),
        || false,
    )?;

    // 1. E2E two-principal noninterference proof: guest sees ONLY front-cam (visible_degree=1),
    //    distinct cache_partition_key, and witness node_count/edge_count leak ZERO hidden nodes!
    let v_owner =
        gauth.query_principal_view("p:owner", TimestampNs(10_000), 1_000, || false, || false)?;
    let v_guest =
        gauth.query_principal_view("p:guest", TimestampNs(10_000), 1_000, || false, || false)?;
    assert_eq!(v_owner.visible_degree, 3);
    assert_eq!(
        v_owner.committable_effects,
        ["eff:send-alert".to_owned()].into_iter().collect()
    );
    assert_eq!(v_guest.visible_degree, 1);
    assert_eq!(
        v_guest.readable_resources,
        ["res:front-cam".to_owned()].into_iter().collect()
    );
    assert!(v_guest.committable_effects.is_empty());
    assert_ne!(v_owner.cache_partition_key, v_guest.cache_partition_key);
    assert_eq!(v_guest.witness.node_count(), 2); // ONLY p:guest + res:front-cam!

    // Adding a secret hidden camera to owner does NOT change guest's view, degree, or cache key!
    let with_secret = gauth.apply_deltas(
        anchor(31),
        ContentDigest::sha256(b"hist:31"),
        Generation(1),
        &scope,
        &[
            AuthDelta::UpsertNode(auth_node(
                "res:vault-cam",
                AuthNodeKind::ScopedResource,
                "prop-alpha",
                &["cam:back"],
                100_000,
                false,
            )),
            AuthDelta::AddEdge(AuthEdgeSpec {
                source_id: "p:owner".to_owned(),
                target_id: "res:vault-cam".to_owned(),
                kind: AuthEdgeKind::MayRead,
                expires_at_ns: TimestampNs(100_000),
                revoked: false,
            }),
        ],
        complete_absence(),
        || false,
    )?;
    let v_guest_after = with_secret.query_principal_view(
        "p:guest",
        TimestampNs(10_000),
        1_000,
        || false,
        || false,
    )?;
    assert_eq!(
        v_guest.cache_partition_key,
        v_guest_after.cache_partition_key
    );
    assert_eq!(v_guest.visible_degree, v_guest_after.visible_degree);
    assert_eq!(
        v_guest.witness.output_digest(),
        v_guest_after.witness.output_digest()
    );
    // True capability noninterference across anchors: cache partition key, visible degree,
    // output digest, decision path, and witness operation counts stay invariant to hidden edges
    // added on `p:owner`!
    assert_eq!(
        v_guest.witness.dominant_operation_counts(),
        v_guest_after.witness.dominant_operation_counts()
    );
    assert_eq!(
        v_guest.witness.decision_path_digest(),
        v_guest_after.witness.decision_path_digest()
    );
    // And at the exact SAME anchor, even the complete witness digest is bit-for-bit identical!
    let mut same_anchor_nodes = nodes.clone();
    same_anchor_nodes.push(auth_node(
        "res:vault-cam",
        AuthNodeKind::ScopedResource,
        "prop-alpha",
        &["cam:back"],
        100_000,
        false,
    ));
    let mut same_anchor_edges = edges.clone();
    same_anchor_edges.push(AuthEdgeSpec {
        source_id: "p:owner".to_owned(),
        target_id: "res:vault-cam".to_owned(),
        kind: AuthEdgeKind::MayRead,
        expires_at_ns: TimestampNs(100_000),
        revoked: false,
    });
    let same_anchor_with_secret = AuthorityGraph::build(
        "proj:g-auth-alpha",
        Generation(1),
        anchor(30),
        ContentDigest::sha256(b"hist:30-secret"),
        &scope,
        same_anchor_nodes,
        same_anchor_edges,
        complete_absence(),
        || false,
    )?;
    let v_guest_same_anchor = same_anchor_with_secret.query_principal_view(
        "p:guest",
        TimestampNs(10_000),
        1_000,
        || false,
        || false,
    )?;
    assert_eq!(
        v_guest.witness.digest(),
        v_guest_same_anchor.witness.digest()
    );

    // Fail-closed narrowing: revoking a narrowing policy MUST fail closed, never widen scope!
    let mut revoked_pol = auth_node(
        "pol:front-only",
        AuthNodeKind::Policy,
        "prop-alpha",
        &["cam:front"],
        100_000,
        true,
    );
    revoked_pol.revoked = true;
    let gauth_revoked_pol = gauth.apply_deltas(
        anchor(32),
        ContentDigest::sha256(b"hist:32"),
        Generation(1),
        &scope,
        &[AuthDelta::UpsertNode(revoked_pol)],
        complete_absence(),
        || false,
    )?;
    assert!(matches!(
        gauth_revoked_pol.query_principal_view(
            "p:guest",
            TimestampNs(10_000),
            1_000,
            || false,
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 2. WorkClaim / ATP / Recommendation / Cognition CANNOT carry MayCommit!
    let mut bad_claim_edges = edges.clone();
    bad_claim_edges.push(AuthEdgeSpec {
        source_id: "claim:work-1".to_owned(),
        target_id: "eff:send-alert".to_owned(),
        kind: AuthEdgeKind::MayCommit,
        expires_at_ns: TimestampNs(100_000),
        revoked: false,
    });
    assert!(matches!(
        AuthorityGraph::build(
            "proj:bad-claim",
            Generation(1),
            anchor(30),
            ContentDigest::sha256(b"h"),
            &scope,
            nodes.clone(),
            bad_claim_edges,
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 3. Delegation escalation, cross-property leak, delegation cycle, expiry, and mid-query revocation fail closed!
    let mut esc_nodes = nodes.clone();
    esc_nodes[1].scope_tags.insert("admin:root".to_owned());
    assert!(matches!(
        AuthorityGraph::build(
            "proj:esc",
            Generation(1),
            anchor(30),
            ContentDigest::sha256(b"h"),
            &scope,
            esc_nodes,
            edges.clone(),
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    let mut cross_nodes = nodes.clone();
    cross_nodes.push(auth_node(
        "res:other-prop",
        AuthNodeKind::ScopedResource,
        "prop-beta",
        &["cam:front"],
        100_000,
        false,
    ));
    let mut cross_edges = edges.clone();
    cross_edges.push(AuthEdgeSpec {
        source_id: "p:owner".to_owned(),
        target_id: "res:other-prop".to_owned(),
        kind: AuthEdgeKind::MayRead,
        expires_at_ns: TimestampNs(100_000),
        revoked: false,
    });
    assert!(matches!(
        AuthorityGraph::build(
            "proj:cross",
            Generation(1),
            anchor(30),
            ContentDigest::sha256(b"h"),
            &scope,
            cross_nodes,
            cross_edges,
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    let cyc_nodes = vec![
        auth_node(
            "p:a",
            AuthNodeKind::Principal,
            "prop-alpha",
            &["x"],
            10_000,
            false,
        ),
        auth_node(
            "p:b",
            AuthNodeKind::Principal,
            "prop-alpha",
            &["x"],
            10_000,
            false,
        ),
    ];
    let cyc_edges = vec![
        AuthEdgeSpec {
            source_id: "p:a".to_owned(),
            target_id: "p:b".to_owned(),
            kind: AuthEdgeKind::DelegatedFrom,
            expires_at_ns: TimestampNs(10_000),
            revoked: false,
        },
        AuthEdgeSpec {
            source_id: "p:b".to_owned(),
            target_id: "p:a".to_owned(),
            kind: AuthEdgeKind::DelegatedFrom,
            expires_at_ns: TimestampNs(10_000),
            revoked: false,
        },
    ];
    assert!(matches!(
        AuthorityGraph::build(
            "proj:cyc",
            Generation(1),
            anchor(30),
            ContentDigest::sha256(b"h"),
            &scope,
            cyc_nodes,
            cyc_edges,
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    assert!(matches!(
        gauth.query_principal_view("p:guest", TimestampNs(50_001), 1_000, || false, || false),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));
    assert!(matches!(
        gauth.query_principal_view("p:owner", TimestampNs(10_000), 1_000, || true, || false),
        Err(TypedUniverseError::AuthorityViolation(_))
    ));

    // 4. v1 -> v2 migration + stale authority generation refusal!
    let v1 = gauth.to_legacy_v1_fixture_bytes(true)?;
    let (mig, rep) = AuthorityGraph::from_canonical_bytes(&v1)?;
    assert!(rep.migrated);
    assert_eq!(mig.universe_digest(), gauth.universe_digest());

    let mut stale_scope = scope;
    stale_scope.expected_authority_generation = 999;
    assert!(matches!(
        AuthorityGraph::build(
            "proj:stale",
            Generation(1),
            anchor(30),
            ContentDigest::sha256(b"h"),
            &stale_scope,
            nodes,
            edges,
            complete_absence(),
            || false
        ),
        Err(TypedUniverseError::Projection(
            ProjectionError::StaleAuthorityGeneration { .. }
        ))
    ));

    println!(
        "CAPLOG {{\"universe\":\"G_auth\",\"ref\":\"PROJ-AUTH-001\",\"owner_degree\":{},\"guest_degree\":{},\"witness_digest\":\"{}\",\"verdict\":\"ok\"}}",
        v_owner.visible_degree,
        v_guest.visible_degree,
        v_guest.witness.digest().to_text()
    );
    Ok(())
}

#[test]
fn g_world_protected_high_loss_survival_affordance_classification_plan_invalidation_and_v1_migration()
-> TestResult {
    let scope = ProjectionAuthorityScope::active_for(GraphUniverse::GWorld, 1, 1);

    let f_core = WorldFactorSpec {
        factor_id: "w:core-motion-driveway".to_owned(),
        kind: WorldFactorKind::CertifiedCoreClaim,
        knowledge_state: WorldKnowledgeState::Certified,
        provenance_class: WorldProvenanceClass::SourceRetained,
        disposition: WorldHypothesisDisposition::Supported,
        plausibility_ppm: 950_000,
        protected_world: None,
        plane: Plane::Cognition,
    };
    let f_benign = WorldFactorSpec {
        factor_id: "w:alt-delivery-driver".to_owned(),
        kind: WorldFactorKind::MaterialAlternative,
        knowledge_state: WorldKnowledgeState::Hypothesized,
        provenance_class: WorldProvenanceClass::DerivedCognition,
        disposition: WorldHypothesisDisposition::ActiveAlternative,
        plausibility_ppm: 880_000,
        protected_world: None,
        plane: Plane::Cognition,
    };
    // Low-probability (2%) HIGH-LOSS protected possible world: authorized resident returning in dark!
    let f_protected_resident = WorldFactorSpec {
        factor_id: "w:protected-resident-returning".to_owned(),
        kind: WorldFactorKind::UnsafeWorldRelation,
        knowledge_state: WorldKnowledgeState::Unknown,
        provenance_class: WorldProvenanceClass::DerivedCognition,
        disposition: WorldHypothesisDisposition::ProtectedHighLoss,
        plausibility_ppm: 20_000,
        protected_world: Some(ProtectedWorldSpec {
            loss_severity_bps: 9_500,
            impossibility_proof: None,
            safe_dominance_proof: None,
        }),
        plane: Plane::Cognition,
    };
    let f_probe = WorldFactorSpec {
        factor_id: "w:probe-second-angle-ir".to_owned(),
        kind: WorldFactorKind::BranchCollapsingProbe,
        knowledge_state: WorldKnowledgeState::Observed,
        provenance_class: WorldProvenanceClass::SourceRetained,
        disposition: WorldHypothesisDisposition::Supported,
        plausibility_ppm: 500_000,
        protected_world: None,
        plane: Plane::Cognition,
    };

    let edges = vec![
        WorldFactorEdge {
            source_id: "w:probe-second-angle-ir".to_owned(),
            target_id: "w:protected-resident-returning".to_owned(),
            relation: "collapses_branch".to_owned(),
        },
        WorldFactorEdge {
            source_id: "w:alt-delivery-driver".to_owned(),
            target_id: "w:protected-resident-returning".to_owned(),
            relation: "contradicts".to_owned(),
        },
    ];

    let gworld = WorldFactorGraph::build(
        "proj:g-world-ambiguous-intrusion",
        Generation(1),
        anchor(40),
        ContentDigest::sha256(b"hist:40"),
        &scope,
        vec![
            f_core.clone(),
            f_benign.clone(),
            f_protected_resident.clone(),
            f_probe.clone(),
        ],
        edges.clone(),
        complete_absence(),
        || false,
    )?;

    // 1. Model rerank + aggressive compression budget=2 MUST preserve the low-probability high-loss
    //    protected world; budget=0 MUST fail closed instead of hiding it!
    let mut adversarial_rerank = BTreeMap::new();
    adversarial_rerank.insert("w:protected-resident-returning".to_owned(), 1_u32);
    adversarial_rerank.insert("w:alt-delivery-driver".to_owned(), 999_999_u32);
    let handoff = gworld.project_compressed_handoff(2, &adversarial_rerank, 1_000, || false)?;
    assert_eq!(handoff.retained_factors.len(), 2);
    assert_eq!(
        handoff.preserved_protected_worlds,
        vec!["w:protected-resident-returning".to_owned()]
    );
    assert!(
        handoff
            .retained_factors
            .iter()
            .any(|f| f.factor_id == "w:protected-resident-returning")
    );
    assert!(!handoff.grants_effect_authority);
    assert!(matches!(
        gworld.project_compressed_handoff(0, &adversarial_rerank, 1_000, || false),
        Err(TypedUniverseError::ProtectedWorldDeletionForbidden(_))
    ));

    // Attempting to delete the unproven protected world via delta fails closed!
    assert!(matches!(
        gworld.apply_deltas(
            anchor(41),
            ContentDigest::sha256(b"hist:41"),
            Generation(1),
            &scope,
            &[WorldDelta::RemoveFactor(
                "w:protected-resident-returning".to_owned()
            )],
            complete_absence(),
            || false,
        ),
        Err(TypedUniverseError::ProtectedWorldDeletionForbidden(_))
    ));

    // 2. E2E ambiguous intrusion affordance classification: siren/lockdown hitting protected unsafe
    //    world is BLOCKED; information-gathering probe & robust evidence-retention are ADMITTED!
    let actions = vec![
        CandidateWorldAction {
            action_id: "act:1-siren-alarm".to_owned(),
            supported_worlds: ["w:core-motion-driveway".to_owned()].into_iter().collect(),
            unsafe_worlds: ["w:protected-resident-returning".to_owned()]
                .into_iter()
                .collect(),
            is_information_gathering_probe: false,
            is_wait_watch: false,
            capability_available: true,
            hard_clamped: false,
        },
        CandidateWorldAction {
            action_id: "act:2-probe-second-cam".to_owned(),
            supported_worlds: [
                "w:core-motion-driveway".to_owned(),
                "w:probe-second-angle-ir".to_owned(),
            ]
            .into_iter()
            .collect(),
            unsafe_worlds: BTreeSet::new(),
            is_information_gathering_probe: true,
            is_wait_watch: false,
            capability_available: true,
            hard_clamped: false,
        },
        CandidateWorldAction {
            action_id: "act:3-pin-evidence-clip".to_owned(),
            supported_worlds: ["w:core-motion-driveway".to_owned()].into_iter().collect(),
            unsafe_worlds: BTreeSet::new(),
            is_information_gathering_probe: false,
            is_wait_watch: false,
            capability_available: true,
            hard_clamped: false,
        },
        CandidateWorldAction {
            action_id: "act:4-wait-watch".to_owned(),
            supported_worlds: ["w:core-motion-driveway".to_owned()].into_iter().collect(),
            unsafe_worlds: BTreeSet::new(),
            is_information_gathering_probe: false,
            is_wait_watch: true,
            capability_available: true,
            hard_clamped: false,
        },
        CandidateWorldAction {
            action_id: "act:5-ptz-offline".to_owned(),
            supported_worlds: ["w:core-motion-driveway".to_owned()].into_iter().collect(),
            unsafe_worlds: BTreeSet::new(),
            is_information_gathering_probe: true,
            is_wait_watch: false,
            capability_available: false,
            hard_clamped: false,
        },
        CandidateWorldAction {
            action_id: "act:6-conditional-chime".to_owned(),
            supported_worlds: ["w:alt-delivery-driver".to_owned()].into_iter().collect(),
            unsafe_worlds: ["w:alt-delivery-driver".to_owned()].into_iter().collect(),
            is_information_gathering_probe: false,
            is_wait_watch: false,
            capability_available: true,
            hard_clamped: false,
        },
    ];
    let (classified, witness) = gworld.classify_affordances(&actions, 1_000, || false)?;
    // Insertion-order invariance: reversed candidate slice yields bit-identical witness digest!
    let mut actions_rev = actions.clone();
    actions_rev.reverse();
    let (classified_rev, witness_rev) =
        gworld.classify_affordances(&actions_rev, 1_000, || false)?;
    assert_eq!(classified, classified_rev);
    assert_eq!(witness.digest(), witness_rev.digest());

    // Duplicate action_id refused fail-closed!
    let mut dup_actions = actions.clone();
    dup_actions.push(actions[0].clone());
    assert!(matches!(
        gworld.classify_affordances(&dup_actions, 1_000, || false),
        Err(TypedUniverseError::InvalidInput(_))
    ));

    // Stale affordance missing a newly added protected world refused by bind_plan!
    let mut stale_aff = classified[1].clone();
    stale_aff.checked_protected_worlds.clear();
    assert!(matches!(
        gworld.bind_plan("plan:stale-aff", &stale_aff),
        Err(TypedUniverseError::MixedAnchorOrGeneration(_))
    ));
    assert_eq!(classified[0].classification, AffordanceClass::Blocked); // siren blocked by protected unsafe world!
    assert_eq!(
        classified[1].classification,
        AffordanceClass::InformationGathering
    );
    assert_eq!(classified[2].classification, AffordanceClass::Robust);
    assert_eq!(classified[3].classification, AffordanceClass::WaitWatch);
    assert_eq!(classified[4].classification, AffordanceClass::Unavailable);
    assert_eq!(classified[5].classification, AffordanceClass::Conditional);

    // 3. Plan binding & conditional-plan invalidation on stale envelope / contradiction!
    assert!(gworld.bind_plan("plan:blocked", &classified[0]).is_err());
    let plan = gworld.bind_plan("plan:probe-ir", &classified[1])?;
    assert!(!plan.grants_effect_authority);
    assert_eq!(
        gworld.revalidate_plan(&plan),
        PlanRevalidationOutcome::Valid
    );

    // New contradictory evidence mutates the envelope -> stale plan is invalidated!
    let mut f_core_conflicted = f_core;
    f_core_conflicted.knowledge_state = WorldKnowledgeState::Conflicted;
    let updated = gworld.apply_deltas(
        anchor(42),
        ContentDigest::sha256(b"hist:42"),
        Generation(1),
        &scope,
        &[WorldDelta::UpsertFactor(f_core_conflicted.clone())],
        complete_absence(),
        || false,
    )?;
    assert!(matches!(
        updated.revalidate_plan(&plan),
        PlanRevalidationOutcome::Invalidated { ref reasons }
            if reasons.iter().any(|r| r == "stale_world_envelope_digest")
    ));

    // Differential parity: incremental == full rebuild!
    let full_updated = WorldFactorGraph::build(
        "proj:g-world-ambiguous-intrusion",
        Generation(1),
        anchor(42),
        ContentDigest::sha256(b"hist:42"),
        &scope,
        vec![f_core_conflicted, f_benign, f_protected_resident, f_probe],
        edges,
        complete_absence(),
        || false,
    )?;
    assert_eq!(
        updated.world_envelope_digest(),
        full_updated.world_envelope_digest()
    );

    // 4. v1 -> v2 migration + checksum tamper refusal!
    let v1 = gworld.to_legacy_v1_fixture_bytes(true)?;
    let (mig, rep) = WorldFactorGraph::from_canonical_bytes(&v1)?;
    assert!(rep.migrated);
    assert_eq!(mig.world_envelope_digest(), gworld.world_envelope_digest());
    let mut tampered = gworld.to_canonical_bytes()?;
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert_eq!(
        WorldFactorGraph::from_canonical_bytes(&tampered).err(),
        Some(TypedUniverseError::ChecksumMismatch)
    );

    println!(
        "CAPLOG {{\"universe\":\"G_world\",\"ref\":\"PROJ-WORLD-001\",\"protected_preserved\":{},\"witness_digest\":\"{}\",\"verdict\":\"ok\"}}",
        handoff.preserved_protected_worlds.len(),
        witness.digest().to_text()
    );
    Ok(())
}
