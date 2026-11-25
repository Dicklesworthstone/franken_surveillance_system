#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-151` (`fss-x4a.23.1`): immutable graph projection and
//! generational-handle core across all 12 registered FSS graph universes.

use fss_core::{ContentDigest, LedgerAnchor, Plane};
use fss_graph_algorithms::bridges::{GraphBudget, analyse_bridges};
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, IMMUTABLE_PROJECTION_DOMAIN, ImmutableGraphProjection,
    PROJECTION_WIRE_MAGIC, PROJECTION_WIRE_VERSION, ProjectionAuthorityScope, ProjectionEdgeSpec,
    ProjectionError, ProjectionGuidance, ProjectionNodeSpec, ProjectionOrientation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn anchor_at(seq: u64) -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site-north");
    anchor.commit_sequence = seq;
    anchor.state_root = ContentDigest::sha256(format!("state-root:{seq}").as_bytes());
    anchor
}

fn history_at(seq: u64) -> ContentDigest {
    ContentDigest::sha256(format!("history:{seq}").as_bytes())
}

fn node(id: &str, plane: Plane, tag: &str) -> ProjectionNodeSpec {
    ProjectionNodeSpec {
        node_id: id.to_owned(),
        plane,
        payload_digest: ContentDigest::sha256(tag.as_bytes()),
    }
}

fn edge(src: &str, dst: &str, rel: &str, weight: u64) -> ProjectionEdgeSpec {
    ProjectionEdgeSpec {
        source_id: src.to_owned(),
        target_id: dst.to_owned(),
        relation: rel.to_owned(),
        weight,
    }
}

#[test]
fn insertion_order_invariance_all_12_universes_bridge_integration_and_handles() -> TestResult {
    // 1. Verify all 12 registered FSS universes are distinct and carry distinct digests
    //    even for identical underlying node/edge sets (never collapsed into one untyped graph).
    let all_universes = [
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
    let mut universe_digests = std::collections::BTreeSet::new();
    let cov_digest = ContentDigest::sha256(b"coverage:complete:seq4");
    for universe in all_universes {
        let auth = ProjectionAuthorityScope::active_for(universe, 3, 1);
        let proj = ImmutableGraphProjection::build(
            universe,
            ProjectionOrientation::Undirected,
            anchor_at(4),
            history_at(4),
            &auth,
            vec![
                node("cam-a", Plane::Authority, "p-a"),
                node("zone-1", Plane::Cognition, "p-z1"),
            ],
            vec![edge("cam-a", "zone-1", "covers", 10)],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        )?;
        assert_eq!(proj.universe(), universe);
        assert!(proj.absence_boundary().certifies_absence());
        assert!(
            universe_digests.insert(proj.generation().projection_digest),
            "universe {} collided with another universe's digest",
            universe.as_str()
        );
    }
    assert_eq!(universe_digests.len(), 12);

    // 2. Insertion-order invariance (CGSE canonical tie-break): reversed nodes & edges and
    //    swapped undirected endpoints produce byte-identical wire encodings and digests.
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 7, 2);
    let nodes_fwd = vec![
        node("switch-core", Plane::Authority, "sw"),
        node("cam-1", Plane::Authority, "c1"),
        node("cam-2", Plane::Authority, "c2"),
        node("zone-gate", Plane::Cognition, "zg"),
    ];
    let edges_fwd = vec![
        edge("switch-core", "cam-1", "feeds", 1),
        edge("switch-core", "cam-2", "feeds", 1),
        edge("cam-1", "zone-gate", "observes", 5),
        edge("cam-2", "zone-gate", "observes", 5),
    ];

    let nodes_rev: Vec<_> = nodes_fwd.iter().rev().cloned().collect();
    let edges_rev = vec![
        edge("zone-gate", "cam-2", "observes", 5),
        edge("zone-gate", "cam-1", "observes", 5),
        edge("cam-2", "switch-core", "feeds", 1),
        edge("cam-1", "switch-core", "feeds", 1),
    ];

    let p_fwd = ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at(10),
        history_at(10),
        &auth,
        nodes_fwd,
        edges_fwd,
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )?;
    let p_rev = ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at(10),
        history_at(10),
        &auth,
        nodes_rev,
        edges_rev,
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )?;

    assert_eq!(p_fwd, p_rev);
    assert_eq!(p_fwd.generation(), p_rev.generation());
    assert_eq!(p_fwd.to_canonical_bytes()?, p_rev.to_canonical_bytes()?);
    assert_eq!(
        IMMUTABLE_PROJECTION_DOMAIN,
        "fss.graph.immutable_projection.v1"
    );

    // 3. Generational handle dereferencing & neighbor expansion in canonical ascending order.
    let h_cam1 = p_fwd
        .handle_for_node_id("cam-1")
        .expect("cam-1 handle present");
    assert_eq!(p_fwd.node(h_cam1)?.node_id, "cam-1");
    let nbrs = p_fwd.neighbors(h_cam1)?;
    assert_eq!(nbrs.len(), 2);
    let nbr_ids: Vec<&str> = nbrs
        .iter()
        .map(|(nh, _)| p_fwd.node(*nh).expect("valid nbr").node_id.as_str())
        .collect();
    assert_eq!(nbr_ids, vec!["switch-core", "zone-gate"]);
    for (_, eh) in &nbrs {
        let e = p_fwd.edge(*eh)?;
        assert!(e.relation == "feeds" || e.relation == "observes");
    }

    // 4. Bridge directly into certified `ALG-BRIDGE-001` (`analyse_bridges`):
    //    Add a leaf sensor hanging off `switch-core` so `switch-core` is an articulation point
    //    and `(cam-leaf, switch-core)` is a bridge!
    let p_with_bridge = ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at(11),
        history_at(11),
        &auth,
        vec![
            node("switch-core", Plane::Authority, "sw"),
            node("cam-1", Plane::Authority, "c1"),
            node("cam-2", Plane::Authority, "c2"),
            node("zone-gate", Plane::Cognition, "zg"),
            node("cam-leaf", Plane::Authority, "cl"),
        ],
        vec![
            edge("switch-core", "cam-1", "feeds", 1),
            edge("switch-core", "cam-2", "feeds", 1),
            edge("cam-1", "zone-gate", "observes", 5),
            edge("cam-2", "zone-gate", "observes", 5),
            edge("switch-core", "cam-leaf", "feeds", 1),
        ],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )?;
    let simple = p_with_bridge.to_undirected_simple_graph()?;
    let analysis = analyse_bridges(&simple, Some("zone-gate"), GraphBudget::registered(&simple))?;
    assert_eq!(analysis.output.articulation_points, vec!["switch-core"]);
    assert_eq!(
        analysis.output.bridges,
        vec![("cam-leaf".to_owned(), "switch-core".to_owned())]
    );

    // 5. Stale handles from anchor 10 fail closed when used against anchor 11 (and vice versa).
    let stale_err = p_with_bridge
        .node(h_cam1)
        .expect_err("handle from seq 10 must fail closed on seq 11 projection");
    assert!(matches!(
        stale_err,
        ProjectionError::StaleHandleGeneration { .. }
    ));
    assert_eq!(
        stale_err.guidance(),
        ProjectionGuidance::ReacquireHandlesForCurrentGeneration
    );
    assert!(matches!(
        p_with_bridge.neighbors(h_cam1),
        Err(ProjectionError::StaleHandleGeneration { .. })
    ));
    let (_, old_edge_handle) = nbrs[0];
    assert!(matches!(
        p_with_bridge.edge(old_edge_handle),
        Err(ProjectionError::StaleHandleGeneration { .. })
    ));

    // 6. Directed projections preserve directionality and refuse lossy `to_undirected_simple_graph`.
    let dir_auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 7, 2);
    let p_dir = ImmutableGraphProjection::build(
        GraphUniverse::GEvidence,
        ProjectionOrientation::Directed,
        anchor_at(11),
        history_at(11),
        &dir_auth,
        vec![
            node("ev-1", Plane::Authority, "e1"),
            node("belief-1", Plane::Cognition, "b1"),
        ],
        vec![edge("ev-1", "belief-1", "supports", 100)],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )?;
    let h_ev = p_dir.handle_for_node_id("ev-1").expect("ev-1 present");
    let h_bel = p_dir
        .handle_for_node_id("belief-1")
        .expect("belief-1 present");
    assert_eq!(p_dir.neighbors(h_ev)?.len(), 1);
    assert_eq!(p_dir.neighbors(h_bel)?.len(), 0);
    assert!(p_dir.to_undirected_simple_graph().is_err());

    // Wire round-trip preserves exact directed & undirected projections.
    let encoded_dir = p_dir.to_canonical_bytes()?;
    assert_eq!(
        ImmutableGraphProjection::from_canonical_bytes(&encoded_dir)?,
        p_dir
    );
    let encoded_undir = p_with_bridge.to_canonical_bytes()?;
    assert_eq!(
        ImmutableGraphProjection::from_canonical_bytes(&encoded_undir)?,
        p_with_bridge
    );

    emit_caplog(
        "fss151_all_universes_cgse_handles_and_bridge_integration",
        "12_universes_distinct_cgse_invariant_handles_and_alg_bridge_001_verified",
        "12_universes_distinct_cgse_invariant_handles_and_alg_bridge_001_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn capability_privacy_prefilter_absence_downgrade_faults_and_hostile_wire() -> TestResult {
    let cov_digest = ContentDigest::sha256(b"coverage:complete:seq20");

    // 1. Capability & privacy filtering BEFORE expansion:
    //    - `cam-bedroom` is redacted under privacy scope.
    //    - `relay-alarm` is in Plane::Effect, which is omitted from `allowed_planes`.
    //    - Incident edges to filtered nodes are suppressed (never expanded!).
    //    - `AbsenceBoundary` MUST automatically downgrade from CertifiedComplete -> UncertifiedOrRedacted.
    let mut scoped_auth = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 5, 9);
    scoped_auth.allowed_planes.remove(&Plane::Effect);
    scoped_auth
        .redacted_node_ids
        .insert("cam-bedroom".to_owned());

    let proj = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor_at(20),
        history_at(20),
        &scoped_auth,
        vec![
            node("cam-front", Plane::Authority, "cf"),
            node("cam-bedroom", Plane::Authority, "cb"),
            node("zone-porch", Plane::Cognition, "zp"),
            node("relay-alarm", Plane::Effect, "ra"),
        ],
        vec![
            edge("cam-front", "zone-porch", "covers", 1),
            edge("cam-bedroom", "zone-porch", "adjacent", 1),
            edge("zone-porch", "relay-alarm", "triggers", 1),
        ],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )?;

    assert_eq!(proj.node_count(), 2);
    assert_eq!(proj.edge_count(), 1);
    assert!(proj.handle_for_node_id("cam-bedroom").is_none());
    assert!(proj.handle_for_node_id("relay-alarm").is_none());
    assert!(!proj.absence_boundary().certifies_absence());
    assert_eq!(
        proj.absence_boundary(),
        &AbsenceBoundary::UncertifiedOrRedacted {
            redacted_node_count: 2,
            suppressed_edge_count: 2,
            reason: "privacy_or_plane_redaction".to_owned(),
        }
    );

    // Changing privacy_epoch invalidates handles even when visible nodes are identical.
    let mut next_epoch_auth = scoped_auth.clone();
    next_epoch_auth.privacy_epoch = 10;
    let proj_next_epoch = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor_at(20),
        history_at(20),
        &next_epoch_auth,
        vec![
            node("cam-front", Plane::Authority, "cf"),
            node("cam-bedroom", Plane::Authority, "cb"),
            node("zone-porch", Plane::Cognition, "zp"),
            node("relay-alarm", Plane::Effect, "ra"),
        ],
        vec![
            edge("cam-front", "zone-porch", "covers", 1),
            edge("cam-bedroom", "zone-porch", "adjacent", 1),
            edge("zone-porch", "relay-alarm", "triggers", 1),
        ],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )?;
    let old_handle = proj.handle_for_node_id("cam-front").expect("front handle");
    assert!(matches!(
        proj_next_epoch.node(old_handle),
        Err(ProjectionError::StaleHandleGeneration { .. })
    ));

    // 2. Unauthorized universe, revoked capability, revoked privacy, stale authority generation,
    //    cooperative cancellation, duplicate nodes/edges, undirected self-loop, unknown endpoints.
    let wrong_univ_err = ImmutableGraphProjection::build(
        GraphUniverse::GAuth,
        ProjectionOrientation::Undirected,
        anchor_at(20),
        history_at(20),
        &scoped_auth,
        vec![],
        vec![],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: cov_digest,
        },
        false,
    )
    .expect_err("unauthorized universe must fail closed");
    assert!(matches!(
        wrong_univ_err,
        ProjectionError::AuthorityRevoked(_)
    ));
    assert_eq!(
        wrong_univ_err.guidance(),
        ProjectionGuidance::ReauthorizeProjection
    );

    let mut revoked_cap = scoped_auth.clone();
    revoked_cap.capability_active = false;
    assert!(matches!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &revoked_cap,
            vec![],
            vec![],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::AuthorityRevoked(_))
    ));

    let mut revoked_priv = scoped_auth.clone();
    revoked_priv.privacy_active = false;
    assert!(matches!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &revoked_priv,
            vec![],
            vec![],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::AuthorityRevoked(_))
    ));

    let mut stale_auth = scoped_auth.clone();
    stale_auth.authority_generation = 6;
    assert_eq!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &stale_auth,
            vec![],
            vec![],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::StaleAuthorityGeneration {
            expected: 5,
            observed: 6,
        })
    );

    assert_eq!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &scoped_auth,
            vec![],
            vec![],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            true,
        ),
        Err(ProjectionError::Cancelled)
    );

    // Duplicate node, undirected self-loop, unknown endpoint, duplicate edge all fail closed.
    let full_auth = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 5, 9);
    assert!(matches!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &full_auth,
            vec![
                node("dup", Plane::Authority, "a"),
                node("dup", Plane::Authority, "b"),
            ],
            vec![],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::InvalidInput(_))
    ));
    assert!(matches!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &full_auth,
            vec![node("n1", Plane::Authority, "a")],
            vec![edge("n1", "n1", "self", 1)],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::InvalidInput(_))
    ));
    assert!(matches!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &full_auth,
            vec![node("n1", Plane::Authority, "a")],
            vec![edge("n1", "ghost", "sees", 1)],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::InvalidInput(_))
    ));
    assert!(matches!(
        ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Undirected,
            anchor_at(20),
            history_at(20),
            &full_auth,
            vec![
                node("n1", Plane::Authority, "a"),
                node("n2", Plane::Authority, "b"),
            ],
            vec![edge("n1", "n2", "sees", 1), edge("n2", "n1", "sees", 2),],
            AbsenceBoundary::CertifiedComplete {
                coverage_witness_digest: cov_digest,
            },
            false,
        ),
        Err(ProjectionError::InvalidInput(_))
    ));

    // 3. Hostile `FSSGPR01` wire decoding fails closed on magic, version, truncation, checksum,
    //    and trailing bytes.
    let wire = proj.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &PROJECTION_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        PROJECTION_WIRE_VERSION
    );

    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ImmutableGraphProjection::from_canonical_bytes(&bad_magic),
        Err(ProjectionError::InvalidMagic)
    );

    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(
        ImmutableGraphProjection::from_canonical_bytes(&bad_ver),
        Err(ProjectionError::UnsupportedVersion { version: 99 })
    );

    let truncated = &wire[..wire.len() - 7];
    assert!(matches!(
        ImmutableGraphProjection::from_canonical_bytes(truncated),
        Err(ProjectionError::MalformedWire(_))
    ));

    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        ImmutableGraphProjection::from_canonical_bytes(&bit_flip),
        Err(ProjectionError::ChecksumMismatch)
    );

    let mut trailing = wire;
    trailing.push(0x00);
    assert!(matches!(
        ImmutableGraphProjection::from_canonical_bytes(&trailing),
        Err(ProjectionError::MalformedWire(_))
    ));

    emit_caplog(
        "fss151_privacy_prefilter_faults_and_hostile_wire",
        "redaction_downgraded_absence_and_all_faults_failed_closed",
        "redaction_downgraded_absence_and_all_faults_failed_closed",
        "pass",
    );
    Ok(())
}
