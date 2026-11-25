#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-152` (`fss-x4a.23.2`): O(1) `Arc`-shared graph snapshot views
//! and deterministic invalidation over [`ImmutableGraphProjection`] (`FSS-151`).

use fss_core::{ContentDigest, LedgerAnchor, Plane};
use fss_graph_algorithms::bridges::GraphBudget;
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionError, ProjectionNodeSpec, ProjectionOrientation,
};
use fss_graph_algorithms::snapshot_view::{
    GRAPH_SNAPSHOT_PUBLICATION_DOMAIN, GraphSnapshotCatalog, SNAPSHOT_RECEIPT_MAGIC,
    SNAPSHOT_RECEIPT_VERSION, SnapshotFreshness, SnapshotGuidance, SnapshotInvalidationReason,
    SnapshotPublicationReceipt, SnapshotViewError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn anchor_at(lineage: &str, seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis(lineage);
    a.commit_sequence = seq;
    a.state_root = ContentDigest::sha256(format!("{lineage}:state:{seq}").as_bytes());
    a
}

fn history_at(tag: &str, seq: u64) -> ContentDigest {
    ContentDigest::sha256(format!("{tag}:hist:{seq}").as_bytes())
}

fn node(id: &str, plane: Plane) -> ProjectionNodeSpec {
    ProjectionNodeSpec {
        node_id: id.to_owned(),
        plane,
        payload_digest: ContentDigest::sha256(id.as_bytes()),
    }
}

fn edge(src: &str, dst: &str, rel: &str) -> ProjectionEdgeSpec {
    ProjectionEdgeSpec {
        source_id: src.to_owned(),
        target_id: dst.to_owned(),
        relation: rel.to_owned(),
        weight: 1,
    }
}

fn build_sensor_proj(
    seq: u64,
    auth: &ProjectionAuthorityScope,
    extra_leaf: bool,
) -> Result<ImmutableGraphProjection, Box<dyn std::error::Error>> {
    let mut nodes = vec![
        node("switch-core", Plane::Authority),
        node("cam-1", Plane::Authority),
        node("cam-2", Plane::Authority),
        node("zone-gate", Plane::Cognition),
    ];
    let mut edges = vec![
        edge("switch-core", "cam-1", "feeds"),
        edge("switch-core", "cam-2", "feeds"),
        edge("cam-1", "zone-gate", "observes"),
        edge("cam-2", "zone-gate", "observes"),
    ];
    if extra_leaf {
        nodes.push(node("cam-leaf", Plane::Authority));
        edges.push(edge("switch-core", "cam-leaf", "feeds"));
    }
    Ok(ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at("site-alpha", seq),
        history_at("site-alpha", seq),
        auth,
        nodes,
        edges,
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: ContentDigest::sha256(format!("cov:{seq}").as_bytes()),
        },
        false,
    )?)
}

#[test]
fn o1_arc_sharing_concurrent_snapshot_isolation_and_typed_invalidation() -> TestResult {
    let mut catalog = GraphSnapshotCatalog::new();
    let auth_v1 = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 1, 1);

    // 1. Publish initial snapshot (seq 10, no leaf bridge yet).
    let proj_v1 = build_sensor_proj(10, &auth_v1, false)?;
    let receipt_v1 = catalog.publish(proj_v1, &auth_v1, false)?;
    assert_eq!(receipt_v1.view_generation, 1);
    assert_eq!(receipt_v1.previous_view_generation, 0);
    assert!(receipt_v1.superseded_projection_digest.is_none());
    assert_eq!(
        GRAPH_SNAPSHOT_PUBLICATION_DOMAIN,
        "fss.graph.snapshot_publication_receipt.v1"
    );

    // 2. Acquire multiple concurrent reader views and verify O(1) Arc sharing (`Arc::ptr_eq`)!
    let reader_a = catalog.acquire_view(GraphUniverse::GSensor, &auth_v1, false)?;
    let reader_b = catalog.acquire_view(GraphUniverse::GSensor, &auth_v1, false)?;
    let reader_c = reader_a.clone();
    assert!(reader_a.shares_backing_projection(&reader_b));
    assert!(reader_a.shares_backing_projection(&reader_c));
    // Catalog holds 1 Arc + 3 reader views = 4 strong references (zero copies!).
    assert_eq!(reader_a.strong_ref_count(), 4);
    assert_eq!(
        catalog.check_freshness(&reader_a),
        SnapshotFreshness::Current
    );
    catalog.require_current(&reader_a, &auth_v1)?;

    // Reader A acquires a handle and runs certified ALG-BRIDGE-001 on v1 (no bridges!).
    let h_sw_v1 = reader_a
        .handle_for_node_id("switch-core")
        .expect("switch-core in v1");
    let bridges_v1 = reader_a.analyse_bridges(
        Some("zone-gate"),
        GraphBudget::registered(&reader_a.projection().to_undirected_simple_graph()?),
    )?;
    assert!(bridges_v1.output.bridges.is_empty());

    // 3. Publish v2 (seq 11, adds `cam-leaf` bridge) while Reader A still holds v1!
    let proj_v2 = build_sensor_proj(11, &auth_v1, true)?;
    let receipt_v2 = catalog.publish(proj_v2, &auth_v1, false)?;
    assert_eq!(receipt_v2.view_generation, 2);
    assert_eq!(receipt_v2.previous_view_generation, 1);
    assert_eq!(
        receipt_v2.superseded_projection_digest,
        Some(receipt_v1.projection_digest)
    );

    // Snapshot isolation: Reader A STILL sees immutable v1 cleanly without torn reads!
    assert_eq!(reader_a.node(h_sw_v1)?.node_id, "switch-core");
    assert_eq!(reader_a.projection().node_count(), 4);
    // Meanwhile freshness check immediately reports exact `AnchorAdvanced { 10 -> 11 }`!
    assert_eq!(
        catalog.check_freshness(&reader_a),
        SnapshotFreshness::Invalidated {
            reason: SnapshotInvalidationReason::AnchorAdvanced {
                old_sequence: 10,
                new_sequence: 11,
            },
            current_view_generation: 2,
            current_projection_digest: Some(receipt_v2.projection_digest),
        }
    );
    let stale_req = catalog
        .require_current(&reader_a, &auth_v1)
        .expect_err("stale view must fail require_current");
    assert_eq!(
        stale_req,
        SnapshotViewError::ViewInvalidated {
            reason: SnapshotInvalidationReason::AnchorAdvanced {
                old_sequence: 10,
                new_sequence: 11,
            },
        }
    );
    assert_eq!(
        stale_req.guidance(),
        SnapshotGuidance::ReacquireCurrentSnapshot
    );

    // Acquire v2 view: sees `cam-leaf` bridge AND refuses v1's stale generational handle!
    let reader_v2 = catalog.acquire_view(GraphUniverse::GSensor, &auth_v1, false)?;
    assert!(!reader_v2.shares_backing_projection(&reader_a));
    assert!(matches!(
        reader_v2.node(h_sw_v1),
        Err(SnapshotViewError::Projection(
            ProjectionError::StaleHandleGeneration { .. }
        ))
    ));
    let bridges_v2 = reader_v2.analyse_bridges(
        Some("zone-gate"),
        GraphBudget::registered(&reader_v2.projection().to_undirected_simple_graph()?),
    )?;
    assert_eq!(
        bridges_v2.output.bridges,
        vec![("cam-leaf".to_owned(), "switch-core".to_owned())]
    );

    // 4. Privacy epoch bump invalidates v2 with `PrivacyEpochChanged` AND blocks stale-epoch acquire!
    let auth_priv2 = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 1, 2);
    // Before v3 publishes, caller with privacy_epoch 2 CANNOT read privacy_epoch 1 snapshot!
    assert!(matches!(
        catalog.acquire_view(GraphUniverse::GSensor, &auth_priv2, false),
        Err(SnapshotViewError::AuthorityMismatch(_))
    ));
    let proj_v3 = build_sensor_proj(11, &auth_priv2, true)?;
    let receipt_v3 = catalog.publish(proj_v3, &auth_priv2, false)?;
    assert_eq!(receipt_v3.view_generation, 3);
    assert_eq!(
        catalog.check_freshness(&reader_v2),
        SnapshotFreshness::Invalidated {
            reason: SnapshotInvalidationReason::PrivacyEpochChanged {
                old_epoch: 1,
                new_epoch: 2,
            },
            current_view_generation: 3,
            current_projection_digest: Some(receipt_v3.projection_digest),
        }
    );

    // 5. Authority generation bump reports `AuthorityGenerationChanged`.
    let reader_v3 = catalog.acquire_view(GraphUniverse::GSensor, &auth_priv2, false)?;
    let auth_gen2 = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 2, 2);
    let proj_v4 = build_sensor_proj(12, &auth_gen2, true)?;
    let receipt_v4 = catalog.publish(proj_v4, &auth_gen2, false)?;
    assert_eq!(
        catalog.check_freshness(&reader_v3),
        SnapshotFreshness::Invalidated {
            reason: SnapshotInvalidationReason::AuthorityGenerationChanged {
                old_generation: 1,
                new_generation: 2,
            },
            current_view_generation: 4,
            current_projection_digest: Some(receipt_v4.projection_digest),
        }
    );
    assert_eq!(catalog.history_for(GraphUniverse::GSensor).len(), 4);

    // 6. Wire round-trip of `SnapshotPublicationReceipt` (`FSSGSV01` v1).
    let wire = receipt_v4.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &SNAPSHOT_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        SNAPSHOT_RECEIPT_VERSION
    );
    assert_eq!(
        SnapshotPublicationReceipt::from_canonical_bytes(&wire)?,
        receipt_v4
    );

    emit_caplog(
        "fss152_o1_arc_sharing_isolation_and_invalidation",
        "arc_ptr_eq_zero_copy_isolation_and_all_invalidation_causes_verified",
        "arc_ptr_eq_zero_copy_isolation_and_all_invalidation_causes_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn anchor_regression_revocation_universe_isolation_cancel_and_hostile_wire() -> TestResult {
    let mut catalog = GraphSnapshotCatalog::new();
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 3, 1);

    // 1. Acquiring unpublished universe fails closed with `UniverseUnavailable`.
    assert_eq!(
        catalog.acquire_view(GraphUniverse::GSensor, &auth, false),
        Err(SnapshotViewError::UniverseUnavailable {
            universe: GraphUniverse::GSensor,
            revocation_reason: None,
        })
    );

    // 2. Cooperative cancellation refuses publish & acquire without mutating catalog.
    let proj_10 = build_sensor_proj(10, &auth, false)?;
    assert_eq!(
        catalog.publish(proj_10.clone(), &auth, true),
        Err(SnapshotViewError::Cancelled)
    );
    let receipt = catalog.publish(proj_10, &auth, false)?;
    assert_eq!(
        catalog.acquire_view(GraphUniverse::GSensor, &auth, true),
        Err(SnapshotViewError::Cancelled)
    );
    let view = catalog.acquire_view(GraphUniverse::GSensor, &auth, false)?;

    // 3. Anchor regression within same site lineage fails closed!
    let proj_regressed = build_sensor_proj(9, &auth, false)?;
    assert_eq!(
        catalog.publish(proj_regressed, &auth, false),
        Err(SnapshotViewError::AnchorRegression {
            previous_sequence: 10,
            attempted_sequence: 9,
        })
    );

    // 4. Explicit revocation invalidates existing view AND blocks new acquisitions,
    //    while leaving other universes (e.g. `G_phys`) completely independent!
    let phys_auth = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 3, 1);
    let phys_proj = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor_at("site-alpha", 10),
        history_at("site-alpha", 10),
        &phys_auth,
        vec![node("room-1", Plane::Authority)],
        vec![],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: ContentDigest::sha256(b"cov-phys"),
        },
        false,
    )?;
    catalog.publish(phys_proj, &phys_auth, false)?;
    let phys_view = catalog.acquire_view(GraphUniverse::GPhys, &phys_auth, false)?;

    catalog.revoke_universe(GraphUniverse::GSensor, "privacy_retention_purge")?;
    assert_eq!(
        catalog.check_freshness(&view),
        SnapshotFreshness::Invalidated {
            reason: SnapshotInvalidationReason::ExplicitRevocation {
                reason: "privacy_retention_purge".to_owned(),
            },
            current_view_generation: 0,
            current_projection_digest: None,
        }
    );
    assert_eq!(
        catalog.acquire_view(GraphUniverse::GSensor, &auth, false),
        Err(SnapshotViewError::UniverseUnavailable {
            universe: GraphUniverse::GSensor,
            revocation_reason: Some("privacy_retention_purge".to_owned()),
        })
    );
    // `G_phys` remains completely unaffected!
    assert_eq!(
        catalog.check_freshness(&phys_view),
        SnapshotFreshness::Current
    );

    // 5. Hostile wire decoding on `FSSGSV01`.
    let wire = receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        SnapshotPublicationReceipt::from_canonical_bytes(&bad_magic),
        Err(SnapshotViewError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        SnapshotPublicationReceipt::from_canonical_bytes(&bad_ver),
        Err(SnapshotViewError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        SnapshotPublicationReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(SnapshotViewError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        SnapshotPublicationReceipt::from_canonical_bytes(&bit_flip),
        Err(SnapshotViewError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x01);
    assert!(matches!(
        SnapshotPublicationReceipt::from_canonical_bytes(&trailing),
        Err(SnapshotViewError::MalformedWire(_))
    ));

    emit_caplog(
        "fss152_regression_revocation_isolation_and_wire",
        "regression_revocation_universe_isolation_and_wire_refusals_verified",
        "regression_revocation_universe_isolation_and_wire_refusals_verified",
        "pass",
    );
    Ok(())
}
