#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-153` (`fss-x4a.23.3`): canonical graph serialization and
//! localized cryptographic hash verification across `UndirectedGraph`, `ImmutableGraphProjection`,
//! and `GraphSnapshotCatalog` (`FSS-151` / `FSS-152`).

use fss_core::{ContentDigest, LedgerAnchor, Plane};
use fss_graph_algorithms::GraphBuilder;
use fss_graph_algorithms::canonical_codec::{
    CANONICAL_GRAPH_MAGIC, CANONICAL_GRAPH_VERSION, CanonicalGraphEnvelope, CanonicalGraphError,
    CanonicalGraphPayload, GRAPH_CANONICAL_ENVELOPE_DOMAIN, GRAPH_MERKLE_STRUCTURE_DOMAIN,
    GraphPayloadKind, HashMismatchComponent,
};
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};
use fss_graph_algorithms::snapshot_view::GraphSnapshotCatalog;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn anchor(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site-fss-153");
    a.commit_sequence = seq;
    a.state_root = d(&format!("state-root-{seq}"));
    a
}

#[test]
fn canonical_graph_serialization_is_permutation_invariant_across_both_families() -> TestResult {
    // 1. UndirectedGraph: two opposite insertion orders yield BIT-IDENTICAL canonical bytes & hashes!
    let mut b1 = GraphBuilder::new();
    b1.add_node("cam-c")
        .add_node("cam-a")
        .add_node("cam-b")
        .add_node("cam-d");
    b1.add_edge("cam-c", "cam-a")
        .add_edge("cam-b", "cam-d")
        .add_edge("cam-a", "cam-b");
    let g1 = b1.build()?;

    let mut b2 = GraphBuilder::new();
    b2.add_node("cam-d")
        .add_node("cam-b")
        .add_node("cam-a")
        .add_node("cam-c");
    b2.add_edge("cam-b", "cam-a")
        .add_edge("cam-d", "cam-b")
        .add_edge("cam-a", "cam-c");
    let g2 = b2.build()?;

    let env1 = CanonicalGraphEnvelope::from_undirected(&g1, false)?;
    let env2 = CanonicalGraphEnvelope::from_undirected(&g2, false)?;
    let wire1 = env1.to_canonical_bytes()?;
    let wire2 = env2.to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(env1.hashes, env2.hashes);
    assert_eq!(env1.envelope_digest, env2.envelope_digest);
    assert_eq!(&wire1[..8], &CANONICAL_GRAPH_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        CANONICAL_GRAPH_VERSION
    );
    assert_eq!(
        GRAPH_CANONICAL_ENVELOPE_DOMAIN,
        "fss.graph.canonical_envelope.v1"
    );
    assert_eq!(
        GRAPH_MERKLE_STRUCTURE_DOMAIN,
        "fss.graph.merkle_structure.v1"
    );

    let (dec_env, dec_payload) = CanonicalGraphEnvelope::from_canonical_bytes(
        &wire1,
        Some(g1.digest()),
        Some(env1.envelope_digest),
        false,
    )?;
    assert_eq!(dec_env, env1);
    assert_eq!(dec_env.payload_kind, GraphPayloadKind::UndirectedSimple);
    let CanonicalGraphPayload::UndirectedSimple(dec_g) = dec_payload else {
        return Err("expected UndirectedSimple payload".into());
    };
    assert_eq!(*dec_g, g1);

    // 2. ImmutableGraphProjection (FSS-151) + ArcSnapshotViewStore (FSS-152) round-trip & permutation invariance!
    let scope = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 2, 1);
    let nodes_a = vec![
        ProjectionNodeSpec {
            node_id: "zone:south".to_owned(),
            plane: Plane::Authority,
            payload_digest: d("south"),
        },
        ProjectionNodeSpec {
            node_id: "zone:north".to_owned(),
            plane: Plane::Authority,
            payload_digest: d("north"),
        },
        ProjectionNodeSpec {
            node_id: "zone:gate".to_owned(),
            plane: Plane::Cognition,
            payload_digest: d("gate"),
        },
    ];
    let edges_a = vec![
        ProjectionEdgeSpec {
            source_id: "zone:north".to_owned(),
            target_id: "zone:gate".to_owned(),
            relation: "adjacent".to_owned(),
            weight: 10,
        },
        ProjectionEdgeSpec {
            source_id: "zone:south".to_owned(),
            target_id: "zone:gate".to_owned(),
            relation: "adjacent".to_owned(),
            weight: 20,
        },
    ];
    let mut nodes_b = nodes_a.clone();
    nodes_b.reverse();
    let mut edges_b = edges_a.clone();
    edges_b.reverse();

    let p1 = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor(5),
        d("hist-5"),
        &scope,
        nodes_a,
        edges_a,
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: d("cov-5"),
        },
        false,
    )?;
    let p2 = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor(5),
        d("hist-5"),
        &scope,
        nodes_b,
        edges_b,
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: d("cov-5"),
        },
        false,
    )?;

    // Publish into FSS-152 catalog and serialize directly from the O(1) Arc handle!
    let mut catalog = GraphSnapshotCatalog::new();
    let _ = catalog.publish(p1, &scope, false)?;
    let view = catalog.acquire_view(GraphUniverse::GPhys, &scope, false)?;

    let p_env1 = CanonicalGraphEnvelope::from_projection(view.projection(), false)?;
    let p_env2 = CanonicalGraphEnvelope::from_projection(&p2, false)?;
    let p_wire1 = p_env1.to_canonical_bytes()?;
    let p_wire2 = p_env2.to_canonical_bytes()?;
    assert_eq!(p_wire1, p_wire2);
    assert_eq!(p_env1.hashes, p_env2.hashes);

    let (p_dec_env, p_dec_payload) = CanonicalGraphEnvelope::from_canonical_bytes(
        &p_wire1,
        Some(p2.generation().projection_digest),
        Some(p_env1.envelope_digest),
        false,
    )?;
    assert_eq!(p_dec_env, p_env1);
    let CanonicalGraphPayload::ImmutableProjection(dec_p) = p_dec_payload else {
        return Err("expected ImmutableProjection payload".into());
    };
    assert_eq!(*dec_p, p2);

    emit_caplog(
        "fss153_permutation_invariant_codec_and_merkle",
        "undirected_and_projection_envelopes_bit_identical_and_verified",
        "undirected_and_projection_envelopes_bit_identical_and_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn canonical_graph_tamper_localization_cancel_and_hostile_wire_fail_closed() -> TestResult {
    let mut b = GraphBuilder::new();
    b.add_node("a").add_node("b").add_node("c");
    b.add_edge("a", "b").add_edge("b", "c");
    let g = b.build()?;

    assert_eq!(
        CanonicalGraphEnvelope::from_undirected(&g, true),
        Err(CanonicalGraphError::Cancelled)
    );

    let env = CanonicalGraphEnvelope::from_undirected(&g, false)?;
    let wire = env.to_canonical_bytes()?;

    // 1. Expected pin mismatch localized cleanly.
    assert_eq!(
        CanonicalGraphEnvelope::from_canonical_bytes(&wire, Some(d("wrong-graph")), None, false),
        Err(CanonicalGraphError::HashMismatch {
            component: HashMismatchComponent::ExpectedPinMismatch
        })
    );

    // 2. Localized tamper detection on individual Merkle roots (with recomputed envelope digest!).
    let mut bad_nodes_root = env.clone();
    bad_nodes_root.hashes.nodes_merkle_root = d("forged-nodes-root");
    bad_nodes_root.envelope_digest = bad_nodes_root.compute_envelope_digest()?;
    assert_eq!(
        bad_nodes_root.verify_and_decode(None, None, false),
        Err(CanonicalGraphError::HashMismatch {
            component: HashMismatchComponent::NodesMerkleRoot
        })
    );

    let mut bad_edges_root = env.clone();
    bad_edges_root.hashes.edges_merkle_root = d("forged-edges-root");
    bad_edges_root.envelope_digest = bad_edges_root.compute_envelope_digest()?;
    assert_eq!(
        bad_edges_root.verify_and_decode(None, None, false),
        Err(CanonicalGraphError::HashMismatch {
            component: HashMismatchComponent::EdgesMerkleRoot
        })
    );

    let mut bad_counts = env;
    bad_counts.hashes.node_count = 99;
    bad_counts.envelope_digest = bad_counts.compute_envelope_digest()?;
    assert_eq!(
        bad_counts.verify_and_decode(None, None, false),
        Err(CanonicalGraphError::HashMismatch {
            component: HashMismatchComponent::StructureCounts
        })
    );

    // 3. Hostile binary wire attacks on `FSSGCH01`.
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        CanonicalGraphEnvelope::from_canonical_bytes(&bad_magic, None, None, false),
        Err(CanonicalGraphError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&5_u32.to_be_bytes());
    assert_eq!(
        CanonicalGraphEnvelope::from_canonical_bytes(&bad_ver, None, None, false),
        Err(CanonicalGraphError::UnsupportedVersion { version: 5 })
    );
    assert!(matches!(
        CanonicalGraphEnvelope::from_canonical_bytes(&wire[..wire.len() - 5], None, None, false),
        Err(CanonicalGraphError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        CanonicalGraphEnvelope::from_canonical_bytes(&bit_flip, None, None, false),
        Err(CanonicalGraphError::HashMismatch {
            component: HashMismatchComponent::EnvelopeChecksum
        })
    );
    let mut trailing = wire;
    trailing.push(0x00);
    assert!(matches!(
        CanonicalGraphEnvelope::from_canonical_bytes(&trailing, None, None, false),
        Err(CanonicalGraphError::MalformedWire(_))
    ));

    emit_caplog(
        "fss153_tamper_localization_and_hostile_wire",
        "merkle_tamper_localization_cancel_and_hostile_wire_failed_closed",
        "merkle_tamper_localization_cancel_and_hostile_wire_failed_closed",
        "pass",
    );
    Ok(())
}
