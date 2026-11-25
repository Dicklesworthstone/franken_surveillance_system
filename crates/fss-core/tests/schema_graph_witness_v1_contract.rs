#![forbid(unsafe_code)]
//! Contract, golden, compatibility, and hostile-input tests for `SCHEMA-GRAPH-WITNESS-001`
//! (`fss.graph_algorithm_witness.v1`, `fss-x4a.30.13`).

use std::collections::BTreeMap;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, GRAPH_WITNESS_FORMAT_VERSION, GRAPH_WITNESS_WIRE_MAGIC, GraphAlgorithmWitness,
    GraphAlgorithmWitnessParams, GraphWitnessCodecError, LedgerAnchor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample_params(error_bound: Option<f64>) -> GraphAlgorithmWitnessParams {
    let mut anchor = LedgerAnchor::genesis("site:graph-witness-test");
    anchor.commit_sequence = 42;
    GraphAlgorithmWitnessParams {
        algorithm_id: "ALG-BRIDGE-001".to_owned(),
        implementation_id: "fss-graph-algorithms:alg-bridge-001:v1".to_owned(),
        projection_id: "SensorCoverageGraph@commit:42".to_owned(),
        anchor,
        node_count: 12,
        edge_count: 19,
        input_digest: ContentDigest::sha256(b"graph-projection-input-42"),
        policy_id: "graph-policy:undirected-simple-cgse:v1".to_owned(),
        dominant_operation_counts: BTreeMap::from([
            ("dfs_edge_scans".to_owned(), 38),
            ("dfs_node_visits".to_owned(), 12),
        ]),
        peak_working_bytes: 2048,
        budget_consumed: BTreeMap::from([
            ("operations".to_owned(), 50),
            ("working_bytes".to_owned(), 2048),
        ]),
        exactness: GraphAlgorithmWitness::EXACT.to_owned(),
        error_bound,
        stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
        decision_path_digest: ContentDigest::sha256(b"cgse-decision-path-42"),
        output_digest: ContentDigest::sha256(b"bridge-output-42"),
    }
}

#[test]
fn graph_witness_v1_roundtrips_binary_json_neg_zero_and_compatibility() -> TestResult {
    let w_exact = GraphAlgorithmWitness::new(sample_params(None))?;
    assert_eq!(
        GraphAlgorithmWitness::SCHEMA,
        "fss.graph_algorithm_witness.v1"
    );
    assert_eq!(
        GraphAlgorithmWitness::DIGEST_DOMAIN,
        "fss.graph_algorithm_witness.receipt.v1"
    );
    assert!(!w_exact.grants_effect_authority());

    // 1. Canonical binary wire round-trip (`FSSGWT01` v1) + determinism check.
    let wire1 = w_exact.to_canonical_bytes()?;
    let wire2 = w_exact.to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(&wire1[..8], &GRAPH_WITNESS_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        GRAPH_WITNESS_FORMAT_VERSION
    );
    let from_wire = GraphAlgorithmWitness::from_canonical_bytes(&wire1)?;
    assert_eq!(from_wire, w_exact);
    assert_eq!(from_wire.digest(), w_exact.digest());

    // 2. Canonical JSON round-trip matching `schemas/graph_algorithm_witness.v1.json`.
    let json = w_exact.to_canonical_json("dev:graph:gen1", "stream:graph:gen1")?;
    let from_json = GraphAlgorithmWitness::from_json(&json)?;
    assert_eq!(from_json, w_exact);
    assert_eq!(
        from_json.to_canonical_json("dev:graph:gen1", "stream:graph:gen1")?,
        json
    );

    // 3. `-0.0` normalization: `Some(-0.0)` and `Some(0.0)` yield identical digests and wire bytes!
    let w_pos_zero = GraphAlgorithmWitness::new(sample_params(Some(0.0)))?;
    let w_neg_zero = GraphAlgorithmWitness::new(sample_params(Some(-0.0)))?;
    assert_eq!(w_pos_zero.digest(), w_neg_zero.digest());
    assert_eq!(
        w_pos_zero.to_canonical_bytes()?,
        w_neg_zero.to_canonical_bytes()?
    );
    let approx = GraphAlgorithmWitness::new(sample_params(Some(0.0125)))?;
    let approx_json = approx.to_canonical_json("dev:graph:gen1", "stream:graph:gen1")?;
    assert_eq!(GraphAlgorithmWitness::from_json(&approx_json)?, approx);

    // 4. Compatibility rule: implementation upgrade preserving algorithm/projection/policy/output passes;
    //    any drift in those four invariants fails closed!
    let mut upgraded_params = sample_params(None);
    upgraded_params.implementation_id = "fss-graph-algorithms:alg-bridge-001:v2".to_owned();
    let upgraded = GraphAlgorithmWitness::new(upgraded_params)?;
    upgraded.verify_preserves_identity(&w_exact)?;

    for mutate in [
        Box::new(|p: &mut GraphAlgorithmWitnessParams| p.algorithm_id = "ALG-CUT-002".to_owned())
            as Box<dyn Fn(&mut GraphAlgorithmWitnessParams)>,
        Box::new(|p| p.projection_id = "OtherGraph@commit:42".to_owned()),
        Box::new(|p| p.policy_id = "graph-policy:directed:v2".to_owned()),
        Box::new(|p| p.output_digest = ContentDigest::sha256(b"drifted-output")),
    ] {
        let mut drifted_params = sample_params(None);
        mutate(&mut drifted_params);
        let drifted = GraphAlgorithmWitness::new(drifted_params)?;
        assert!(matches!(
            drifted.verify_preserves_identity(&w_exact),
            Err(GraphWitnessCodecError::CompatibilityViolation(_))
        ));
    }

    emit_caplog(
        "schema_graph_witness_v1_roundtrip_and_compat",
        "binary_json_neg_zero_and_identity_preservation_verified",
        "binary_json_neg_zero_and_identity_preservation_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn graph_witness_v1_refuses_hostile_json_wire_and_non_canonical_maps() -> TestResult {
    let witness = GraphAlgorithmWitness::new(sample_params(Some(0.05)))?;
    let json = witness.to_canonical_json("dev:graph:gen1", "stream:graph:gen1")?;

    // 1. Hostile JSON: unknown field, wrong root schema, wrong nested anchor schema, duplicate key, negative errorBound.
    let unknown_prop = json.replacen('{', "{\"rogueField\":1,", 1);
    assert!(matches!(
        GraphAlgorithmWitness::from_json(&unknown_prop),
        Err(GraphWitnessCodecError::MalformedPayload(_))
    ));
    let wrong_schema = json.replace(
        "fss.graph_algorithm_witness.v1",
        "fss.graph_algorithm_witness.v99",
    );
    assert!(matches!(
        GraphAlgorithmWitness::from_json(&wrong_schema),
        Err(GraphWitnessCodecError::SchemaMismatch {
            expected: "fss.graph_algorithm_witness.v1",
            ..
        })
    ));
    let wrong_anchor_schema = json.replace("fss.evidence_anchor.v1", "fss.evidence_anchor.v99");
    assert!(matches!(
        GraphAlgorithmWitness::from_json(&wrong_anchor_schema),
        Err(GraphWitnessCodecError::SchemaMismatch {
            expected: "fss.evidence_anchor.v1",
            ..
        })
    ));
    let dup_key = json.replacen("\"policyId\":", "\"policyId\":\"dup\",\"policyId\":", 1);
    assert!(matches!(
        GraphAlgorithmWitness::from_json(&dup_key),
        Err(GraphWitnessCodecError::MalformedPayload(_))
    ));
    let neg_bound = json.replace("\"errorBound\":0.05", "\"errorBound\":-0.05");
    assert_eq!(
        GraphAlgorithmWitness::from_json(&neg_bound),
        Err(GraphWitnessCodecError::Contract(
            ContractError::InvalidDigest
        ))
    );

    // 2. Hostile binary wire: bad magic, unsupported version, truncation, checksum tamper, trailing byte.
    let wire = witness.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        GraphAlgorithmWitness::from_canonical_bytes(&bad_magic),
        Err(GraphWitnessCodecError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&7_u32.to_be_bytes());
    assert_eq!(
        GraphAlgorithmWitness::from_canonical_bytes(&bad_ver),
        Err(GraphWitnessCodecError::UnsupportedVersion { version: 7 })
    );
    assert!(matches!(
        GraphAlgorithmWitness::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(GraphWitnessCodecError::MalformedPayload(_))
    ));
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_eq!(
        GraphAlgorithmWitness::from_canonical_bytes(&tampered),
        Err(GraphWitnessCodecError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xAA);
    assert!(matches!(
        GraphAlgorithmWitness::from_canonical_bytes(&trailing),
        Err(GraphWitnessCodecError::MalformedPayload(_))
    ));

    // 3. Non-canonical raw `-0.0` float bits and non-ascending counter keys MUST fail CanonicalDecode!
    let mut enc = CanonicalEncoder::new();
    enc.text(GraphAlgorithmWitness::DIGEST_DOMAIN);
    enc.text(witness.algorithm_id());
    enc.text(witness.implementation_id());
    enc.text(witness.projection_id());
    witness.anchor().encode_canonical(&mut enc);
    enc.u64(witness.node_count());
    enc.u64(witness.edge_count());
    enc.digest(witness.input_digest());
    enc.text(witness.policy_id());
    enc.u64(2);
    enc.text("z_second");
    enc.u64(1);
    enc.text("a_first");
    enc.u64(2);
    enc.u64(witness.peak_working_bytes());
    enc.u64(0);
    enc.text(witness.exactness());
    enc.tag(0);
    enc.text(witness.stop_reason());
    enc.digest(witness.decision_path_digest());
    enc.digest(witness.output_digest());
    let non_canonical_bytes = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&non_canonical_bytes);
    assert_eq!(
        GraphAlgorithmWitness::decode_canonical(&mut dec),
        Err(ContractError::NonCanonicalOrdering)
    );

    emit_caplog(
        "schema_graph_witness_v1_faults",
        "hostile_json_wire_and_non_canonical_encoding_failed_closed",
        "hostile_json_wire_and_non_canonical_encoding_failed_closed",
        "pass",
    );
    Ok(())
}
