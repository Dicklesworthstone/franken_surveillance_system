#![forbid(unsafe_code)]
//! Frozen v1 contract and fault suite for `FSS-101` (`fss-x4a.9.8`):
//! `EvidenceDeltaBatch` v1 canonical ordering, anchor continuity, plane ownership,
//! idempotency, crash-safe staging, and hand-audited `FSSBAT01` binary codec.

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    LedgerSnapshotRetention, ObjectId, OperationId, Plane, ReferenceLedger, TimestampNs,
};
use fss_ledger::{BatchCodecError, decode_batch, encode_batch};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SCHEMA_JSON: &str = include_str!("../../../schemas/evidence_delta_batch.v1.json");

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[allow(clippy::too_many_arguments)]
fn make_delta(
    delta_id: &str,
    family: &str,
    object_id: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
    plane: Plane,
    witness: Option<&str>,
    op: Option<&str>,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: family.to_owned(),
        object_id: ObjectId::parse(object_id)?,
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?,
        plane,
        payload_digest: ContentDigest::sha256(
            format!("{family}:{object_id}:{new_generation}").as_bytes(),
        ),
        witness_digest: witness.map(|w| ContentDigest::sha256(w.as_bytes())),
        operation_id: op.map(OperationId::parse).transpose()?,
    })
}

fn canonical_fixture_batch() -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
    let ledger = ReferenceLedger::new("site:fss101-freeze");
    let d1 = make_delta(
        "delta:001",
        "alert_effect",
        "object:eff-01",
        None,
        1,
        Plane::Effect,
        Some("witness:eff-01"),
        Some("operation:notify-01"),
    )?;
    let d2 = make_delta(
        "delta:002",
        "hypothesis",
        "object:hyp-01",
        None,
        1,
        Plane::Cognition,
        Some("witness:hyp-01"),
        None,
    )?;
    let d3 = make_delta(
        "delta:003",
        "sensor_capsule",
        "object:cap-01",
        None,
        1,
        Plane::Authority,
        None,
        None,
    )?;
    let c1 = ContentDigest::sha256(b"child-root-1");
    let c2 = ContentDigest::sha256(b"child-root-2");
    let batch = ledger.prepare_batch(
        BatchId::parse("batch:fss101-v1-golden")?,
        vec![d3, d1, d2],
        [c2, c1, c2],
    )?;
    Ok(batch)
}

#[test]
fn frozen_v1_schema_ordering_and_permutation_invariance() -> TestResult {
    // 1. Registered schema identity matches machine schema file.
    assert_eq!(EvidenceDeltaBatch::SCHEMA, "fss.evidence_delta_batch.v1");
    assert!(SCHEMA_JSON.contains("\"const\": \"fss.evidence_delta_batch.v1\""));
    for required_field in [
        "\"schema\"",
        "\"batchId\"",
        "\"basisAnchor\"",
        "\"newAnchor\"",
        "\"deltas\"",
        "\"children\"",
        "\"batchDigest\"",
    ] {
        assert!(
            SCHEMA_JSON.contains(required_field),
            "evidence_delta_batch.v1.json missing required field {required_field}"
        );
    }

    // 2. Canonical ordering `(family, object_id, new_generation, delta_id)` and strictly ascending
    //    unique `children` digests are permutation-invariant across all input orderings.
    let canonical = canonical_fixture_batch()?;
    assert!(canonical.is_canonically_ordered());
    assert_eq!(canonical.deltas.len(), 3);
    assert_eq!(canonical.deltas[0].family, "alert_effect");
    assert_eq!(canonical.deltas[1].family, "hypothesis");
    assert_eq!(canonical.deltas[2].family, "sensor_capsule");
    assert_eq!(canonical.children.len(), 2);
    assert!(canonical.children[0] < canonical.children[1]);

    let wire = encode_batch(&canonical)?;
    assert_eq!(&wire[0..8], b"FSSBAT01");
    assert_eq!(&wire[8..10], &1_u16.to_be_bytes());
    let decoded = decode_batch(&wire)?;
    assert_eq!(decoded, canonical);

    // Every permutation of input deltas and children must produce byte-identical wire encoding
    // and identical batch_digest + new_anchor.state_root.
    let d_all = canonical.deltas.clone();
    let c_all = canonical.children.clone();
    let permutations: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for (idx, perm) in permutations.into_iter().enumerate() {
        let ledger = ReferenceLedger::new("site:fss101-freeze");
        let permuted_deltas = vec![
            d_all[perm[0]].clone(),
            d_all[perm[1]].clone(),
            d_all[perm[2]].clone(),
        ];
        let permuted_children = if idx % 2 == 0 {
            vec![c_all[0], c_all[1], c_all[0]]
        } else {
            vec![c_all[1], c_all[0], c_all[1]]
        };
        let prepared = ledger.prepare_batch(
            BatchId::parse("batch:fss101-v1-golden")?,
            permuted_deltas,
            permuted_children,
        )?;
        assert_eq!(prepared.batch_digest, canonical.batch_digest);
        assert_eq!(
            prepared.new_anchor.state_root,
            canonical.new_anchor.state_root
        );
        assert_eq!(encode_batch(&prepared)?, wire);
    }

    // Re-encoding twice is bit-identical and deterministic.
    let wire_digest = ContentDigest::sha256(&wire);
    assert_eq!(wire_digest, ContentDigest::sha256(&encode_batch(&decoded)?));

    emit_caplog(
        "fss101_schema_ordering_and_permutation_invariance",
        "all_6_permutations_byte_identical",
        "all_6_permutations_byte_identical",
        "pass",
    );
    Ok(())
}

#[test]
fn wire_codec_refuses_corrupt_magic_versions_truncation_trailing_noncanonical_and_alloc_bombs()
-> TestResult {
    let canonical = canonical_fixture_batch()?;
    let wire = encode_batch(&canonical)?;

    // 1. Invalid magic fails closed.
    let mut bad_magic = wire.clone();
    bad_magic[7] = b'9';
    assert_eq!(decode_batch(&bad_magic), Err(BatchCodecError::InvalidMagic));

    // 2. Unsupported versions (0, 2, u16::MAX) fail closed.
    for bad_ver in [0_u16, 2_u16, u16::MAX] {
        let mut buf = wire.clone();
        buf[8..10].copy_from_slice(&bad_ver.to_be_bytes());
        assert_eq!(
            decode_batch(&buf),
            Err(BatchCodecError::UnsupportedVersion(bad_ver))
        );
    }

    // 3. Every strict truncation prefix 0..wire.len() fails closed with UnexpectedEof.
    for cut in 0..wire.len() {
        assert_eq!(
            decode_batch(&wire[..cut]),
            Err(BatchCodecError::UnexpectedEof),
            "truncation at byte {cut} must return UnexpectedEof"
        );
    }

    // 4. Trailing bytes fail closed.
    let mut trailing = wire.clone();
    trailing.push(0x00);
    assert_eq!(decode_batch(&trailing), Err(BatchCodecError::TrailingBytes));

    // 5. Crafted pre-allocation DoS bomb (delta_count = 16_384 on a truncated buffer)
    //    must fail closed immediately with UnexpectedEof rather than allocating megabytes.
    let mut bomb = Vec::new();
    bomb.extend_from_slice(b"FSSBAT01");
    bomb.extend_from_slice(&1_u16.to_be_bytes());
    // batch_id = "batch:b"
    bomb.extend_from_slice(&7_u32.to_be_bytes());
    bomb.extend_from_slice(b"batch:b");
    // basis_anchor + new_anchor (minimal valid anchors)
    for _ in 0..2 {
        bomb.extend_from_slice(&4_u32.to_be_bytes());
        bomb.extend_from_slice(b"site");
        for _ in 0..6 {
            bomb.extend_from_slice(&0_u64.to_be_bytes());
        }
        bomb.push(1);
        bomb.extend_from_slice(&[0_u8; 32]);
    }
    // Claim 16_384 deltas with 0 remaining bytes.
    bomb.extend_from_slice(&16_384_u32.to_be_bytes());
    assert_eq!(decode_batch(&bomb), Err(BatchCodecError::UnexpectedEof));

    // Over-bound delta count (16_385) fails closed with BoundExceeded("deltas").
    let mut over_bound = bomb.clone();
    let count_offset = over_bound.len() - 4;
    over_bound[count_offset..].copy_from_slice(&16_385_u32.to_be_bytes());
    assert_eq!(
        decode_batch(&over_bound),
        Err(BatchCodecError::BoundExceeded("deltas"))
    );

    // 6. Non-canonical delta ordering and unsorted/duplicate children fail encode_batch.
    let mut swapped_deltas = canonical.clone();
    swapped_deltas.deltas.swap(0, 1);
    swapped_deltas.batch_digest = swapped_deltas.computed_digest();
    assert!(!swapped_deltas.is_canonically_ordered());
    assert_eq!(
        encode_batch(&swapped_deltas),
        Err(BatchCodecError::Contract(
            ContractError::NonCanonicalOrdering
        ))
    );

    let mut dup_children = canonical.clone();
    dup_children.children.push(dup_children.children[0]);
    dup_children.batch_digest = dup_children.computed_digest();
    assert!(!dup_children.is_canonically_ordered());
    assert_eq!(
        encode_batch(&dup_children),
        Err(BatchCodecError::Contract(
            ContractError::NonCanonicalOrdering
        ))
    );

    // 7. Digest mismatch fails both encode_batch and decode_batch.
    let mut bad_digest = canonical;
    bad_digest.batch_digest = ContentDigest::sha256(b"forged-batch-digest");
    assert_eq!(
        encode_batch(&bad_digest),
        Err(BatchCodecError::Contract(ContractError::DigestMismatch))
    );
    let mut flipped_wire = wire;
    let last = flipped_wire.len() - 1;
    flipped_wire[last] ^= 0xFF;
    assert_eq!(
        decode_batch(&flipped_wire),
        Err(BatchCodecError::Contract(ContractError::DigestMismatch))
    );

    emit_caplog(
        "fss101_wire_codec_hostile_refusals",
        "all_wire_faults_and_alloc_bombs_refused",
        "all_wire_faults_and_alloc_bombs_refused",
        "pass",
    );
    Ok(())
}

#[test]
fn anchor_successor_plane_ownership_idempotency_and_staged_append_semantics() -> TestResult {
    let mut ledger = ReferenceLedger::new("site:fss101-freeze");
    let first = canonical_fixture_batch()?;

    // 1. Every invalid anchor successor mutation MUST be rejected atomically without mutating state.
    let mut bad_lineage = first.clone();
    bad_lineage.new_anchor.site_lineage = "site:other".to_owned();
    bad_lineage.batch_digest = bad_lineage.computed_digest();
    assert_eq!(
        ledger.append(bad_lineage),
        Err(ContractError::InvalidAnchorSuccessor)
    );

    let mut bad_seq = first.clone();
    bad_seq.new_anchor.commit_sequence = 2;
    bad_seq.batch_digest = bad_seq.computed_digest();
    assert_eq!(
        ledger.append(bad_seq),
        Err(ContractError::InvalidAnchorSuccessor)
    );

    for epoch_case in 0..5 {
        let mut mutated = first.clone();
        match epoch_case {
            0 => mutated.new_anchor.ledger_epoch += 1,
            1 => mutated.new_anchor.adapter_registry_epoch += 1,
            2 => mutated.new_anchor.schema_epoch += 1,
            3 => mutated.new_anchor.policy_epoch += 1,
            _ => mutated.new_anchor.privacy_epoch += 1,
        }
        mutated.batch_digest = mutated.computed_digest();
        assert_eq!(
            ledger.append(mutated),
            Err(ContractError::InvalidAnchorSuccessor),
            "epoch drift case {epoch_case} must fail InvalidAnchorSuccessor"
        );
    }

    let mut bad_root = first.clone();
    bad_root.new_anchor.state_root = ContentDigest::sha256(b"wrong-state-root");
    bad_root.batch_digest = bad_root.computed_digest();
    assert_eq!(ledger.append(bad_root), Err(ContractError::DigestMismatch));
    assert_eq!(ledger.current().anchor.commit_sequence, 0);

    // 2. Crash-safe stage -> suspend -> cloned-owner refusal -> original-owner resume -> commit.
    let staged = ledger.stage_append(first.clone())?;
    let suspended = staged.suspend();
    let mut cloned = ledger.clone();
    let err = cloned
        .resume_append(suspended)
        .err()
        .ok_or("cloned ledger must not resume another owner's suspended append")?;
    assert_eq!(*err.error(), ContractError::StaleAnchor);
    let (_ce, recovered_token) = err.into_parts();
    let committed = ledger.resume_append(recovered_token)?.commit().clone();
    assert_eq!(committed.anchor.commit_sequence, 1);

    // 3. Cross-plane hijack on an existing object MUST fail closed with ObjectPlaneConflict.
    let plane_hijack = make_delta(
        "delta:hijack",
        "sensor_capsule",
        "object:cap-01",
        Some(1),
        2,
        Plane::Cognition,
        None,
        None,
    )?;
    assert_eq!(
        ledger.prepare_batch(BatchId::parse("batch:hijack")?, vec![plane_hijack], []),
        Err(ContractError::ObjectPlaneConflict {
            object_id: ObjectId::parse("object:cap-01")?,
            committed_plane: Plane::Authority,
            delta_plane: Plane::Cognition,
        })
    );

    // 4. Duplicate object in one batch & skipped generation fail closed with GenerationConflict.
    let valid_update = make_delta(
        "delta:upd-1",
        "sensor_capsule",
        "object:cap-01",
        Some(1),
        2,
        Plane::Authority,
        None,
        None,
    )?;
    let dup_update = make_delta(
        "delta:upd-2",
        "sensor_capsule",
        "object:cap-01",
        Some(1),
        2,
        Plane::Authority,
        None,
        None,
    )?;
    assert_eq!(
        ledger.prepare_batch(
            BatchId::parse("batch:dup-obj")?,
            vec![valid_update.clone(), dup_update],
            [],
        ),
        Err(ContractError::GenerationConflict)
    );
    let skipped_gen = make_delta(
        "delta:skip",
        "sensor_capsule",
        "object:cap-01",
        Some(1),
        3,
        Plane::Authority,
        None,
        None,
    )?;
    assert_eq!(
        ledger.prepare_batch(BatchId::parse("batch:skip-gen")?, vec![skipped_gen], []),
        Err(ContractError::GenerationConflict)
    );

    // 5. Reusing an already-committed BatchId with different content fails IdempotencyConflict,
    //    while resubmitting the exact prior batch fails StaleAnchor.
    let conflicting_reuse = ledger.prepare_batch(
        BatchId::parse("batch:fss101-v1-golden")?,
        vec![valid_update.clone()],
        [],
    )?;
    assert_eq!(
        ledger.append(conflicting_reuse),
        Err(ContractError::IdempotencyConflict)
    );
    assert_eq!(
        ledger.append(first.clone()),
        Err(ContractError::StaleAnchor)
    );

    // 6. Legitimate successor batch commits cleanly and matches both FullHistory & CurrentOnly replay.
    let second = ledger.prepare_batch(
        BatchId::parse("batch:fss101-v1-seq2")?,
        vec![valid_update],
        [],
    )?;
    let terminal = ledger.append(second.clone())?.anchor.clone();
    assert_eq!(terminal.commit_sequence, 2);

    let full_replay = ReferenceLedger::replay_with_snapshot_retention(
        "site:fss101-freeze",
        LedgerSnapshotRetention::FullHistory,
        [first.clone(), second.clone()],
    )?;
    let current_only_replay = ReferenceLedger::replay_with_snapshot_retention(
        "site:fss101-freeze",
        LedgerSnapshotRetention::CurrentOnly,
        [first, second],
    )?;
    assert_eq!(full_replay.current().anchor, terminal);
    assert_eq!(current_only_replay.current().anchor, terminal);
    assert_eq!(full_replay.retained_snapshot_count(), 3);
    assert_eq!(current_only_replay.retained_snapshot_count(), 1);
    assert_eq!(full_replay.batches(), current_only_replay.batches());

    emit_caplog(
        "fss101_anchor_plane_idempotency_and_replay",
        "all_anchor_and_replay_invariants_verified",
        "all_anchor_and_replay_invariants_verified",
        "pass",
    );
    Ok(())
}
