#![forbid(unsafe_code)]
//! Integration contract tests for FSS-019 Replay Bundle v1 Reader/Writer (fss-x4a.7.7).

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::{LedgerOracle, OracleLimits};
use fss_object::{SpoolLimits, StagingSpool};
use fss_publication::{
    MAX_REPLAY_FAULT_DIRECTIVES, MAX_REPLAY_FAULT_REORDER_WINDOW, MAX_REPLAY_TEMP_ATTEMPTS,
    REPLAY_BUNDLE_DOMAIN, REPLAY_TRAILER_LEN, ReplayBundle, ReplayBundleError, ReplayBundleLimits,
    ReplayBundleReader, ReplayBundleWriter, ReplayFaultAction, ReplayFaultDirective,
    ReplayFaultSchedule, ReplayMetadata, ReplayObject, replay_bundle_digest, replay_temp_path_for,
};

type TestResult = Result<(), Box<dyn Error>>;

fn temp_bundle_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "fss-replay-bundle-test-{}-{name}.replay",
        std::process::id()
    ))
}

fn sample_metadata(lineage: &str) -> ReplayMetadata {
    ReplayMetadata {
        site_lineage: lineage.to_owned(),
        seed: 42,
        schema_generation: 1,
        policy_generation: 1,
        model_generation: 1,
        device_generation: 1,
    }
}

fn clean_fault_schedule() -> ReplayFaultSchedule {
    ReplayFaultSchedule::empty(12345, 0)
}

fn sample_fault_schedule() -> Result<ReplayFaultSchedule, ReplayBundleError> {
    ReplayFaultSchedule::new(
        12345,
        16,
        vec![
            ReplayFaultDirective {
                source_sequence: 1,
                action: ReplayFaultAction::Pass,
            },
            ReplayFaultDirective {
                source_sequence: 2,
                action: ReplayFaultAction::Delay { ticks: 5 },
            },
            ReplayFaultDirective {
                source_sequence: 3,
                action: ReplayFaultAction::Duplicate { copies: 2 },
            },
            ReplayFaultDirective {
                source_sequence: 4,
                action: ReplayFaultAction::Corrupt { mutation_tag: 1 },
            },
            ReplayFaultDirective {
                source_sequence: 5,
                action: ReplayFaultAction::Drop,
            },
        ],
    )
}

struct TestReplayFixture {
    oracle: LedgerOracle,
    batches: Vec<EvidenceDeltaBatch>,
    objects: Vec<ReplayObject>,
    manifest_root: ContentDigest,
}

fn create_test_fixture(lineage: &str) -> Result<TestReplayFixture, Box<dyn Error>> {
    let limits = OracleLimits::new(100, 1000)?;
    let mut oracle = LedgerOracle::new(lineage, limits)?;

    // Object 1 payload & witness
    let payload1 = b"camera-alpha-capture-packet-001".to_vec();
    let witness1 = b"witness-proof-for-alpha-001".to_vec();
    let obj_payload1 = ReplayObject::new(
        ObjectId::parse("object:payload:alpha:1")?,
        Plane::Authority,
        payload1,
    );
    let obj_witness1 = ReplayObject::new(
        ObjectId::parse("object:witness:alpha:1")?,
        Plane::Authority,
        witness1,
    );

    // Child root 1
    let child_payload1 = b"child-manifest-root-001".to_vec();
    let obj_child1 = ReplayObject::new(
        ObjectId::parse("object:manifest:child:1")?,
        Plane::Authority,
        child_payload1,
    );

    let delta1 = EvidenceDelta {
        delta_id: "delta:alpha:1".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:camera:alpha")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?,
        plane: Plane::Authority,
        payload_digest: obj_payload1.digest,
        witness_digest: Some(obj_witness1.digest),
        operation_id: None,
    };

    let batch1 = oracle.prepare_batch(
        BatchId::parse("batch:alpha:1")?,
        vec![delta1],
        [obj_child1.digest],
    )?;
    let stage1 = oracle.stage(batch1.clone())?;
    oracle.commit(stage1)?;

    // Object 2 payload
    let payload2 = b"camera-beta-capture-packet-002".to_vec();
    let obj_payload2 = ReplayObject::new(
        ObjectId::parse("object:payload:beta:2")?,
        Plane::Authority,
        payload2,
    );

    let delta2 = EvidenceDelta {
        delta_id: "delta:beta:2".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:camera:beta")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(2_000), TimestampNs(3_000))?,
        plane: Plane::Authority,
        payload_digest: obj_payload2.digest,
        witness_digest: None,
        operation_id: None,
    };

    let batch2 = oracle.prepare_batch(BatchId::parse("batch:beta:2")?, vec![delta2], Vec::new())?;
    let stage2 = oracle.stage(batch2.clone())?;
    oracle.commit(stage2)?;

    let objects = vec![obj_payload1, obj_witness1, obj_child1, obj_payload2];
    let manifest_root = oracle.head_anchor().state_root;

    Ok(TestReplayFixture {
        oracle,
        batches: vec![batch1, batch2],
        objects,
        manifest_root,
    })
}

#[test]
fn test_replay_bundle_roundtrip_bit_identical_state_root() -> TestResult {
    let lineage = "site:test:replay:roundtrip";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata.clone(),
        fault_schedule.clone(),
        fixture.batches.clone(),
        fixture.objects.clone(),
    )?;

    // 1. Write bundle to disk
    let path = temp_bundle_path("roundtrip");
    let receipt = ReplayBundleWriter::write_to_path(&path, &bundle)?;
    assert_eq!(receipt.manifest_root, fixture.manifest_root);
    assert_eq!(receipt.batch_count, 2);
    assert_eq!(receipt.object_count, 4);
    assert!(receipt.total_bytes > 0);

    // 2. Read back from path with rigorous validation
    let read_bundle = ReplayBundleReader::read_from_path(&path)?;
    assert_eq!(read_bundle.manifest_root(), fixture.manifest_root);
    assert_eq!(read_bundle.metadata(), &metadata);
    assert_eq!(read_bundle.fault_schedule(), &fault_schedule);
    assert_eq!(read_bundle.batches().len(), 2);
    assert_eq!(read_bundle.objects().len(), 4);

    // 3. Replay through fresh oracle and verify bit-identical state root
    let replayed_oracle = read_bundle.replay()?;
    assert_eq!(replayed_oracle.head_anchor(), fixture.oracle.head_anchor());
    assert_eq!(
        replayed_oracle.head_anchor().state_root,
        fixture.oracle.head_anchor().state_root
    );
    assert_eq!(
        replayed_oracle.head_history_root(),
        fixture.oracle.head_history_root()
    );
    assert_eq!(replayed_oracle.head_anchor().commit_sequence, 2);

    // 4. Replay through an existing oracle at genesis
    let limits = OracleLimits::new(100, 1000)?;
    let mut oracle2 = LedgerOracle::new(lineage, limits)?;
    let commit_receipt = read_bundle.replay_through_oracle(&mut oracle2)?;
    assert_eq!(commit_receipt.anchor, *fixture.oracle.head_anchor());
    assert_eq!(
        oracle2.head_anchor().state_root,
        fixture.oracle.head_anchor().state_root
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_replay_bundle_spool_objects() -> TestResult {
    let lineage = "site:test:replay:spool";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects.clone(),
    )?;

    let spool_dir = temp_bundle_path("spool-objects-dir");
    let _ = fs::remove_dir_all(&spool_dir);
    let limits = SpoolLimits::new(16, 1024 * 1024, 1024 * 1024, 64);
    let mut spool = StagingSpool::open(&spool_dir, limits)?;
    let receipts = bundle.spool_objects(&mut spool)?;
    assert_eq!(receipts.len(), fixture.objects.len());

    for (receipt, obj) in receipts.iter().zip(fixture.objects.iter()) {
        assert_eq!(receipt.digest, obj.digest);
        let stored = spool.read(receipt.digest)?;
        assert_eq!(stored, obj.payload);
    }

    let _ = fs::remove_dir_all(&spool_dir);
    Ok(())
}

#[test]
fn test_manifest_closure_missing_payload_fails_closed() -> TestResult {
    let lineage = "site:test:replay:closure_payload";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Missing delta payload object: retain only witness, child, and second payload
    let mut incomplete_objects = fixture.objects.clone();
    let missing_obj = incomplete_objects.remove(0); // missing obj_payload1

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        incomplete_objects,
    );

    match res {
        Err(ReplayBundleError::BrokenManifestClosure { missing_digest }) => {
            assert_eq!(missing_digest, missing_obj.digest);
        }
        other => return Err(format!("expected BrokenManifestClosure, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_manifest_closure_missing_witness_fails_closed() -> TestResult {
    let lineage = "site:test:replay:closure_witness";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Missing witness object
    let mut incomplete_objects = fixture.objects.clone();
    let missing_obj = incomplete_objects.remove(1); // missing obj_witness1

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        incomplete_objects,
    );

    match res {
        Err(ReplayBundleError::BrokenManifestClosure { missing_digest }) => {
            assert_eq!(missing_digest, missing_obj.digest);
        }
        other => return Err(format!("expected BrokenManifestClosure, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_manifest_closure_missing_child_root_fails_closed() -> TestResult {
    let lineage = "site:test:replay:closure_child";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Missing child root object
    let mut incomplete_objects = fixture.objects.clone();
    let missing_obj = incomplete_objects.remove(2); // missing obj_child1

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        incomplete_objects,
    );

    match res {
        Err(ReplayBundleError::BrokenManifestClosure { missing_digest }) => {
            assert_eq!(missing_digest, missing_obj.digest);
        }
        other => return Err(format!("expected BrokenManifestClosure, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_tampered_object_payload_digest_mismatch_fails_closed() -> TestResult {
    let lineage = "site:test:replay:tampered_obj";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let mut bytes = ReplayBundleWriter::to_bytes(&bundle)?;

    // Locate the first object payload inside serialized bytes and corrupt one byte
    let needle = b"camera-alpha-capture-packet-001";
    let pos = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or("needle not found in bytes")?;
    bytes[pos] ^= 0xFF;

    // Reading back must detect corruption either in object digest or trailer checksum
    let res = ReplayBundleReader::from_bytes(&bytes);
    match res {
        Err(ReplayBundleError::ChecksumMismatch { .. })
        | Err(ReplayBundleError::ObjectDigestMismatch { .. }) => {
            // Correct fail-closed behavior
        }
        other => return Err(format!("expected corruption error, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_corrupted_checksum_trailer_fails_closed() -> TestResult {
    let lineage = "site:test:replay:corrupt_trailer";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let mut bytes = ReplayBundleWriter::to_bytes(&bundle)?;
    // Corrupt the last byte (part of SHA-256 trailer checksum)
    let last_idx = bytes.len() - 1;
    bytes[last_idx] ^= 0xFF;

    let res = ReplayBundleReader::from_bytes(&bytes);
    match res {
        Err(ReplayBundleError::ChecksumMismatch { .. }) => {
            // Correct: trailer checksum rejection
        }
        other => return Err(format!("expected ChecksumMismatch, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_truncated_bundle_fails_closed() -> TestResult {
    let lineage = "site:test:replay:truncate";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let bytes = ReplayBundleWriter::to_bytes(&bundle)?;

    // Truncate at various cutoffs
    let cutoffs = [
        0,
        4,
        8,
        16,
        bytes.len() / 4,
        bytes.len() / 2,
        bytes.len() - 34, // right before trailer
        bytes.len() - 1,  // missing last byte of trailer
    ];

    for cutoff in cutoffs {
        let truncated = &bytes[..cutoff];
        let res = ReplayBundleReader::from_bytes(truncated);
        assert!(
            res.is_err(),
            "expected error for truncated bundle of len {cutoff}, got Ok"
        );
    }

    Ok(())
}

#[test]
fn test_discontinuous_batch_sequence_fails_closed() -> TestResult {
    let lineage = "site:test:replay:discontinuous";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Create a batch whose basis anchor does not match batch 1's new anchor
    let mut invalid_batches = fixture.batches.clone();
    invalid_batches[1].basis_anchor.commit_sequence = 999;
    invalid_batches[1].batch_digest = invalid_batches[1].computed_digest();

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        invalid_batches,
        fixture.objects,
    );

    match res {
        Err(ReplayBundleError::BatchDiscontinuousAnchor { .. })
        | Err(ReplayBundleError::BatchSequenceInvalid { .. }) => {
            // Correct behavior
        }
        other => return Err(format!("expected discontinuity error, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_batch_lineage_mismatch_fails_closed() -> TestResult {
    let lineage = "site:test:replay:lineage";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata("site:foreign:lineage"); // mismatch with batch lineage
    let fault_schedule = sample_fault_schedule()?;

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    );

    match res {
        Err(ReplayBundleError::BatchLineageMismatch { .. }) => {
            // Correct behavior
        }
        other => return Err(format!("expected BatchLineageMismatch, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_empty_bundle_fails_closed() -> TestResult {
    let lineage = "site:test:replay:empty";
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let res = ReplayBundle::new(
        ContentDigest::sha256(b"empty"),
        metadata,
        fault_schedule,
        Vec::new(),
        Vec::new(),
    );

    match res {
        Err(ReplayBundleError::EmptyBundle) => {
            // Correct behavior
        }
        other => return Err(format!("expected EmptyBundle, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_batches_at_bound_and_bound_plus_one() -> TestResult {
    let lineage = "site:test:replay:bound_batches";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Limit max_batches to exactly 2 (at bound)
    let limits_at_bound = ReplayBundleLimits {
        max_batches: 2,
        ..ReplayBundleLimits::default()
    };
    let bundle_at_bound = ReplayBundle::new_with_limits(
        fixture.manifest_root,
        metadata.clone(),
        fault_schedule.clone(),
        fixture.batches.clone(),
        fixture.objects.clone(),
        &limits_at_bound,
    );
    assert!(bundle_at_bound.is_ok(), "at bound must succeed");

    // Limit max_batches to 1 (fixture has 2, so bound + 1)
    let limits_exceeded = ReplayBundleLimits {
        max_batches: 1,
        ..ReplayBundleLimits::default()
    };
    let bundle_exceeded = ReplayBundle::new_with_limits(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
        &limits_exceeded,
    );
    match bundle_exceeded {
        Err(ReplayBundleError::BoundExceeded("batches")) => {}
        other => return Err(format!("expected BoundExceeded(batches), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_objects_at_bound_and_bound_plus_one() -> TestResult {
    let lineage = "site:test:replay:bound_objects";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Limit max_objects to exactly 4 (at bound)
    let limits_at_bound = ReplayBundleLimits {
        max_objects: 4,
        ..ReplayBundleLimits::default()
    };
    let bundle_at_bound = ReplayBundle::new_with_limits(
        fixture.manifest_root,
        metadata.clone(),
        fault_schedule.clone(),
        fixture.batches.clone(),
        fixture.objects.clone(),
        &limits_at_bound,
    );
    assert!(bundle_at_bound.is_ok(), "at bound must succeed");

    // Limit max_objects to 3 (fixture has 4, so bound + 1)
    let limits_exceeded = ReplayBundleLimits {
        max_objects: 3,
        ..ReplayBundleLimits::default()
    };
    let bundle_exceeded = ReplayBundle::new_with_limits(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
        &limits_exceeded,
    );
    match bundle_exceeded {
        Err(ReplayBundleError::BoundExceeded("objects")) => {}
        other => return Err(format!("expected BoundExceeded(objects), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_fault_directives_at_bound_and_bound_plus_one() -> TestResult {
    let schedule_at_bound = ReplayFaultSchedule::new(
        1,
        MAX_REPLAY_FAULT_REORDER_WINDOW,
        vec![
            ReplayFaultDirective {
                source_sequence: 1,
                action: ReplayFaultAction::Pass,
            };
            MAX_REPLAY_FAULT_DIRECTIVES
        ],
    );
    assert!(schedule_at_bound.is_ok(), "at bound must succeed");

    let schedule_exceeded = ReplayFaultSchedule::new(
        1,
        MAX_REPLAY_FAULT_REORDER_WINDOW,
        vec![
            ReplayFaultDirective {
                source_sequence: 1,
                action: ReplayFaultAction::Pass,
            };
            MAX_REPLAY_FAULT_DIRECTIVES + 1
        ],
    );
    match schedule_exceeded {
        Err(ReplayBundleError::BoundExceeded("fault_directives")) => {}
        other => {
            return Err(format!("expected BoundExceeded(fault_directives), got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_bounds_fault_reorder_window_at_bound_and_bound_plus_one() -> TestResult {
    let schedule_at_bound =
        ReplayFaultSchedule::new(1, MAX_REPLAY_FAULT_REORDER_WINDOW, Vec::new());
    assert!(schedule_at_bound.is_ok(), "at bound must succeed");

    let schedule_exceeded =
        ReplayFaultSchedule::new(1, MAX_REPLAY_FAULT_REORDER_WINDOW + 1, Vec::new());
    match schedule_exceeded {
        Err(ReplayBundleError::BoundExceeded("fault_reorder_window")) => {}
        other => {
            return Err(
                format!("expected BoundExceeded(fault_reorder_window), got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_bounds_object_payload_bytes_at_bound_and_bound_plus_one() -> TestResult {
    let lineage = "site:test:replay:bound_payload";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    // Determine max payload size in fixture
    let max_len = fixture
        .objects
        .iter()
        .map(|o| o.payload.len())
        .max()
        .unwrap_or(0);

    let limits_at_bound = ReplayBundleLimits {
        max_object_bytes: max_len,
        ..ReplayBundleLimits::default()
    };
    let bundle_at_bound = ReplayBundle::new_with_limits(
        fixture.manifest_root,
        metadata.clone(),
        fault_schedule.clone(),
        fixture.batches.clone(),
        fixture.objects.clone(),
        &limits_at_bound,
    );
    assert!(bundle_at_bound.is_ok(), "at bound must succeed");

    let limits_exceeded = ReplayBundleLimits {
        max_object_bytes: max_len.saturating_sub(1),
        ..ReplayBundleLimits::default()
    };
    let bundle_exceeded = ReplayBundle::new_with_limits(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
        &limits_exceeded,
    );
    match bundle_exceeded {
        Err(ReplayBundleError::BoundExceeded("object_payload")) => {}
        other => {
            return Err(format!("expected BoundExceeded(object_payload), got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_bounds_site_lineage_text_at_bound_and_bound_plus_one() -> TestResult {
    let lineage_len = 20;
    let lineage = "a".repeat(lineage_len);
    let metadata = sample_metadata(&lineage);

    let limits_at_bound = ReplayBundleLimits {
        max_text_bytes: lineage_len,
        ..ReplayBundleLimits::default()
    };
    assert!(metadata.validate(&limits_at_bound).is_ok());

    let limits_exceeded = ReplayBundleLimits {
        max_text_bytes: lineage_len - 1,
        ..ReplayBundleLimits::default()
    };
    match metadata.validate(&limits_exceeded) {
        Err(ReplayBundleError::BoundExceeded("site_lineage")) => {}
        other => return Err(format!("expected BoundExceeded(site_lineage), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_total_bytes_at_bound_and_bound_plus_one() -> TestResult {
    let lineage = "site:test:replay:total_bytes";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let bytes = ReplayBundleWriter::to_bytes(&bundle)?;
    let total_len = bytes.len();

    let limits_at_bound = ReplayBundleLimits {
        max_total_bytes: total_len,
        ..ReplayBundleLimits::default()
    };
    let res_at_bound = ReplayBundleWriter::to_bytes_with_limits(&bundle, &limits_at_bound);
    assert!(res_at_bound.is_ok(), "at bound must succeed");

    let limits_exceeded = ReplayBundleLimits {
        max_total_bytes: total_len - 1,
        ..ReplayBundleLimits::default()
    };
    let res_exceeded = ReplayBundleWriter::to_bytes_with_limits(&bundle, &limits_exceeded);
    match res_exceeded {
        Err(ReplayBundleError::BoundExceeded("total_bytes")) => {}
        other => return Err(format!("expected BoundExceeded(total_bytes), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_replay_temp_path_is_pure_function() -> TestResult {
    let dummy_path = PathBuf::from("/tmp/test/bundle.replay");
    let dummy_digest = ContentDigest::sha256(b"pure-test");
    let path0 = replay_temp_path_for(&dummy_path, dummy_digest, 0);
    let path1 = replay_temp_path_for(&dummy_path, dummy_digest, 1);
    assert_ne!(path0, path1);
    let path0_again = replay_temp_path_for(&dummy_path, dummy_digest, 0);
    assert_eq!(path0, path0_again);
    assert!(
        path0
            .to_string_lossy()
            .contains(&format!("{}", std::process::id()))
    );
    Ok(())
}

#[test]
fn test_replay_bundle_writer_skips_existing_temp_and_does_not_clobber() -> TestResult {
    let lineage = "site:test:replay:skips_existing";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let path = temp_bundle_path("skips-existing");
    let _ = fs::remove_file(&path);

    // Compute the digest to determine candidate temp paths
    let bundle_digest = bundle.digest()?;
    let temp_attempt0 = replay_temp_path_for(&path, bundle_digest, 0);

    // Plant an existing file at attempt 0 with sentinel bytes
    let sentinel = b"sentinel-bytes-that-must-survive";
    fs::write(&temp_attempt0, sentinel)?;

    // Write should succeed by taking attempt 1
    let receipt = ReplayBundleWriter::write_to_path(&path, &bundle)?;
    assert_eq!(receipt.manifest_root, fixture.manifest_root);

    // Sentinel at attempt 0 must remain completely untouched
    let surviving = fs::read(&temp_attempt0)?;
    assert_eq!(surviving, sentinel);

    // Clean up
    let _ = fs::remove_file(&temp_attempt0);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn test_replay_bundle_writer_bounded_temp_retry_exhaustion_is_typed() -> TestResult {
    let lineage = "site:test:replay:exhaustion";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let path = temp_bundle_path("exhaustion");
    let _ = fs::remove_file(&path);

    let bundle_digest = bundle.digest()?;

    // Plant existing files for all bounded attempts 0..MAX_REPLAY_TEMP_ATTEMPTS
    let mut planted_paths = Vec::new();
    for attempt in 0..MAX_REPLAY_TEMP_ATTEMPTS {
        let p = replay_temp_path_for(&path, bundle_digest, attempt);
        fs::write(&p, format!("occupied-attempt-{attempt}"))?;
        planted_paths.push(p);
    }

    // Attempting to write must fail with typed ReplayTempExhausted error
    let res = ReplayBundleWriter::write_to_path(&path, &bundle);
    match res {
        Err(ReplayBundleError::ReplayTempExhausted { attempts, .. }) => {
            assert_eq!(attempts, MAX_REPLAY_TEMP_ATTEMPTS);
        }
        other => {
            return Err(format!("expected ReplayTempExhausted, got {other:?}").into());
        }
    }

    // Destination file must not exist
    assert!(!path.exists());

    // Clean up planted paths
    for p in planted_paths {
        let _ = fs::remove_file(p);
    }

    Ok(())
}

#[test]
fn test_replay_bundle_digest_returns_result_and_never_fabricates() -> TestResult {
    let lineage = "site:test:replay:digest_result";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = sample_fault_schedule()?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    // Valid bundle digest returns Ok
    let digest = bundle.digest()?;
    assert_ne!(digest, ContentDigest::sha256(b""));

    // Constrained limits must return typed BoundExceeded error, NEVER fabricate empty sha256
    let tight_limits = ReplayBundleLimits {
        max_batches: 1, // bundle has 2 batches
        ..ReplayBundleLimits::default()
    };
    let res = bundle.digest_with_limits(&tight_limits);
    match res {
        Err(ReplayBundleError::BoundExceeded("batches")) => {}
        other => return Err(format!("expected BoundExceeded(batches), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_replay_enforces_fault_schedule_drop_directive() -> TestResult {
    let lineage = "site:test:replay:fault_enforced";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);

    // Schedule a drop directive targeting batch sequence 2
    let fault_schedule = ReplayFaultSchedule::new(
        12345,
        16,
        vec![ReplayFaultDirective {
            source_sequence: 2,
            action: ReplayFaultAction::Drop,
        }],
    )?;

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    // Replay should evaluate the fault schedule and fail or alter execution
    let res = bundle.replay();
    assert!(
        res.is_err(),
        "bundle.replay() completely ignored ReplayFaultAction::Drop and committed all batches cleanly"
    );
    Ok(())
}

#[test]
fn test_replay_bundle_binds_registered_digest_domain() -> TestResult {
    let lineage = "site:test:replay:domain_tag";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let bytes = ReplayBundleWriter::to_bytes(&bundle)?;
    let domain_bytes = REPLAY_BUNDLE_DOMAIN.as_bytes();
    let contains_domain = bytes.windows(domain_bytes.len()).any(|w| w == domain_bytes);
    assert!(
        contains_domain,
        "serialized replay bundle envelope must bind registered domain tag fss.replay_bundle.v1"
    );

    let raw_sha256 = ContentDigest::sha256(&bytes[..bytes.len() - 33]);
    let bundle_digest = bundle.digest()?;
    assert_ne!(
        bundle_digest, raw_sha256,
        "bundle digest must be domain-separated using fss.replay_bundle.v1, not bare sha256"
    );
    Ok(())
}

#[test]
fn test_manifest_root_rejects_arbitrary_unrelated_object_digest() -> TestResult {
    let lineage = "site:test:replay:root_bypass";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    // Use witness object digest as manifest root
    let arbitrary_obj_digest = fixture.objects[1].digest;
    assert_ne!(arbitrary_obj_digest, fixture.manifest_root);

    let res = ReplayBundle::new(
        arbitrary_obj_digest,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    );

    assert!(
        res.is_err(),
        "ReplayBundle::new accepted an arbitrary witness object digest as manifest_root without verification"
    );
    Ok(())
}

#[test]
fn test_manifest_closure_rejects_plane_mismatch_between_delta_and_object() -> TestResult {
    let lineage = "site:test:replay:plane_mismatch";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    let mut mismatched_objects = fixture.objects.clone();
    mismatched_objects[0].plane = Plane::Effect; // Delta specifies Plane::Authority

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        mismatched_objects,
    );

    assert!(
        res.is_err(),
        "manifest closure accepted an object whose plane (Effect) disagrees with delta plane (Authority)"
    );
    Ok(())
}

#[test]
fn test_batch_sequence_u64_max_fails_with_typed_error_not_panic() -> TestResult {
    let lineage = "site:test:replay:overflow";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    let mut overflow_batches = fixture.batches.clone();
    overflow_batches[0].basis_anchor.commit_sequence = u64::MAX;
    overflow_batches[0].new_anchor.commit_sequence = 0;
    overflow_batches[0].batch_digest = overflow_batches[0].computed_digest();

    let res = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        overflow_batches,
        fixture.objects,
    );

    assert!(
        res.is_err(),
        "must return typed error on sequence overflow without panic"
    );
    Ok(())
}

#[test]
fn test_bounds_object_id_text_at_bound_and_bound_plus_one() -> TestResult {
    let lineage = "site:short";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    // Max text length for object_id
    let max_obj_id_len = fixture
        .objects
        .iter()
        .map(|o| o.object_id.as_str().len())
        .max()
        .unwrap_or(32);
    assert!(
        lineage.len() < max_obj_id_len,
        "lineage must be shorter than object_id to isolate object_id bounding"
    );

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let limits_at_bound = ReplayBundleLimits {
        max_text_bytes: max_obj_id_len,
        ..ReplayBundleLimits::default()
    };
    let res_at_bound = ReplayBundleWriter::to_bytes_with_limits(&bundle, &limits_at_bound);
    assert!(
        res_at_bound.is_ok(),
        "at bound for object_id text must succeed"
    );

    let limits_exceeded = ReplayBundleLimits {
        max_text_bytes: max_obj_id_len - 1,
        ..ReplayBundleLimits::default()
    };
    let res_exceeded = ReplayBundleWriter::to_bytes_with_limits(&bundle, &limits_exceeded);
    match res_exceeded {
        Err(ReplayBundleError::BoundExceeded("text")) => {}
        other => return Err(format!("expected BoundExceeded(text), got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_reader_rejects_invalid_domain_tag() -> TestResult {
    let lineage = "site:test:replay:invalid_domain";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let mut bytes = ReplayBundleWriter::to_bytes(&bundle)?;
    // Mutate the domain tag in the body
    let domain_bytes = REPLAY_BUNDLE_DOMAIN.as_bytes();
    let pos = bytes
        .windows(domain_bytes.len())
        .position(|w| w == domain_bytes)
        .ok_or("domain tag not found in serialized bytes")?;
    bytes[pos] = b'X';
    // Recompute trailer checksum so it passes trailer check and hits domain check
    let body_len = bytes.len() - REPLAY_TRAILER_LEN;
    let new_digest = replay_bundle_digest(&bytes[..body_len]);
    bytes[body_len + 1..].copy_from_slice(&new_digest.bytes());

    let res = ReplayBundleReader::from_bytes(&bytes);
    match res {
        Err(ReplayBundleError::InvalidDomain(domain)) => {
            assert_ne!(domain, REPLAY_BUNDLE_DOMAIN);
        }
        other => return Err(format!("expected InvalidDomain error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_writer_syncs_parent_directory_after_rename() -> TestResult {
    let lineage = "site:test:replay:dir_sync";
    let fixture = create_test_fixture(lineage)?;
    let metadata = sample_metadata(lineage);
    let fault_schedule = clean_fault_schedule();

    let bundle = ReplayBundle::new(
        fixture.manifest_root,
        metadata,
        fault_schedule,
        fixture.batches,
        fixture.objects,
    )?;

    let path = temp_bundle_path("dir-sync-proof");
    let _ = fs::remove_file(&path);

    let receipt = ReplayBundleWriter::write_to_path(&path, &bundle)?;
    assert_eq!(receipt.manifest_root, fixture.manifest_root);
    assert!(
        path.exists(),
        "Target bundle file must exist after atomic write and dir sync"
    );

    let read_bundle = ReplayBundleReader::read_from_path(&path)?;
    assert_eq!(read_bundle.manifest_root(), fixture.manifest_root);

    let _ = fs::remove_file(&path);
    Ok(())
}
