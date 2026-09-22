#![forbid(unsafe_code)]
//! Deterministic contract tests for [`ReferenceDeployment`].

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use fss_core::{
    BatchId, CapsuleId, CaptureInterval, ContentDigest, EventId, EvidenceDelta, EvidenceDeltaBatch,
    IdempotencyKey, ObjectId, ObligationId, OperationId, Plane, ProbabilityInterval, SensorId,
    TimestampNs,
};
use fss_ledger::{DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, doctor_path};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_publication::SlotName;
use fss_reference::reference_deployment::KNOWN_LEDGER_DELTA_FAMILIES;
use fss_reference::{
    DEPLOYMENT_CANCEL_STAGES, DEPLOYMENT_LAYOUT_FILENAME, DeliveryPlan, DeploymentLayout,
    DeploymentLimits, DurableEffectError, MockModelScript, MockModelSpec, MockSemanticLabel,
    PrepareAlertParams, RecoveryAction, RecoveryReceipt, ReferenceDeployment, ReferenceError,
    ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision,
    ReferenceProviderBehavior, ReplayCx, VirtualCameraSpec, execute_mock_model,
    run_reference_capture,
};

fn temp_deployment_dir(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nanos = 1_700_000_000_u64;
    let dir = std::env::temp_dir().join(format!(
        "fss-ref-deploy-{tag}-{nanos}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn sample_interval(start: u64, end: u64) -> Result<CaptureInterval, Box<dyn Error>> {
    let earliest = TimestampNs(start as i128);
    let latest = TimestampNs(end as i128);
    Ok(CaptureInterval::new(earliest, latest)?)
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = fss_core::RootAuthoritySpec {
        trace_id: format!("trace:test-{label}"),
        operation_id: OperationId::parse(format!("operation:test-{label}"))?,
        principal: format!("operator:test-{label}"),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = fss_core::ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("test-replay-cx-{label}-{}", std::process::id()));
    let io = fss_reference::ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

#[test]
fn open_and_reopen_empty_and_existing_root() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("open-reopen")?;
    let cx = test_cx("open-reopen")?;

    // 1. Open empty root creates all required directories and LAYOUT.
    let mut dep = ReferenceDeployment::open(&dir, "site:deploy:test", &cx)?;
    assert_eq!(dep.root(), dir.as_path());
    assert_eq!(dep.site_lineage(), "site:deploy:test");

    let layout_file = dir.join(DEPLOYMENT_LAYOUT_FILENAME);
    assert!(layout_file.exists());
    let expected_layout = DeploymentLayout::new(
        "site:deploy:test",
        DeploymentLimits::standard().canonical_digest()?,
    );
    assert_eq!(dep.layout_report(), &expected_layout);

    // Stage and publish an object.
    let slot = SlotName::parse("slot-sample")?;
    let staged = dep.stage_and_publish(&slot, &[b"sample-payload-1"], &cx)?;
    assert_eq!(staged.slot, slot);
    let manifest = ObjectManifest::new("slot-sample", staged.manifest.children().to_vec(), None)?;
    let receipt = dep.publish_and_commit(&slot, &manifest, sample_interval(1, 2)?, &cx)?;
    assert_eq!(receipt.slot, slot);

    let anchor_before = dep.current_anchor().clone();
    drop(dep);

    // 2. Reopen existing root recovers layout and state.
    let dep2 = ReferenceDeployment::reopen(&dir, "site:deploy:test", &cx)?;
    assert_eq!(dep2.current_anchor(), &anchor_before);
    assert_eq!(dep2.layout_report(), &expected_layout);

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn dir_entry_names(dir: &std::path::Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

#[test]
fn not_a_deployment_on_non_empty_root_without_layout() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("not-a-deployment")?;
    let cx = test_cx("not-a-deployment")?;

    // Populate directory with foreign file and no LAYOUT.
    fs::write(dir.join("foreign.txt"), b"foreign data")?;

    let err = match ReferenceDeployment::open(&dir, "site:nonempty", &cx) {
        Err(e) => e,
        Ok(_) => return Err("expected open on non-empty root without LAYOUT to fail".into()),
    };
    assert!(err.is_not_a_deployment());
    assert_eq!(fs::read(dir.join("foreign.txt"))?, b"foreign data");
    assert_eq!(dir_entry_names(&dir)?, vec!["foreign.txt"]);

    // open_for_recovery must also refuse without creating LAYOUT or objects.
    let rec_err = match ReferenceDeployment::open_for_recovery(
        &dir,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    ) {
        Err(e) => e,
        Ok(_) => return Err("expected recovery on non-deployment to fail".into()),
    };
    assert!(rec_err.is_not_a_deployment());
    assert!(!dir.join(DEPLOYMENT_LAYOUT_FILENAME).exists());
    assert!(!dir.join("objects").exists());
    assert_eq!(dir_entry_names(&dir)?, vec!["foreign.txt"]);

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn path_independence_produces_identical_digests_and_anchors() -> Result<(), Box<dyn Error>> {
    let dir_a = temp_deployment_dir("path-indep-a")?;
    let dir_b = temp_deployment_dir("path-indep-b")?;
    let cx = test_cx("path-indep")?;

    let mut dep_a = ReferenceDeployment::open(&dir_a, "site:path:indep", &cx)?;
    let mut dep_b = ReferenceDeployment::open(&dir_b, "site:path:indep", &cx)?;

    // Layout digests must be identical regardless of root path.
    let digest_a = dep_a.layout_report().canonical_digest()?;
    let digest_b = dep_b.layout_report().canonical_digest()?;
    assert_eq!(digest_a, digest_b);

    // Identical staging and publication produce identical receipts.
    let slot = SlotName::parse("slot-deterministic")?;
    let payload = b"deterministic-content-bytes-001";
    let digest_a = dep_a.stage_payload(payload)?;
    let digest_b = dep_b.stage_payload(payload)?;
    assert_eq!(digest_a, digest_b);

    // Identical publish_and_commit produces identical root ledger receipts.
    let manifest_a = ObjectManifest::new("slot-deterministic", [digest_a], None)?;
    let manifest_b = ObjectManifest::new("slot-deterministic", [digest_b], None)?;
    let validity = sample_interval(100, 200)?;

    let commit_a = dep_a.publish_and_commit(&slot, &manifest_a, validity, &cx)?;
    let commit_b = dep_b.publish_and_commit(&slot, &manifest_b, validity, &cx)?;
    assert_eq!(commit_a.root, commit_b.root);
    assert_eq!(commit_a.anchor, commit_b.anchor);
    assert_eq!(dep_a.current_anchor(), dep_b.current_anchor());

    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
    Ok(())
}

#[test]
fn second_concurrent_open_returns_deployment_locked() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("locked")?;
    let cx = test_cx("locked")?;

    let dep1 = ReferenceDeployment::open(&dir, "site:lock:test", &cx)?;

    // Second open on the same root returns typed DeploymentLocked error.
    let err = match ReferenceDeployment::open(&dir, "site:lock:test", &cx) {
        Err(e) => e,
        Ok(_) => return Err("expected second open to fail with deployment locked".into()),
    };

    assert!(err.is_deployment_locked());
    match err {
        ReferenceError::DeploymentLocked { path } => {
            assert_eq!(path, dir.join("objects").join("LOCK"));
        }
        other => return Err(format!("expected DeploymentLocked, got {other:?}").into()),
    }

    // Drop first deployment; second open now succeeds.
    drop(dep1);
    let dep2 = ReferenceDeployment::open(&dir, "site:lock:test", &cx)?;
    assert_eq!(dep2.site_lineage(), "site:lock:test");

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn refused_second_open_leaves_both_journals_byte_identical() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("journals-untouched")?;
    let cx = test_cx("journals-untouched")?;

    let mut dep1 = ReferenceDeployment::open(&dir, "site:untouched", &cx)?;
    let slot = SlotName::parse("slot-untouched")?;
    let payload_digest = dep1.stage_payload(b"untouched-payload")?;
    let manifest = ObjectManifest::new("slot-untouched", [payload_digest], None)?;
    let _commit = dep1.publish_and_commit(&slot, &manifest, sample_interval(10, 20)?, &cx)?;

    let ledger_path = dir.join("ledger/journal.fssj");
    let effects_path = dir.join("effects/journal.fssj");

    let ledger_bytes_before = fs::read(&ledger_path)?;
    let effects_bytes_before = fs::read(&effects_path)?;

    // Attempt second open while dep1 is active.
    let err = match ReferenceDeployment::open(&dir, "site:untouched", &cx) {
        Err(e) => e,
        Ok(_) => return Err("expected second open to fail".into()),
    };
    assert!(err.is_deployment_locked());

    // Both journals must remain strictly byte-identical.
    let ledger_bytes_after = fs::read(&ledger_path)?;
    let effects_bytes_after = fs::read(&effects_path)?;
    assert_eq!(ledger_bytes_before, ledger_bytes_after);
    assert_eq!(effects_bytes_before, effects_bytes_after);

    drop(dep1);
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn incomplete_journal_tail_surfaces_typed_error_and_open_for_recovery_truncates()
-> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("incomplete-tail")?;
    let cx = test_cx("incomplete-tail")?;

    let mut dep = ReferenceDeployment::open(&dir, "site:tail:test", &cx)?;
    let slot = SlotName::parse("slot-tail")?;
    let payload_digest = dep.stage_payload(b"tail-object")?;
    let manifest = ObjectManifest::new("slot-tail", [payload_digest], None)?;
    let _commit = dep.publish_and_commit(&slot, &manifest, sample_interval(10, 20)?, &cx)?;
    drop(dep);

    // Corrupt ledger journal by appending a torn record header (matching magic prefix).
    let ledger_path = dir.join("ledger/journal.fssj");
    let len_before = fs::metadata(&ledger_path)?.len();
    {
        let mut file = OpenOptions::new().append(true).open(&ledger_path)?;
        file.write_all(b"FSSJRN01\x00\x01torn-header-bytes")?;
        file.flush()?;
    }

    // Reopen must reject incomplete tail with next_affordance naming recover.
    let expected_affordance = format!(
        "fss-lab recover --root {} --truncate-ledger-tail",
        dir.display()
    );
    let err = match ReferenceDeployment::open(&dir, "site:tail:test", &cx) {
        Err(e) => e,
        Ok(_) => return Err("expected open to reject incomplete tail".into()),
    };

    match err {
        ReferenceError::IncompleteJournalTail {
            path,
            next_affordance,
            ..
        } => {
            assert_eq!(path, ledger_path);
            assert_eq!(next_affordance, expected_affordance);
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    // Execute open_for_recovery to truncate incomplete tail.
    let recovery_receipt = ReferenceDeployment::open_for_recovery(
        &dir,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    )?;

    match recovery_receipt {
        RecoveryReceipt::TruncatedLedgerTail {
            path,
            committed_len,
            truncated_bytes,
            last_root_before,
            last_root_after,
        } => {
            assert_eq!(path, ledger_path);
            assert_eq!(committed_len, len_before);
            assert_eq!(truncated_bytes, 8 + 2 + 17); // magic (8) + version (2) + torn text (17)
            assert_eq!(last_root_before, last_root_after);
        }
        other => return Err(format!("unexpected recovery receipt: {other:?}").into()),
    }

    // Reopen now succeeds cleanly.
    let dep2 = ReferenceDeployment::open(&dir, "site:tail:test", &cx)?;
    assert_eq!(dep2.site_lineage(), "site:tail:test");

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn recovery_refuses_corrupt_history_with_structurally_valid_record() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("corrupt-history")?;
    let cx = test_cx("corrupt-history")?;

    let mut dep = ReferenceDeployment::open(&dir, "site:history:test", &cx)?;
    let slot = SlotName::parse("slot-history")?;
    let payload_digest = dep.stage_payload(b"history-payload-1")?;
    let manifest = ObjectManifest::new("slot-history", [payload_digest], None)?;
    let _commit = dep.publish_and_commit(&slot, &manifest, sample_interval(1, 2)?, &cx)?;
    drop(dep);

    let ledger_path = dir.join("ledger/journal.fssj");

    // Synthesize a structurally valid record with non-sequential sequence (seq 999 instead of 2).
    let record_magic = b"FSSJRN01";
    let version: u16 = 1;
    let sequence: u64 = 999;
    let kind: u16 = 1;
    let payload = b"structurally-valid-payload";
    let payload_len: u32 = payload.len() as u32;
    let previous_root = [0_u8; 32];
    let payload_digest = fss_core::sha256(payload);

    // Compute expected root for valid framing:
    let mut root_buf = Vec::new();
    root_buf.extend_from_slice(b"FSS-JOURNAL-RECORD-ROOT-V1\0");
    root_buf.extend_from_slice(&sequence.to_be_bytes());
    root_buf.extend_from_slice(&kind.to_be_bytes());
    root_buf.extend_from_slice(&payload_len.to_be_bytes());
    root_buf.extend_from_slice(&previous_root);
    root_buf.extend_from_slice(&payload_digest);
    let committed_root = fss_core::sha256(&root_buf);

    let mut valid_record_bytes = Vec::new();
    valid_record_bytes.extend_from_slice(record_magic);
    valid_record_bytes.extend_from_slice(&version.to_be_bytes());
    valid_record_bytes.extend_from_slice(&sequence.to_be_bytes());
    valid_record_bytes.extend_from_slice(&kind.to_be_bytes());
    valid_record_bytes.extend_from_slice(&payload_len.to_be_bytes());
    valid_record_bytes.extend_from_slice(&previous_root);
    valid_record_bytes.extend_from_slice(&payload_digest);
    valid_record_bytes.extend_from_slice(payload);
    valid_record_bytes.extend_from_slice(b"FSSCMT01");
    valid_record_bytes.extend_from_slice(&committed_root);

    // Append this valid record to the ledger.
    {
        let mut file = OpenOptions::new().append(true).open(&ledger_path)?;
        file.write_all(&valid_record_bytes)?;
        file.flush()?;
    }

    // doctor reports foreign range starting at this record.
    let report = doctor_path(&ledger_path)?;
    assert!(report.has_foreign_bytes());
    let plan = report.plan(&ledger_path)?;

    // Attempting to apply repair must be refused with RecoverCorruptHistory.
    let err = match ReferenceDeployment::open_for_recovery(
        &dir,
        RecoveryAction::ApplySealedLedgerRepair {
            plan_digest: plan.plan_digest(),
        },
        &cx,
    ) {
        Err(e) => e,
        Ok(_) => return Err("expected recovery to refuse corrupt history".into()),
    };

    assert!(err.is_recover_corrupt_history());
    match err {
        ReferenceError::RecoverCorruptHistory { path, offset } => {
            assert_eq!(path, ledger_path);
            assert_eq!(offset, report.committed_len());
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn recovery_applies_sealed_repair_for_non_record_foreign_bytes() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("quarantine-garbage")?;
    let cx = test_cx("quarantine-garbage")?;

    let mut dep = ReferenceDeployment::open(&dir, "site:garbage:test", &cx)?;
    let slot = SlotName::parse("slot-garbage")?;
    let payload_digest = dep.stage_payload(b"pre-garbage-payload")?;
    let manifest = ObjectManifest::new("slot-garbage", [payload_digest], None)?;
    let _commit = dep.publish_and_commit(&slot, &manifest, sample_interval(1, 5)?, &cx)?;
    drop(dep);

    let ledger_path = dir.join("ledger/journal.fssj");
    let committed_len_before = fs::metadata(&ledger_path)?.len();

    // Append arbitrary trailing garbage (no RECORD_MAGIC).
    {
        let mut file = OpenOptions::new().append(true).open(&ledger_path)?;
        file.write_all(b"random-non-record-foreign-trailing-bytes-1234567890")?;
        file.flush()?;
    }

    let report = doctor_path(&ledger_path)?;
    assert!(report.has_foreign_bytes());
    let plan = report.plan(&ledger_path)?;

    let recovery_receipt = ReferenceDeployment::open_for_recovery(
        &dir,
        RecoveryAction::ApplySealedLedgerRepair {
            plan_digest: plan.plan_digest(),
        },
        &cx,
    )?;

    match recovery_receipt {
        RecoveryReceipt::AppliedLedgerRepair(receipt) => {
            assert_eq!(receipt.committed_len(), committed_len_before);
            assert_eq!(receipt.quarantined_length(), 51);
        }
        other => return Err(format!("unexpected recovery receipt: {other:?}").into()),
    }

    // After repair, journal reopens cleanly.
    let dep2 = ReferenceDeployment::open(&dir, "site:garbage:test", &cx)?;
    assert_eq!(dep2.site_lineage(), "site:garbage:test");

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn append_batch_idempotency_and_conflict() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("batch-idempotency")?;
    let cx = test_cx("batch-idempotency")?;

    let mut dep = ReferenceDeployment::open(&dir, "site:batch:idemp", &cx)?;
    let payload_digest_1 = dep.stage_payload(b"batch-payload-1")?;
    let payload_digest_2 = dep.stage_payload(b"batch-payload-2")?;

    let delta_1 = EvidenceDelta {
        delta_id: "delta:batch:001".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor:1")?,
        prior_generation: None,
        new_generation: 1,
        validity: sample_interval(100, 200)?,
        plane: Plane::Authority,
        payload_digest: payload_digest_1,
        witness_digest: None,
        operation_id: None,
    };

    let batch_id_1 = BatchId::parse("batch:authority:001")?;
    let anchor_1 = dep.append_batch(
        batch_id_1.clone(),
        vec![delta_1.clone()],
        vec![payload_digest_1],
        &cx,
    )?;
    assert_eq!(anchor_1.commit_sequence, 1);

    // 1. Immediate identical retry returns committed anchor.
    let retry_anchor = dep.append_batch(
        batch_id_1.clone(),
        vec![delta_1.clone()],
        vec![payload_digest_1],
        &cx,
    )?;
    assert_eq!(retry_anchor, anchor_1);

    // 2. Commit an unrelated batch.
    let delta_2 = EvidenceDelta {
        delta_id: "delta:batch:002".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor:2")?,
        prior_generation: None,
        new_generation: 1,
        validity: sample_interval(200, 300)?,
        plane: Plane::Authority,
        payload_digest: payload_digest_2,
        witness_digest: None,
        operation_id: None,
    };
    let batch_id_2 = BatchId::parse("batch:authority:002")?;
    let anchor_2 = dep.append_batch(batch_id_2, vec![delta_2], vec![payload_digest_2], &cx)?;
    assert_eq!(anchor_2.commit_sequence, 2);

    // 3. Retry batch 1 after unrelated batch commit returns original anchor_1, NOT anchor_2.
    let retry_anchor_after = dep.append_batch(
        batch_id_1.clone(),
        vec![delta_1.clone()],
        vec![payload_digest_1],
        &cx,
    )?;
    assert_eq!(retry_anchor_after, anchor_1);

    // 4. Drop and reopen: retry batch 1 still returns original anchor_1.
    drop(dep);
    let mut dep_reopened = ReferenceDeployment::open(&dir, "site:batch:idemp", &cx)?;
    let retry_reopened = dep_reopened.append_batch(
        batch_id_1.clone(),
        vec![delta_1.clone()],
        vec![payload_digest_1],
        &cx,
    )?;
    assert_eq!(retry_reopened, anchor_1);

    // 5. Conflicting content under existing batch_id_1 fails with BatchIdConflict.
    let conflicting_delta = EvidenceDelta {
        delta_id: "delta:batch:conflict".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor:conflict")?,
        prior_generation: None,
        new_generation: 1,
        validity: sample_interval(500, 600)?,
        plane: Plane::Authority,
        payload_digest: payload_digest_1,
        witness_digest: None,
        operation_id: None,
    };
    // The offered digest is the digest of the offered content under the committed batch's
    // anchors, recomputed here independently of the deployment.
    let committed = dep_reopened.ledger().batches()[0].clone();
    assert_eq!(committed.batch_id, batch_id_1);
    let offered = EvidenceDeltaBatch {
        batch_id: batch_id_1.clone(),
        basis_anchor: committed.basis_anchor.clone(),
        new_anchor: committed.new_anchor.clone(),
        deltas: vec![conflicting_delta.clone()],
        children: vec![payload_digest_1],
        batch_digest: ContentDigest::sha256(b""),
    }
    .computed_digest();
    assert_ne!(offered, committed.batch_digest);
    let conflict_err = dep_reopened.append_batch(
        batch_id_1.clone(),
        vec![conflicting_delta],
        vec![payload_digest_1],
        &cx,
    );
    match conflict_err {
        Err(ReferenceError::DurableLedger(boxed)) => match *boxed {
            DurableLedgerError::BatchIdConflict {
                batch_id,
                committed_sequence,
                committed_digest,
                offered_digest,
            } => {
                assert_eq!(batch_id, batch_id_1);
                assert_eq!(committed_sequence, 1);
                assert_eq!(committed_digest, committed.batch_digest);
                assert_eq!(offered_digest, offered);
            }
            other => return Err(format!("expected BatchIdConflict, got {other:?}").into()),
        },
        other => return Err(format!("expected a durable ledger refusal, got {other:?}").into()),
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn capacity_limits_refusals_name_limits() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("capacity-limits")?;
    let cx = test_cx("capacity-limits")?;

    let dep = ReferenceDeployment::open(&dir, "site:capacity:test", &cx)?;

    // Spool object max exceeded.
    let huge_payload = vec![0_u8; 100];
    let custom_limits = DeploymentLimits {
        spool_object_max_bytes: 50,
        ..DeploymentLimits::standard()
    };
    drop(dep);
    let _ = fs::remove_dir_all(&dir);

    let mut dep_limited =
        ReferenceDeployment::open_with_limits(&dir, "site:capacity:test", custom_limits, &cx)?;

    let err = dep_limited.stage_payload(&huge_payload);
    match err {
        Err(ReferenceError::CapacityExceeded {
            limit,
            maximum,
            actual,
        }) => {
            assert_eq!(limit, "spool_object_max_bytes");
            assert_eq!(maximum, 50);
            assert_eq!(actual, 100);
        }
        other => return Err(format!("unexpected error: {other:?}").into()),
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// Builds a policy decision corroborated by two independent virtual cameras whose captures are
/// committed in the deployment ledger, and stages the model receipts in the deployment spool so
/// the deployment can publish the event.
fn corroborated_decision(
    dep: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let captures_path = std::env::temp_dir().join(format!(
        "fss-refdep-captures-{}-{}.journal",
        "contract",
        std::process::id()
    ));
    let _stale = fs::remove_file(&captures_path);
    let mut captures = DurableReferenceLedger::open(
        &captures_path,
        "site:refdep-captures",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut observations = Vec::new();
    for (name, seed) in [("alpha", 111), ("beta", 222)] {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:cam:{name}"))?,
            sensor_id: SensorId::parse(format!("sensor:cam:{name}"))?,
            seed,
            packet_count: 2,
            packet_bytes: 32,
            start_ns: 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 1_000,
        };
        let capture = run_reference_capture(
            &spec,
            &DeliveryPlan::identity(spec.packet_count)?,
            &mut objects,
            &mut captures,
        )?;
        let model = MockModelSpec::new(
            format!("mock:cam:{name}:v1"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.99, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut objects)?;
        observations.push(ReferenceModelObservation::new(
            result,
            format!("power:cam:{name}"),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        )?);
    }
    let decision = dep.evaluate_policy(
        EventId::parse("event:unknown-presence:deployment")?,
        observations,
        cx,
    )?;
    assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);
    for receipt in &decision.event.model_receipts {
        let staged = dep.stage_payload(objects.read_verified(*receipt)?)?;
        assert_eq!(staged, *receipt);
    }
    Ok(decision)
}

#[test]
fn simulated_alert_dispatch_routes_through_deployment_provider() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("alert-dispatch")?;
    let cx = test_cx("alert-dispatch")?;

    let mut dep = ReferenceDeployment::open(&dir, "site:alert:dispatch", &cx)?;

    // A corroborated event published through the deployment, and an alert prepared against the
    // deployment's own authority ledger and durable effect journal.
    let decision = corroborated_decision(&mut dep, &cx)?;
    let event_receipt = dep.publish_event(&decision, &cx)?;
    let plan = {
        let (effects, ledger) = dep.effects_and_ledger();
        effects.prepare_alert(PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: ledger,
            operation_id: OperationId::parse("op:alert:001")?,
            idempotency_key: IdempotencyKey::parse("idemp:alert:001")?,
            obligation_id: ObligationId::parse("ob:alert:001")?,
            channel: "simulated-channel".to_owned(),
            now: TimestampNs(1_700_000_000),
        })?
    };
    assert_eq!(dep.alert_provider().message_count(), 0);

    let t_commit = TimestampNs(1_700_000_001);
    let t_outcome = TimestampNs(1_700_000_002);

    // Dispatch alert through deployment.
    let receipt = dep.dispatch_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        t_commit,
        t_outcome,
        &cx,
    )?;

    assert_eq!(receipt.state, fss_core::EffectState::AdapterAccepted);
    assert_eq!(dep.alert_provider().message_count(), 1);

    // The same dispatch again is refused by the effect journal before the provider is touched:
    // the provider still holds exactly one message.
    let repeat = dep.dispatch_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        t_commit,
        t_outcome,
        &cx,
    );
    match repeat {
        Err(ReferenceError::DurableEffect(boxed)) => assert!(
            matches!(
                *boxed,
                DurableEffectError::Contract(fss_core::ContractError::InvalidEffectTransition)
            ),
            "{boxed:?}"
        ),
        other => {
            return Err(format!("expected a refused repeat dispatch, got {other:?}").into());
        }
    }
    assert_eq!(dep.alert_provider().message_count(), 1);

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cooperative_cancellation_aborts_operations_and_drains() -> Result<(), Box<dyn Error>> {
    let dir = temp_deployment_dir("cancellation")?;
    let cx = test_cx("cancellation")?;
    cx.request_cancellation();

    let cx_open = test_cx("cancellation-open")?;
    let mut dep = ReferenceDeployment::open(&dir, "site:cancel:test", &cx_open)?;
    let slot = SlotName::parse("slot-cancel")?;

    let res = dep.stage_and_publish(&slot, &[b"payload"], &cx);
    assert!(cx.is_drain_completed());
    match res {
        Err(ReferenceError::CancellationRequested { stage }) => {
            assert_eq!(stage, "stage_objects");
        }
        Err(other) => return Err(format!("unexpected cancellation error: {other:?}").into()),
        Ok(_) => return Err("expected cancellation to fail operation".into()),
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn exported_constants_and_tables_integrity() -> Result<(), Box<dyn Error>> {
    // 10 = 9 + FAMILY_FILE_IMPORT (fss-2h5zq.23).
    assert_eq!(KNOWN_LEDGER_DELTA_FAMILIES.len(), 10);
    for family in KNOWN_LEDGER_DELTA_FAMILIES {
        assert!(!family.is_empty());
    }

    // The standard limits are mutually consistent for the publisher and its spool.
    DeploymentLimits::standard()
        .to_publication_limits()
        .validate()?;

    assert_eq!(DEPLOYMENT_CANCEL_STAGES.len(), 14);
    for stage in DEPLOYMENT_CANCEL_STAGES {
        assert!(!stage.is_empty());
    }

    for point in [
        fss_publication::PublishCutPoint::AfterChildrenVerified,
        fss_publication::PublishCutPoint::AfterManifestBody,
        fss_publication::PublishCutPoint::AfterRootTempWrite,
        fss_publication::PublishCutPoint::AfterRootRename,
    ] {
        let err: ReferenceError =
            fss_publication::LocalPublicationError::Cancelled { point }.into();
        match err {
            ReferenceError::CancellationRequested { stage } => {
                assert!(DEPLOYMENT_CANCEL_STAGES.contains(&stage));
            }
            other => return Err(format!("expected CancellationRequested, got {other:?}").into()),
        }
    }
    Ok(())
}
