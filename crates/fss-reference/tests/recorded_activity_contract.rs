#![forbid(unsafe_code)]
//! Real retained imports through the native activity producer's failure and retry boundaries.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EvidenceOrigin, KnowledgeCell, KnowledgeState,
    ObjectId, OperationId, Plane, ProvenanceClass, RootAuthoritySpec, SensorId, StreamId,
    TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_reference::activity_replay::ActivityReplayPlan;
use fss_reference::activity_replay::operator::{
    ActivityVerificationLimits, ActivityVerificationRequest, VerifiedActivityObservation,
    verify_retained_activity,
};
use fss_reference::activity_replay::provenance::{ActivityEvidenceRole, ActivityProjectionError};
use fss_reference::executor_activity::ActivityThresholdPolicy;
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1_SHA256;
use fss_reference::ingest::recorded_activity::{
    RecordedActivityError, RecordedActivityLimits, RecordedActivityRequest,
    STAGE_ACTIVITY_BEFORE_PUBLISH, STAGE_ACTIVITY_RESULT, produce_recorded_activity,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, ExecBudget, FileIngestAdapter, FileIngestLimits,
    FileIngestRequest, ReferenceDeployment, ReplayCx, ReplayIoAuthority, ScalarExecCx,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:recorded-activity";
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> TestResult<Self> {
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-recorded-activity-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("scratch directory allowance exhausted".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-activity".to_owned(),
        operation_id: OperationId::parse("operation:recorded-activity")?,
        principal: "operator:recorded-activity".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned(), ADP_FILE_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"recorded-activity-test"),
        generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.join("scratch"),
    )?))
}

struct Fixture {
    deployment: ReferenceDeployment,
    request: RecordedActivityRequest,
    cx: ReplayCx,
    root: PathBuf,
    _scratch: Scratch,
}
fn fixture() -> TestResult<Fixture> {
    recording(&[BACKGROUND, GRADIENT], 0, 1)
}

fn recording(sources: &[&[u8]], reference_segment: usize, segment: usize) -> TestResult<Fixture> {
    let scratch = Scratch::new()?;
    let root = scratch.0.join("deployment");
    let cx = context(&scratch.0)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let input = scratch.0.join("input.mjpeg");
    fs::write(&input, sources.concat())?;
    let sensor = SensorId::parse("sensor:recorded-activity")?;
    let stream = StreamId::parse("stream:recorded-activity")?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(&input, sensor.clone(), stream.clone())
            .with_receive_time(TimestampNs(5_000_000_000))
            .with_limits(FileIngestLimits {
                chunk_bytes: 67,
                max_batch_deltas: 8,
                ..FileIngestLimits::standard()
            }),
        &cx,
        &mut deployment,
    )?;
    assert_eq!(imported.capsule_count, sources.len());
    // Neither initial production nor a retry can fall back to the former input file.
    fs::remove_file(input)?;
    Ok(Fixture {
        deployment,
        cx,
        root,
        _scratch: scratch,
        request: RecordedActivityRequest {
            import_identity: imported.import_identity,
            reference_segment,
            segment,
            expected_package_sha256: ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?,
            plan: ActivityReplayPlan {
                sensor_id: sensor,
                stream_id: stream,
                job_id: "job:recorded-activity".to_owned(),
                policy: ActivityThresholdPolicy::reference()?,
                interpretation: ComponentInterpretation::Grayscale,
                execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
            },
        },
    })
}
fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                found.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
    }
    Ok(found)
}

#[test]
fn independent_package_and_shared_read_publication_history_budgets_refuse_before_writes()
-> TestResult {
    let mut f = fixture()?;
    let before = tree(&f.root)?;
    let mut wrong = f.request.clone();
    wrong.expected_package_sha256 = ContentDigest::sha256(b"another package");
    assert!(matches!(
        produce_recorded_activity(
            &mut f.deployment,
            wrong,
            RecordedActivityLimits::default(),
            &f.cx,
            &ScalarExecCx::new()
        ),
        Err(RecordedActivityError::PackagePin)
    ));
    for limits in [
        RecordedActivityLimits {
            max_source_read_bytes: 1,
            ..RecordedActivityLimits::default()
        },
        RecordedActivityLimits {
            max_staged_bytes: 1,
            ..RecordedActivityLimits::default()
        },
        RecordedActivityLimits {
            max_history_batches: 0,
            ..RecordedActivityLimits::default()
        },
        RecordedActivityLimits {
            max_history_entries: 1,
            ..RecordedActivityLimits::default()
        },
    ] {
        assert!(
            produce_recorded_activity(
                &mut f.deployment,
                f.request.clone(),
                limits,
                &f.cx,
                &ScalarExecCx::new()
            )
            .is_err()
        );
        assert_eq!(before, tree(&f.root)?);
    }
    Ok(())
}

#[test]
fn cancellation_after_computation_but_before_publication_leaves_import_unchanged() -> TestResult {
    let mut f = fixture()?;
    let before = tree(&f.root)?;
    f.cx.set_cancel_at_checkpoint(STAGE_ACTIVITY_BEFORE_PUBLISH);
    let scalar = ScalarExecCx::new();
    let result = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &scalar,
    );
    assert!(
        matches!(result, Err(RecordedActivityError::Cancelled)),
        "{result:?}"
    );
    assert!(scalar.is_drain_completed());
    assert_eq!(before, tree(&f.root)?);
    Ok(())
}

#[test]
fn source_commit_survives_cancellation_and_cold_exact_retry_finishes_once() -> TestResult {
    let mut f = fixture()?;
    f.cx.set_cancel_at_checkpoint(STAGE_ACTIVITY_RESULT);
    let result = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    );
    assert!(
        matches!(result, Err(RecordedActivityError::Cancelled)),
        "{result:?}"
    );
    let roots: Vec<_> = f
        .deployment
        .publisher()
        .visible_roots()
        .filter(|root| root.slot.as_str().starts_with("xi-"))
        .map(|root| (root.slot.clone(), root.root))
        .collect();
    assert_eq!(
        roots.len(),
        1,
        "complete source custody must survive cancellation"
    );
    assert!(!f.deployment.ledger().batches().iter().any(|batch| {
        batch
            .deltas
            .iter()
            .any(|delta| delta.family == "executor_model_result")
    }));
    drop(f.deployment);
    let fresh = context(&f._scratch.0)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &fresh)?;
    let completed = produce_recorded_activity(
        &mut deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &fresh,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        roots,
        vec![(completed.source_slot.clone(), completed.source_root)]
    );
    assert!(!completed.retained.result.supports_absence_claim());
    assert!(completed.source_read_bytes > 0 && completed.decode_work > 0);
    let before_retry = tree(&f.root)?;
    let retried = produce_recorded_activity(
        &mut deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &fresh,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        completed.retained.result_digest,
        retried.retained.result_digest
    );
    assert_eq!(completed.final_anchor, retried.final_anchor);
    assert_eq!(completed.source_read_bytes, retried.source_read_bytes);
    assert_eq!(completed.decode_work, retried.decode_work);
    assert_eq!(before_retry, tree(&f.root)?);
    Ok(())
}

#[test]
fn exact_retry_refuses_damaged_published_jpeg_copy_without_repairing_it() -> TestResult {
    let mut f = fixture()?;
    let complete = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    // The input was split into 67-byte chunks. This complete-JPEG role is a different object;
    // the original imported source still verifies, so this specifically exercises retry custody.
    let copied = f
        .deployment
        .publisher()
        .spool()
        .object_path(complete.retained.result.input_capture_root);
    fs::write(&copied, b"damaged published JPEG role")?;
    let before = tree(&f.root)?;
    let retry = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    );
    assert!(
        matches!(retry, Err(RecordedActivityError::Spool(_))),
        "{retry:?}"
    );
    assert_eq!(
        before,
        tree(&f.root)?,
        "retry repaired a damaged immutable publication"
    );
    Ok(())
}

#[test]
fn distinct_earlier_capsules_with_identical_jpegs_share_result_without_colliding_roles()
-> TestResult {
    let mut f = recording(&[BACKGROUND, BACKGROUND, GRADIENT], 0, 2)?;
    let first = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    f.request.reference_segment = 1;
    let second = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(first.retained.result_digest, second.retained.result_digest);
    assert_eq!(first.retained.anchor, second.retained.anchor);
    assert_ne!(first.reference_capsule, second.reference_capsule);
    assert_ne!(first.source_slot, second.source_slot);
    assert_ne!(first.source_root, second.source_root);
    drop(f.deployment);
    let mut observations = Vec::new();
    for receipt in [first, second] {
        let slots = [receipt.source_slot.clone()];
        let verified = verify_retained_activity(
            ActivityVerificationRequest {
                root: &f.root,
                site: SITE,
                expected_ledger_root: None,
                result: receipt.retained.result_digest,
                reference_capsule: receipt.reference_capsule,
                source_slots: &slots,
                plan: receipt.plan.clone(),
            },
            &HostSpoolIo,
            ActivityVerificationLimits::default(),
            &ScalarExecCx::new(),
            &|| false,
        )?;
        assert_eq!(
            verified.result().object_digest(),
            receipt.retained.result_digest
        );
        observations.push(verified);
    }
    // Equal native result bytes do not identify the reference capsule or its publication.
    // Each private owner binds its exact complete role closure and cannot authenticate the other.
    let first_projection = observations[0].knowledge_projection()?;
    let second_projection = observations[1].knowledge_projection()?;
    assert_ne!(
        first_projection.integrity_digest(),
        second_projection.integrity_digest()
    );
    assert!(
        observations[0]
            .verify_knowledge_projection(second_projection.claim())
            .is_err()
    );
    assert!(
        observations[1]
            .verify_knowledge_projection(first_projection.claim())
            .is_err()
    );
    Ok(())
}

fn verified_recording(quiet: bool) -> TestResult<(VerifiedActivityObservation, Scratch)> {
    let mut f = if quiet {
        recording(&[BACKGROUND, BACKGROUND], 0, 1)?
    } else {
        fixture()?
    };
    let receipt = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    drop(f.deployment);
    let before = tree(&f.root)?;
    let slots = [receipt.source_slot];
    let observation = verify_retained_activity(
        ActivityVerificationRequest {
            root: &f.root,
            site: SITE,
            expected_ledger_root: None,
            result: receipt.retained.result_digest,
            reference_capsule: receipt.reference_capsule,
            source_slots: &slots,
            plan: receipt.plan,
        },
        &HostSpoolIo,
        ActivityVerificationLimits::default(),
        &ScalarExecCx::new(),
        &|| false,
    )?;
    assert_eq!(before, tree(&f.root)?);
    Ok((observation, f._scratch))
}

#[test]
fn verified_activity_preserves_real_producer_origins_without_promoting_metadata() -> TestResult {
    let (observation, _scratch) = verified_recording(false)?;
    let projection = observation.knowledge_projection()?;
    let claim = projection.claim();
    assert_eq!(&claim.anchor, observation.belief().anchor());
    assert_eq!(claim.ledger_root, observation.ledger_root());
    assert_eq!(
        claim.derivation_receipt,
        observation.belief().derivation_receipt()
    );
    assert_eq!(claim.cell.knowledge_state(), KnowledgeState::Estimated);
    assert_eq!(claim.cell.provenance(), ProvenanceClass::Derived);
    assert!(!claim.cell.is_irreversible_effect_premise(TimestampNs(0)));
    assert_eq!(claim.roles.len(), 8);
    for (binding, role) in claim.roles.iter().zip(ActivityEvidenceRole::ALL) {
        assert_eq!(binding.role, role);
        assert_eq!(binding.origin, role.origin());
        assert!(claim.cell.evidence().iter().any(|reference| {
            reference.digest == binding.evidence.digest && reference.origin == binding.origin
        }));
        assert_eq!(binding.evidence.revision.plane, Plane::Authority);
    }
    for index in [2, 3] {
        assert_eq!(
            claim.roles[index].origin,
            EvidenceOrigin::Produced(ProvenanceClass::Observed)
        );
    }
    for index in [0, 1, 4, 5, 6, 7] {
        assert_eq!(
            claim.roles[index].origin,
            EvidenceOrigin::Produced(ProvenanceClass::Derived)
        );
    }
    assert_eq!(projection.integrity_digest(), claim.integrity_digest()?);
    let accepted = observation.verify_knowledge_projection(claim)?;
    assert_eq!(accepted.integrity_digest(), projection.integrity_digest());
    Ok(())
}

#[test]
fn producer_owner_rejects_relabelled_omitted_and_substituted_cells_even_after_rehash() -> TestResult
{
    let (observation, _scratch) = verified_recording(false)?;
    let projection = observation.knowledge_projection()?;
    let expected = projection.claim();
    let mut forged = Vec::new();

    let mut changed = expected.clone();
    let mut params = changed.cell.to_params();
    params.knowledge_state = KnowledgeState::Known;
    params.provenance = ProvenanceClass::Observed;
    changed.cell = KnowledgeCell::new(params)?;
    assert!(changed.cell.is_irreversible_effect_premise(TimestampNs(0)));
    forged.push(changed);

    let mut changed = expected.clone();
    // The former structural projection defaults all supporting origins to Derived, losing the
    // two original-byte roles. Even this weakening is not the producer's exact projection.
    changed.cell = observation
        .belief()
        .to_knowledge_cell(observation.belief().anchor())?;
    forged.push(changed);

    let mut changed = expected.clone();
    changed.cell = changed.cell.with_evidence_origins(&vec![
        EvidenceOrigin::Produced(
            ProvenanceClass::Observed
        );
        expected.cell.evidence().len()
    ])?;
    forged.push(changed);

    for action in ["statement", "omission", "substitution", "laboratory"] {
        let mut changed = expected.clone();
        let mut params = changed.cell.to_params();
        let mut origins = changed
            .cell
            .evidence()
            .iter()
            .map(|reference| reference.origin)
            .collect::<Vec<_>>();
        match action {
            "statement" => params.statement = "physically verified person present".to_owned(),
            "omission" => {
                params.evidence.pop();
                origins.pop();
            }
            "substitution" => {
                params.evidence[0] = ContentDigest::sha256(b"unrelated retained bytes")
            }
            "laboratory" => origins[0] = EvidenceOrigin::Laboratory,
            _ => return Err("unknown cell mutation fixture".into()),
        }
        changed.cell = KnowledgeCell::new(params)?.with_evidence_origins(&origins)?;
        forged.push(changed);
    }
    for changed in forged {
        assert_ne!(changed.integrity_digest()?, projection.integrity_digest());
        assert_eq!(
            observation.verify_knowledge_projection(&changed).err(),
            Some(ActivityProjectionError::CellMismatch),
        );
    }
    Ok(())
}

#[test]
fn producer_owner_checks_all_role_revisions_anchor_and_producer_coordinates() -> TestResult {
    let (observation, _scratch) = verified_recording(false)?;
    let projection = observation.knowledge_projection()?;
    let expected = projection.claim();
    for action in [
        "missing",
        "duplicate",
        "reorder",
        "origin",
        "digest",
        "authority",
        "generation",
        "family",
        "plane",
        "root",
        "validity",
    ] {
        let mut changed = expected.clone();
        match action {
            "missing" => {
                changed.roles.pop();
            }
            "duplicate" => changed.roles[7] = changed.roles[6].clone(),
            "reorder" => changed.roles.swap(2, 3),
            "origin" => {
                changed.roles[0].origin = EvidenceOrigin::Produced(ProvenanceClass::Observed)
            }
            "digest" => changed.roles[0].evidence.digest = ContentDigest::sha256(b"other result"),
            "authority" => {
                changed.roles[0].evidence.authority = ObjectId::parse("object:other:publication")?
            }
            "generation" => changed.roles[0].evidence.revision.generation += 1,
            "family" => {
                changed.roles[0].evidence.revision.family = "different semantic family".to_owned()
            }
            "plane" => changed.roles[0].evidence.revision.plane = Plane::Cognition,
            "root" => {
                changed.roles[0].evidence.revision.payload_digest =
                    ContentDigest::sha256(b"other container")
            }
            "validity" => changed.roles[0].evidence.revision.validity.latest.0 += 1,
            _ => return Err("unknown role mutation fixture".into()),
        }
        // Any caller can rehash public claims. That changes integrity, never authentication.
        assert_ne!(changed.integrity_digest()?, projection.integrity_digest());
        assert_eq!(
            observation.verify_knowledge_projection(&changed).err(),
            Some(ActivityProjectionError::EvidenceClosureMismatch),
            "{action}",
        );
    }
    for action in ["privacy", "history", "algorithm", "generation", "receipt"] {
        let mut changed = expected.clone();
        let refusal = match action {
            "privacy" => {
                changed.anchor.privacy_epoch += 1;
                ActivityProjectionError::AnchorMismatch
            }
            "history" => {
                changed.ledger_root = ContentDigest::sha256(b"other history");
                ActivityProjectionError::AnchorMismatch
            }
            "algorithm" => {
                changed.producer_algorithm = "alg:foreign:v1".to_owned();
                ActivityProjectionError::ProducerMismatch
            }
            "generation" => {
                changed.producer_generation += 1;
                ActivityProjectionError::ProducerMismatch
            }
            "receipt" => {
                changed.derivation_receipt = ContentDigest::sha256(b"other receipt");
                ActivityProjectionError::ProducerMismatch
            }
            _ => return Err("unknown producer mutation fixture".into()),
        };
        assert_ne!(changed.integrity_digest()?, projection.integrity_digest());
        assert_eq!(
            observation.verify_knowledge_projection(&changed).err(),
            Some(refusal)
        );
    }
    let mut oversized = expected.clone();
    oversized.roles.push(oversized.roles[0].clone());
    assert!(oversized.integrity_digest().is_err());
    assert_eq!(
        observation.verify_knowledge_projection(&oversized).err(),
        Some(ActivityProjectionError::EvidenceClosureMismatch)
    );
    for dimension in ["evidence", "contradictions"] {
        let mut oversized = expected.clone();
        let mut params = oversized.cell.to_params();
        let roots = vec![ContentDigest::sha256(b"oversized inventory"); 9];
        match dimension {
            "evidence" => params.evidence = roots,
            "contradictions" => params.contradictions = roots,
            _ => return Err("unknown bound fixture".into()),
        }
        oversized.cell = KnowledgeCell::new(params)?;
        assert!(oversized.integrity_digest().is_err(), "{dimension}");
        assert_eq!(
            observation.verify_knowledge_projection(&oversized).err(),
            Some(ActivityProjectionError::CellMismatch)
        );
    }
    for dimension in ["algorithm", "anchor", "family"] {
        let mut oversized = expected.clone();
        let text = "x".repeat(fss_core::MAX_CANONICAL_TEXT_BYTES + 1);
        match dimension {
            "algorithm" => oversized.producer_algorithm = text,
            "anchor" => oversized.anchor.site_lineage = text,
            "family" => oversized.roles[0].evidence.revision.family = text,
            _ => return Err("unknown text-bound fixture".into()),
        }
        assert!(oversized.integrity_digest().is_err(), "{dimension}");
        assert!(observation.verify_knowledge_projection(&oversized).is_err());
    }
    Ok(())
}

#[test]
fn identical_original_bytes_preserve_two_roles_and_cannot_hide_an_omission() -> TestResult {
    let (observation, _scratch) = verified_recording(true)?;
    let projection = observation.knowledge_projection()?;
    let expected = projection.claim();
    assert_eq!(
        expected.roles[2].evidence.digest,
        expected.roles[3].evidence.digest
    );
    assert_eq!(
        expected.roles[6].evidence.digest,
        expected.roles[7].evidence.digest
    );
    assert_eq!(expected.roles.len(), 8);
    assert_eq!(expected.cell.evidence().len(), 6);
    assert_eq!(
        expected
            .cell
            .evidence()
            .iter()
            .filter(
                |reference| reference.origin == EvidenceOrigin::Produced(ProvenanceClass::Observed)
            )
            .count(),
        1
    );
    for index in [3, 7] {
        let mut missing_alias = expected.clone();
        missing_alias.roles.remove(index);
        // The complete digest/origin set and cell are unchanged, yet a required role is lost.
        assert_eq!(
            missing_alias.cell.cell_digest(),
            expected.cell.cell_digest()
        );
        assert_eq!(
            observation
                .verify_knowledge_projection(&missing_alias)
                .err(),
            Some(ActivityProjectionError::EvidenceClosureMismatch)
        );
    }
    Ok(())
}
