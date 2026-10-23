#![forbid(unsafe_code)]
//! Fresh-process operator verification of actual retained native activity and original sources.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{
    BudgetVector, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    ContextAuthority, OperationId, RootAuthoritySpec, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_publication::{SlotName, root_reachability_object_id};
use fss_reference::activity_replay::ActivityReplayPlan;
use fss_reference::activity_replay::belief::{ActivityEvidenceBinding, ActivityEvidenceSet};
use fss_reference::activity_replay::operator::{
    ActivityVerificationError, ActivityVerificationLimits, ActivityVerificationRequest,
    verify_retained_activity,
};
use fss_reference::executor_activity::{
    ActivityExecutorModel, ActivityFrameBinding, ActivityThresholdPolicy, ExecutorModelOutcome,
    ExecutorModelResult, retain_executor_result, rgb_decode_receipt_bytes,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, ExecBudget, ReferenceDeployment, ReplayCx,
    ReplayIoAuthority, ScalarExecCx,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> TestResult<Self> {
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-activity-belief-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("scratch identity allowance exhausted".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:activity-belief-test".to_owned(),
        operation_id: OperationId::parse("operation:activity-belief-test")?,
        principal: "operator:activity-belief-test".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned(), ADP_FILE_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"activity-belief-test-universe"),
        generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.join("scratch"),
    )?))
}
fn capsule(bytes: &[u8], sequence: u64) -> TestResult<SensorCapsule> {
    let capture = CaptureInterval::new(TimestampNs(0), TimestampNs(5_000_000_000))?;
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:belief:{sequence}"))?,
        sensor_id: SensorId::parse("sensor:belief")?,
        stream_id: StreamId::parse("stream:belief")?,
        sequence,
        capture,
        receive_time: capture.latest,
        clock_basis: ClockBasis::Estimated,
        source: bytes,
        frame_count: 1,
        gap_before: false,
    })?)
}

struct Fixture {
    root: PathBuf,
    plan: ActivityReplayPlan,
    evidence: ActivityEvidenceSet,
    result: ExecutorModelResult,
    source_record: PathBuf,
    source_object: PathBuf,
    // Dropped last, after the publisher's locks and journal handles.
    _scratch: Scratch,
}
fn fixture(quiet: bool, altered_result: bool) -> TestResult<Fixture> {
    let scratch = Scratch::new()?;
    let cx = context(&scratch.0)?;
    let root = scratch.0.join("deployment");
    let mut deployment = ReferenceDeployment::open(&root, "site:activity-belief", &cx)?;
    let scalar = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&scalar)?;
    let plan = ActivityReplayPlan {
        sensor_id: SensorId::parse("sensor:belief")?,
        stream_id: StreamId::parse("stream:belief")?,
        job_id: "job:belief".to_owned(),
        policy: ActivityThresholdPolicy::reference()?,
        interpretation: ComponentInterpretation::Grayscale,
        execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
    };
    let frame_source = if quiet { BACKGROUND } else { GRADIENT };
    let decode = |bytes: &[u8]| {
        decode_rgb(
            bytes,
            ContentDigest::sha256(bytes).bytes(),
            plan.interpretation,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(20_000_000),
        )
    };
    let frame = decode(frame_source)?;
    let reference = decode(BACKGROUND)?;
    let fc = capsule(frame_source, 1)?;
    let rc = capsule(BACKGROUND, 0)?;
    let (mut result, receipt) = model.invoke(
        &plan.sensor_id,
        ActivityFrameBinding {
            pixels: frame.pixels(),
            receipt: frame.receipt(),
            source_digest: fc.source_digest,
            capsule: &fc,
        },
        ActivityFrameBinding {
            pixels: reference.pixels(),
            receipt: reference.receipt(),
            source_digest: rc.source_digest,
            capsule: &rc,
        },
        &plan.policy,
        plan.execution,
        &plan.job_id,
        &scalar,
    )?;
    if altered_result {
        result.outcome = ExecutorModelOutcome::NoActivity {
            score_bits: 0.0_f32.to_bits(),
        };
    }
    let source_objects = [
        frame_source.to_vec(),
        BACKGROUND.to_vec(),
        fc.try_canonical_bytes()?,
        rc.try_canonical_bytes()?,
        rgb_decode_receipt_bytes(&frame.receipt()),
        rgb_decode_receipt_bytes(&reference.receipt()),
    ];
    let source_slot = SlotName::parse("activity-originals")?;
    // Publication has a canonical set of objects, while the engine keeps all named roles.
    // Identical frames also share their decode record; neither alias is a second object.
    let mut refs: Vec<_> = source_objects.iter().map(Vec::as_slice).collect();
    refs.sort_unstable();
    refs.dedup();
    let staged = deployment.stage_and_publish(&source_slot, &refs, &cx)?;
    let _ = deployment.publish_and_commit(&source_slot, &staged.manifest, fc.capture, &cx)?;
    // Use the pre-existing real retention writer; it stores native result/receipt as cognition.
    let retained = retain_executor_result(&mut deployment, &result, &receipt, fc.capture, &cx)?;
    let result_slot = deployment
        .publisher()
        .visible_roots()
        .find(|entry| entry.root == retained.root)
        .ok_or("result root not published")?
        .slot
        .clone();
    let source_id = root_reachability_object_id(&source_slot)?;
    let result_id = root_reachability_object_id(&result_slot)?;
    let source_revision = deployment
        .ledger()
        .current()
        .objects
        .get(&source_id)
        .ok_or("source revision")?
        .clone();
    let result_revision = deployment
        .ledger()
        .current()
        .objects
        .get(&result_id)
        .ok_or("result revision")?
        .clone();
    let source = |index: usize| ActivityEvidenceBinding {
        digest: ContentDigest::sha256(&source_objects[index]),
        authority: source_id.clone(),
        revision: source_revision.clone(),
    };
    let evidence = ActivityEvidenceSet {
        result: ActivityEvidenceBinding {
            digest: result.object_digest(),
            authority: result_id.clone(),
            revision: result_revision.clone(),
        },
        invocation: ActivityEvidenceBinding {
            digest: result.invocation_receipt_object,
            authority: result_id,
            revision: result_revision,
        },
        frame_source: source(0),
        reference_source: source(1),
        frame_capsule: source(2),
        reference_capsule: source(3),
        frame_decode: source(4),
        reference_decode: source(5),
    };
    let source_record = deployment
        .publisher()
        .root_dir()
        .join("roots")
        .join("activity-originals.root");
    let source_object = deployment.publisher().spool().object_path(fc.source_digest);
    drop(deployment);
    Ok(Fixture {
        root,
        plan,
        evidence,
        result,
        source_record,
        source_object,
        _scratch: scratch,
    })
}

fn run(f: &Fixture, changes: &[(&str, String)]) -> TestResult<Output> {
    let mut options = BTreeMap::from([
        ("--site", "site:activity-belief".to_owned()),
        ("--result", f.result.object_digest().to_text()),
        (
            "--reference-capsule",
            f.evidence.reference_capsule.digest.to_text(),
        ),
        ("--source-slot", "activity-originals".to_owned()),
        ("--sensor", "sensor:belief".to_owned()),
        ("--stream", "stream:belief".to_owned()),
        ("--job", "job:belief".to_owned()),
        ("--interpretation", "grayscale".to_owned()),
        ("--execution-macs", "10000000".to_owned()),
        ("--execution-bytes", (16 * 1024 * 1024).to_string()),
    ]);
    for (key, value) in changes {
        options.insert(key, value.clone());
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-evidence"));
    command.arg("verify-activity").arg("--root").arg(&f.root);
    for (key, value) in options {
        command.arg(key).arg(value);
    }
    Ok(command.output()?)
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut rows = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                rows.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
    }
    Ok(rows)
}

fn refused(output: Output) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "a refusal emitted a partial success report"
    );
    assert!(!output.stderr.is_empty());
}

#[test]
fn cold_process_replays_actual_native_activity_without_writing() -> TestResult {
    let f = fixture(false, false)?;
    let before = tree(&f.root)?;
    let output = run(&f, &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    for field in [
        "\"verified\":true",
        "\"knowledgeState\":\"estimated\"",
        "\"provenance\":\"derived\"",
        "\"derivations\":1",
        "\"outcome\":\"activity\"",
        "\"supportsAbsenceClaim\":false",
        "\"effectsAuthorized\":false",
    ] {
        assert!(report.contains(field), "missing {field}: {report}");
    }
    assert!(report.contains("no presence or absence claim"));
    assert_eq!(before, tree(&f.root)?);
    // A root learned from the complete report is a reusable exact history pin.
    let pin = report
        .split("\"ledger_root\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("missing pin")?;
    let pinned = run(&f, &[("--expected-ledger-root", pin.to_owned())])?;
    assert!(
        pinned.status.success(),
        "{}",
        String::from_utf8_lossy(&pinned.stderr)
    );
    assert_eq!(String::from_utf8(pinned.stdout)?, report);
    Ok(())
}

#[test]
fn quiet_identical_frames_keep_distinct_roles_without_claiming_absence() -> TestResult {
    let f = fixture(true, false)?;
    assert_eq!(
        f.evidence.frame_source.digest,
        f.evidence.reference_source.digest
    );
    assert_eq!(
        f.evidence.frame_decode.digest,
        f.evidence.reference_decode.digest
    );
    let output = run(&f, &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    assert!(report.contains("\"outcome\":\"no_activity\""));
    assert!(report.contains("\"supportsAbsenceClaim\":false"));
    assert!(report.contains("\"uncertainty\":{\"lowerPpm\":0,\"upperPpm\":1000000}"));
    assert!(report.contains("\"role\":\"reference_decode\""));
    Ok(())
}

#[test]
fn a_canonically_retained_false_score_fails_original_frame_replay() -> TestResult {
    let f = fixture(false, true)?;
    let before = tree(&f.root)?;
    refused(run(&f, &[])?);
    assert_eq!(before, tree(&f.root)?);
    Ok(())
}

#[test]
fn independent_scope_anchor_invocation_and_resource_bounds_are_enforced() -> TestResult {
    let f = fixture(false, false)?;
    let before = tree(&f.root)?;
    for change in [
        ("--job", "job:other".to_owned()),
        ("--stream", "stream:other".to_owned()),
        ("--source-slot", "unselected-originals".to_owned()),
        (
            "--reference-capsule",
            f.evidence.frame_capsule.digest.to_text(),
        ),
        (
            "--expected-ledger-root",
            ContentDigest::sha256(b"wrong-head").to_text(),
        ),
        ("--execution-macs", "9999999".to_owned()),
        ("--max-decode-work", "0".to_owned()),
        ("--max-custody-read-bytes", "1".to_owned()),
        ("--max-objects", "1".to_owned()),
        ("--max-journal-bytes", "1".to_owned()),
        ("--max-report-bytes", "1024".to_owned()),
    ] {
        refused(run(&f, &[change])?);
    }
    assert_eq!(before, tree(&f.root)?);
    Ok(())
}

#[test]
fn missing_or_corrupt_original_custody_never_becomes_a_verified_result() -> TestResult {
    let f = fixture(false, false)?;
    let saved = fs::read(&f.source_object)?;
    fs::write(&f.source_object, b"corrupt retained original")?;
    refused(run(&f, &[])?);
    fs::write(&f.source_object, saved)?;
    fs::remove_file(&f.source_record)?;
    // Intact copied payload bytes cannot substitute for the exact selected slot record.
    refused(run(&f, &[])?);
    Ok(())
}

#[test]
fn cancellation_and_missing_deployment_do_not_create_or_mutate_files() -> TestResult {
    let mut f = fixture(false, false)?;
    let before = tree(&f.root)?;
    let slots = [SlotName::parse("activity-originals")?];
    let scalar = ScalarExecCx::new();
    let result = verify_retained_activity(
        ActivityVerificationRequest {
            root: &f.root,
            site: "site:activity-belief",
            expected_ledger_root: None,
            result: f.result.object_digest(),
            reference_capsule: f.evidence.reference_capsule.digest,
            source_slots: &slots,
            plan: f.plan.clone(),
        },
        &HostSpoolIo,
        ActivityVerificationLimits::default(),
        &scalar,
        &|| true,
    );
    assert!(matches!(result, Err(ActivityVerificationError::Cancelled)));
    assert_eq!(before, tree(&f.root)?);
    let missing = f._scratch.0.join("never-created");
    f.root = missing.clone();
    refused(run(&f, &[])?);
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn unrelated_real_deletion_is_verified_and_corrupt_deletion_proof_refuses() -> TestResult {
    use fss_reference::deletion::{commit_deletion, plan_deletion};
    use fss_reference::{FileIngestAdapter, FileIngestLimits, FileIngestRequest};
    let f = fixture(false, false)?;
    let cx = context(&f._scratch.0)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, "site:activity-belief", &cx)?;
    let frame = include_bytes!("../../../tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let input = f._scratch.0.join("unrelated.mjpeg");
    fs::write(&input, frame.repeat(2))?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            input,
            SensorId::parse("sensor:unrelated")?,
            StreamId::parse("stream:unrelated")?,
        )
        .with_receive_time(TimestampNs(2_000_000_000))
        .with_limits(FileIngestLimits {
            chunk_bytes: frame.len() as u64,
            max_batch_deltas: 8,
            ..FileIngestLimits::standard()
        }),
        &cx,
        &mut deployment,
    )?;
    let plan = plan_deletion(&deployment, imported.import_identity, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let plan_digest = plan.digest()?;
    commit_deletion(
        &mut deployment,
        plan_digest,
        plan.approval_digest("operator:activity-belief-test")?,
        "operator:activity-belief-test",
        &cx,
    )?;
    let plan_path = deployment.publisher().spool().object_path(plan_digest);
    drop(deployment);
    let before = tree(&f.root)?;
    let output = run(&f, &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    assert!(!report.contains("\"deletionRecordReads\":0"));
    assert_eq!(before, tree(&f.root)?);
    refused(run(&f, &[("--max-deletion-bytes", "1".to_owned())])?);
    fs::write(&plan_path, b"corrupt committed deletion proof")?;
    refused(run(&f, &[])?);
    Ok(())
}

#[test]
fn authority_advance_after_initial_read_refuses_even_with_intact_sources() -> TestResult {
    let f = fixture(false, false)?;
    let calls = AtomicU64::new(0);
    let slots = [SlotName::parse("activity-originals")?];
    // The second cancellation checkpoint follows the first completed history read. Commit a real
    // independent batch then, preserving all original payloads and publication records.
    let checkpoint = || {
        if calls.fetch_add(1, Ordering::Relaxed) == 1 {
            let advance = || -> TestResult {
                let cx = context(&f._scratch.0)?;
                let mut deployment =
                    ReferenceDeployment::reopen(&f.root, "site:activity-belief", &cx)?;
                deployment.append_batch(
                    fss_core::BatchId::parse("batch:activity-observed-drift")?,
                    vec![],
                    vec![],
                    &cx,
                )?;
                Ok(())
            };
            if let Err(error) = advance() {
                panic!("could not append test authority: {error}");
            }
        }
        false
    };
    let result = verify_retained_activity(
        ActivityVerificationRequest {
            root: &f.root,
            site: "site:activity-belief",
            expected_ledger_root: None,
            result: f.result.object_digest(),
            reference_capsule: f.evidence.reference_capsule.digest,
            source_slots: &slots,
            plan: f.plan.clone(),
        },
        &HostSpoolIo,
        ActivityVerificationLimits::default(),
        &ScalarExecCx::new(),
        &checkpoint,
    );
    assert!(
        matches!(result, Err(ActivityVerificationError::AuthorityChanged)),
        "{result:?}"
    );
    Ok(())
}
