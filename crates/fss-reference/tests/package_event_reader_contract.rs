#![forbid(unsafe_code)]
//! Published detector-package candidates remain reconstructible from custody after restart.
//! The fixture runs one real package inference per test; it makes no detection-quality claim.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BatchId, BudgetVector, CanonicalEncode, ContentDigest, EventId, EventKind, EventState,
    EvidenceDelta, ObjectId, OperationId, Plane, SensorId, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectReport, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageDetectionRecord, PackageEvent, PackageEventError,
    PackageEventProposal, PackageEventReceipt, PackageEventStatus, PackageTrackingConfig,
    RetainedPackageDetection, retain_package_detection,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx, ScalarExecCx,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:package-event-reader";
const SENSOR: &str = "sensor:package-event-reader";
const JPEG: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-event-reader-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-event-reader".into(),
        operation_id: OperationId::parse("operation:package-event-reader")?,
        principal: "principal:package-event-reader".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    report: PackageAnalysisReport,
    proposal: PackageEventProposal,
    receipt: PackageEventReceipt,
}
struct DetectionFixture {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    package: RgbDetectorPackage,
    detection: PackageDetectReport,
}
fn detection_fixture(label: &str) -> Test<DetectionFixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("source.jpg");
    fs::write(&source, JPEG)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &source,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:package-event-reader")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    fs::remove_file(&source)?;
    let scalar = ScalarExecCx::new();
    let package = RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_SHA256)?,
        1 << 40,
        &cx,
        &scalar,
    )?;
    let detection = run_package_detection(
        &deployment,
        &package,
        &PackageDetectRequest {
            import_identity: imported.import_identity,
            first_segment: 0,
            segment_count: 1,
            interpretation: ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(),
        &cx,
        &scalar,
    )?;
    Ok(DetectionFixture {
        directory,
        root,
        cx,
        deployment,
        package,
        detection,
    })
}

fn fixture(label: &str) -> Test<Fixture> {
    let DetectionFixture {
        directory,
        root,
        cx,
        mut deployment,
        package,
        detection,
    } = detection_fixture(label)?;
    retain_package_detection(&mut deployment, &package, &detection, &cx)?;
    drop(package);
    let report = PackageAnalysisReport::read(
        &deployment,
        detection.digest,
        "tie",
        PackageTrackingConfig {
            confirmation_hits: 1,
            maximum_missed_frames: 1,
            minimum_iou_ppm: 100_000,
        },
        &cx,
    )?;
    let track = report
        .tracks()
        .iter()
        .find(|t| t.confirmed)
        .ok_or("fixture track missing")?
        .identity;
    let proposal =
        PackageEventProposal::prepare(&deployment, report.encoded(), report.digest(), track, &cx)?;
    let receipt = proposal.publish(&mut deployment, proposal.digest(), &cx)?;
    Ok(Fixture {
        directory,
        root,
        cx,
        deployment,
        report,
        proposal,
        receipt,
    })
}

fn assert_record(record: &PackageEvent, f: &Fixture) {
    assert_eq!(record.event(), &f.receipt.event);
    assert_eq!(record.root(), f.receipt.event_root);
    assert_eq!(record.authority_anchor(), &f.receipt.authority_anchor);
    assert_eq!(record.report().encoded(), f.report.encoded());
    assert_eq!(record.track(), f.receipt.track);
    assert_eq!(record.event().state, EventState::Indeterminate);
    assert_eq!(record.event().kind, EventKind::Unclassified);
    assert!(record.event().decision_path.abstained);
    assert_eq!(record.event().revision, 1);
}

#[test]
fn cold_read_and_exact_retries_preserve_the_original_revision_and_anchor() -> Test {
    let mut f = fixture("cold")?;
    let before = f.deployment.current_anchor().clone();
    for _ in 0..2 {
        let proposal = PackageEventProposal::prepare(
            &f.deployment,
            f.report.encoded(),
            f.report.digest(),
            f.receipt.track,
            &f.cx,
        )?;
        assert_eq!(proposal.status(), PackageEventStatus::AlreadyPublished);
        assert_eq!(proposal.digest(), f.proposal.digest());
        let receipt = proposal.publish(&mut f.deployment, proposal.digest(), &f.cx)?;
        assert_eq!(receipt.event_root, f.receipt.event_root);
        assert_eq!(receipt.authority_anchor, f.receipt.authority_anchor);
    }
    assert_record(
        &PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx)?,
        &f,
    );
    assert_eq!(f.deployment.current_anchor(), &before);
    // A completely separate event moves the head. Reads must still report the original
    // authority anchor of the selected package event, never the deployment's current head.
    let mut unrelated = f.receipt.event.clone();
    unrelated.event_id = EventId::parse("event:unrelated")?;
    f.deployment.publish_event(
        &ReferencePolicyDecision {
            event: unrelated,
            action: ReferencePolicyAction::Hold,
        },
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    assert_ne!(&head, &f.receipt.authority_anchor);
    assert_record(
        &PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx)?,
        &f,
    );
    // Close all authority owners and recover only the deployment, without a loose report or
    // source file (and without any loaded model instance).
    let Fixture {
        directory,
        root,
        cx,
        deployment,
        report,
        proposal,
        receipt,
    } = f;
    drop(deployment);
    cx.drain_and_finalize();
    let cx = context(&root)?;
    let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let f = Fixture {
        directory,
        root,
        cx,
        deployment,
        report,
        proposal,
        receipt,
    };
    assert_record(
        &PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx)?,
        &f,
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    assert!(!f.directory.0.join("source.jpg").exists());
    for stage in [
        "package_event:read",
        "package_event:read_history",
        "package_event:read_provenance",
        "package_event:read_provenance_object",
    ] {
        let cancelled = context(&f.root)?;
        cancelled.set_cancel_at_checkpoint(stage);
        assert!(
            matches!(
                PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &cancelled),
                Err(PackageEventError::Cancelled)
            ),
            "{stage}"
        );
        assert_eq!(f.deployment.current_anchor(), &head);
    }
    assert!(matches!(
        PackageEvent::open(
            &f.deployment,
            &EventId::parse("event:package:missing")?,
            &f.cx
        ),
        Err(PackageEventError::EventUnavailable)
    ));
    Ok(())
}

#[test]
fn damaged_or_missing_event_report_proof_capsule_and_source_are_never_repaired_by_retry() -> Test {
    let mut f = fixture("corrupt")?;
    let before = f.deployment.current_anchor().clone();
    let source = RetainedFileImport::open(
        &f.deployment,
        f.report.retained().record().import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let digests = [
        f.receipt.event_root,
        ContentDigest::sha256(&f.receipt.event.try_canonical_bytes()?),
        f.receipt.provenance_root,
        f.report.digest(),
        f.report.retained().record_digest(),
        f.report.retained().record().report_digest,
        f.receipt.event.evidence[0].digest,
        f.receipt.event.evidence[0]
            .capsule_digest
            .ok_or("capsule missing")?,
        source.manifest().ordered_chunks[0],
    ];
    for digest in digests {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        let mut damaged = bytes.clone();
        let last = damaged.last_mut().ok_or("empty spool file")?;
        *last ^= 1;
        fs::write(&path, &damaged)?;
        assert!(
            PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx).is_err(),
            "{digest}"
        );
        assert!(
            PackageEventProposal::prepare(
                &f.deployment,
                f.report.encoded(),
                f.report.digest(),
                f.receipt.track,
                &f.cx
            )
            .is_err(),
            "prepare {digest}"
        );
        assert!(
            f.proposal
                .publish(&mut f.deployment, f.proposal.digest(), &f.cx)
                .is_err(),
            "retry {digest}"
        );
        assert_eq!(fs::read(&path)?, damaged, "refusal rewrote {digest}");
        assert_eq!(f.deployment.current_anchor(), &before);
        fs::write(&path, &bytes)?;
        assert_record(
            &PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx)?,
            &f,
        );
    }
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(source.manifest().ordered_chunks[0]);
    let bytes = fs::read(&path)?;
    fs::remove_file(&path)?;
    assert!(PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx).is_err());
    assert!(
        f.proposal
            .publish(&mut f.deployment, f.proposal.digest(), &f.cx)
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(f.deployment.current_anchor(), &before);
    fs::write(path, bytes)?;
    Ok(())
}

#[test]
fn self_consistent_successor_cannot_replace_the_published_package_candidate() -> Test {
    let mut f = fixture("successor")?;
    let mut changed = f.receipt.event.clone();
    changed.revision = 2;
    changed.supersedes = Some(f.receipt.event.revision_digest());
    changed.uncertainty_reason = Some("an independently changed event".into());
    changed.validate()?;
    f.deployment.publish_event(
        &ReferencePolicyDecision {
            event: changed,
            action: ReferencePolicyAction::Hold,
        },
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    assert!(matches!(
        PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx),
        Err(PackageEventError::Conflict)
    ));
    assert!(matches!(
        f.proposal
            .publish(&mut f.deployment, f.proposal.digest(), &f.cx),
        Err(PackageEventError::Conflict)
    ));
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn nonextending_successor_is_refused_before_readable_authority_changes() -> Test {
    let mut f = fixture("nonextension")?;
    let head = f.deployment.current_anchor().clone();
    let mut forged = f.receipt.event.clone();
    forged.revision = 2;
    forged.supersedes = Some(ContentDigest::sha256(b"not the preceding revision"));
    forged.validate()?;
    assert!(
        f.deployment
            .publish_event(
                &ReferencePolicyDecision {
                    event: forged,
                    action: ReferencePolicyAction::Hold,
                },
                &f.cx
            )
            .is_err()
    );
    assert_record(
        &PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx)?,
        &f,
    );
    let retried = f
        .proposal
        .publish(&mut f.deployment, f.proposal.digest(), &f.cx)?;
    assert_eq!(retried.authority_anchor, f.receipt.authority_anchor);
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn later_privacy_policy_refuses_historical_coordinates_without_mutating_the_event() -> Test {
    let mut f = fixture("privacy")?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [64, 48], &[[0, 0, 64, 48]])?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    let refused = PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx).unwrap_err();
    assert_eq!(
        refused.stable_id(),
        "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
    );
    assert_eq!(
        f.proposal
            .publish(&mut f.deployment, f.proposal.digest(), &f.cx)
            .unwrap_err()
            .stable_id(),
        refused.stable_id()
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn legacy_delayed_retention_cannot_relabel_an_unmasked_computation() -> Test {
    let mut f = detection_fixture("delayed-privacy")?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [64, 48], &[[0, 0, 64, 48]])?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = f.deployment.current_anchor().clone();
    // The new writer refuses a completed pre-mask computation at retention time.
    assert_eq!(
        retain_package_detection(&mut f.deployment, &f.package, &f.detection, &f.cx)
            .unwrap_err()
            .stable_id(),
        "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
    );
    assert_eq!(f.deployment.current_anchor(), &before);

    // Construct exactly the legacy writer's retained object graph: its publication anchor is
    // AFTER the mask declaration even though the actual report says no_policy_declared.
    // This is a test-owned simulation of historical bytes, not application repair.
    let record = PackageDetectionRecord::from_report(&f.package, &f.detection)?;
    let record_digest = f.deployment.stage_payload(&record.encode()?)?;
    assert_eq!(
        f.deployment.stage_payload(f.detection.json.as_bytes())?,
        f.detection.digest
    );
    let id = record
        .report_digest
        .to_text()
        .trim_start_matches("sha256:")
        .to_owned();
    let slot = SlotName::parse(&format!("pd-{id}"))?;
    let mut children = vec![record.report_digest, record.import_root];
    children.extend(record.frames.iter().map(|frame| frame.capsule_digest));
    let manifest = ObjectManifest::new(slot.as_str(), children, Some(record_digest))?;
    for digest in manifest.children().iter().copied().chain([record_digest]) {
        f.deployment.publisher_mut().verify_object(digest)?;
    }
    f.deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    let interval = record.frames[0].capture;
    f.deployment
        .publish_and_commit(&slot, &manifest, interval, &f.cx)?;
    let delta = EvidenceDelta {
        delta_id: format!("delta:package-detection:{id}"),
        family: "package_detection_record".into(),
        object_id: ObjectId::parse(format!("object:package-detection:{id}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: interval,
        plane: Plane::Cognition,
        payload_digest: record_digest,
        witness_digest: Some(manifest.root()),
        operation_id: None,
    };
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    f.deployment.append_batch(
        BatchId::parse(format!("batch:package-detection:{id}"))?,
        vec![delta],
        children,
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    assert_eq!(
        RetainedPackageDetection::open(&f.deployment, f.detection.digest, &f.cx)
            .unwrap_err()
            .stable_id(),
        "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn deletion_withdraws_package_readability_and_never_resurrects_evidence() -> Test {
    let mut f = fixture("deleted")?;
    let plan = plan_deletion(
        &f.deployment,
        f.report.retained().record().import_identity,
        &f.cx,
    )?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let digest = plan.digest()?;
    let approval = approval_digest(digest, SITE, "principal:package-event-reader")?;
    commit_deletion(
        &mut f.deployment,
        digest,
        approval,
        "principal:package-event-reader",
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    assert!(PackageEvent::open(&f.deployment, &f.receipt.event.event_id, &f.cx).is_err());
    assert!(
        f.proposal
            .publish(&mut f.deployment, f.proposal.digest(), &f.cx)
            .is_err()
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}
