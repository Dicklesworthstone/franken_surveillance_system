#![forbid(unsafe_code)]
//! A retained trained-package candidate can disclose its verified footage without rerunning inference.

use fss_core::{CanonicalDecoder, CanonicalEncoder};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageEvent, PackageEventProposal, PackageTrackingConfig,
    retain_package_detection,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::original_media_export::{
    OriginalMediaExportRecord, PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN,
    PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE,
};

use super::*;

#[path = "package/reviewed.rs"]
mod reviewed;

const JPEG: &[u8] =
    include_bytes!("../../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE: &[u8] = include_bytes!("../../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn fixture(label: &str) -> Test<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let authority = authority(true)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    // Only the first frame is analyzed. The export must still identify and disclose the whole
    // three-frame source, including the two frames outside that candidate's interval.
    let source = JPEG.repeat(3);
    let input = directory.0.join("source.mjpeg");
    fs::write(&input, &source)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:original-media")?,
            StreamId::parse("stream:package-media-export")?,
        )
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    fs::remove_file(input)?;
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
            interpretation: fss_codec_mjpeg::ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(),
        &cx,
        &scalar,
    )?;
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
        .ok_or("package fixture track missing")?
        .identity;
    let proposal =
        PackageEventProposal::prepare(&deployment, report.encoded(), report.digest(), track, &cx)?;
    let receipt = proposal.publish(&mut deployment, proposal.digest(), &cx)?;
    let request = OriginalMediaExportRequest {
        event: EventExportRequest {
            event_id: receipt.event.event_id.clone(),
            expected_revision: receipt.event.revision_digest(),
            recipient: "recipient:owner-package-case".into(),
            purpose: "Review the original footage supporting a detector-package candidate".into(),
            expires_at: TimestampNs(2_000_000_000_000),
        },
        import_identity: imported.import_identity,
        expected_import_root: report.retained().record().import_root,
        whole_source_authorized: true,
        destination_binding: ContentDigest::sha256(b"approved-package-event-destination"),
        max_source_bytes: 4 * 1024 * 1024,
        attested_now: CaptureInterval::new(
            TimestampNs(1_000_000_000_000),
            TimestampNs(1_000_000_001_000),
        )?,
    };
    Ok(Fixture {
        directory,
        deployment,
        authority,
        cx,
        request,
        source,
    })
}

#[test]
fn package_candidate_cold_export_preserves_footage_uncertainty_and_exact_custody() -> Test {
    let f = fixture("package-cold")?;
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let native = PackageEvent::open(&reopened, &f.request.event.event_id, &f.cx)?;
    let preview = preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx)?;
    assert_eq!(preview.profile(), PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE);
    assert_eq!(preview.media_bytes(), f.source);
    assert_eq!(preview.media_filename(), "source.mjpeg");
    let json = preview.record_json();
    for field in [
        "\"schema\":\"fss.original_media_export.v3\"",
        "\"event_profile\":\"package_track\"",
        "\"state\":\"indeterminate\"",
        "\"kind\":\"unclassified\"",
        "\"decision_abstained\":true",
        "\"source_segments\":3",
        "\"event_source_count\":1",
        "\"native_perception_reexecuted\":false",
        "\"context_outside_event_may_be_included\":true",
        "\"audio_included\":false",
    ] {
        assert!(
            json.contains(field),
            "missing package disclosure {field}: {json}"
        );
    }
    assert!(json.contains(&native.event().decision_path.fingerprint.to_text()));
    assert!(json.contains(&native.report().retained().root().to_text()));
    let mut decoder = CanonicalDecoder::new(preview.record_bytes());
    assert_eq!(decoder.bytes()?, b"FSSEXM01");
    assert_eq!(decoder.u32()?, 3);
    assert_eq!(decoder.text()?, PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN);
    let prepared = approve_original_media_export(
        &reopened,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    revalidate_original_media_export(&reopened, &prepared, &f.authority, &f.cx)?;
    let verified = verify_original_media_export(
        preview.manifest_bytes(),
        preview.record_bytes(),
        preview.media_bytes(),
        preview.root(),
    )?;
    assert_eq!(verified.to_bytes(), preview.record_bytes());
    assert_eq!(verified.to_json(), json);
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    Ok(())
}

#[test]
fn package_export_cannot_substitute_a_source_or_downgrade_its_profile() -> Test {
    let f = fixture("package-binding")?;
    let before = f.snapshot();
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let mut wrong = f.request.clone();
    wrong.import_identity = ContentDigest::sha256(b"unrelated retained camera");
    assert!(matches!(
        preview_original_media_export(&f.deployment, &wrong, &f.authority, &f.cx),
        Err(OriginalMediaExportError::SourceNotInEvent)
    ));
    wrong = f.request.clone();
    wrong.expected_import_root = ContentDigest::sha256(b"substituted source root");
    assert!(matches!(
        preview_original_media_export(&f.deployment, &wrong, &f.authority, &f.cx),
        Err(OriginalMediaExportError::CustodyMismatch)
    ));
    wrong = f.request.clone();
    wrong.event.expected_revision = ContentDigest::sha256(b"substituted event revision");
    assert!(preview_original_media_export(&f.deployment, &wrong, &f.authority, &f.cx).is_err());
    let mut prefix = CanonicalEncoder::new();
    prefix.bytes(b"FSSEXM01");
    let position = prefix.finish().len();
    for version in [1_u32, 2, 4] {
        let mut changed = preview.record_bytes().to_vec();
        changed[position..position + 4].copy_from_slice(&version.to_be_bytes());
        assert!(OriginalMediaExportRecord::from_bytes(&changed).is_err());
    }
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn package_approval_cannot_release_after_source_or_provenance_custody_loss() -> Test {
    let f = fixture("package-damaged")?;
    let native = PackageEvent::open(&f.deployment, &f.request.event.event_id, &f.cx)?;
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let prepared = approve_original_media_export(
        &f.deployment,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.request.import_identity,
        Default::default(),
        &f.cx,
    )?;
    let source_chunk = *retained
        .manifest()
        .ordered_chunks
        .last()
        .ok_or("source chunk missing")?;
    for digest in [
        source_chunk,
        native.report().digest(),
        native.report().retained().record_digest(),
    ] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        fs::write(&path, b"damaged retained source or package proof")?;
        let before = f.snapshot();
        assert!(
            revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx)
                .is_err()
        );
        assert!(
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx).is_err()
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(
            fs::read(&path)?,
            b"damaged retained source or package proof"
        );
        // Restore only the test-injected bytes; the application must never repair on read.
        fs::write(path, bytes)?;
    }
    revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx)?;
    Ok(())
}

#[test]
fn package_media_masks_deletion_and_operator_successors_invalidate_release() -> Test {
    for (change, already_reviewed) in [
        ("mask", false),
        ("delete", false),
        ("review", false),
        ("mask", true),
        ("delete", true),
        ("review", true),
    ] {
        let mut f = fixture(&format!("package-{change}-{already_reviewed}"))?;
        if already_reviewed {
            reviewed::review(&mut f, ReviewDisposition::Investigate)?;
        }
        let preview =
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
        let prepared = approve_original_media_export(
            &f.deployment,
            &f.request,
            preview.approval(),
            &f.authority,
            &f.cx,
        )?;
        match change {
            "mask" => {
                let policy = PrivacyMaskPolicy::new(
                    SensorId::parse("sensor:original-media")?,
                    [64, 48],
                    &[[0, 0, 8, 48]],
                )?;
                let approval = preview_mask(&f.deployment, &policy)?.approval;
                declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
            }
            "delete" => {
                let plan = plan_deletion(&f.deployment, f.request.import_identity, &f.cx)?;
                assert!(plan.blockers.is_empty());
                let approval = plan.approval_digest(ACTOR)?;
                commit_deletion(&mut f.deployment, plan.digest()?, approval, ACTOR, &f.cx)?;
            }
            "review" => {
                let request = ReviewRequest {
                    event_id: f.request.event.event_id.clone(),
                    expected_revision: f.request.event.expected_revision,
                    disposition: ReviewDisposition::Resolve,
                    reason: "An operator assertion is not recomputed package evidence".into(),
                };
                let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
                let review = commit_review(
                    &mut f.deployment,
                    &request,
                    preview.approval(),
                    &f.authority,
                    &f.cx,
                )?;
                f.request.event.expected_revision = review.review.event().revision_digest();
            }
            _ => return Err("unknown fixture change".into()),
        }
        let before = f.snapshot();
        assert!(matches!(
            revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx),
            Err(OriginalMediaExportError::AuthorityChanged)
        ));
        if change == "review" {
            let current =
                preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
            assert_eq!(
                current.profile(),
                fss_reference::original_media_export::REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE
            );
            assert_eq!(current.media_bytes(), f.source);
            assert_ne!(current.approval(), preview.approval());
            assert!(matches!(
                approve_original_media_export(
                    &f.deployment,
                    &f.request,
                    preview.approval(),
                    &f.authority,
                    &f.cx
                ),
                Err(OriginalMediaExportError::StaleApproval)
            ));
        } else {
            assert!(
                preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)
                    .is_err()
            );
        }
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}
