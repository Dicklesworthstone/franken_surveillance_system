#![forbid(unsafe_code)]
//! The operator's existing media-export command also carries source-verified package candidates.

use super::*;
use fss_reference::ScalarExecCx;
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageEventProposal, PackageTrackingConfig, retain_package_detection,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;

const JPEG: &[u8] =
    include_bytes!("../../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE: &[u8] = include_bytes!("../../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn fixture() -> Test<Fixture> {
    let directory = Directory::new("package-event")?;
    let root = directory.0.join("deployment");
    let output = directory.0.join("package-event-footage");
    let source = JPEG.repeat(3);
    let input = directory.0.join("source.mjpeg");
    fs::write(&input, &source)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &input,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:package-export")?,
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
    let detected = run_package_detection(
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
    retain_package_detection(&mut deployment, &package, &detected, &cx)?;
    drop(package);
    let report = PackageAnalysisReport::read(
        &deployment,
        detected.digest,
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
        .ok_or("package track missing")?
        .identity;
    let proposal =
        PackageEventProposal::prepare(&deployment, report.encoded(), report.digest(), track, &cx)?;
    let receipt = proposal.publish(&mut deployment, proposal.digest(), &cx)?;
    let revision = receipt.event.revision_digest();
    let event_id = receipt.event.event_id;
    let identity = imported.import_identity;
    let import_root = report.retained().record().import_root;
    let retained = RetainedFileImport::open(&deployment, identity, Default::default(), &cx)?;
    let chunk = *retained
        .manifest()
        .ordered_chunks
        .first()
        .ok_or("source chunk missing")?;
    let source_chunk = deployment.publisher().spool().object_path(chunk);
    drop(deployment);
    cx.drain_and_finalize();
    Ok(Fixture {
        directory,
        root,
        output,
        source,
        source_chunk,
        identity,
        import_root,
        event_id,
        revision,
    })
}

#[test]
fn trained_package_candidate_exports_after_restart_and_verifies_offline() -> Test {
    let _serial = SERIAL.lock().unwrap();
    let fixture = fixture()?;
    let journals = fixture.journals()?;
    let preview = fixture.preview()?;
    let record = field(&preview, "record")?;
    assert_eq!(text(record, "schema")?, "fss.original_media_export.v3");
    assert_eq!(
        text(record, "profile")?,
        "event-package-original-media-whole-source-v3"
    );
    assert_eq!(text(record, "event_profile")?, "package_track");
    assert_eq!(
        text(field(record, "event_summary")?, "state")?,
        "indeterminate"
    );
    assert_eq!(
        text(field(record, "event_summary")?, "kind")?,
        "unclassified"
    );
    assert_eq!(field(record, "source_segments")?.integer(), Some(3));
    assert_eq!(
        field(record, "native_perception_reexecuted")?.boolean(),
        Some(false)
    );
    let args = approved(fixture.args(), text(&preview, "approval_digest")?);
    let committed = success(&execute(&args)?)?;
    assert_eq!(text(&committed, "status")?, "exported_original_media");
    assert_eq!(
        field(&committed, "export_root")?,
        field(&preview, "export_root")?
    );
    assert_eq!(
        fs::read(fixture.output.join("source.mjpeg"))?,
        fixture.source
    );
    let package = package_snapshot(&fixture.output)?;
    let retried = success(&execute(&args)?)?;
    assert_eq!(text(&retried, "status")?, "already_exported_original_media");
    assert_eq!(package_snapshot(&fixture.output)?, package);
    assert_eq!(fixture.journals()?, journals);
    fs::rename(
        &fixture.root,
        fixture.directory.0.join("deployment-offline"),
    )?;
    let verified = success(&execute(
        &fixture.verify_args(text(&preview, "export_root")?),
    )?)?;
    assert_eq!(text(&verified, "status")?, "verified_original_media");
    assert_eq!(
        field(&verified, "current_deployment_state_checked")?.boolean(),
        Some(false)
    );
    assert_eq!(field(&verified, "delivery_proven")?.boolean(), Some(false));
    Ok(())
}

fn assert_reviewed_package_record(
    record: &Value,
    original: &Value,
    reviews: &[ReviewWitness],
) -> Test {
    assert_eq!(text(record, "schema")?, "fss.original_media_export.v4");
    assert_eq!(
        text(record, "profile")?,
        "event-reviewed-package-original-media-whole-source-v4"
    );
    assert_eq!(text(record, "event_profile")?, "package_track");
    assert_eq!(text(record, "native_origin_state")?, "indeterminate");
    assert_eq!(text(record, "native_origin_kind")?, "unclassified");
    assert_eq!(
        field(record, "native_origin_calibrated")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(record, "native_origin_revision")?,
        field(original, "revision_digest")?
    );
    assert_eq!(
        field(record, "native_origin_event_root")?,
        field(original, "event_root")?
    );
    assert_eq!(
        field(record, "native_origin_authority_sequence")?.integer(),
        field(field(original, "event_anchor")?, "capsuleSequence")?.integer()
    );
    assert_eq!(
        field(record, "review_count")?.integer(),
        Some(reviews.len() as i128)
    );
    let chain = field(record, "review_chain")?
        .array()
        .ok_or("missing operator chain")?;
    assert_eq!(chain.len(), reviews.len());
    for (entry, expected) in chain.iter().zip(reviews) {
        assert_eq!(field(entry, "revision")?.integer(), Some(expected.revision));
        assert_eq!(
            text(entry, "event_revision")?,
            expected.event_revision.to_text()
        );
        assert_eq!(text(entry, "event_root")?, expected.event_root.to_text());
        assert_eq!(
            text(entry, "statement_digest")?,
            expected.statement_digest.to_text()
        );
        assert_eq!(
            text(entry, "statement_root")?,
            expected.statement_root.to_text()
        );
        assert_eq!(text(entry, "disposition")?, expected.disposition);
        assert_eq!(text(entry, "assertion_class")?, "operator");
        assert_eq!(field(entry, "sensor_support_added")?.boolean(), Some(false));
    }
    for name in [
        "review_reasons_included",
        "reviewer_identity_included",
        "review_is_sensor_recomputation",
        "native_perception_reexecuted",
    ] {
        assert_eq!(field(record, name)?.boolean(), Some(false));
    }
    let summary = field(record, "event_summary")?;
    assert_eq!(text(summary, "state")?, "resolved");
    assert_eq!(text(summary, "kind")?, "unclassified");
    assert_eq!(
        text(summary, "event_revision_digest")?,
        reviews
            .last()
            .ok_or("missing last review")?
            .event_revision
            .to_text()
    );
    Ok(())
}

#[test]
fn reviewed_package_exports_complete_current_assertions_and_original_footage_after_restart() -> Test
{
    let _serial = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let mut fixture = fixture()?;
    let original = fixture.review_show()?;
    let native = fixture.preview()?;
    let stale_native = approved(fixture.args(), text(&native, "approval_digest")?);
    const REVIEWER: &str = "principal:private-package-reviewer";
    const REASON: &str = "Private case notes do not become native detector corroboration";
    let first = fixture.review("investigate", REVIEWER, REASON)?;
    let intermediate = fixture.preview()?;
    let stale_review = approved(fixture.args(), text(&intermediate, "approval_digest")?);
    let second = fixture.review("investigate", REVIEWER, REASON)?;
    let third = fixture.review("resolve", REVIEWER, REASON)?;
    let reviews = [first, second, third];
    let journals = fixture.journals()?;
    for args in [
        stale_native,
        stale_review,
        approved(fixture.args(), text(&native, "approval_digest")?),
    ] {
        refused(&execute(&args)?);
        assert!(!fixture.output.exists());
    }
    let preview = fixture.preview()?;
    assert_reviewed_package_record(
        field(&preview, "record")?,
        field(&original, "result")?,
        &reviews,
    )?;
    // The original native proof and retained detection stay distinct from every review root.
    for name in [
        "event_provenance_root",
        "analysis_roots",
        "source_sha256",
        "source_import_root",
    ] {
        assert_eq!(
            field(field(&preview, "record")?, name)?,
            field(field(&native, "record")?, name)?
        );
    }
    let args = approved(fixture.args(), text(&preview, "approval_digest")?);
    let mut statement_path = None;
    fixture.update(|deployment, _| {
        statement_path = Some(
            deployment
                .publisher()
                .spool()
                .object_path(reviews[0].statement_digest),
        );
        Ok(())
    })?;
    let statement_path = statement_path.ok_or("missing statement path")?;
    let statement = fs::read(&statement_path)?;
    fs::remove_file(&statement_path)?;
    refused(&execute(&args)?);
    assert!(!fixture.output.exists());
    assert!(
        !statement_path.exists(),
        "export must not repair lost historical review custody"
    );
    assert_eq!(fixture.journals()?, journals);
    fs::write(statement_path, statement)?;
    let exported = success(&execute(&args)?)?;
    assert_eq!(text(&exported, "status")?, "exported_original_media");
    assert_eq!(
        field(&exported, "export_root")?,
        field(&preview, "export_root")?
    );
    assert_eq!(
        fs::read(fixture.output.join("source.mjpeg"))?,
        fixture.source
    );
    let package = package_snapshot(&fixture.output)?;
    for (name, bytes) in &package {
        if name != "source.mjpeg" {
            let rendered = String::from_utf8_lossy(bytes);
            assert!(!rendered.contains(REVIEWER));
            assert!(!rendered.contains(REASON));
        }
    }
    assert_eq!(
        text(&success(&execute(&args)?)?, "status")?,
        "already_exported_original_media"
    );
    assert_eq!(package_snapshot(&fixture.output)?, package);
    assert_eq!(fixture.journals()?, journals);
    fs::rename(
        &fixture.root,
        fixture.directory.0.join("reviewed-package-offline"),
    )?;
    let verified = success(&execute(
        &fixture.verify_args(text(&preview, "export_root")?),
    )?)?;
    assert_eq!(text(&verified, "status")?, "verified_original_media");
    assert_reviewed_package_record(
        field(&verified, "record")?,
        field(&original, "result")?,
        &reviews,
    )?;
    assert_eq!(
        field(&verified, "current_deployment_state_checked")?.boolean(),
        Some(false)
    );
    assert_eq!(field(&verified, "delivery_proven")?.boolean(), Some(false));
    Ok(())
}
