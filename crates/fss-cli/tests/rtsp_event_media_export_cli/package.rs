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
