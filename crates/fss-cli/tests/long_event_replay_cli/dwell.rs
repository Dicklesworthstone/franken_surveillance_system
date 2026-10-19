#![forbid(unsafe_code)]
//! General cold read/verify over the upstream sampled-dwell producer and exact native media.

use super::*;

const AVC: &[u8] =
    include_bytes!("../../../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4");
const HEVC: &[u8] =
    include_bytes!("../../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4");
const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn inter_fixture(label: &str, bytes: &[u8]) -> Test<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("operator's $data deployment");
    let input = directory.0.join("native original.mp4");
    fs::write(&input, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut limits = FileIngestLimits::standard();
    limits.max_segments = 1024;
    limits.chunk_bytes = 4096;
    let request = FileIngestRequest::new(
        &input,
        SensorId::parse("sensor:cold-dwell")?,
        StreamId::parse("stream:cold-dwell")?,
    )
    .with_limits(limits)
    .with_receive_time(TimestampNs(1_000_000_000_000))
    .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
    let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
    let retained =
        RetainedFileImport::open(&deployment, import, RetainedReadLimits::default(), &cx)?;
    let source_chunk = deployment
        .publisher()
        .spool()
        .object_path(retained.manifest().ordered_chunks[0]);
    drop(deployment);
    cx.drain_and_finalize();
    fs::remove_file(input)?;
    Ok(Fixture {
        directory,
        root,
        imports: vec![import],
        source_chunk,
    })
}

fn publish_dwell(
    f: &Fixture,
    interpretation: &str,
    size: [u32; 2],
    duration: u64,
    trained: bool,
) -> Test<EventId> {
    let mut args = f.base("watch");
    args.extend([
        "--import-id".into(),
        f.imports[0].to_text().into(),
        "--interpretation".into(),
        interpretation.into(),
        "--zone".into(),
        format!("porch:0,0,{},{}", size[0], size[1]).into(),
        "--stream-dwell".into(),
        "--dwell-for-ns".into(),
        duration.to_string().into(),
        "--dwell-max-gap-ns".into(),
        "1000000000".into(),
        "--dwell-min-observations".into(),
        "3".into(),
        "--learning-rate-num".into(),
        "0".into(),
    ]);
    let package = f.directory.0.join("operator's $models.fmpk");
    if trained {
        fs::write(&package, PACKAGE)?;
        args.extend([
            "--detector-package".into(),
            package.as_os_str().to_owned(),
            "--detector-digest".into(),
            PACKAGE_DIGEST.into(),
            "--detector-max-inferences".into(),
            "1".into(),
            "--detector-frames-per-track".into(),
            "3".into(),
        ]);
    }
    let before = f.snapshot()?;
    let preview = good(run(&args)?)?;
    let candidates = member(&preview, "candidates")?
        .array()
        .ok_or("dwell candidates")?;
    let candidate = candidates.first().ok_or("qualifying dwell candidate")?;
    let event = EventId::parse(field(candidate, "event_id")?)?;
    assert!(
        member(candidate, "trigger_segment")?
            .integer()
            .ok_or("trigger")?
            > member(candidate, "first_segment")?
                .integer()
                .ok_or("first")?
    );
    if trained {
        let classes = member(candidate, "class_evidence")?
            .array()
            .ok_or("class annotations")?;
        assert_eq!(classes.len(), 3);
        assert_eq!(field(&classes[0], "selection")?, "dwell_start");
        assert!(
            classes[1..]
                .iter()
                .all(|item| field(item, "selection").is_ok_and(|value| value == "following_match"))
        );
    }
    assert_eq!(f.snapshot()?, before);
    args.extend([
        "--approve".into(),
        field(candidate, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    let candidates = member(&published, "candidates")?
        .array()
        .ok_or("published candidates")?;
    assert_eq!(
        field(candidates.first().ok_or("published dwell")?, "status")?,
        "published"
    );
    assert_eq!(f.snapshot()?.1, before.1);
    if trained {
        fs::remove_file(package)?;
    }
    Ok(event)
}

#[test]
fn trained_avc_and_hevc_dwell_events_cold_read_and_verify_without_loose_inputs() -> Test {
    for (label, bytes, size, frames, duration) in [
        ("dwell-avc", AVC, [48, 32], 300, 20_000_000_000),
        ("dwell-hevc", HEVC, [96, 48], 14, 1),
    ] {
        let f = inter_fixture(label, bytes)?;
        let event = publish_dwell(&f, "ycbcr", size, duration, true)?;
        let before = f.snapshot()?;
        let read_args = f.read(&event);
        let inspection = good(run(&read_args)?)?;
        assert_eq!(field(&inspection, "profile")?, "long_dwell");
        assert_eq!(field(&inspection, "status")?, "inspected_not_replayed");
        assert_eq!(
            field(&inspection, "configuration_source")?,
            "retained_canonical_dwell_and_detector_recipe"
        );
        let detector = member(&inspection, "retained_detector")?;
        assert_eq!(field(detector, "package_digest")?, PACKAGE_DIGEST);
        assert_eq!(
            member(detector, "loose_model_file_required")?,
            &Value::Bool(false)
        );
        assert_eq!(member(&inspection, "native_replayed")?, &Value::Bool(false));
        assert_eq!(f.snapshot()?, before);
        let verify_args = verification_args(&inspection)?;
        let verified = good(run(&verify_args)?)?;
        assert_eq!(field(&verified, "status")?, "native_replay_matched");
        assert_eq!(
            member(&verified, "frames_replayed")?.integer(),
            Some(frames)
        );
        assert_eq!(member(&verified, "event")?, member(&inspection, "event")?);
        assert_eq!(
            member(&verified, "physical_truth_verified")?,
            &Value::Bool(false)
        );
        assert_eq!(
            member(&verified, "persistent_verification_record_written")?,
            &Value::Bool(false)
        );
        assert_eq!(member(&verified, "alert_authorized")?, &Value::Bool(false));
        assert_eq!(f.snapshot()?, before);

        let cx = context(&f.root)?;
        let deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
        let retained_package = deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::parse(PACKAGE_DIGEST)?);
        drop(deployment);
        cx.drain_and_finalize();
        fs::remove_file(retained_package)?;
        refuses(run(&read_args)?, "ERR-");
        refuses(run(&verify_args)?, "ERR-");
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn model_free_dwell_cold_route_reports_historical_ceilings_and_requires_exact_pins() -> Test {
    let f = Fixture::new("dwell-model-free", 1)?;
    let event = publish_dwell(&f, "gray", [48, 32], 500_000_000, false)?;
    let before = f.snapshot()?;
    let inspection = good(run(&f.read(&event))?)?;
    assert_eq!(field(&inspection, "profile")?, "long_dwell");
    assert_eq!(
        field(&inspection, "configuration_source")?,
        "retained_semantic_dwell_recipe"
    );
    assert_eq!(
        field(&inspection, "decoder_and_read_ceiling_source")?,
        "current_caller_bounded_ceilings_historical_ceilings_not_retained"
    );
    let args = verification_args(&inspection)?;
    let verified = good(run(&args)?)?;
    assert_eq!(
        member(&verified, "frames_replayed")?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(member(&verified, "event")?, member(&inspection, "event")?);
    for key in ["--expected-event-revision", "--expected-provenance-root"] {
        let mut stale = args.clone();
        set(
            &mut stale,
            key,
            &ContentDigest::sha256(b"other dwell selection").to_text(),
        )?;
        refuses(run(&stale)?, "ERR-");
    }
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
