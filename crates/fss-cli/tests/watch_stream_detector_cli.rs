#![forbid(unsafe_code)]
//! Whole-recording detector selection, publication and retained-package replay through real
//! processes. The synthetic square is a plumbing fixture, not detector-quality evidence.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:stream-detector-cli";
const FRAMES: usize = 170;
const APPEARANCE: usize = 150;
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-detector-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    import: ContentDigest,
    package: PathBuf,
    retained_package: PathBuf,
}
impl Fixture {
    fn mjpeg(label: &str, appearance: bool) -> Test<Self> {
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let background = vec![40_u8; 48 * 32];
        let mut foreground = background.clone();
        for y in 8..24 {
            for x in 8..24 {
                foreground[y * 48 + x] = 220;
            }
        }
        let dark = encode_jpeg(48, 32, &background, &config)?;
        let square = encode_jpeg(48, 32, &foreground, &config)?;
        let mut bytes = Vec::new();
        for frame in 0..FRAMES {
            bytes.extend_from_slice(if appearance && frame >= APPEARANCE {
                &square
            } else {
                &dark
            });
        }
        Self::import(label, &bytes, "mjpeg", FRAMES)
    }

    fn import(label: &str, bytes: &[u8], extension: &str, frames: usize) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment with spaces");
        let input = directory.0.join(format!("source.{extension}"));
        let package = directory.0.join("model with spaces.fmpk");
        fs::write(&input, bytes)?;
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk"),
            &package,
        )?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:stream-detector-fixture".into(),
            operation_id: OperationId::parse("operation:stream-detector-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(65_536)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = frames + 1;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:stream-detector")?,
            StreamId::parse("stream:stream-detector")?,
        )
        .with_limits(limits)
        .with_receive_time(TimestampNs(1_000_000_000_000))
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        let retained_package = deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::parse(PACKAGE_DIGEST)?);
        drop(deployment);
        cx.drain_and_finalize();
        fs::remove_file(input)?;
        Ok(Self {
            directory,
            root,
            import,
            package,
            retained_package,
        })
    }

    fn plain(&self) -> Vec<OsString> {
        vec![
            "watch".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--import-id".into(),
            self.import.to_text().into(),
            "--interpretation".into(),
            "gray".into(),
            "--zone".into(),
            "porch:0,0,48,32".into(),
            "--stream-watch".into(),
        ]
    }

    fn detected(&self) -> Vec<OsString> {
        let mut args = self.plain();
        args.extend([
            "--detector-package".into(),
            self.package.as_os_str().to_owned(),
            "--detector-digest".into(),
            PACKAGE_DIGEST.into(),
            "--detector-max-inferences".into(),
            "1".into(),
        ]);
        args
    }

    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse(&String::from_utf8(output.stdout)?)?)
}
fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal emitted a JSON prefix");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn member<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text(value: &Value, key: &str) -> Test<String> {
    member(value, key)?
        .text()
        .map(str::to_owned)
        .ok_or_else(|| format!("non-text {key}").into())
}
fn count(value: &Value, key: &str) -> Test<i128> {
    member(value, key)?
        .integer()
        .ok_or_else(|| format!("non-integer {key}").into())
}
fn array<'a>(value: &'a Value, key: &str) -> Test<&'a [Value]> {
    member(value, key)?
        .array()
        .ok_or_else(|| format!("non-array {key}").into())
}
fn candidate(report: &Value) -> Test<&Value> {
    let items = array(report, "candidates")?;
    assert_eq!(items.len(), 1);
    Ok(&items[0])
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing option")?;
    *args.get_mut(index + 1).ok_or("missing value")? = value.into();
    Ok(())
}
fn unchanged_authority(report: &Value) -> Test {
    for (key, expected) in [
        ("event_kind", "unclassified"),
        ("event_state", "indeterminate"),
        ("policy_action", "hold"),
    ] {
        assert_eq!(text(report, key)?, expected);
    }
    for key in [
        "calibrated",
        "corroborated",
        "absence_certifiable",
        "alert_authorized",
    ] {
        assert_eq!(member(report, key)?, &Value::Bool(false));
    }
    Ok(())
}

#[test]
fn late_entry_runs_native_detector_and_retained_package_replays_after_loose_files_are_gone() -> Test
{
    let f = Fixture::mjpeg("cold", true)?;
    let before = f.snapshot()?;
    let plain = good(run(&f.plain())?)?;
    let mut args = f.detected();
    let preview = good(run(&args)?)?;
    let entry = candidate(&preview)?;
    let cascade = member(&preview, "detector_cascade")?;
    assert_eq!(count(&preview, "frames_decoded")?, FRAMES as i128);
    assert!(count(entry, "entry_position")? >= APPEARANCE as i128);
    assert_eq!(count(cascade, "inference_count")?, 1);
    assert_eq!(array(cascade, "selected_segments")?.len(), 1);
    assert_eq!(
        array(cascade, "inferred_segments")?,
        array(cascade, "selected_segments")?
    );
    assert_eq!(array(cascade, "budget_skipped_segments")?.len(), 0);
    assert_eq!(array(entry, "class_evidence")?.len(), 1);
    assert_eq!(member(&preview, "model_invoked")?, &Value::Bool(true));
    let selected_pixels = count(cascade, "additional_pixel_samples_processed")?;
    assert!(selected_pixels > 0);
    assert_eq!(
        count(&preview, "pixel_samples_processed")?,
        count(&plain, "pixel_samples_processed")? + selected_pixels
    );
    assert_eq!(
        count(&preview, "source_chunk_bytes_read")?,
        count(&plain, "source_chunk_bytes_read")? + count(cascade, "source_chunk_bytes_read")?
    );
    assert_ne!(
        text(&preview, "analysis_digest")?,
        text(&plain, "analysis_digest")?
    );
    assert_ne!(
        text(entry, "proposal_digest")?,
        text(candidate(&plain)?, "proposal_digest")?
    );
    assert!(text(entry, "publish_command")?.contains("--detector-package"));
    unchanged_authority(&preview)?;
    assert_eq!(f.snapshot()?, before);

    args.extend(["--approve".into(), text(entry, "proposal_digest")?.into()]);
    let published = good(run(&args)?)?;
    assert_eq!(text(candidate(&published)?, "status")?, "published");
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    let retry = good(run(&args)?)?;
    assert_eq!(text(candidate(&retry)?, "status")?, "already_published");
    assert_eq!(f.snapshot()?, after);

    fs::remove_file(&f.package)?;
    let event = text(candidate(&published)?, "event_id")?;
    let read_args = vec![
        "read".into(),
        "--root".into(),
        f.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--event-id".into(),
        event.clone().into(),
    ];
    let read = good(run(&read_args)?)?;
    assert_eq!(text(&read, "status")?, "inspected_not_replayed");
    assert_eq!(member(&read, "native_replayed")?, &Value::Bool(false));
    let retained_detector = member(&read, "retained_detector")?;
    assert_eq!(text(retained_detector, "package_digest")?, PACKAGE_DIGEST);
    assert_eq!(
        member(retained_detector, "loose_model_file_required")?,
        &Value::Bool(false)
    );
    let verify_args = vec![
        "verify".into(),
        "--root".into(),
        f.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--event-id".into(),
        event.into(),
        "--expected-event-revision".into(),
        text(&read, "event_revision_digest")?.into(),
        "--expected-provenance-root".into(),
        text(&read, "provenance_root")?.into(),
        "--execute-perception".into(),
        "yes".into(),
    ];
    let verified = good(run(&verify_args)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(member(&verified, "event")?, member(&read, "event")?);
    assert_eq!(
        member(&verified, "physical_truth_verified")?,
        &Value::Bool(false)
    );
    assert_eq!(f.snapshot()?, after);

    // A retained recipe is insufficient when its exact model archive is no longer in custody.
    // Exercise both new processes with the same successful event pins and no loose package.
    let removed_package = f.directory.0.join("retained-model-removed.fmpk");
    fs::rename(&f.retained_package, &removed_package)?;
    let missing_read = run(&read_args)?;
    let missing_verify = run(&verify_args)?;
    fs::rename(removed_package, &f.retained_package)?;
    refuses(missing_read, "ERR-");
    refuses(missing_verify, "ERR-");
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn complete_recording_shares_one_inference_allowance_and_keeps_skipped_evidence() -> Test {
    let f = Fixture::mjpeg("allowance", true)?;
    let before = f.snapshot()?;
    let mut args = f.detected();
    args.extend(["--detector-frames-per-track".into(), "3".into()]);
    let report = good(run(&args)?)?;
    let cascade = member(&report, "detector_cascade")?;
    assert_eq!(count(cascade, "inference_count")?, 1);
    assert_eq!(array(cascade, "selected_segments")?.len(), 3);
    assert_eq!(array(cascade, "budget_skipped_segments")?.len(), 2);
    assert_eq!(member(cascade, "budget_exhausted")?, &Value::Bool(true));
    let evidence = array(candidate(&report)?, "class_evidence")?;
    assert_eq!(evidence.len(), 3);
    assert_eq!(
        evidence
            .iter()
            .filter(|item| {
                text(item, "outcome").is_ok_and(|outcome| outcome == "budget_exhausted")
            })
            .count(),
        2
    );
    unchanged_authority(&report)?;
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn package_identity_and_changed_allowance_cannot_reuse_an_approval() -> Test {
    let f = Fixture::mjpeg("stale", true)?;
    let before = f.snapshot()?;
    let preview = good(run(&f.detected())?)?;
    let mut changed = f.detected();
    set(&mut changed, "--detector-max-inferences", "2")?;
    changed.extend([
        "--approve".into(),
        text(candidate(&preview)?, "proposal_digest")?.into(),
    ]);
    refuses(run(&changed)?, "ERR-WATCH-APPROVAL-STALE-001");

    let mut wrong = f.detected();
    set(
        &mut wrong,
        "--detector-digest",
        &ContentDigest::sha256(b"wrong package").to_text(),
    )?;
    // If the import is missing too, the package mismatch must still win before source reads.
    set(
        &mut wrong,
        "--import-id",
        &ContentDigest::sha256(b"missing import").to_text(),
    )?;
    refuses(run(&wrong)?, "ERR-MODEL-PACKAGE-DIGEST-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn health_gate_and_whole_scan_budgets_still_apply_when_detector_is_requested() -> Test {
    let f = Fixture::mjpeg("gates", true)?;
    let before = f.snapshot()?;
    let mut args = f.detected();
    args.extend(["--sensor-health".into(), "conservative-v1".into()]);
    let preview = good(run(&args)?)?;
    assert_eq!(member(&preview, "publication_blocked")?, &Value::Bool(true));
    assert_eq!(
        member(candidate(&preview)?, "publish_command")?,
        &Value::Null
    );
    args.extend([
        "--approve".into(),
        text(candidate(&preview)?, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&args)?,
        "sensor-health findings or incomplete screening",
    );
    for key in [
        "--stream-read-bytes",
        "--stream-pixel-budget",
        "--stream-assignment-work",
    ] {
        let export = f.directory.0.join("must-not-exist.json");
        let mut limited = f.detected();
        limited.extend([
            key.into(),
            "1".into(),
            "--report-out".into(),
            export.as_os_str().to_owned(),
        ]);
        refuses(run(&limited)?, "ERR-WATCH-LIMIT-001");
        assert!(!export.exists());
        assert_eq!(f.snapshot()?, before);
    }
    // Exactly the cheap scan's luma allowance still cannot finance the selected RGB pass.
    // In particular, beginning detector execution must not renew the aggregate pixel budget.
    let mut exhausted = f.detected();
    exhausted.extend([
        "--stream-pixel-budget".into(),
        (FRAMES * 48 * 32).to_string().into(),
    ]);
    refuses(run(&exhausted)?, "ERR-WATCH-LIMIT-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn quiet_recording_does_not_invoke_the_model_or_certify_absence() -> Test {
    let f = Fixture::mjpeg("quiet", false)?;
    let before = f.snapshot()?;
    let report = good(run(&f.detected())?)?;
    assert_eq!(count(&report, "frames_decoded")?, FRAMES as i128);
    assert_eq!(count(&report, "candidate_count")?, 0);
    assert_eq!(
        count(member(&report, "detector_cascade")?, "inference_count")?,
        0
    );
    assert_eq!(member(&report, "model_invoked")?, &Value::Bool(false));
    unchanged_authority(&report)?;
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn inter_coded_recording_uses_native_rgb_on_selected_display_order_observations() -> Test {
    let avc = include_bytes!("../../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4")
        .as_slice();
    let hevc =
        include_bytes!("../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4")
            .as_slice();
    for (name, bytes, count_frames, zone) in [
        ("avc", avc, 300, "porch:0,0,48,32"),
        ("hevc", hevc, 14, "porch:0,0,96,48"),
    ] {
        let f = Fixture::import(name, bytes, "mp4", count_frames)?;
        let before = f.snapshot()?;
        let mut args = f.detected();
        set(&mut args, "--interpretation", "ycbcr")?;
        set(&mut args, "--zone", zone)?;
        let report = good(run(&args)?)?;
        assert_eq!(count(&report, "frames_decoded")?, count_frames as i128);
        assert_eq!(count(&report, "candidate_count")?, 1);
        let cascade = member(&report, "detector_cascade")?;
        assert_eq!(count(cascade, "inference_count")?, 1);
        let frames = array(cascade, "frames")?;
        assert_eq!(frames.len(), 1);
        assert_eq!(text(&frames[0], "color")?, "ycbcr420_bt601_limited_rgb");
        assert_eq!(
            count(&frames[0], "segment")?,
            count(candidate(&report)?, "entry_segment")?
        );
        unchanged_authority(&report)?;
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}
