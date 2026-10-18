#![forbid(unsafe_code)]
//! Trained whole-recording corroboration through real native CLI processes. Synthetic mirrored
//! views exercise computation, bounded work and retained custody, not detector accuracy.

#[path = "corroborate_stream_detector_cli/fusion.rs"]
mod fusion;

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
const SITE: &str = "site:stream-corroborate-detector-cli";
const FRAMES: usize = 170;
const APPEARANCE: usize = 150;
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-corrob-detector-cli-{label}-{}-{attempt}",
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
    imports: [ContentDigest; 2],
    package: PathBuf,
    retained_package: PathBuf,
}
impl Fixture {
    fn mjpeg(label: &str, appearance: bool) -> Test<Self> {
        Self::import(
            label,
            [&scene(appearance, false)?, &scene(appearance, true)?],
            "mjpeg",
            FRAMES,
        )
    }

    fn import(label: &str, source: [&[u8]; 2], extension: &str, frames: usize) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment with spaces");
        let package = directory.0.join("model with spaces.fmpk");
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk"),
            &package,
        )?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:stream-corroborate-detector-fixture".into(),
            operation_id: OperationId::parse("operation:stream-corroborate-detector-fixture")?,
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
        let mut imports = Vec::new();
        for (index, name) in ["east", "west"].into_iter().enumerate() {
            let input = directory.0.join(format!("source-{name}.{extension}"));
            fs::write(&input, source[index])?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = frames + 1;
            limits.chunk_bytes = 4096;
            let request = FileIngestRequest::new(
                &input,
                SensorId::parse(format!("sensor:stream-corrob-detector-{name}"))?,
                StreamId::parse(format!("stream:stream-corrob-detector-{name}"))?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(
                TimestampNs(1_000_000_000),
                1_000_000,
                10.0,
            )?);
            imports.push(FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity);
            // Both recordings must be reconstructed entirely from retained source custody.
            fs::remove_file(input)?;
        }
        let retained_package = deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::parse(PACKAGE_DIGEST)?);
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            imports: imports.try_into().map_err(|_| "two imports required")?,
            package,
            retained_package,
        })
    }

    fn plain(&self) -> Vec<OsString> {
        vec![
            "corroborate".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--camera".into(),
            format!("east:{}", self.imports[0]).into(),
            "--camera".into(),
            format!("west:{}", self.imports[1]).into(),
            "--ground".into(),
            "east:1,0,0,0,1,0,0,0,1".into(),
            "--ground".into(),
            "west:-1,0,48,0,1,0,0,0,1".into(),
            "--zone".into(),
            "door:8,16,16,16".into(),
            "--interpretation".into(),
            "gray".into(),
            "--time-gate-ns".into(),
            "250000000".into(),
            "--distance-gate".into(),
            "4".into(),
            "--stream-corroborate".into(),
        ]
    }

    fn detected(&self, allowance: usize) -> Vec<OsString> {
        let mut args = self.plain();
        args.extend([
            "--detector-package".into(),
            self.package.as_os_str().to_owned(),
            "--detector-digest".into(),
            PACKAGE_DIGEST.into(),
            "--detector-max-inferences".into(),
            allowance.to_string().into(),
            "--detector-frames-per-track".into(),
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

fn scene(appearance: bool, mirrored: bool) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut pixels = vec![40_u8; 48 * 32];
    let background = encode_jpeg(48, 32, &pixels, &config)?;
    let left = if mirrored { 24 } else { 8 };
    for y in 8..24 {
        for x in left..left + 16 {
            pixels[y * 48 + x] = 220;
        }
    }
    let square = encode_jpeg(48, 32, &pixels, &config)?;
    let mut bytes = Vec::new();
    for frame in 0..FRAMES {
        bytes.extend_from_slice(if appearance && frame >= APPEARANCE {
            &square
        } else {
            &background
        });
    }
    Ok(bytes)
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
    let values = array(report, "candidates")?;
    assert_eq!(values.len(), 1);
    Ok(&values[0])
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing option")?;
    *args.get_mut(index + 1).ok_or("missing value")? = value.into();
    Ok(())
}
fn replace(args: &mut [OsString], previous: &str, value: &str) -> Test {
    *args
        .iter_mut()
        .find(|arg| arg.to_str() == Some(previous))
        .ok_or("missing argument")? = value.into();
    Ok(())
}
fn unchanged_policy(report: &Value, state: &str, action: &str) -> Test {
    assert_eq!(text(candidate(report)?, "event_kind")?, "unclassified");
    assert_eq!(text(candidate(report)?, "event_state")?, state);
    assert_eq!(text(candidate(report)?, "policy_action")?, action);
    for key in [
        "calibrated",
        "physical_arrival_proved",
        "absence_certifiable",
        "alert_authorized",
        "alert_prepared",
        "effects_authorized",
    ] {
        assert_eq!(member(report, key)?, &Value::Bool(false));
    }
    Ok(())
}

#[test]
fn late_entries_run_both_models_and_cold_replay_retains_exact_camera_associations() -> Test {
    let f = Fixture::mjpeg("cold", true)?;
    let before = f.snapshot()?;
    let plain = good(run(&f.plain())?)?;
    let mut args = f.detected(2);
    let preview = good(run(&args)?)?;
    let global = member(&preview, "detector_cascade")?;
    assert_eq!(text(global, "budget_scope")?, "both_recordings");
    assert_eq!(count(global, "shared_inference_allowance")?, 2);
    assert_eq!(count(global, "inferences_completed")?, 2);
    assert_eq!(count(global, "inference_pipeline_attempts")?, 2);
    let cameras = array(&preview, "cameras")?;
    let plain_cameras = array(&plain, "cameras")?;
    let entries = array(&preview, "entries")?;
    assert_eq!(cameras.len(), 2);
    assert_eq!(entries.len(), 2);
    for ((camera, plain_camera), entry) in cameras.iter().zip(plain_cameras).zip(entries) {
        assert_eq!(count(camera, "frames_decoded")?, FRAMES as i128);
        assert!(count(entry, "entry_position")? >= APPEARANCE as i128);
        assert_eq!(text(entry, "camera")?, text(camera, "camera")?);
        let cascade = member(camera, "detector_cascade")?;
        assert_eq!(count(cascade, "inference_count")?, 1);
        let frames = array(cascade, "frames")?;
        assert_eq!(frames.len(), 1);
        assert!(count(&frames[0], "executed_macs")? > 0);
        assert_eq!(count(&frames[0], "segment")?, count(entry, "segment")?);
        let classes = array(entry, "class_evidence")?;
        assert_eq!(classes.len(), 1);
        assert_eq!(count(&classes[0], "segment")?, count(entry, "segment")?);
        assert_eq!(text(&classes[0], "selection")?, "zone_entry");
        assert!(
            count(camera, "pixel_samples_processed")?
                > count(plain_camera, "pixel_samples_processed")?
        );
        assert!(
            count(camera, "source_chunk_bytes_read")?
                > count(plain_camera, "source_chunk_bytes_read")?
        );
    }
    assert_ne!(
        text(&array(&entries[0], "class_evidence")?[0], "evidence_digest")?,
        text(&array(&entries[1], "class_evidence")?[0], "evidence_digest")?
    );
    assert_ne!(
        text(&preview, "analysis_digest")?,
        text(&plain, "analysis_digest")?
    );
    assert_ne!(
        text(candidate(&preview)?, "proposal_digest")?,
        text(candidate(&plain)?, "proposal_digest")?
    );
    assert!(text(candidate(&preview)?, "publish_command")?.contains("--detector-package"));
    unchanged_policy(&preview, "corroborated", "prepare_alert")?;
    assert_eq!(f.snapshot()?, before);

    args.extend([
        "--approve".into(),
        text(candidate(&preview)?, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    assert_eq!(text(candidate(&published)?, "status")?, "published");
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1, "no alert or other effect is dispatched");
    let retry = good(run(&args)?)?;
    assert_eq!(text(candidate(&retry)?, "status")?, "already_published");
    assert_eq!(f.snapshot()?, after);

    fs::remove_file(&f.package)?;
    let event_id = text(candidate(&published)?, "event_id")?;
    let read_args = vec![
        "read".into(),
        "--root".into(),
        f.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--event-id".into(),
        event_id.clone().into(),
    ];
    let read = good(run(&read_args)?)?;
    assert_eq!(text(&read, "status")?, "inspected_not_replayed");
    assert_eq!(member(&read, "native_replayed")?, &Value::Bool(false));
    let retained = member(&read, "retained_detector")?;
    assert_eq!(text(retained, "package_digest")?, PACKAGE_DIGEST);
    assert_eq!(
        member(retained, "loose_model_file_required")?,
        &Value::Bool(false)
    );
    let event = member(&read, "event")?;
    let probability = member(event, "probability")?;
    assert_eq!(member(probability, "lower")?, &Value::Number("0.0".into()));
    assert_eq!(member(probability, "upper")?, &Value::Number("1.0".into()));
    assert_eq!(member(probability, "calibrationGeneration")?, &Value::Null);
    assert!(
        array(event, "modelReceipts")?.is_empty(),
        "class records are not invented invocation receipts"
    );
    // Class records belong to the retained association/provenance closure. They are not
    // additional votes in the ground-entry policy event. Native verify below rechecks every
    // selected class source/capsule binding while reproducing both complete camera analyses.
    for entry in entries {
        let digest = text(&array(entry, "class_evidence")?[0], "evidence_digest")?;
        assert!(
            array(event, "evidence")?
                .iter()
                .all(|edge| { text(edge, "digest").is_ok_and(|value| value != digest) })
        );
    }
    let verify_args = vec![
        "verify".into(),
        "--root".into(),
        f.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--event-id".into(),
        event_id.into(),
        "--expected-event-revision".into(),
        text(&read, "event_revision_digest")?.into(),
        "--expected-provenance-root".into(),
        text(&read, "provenance_root")?.into(),
        "--execute-perception".into(),
        "yes".into(),
    ];
    let verified = good(run(&verify_args)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(member(&verified, "event")?, event);
    assert_eq!(
        member(&verified, "physical_truth_verified")?,
        &Value::Bool(false)
    );
    assert_eq!(f.snapshot()?, after);

    let removed = f.directory.0.join("removed-retained-model.fmpk");
    fs::rename(&f.retained_package, &removed)?;
    let missing_read = run(&read_args)?;
    let missing_verify = run(&verify_args)?;
    fs::rename(removed, &f.retained_package)?;
    refuses(missing_read, "ERR-");
    refuses(missing_verify, "ERR-");
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn one_allowance_spans_both_cameras_and_changed_recipe_or_common_cause_requires_new_approval()
-> Test {
    let f = Fixture::mjpeg("allowance", true)?;
    let before = f.snapshot()?;
    let args = f.detected(1);
    let report = good(run(&args)?)?;
    let global = member(&report, "detector_cascade")?;
    assert_eq!(count(global, "shared_inference_allowance")?, 1);
    assert_eq!(count(global, "inferences_completed")?, 1);
    let cameras = array(&report, "cameras")?;
    assert_eq!(
        count(member(&cameras[0], "detector_cascade")?, "inference_count")?,
        1
    );
    assert_eq!(
        count(member(&cameras[1], "detector_cascade")?, "inference_count")?,
        0
    );
    assert_eq!(
        array(
            member(&cameras[1], "detector_cascade")?,
            "budget_skipped_segments"
        )?
        .len(),
        1
    );
    let second_class = &array(&array(&report, "entries")?[1], "class_evidence")?[0];
    assert_eq!(text(second_class, "outcome")?, "budget_exhausted");
    assert_eq!(member(second_class, "supports")?, &Value::Bool(false));
    unchanged_policy(&report, "corroborated", "prepare_alert")?;
    let approval = text(candidate(&report)?, "proposal_digest")?;
    let mut changed = f.detected(2);
    changed.extend(["--approve".into(), approval.clone().into()]);
    refuses(run(&changed)?, "ERR-CORROBORATE-APPROVAL-STALE-001");

    let mut shared = args;
    shared.extend([
        "--failure-domain".into(),
        "model:shared-family=east,west".into(),
    ]);
    let constrained = good(run(&shared)?)?;
    unchanged_policy(&constrained, "witnessed", "hold")?;
    assert_eq!(
        count(
            member(&constrained, "detector_cascade")?,
            "inferences_completed"
        )?,
        1
    );
    assert_ne!(text(candidate(&constrained)?, "proposal_digest")?, approval);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn package_preflight_health_screen_and_per_camera_whole_scan_limits_fail_without_writes() -> Test {
    let f = Fixture::mjpeg("gates", true)?;
    let before = f.snapshot()?;
    let mut wrong = f.detected(1);
    set(
        &mut wrong,
        "--detector-digest",
        &ContentDigest::sha256(b"wrong package").to_text(),
    )?;
    set(
        &mut wrong,
        "--camera",
        &format!("east:{}", ContentDigest::sha256(b"missing source")),
    )?;
    refuses(run(&wrong)?, "ERR-MODEL-PACKAGE-DIGEST-001");
    assert_eq!(f.snapshot()?, before);

    for key in [
        "--stream-read-bytes",
        "--stream-pixel-budget",
        "--stream-assignment-work",
    ] {
        let output = f.directory.0.join("must-not-exist.json");
        let mut limited = f.detected(1);
        limited.extend([
            key.into(),
            "1".into(),
            "--report-out".into(),
            output.as_os_str().to_owned(),
        ]);
        refuses(run(&limited)?, "ERR-WATCH-LIMIT-001");
        assert!(!output.exists());
        assert_eq!(f.snapshot()?, before);
    }
    // The native luma pass alone consumes this whole-camera pixel allowance. Selected RGB
    // work cannot replenish it, even though its model inference allowance remains nonzero.
    let mut exhausted = f.detected(1);
    exhausted.extend([
        "--stream-pixel-budget".into(),
        (FRAMES * 48 * 32).to_string().into(),
    ]);
    refuses(run(&exhausted)?, "ERR-WATCH-LIMIT-001");
    let mut screened = f.detected(1);
    screened.extend(["--sensor-health".into(), "conservative-v1".into()]);
    let blocked = good(run(&screened)?)?;
    assert_eq!(member(&blocked, "publication_blocked")?, &Value::Bool(true));
    assert_eq!(
        member(candidate(&blocked)?, "publish_command")?,
        &Value::Null
    );
    screened.extend([
        "--approve".into(),
        text(candidate(&blocked)?, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&screened)?,
        "sensor-health findings or incomplete screening",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn quiet_recordings_never_invoke_the_model_or_certify_absence() -> Test {
    let f = Fixture::mjpeg("quiet", false)?;
    let before = f.snapshot()?;
    let report = good(run(&f.detected(2))?)?;
    assert_eq!(count(&report, "entry_count")?, 0);
    assert_eq!(count(&report, "candidate_count")?, 0);
    assert_eq!(
        count(member(&report, "detector_cascade")?, "inferences_completed")?,
        0
    );
    assert_eq!(member(&report, "model_invoked")?, &Value::Bool(false));
    assert_eq!(member(&report, "absence_certifiable")?, &Value::Bool(false));
    assert_eq!(member(&report, "alert_authorized")?, &Value::Bool(false));
    for camera in array(&report, "cameras")? {
        assert_eq!(count(camera, "frames_decoded")?, FRAMES as i128);
        assert!(array(member(camera, "detector_cascade")?, "frames")?.is_empty());
    }
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn avc_and_hevc_ground_matches_run_native_color_on_each_source() -> Test {
    let avc = include_bytes!("../../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4")
        .as_slice();
    let hevc =
        include_bytes!("../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4")
            .as_slice();
    for (name, bytes, frames, zone) in [
        ("avc", avc, 300, "door:0,0,48,32"),
        ("hevc", hevc, 14, "door:0,0,96,48"),
    ] {
        let f = Fixture::import(name, [bytes, bytes], "mp4", frames)?;
        let before = f.snapshot()?;
        let mut args = f.detected(2);
        set(&mut args, "--interpretation", "ycbcr")?;
        set(&mut args, "--zone", zone)?;
        replace(
            &mut args,
            "west:-1,0,48,0,1,0,0,0,1",
            "west:1,0,0,0,1,0,0,0,1",
        )?;
        let report = good(run(&args)?)?;
        assert_eq!(
            count(member(&report, "detector_cascade")?, "inferences_completed")?,
            2
        );
        let entries = array(&report, "entries")?;
        assert_eq!(entries.len(), 2);
        for (camera, entry) in array(&report, "cameras")?.iter().zip(entries) {
            assert_eq!(count(camera, "frames_decoded")?, frames as i128);
            let inferred = array(member(camera, "detector_cascade")?, "frames")?;
            assert_eq!(inferred.len(), 1);
            assert_eq!(text(&inferred[0], "color")?, "ycbcr420_bt601_limited_rgb");
            assert!(count(&inferred[0], "executed_macs")? > 0);
            assert_eq!(count(&inferred[0], "segment")?, count(entry, "segment")?);
        }
        unchanged_policy(&report, "corroborated", "prepare_alert")?;
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}
