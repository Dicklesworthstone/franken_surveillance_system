#![forbid(unsafe_code)]
//! Cold executable inspection of codec-pinned replay receipts and native originals.

#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod hevc_recording_support;
#[path = "../../fss-reference/tests/recording_support/mod.rs"]
mod recording_support;
#[path = "archive_replay_process/time.rs"]
mod time;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse};
use fss_cli::{ERR_CLI_DUPLICATE_OPTION, ERR_CLI_UNKNOWN_OPTION, ExitIdentity};
use fss_core::{
    CanonicalEncode, ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord,
};
use fss_object::SpoolLimits;
use fss_publication::{
    LOCAL_TOMBSTONES_DIR, LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName,
};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{
    RecordingProgress, RecordingPublication, load_recording,
};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{
    ReplayReceipt, ReplayRequest, ReplayTermination, ReplayWindowProof, publish_replay_receipt,
};
use recording_support::{Error, fixture, scope};

type Test<T = ()> = Result<T, Error>;
static NEXT: AtomicUsize = AtomicUsize::new(0);
// Native owner locks must not be inherited by a concurrently spawned test process.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("archive_replay_process")
        .join(format!(
            "{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        128,
        SpoolLimits::new(128, 32 * 1024 * 1024, 8 * 1024 * 1024, 256),
    )
}

fn request() -> Test<ReplayRequest> {
    Ok(ReplayRequest::new(
        scope()?,
        ContentDigest::sha256(b"approved credential-free replay route"),
        ReplayWindow::from_timestamps("20261105T010000Z", "20261105T010500Z")?,
        ContentDigest::sha256(b"original decode clock"),
    )?)
}

fn catalog_scope(request: &ReplayRequest) -> CatalogScope {
    CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    }
}

fn prepare(
    request: ReplayRequest,
    windows: Vec<ReplayWindowProof>,
    termination: ReplayTermination,
    complete: bool,
) -> Test<ReplayReceipt> {
    let accepted = ReplayAcceptance::new(
        7,
        request.window(),
        ReplayWindow::from_timestamps("20261105T010100Z", "20261105T010400Z")?,
    )?;
    Ok(ReplayReceipt::prepare(
        request.clone(),
        catalog_scope(&request),
        ContentDigest::sha256(b"complete approved capture plan"),
        accepted,
        windows,
        termination,
        complete,
    )?)
}

fn publish_original(
    publisher: &mut LocalRootPublisher,
    slot: &SlotName,
    recording: &PreparedRecording,
) -> Test {
    let mut job = RecordingPublication::new(
        recording,
        publisher,
        slot.clone(),
        recording.byte_len(),
        100,
    )?;
    for now in 0..4 {
        assert!(matches!(
            job.step(now, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        job.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}

fn setup(
    name: &str,
    count: usize,
    termination: ReplayTermination,
    complete: bool,
) -> Test<(PathBuf, ReplayReceipt)> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let request = request()?;
    let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
    let source = fixture(913, true)?;
    let mut windows = Vec::new();
    for ordinal in 0..count {
        let original = source.prepare_at(ordinal as u64 * 3600)?;
        let slot = namespace.window_slot(ordinal)?;
        publish_original(&mut publisher, &slot, &original)?;
        windows.push(ReplayWindowProof::from_avc(slot, &original)?);
    }
    let receipt = prepare(request, windows, termination, complete)?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    drop(publisher);
    Ok((root, receipt))
}

fn args(root: &Path, receipt: &ReplayReceipt) -> Vec<OsString> {
    let scope = receipt.scope();
    let mut args = vec![
        OsString::from("inspect-replay"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
    ];
    for (key, value) in [
        ("--codec", receipt.request().codec().as_str().to_owned()),
        ("--sensor", scope.recording.sensor.as_str().to_owned()),
        ("--stream", scope.recording.stream.as_str().to_owned()),
        ("--generation", scope.recording.generation.to_string()),
        ("--anchor", scope.recording.anchor.to_text()),
        ("--receive-clock", scope.recording.receive_clock.to_text()),
        ("--decode-clock", scope.decode_clock.to_text()),
        ("--time-scale", scope.time_scale.to_string()),
        ("--expected-replay-root", receipt.root().to_text()),
        (
            "--expected-replay-request",
            receipt.request().digest().to_text(),
        ),
    ] {
        args.push(key.into());
        args.push(value.into());
    }
    args
}

fn change(args: &mut Vec<OsString>, key: &str, value: Option<&str>) -> Test {
    if let Some(at) = args.iter().position(|arg| arg == key) {
        if let Some(value) = value {
            args[at + 1] = value.into();
        } else {
            args.drain(at..at + 2);
        }
    } else if let Some(value) = value {
        args.push(key.into());
        args.push(value.into());
    } else {
        return Err("fixture option missing".into());
    }
    Ok(())
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .output()?)
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|object| object.get(key))
        .ok_or("missing report field")?)
}

fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    Ok(field(value, key)?.text().ok_or("expected report text")?)
}

fn report(output: Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 64 * 1024);
    Ok(parse(&String::from_utf8(output.stdout)?)?)
}

#[test]
fn help_exposes_exact_cold_pins_and_keeps_utc_claims_separate() -> Test {
    let _serial = serial();
    for args in [vec!["help"], vec!["inspect-replay", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
            .args(args)
            .output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout)?;
        for required in [
            "inspect-replay",
            "--expected-replay-root",
            "--expected-replay-request",
            "--decode-clock",
            "--max-object-bytes",
            "not calibrated frame",
            "64 KiB",
        ] {
            assert!(text.contains(required), "missing help: {required}");
        }
    }
    Ok(())
}

#[test]
fn malformed_pins_and_limits_refuse_before_storage_and_never_echo_values() -> Test {
    let _serial = serial();
    let missing = path("PRIVATE_PATH_SENTINEL");
    let receipt = prepare(
        request()?,
        Vec::new(),
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    for (key, value) in [
        ("--expected-replay-root", None),
        (
            "--expected-replay-request",
            Some("PRIVATE_PASSWORD_SENTINEL"),
        ),
        ("--codec", Some("mjpeg")),
        ("--max-object-bytes", Some("33554433")),
        ("--timeout-ms", Some("0")),
    ] {
        let mut args = args(&missing, &receipt);
        change(&mut args, key, value)?;
        let output = run(&args)?;
        assert_eq!(
            output.status.code(),
            Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
        );
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(!error.contains("PRIVATE_PASSWORD_SENTINEL"));
        assert!(!error.contains("PRIVATE_PATH_SENTINEL"));
        assert!(!missing.exists());
    }
    for (key, code) in [
        ("--expected-replay-root", ERR_CLI_DUPLICATE_OPTION),
        ("--uri", ERR_CLI_UNKNOWN_OPTION),
    ] {
        let mut args = args(&missing, &receipt);
        args.extend([
            OsString::from(key),
            OsString::from("PRIVATE_PASSWORD_SENTINEL"),
        ]);
        let output = run(&args)?;
        assert_eq!(
            output.status.code(),
            Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
        );
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains(code));
        assert!(!error.contains("PRIVATE_PASSWORD_SENTINEL"));
        assert!(!missing.exists());
    }
    Ok(())
}

#[test]
fn a_misspelled_archive_is_not_created_and_emits_no_report() -> Test {
    let _serial = serial();
    let missing = path("PRIVATE_MISSING_ARCHIVE_SENTINEL");
    let receipt = prepare(
        request()?,
        Vec::new(),
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    let output = run(&args(&missing, &receipt))?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8(output.stderr)?.contains("PRIVATE_MISSING_ARCHIVE_SENTINEL"));
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn cold_inspection_reports_exact_acknowledgement_and_native_verified_originals() -> Test {
    let _serial = serial();
    let (root, receipt) = setup("cold-originals", 2, ReplayTermination::RequestedStop, true)?;
    let report = report(run(&args(&root, &receipt))?)?;
    assert_eq!(
        text(&report, "schema")?,
        "fss.local_replay_operator_report.v1"
    );
    assert_eq!(text(&report, "command")?, "inspect-replay");
    assert_eq!(
        text(&report, "replay_receipt_root")?,
        receipt.root().to_text()
    );
    assert_eq!(
        text(&report, "replay_request")?,
        receipt.request().digest().to_text()
    );
    assert_eq!(
        text(&report, "anchor")?,
        receipt.scope().recording.anchor.to_text()
    );
    assert_eq!(
        text(&report, "receive_clock")?,
        receipt.scope().recording.receive_clock.to_text()
    );
    assert_eq!(
        text(&report, "decode_clock")?,
        receipt.request().decode_clock().to_text()
    );
    assert_eq!(
        text(&report, "requested_range")?,
        "clock=20261105T010000Z-20261105T010500Z"
    );
    assert_eq!(
        text(&report, "acknowledged_range")?,
        "clock=20261105T010100Z-20261105T010400Z"
    );
    assert_eq!(field(&report, "play_cseq")?.integer(), Some(7));
    assert_eq!(field(&report, "durable_windows")?.integer(), Some(2));
    assert_eq!(
        field(&report, "publication_complete")?.boolean(),
        Some(true)
    );
    assert_eq!(text(&report, "termination")?, "requested_stop");
    assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
    assert_eq!(text(&report, "frame_capture_time")?, "unknown");
    assert_eq!(
        field(&report, "source_bytes_emitted")?.boolean(),
        Some(false)
    );
    assert_eq!(field(&report, "operation_complete")?.boolean(), Some(true));
    let windows = field(&report, "windows")?.array().ok_or("window list")?;
    assert_eq!(windows.len(), receipt.windows().len());
    let publisher = LocalRootPublisher::open(&root, limits())?;
    for (ordinal, (window, original)) in windows.iter().zip(receipt.windows()).enumerate() {
        assert_eq!(field(window, "ordinal")?.integer(), Some(ordinal as i128));
        assert_eq!(text(window, "root")?, original.root().to_text());
        assert_eq!(text(window, "slot")?, original.slot().as_str());
        assert_eq!(
            field(window, "whole_window_bytes")?.integer(),
            Some(original.byte_len() as i128)
        );
        let recording = load_recording(
            &publisher,
            original.slot(),
            original.root(),
            receipt.request().scope(),
            &NeverCancel,
        )?;
        assert_eq!(
            recording.children().map(|(_, digest, _)| digest),
            original.original_leaf_digests()
        );
        assert_eq!(
            recording.summary().decode_interval,
            original.decode_interval()
        );
    }
    assert_eq!(
        publisher.spool().read(receipt.root())?,
        receipt.manifest().canonical_bytes()
    );
    Ok(())
}

#[test]
fn hevc_cold_inspection_uses_the_pinned_codec_and_refuses_avc_substitution() -> Test {
    let _serial = serial();
    let root = path("hevc-native-originals");
    let template = request()?;
    let request = ReplayRequest::new_hevc(
        hevc_recording_support::scope()?,
        template.route(),
        template.window(),
        template.base_decode_clock(),
    )?;
    let namespace = HevcArchiveNamespace::new(catalog_scope(&request))?;
    let packets = hevc_recording_support::packets()?;
    let original =
        hevc_recording_support::prepare(&packets[..8], &hevc_recording_support::timings(2))?;
    assert_eq!(original.source_only_nals(), 3);
    let slot = namespace.window_slot(0)?;
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    publish_original(&mut publisher, &slot, original.publication_plan())?;
    let receipt = prepare(
        request,
        vec![ReplayWindowProof::from_hevc(slot, &original)?],
        ReplayTermination::RequestedStop,
        true,
    )?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    drop(publisher);
    let report = report(run(&args(&root, &receipt))?)?;
    assert_eq!(text(&report, "codec")?, "hevc");
    assert_eq!(text(&report, "namespace")?, namespace.digest().to_text());
    assert_eq!(
        text(&report, "replay_receipt_slot")?,
        receipt.slot()?.as_str()
    );
    assert_eq!(
        text(&report, "replay_request")?,
        receipt.request().digest().to_text()
    );
    assert_eq!(field(&report, "durable_windows")?.integer(), Some(1));
    assert_eq!(
        field(&report, "original_source_verified")?.boolean(),
        Some(true)
    );
    assert_eq!(text(&report, "frame_capture_time")?, "unknown");
    assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
    let mut wrong = args(&root, &receipt);
    change(&mut wrong, "--codec", Some("avc"))?;
    let output = run(&wrong)?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn foreign_receipt_request_authority_and_decode_pins_emit_no_partial_report() -> Test {
    let _serial = serial();
    let (root, receipt) = setup("wrong-pins", 1, ReplayTermination::Budget, true)?;
    let wrong = ContentDigest::sha256(b"different independent pin").to_text();
    for key in [
        "--expected-replay-root",
        "--expected-replay-request",
        "--anchor",
        "--receive-clock",
        "--decode-clock",
    ] {
        let mut args = args(&root, &receipt);
        change(&mut args, key, Some(&wrong))?;
        let output = run(&args)?;
        assert_eq!(
            output.status.code(),
            Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
        );
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn locked_owner_and_exhausted_inventory_budget_refuse_without_success_output() -> Test {
    let _serial = serial();
    let (root, receipt) = setup(
        "owner-and-budget",
        2,
        ReplayTermination::RequestedStop,
        true,
    )?;
    let publisher = LocalRootPublisher::open(&root, limits())?;
    let locked = run(&args(&root, &receipt))?;
    assert_eq!(
        locked.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(locked.stdout.is_empty());
    drop(publisher);
    let mut args = args(&root, &receipt);
    change(&mut args, "--max-objects", Some("1"))?;
    let exhausted = run(&args)?;
    assert_eq!(
        exhausted.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(exhausted.stdout.is_empty());
    Ok(())
}

#[test]
fn a_tombstoned_original_source_cannot_be_presented_as_verified_replay() -> Test {
    let _serial = serial();
    let (root, receipt) = setup(
        "tombstoned-source",
        1,
        ReplayTermination::RequestedStop,
        true,
    )?;
    let source = receipt.windows()[0].original_leaf_digests()[0];
    let witness_bytes = b"authorized deletion fixture witness";
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let witness = publisher.stage_object(witness_bytes)?;
    drop(publisher);
    // Bring in a durable, owner-produced tombstone while the original owner is closed.
    let donor_root = path("tombstone-donor");
    let mut donor = LocalRootPublisher::open(&donor_root, limits())?;
    assert_eq!(donor.stage_object(witness_bytes)?, witness);
    donor.record_tombstone(TombstoneRecord::new(
        ObjectId::parse("object:archive-replay-process-fixture")?,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        Some(witness),
        source,
    )?)?;
    drop(donor);
    for entry in std::fs::read_dir(donor_root.join(LOCAL_TOMBSTONES_DIR))? {
        let entry = entry?;
        std::fs::copy(
            entry.path(),
            root.join(LOCAL_TOMBSTONES_DIR).join(entry.file_name()),
        )?;
    }
    let output = run(&args(&root, &receipt))?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn an_accepted_empty_attempt_reports_zero_media_and_preserves_failed_termination() -> Test {
    let _serial = serial();
    let (root, receipt) = setup(
        "empty-attempt",
        0,
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    let report = report(run(&args(&root, &receipt))?)?;
    assert_eq!(field(&report, "durable_windows")?.integer(), Some(0));
    assert!(
        field(&report, "windows")?
            .array()
            .ok_or("window list")?
            .is_empty()
    );
    assert_eq!(text(&report, "termination")?, "protocol_failure");
    assert_eq!(
        field(&report, "publication_complete")?.boolean(),
        Some(false)
    );
    assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
    assert_eq!(text(&report, "frame_capture_time")?, "unknown");
    Ok(())
}
