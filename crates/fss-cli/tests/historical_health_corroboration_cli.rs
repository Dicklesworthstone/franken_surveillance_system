#![forbid(unsafe_code)]
//! Independent per-camera historical diagnostic retention through the real corroboration CLI.
//! Synthetic quiet recordings exercise custody and authority boundaries, not field accuracy.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:historical-health-corroboration-cli";
const FRAMES: usize = 24;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-health-corroboration-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:health-corroboration-fixture".into(),
        operation_id: OperationId::parse("operation:health-corroboration-fixture")?,
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
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Fixture {
    root: PathBuf,
    imports: [ContentDigest; 2],
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        Self::with_refused_east(label, false)
    }
    fn with_refused_east(label: &str, all_refused: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("owner's $two-camera archive");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let first = encode_jpeg(32, 32, &[80; 32 * 32], &config)?;
        let second = encode_jpeg(32, 32, &[88; 32 * 32], &config)?;
        let mut refused = first.clone();
        let sof = refused
            .windows(2)
            .position(|pair| pair == [0xff, 0xc0])
            .ok_or("JPEG SOF0")?;
        refused[sof + 1] = 0xc2;
        let mut imports = Vec::new();
        for (camera, name) in ["east", "west"].into_iter().enumerate() {
            let input = directory.0.join(format!("original-{name}.mjpeg"));
            let mut bytes = Vec::new();
            for frame in 0..FRAMES {
                // East freezes. West changes by less than the foreground threshold and never
                // meets the exact-repetition diagnostic, so both have no entry or pair.
                bytes.extend_from_slice(if camera == 0 && all_refused {
                    &refused
                } else if camera == 0 || frame % 2 == 0 {
                    &first
                } else {
                    &second
                });
            }
            fs::write(&input, bytes)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = FRAMES + 1;
            limits.chunk_bytes = 4096;
            let import = FileIngestAdapter::ingest(
                FileIngestRequest::new(
                    &input,
                    SensorId::parse(format!("sensor:health-corroboration-{name}"))?,
                    StreamId::parse(format!("stream:health-corroboration-{name}"))?,
                )
                .with_limits(limits)
                .with_capture_hint(CaptureHint::new(TimestampNs(1_000_000_000), 0, 10.0)?)
                .with_receive_time(TimestampNs(1_000_000_000_000)),
                &cx,
                &mut deployment,
            )?
            .import_identity;
            imports.push(import);
            fs::remove_file(input)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            root,
            imports: imports.try_into().map_err(|_| "two imports required")?,
            _directory: directory,
        })
    }
    fn args(&self) -> Vec<OsString> {
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
            "west:1,0,0,0,1,0,0,0,1".into(),
            "--zone".into(),
            "porch:0,0,32,32".into(),
            "--interpretation".into(),
            "gray".into(),
            "--time-gate-ns".into(),
            "250000000".into(),
            "--distance-gate".into(),
            "4".into(),
            "--stream-corroborate".into(),
            "--sensor-health".into(),
            "conservative-v1".into(),
        ]
    }
    fn watch(&self, camera: usize) -> Vec<OsString> {
        vec![
            "watch".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--import-id".into(),
            self.imports[camera].to_text().into(),
            "--interpretation".into(),
            "gray".into(),
            "--zone".into(),
            "porch:0,0,32,32".into(),
            "--stream-watch".into(),
            "--sensor-health".into(),
            "conservative-v1".into(),
        ]
    }
    fn read(&self, digest: &str) -> Vec<OsString> {
        vec![
            "health".into(),
            "read".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--diagnostic-digest".into(),
            digest.into(),
        ]
    }
    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
    fn diagnostic_digests(&self) -> Test<BTreeSet<ContentDigest>> {
        let cx = context(&self.root)?;
        let deployment = ReferenceDeployment::reopen(&self.root, SITE, &cx)?;
        let mut diagnostics = BTreeSet::new();
        for revision in deployment.ledger().current().objects.values() {
            if revision.family == "historical_sensor_health" {
                diagnostics.insert(revision.payload_digest);
            }
            assert!(!matches!(
                revision.family.as_str(),
                "event_revision"
                    | "coverage_witness"
                    | "sensor_tamper_status"
                    | "alert_effect_outcome"
            ));
        }
        assert_eq!(deployment.effects().operations().count(), 0);
        assert_eq!(deployment.alert_provider().message_count(), 0);
        drop(deployment);
        cx.drain_and_finalize();
        Ok(diagnostics)
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
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}
fn refuses(output: Output) {
    assert!(
        !output.status.success(),
        "unexpected successful authority request"
    );
    assert!(
        output.stdout.is_empty(),
        "refusal emitted a successful JSON prefix"
    );
    assert!(
        !output.stderr.is_empty(),
        "refusal needs a typed explanation"
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
fn camera<'a>(report: &'a Value, name: &str) -> Test<&'a Value> {
    array(report, "historical_health")?
        .iter()
        .find(|row| {
            row.object()
                .and_then(|fields| fields.get("camera"))
                .and_then(Value::text)
                == Some(name)
        })
        .ok_or_else(|| format!("missing historical diagnostic for {name}").into())
}

// Decode only the emitted literal single-quote/backslash command grammar and execute the known
// binary directly. Shell expansion and an operator-supplied executable are never involved.
fn command_args(row: &Value, key: &str) -> Test<Vec<OsString>> {
    let command = text(row, key)?;
    let mut args = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut started = false;
    for ch in command.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            started = true;
        } else if quoted {
            if ch == '\'' {
                quoted = false;
            } else {
                word.push(ch);
            }
        } else {
            match ch {
                '\'' => {
                    quoted = true;
                    started = true;
                }
                '\\' => escaped = true,
                '$' | '\u{0060}' | '"' => return Err("unquoted command expansion".into()),
                ch if ch.is_whitespace() => {
                    if started {
                        args.push(OsString::from(std::mem::take(&mut word)));
                        started = false;
                    }
                }
                ch => {
                    word.push(ch);
                    started = true;
                }
            }
        }
    }
    if quoted || escaped {
        return Err("unfinished command quoting".into());
    }
    if started {
        args.push(word.into());
    }
    if args.first().is_none_or(|arg| arg != "fss-event") {
        return Err("unexpected executable".into());
    }
    let _ = args.remove(0);
    Ok(args)
}

#[test]
fn degraded_camera_with_no_pairs_retains_independently_and_replays_observed_recipe_cold() -> Test {
    let f = Fixture::new("empty-pairs")?;
    let before = f.snapshot()?;
    let preview = good(run(&f.args())?)?;
    assert_eq!(count(&preview, "candidate_count")?, 0);
    assert_eq!(count(&preview, "entry_count")?, 0);
    assert_eq!(member(&preview, "publication_blocked")?, &Value::Bool(true));
    assert_eq!(array(&preview, "historical_health")?.len(), 2);
    let east = camera(&preview, "east")?;
    let west = camera(&preview, "west")?;
    assert_eq!(text(east, "status")?, "prepared");
    assert_eq!(text(west, "status")?, "prepared");
    assert_eq!(
        f.snapshot()?,
        before,
        "both native previews remain read-only"
    );
    let digest = text(east, "record_digest")?;
    let root = text(east, "provenance_root")?;
    let args = command_args(east, "retain_command")?;
    let retained = good(run(&args)?)?;
    assert_eq!(text(camera(&retained, "east")?, "status")?, "retained");
    assert_eq!(text(camera(&retained, "west")?, "status")?, "prepared");
    assert_eq!(
        f.diagnostic_digests()?,
        BTreeSet::from([ContentDigest::parse(&digest)?])
    );
    assert_eq!(
        f.snapshot()?.1,
        before.1,
        "retention creates no alert effects"
    );
    let inspected = good(run(&f.read(&digest))?)?;
    assert_eq!(text(&inspected, "status")?, "inspected_not_replayed");
    assert_eq!(member(&inspected, "native_replayed")?, &Value::Bool(false));
    assert_eq!(
        text(member(&inspected, "record")?, "sensor_id")?,
        "sensor:health-corroboration-east"
    );
    assert_eq!(
        text(member(&inspected, "record")?, "status")?,
        "suspected_degradation"
    );
    let stable = f.snapshot()?;
    let verified = good(run(&command_args(&inspected, "verification_command")?)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(member(&verified, "native_replayed")?, &Value::Bool(true));
    assert_eq!(text(&verified, "provenance_root")?, root);
    assert_eq!(count(&verified, "frames_replayed")?, FRAMES as i128);
    assert_eq!(f.snapshot()?, stable, "native replay is read-only");
    let repeated = good(run(&args)?)?;
    assert_eq!(
        text(camera(&repeated, "east")?, "status")?,
        "already_retained"
    );
    assert_eq!(text(camera(&repeated, "west")?, "status")?, "prepared");
    assert_eq!(
        f.snapshot()?,
        stable,
        "exact per-camera retry appends nothing"
    );
    Ok(())
}

#[test]
fn another_scan_recipe_or_receipt_digest_cannot_authorize_a_camera_diagnostic() -> Test {
    let f = Fixture::new("exact-approval")?;
    let preview = good(run(&f.args())?)?;
    let east = camera(&preview, "east")?;
    let west = camera(&preview, "west")?;
    let east_approval = text(east, "approval_digest")?;
    let west_receipt = text(west, "record_digest")?;
    let watch = good(run(&f.watch(0))?)?;
    let watch_approval = text(member(&watch, "historical_health")?, "approval_digest")?;
    let before = f.snapshot()?;
    for wrong in [watch_approval, west_receipt] {
        let mut args = f.args();
        args.extend(["--retain-health".into(), wrong.into()]);
        refuses(run(&args)?);
        assert_eq!(
            f.snapshot()?,
            before,
            "a digest in another role grants no diagnostic authority"
        );
    }
    let mut without_stream = f.args();
    without_stream.retain(|value| value != "--stream-corroborate");
    without_stream.extend(["--retain-health".into(), east_approval.clone().into()]);
    refuses(run(&without_stream)?);
    assert_eq!(
        f.snapshot()?,
        before,
        "diagnostic approval cannot enter the short corroboration path"
    );
    let mut without_health = f.args();
    let health_index = without_health
        .iter()
        .position(|value| value == "--sensor-health")
        .ok_or("fixture health screen flag")?;
    let _ = without_health.drain(health_index..health_index + 2);
    without_health.extend(["--retain-health".into(), east_approval.clone().into()]);
    refuses(run(&without_health)?);
    assert_eq!(
        f.snapshot()?,
        before,
        "diagnostic approval requires the explicit conservative screen"
    );
    let mut changed = f.args();
    changed.extend(["--stream-read-bytes".into(), "268435456".into()]);
    let revised = good(run(&changed)?)?;
    assert_ne!(
        text(camera(&revised, "east")?, "approval_digest")?,
        east_approval
    );
    changed.extend(["--retain-health".into(), east_approval.clone().into()]);
    refuses(run(&changed)?);
    assert_eq!(
        f.snapshot()?,
        before,
        "stored aggregate ceilings are part of the exact approval"
    );
    let mut mixed = f.args();
    mixed.extend([
        "--retain-health".into(),
        east_approval.into(),
        "--approve".into(),
        ContentDigest::sha256(b"event approval").to_text().into(),
    ]);
    refuses(run(&mixed)?);
    assert_eq!(
        f.snapshot()?,
        before,
        "mixed effect/event approvals are rejected before retention"
    );
    assert!(f.diagnostic_digests()?.is_empty());
    Ok(())
}

#[test]
fn later_clear_camera_receipt_does_not_replace_or_clear_retained_degraded_camera() -> Test {
    let f = Fixture::new("two-independent")?;
    let preview = good(run(&f.args())?)?;
    let east = camera(&preview, "east")?;
    let west = camera(&preview, "west")?;
    let east_digest = text(east, "record_digest")?;
    let west_digest = text(west, "record_digest")?;
    let east_args = command_args(east, "retain_command")?;
    let west_args = command_args(west, "retain_command")?;
    let first = good(run(&east_args)?)?;
    assert_eq!(text(camera(&first, "west")?, "status")?, "prepared");
    let effects = f.snapshot()?.1;
    let second = good(run(&west_args)?)?;
    assert_eq!(
        text(camera(&second, "east")?, "status")?,
        "already_retained"
    );
    assert_eq!(text(camera(&second, "west")?, "status")?, "retained");
    assert_eq!(count(&second, "candidate_count")?, 0);
    assert_eq!(member(&second, "publication_blocked")?, &Value::Bool(true));
    assert_eq!(
        f.diagnostic_digests()?,
        BTreeSet::from([
            ContentDigest::parse(&east_digest)?,
            ContentDigest::parse(&west_digest)?
        ])
    );
    let east_read = good(run(&f.read(&east_digest))?)?;
    let west_read = good(run(&f.read(&west_digest))?)?;
    assert_eq!(
        text(member(&east_read, "record")?, "status")?,
        "suspected_degradation"
    );
    assert_eq!(
        text(member(&west_read, "record")?, "status")?,
        "no_findings"
    );
    assert_eq!(
        member(member(&west_read, "record")?, "current_health_proved")?,
        &Value::Bool(false)
    );
    assert_eq!(f.snapshot()?.1, effects);
    let stable = f.snapshot()?;
    let repeated = good(run(&west_args)?)?;
    assert_eq!(
        text(camera(&repeated, "west")?, "status")?,
        "already_retained"
    );
    assert_eq!(f.snapshot()?, stable);
    Ok(())
}

#[test]
fn entirely_refused_camera_retains_only_requested_hints_and_reproduces_zero_screened_frames() -> Test
{
    let f = Fixture::with_refused_east("all-refused-camera", true)?;
    let mut args = f.args();
    args.push("--tolerate-decode-refusals".into());
    let before = f.snapshot()?;
    let preview = good(run(&args)?)?;
    assert_eq!(count(&preview, "entry_count")?, 0);
    assert_eq!(count(&preview, "candidate_count")?, 0);
    assert_eq!(member(&preview, "publication_blocked")?, &Value::Bool(true));
    let east_camera = array(&preview, "cameras")?
        .iter()
        .find(|row| {
            row.object()
                .and_then(|fields| fields.get("camera"))
                .and_then(Value::text)
                == Some("east")
        })
        .ok_or("missing east camera projection")?;
    assert_eq!(count(east_camera, "frames_decoded")?, 0);
    assert_eq!(
        text(east_camera, "capture_scope_semantics")?,
        "requested_source_capsule_hints_when_no_frames_screened"
    );
    let east = camera(&preview, "east")?;
    let west = camera(&preview, "west")?;
    let receipt = member(east, "receipt")?;
    assert_eq!(text(receipt, "status")?, "incomplete");
    assert_eq!(
        text(receipt, "capture_scope_semantics")?,
        "requested_source_capsule_hints_when_no_frames_screened"
    );
    assert_eq!(member(receipt, "time_reliable")?, &Value::Bool(false));
    assert_eq!(
        count(member(receipt, "sensor_health")?, "frames_screened")?,
        0
    );
    assert_eq!(text(member(west, "receipt")?, "status")?, "no_findings");
    assert_eq!(
        f.snapshot()?,
        before,
        "entirely refused camera preview still writes nothing"
    );
    let digest = text(east, "record_digest")?;
    let retain_args = command_args(east, "retain_command")?;
    assert!(
        retain_args
            .iter()
            .any(|value| value == "--tolerate-decode-refusals")
    );
    let retained = good(run(&retain_args)?)?;
    assert_eq!(text(camera(&retained, "east")?, "status")?, "retained");
    assert_eq!(text(camera(&retained, "west")?, "status")?, "prepared");
    assert_eq!(
        f.diagnostic_digests()?,
        BTreeSet::from([ContentDigest::parse(&digest)?])
    );
    assert_eq!(f.snapshot()?.1, before.1);
    let inspected = good(run(&f.read(&digest))?)?;
    let stable = f.snapshot()?;
    let verified = good(run(&command_args(&inspected, "verification_command")?)?)?;
    assert_eq!(text(&verified, "status")?, "native_replay_matched");
    assert_eq!(count(&verified, "frames_replayed")?, 0);
    assert_eq!(text(member(&verified, "record")?, "status")?, "incomplete");
    assert_eq!(
        member(member(&verified, "record")?, "time_reliable")?,
        &Value::Bool(false)
    );
    assert_eq!(
        f.snapshot()?,
        stable,
        "native reproduction of refusal grants no frame evidence"
    );
    let repeated = good(run(&retain_args)?)?;
    assert_eq!(
        text(camera(&repeated, "east")?, "status")?,
        "already_retained"
    );
    assert_eq!(f.snapshot()?, stable);
    Ok(())
}
