#![forbid(unsafe_code)]
//! Real producer and CLI over retained native recordings, with the input files removed.
//! Synthetic scenes prove reproducibility and refusal boundaries, not field detection quality.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, EventId, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-event-replay-cli";
const FRAMES: usize = 160;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-long-replay-cli-{label}-{}-{attempt}",
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
        trace_id: "trace:long-event-replay-cli-fixture".into(),
        operation_id: OperationId::parse("operation:long-event-replay-cli-fixture")?,
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
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn scene(mirrored: bool) -> Test<Vec<u8>> {
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
    let occupied = encode_jpeg(48, 32, &pixels, &config)?;
    let mut bytes = Vec::new();
    for frame in 0..FRAMES {
        bytes.extend_from_slice(if frame >= 140 { &occupied } else { &background });
    }
    Ok(bytes)
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    imports: Vec<ContentDigest>,
    source_chunk: PathBuf,
}
impl Fixture {
    fn new(label: &str, cameras: usize) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("operator's $data deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut imports = Vec::new();
        let mut source_chunk = None;
        for (index, name) in ["east", "west"].into_iter().take(cameras).enumerate() {
            let input = directory.0.join(format!("source-{name}.mjpeg"));
            fs::write(&input, scene(index == 1)?)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = FRAMES + 1;
            limits.chunk_bytes = 4096;
            let request = FileIngestRequest::new(
                &input,
                SensorId::parse(format!("sensor:long-replay-{name}"))?,
                StreamId::parse(format!("stream:long-replay-{name}"))?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(1_000_000_000), 1_000_000, 10.0)?);
            let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
            let retained = RetainedFileImport::open(
                &deployment, import, RetainedReadLimits::default(), &cx,
            )?;
            source_chunk.get_or_insert_with(|| {
                deployment.publisher().spool().object_path(retained.manifest().ordered_chunks[0])
            });
            imports.push(import);
            fs::remove_file(input)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            imports,
            source_chunk: source_chunk.ok_or("fixture needs a source")?,
        })
    }
    fn base(&self, action: &str) -> Vec<OsString> {
        vec![
            action.into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
        ]
    }
    fn publish(&self, shared_causes: bool) -> Test<EventId> {
        let mut args = if self.imports.len() == 1 {
            let mut args = self.base("watch");
            args.extend([
                "--import-id".into(), self.imports[0].to_text().into(),
                "--interpretation".into(), "gray".into(),
                "--zone".into(), "porch:0,0,48,32".into(),
                "--stream-watch".into(),
            ]);
            args
        } else {
            let mut args = self.base("corroborate");
            args.extend([
                "--camera".into(), format!("east:{}", self.imports[0]).into(),
                "--camera".into(), format!("west:{}", self.imports[1]).into(),
                "--ground".into(), "east:1,0,0,0,1,0,0,0,1".into(),
                "--ground".into(), "west:-1,0,48,0,1,0,0,0,1".into(),
                "--zone".into(), "door:8,16,16,16".into(),
                "--interpretation".into(), "gray".into(),
                "--time-gate-ns".into(), "250000000".into(),
                "--distance-gate".into(), "4".into(),
                "--stream-corroborate".into(),
            ]);
            if shared_causes {
                args.extend(["--failure-domain".into(), "power:shared=east,west".into()]);
            }
            args
        };
        let before = self.snapshot()?;
        let preview = good(run(&args)?)?;
        let candidates = member(&preview, "candidates")?.array().ok_or("candidate array")?;
        assert_eq!(candidates.len(), 1, "{preview:?}");
        if self.imports.len() == 1 {
            assert!(member(&candidates[0], "entry_position")?.integer().is_some_and(|n| n >= 140));
        }
        let event = EventId::parse(field(&candidates[0], "event_id")?)?;
        let approval = field(&candidates[0], "proposal_digest")?;
        assert_eq!(self.snapshot()?, before);
        args.extend(["--approve".into(), approval.into()]);
        let published = good(run(&args)?)?;
        let first = member(&published, "candidates")?.array().ok_or("candidate array")?;
        assert_eq!(field(&first[0], "status")?, "published");
        assert_eq!(self.snapshot()?.1, before.1);
        Ok(event)
    }
    fn read(&self, event: &EventId) -> Vec<OsString> {
        let mut args = self.base("read");
        args.extend([
            "--event-id".into(), event.as_str().into(),
            "--principal".into(), "principal:cold-reader".into(),
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
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event")).args(args).output()?)
}
fn good(output: Output) -> Test<Value> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}
fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal emitted a success prefix");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn member<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value.object().and_then(|value| value.get(key))
        .ok_or_else(|| format!("missing field {key}").into())
}
fn field(value: &Value, key: &str) -> Test<String> {
    member(value, key)?.text().map(str::to_owned)
        .ok_or_else(|| format!("missing string field {key}").into())
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let index = args.iter().position(|arg| arg == key).ok_or("missing argument")?;
    *args.get_mut(index + 1).ok_or("missing value")? = value.into();
    Ok(())
}

// Interpret only the exact command's single-quote/backslash argument grammar. The test executes
// the actual binary with argv, never a shell, expansion, or an operator-supplied executable.
fn verification_args(inspection: &Value) -> Test<Vec<OsString>> {
    let command = field(inspection, "verification_command")?;
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
            if ch == '\'' { quoted = false; } else { word.push(ch); }
        } else {
            match ch {
                '\'' => { quoted = true; started = true; }
                '\\' => { escaped = true; }
                '$' | '\u{0060}' | '"' => return Err("unquoted command expansion".into()),
                ch if ch.is_whitespace() => {
                    if started {
                        args.push(OsString::from(std::mem::take(&mut word)));
                        started = false;
                    }
                }
                ch => { word.push(ch); started = true; }
            }
        }
    }
    if quoted || escaped { return Err("unfinished quoted command".into()); }
    if started { args.push(word.into()); }
    if args.first().is_none_or(|arg| arg != "fss-event") {
        return Err("unexpected command executable".into());
    }
    args.remove(0);
    Ok(args)
}

#[test]
fn whole_recording_watch_cold_read_and_emitted_native_verify_command_preserve_authority() -> Test {
    let f = Fixture::new("watch", 1)?;
    let event = f.publish(false)?;
    let before = f.snapshot()?;
    let inspection = good(run(&f.read(&event))?)?;
    assert_eq!(field(&inspection, "status")?, "inspected_not_replayed");
    assert_eq!(member(&inspection, "native_replayed")?, &Value::Bool(false));
    assert_eq!(member(&inspection, "frames_replayed")?, &Value::Null);
    assert_eq!(member(&inspection, "analysis_roots")?.array().ok_or("roots")?.len(), 1);
    assert_eq!(f.snapshot()?, before);
    let args = verification_args(&inspection)?;
    for _ in 0..2 {
        let verified = good(run(&args)?)?;
        assert_eq!(field(&verified, "status")?, "native_replay_matched");
        assert_eq!(member(&verified, "frames_replayed")?.integer(), Some(FRAMES as i128));
        assert_eq!(member(&verified, "event")?, member(&inspection, "event")?);
        assert_eq!(member(&verified, "native_replayed")?, &Value::Bool(true));
        assert_eq!(member(&verified, "physical_truth_verified")?, &Value::Bool(false));
        assert_eq!(member(&verified, "persistent_verification_record_written")?, &Value::Bool(false));
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn both_corroboration_scans_replay_with_shared_cause_state_and_distinct_provenance_pin() -> Test {
    let f = Fixture::new("corroboration", 2)?;
    let event = f.publish(true)?;
    let before = f.snapshot()?;
    let inspection = good(run(&f.read(&event))?)?;
    assert_eq!(field(member(&inspection, "event")?, "state")?, "witnessed");
    assert_eq!(member(&inspection, "analysis_roots")?.array().ok_or("roots")?.len(), 2);
    assert_ne!(field(&inspection, "provenance_root")?, field(&inspection, "decision_fingerprint")?);
    let verified = good(run(&verification_args(&inspection)?)?)?;
    assert_eq!(member(&verified, "frames_replayed")?.integer(), Some((2 * FRAMES) as i128));
    assert_eq!(member(&verified, "event")?, member(&inspection, "event")?);
    assert_eq!(member(&verified, "alert_authorized")?, &Value::Bool(false));
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn stale_selection_missing_execution_and_work_bounds_never_emit_success_or_modify_journals() -> Test {
    let f = Fixture::new("pins", 1)?;
    let event = f.publish(false)?;
    let inspection = good(run(&f.read(&event))?)?;
    let before = f.snapshot()?;
    let base = verification_args(&inspection)?;
    for key in ["--expected-event-revision", "--expected-provenance-root"] {
        let mut args = base.clone();
        set(&mut args, key, &ContentDigest::sha256(b"wrong selection").to_text())?;
        refuses(run(&args)?, "ERR-");
        assert_eq!(f.snapshot()?, before);
    }
    let mut args = base.clone();
    let index = args.iter().position(|arg| arg == "--execute-perception").ok_or("execution option")?;
    args.drain(index..index + 2);
    refuses(run(&args)?, "execute-perception");
    for key in [
        "--source-read-bytes", "--pixel-budget", "--assignment-work", "--trace-bytes",
        "--decode-work", "--max-metadata-bytes", "--max-report-bytes",
    ] {
        let mut args = base.clone();
        set(&mut args, key, "1")?;
        refuses(run(&args)?, "ERR-");
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn changed_privacy_and_damaged_retained_originals_refuse_native_verification() -> Test {
    for privacy in [true, false] {
        let f = Fixture::new(if privacy { "privacy" } else { "damage" }, 1)?;
        let event = f.publish(false)?;
        let inspection = good(run(&f.read(&event))?)?;
        let args = verification_args(&inspection)?;
        if privacy {
            let cx = context(&f.root)?;
            let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
            let mask = PrivacyMaskPolicy::new(
                SensorId::parse("sensor:long-replay-east")?, [48, 32], &[[40, 0, 8, 32]],
            )?;
            let approval = preview_mask(&deployment, &mask)?.approval;
            declare_mask(&mut deployment, &mask, approval, &cx)?;
            drop(deployment);
            cx.drain_and_finalize();
        } else {
            let mut bytes = fs::read(&f.source_chunk)?;
            *bytes.last_mut().ok_or("empty retained source chunk")? ^= 0x80;
            fs::write(&f.source_chunk, bytes)?;
        }
        let before = f.snapshot()?;
        refuses(run(&args)?, "ERR-");
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn malformed_missing_and_wrong_site_requests_do_not_create_or_rebind_deployments() -> Test {
    let directory = Directory::new("missing")?;
    let root = directory.0.join("absent");
    let base: Vec<OsString> = vec![
        "read".into(), "--root".into(), root.as_os_str().to_owned(),
        "--site".into(), SITE.into(),
        "--event-id".into(), format!("event:long-watch:{}", "1".repeat(64)).into(),
    ];
    refuses(run(&base)?, "ERR-CLI");
    assert!(!root.exists());
    for extra in [
        vec!["--max-metadata-bytes", "0"], vec!["--approve", "sha256:wrong"],
        vec!["--site", "site:duplicate"], vec!["--execute-perception", "yes"],
        vec!["--max-report-bytes"],
    ] {
        let mut args = base.clone();
        args.extend(extra.into_iter().map(OsString::from));
        refuses(run(&args)?, "ERR-CLI");
        assert!(!root.exists());
    }
    let f = Fixture::new("wrong-site", 1)?;
    let event = f.publish(false)?;
    let before = f.snapshot()?;
    let mut args = f.read(&event);
    set(&mut args, "--site", "site:wrong")?;
    refuses(run(&args)?, "site does not match");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn optional_exports_are_complete_create_only_and_outside_the_deployment() -> Test {
    let f = Fixture::new("exports", 1)?;
    let event = f.publish(false)?;
    let before = f.snapshot()?;
    let report_path = f.directory.0.join("inspection.json");
    let event_path = f.directory.0.join("event.json");
    let mut args = f.read(&event);
    args.extend([
        "--report-out".into(), report_path.as_os_str().to_owned(),
        "--event-out".into(), event_path.as_os_str().to_owned(),
    ]);
    let inspected = good(run(&args)?)?;
    assert_eq!(parse(&fs::read_to_string(&report_path)?)?, inspected);
    assert_eq!(parse(&fs::read_to_string(&event_path)?)?, *member(&inspected, "event")?);
    refuses(run(&args)?, "ERR-CLI");
    let mut forbidden = f.read(&event);
    forbidden.extend([
        "--event-out".into(), f.root.join("forbidden-event.json").into_os_string(),
    ]);
    refuses(run(&forbidden)?, "outside the deployment");
    assert!(!f.root.join("forbidden-event.json").exists());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
