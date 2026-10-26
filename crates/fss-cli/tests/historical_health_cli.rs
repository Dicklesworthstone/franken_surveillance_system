#![forbid(unsafe_code)]
//! Historical health retention through the real CLI over original-file-free recordings.
//! Frozen synthetic scenes prove recovery and authority boundaries, not physical tamper.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::long_watch::{LongWatchLimits, LongWatchReport};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchOptions, WatchPlan, WatchReport, WatchTrackerConfig,
    WatchZone,
};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:stream-health-cli";
const FRAMES: usize = 160;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-health-cli-{label}-{}-{attempt}",
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
        trace_id: "trace:stream-health-cli-fixture".into(),
        operation_id: OperationId::parse("operation:stream-health-cli-fixture")?,
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
    import: ContentDigest,
    source_chunk: PathBuf,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, appearance: Option<usize>) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("operator's $recording deployment");
        let input = directory.0.join("original.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let background = vec![40_u8; 48 * 32];
        let mut pixels = background.clone();
        for y in 8..24 {
            for x in 8..24 {
                pixels[y * 48 + x] = 220;
            }
        }
        let quiet = encode_jpeg(48, 32, &background, &config)?;
        let occupied = encode_jpeg(48, 32, &pixels, &config)?;
        let mut bytes = Vec::new();
        for frame in 0..FRAMES {
            bytes.extend_from_slice(if appearance.is_some_and(|first| frame >= first) {
                &occupied
            } else {
                &quiet
            });
        }
        fs::write(&input, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:stream-health")?,
            StreamId::parse("stream:stream-health")?,
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
        Ok(Self {
            root,
            import,
            source_chunk,
            _directory: directory,
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

    fn watch(&self) -> Vec<OsString> {
        let mut args = self.base("watch");
        args.extend([
            "--import-id".into(),
            self.import.to_text().into(),
            "--interpretation".into(),
            "gray".into(),
            "--zone".into(),
            "porch:0,0,48,32".into(),
            "--stream-watch".into(),
            "--sensor-health".into(),
            "conservative-v1".into(),
        ]);
        args
    }

    fn read(&self, digest: &str) -> Vec<OsString> {
        let mut args = vec!["health".into()];
        args.extend(self.base("read"));
        args.extend(["--diagnostic-digest".into(), digest.into()]);
        args
    }

    fn verify(&self, digest: &str, provenance: &str) -> Vec<OsString> {
        let mut args = self.read(digest);
        args[1] = "verify".into();
        args.extend([
            "--expected-provenance-root".into(),
            provenance.into(),
            "--execute-perception".into(),
            "yes".into(),
        ]);
        args
    }

    fn retain(&self) -> Test<Value> {
        let mut args = self.watch();
        let preview = good(run(&args)?)?;
        let approval = field(member(&preview, "historical_health")?, "approval_digest")?;
        args.extend(["--retain-health".into(), approval.into()]);
        good(run(&args)?)
    }

    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }

    fn assert_health_is_historical_only(&self) -> Test {
        let cx = context(&self.root)?;
        let deployment = ReferenceDeployment::reopen(&self.root, SITE, &cx)?;
        let mut families = BTreeMap::new();
        for revision in deployment.ledger().current().objects.values() {
            *families.entry(revision.family.as_str()).or_insert(0_usize) += 1;
        }
        assert_eq!(families.get("historical_sensor_health"), Some(&1));
        for forbidden in [
            "event_revision",
            "coverage_witness",
            "sensor_tamper_status",
            "alert_effect_outcome",
        ] {
            assert!(!families.contains_key(forbidden), "unexpected {forbidden}");
        }
        assert_eq!(deployment.alert_provider().message_count(), 0);
        drop(deployment);
        cx.drain_and_finalize();
        Ok(())
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
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing field {key}").into())
}
fn field(value: &Value, key: &str) -> Test<String> {
    member(value, key)?
        .text()
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string field {key}").into())
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing option")?;
    *args.get_mut(index + 1).ok_or("missing option value")? = value.into();
    Ok(())
}

// Decode only the emitted command's literal single-quote/backslash grammar. Execute argv
// against the known binary, never through a shell or an operator-supplied executable.
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
                '\\' => {
                    escaped = true;
                }
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
        return Err("unexpected verification executable".into());
    }
    args.remove(0);
    Ok(args)
}

#[test]
fn frozen_recording_without_an_entry_is_retained_and_replayed_after_cold_restart() -> Test {
    let f = Fixture::new("no-entry", None)?;
    let before = f.journals()?;
    let mut args = f.watch();
    let preview = good(run(&args)?)?;
    assert_eq!(
        member(&preview, "frames_decoded")?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(member(&preview, "candidate_count")?.integer(), Some(0));
    assert_eq!(member(&preview, "publication_blocked")?, &Value::Bool(true));
    assert_eq!(
        member(&preview, "absence_certifiable")?,
        &Value::Bool(false)
    );
    let planned = member(&preview, "historical_health")?;
    assert_eq!(field(planned, "status")?, "prepared");
    let digest = field(planned, "record_digest")?;
    let approval = field(planned, "approval_digest")?;
    assert_ne!(
        digest, approval,
        "retained record identity is not approval authority"
    );
    assert_eq!(f.journals()?, before);

    args.extend(["--retain-health".into(), approval.into()]);
    let retained = good(run(&args)?)?;
    let record = member(&retained, "historical_health")?;
    assert_eq!(field(record, "status")?, "retained");
    assert_eq!(field(record, "record_digest")?, digest);
    let provenance = field(record, "provenance_root")?;
    let after = f.journals()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1, "health retention changed effect history");
    f.assert_health_is_historical_only()?;

    let retry = good(run(&args)?)?;
    assert_eq!(
        field(member(&retry, "historical_health")?, "status")?,
        "already_retained"
    );
    assert_eq!(f.journals()?, after);
    let inspected = good(run(&f.read(&digest))?)?;
    assert_eq!(field(&inspected, "status")?, "inspected_not_replayed");
    assert_eq!(member(&inspected, "native_replayed")?, &Value::Bool(false));
    assert_eq!(
        member(&inspected, "source_and_trace_verified")?,
        &Value::Bool(false)
    );
    assert_eq!(
        member(&inspected, "current_privacy_revalidated")?,
        &Value::Bool(false)
    );
    assert_eq!(member(&inspected, "frames_replayed")?, &Value::Null);
    assert_eq!(field(&inspected, "record_digest")?, digest);
    assert_eq!(field(&inspected, "provenance_root")?, provenance);
    let verified = good(run(&f.verify(&digest, &provenance))?)?;
    assert_eq!(field(&verified, "status")?, "native_replay_matched");
    assert_eq!(member(&verified, "native_replayed")?, &Value::Bool(true));
    assert_eq!(
        member(&verified, "source_and_trace_verified")?,
        &Value::Bool(true)
    );
    assert_eq!(
        member(&verified, "current_privacy_revalidated")?,
        &Value::Bool(true)
    );
    assert_eq!(
        member(&verified, "frames_replayed")?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(member(&verified, "record")?, member(&inspected, "record")?);
    for report in [&inspected, &verified] {
        for field in [
            "current_health_proved",
            "tamper_proved",
            "absence_certifiable",
            "event_verified",
            "effects_authorized",
        ] {
            assert_eq!(member(report, field)?, &Value::Bool(false), "{field}");
        }
    }
    assert_eq!(f.journals()?, after);
    Ok(())
}

#[test]
fn later_retained_health_withdraws_prior_coverage_and_certified_silence_through_real_cli() -> Test {
    let f = Fixture::new("coverage-withdrawal", None)?;
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    // An older unscreened analysis treated the frozen source as a quiet recorded window.
    // Retaining a later screened diagnostic must change read-side decisions without rewriting it.
    let plan = WatchPlan {
        import_identity: f.import,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment: FRAMES - 32,
        segment_count: 32,
        zones: vec![WatchZone {
            zone_id: "porch".into(),
            x: 0,
            y: 0,
            width: 48,
            height: 32,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    let mut report = WatchReport::analyze(&deployment, &plan, &WatchLimits::default(), &cx)?;
    assert!(report.candidates().is_empty());
    assert!(report.coverage().witnesses().next().is_some());
    report.retain_coverage(&mut deployment, report.coverage_approval(), &cx)?;
    drop(deployment);
    cx.drain_and_finalize();

    let agent = |verb: &str, extra: &[&str]| -> Test<Value> {
        good(
            Command::new(env!("CARGO_BIN_EXE_fss"))
                .args([verb, "--json", "--root"])
                .arg(&f.root)
                .args(["--view", "brief"])
                .args(extra)
                .output()?,
        )
    };
    let before = f.journals()?;
    let orientation = agent("orient", &[])?;
    let frame = member(member(&orientation, "payload")?, "situationFrame")?;
    let coverage = member(frame, "coverage")?;
    assert_eq!(
        member(coverage, "absenceClaimsCertified")?,
        &Value::Bool(true)
    );
    assert_eq!(field(coverage, "status")?, "complete_for_declared_domain");
    let since = member(&orientation, "proofPointers")?
        .array()
        .ok_or("proof pointers")?
        .iter()
        .filter_map(Value::text)
        .find(|value| value.starts_with("anchor:"))
        .ok_or("orientation anchor")?
        .to_owned();
    let quiet = agent("follow", &["--since", &since])?;
    assert_ne!(
        member(member(&quiet, "payload")?, "silenceCertificate")?,
        &Value::Null
    );
    assert_eq!(
        f.journals()?,
        before,
        "orientation and follow must be read-only"
    );

    let retained = f.retain()?;
    let diagnostic = field(member(&retained, "historical_health")?, "record_digest")?;
    let after_retention = f.journals()?;
    assert_ne!(before.0, after_retention.0);
    assert_eq!(
        before.1, after_retention.1,
        "diagnostics cannot dispatch effects"
    );

    let orientation = agent("orient", &[])?;
    let frame = member(member(&orientation, "payload")?, "situationFrame")?;
    let coverage = member(frame, "coverage")?;
    assert_eq!(field(coverage, "status")?, "not_observable");
    assert_eq!(
        member(coverage, "absenceClaimsCertified")?,
        &Value::Bool(false)
    );
    assert!(
        member(coverage, "witnessIds")?
            .array()
            .ok_or("witness ids")?
            .is_empty()
    );
    assert_ne!(field(&orientation, "completeness")?, "complete");
    let zone = member(frame, "knowledgeCells")?
        .array()
        .ok_or("knowledge cells")?
        .iter()
        .find(|cell| {
            field(cell, "cellId")
                .is_ok_and(|id| id.starts_with("claim:coverage:") && id.ends_with(":zone:porch"))
        })
        .ok_or("porch coverage cell")?;
    assert!(
        member(zone, "contradictingEvidence")?
            .array()
            .ok_or("contradicting evidence")?
            .iter()
            .any(|value| value.text() == Some(diagnostic.as_str()))
    );

    let changed = agent("follow", &["--since", &since])?;
    let payload = member(&changed, "payload")?;
    assert_eq!(member(payload, "silenceCertificate")?, &Value::Null);
    let classes = member(payload, "classes")?.array().ok_or("delta classes")?;
    assert!(
        classes
            .iter()
            .any(|value| value.text() == Some("coverage_loss"))
    );
    assert!(
        classes
            .iter()
            .any(|value| value.text() == Some("sensor_health"))
    );
    assert_eq!(
        f.journals()?,
        after_retention,
        "cold reads must preserve retained history"
    );
    assert_eq!(
        agent("orient", &[])?,
        orientation,
        "identical evidence must render deterministically"
    );
    Ok(())
}

#[test]
fn health_approval_is_independent_of_blocked_event_approval_and_exact_scan_recipe() -> Test {
    let f = Fixture::new("approval", Some(140))?;
    let before = f.journals()?;
    let base = f.watch();
    let preview = good(run(&base)?)?;
    let candidates = member(&preview, "candidates")?
        .array()
        .ok_or("candidates")?;
    assert_eq!(candidates.len(), 1);
    let event_approval = field(&candidates[0], "proposal_digest")?;
    let approval = field(member(&preview, "historical_health")?, "approval_digest")?;
    assert_ne!(approval, event_approval);
    let mut blocked = base.clone();
    blocked.extend(["--approve".into(), event_approval.clone().into()]);
    refuses(
        run(&blocked)?,
        "sensor-health findings or incomplete screening",
    );
    for incorrect in [
        event_approval,
        ContentDigest::sha256(b"wrong approval").to_text(),
    ] {
        let mut args = base.clone();
        args.extend(["--retain-health".into(), incorrect.into()]);
        refuses(run(&args)?, "ERR-");
        assert_eq!(f.journals()?, before);
    }
    let mut changed = base.clone();
    set(&mut changed, "--zone", "renamed:0,0,48,32")?;
    changed.extend(["--retain-health".into(), approval.clone().into()]);
    refuses(run(&changed)?, "ERR-");
    assert_eq!(f.journals()?, before);
    let mut changed_budget = base.clone();
    changed_budget.extend([
        "--stream-pixel-budget".into(),
        "2147483648".into(),
        "--retain-health".into(),
        approval.clone().into(),
    ]);
    refuses(run(&changed_budget)?, "ERR-");
    assert_eq!(f.journals()?, before);
    let mut exact = base;
    exact.extend(["--retain-health".into(), approval.into()]);
    let retained = good(run(&exact)?)?;
    assert_eq!(
        member(&retained, "publication_blocked")?,
        &Value::Bool(true)
    );
    assert_eq!(
        member(&retained, "absence_certifiable")?,
        &Value::Bool(false)
    );
    assert_eq!(f.journals()?.1, before.1);
    f.assert_health_is_historical_only()?;
    Ok(())
}

#[test]
fn stream_dwell_diagnostics_do_not_depend_on_a_publishable_dwell_episode() -> Test {
    let f = Fixture::new("dwell", None)?;
    let before = f.journals()?;
    let mut args = f.watch();
    let flag = args
        .iter()
        .position(|arg| arg == "--stream-watch")
        .ok_or("whole-recording mode")?;
    args[flag] = "--stream-dwell".into();
    args.extend([
        "--dwell-for-ns".into(),
        "1000000000".into(),
        "--dwell-max-gap-ns".into(),
        "100000000".into(),
    ]);
    let preview = good(run(&args)?)?;
    assert_eq!(field(&preview, "format")?, "fss.long_dwell_report.v1");
    assert_eq!(
        member(member(&preview, "sensor_health")?, "publication_blocked")?,
        &Value::Bool(true)
    );
    assert_eq!(
        member(&preview, "absence_certifiable")?,
        &Value::Bool(false)
    );
    let approval = field(member(&preview, "historical_health")?, "approval_digest")?;
    assert_eq!(f.journals()?, before);
    args.extend(["--retain-health".into(), approval.into()]);
    let retained = good(run(&args)?)?;
    let health = member(&retained, "historical_health")?;
    let digest = field(health, "record_digest")?;
    let provenance = field(health, "provenance_root")?;
    assert_eq!(field(health, "status")?, "retained");
    let after = f.journals()?;
    assert_ne!(before.0, after.0);
    assert_eq!(before.1, after.1);
    let verified = good(run(&f.verify(&digest, &provenance))?)?;
    assert_eq!(field(&verified, "status")?, "native_replay_matched");
    assert_eq!(member(&verified, "native_replayed")?, &Value::Bool(true));
    assert_eq!(f.journals()?, after);
    f.assert_health_is_historical_only()?;
    Ok(())
}

#[test]
fn library_default_recipe_replays_through_the_exact_cold_cli_verification_command() -> Test {
    let f = Fixture::new("library-defaults", None)?;
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let plan = WatchPlan {
        import_identity: f.import,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0,
        segment_count: FRAMES,
        zones: vec![WatchZone {
            zone_id: "porch".into(),
            x: 0,
            y: 0,
            width: 48,
            height: 32,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    // The library defaults retain wider unused AVC/HEVC numeric ceilings than the
    // watch CLI's common pixel option. They are still part of the exact stored recipe.
    let limits = LongWatchLimits::default();
    let report = LongWatchReport::analyze_screened(
        &deployment,
        &plan,
        WatchOptions::default(),
        &limits,
        &cx,
    )?;
    let diagnostic = report
        .health_diagnostic()
        .ok_or("missing native diagnostic")?;
    let retention = diagnostic.retain(&mut deployment, diagnostic.approval_digest(), &cx)?;
    drop(deployment);
    cx.drain_and_finalize();
    let before = f.journals()?;
    let mut read = f.read(&retention.record_digest.to_text());
    read.extend(["--principal".into(), "principal:fixture".into()]);
    let inspected = good(run(&read)?)?;
    let bounds = member(&inspected, "bounds")?;
    assert!(
        member(bounds, "h264_max_macroblocks")?
            .integer()
            .is_some_and(|bound| bound >= i128::from(limits.decode.h264_limits.max_macroblocks))
    );
    assert!(
        member(bounds, "h265_max_luma_samples")?
            .integer()
            .is_some_and(|bound| bound >= i128::from(limits.decode.h265_limits.max_luma_samples))
    );
    let verified = good(run(&verification_args(&inspected)?)?)?;
    assert_eq!(field(&verified, "status")?, "native_replay_matched");
    assert_eq!(
        member(&verified, "frames_replayed")?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(member(&verified, "record")?, member(&inspected, "record")?);
    assert_eq!(f.journals()?, before);
    f.assert_health_is_historical_only()?;
    Ok(())
}

#[test]
fn cold_selection_budgets_and_damaged_source_refuse_without_changing_history() -> Test {
    let f = Fixture::new("cold-boundaries", None)?;
    let retained = f.retain()?;
    let health = member(&retained, "historical_health")?;
    let digest = field(health, "record_digest")?;
    let provenance = field(health, "provenance_root")?;
    let before = f.journals()?;
    for action in ["read", "verify"] {
        for key in ["--max-metadata-bytes", "--max-report-bytes"] {
            let mut args = if action == "read" {
                f.read(&digest)
            } else {
                f.verify(&digest, &provenance)
            };
            args.extend([key.into(), "1".into()]);
            refuses(run(&args)?, "ERR-");
            assert_eq!(f.journals()?, before);
        }
    }
    let wrong = ContentDigest::sha256(b"not the selected provenance").to_text();
    refuses(run(&f.verify(&digest, &wrong))?, "ERR-");
    for key in [
        "--source-read-bytes",
        "--pixel-budget",
        "--assignment-work",
        "--trace-bytes",
        "--decode-work",
        "--max-dimension",
        "--max-pixels",
        "--max-segment-bytes",
    ] {
        let mut args = f.verify(&digest, &provenance);
        args.extend([key.into(), "1".into()]);
        refuses(run(&args)?, "ERR-");
        assert_eq!(f.journals()?, before);
    }
    fs::write(&f.source_chunk, b"damaged retained original")?;
    refuses(run(&f.verify(&digest, &provenance))?, "ERR-");
    assert_eq!(f.journals()?, before);
    Ok(())
}

#[test]
fn missing_screening_mixed_approvals_and_unapproved_execution_fail_before_deployment_io() -> Test {
    let directory = Directory::new("parse")?;
    let root = directory.0.join("must-not-exist");
    let digest = ContentDigest::sha256(b"parse-only fixture").to_text();
    let base: Vec<OsString> = vec![
        "watch".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--import-id".into(),
        digest.clone().into(),
        "--interpretation".into(),
        "gray".into(),
        "--zone".into(),
        "porch:0,0,48,32".into(),
    ];
    for extra in [
        vec!["--retain-health", &digest],
        vec!["--stream-watch", "--retain-health", &digest],
        vec![
            "--sensor-health",
            "conservative-v1",
            "--retain-health",
            &digest,
        ],
        vec![
            "--stream-watch",
            "--sensor-health",
            "conservative-v1",
            "--retain-health",
            &digest,
            "--approve",
            &digest,
        ],
        vec![
            "--stream-watch",
            "--sensor-health",
            "conservative-v1",
            "--retain-health",
            &digest,
            "--retain-health",
            &digest,
        ],
    ] {
        let mut args = base.clone();
        args.extend(extra.into_iter().map(OsString::from));
        refuses(run(&args)?, "ERR-");
        assert!(!root.exists());
    }
    let mut verify: Vec<OsString> = vec![
        "health".into(),
        "verify".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--diagnostic-digest".into(),
        digest.clone().into(),
        "--expected-provenance-root".into(),
        digest.into(),
    ];
    refuses(run(&verify)?, "execute-perception");
    assert!(!root.exists());
    verify.extend(["--execute-perception".into(), "no".into()]);
    refuses(run(&verify)?, "execute-perception");
    assert!(!root.exists());
    Ok(())
}
