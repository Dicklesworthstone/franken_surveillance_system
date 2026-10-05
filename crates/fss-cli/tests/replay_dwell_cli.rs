#![forbid(unsafe_code)]
//! Actual binary, committed native producer and retained source; no mocked replay result.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, EventId, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::long_dwell_replay::DwellReplayPins;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:replay-dwell-cli";
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-replay-dwell-cli-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:replay-dwell-cli".into(), operation_id: OperationId::parse("operation:replay-dwell-cli")?,
        principal: "principal:fixture".into(), capabilities: vec!["ADP-REPLAY-001".into()], deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
struct Fixture { root: PathBuf, event: EventId, _directory: Directory }
impl Fixture {
    fn new(label: &str, frames: usize, screened: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("operator's deployment");
        let input = directory.0.join("source.mjpeg");
        let config = JpegConfig { quality: 90, subsampling: Subsampling::Grayscale, restart_interval: 0, custom_markers: Vec::new() };
        let mut bytes = Vec::new();
        for index in 0..frames {
            let mut pixels = vec![40_u8 + (index % 2) as u8 * 8; 48 * 32];
            if index >= 3 { for y in 8..24 { for x in 8..24 { pixels[y * 48 + x] = 220; } } }
            bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
        }
        fs::write(&input, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard(); limits.max_segments = frames + 1; limits.chunk_bytes = 4096;
        let identity = FileIngestAdapter::ingest(FileIngestRequest::new(&input, SensorId::parse("sensor:replay-dwell-cli")?, StreamId::parse("stream:replay-dwell-cli")?)
            .with_limits(limits).with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)), &cx, &mut deployment)?.import_identity;
        let plan = WatchPlan {
            import_identity: identity, interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0, segment_count: frames,
            zones: vec![WatchZone { zone_id: "porch".into(), x: 0, y: 0, width: 32, height: 32 }],
            detector: WatchDetectorConfig::default(), tracker: WatchTrackerConfig::default(),
        };
        let rule = DwellPolicy { minimum_duration_ns: 500_000_000, maximum_sample_gap_ns: 100_000_000, minimum_observations: 3 };
        let run = if screened { LongDwellReport::analyze_screened } else { LongDwellReport::analyze };
        let mut report = run(&deployment, &plan, rule, WatchOptions::default(), &LongDwellLimits::default(), &cx)?;
        assert_eq!(report.candidates().len(), 1);
        let candidate = &report.candidates()[0];
        let event = candidate.event().event_id.clone();
        let approval = candidate.proposal_digest();
        assert_eq!(report.publish(&mut deployment, &std::collections::BTreeSet::from([approval]), &cx)?, 1);
        drop(deployment); cx.drain_and_finalize(); fs::remove_file(input)?;
        Ok(Self { root, event, _directory: directory })
    }
    fn args(&self, action: &str) -> Vec<OsString> {
        vec![action.into(), "--root".into(), self.root.as_os_str().to_owned(), "--site".into(), SITE.into(), "--event-id".into(), self.event.as_str().into()]
    }
    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((fs::read(self.root.join("ledger/journal.fssj"))?, fs::read(self.root.join("effects/journal.fssj"))?))
    }
    fn pins(&self) -> Test<DwellReplayPins> {
        let inspected = good(run(&self.args("inspect"))?)?;
        Ok(DwellReplayPins {
            event_revision: ContentDigest::parse(&field(&inspected, "event_revision_digest")?)?,
            analysis_root: ContentDigest::parse(&field(&inspected, "analysis_root")?)?,
        })
    }
    fn verify(&self, pins: DwellReplayPins) -> Vec<OsString> {
        let mut args = self.args("verify");
        args.extend(["--expected-event-revision".into(), pins.event_revision.to_text().into(),
            "--expected-analysis-root".into(), pins.analysis_root.to_text().into(), "--execute-perception".into(), "yes".into()]);
        args
    }
}
fn run(args: &[OsString]) -> Test<Output> { Ok(Command::new(env!("CARGO_BIN_EXE_fss-replay-dwell")).args(args).output()?) }
fn good(output: Output) -> Test<String> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with('{') && text.ends_with("}\n"));
    Ok(text)
}
fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success()); assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains(reason), "{}", String::from_utf8_lossy(&output.stderr));
}
fn field(text: &str, key: &str) -> Test<String> {
    // Synthetic digest-valued fields only, never general JSON or escaped shell text.
    let marker = format!("\"{key}\":\"");
    let value = text.split_once(&marker).ok_or("field missing")?.1.split_once('"').ok_or("field unterminated")?.0;
    ContentDigest::parse(value)?;
    Ok(value.to_owned())
}

#[test]
fn inspection_is_not_replay_and_native_verification_is_repeatable_without_the_input_file() -> Test {
    let f = Fixture::new("cold", 300, false)?;
    let before = f.snapshot()?;
    let inspected = good(run(&f.args("inspect"))?)?;
    assert!(inspected.contains("\"native_replayed\":false"));
    assert!(inspected.contains("\"frames_replayed\":null"));
    assert!(inspected.contains("\"segment_count\":300"));
    assert!(inspected.contains("--execute-perception yes"));
    assert!(inspected.contains("operator"));
    let pins = f.pins()?;
    for _ in 0..2 {
        let verified = good(run(&f.verify(pins))?)?;
        assert!(verified.contains("\"status\":\"native_replay_matched\""));
        assert!(verified.contains("\"frames_replayed\":300"));
        assert!(verified.contains("\"physical_truth_verified\":false"));
        assert!(verified.contains("\"persistent_verification_record_written\":false"));
        assert_eq!(field(&verified, "analysis_root")?, pins.analysis_root.to_text());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn screened_execution_is_reconstructed_from_custody_and_cannot_be_overridden() -> Test {
    let f = Fixture::new("screened", 40, true)?;
    let pins = f.pins()?;
    let before = f.snapshot()?;
    let verified = good(run(&f.verify(pins))?)?;
    assert!(verified.contains("\"screening_policy\":\"conservative-v1\""));
    assert!(verified.contains("\"health_certified\":false"));
    let mut args = f.verify(pins); args.extend(["--sensor-health".into(), "none".into()]);
    refuses(run(&args)?, "inapplicable");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn stale_selection_and_missing_execution_acknowledgement_never_emit_success() -> Test {
    let f = Fixture::new("pins", 40, false)?;
    let pins = f.pins()?;
    let before = f.snapshot()?;
    for bad in [DwellReplayPins { event_revision: ContentDigest::sha256(b"wrong event"), ..pins },
        DwellReplayPins { analysis_root: ContentDigest::sha256(b"wrong analysis"), ..pins }] {
        refuses(run(&f.verify(bad))?, "dwell_replay_selection_changed");
    }
    let mut no_ack = f.verify(pins); no_ack.truncate(no_ack.len() - 2);
    refuses(run(&no_ack)?, "execute-perception");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn missing_deployments_and_malformed_requests_do_not_create_a_layout() -> Test {
    let directory = Directory::new("parse")?;
    let root = directory.0.join("does-not-exist");
    let base: Vec<OsString> = vec!["inspect".into(), "--root".into(), root.as_os_str().to_owned(), "--site".into(), SITE.into(), "--event-id".into(), "event:missing".into()];
    refuses(run(&base)?, "ERR-CLI");
    assert!(!root.exists());
    for extra in [vec!["--max-metadata-bytes", "0"], vec!["--max-report-bytes", "18446744073709551616"],
        vec!["--site", "site:duplicate"], vec!["--execute-perception", "yes"], vec!["--max-report-bytes"]] {
        let mut args = base.clone(); args.extend(extra.into_iter().map(OsString::from));
        assert!(!run(&args)?.status.success());
        assert!(!root.exists());
    }
    Ok(())
}

#[test]
fn whole_scan_and_output_bounds_never_leave_a_partial_json_verification() -> Test {
    let f = Fixture::new("budgets", 40, false)?;
    let pins = f.pins()?;
    let before = f.snapshot()?;
    for option in ["--source-read-bytes", "--pixel-budget", "--assignment-work", "--trace-bytes", "--decode-work", "--max-report-bytes"] {
        let mut args = f.verify(pins); args.extend([option.into(), "1".into()]);
        let result = run(&args)?;
        assert!(!result.status.success()); assert!(result.stdout.is_empty());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn privacy_changes_after_inspection_cannot_replay_the_old_unmasked_lineage() -> Test {
    let f = Fixture::new("privacy", 40, false)?;
    let pins = f.pins()?;
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let mask = PrivacyMaskPolicy::new(SensorId::parse("sensor:replay-dwell-cli")?, [48, 32], &[[40, 0, 8, 32]])?;
    let approval = preview_mask(&deployment, &mask)?.approval;
    declare_mask(&mut deployment, &mask, approval, &cx)?;
    drop(deployment); cx.drain_and_finalize();
    let before = f.snapshot()?;
    refuses(run(&f.verify(pins))?, "dwell_replay_privacy_changed");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
