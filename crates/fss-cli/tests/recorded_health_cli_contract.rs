#![forbid(unsafe_code)]
//! Real-process entry-watch and corroboration health screening over retained synthetic sources.
//! These fixtures prove conservative admission, custody and approval wiring, not camera quality.

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
const SITE: &str = "site:recorded-health-cli";
const FRAMES: usize = 32;
const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-recorded-health-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Scene {
    Changing,
    Frozen,
    LateFreeze,
    Dark,
    Bright,
    Contrast,
    DecodeGap,
}

fn scene(kind: Scene) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for index in 0..FRAMES {
        let background = if matches!(kind, Scene::Frozen)
            || (matches!(kind, Scene::LateFreeze) && index >= 15)
        {
            40
        } else {
            40 + (index % 2) as u8 * 8
        };
        let mut pixels = vec![background; (WIDTH * HEIGHT) as usize];
        if index >= 3 {
            for y in 8..24 {
                for x in 8..24 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        if index >= 15 {
            match kind {
                Scene::Dark => pixels.fill(0),
                Scene::Bright => pixels.fill(255),
                Scene::Contrast => pixels.fill(100),
                _ => {}
            }
        }
        let mut frame = encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?;
        if matches!(kind, Scene::DecodeGap) && index == 16 {
            let sof = frame
                .windows(2)
                .position(|window| window == [0xff, 0xc0])
                .ok_or("SOF0 missing")?;
            frame[sof + 1] = 0xc2;
        }
        bytes.extend(frame);
    }
    Ok(bytes)
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    imports: Vec<ContentDigest>,
}
impl Fixture {
    fn new(label: &str, scenes: &[Scene]) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("owner's recording archive");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:recorded-health-cli".into(),
            operation_id: OperationId::parse("operation:recorded-health-cli")?,
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
        for (index, kind) in scenes.iter().enumerate() {
            let input = directory.0.join(format!("camera-{index}.mjpeg"));
            fs::write(&input, scene(*kind)?)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = FRAMES + 1;
            limits.chunk_bytes = 4096;
            imports.push(
                FileIngestAdapter::ingest(
                    FileIngestRequest::new(
                        &input,
                        SensorId::parse(format!("sensor:health-{index}"))?,
                        StreamId::parse(format!("stream:health-{index}"))?,
                    )
                    .with_limits(limits)
                    .with_capture_hint(CaptureHint::new(TimestampNs(1_000_000_000), 0, 10.0)?)
                    .with_receive_time(TimestampNs(1_000_000_000_000)),
                    &cx,
                    &mut deployment,
                )?
                .import_identity,
            );
            // Every later invocation must reconstruct from retained custody, including cold retry.
            fs::remove_file(input)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            imports,
        })
    }

    fn watch(&self, screened: bool) -> Vec<OsString> {
        let mut args = base("watch", &self.root);
        args.extend(["--import-id".into(), self.imports[0].to_text().into()]);
        screen_option(&mut args, screened);
        args
    }

    fn corroborate(&self, screened: bool) -> Vec<OsString> {
        let mut args = base("corroborate", &self.root);
        for (index, import) in self.imports.iter().enumerate() {
            args.extend([
                "--camera".into(),
                format!("camera-{index}:{import}").into(),
                "--ground".into(),
                format!("camera-{index}:1,0,0,0,1,0,0,0,1").into(),
            ]);
        }
        args.extend(["--time-gate-ns", "250000000", "--distance-gate", "16"].map(OsString::from));
        screen_option(&mut args, screened);
        args
    }

    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

fn base(command: &str, root: &Path) -> Vec<OsString> {
    vec![
        command.into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--interpretation".into(),
        "gray".into(),
        "--zone".into(),
        "entry:0,0,32,48".into(),
        "--zone".into(),
        "quiet:64,0,32,48".into(),
    ]
}

fn screen_option(args: &mut Vec<OsString>, enabled: bool) {
    if enabled {
        args.extend(["--sensor-health", "conservative-v1"].map(OsString::from));
    }
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(args)
        .output()?)
}

fn good(args: &[OsString]) -> Test<(String, Value)> {
    let output = run(args)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with('{') && text.ends_with("}\n"));
    let json = parse(&text)?;
    Ok((text, json))
}

fn refuses(args: &[OsString], reason: &str) -> Test {
    let output = run(args)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing field {key}").into())
}

fn number(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?.integer().ok_or("not an integer".into())
}

fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?.text().ok_or("not a string".into())
}

fn items<'a>(value: &'a Value, key: &str) -> Test<&'a [Value]> {
    field(value, key)?.array().ok_or("not an array".into())
}

fn coverage_records(report: &Value) -> Test<&[Value]> {
    items(field(report, "coverage")?, "records")
}

fn proposal(report: &Value) -> Test<&str> {
    text(
        items(report, "candidates")?.first().ok_or("no candidate")?,
        "proposal_digest",
    )
}

/// A retained witness may cover a clear interval, but no screened suspect position.
fn check_witness_exclusions(record: &Value) -> Test {
    let health = field(record, "sensor_health")?;
    let affected: Vec<i128> = items(health, "affected_segments")?
        .iter()
        .chain(items(health, "withdrawn_track_segments")?.iter())
        .map(|value| value.integer().ok_or("excluded segment is not an integer"))
        .collect::<Result<_, _>>()?;
    for zone in items(record, "zones")? {
        for witness in items(zone, "witnesses")? {
            let start = number(witness, "first_segment")?;
            let end = number(witness, "last_segment")?;
            assert!(
                affected
                    .iter()
                    .all(|segment| !(start..=end).contains(segment))
            );
        }
    }
    Ok(())
}

#[test]
fn frozen_entry_is_diagnostic_and_cannot_reuse_an_unscreened_approval() -> Test {
    let fixture = Fixture::new("frozen", &[Scene::Frozen])?;
    let before = fixture.snapshot()?;
    let (plain_bytes, plain) = good(&fixture.watch(false))?;
    assert_eq!(number(&plain, "candidate_count")?, 1);
    assert!(!plain_bytes.contains("\"sensor_health\":"));
    assert_eq!(good(&fixture.watch(false))?.0, plain_bytes);
    let (screened_bytes, screened) = good(&fixture.watch(true))?;
    assert_eq!(number(&screened, "candidate_count")?, 0);
    assert!(screened_bytes.contains("exact_frame_repetition"));
    assert!(screened_bytes.contains("sensor_health_degraded"));
    let health = field(&screened, "sensor_health")?;
    assert_eq!(text(health, "status")?, "suspected_degradation");
    assert_eq!(field(health, "health_certified")?.boolean(), Some(false));
    assert_eq!(number(health, "frames_screened")?, FRAMES as i128);
    assert_eq!(items(health, "observations")?.len(), FRAMES);
    assert_eq!(number(field(&screened, "coverage")?, "witness_count")?, 0);
    check_witness_exclusions(&coverage_records(&screened)?[0])?;
    assert_eq!(fixture.snapshot()?, before);
    let mut approve = fixture.watch(true);
    approve.extend(["--approve".into(), proposal(&plain)?.into()]);
    refuses(&approve, "ERR-WATCH-APPROVAL-STALE-001")?;
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn late_freeze_withdraws_the_earlier_entry_without_replacing_it_with_absence() -> Test {
    let fixture = Fixture::new("late-freeze", &[Scene::LateFreeze])?;
    let before = fixture.snapshot()?;
    // Preserve the stationary foreground track until the late freeze is observed.
    let mut plain_args = fixture.watch(false);
    plain_args.extend(["--learning-rate-den", "1024"].map(OsString::from));
    let mut screened_args = fixture.watch(true);
    screened_args.extend(["--learning-rate-den", "1024"].map(OsString::from));
    let (_, plain) = good(&plain_args)?;
    assert_eq!(number(&plain, "candidate_count")?, 1);
    let (bytes, screened) = good(&screened_args)?;
    assert_eq!(number(&screened, "candidate_count")?, 0);
    assert!(bytes.contains("sensor_health_dependent_track"));
    let health = field(&screened, "sensor_health")?;
    let measured = items(health, "affected_segments")?;
    let withdrawn = items(health, "withdrawn_track_segments")?;
    assert!(withdrawn.iter().any(|segment| !measured.contains(segment)));
    check_witness_exclusions(&coverage_records(&screened)?[0])?;
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn persistent_clipping_and_contrast_loss_cannot_supply_absence_witnesses() -> Test {
    for (label, kind, finding) in [
        ("dark", Scene::Dark, "persistent_dark_field"),
        ("bright", Scene::Bright, "persistent_bright_field"),
        ("contrast", Scene::Contrast, "contrast_collapse"),
    ] {
        let fixture = Fixture::new(label, &[kind])?;
        let before = fixture.snapshot()?;
        let (report_bytes, report) = good(&fixture.watch(true))?;
        assert!(report_bytes.contains(finding));
        assert!(report_bytes.contains("sensor_health_degraded"));
        assert_eq!(
            text(field(&report, "sensor_health")?, "status")?,
            "suspected_degradation"
        );
        assert_eq!(
            field(&report, "absence_certifiable")?.boolean(),
            Some(false)
        );
        check_witness_exclusions(&coverage_records(&report)?[0])?;
        assert_eq!(fixture.snapshot()?, before);

        let coverage = field(&report, "coverage")?;
        let mut retain = fixture.watch(true);
        retain.extend([
            "--retain-coverage".into(),
            text(coverage, "approval_digest")?.into(),
        ]);
        let (_, retained) = good(&retain)?;
        assert_eq!(
            text(field(&retained, "coverage")?, "coverage_status")?,
            "retained"
        );
        check_witness_exclusions(&coverage_records(&retained)?[0])?;
        assert_eq!(fixture.snapshot()?.1, before.1);
    }
    Ok(())
}

#[test]
fn clear_screen_approvals_bind_policy_through_publication_reanalysis_and_cold_retry() -> Test {
    let fixture = Fixture::new("clear", &[Scene::Changing])?;
    let before = fixture.snapshot()?;
    let (_, plain) = good(&fixture.watch(false))?;
    let (screened_bytes, screened) = good(&fixture.watch(true))?;
    assert_eq!(
        text(field(&screened, "sensor_health")?, "status")?,
        "clear_screen_not_health_evidence"
    );
    assert_eq!(
        field(field(&screened, "sensor_health")?, "health_certified")?.boolean(),
        Some(false)
    );
    assert_eq!(number(&screened, "candidate_count")?, 1);
    assert!(screened_bytes.contains("--sensor-health conservative-v1"));
    assert_ne!(proposal(&plain)?, proposal(&screened)?);
    for (screen, wrong) in [(true, &plain), (false, &screened)] {
        let mut args = fixture.watch(screen);
        args.extend(["--approve".into(), proposal(wrong)?.into()]);
        refuses(&args, "ERR-WATCH-APPROVAL-STALE-001")?;
    }
    // A wrong coverage approval must refuse before the otherwise valid event is published.
    let mut mixed = fixture.watch(true);
    mixed.extend([
        "--approve".into(),
        proposal(&screened)?.into(),
        "--retain-coverage".into(),
        text(field(&plain, "coverage")?, "approval_digest")?.into(),
    ]);
    refuses(&mixed, "ERR-COVERAGE-APPROVAL-STALE-001")?;
    assert_eq!(fixture.snapshot()?, before);

    let mut approve = fixture.watch(true);
    approve.extend(["--approve".into(), proposal(&screened)?.into()]);
    let (_, published) = good(&approve)?;
    assert_eq!(number(&published, "published_count")?, 1);
    assert_eq!(
        field(&published, "sensor_health")?,
        field(&screened, "sensor_health")?
    );
    let bound = field(&coverage_records(&published)?[0], "sensor_health")?;
    let summary = field(&screened, "sensor_health")?;
    for key in [
        "policy",
        "digest",
        "status",
        "observations",
        "affected_segments",
        "withdrawn_track_segments",
    ] {
        assert_eq!(field(bound, key)?, field(summary, key)?);
    }
    ContentDigest::parse(text(bound, "coverage_receipt_digest")?)?;
    let after = fixture.snapshot()?;
    assert_ne!(before.0, after.0);
    assert_eq!(before.1, after.1);
    let report_path = fixture.directory.0.join("screened-report.json");
    approve.extend(["--report-out".into(), report_path.as_os_str().to_owned()]);
    let (retry_bytes, retry) = good(&approve)?;
    assert_eq!(number(&retry, "already_published_count")?, 1);
    assert_eq!(
        text(&retry, "analysis_digest")?,
        text(&screened, "analysis_digest")?
    );
    assert_eq!(fs::read_to_string(report_path)?, retry_bytes);
    assert_eq!(fixture.snapshot()?, after);
    Ok(())
}

#[test]
fn a_frozen_second_camera_cannot_corroborate_or_cover_its_suspect_interval() -> Test {
    let fixture = Fixture::new("two-camera-freeze", &[Scene::Changing, Scene::Frozen])?;
    let before = fixture.snapshot()?;
    let (_, plain) = good(&fixture.corroborate(false))?;
    assert_eq!(number(&plain, "candidate_count")?, 1);
    let (_, screened) = good(&fixture.corroborate(true))?;
    assert_eq!(number(&screened, "candidate_count")?, 0);
    let cameras = items(&screened, "cameras")?;
    assert_eq!(
        text(field(&cameras[0], "sensor_health")?, "status")?,
        "clear_screen_not_health_evidence"
    );
    assert_eq!(
        text(field(&cameras[1], "sensor_health")?, "status")?,
        "suspected_degradation"
    );
    for record in coverage_records(&screened)? {
        check_witness_exclusions(record)?;
    }
    let mut approve = fixture.corroborate(true);
    approve.extend(["--approve".into(), proposal(&plain)?.into()]);
    refuses(&approve, "ERR-CORROBORATE-APPROVAL-STALE-001")?;
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn two_clear_screens_keep_distinct_provenance_and_explicit_event_approval() -> Test {
    let fixture = Fixture::new("two-camera-clear", &[Scene::Changing, Scene::Changing])?;
    let before = fixture.snapshot()?;
    let (plain_bytes, plain) = good(&fixture.corroborate(false))?;
    assert!(!plain_bytes.contains("\"sensor_health\":"));
    let (preview_bytes, preview) = good(&fixture.corroborate(true))?;
    assert_eq!(number(&preview, "candidate_count")?, 1);
    assert_ne!(proposal(&plain)?, proposal(&preview)?);
    assert!(preview_bytes.contains("--sensor-health conservative-v1"));
    let cameras = items(&preview, "cameras")?;
    for camera in cameras {
        assert_eq!(
            text(field(camera, "sensor_health")?, "status")?,
            "clear_screen_not_health_evidence"
        );
    }
    assert_ne!(
        field(&cameras[0], "sensor_health")?,
        field(&cameras[1], "sensor_health")?
    );
    assert_eq!(fixture.snapshot()?, before);
    let mut args = fixture.corroborate(true);
    args.extend(["--approve".into(), proposal(&preview)?.into()]);
    let (_, published) = good(&args)?;
    assert_eq!(number(&published, "published_count")?, 1);
    for (old, new) in coverage_records(&preview)?
        .iter()
        .zip(coverage_records(&published)?)
    {
        assert_eq!(field(old, "sensor_health")?, field(new, "sensor_health")?);
    }
    let after = fixture.snapshot()?;
    assert_ne!(before.0, after.0);
    assert_eq!(before.1, after.1);
    let (_, repeated) = good(&args)?;
    assert_eq!(number(&repeated, "already_published_count")?, 1);
    assert_eq!(fixture.snapshot()?, after);
    Ok(())
}

#[test]
fn recovery_keeps_a_decode_gap_even_with_a_clear_visual_screen() -> Test {
    let fixture = Fixture::new("decode-gap", &[Scene::DecodeGap])?;
    let before = fixture.snapshot()?;
    let mut args = fixture.watch(true);
    args.push("--tolerate-decode-refusals".into());
    let (bytes, report) = good(&args)?;
    assert_eq!(
        number(field(&report, "sensor_health")?, "frames_screened")?,
        FRAMES as i128 - 1
    );
    assert!(bytes.contains("decode_refused"));
    for zone in items(&coverage_records(&report)?[0], "zones")? {
        for witness in items(zone, "witnesses")? {
            let start = number(witness, "first_segment")?;
            let end = number(witness, "last_segment")?;
            assert!(!(start..=end).contains(&16));
        }
    }
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn invalid_policies_and_duplicate_options_refuse_before_deployment_io() -> Test {
    let directory = Directory::new("argument-errors")?;
    let root = directory.0.join("must-not-exist");
    for command in ["watch", "corroborate"] {
        for (extra, reason) in [
            (
                vec!["--sensor-health", "latest"],
                "requires policy conservative-v1",
            ),
            (vec!["--sensor-health"], "missing value"),
            (
                vec![
                    "--sensor-health",
                    "conservative-v1",
                    "--sensor-health",
                    "conservative-v1",
                ],
                "duplicate --sensor-health",
            ),
        ] {
            let mut args = base(command, &root);
            args.extend(extra.into_iter().map(OsString::from));
            refuses(&args, reason)?;
            assert!(!root.exists());
        }
    }
    Ok(())
}
