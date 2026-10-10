#![forbid(unsafe_code)]
//! Whole-recording two-camera corroboration through native media and the real CLI.
//! Synthetic mirrored views prove composition and authority boundaries, not field accuracy.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:stream-corroborate-cli";
const FRAMES: usize = 300;
const IDENTITY: &str = "east:1,0,0,0,1,0,0,0,1";
const MIRROR: &str = "west:-1,0,48,0,1,0,0,0,1";
const ZONE: &str = "door:8,16,16,16";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-corroborate-cli-{label}-{}-{attempt}",
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

struct Fixture {
    directory: Directory,
    root: PathBuf,
    imports: [ContentDigest; 2],
}
impl Fixture {
    fn mjpeg(
        label: &str,
        frames: usize,
        appearance: Option<usize>,
        known_time: [bool; 2],
    ) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment with spaces");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:stream-corroborate-cli".into(),
            operation_id: OperationId::parse("operation:stream-corroborate-cli")?,
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
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut imports = Vec::new();
        for (camera, name) in ["east", "west"].into_iter().enumerate() {
            let input = directory.0.join(format!("original-{name}.mjpeg"));
            fs::write(&input, scene(frames, appearance, camera == 1)?)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = frames + 1;
            limits.chunk_bytes = 4096;
            let mut request = FileIngestRequest::new(
                &input,
                SensorId::parse(format!("sensor:stream-corroborate-{name}"))?,
                StreamId::parse(format!("stream:stream-corroborate-{name}"))?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000));
            if known_time[camera] {
                request = request.with_capture_hint(CaptureHint::new(
                    TimestampNs(1_000_000_000),
                    1_000_000,
                    10.0,
                )?);
            }
            imports.push(FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity);
            // Every CLI call must reconstruct both sources entirely from retained custody.
            fs::remove_file(input)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        let imports = imports.try_into().map_err(|_| "two imports required")?;
        Ok(Self {
            directory,
            root,
            imports,
        })
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = base(&self.root, self.imports);
        args.push("--stream-corroborate".into());
        args
    }

    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

fn scene(frames: usize, appearance: Option<usize>, mirrored: bool) -> Test<Vec<u8>> {
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
    for frame in 0..frames {
        bytes.extend_from_slice(if appearance.is_some_and(|first| frame >= first) {
            &occupied
        } else {
            &background
        });
    }
    Ok(bytes)
}

fn base(root: &Path, imports: [ContentDigest; 2]) -> Vec<OsString> {
    vec![
        "corroborate".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--camera".into(),
        format!("east:{}", imports[0]).into(),
        "--camera".into(),
        format!("west:{}", imports[1]).into(),
        "--ground".into(),
        IDENTITY.into(),
        "--ground".into(),
        MIRROR.into(),
        "--zone".into(),
        ZONE.into(),
        "--interpretation".into(),
        "gray".into(),
        "--time-gate-ns".into(),
        "250000000".into(),
        "--distance-gate".into(),
        "4".into(),
    ]
}
fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
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
fn digest_field(text: &str, key: &str) -> Test<String> {
    // These fixtures only extract known digest fields, not arbitrary JSON strings.
    let marker = format!("\"{key}\":\"");
    let rest = text.split_once(&marker).ok_or("missing digest field")?.1;
    let value = rest.split_once('"').ok_or("unterminated digest")?.0;
    ContentDigest::parse(value)?;
    Ok(value.to_owned())
}
fn unsigned_fields(text: &str, key: &str) -> Test<Vec<u64>> {
    let marker = format!("\"{key}\":");
    text.split(&marker)
        .skip(1)
        .map(|rest| {
            let value: String = rest.chars().take_while(char::is_ascii_digit).collect();
            Ok(value.parse()?)
        })
        .collect()
}
fn unsigned_field(text: &str, key: &str) -> Test<u64> {
    unsigned_fields(text, key)?
        .into_iter()
        .next()
        .ok_or_else(|| format!("missing numeric field {key}").into())
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let position = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing option")?;
    *args.get_mut(position + 1).ok_or("missing option value")? = value.into();
    Ok(())
}

#[test]
fn late_mirrored_ground_entries_publish_once_from_retained_sources() -> Test {
    let f = Fixture::mjpeg("late", FRAMES, Some(180), [true; 2])?;
    let before = f.snapshot()?;
    let mut args = f.args();
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"format\":\"fss.long_corroboration_report.v1\""));
    assert_eq!(unsigned_fields(&preview, "frames_decoded")?, vec![300, 300]);
    assert_eq!(unsigned_field(&preview, "entry_count")?, 2);
    assert_eq!(unsigned_field(&preview, "candidate_count")?, 1);
    let positions = unsigned_fields(&preview, "entry_position")?;
    assert_eq!(positions.len(), 2);
    assert!(positions.iter().all(|position| *position >= 180));
    assert_eq!(
        preview.matches("\"disposition\":\"corroborated\"").count(),
        2
    );
    for expected in [
        "\"event_state\":\"corroborated\"",
        "\"event_kind\":\"unclassified\"",
        "\"policy_action\":\"prepare_alert\"",
        "\"model_invoked\":false",
        "\"physical_arrival_proved\":false",
        "\"absence_certifiable\":false",
        "\"alert_authorized\":false",
        "event:long-corroborated:",
        "--stream-corroborate",
    ] {
        assert!(preview.contains(expected), "missing {expected}");
    }
    assert!(preview.contains('\''), "rerun must quote deployment paths");
    assert_eq!(f.snapshot()?, before);
    assert_eq!(good(run(&args)?)?, preview);

    args.extend([
        "--approve".into(),
        digest_field(&preview, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    assert!(published.contains("\"status\":\"published\""));
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1, "corroboration must not dispatch effects");

    let output = f.directory.0.join("corroboration report.json");
    args.extend(["--report-out".into(), output.as_os_str().to_owned()]);
    let retry = good(run(&args)?)?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(
        digest_field(&retry, "analysis_digest")?,
        digest_field(&preview, "analysis_digest")?
    );
    assert_eq!(fs::read_to_string(output)?, retry);
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn shared_causes_keep_witnessed_activity_and_require_a_new_exact_approval() -> Test {
    let f = Fixture::mjpeg("shared-causes", FRAMES, Some(180), [true; 2])?;
    let before = f.snapshot()?;
    let undeclared = good(run(&f.args())?)?;
    let old_approval = digest_field(&undeclared, "proposal_digest")?;
    let mut args = f.args();
    args.extend(
        [
            "--failure-domain",
            "power:shared-circuit=east,west",
            "--failure-domain",
            "network:east-lan=east",
            "--failure-domain",
            "network:west-lan=west",
        ]
        .map(OsString::from),
    );
    let preview = good(run(&args)?)?;
    assert_eq!(unsigned_field(&preview, "candidate_count")?, 1);
    assert_eq!(unsigned_field(&preview, "dependency_cluster_count")?, 1);
    assert!(preview.contains("\"event_state\":\"witnessed\""));
    assert!(preview.contains("\"policy_action\":\"hold\""));
    assert!(preview.contains("\"independence_certified\":false"));
    assert!(preview.contains("power:shared-circuit=east,west"));
    assert!(!preview.contains("\"disposition\":\"corroborated\""));
    let approval = digest_field(&preview, "proposal_digest")?;
    assert_ne!(approval, old_approval);
    let mut stale = args.clone();
    stale.extend(["--approve".into(), old_approval.into()]);
    refuses(run(&stale)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, before);

    args.extend(["--approve".into(), approval.into()]);
    let published = good(run(&args)?)?;
    assert!(published.contains("\"status\":\"published\""));
    assert!(published.contains("\"event_state\":\"witnessed\""));
    assert!(published.contains("\"policy_action\":\"hold\""));
    assert!(published.contains("\"alert_authorized\":false"));
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(good(run(&args)?)?.contains("\"status\":\"already_published\""));
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn all_aggregate_limits_refuse_before_export_or_publication() -> Test {
    let f = Fixture::mjpeg("budgets", FRAMES, Some(180), [true; 2])?;
    let before = f.snapshot()?;
    for (index, key) in [
        "--stream-read-bytes",
        "--stream-pixel-budget",
        "--stream-assignment-work",
        "--stream-trace-bytes",
    ]
    .into_iter()
    .enumerate()
    {
        let output = f.directory.0.join(format!("refused-{index}.json"));
        let mut args = f.args();
        args.extend([
            key.into(),
            "1".into(),
            "--report-out".into(),
            output.as_os_str().to_owned(),
        ]);
        refuses(run(&args)?, "ERR-WATCH-LIMIT-001");
        assert!(!output.exists());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn unsupported_options_and_orphan_budgets_refuse_before_deployment_io() -> Test {
    let directory = Directory::new("parse")?;
    let root = directory.0.join("must-not-exist");
    let prefix = base(
        &root,
        [
            ContentDigest::sha256(b"east"),
            ContentDigest::sha256(b"west"),
        ],
    );
    let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    for (extra, reason) in [
        (
            vec!["--stream-corroborate", "--stream-corroborate"],
            "duplicate",
        ),
        (
            vec!["--stream-corroborate", "--stream-watch"],
            "missing value",
        ),
        (
            vec!["--stream-corroborate", "--segment-count", "300"],
            "unknown or inapplicable",
        ),
        (
            vec!["--stream-corroborate", "--retain-coverage", digest],
            "does not admit coverage",
        ),
        (
            vec!["--stream-corroborate", "--visibility-grid", "4"],
            "does not admit coverage",
        ),
        (
            vec![
                "--stream-corroborate",
                "--detector-package",
                "/unused/model",
            ],
            "does not admit detector",
        ),
        (
            vec![
                "--stream-corroborate",
                "--pose",
                "east:48,32,24,24,24,16,1,0,0,0,1,0,0,0,1,0,0,10",
            ],
            "pose and calibration generation options are unsupported",
        ),
        (
            vec!["--stream-corroborate", "--camera-generation", "east:1:1"],
            "pose and calibration generation options are unsupported",
        ),
        (
            vec![
                "--stream-corroborate",
                "--calibration",
                "/unused/calibration",
                "--calibration-digest",
                digest,
            ],
            "does not admit coverage",
        ),
        (
            vec!["--stream-corroborate", "--stream-trace-bytes", "0"],
            "limits out of bounds",
        ),
        (
            vec!["--stream-corroborate", "--sensor-health", "latest"],
            "requires policy conservative-v1",
        ),
    ] {
        let mut args = prefix.clone();
        args.extend(extra.into_iter().map(OsString::from));
        refuses(run(&args)?, reason);
        assert!(!root.exists());
    }
    for key in [
        "--stream-read-bytes",
        "--stream-pixel-budget",
        "--stream-assignment-work",
        "--stream-trace-bytes",
    ] {
        let mut args = prefix.clone();
        args.extend([key, "100"].map(OsString::from));
        refuses(run(&args)?, "require --stream-corroborate");
        assert!(!root.exists());
    }
    Ok(())
}

#[test]
fn either_unknown_camera_time_refuses_before_decoding_the_other_camera() -> Test {
    for (label, time) in [
        ("unknown-east", [false, true]),
        ("unknown-west", [true, false]),
    ] {
        let f = Fixture::mjpeg(label, FRAMES, Some(180), time)?;
        let before = f.snapshot()?;
        let mut args = f.args();
        args.extend(["--work-units", "0"].map(OsString::from));
        refuses(run(&args)?, "ERR-CORROBORATE-TIME-UNKNOWN-001");
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn health_findings_preserve_diagnostics_and_block_even_exact_publication() -> Test {
    let f = Fixture::mjpeg("health", FRAMES, Some(180), [true; 2])?;
    let before = f.snapshot()?;
    let mut args = f.args();
    args.extend(["--sensor-health", "conservative-v1"].map(OsString::from));
    let preview = good(run(&args)?)?;
    assert_eq!(
        unsigned_fields(&preview, "frames_screened")?,
        vec![300, 300]
    );
    assert_eq!(unsigned_field(&preview, "entry_count")?, 2);
    assert_eq!(unsigned_field(&preview, "candidate_count")?, 1);
    assert!(preview.contains("exact_frame_repetition"));
    assert!(preview.contains("\"publication_blocked\":true"));
    assert!(preview.contains("\"publish_command\":null"));
    args.extend([
        "--approve".into(),
        digest_field(&preview, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&args)?,
        "sensor-health findings or incomplete screening",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn ordinary_and_streaming_approvals_and_changed_budget_approvals_are_distinct() -> Test {
    let f = Fixture::mjpeg("approval", 14, Some(3), [true; 2])?;
    let before = f.snapshot()?;
    let ordinary = base(&f.root, f.imports);
    let streaming = f.args();
    let short_preview = good(run(&ordinary)?)?;
    let stream_preview = good(run(&streaming)?)?;
    let short_approval = digest_field(&short_preview, "proposal_digest")?;
    let stream_approval = digest_field(&stream_preview, "proposal_digest")?;
    assert_ne!(short_approval, stream_approval);
    for (mut args, approval) in [
        (streaming.clone(), short_approval),
        (ordinary, stream_approval.clone()),
    ] {
        args.extend(["--approve".into(), approval.into()]);
        refuses(run(&args)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    }
    let mut changed_budget = streaming.clone();
    changed_budget.extend([
        "--stream-pixel-budget".into(),
        "2147483648".into(),
        "--approve".into(),
        stream_approval.clone().into(),
    ]);
    refuses(run(&changed_budget)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    let mut changed_zone = streaming;
    set(&mut changed_zone, "--zone", "renamed:8,16,16,16")?;
    changed_zone.extend(["--approve".into(), stream_approval.into()]);
    refuses(run(&changed_zone)?, "ERR-CORROBORATE-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn quiet_complete_recordings_never_establish_absence_or_silent_short_mode_truncation() -> Test {
    let f = Fixture::mjpeg("quiet", FRAMES, None, [true; 2])?;
    let before = f.snapshot()?;
    let preview = good(run(&f.args())?)?;
    assert_eq!(unsigned_fields(&preview, "frames_decoded")?, vec![300, 300]);
    assert_eq!(unsigned_field(&preview, "entry_count")?, 0);
    assert_eq!(unsigned_field(&preview, "candidate_count")?, 0);
    assert!(preview.contains("\"absence_certifiable\":false"));
    assert!(preview.contains("\"physical_arrival_proved\":false"));
    refuses(run(&base(&f.root, f.imports))?, "128");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
