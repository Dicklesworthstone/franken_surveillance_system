#![forbid(unsafe_code)]
//! The actual fss-event binary, real retained MJPEG, and its durable journals.
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:dwell-cli";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for i in 0..100 {
            let p = std::env::temp_dir()
                .join(format!("fss-dwell-cli-{label}-{}-{i}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    root: PathBuf,
    import: ContentDigest,
    dir: Directory,
}
impl Fixture {
    fn new(label: &str, timing: bool) -> Test<Self> {
        let dir = Directory::new(label)?;
        let root = dir.0.join("deployment");
        let path = dir.0.join("camera.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut bytes = Vec::new();
        for index in 0..14 {
            let mut pixels = vec![40_u8; 96 * 48];
            if index >= 3 {
                let left = (index - 3) * 8;
                for y in 8..24 {
                    for x in left..left + 16 {
                        pixels[y * 96 + x] = 220;
                    }
                }
            }
            bytes.extend(encode_jpeg(96, 48, &pixels, &config)?);
        }
        fs::write(&path, bytes)?;
        let auth = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:dwell-cli".into(),
            operation_id: OperationId::parse("operation:dwell-cli")?,
            principal: "principal:local-operator".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&auth, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut request = FileIngestRequest::new(
            &path,
            SensorId::parse("sensor:dwell-cli")?,
            StreamId::parse("stream:dwell-cli")?,
        )
        .with_receive_time(TimestampNs(10_000_000_000));
        if timing {
            request = request.with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        }
        let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        drop(deployment);
        cx.drain_and_finalize();
        // Everything the child needs must come from retained custody, never the original file.
        fs::remove_file(path)?;
        Ok(Self { root, import, dir })
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command.args(["watch", "--root"]).arg(&self.root).args([
            "--site",
            SITE,
            "--import-id",
            &self.import.to_text(),
            "--interpretation",
            "gray",
            "--zone",
            "yard:0,0,96,48",
        ]);
        command
    }
    fn dwell(&self) -> Command {
        let mut command = self.command();
        command.args([
            "--dwell-for-ns",
            "200000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--dwell-min-observations",
            "3",
        ]);
        command
    }
    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}
fn succeeded(output: Output) -> Test<String> {
    if !output.status.success() {
        return Err(format!("child refused: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn refused(output: Output) -> Test<String> {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "refusal must not emit a partial report"
    );
    Ok(String::from_utf8(output.stderr)?)
}
fn digest_field(text: &str, name: &str) -> Test<ContentDigest> {
    let prefix = format!("\"{name}\":\"");
    let value = text
        .split_once(&prefix)
        .ok_or("missing digest field")?
        .1
        .split_once('"')
        .ok_or("unterminated digest field")?
        .0;
    Ok(ContentDigest::parse(value)?)
}

#[test]
fn preview_publish_and_exact_cold_retry_use_distinct_dwell_approvals() -> Test {
    let f = Fixture::new("lifecycle", true)?;
    let before = f.journals()?;
    let entry = succeeded(f.command().output()?)?;
    let preview = succeeded(f.dwell().output()?)?;
    assert!(preview.contains("\"format\":\"fss.recorded_dwell_report.v1\""));
    assert!(preview.contains("\"candidate_count\":1,"));
    assert!(preview.contains("--dwell-for-ns 200000000 --dwell-max-gap-ns 100000000"));
    assert!(preview.contains("\"continuous_occupancy_certified\":false"));
    assert!(preview.contains("\"alert_authorized\":false"));
    assert_eq!(f.journals()?, before);
    assert_eq!(succeeded(f.command().output()?)?, entry);
    let approval = digest_field(&preview, "proposal_digest")?;
    assert_ne!(approval, digest_field(&entry, "proposal_digest")?);
    let published = succeeded(
        f.dwell()
            .args(["--approve", &approval.to_text()])
            .output()?,
    )?;
    assert!(published.contains("\"status\":\"published\""));
    let after = f.journals()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    let retry = succeeded(
        f.dwell()
            .args(["--approve", &approval.to_text()])
            .output()?,
    )?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(digest_field(&retry, "proposal_digest")?, approval);
    assert_eq!(f.journals()?, after);
    Ok(())
}

#[test]
fn entry_and_other_rule_approvals_are_refused_before_mutation() -> Test {
    let f = Fixture::new("approval", true)?;
    let entry = succeeded(f.command().output()?)?;
    let original = succeeded(f.dwell().output()?)?;
    let before = f.journals()?;
    let entry_approval = digest_field(&entry, "proposal_digest")?;
    let error = refused(
        f.dwell()
            .args(["--approve", &entry_approval.to_text()])
            .output()?,
    )?;
    assert!(error.contains("ERR-WATCH-APPROVAL-STALE-001"));
    let old = digest_field(&original, "proposal_digest")?;
    let error = refused(
        f.command()
            .args([
                "--dwell-for-ns",
                "300000000",
                "--dwell-max-gap-ns",
                "100000000",
                "--dwell-min-observations",
                "3",
                "--approve",
                &old.to_text(),
            ])
            .output()?,
    )?;
    assert!(error.contains("ERR-WATCH-APPROVAL-STALE-001"));
    assert_eq!(f.journals()?, before);
    Ok(())
}

#[test]
fn unknown_capture_time_refuses_without_event_or_effect_writes() -> Test {
    let f = Fixture::new("time", false)?;
    let before = f.journals()?;
    let error = refused(f.dwell().output()?)?;
    assert!(error.contains("capture-time hints"));
    assert_eq!(f.journals()?, before);
    Ok(())
}

#[test]
fn incomplete_unbounded_and_coverage_rules_fail_before_opening_a_root() -> Test {
    let dir = Directory::new("parse")?;
    let root = dir.0.join("must-not-exist");
    let digest = ContentDigest::sha256(b"not an imported recording").to_text();
    let cases: &[&[&str]] = &[
        &["--dwell-for-ns", "1"],
        &["--dwell-max-gap-ns", "1"],
        &["--dwell-min-observations", "2"],
        &["--dwell-for-ns", "0", "--dwell-max-gap-ns", "1"],
        &[
            "--dwell-for-ns",
            "86400000000001",
            "--dwell-max-gap-ns",
            "1",
        ],
        &[
            "--dwell-for-ns",
            "1",
            "--dwell-max-gap-ns",
            "1",
            "--dwell-min-observations",
            "129",
        ],
        &[
            "--dwell-for-ns",
            "1",
            "--dwell-max-gap-ns",
            "1",
            "--retain-coverage",
            &digest,
        ],
    ];
    for args in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"])
            .arg(&root)
            .args([
                "--site",
                SITE,
                "--import-id",
                &digest,
                "--interpretation",
                "gray",
                "--zone",
                "yard:0,0,96,48",
            ])
            .args(*args)
            .output()?;
        refused(output)?;
        assert!(!root.exists());
    }
    Ok(())
}

#[test]
fn a_short_visit_is_reported_as_no_dwell_not_absence() -> Test {
    let f = Fixture::new("brief", true)?;
    let report = succeeded(
        f.command()
            .args([
                "--dwell-for-ns",
                "2000000000",
                "--dwell-max-gap-ns",
                "100000000",
            ])
            .output()?,
    )?;
    assert!(report.contains("\"candidate_count\":0,"));
    assert!(report.contains("\"absence_certifiable\":false"));
    assert!(!report.contains("--approve"));
    Ok(())
}

#[test]
fn preview_report_export_is_the_complete_stdout_report() -> Test {
    let f = Fixture::new("report", true)?;
    let before = f.journals()?;
    let target = f.dir.0.join("observed dwell.json");
    let output = f.dwell().arg("--report-out").arg(&target).output()?;
    let text = succeeded(output)?;
    assert_eq!(fs::read_to_string(target)?, text);
    assert_eq!(f.journals()?, before);
    Ok(())
}
