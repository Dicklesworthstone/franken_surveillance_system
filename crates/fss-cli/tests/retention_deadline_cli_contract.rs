#![forbid(unsafe_code)]
//! Native CLI composition: minimum retention, explicit time assertions, expiry and deletion.
//! Synthetic imports exercise custody and authority, not clock authentication or legal policy.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const HOLD: &str = env!("CARGO_BIN_EXE_fss-hold");
const EVENT: &str = env!("CARGO_BIN_EXE_fss-event");
const SITE: &str = "site:retention-cli";

struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        for n in 0..100 {
            let path =
                std::env::temp_dir().join(format!("fss-retention-cli-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(output: Output) -> TestResult<String> {
    if !output.status.success() {
        return Err(format!(
            "command refused: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn digest_field(json: &str, field: &str) -> TestResult<String> {
    let marker = format!("\"{field}\":\"");
    if json.matches(marker.as_str()).count() != 1 {
        return Err("expected one digest field".into());
    }
    let value = json
        .split_once(marker.as_str())
        .ok_or("missing digest")?
        .1
        .split('"')
        .next()
        .ok_or("unterminated digest")?;
    Ok(ContentDigest::parse(value)?.to_text())
}

#[test]
fn due_is_read_only_and_only_approved_expiry_unblocks_native_deletion() -> TestResult {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retention-cli".into(),
        operation_id: OperationId::parse("operation:retention-cli")?,
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
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let path = directory.0.join("source.mjpeg");
    fs::write(
        &path,
        encode_jpeg(
            16,
            16,
            &[40; 256],
            &JpegConfig {
                quality: 90,
                subsampling: Subsampling::Grayscale,
                restart_interval: 0,
                custom_markers: Vec::new(),
            },
        )?,
    )?;
    let request = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:retention-cli")?,
        StreamId::parse("stream:retention-cli")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000))
    .with_format_hint(FileFormatHint::JpegStream);
    let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
    let import = identity.to_text();
    drop(deployment); // Do not hold the writer lock across subprocess calls.

    let mutation =
        |action: &str, now: Option<&str>, approval: Option<&str>| -> TestResult<Output> {
            let mut command = Command::new(HOLD);
            command.arg(action).arg("--root").arg(&root).args([
                "--site",
                SITE,
                "--hold-id",
                "minimum",
                "--import-id",
                &import,
                "--reason",
                "Owner retention decision",
            ]);
            if action != "release" {
                command.args(["--until-ns", "1000"]);
            }
            if let Some(now) = now {
                command.args(["--attested-now-ns", now]);
            }
            if let Some(approval) = approval {
                command.args(["--approve", approval]);
            }
            Ok(command.output()?)
        };
    let deletion = || -> TestResult<String> {
        success(
            Command::new(EVENT)
                .args(["delete", "plan"])
                .arg("--root")
                .arg(&root)
                .args(["--site", SITE, "--import-id", &import])
                .output()?,
        )
    };
    let preview = success(mutation("retain", None, None)?)?;
    assert!(preview.contains("\"state\":\"retained_until\""));
    assert!(preview.contains("\"not_before_ns\":\"1000\""));
    let approval = digest_field(&preview, "approval_digest")?;
    assert!(
        success(mutation("retain", None, Some(&approval))?)?.contains("\"status\":\"committed\"")
    );
    assert!(
        success(mutation("retain", None, Some(&approval))?)?
            .contains("\"status\":\"already_current\"")
    );
    let before = fs::read(root.join("ledger/journal.fssj"))?;
    for (now, readiness, count) in [
        ("998:999", "not_due", 0),
        ("999:1001", "time_uncertain", 0),
        ("1000:1002", "eligible_for_expiry", 1),
    ] {
        let due = success(
            Command::new(HOLD)
                .arg("due")
                .arg("--root")
                .arg(&root)
                .args(["--site", SITE, "--attested-now-ns", now])
                .output()?,
        )?;
        assert!(
            due.contains(&format!("\"time_readiness\":\"{readiness}\"")),
            "{due}"
        );
        assert!(
            due.contains(&format!("\"eligible_for_expiry\":{count}")),
            "{due}"
        );
        assert!(due.contains("operator_assertion_not_authenticated_clock"));
        assert!(due.contains("\"deletion_blocking\":true"));
        assert!(deletion()?.contains("\"kind\":\"evidence_hold\""));
        assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, before);
    }
    assert!(!mutation("release", None, None)?.status.success());
    assert!(!mutation("expire", Some("999:1001"), None)?.status.success());
    let expiry_preview = success(mutation("expire", Some("1000:1002"), None)?)?;
    let expiry = digest_field(&expiry_preview, "approval_digest")?;
    assert_ne!(expiry, approval);
    assert!(
        !mutation("expire", Some("1000:1002"), Some(&approval))?
            .status
            .success()
    );
    assert!(
        !mutation("expire", Some("1000:1003"), Some(&expiry))?
            .status
            .success()
    );
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, before);
    assert!(
        success(mutation("expire", Some("1000:1002"), Some(&expiry))?)?
            .contains("\"state\":\"expired\"")
    );
    assert!(
        success(mutation("expire", Some("1000:1002"), Some(&expiry))?)?
            .contains("\"status\":\"already_current\"")
    );

    let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    RetainedFileImport::open(&deployment, identity, RetainedReadLimits::default(), &cx)?;
    drop(deployment); // Expiry did not remove source; deletion remains a separate approval.
    let plan = deletion()?;
    assert!(!plan.contains("\"kind\":\"evidence_hold\""));
    let deleted = success(
        Command::new(EVENT)
            .args(["delete", "commit"])
            .arg("--root")
            .arg(&root)
            .args([
                "--site",
                SITE,
                "--plan",
                &digest_field(&plan, "plan_digest")?,
                "--approve",
                &digest_field(&plan, "approval_digest")?,
            ])
            .output()?,
    )?;
    assert!(deleted.contains("\"outcome\":\"completed\""));
    let listed = success(
        Command::new(HOLD)
            .arg("list")
            .arg("--root")
            .arg(&root)
            .args(["--site", SITE])
            .output()?,
    )?;
    assert!(listed.contains("\"active_holds\":0"));
    assert!(listed.contains("\"state\":\"expired\""));
    assert!(listed.contains("\"earliest_ns\":\"1000\""));
    Ok(())
}

#[test]
fn absent_clock_malformed_bounds_and_cross_command_options_never_create_a_root() -> TestResult {
    let directory = Directory::new()?;
    let absent = directory.0.join("not-a-deployment");
    for suffix in [
        vec![],
        vec!["--attested-now-ns", "2:1"],
        vec!["--attested-now-ns", "1:2:3"],
        vec!["--attested-now-ns", "1:2", "--approve", "sha256:bad"],
    ] {
        let result = Command::new(HOLD)
            .arg("due")
            .arg("--root")
            .arg(&absent)
            .args(["--site", SITE])
            .args(suffix)
            .output()?;
        assert!(!result.status.success());
        assert!(!absent.exists());
    }
    let result = Command::new(HOLD)
        .arg("due")
        .arg("--root")
        .arg(&absent)
        .args(["--site", SITE, "--attested-now-ns", "1:2"])
        .output()?;
    assert!(!result.status.success());
    assert!(!absent.exists());
    Ok(())
}
