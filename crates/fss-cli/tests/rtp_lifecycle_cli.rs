#![forbid(unsafe_code)]
//! Real operator commands share RTP import, preservation and deletion authority.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;

use fss_core::ContentDigest;
use rtpdump_support::{Error, TestResult, real_dump};
use std::path::PathBuf;
use std::process::{Command, Output};

const SITE: &str = "site:rtp-lifecycle-cli";
struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Result<Self, Error> {
        let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base)?;
        for at in 0..1000 {
            let path = base.join(format!("rtp-lifecycle-{label}-{}-{at}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory allowance exhausted".into())
    }
    fn command(&self, bin: &str, verbs: &[&str]) -> Command {
        let mut c = Command::new(bin);
        c.args(verbs)
            .arg("--root")
            .arg(self.0.join("deployment"))
            .args(["--site", SITE]);
        c
    }
    fn import(&self, sensor: &str, damaged: bool) -> Result<String, Error> {
        let source = self.0.join(format!("{sensor}.rtpdump"));
        let mut bytes = real_dump(true);
        if damaged {
            bytes.extend_from_slice(&[0, 10, 0]);
        }
        std::fs::write(&source, bytes)?;
        let result = self
            .command(env!("CARGO_BIN_EXE_fss-file"), &["import"])
            .arg("--input")
            .arg(&source)
            .args([
                "--sensor",
                &format!("sensor:{sensor}"),
                "--stream",
                &format!("stream:{sensor}"),
                "--receive-time-ns",
                "1000000000",
                "--media-format",
                "rtpplay",
                "--rtp-generation",
                "1",
                "--rtp-ssrc",
                "7",
                "--rtp-payload-type",
                "96",
                "--rtp-mode",
                "non-interleaved",
            ])
            .output()?;
        let text = success(result)?;
        let root = text
            .lines()
            .find_map(|line| line.strip_prefix("import_root="))
            .ok_or("RTP root missing")?;
        ContentDigest::parse(root)?;
        // Every later operation must work without the original path or in-memory receipt.
        std::fs::remove_file(source)?;
        Ok(root.to_owned())
    }
    fn plan(&self, root: &str) -> Result<String, Error> {
        success(
            self.command(env!("CARGO_BIN_EXE_fss-event"), &["delete", "plan"])
                .args(["--import-id", root])
                .output()?,
        )
    }
    fn commit(&self, plan: &str) -> Result<Output, Error> {
        Ok(self
            .command(env!("CARGO_BIN_EXE_fss-event"), &["delete", "commit"])
            .args([
                "--plan",
                &digest(plan, "plan_digest")?,
                "--approve",
                &digest(plan, "approval_digest")?,
            ])
            .output()?)
    }
    fn hold(&self, action: &str, root: &str, approval: Option<&str>) -> Result<String, Error> {
        let mut c = self.command(env!("CARGO_BIN_EXE_fss-hold"), &[action]);
        c.args([
            "--hold-id",
            "incident",
            "--import-id",
            root,
            "--reason",
            "Owner incident review",
        ]);
        if let Some(a) = approval {
            c.args(["--approve", a]);
        }
        success(c.output()?)
    }
    fn inspect(&self, root: &str) -> Result<Output, Error> {
        Ok(self
            .command(env!("CARGO_BIN_EXE_fss-decode-rtp"), &["inspect"])
            .args(["--source-root", root])
            .output()?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn success(output: Output) -> Result<String, Error> {
    if !output.status.success() {
        return Err(format!(
            "child refused: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn digest(json: &str, field: &str) -> Result<String, Error> {
    let prefix = format!("\"{field}\":\"");
    if json.matches(&prefix).count() != 1 {
        return Err(format!("ambiguous field {field}").into());
    }
    let value = json
        .split_once(&prefix)
        .ok_or("missing field")?
        .1
        .split('"')
        .next()
        .ok_or("missing digest")?;
    Ok(ContentDigest::parse(value)?.to_text())
}
fn denied(output: Output) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ERR-EVIDENCE-DELETED-001"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn original_rtp_hold_release_and_delete_use_existing_operator_commands() -> TestResult {
    let f = Fixture::new("hold")?;
    let root = f.import("north", false)?;
    let proposed = f.hold("place", &root, None)?;
    assert!(proposed.contains("\"status\":\"proposed\""));
    let approval = digest(&proposed, "approval_digest")?;
    assert!(
        f.hold("place", &root, Some(&approval))?
            .contains("\"status\":\"committed\"")
    );
    assert!(
        f.hold("place", &root, Some(&approval))?
            .contains("\"status\":\"already_current\"")
    );
    let blocked = f.plan(&root)?;
    assert!(blocked.contains("\"status\":\"blocked\""));
    assert!(blocked.contains("\"kind\":\"evidence_hold\""));
    assert!(!f.commit(&blocked)?.status.success());
    success(f.inspect(&root)?)?;
    let release = digest(&f.hold("release", &root, None)?, "approval_digest")?;
    f.hold("release", &root, Some(&release))?;
    let plan = f.plan(&root)?;
    assert!(plan.contains("\"mechanism\":\"filesystem_unlink\""));
    let committed = success(f.commit(&plan)?)?;
    assert!(committed.contains("\"outcome\":\"completed\""));
    assert!(success(f.commit(&plan)?)?.contains("already_complete"));
    denied(f.inspect(&root)?);
    let list = success(
        f.command(env!("CARGO_BIN_EXE_fss-hold"), &["list"])
            .output()?,
    )?;
    assert!(list.contains("\"active_holds\":0"));
    assert!(list.contains("\"state\":\"released\""));
    Ok(())
}

#[test]
fn sensor_deletion_preserves_another_recording_that_shares_original_packet_bytes() -> TestResult {
    let f = Fixture::new("shared")?;
    let north = f.import("north", false)?;
    let south = f.import("south", false)?;
    assert_ne!(north, south);
    let plan = success(
        f.command(env!("CARGO_BIN_EXE_fss-event"), &["delete", "plan"])
            .args(["--sensor-id", "sensor:north"])
            .output()?,
    )?;
    assert!(plan.contains(&north));
    success(f.commit(&plan)?)?;
    denied(f.inspect(&north)?);
    success(f.inspect(&south)?)?;
    let images = f.0.join("south.pgm");
    let report = success(
        f.command(env!("CARGO_BIN_EXE_fss-decode-rtp"), &["decode"])
            .args(["--source-root", &south, "--custody", "current"])
            .arg("--output")
            .arg(&images)
            .output()?,
    )?;
    assert!(report.contains("decode_complete=true"));
    assert!(images.exists());
    Ok(())
}

#[test]
fn malformed_rtp_custody_is_deletable_and_deleted_root_never_creates_pixel_output() -> TestResult {
    let f = Fixture::new("malformed")?;
    let root = f.import("north", true)?;
    let report = success(f.inspect(&root)?)?;
    assert!(report.contains("container_end=framing_refused"));
    let plan = f.plan(&root)?;
    success(f.commit(&plan)?)?;
    let images = f.0.join("must-not-exist.pgm");
    denied(
        f.command(env!("CARGO_BIN_EXE_fss-decode-rtp"), &["decode"])
            .args(["--source-root", &root, "--custody", "current"])
            .arg("--output")
            .arg(&images)
            .output()?,
    );
    assert!(!images.exists());
    // Holds may preserve evidence before deletion, never resurrect its old authority after it.
    let late = f
        .command(env!("CARGO_BIN_EXE_fss-hold"), &["place"])
        .args([
            "--hold-id",
            "late",
            "--import-id",
            &root,
            "--reason",
            "Late request",
        ])
        .output()?;
    assert!(!late.status.success());
    denied(f.inspect(&root)?);
    Ok(())
}

#[test]
fn stale_rtp_deletion_approval_cannot_remove_either_new_or_original_custody() -> TestResult {
    let f = Fixture::new("stale")?;
    let north = f.import("north", false)?;
    let stale = f.plan(&north)?;
    let south = f.import("south", false)?;
    let denied_commit = f.commit(&stale)?;
    assert!(!denied_commit.status.success());
    assert!(String::from_utf8_lossy(&denied_commit.stderr).contains("ERR-DELETION-PLAN-STALE-001"));
    success(f.inspect(&north)?)?;
    success(f.inspect(&south)?)?;
    Ok(())
}
