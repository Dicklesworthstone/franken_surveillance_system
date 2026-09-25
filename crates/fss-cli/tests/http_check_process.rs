#![forbid(unsafe_code)]
//! A separate CLI process must use real original objects and native media checking.
#[path = "../../fss-reference/tests/http_check_support/mod.rs"]
mod support;
use fss_cli::ExitIdentity;
use std::process::{Command, Output};
use support::*;

const PRIVACY_SITE: &str = "site:check-http-privacy";
const PRIVACY_SENSOR: &str = "sensor:check-http";
/// An existing, closed deployment retaining the recorded sensor's mask authority (none, or one
/// rectangle policy at the fixture's 17x13 resolution).
struct PrivacyRoot(std::path::PathBuf);
impl PrivacyRoot {
    fn new(policy: Option<[u32; 4]>) -> Test<Self> {
        use fss_core::region::{ContextAuthority, RootAuthoritySpec};
        use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId};
        use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
        use fss_reference::{ReferenceDeployment, ReplayCx};
        let mut dir = None;
        for n in 0..128 {
            let path = std::env::temp_dir()
                .join(format!("fss-check-http-privacy-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    dir = Some(path);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let this = Self(dir.ok_or("privacy fixture directory bound")?);
        let root = this.deployment();
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:check-http-privacy".into(),
            operation_id: OperationId::parse("operation:check-http-privacy")?,
            principal: "principal:check-http-privacy".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(PRIVACY_SITE.as_bytes()),
            generation: 1,
        })?;
        authority.validate()?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, PRIVACY_SITE, &cx)?;
        if let Some(rectangle) = policy {
            let policy =
                PrivacyMaskPolicy::new(SensorId::parse(PRIVACY_SENSOR)?, [17, 13], &[rectangle])?;
            let preview = preview_mask(&deployment, &policy)?;
            declare_mask(&mut deployment, &policy, preview.approval, &cx)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        Ok(this)
    }
    fn deployment(&self) -> std::path::PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for PrivacyRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
/// Decoding check naming the recorded sensor of a no-policy deployment.
fn invoke(root: &std::path::Path, f: &Fixture, extra: &[&str]) -> Test<Output> {
    let privacy = PrivacyRoot::new(None)?;
    invoke_with(root, f, extra, Some(&privacy.deployment()))
}
fn invoke_with(
    root: &std::path::Path,
    f: &Fixture,
    extra: &[&str],
    privacy: Option<&std::path::Path>,
) -> Test<Output> {
    let r = f.request;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-archive"));
    command.arg("check-http").arg("--root").arg(root);
    if let Some(deployment) = privacy {
        command.arg("--privacy-root").arg(deployment).args([
            "--site",
            PRIVACY_SITE,
            "--sensor",
            PRIVACY_SENSOR,
        ]);
    }
    Ok(command
        .args([
            "--source",
            &r.source.source.to_string(),
            "--generation",
            &r.source.generation.to_string(),
            "--receive-clock",
            &r.source.receive_clock.to_string(),
            "--retention-evidence",
            &r.source.retention_evidence.to_string(),
            "--head",
            &r.head.to_string(),
            "--reads",
            &r.reads.to_string(),
            "--bytes",
            &r.bytes.to_string(),
            "--read-originals",
            "yes",
            "--decode",
            "grayscale",
            "--timeout-ms",
            "10000",
        ])
        .args(extra)
        .output()?)
}
/// Serializes this binary's tests. Every test holds native flock owner locks in this process and
/// spawns real CLI processes. A child spawned by a concurrent test thread inherits, until its exec
/// closes it, every descriptor open at that instant, including another test's held owner lock; the
/// flock then outlives its owner's drop, and that test's next open or child sees Locked/Busy.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[test]
fn real_process_checks_cold_originals_and_emits_no_media_or_paths() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG])?;
    let output = invoke(&d.0, &f, &[])?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::SUCCESS.code))
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with(
        "{\"schema\":\"fss.local_http_check.v1\",\"command\":\"check-http\",\"status\":\"complete\""
    ));
    assert!(text.ends_with("]}\n"));
    assert_eq!(text.matches("\"ordinal\":").count(), 2);
    assert!(text.contains("\"checked_frames\":2,"));
    assert_eq!(text.matches("\"dimensions\":[17,13]").count(), 2);
    assert!(text.contains("\"source_bytes_emitted\":false"));
    assert!(text.contains("\"new_roots_published\":false"));
    assert!(!text.contains("camera.invalid"));
    assert!(!text.contains(d.0.to_str().ok_or("fixture path")?));
    assert!(output.stderr.is_empty());
    assert_eq!(open(&d.0)?.visible_roots().count(), 1);
    Ok(())
}
#[test]
fn incomplete_prefix_is_a_nonzero_exit_with_a_preserved_report() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, true, &[JPEG])?;
    let output = invoke(&d.0, &f, &[])?;
    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"status\":\"prefix_exhausted\""));
    assert!(text.contains("\"checked_frames\":1,"));
    assert!(text.contains("\"termination\":null"));
    assert!(text.contains("\"completion_root\":null"));
    Ok(())
}
#[test]
fn bounded_refusal_preserves_error_class_and_never_claims_success() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    for extra in [["--max-steps", "1"], ["--max-decode-work", "0"]] {
        let output = invoke(&d.0, &f, &extra)?;
        assert!(!output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("\"status\":\"refused\""));
        assert!(text.contains("\"checked_frames\":0,"));
        assert!(!text.contains("\"error\":null"));
    }
    Ok(())
}
#[test]
fn output_limit_never_truncates_an_apparently_successful_json_object() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG, JPEG])?;
    let output = invoke(&d.0, &f, &["--max-report-bytes", "1024"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("report exceeds selected output bound"));
    Ok(())
}
#[test]
fn malformed_options_never_echo_secrets_or_create_an_archive() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let missing = d.0.join("missing");
    let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .arg("check-http")
        .arg("--root")
        .arg(&missing)
        .args(["--unknown", "CANARY-SECRET-NEVER-ECHO"])
        .output()?;
    assert!(!output.status.success());
    assert!(!missing.exists());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8(output.stderr)?.contains("CANARY-SECRET-NEVER-ECHO"));
    Ok(())
}
#[test]
fn corrupt_originals_are_not_repaired_by_the_operator_command() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    let text = f.wire_digest.to_text();
    let path =
        d.0.join("spool/objects")
            .join(text.strip_prefix("sha256:").ok_or("algorithm")?);
    std::fs::write(&path, b"corrupt-original")?;
    let output = invoke(&d.0, &f, &[])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(path)?, b"corrupt-original");
    Ok(())
}

#[test]
fn a_decoding_check_names_the_sensor_and_digests_only_its_masked_luma() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    // No sensor named: refused before the archive is read, with no report on stdout.
    let refused = invoke_with(&d.0, &f, &[], None)?;
    assert_eq!(
        refused.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8(refused.stderr)?.starts_with("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001:")
    );
    // The native decode of the fixture before any masking existed (captured at 40bf5a6).
    let unmasked = "sha256:5875da5ed7274432c2e42d253dae128c4a7d4be02f9122f72f3688a0a0b86f1d";
    // A sensor without a policy: the codec's luma, and the explicit no-policy marker.
    let open = PrivacyRoot::new(None)?;
    let output = invoke_with(&d.0, &f, &[], Some(&open.deployment()))?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"privacy_mask\":{\"binding\":\"no_policy_declared\""));
    assert!(text.contains(&format!("\"luma\":\"{unmasked}\"")));
    // A masked sensor: the block holds the fill in the digested plane.
    let masked = PrivacyRoot::new(Some([0, 0, 8, 8]))?;
    let output = invoke_with(&d.0, &f, &[], Some(&masked.deployment()))?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"privacy_mask\":{\"binding\":\"sensor_policy\""));
    assert!(text.contains("\"applied_redaction_transform\":\"transform:bounding_box_redact\""));
    assert!(text.contains("\"luma\":\"sha256:"));
    assert!(!text.contains(unmasked));
    Ok(())
}
