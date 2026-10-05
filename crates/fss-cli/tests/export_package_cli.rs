#![forbid(unsafe_code)]
#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
//! Real process handoff of committed redacted exports; fixtures use real local journals.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis,
    EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, OperationId,
    ProbabilityInterval, TimestampNs,
};
use fss_reference::evidence_export::{
    CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EventExportRequest, commit_export, preview_export,
};
use fss_reference::{ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:portable-export-cli";
const ACTOR: &str = "principal:portable-export-cli";
const RECIPIENT: &str = "recipient:case-7";
// Avoid another fixture's briefly inherited deployment lock while a test forks a CLI child.
static SERIAL: Mutex<()> = Mutex::new(());

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-cli-{label}-{}-{n}", std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Fixture {
    root: PathBuf,
    output: PathBuf,
    export_root: ContentDigest,
    directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        // Spaces and a quote exercise shell rendering without executing a returned shell string.
        let output = directory.0.join("owner's case package.fssp");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:portable-export-cli".into(),
            operation_id: OperationId::parse("operation:portable-export-cli")?,
            principal: ACTOR.into(),
            capabilities: vec!["ADP-REPLAY-001".into(), CAP_EXPORT_PREPARE.into(), CAP_EXPORT_COMMIT.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(8192).build()?,
            privacy_scope: "privacy:redacted-export-test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.into(),
            event_id: EventId::parse("event:portable-export-cli")?,
            revision: 1,
            supersedes: None,
            state: EventState::Indeterminate,
            kind: EventKind::Unclassified,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some("Synthetic unresolved observation".into()),
            zone_ids: vec!["private-zone-name".into()],
            track_ids: vec!["private-track-name".into()],
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(b"private source sentinel"),
                class: EvidenceClass::Assertion,
                failure_domain: "sensor:private-door".into(),
                supports: false,
                relation: EvidenceEdgeRelation::DerivedFrom,
                capsule_digest: None,
                identity_digest: Some(ContentDigest::sha256(b"private identity")),
            }],
            model_receipts: vec![ContentDigest::sha256(b"private model sentinel")],
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"policy"),
                fingerprint: ContentDigest::sha256(b"decision"),
                abstained: true,
                abstention_reason: Some("synthetic".into()),
            },
        };
        deployment.stage_payload(b"private source sentinel")?;
        deployment.stage_payload(b"private model sentinel")?;
        deployment.publish_event(&ReferencePolicyDecision {
            event: event.clone(), action: ReferencePolicyAction::Hold,
        }, &cx)?;
        let request = EventExportRequest {
            event_id: event.event_id.clone(),
            expected_revision: event.revision_digest(),
            recipient: RECIPIENT.into(),
            purpose: "Owner-authorized case review".into(),
            expires_at: TimestampNs(100),
        };
        let preview = preview_export(&deployment, &request, &authority, &cx)?;
        let export_root = preview.root();
        commit_export(&mut deployment, &request, preview.approval(), &authority, &cx)?;
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self { root, output, export_root, directory })
    }

    fn pack(&self) -> Vec<OsString> {
        vec![
            "pack".into(), "--root".into(), self.root.as_os_str().to_owned(),
            "--site".into(), SITE.into(), "--principal".into(), ACTOR.into(),
            "--export-root".into(), self.export_root.to_text().into(),
            "--recipient".into(), RECIPIENT.into(), "--attested-now-ns".into(), "30:40".into(),
            "--out".into(), self.output.as_os_str().to_owned(),
        ]
    }
    fn verify(&self, input: &Path) -> Vec<OsString> {
        vec![
            "verify".into(), "--input".into(), input.as_os_str().to_owned(),
            "--export-root".into(), self.export_root.to_text().into(),
            "--recipient".into(), RECIPIENT.into(), "--attested-now-ns".into(), "30:40".into(),
        ]
    }
    fn create(&self) -> Test<(String, Output)> {
        let preview = execute(&self.pack())?;
        success(&preview);
        let approval = field(&preview, "approval_digest")?;
        let output = execute(&approved(self.pack(), &approval))?;
        success(&output);
        Ok((approval, output))
    }
    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

fn execute(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-export-package")).args(args).output()?)
}
fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
fn refused(output: &Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal must not emit a partial record");
    assert!(String::from_utf8_lossy(&output.stderr).contains(reason),
        "expected {reason}, got {}", String::from_utf8_lossy(&output.stderr));
}
// Only read unescaped digest/status values, not arbitrary package JSON or returned shell text.
fn field(output: &Output, key: &str) -> Test<String> {
    let text = std::str::from_utf8(&output.stdout)?;
    let needle = format!("\"{key}\"");
    let (_, suffix) = text.split_once(&needle).ok_or("missing output field")?;
    let value = suffix.trim_start().strip_prefix(':').ok_or("missing field separator")?
        .trim_start().strip_prefix('"').ok_or("expected string field")?;
    Ok(value.split_once('"').ok_or("unterminated field")?.0.to_owned())
}
fn set(args: &mut [OsString], key: &str, value: OsString) -> Test {
    let index = args.iter().position(|arg| arg == key).ok_or("option absent")?;
    *args.get_mut(index + 1).ok_or("value absent")? = value;
    Ok(())
}
fn approved(mut args: Vec<OsString>, approval: &str) -> Vec<OsString> {
    args.extend(["--approve".into(), approval.into()]);
    args
}

#[test]
fn preview_commit_exact_retry_and_offline_verification_need_no_source_deployment() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("roundtrip")?;
    let before = fixture.journals()?;
    let preview = execute(&fixture.pack())?;
    success(&preview);
    assert_eq!(field(&preview, "status")?, "proposed");
    assert!(!fixture.output.exists());
    let approval = field(&preview, "approval_digest")?;
    let written = execute(&approved(fixture.pack(), &approval))?;
    success(&written);
    assert_eq!(field(&written, "status")?, "created");
    let bytes = fs::read(&fixture.output)?;
    let inode = fs::metadata(&fixture.output)?.ino();
    assert_eq!(fs::metadata(&fixture.output)?.mode() & 0o777, 0o600);
    let retry = execute(&approved(fixture.pack(), &approval))?;
    success(&retry);
    assert_eq!(field(&retry, "status")?, "already_present");
    assert_eq!(fs::metadata(&fixture.output)?.ino(), inode);
    assert_eq!(fs::read(&fixture.output)?, bytes);
    assert_eq!(fixture.journals()?, before);
    fs::rename(&fixture.root, fixture.directory.0.join("deployment-unavailable"))?;
    let verified = execute(&fixture.verify(&fixture.output))?;
    success(&verified);
    assert_eq!(field(&verified, "status")?, "verified_against_supplied_root");
    assert_eq!(field(&verified, "package_digest")?, field(&written, "package_digest")?);
    let text = std::str::from_utf8(&verified.stdout)?;
    assert!(text.contains("\"signature_verified\":false"));
    assert!(text.contains("\"state\":\"indeterminate\""));
    for private in ["private-zone-name", "private-track-name", "sensor:private-door",
        "private source sentinel", "private model sentinel"] {
        assert!(!text.contains(private));
        assert!(!bytes.windows(private.len()).any(|w| w == private.as_bytes()));
    }
    assert!(!fixture.root.exists(), "offline verification did not open/create a deployment");
    Ok(())
}

#[test]
fn stale_file_approvals_do_not_authorize_another_path_time_or_actor() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("stale")?;
    let preview = execute(&fixture.pack())?;
    success(&preview);
    let approval = field(&preview, "approval_digest")?;
    let before = fixture.journals()?;
    for (key, value, reason) in [
        ("--out", fixture.directory.0.join("other.fssp").into_os_string(), "ERR-EXPORT-APPROVAL-STALE-001"),
        ("--attested-now-ns", OsString::from("31:40"), "ERR-EXPORT-APPROVAL-STALE-001"),
        ("--principal", OsString::from("principal:other"), "export_authority_denied"),
    ] {
        let mut args = fixture.pack();
        set(&mut args, key, value)?;
        refused(&execute(&approved(args, &approval))?, reason);
    }
    assert!(!fixture.output.exists());
    assert!(!fixture.directory.0.join("other.fssp").exists());
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn offline_verifier_refuses_mismatched_root_recipient_uncertain_expiry_and_tampering() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("verify-refusals")?;
    fixture.create()?;
    let bytes = fs::read(&fixture.output)?;
    for (key, value, reason) in [
        ("--export-root", ContentDigest::sha256(b"wrong root").to_text(), "expected_export_root_mismatch"),
        ("--recipient", "recipient:other".to_owned(), "recipient_mismatch"),
        ("--attested-now-ns", "90:100".to_owned(), "expiry_overlaps_attested_time"),
        ("--attested-now-ns", "100:100".to_owned(), "expired_under_attested_time"),
    ] {
        let mut args = fixture.verify(&fixture.output);
        set(&mut args, key, value.into())?;
        refused(&execute(&args)?, reason);
    }
    let corrupt = fixture.directory.0.join("corrupt.fssp");
    let mut damaged = bytes.clone();
    let last = damaged.last_mut().ok_or("empty package")?;
    *last ^= 1;
    fs::write(&corrupt, damaged)?;
    refused(&execute(&fixture.verify(&corrupt))?, "malformed_package");
    fs::write(&corrupt, &bytes[..bytes.len() - 1])?;
    refused(&execute(&fixture.verify(&corrupt))?, "malformed_package");
    assert_eq!(fs::read(&fixture.output)?, bytes);
    Ok(())
}

#[test]
fn conflicting_output_and_symlink_alias_into_deployment_are_refused() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("output-refusal")?;
    let preview = execute(&fixture.pack())?;
    success(&preview);
    let approval = field(&preview, "approval_digest")?;
    fs::write(&fixture.output, b"existing unrelated data")?;
    let inode = fs::metadata(&fixture.output)?.ino();
    refused(&execute(&approved(fixture.pack(), &approval))?, "output_exists_or_identity_changed");
    assert_eq!(fs::read(&fixture.output)?, b"existing unrelated data");
    assert_eq!(fs::metadata(&fixture.output)?.ino(), inode);
    let alias = fixture.directory.0.join("deployment-alias");
    symlink(&fixture.root, &alias)?;
    let mut args = fixture.pack();
    set(&mut args, "--out", alias.join("case.fssp").into_os_string())?;
    refused(&execute(&args)?, "outside_deployment");
    assert!(!fixture.root.join("case.fssp").exists());
    Ok(())
}

#[test]
fn replacing_the_destination_directory_invalidates_the_previous_file_approval() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let mut fixture = Fixture::new("directory-pin")?;
    let destination = fixture.directory.0.join("handoff");
    fs::create_dir(&destination)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    fixture.output = destination.join("case.fssp");
    let preview = execute(&fixture.pack())?;
    success(&preview);
    let approval = field(&preview, "approval_digest")?;
    fs::rename(&destination, fixture.directory.0.join("old-handoff"))?;
    fs::create_dir(&destination)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    refused(&execute(&approved(fixture.pack(), &approval))?, "ERR-EXPORT-APPROVAL-STALE-001");
    assert!(!fixture.output.exists());
    assert!(!fixture.directory.0.join("old-handoff/case.fssp").exists());
    Ok(())
}

#[test]
fn malformed_requests_fail_before_storage_and_help_describes_the_trust_boundary() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let directory = Directory::new("parse")?;
    let missing = directory.0.join("does-not-exist.fssp");
    let root = ContentDigest::sha256(b"root").to_text();
    let mut args: Vec<OsString> = vec![
        "verify".into(), "--input".into(), missing.clone().into_os_string(),
        "--export-root".into(), root.into(), "--recipient".into(), RECIPIENT.into(),
        "--attested-now-ns".into(), "40:30".into(),
    ];
    let bad = execute(&args)?;
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    set(&mut args, "--attested-now-ns", "30:40".into())?;
    args.extend(["--recipient".into(), "recipient:duplicate".into()]);
    let duplicate = execute(&args)?;
    assert_eq!(duplicate.status.code(), Some(2));
    assert!(duplicate.stdout.is_empty());
    assert!(!missing.exists());
    let help = execute(&["--help".into()])?;
    success(&help);
    let text = std::str::from_utf8(&help.stdout)?;
    assert!(text.contains("independent trusted channel"));
    assert!(text.contains("METADATA ONLY"));
    assert!(text.contains("expiry does not erase existing copies"));
    Ok(())
}
