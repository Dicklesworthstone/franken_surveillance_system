#![forbid(unsafe_code)]
//! Real native deployment readback: the UI must not initialize, repair or rewrite custody.
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::{ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type Test = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("fss-dashboard-contract-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn context(directory: &Directory) -> Result<ReplayCx, Box<dyn Error>> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:dashboard-test".to_owned(),
        operation_id: OperationId::parse("operation:dashboard-test")?,
        principal: "operator:dashboard-test".to_owned(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"dashboard test anchor"),
        generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority, directory.0.join("scratch"))?))
}
fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error>> {
    fn visit(root: &Path, dir: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                result.insert(path.strip_prefix(root)?.to_owned(), Vec::new());
                visit(root, &path, result)?;
            } else {
                result.insert(path.strip_prefix(root)?.to_owned(), fs::read(&path)?);
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}
fn snapshot(root: &Path, site: &str) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .arg("--snapshot").arg("--root").arg(root)
        .args(["--site", site, "--allow-local-metadata", "yes"])
        .output()?)
}
#[test]
fn native_empty_deployment_is_read_without_new_files_or_journal_writes() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    let cx = context(&directory)?;
    drop(ReferenceDeployment::open(&root, "site:dashboard-test", &cx)?);
    let before = inventory(&root)?;
    for _ in 0..2 {
        let output = snapshot(&root, "site:dashboard-test")?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let body = String::from_utf8(output.stdout)?;
        for field in ["\"format\":\"fss.operator_dashboard.v1\"", "\"demo\":false", "\"site\":\"site:dashboard-test\"", "\"events\":[]", "\"imports\":[]", "\"openObligations\":0", "\"indeterminateOperations\":0"] {
            assert!(body.contains(field), "missing {field}: {body}");
        }
        assert!(!body.contains("event:demo:"));
        assert_eq!(inventory(&root)?, before);
    }
    Ok(())
}
#[test]
fn wrong_site_and_damaged_layout_never_substitute_demo_or_repair_the_root() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    let cx = context(&directory)?;
    drop(ReferenceDeployment::open(&root, "site:dashboard-test", &cx)?);
    let before = inventory(&root)?;
    let output = snapshot(&root, "site:another-site")?;
    assert!(!output.status.success()); assert!(output.stdout.is_empty());
    assert_eq!(inventory(&root)?, before);
    fs::write(root.join("LAYOUT"), b"deliberately damaged layout\n")?;
    let damaged = inventory(&root)?;
    let output = snapshot(&root, "site:dashboard-test")?;
    assert!(!output.status.success()); assert!(output.stdout.is_empty());
    assert_eq!(inventory(&root)?, damaged);
    Ok(())
}
#[test]
fn missing_deployment_is_not_created_and_demo_cannot_select_one() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("not-present");
    let output = snapshot(&root, "site:dashboard-test")?;
    assert!(!output.status.success()); assert!(output.stdout.is_empty()); assert!(!root.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .args(["--demo", "--snapshot", "--root"]).arg(&root).output()?;
    assert!(!output.status.success()); assert!(output.stdout.is_empty()); assert!(!root.exists());
    Ok(())
}
