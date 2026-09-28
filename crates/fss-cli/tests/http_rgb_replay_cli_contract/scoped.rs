#![forbid(unsafe_code)]
//! Real binary cross-store selection. Configuration-only fixtures never claim model execution.
use super::*;
const POLICY_SITE: &str = "site:external-replay-policy";

fn prepared(label: &str) -> Test<(Directory, PathBuf, PathBuf, ReplayCx, HttpRgbHistoryTip)> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("history");
    let original = directory.0.join("original");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut work = WorkBudget::new(1_000_000_000_000);
    let history = history(&mut work)?;
    let tip = history.tip()?;
    history.publish(
        tip,
        &mut deployment,
        HistoryAccess {
            history: &Authority(tip.session),
            evidence: &NoOriginals,
        },
        HistoryLimits::default(),
        &mut RgbEvidenceBudget::new(1_000_000_000),
        &mut work,
        &cx,
    )?;
    drop(deployment);
    archive(&original)?;
    Ok((directory, root, original, cx, tip))
}
fn command(root: &std::path::Path, original: &std::path::Path, tip: HttpRgbHistoryTip) -> Command {
    let mut c = Command::new(REPLAY);
    c.arg("http-rgb")
        .arg("--root")
        .arg(root)
        .args([
            "--site",
            SITE,
            "--session",
            &tip.session.to_text(),
            "--expected-root",
            &tip.root.to_text(),
            "--expected-revision",
            &tip.revision.to_string(),
            "--read-originals",
            "yes",
            "--execute-model",
            "yes",
            "--max-attempts",
            "0",
        ])
        .arg("--original-root")
        .arg(original);
    c
}
fn policy(root: &std::path::Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:external-replay-policy".into(),
        operation_id: OperationId::parse("operation:external-replay-policy")?,
        principal: "principal:test-owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(POLICY_SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    drop(ReferenceDeployment::open(root, POLICY_SITE, &cx)?);
    Ok(cx)
}

#[test]
fn external_policy_authority_is_named_in_native_report_without_rewriting_either_store() -> Test {
    let (directory, root, original, cx, tip) = prepared("external")?;
    let privacy = directory.0.join("privacy");
    let policy_cx = policy(&privacy)?;
    let before = ReferenceDeployment::reopen(&root, SITE, &cx)?
        .current_anchor()
        .clone();
    let policy_before = ReferenceDeployment::reopen(&privacy, POLICY_SITE, &policy_cx)?
        .current_anchor()
        .clone();
    let report = success(
        command(&root, &original, tip)
            .arg("--privacy-root")
            .arg(&privacy)
            .args(["--privacy-site", POLICY_SITE])
            .output()?,
    )?;
    assert!(report.contains(&format!("\"privacy_site\":\"{POLICY_SITE}\"")));
    assert!(report.contains("\"status\":\"configuration_only\""));
    assert!(report.contains("\"execution_attempts\":0"));
    assert!(report.contains("\"source_complete\":false"));
    assert_eq!(
        ReferenceDeployment::reopen(&root, SITE, &cx)?.current_anchor(),
        &before
    );
    assert_eq!(
        ReferenceDeployment::reopen(&privacy, POLICY_SITE, &policy_cx)?.current_anchor(),
        &policy_before
    );
    cx.drain_and_finalize();
    policy_cx.drain_and_finalize();
    Ok(())
}

#[test]
fn missing_or_wrong_external_policy_authority_never_falls_back_to_history_policy() -> Test {
    let (directory, root, original, cx, tip) = prepared("missing-external")?;
    let privacy = directory.0.join("absent-policy");
    let refused = command(&root, &original, tip)
        .arg("--privacy-root")
        .arg(&privacy)
        .args(["--privacy-site", POLICY_SITE])
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(!privacy.exists());
    let policy_cx = policy(&privacy)?;
    let wrong = command(&root, &original, tip)
        .arg("--privacy-root")
        .arg(&privacy)
        .args(["--privacy-site", "site:not-the-policy-owner"])
        .output()?;
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    assert!(ReferenceDeployment::reopen(&privacy, POLICY_SITE, &policy_cx).is_ok());
    cx.drain_and_finalize();
    policy_cx.drain_and_finalize();
    Ok(())
}

#[test]
fn aliased_history_as_external_policy_is_refused_before_a_second_lock() -> Test {
    let (_directory, root, original, cx, tip) = prepared("overlap")?;
    for alias in [root.clone(), root.join(".")] {
        let refused = command(&root, &original, tip)
            .arg("--privacy-root")
            .arg(alias)
            .args(["--privacy-site", SITE])
            .output()?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
    }
    assert!(ReferenceDeployment::reopen(&root, SITE, &cx).is_ok());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn explicit_wire_tip_cannot_manufacture_source_for_configuration_only_history() -> Test {
    let (_directory, root, original, cx, tip) = prepared("empty-wire")?;
    let head = ContentDigest::sha256(b"unretained source").to_text();
    let refused = command(&root, &original, tip)
        .args([
            "--wire-head",
            &head,
            "--wire-reads",
            "1",
            "--wire-bytes",
            "100",
        ])
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-HTTP-RGB-REPLAY-MISMATCH-001"));
    let normal = success(command(&root, &original, tip).output()?)?;
    assert!(normal.contains("\"status\":\"configuration_only\""));
    cx.drain_and_finalize();
    Ok(())
}
