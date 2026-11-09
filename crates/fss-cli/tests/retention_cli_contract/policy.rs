#![forbid(unsafe_code)]
//! Real CLI policy adoption and exact policy-bound local cleanup.

use super::*;
use fss_reference::deletion::retention::policy::request_from_policy;

fn policy_change(
    root: &Path,
    verb: &str,
    state: &str,
    expected: Option<ContentDigest>,
    approval: Option<ContentDigest>,
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.args(["delete", verb, "--root"]).arg(root).args([
        "--site",
        SITE,
        "--sensor-id",
        SENSOR,
        "--state",
        state,
        "--retain-for-ns",
        &KEEP_NS.to_string(),
        "--max-retained-source-bytes",
        "0",
        "--expected-policy",
        &expected.map_or_else(|| "none".to_owned(), |pin| pin.to_text()),
        "--attested-now-ns",
        &format!("{NOW}:{NOW}"),
        "--reason",
        "Owner's reviewed file cleanup",
    ]);
    if let Some(approval) = approval {
        command.args(["--approve", &approval.to_text()]);
    }
    output(&mut command)
}

fn policy_cleanup(
    root: &Path,
    verb: &str,
    pin: ContentDigest,
    now: i128,
    approval: Option<(ContentDigest, ContentDigest)>,
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.args(["delete", verb, "--root"]).arg(root).args([
        "--site",
        SITE,
        "--policy",
        &pin.to_text(),
        "--attested-now-ns",
        &format!("{now}:{now}"),
    ]);
    if let Some((plan, approval)) = approval {
        command.args(["--plan", &plan.to_text(), "--approve", &approval.to_text()]);
    }
    output(&mut command)
}

fn policy_show(root: &Path) -> TestResult<Output> {
    output(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["delete", "policy-show", "--root"])
            .arg(root)
            .args(["--site", SITE, "--sensor-id", SENSOR]),
    )
}

#[test]
fn cli_adopts_inspects_and_executes_exact_policy_bound_cleanup_with_cold_retry() -> TestResult {
    let dir = Directory::new("policy-cleanup")?;
    let old = import(&dir, "old", SENSOR, Some(1_000_000_000), &movie(40)?)?;
    let young = import(&dir, "young", SENSOR, Some(9_000_000_000), &movie(80)?)?;
    let root = dir.root();
    let before = files(&root)?;
    let proposed = policy_change(&root, "policy-plan", "enabled", None, None)?;
    success(&proposed);
    let text = std::str::from_utf8(&proposed.stdout)?;
    assert!(text.contains("\"format\":\"fss.retention_policy_cli.v1\""));
    assert!(text.contains("\"automatic_deletion_authorized\":false"));
    assert!(text.contains("\"deletion_authorized\":false"));
    assert!(text.contains("--expected-policy none"));
    assert!(text.contains("--max-retained-source-bytes 0"));
    assert!(text.contains("policy-commit"));
    let pin = digest_field(&proposed, "policy_digest")?;
    let adoption_approval = digest_field(&proposed, "approval_digest")?;
    assert_eq!(files(&root)?, before);
    let adopted = policy_change(
        &root,
        "policy-commit",
        "enabled",
        None,
        Some(adoption_approval),
    )?;
    success(&adopted);
    assert_eq!(digest_field(&adopted, "policy_digest")?, pin);
    assert!(std::str::from_utf8(&adopted.stdout)?.contains("\"media_deleted\":false"));
    {
        let cx = context(&root)?;
        let deployment = open(&root, &cx)?;
        assert!(DeletionIndex::read(&deployment)?.entries().is_empty());
        for identity in [old, young] {
            RetainedFileImport::open(&deployment, identity, RetainedReadLimits::default(), &cx)?;
        }
    }
    let current = policy_show(&root)?;
    assert_eq!(digest_field(&current, "policy_digest")?, pin);
    let after_adoption = files(&root)?;
    let repeat = policy_change(
        &root,
        "policy-commit",
        "enabled",
        None,
        Some(adoption_approval),
    )?;
    success(&repeat);
    assert!(std::str::from_utf8(&repeat.stdout)?.contains("\"outcome\":\"already_current\""));
    assert_eq!(files(&root)?, after_adoption);
    let preview = policy_cleanup(&root, "retention-plan", pin, NOW, None)?;
    success(&preview);
    let text = std::str::from_utf8(&preview.stdout)?;
    assert!(text.contains("\"format\":\"fss.retention_selection.v4\""));
    assert!(text.contains(&format!("--policy {pin} --attested-now-ns {NOW}:{NOW}")));
    assert!(!text.contains("--sensor-id"));
    assert!(!text.contains("--retain-for-ns"));
    assert!(!text.contains("--max-retained-source-bytes"));
    assert!(text.contains("\"max_retained_source_bytes\":\"0\""));
    let plan = digest_field(&preview, "plan_digest")?;
    let approval = digest_field(&preview, "approval_digest")?;
    {
        let cx = context(&root)?;
        let deployment = open(&root, &cx)?;
        let request = request_from_policy(
            &deployment,
            pin,
            CaptureInterval::new(TimestampNs(NOW), TimestampNs(NOW))?,
            &cx,
        )?;
        let prepared = plan_retention(&deployment, &request, &cx)?
            .deletion
            .ok_or("plan")?;
        assert_eq!(prepared.digest()?, plan);
        assert_eq!(prepared.imports, vec![old]);
    }
    refused(
        &policy_cleanup(
            &root,
            "retention-commit",
            pin,
            NOW + 1,
            Some((plan, approval)),
        )?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    assert_eq!(files(&root)?, after_adoption);
    success(&policy_cleanup(
        &root,
        "retention-commit",
        pin,
        NOW,
        Some((plan, approval)),
    )?);
    {
        let cx = context(&root)?;
        let deployment = open(&root, &cx)?;
        assert!(DeletionIndex::read(&deployment)?.import(old).is_some());
        RetainedFileImport::open(&deployment, young, RetainedReadLimits::default(), &cx)?;
    }
    let after = files(&root)?;
    let retry = policy_cleanup(&root, "retention-commit", pin, NOW, Some((plan, approval)))?;
    success(&retry);
    assert!(std::str::from_utf8(&retry.stdout)?.contains("\"outcome\":\"already_complete\""));
    assert_eq!(files(&root)?, after);
    Ok(())
}

#[test]
fn cli_refuses_stale_adoption_and_disabled_or_superseded_policy_without_writes() -> TestResult {
    let dir = Directory::new("policy-stale")?;
    import(&dir, "old", SENSOR, Some(1_000_000_000), &movie(40)?)?;
    let root = dir.root();
    let stale = policy_change(&root, "policy-plan", "enabled", None, None)?;
    let stale_approval = digest_field(&stale, "approval_digest")?;
    import(&dir, "later", SENSOR, Some(2_000_000_000), &movie(80)?)?;
    let before = files(&root)?;
    refused(
        &policy_change(
            &root,
            "policy-commit",
            "enabled",
            None,
            Some(stale_approval),
        )?,
        "ERR-RETENTION-POLICY-APPROVAL-001",
    );
    assert_eq!(files(&root)?, before);
    let proposed = policy_change(&root, "policy-plan", "enabled", None, None)?;
    let approval = digest_field(&proposed, "approval_digest")?;
    let first = digest_field(&proposed, "policy_digest")?;
    success(&policy_change(
        &root,
        "policy-commit",
        "enabled",
        None,
        Some(approval),
    )?);
    let old_preview = policy_cleanup(&root, "retention-plan", first, NOW, None)?;
    let plan = digest_field(&old_preview, "plan_digest")?;
    let approval = digest_field(&old_preview, "approval_digest")?;
    let disabled = policy_change(&root, "policy-plan", "disabled", Some(first), None)?;
    let disable_approval = digest_field(&disabled, "approval_digest")?;
    let second = digest_field(&disabled, "policy_digest")?;
    success(&policy_change(
        &root,
        "policy-commit",
        "disabled",
        Some(first),
        Some(disable_approval),
    )?);
    let before = files(&root)?;
    refused(
        &policy_cleanup(&root, "retention-plan", first, NOW, None)?,
        "ERR-RETENTION-POLICY-STALE-001",
    );
    refused(
        &policy_cleanup(&root, "retention-plan", second, NOW, None)?,
        "ERR-RETENTION-POLICY-STALE-001",
    );
    refused(
        &policy_cleanup(
            &root,
            "retention-commit",
            first,
            NOW,
            Some((plan, approval)),
        )?,
        "ERR-RETENTION-POLICY-STALE-001",
    );
    refused(
        &policy_change(&root, "policy-plan", "enabled", Some(first), None)?,
        "ERR-RETENTION-POLICY-STALE-001",
    );
    let shown = policy_show(&root)?;
    success(&shown);
    assert_eq!(digest_field(&shown, "policy_digest")?, second);
    assert!(std::str::from_utf8(&shown.stdout)?.contains("\"state\":\"disabled\""));
    assert!(std::str::from_utf8(&shown.stdout)?.contains("\"generation\":\"2\""));
    assert_eq!(files(&root)?, before);
    Ok(())
}
