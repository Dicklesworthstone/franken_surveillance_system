#![forbid(unsafe_code)]
//! Real immutable retention reads while the native writer remains open.

use super::*;
use fss_reference::deletion::holds::{HoldError, list_holds};
use fss_reference::deletion::inspection::{
    STAGE_INSPECTION_FINAL, inspect_holds, inspect_policies, inspection_limits,
};
use fss_reference::deletion::retention::policy::{
    PolicyChangeRequest, PolicyError, RetentionPolicyRecord, commit_policy_change, list_policies,
    preview_policy_change,
};
use fss_reference::retained_source::ImmutableRetainedReadLimits;

fn limits() -> ImmutableRetainedReadLimits {
    let mut limits = inspection_limits();
    limits.max_read_bytes = 64 * 1024 * 1024;
    limits.max_read_objects = 8192;
    limits
}

fn read_cx(f: &Fixture) -> TestResult<ReplayCx> {
    Ok(ReplayCx::from_context_authority_read_only(
        &f.authority,
        f.deployment.root().to_path_buf(),
    )?)
}

fn adopt(f: &mut Fixture, prior: Option<ContentDigest>) -> TestResult<RetentionPolicyRecord> {
    let request = PolicyChangeRequest {
        sensor: SensorId::parse(SENSOR)?,
        enabled: true,
        retain_for_ns: if prior.is_some() { 200 } else { 100 },
        max_retained_source_bytes: Some(0),
        expected_policy: prior,
        attested_now: interval(1000, 1010)?,
        reason: "Owner retention settings".to_owned(),
    };
    let preview = preview_policy_change(&f.deployment, &request, &f.authority, &f.cx)?;
    Ok(commit_policy_change(
        &mut f.deployment,
        &request,
        preview.record.approval(),
        &f.authority,
        &f.cx,
    )?
    .record)
}

#[test]
fn native_records_match_with_writer_held_and_source_media_absent_without_repair() -> TestResult {
    let mut f = Fixture::new("immutable-retention-writer")?;
    let free = f.ingest("released", 40)?;
    let protected = f.ingest("deadline", 80)?;
    f.hold("released", free, HoldState::Held)?;
    f.hold("released", free, HoldState::Released)?;
    f.hold(
        "deadline",
        protected,
        HoldState::Until {
            not_before: TimestampNs(2000),
        },
    )?;
    let first = adopt(&mut f, None)?;
    assert!(first.affected_plan().is_some());
    let current = adopt(&mut f, Some(first.digest()))?;
    let expected_holds = list_holds(&f.deployment, &f.authority, &f.cx)?;
    let expected_policies = list_policies(&f.deployment, &f.authority, &f.cx)?;
    assert_eq!(expected_policies, [current]);
    fs::write(
        f.deployment
            .root()
            .join("LAYOUT.tmp.inspection-must-preserve"),
        b"no recovery",
    )?;
    // Policy and hold records remain inspectable even when the original recording is absent.
    // This endpoint does not claim that recording custody or coverage was verified.
    for source in [free.source, protected.source] {
        fs::remove_file(f.deployment.publisher().spool().object_path(source))?;
    }
    let before = snapshot(f.deployment.root())?;
    let cx = read_cx(&f)?;
    let held = inspect_holds(f.deployment.root(), &f.authority, limits(), &cx, &|| false)?;
    let policies = inspect_policies(f.deployment.root(), &f.authority, limits(), &cx, &|| false)?;
    assert_eq!(held.records, expected_holds);
    assert_eq!(policies.records, expected_policies);
    assert_eq!(&held.anchor, f.deployment.current_anchor());
    assert_eq!(&policies.anchor, f.deployment.current_anchor());
    assert!(held.read_usage.read_bytes > 0 && held.read_usage.read_objects > 0);
    assert!(policies.read_usage.read_bytes > 0 && policies.read_usage.read_objects > 0);
    assert_eq!(snapshot(f.deployment.root())?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn exact_complete_allowance_succeeds_but_one_missing_byte_or_read_refuses() -> TestResult {
    let mut f = Fixture::new("immutable-retention-budget")?;
    let import = f.ingest("source", 40)?;
    f.hold("incident", import, HoldState::Held)?;
    adopt(&mut f, None)?;
    let before = snapshot(f.deployment.root())?;
    let cx = read_cx(&f)?;
    let held = inspect_holds(f.deployment.root(), &f.authority, limits(), &cx, &|| false)?;
    let policies = inspect_policies(f.deployment.root(), &f.authority, limits(), &cx, &|| false)?;
    for policy in [false, true] {
        let usage = if policy {
            policies.read_usage
        } else {
            held.read_usage
        };
        let mut exact = limits();
        exact.max_read_bytes = usize::try_from(usage.read_bytes)?;
        exact.max_read_objects = usize::try_from(usage.read_objects)?;
        let run = |limit| -> bool {
            if policy {
                inspect_policies(f.deployment.root(), &f.authority, limit, &cx, &|| false).is_ok()
            } else {
                inspect_holds(f.deployment.root(), &f.authority, limit, &cx, &|| false).is_ok()
            }
        };
        assert!(run(exact));
        let mut short = exact;
        short.max_read_bytes -= 1;
        assert!(!run(short), "final byte allowance must not replenish");
        short = exact;
        short.max_read_objects -= 1;
        assert!(!run(short), "final read allowance must not replenish");
    }
    assert_eq!(snapshot(f.deployment.root())?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn history_records_and_policy_impact_are_required_even_for_terminal_or_superseded_state()
-> TestResult {
    let mut f = Fixture::new("immutable-retention-custody")?;
    let import = f.ingest("source", 40)?;
    f.hold("incident", import, HoldState::Held)?;
    let placed = list_holds(&f.deployment, &f.authority, &f.cx)?.remove(0);
    f.hold("incident", import, HoldState::Released)?;
    let first = adopt(&mut f, None)?;
    let current = adopt(&mut f, Some(first.digest()))?;
    let impact = first.affected_plan().ok_or("retained impact plan")?;
    let cx = read_cx(&f)?;
    for (digest, policy) in [
        (placed.digest(), false),
        (first.digest(), true),
        (current.digest(), true),
        (impact, true),
    ] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let original = fs::read(&path)?;
        for damage in [None, Some(vec![0; original.len()])] {
            match damage {
                None => fs::remove_file(&path)?,
                Some(bytes) => fs::write(&path, bytes)?,
            }
            let before = snapshot(f.deployment.root())?;
            if policy {
                assert!(
                    inspect_policies(f.deployment.root(), &f.authority, limits(), &cx, &|| false)
                        .is_err()
                );
            } else {
                assert!(
                    inspect_holds(f.deployment.root(), &f.authority, limits(), &cx, &|| false)
                        .is_err()
                );
            }
            assert_eq!(snapshot(f.deployment.root())?, before);
            fs::write(&path, &original)?;
        }
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn admission_and_final_cancellation_never_create_or_modify_a_deployment() -> TestResult {
    let f = Fixture::new("immutable-retention-admission")?;
    let cx = read_cx(&f)?;
    let before = snapshot(f.deployment.root())?;
    for change in [0, 1] {
        let mut foreign = f.authority.clone();
        if change == 0 {
            foreign.principal = "principal:foreign".to_owned();
        } else {
            foreign.anchor_universe = ContentDigest::sha256(b"site:foreign");
        }
        assert!(matches!(
            inspect_holds(f.deployment.root(), &foreign, limits(), &cx, &|| false),
            Err(HoldError::Unauthorized)
        ));
        assert!(matches!(
            inspect_policies(f.deployment.root(), &foreign, limits(), &cx, &|| false),
            Err(PolicyError::Unauthorized)
        ));
    }
    let mut tight_authority = f.authority.clone();
    tight_authority.budgets.bytes = 1;
    assert!(matches!(
        inspect_holds(
            f.deployment.root(),
            &tight_authority,
            limits(),
            &cx,
            &|| false
        ),
        Err(HoldError::Limit)
    ));
    let mut enlarged = limits();
    enlarged.max_read_objects = inspection_limits().max_read_objects + 1;
    assert!(matches!(
        inspect_policies(f.deployment.root(), &f.authority, enlarged, &cx, &|| false),
        Err(PolicyError::Limit)
    ));
    assert!(matches!(
        inspect_holds(f.deployment.root(), &f.authority, limits(), &cx, &|| true),
        Err(HoldError::Cancelled)
    ));
    for policy in [false, true] {
        let fresh = read_cx(&f)?;
        fresh.set_cancel_at_checkpoint(STAGE_INSPECTION_FINAL);
        if policy {
            assert!(matches!(
                inspect_policies(f.deployment.root(), &f.authority, limits(), &fresh, &|| {
                    false
                }),
                Err(PolicyError::Cancelled)
            ));
        } else {
            assert!(matches!(
                inspect_holds(f.deployment.root(), &f.authority, limits(), &fresh, &|| {
                    false
                }),
                Err(HoldError::Cancelled)
            ));
        }
        fresh.drain_and_finalize();
    }
    let absent = f.directory.0.join("must-not-create");
    let absent_cx = ReplayCx::from_context_authority_read_only(&f.authority, absent.clone())?;
    assert!(inspect_holds(&absent, &f.authority, limits(), &absent_cx, &|| false).is_err());
    assert!(inspect_policies(&absent, &f.authority, limits(), &absent_cx, &|| false).is_err());
    assert!(!absent.exists());
    assert_eq!(snapshot(f.deployment.root())?, before);
    cx.drain_and_finalize();
    absent_cx.drain_and_finalize();
    Ok(())
}

#[test]
fn torn_ledger_or_effect_journal_is_refused_without_recovery_or_empty_result() -> TestResult {
    for journal in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let f = Fixture::new("immutable-retention-torn-tail")?;
        let cx = read_cx(&f)?;
        let path = f.deployment.root().join(journal);
        let mut bytes = fs::read(&path)?;
        bytes.extend_from_slice(b"torn");
        fs::write(path, bytes)?;
        let before = snapshot(f.deployment.root())?;
        assert!(
            inspect_holds(f.deployment.root(), &f.authority, limits(), &cx, &|| false).is_err()
        );
        assert!(
            inspect_policies(f.deployment.root(), &f.authority, limits(), &cx, &|| false).is_err()
        );
        assert_eq!(snapshot(f.deployment.root())?, before);
        cx.drain_and_finalize();
    }
    Ok(())
}
