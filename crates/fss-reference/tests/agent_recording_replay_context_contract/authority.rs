#![forbid(unsafe_code)]

use super::*;
use std::sync::atomic::AtomicI64;

#[test]
fn absent_or_mismatched_source_permits_refuse_before_either_owner_is_read() -> TestResult {
    let f = Fixture::new("context-source-permit")?;
    let limits = RecordingReplayContextLimits::default();
    let authority = f.authority(&limits)?;
    let now = || TimestampNs(0);
    let permit = ReplaySourceReadPermit::authorize(&authority, &f.request, limits.replay, &now)?;
    let io = ReadOnlyIo::default();
    let missing = path("not-a-deployment");
    assert!(matches!(
        query_recordings_replay_in_deployment(
            &io,
            &missing,
            &f.native.root,
            &f.request,
            &limits,
            None,
            &|| false,
        ),
        Err(E::Unauthorized)
    ));
    for case in 0..6 {
        let mut request = f.request.clone();
        let mut changed = limits;
        match case {
            0 => request.principal = PrincipalId::parse("principal:another-owner")?,
            1 => request.replay.receipt_root = ContentDigest::sha256(b"another-receipt"),
            2 => request.replay.ntp_era += 1,
            3 => request.replay.end_ns += 1,
            4 => changed.replay.originals.max_io_calls -= 1,
            _ => request.replay.limits.max_results -= 1,
        }
        assert!(
            matches!(
                query_recordings_replay_in_deployment(
                    &io,
                    &missing,
                    &f.native.root,
                    &request,
                    &changed,
                    Some(&permit),
                    &|| false,
                ),
                Err(E::Unauthorized)
            ),
            "case {case}"
        );
    }
    assert_eq!(io.calls.load(Ordering::SeqCst), 0);
    assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn query_capability_and_historical_pins_cannot_authorize_source_reads() -> TestResult {
    let f = Fixture::new("context-source-grant")?;
    let limits = RecordingReplayContextLimits::default();
    let base = f.authority(&limits)?;
    let now = || TimestampNs(10);
    let metadata_only = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: base.trace_id.clone(),
        operation_id: base.operation_id.clone(),
        principal: base.principal.clone(),
        capabilities: vec![RuntimeGrant::AgentQuery.as_str().to_owned()],
        deadline: base.deadline,
        priority: base.priority,
        budgets: base.budgets,
        privacy_scope: base.privacy_scope.clone(),
        retention_scope: base.retention_scope.clone(),
        anchor_universe: base.anchor_universe,
        generation: base.generation,
    })?;
    assert!(matches!(
        ReplaySourceReadPermit::authorize(&metadata_only, &f.request, limits.replay, &now),
        Err(E::Unauthorized)
    ));
    for case in 0..6 {
        let mut denied = base.clone();
        match case {
            0 => denied.principal = "principal:another-owner".to_owned(),
            1 => denied.anchor_universe = ContentDigest::sha256(b"another-source-universe"),
            2 => denied.generation += 1,
            3 => denied.cancellation_reason = Some("source grant revoked".to_owned()),
            4 => denied.deadline = Some(TimestampNs(10)),
            _ => denied.budgets = BudgetVector::default(),
        }
        assert!(
            matches!(
                ReplaySourceReadPermit::authorize(&denied, &f.request, limits.replay, &now),
                Err(E::Unauthorized)
            ),
            "case {case}"
        );
    }
    Ok(())
}

#[test]
fn source_deadline_and_revocation_stop_before_or_during_original_reads() -> TestResult {
    let f = Fixture::new("context-live-source-authority")?;
    let limits = RecordingReplayContextLimits::default();
    let mut authority = f.authority(&limits)?;
    authority.deadline = Some(TimestampNs(100));
    let clock = AtomicI64::new(0);
    let now = || TimestampNs(i128::from(clock.load(Ordering::SeqCst)));
    let permit = ReplaySourceReadPermit::authorize(&authority, &f.request, limits.replay, &now)?;
    clock.store(100, Ordering::SeqCst);
    let io = ReadOnlyIo::default();
    assert!(matches!(
        query_recordings_replay_in_deployment(
            &io,
            &f.deployment,
            &f.native.root,
            &f.request,
            &limits,
            Some(&permit),
            &|| false,
        ),
        Err(E::Unauthorized)
    ));
    assert_eq!(io.calls.load(Ordering::SeqCst), 0);

    clock.store(0, Ordering::SeqCst);
    let publisher = f.native.open()?;
    let source = publisher
        .spool()
        .object_path(f.native.receipt.windows()[0].original_leaf_digests()[0]);
    let io = ReadOnlyIo::default();
    let cancelled = || {
        if io.opened_count(&source) > 0 {
            clock.store(100, Ordering::SeqCst);
        }
        false
    };
    let error = query_recordings_replay_in_deployment(
        &io,
        &f.deployment,
        &f.native.root,
        &f.request,
        &limits,
        Some(&permit),
        &cancelled,
    )
    .err()
    .ok_or("expired original retrieval must refuse")?;
    assert!(
        matches!(error, E::Replay(ref error) if error.code() == "ERR-REPLAY-TIME-CANCELLED-001")
    );
    assert_eq!(io.opened_count(&source), 1);
    assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn stable_grant_identity_excludes_process_clocks_but_binds_privacy_and_read_ceilings() -> TestResult
{
    let f = Fixture::new("context-stable-source-grant")?;
    let limits = RecordingReplayContextLimits::default();
    let base = f.authority(&limits)?;
    let now = || TimestampNs(1);
    let original = ReplaySourceReadPermit::authorize(&base, &f.request, limits.replay, &now)?;
    let mut other_process = base.clone();
    other_process.trace_id = "trace:another-query-process".to_owned();
    other_process.operation_id = OperationId::parse("operation:another-query-process")?;
    other_process.deadline = Some(TimestampNs(99));
    let repeated =
        ReplaySourceReadPermit::authorize(&other_process, &f.request, limits.replay, &now)?;
    assert_eq!(original.digest(), repeated.digest());
    let mut changed = base.clone();
    changed.privacy_scope = "privacy:another-source-domain".to_owned();
    let new_scope = ReplaySourceReadPermit::authorize(&changed, &f.request, limits.replay, &now)?;
    assert_ne!(original.digest(), new_scope.digest());
    let mut fewer = limits.replay;
    fewer.originals.max_io_calls -= 1;
    let narrower = ReplaySourceReadPermit::authorize(&base, &f.request, fewer, &now)?;
    assert_ne!(original.digest(), narrower.digest());
    Ok(())
}
