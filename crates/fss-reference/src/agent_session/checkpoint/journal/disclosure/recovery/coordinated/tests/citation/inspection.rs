#![forbid(unsafe_code)]
//! Historical source receipts remain inspectable through the single disclosure/case owner.

use super::*;
use crate::agent_session::checkpoint::journal::coordination::investigations::SourceCitationInspection;

const CEILING: usize = 2 * 1024 * 1024;

fn lookup(
    f: &Fixture, owner: &mut DurableDisclosureStore, destination: &SourceCitationTarget,
    request: &HydrationRequest, maximum: usize,
) -> Value<SourceCitationInspection> {
    Ok(owner.inspect_source_citation(&f.params.principal_id, &f.params.session_id,
        destination, request.request_digest, maximum, TimestampNs(20))?)
}

#[test]
fn lost_transport_acknowledgement_can_be_recovered_without_source_or_descriptor() -> Value {
    let (mut f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let destination = target(&initial);
    let request = f.request(HydrationLevel::H3)?;
    let receipt = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20))?;
    let root = owner.committed_root();
    let expected = receipt.digest(); // Test oracle; a real lost-ack caller needs only target/request.
    drop(receipt);
    drop(owner);
    f.reader.objects = InMemoryObjectStore::new(ObjectLimits::default());
    let mut owner = DurableDisclosureStore::open_existing_with_coordination(f.path(), root,
        DurableSessionLimits::default(), ceilings(), ReferenceHydrationCatalog::new())?;
    let result = lookup(&f, &mut owner, &destination, &request, CEILING)?;
    assert_eq!(result.citation_root(), Some(root));
    assert_eq!(result.receipt().ok_or("committed receipt was lost")?.digest(), expected);
    assert_eq!(result.inspected_root(), owner.committed_root());
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(f.remaining(&mut owner)?, 62);
    assert!(owner.catalog().current_descriptor(&f.handle.handle_id).is_none());
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some());
    assert_eq!(owner.catalog().stored_payload_bytes(), 0);
    f.no_source_in_journal()
}

#[test]
fn inspection_preserves_live_and_consumed_continuations_across_repeated_restart() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let preview = owner.hydrate(&f.params.principal_id, &f.alias, &f.request(HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = preview.response.receipt.continuation.ok_or("missing continuation")?;
    let destination = target(&initial);
    let request = f.request(HydrationLevel::H3)?;
    let receipt = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20))?;
    let before = owner.catalog().checkpoint_cursors(TimestampNs(20), 65536)?;
    assert_eq!(lookup(&f, &mut owner, &destination, &request, CEILING)?.receipt(), Some(&receipt));
    assert_eq!(owner.catalog().checkpoint_cursors(TimestampNs(20), 65536)?, before);
    assert_eq!(f.remaining(&mut owner)?, 60);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    let mut continued = request.clone();
    continued.continuation = Some(cursor.clone());
    continued.request_digest = continued.computed_digest();
    continued.request_id = format!("hydration-request:{}", continued.request_digest);
    owner.hydrate_from_source(&f.params.principal_id, &f.alias, &continued, &f.reader, TimestampNs(20))?;
    let before = owner.catalog().checkpoint_cursors(TimestampNs(20), 65536)?;
    assert_eq!(lookup(&f, &mut owner, &destination, &request, CEILING)?.receipt(), Some(&receipt));
    assert_eq!(owner.catalog().checkpoint_cursors(TimestampNs(20), 65536)?, before);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert!(owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert!(owner.hydrate_from_source(&f.params.principal_id, &f.alias, &continued, &f.reader, TimestampNs(20)).is_err());
    assert_eq!(f.reader.reads.get(), 2);
    assert_eq!(f.remaining(&mut owner)?, 58);
    f.no_source_in_journal()
}

#[test]
fn new_case_reader_can_inspect_without_reviving_the_closed_source_session() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let destination = target(&initial);
    let request = f.request(HydrationLevel::H3)?;
    let receipt = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20))?;
    owner.close(&f.params.principal_id, &f.params.session_id, TimestampNs(20))?;
    let mut observer = f.params.clone();
    observer.session_id = SessionId::parse("session:inspection-only")?;
    observer.capabilities = BTreeSet::from([CAPABILITY_INVESTIGATE.into()]);
    owner.open_session(observer.clone(), f.handle.contract_basis.clone(), TimestampNs(20))?;
    let root = owner.committed_root();
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing_with_coordination(f.path(), root,
        DurableSessionLimits::default(), ceilings(), ReferenceHydrationCatalog::new())?;
    let result = owner.inspect_source_citation(&observer.principal_id, &observer.session_id,
        &destination, request.request_digest, CEILING, TimestampNs(20))?;
    assert_eq!(result.receipt(), Some(&receipt));
    assert_eq!(owner.remaining_token_budget(&observer.principal_id, &observer.session_id, TimestampNs(20))?, 64);
    assert!(lookup(&f, &mut owner, &destination, &request, CEILING).is_err());
    assert_eq!(f.reader.reads.get(), 1);
    Ok(())
}

#[test]
fn uncertain_inspection_fences_disclosure_and_claims_until_joint_reconciliation() -> Value {
    for (phase, committed) in [(AppendPhase::BodySync, false), (AppendPhase::CommitSync, true)] {
        let (f, mut owner) = Fixture::new()?;
        let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
        let destination = target(&initial);
        let request = f.request(HydrationLevel::H3)?;
        let receipt = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
            &destination, &request, &f.reader, TimestampNs(20))?;
        owner.sessions.journal.fail_after_phase(phase);
        assert!(lookup(&f, &mut owner, &destination, &request, CEILING).is_err());
        assert!(owner.needs_reconciliation());
        assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20)).is_err());
        assert!(owner.hydrate_from_source(&f.params.principal_id, &f.alias, &request, &f.reader, TimestampNs(20)).is_err());
        assert_eq!(owner.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
        let root = owner.committed_root();
        drop(owner);
        let mut owner = f.reopen(root)?;
        assert_eq!(lookup(&f, &mut owner, &destination, &request, CEILING)?.receipt(), Some(&receipt));
        assert_eq!(f.reader.reads.get(), 1);
        assert_eq!(f.remaining(&mut owner)?, 62);
    }
    Ok(())
}

#[test]
fn charged_but_unlinked_restart_returns_no_receipt_without_refund_or_read() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let destination = target(&initial);
    let request = f.request(HydrationLevel::H3)?;
    owner.sessions.limits.max_records = owner.sessions.records + 1;
    assert!(matches!(owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20)), Err(SourceCitationError::Link { .. })));
    let root = owner.committed_root();
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing_with_coordination(f.path(), root,
        DurableSessionLimits::default(), ceilings(), ReferenceHydrationCatalog::new())?;
    let result = lookup(&f, &mut owner, &destination, &request, 0)?;
    assert!(result.receipt().is_none());
    assert!(result.citation_root().is_none());
    assert_eq!(f.remaining(&mut owner)?, 62);
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(inspect(&f, &mut owner)?, initial);
    Ok(())
}

#[test]
fn torn_later_work_recovers_then_inspects_the_prior_citation_without_custody() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let destination = target(&initial);
    let request = f.request(HydrationLevel::H3)?;
    let receipt = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20))?;
    let root = owner.committed_root();
    owner.sessions.journal.fail_after_phase(AppendPhase::BodySync);
    assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20)).is_err());
    drop(owner);
    let (mut owner, recovery) = DurableDisclosureStore::recover_existing_with_coordination(f.path(), root,
        DurableSessionLimits::default(), ceilings(), IncompleteTailPolicy::Truncate, ReferenceHydrationCatalog::new())?;
    assert!(recovery.discarded_bytes() > 0);
    assert_eq!(lookup(&f, &mut owner, &destination, &request, CEILING)?.receipt(), Some(&receipt));
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(f.remaining(&mut owner)?, 62);
    f.no_source_in_journal()
}
