#![forbid(unsafe_code)]
//! Source-backed case revisions share durable custody requirements and disclosure replay state.

use super::*;
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationError, SourceCitationError, SourceCitationTarget,
};

mod inspection;

fn target(revision: &InvestigationRevision) -> SourceCitationTarget {
    SourceCitationTarget {
        case_id: revision.record().investigation_id.clone(), expected: revision.digest(),
        hypothesis: "hypothesis:a".into(), contradicts: false,
    }
}

fn inspect(f: &Fixture, owner: &mut DurableDisclosureStore) -> Value<InvestigationRevision> {
    Ok(owner.investigate(&f.params.principal_id, &f.params.session_id,
        InvestigationCommand::Inspect { case_id: "case:source".into(), revision: None }, TimestampNs(20))?)
}

#[test]
fn source_backed_citation_retains_its_charge_scope_and_case_across_restart() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let destination = target(&initial);
    let request = f.request(HydrationLevel::H3)?;
    let receipt = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20))?;
    assert_eq!(receipt.acquisition().subject_digest(), f.handle.subject_digest);
    assert_eq!(receipt.acquisition().publication_root(), f.root);
    assert_eq!(receipt.acquisition().charged_tokens(), 2);
    assert_ne!(receipt.acquisition().charged_root(), owner.committed_root());
    assert_eq!(receipt.revision().record().hypotheses[0].evidence, vec![f.handle.subject_digest]);
    assert_eq!(receipt.revision().record().hypotheses[0].epistemic_state, KnowledgeState::Unknown);
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(f.remaining(&mut owner)?, 62);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert_eq!(inspect(&f, &mut owner)?, *receipt.revision());
    assert_eq!(f.reader.reads.get(), 1);
    assert!(matches!(owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &destination, &request, &f.reader, TimestampNs(20)),
        Err(SourceCitationError::Preflight(DurableInvestigationError::Refused(InvestigationError::StaleRevision)))));
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(f.remaining(&mut owner)?, 62);
    let mut counter = target(receipt.revision());
    counter.contradicts = true;
    let counter = owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &counter, &request, &f.reader, TimestampNs(20))?;
    assert_eq!(counter.revision().record().hypotheses[0].contradictions, vec![f.handle.subject_digest]);
    assert_eq!(counter.revision().record().hypotheses[0].evidence, vec![f.handle.subject_digest]);
    assert_eq!(f.remaining(&mut owner)?, 60);
    f.no_source_in_journal()
}

#[test]
fn volatile_and_foreign_checkpoint_pins_are_not_this_journals_commitment() -> Value {
    for imported in [false, true] {
        let (f, original) = Fixture::new()?;
        drop(original);
        let mut catalog = f.catalog.clone();
        if imported {
            let bytes = catalog.checkpoint_cursors(TimestampNs(10), 65536)?;
            catalog.restore_cursor_checkpoint(&bytes, 65536, TimestampNs(10))?;
            assert!(catalog.source_binding_requirement(f.handle.descriptor_digest).is_some());
        }
        let path = f.directory.0.join("unregistered.fssj");
        let mut owner = DurableDisclosureStore::create(&path, DurableSessionLimits::default(), catalog)?;
        owner.open_session(f.params.clone(), f.handle.contract_basis.clone(), TimestampNs(10))?;
        let alias = owner.bind(&f.params.principal_id, &SessionBindingRequest {
            session_id: f.params.session_id.clone(), generation: 0,
            handle_id: f.handle.handle_id.clone(), descriptor_digest: f.handle.descriptor_digest,
        }, TimestampNs(10))?;
        owner.enable_coordination(ceilings())?;
        owner.enable_investigations(InvestigationLimits::default())?;
        let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
        let root = owner.committed_root();
        let before = fs::read(&path)?;
        assert!(matches!(owner.cite_investigation_source(&f.params.principal_id, &alias,
            &target(&initial), &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20)),
            Err(SourceCitationError::Preflight(DurableInvestigationError::Refused(InvestigationError::EvidenceRequired)))));
        assert_eq!(fs::read(&path)?, before);
        assert_eq!(owner.committed_root(), root);
        assert_eq!(f.reader.reads.get(), 0);
        assert_eq!(f.remaining(&mut owner)?, 64);
        owner.bind_source_object_durable(&f.handle.handle_id, f.handle.descriptor_digest, f.root, &f.reader, TimestampNs(20))?;
        owner.cite_investigation_source(&f.params.principal_id, &alias,
            &target(&initial), &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20))?;
        assert_eq!(f.reader.reads.get(), 2); // Explicit registration plus a fresh acquisition.
        assert_eq!(f.remaining(&mut owner)?, 62);
    }
    Ok(())
}

#[test]
fn mismatched_case_principal_and_downgrade_refuse_before_source_acquisition() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    for scenario in 0..4 {
        let mut destination = target(&initial);
        let mut request = f.request(HydrationLevel::H3)?;
        let other = PrincipalId::parse("principal:other")?;
        let principal = if scenario == 0 { &other } else { &f.params.principal_id };
        if scenario == 1 { destination.expected = ContentDigest::sha256(b"not the current case"); }
        if scenario == 2 { request.allow_lower_level = true; }
        if scenario == 3 { destination.hypothesis = "hypothesis:absent".into(); }
        request.request_digest = request.computed_digest();
        request.request_id = format!("hydration-request:{}", request.request_digest);
        let root = owner.committed_root();
        assert!(owner.cite_investigation_source(principal, &f.alias, &destination, &request, &f.reader, TimestampNs(20)).is_err());
        assert_eq!(owner.committed_root(), root);
        assert_eq!(f.reader.reads.get(), 0);
        assert_eq!(f.remaining(&mut owner)?, 64);
    }
    Ok(())
}

#[test]
fn link_capacity_refusal_retains_the_acquisition_charge_without_retrying_source() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    // Admit the existing acquisition checkpoint but no additional citation record.
    owner.sessions.limits.max_records = owner.sessions.records + 1;
    let acquisition = match owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &target(&initial), &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20)) {
        Err(SourceCitationError::Link { acquisition, cause: DurableInvestigationError::Durability(DurableSessionError::CapacityExceeded) }) => acquisition,
        result => return Err(format!("expected charged link refusal, got {result:?}").into()),
    };
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(acquisition.charged_root(), owner.committed_root());
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert_eq!(f.remaining(&mut owner)?, 62);
    assert_eq!(inspect(&f, &mut owner)?, initial);
    assert_eq!(f.reader.reads.get(), 1);
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some());
    f.no_source_in_journal()
}

#[test]
fn acquisition_append_uncertainty_never_publishes_a_case_revision() -> Value {
    for (phase, committed) in [(AppendPhase::BodySync, false), (AppendPhase::CommitSync, true)] {
        let (f, mut owner) = Fixture::new()?;
        let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
        owner.sessions.journal.fail_after_phase(phase);
        assert!(matches!(owner.cite_investigation_source(&f.params.principal_id, &f.alias,
            &target(&initial), &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20)),
            Err(SourceCitationError::Acquisition(_))));
        assert!(owner.needs_reconciliation());
        assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20)).is_err());
        owner.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        assert_eq!(inspect(&f, &mut owner)?, initial);
        assert_eq!(f.remaining(&mut owner)?, if committed { 62 } else { 64 });
        assert_eq!(f.reader.reads.get(), 1);
        let root = owner.committed_root();
        drop(owner);
        let mut owner = f.reopen(root)?;
        assert_eq!(inspect(&f, &mut owner)?, initial);
        assert_eq!(f.reader.reads.get(), 1);
        f.no_source_in_journal()?;
    }
    Ok(())
}

#[test]
fn case_acquisition_preserves_an_existing_disclosure_continuation_through_restart() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let initial = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let preview = owner.hydrate(&f.params.principal_id, &f.alias, &f.request(HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = preview.response.receipt.continuation.ok_or("no continuation")?;
    owner.cite_investigation_source(&f.params.principal_id, &f.alias,
        &target(&initial), &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20))?;
    assert!(!owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert_eq!(f.remaining(&mut owner)?, 60);
    let mut request = f.request(HydrationLevel::H3)?;
    request.continuation = Some(cursor.clone());
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
    owner.hydrate_from_source(&f.params.principal_id, &f.alias, &request, &f.reader, TimestampNs(20))?;
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert_eq!(f.remaining(&mut owner)?, 58);
    assert!(owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert!(owner.hydrate_from_source(&f.params.principal_id, &f.alias, &request, &f.reader, TimestampNs(20)).is_err());
    assert_eq!(f.reader.reads.get(), 2);
    f.no_source_in_journal()
}
