#![forbid(unsafe_code)]
//! Real citation journals, including completed links whose acknowledgements were lost.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::agent_session::checkpoint::journal::{SessionAppendRecovery, SESSION_CHECKPOINT_RECORD_KIND};
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationLimits, CAPABILITY_INVESTIGATE,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::tests::{basis, opening, params};
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::agent_session::SessionBindingRequest;
use fss_core::{
    AgentSessionParams, BudgetVector, HandleAvailability, HydrationPurpose, HydrationRequestSpec,
    LaboratoryAccess, MissionId, SemanticHandle, SemanticHandleSpec,
};
use fss_ledger::{AppendPhase, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"original evidence is never read again by historical receipt inspection";
const CEILING: usize = 2 * 1024 * 1024;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Value<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!("fss-citation-inspection-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive fixture directory capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Fixture {
    directory: Directory,
    store: DurableSessionStore,
    source: InMemoryObjectStore,
    catalog: ReferenceHydrationCatalog,
    params: AgentSessionParams,
    alias: SessionAlias,
    target: SourceCitationTarget,
    request: HydrationRequest,
}
impl Fixture {
    fn new(tokens: u64) -> Value<Self> {
        let directory = Directory::new()?;
        let mut p = params("session:a")?;
        p.capabilities.insert("capability:source".into());
        let mut source = InMemoryObjectStore::new(ObjectLimits::default());
        let subject = source.put_verified(SOURCE)?;
        let root = source.publish_manifest(ObjectManifest::new("original", [subject], None)?)?.root;
        let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3]);
        let quote = BudgetVector::builder().bytes(1024).tokens(tokens).build()?;
        let descriptor = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis(), anchor: p.current_anchor.clone(), subject_id: "subject:source".into(),
            subject_digest: subject, semantic_type: "source_object".into(), source_id: "sensor:source".into(),
            capture_interval: None, spatial_scope: None, privacy_class: "private:property".into(),
            applied_transform: None, availability: HandleAvailability::Available, retention_until: TimestampNs(900),
            required_capabilities: levels.iter().map(|level| (*level, BTreeSet::from(["capability:source".into()]))).collect(),
            estimated_costs: levels.iter().map(|level| (*level, quote)).collect(), levels,
            laboratory_access: LaboratoryAccess::Unavailable, debug_capability: None,
            derivative_handles: BTreeSet::new(), published_at: TimestampNs(1),
        })?;
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(descriptor.clone())?;
        catalog.bind_source_object(&descriptor.handle_id, descriptor.descriptor_digest, root, &source)?;
        let mut store = DurableSessionStore::create(directory.0.join("session.fssj"), DurableSessionLimits::default())?;
        store.open(p.clone(), basis(), TimestampNs(10))?;
        store.enable_coordination(WorkClaimLimits::default())?;
        store.enable_investigations(InvestigationLimits::default())?;
        let alias = store.bind(&p.principal_id, &SessionBindingRequest {
            session_id: p.session_id.clone(), generation: 0, handle_id: descriptor.handle_id.clone(),
            descriptor_digest: descriptor.descriptor_digest,
        }, &catalog, TimestampNs(10))?;
        let revision = store.investigate(&p.principal_id, &p.session_id, opening()?, TimestampNs(10))?;
        let target = SourceCitationTarget { case_id: "case:window".into(), expected: revision.digest(),
            hypothesis: "hypothesis:a".into(), contradicts: false };
        let request = HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: basis(), session_id: p.session_id.clone(), handle_id: descriptor.handle_id,
            expected_descriptor_digest: descriptor.descriptor_digest, expected_subject_digest: subject,
            anchor: p.current_anchor.clone(), requested_level: HydrationLevel::H3, allow_lower_level: false,
            available_capabilities: p.capabilities.clone(), authorized_privacy_classes: p.privacy_scope.clone(),
            budget: quote, purpose: HydrationPurpose::Routine, continuation: None, issued_at: TimestampNs(10),
        })?;
        Ok(Self { directory, store, source, catalog, params: p, alias, target, request })
    }
    fn path(&self) -> PathBuf { self.directory.0.join("session.fssj") }
    fn cite(&mut self) -> Result<SourceCitationReceipt, SourceCitationError> {
        self.store.cite_investigation_source(&self.params.principal_id, &self.alias, &self.target,
            &self.request, &mut self.catalog, &self.source, TimestampNs(10))
    }
    fn inspect(&mut self, maximum: usize) -> Result<SourceCitationInspection, DurableInvestigationError> {
        self.store.inspect_source_citation(&self.params.principal_id, &self.params.session_id,
            &self.target, self.request.request_digest, maximum, TimestampNs(10))
    }
    fn remaining(&mut self) -> Value<u64> {
        Ok(self.store.remaining_token_budget(&self.params.principal_id, &self.params.session_id, TimestampNs(10))?)
    }
    fn forget_source(&mut self) {
        self.source = InMemoryObjectStore::new(ObjectLimits::default());
        self.catalog = ReferenceHydrationCatalog::new();
    }
    fn reopen(mut self) -> Value<Self> {
        let root = self.store.committed_root();
        let path = self.path();
        drop(self.store);
        self.store = DurableSessionStore::open_existing_with_coordination(path, root,
            DurableSessionLimits::default(), WorkClaimLimits::default())?;
        Ok(self)
    }
}

#[test]
fn historical_receipt_survives_case_progress_restart_and_missing_source() -> Value {
    let mut f = Fixture::new(3)?;
    let receipt = f.cite()?;
    let citation_root = f.store.committed_root();
    let current = f.store.investigate(&f.params.principal_id, &f.params.session_id,
        InvestigationCommand::Change { case_id: f.target.case_id.clone(), expected: receipt.revision().digest(),
            change: InvestigationChange::Activate }, TimestampNs(10))?;
    assert_ne!(current.digest(), receipt.revision().digest());
    f.forget_source();
    let mut f = f.reopen()?;
    let inspected = f.inspect(CEILING)?;
    assert_eq!(inspected.receipt(), Some(&receipt));
    assert_eq!(inspected.citation_root(), Some(citation_root));
    assert_eq!(inspected.inspected_root(), f.store.committed_root());
    assert_ne!(inspected.inspected_root(), citation_root);
    assert_eq!(f.store.investigation_heads(), vec![current]);
    assert_eq!(f.remaining()?, 97);
    assert!(!fs::read(f.path())?.windows(SOURCE.len()).any(|part| part == SOURCE));
    f.store.verify_storage()?;
    Ok(())
}

#[test]
fn matching_is_exact_and_missing_link_does_not_claim_no_charge() -> Value {
    let mut f = Fixture::new(3)?;
    assert!(f.inspect(0)?.receipt().is_none());
    let receipt = f.cite()?;
    for scenario in 0..4 {
        let mut target = f.target.clone();
        let mut request = f.request.request_digest;
        match scenario {
            0 => target.hypothesis = "hypothesis:b".into(),
            1 => target.contradicts = true,
            2 => target.expected = ContentDigest::sha256(b"other predecessor"),
            _ => request = ContentDigest::sha256(b"different request"),
        }
        let result = f.store.inspect_source_citation(&f.params.principal_id, &f.params.session_id,
            &target, request, 0, TimestampNs(10))?;
        assert!(result.receipt().is_none());
        assert!(result.citation_root().is_none());
        assert_eq!(result.receipt_bytes(), 0);
        assert_eq!(f.remaining()?, 97);
    }
    assert_eq!(f.inspect(CEILING)?.receipt(), Some(&receipt));
    Ok(())
}

#[test]
fn full_revision_not_just_digest_is_priced_at_the_exact_output_boundary() -> Value {
    let mut f = Fixture::new(3)?;
    let receipt = f.cite()?;
    let required = f.inspect(CEILING)?.receipt_bytes();
    assert!(required > receipt.revision().try_canonical_bytes()?.len());
    assert!(matches!(f.inspect(required - 1), Err(DurableInvestigationError::Durability(DurableSessionError::CapacityExceeded))));
    assert_eq!(f.inspect(required)?.receipt(), Some(&receipt));
    assert_eq!(f.remaining()?, 97);
    Ok(())
}

#[test]
fn all_link_fault_phases_reconcile_without_reading_source_again() -> Value {
    for (phase, committed) in [(AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true)] {
        // At the same clock a zero-token acquisition has no session change: fault the actual link.
        let mut f = Fixture::new(0)?;
        f.store.journal.fail_after_phase(phase);
        assert!(matches!(f.cite(), Err(SourceCitationError::Link { .. })));
        let before = fs::read(f.path())?;
        assert!(matches!(f.inspect(CEILING), Err(DurableInvestigationError::Durability(DurableSessionError::ReconciliationRequired))));
        assert_eq!(fs::read(f.path())?, before);
        f.forget_source();
        assert_eq!(f.store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
        let mut f = f.reopen()?;
        let result = f.inspect(CEILING)?;
        assert_eq!(result.receipt().is_some(), committed);
        if let Some(receipt) = result.receipt() { assert_eq!(receipt.acquisition().charged_tokens(), 0); }
        assert_eq!(f.remaining()?, 100);
    }
    Ok(())
}

#[test]
fn current_principal_mission_privacy_capability_and_liveness_gate_historical_metadata() -> Value {
    for scenario in 0..5 {
        let mut f = Fixture::new(3)?;
        f.cite()?;
        let mut p = params("session:observer")?;
        match scenario {
            0 => p.principal_id = PrincipalId::parse("principal:other")?,
            1 => p.mission_id = MissionId::parse("mission:other")?,
            2 => p.privacy_scope.clear(),
            3 => { p.capabilities.remove(CAPABILITY_INVESTIGATE); }
            _ => {}
        }
        f.store.open(p.clone(), basis(), TimestampNs(10))?;
        if scenario == 4 { f.store.close(&p.principal_id, &p.session_id, TimestampNs(10))?; }
        assert!(f.store.inspect_source_citation(&p.principal_id, &p.session_id,
            &f.target, f.request.request_digest, CEILING, TimestampNs(10)).is_err());
        assert_eq!(f.remaining()?, 97);
    }
    Ok(())
}

#[test]
fn new_session_can_inspect_after_old_session_closed_without_regranting_source_access() -> Value {
    let mut f = Fixture::new(3)?;
    let receipt = f.cite()?;
    f.store.close(&f.params.principal_id, &f.params.session_id, TimestampNs(10))?;
    let p = params("session:replacement")?; // Investigation grant only; no source grant or alias.
    f.store.open(p.clone(), basis(), TimestampNs(10))?;
    f.forget_source();
    let result = f.store.inspect_source_citation(&p.principal_id, &p.session_id,
        &f.target, f.request.request_digest, CEILING, TimestampNs(10))?;
    assert_eq!(result.receipt(), Some(&receipt));
    assert_eq!(f.store.remaining_token_budget(&p.principal_id, &p.session_id, TimestampNs(10))?, 100);
    assert!(f.inspect(CEILING).is_err());
    Ok(())
}

#[test]
fn corrupt_complete_history_is_refused_before_appending_an_inspection() -> Value {
    let mut f = Fixture::new(3)?;
    f.cite()?;
    let root = f.store.committed_root();
    let mut bytes = fs::read(f.path())?;
    bytes[100] ^= 1;
    fs::write(f.path(), &bytes)?;
    assert!(f.inspect(CEILING).is_err());
    assert_eq!(fs::read(f.path())?, bytes);
    assert_eq!(f.store.committed_root(), root);
    Ok(())
}

#[test]
fn uncertain_inspection_returns_nothing_then_reconciles_without_recharging() -> Value {
    let mut f = Fixture::new(3)?;
    let receipt = f.cite()?;
    f.forget_source();
    f.store.journal.fail_after_phase(AppendPhase::CommitSync);
    assert!(f.inspect(CEILING).is_err());
    assert!(f.store.needs_reconciliation());
    assert_eq!(f.store.reconcile_pending(IncompleteTailPolicy::Reject)?, SessionAppendRecovery::Committed);
    let mut f = f.reopen()?;
    assert_eq!(f.inspect(CEILING)?.receipt(), Some(&receipt));
    assert_eq!(f.remaining()?, 97);
    Ok(())
}

#[test]
fn charged_unlinked_acquisition_remains_distinct_from_committed_citation_on_restart() -> Value {
    let mut f = Fixture::new(3)?;
    f.store.limits.max_records = f.store.records + 1;
    let acquisition = match f.cite() {
        Err(SourceCitationError::Link { acquisition, cause: DurableInvestigationError::Durability(DurableSessionError::CapacityExceeded) }) => acquisition,
        result => return Err(format!("expected charged but unlinked acquisition: {result:?}").into()),
    };
    assert_eq!(acquisition.charged_root(), f.store.committed_root());
    let report = fss_ledger::recover_bytes(&fs::read(f.path())?)?;
    assert_eq!(report.records().last().ok_or("no charge record")?.kind(), SESSION_CHECKPOINT_RECORD_KIND);
    f.forget_source();
    let mut f = f.reopen()?;
    let result = f.inspect(CEILING)?;
    assert!(result.receipt().is_none());
    assert_eq!(f.remaining()?, 97);
    assert_eq!(f.store.investigation_heads()[0].digest(), f.target.expected);
    Ok(())
}
