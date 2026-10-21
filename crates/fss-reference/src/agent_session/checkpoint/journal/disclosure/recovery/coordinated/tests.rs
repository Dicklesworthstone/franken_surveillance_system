#![forbid(unsafe_code)]
//! Native mixed-history tests: there is never a second session writer or a replay-state reset.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::agent_session::{SessionAlias, SessionBindingRequest};
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    CAPABILITY_INVESTIGATE, InvestigationChange,
};
use crate::agent_session::work_claims::{CAPABILITY_WORK_CLAIM, WorkClaimRequest};
use crate::{PublishedSourceReader, SourceHydrationError};
use fss_core::{
    AgentSessionParams, BudgetVector, CaseHypothesis, CaseId, Completeness, ContractBasis,
    ContractBasisRegistryBytes, HandleAvailability, HydrationArtifact, HydrationLevel,
    HydrationPurpose, HydrationRequest, HydrationRequestSpec, InvestigationLifecycle,
    InvestigationState, InvestigationStateParams, KnowledgeState, LaboratoryAccess, LedgerAnchor,
    MissionId, SemanticHandle, SemanticHandleSpec,
};
use fss_ledger::AppendPhase;
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

type Value<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"synthetic original; never a session or claim journal payload";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Value<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-coordinated-disclosure-{}-{}", std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Reader { objects: InMemoryObjectStore, reads: Cell<usize> }
impl PublishedSourceReader for Reader {
    fn read_published_source(&self, root: ContentDigest, subject: ContentDigest, maximum: u64)
        -> Result<Vec<u8>, SourceHydrationError> {
        self.reads.set(self.reads.get() + 1);
        self.objects.read_published_source(root, subject, maximum)
    }
}

fn ceilings() -> WorkClaimLimits {
    WorkClaimLimits { max_claims: 8, max_revisions: 32, max_dependencies: 4, max_lease_ns: 100 }
}

struct Fixture {
    directory: Directory,
    params: AgentSessionParams,
    handle: SemanticHandle,
    root: ContentDigest,
    alternate: ContentDigest,
    reader: Reader,
    catalog: ReferenceHydrationCatalog,
    alias: SessionAlias,
}
impl Fixture {
    fn new() -> Value<(Self, DurableDisclosureStore)> {
        let directory = Directory::new()?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::default());
        let subject = objects.put_verified(SOURCE)?;
        let root = objects.publish_manifest(ObjectManifest::new("source", [subject], None)?)?.root;
        let alternate = objects.publish_manifest(ObjectManifest::new("other", [subject], None)?)?.root;
        let reader = Reader { objects, reads: Cell::new(0) };
        let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s", b"o", b"v", b"c", b"e", b"cost", "coordinated-disclosure:test",
        ));
        let levels = BTreeSet::from([
            HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2, HydrationLevel::H3,
        ]);
        let quote = BudgetVector::builder().bytes(1024).tokens(2).build()?;
        let handle = SemanticHandle::publish(SemanticHandleSpec {
            contract_basis: basis.clone(), anchor: LedgerAnchor::genesis("site:coordinated"),
            subject_id: "subject:source".into(), subject_digest: subject,
            semantic_type: "source_object".into(), source_id: "sensor:fixture".into(),
            capture_interval: None, spatial_scope: None, privacy_class: "private:property".into(),
            applied_transform: None, availability: HandleAvailability::Available,
            retention_until: TimestampNs(100),
            required_capabilities: levels.iter().map(|level| (*level, BTreeSet::from(["capability:read".into()]))).collect(),
            estimated_costs: levels.iter().map(|level| (*level, quote)).collect(), levels,
            laboratory_access: LaboratoryAccess::Unavailable, debug_capability: None,
            derivative_handles: BTreeSet::new(), published_at: TimestampNs(1),
        })?;
        let mut catalog = ReferenceHydrationCatalog::new();
        catalog.register_descriptor(handle.clone())?;
        catalog.register_artifact(&handle.handle_id, handle.descriptor_digest,
            HydrationArtifact::publish(HydrationLevel::H2, "text/plain", b"preview".to_vec(),
                [subject], Completeness::Complete, None)?)?;
        catalog.bind_source_object(&handle.handle_id, handle.descriptor_digest, root, &reader)?;
        let params = AgentSessionParams {
            session_id: SessionId::parse("session:coordinated")?,
            principal_id: PrincipalId::parse("principal:owner")?,
            mission_id: MissionId::parse("mission:coordinated")?,
            capabilities: BTreeSet::from([
                CAPABILITY_WORK_CLAIM.into(), CAPABILITY_INVESTIGATE.into(), "capability:read".into(),
            ]),
            privacy_scope: BTreeSet::from([handle.privacy_class.clone()]),
            current_anchor: handle.anchor.clone(), view_id: "AVIEW-001".into(), token_budget: 64,
            symbol_table_generation: 0, last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0, expires_at_ns: 1000,
        };
        let mut owner = DurableDisclosureStore::create(
            directory.0.join("sessions.fssj"), DurableSessionLimits::default(), catalog.clone(),
        )?;
        owner.open_session(params.clone(), basis, TimestampNs(10))?;
        let alias = owner.bind(&params.principal_id, &SessionBindingRequest {
            session_id: params.session_id.clone(), generation: 0, handle_id: handle.handle_id.clone(),
            descriptor_digest: handle.descriptor_digest,
        }, TimestampNs(10))?;
        owner.bind_source_object_durable(&handle.handle_id, handle.descriptor_digest, root, &reader, TimestampNs(10))?;
        owner.enable_coordination(ceilings())?;
        owner.enable_investigations(InvestigationLimits::default())?;
        reader.reads.set(0);
        Ok((Self { directory, params, handle, root, alternate, reader, catalog, alias }, owner))
    }
    fn path(&self) -> PathBuf { self.directory.0.join("sessions.fssj") }
    fn reopen(&self, root: ContentDigest) -> Value<DurableDisclosureStore> {
        Ok(DurableDisclosureStore::open_existing_with_coordination(
            self.path(), root, DurableSessionLimits::default(), ceilings(), self.catalog.clone(),
        )?)
    }
    fn claim(&self) -> Value<CoordinationCommand> {
        Ok(CoordinationCommand::Acquire(WorkClaimRequest {
            claim_id: "claim:source".into(), case_id: CaseId::parse("case:source")?,
            work_root: ContentDigest::sha256(b"inspect this exact source"),
            privacy_class: self.handle.privacy_class.clone(), expires_at: TimestampNs(90),
            dependencies: BTreeSet::new(),
        }))
    }
    fn opening(&self) -> Value<InvestigationCommand> {
        Ok(InvestigationCommand::Open {
            privacy_class: self.handle.privacy_class.clone(),
            record: Box::new(InvestigationState::new(InvestigationStateParams {
                investigation_id: "case:source".into(), contract_basis: self.handle.contract_basis.clone(),
                mission_id: self.params.mission_id.clone(), revision: 1, state: InvestigationLifecycle::Draft,
                question: "Which observation explains this source?".into(),
                decision_informed: "Which bounded evidence should be read?".into(),
                basis_anchor: self.handle.anchor.clone(),
                hypotheses: ["hypothesis:a", "hypothesis:b"].into_iter().map(|id| CaseHypothesis {
                    hypothesis_id: id.into(), description: id.into(), epistemic_state: KnowledgeState::Unknown,
                    predictions: vec!["inspect source".into()], evidence: vec![], contradictions: vec![],
                }).collect(),
                knowns: vec![], unknowns: vec![], discriminators: vec![], probes: vec!["probe:source".into()],
                stop_rules: vec!["bounded assessment".into()], decision_deadline_ns: 100,
            })?),
        })
    }
    fn request(&self, level: HydrationLevel) -> Value<HydrationRequest> {
        Ok(HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: self.handle.contract_basis.clone(), session_id: self.params.session_id.clone(),
            handle_id: self.handle.handle_id.clone(), expected_descriptor_digest: self.handle.descriptor_digest,
            expected_subject_digest: self.handle.subject_digest, anchor: self.handle.anchor.clone(),
            requested_level: level, allow_lower_level: false,
            available_capabilities: self.params.capabilities.clone(), authorized_privacy_classes: self.params.privacy_scope.clone(),
            budget: BudgetVector::builder().bytes(1024).tokens(2).build()?, purpose: HydrationPurpose::Routine,
            continuation: None, issued_at: TimestampNs(20),
        })?)
    }
    fn remaining(&self, owner: &mut DurableDisclosureStore) -> Value<u64> {
        Ok(owner.remaining_token_budget(&self.params.principal_id, &self.params.session_id, TimestampNs(20))?)
    }
    fn no_source_in_journal(&self) -> Value {
        assert!(!fs::read(self.path())?.windows(SOURCE.len()).any(|window| window == SOURCE));
        Ok(())
    }
}

#[test]
fn interleaved_claim_case_registration_and_source_continuation_survive_restart() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let claim = owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20))?;
    let case = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
    let preview = owner.hydrate(&f.params.principal_id, &f.alias, &f.request(HydrationLevel::H2)?, TimestampNs(20))?;
    let cursor = preview.response.receipt.continuation.ok_or("no source continuation")?;
    let mut source = f.request(HydrationLevel::H3)?;
    source.continuation = Some(cursor.clone());
    source.request_digest = source.computed_digest();
    source.request_id = format!("hydration-request:{}", source.request_digest);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert_eq!(f.reader.reads.get(), 0);
    assert_eq!(f.remaining(&mut owner)?, 62);
    assert_eq!(owner.coordinate(&f.params.principal_id, &f.params.session_id,
        CoordinationCommand::Inspect { claim_id: "claim:source".into() }, TimestampNs(20))?, claim);
    assert_eq!(owner.investigate(&f.params.principal_id, &f.params.session_id,
        InvestigationCommand::Inspect { case_id: "case:source".into(), revision: None }, TimestampNs(20))?, case);
    let delivered = owner.hydrate_from_source(&f.params.principal_id, &f.alias, &source, &f.reader, TimestampNs(20))?;
    assert_eq!(delivered.response.artifact.ok_or("no original")?.payload, SOURCE);
    let root = owner.committed_root();
    drop(owner);
    let mut owner = f.reopen(root)?;
    assert_eq!(f.remaining(&mut owner)?, 60);
    assert!(owner.catalog().issued_cursor(&cursor.cursor_digest).ok_or("lost cursor")?.consumed);
    assert!(owner.hydrate_from_source(&f.params.principal_id, &f.alias, &source, &f.reader, TimestampNs(20)).is_err());
    assert_eq!(f.reader.reads.get(), 1);
    assert_eq!(f.remaining(&mut owner)?, 60);
    f.no_source_in_journal()
}

#[test]
fn no_profile_or_insufficient_claim_ceiling_never_adopts_or_rewrites_history() -> Value {
    let (f, owner) = Fixture::new()?;
    let root = owner.committed_root();
    drop(owner);
    let before = fs::read(f.path())?;
    assert!(DurableDisclosureStore::open_existing(f.path(), root, DurableSessionLimits::default(), f.catalog.clone()).is_err());
    assert!(DurableDisclosureStore::open_existing_with_coordination(f.path(), root,
        DurableSessionLimits::default(), WorkClaimLimits { max_claims: 0, ..ceilings() }, f.catalog.clone()).is_err());
    assert_eq!(fs::read(f.path())?, before);
    let owner = f.reopen(root)?;
    assert_eq!(owner.committed_root(), root);
    assert_eq!(f.reader.reads.get(), 0);
    Ok(())
}

#[test]
fn claim_append_uncertainty_fences_disclosure_until_the_same_owner_reconciles() -> Value {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true),
    ] {
        let (f, mut owner) = Fixture::new()?;
        owner.sessions.journal.fail_after_phase(phase);
        assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20)).is_err());
        assert!(owner.needs_reconciliation());
        assert!(owner.hydrate_from_source(&f.params.principal_id, &f.alias, &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20)).is_err());
        assert_eq!(f.reader.reads.get(), 0);
        assert_eq!(owner.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
        assert!(!owner.needs_reconciliation());
        assert_eq!(f.remaining(&mut owner)?, 64);
        let result = owner.coordinate(&f.params.principal_id, &f.params.session_id,
            CoordinationCommand::Inspect { claim_id: "claim:source".into() }, TimestampNs(20));
        assert_eq!(result.is_ok(), committed);
        let root = owner.committed_root();
        drop(owner);
        let mut owner = f.reopen(root)?;
        assert_eq!(f.remaining(&mut owner)?, 64);
        f.no_source_in_journal()?;
    }
    Ok(())
}

#[test]
fn disclosure_append_uncertainty_fences_case_changes_and_preserves_claims() -> Value {
    for (phase, committed) in [(AppendPhase::BodySync, false), (AppendPhase::CommitSync, true)] {
        let (f, mut owner) = Fixture::new()?;
        let claim = owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20))?;
        let case = owner.investigate(&f.params.principal_id, &f.params.session_id, f.opening()?, TimestampNs(20))?;
        owner.sessions.journal.fail_after_phase(phase);
        assert!(owner.hydrate_from_source(&f.params.principal_id, &f.alias, &f.request(HydrationLevel::H3)?, &f.reader, TimestampNs(20)).is_err());
        assert!(owner.investigate(&f.params.principal_id, &f.params.session_id, InvestigationCommand::Change {
            case_id: "case:source".into(), expected: case.digest(), change: InvestigationChange::Activate,
        }, TimestampNs(20)).is_err());
        owner.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        assert_eq!(f.remaining(&mut owner)?, if committed { 62 } else { 64 });
        assert_eq!(f.reader.reads.get(), 1);
        assert_eq!(owner.investigate(&f.params.principal_id, &f.params.session_id,
            InvestigationCommand::Inspect { case_id: "case:source".into(), revision: None }, TimestampNs(20))?, case);
        assert_eq!(owner.coordinate(&f.params.principal_id, &f.params.session_id,
            CoordinationCommand::Inspect { claim_id: "claim:source".into() }, TimestampNs(20))?, claim);
    }
    Ok(())
}

#[test]
fn mixed_cold_recovery_admits_ceilings_and_custody_before_truncating() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let root = owner.committed_root();
    owner.sessions.journal.fail_after_phase(AppendPhase::BodySync);
    assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20)).is_err());
    drop(owner);
    let before = fs::read(f.path())?;
    let mut wrong = ReferenceHydrationCatalog::new();
    wrong.register_descriptor(f.handle.clone())?;
    wrong.bind_source_object(&f.handle.handle_id, f.handle.descriptor_digest, f.alternate, &f.reader)?;
    let reads = f.reader.reads.get();
    for (limits, catalog) in [
        (WorkClaimLimits { max_claims: 0, ..ceilings() }, f.catalog.clone()), (ceilings(), wrong),
    ] {
        assert!(DurableDisclosureStore::recover_existing_with_coordination(f.path(), root,
            DurableSessionLimits::default(), limits, IncompleteTailPolicy::Truncate, catalog).is_err());
        assert_eq!(fs::read(f.path())?, before);
    }
    assert!(DurableDisclosureStore::recover_existing(f.path(), root, DurableSessionLimits::default(),
        IncompleteTailPolicy::Truncate, f.catalog.clone()).is_err());
    assert_eq!(fs::read(f.path())?, before);
    let (mut owner, receipt) = DurableDisclosureStore::recover_existing_with_coordination(f.path(), root,
        DurableSessionLimits::default(), ceilings(), IncompleteTailPolicy::Truncate, ReferenceHydrationCatalog::new())?;
    let after = fs::read(f.path())?;
    assert!(after.len() < before.len());
    assert_eq!(receipt.discarded_tail_digest(), Some(ContentDigest::sha256(&before[after.len()..])));
    assert_eq!(receipt.discarded_bytes(), (before.len() - after.len()) as u64);
    assert!(owner.catalog().source_binding_requirement(f.handle.descriptor_digest).is_some());
    assert_eq!(f.reader.reads.get(), reads);
    assert_eq!(f.remaining(&mut owner)?, 64);
    Ok(())
}

#[test]
fn lost_claim_acknowledgement_recovers_only_at_the_new_root_without_source_io() -> Value {
    let (f, mut owner) = Fixture::new()?;
    let old = owner.committed_root();
    owner.sessions.journal.fail_after_phase(AppendPhase::CommitSync);
    assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id, f.claim()?, TimestampNs(20)).is_err());
    drop(owner);
    let before = fs::read(f.path())?;
    assert!(DurableDisclosureStore::recover_existing_with_coordination(f.path(), old,
        DurableSessionLimits::default(), ceilings(), IncompleteTailPolicy::Truncate, f.catalog.clone()).is_err());
    assert_eq!(fs::read(f.path())?, before);
    // The synthetic owner independently authorizes this test's new prefix; inspection alone is
    // not a production root-authentication mechanism.
    let head = DurableSessionStore::inspect_with_coordination(f.path(), DurableSessionLimits::default(), ceilings())?.root;
    let (mut owner, receipt) = DurableDisclosureStore::recover_existing_with_coordination(f.path(), head,
        DurableSessionLimits::default(), ceilings(), IncompleteTailPolicy::Reject, f.catalog.clone())?;
    assert_eq!(receipt.discarded_bytes(), 0);
    assert!(owner.coordinate(&f.params.principal_id, &f.params.session_id,
        CoordinationCommand::Inspect { claim_id: "claim:source".into() }, TimestampNs(20)).is_ok());
    assert_eq!(f.reader.reads.get(), 0);
    assert_eq!(f.remaining(&mut owner)?, 64);
    Ok(())
}
