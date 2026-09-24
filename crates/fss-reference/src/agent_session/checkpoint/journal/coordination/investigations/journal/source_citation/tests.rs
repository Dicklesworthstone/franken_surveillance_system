#![forbid(unsafe_code)]
use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::super::InvestigationLimits;
use super::super::super::tests::{basis, opening, params};
use super::*;
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::agent_session::{SessionBindingRequest, SessionRefresh};
use fss_core::{
    AgentSessionParams, BudgetVector, Generation, HandleAvailability, HydrationPurpose,
    HydrationRequestSpec, KnowledgeState, LaboratoryAccess, ObjectId, SemanticHandle,
    SemanticHandleSpec, TombstoneReason, TombstoneRecord,
};
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

type TestResult = Result<(), Box<dyn Error>>;
const SOURCE: &[u8] = b"private original source: never serialize these bytes into the case journal";
static SERIAL: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
    for _ in 0..128 {
        let n = SERIAL.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "fss-source-citation-{}-{n}.journal",
            std::process::id()
        ));
        if !p.exists() {
            return Ok(p);
        }
    }
    Err("test path capacity exceeded".into())
}

struct Fixture {
    store: DurableSessionStore,
    catalog: ReferenceHydrationCatalog,
    source: InMemoryObjectStore,
    p: AgentSessionParams,
    alias: SessionAlias,
    handle: SemanticHandle,
    target: SourceCitationTarget,
    request: HydrationRequest,
}

fn fixture(tokens: u64) -> Result<Fixture, Box<dyn Error>> {
    fixture_privacy(tokens, "private:property")
}
fn fixture_privacy(tokens: u64, privacy: &str) -> Result<Fixture, Box<dyn Error>> {
    let mut p = params("session:a")?;
    p.capabilities.insert("capability:source".to_owned());
    p.privacy_scope.insert(privacy.to_owned());
    let mut source = InMemoryObjectStore::new(ObjectLimits::new(32, 65_536));
    let subject = source.put_verified(SOURCE)?;
    let root = source
        .publish_manifest(ObjectManifest::new("source", [subject], None)?)?
        .root;
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
    ]);
    let cost = BudgetVector::builder()
        .tokens(tokens)
        .bytes(1_024)
        .build()?;
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: p.current_anchor.clone(),
        subject_id: "subject:source".to_owned(),
        subject_digest: subject,
        semantic_type: "source_object".to_owned(),
        source_id: "sensor:source".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: privacy.to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(900),
        required_capabilities: levels
            .iter()
            .map(|l| (*l, BTreeSet::from(["capability:source".to_owned()])))
            .collect(),
        estimated_costs: levels.iter().map(|l| (*l, cost)).collect(),
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    catalog.bind_source_object(&handle.handle_id, handle.descriptor_digest, root, &source)?;
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    store.open(p.clone(), basis(), TimestampNs(10))?;
    store.enable_coordination(WorkClaimLimits::default())?;
    store.enable_investigations(InvestigationLimits::default())?;
    let alias = store.bind(
        &p.principal_id,
        &SessionBindingRequest {
            session_id: p.session_id.clone(),
            generation: 0,
            handle_id: handle.handle_id.clone(),
            descriptor_digest: handle.descriptor_digest,
        },
        &catalog,
        TimestampNs(10),
    )?;
    let revision =
        store.investigate(&p.principal_id, &p.session_id, opening()?, TimestampNs(10))?;
    let target = SourceCitationTarget {
        case_id: revision.record().investigation_id.clone(),
        expected: revision.digest(),
        hypothesis: "hypothesis:a".to_owned(),
        contradicts: false,
    };
    let request = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: basis(),
        session_id: p.session_id.clone(),
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: subject,
        anchor: p.current_anchor.clone(),
        requested_level: HydrationLevel::H3,
        allow_lower_level: false,
        available_capabilities: p.capabilities.clone(),
        authorized_privacy_classes: p.privacy_scope.clone(),
        budget: cost,
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10),
    })?;
    Ok(Fixture {
        store,
        catalog,
        source,
        p,
        alias,
        handle,
        target,
        request,
    })
}

impl Fixture {
    fn cite(&mut self) -> Result<SourceCitationReceipt, SourceCitationError> {
        self.store.cite_investigation_source(
            &self.p.principal_id,
            &self.alias,
            &self.target,
            &self.request,
            &mut self.catalog,
            &self.source,
            TimestampNs(10),
        )
    }
    fn head(&self) -> Result<&InvestigationRevision, Box<dyn Error>> {
        Ok(&self
            .store
            .coordination
            .as_ref()
            .ok_or("coordination")?
            .cases
            .as_ref()
            .ok_or("cases")?
            .entries
            .get(&self.target.case_id)
            .ok_or("case")?
            .head)
    }
    fn remaining(&mut self) -> Result<u64, Box<dyn Error>> {
        Ok(self.store.remaining_token_budget(
            &self.p.principal_id,
            &self.p.session_id,
            TimestampNs(10),
        )?)
    }
}

struct Probe<'a> {
    store: &'a InMemoryObjectStore,
    calls: Cell<usize>,
    wrong: bool,
}
impl PublishedSourceReader for Probe<'_> {
    fn read_published_source(
        &self,
        root: ContentDigest,
        subject: ContentDigest,
        max: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.calls.set(self.calls.get() + 1);
        if self.wrong {
            Ok(b"not the original source".to_vec())
        } else {
            self.store.read_published_source(root, subject, max)
        }
    }
}
fn reseal(r: &mut HydrationRequest) {
    r.request_digest = r.computed_digest();
    r.request_id = format!("hydration-request:{}", r.request_digest);
}

#[test]
fn exact_source_citation_binds_charge_and_case_without_copying_footage_or_promoting_truth()
-> TestResult {
    for contradicts in [false, true] {
        let mut f = fixture(3)?;
        f.target.contradicts = contradicts;
        let old = f.head()?.clone();
        let result = f.cite()?;
        assert_eq!(
            result.acquisition().subject_digest(),
            f.handle.subject_digest
        );
        assert_eq!(result.acquisition().charged_tokens(), 3);
        assert_eq!(result.revision().predecessor(), Some(old.digest()));
        let h = &result.revision().record().hypotheses[0];
        assert_eq!(
            if contradicts {
                h.contradictions.as_slice()
            } else {
                h.evidence.as_slice()
            },
            &[f.handle.subject_digest]
        );
        assert_eq!(h.epistemic_state, KnowledgeState::Unknown);
        assert_eq!(result.revision().control(), old.control());
        assert_eq!(result.revision().record().unknowns, old.record().unknowns);
        assert_eq!(f.remaining()?, 97);
        let bytes = std::fs::read(f.store.path())?;
        assert!(!bytes.windows(SOURCE.len()).any(|b| b == SOURCE));
        assert_eq!(f.catalog.stored_payload_bytes(), 0);
        let report = fss_ledger::recover_bytes(&bytes)?;
        let last = report.records().last().ok_or("record")?;
        let (_, acquired, _, _, digest) = decode(last.payload())?;
        assert_eq!(digest, result.digest());
        assert_eq!(&acquired, result.acquisition());
        assert_eq!(
            acquired.charge_root,
            report.records()[report.records().len() - 2].root()
        );
        f.store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn stale_target_bad_hypothesis_wrong_principal_and_downgrade_fail_before_io() -> TestResult {
    for case in 0..6 {
        let mut f = fixture(3)?;
        let principal = if case == 2 {
            PrincipalId::parse("principal:other")?
        } else {
            f.p.principal_id.clone()
        };
        match case {
            0 => f.target.expected = ContentDigest::sha256(b"stale"),
            1 => f.target.hypothesis = "hypothesis:missing".to_owned(),
            3 => {
                f.request.requested_level = HydrationLevel::H2;
                reseal(&mut f.request);
            }
            4 => {
                f.request.allow_lower_level = true;
                reseal(&mut f.request);
            }
            5 => f.target.case_id = "case:missing".to_owned(),
            _ => {}
        }
        let root = f.store.committed_root();
        let probe = Probe {
            store: &f.source,
            calls: Cell::new(0),
            wrong: false,
        };
        assert!(matches!(
            f.store.cite_investigation_source(
                &principal,
                &f.alias,
                &f.target,
                &f.request,
                &mut f.catalog,
                &probe,
                TimestampNs(10)
            ),
            Err(SourceCitationError::Preflight(_))
        ));
        assert_eq!(probe.calls.get(), 0);
        assert_eq!(f.store.committed_root(), root);
    }
    Ok(())
}

#[test]
fn source_privacy_must_match_case_even_when_the_session_holds_both_domains() -> TestResult {
    let mut f = fixture_privacy(3, "private:other")?;
    let probe = Probe {
        store: &f.source,
        calls: Cell::new(0),
        wrong: false,
    };
    assert!(matches!(
        f.store.cite_investigation_source(
            &f.p.principal_id,
            &f.alias,
            &f.target,
            &f.request,
            &mut f.catalog,
            &probe,
            TimestampNs(10)
        ),
        Err(SourceCitationError::Preflight(_))
    ));
    assert_eq!(probe.calls.get(), 0);
    assert_eq!(f.remaining()?, 100);
    Ok(())
}

#[test]
fn source_substitution_and_revoked_alias_cannot_attach_or_charge_evidence() -> TestResult {
    let mut f = fixture(3)?;
    let probe = Probe {
        store: &f.source,
        calls: Cell::new(0),
        wrong: true,
    };
    assert!(matches!(
        f.store.cite_investigation_source(
            &f.p.principal_id,
            &f.alias,
            &f.target,
            &f.request,
            &mut f.catalog,
            &probe,
            TimestampNs(10)
        ),
        Err(SourceCitationError::Acquisition(_))
    ));
    assert_eq!(probe.calls.get(), 1);
    assert_eq!(f.head()?.digest(), f.target.expected);
    assert_eq!(f.remaining()?, 100);
    let s = f
        .store
        .session(&f.p.principal_id, &f.p.session_id, TimestampNs(10))?;
    f.store.refresh(
        &f.p.principal_id,
        &f.p.session_id,
        SessionRefresh {
            expected_session_digest: s.session_digest(),
            current_anchor: s.current_anchor,
            capabilities: BTreeSet::from([super::super::super::CAPABILITY_INVESTIGATE.to_owned()]),
            privacy_scope: s.privacy_scope,
        },
        TimestampNs(10),
    )?;
    let probe = Probe {
        store: &f.source,
        calls: Cell::new(0),
        wrong: false,
    };
    assert!(
        f.store
            .cite_investigation_source(
                &f.p.principal_id,
                &f.alias,
                &f.target,
                &f.request,
                &mut f.catalog,
                &probe,
                TimestampNs(10)
            )
            .is_err()
    );
    assert_eq!(probe.calls.get(), 0);
    Ok(())
}

#[test]
fn restart_preserves_citation_and_stale_retry_cannot_charge_twice() -> TestResult {
    let mut f = fixture(3)?;
    let receipt = f.cite()?;
    let root = f.store.committed_root();
    let path = f.store.path().to_path_buf();
    drop(f.store);
    f.store = DurableSessionStore::open_existing_with_coordination(
        path,
        root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(f.head()?, receipt.revision());
    assert_eq!(f.remaining()?, 97);
    let probe = Probe {
        store: &f.source,
        calls: Cell::new(0),
        wrong: false,
    };
    assert!(matches!(
        f.store.cite_investigation_source(
            &f.p.principal_id,
            &f.alias,
            &f.target,
            &f.request,
            &mut f.catalog,
            &probe,
            TimestampNs(10)
        ),
        Err(SourceCitationError::Preflight(_))
    ));
    assert_eq!(probe.calls.get(), 0);
    f.store.verify_storage()?;
    Ok(())
}

fn phases() -> [(AppendPhase, bool); 4] {
    [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ]
}

#[test]
fn acquisition_uncertainty_fences_without_publishing_a_case_citation() -> TestResult {
    for (phase, committed) in phases() {
        let mut f = fixture(3)?;
        f.store.journal.fail_after_phase(phase);
        assert!(matches!(
            f.cite(),
            Err(SourceCitationError::Acquisition(
                DurableSourceHydrationError::Durability(_)
            ))
        ));
        assert!(f.store.needs_reconciliation());
        assert_eq!(f.head()?.digest(), f.target.expected);
        let outcome = f.store.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        assert_eq!(outcome == SessionAppendRecovery::Committed, committed);
        assert_eq!(f.remaining()?, if committed { 97 } else { 100 });
        assert_eq!(f.head()?.digest(), f.target.expected);
        f.store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn link_uncertainty_and_cold_recovery_never_erase_a_complete_case_change() -> TestResult {
    for (phase, committed) in phases() {
        for cold in [false, true] {
            // A zero token quote at the already-observed time needs no new charge checkpoint:
            // the injected next append is the citation stage, not source acquisition.
            let mut f = fixture(0)?;
            let previous = f.store.committed_root();
            f.store.journal.fail_after_phase(phase);
            let acquired = match f.cite() {
                Err(SourceCitationError::Link { acquisition, .. }) => acquisition,
                _ => return Err("expected a source-acquired link failure".into()),
            };
            assert_eq!(acquired.charged_root(), previous);
            assert!(f.store.needs_reconciliation());
            assert_eq!(f.head()?.digest(), f.target.expected);
            if cold {
                let path = f.store.path().to_path_buf();
                drop(f.store);
                let tip = fss_ledger::inspect(&path)?.last_root();
                if committed {
                    let before = std::fs::read(&path)?;
                    assert!(
                        DurableSessionStore::recover_existing_with_coordination(
                            &path,
                            previous,
                            DurableSessionLimits::default(),
                            WorkClaimLimits::default(),
                            IncompleteTailPolicy::Truncate
                        )
                        .is_err()
                    );
                    assert_eq!(std::fs::read(&path)?, before);
                }
                f.store = DurableSessionStore::recover_existing_with_coordination(
                    path,
                    tip,
                    DurableSessionLimits::default(),
                    WorkClaimLimits::default(),
                    IncompleteTailPolicy::Truncate,
                )?
                .0;
            } else {
                let outcome = f.store.reconcile_pending(IncompleteTailPolicy::Truncate)?;
                assert_eq!(outcome == SessionAppendRecovery::Committed, committed);
            }
            assert_eq!(f.head()?.digest() != f.target.expected, committed);
            f.store.verify_storage()?;
        }
    }
    Ok(())
}

#[test]
fn link_capacity_failure_retains_the_committed_charge_and_reports_partial_completion() -> TestResult
{
    let mut f = fixture(3)?;
    f.store.limits.max_records = f.store.records + 1;
    let acquired = match f.cite() {
        Err(SourceCitationError::Link {
            acquisition,
            cause: DurableInvestigationError::Durability(DurableSessionError::CapacityExceeded),
        }) => acquisition,
        _ => return Err("expected charged but unlinked capacity failure".into()),
    };
    assert_eq!(f.store.committed_root(), acquired.charged_root());
    assert_eq!(f.head()?.digest(), f.target.expected);
    let path = f.store.path().to_path_buf();
    let root = f.store.committed_root();
    drop(f.store);
    f.store = DurableSessionStore::open_existing_with_coordination(
        path,
        root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(f.remaining()?, 97);
    assert_eq!(f.head()?.digest(), f.target.expected);
    Ok(())
}

#[test]
fn source_tombstone_after_citation_is_not_bypassed_by_retained_case_history() -> TestResult {
    let mut f = fixture(3)?;
    let result = f.cite()?;
    f.target.expected = result.revision().digest();
    let prior = Generation::parse_positive(1)?;
    let proof = f.source.put_verified(b"authorized deletion receipt")?;
    let tombstone = TombstoneRecord::new(
        ObjectId::parse("source:deleted")?,
        prior.next()?,
        prior,
        TombstoneReason::Deleted,
        Some(proof),
        f.handle.subject_digest,
    )?;
    f.source.tombstone(f.handle.subject_digest, tombstone)?;
    assert!(matches!(f.cite(), Err(SourceCitationError::Acquisition(_))));
    assert_eq!(f.head()?, result.revision());
    assert_eq!(f.remaining()?, 97);
    // Replay is historical metadata, not a reread or a source cache.
    f.store.verify_storage()?;
    Ok(())
}

#[test]
fn forged_charge_root_alias_or_revision_is_rejected_before_tail_truncation() -> TestResult {
    for mutation in 0..3 {
        let mut f = fixture(3)?;
        let mut receipt = f.cite()?;
        let report = fss_ledger::inspect(f.store.path())?;
        let after = f.store.checkpoint_digest;
        match mutation {
            0 => receipt.acquisition.charge_root = ContentDigest::sha256(b"other charge"),
            1 => receipt.acquisition.subject = ContentDigest::sha256(b"substituted alias subject"),
            _ => receipt.target.expected = ContentDigest::sha256(b"other case predecessor"),
        }
        let path = unused_path()?;
        let mut forged = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        for record in &report.records()[..report.records().len() - 1] {
            forged.append(record.kind(), record.payload())?;
        }
        forged.append(COORDINATION_COMMAND_RECORD_KIND, &encode(&receipt, after)?)?;
        let root = forged.last_root();
        drop(forged);
        let mut file = OpenOptions::new().append(true).open(&path)?;
        file.write_all(b"FSSJ")?;
        file.sync_all()?;
        drop(file);
        let before = std::fs::read(&path)?;
        assert!(
            DurableSessionStore::recover_existing_with_coordination(
                &path,
                root,
                DurableSessionLimits::default(),
                WorkClaimLimits::default(),
                IncompleteTailPolicy::Truncate
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}

#[test]
fn every_truncated_record_prefix_trailing_byte_and_noncanonical_flag_is_refused() -> TestResult {
    let mut f = fixture(3)?;
    let receipt = f.cite()?;
    let bytes = encode(&receipt, f.store.checkpoint_digest)?;
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode(&extra).is_err());
    let (target, acquired, revision, after, digest) = decode(&bytes)?;
    assert_eq!(target, receipt.target);
    assert_eq!(acquired, receipt.acquisition);
    assert_eq!(revision, receipt.revision.digest());
    assert_eq!(digest, receipt.digest());
    assert_eq!(after, f.store.checkpoint_digest);
    let mut flag = bytes;
    let mut e = CanonicalEncoder::new();
    e.text(RECORD);
    e.text(&target.case_id);
    e.digest(target.expected);
    e.text(&target.hypothesis);
    flag[e.finish_checked()?.len()] = 2;
    assert!(decode(&flag).is_err());
    Ok(())
}
