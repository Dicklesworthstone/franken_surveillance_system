#![forbid(unsafe_code)]
//! Real shared journal transitions. Native media custody is separately exercised by CLI fixtures;
//! these synthetic native-owner reports qualify case linkage, replay and crash boundaries.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationLimits,
    tests::{basis, opening, params},
};
use crate::agent_session::checkpoint::journal::supervision::{
    SupervisionRegistration, SupervisionSubscription,
};
use crate::agent_session::work_claims::WorkClaimLimits;
use fss_core::{AgentSession, KnowledgeState};

mod recovery;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PRIVATE_REPORT: &[u8] =
    br#"{"native_owner":"synthetic journal fixture","hypothesis":"hypothesis:a"}"#;
const RECEIPT_CEILING: usize = 64 * 1024;

struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-probe-citation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive probe citation fixture capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: Directory,
    store: DurableSessionStore,
    session: AgentSession,
    target: ProbeCitationTarget,
    registration: SupervisionRegistration,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = Directory::new()?;
        let mut input = params("session:probe")?;
        input.capabilities.extend(
            [
                "CAP-AGENT-SESSION-READ-001",
                "CAP-AGENT-SESSION-WRITE-001",
                "CAP-AGENT-SITUATION-READ-001",
                CASE_WRITE,
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let mut store = DurableSessionStore::create(
            directory.0.join("session.fssj"),
            DurableSessionLimits::default(),
        )?;
        let session = store.open(input, basis(), TimestampNs(10))?;
        store.enable_coordination(WorkClaimLimits::default())?;
        store.enable_investigations(InvestigationLimits::default())?;
        let revision = store.investigate(
            &session.principal_id,
            &session.session_id,
            opening()?,
            TimestampNs(10),
        )?;
        let target = ProbeCitationTarget {
            case_id: "case:window".into(),
            expected: revision.digest(),
            hypothesis: "hypothesis:a".into(),
            contradicts: false,
        };
        let configuration =
            br#"{"profile":"synthetic native owner","hypothesis":"hypothesis:a"}"#.to_vec();
        let registration = SupervisionRegistration {
            session_id: session.session_id.clone(),
            subscription_id: "probe:crop".into(),
            configuration_digest: ContentDigest::sha256(&configuration),
            configuration,
            max_read_bytes: 1024,
            max_read_attempts: 8,
            maximum_attempts: 8,
            max_report_bytes: 4096,
        };
        store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        Ok(Self {
            directory,
            store,
            session,
            target,
            registration,
        })
    }

    fn path(&self) -> PathBuf {
        self.directory.0.join("session.fssj")
    }
    fn head(&self) -> SupervisionSessionHead {
        SupervisionSessionHead {
            anchor: self.session.current_anchor.clone(),
            ledger_root: ContentDigest::sha256(b"synthetic native ledger observation"),
            effect_root: ContentDigest::sha256(b"synthetic native effect observation"),
            observed_at: TimestampNs(10),
        }
    }
    fn native(&mut self, replayed: bool) -> TestResult<SupervisionSessionDelivery> {
        let state = self.store.inspect_supervision(
            &self.session.principal_id,
            &self.registration,
            TimestampNs(10),
        )?;
        let state = self.store.reserve_supervision(
            &self.session.principal_id,
            &state,
            &self.session.current_anchor,
            TimestampNs(10),
        )?;
        let reservation = state.reservation().ok_or("missing reservation")?.clone();
        let (state, payload, validation) = if replayed {
            let pending = state.pending().ok_or("missing historical pending")?;
            let (state, payload) = self.store.release_supervision_payload(
                &self.session.principal_id,
                &state,
                &reservation,
                pending.receipt(),
                TimestampNs(10),
            )?;
            (
                state,
                payload,
                Some(SupervisionValidation {
                    basis: self.session.current_anchor.clone(),
                    receipt: ContentDigest::sha256(b"synthetic native revalidation"),
                    reserved_bytes: 37,
                    read_attempts: 2,
                }),
            )
        } else {
            let state = self.store.publish_supervision(
                &self.session.principal_id,
                &state,
                &reservation,
                PRIVATE_REPORT.to_vec(),
                vec![],
                ContentDigest::sha256(b"synthetic native report receipt"),
                TimestampNs(10),
            )?;
            (state, PRIVATE_REPORT.to_vec(), None)
        };
        let pending = state.pending().ok_or("missing published report")?.clone();
        Ok(SupervisionSessionDelivery {
            session: self.session.clone(),
            head: self.head(),
            subscription: state,
            journal_root: self.store.committed_root(),
            outcome: SupervisionSessionOutcome::Report {
                payload,
                pending,
                replayed,
                validation,
            },
        })
    }
    fn preflight(&mut self) -> Result<(), DurableInvestigationError> {
        self.store.preflight_supervision_citation(
            &self.session.principal_id,
            &self.session.session_id,
            &self.target,
            &self.registration.subscription_id,
            &self.session.current_anchor,
            TimestampNs(10),
        )
    }
    fn cite(
        &mut self,
        delivery: &SupervisionSessionDelivery,
    ) -> Result<ProbeCitationReceipt, DurableInvestigationError> {
        self.store.cite_supervision_report(
            &self.session.principal_id,
            &self.target,
            ContentDigest::sha256(b"exact original case probe command"),
            delivery,
            "hypothesis:a",
        )
    }
    fn inspect(
        &mut self,
        maximum: usize,
    ) -> Result<ProbeCitationInspection, DurableInvestigationError> {
        self.store.inspect_probe_citation(
            &self.session.principal_id,
            &self.session.session_id,
            &self.target,
            &self.registration.subscription_id,
            maximum,
            TimestampNs(10),
        )
    }
    fn retained(&self) -> TestResult<SupervisionSubscription> {
        crate::agent_session::checkpoint::journal::inspect_session_bytes(
            &fs::read(self.path())?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?
        .supervisions
        .into_iter()
        .find(|state| state.registration().session_id == self.session.session_id)
        .ok_or_else(|| "missing retained subscription".into())
    }
    fn reopen(mut self) -> TestResult<Self> {
        let root = self.store.committed_root();
        let path = self.path();
        drop(self.store);
        self.store = DurableSessionStore::open_existing_with_coordination(
            path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        Ok(self)
    }
}

#[test]
fn exact_native_report_is_cited_without_assessment_ack_or_source_charge() -> TestResult {
    for contradicts in [false, true] {
        let mut f = Fixture::new()?;
        f.target.contradicts = contradicts;
        let before = fs::read(f.path())?;
        f.preflight()?;
        assert_eq!(fs::read(f.path())?, before);
        let original_case = f.store.investigation_heads()[0].clone();
        let delivery = f.native(false)?;
        let receipt = f.cite(&delivery)?;
        let citation_root = f.store.committed_root();
        assert_eq!(receipt.custody().native_root(), delivery.journal_root);
        assert_eq!(
            receipt.custody().pending_receipt(),
            delivery.subscription.pending().ok_or("pending")?.receipt()
        );
        assert_eq!(receipt.custody().attempts_reserved(), 1);
        assert!(!receipt.custody().replayed());
        assert!(receipt.custody().validation().is_none());
        assert_eq!(receipt.revision().predecessor(), Some(f.target.expected));
        let hypothesis = &receipt.revision().record().hypotheses[0];
        assert_eq!(
            if contradicts {
                &hypothesis.contradictions
            } else {
                &hypothesis.evidence
            },
            &vec![ContentDigest::sha256(PRIVATE_REPORT)]
        );
        assert_eq!(hypothesis.epistemic_state, KnowledgeState::Unknown);
        assert_eq!(receipt.revision().control(), original_case.control());
        assert_eq!(
            receipt.revision().record().unknowns,
            original_case.record().unknowns
        );
        assert_eq!(f.retained()?, delivery.subscription);
        let mut f = f.reopen()?;
        let inspection = f.inspect(RECEIPT_CEILING)?;
        assert_eq!(inspection.receipt(), Some(&receipt));
        assert_eq!(inspection.citation_root(), Some(citation_root));
        assert_eq!(f.retained()?, delivery.subscription);
        assert_eq!(
            f.store.remaining_token_budget(
                &f.session.principal_id,
                &f.session.session_id,
                TimestampNs(10)
            )?,
            100
        );
    }
    Ok(())
}

#[test]
fn pending_report_requires_exact_successful_release_and_preserves_its_historical_identity()
-> TestResult {
    let mut f = Fixture::new()?;
    let original = f.native(false)?;
    let delivery = f.native(true)?;
    assert_ne!(delivery.journal_root, original.journal_root);
    assert!(f.cite(&original).is_err());
    let receipt = f.cite(&delivery)?;
    assert!(receipt.custody().replayed());
    assert!(receipt.custody().validation().is_some());
    assert_eq!(
        receipt.custody().payload_digest(),
        ContentDigest::sha256(PRIVATE_REPORT)
    );
    assert_eq!(
        receipt.custody().pending_receipt(),
        original.subscription.pending().ok_or("pending")?.receipt()
    );
    assert_eq!(receipt.custody().attempts_reserved(), 2);
    assert_eq!(f.retained()?, delivery.subscription);
    f.reopen()?.store.verify_storage()?;
    Ok(())
}

#[test]
fn stale_case_missing_hypothesis_probe_basis_or_deadline_refuses_before_native_work() -> TestResult
{
    for scenario in 0..6 {
        let mut f = Fixture::new()?;
        let mut anchor = f.session.current_anchor.clone();
        let mut subscription = f.registration.subscription_id.clone();
        let mut now = TimestampNs(10);
        match scenario {
            0 => f.target.expected = ContentDigest::sha256(b"stale predecessor"),
            1 => f.target.hypothesis = "hypothesis:missing".into(),
            2 => subscription = "probe:unregistered".into(),
            3 => anchor.state_root = ContentDigest::sha256(b"different report authority"),
            4 => now = TimestampNs(101),
            _ => f.target.case_id = "case:hidden".into(),
        }
        let before = fs::read(f.path())?;
        assert!(
            f.store
                .preflight_supervision_citation(
                    &f.session.principal_id,
                    &f.session.session_id,
                    &f.target,
                    &subscription,
                    &anchor,
                    now
                )
                .is_err()
        );
        assert_eq!(fs::read(f.path())?, before);
        assert_eq!(f.retained()?.attempts_reserved(), 0);
    }
    Ok(())
}

#[test]
fn wrong_payload_metadata_action_hypothesis_or_intervening_record_cannot_link() -> TestResult {
    for scenario in 0..5 {
        let mut f = Fixture::new()?;
        let mut delivery = f.native(false)?;
        let mut hypothesis = "hypothesis:a";
        match scenario {
            0 => {
                if let SupervisionSessionOutcome::Report { payload, .. } = &mut delivery.outcome {
                    payload.push(b'!');
                }
            }
            1 => delivery.outcome = SupervisionSessionOutcome::Inspected,
            2 => hypothesis = "hypothesis:b",
            3 => {
                f.store.investigate(
                    &f.session.principal_id,
                    &f.session.session_id,
                    InvestigationCommand::Inspect {
                        case_id: f.target.case_id.clone(),
                        revision: None,
                    },
                    TimestampNs(10),
                )?;
                delivery.journal_root = f.store.committed_root();
            }
            _ => {
                f.store.reserve_supervision(
                    &f.session.principal_id,
                    &delivery.subscription,
                    &f.session.current_anchor,
                    TimestampNs(10),
                )?;
                delivery.journal_root = f.store.committed_root();
            }
        }
        let before = fs::read(f.path())?;
        assert!(
            f.store
                .cite_supervision_report(
                    &f.session.principal_id,
                    &f.target,
                    ContentDigest::sha256(b"request"),
                    &delivery,
                    hypothesis
                )
                .is_err()
        );
        assert_eq!(fs::read(f.path())?, before);
        assert_eq!(f.store.investigation_heads()[0].digest(), f.target.expected);
    }
    Ok(())
}
