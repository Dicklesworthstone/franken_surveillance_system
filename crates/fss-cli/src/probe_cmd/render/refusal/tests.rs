#![forbid(unsafe_code)]
//! Real durable owners with an explicitly synthetic, local-only native source adapter.
//! This proves post-commit recovery disclosure, not detector or acquisition accuracy.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentView, BudgetVector, CaseHypothesis, ContentDigest, ContextAuthority, ContractError,
    EventId, KnowledgeState, LedgerAnchor, OperationId, PrincipalId, RootAuthoritySpec,
};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationChange, ProbeCitationTarget,
};
use fss_reference::agent_session::checkpoint::journal::supervision::{
    PendingSupervisionDelivery, SupervisionRegistration, SupervisionSourcePin,
};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::investigation::{
    CaseAction, CaseDeadline, CaseDraft, InvestigateRequest, investigate,
};
use fss_reference::deployment_session::probe::case::{
    CaseProbeAction, charge_linked_probe_delivery, commit_probe_case, preflight_probe_case,
};
use fss_reference::deployment_session::probe::{ProbeRequest, admit_probe};
use fss_reference::deployment_session::supervision::{
    SupervisionAction, SupervisionAdapterError, SupervisionEvaluation, SupervisionEvaluator,
    SupervisionSessionBinding, SupervisionSessionBoundary, SupervisionSessionControl,
    SupervisionSessionRequest, SupervisionValidation, supervise_existing_session_at,
    supervise_session,
};
use fss_reference::deployment_session::{OpenSessionRequest, open_session};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

use crate::error::ExitIdentity;
use crate::json_input::{Value, parse};
use crate::probe_cmd::render::{CaseProjection, response_with_case};
use crate::probe_cmd::{ProbeArgs, ProbeFailure};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &[u8] = b"explicitly synthetic local retained-probe source";
const REPORT: &[u8] =
    br#"{"fixture":"synthetic native custody","hypothesis":"hypothesis:fixture"}"#;
const CASE: &str = "case:probe-refusal";
const HYPOTHESIS: &str = "hypothesis:fixture";
const SUBSCRIPTION: &str = "probe:refusal";

struct Directory(PathBuf);

impl Directory {
    fn new() -> TestResult<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-probe-refusal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("exclusive refusal fixture directory unavailable".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct SyntheticEvaluator<'a> {
    root: &'a Path,
    source: &'a Path,
    principal: &'a PrincipalId,
    registration: &'a SupervisionRegistration,
    evaluations: usize,
}

impl SyntheticEvaluator<'_> {
    fn refused() -> SupervisionAdapterError {
        SupervisionAdapterError {
            identity: "fixture:synthetic-source-refused",
            reason: "synthetic source or exact native binding differs".to_owned(),
        }
    }

    fn source_pin(&self) -> Result<SupervisionSourcePin, SupervisionAdapterError> {
        let bytes = fs::read(self.source).map_err(|_| Self::refused())?;
        if bytes != SOURCE {
            return Err(Self::refused());
        }
        Ok(SupervisionSourcePin {
            event_id: EventId::parse("event:package:synthetic-refusal-source")
                .map_err(|_| Self::refused())?,
            event_root: ContentDigest::sha256(&bytes),
            source_verified: true,
            health_digest: None,
        })
    }
}

impl SupervisionSessionControl for SyntheticEvaluator<'_> {
    fn admit_session(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        _: SupervisionSessionBoundary,
    ) -> Result<(), SupervisionAdapterError> {
        if binding.root() != self.root
            || binding.principal() != self.principal
            || &binding.request().registration != self.registration
        {
            return Err(Self::refused());
        }
        Ok(())
    }
}

impl SupervisionEvaluator for SyntheticEvaluator<'_> {
    fn evaluate(
        &mut self,
        _: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
    ) -> Result<SupervisionEvaluation, SupervisionAdapterError> {
        let source = self.source_pin()?;
        self.evaluations += 1;
        Ok(SupervisionEvaluation {
            basis: anchor.clone(),
            payload: REPORT.to_vec(),
            report_receipt: ContentDigest::sha256(REPORT),
            sources: vec![source],
            detection_sources: Vec::new(),
        })
    }

    fn revalidate(
        &mut self,
        _: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
        pending: &PendingSupervisionDelivery,
    ) -> Result<SupervisionValidation, SupervisionAdapterError> {
        if pending.source_inventory() != [self.source_pin()?] {
            return Err(Self::refused());
        }
        Ok(SupervisionValidation {
            basis: anchor.clone(),
            receipt: ContentDigest::sha256(b"synthetic refusal source revalidation"),
            reserved_bytes: SOURCE.len() as u64,
            read_attempts: 1,
        })
    }
}

fn retained(root: &Path) -> TestResult<SessionRecoveryState> {
    Ok(inspect_session_bytes(
        &fs::read(root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?)
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing response field {key}").into())
}

#[test]
fn packaging_refusal_preserves_real_case_pending_and_committed_charge() -> TestResult {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    fs::create_dir(&root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:probe-refusal-fixture".to_owned(),
        operation_id: OperationId::parse("operation:probe-refusal-fixture")?,
        principal: "operator:probe-refusal-fixture".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::ZERO,
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"explicit probe refusal fixture"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        directory.0.join("io"),
    )?);
    drop(ReferenceDeployment::open(&root, "site:probe-refusal", &cx)?);
    cx.drain_and_finalize();
    let opened = open_session(
        &root,
        &OpenSessionRequest {
            mission: "Preserve committed probe progress through delivery refusal".to_owned(),
            objective: "Recover an exact citation without repeating source work".to_owned(),
            principal: PrincipalId::parse("principal:probe-refusal")?,
            view: AgentView::EpistemicMap,
            token_budget: 100_000,
        },
    )?;
    let session = &opened.session;
    let mut case_request = InvestigateRequest {
        session_id: session.session_id.clone(),
        principal: session.principal_id.clone(),
        action: CaseAction::Open(Box::new(CaseDraft {
            case_id: CASE.to_owned(),
            question: "Does this retained observation support the hypothesis?".to_owned(),
            decision_informed: "Choose the next independent observation".to_owned(),
            hypotheses: [HYPOTHESIS, "hypothesis:alternative"]
                .into_iter()
                .map(|id| CaseHypothesis {
                    hypothesis_id: id.to_owned(),
                    description: id.to_owned(),
                    epistemic_state: KnowledgeState::Unknown,
                    predictions: Vec::new(),
                    evidence: Vec::new(),
                    contradictions: Vec::new(),
                })
                .collect(),
            knowns: Vec::new(),
            unknowns: Vec::new(),
            discriminators: Vec::new(),
            probes: vec![SUBSCRIPTION.to_owned()],
            stop_rules: vec!["Inspect independent evidence".to_owned()],
            deadline: CaseDeadline::After(1_000_000_000),
        })),
    };
    let drafted = investigate(&root, &case_request)?;
    case_request.action = CaseAction::Change {
        case_id: CASE.to_owned(),
        expected: drafted.revision.ok_or("draft revision")?.digest(),
        change: InvestigationChange::Activate,
    };
    let active = investigate(&root, &case_request)?;
    let target = ProbeCitationTarget {
        case_id: CASE.to_owned(),
        expected: active.revision.ok_or("active revision")?.digest(),
        hypothesis: HYPOTHESIS.to_owned(),
        contradicts: false,
    };
    let configuration = br#"{"profile":"synthetic-unit-fixture"}"#.to_vec();
    let registration = SupervisionRegistration {
        session_id: session.session_id.clone(),
        subscription_id: SUBSCRIPTION.to_owned(),
        configuration_digest: ContentDigest::sha256(&configuration),
        configuration,
        max_read_bytes: 4096,
        max_read_attempts: 4,
        maximum_attempts: 4,
        max_report_bytes: 4096,
    };
    let source = directory.0.join("synthetic-source");
    fs::write(&source, SOURCE)?;
    let mut evaluator = SyntheticEvaluator {
        root: &root,
        source: &source,
        principal: &session.principal_id,
        registration: &registration,
        evaluations: 0,
    };
    let limits = OrientLimits {
        max_journal_bytes: 32 * 1024 * 1024,
        ..OrientLimits::default()
    };
    let mut native_request = SupervisionSessionRequest {
        registration: registration.clone(),
        expected_authority_root: session.current_anchor.state_root,
        action: SupervisionAction::Inspect,
    };
    let initial = supervise_session(
        &root,
        &session.principal_id,
        &native_request,
        &limits,
        &mut evaluator,
    )?;
    assert_eq!(evaluator.evaluations, 0);
    let expected_state = initial.subscription.digest();
    let request = ProbeRequest {
        session_id: session.session_id.clone(),
        principal: session.principal_id.clone(),
        subscription_id: SUBSCRIPTION.to_owned(),
        expected_authority_root: session.current_anchor.state_root,
        view: AgentView::Case,
        action: SupervisionAction::Poll,
    };
    let admission = preflight_probe_case(
        &root,
        &request,
        &target,
        expected_state,
        &registration,
        HYPOTHESIS,
    )?;
    native_request.action = SupervisionAction::Poll;
    let guarded = supervise_existing_session_at(
        &root,
        &session.principal_id,
        &native_request,
        expected_state,
        &limits,
        &mut evaluator,
    )?;
    assert_eq!(evaluator.evaluations, 1);
    let linked = commit_probe_case(&root, &admission, &guarded).map_err(|error| error.error)?;
    let context = admit_probe(&root, &request)?;
    let before_charge = retained(&root)?;
    let charge =
        charge_linked_probe_delivery(&root, &request, &context, guarded.delivery(), &linked, 500)
            .map_err(|error| error.error)?;
    let charged = retained(&root)?;
    assert_eq!(charged.sessions.len(), 1);
    assert_eq!(
        charged.sessions[0].spent_tokens,
        before_charge.sessions[0].spent_tokens + 500
    );
    assert_eq!(charged.supervisions, before_charge.supervisions);
    assert_eq!(charged.cases, before_charge.cases);
    assert_eq!(charged.inspection.root, charge.journal_root);
    let journal = fs::read(root.join("agent/sessions/journal.fssj"))?;
    let args = ProbeArgs {
        root: root.clone(),
        request,
        case: Some(CaseProbeAction::Cite {
            target,
            expected_subscription_state: expected_state,
        }),
    };
    // Each repeated diagnostic is below the individual context-item limit, but protected
    // inclusion as both warning and proposition alone exceeds Case's complete pack ceiling.
    let failure = ProbeFailure::stage(
        "ERR-OP-PRECONDITION-FAILED-001",
        "late refusal detail ".repeat(650),
        true,
    );
    assert!((failure.reason.len() * 2).div_ceil(4) > args.request.view.maximum_tokens() as usize);
    let packaging_error = response_with_case(
        &args,
        &context,
        Some(guarded.delivery()),
        None,
        Some(&charge),
        Some(&failure),
        Some(&CaseProjection::Linked(&linked)),
    )
    .err()
    .ok_or("complete protected refusal unexpectedly fit")?;
    assert!(
        matches!(
            packaging_error.downcast_ref::<ContractError>(),
            Some(ContractError::BudgetExhausted)
        ),
        "expected the real complete-pack budget refusal: {packaging_error}",
    );
    let (text, exit) = crate::probe_cmd::case::fail(
        &args,
        &context,
        Some(guarded.delivery()),
        Some(CaseProjection::Linked(&linked)),
        Some(&charge),
        &failure,
    );
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    let answer = parse(&text)?;
    assert_eq!(field(&answer, "payload")?, &Value::Null);
    assert_eq!(field(&answer, "compressionReceiptId")?, &Value::Null);
    assert_eq!(field(&answer, "outcome")?.text(), Some("partial"));
    assert_eq!(
        field(&answer, "effectiveViewId")?.text(),
        Some(AgentView::Case.id())
    );
    assert_eq!(
        field(&answer, "safeRetry")?.text(),
        Some("yes_after_reconcile")
    );
    assert_eq!(
        field(&answer, "payloadDigest")?.text(),
        Some(ContentDigest::sha256(b"null").to_text().as_str())
    );
    assert!(text.len() <= crate::probe_cmd::MAX_PROBE_OUTPUT_BYTES);
    assert!((text.len() as u64).div_ceil(4) <= u64::from(AgentView::Case.maximum_tokens()));
    assert!(
        !text.contains(&failure.reason),
        "unbounded diagnostic escaped fallback"
    );
    let pending = guarded
        .delivery()
        .subscription
        .pending()
        .ok_or("pending native report")?;
    let proofs = field(&answer, "proofPointers")?
        .array()
        .ok_or("proof list")?;
    for digest in [
        linked.receipt().digest(),
        linked.receipt().revision().digest(),
        linked.receipt().custody().digest(),
        linked.journal_root(),
        linked.native_journal_root(),
        pending.receipt(),
        pending.report_receipt(),
        pending.payload_digest(),
        charge.journal_root,
    ] {
        assert!(
            proofs.contains(&Value::Text(digest.to_text())),
            "lost known receipt {digest}"
        );
    }
    let completed = field(field(&answer, "executionBoundary")?, "completed")?
        .array()
        .ok_or("completed boundary")?;
    assert!(
        completed
            .iter()
            .filter_map(Value::text)
            .any(|row| row.contains("Definitely retained case link"))
    );
    assert!(
        completed
            .iter()
            .filter_map(Value::text)
            .any(|row| row.contains("Definitely committed output charge 500 tokens"))
    );
    let budgets = field(&answer, "budgets")?;
    assert_eq!(
        field(field(budgets, "consumed")?, "tokens")?.integer(),
        Some(500)
    );
    assert_eq!(fs::read(root.join("agent/sessions/journal.fssj"))?, journal);
    assert_eq!(
        retained(&root)?,
        charged,
        "rendering changed durable work or tokens"
    );
    assert_eq!(evaluator.evaluations, 1);
    assert_eq!(charged.supervisions[0].last_acknowledged(), None);

    // The real CLI Case-overflow fixture validates the outer JSON schema in the integration
    // harness. Keep this native-owner fixture entirely inside the Rust test process.
    Ok(())
}
