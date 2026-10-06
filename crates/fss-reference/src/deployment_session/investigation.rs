#![forbid(unsafe_code)]
//! Durable, mission-scoped investigation cases over a deployment root (AOP-006 `investigate`).
//!
//! **Agent plane only.** Cases are committed to the deployment's existing session journal
//! (`<root>/agent/sessions/journal.fssj`) through the durable case engine in
//! [`crate::agent_session::checkpoint::journal::coordination::investigations`]; the authority
//! ledger, the effect journal, and the spool are only read. A case is cognition: recording a
//! hypothesis, citation, probe, or conclusion never executes a probe, never certifies physical
//! truth, and never grants effect authority.
//!
//! **Basis.** A case is opened at the session's exact anchor and contract basis; every change
//! re-checks both, so a case opened before a `session resume` is refused as stale until it is
//! explicitly rebased. A rebase names the session's current anchor and cites, as its rationale,
//! the session's committed workspace revision at that anchor (the runtime-verified record of the
//! move). Old citations then need readmission before they can support an assessment.
//!
//! **Clock.** `now` is the deployment evidence clock (as for sessions), so decision deadlines and
//! the case store's clock watermark are measured on committed evidence time.
//!
//! **Refusals.** A refused command can still advance session or case clock watermarks; the
//! journal commits (and the root pin is replaced) before the refusal is returned.

use fss_core::{
    AgentSession, CaseDiscriminator, CaseHypothesis, ContentDigest, HypothesisDisposition,
    InvestigationLifecycle, InvestigationState, InvestigationStateParams, KnownStatement,
    LedgerAnchor, PrincipalId, SessionId, TimestampNs,
};

use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, OrientCaseBrief,
    OrientLimits, SESSION_PRIVACY_SCOPE, SessionJournal, digest_of, evidence_now, orient_bound,
};
use crate::agent_session::checkpoint::journal::DurableSessionStore;
use crate::agent_session::checkpoint::journal::coordination::investigations::evolution::{
    InvestigationCitation, InvestigationEvolution, InvestigationEvolutionRequest,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationChange, InvestigationCommand, InvestigationError, InvestigationRevision,
};
use fss_core::CanonicalEncode;

/// Privacy domain every case is admitted under (the session's only privacy class).
pub const CASE_PRIVACY_CLASS: &str = SESSION_PRIVACY_SCOPE;

/// How the decision deadline of a new case is given.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseDeadline {
    /// Absolute deployment evidence time, in nanoseconds.
    At(i128),
    /// Nanoseconds after the current deployment evidence time.
    After(i128),
}

/// The caller-authored content of a new case. Identity, mission, revision, lifecycle state, basis
/// anchor, and contract basis are never taken from the caller: they come from the live session.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseDraft {
    /// Stable case identity (`[A-Za-z0-9._:-]`, 1..=128 characters).
    pub case_id: String,
    /// The question the case answers.
    pub question: String,
    /// The decision the answer informs.
    pub decision_informed: String,
    /// Competing hypotheses (at least two).
    pub hypotheses: Vec<CaseHypothesis>,
    /// Known statements, each with its own knowledge state.
    pub knowns: Vec<KnownStatement>,
    /// Unknowns carried explicitly (they must be acknowledged at conclusion).
    pub unknowns: Vec<KnownStatement>,
    /// Discriminating observations.
    pub discriminators: Vec<CaseDiscriminator>,
    /// Probe handles (recorded, never executed).
    pub probes: Vec<String>,
    /// Stop rules (at least one; conclusion must name one exactly).
    pub stop_rules: Vec<String>,
    /// Decision deadline.
    pub deadline: CaseDeadline,
}

/// One `investigate` intent.
#[derive(Clone, Debug, PartialEq)]
pub enum CaseAction {
    /// Open a new case in `draft` (an identical retry returns the existing head).
    Open(Box<CaseDraft>),
    /// Read the current head, or an exact retained revision.
    Inspect {
        /// Stable case identity.
        case_id: String,
        /// Exact historical revision, or the head.
        revision: Option<ContentDigest>,
    },
    /// Apply one typed change to exactly the expected head.
    Change {
        /// Stable case identity.
        case_id: String,
        /// Full head revision digest (optimistic precondition).
        expected: ContentDigest,
        /// Typed change.
        change: InvestigationChange,
    },
    /// Invalidate the case's old applicability at the session's current (newer) anchor.
    Rebase {
        /// Stable case identity.
        case_id: String,
        /// Full head revision digest.
        expected: ContentDigest,
    },
    /// Readmit an inherited citation after a rebase, on the evidence owner's receipt.
    Readmit {
        /// Stable case identity.
        case_id: String,
        /// Full head revision digest.
        expected: ContentDigest,
        /// Inherited citation and its exact intended use.
        citation: InvestigationCitation,
        /// Applicability receipt supplied by the evidence owner.
        witness: ContentDigest,
    },
    /// Append a previously unnamed alternative with a discriminator and a probe handle.
    Expand {
        /// Stable case identity.
        case_id: String,
        /// Full head revision digest.
        expected: ContentDigest,
        /// New hypothesis (starts unknown, no evidence).
        hypothesis: Box<CaseHypothesis>,
        /// Discriminator separating it from at least one existing hypothesis.
        discriminator: Box<CaseDiscriminator>,
        /// Probe handle (recorded, never executed).
        probe: String,
    },
    /// List the heads of every case visible to the session (no case is changed).
    List,
}

impl CaseAction {
    /// Stable spelling of the intent family (`--transition` / intent names).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Open(_) => "open",
            Self::Inspect { .. } => "inspect",
            Self::Change { change, .. } => match change {
                InvestigationChange::Activate => "activate",
                InvestigationChange::Cite { .. } => "cite",
                InvestigationChange::Assess { .. } => "assess",
                InvestigationChange::SetState { .. } => "set_state",
                InvestigationChange::Conclude { .. } => "conclude",
            },
            Self::Rebase { .. } => "rebase",
            Self::Readmit { .. } => "readmit",
            Self::Expand { .. } => "expand",
            Self::List => "list",
        }
    }

    /// True when the intent can append a case revision.
    #[must_use]
    pub const fn writes_case(&self) -> bool {
        !matches!(self, Self::Inspect { .. } | Self::List)
    }
}

/// One `investigate` request. Principal and session come from the caller; time from the runtime.
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigateRequest {
    /// Session whose authority admits the command.
    pub session_id: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// The intent.
    pub action: CaseAction,
}

/// The answer to one admitted `investigate` command.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseAnswer {
    /// The live session after the command.
    pub session: AgentSession,
    /// The addressed revision (absent for `List`).
    pub revision: Option<InvestigationRevision>,
    /// Heads of every case visible to the session, in stable identity order.
    pub cases: Vec<InvestigationRevision>,
    /// Situation as of the session's anchor, bound to the session.
    pub orientation: DeploymentOrientation,
    /// Whether this command appended a case revision.
    pub committed: bool,
    /// Committed session-journal root after the command.
    pub journal_root: ContentDigest,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
    /// Deployment evidence time the command ran at.
    pub now: TimestampNs,
    /// True when the deployment head has moved past the session's anchor (hand off and resume
    /// to rebase the session, then rebase each case).
    pub head_moved: bool,
}

/// True for a case that still needs cognition (not resolved, refuted, cancelled, or closed).
#[must_use]
pub const fn is_open_state(state: InvestigationLifecycle) -> bool {
    !matches!(
        state,
        InvestigationLifecycle::Resolved
            | InvestigationLifecycle::Refuted
            | InvestigationLifecycle::Cancelled
            | InvestigationLifecycle::Closed
    )
}

/// Heads visible to `session`: same principal, same mission, and an admitted privacy domain.
pub(super) fn visible_cases(
    store: &DurableSessionStore,
    session: &AgentSession,
) -> Vec<InvestigationRevision> {
    store
        .investigation_heads()
        .into_iter()
        .filter(|head| {
            head.principal() == &session.principal_id
                && head.record().mission_id == session.mission_id
                && session.privacy_scope.contains(head.privacy_class())
        })
        .collect()
}

/// The open cases visible to `session`, as a session-bound orientation at `anchor` lists them.
pub(super) fn case_briefs(
    store: &DurableSessionStore,
    session: &AgentSession,
    anchor: &LedgerAnchor,
) -> Vec<OrientCaseBrief> {
    visible_cases(store, session)
        .iter()
        .filter(|case| is_open_state(case.record().state))
        .map(|case| OrientCaseBrief {
            case_id: case.record().investigation_id.clone(),
            state: case.record().state.as_str().to_owned(),
            revision: case.record().revision,
            live_hypotheses: case
                .control()
                .hypotheses()
                .iter()
                .filter(|(_, disposition)| **disposition == HypothesisDisposition::Live)
                .map(|(hypothesis, _)| hypothesis.clone())
                .collect(),
            rebase_required: &case.record().basis_anchor != anchor,
        })
        .collect()
}

/// Identities of the open cases among `cases`, in stable order.
#[must_use]
pub fn open_case_ids(cases: &[InvestigationRevision]) -> Vec<String> {
    cases
        .iter()
        .filter(|case| is_open_state(case.record().state))
        .map(|case| case.record().investigation_id.clone())
        .collect()
}

/// Open cases whose basis anchor is no longer the session's anchor (they need a rebase).
#[must_use]
pub fn stale_case_ids(cases: &[InvestigationRevision], session: &AgentSession) -> Vec<String> {
    cases
        .iter()
        .filter(|case| {
            is_open_state(case.record().state)
                && case.record().basis_anchor != session.current_anchor
        })
        .map(|case| case.record().investigation_id.clone())
        .collect()
}

fn encode_action(encoder: &mut fss_core::CanonicalEncoder, action: &CaseAction) {
    encoder.text(action.name());
    match action {
        CaseAction::Open(draft) => {
            encoder.text(&draft.case_id);
            encoder.text(&draft.question);
            encoder.text(&draft.decision_informed);
            encoder.u32(draft.hypotheses.len() as u32);
            for hypothesis in &draft.hypotheses {
                encoder.text(&hypothesis.hypothesis_id);
                encoder.text(&hypothesis.description);
                hypothesis.epistemic_state.encode_canonical(encoder);
                encoder.u32(hypothesis.predictions.len() as u32);
                for prediction in &hypothesis.predictions {
                    encoder.text(prediction);
                }
            }
            for group in [&draft.knowns, &draft.unknowns] {
                encoder.u32(group.len() as u32);
                for statement in group {
                    encoder.text(&statement.statement_id);
                    encoder.text(&statement.text);
                    statement.epistemic_state.encode_canonical(encoder);
                    encoder.u32(statement.basis.len() as u32);
                    for basis in &statement.basis {
                        encoder.text(basis);
                    }
                }
            }
            encoder.u32(draft.discriminators.len() as u32);
            for discriminator in &draft.discriminators {
                encoder.text(&discriminator.discriminator_id);
                encoder.text(&discriminator.description);
                encoder.u32(discriminator.separates.len() as u32);
                for separated in &discriminator.separates {
                    encoder.text(separated);
                }
                encoder.u32(discriminator.expected_outcomes.len() as u32);
                for outcome in &discriminator.expected_outcomes {
                    encoder.text(outcome);
                }
            }
            encoder.u32(draft.probes.len() as u32);
            for probe in &draft.probes {
                encoder.text(probe);
            }
            encoder.u32(draft.stop_rules.len() as u32);
            for rule in &draft.stop_rules {
                encoder.text(rule);
            }
            match draft.deadline {
                CaseDeadline::At(at) => {
                    encoder.text("at");
                    encoder.i128(at);
                }
                CaseDeadline::After(after) => {
                    encoder.text("after");
                    encoder.i128(after);
                }
            }
        }
        CaseAction::Inspect { case_id, revision } => {
            encoder.text(case_id);
            encoder.bool(revision.is_some());
            if let Some(revision) = revision {
                encoder.digest(*revision);
            }
        }
        CaseAction::Change {
            case_id,
            expected,
            change,
        } => {
            encoder.text(case_id);
            encoder.digest(*expected);
            match change {
                InvestigationChange::Activate => {}
                InvestigationChange::Cite {
                    hypothesis,
                    evidence,
                    contradicts,
                } => {
                    encoder.text(hypothesis);
                    encoder.digest(*evidence);
                    encoder.bool(*contradicts);
                }
                InvestigationChange::Assess {
                    hypothesis,
                    disposition,
                    evidence,
                } => {
                    encoder.text(hypothesis);
                    encoder.text(disposition.as_str());
                    encoder.digest(*evidence);
                }
                InvestigationChange::SetState { state, reason } => {
                    encoder.text(state.as_str());
                    encoder.digest(*reason);
                }
                InvestigationChange::Conclude {
                    refuted,
                    stop_rule,
                    assessment,
                    residual_unknowns,
                } => {
                    encoder.bool(*refuted);
                    encoder.text(stop_rule);
                    encoder.digest(*assessment);
                    encoder.u32(residual_unknowns.len() as u32);
                    for residual in residual_unknowns {
                        encoder.text(residual);
                    }
                }
            }
        }
        CaseAction::Rebase { case_id, expected } => {
            encoder.text(case_id);
            encoder.digest(*expected);
        }
        CaseAction::Readmit {
            case_id,
            expected,
            citation,
            witness,
        } => {
            encoder.text(case_id);
            encoder.digest(*expected);
            encoder.text(&citation.hypothesis);
            encoder.digest(citation.evidence);
            encoder.bool(citation.contradicts);
            encoder.digest(*witness);
        }
        CaseAction::Expand {
            case_id,
            expected,
            hypothesis,
            discriminator,
            probe,
        } => {
            encoder.text(case_id);
            encoder.digest(*expected);
            encoder.text(&hypothesis.hypothesis_id);
            encoder.text(&hypothesis.description);
            encoder.u32(hypothesis.predictions.len() as u32);
            for prediction in &hypothesis.predictions {
                encoder.text(prediction);
            }
            encoder.text(&discriminator.discriminator_id);
            encoder.text(&discriminator.description);
            encoder.u32(discriminator.separates.len() as u32);
            for separated in &discriminator.separates {
                encoder.text(separated);
            }
            encoder.u32(discriminator.expected_outcomes.len() as u32);
            for outcome in &discriminator.expected_outcomes {
                encoder.text(outcome);
            }
            encoder.text(probe);
        }
        CaseAction::List => {}
    }
}

/// Runs one `investigate` command against the deployment's session journal (AOP-006).
///
/// The session must be live and hold the case grant. The case store is initialized on first use
/// (one-way, fixed ceilings). Every write is committed to the session journal and the journal
/// root is pinned before the answer (or the refusal) is returned. The situation returned is the
/// one as of the session's anchor, the anchor every case revision is bound to.
pub fn investigate(
    root: &std::path::Path,
    request: &InvestigateRequest,
) -> Result<CaseAnswer, DeploymentSessionError> {
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let request_digest = digest_of("fss.reference_investigate_request.v1", |encoder| {
        request.session_id.encode_canonical(encoder);
        request.principal.encode_canonical(encoder);
        encode_action(encoder, &request.action);
        head.anchor.encode_canonical(encoder);
    });
    let mut journal = SessionJournal::open(root)?;
    let principal = &request.principal;
    let session_id = &request.session_id;
    let super::SessionPosition {
        session,
        workspace,
        snapshot,
        head_moved,
    } = super::session_position(&mut journal, &history, principal, session_id, now)?;
    let refused = |journal: &SessionJournal, error: InvestigationError| {
        journal.commit_pin()?;
        Err(DeploymentSessionError::CaseRefused(error))
    };
    if !journal.store.investigations_enabled() {
        match &request.action {
            CaseAction::Open(_) => journal.enable_cases()?,
            CaseAction::List => {}
            // No case was ever opened in this deployment: indistinguishable from an unknown case.
            _ => return refused(&journal, InvestigationError::Unavailable),
        }
    }
    let heads_before: Vec<ContentDigest> = journal
        .store
        .investigation_heads()
        .iter()
        .map(InvestigationRevision::digest)
        .collect();
    let outcome = match &request.action {
        CaseAction::List => None,
        CaseAction::Open(draft) => {
            let deadline = match draft.deadline {
                CaseDeadline::At(at) => Some(at),
                CaseDeadline::After(after) if after > 0 => now.0.checked_add(after),
                CaseDeadline::After(_) => None,
            };
            let Some(deadline) = deadline else {
                return refused(&journal, InvestigationError::InvalidRecord);
            };
            let record = InvestigationState::new(InvestigationStateParams {
                investigation_id: draft.case_id.clone(),
                // The session's stored basis: every deployment session is opened under the
                // reference contract basis its orientation compiles with.
                contract_basis: fss_core::reference_contract_basis(),
                mission_id: session.mission_id.clone(),
                revision: 1,
                state: InvestigationLifecycle::Draft,
                question: draft.question.clone(),
                decision_informed: draft.decision_informed.clone(),
                basis_anchor: session.current_anchor.clone(),
                hypotheses: draft.hypotheses.clone(),
                knowns: draft.knowns.clone(),
                unknowns: draft.unknowns.clone(),
                discriminators: draft.discriminators.clone(),
                probes: draft.probes.clone(),
                stop_rules: draft.stop_rules.clone(),
                decision_deadline_ns: deadline,
            });
            let Ok(record) = record else {
                return refused(&journal, InvestigationError::InvalidRecord);
            };
            Some(journal.store.investigate(
                principal,
                session_id,
                InvestigationCommand::Open {
                    record: Box::new(record),
                    privacy_class: CASE_PRIVACY_CLASS.to_owned(),
                },
                now,
            ))
        }
        CaseAction::Inspect { case_id, revision } => Some(journal.store.investigate(
            principal,
            session_id,
            InvestigationCommand::Inspect {
                case_id: case_id.clone(),
                revision: *revision,
            },
            now,
        )),
        CaseAction::Change {
            case_id,
            expected,
            change,
        } => Some(journal.store.investigate(
            principal,
            session_id,
            InvestigationCommand::Change {
                case_id: case_id.clone(),
                expected: *expected,
                change: change.clone(),
            },
            now,
        )),
        CaseAction::Rebase { case_id, expected } => Some(journal.store.evolve_investigation(
            principal,
            session_id,
            InvestigationEvolutionRequest {
                case_id: case_id.clone(),
                expected: *expected,
                change: InvestigationEvolution::Rebase {
                    anchor: session.current_anchor.clone(),
                    witness: workspace.digest(),
                },
            },
            now,
        )),
        CaseAction::Readmit {
            case_id,
            expected,
            citation,
            witness,
        } => Some(journal.store.evolve_investigation(
            principal,
            session_id,
            InvestigationEvolutionRequest {
                case_id: case_id.clone(),
                expected: *expected,
                change: InvestigationEvolution::ReadmitCitation {
                    citation: citation.clone(),
                    witness: *witness,
                },
            },
            now,
        )),
        CaseAction::Expand {
            case_id,
            expected,
            hypothesis,
            discriminator,
            probe,
        } => Some(journal.store.evolve_investigation(
            principal,
            session_id,
            InvestigationEvolutionRequest {
                case_id: case_id.clone(),
                expected: *expected,
                change: InvestigationEvolution::Expand {
                    hypothesis: hypothesis.clone(),
                    discriminator: discriminator.clone(),
                    probe: probe.clone(),
                },
            },
            now,
        )),
    };
    let revision = match outcome {
        None => None,
        Some(Ok(revision)) => Some(revision),
        Some(Err(error)) => {
            let error = DeploymentSessionError::from(error);
            if matches!(error, DeploymentSessionError::CaseRefused(_)) {
                journal.commit_pin()?;
            }
            return Err(error);
        }
    };
    let session = journal.store.session(principal, session_id, now)?;
    journal.commit_pin()?;
    let heads_after: Vec<ContentDigest> = journal
        .store
        .investigation_heads()
        .iter()
        .map(InvestigationRevision::digest)
        .collect();
    let committed = heads_before != heads_after;
    let cases = visible_cases(&journal.store, &session);
    let orientation = orient_bound(
        &snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        case_briefs(&journal.store, &session, &session.current_anchor),
    )?;
    Ok(CaseAnswer {
        session,
        revision,
        cases,
        orientation,
        committed,
        journal_root: journal.store.committed_root(),
        request_digest,
        now,
        head_moved,
    })
}
