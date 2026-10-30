#![forbid(unsafe_code)]
//! Exact case use of an admitted retained probe, with independently recoverable link custody.

use std::path::Path;

use fss_core::{AgentSession, CaseId, ContentDigest, DigestAlgorithm, TimestampNs};

use super::{ProbeCharge, ProbeChargeFailure, ProbeContext, ProbeRequest};
use crate::agent_session::checkpoint::journal::DurableSessionStore;
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationError, ProbeCitationInspection, ProbeCitationReceipt, ProbeCitationTarget,
};
use crate::agent_session::checkpoint::journal::supervision::SupervisionRegistration;
use crate::deployment_session::supervision::{
    GuardedSupervisionDelivery, SupervisionAction, SupervisionSessionDelivery,
    SupervisionSessionHead, SupervisionSessionOutcome, observe_head,
};
use crate::deployment_session::{
    DeploymentHistory, DeploymentSessionError, OrientLimits, SessionJournal, digest_of,
};

/// Optional exact use of a native Poll result, or a historical lookup with no native work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseProbeAction {
    /// Explicit support or counterevidence use; never an automatic assessment.
    Cite {
        /// Exact case predecessor and explicitly selected evidence side.
        target: ProbeCitationTarget,
        /// Explicit pre-work native state. An ambiguous retry cannot reserve more source work.
        expected_subscription_state: ContentDigest,
    },
    /// Recover a prior exact link after lost output; absence never authorizes a retry.
    InspectCitation(ProbeCitationTarget),
}

impl CaseProbeAction {
    /// Validate the closed link/lookup profile before configuration recovery or source work.
    pub fn validate(&self, request: &ProbeRequest) -> Result<(), DeploymentSessionError> {
        request.validate()?;
        let target = self.target();
        if CaseId::parse(target.case_id.as_str()).is_err()
            || CaseId::parse(target.hypothesis.as_str()).is_err()
            || target.case_id.len() > 128
            || target.hypothesis.len() > 128
            || target.expected.algorithm() != DigestAlgorithm::Sha256
            || target.expected.bytes() == [0; 32]
        {
            return Err(invalid());
        }
        match self {
            Self::Cite {
                expected_subscription_state,
                ..
            } if request.action == SupervisionAction::Poll
                && expected_subscription_state.algorithm() == DigestAlgorithm::Sha256
                && expected_subscription_state.bytes() != [0; 32] =>
            {
                Ok(())
            }
            Self::InspectCitation(_) if request.action == SupervisionAction::Inspect => Ok(()),
            _ => Err(invalid()),
        }
    }
    /// Exact case predecessor, hypothesis and operator-selected side.
    #[must_use]
    pub const fn target(&self) -> &ProbeCitationTarget {
        match self {
            Self::Cite { target, .. } | Self::InspectCitation(target) => target,
        }
    }

    /// Stable AOP-006 transition spelling.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Cite { .. } => "probe",
            Self::InspectCitation(_) => "probe-citation",
        }
    }

    /// An exact case target cannot share a command identity with an unlinked native poll.
    #[must_use]
    pub fn digest(&self, request: &ProbeRequest) -> ContentDigest {
        let target = self.target();
        digest_of("fss.reference_investigation_case_probe_request.v1", |e| {
            e.digest(request.digest());
            e.text(self.name());
            e.text(&target.case_id);
            e.digest(target.expected);
            e.text(&target.hypothesis);
            e.bool(target.contradicts);
            if let Self::Cite {
                expected_subscription_state,
                ..
            } = self
            {
                e.bool(true);
                e.digest(*expected_subscription_state);
            } else {
                e.bool(false);
            }
        })
    }
}

/// Private-field preflight result. It admits no source by itself and cannot bypass final CAS.
#[derive(Clone, Debug)]
pub struct ProbeCaseAdmission {
    request: ProbeRequest,
    target: ProbeCitationTarget,
    request_digest: ContentDigest,
    configuration: ContentDigest,
    expected_subscription_state: ContentDigest,
    native_hypothesis: String,
}

fn refused(reason: &str) -> DeploymentSessionError {
    DeploymentSessionError::SessionStale(reason.to_owned())
}

fn invalid() -> DeploymentSessionError {
    DeploymentSessionError::CaseRefused(InvestigationError::InvalidRecord)
}

fn current_head(root: &Path) -> Result<SupervisionSessionHead, DeploymentSessionError> {
    let history = DeploymentHistory::read(root, &OrientLimits::default())?;
    observe_head(&history).map_err(|error| DeploymentSessionError::Internal(error.to_string()))
}

/// Check the actual case owner on a fork before native evaluation/revalidation.
///
/// The shared native recipe owner supplies its checked hypothesis identity. Configuration is
/// opaque to the reference journal; the eventual receipt preserves this as a native-owner
/// assertion, not an independently replayed interpretation of the recipe bytes. The expected
/// report anchor is the existing pending anchor, or the current head for a new native report.
pub fn preflight_probe_case(
    root: &Path,
    request: &ProbeRequest,
    target: &ProbeCitationTarget,
    expected_subscription_state: ContentDigest,
    registration: &SupervisionRegistration,
    native_hypothesis: &str,
) -> Result<ProbeCaseAdmission, DeploymentSessionError> {
    request.validate()?;
    if request.action != SupervisionAction::Poll
        || expected_subscription_state.algorithm() != DigestAlgorithm::Sha256
        || expected_subscription_state.bytes() == [0; 32]
        || registration.session_id != request.session_id
        || registration.subscription_id != request.subscription_id
        || native_hypothesis != target.hypothesis
    {
        return Err(invalid());
    }
    let mut journal = SessionJournal::open(root)?;
    let result = (|| {
        let head = current_head(root)?;
        if head.anchor.state_root != request.expected_authority_root {
            return Err(refused("case probe authority changed before preflight"));
        }
        let state = journal
            .store
            .inspect_supervision(&request.principal, registration, head.observed_at)
            .map_err(|error| DeploymentSessionError::StoreInvalid(error.to_string()))?;
        if state.digest() != expected_subscription_state {
            return Err(refused(
                "case probe subscription differs from the explicit pre-work state; inspect progress before choosing a new state",
            ));
        }
        let report_anchor = state
            .pending()
            .map_or(&head.anchor, |pending| pending.anchor());
        journal.store.preflight_supervision_citation(
            &request.principal,
            &request.session_id,
            target,
            &request.subscription_id,
            report_anchor,
            head.observed_at,
        )?;
        if current_head(root)? != head {
            return Err(refused("case probe authority changed during preflight"));
        }
        Ok(ProbeCaseAdmission {
            request: request.clone(),
            target: target.clone(),
            request_digest: CaseProbeAction::Cite {
                target: target.clone(),
                expected_subscription_state,
            }
            .digest(request),
            configuration: registration.configuration_digest,
            expected_subscription_state,
            native_hypothesis: native_hypothesis.to_owned(),
        })
    })();
    // Native metadata admission may have retained a clock, even if the case preflight refused.
    journal.commit_pin()?;
    result
}

/// Sealed continuation from one exact native result to its committed case use.
/// The original native delivery and journal root are never rewritten.
#[derive(Clone, Debug)]
pub struct ProbeCaseLink {
    request: ProbeRequest,
    request_digest: ContentDigest,
    receipt: ProbeCitationReceipt,
    native_root: ContentDigest,
    journal_root: ContentDigest,
    subscription: ContentDigest,
    session: AgentSession,
    head: SupervisionSessionHead,
}

impl ProbeCaseLink {
    /// Historical result and exact immutable case revision.
    #[must_use]
    pub const fn receipt(&self) -> &ProbeCitationReceipt {
        &self.receipt
    }
    /// Session commit publishing the link; pending native delivery remains unacknowledged.
    #[must_use]
    pub const fn journal_root(&self) -> ContentDigest {
        self.journal_root
    }
    /// Original successful native Publish/Release root, preserved separately from the link.
    #[must_use]
    pub const fn native_journal_root(&self) -> ContentDigest {
        self.native_root
    }
    /// Exact original link-bearing command identity.
    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        self.request_digest
    }
}

/// A failed final boundary can leave a definite case link, independently of output or charging.
#[derive(Debug)]
pub struct ProbeCaseLinkFailure {
    /// Owning current-authority, case or durability refusal.
    pub error: DeploymentSessionError,
    /// Known committed revision/receipt; uncertainty never causes an automatic retry.
    pub committed: Option<ProbeCaseLink>,
}

/// Link only the native result of this preflight, with exact native-record adjacency.
pub fn commit_probe_case(
    root: &Path,
    admission: &ProbeCaseAdmission,
    guarded: &GuardedSupervisionDelivery,
) -> Result<ProbeCaseLink, ProbeCaseLinkFailure> {
    let mut committed = None;
    let result = (|| {
        let request = &admission.request;
        let delivery = guarded.delivery();
        if guarded.expected_subscription_state() != admission.expected_subscription_state
            || !matches!(delivery.outcome, SupervisionSessionOutcome::Report { .. })
            || delivery.session.session_id != request.session_id
            || delivery.session.principal_id != request.principal
            || delivery.subscription.registration().subscription_id != request.subscription_id
            || delivery.subscription.registration().configuration_digest != admission.configuration
            || delivery.head.anchor.state_root != request.expected_authority_root
        {
            return Err(invalid());
        }
        let mut journal = SessionJournal::open(root)?;
        if journal.store.committed_root() != delivery.journal_root
            || current_head(root)? != delivery.head
        {
            return Err(refused("native probe result changed before case linkage"));
        }
        let linked = journal
            .store
            .cite_supervision_report(
                &request.principal,
                &admission.target,
                admission.request_digest,
                delivery,
                &admission.native_hypothesis,
            )
            .map_err(DeploymentSessionError::from);
        if let Ok(receipt) = &linked {
            committed = Some(ProbeCaseLink {
                request: request.clone(),
                request_digest: admission.request_digest,
                receipt: receipt.clone(),
                native_root: delivery.journal_root,
                journal_root: journal.store.committed_root(),
                subscription: delivery.subscription.digest(),
                session: delivery.session.clone(),
                head: delivery.head.clone(),
            });
        }
        journal.commit_pin()?;
        linked?;
        if current_head(root)? != delivery.head {
            return Err(refused(
                "authority changed after the durable probe case link",
            ));
        }
        committed.clone().ok_or_else(invalid)
    })();
    result.map_err(|error| ProbeCaseLinkFailure { error, committed })
}

/// Historical link inspection admitted to a current case reader, with no source read or relink.
#[derive(Clone, Debug)]
pub struct ProbeCaseInspection {
    request: ProbeRequest,
    target: ProbeCitationTarget,
    request_digest: ContentDigest,
    inspection: ProbeCitationInspection,
    session: AgentSession,
    head: SupervisionSessionHead,
}

impl ProbeCaseInspection {
    /// Exact historical record, if present in the verified prefix.
    #[must_use]
    pub const fn inspection(&self) -> &ProbeCitationInspection {
        &self.inspection
    }
    /// This lookup's request identity; distinct from the historical native probe request.
    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        self.request_digest
    }
    /// Verified prefix after ordinary live case-read admission.
    #[must_use]
    pub fn journal_root(&self) -> ContentDigest {
        self.inspection.inspected_root()
    }
}

/// Historical metadata can already have been read when a later pin/head check refuses delivery.
#[derive(Debug)]
pub struct ProbeCaseInspectionFailure {
    /// Owning admission, history or pin refusal.
    pub error: DeploymentSessionError,
    /// Exact definitely inspected result; no current custody or automatic retry is implied.
    pub inspected: Option<ProbeCaseInspection>,
}

/// Recover an exact historical link even when a later case revision or new session is current.
/// No pending report, native attempt, case revision or source-hydration cursor is changed.
pub fn inspect_probe_case(
    root: &Path,
    request: &ProbeRequest,
    target: &ProbeCitationTarget,
) -> Result<ProbeCaseInspection, ProbeCaseInspectionFailure> {
    let mut inspected = None;
    let result = (|| {
        request.validate()?;
        if request.action != SupervisionAction::Inspect {
            return Err(invalid());
        }
        let mut journal = SessionJournal::open(root)?;
        let result = (|| {
            let head = current_head(root)?;
            if head.anchor.state_root != request.expected_authority_root {
                return Err(refused(
                    "probe citation lookup requires the exact current authority",
                ));
            }
            let session =
                journal
                    .store
                    .session(&request.principal, &request.session_id, head.observed_at)?;
            if !session.capabilities.contains("CAP-AGENT-CASE-WRITE-001") {
                return Err(DeploymentSessionError::CaseRefused(
                    InvestigationError::Denied,
                ));
            }
            let inspection = journal.store.inspect_probe_citation(
                &request.principal,
                &request.session_id,
                target,
                &request.subscription_id,
                1024 * 1024 + 16 * 1024,
                head.observed_at,
            )?;
            let outcome = ProbeCaseInspection {
                request: request.clone(),
                target: target.clone(),
                request_digest: CaseProbeAction::InspectCitation(target.clone()).digest(request),
                inspection,
                session,
                head,
            };
            inspected = Some(outcome.clone());
            Ok(outcome)
        })();
        journal.commit_pin()?;
        let outcome = result?;
        if current_head(root)? != outcome.head {
            return Err(refused(
                "authority changed after historical probe citation inspection",
            ));
        }
        Ok(outcome)
    })();
    result.map_err(|error| ProbeCaseInspectionFailure { error, inspected })
}

#[allow(clippy::too_many_arguments)] // every sealed authority and budget coordinate stays explicit
fn charge_case_output(
    root: &Path,
    request: &ProbeRequest,
    context: &ProbeContext,
    session: &AgentSession,
    head: &SupervisionSessionHead,
    expected_root: ContentDigest,
    quoted_tokens: u64,
    debit: impl FnOnce(&mut DurableSessionStore, TimestampNs) -> Result<u64, DeploymentSessionError>,
) -> Result<ProbeCharge, ProbeChargeFailure> {
    let mut committed = None;
    let result = (|| {
        if quoted_tokens == 0
            || quoted_tokens > u64::from(request.view.maximum_tokens())
            || quoted_tokens > context.remaining_tokens
            || context.oriented.orientation.view != request.view
            || context.oriented.session != *session
            || context.oriented.journal_root != expected_root
            || context.oriented.orientation.capsule().anchor != head.anchor
            || context.ledger_root != head.ledger_root
            || context.effect_root != head.effect_root
            || session.session_id != request.session_id
            || session.principal_id != request.principal
            || head.anchor.state_root != request.expected_authority_root
        {
            return Err(invalid());
        }
        let mut journal = SessionJournal::open(root)?;
        if journal.store.committed_root() != expected_root || current_head(root)? != *head {
            return Err(refused(
                "probe case projection changed before its durable quote",
            ));
        }
        let charge = debit(&mut journal.store, head.observed_at);
        if let Ok(remaining_tokens) = charge.as_ref() {
            committed = Some(ProbeCharge {
                journal_root: journal.store.committed_root(),
                quoted_tokens,
                remaining_tokens: *remaining_tokens,
            });
        }
        journal.commit_pin()?;
        charge?;
        if current_head(root)? != *head {
            return Err(refused(
                "authority changed after probe case projection charge",
            ));
        }
        committed.clone().ok_or_else(invalid)
    })();
    result.map_err(|error| ProbeChargeFailure { error, committed })
}

/// Charge under the sealed post-link root without changing the original native delivery root.
pub fn charge_linked_probe_delivery(
    root: &Path,
    request: &ProbeRequest,
    context: &ProbeContext,
    delivery: &SupervisionSessionDelivery,
    linked: &ProbeCaseLink,
    quoted_tokens: u64,
) -> Result<ProbeCharge, ProbeChargeFailure> {
    if linked.request != *request
        || linked.native_root != delivery.journal_root
        || linked.subscription != delivery.subscription.digest()
        || linked.session != delivery.session
        || linked.head != delivery.head
    {
        return Err(ProbeChargeFailure {
            error: invalid(),
            committed: None,
        });
    }
    charge_case_output(
        root,
        request,
        context,
        &linked.session,
        &linked.head,
        linked.journal_root,
        quoted_tokens,
        |store, now| {
            store
                .charge_supervision_projection(
                    &request.principal,
                    &delivery.subscription,
                    request.view,
                    quoted_tokens,
                    now,
                )
                .map_err(|error| DeploymentSessionError::StoreInvalid(error.to_string()))
        },
    )
}

/// Price metadata-only historical inspection under the current reader, without reviving its source.
pub fn charge_probe_case_inspection(
    root: &Path,
    request: &ProbeRequest,
    context: &ProbeContext,
    inspected: &ProbeCaseInspection,
    quoted_tokens: u64,
) -> Result<ProbeCharge, ProbeChargeFailure> {
    if inspected.request != *request {
        return Err(ProbeChargeFailure {
            error: invalid(),
            committed: None,
        });
    }
    charge_case_output(
        root,
        request,
        context,
        &inspected.session,
        &inspected.head,
        inspected.journal_root(),
        quoted_tokens,
        |store, now| {
            store
                .charge_probe_citation_inspection(
                    &request.principal,
                    &request.session_id,
                    &inspected.target,
                    request.view,
                    quoted_tokens,
                    now,
                )
                .map_err(Into::into)
        },
    )
}
