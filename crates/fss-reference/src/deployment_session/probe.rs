#![forbid(unsafe_code)]
//! AOP-006 admission for an explicitly selected, already registered retained-source probe.
//!
//! The supervisor journal and native evaluator remain the sole work and custody owners. This
//! layer adds the registered investigation capability and a protected current session context;
//! it cannot register a recipe, broaden grants, claim a physical fact or execute an effect.

use std::path::Path;

use fss_core::{
    AgentView, CanonicalEncode, ContentDigest, DigestAlgorithm, PrincipalId, SessionId,
};

use super::orient::{
    OrientSessionRequest, OrientedSession, project_probe_session_read, with_admitted_session_read,
};
use super::supervision::SupervisionAction;
use super::supervision::{SupervisionSessionDelivery, observe_head};
use super::{DeploymentSessionError, digest_of};
use crate::agent_session::checkpoint::journal::coordination::investigations::InvestigationError;

/// One existing subscription and exactly one explicit native action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRequest {
    /// Existing live session, never created or renewed by this request.
    pub session_id: SessionId,
    /// Admitted local principal, not an authority supplied by a recipe.
    pub principal: PrincipalId,
    /// Exact already registered session-local subscription label.
    pub subscription_id: String,
    /// Explicit current deployment authority, never silently rebased.
    pub expected_authority_root: ContentDigest,
    /// Explicit registered output view; Case is the transport default, never silently widened.
    pub view: AgentView,
    /// Inspect, poll, exact ACK, discard or one permitted scheduled advance.
    pub action: SupervisionAction,
}

impl ProbeRequest {
    /// Validate the closed retained-probe profile before session or source work.
    pub fn validate(&self) -> Result<(), DeploymentSessionError> {
        let valid_digest = |value: ContentDigest| {
            value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
        };
        let valid_action = match self.action {
            SupervisionAction::Inspect | SupervisionAction::Poll => true,
            SupervisionAction::Acknowledge(receipt) | SupervisionAction::Discard(receipt) => {
                valid_digest(receipt)
            }
            SupervisionAction::Advance {
                target_count,
                after_receipt,
            } => (2..=32).contains(&target_count) && valid_digest(after_receipt),
            SupervisionAction::ConfigureSchedule { .. } => false,
        };
        if fss_core::validate_id(&self.subscription_id).is_err()
            || !valid_digest(self.expected_authority_root)
            || !valid_action
            || !matches!(self.view, AgentView::Case | AgentView::Forensic)
        {
            return Err(DeploymentSessionError::CaseRefused(
                InvestigationError::InvalidRecord,
            ));
        }
        Ok(())
    }

    /// Stable AOP-006 intent spelling.
    pub const fn name(&self) -> &'static str {
        match self.action {
            SupervisionAction::Poll => "probe",
            SupervisionAction::Inspect => "probe-inspect",
            SupervisionAction::Acknowledge(_) => "probe-ack",
            SupervisionAction::Discard(_) => "probe-discard",
            SupervisionAction::Advance { .. } => "probe-advance",
            SupervisionAction::ConfigureSchedule { .. } => "unsupported-probe-configuration",
        }
    }

    /// Exact command identity. An ACK, discard or advance can never alias a poll request.
    pub fn digest(&self) -> ContentDigest {
        digest_of("fss.reference_investigation_probe_request.v1", |e| {
            self.principal.encode_canonical(e);
            self.session_id.encode_canonical(e);
            e.text(&self.subscription_id);
            e.digest(self.expected_authority_root);
            e.text(self.view.id());
            e.text(self.name());
            match self.action {
                SupervisionAction::Acknowledge(receipt) | SupervisionAction::Discard(receipt) => {
                    e.digest(receipt)
                }
                SupervisionAction::Advance {
                    target_count,
                    after_receipt,
                } => {
                    e.u32(target_count);
                    e.digest(after_receipt);
                }
                _ => {}
            }
        })
    }
}

/// Protected current context under the same immutable session admission as the probe grant.
pub struct ProbeContext {
    /// Ordinary session orientation, with uncertainty and active obligations preserved.
    pub oriented: OrientedSession,
    /// Exact canonical authority journal root of this context.
    pub ledger_root: ContentDigest,
    /// Exact effect journal root; reading it grants no effect authority.
    pub effect_root: ContentDigest,
    /// Remaining cumulative session allowance, never replenished by a probe.
    pub remaining_tokens: u64,
    /// Session journal and root-pin bytes read by this admission, including verification.
    pub session_bytes_read: u64,
}

/// Admit the live AOP-006 capability before recipe recovery or native work.
///
/// The existing read owner holds the session lock across complete replay, grant checks and
/// protected context compilation. The native supervision owner separately rechecks its pinned
/// complete authority projection before every action. No clock, budget, workspace or lease is
/// changed here. The finite supervisor invocation is the only writer.
pub fn admit_probe(
    root: &Path,
    request: &ProbeRequest,
) -> Result<ProbeContext, DeploymentSessionError> {
    request.validate()?;
    let (mut context, bytes, _) =
        with_admitted_session_read(root, &request.principal, &request.session_id, |read| {
            if !read
                .session
                .capabilities
                .contains("CAP-AGENT-CASE-WRITE-001")
            {
                return Err(DeploymentSessionError::CaseRefused(
                    InvestigationError::Denied,
                ));
            }
            if read.head.anchor.state_root != request.expected_authority_root {
                return Err(DeploymentSessionError::SessionStale(
                    "retained probe requires the exact explicitly selected authority root"
                        .to_owned(),
                ));
            }
            let oriented = project_probe_session_read(
                read,
                &OrientSessionRequest {
                    session_id: request.session_id.clone(),
                    principal: request.principal.clone(),
                    view: request.view,
                    budget_tokens: None,
                },
            )?;
            Ok(ProbeContext {
                oriented,
                ledger_root: read.head.ledger_root,
                effect_root: read.head.effect_journal_root,
                remaining_tokens: read.remaining_tokens,
                session_bytes_read: 0,
            })
        })?;
    context.session_bytes_read = bytes;
    Ok(context)
}

/// Durable quoted-token debit, distinct from native cumulative source-work reservations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeCharge {
    /// Exact synchronized session checkpoint containing this debit.
    pub journal_root: ContentDigest,
    /// Complete selected-view projection quote; not measured model/runtime tokens.
    pub quoted_tokens: u64,
    /// Remaining lifetime session allowance after this debit.
    pub remaining_tokens: u64,
}

/// A failed final delivery may already have consumed its token quote.
#[derive(Debug)]
pub struct ProbeChargeFailure {
    /// Native admission, persistence or current-history refusal.
    pub error: DeploymentSessionError,
    /// Definitely committed debit, even if the final root pin or head check later failed.
    pub committed: Option<ProbeCharge>,
}

impl std::fmt::Display for ProbeChargeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for ProbeChargeFailure {}

/// Debit a privately prepared complete response before releasing it to any transport.
///
/// The exact admitted journal, workspace and subscription must still be current. This acquires
/// one native session writer, checks full bounded history before and after the charge, and never
/// acknowledges, discards, advances, re-evaluates or replaces a pending report. An uncertain
/// append may retain a charge without output; recovery never refunds it or redelivers itself.
pub fn charge_probe_delivery(
    root: &Path,
    request: &ProbeRequest,
    context: &ProbeContext,
    delivery: &SupervisionSessionDelivery,
    quoted_tokens: u64,
) -> Result<ProbeCharge, ProbeChargeFailure> {
    let mut committed = None;
    let result = (|| -> Result<ProbeCharge, DeploymentSessionError> {
        request.validate()?;
        if quoted_tokens == 0
            || quoted_tokens > u64::from(request.view.maximum_tokens())
            || quoted_tokens > context.remaining_tokens
            || context.oriented.orientation.view != request.view
            || context.oriented.session != delivery.session
            || context.oriented.journal_root != delivery.journal_root
            || context.oriented.orientation.capsule().anchor != delivery.head.anchor
            || context.ledger_root != delivery.head.ledger_root
            || context.effect_root != delivery.head.effect_root
            || delivery.session.session_id != request.session_id
            || delivery.session.principal_id != request.principal
            || delivery.subscription.registration().subscription_id != request.subscription_id
        {
            return Err(DeploymentSessionError::CaseRefused(
                InvestigationError::InvalidRecord,
            ));
        }
        let limits = crate::agent_orient::OrientLimits::default();
        let mut journal = super::SessionJournal::open(root)?;
        if journal.store.committed_root() != context.oriented.journal_root {
            return Err(DeploymentSessionError::SessionStale(
                "probe delivery journal changed".to_owned(),
            ));
        }
        let history = super::DeploymentHistory::read(root, &limits)?;
        let head =
            observe_head(&history).map_err(|e| DeploymentSessionError::Internal(e.to_string()))?;
        if head != delivery.head || head.anchor.state_root != request.expected_authority_root {
            return Err(DeploymentSessionError::SessionStale(
                "probe delivery authority changed".to_owned(),
            ));
        }
        let charged = journal
            .store
            .charge_supervision_projection(
                &request.principal,
                &delivery.subscription,
                request.view,
                quoted_tokens,
                head.observed_at,
            )
            .map_err(|error| DeploymentSessionError::StoreInvalid(error.to_string()));
        if let Ok(remaining_tokens) = charged.as_ref() {
            committed = Some(ProbeCharge {
                journal_root: journal.store.committed_root(),
                quoted_tokens,
                remaining_tokens: *remaining_tokens,
            });
        }
        // A failed admission may still retain a clock observation. Commit the pin before return.
        journal.commit_pin()?;
        charged?;
        let current = super::DeploymentHistory::read(root, &limits)?;
        if observe_head(&current).map_err(|e| DeploymentSessionError::Internal(e.to_string()))?
            != head
        {
            return Err(DeploymentSessionError::SessionStale(
                "probe authority changed after durable token charge".to_owned(),
            ));
        }
        committed.clone().ok_or_else(|| {
            DeploymentSessionError::Internal("probe charge receipt missing".to_owned())
        })
    })();
    result.map_err(|error| ProbeChargeFailure { error, committed })
}
