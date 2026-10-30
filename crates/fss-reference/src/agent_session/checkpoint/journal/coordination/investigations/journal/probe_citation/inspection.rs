#![forbid(unsafe_code)]
//! Historical link recovery has no dependency on live source or the original subscription lease.

use super::*;
use crate::agent_session::ReferenceSessionError;
use crate::agent_session::checkpoint::journal::coordination::investigations::MAX_INVESTIGATION_BYTES;

/// Exact historical result under current case-reader authority, never a fresh native report.
///
/// Absence does not prove that no attempt was charged: native publication may have preceded an
/// interrupted citation. It cannot authorize a relink, source retry, refund or implicit ACK.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeCitationInspection {
    inspected_root: ContentDigest,
    committed: Option<(ContentDigest, ProbeCitationReceipt)>,
    receipt_bytes: usize,
}

impl ProbeCitationInspection {
    /// Exact verified journal prefix after ordinary live case-read admission.
    pub const fn inspected_root(&self) -> ContentDigest {
        self.inspected_root
    }
    /// Original citation commit, distinct from the later reader-admission root.
    pub fn citation_root(&self) -> Option<ContentDigest> {
        self.committed.as_ref().map(|(root, _)| *root)
    }
    /// Original proof and historical case revision, even after the visible case advances.
    pub fn receipt(&self) -> Option<&ProbeCitationReceipt> {
        self.committed.as_ref().map(|(_, receipt)| receipt)
    }
    /// Full saved record plus reconstructed revision bytes admitted to the output ceiling.
    pub const fn receipt_bytes(&self) -> usize {
        self.receipt_bytes
    }
}

impl DurableSessionStore {
    fn admit_probe_citation_reader(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        target: &ProbeCitationTarget,
        now: TimestampNs,
    ) -> Result<InvestigationRevision, DurableInvestigationError> {
        self.preflight()?;
        target.validate().map_err(refusal)?;
        self.verify_storage()?;
        // Retain ordinary refusal-side clock/expiry observations before returning any metadata.
        let live = self.session(principal, session, now)?;
        if !live.capabilities.contains(CASE_WRITE) {
            return Err(refusal(InvestigationError::Denied));
        }
        self.investigate(
            principal,
            session,
            InvestigationCommand::Inspect {
                case_id: target.case_id.clone(),
                revision: None,
            },
            now,
        )
    }

    /// Recover one exact original case target and subscription without running a native probe.
    ///
    /// Case CAS makes a committed target unique. Original request, session, configuration and
    /// authority remain in the returned receipt; a new same-principal/mission session does not
    /// revive the old lease or turn historical custody into a current availability assertion.
    /// The complete journal and record/revision byte bounds refuse before partial disclosure.
    pub fn inspect_probe_citation(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        target: &ProbeCitationTarget,
        subscription: &str,
        max_receipt_bytes: usize,
        now: TimestampNs,
    ) -> Result<ProbeCitationInspection, DurableInvestigationError> {
        if subscription.is_empty()
            || subscription.len() > 128
            || fss_core::validate_id(subscription).is_err()
        {
            return Err(refusal(InvestigationError::InvalidRecord));
        }
        let visible = self.admit_probe_citation_reader(principal, session, target, now)?;
        let report = read_report(self.path(), self.limits)?;
        let inspected_root = self.committed_root();
        if report.last_root() != inspected_root
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let cases = self
            .coordination
            .as_ref()
            .and_then(|state| state.cases.as_ref())
            .ok_or(DurableSessionError::InvalidHistory)?;
        let case = cases
            .entries
            .get(&target.case_id)
            .ok_or(DurableSessionError::InvalidHistory)?;
        let mut committed = None;
        let mut receipt_bytes = 0;
        for record in report.records() {
            if record.kind() != COORDINATION_COMMAND_RECORD_KIND {
                continue;
            }
            let mut d = CanonicalDecoder::new(record.payload());
            if d.text()? != RECORD {
                continue;
            }
            let (recorded_target, custody, revision, after, digest) =
                codec::decode(record.payload())?;
            if recorded_target != *target || custody.native.subscription != subscription {
                continue;
            }
            if committed.is_some()
                || custody.native.principal != *principal
                || custody.privacy_class != visible.privacy_class()
            {
                return Err(DurableSessionError::InvalidHistory.into());
            }
            let revision = std::iter::once(&case.head)
                .chain(case.history.iter())
                .find(|candidate| candidate.digest() == revision)
                .ok_or(DurableSessionError::InvalidHistory)?;
            if revision.principal() != principal
                || revision.record().mission_id != visible.record().mission_id
                || revision.privacy_class() != visible.privacy_class()
                || revision.predecessor() != Some(target.expected)
                || revision.author_session != custody.native.session
                || revision.changed_at != custody.native.observed_at
            {
                return Err(DurableSessionError::InvalidHistory.into());
            }
            let revision_bytes = revision
                .try_canonical_bytes()
                .map_err(DurableSessionError::from)?
                .len();
            receipt_bytes = record
                .payload()
                .len()
                .checked_add(revision_bytes)
                .ok_or(DurableSessionError::CapacityExceeded)?;
            if revision_bytes > MAX_INVESTIGATION_BYTES || receipt_bytes > max_receipt_bytes {
                return Err(DurableSessionError::CapacityExceeded.into());
            }
            let receipt = ProbeCitationReceipt {
                custody,
                target: recorded_target,
                revision: revision.clone(),
            };
            if receipt.digest() != digest || codec::encode(&receipt, after)? != record.payload() {
                return Err(DurableSessionError::InvalidHistory.into());
            }
            committed = Some((record.root(), receipt));
        }
        Ok(ProbeCitationInspection {
            inspected_root,
            committed,
            receipt_bytes,
        })
    }

    /// Charge the explicitly selected bounded Case or Forensic metadata projection.
    /// Current case visibility and CASE-WRITE are required; the old subscription is not reopened,
    /// no native attempts are spent, and historical receipt inspection never refunds prior cost.
    pub(crate) fn charge_probe_citation_inspection(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        target: &ProbeCitationTarget,
        view: fss_core::AgentView,
        tokens: u64,
        now: TimestampNs,
    ) -> Result<u64, DurableInvestigationError> {
        if !matches!(
            view,
            fss_core::AgentView::Case | fss_core::AgentView::Forensic
        ) || tokens == 0
            || tokens > u64::from(view.maximum_tokens())
        {
            return Err(refusal(InvestigationError::InvalidRecord));
        }
        self.admit_probe_citation_reader(principal, session, target, now)?;
        self.transact(|memory| {
            let entry = memory.live_entry(principal, session, now)?;
            if !entry.session.capabilities.contains(CASE_WRITE) {
                return Err(ReferenceSessionError::GrantEscalation);
            }
            entry.spent_tokens = entry
                .spent_tokens
                .checked_add(tokens)
                .filter(|spent| *spent <= entry.session.token_budget)
                .ok_or(ReferenceSessionError::BudgetExceeded)?;
            Ok(entry.session.token_budget - entry.spent_tokens)
        })
        .map_err(Into::into)
    }
}
