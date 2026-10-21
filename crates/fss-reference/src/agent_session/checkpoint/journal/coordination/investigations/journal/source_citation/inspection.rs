#![forbid(unsafe_code)]
//! Recover an exact committed citation without reacquiring source or repeating its case mutation.

use super::*;
use crate::agent_session::checkpoint::journal::read_report;
use crate::agent_session::checkpoint::journal::coordination::investigations::MAX_INVESTIGATION_BYTES;

/// Historical result scoped to one verified journal prefix and a currently authorized case reader.
///
/// A missing receipt means only that this exact target/request has no committed citation in that
/// prefix. Acquisition may still have been charged before a failed link. It is NOT permission to
/// refund, reacquire, retry the link, or infer that no source was read. No source bytes or current
/// custody claim are returned. This result has no canonical decoder and is not a bearer grant.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceCitationInspection {
    inspected_root: ContentDigest,
    committed: Option<(ContentDigest, SourceCitationReceipt)>,
    receipt_bytes: usize,
}

impl SourceCitationInspection {
    /// Exact prefix inspected after durable case-read admission, including its clock observation.
    #[must_use]
    pub const fn inspected_root(&self) -> ContentDigest {
        self.inspected_root
    }

    /// Historical commit that published the citation, not the later inspection/admission root.
    #[must_use]
    pub fn citation_root(&self) -> Option<ContentDigest> {
        self.committed.as_ref().map(|(root, _)| *root)
    }

    /// The original receipt and historical case revision, even if the current case has advanced.
    /// None does not distinguish an unattempted acquisition from a charged-but-unlinked one.
    #[must_use]
    pub fn receipt(&self) -> Option<&SourceCitationReceipt> {
        self.committed.as_ref().map(|(_, receipt)| receipt)
    }

    /// Canonical saved-record bytes plus complete revision bytes admitted to the result ceiling.
    /// Zero when no citation matched. This is not measured memory, CPU, physical I/O or token cost.
    #[must_use]
    pub const fn receipt_bytes(&self) -> usize {
        self.receipt_bytes
    }
}

impl DurableSessionStore {
    /// Inspects the exact historical outcome after a citation acknowledgement was lost.
    ///
    /// The target includes the ORIGINAL predecessor, hypothesis and evidence side. The request
    /// digest must be the original hydration request, not a newly issued replacement. At most one
    /// matching citation may exist; ambiguity refuses instead of choosing a last or best result.
    ///
    /// Complete bounded journal validation precedes mutation. The existing investigation Inspect
    /// operation then checks the live principal, session, capability, mission and case privacy,
    /// durably retaining its ordinary clock/expiry observation. A new authorized session in the
    /// same principal/mission may inspect an old session's receipt; no expired session is revived.
    /// The inspection may consume journal capacity, but never debits source tokens, changes a case
    /// revision or touches a hydration cursor. An uncertain admission fences the shared owner and
    /// returns no receipt until ordinary reconciliation succeeds.
    ///
    /// Source, descriptor, alias and catalog availability are deliberately irrelevant to this
    /// HISTORICAL lookup. No reader is invoked and no link is retried. Stored receipt, revision and
    /// exact record bytes must agree with the semantically replayed history. A result cannot prove
    /// current source retention, hypothesis truth, applicability or effect authority.
    ///
    /// The scan is bounded by this owner's journal byte/record limits and retained case history.
    /// `max_receipt_bytes` bounds saved-record bytes plus the full reconstructed revision, not merely
    /// its digest. Overflow refuses without partial output. Revision encoding itself is already
    /// bounded by MAX_INVESTIGATION_BYTES; this ceiling is not a preemptive CPU or allocation meter.
    pub fn inspect_source_citation(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        target: &SourceCitationTarget,
        request: ContentDigest,
        max_receipt_bytes: usize,
        now: TimestampNs,
    ) -> Result<SourceCitationInspection, DurableInvestigationError> {
        self.preflight()?;
        target.validate().map_err(DurableInvestigationError::Refused)?;
        if target.case_id.len() > 128 || target.hypothesis.len() > 128 {
            return Err(DurableInvestigationError::Refused(InvestigationError::InvalidRecord));
        }
        // Do not append even an observation to corrupt complete history.
        self.verify_storage()?;
        let visible = self.investigate(
            principal,
            session,
            InvestigationCommand::Inspect { case_id: target.case_id.clone(), revision: None },
            now,
        )?;
        let report = read_report(self.path(), self.limits)?;
        let inspected_root = self.committed_root();
        if report.last_root() != inspected_root
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let cases = self.coordination.as_ref().and_then(|state| state.cases.as_ref())
            .ok_or(DurableSessionError::InvalidHistory)?;
        let case = cases.entries.get(&target.case_id).ok_or(DurableSessionError::InvalidHistory)?;
        let mut found = None;
        let mut receipt_bytes = 0;
        for record in report.records() {
            if record.kind() != COORDINATION_COMMAND_RECORD_KIND {
                continue;
            }
            let mut prefix = CanonicalDecoder::new(record.payload());
            if prefix.text().map_err(DurableSessionError::from)? != RECORD {
                continue;
            }
            let (recorded_target, acquisition, revision, after, digest) = decode(record.payload())?;
            if recorded_target != *target || acquisition.request != request {
                continue;
            }
            if found.is_some() || acquisition.principal != *principal
                || acquisition.privacy_class != visible.privacy_class()
            {
                return Err(DurableSessionError::InvalidHistory.into());
            }
            let revision = std::iter::once(&case.head).chain(case.history.iter())
                .find(|candidate| candidate.digest() == revision)
                .ok_or(DurableSessionError::InvalidHistory)?;
            if revision.principal() != principal
                || revision.record().mission_id != visible.record().mission_id
                || revision.privacy_class() != visible.privacy_class()
                || revision.predecessor() != Some(target.expected)
            {
                return Err(DurableSessionError::InvalidHistory.into());
            }
            let revision_bytes = revision.try_canonical_bytes()
                .map_err(DurableSessionError::from)?.len();
            receipt_bytes = record.payload().len().checked_add(revision_bytes)
                .ok_or(DurableSessionError::CapacityExceeded)?;
            if revision_bytes > MAX_INVESTIGATION_BYTES || receipt_bytes > max_receipt_bytes {
                return Err(DurableSessionError::CapacityExceeded.into());
            }
            let receipt = SourceCitationReceipt {
                acquisition, target: recorded_target, revision: revision.clone(),
            };
            if receipt.digest() != digest || encode(&receipt, after)? != record.payload() {
                return Err(DurableSessionError::InvalidHistory.into());
            }
            found = Some((record.root(), receipt));
        }
        Ok(SourceCitationInspection { inspected_root, committed: found, receipt_bytes })
    }
}

#[cfg(test)]
mod tests;
