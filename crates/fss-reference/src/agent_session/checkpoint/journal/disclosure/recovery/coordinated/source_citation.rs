#![forbid(unsafe_code)]
//! Case source acquisition must use a custody profile already committed by this exact owner.

use super::*;
use crate::agent_session::SessionAlias;
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    InvestigationError, SourceCitationError, SourceCitationInspection, SourceCitationReceipt,
    SourceCitationTarget,
};
use crate::agent_session::checkpoint::journal::disclosure::{
    MAX_RECORD_BYTES, SESSION_CHECKPOINT_RECORD_KIND, read_report, source_registration,
};
use crate::hydration::cursor_checkpoint::{CursorCheckpoint, MAX_RECORDS};
use crate::{PublishedSourceReader, SourceObjectBinding};
use fss_core::HydrationRequest;

fn preflight_error(error: DisclosureError) -> SourceCitationError {
    let cause = match error {
        DisclosureError::Durability(error) => DurableInvestigationError::Durability(error),
        DisclosureError::Session(error) => DurableInvestigationError::Durability(
            DurableSessionError::Session(error),
        ),
        // No private descriptor, cursor or source identity is exposed by catalog refusal.
        _ => DurableInvestigationError::Refused(InvestigationError::EvidenceRequired),
    };
    SourceCitationError::Preflight(cause)
}

impl DurableDisclosureStore {
    /// Acquires original source and cites it through the existing two-stage case transaction.
    ///
    /// Before any new source I/O, the exact binding must already be present in this journal's
    /// latest protected catalog checkpoint, not just in a reconstructed or volatile catalog.
    /// Use bind_source_object_durable to establish that requirement explicitly. A prior charged
    /// disclosure's source commitment is also sufficient. Neither one proves current custody:
    /// the selected reader still performs the full live read and binding validation.
    ///
    /// Existing case/session/privacy/basis/deadline/CAS checks run before acquisition. Only exact
    /// direct H3 requests without a continuation or downgrade are accepted by the native owner.
    /// A successful acquisition charge and subsequent case link remain TWO separate commits.
    /// Link failure retains its acquisition witness, never refunds or retries it; uncertain
    /// writes fence this whole owner. The ordinary SourceCitationError preserves those stages.
    ///
    /// No footage is returned or cached, no hypothesis is promoted to physical truth, and no
    /// effect grant is minted. Temporary source-hydration cursor changes are discarded: this
    /// case-facing operation exports no continuation and cannot consume a pre-existing one.
    /// Its receipt is the existing SourceCitationReceipt, not a disclosure-admission receipt.
    /// The runtime still owns descriptor publication, authentication and current privacy policy.
    pub fn cite_investigation_source(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        target: &SourceCitationTarget,
        request: &HydrationRequest,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<SourceCitationReceipt, SourceCitationError> {
        self.sessions.preflight()
            .map_err(|error| SourceCitationError::Preflight(error.into()))?;
        self.synchronize_catalog(Some(now)).map_err(preflight_error)?;
        // Resolve authenticated session/alias visibility on staged authority before inspecting
        // the private source requirement. Do not publish refusal-side preflight clocks.
        let mut admission = self.sessions.memory.clone();
        admission.resolve(principal, alias, &self.catalog, now)
            .map_err(|error| SourceCitationError::Preflight(
                DurableInvestigationError::Durability(DurableSessionError::Session(error)),
            ))?;
        let binding = self.catalog.source_binding(
            &request.handle_id, request.expected_descriptor_digest,
        ).ok_or_else(|| SourceCitationError::Preflight(
            DurableInvestigationError::Refused(InvestigationError::EvidenceRequired),
        ))?;
        self.require_committed_source(request.expected_descriptor_digest, binding)
            .map_err(preflight_error)?;
        // The native case-facing hydrator charges session authority but deliberately does not
        // journal its catalog. Keep its temporary catalog separate so no unjournaled cursor
        // issuance/retirement escapes into the durable disclosure owner's live catalog.
        let mut staged_catalog = self.catalog.clone();
        self.sessions.cite_investigation_source(
            principal, alias, target, request, &mut staged_catalog, reader, now,
        )
    }

    /// Recovers an exact historical citation receipt after a lost acknowledgement, without source.
    ///
    /// Use the original target/predecessor and hydration request digest. Current case visibility
    /// and the shared journal's complete-history/append rules still apply, including its ordinary
    /// durable clock observation. No reader, descriptor or alias is required; source availability
    /// is not a precondition for inspecting history. A new live session in the authorized mission
    /// can inspect the old session's receipt without regaining a source-read grant.
    ///
    /// A missing receipt establishes only that this exact link is not committed at the inspected
    /// root. It does NOT prove acquisition was uncharged, authorize retry, or refund any tokens.
    /// The result ceiling includes both the saved citation record and its entire historical case
    /// revision. This delegates to the native investigation owner and never mutates catalog
    /// bindings, source requirements or active/consumed continuations. Append uncertainty fences
    /// every operation on this owner; reconcile normally before asking again.
    pub fn inspect_source_citation(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        target: &SourceCitationTarget,
        request: ContentDigest,
        max_receipt_bytes: usize,
        now: TimestampNs,
    ) -> Result<SourceCitationInspection, DurableInvestigationError> {
        self.sessions.inspect_source_citation(
            principal, session, target, request, max_receipt_bytes, now,
        )
    }

    fn require_committed_source(
        &self,
        descriptor: ContentDigest,
        binding: &SourceObjectBinding,
    ) -> Result<(), DisclosureError> {
        let report = read_report(self.sessions.path(), self.sessions.limits)?;
        if report.last_root() != self.committed_root() || report.incomplete_tail().is_some() {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let record = report.records().iter().rev().find(|record| {
            record.kind() == SESSION_CHECKPOINT_RECORD_KIND
                && source_registration::has_catalog_snapshot(record.payload())
        }).ok_or(fss_core::HydrationError::LevelUnavailable)?;
        let (bytes, _) = source_registration::catalog_snapshot(record.payload(), self.sessions.limits)?;
        let checkpoint = CursorCheckpoint::decode(bytes, MAX_RECORD_BYTES, MAX_RECORDS)?;
        if !checkpoint.requires_source(descriptor, binding.custody_binding_digest()) {
            return Err(fss_core::HydrationError::LevelUnavailable.into());
        }
        Ok(())
    }
}
