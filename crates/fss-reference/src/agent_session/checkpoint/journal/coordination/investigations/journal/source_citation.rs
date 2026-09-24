#![forbid(unsafe_code)]
//! Acquire original source through session authority, then journal its exact use in a case.
//!
//! Acquisition and citation are deliberately two durable stages. A failed link cannot refund an
//! acquired source or pretend that its charge never committed. Recorded custody is historical;
//! replay does not reread deleted footage or turn source identity into physical-world knowledge.

use std::fmt;

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaseId, ContentDigest, HydrationLevel,
    HydrationRequest, PrincipalId, SessionId, TimestampNs,
};
use fss_ledger::RecoveryReport;

use super::{
    COORDINATION_COMMAND_RECORD_KIND, CoordinationState, DurableInvestigationError,
    DurableSessionError, DurableSessionLimits, DurableSessionStore, InvestigationChange,
    InvestigationCommand, InvestigationError, InvestigationRevision, PendingSession,
};
use crate::agent_session::checkpoint::journal::coordination::source_hydration::DurableSourceHydrationError;
use crate::agent_session::{ReferenceSessionStore, SessionAlias};
use crate::{PublishedSourceReader, ReferenceHydrationCatalog, SourceHydrationError};

pub(super) const RECORD: &str = "fss.reference_source_citation_record.v1";
const RECEIPT: &str = "fss.reference_source_citation_receipt.v1";
const ACQUISITION: &str = "fss.reference_source_citation_acquisition.v1";
const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Exact intended use of a source, not permission to disclose it or replace a case revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCitationTarget {
    /// Existing investigation identity.
    pub case_id: String,
    /// Full current case revision; successful retries with this old revision are refused pre-I/O.
    pub expected: ContentDigest,
    /// Existing hypothesis receiving the citation.
    pub hypothesis: String,
    /// Counterevidence when true, supporting evidence otherwise.
    pub contradicts: bool,
}

impl SourceCitationTarget {
    fn command(&self, evidence: ContentDigest) -> InvestigationCommand {
        InvestigationCommand::Change {
            case_id: self.case_id.clone(),
            expected: self.expected,
            change: InvestigationChange::Cite {
                hypothesis: self.hypothesis.clone(),
                evidence,
                contradicts: self.contradicts,
            },
        }
    }

    fn validate(&self) -> Result<(), InvestigationError> {
        CaseId::parse(self.case_id.as_str()).map_err(|_| InvestigationError::InvalidRecord)?;
        CaseId::parse(self.hypothesis.as_str()).map_err(|_| InvestigationError::InvalidRecord)?;
        Ok(())
    }
}

/// Private-field historical custody/charging witness minted only after live exact H3 validation.
///
/// The journal and acquisition roots require independently trusted custody. This is not a bearer
/// capability, an applicability assessment, or evidence that source remains available after now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAcquisition {
    principal: PrincipalId,
    session: SessionId,
    generation: u64,
    slot: u64,
    handle_id: String,
    privacy_class: String,
    descriptor: ContentDigest,
    subject: ContentDigest,
    publication: ContentDigest,
    artifact: ContentDigest,
    request: ContentDigest,
    hydration_receipt: ContentDigest,
    charge_root: ContentDigest,
    charged_session: ContentDigest,
    tokens: u64,
    payload_bytes: u64,
    observed_at: TimestampNs,
}

impl SourceAcquisition {
    /// Journal root after acquisition; a failed subsequent link does not roll this back.
    #[must_use]
    pub const fn charged_root(&self) -> ContentDigest {
        self.charge_root
    }
    /// Exact original source object that was acquired, not an arbitrary caller citation.
    #[must_use]
    pub const fn subject_digest(&self) -> ContentDigest {
        self.subject
    }
    /// Publication closure reverified by the source owner at acquisition time.
    #[must_use]
    pub const fn publication_root(&self) -> ContentDigest {
        self.publication
    }
    /// Exact receipt from the existing source hydration protocol.
    #[must_use]
    pub const fn hydration_receipt_digest(&self) -> ContentDigest {
        self.hydration_receipt
    }
    /// Quoted tokens charged for acquisition, not a measured compute or I/O cost.
    #[must_use]
    pub const fn charged_tokens(&self) -> u64 {
        self.tokens
    }
    /// Historical runtime observation time; not a promise of future availability.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Canonical audit identity of this observation, not authentication by itself.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(ACQUISITION)
    }
}

impl CanonicalEncode for SourceAcquisition {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        self.principal.encode_canonical(e);
        self.session.encode_canonical(e);
        e.u64(self.generation);
        e.u64(self.slot);
        e.text(&self.handle_id);
        e.text(&self.privacy_class);
        for digest in [
            self.descriptor,
            self.subject,
            self.publication,
            self.artifact,
            self.request,
            self.hydration_receipt,
            self.charge_root,
            self.charged_session,
        ] {
            e.digest(digest);
        }
        e.u64(self.tokens);
        e.u64(self.payload_bytes);
        e.i128(self.observed_at.0);
    }
}

/// Both stages succeeded. Source bytes are deliberately absent from this case-facing result.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceCitationReceipt {
    acquisition: SourceAcquisition,
    target: SourceCitationTarget,
    revision: InvestigationRevision,
}

impl SourceCitationReceipt {
    /// Historical acquisition/charge witness retained in the citation journal record.
    #[must_use]
    pub const fn acquisition(&self) -> &SourceAcquisition {
        &self.acquisition
    }
    /// Exact hypothesis, side, and predecessor to which this observation was attached.
    #[must_use]
    pub const fn target(&self) -> &SourceCitationTarget {
        &self.target
    }
    /// New immutable case revision. Knowledge states and applicability barriers are unchanged.
    #[must_use]
    pub const fn revision(&self) -> &InvestigationRevision {
        &self.revision
    }
    /// Binds the acquisition and exact case use; never a source-disclosure capability.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(RECEIPT);
        self.acquisition.encode_canonical(&mut e);
        encode_target(&self.target, &mut e);
        e.digest(self.revision.digest());
        ContentDigest::sha256(&e.finish())
    }
}

/// Failure stages remain distinguishable; a charged-but-unlinked source is never called success.
#[derive(Debug)]
pub enum SourceCitationError {
    /// No acquisition was started. Cloned case preflight never modifies live authority.
    Preflight(DurableInvestigationError),
    /// The source hydrator refused or has an uncertain charge; inspect/reconcile its own outcome.
    Acquisition(DurableSourceHydrationError),
    /// Hydration returned, but exact source-response validation failed. Never attach that result.
    Validation {
        /// Known journal root after the hydration call; a charge may already be committed.
        charged_root: ContentDigest,
        /// Private nested cause, not suitable for unfiltered transport diagnostics.
        cause: SourceHydrationError,
    },
    /// Source acquisition succeeded; the citation did not return a committed result.
    /// A durability error can mean an indeterminate link. Reconcile, then inspect; never resend.
    Link {
        /// Exact successful acquisition that must not be refunded or represented as unattempted.
        acquisition: Box<SourceAcquisition>,
        /// Expected refusal or shared-journal uncertainty.
        cause: DurableInvestigationError,
    },
}

impl fmt::Display for SourceCitationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Preflight(_) => "source citation preflight refused",
            Self::Acquisition(_) => "source citation acquisition did not complete",
            Self::Validation { .. } => "source citation validation refused after hydration",
            Self::Link { .. } => "source acquired; citation requires inspection or reconciliation",
        })
    }
}
impl std::error::Error for SourceCitationError {}

impl DurableSessionStore {
    /// Acquires exact original H3 evidence, commits its charge, then journals its use in a case.
    ///
    /// The case and source must share the exact privacy class, anchor and ContractBasis. Case
    /// preflight runs on clones before source I/O. Only direct H3 requests without downgrade or
    /// continuation are accepted; this case-facing path does not export raw bytes or cursors.
    ///
    /// These are TWO commits, not a distributed transaction with custody. A link error retains
    /// the successful acquisition witness and never refunds/retries it. The trusted owner supplies
    /// the catalog/reader and runtime clock. Source existence proves neither the hypothesis nor
    /// current applicability: ordinary rebase/readmission and assessment rules are untouched.
    #[allow(clippy::too_many_arguments)] // all authority and custody owners remain explicit
    pub fn cite_investigation_source(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        target: &SourceCitationTarget,
        request: &HydrationRequest,
        catalog: &mut ReferenceHydrationCatalog,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<SourceCitationReceipt, SourceCitationError> {
        self.preflight()
            .map_err(|e| SourceCitationError::Preflight(e.into()))?;
        let preflight = || -> Result<_, DurableInvestigationError> {
            target
                .validate()
                .map_err(DurableInvestigationError::Refused)?;
            if request.requested_level != HydrationLevel::H3
                || request.allow_lower_level
                || request.continuation.is_some()
            {
                return Err(DurableInvestigationError::Refused(
                    InvestigationError::InvalidRecord,
                ));
            }
            let state = self
                .coordination
                .as_ref()
                .ok_or(DurableSessionError::InvalidHistory)?;
            let mut cases = state
                .cases
                .as_ref()
                .ok_or(DurableSessionError::InvalidHistory)?
                .clone();
            let mut memory = self.memory.clone();
            let prior = cases
                .execute(
                    &mut memory,
                    principal,
                    &alias.session_id,
                    &InvestigationCommand::Inspect {
                        case_id: target.case_id.clone(),
                        revision: None,
                    },
                    now,
                )
                .map_err(DurableInvestigationError::Refused)?;
            if prior.digest() != target.expected {
                return Err(DurableInvestigationError::Refused(
                    InvestigationError::StaleRevision,
                ));
            }
            // Lookup after case admission. The descriptor comes from the authority-owned catalog.
            let descriptor = catalog
                .current_descriptor(&request.handle_id)
                .filter(|h| {
                    h.descriptor_digest == request.expected_descriptor_digest
                        && h.subject_digest == request.expected_subject_digest
                })
                .ok_or(DurableInvestigationError::Refused(
                    InvestigationError::EvidenceRequired,
                ))?
                .clone();
            if descriptor.handle_id.len() > 1_024 || descriptor.privacy_class.len() > 256 {
                return Err(DurableInvestigationError::Refused(
                    InvestigationError::CapacityExceeded,
                ));
            }
            if prior.privacy_class != descriptor.privacy_class
                || prior.record.basis_anchor != descriptor.anchor
                || prior.record.contract_basis != descriptor.contract_basis
            {
                return Err(DurableInvestigationError::Refused(
                    InvestigationError::StaleBasis,
                ));
            }
            let binding = catalog
                .source_binding(&descriptor.handle_id, descriptor.descriptor_digest)
                .ok_or(DurableInvestigationError::Refused(
                    InvestigationError::EvidenceRequired,
                ))?
                .clone();
            // Exercise the actual owner, including hypothesis, deadline, CAS and retained-byte limits.
            cases
                .execute(
                    &mut memory,
                    principal,
                    &alias.session_id,
                    &target.command(descriptor.subject_digest),
                    now,
                )
                .map_err(DurableInvestigationError::Refused)?;
            Ok((descriptor, binding))
        };
        let (descriptor, binding) = preflight().map_err(SourceCitationError::Preflight)?;
        let response = self
            .hydrate_from_source(principal, alias, request, catalog, reader, now)
            .map_err(SourceCitationError::Acquisition)?;
        binding
            .validate_response(request, &descriptor, &response)
            .map_err(|cause| SourceCitationError::Validation {
                charged_root: self.committed_root(),
                cause,
            })?;
        let acquisition = SourceAcquisition {
            principal: principal.clone(),
            session: alias.session_id.clone(),
            generation: alias.generation,
            slot: alias.slot,
            handle_id: descriptor.handle_id,
            privacy_class: descriptor.privacy_class,
            descriptor: descriptor.descriptor_digest,
            subject: binding.subject_digest(),
            publication: binding.publication_root(),
            artifact: binding.artifact_digest(),
            request: request.request_digest,
            hydration_receipt: response.receipt.receipt_digest,
            charge_root: self.committed_root(),
            charged_session: self.checkpoint_digest,
            tokens: response.receipt.cost.tokens,
            payload_bytes: binding.payload_bytes(),
            observed_at: now,
        };
        // Do not keep footage alive while cloning history or synchronizing the citation journal.
        drop(response);
        self.commit_source_citation(target, &acquisition)
            .map_err(|cause| SourceCitationError::Link {
                acquisition: Box::new(acquisition),
                cause,
            })
    }

    fn commit_source_citation(
        &mut self,
        target: &SourceCitationTarget,
        acquisition: &SourceAcquisition,
    ) -> Result<SourceCitationReceipt, DurableInvestigationError> {
        self.preflight()?;
        let mut state = self
            .coordination
            .as_ref()
            .ok_or(DurableSessionError::InvalidHistory)?
            .fork();
        let mut memory = self.memory.clone();
        let receipt = apply(target, acquisition, &mut memory, &mut state, self.limits)?;
        let checkpoint = memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?;
        let payload = encode(&receipt, checkpoint.digest())?;
        self.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: Some(state),
            record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
        })?;
        Ok(receipt)
    }

    // Called by the shared replay entrypoint before installation or incomplete-tail truncation.
    pub(in crate::agent_session::checkpoint::journal) fn verify_source_charge_links(
        report: &RecoveryReport,
    ) -> Result<(), DurableSessionError> {
        for (index, record) in report.records().iter().enumerate() {
            if record.kind() != COORDINATION_COMMAND_RECORD_KIND {
                continue;
            }
            let mut d = CanonicalDecoder::new(record.payload());
            if d.text()? != RECORD {
                continue;
            }
            let (_, acquisition, _, _, _) = decode(record.payload())?;
            let previous = index
                .checked_sub(1)
                .and_then(|i| report.records().get(i))
                .ok_or(DurableSessionError::InvalidHistory)?;
            if previous.root() != acquisition.charge_root
                || (acquisition.tokens > 0 && previous.kind()
                    != crate::agent_session::checkpoint::journal::SESSION_CHECKPOINT_RECORD_KIND)
            { return Err(DurableSessionError::InvalidHistory); }
        }
        Ok(())
    }
}

fn apply(
    target: &SourceCitationTarget,
    acquisition: &SourceAcquisition,
    memory: &mut ReferenceSessionStore,
    state: &mut CoordinationState,
    limits: DurableSessionLimits,
) -> Result<SourceCitationReceipt, DurableInvestigationError> {
    target
        .validate()
        .map_err(DurableInvestigationError::Refused)?;
    if memory
        .checkpoint(limits.max_checkpoint_bytes)
        .map_err(DurableSessionError::from)?
        .digest()
        != acquisition.charged_session
    {
        return Err(DurableSessionError::InvalidHistory.into());
    }
    let session = memory
        .sessions
        .get(&acquisition.session)
        .ok_or(DurableSessionError::InvalidHistory)?;
    let symbol = session
        .symbols
        .get(&acquisition.slot)
        .ok_or(DurableSessionError::InvalidHistory)?;
    if session.closed
        || session.session.principal_id != acquisition.principal
        || session.session.symbol_table_generation != acquisition.generation
        || session.last_observed_at != acquisition.observed_at
        || !session
            .session
            .privacy_scope
            .contains(&acquisition.privacy_class)
        || session.spent_tokens < acquisition.tokens
        || symbol.handle_id != acquisition.handle_id
        || symbol.descriptor_digest != acquisition.descriptor
        || symbol.subject_digest != acquisition.subject
    {
        return Err(DurableSessionError::InvalidHistory.into());
    }
    let cases = state
        .cases
        .as_mut()
        .ok_or(DurableSessionError::InvalidHistory)?;
    let prior = cases
        .entries
        .get(&target.case_id)
        .ok_or(DurableSessionError::InvalidHistory)?;
    if prior.head.privacy_class != acquisition.privacy_class {
        return Err(DurableSessionError::InvalidHistory.into());
    }
    let revision = cases
        .execute(
            memory,
            &acquisition.principal,
            &acquisition.session,
            &target.command(acquisition.subject),
            acquisition.observed_at,
        )
        .map_err(DurableInvestigationError::Refused)?;
    Ok(SourceCitationReceipt {
        acquisition: acquisition.clone(),
        target: target.clone(),
        revision,
    })
}

fn encode_target(target: &SourceCitationTarget, e: &mut CanonicalEncoder) {
    e.text(&target.case_id);
    e.digest(target.expected);
    e.text(&target.hypothesis);
    e.bool(target.contradicts);
}

fn encode(
    receipt: &SourceCitationReceipt,
    after: ContentDigest,
) -> Result<Vec<u8>, DurableSessionError> {
    let mut e = CanonicalEncoder::new();
    e.text(RECORD);
    encode_target(&receipt.target, &mut e);
    receipt.acquisition.encode_canonical(&mut e);
    e.digest(receipt.revision.digest());
    e.digest(after);
    e.digest(receipt.digest());
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

type Decoded = (
    SourceCitationTarget,
    SourceAcquisition,
    ContentDigest,
    ContentDigest,
    ContentDigest,
);
fn decode(bytes: &[u8]) -> Result<Decoded, DurableSessionError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != RECORD {
        return Err(DurableSessionError::InvalidHistory);
    }
    let target = SourceCitationTarget {
        case_id: text(&mut d, 128)?,
        expected: d.digest()?,
        hypothesis: text(&mut d, 128)?,
        contradicts: d.bool()?,
    };
    target
        .validate()
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    let acquisition = SourceAcquisition {
        principal: PrincipalId::parse(text(&mut d, 128)?)?,
        session: SessionId::parse(text(&mut d, 128)?)?,
        generation: d.u64()?,
        slot: d.u64()?,
        handle_id: text(&mut d, 1_024)?,
        privacy_class: text(&mut d, 256)?,
        descriptor: d.digest()?,
        subject: d.digest()?,
        publication: d.digest()?,
        artifact: d.digest()?,
        request: d.digest()?,
        hydration_receipt: d.digest()?,
        charge_root: d.digest()?,
        charged_session: d.digest()?,
        tokens: d.u64()?,
        payload_bytes: d.u64()?,
        observed_at: TimestampNs(d.i128()?),
    };
    if acquisition.slot == 0
        || acquisition.observed_at.0 < 0
        || acquisition.payload_bytes > fss_object::MAX_OBJECT_BYTES as u64
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    let revision = d.digest()?;
    let after = d.digest()?;
    let receipt = d.digest()?;
    d.ensure_finished()?;
    Ok((target, acquisition, revision, after, receipt))
}

fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, DurableSessionError> {
    let value = d.text()?;
    if value.is_empty() || value.len() > maximum {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(value.to_owned())
}

pub(super) fn replay(
    bytes: &[u8],
    sessions: &mut ReferenceSessionStore,
    state: &mut CoordinationState,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    let (target, acquisition, expected, after, receipt_digest) = decode(bytes)?;
    let receipt = apply(&target, &acquisition, sessions, state, limits)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    if receipt.revision.digest() != expected
        || receipt.digest() != receipt_digest
        || sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != after
        || encode(&receipt, after)? != bytes
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
