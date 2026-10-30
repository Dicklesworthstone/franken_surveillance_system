#![forbid(unsafe_code)]
//! Attach one completed retained probe to an exact case revision without changing its assessment.
//!
//! Native work, citation, and output charging are separate durable stages. The citation records
//! historical native-owner custody, not current source availability or a hypothesis truth claim.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaseId, ContentDigest,
    DigestAlgorithm, LedgerAnchor, PrincipalId, SessionId, TimestampNs,
};
use fss_ledger::RecoveryReport;

use super::{
    COORDINATION_COMMAND_RECORD_KIND, CoordinationState, DurableInvestigationError,
    DurableSessionError, DurableSessionLimits, DurableSessionStore, InvestigationChange,
    InvestigationCommand, InvestigationError, InvestigationRevision, PendingSession,
};
use crate::agent_session::ReferenceSessionStore;
use crate::agent_session::checkpoint::journal::supervision::{
    SUPERVISION_COMMAND_RECORD_KIND, SupervisionState,
    case_citation::{self, ProbeStatePin},
};
use crate::agent_session::checkpoint::journal::{read_report, replay_all};
use crate::deployment_session::supervision::{
    SupervisionSessionDelivery, SupervisionSessionHead, SupervisionSessionOutcome,
    SupervisionValidation,
};

mod codec;
mod inspection;
pub use inspection::ProbeCitationInspection;

const RECORD: &str = "fss.reference_probe_citation_record.v1";
const CUSTODY: &str = "fss.reference_probe_custody.v1";
const RECEIPT: &str = "fss.reference_probe_citation_receipt.v1";
const MAX_RECORD_BYTES: usize = 16 * 1024;
const CASE_WRITE: &str = "CAP-AGENT-CASE-WRITE-001";
const NATIVE_PRIVACY: &str = "private:property";

/// An explicit citation to an existing hypothesis, not an automatic assessment or effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeCitationTarget {
    /// Existing visible case identity.
    pub case_id: String,
    /// Exact original predecessor; a successful citation never silently rebases this CAS.
    pub expected: ContentDigest,
    /// Existing hypothesis also named by the native recipe owner.
    pub hypothesis: String,
    /// Explicit operator choice of counterevidence versus supporting evidence.
    pub contradicts: bool,
}

impl ProbeCitationTarget {
    fn validate(&self) -> Result<(), InvestigationError> {
        CaseId::parse(self.case_id.as_str()).map_err(|_| InvestigationError::InvalidRecord)?;
        CaseId::parse(self.hypothesis.as_str()).map_err(|_| InvestigationError::InvalidRecord)?;
        if self.case_id.len() > 128 || self.hypothesis.len() > 128 || !sha(self.expected) {
            return Err(InvestigationError::InvalidRecord);
        }
        Ok(())
    }

    fn command(&self, payload: ContentDigest) -> InvestigationCommand {
        InvestigationCommand::Change {
            case_id: self.case_id.clone(),
            expected: self.expected,
            change: InvestigationChange::Cite {
                hypothesis: self.hypothesis.clone(),
                evidence: payload,
                contradicts: self.contradicts,
            },
        }
    }
}

/// Private historical proof of the native transition that immediately preceded the citation.
///
/// Hypothesis mapping and the optional validation receipt are explicit native-owner assertions.
/// Replay verifies their exact retained association, not the opaque recipe's source semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeCustody {
    native: ProbeStatePin,
    native_root: ContentDigest,
    request: ContentDigest,
    native_hypothesis: String,
    privacy_class: String,
    head: SupervisionSessionHead,
    validation: Option<SupervisionValidation>,
}

impl ProbeCustody {
    /// Principal admitted for the original native operation.
    pub const fn principal(&self) -> &PrincipalId {
        &self.native.principal
    }
    /// Original source-work session; historical inspection may use another authorized session.
    pub const fn session(&self) -> &SessionId {
        &self.native.session
    }
    /// Exact original session-local subscription label.
    pub fn subscription_id(&self) -> &str {
        &self.native.subscription
    }
    /// Original caller intent digest, separate from the native configuration and report.
    pub const fn request_digest(&self) -> ContentDigest {
        self.request
    }
    /// Exact original immutable native configuration bytes' digest.
    pub const fn configuration_digest(&self) -> ContentDigest {
        self.native.configuration
    }
    /// Complete supervisor progress after the native operation, including all lifetime charges.
    pub const fn subscription_digest(&self) -> ContentDigest {
        self.native.subscription_state
    }
    /// Journal root containing the immediately preceding successful native Publish/Release.
    pub const fn native_root(&self) -> ContentDigest {
        self.native_root
    }
    /// Exact pending report receipt; citation neither acknowledges nor discards it.
    pub const fn pending_receipt(&self) -> ContentDigest {
        self.native.pending
    }
    /// Original native report receipt, distinct from its retained payload digest.
    pub const fn report_receipt(&self) -> ContentDigest {
        self.native.report
    }
    /// Exact retained report bytes, used as the case's evidence citation.
    pub const fn payload_digest(&self) -> ContentDigest {
        self.native.payload
    }
    /// Complete report byte length; this receipt never discloses the report itself.
    pub const fn payload_bytes(&self) -> u64 {
        self.native.payload_bytes
    }
    /// Original historical report authority, preserved separately from revalidation authority.
    pub const fn report_anchor(&self) -> &LedgerAnchor {
        &self.native.report_anchor
    }
    /// Native owner's separately observed current authority and effect journal roots.
    pub const fn head(&self) -> &SupervisionSessionHead {
        &self.head
    }
    /// Native recipe owner's exact hypothesis assertion; not independently parsed on replay.
    pub fn native_hypothesis(&self) -> &str {
        &self.native_hypothesis
    }
    /// Existing native disclosure class retained by the case.
    pub fn privacy_class(&self) -> &str {
        &self.privacy_class
    }
    /// True when the native owner revalidated a previously pending report.
    pub const fn replayed(&self) -> bool {
        self.native.replayed
    }
    /// Native-owner current validation metadata; not a proof that source remains available.
    pub const fn validation(&self) -> Option<&SupervisionValidation> {
        self.validation.as_ref()
    }
    /// Original lifetime native attempt count after this operation; never refunded by linking.
    pub const fn attempts_reserved(&self) -> u32 {
        self.native.attempts_reserved
    }
    /// Exact original cumulative window prefix, if a schedule was explicitly configured.
    pub const fn active_window_count(&self) -> Option<u32> {
        self.native.active_window_count
    }
    /// Original admitted evidence-clock observation, not an invented wall clock.
    pub const fn observed_at(&self) -> TimestampNs {
        self.native.observed_at
    }
    /// Canonical audit identity; independent journal custody is still required.
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(CUSTODY)
    }
}

impl CanonicalEncode for ProbeCustody {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        codec::encode_custody(self, e);
    }
}

/// Both native custody and the exact case write committed; no source bytes or effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeCitationReceipt {
    custody: ProbeCustody,
    target: ProbeCitationTarget,
    revision: InvestigationRevision,
}

impl ProbeCitationReceipt {
    /// Historical native transition and the unchanged pending report identity.
    pub const fn custody(&self) -> &ProbeCustody {
        &self.custody
    }
    /// Original case predecessor, hypothesis and operator-selected side.
    pub const fn target(&self) -> &ProbeCitationTarget {
        &self.target
    }
    /// Exact resulting immutable revision, with epistemic states and assessments unchanged.
    pub const fn revision(&self) -> &InvestigationRevision {
        &self.revision
    }
    /// Canonical identity of both stages, not a source-disclosure capability.
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(RECEIPT);
        self.custody.encode_canonical(&mut e);
        codec::encode_target(&self.target, &mut e);
        e.digest(self.revision.digest());
        ContentDigest::sha256(&e.finish())
    }
}

fn sha(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}

fn refusal(error: InvestigationError) -> DurableInvestigationError {
    DurableInvestigationError::Refused(error)
}

struct CitationSource<'a> {
    subscription: &'a str,
    anchor: &'a LedgerAnchor,
    payload: ContentDigest,
}

fn case_preflight(
    memory: &mut ReferenceSessionStore,
    state: &mut CoordinationState,
    principal: &PrincipalId,
    session: &SessionId,
    target: &ProbeCitationTarget,
    source: CitationSource<'_>,
    now: TimestampNs,
) -> Result<InvestigationRevision, DurableInvestigationError> {
    let CitationSource {
        subscription,
        anchor,
        payload,
    } = source;
    target.validate().map_err(refusal)?;
    let live = memory
        .live_entry(principal, session, now)
        .map_err(|_| refusal(InvestigationError::Unavailable))?;
    if !live.session.capabilities.contains(CASE_WRITE) {
        return Err(refusal(InvestigationError::Denied));
    }
    let cases = state
        .cases
        .as_mut()
        .ok_or(DurableSessionError::InvalidHistory)?;
    let prior = cases
        .execute(
            memory,
            principal,
            session,
            &InvestigationCommand::Inspect {
                case_id: target.case_id.clone(),
                revision: None,
            },
            now,
        )
        .map_err(refusal)?;
    if prior.digest() != target.expected {
        return Err(refusal(InvestigationError::StaleRevision));
    }
    if prior.privacy_class != NATIVE_PRIVACY || prior.record.basis_anchor != *anchor {
        return Err(refusal(InvestigationError::StaleBasis));
    }
    if !prior
        .record
        .probes
        .iter()
        .any(|probe| probe == subscription)
    {
        return Err(refusal(InvestigationError::EvidenceRequired));
    }
    cases
        .execute(memory, principal, session, &target.command(payload), now)
        .map_err(refusal)
}

impl DurableSessionStore {
    /// Exercise the real case CAS, basis, hypothesis, privacy, deadline and capacity before reads.
    /// All case/session changes are on a fork. This never reserves work or appends an observation.
    pub(crate) fn preflight_supervision_citation(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        target: &ProbeCitationTarget,
        subscription: &str,
        expected_report_anchor: &LedgerAnchor,
        now: TimestampNs,
    ) -> Result<(), DurableInvestigationError> {
        self.preflight()?;
        self.verify_storage()?;
        let report = read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let restored = replay_all(
            &report,
            self.limits,
            self.coordination.as_ref().map(|s| s.limits),
        )?;
        let mut memory = restored.memory;
        let mut state = restored
            .coordination
            .ok_or(DurableSessionError::InvalidHistory)?;
        let current = case_citation::admit_subscription(
            &mut memory,
            &restored.supervisions,
            principal,
            session,
            subscription,
            now,
        )?;
        if current
            .pending()
            .is_some_and(|pending| pending.anchor() != expected_report_anchor)
        {
            return Err(refusal(InvestigationError::StaleBasis));
        }
        let payload = current.pending().map_or_else(
            || ContentDigest::sha256(b"bounded native probe citation preflight"),
            |pending| pending.payload_digest(),
        );
        case_preflight(
            &mut memory,
            &mut state,
            principal,
            session,
            target,
            CitationSource {
                subscription,
                anchor: expected_report_anchor,
                payload,
            },
            now,
        )?;
        Ok(())
    }

    /// Link only a successful native Poll result at the current exact journal root.
    ///
    /// The complete retained prefix authenticates the immediately preceding Publish/Release.
    /// No report is acknowledged, no source work is repeated, and no failed link refunds work.
    /// An uncertain append fences the shared owner; reconcile and inspect instead of relinking.
    pub(crate) fn cite_supervision_report(
        &mut self,
        principal: &PrincipalId,
        target: &ProbeCitationTarget,
        request_digest: ContentDigest,
        delivery: &SupervisionSessionDelivery,
        native_hypothesis: &str,
    ) -> Result<ProbeCitationReceipt, DurableInvestigationError> {
        self.preflight()?;
        target.validate().map_err(refusal)?;
        if !sha(request_digest)
            || native_hypothesis != target.hypothesis
            || delivery.session.principal_id != *principal
            || self.committed_root() != delivery.journal_root
        {
            return Err(refusal(InvestigationError::InvalidRecord));
        }
        self.verify_storage()?;
        let report = read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let restored = replay_all(
            &report,
            self.limits,
            self.coordination.as_ref().map(|s| s.limits),
        )?;
        let previous = report
            .records()
            .last()
            .ok_or(DurableSessionError::InvalidHistory)?;
        if previous.kind() != SUPERVISION_COMMAND_RECORD_KIND {
            return Err(refusal(InvestigationError::InvalidRecord));
        }
        let native = case_citation::pin_transition(previous.payload(), &restored.supervisions)?;
        let SupervisionSessionOutcome::Report {
            payload,
            pending,
            replayed,
            validation,
        } = &delivery.outcome
        else {
            return Err(refusal(InvestigationError::InvalidRecord));
        };
        let live = restored
            .memory
            .sessions
            .get(&native.session)
            .ok_or(DurableSessionError::InvalidHistory)?;
        if native.principal != *principal
            || native.session != delivery.session.session_id
            || live.session != delivery.session
            || native.subscription != delivery.subscription.registration().subscription_id
            || native.subscription_state != delivery.subscription.digest()
            || delivery.subscription.pending() != Some(pending)
            || native.payload != ContentDigest::sha256(payload)
            || native.payload_bytes != payload.len() as u64
            || native.pending != pending.receipt()
            || native.report != pending.report_receipt()
            || native.replayed != *replayed
            || native.observed_at != delivery.head.observed_at
            || (*replayed != validation.is_some())
            || validation.as_ref().is_some_and(|validation| {
                validation.basis != delivery.head.anchor
                    || !sha(validation.receipt)
                    || validation.reserved_bytes
                        > delivery.subscription.registration().max_read_bytes
                    || validation.read_attempts
                        > delivery.subscription.registration().max_read_attempts
            })
        {
            return Err(refusal(InvestigationError::InvalidRecord));
        }
        let custody = ProbeCustody {
            native,
            native_root: previous.root(),
            request: request_digest,
            native_hypothesis: native_hypothesis.to_owned(),
            privacy_class: NATIVE_PRIVACY.to_owned(),
            head: delivery.head.clone(),
            validation: validation.clone(),
        };
        let mut state = restored
            .coordination
            .ok_or(DurableSessionError::InvalidHistory)?;
        let mut memory = restored.memory;
        let receipt = apply(
            target,
            &custody,
            &mut memory,
            &mut state,
            &restored.supervisions,
            self.limits,
        )?;
        let checkpoint = memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?;
        let payload = codec::encode(&receipt, checkpoint.digest())?;
        self.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: Some(state),
            record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
        })?;
        Ok(receipt)
    }

    /// Validate physical adjacency before replay installs state or repairs an incomplete tail.
    pub(in crate::agent_session::checkpoint::journal) fn verify_probe_custody_links(
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
            let (_, custody, _, _, _) = codec::decode(record.payload())?;
            let previous = index
                .checked_sub(1)
                .and_then(|i| report.records().get(i))
                .ok_or(DurableSessionError::InvalidHistory)?;
            if previous.kind() != SUPERVISION_COMMAND_RECORD_KIND
                || previous.root() != custody.native_root
            {
                return Err(DurableSessionError::InvalidHistory);
            }
            case_citation::verify_transition(previous.payload(), &custody.native)?;
        }
        Ok(())
    }

    /// A narrow dispatch hook gives this one coordination record both replay-owned state planes.
    pub(in crate::agent_session::checkpoint::journal) fn replay_probe_citation(
        payload: &[u8],
        memory: &mut ReferenceSessionStore,
        coordination: &mut CoordinationState,
        supervisions: &SupervisionState,
        limits: DurableSessionLimits,
    ) -> Result<bool, DurableSessionError> {
        let mut d = CanonicalDecoder::new(payload);
        if d.text()? != RECORD {
            return Ok(false);
        }
        let (target, custody, revision, after, digest) = codec::decode(payload)?;
        let receipt = apply(
            &target,
            &custody,
            memory,
            coordination,
            supervisions,
            limits,
        )
        .map_err(|_| DurableSessionError::InvalidHistory)?;
        if receipt.revision.digest() != revision
            || receipt.digest() != digest
            || memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != after
            || codec::encode(&receipt, after)? != payload
        {
            return Err(DurableSessionError::InvalidHistory);
        }
        Ok(true)
    }
}

fn apply(
    target: &ProbeCitationTarget,
    custody: &ProbeCustody,
    memory: &mut ReferenceSessionStore,
    coordination: &mut CoordinationState,
    supervisions: &SupervisionState,
    limits: DurableSessionLimits,
) -> Result<ProbeCitationReceipt, DurableInvestigationError> {
    codec::validate_custody(custody)?;
    if target.hypothesis != custody.native_hypothesis
        || memory
            .checkpoint(limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?
            .digest()
            != custody.native.checkpoint
    {
        return Err(DurableSessionError::InvalidHistory.into());
    }
    let subscription = case_citation::verify_state(memory, supervisions, &custody.native)?;
    if custody.validation.as_ref().is_some_and(|validation| {
        validation.reserved_bytes > subscription.registration().max_read_bytes
            || validation.read_attempts > subscription.registration().max_read_attempts
    }) {
        return Err(DurableSessionError::InvalidHistory.into());
    }
    let revision = case_preflight(
        memory,
        coordination,
        &custody.native.principal,
        &custody.native.session,
        target,
        CitationSource {
            subscription: &custody.native.subscription,
            anchor: &custody.native.report_anchor,
            payload: custody.native.payload,
        },
        custody.native.observed_at,
    )?;
    Ok(ProbeCitationReceipt {
        custody: custody.clone(),
        target: target.clone(),
        revision,
    })
}

#[cfg(test)]
mod tests;
