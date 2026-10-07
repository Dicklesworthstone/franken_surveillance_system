#![forbid(unsafe_code)]
//! Immutable shared findings, explicit disagreements, and conflict reports (FSS-227), the
//! shared case-board intent family of AOP-006 `investigate`.
//!
//! **Cognition plane.** A finding is one session's evidence-linked claim about a case (optionally
//! one hypothesis of it), with its own knowledge state, published root-last under
//! `<root>/agent/publications/` (the canonical record plus its `fss.agent_finding.v1` rendering)
//! and never rewritten. A later finding may *supersede* an earlier one of the same principal
//! (one successor each), *withdraw* it, or *disagree with* any active finding on the same case.
//! Nothing here mutates evidence, a case revision, policy, or an effect.
//!
//! **Conflicts are never resolved by ranking.** Two active findings in explicit disagreement are
//! a conflict: each is reported `conflicted` (its own recorded state is kept) and the situation
//! lists one probe affordance per disputed finding until a supersession or withdrawal ends the
//! dispute. Superseded and withdrawn findings stay readable as `stale` audit facts.

use std::collections::BTreeMap;
use std::path::Path;

use fss_core::{
    AgentFinding, AgentSession, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, ContentDigest, ContractError, KnowledgeState, LedgerAnchor, MissionId,
    PrincipalId, SessionId, TimestampNs,
};
use fss_publication::SlotName;

use crate::agent_orient::OrientFindingBrief;

use super::investigation::visible_cases;
use super::{
    DeploymentHistory, DeploymentOrientation, DeploymentSessionError, MAX_RECORD_BYTES,
    MAX_RECORD_ITEMS, OrientLimits, SessionJournal, digest_of, evidence_now, hex, orient_bound,
    publish_record, read_published,
};

const FINDING_RECORD_DOMAIN: &str = "fss.reference_agent_finding.v1";
const FINDING_IDENTITY_DOMAIN: &str = "fss.reference_agent_finding_identity.v1";
const FINDING_REQUEST_DOMAIN: &str = "fss.reference_agent_finding_request.v1";
/// Registered grant a finding requires (a case-board write).
pub const CAPABILITY_FINDING: &str = "CAP-AGENT-CASE-WRITE-001";
/// Most evidence handles on either side of one finding.
pub const MAX_FINDING_EVIDENCE: usize = 256;
/// Most findings one finding may disagree with, or follow-ups it may suggest.
pub const MAX_FINDING_LINKS: usize = 64;
/// Largest finding statement.
pub const MAX_FINDING_CLAIM_BYTES: usize = 8192;

/// One immutable finding record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingRecord {
    /// Stable identity (`finding:<32 hex>`), derived from everything below but the time.
    pub finding_id: String,
    /// The author session's mission.
    pub mission_id: MissionId,
    /// The author session's principal.
    pub principal: PrincipalId,
    /// The author session.
    pub session_id: SessionId,
    /// The case the finding is about.
    pub case_id: String,
    /// The case revision the finding was made against (its method receipt).
    pub case_revision: ContentDigest,
    /// The hypothesis the finding is about, when it is about one.
    pub hypothesis_id: Option<String>,
    /// The author session's anchor.
    pub anchor: LedgerAnchor,
    /// The claim.
    pub claim: String,
    /// The finding's own knowledge state.
    pub epistemic_state: KnowledgeState,
    /// Supporting evidence handles (at least one).
    pub supporting: Vec<String>,
    /// Contradicting evidence handles.
    pub contradicting: Vec<String>,
    /// Suggested follow-up handles.
    pub follow_up: Vec<String>,
    /// Active findings this one explicitly disagrees with.
    pub disagrees_with: Vec<String>,
    /// The finding this one supersedes (same principal and case).
    pub supersedes: Option<String>,
    /// True for a withdrawal record (it supersedes and withdraws its target).
    pub withdrawn: bool,
    /// Publication time on the deployment evidence clock.
    pub created_at: TimestampNs,
}

fn encode_texts(encoder: &mut CanonicalEncoder, values: &[String]) {
    encoder.u32(values.len() as u32);
    for value in values {
        encoder.text(value);
    }
}

fn decode_texts(decoder: &mut CanonicalDecoder<'_>) -> Result<Vec<String>, ContractError> {
    let count = decoder.u32()? as usize;
    if count > MAX_RECORD_ITEMS {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decoder.text()?.to_owned());
    }
    Ok(out)
}

fn encode_optional(encoder: &mut CanonicalEncoder, value: Option<&str>) {
    encoder.bool(value.is_some());
    if let Some(value) = value {
        encoder.text(value);
    }
}

fn decode_optional(decoder: &mut CanonicalDecoder<'_>) -> Result<Option<String>, ContractError> {
    Ok(if decoder.bool()? {
        Some(decoder.text()?.to_owned())
    } else {
        None
    })
}

impl FindingRecord {
    /// The content fields every identity and record binds (all but the identity and time).
    fn encode_content(&self, encoder: &mut CanonicalEncoder) {
        self.mission_id.encode_canonical(encoder);
        self.principal.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        encoder.text(&self.case_id);
        encoder.digest(self.case_revision);
        encode_optional(encoder, self.hypothesis_id.as_deref());
        self.anchor.encode_canonical(encoder);
        encoder.text(&self.claim);
        self.epistemic_state.encode_canonical(encoder);
        encode_texts(encoder, &self.supporting);
        encode_texts(encoder, &self.contradicting);
        encode_texts(encoder, &self.follow_up);
        encode_texts(encoder, &self.disagrees_with);
        encode_optional(encoder, self.supersedes.as_deref());
        encoder.bool(self.withdrawn);
    }

    /// The identity of this content: an identical finding is an exact retry.
    #[must_use]
    pub fn identity(&self) -> String {
        let digest = digest_of(FINDING_IDENTITY_DOMAIN, |encoder| {
            self.encode_content(encoder);
        });
        format!(
            "finding:{}",
            hex(digest).chars().take(32).collect::<String>()
        )
    }

    /// Canonical record bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(FINDING_RECORD_DOMAIN);
        encoder.text(&self.finding_id);
        self.encode_content(&mut encoder);
        encoder.i128(self.created_at.0);
        encoder.finish()
    }

    /// Decodes exactly canonical record bytes whose identity is their content's.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != FINDING_RECORD_DOMAIN {
            return Err(ContractError::DigestMismatch);
        }
        let finding_id = decoder.text()?.to_owned();
        let record = Self {
            finding_id,
            mission_id: MissionId::parse(decoder.text()?)?,
            principal: PrincipalId::parse(decoder.text()?)?,
            session_id: SessionId::decode_canonical(&mut decoder)?,
            case_id: decoder.text()?.to_owned(),
            case_revision: ContentDigest::decode_canonical(&mut decoder)?,
            hypothesis_id: decode_optional(&mut decoder)?,
            anchor: LedgerAnchor::decode_canonical(&mut decoder)?,
            claim: decoder.text()?.to_owned(),
            epistemic_state: KnowledgeState::decode_canonical(&mut decoder)?,
            supporting: decode_texts(&mut decoder)?,
            contradicting: decode_texts(&mut decoder)?,
            follow_up: decode_texts(&mut decoder)?,
            disagrees_with: decode_texts(&mut decoder)?,
            supersedes: decode_optional(&mut decoder)?,
            withdrawn: decoder.bool()?,
            created_at: TimestampNs(decoder.i128()?),
        };
        decoder.ensure_finished()?;
        if record.to_bytes() != bytes || record.finding_id != record.identity() {
            return Err(ContractError::DigestMismatch);
        }
        Ok(record)
    }

    /// The schema-faithful core finding (validates the evidence and identity bounds).
    pub fn finding(&self) -> Result<AgentFinding, ContractError> {
        let mut affected = vec![self.case_id.clone()];
        affected.extend(self.hypothesis_id.iter().cloned());
        AgentFinding::new(
            self.finding_id.clone(),
            self.mission_id.clone(),
            None,
            self.principal.as_str(),
            self.anchor.clone(),
            self.claim.clone(),
            self.epistemic_state,
            self.supporting.clone(),
            self.contradicting.clone(),
            Vec::new(),
            Vec::new(),
            vec![self.case_revision.to_text()],
            affected,
            self.follow_up.clone(),
            self.created_at.0.max(0),
        )
    }

    fn slot(finding_id: &str) -> Result<SlotName, DeploymentSessionError> {
        SlotName::parse(&format!(
            "finding-{}",
            hex(ContentDigest::sha256(finding_id.as_bytes()))
        ))
        .map_err(|_| DeploymentSessionError::Internal("finding slot name".to_owned()))
    }
}

/// One published finding with its derived standing on the case board.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingView {
    /// The immutable record.
    pub record: FindingRecord,
    /// Root of its publication.
    pub root: ContentDigest,
    /// Digest of its `fss.agent_finding.v1` rendering (the root's other child).
    pub rendering: ContentDigest,
    /// The finding that superseded (or withdrew) it, if any.
    pub superseded_by: Option<String>,
    /// Active findings in explicit disagreement with it (either direction), when it is active.
    pub disputed_by: Vec<String>,
}

impl FindingView {
    /// Whether the finding still stands (neither superseded nor itself a withdrawal).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.superseded_by.is_none() && !self.record.withdrawn
    }

    /// The state a reader is shown: `conflicted` while disputed, `stale` once superseded or
    /// withdrawn, otherwise the finding's own recorded state.
    #[must_use]
    pub fn standing(&self) -> KnowledgeState {
        if !self.is_active() {
            KnowledgeState::Stale
        } else if self.disputed_by.is_empty() {
            self.record.epistemic_state
        } else {
            KnowledgeState::Conflicted
        }
    }
}

/// Every finding of `mission_id` by `principal`, in identity order, with its standing.
pub(super) fn mission_findings(
    root: &Path,
    mission_id: &MissionId,
    principal: &PrincipalId,
) -> Result<Vec<FindingView>, DeploymentSessionError> {
    let mut records: BTreeMap<String, (FindingRecord, ContentDigest, ContentDigest)> =
        BTreeMap::new();
    for published in super::published_records(root, "finding-")? {
        let record = FindingRecord::from_bytes(&published.record).map_err(|error| {
            DeploymentSessionError::StoreInvalid(format!(
                "a finding record does not verify: {error}"
            ))
        })?;
        let rendering = published.children.first().copied().ok_or_else(|| {
            DeploymentSessionError::StoreInvalid("a finding root carries no rendering".to_owned())
        })?;
        if record.mission_id == *mission_id && record.principal == *principal {
            records.insert(
                record.finding_id.clone(),
                (record, published.root, rendering),
            );
        }
    }
    let superseded: BTreeMap<String, String> = records
        .values()
        .filter_map(|(record, _, _)| {
            record
                .supersedes
                .clone()
                .map(|target| (target, record.finding_id.clone()))
        })
        .collect();
    let active = |id: &str| {
        records
            .get(id)
            .is_some_and(|(record, _, _)| !record.withdrawn && !superseded.contains_key(id))
    };
    let mut views = Vec::with_capacity(records.len());
    for (id, (record, root, rendering)) in &records {
        let mut disputed_by: Vec<String> = Vec::new();
        if active(id) {
            disputed_by.extend(
                record
                    .disagrees_with
                    .iter()
                    .filter(|other| active(other))
                    .cloned(),
            );
            disputed_by.extend(
                records
                    .values()
                    .filter(|(other, _, _)| {
                        active(&other.finding_id) && other.disagrees_with.contains(id)
                    })
                    .map(|(other, _, _)| other.finding_id.clone()),
            );
            disputed_by.sort();
            disputed_by.dedup();
        }
        views.push(FindingView {
            record: record.clone(),
            root: *root,
            rendering: *rendering,
            superseded_by: superseded.get(id).cloned(),
            disputed_by,
        });
    }
    Ok(views)
}

/// The active findings of the session's mission, as its situation lists them.
pub(super) fn finding_briefs(
    root: &Path,
    session: &AgentSession,
) -> Result<Vec<OrientFindingBrief>, DeploymentSessionError> {
    Ok(
        mission_findings(root, &session.mission_id, &session.principal_id)?
            .into_iter()
            .filter(FindingView::is_active)
            .map(|view| OrientFindingBrief {
                finding_id: view.record.finding_id,
                case_id: view.record.case_id,
                disputed_by: view.disputed_by,
            })
            .collect(),
    )
}

/// What a finding transition asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingAction {
    /// Publish a finding (optionally superseding one, or disagreeing with others).
    Publish(FindingDraft),
    /// Publish a withdrawal of one of the principal's active findings.
    Withdraw {
        /// The finding withdrawn.
        finding_id: String,
        /// Why (the withdrawal's statement).
        claim: String,
        /// Evidence for the withdrawal.
        supporting: Vec<String>,
    },
    /// List the mission's findings and conflicts (optionally one case's).
    List {
        /// Restrict to one case.
        case_id: Option<String>,
    },
}

/// A new finding's content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingDraft {
    /// The case.
    pub case_id: String,
    /// The hypothesis, when the finding is about one.
    pub hypothesis_id: Option<String>,
    /// The claim.
    pub claim: String,
    /// The finding's own knowledge state.
    pub epistemic_state: KnowledgeState,
    /// Supporting evidence handles.
    pub supporting: Vec<String>,
    /// Contradicting evidence handles.
    pub contradicting: Vec<String>,
    /// Suggested follow-up handles.
    pub follow_up: Vec<String>,
    /// Active findings this one disagrees with.
    pub disagrees_with: Vec<String>,
    /// The principal's active finding this one supersedes.
    pub supersedes: Option<String>,
}

/// One finding request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingRequest {
    /// Session whose authority admits the command.
    pub session_id: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// The action.
    pub action: FindingAction,
}

/// The answer to one finding request.
#[derive(Clone, Debug)]
pub struct FindingAnswer {
    /// The live session.
    pub session: AgentSession,
    /// The finding published or found (`None` for a list).
    pub finding: Option<FindingView>,
    /// The mission's findings with their standing (the list, or every finding after a write).
    pub findings: Vec<FindingView>,
    /// True when this request published a new record.
    pub committed: bool,
    /// Session-bound situation as of the session's anchor.
    pub orientation: DeploymentOrientation,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
    /// Deployment evidence time.
    pub now: TimestampNs,
    /// True when the deployment head lies past the session's anchor.
    pub head_moved: bool,
}

fn refused(reason: impl Into<String>) -> DeploymentSessionError {
    DeploymentSessionError::FindingRefused(reason.into())
}

fn stale(reason: impl Into<String>) -> DeploymentSessionError {
    DeploymentSessionError::FindingStale(reason.into())
}

/// The record a publish or withdraw request would publish, validated against the board.
fn draft_record(
    root: &Path,
    journal: &SessionJournal,
    session: &AgentSession,
    action: &FindingAction,
    now: TimestampNs,
) -> Result<FindingRecord, DeploymentSessionError> {
    let board = mission_findings(root, &session.mission_id, &session.principal_id)?;
    let find = |id: &str| board.iter().find(|view| view.record.finding_id == id);
    let (draft, withdrawn) = match action {
        FindingAction::List { .. } => {
            return Err(DeploymentSessionError::Internal(
                "a list publishes nothing".to_owned(),
            ));
        }
        FindingAction::Publish(draft) => (draft.clone(), false),
        FindingAction::Withdraw {
            finding_id,
            claim,
            supporting,
        } => {
            let target = find(finding_id)
                .ok_or_else(|| refused(format!("no finding `{finding_id}` is visible")))?;
            (
                FindingDraft {
                    case_id: target.record.case_id.clone(),
                    hypothesis_id: target.record.hypothesis_id.clone(),
                    claim: claim.clone(),
                    epistemic_state: KnowledgeState::Stale,
                    supporting: supporting.clone(),
                    contradicting: Vec::new(),
                    follow_up: Vec::new(),
                    disagrees_with: Vec::new(),
                    supersedes: Some(finding_id.clone()),
                },
                true,
            )
        }
    };
    if draft.claim.is_empty() || draft.claim.len() > MAX_FINDING_CLAIM_BYTES {
        return Err(refused(format!(
            "a finding claim must be 1..={MAX_FINDING_CLAIM_BYTES} bytes"
        )));
    }
    if draft.supporting.is_empty()
        || draft.supporting.len() > MAX_FINDING_EVIDENCE
        || draft.contradicting.len() > MAX_FINDING_EVIDENCE
        || draft.follow_up.len() > MAX_FINDING_LINKS
        || draft.disagrees_with.len() > MAX_FINDING_LINKS
    {
        return Err(refused(format!(
            "a finding cites 1..={MAX_FINDING_EVIDENCE} supporting handles, at most \
             {MAX_FINDING_EVIDENCE} contradicting handles, and at most {MAX_FINDING_LINKS} \
             disagreements and follow-ups"
        )));
    }
    let case = visible_cases(&journal.store, session)
        .into_iter()
        .find(|case| case.record().investigation_id == draft.case_id)
        .ok_or_else(|| {
            refused(format!(
                "no case `{}` is visible to this session",
                draft.case_id
            ))
        })?;
    if let Some(hypothesis) = &draft.hypothesis_id
        && !case
            .record()
            .hypotheses
            .iter()
            .any(|candidate| candidate.hypothesis_id == *hypothesis)
    {
        return Err(refused(format!(
            "case `{}` has no hypothesis `{hypothesis}`",
            draft.case_id
        )));
    }
    for other in &draft.disagrees_with {
        let view =
            find(other).ok_or_else(|| refused(format!("no finding `{other}` is visible")))?;
        if view.record.case_id != draft.case_id {
            return Err(refused(format!(
                "finding `{other}` is about another case; disagreement is per case"
            )));
        }
        if !view.is_active() {
            return Err(stale(format!(
                "finding `{other}` was superseded or withdrawn; disagree with its successor"
            )));
        }
    }
    if let Some(target) = &draft.supersedes {
        let view =
            find(target).ok_or_else(|| refused(format!("no finding `{target}` is visible")))?;
        if view.record.case_id != draft.case_id {
            return Err(refused(format!("finding `{target}` is about another case")));
        }
        if !view.is_active() {
            return Err(stale(format!(
                "finding `{target}` was already superseded or withdrawn (one successor each)"
            )));
        }
    }
    let mut supporting = draft.supporting;
    supporting.sort();
    supporting.dedup();
    let mut contradicting = draft.contradicting;
    contradicting.sort();
    contradicting.dedup();
    let mut disagrees_with = draft.disagrees_with;
    disagrees_with.sort();
    disagrees_with.dedup();
    let mut record = FindingRecord {
        finding_id: String::new(),
        mission_id: session.mission_id.clone(),
        principal: session.principal_id.clone(),
        session_id: session.session_id.clone(),
        case_id: draft.case_id,
        case_revision: case.digest(),
        hypothesis_id: draft.hypothesis_id,
        anchor: session.current_anchor.clone(),
        claim: draft.claim,
        epistemic_state: draft.epistemic_state,
        supporting,
        contradicting,
        follow_up: draft.follow_up,
        disagrees_with,
        supersedes: draft.supersedes,
        withdrawn,
        created_at: now,
    };
    record.finding_id = record.identity();
    if record.disagrees_with.contains(&record.finding_id)
        || record.supersedes.as_deref() == Some(record.finding_id.as_str())
    {
        return Err(refused("a finding cannot refer to itself"));
    }
    record.finding()?;
    Ok(record)
}

/// Applies one finding action. A publish or withdrawal is validated against the case board and
/// published root-last; an identical request is an exact retry returning the published record.
/// `render` produces the `fss.agent_finding.v1` rendering published beside a new record.
pub fn finding(
    root: &Path,
    request: &FindingRequest,
    render: &dyn Fn(&FindingRecord) -> Result<String, ContractError>,
) -> Result<FindingAnswer, DeploymentSessionError> {
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let mut journal = SessionJournal::open(root)?;
    let position = super::session_position(
        &mut journal,
        &history,
        &request.principal,
        &request.session_id,
        now,
    )?;
    let session = position.session;
    let outcome = (|| -> Result<(Option<String>, bool), DeploymentSessionError> {
        if !session.capabilities.contains(CAPABILITY_FINDING) {
            return Err(DeploymentSessionError::CaseRefused(
                crate::agent_session::checkpoint::journal::coordination::investigations::InvestigationError::Denied,
            ));
        }
        if matches!(request.action, FindingAction::List { .. }) {
            return Ok((None, false));
        }
        let mut record = draft_record(root, &journal, &session, &request.action, now)?;
        let slot = FindingRecord::slot(&record.finding_id)?;
        if let Some(existing) = read_published(root, &slot)? {
            let existing = FindingRecord::from_bytes(&existing.record).map_err(|error| {
                DeploymentSessionError::StoreInvalid(format!(
                    "the finding record does not verify: {error}"
                ))
            })?;
            return Ok((Some(existing.finding_id), false));
        }
        let rendering = render(&record)?;
        record.created_at = now;
        publish_record(
            root,
            &slot,
            "agent-finding",
            &record.to_bytes(),
            &[rendering.into_bytes()],
            None,
        )?;
        Ok((Some(record.finding_id), true))
    })();
    let (finding_id, committed) = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            journal.commit_pin()?;
            return Err(error);
        }
    };
    let mut findings = mission_findings(root, &session.mission_id, &session.principal_id)?;
    if let FindingAction::List {
        case_id: Some(case_id),
    } = &request.action
    {
        findings.retain(|view| view.record.case_id == *case_id);
    }
    let finding = finding_id.and_then(|id| {
        findings
            .iter()
            .find(|view| view.record.finding_id == id)
            .cloned()
    });
    let orientation = orient_bound(
        Some((root, &head)),
        &position.snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
        super::session_briefs(root, &journal.store, &session, &session.current_anchor, now)?,
    )?;
    journal.commit_pin()?;
    let request_digest = digest_of(FINDING_REQUEST_DOMAIN, |encoder| {
        request.session_id.encode_canonical(encoder);
        request.principal.encode_canonical(encoder);
        match &request.action {
            FindingAction::List { case_id } => {
                encoder.text("list");
                encode_optional(encoder, case_id.as_deref());
            }
            FindingAction::Publish(_) | FindingAction::Withdraw { .. } => {
                encoder.text("publish");
                encode_optional(
                    encoder,
                    finding.as_ref().map(|view| view.record.finding_id.as_str()),
                );
            }
        }
        head.anchor.encode_canonical(encoder);
    });
    Ok(FindingAnswer {
        session,
        finding,
        findings,
        committed,
        orientation,
        request_digest,
        now,
        head_moved: position.head_moved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Result<FindingRecord, ContractError> {
        let mut record = FindingRecord {
            finding_id: String::new(),
            mission_id: MissionId::parse("mission:a")?,
            principal: PrincipalId::parse("principal:local-operator")?,
            session_id: SessionId::parse("session:a")?,
            case_id: "case:a".to_owned(),
            case_revision: ContentDigest::sha256(b"case"),
            hypothesis_id: Some("h:entry".to_owned()),
            anchor: LedgerAnchor::genesis("site:findings"),
            claim: "A person entered.".to_owned(),
            epistemic_state: KnowledgeState::Estimated,
            supporting: vec![ContentDigest::sha256(b"support").to_text()],
            contradicting: Vec::new(),
            follow_up: vec!["probe:hallway".to_owned()],
            disagrees_with: vec!["finding:other".to_owned()],
            supersedes: None,
            withdrawn: false,
            created_at: TimestampNs(9),
        };
        record.finding_id = record.identity();
        Ok(record)
    }

    #[test]
    fn finding_records_round_trip_and_bind_their_identity() -> Result<(), ContractError> {
        let record = record()?;
        let bytes = record.to_bytes();
        assert_eq!(FindingRecord::from_bytes(&bytes)?, record);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(FindingRecord::from_bytes(&trailing).is_err());
        // A record whose content no longer matches its identity never verifies.
        let mut tampered = record.clone();
        tampered.claim = "Nobody entered.".to_owned();
        assert!(FindingRecord::from_bytes(&tampered.to_bytes()).is_err());
        // Time is not identity: an identical finding later is the same finding.
        let mut later = record.clone();
        later.created_at = TimestampNs(99);
        assert_eq!(later.identity(), record.identity());
        record.finding()?;
        Ok(())
    }

    #[test]
    fn a_finding_without_support_is_refused_by_the_core_contract() -> Result<(), ContractError> {
        let mut record = record()?;
        record.supporting.clear();
        assert!(record.finding().is_err());
        Ok(())
    }
}
