#![forbid(unsafe_code)]
//! Versioned private command bytes. Not a new public transport schema or serde durable format.

use super::*;
use fss_core::{
    CanonicalDecode, CaseDiscriminator, CaseHypothesis, KnowledgeState, KnownStatement,
    LedgerAnchor, MissionId,
};

const REQUEST: &str = "fss.reference_investigation_request.v1";

pub(super) struct Request {
    pub(super) principal: PrincipalId,
    pub(super) session: SessionId,
    pub(super) command: InvestigationCommand,
    pub(super) now: TimestampNs,
}

pub(super) fn encode(request: &Request) -> Result<Vec<u8>, DurableSessionError> {
    validation::command(&request.command).map_err(|_| DurableSessionError::InvalidHistory)?;
    let mut e = CanonicalEncoder::new();
    e.text(REQUEST);
    e.text(request.principal.as_str());
    e.text(request.session.as_str());
    e.i128(request.now.0);
    match &request.command {
        InvestigationCommand::Open {
            record,
            privacy_class,
        } => {
            e.tag(1);
            e.text(privacy_class);
            encode_case(&mut e, record)?;
        }
        InvestigationCommand::Inspect { case_id, revision } => {
            e.tag(2);
            e.text(case_id);
            e.bool(revision.is_some());
            if let Some(root) = revision {
                e.digest(*root);
            }
        }
        InvestigationCommand::Change {
            case_id,
            expected,
            change,
        } => {
            e.tag(3);
            e.text(case_id);
            e.digest(*expected);
            match change {
                InvestigationChange::Activate => e.tag(1),
                InvestigationChange::Cite {
                    hypothesis,
                    evidence,
                    contradicts,
                } => {
                    e.tag(2);
                    e.text(hypothesis);
                    e.digest(*evidence);
                    e.bool(*contradicts);
                }
                InvestigationChange::Assess {
                    hypothesis,
                    disposition,
                    evidence,
                } => {
                    e.tag(3);
                    e.text(hypothesis);
                    e.tag(disposition_code(*disposition)?);
                    e.digest(*evidence);
                }
                InvestigationChange::SetState { state, reason } => {
                    e.tag(4);
                    e.tag(lifecycle_code(*state));
                    e.digest(*reason);
                }
                InvestigationChange::Conclude {
                    refuted,
                    stop_rule,
                    assessment,
                    residual_unknowns,
                } => {
                    e.tag(5);
                    e.bool(*refuted);
                    e.text(stop_rule);
                    e.digest(*assessment);
                    e.u32(residual_unknowns.len() as u32);
                    for id in residual_unknowns {
                        e.text(id);
                    }
                }
            }
        }
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_INVESTIGATION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Request, DurableSessionError> {
    if bytes.len() > MAX_INVESTIGATION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != REQUEST {
        return Err(DurableSessionError::InvalidHistory);
    }
    let principal = PrincipalId::parse(text(&mut d, 128)?)?;
    let session = SessionId::parse(text(&mut d, 128)?)?;
    let now = TimestampNs(d.i128()?);
    let command = match d.tag()? {
        1 => {
            let privacy_class = text(&mut d, 256)?;
            InvestigationCommand::Open {
                record: Box::new(decode_case(&mut d)?),
                privacy_class,
            }
        }
        2 => InvestigationCommand::Inspect {
            case_id: text(&mut d, 128)?,
            revision: if d.bool()? { Some(d.digest()?) } else { None },
        },
        3 => {
            let case_id = text(&mut d, 128)?;
            let expected = d.digest()?;
            let change = match d.tag()? {
                1 => InvestigationChange::Activate,
                2 => InvestigationChange::Cite {
                    hypothesis: text(&mut d, 128)?,
                    evidence: d.digest()?,
                    contradicts: d.bool()?,
                },
                3 => InvestigationChange::Assess {
                    hypothesis: text(&mut d, 128)?,
                    disposition: disposition(d.tag()?)?,
                    evidence: d.digest()?,
                },
                4 => InvestigationChange::SetState {
                    state: lifecycle(d.tag()?)?,
                    reason: d.digest()?,
                },
                5 => {
                    let refuted = d.bool()?;
                    let stop_rule = text(&mut d, 1_024)?;
                    let assessment = d.digest()?;
                    let ids = list(&mut d, 256, |d| text(d, 128))?;
                    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                        return Err(DurableSessionError::InvalidHistory);
                    }
                    InvestigationChange::Conclude {
                        refuted,
                        stop_rule,
                        assessment,
                        residual_unknowns: ids.into_iter().collect(),
                    }
                }
                _ => return Err(DurableSessionError::InvalidHistory),
            };
            InvestigationCommand::Change {
                case_id,
                expected,
                change,
            }
        }
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    d.ensure_finished()?;
    let request = Request {
        principal,
        session,
        command,
        now,
    };
    // Reject nested normalization or alternative spellings; retain exact interpretation.
    if encode(&request)? != bytes {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(request)
}

fn encode_case(
    e: &mut CanonicalEncoder,
    r: &InvestigationState,
) -> Result<(), DurableSessionError> {
    e.text(&r.investigation_id);
    e.bytes(&r.contract_basis.try_canonical_bytes()?);
    e.text(r.mission_id.as_str());
    e.u64(r.revision);
    e.tag(lifecycle_code(r.state));
    e.text(&r.question);
    e.text(&r.decision_informed);
    e.bytes(&r.basis_anchor.try_canonical_bytes()?);
    e.u32(r.hypotheses.len() as u32);
    for h in &r.hypotheses {
        e.text(&h.hypothesis_id);
        e.text(&h.description);
        e.tag(knowledge_code(h.epistemic_state));
        strings(e, &h.predictions);
        digests(e, &h.evidence);
        digests(e, &h.contradictions);
    }
    for group in [&r.knowns, &r.unknowns] {
        e.u32(group.len() as u32);
        for s in group {
            e.text(&s.statement_id);
            e.text(&s.text);
            e.tag(knowledge_code(s.epistemic_state));
            strings(e, &s.basis);
        }
    }
    e.u32(r.discriminators.len() as u32);
    for discriminator in &r.discriminators {
        e.text(&discriminator.discriminator_id);
        e.text(&discriminator.description);
        strings(e, &discriminator.separates);
        strings(e, &discriminator.expected_outcomes);
    }
    strings(e, &r.probes);
    strings(e, &r.stop_rules);
    e.i128(r.decision_deadline_ns);
    Ok(())
}

fn decode_case(d: &mut CanonicalDecoder<'_>) -> Result<InvestigationState, DurableSessionError> {
    let investigation_id = text(d, 128)?;
    let contract_basis = ContractBasis::from_canonical_bytes(d.bytes()?)?;
    let mission_id = MissionId::parse(text(d, 128)?)?;
    let revision = d.u64()?;
    let state = lifecycle(d.tag()?)?;
    let question = text(d, 8_192)?;
    let decision_informed = text(d, 1_024)?;
    let mut anchor_decoder = CanonicalDecoder::new(d.bytes()?);
    let basis_anchor = LedgerAnchor::decode_canonical(&mut anchor_decoder)?;
    anchor_decoder.ensure_finished()?;
    let hypotheses = list(d, 64, |d| {
        Ok(CaseHypothesis {
            hypothesis_id: text(d, 128)?,
            description: text(d, 8_192)?,
            epistemic_state: knowledge(d.tag()?)?,
            predictions: list(d, 128, |d| text(d, 1_024))?,
            evidence: list(d, 256, |d| Ok(d.digest()?))?,
            contradictions: list(d, 128, |d| Ok(d.digest()?))?,
        })
    })?;
    let knowns = statements(d)?;
    let unknowns = statements(d)?;
    let discriminators = list(d, 128, |d| {
        Ok(CaseDiscriminator {
            discriminator_id: text(d, 128)?,
            description: text(d, 1_024)?,
            separates: list(d, 64, |d| text(d, 128))?,
            expected_outcomes: list(d, 64, |d| text(d, 1_024))?,
        })
    })?;
    let record = InvestigationState::new(InvestigationStateParams {
        investigation_id,
        contract_basis,
        mission_id,
        revision,
        state,
        question,
        decision_informed,
        basis_anchor,
        hypotheses,
        knowns,
        unknowns,
        discriminators,
        probes: list(d, 128, |d| text(d, 128))?,
        stop_rules: list(d, 64, |d| text(d, 1_024))?,
        decision_deadline_ns: d.i128()?,
    })?;
    validation::record_fields(&record).map_err(|_| DurableSessionError::InvalidHistory)?;
    Ok(record)
}

fn statements(d: &mut CanonicalDecoder<'_>) -> Result<Vec<KnownStatement>, DurableSessionError> {
    list(d, 256, |d| {
        Ok(KnownStatement {
            statement_id: text(d, 128)?,
            text: text(d, 8_192)?,
            epistemic_state: knowledge(d.tag()?)?,
            basis: list(d, 256, |d| text(d, 128))?,
        })
    })
}
fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, DurableSessionError> {
    let value = d.text()?;
    if value.is_empty() || value.len() > maximum {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(value.to_owned())
}
fn list<'a, T>(
    d: &mut CanonicalDecoder<'a>,
    maximum: usize,
    mut read: impl FnMut(&mut CanonicalDecoder<'a>) -> Result<T, DurableSessionError>,
) -> Result<Vec<T>, DurableSessionError> {
    let count = usize::try_from(d.u32()?).map_err(|_| DurableSessionError::CapacityExceeded)?;
    if count > maximum {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut result = Vec::new();
    for _ in 0..count {
        result.push(read(d)?);
    }
    Ok(result)
}
fn strings(e: &mut CanonicalEncoder, values: &[String]) {
    e.u32(values.len() as u32);
    for value in values {
        e.text(value);
    }
}
fn digests(e: &mut CanonicalEncoder, values: &[ContentDigest]) {
    e.u32(values.len() as u32);
    for value in values {
        e.digest(*value);
    }
}

fn lifecycle_code(value: InvestigationLifecycle) -> u8 {
    use InvestigationLifecycle as L;
    match value {
        L::Draft => 1,
        L::Active => 2,
        L::AwaitingEvidence => 3,
        L::AwaitingApproval => 4,
        L::Blocked => 5,
        L::Resolved => 6,
        L::Refuted => 7,
        L::Cancelled => 8,
        L::Indeterminate => 9,
        L::Closed => 10,
    }
}
fn lifecycle(code: u8) -> Result<InvestigationLifecycle, DurableSessionError> {
    use InvestigationLifecycle as L;
    match code {
        1 => Ok(L::Draft),
        2 => Ok(L::Active),
        3 => Ok(L::AwaitingEvidence),
        4 => Ok(L::AwaitingApproval),
        5 => Ok(L::Blocked),
        6 => Ok(L::Resolved),
        7 => Ok(L::Refuted),
        8 => Ok(L::Cancelled),
        9 => Ok(L::Indeterminate),
        10 => Ok(L::Closed),
        _ => Err(DurableSessionError::InvalidHistory),
    }
}
fn knowledge_code(value: KnowledgeState) -> u8 {
    use KnowledgeState as K;
    match value {
        K::Known => 1,
        K::Estimated => 2,
        K::Unknown => 3,
        K::Conflicted => 4,
        K::Stale => 5,
        K::NotObservable => 6,
        K::Redacted => 7,
        K::Indeterminate => 8,
        K::NotApplicable => 9,
    }
}
fn knowledge(code: u8) -> Result<KnowledgeState, DurableSessionError> {
    use KnowledgeState as K;
    match code {
        1 => Ok(K::Known),
        2 => Ok(K::Estimated),
        3 => Ok(K::Unknown),
        4 => Ok(K::Conflicted),
        5 => Ok(K::Stale),
        6 => Ok(K::NotObservable),
        7 => Ok(K::Redacted),
        8 => Ok(K::Indeterminate),
        9 => Ok(K::NotApplicable),
        _ => Err(DurableSessionError::InvalidHistory),
    }
}
fn disposition_code(value: HypothesisDisposition) -> Result<u8, DurableSessionError> {
    use HypothesisDisposition as D;
    [
        D::Live,
        D::Supported,
        D::Disfavored,
        D::Refuted,
        D::Resolved,
        D::Superseded,
    ]
    .iter()
    .position(|candidate| *candidate == value)
    .map(|index| index as u8 + 1)
    .ok_or(DurableSessionError::InvalidHistory)
}
fn disposition(code: u8) -> Result<HypothesisDisposition, DurableSessionError> {
    use HypothesisDisposition as D;
    match code {
        1 => Ok(D::Live),
        2 => Ok(D::Supported),
        3 => Ok(D::Disfavored),
        4 => Ok(D::Refuted),
        5 => Ok(D::Resolved),
        6 => Ok(D::Superseded),
        _ => Err(DurableSessionError::InvalidHistory),
    }
}
