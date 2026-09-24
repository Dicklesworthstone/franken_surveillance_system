#![forbid(unsafe_code)]
//! Versioned evolution commands in the existing joint session/work/case journal.

use super::super::evolution::{
    InvestigationCitation, InvestigationEvolution, InvestigationEvolutionRequest, validate_request,
};
use super::*;
use fss_core::{CanonicalDecode, CaseDiscriminator, CaseHypothesis, KnowledgeState, LedgerAnchor};

pub(super) const RECORD: &str = "fss.reference_investigation_evolution_record.v1";
const REQUEST: &str = "fss.reference_investigation_evolution_request.v1";

impl DurableSessionStore {
    /// Durably rebase, readmit an inherited citation, or expand an investigation's alternatives.
    ///
    /// The runtime authenticates the principal and authorizes all citations/receipts beforehand.
    /// Sessions, work claims and cases share one staged commit. An uncertain append fences all
    /// APIs; existing pending and cold recovery replay this exact version before acknowledging.
    /// This does not execute probes, prove custody, promote knowledge or grant effect authority.
    pub fn evolve_investigation(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        request: InvestigationEvolutionRequest,
        now: TimestampNs,
    ) -> Result<InvestigationRevision, DurableInvestigationError> {
        self.preflight()?;
        validate_request(&request).map_err(DurableInvestigationError::Refused)?;
        let request_bytes = encode_request(principal, session, &request, now)?;
        let mut state = self
            .coordination
            .as_ref()
            .ok_or(DurableSessionError::InvalidHistory)?
            .fork();
        let cases = state
            .cases
            .as_mut()
            .ok_or(DurableSessionError::InvalidHistory)?;
        let mut memory = self.memory.clone();
        let result = cases.evolve(&mut memory, principal, session, &request, now);
        let staged = (|| -> Result<PendingSession, DurableSessionError> {
            let checkpoint = memory.checkpoint(self.limits.max_checkpoint_bytes)?;
            let payload = encode_record(
                &request_bytes,
                self.checkpoint_digest,
                checkpoint.digest(),
                outcome(&result),
            )?;
            Ok(PendingSession {
                memory,
                checkpoint,
                coordination: Some(state),
                record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
            })
        })();
        let pending = match staged {
            Ok(pending) => pending,
            Err(error) => {
                self.fenced = true;
                return Err(error.into());
            }
        };
        self.commit_candidate(pending)?;
        result.map_err(DurableInvestigationError::Refused)
    }
}

fn encode_record(
    request: &[u8],
    before: ContentDigest,
    after: ContentDigest,
    result: ContentDigest,
) -> Result<Vec<u8>, DurableSessionError> {
    let mut e = CanonicalEncoder::new();
    e.text(RECORD);
    e.bytes(request);
    e.digest(before);
    e.digest(after);
    e.digest(result);
    bounded_bytes(e)
}

pub(super) fn replay(
    payload: &[u8],
    sessions: &mut ReferenceSessionStore,
    state: &mut CoordinationState,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if payload.len() > MAX_INVESTIGATION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(payload);
    if d.text()? != RECORD {
        return Err(DurableSessionError::InvalidHistory);
    }
    let request_bytes = d.bytes()?;
    let before = d.digest()?;
    let after = d.digest()?;
    let expected = d.digest()?;
    d.ensure_finished()?;
    let (principal, session, request, now) = decode_request(request_bytes)?;
    if sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != before {
        return Err(DurableSessionError::InvalidHistory);
    }
    let cases = state
        .cases
        .as_mut()
        .ok_or(DurableSessionError::InvalidHistory)?;
    let result = cases.evolve(sessions, &principal, &session, &request, now);
    if outcome(&result) != expected
        || sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != after
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

fn encode_request(
    principal: &PrincipalId,
    session: &SessionId,
    request: &InvestigationEvolutionRequest,
    now: TimestampNs,
) -> Result<Vec<u8>, DurableSessionError> {
    validate_request(request).map_err(|_| DurableSessionError::InvalidHistory)?;
    let mut e = CanonicalEncoder::new();
    e.text(REQUEST);
    principal.encode_canonical(&mut e);
    session.encode_canonical(&mut e);
    e.i128(now.0);
    e.text(&request.case_id);
    e.digest(request.expected);
    match &request.change {
        InvestigationEvolution::Rebase { anchor, witness } => {
            e.tag(1);
            e.bytes(&anchor.try_canonical_bytes()?);
            e.digest(*witness);
        }
        InvestigationEvolution::ReadmitCitation { citation, witness } => {
            e.tag(2);
            e.text(&citation.hypothesis);
            e.digest(citation.evidence);
            e.bool(citation.contradicts);
            e.digest(*witness);
        }
        InvestigationEvolution::Expand {
            hypothesis: h,
            discriminator: d,
            probe,
        } => {
            e.tag(3);
            e.text(&h.hypothesis_id);
            e.text(&h.description);
            strings(&mut e, &h.predictions);
            // Unknown state and empty evidence are fixed by this command contract, not defaults
            // for omitted user fields. validate_request rejects any attempted other state.
            e.text(&d.discriminator_id);
            e.text(&d.description);
            strings(&mut e, &d.separates);
            strings(&mut e, &d.expected_outcomes);
            e.text(probe);
        }
    }
    bounded_bytes(e)
}

fn decode_request(
    bytes: &[u8],
) -> Result<
    (
        PrincipalId,
        SessionId,
        InvestigationEvolutionRequest,
        TimestampNs,
    ),
    DurableSessionError,
> {
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
    let case_id = text(&mut d, 128)?;
    let expected = d.digest()?;
    let change = match d.tag()? {
        1 => {
            let anchor_bytes = d.bytes()?;
            if anchor_bytes.len() > 4_096 {
                return Err(DurableSessionError::CapacityExceeded);
            }
            let mut nested = CanonicalDecoder::new(anchor_bytes);
            let anchor = LedgerAnchor::decode_canonical(&mut nested)?;
            nested.ensure_finished()?;
            if anchor.try_canonical_bytes()? != anchor_bytes {
                return Err(DurableSessionError::InvalidHistory);
            }
            InvestigationEvolution::Rebase {
                anchor,
                witness: d.digest()?,
            }
        }
        2 => InvestigationEvolution::ReadmitCitation {
            citation: InvestigationCitation {
                hypothesis: text(&mut d, 128)?,
                evidence: d.digest()?,
                contradicts: d.bool()?,
            },
            witness: d.digest()?,
        },
        3 => {
            let hypothesis = Box::new(CaseHypothesis {
                hypothesis_id: text(&mut d, 128)?,
                description: text(&mut d, 8_192)?,
                predictions: list(&mut d, 128, 1_024)?,
                epistemic_state: KnowledgeState::Unknown,
                evidence: vec![],
                contradictions: vec![],
            });
            let discriminator = Box::new(CaseDiscriminator {
                discriminator_id: text(&mut d, 128)?,
                description: text(&mut d, 1_024)?,
                separates: list(&mut d, 64, 128)?,
                expected_outcomes: list(&mut d, 64, 1_024)?,
            });
            InvestigationEvolution::Expand {
                hypothesis,
                discriminator,
                probe: text(&mut d, 128)?,
            }
        }
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    d.ensure_finished()?;
    let request = InvestigationEvolutionRequest {
        case_id,
        expected,
        change,
    };
    // Full re-encoding both validates nested semantics and rejects alternative spellings.
    if encode_request(&principal, &session, &request, now)? != bytes {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok((principal, session, request, now))
}

fn strings(e: &mut CanonicalEncoder, strings: &[String]) {
    e.u32(strings.len() as u32);
    for value in strings {
        e.text(value);
    }
}
fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, DurableSessionError> {
    let value = d.text()?;
    if value.is_empty() || value.len() > maximum {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(value.to_owned())
}
fn list(
    d: &mut CanonicalDecoder<'_>,
    maximum: usize,
    string_maximum: usize,
) -> Result<Vec<String>, DurableSessionError> {
    let count = usize::try_from(d.u32()?).map_err(|_| DurableSessionError::CapacityExceeded)?;
    if count > maximum {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(text(d, string_maximum)?);
    }
    Ok(values)
}
fn bounded_bytes(e: CanonicalEncoder) -> Result<Vec<u8>, DurableSessionError> {
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_INVESTIGATION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
