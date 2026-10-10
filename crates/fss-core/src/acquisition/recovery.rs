#![forbid(unsafe_code)]
//! Sequence-accounted degradation and recovery without certifying a damaged interval.

use super::*;

/// Additive canonical schema; the embedded degradation keeps its original v1 encoding.
pub const SCHEMA_WINDOWED_DEGRADATION: &str = "fss.acquisition.windowed_degradation.v1";

/// A nonempty degraded sequence window chained to this exact acquisition request.
///
/// This records unavailable continuity, not a substitute continuity witness. Its predecessor
/// must be the first-frame witness, the immediately preceding verified window, or the previous
/// windowed degradation. Later recovery covers only a new clean window after this span.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowedDegradationEvidence {
    /// Full request identity, including stream generation, authority and source configuration.
    pub request_digest: ContentDigest,
    /// Exact immediately preceding first-frame, continuity or windowed-degradation witness.
    pub predecessor_digest: ContentDigest,
    /// First unavailable sequence position, inclusive.
    pub window_start_seq: u64,
    /// Last unavailable sequence position, inclusive.
    pub window_end_seq: u64,
    /// Original lost dimensions and invalidated negative claims, never rewritten by recovery.
    pub degradation: DegradationEvidence,
}

impl WindowedDegradationEvidence {
    /// Canonical schema identity.
    pub const SCHEMA: &'static str = SCHEMA_WINDOWED_DEGRADATION;

    /// Canonical identity of the request, predecessor, sequence span and degradation together.
    #[must_use]
    pub fn evidence_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }

    fn verify_structure(&self) -> Result<(), AcquisitionError> {
        let span = self
            .window_end_seq
            .checked_sub(self.window_start_seq)
            .and_then(|difference| difference.checked_add(1))
            .ok_or_else(|| AcquisitionError::ContinuityGapDetected {
                detail: "degraded window is reversed or its inclusive span overflows".to_owned(),
            })?;
        if u64::from(self.degradation.observed_packet_loss) > span {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "degraded packet loss exceeds its sequence span".to_owned(),
            });
        }
        self.degradation.verify(
            &self.degradation.source_id,
            &self.degradation.device_id,
            &self.degradation.adapter_id,
        )
    }

    /// Checks bounded structure and binding to an exact request; adjacency is session-owned.
    pub fn verify(&self, request: &AcquisitionRequest) -> Result<(), AcquisitionError> {
        self.verify_structure()?;
        if self.request_digest != request.request_digest() {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "windowed degradation names another acquisition request".to_owned(),
            });
        }
        self.degradation.verify(
            &request.source_identity.source_id,
            &request.device_identity.device_id,
            &request.adapter_identity.adapter_id,
        )
    }
}

impl CanonicalEncode for WindowedDegradationEvidence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.digest(self.request_digest);
        encoder.digest(self.predecessor_digest);
        encoder.u64(self.window_start_seq);
        encoder.u64(self.window_end_seq);
        self.degradation.encode_canonical(encoder);
    }
}

impl CanonicalDecode for WindowedDegradationEvidence {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        if decoder.text()? != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let value = Self {
            request_digest: decoder.digest()?,
            predecessor_digest: decoder.digest()?,
            window_start_seq: decoder.u64()?,
            window_end_seq: decoder.u64()?,
            degradation: DegradationEvidence::decode_canonical(decoder)?,
        };
        value
            .verify_structure()
            .map_err(|_| ContractError::NonCanonicalOrdering)?;
        Ok(value)
    }
}

pub(super) fn require_next_sequence(end: u64, start: u64) -> Result<(), AcquisitionError> {
    if end.checked_add(1) != Some(start) {
        return Err(AcquisitionError::ContinuityGapDetected {
            detail: format!(
                "next window must start immediately after sequence {end}, received {start}"
            ),
        });
    }
    Ok(())
}

impl AcquisitionSession {
    // `first` permits the same starting sequence as the first picture, as in the v1 contract.
    fn window_predecessor(&self) -> Result<(ContentDigest, u64, bool), AcquisitionError> {
        match &self.state {
            AcquisitionState::FirstFrameObserved { first_frame, .. } => Ok((
                first_frame.witness_digest(),
                first_frame.sequence_number,
                true,
            )),
            AcquisitionState::ContinuityVerified { continuity, .. } => Ok((
                continuity.witness_digest(),
                continuity.window_end_seq,
                false,
            )),
            AcquisitionState::Degraded {
                last_windowed_degradation: Some(window),
                ..
            } => Ok((window.evidence_digest(), window.window_end_seq, false)),
            _ => Err(AcquisitionError::MissingWitness {
                state: AcquisitionStateKind::Degraded,
                witness_type: "an exact first-frame, continuity or windowed-degradation predecessor is required",
            }),
        }
    }

    /// Exact predecessor for a new sequence-accounted degradation.
    ///
    /// An indeterminate state or an unscoped degradation cannot manufacture a sequence cursor.
    pub fn continuity_predecessor_digest(&self) -> Result<ContentDigest, AcquisitionError> {
        self.window_predecessor().map(|(digest, _, _)| digest)
    }

    /// Records a degraded window without certifying any position in that window.
    ///
    /// All checks precede mutation. Windows must be adjacent, nonempty and bound to the exact
    /// request and predecessor. A clean subsequent witness may recover the same generation;
    /// absence over this span remains forbidden. An unscoped or indeterminate predecessor
    /// requires explicit reconciliation or reconnect instead of guessing a missing span.
    pub fn degrade_window(
        &mut self,
        evidence: WindowedDegradationEvidence,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        evidence.verify(self.request())?;
        let (predecessor, end, first) = self.window_predecessor()?;
        if evidence.predecessor_digest != predecessor {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "windowed degradation predecessor does not match the current witness"
                    .to_owned(),
            });
        }
        if !(first && evidence.window_start_seq == end) {
            require_next_sequence(end, evidence.window_start_seq)?;
        }
        // `degrade` remains the single owner of transition admission and retained auth/custody.
        // It verifies before writing; no fallible operation follows its successful transition.
        let digest = evidence.evidence_digest();
        self.degrade(evidence.degradation.clone(), now_ns)?;
        if let AcquisitionState::Degraded {
            last_windowed_degradation,
            ..
        } = &mut self.state
        {
            *last_windowed_degradation = Some(Box::new(evidence));
        }
        if let Some(record) = self.history.last_mut() {
            record.witness_digest = digest;
            record.note = "degraded sequence window recorded; absence invalidated".to_owned();
        }
        self.has_windowed_gap = true;
        Ok(())
    }

    pub(super) fn recovery_window_for_verification(
        &self,
    ) -> Result<Option<&WindowedDegradationEvidence>, AcquisitionError> {
        let state = match &self.state {
            AcquisitionState::Indeterminate { prior_state, .. } => prior_state.as_ref(),
            other => other,
        };
        match state {
            AcquisitionState::Degraded {
                last_windowed_degradation: Some(window),
                ..
            } => Ok(Some(window)),
            AcquisitionState::Degraded {
                last_windowed_degradation: None,
                ..
            } if self.has_windowed_gap => Err(AcquisitionError::MissingWitness {
                state: AcquisitionStateKind::ContinuityVerified,
                witness_type: "unscoped degradation cannot erase a recorded sequence gap; reconnect or restore an exact known state",
            }),
            _ => Ok(None),
        }
    }

    /// Checks absence only inside the current verified window of the named stream generation.
    ///
    /// Both inclusive sequence and presentation-time bounds must be contained. The returned
    /// witness is valid only for that supplied scope, never for an earlier degraded window or
    /// the entire generation. A coverage witness that is itself uncertified remains refused.
    /// The scope is conjunctive: generation AND sequence interval AND presentation-time
    /// interval. This does not certify a time-only query, infer clock continuity across a gap,
    /// or establish a mapping for unobserved timestamps inside either interval.
    pub fn check_absence_claim_allowed_in_window(
        &self,
        generation: &StreamGeneration,
        start_seq: u64,
        end_seq: u64,
        start_pts_ns: TimestampNs,
        end_pts_ns: TimestampNs,
    ) -> Result<&ContinuityWitness, AcquisitionError> {
        if generation != &self.request().source_identity.stream_generation {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "absence scope names another stream generation".to_owned(),
            });
        }
        let AcquisitionState::ContinuityVerified { continuity, .. } = &self.state else {
            return Err(AcquisitionError::AbsenceClaimForbidden {
                state: self.state_kind(),
                detail: "window-scoped absence requires current verified continuity",
            });
        };
        if start_seq > end_seq
            || start_pts_ns > end_pts_ns
            || start_seq < continuity.window_start_seq
            || end_seq > continuity.window_end_seq
            || start_pts_ns < continuity.window_start_pts_ns
            || end_pts_ns > continuity.window_end_pts_ns
        {
            return Err(AcquisitionError::AbsenceClaimForbidden {
                state: self.state_kind(),
                detail: "absence scope must fit wholly inside the current verified sequence and time window",
            });
        }
        if !continuity.coverage_witness.certifies_absence() {
            return Err(AcquisitionError::InvalidCoverageWitness {
                detail: "current window coverage does not certify absence".to_owned(),
            });
        }
        Ok(continuity)
    }

    pub(super) fn verify_reconciled_continuity_state(
        &self,
        resolved: &AcquisitionState,
        now_ns: TimestampNs,
    ) -> Result<(), AcquisitionError> {
        let AcquisitionState::Indeterminate { prior_state, .. } = &self.state else {
            return Err(AcquisitionError::IndeterminateStateUnresolved {
                detail: "reconciliation requires an indeterminate state".to_owned(),
            });
        };
        // Reinstating the exact prior state does not add coverage or discard a gap.
        if resolved == prior_state.as_ref() {
            return Ok(());
        }
        let mut candidate = Self {
            state: prior_state.as_ref().clone(),
            history: Vec::new(),
            has_windowed_gap: self.has_windowed_gap,
        };
        match resolved {
            AcquisitionState::ContinuityVerified { continuity, .. } => {
                candidate.verify_continuity(continuity.as_ref().clone(), now_ns)?;
            }
            AcquisitionState::Degraded {
                degradation,
                last_windowed_degradation,
                ..
            } => match last_windowed_degradation {
                Some(window) => candidate.degrade_window(window.as_ref().clone(), now_ns)?,
                None => candidate.degrade(degradation.as_ref().clone(), now_ns)?,
            },
            _ => return Ok(()),
        }
        if candidate.state != *resolved {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "reconciled acquisition state substitutes retained custody or witnesses"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
