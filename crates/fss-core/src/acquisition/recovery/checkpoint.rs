//! Bounded, externally anchored lifecycle checkpoints. No device handles or media bytes.

use super::*;

const MAX_STATE_DEPTH: usize = 8;

fn malformed(detail: &str) -> AcquisitionError {
    AcquisitionError::NonCanonicalEncoding {
        detail: detail.to_owned(),
    }
}

fn decode_error(error: ContractError) -> AcquisitionError {
    AcquisitionError::NonCanonicalEncoding {
        detail: format!("invalid acquisition checkpoint: {error}"),
    }
}

impl AcquisitionSession {
    /// Schema identity constant (`fss.acquisition.session_checkpoint.v1`).
    pub const CHECKPOINT_SCHEMA: &'static str = "fss.acquisition.session_checkpoint.v1";

    /// Maximum encoded lifecycle checkpoint size, including the bounded audit tail (4 MiB).
    pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;

    /// Encodes the exact request, retained witnesses, sticky gap flag and audit tail.
    ///
    /// The SHA-256 of these bytes must be committed separately to trusted durable custody.
    /// This method does not perform I/O, retain media payloads, establish file durability or
    /// prove that referenced source bytes still exist. The schema is independent of existing
    /// witness schemas; their canonical encodings are embedded unchanged.
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, AcquisitionError> {
        verify_state(&self.state, self.request(), self.has_windowed_gap, 0)?;
        verify_history(self)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::CHECKPOINT_SCHEMA);
        self.request().encode_canonical(&mut encoder);
        encoder.bool(self.has_windowed_gap);
        encode_state(&self.state, &mut encoder);
        encoder.u32(self.history.len() as u32);
        for record in &self.history {
            record.encode_canonical(&mut encoder);
        }
        let bytes = encoder.finish_checked().map_err(decode_error)?;
        if bytes.len() > Self::MAX_CHECKPOINT_BYTES {
            return Err(AcquisitionError::BoundsViolation {
                field: "acquisition_checkpoint_bytes",
                max: Self::MAX_CHECKPOINT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(bytes)
    }

    /// Restores a checkpoint only against an independently trusted digest and exact request.
    ///
    /// The caller must obtain both expected digests from durable custody, not from the input
    /// being restored. A checkpoint hash alone is not proof of freshness: custody must name
    /// the latest committed checkpoint to reject rollback. Schema, size, recursion, witness
    /// bindings, audit continuity, canonical round-trip and trailing bytes are checked before
    /// any session is returned. Unknown or damaged input never falls back to a fresh session.
    ///
    /// Failed and cancelled sessions remain terminal. An already indeterminate session stays
    /// indeterminate. A request that never started remains requested. An authenticated-only
    /// session fails retryably and must reauthenticate in a new generation. Active states gain an
    /// explicit restart-uncertainty receipt, retaining the exact prior state for reconciliation.
    /// A restarted active generation cannot make interval-free absence claims, even after
    /// reconciliation. Neither media custody nor live transport continuity is re-established.
    pub fn restore_checkpoint(
        bytes: &[u8],
        expected_checkpoint_digest: ContentDigest,
        expected_request_digest: ContentDigest,
        now_ns: TimestampNs,
    ) -> Result<Self, AcquisitionError> {
        if bytes.len() > Self::MAX_CHECKPOINT_BYTES {
            return Err(AcquisitionError::BoundsViolation {
                field: "acquisition_checkpoint_bytes",
                max: Self::MAX_CHECKPOINT_BYTES,
                actual: bytes.len(),
            });
        }
        if ContentDigest::sha256(bytes) != expected_checkpoint_digest {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "checkpoint bytes do not match the trusted custody digest".to_owned(),
            });
        }
        if now_ns.0 < 0 {
            return Err(AcquisitionError::InvalidTimestamp {
                detail: "checkpoint recovery timestamp must be nonnegative".to_owned(),
            });
        }
        let mut session = decode_session(bytes).map_err(decode_error)?;
        if session.request().request_digest() != expected_request_digest {
            return Err(AcquisitionError::WitnessMismatch {
                detail: "checkpoint belongs to another request or stream generation".to_owned(),
            });
        }
        if session.checkpoint_bytes()? != bytes {
            return Err(malformed("checkpoint encoding is not canonical"));
        }
        match session.state_kind() {
            AcquisitionStateKind::Requested
            | AcquisitionStateKind::Failed
            | AcquisitionStateKind::Cancelled => return Ok(session),
            AcquisitionStateKind::Authenticated => {
                // Authentication has no Indeterminate transition in the lifecycle contract.
                // Do not restore an old receipt as a current authorization grant.
                let request = session.request();
                let failure = FailureWitness {
                    adapter_id: request.adapter_identity.adapter_id.clone(),
                    device_id: request.device_identity.device_id.clone(),
                    source_id: request.source_identity.source_id.clone(),
                    failed_at_ns: now_ns,
                    error_code: "restart_requires_reauthentication".to_owned(),
                    error_message: "checkpoint restored before adapter acceptance; reauthenticate in a new generation"
                        .to_owned(),
                    retryable: true,
                };
                session.fail(failure, now_ns)?;
                return Ok(session);
            }
            AcquisitionStateKind::Indeterminate => {
                // Do not nest another uncertainty state on every subsequent restart.
                // Conservative even if the retained prior state was not yet acquiring.
                session.has_windowed_gap = true;
                return Ok(session);
            }
            _ => {}
        }
        let request = session.request();
        let witness = IndeterminateWitness {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            indeterminate_at_ns: now_ns,
            reason: "checkpoint restored; live transport and media custody require reconciliation"
                .to_owned(),
            unresolved_obligations: vec![
                "verify-retained-media-custody".to_owned(),
                "reestablish-authorized-transport".to_owned(),
                "account-for-restart-continuity-gap".to_owned(),
            ],
        };
        session.mark_indeterminate(witness, now_ns)?;
        session.has_windowed_gap = true;
        Ok(session)
    }
}

fn verify_history(session: &AcquisitionSession) -> Result<(), AcquisitionError> {
    if session.history.is_empty() || session.history.len() > MAX_HISTORY_LEN {
        return Err(AcquisitionError::BoundsViolation {
            field: "acquisition_checkpoint_history",
            max: MAX_HISTORY_LEN,
            actual: session.history.len(),
        });
    }
    for record in &session.history {
        if record.note.len() > MAX_NOTE_LEN {
            return Err(AcquisitionError::BoundsViolation {
                field: "acquisition_checkpoint_note",
                max: MAX_NOTE_LEN,
                actual: record.note.len(),
            });
        }
        // Reconnect is intentionally admitted outside the forward-transition table.
        if record.to != AcquisitionStateKind::Requested
            && !is_allowed_transition(record.from, record.to)
        {
            return Err(malformed("checkpoint audit contains an illegal transition"));
        }
    }
    if session
        .history
        .windows(2)
        .any(|pair| pair[0].to != pair[1].from)
    {
        return Err(malformed("checkpoint audit tail is not contiguous"));
    }
    let Some(last) = session.history.last() else {
        return Err(malformed("checkpoint audit tail is missing"));
    };
    if last.to != session.state_kind() || last.witness_digest != state_digest(&session.state) {
        return Err(malformed(
            "checkpoint audit does not terminate at its retained state",
        ));
    }
    Ok(())
}

fn state_digest(state: &AcquisitionState) -> ContentDigest {
    match state {
        AcquisitionState::Requested(request) => request.request_digest(),
        AcquisitionState::Authenticated { auth, .. } => auth.receipt_digest(),
        AcquisitionState::AdapterAccepted { ack, .. } => ack.ack_digest(),
        AcquisitionState::FirstFrameObserved { first_frame, .. } => first_frame.witness_digest(),
        AcquisitionState::ContinuityVerified { continuity, .. } => continuity.witness_digest(),
        AcquisitionState::Degraded {
            degradation,
            last_windowed_degradation,
            ..
        } => last_windowed_degradation.as_ref().map_or_else(
            || degradation.evidence_digest(),
            |window| window.evidence_digest(),
        ),
        AcquisitionState::Failed { failure, .. } => failure.witness_digest(),
        AcquisitionState::Cancelled { quiescence, .. } => quiescence.receipt_digest(),
        AcquisitionState::Indeterminate { witness, .. } => witness.witness_digest(),
    }
}

fn verify_state(
    state: &AcquisitionState,
    request: &AcquisitionRequest,
    has_gap: bool,
    depth: usize,
) -> Result<(), AcquisitionError> {
    if depth > MAX_STATE_DEPTH {
        return Err(malformed("checkpoint state nesting exceeds its bound"));
    }
    if state.request() != request {
        return Err(malformed(
            "checkpoint substitutes a retained acquisition request",
        ));
    }
    request.verify()?;
    let source = &request.source_identity.source_id;
    let device = &request.device_identity.device_id;
    let adapter = &request.adapter_identity.adapter_id;
    let (auth, ack) = match state {
        AcquisitionState::Requested(_) => return Ok(()),
        AcquisitionState::Authenticated { auth, .. } => (auth, None),
        AcquisitionState::AdapterAccepted { auth, ack, .. }
        | AcquisitionState::FirstFrameObserved { auth, ack, .. }
        | AcquisitionState::ContinuityVerified { auth, ack, .. }
        | AcquisitionState::Degraded { auth, ack, .. } => (auth, Some(ack)),
        AcquisitionState::Failed {
            failure,
            prior_state,
            ..
        } => {
            if !is_allowed_transition(*prior_state, AcquisitionStateKind::Failed) {
                return Err(malformed("checkpoint failure has an illegal predecessor"));
            }
            return failure.verify(source, device, adapter);
        }
        AcquisitionState::Cancelled {
            quiescence,
            prior_state,
            ..
        } => {
            if !is_allowed_transition(*prior_state, AcquisitionStateKind::Cancelled) {
                return Err(malformed(
                    "checkpoint cancellation has an illegal predecessor",
                ));
            }
            return quiescence.verify(adapter, device, source);
        }
        AcquisitionState::Indeterminate {
            witness,
            prior_state,
            ..
        } => {
            if !is_allowed_transition(prior_state.kind(), AcquisitionStateKind::Indeterminate) {
                return Err(malformed(
                    "checkpoint uncertainty has an illegal predecessor",
                ));
            }
            witness.verify(source, device, adapter)?;
            return verify_state(prior_state, request, has_gap, depth + 1);
        }
    };
    // Validate the historical receipt at issuance, not as a grant of current authorization.
    auth.verify(
        adapter,
        device,
        request.requested_capabilities,
        auth.authorized_at_ns,
    )?;
    // The receipt must name the SAME credential method the request's adapter
    // identity configures — otherwise a receipt from a weaker method would
    // satisfy a stronger requirement.
    if auth.method != request.adapter_identity.credential_method {
        return Err(malformed(
            "checkpoint auth receipt credential method differs from the request",
        ));
    }
    if let Some(ack) = ack {
        ack.verify(&request.request_digest(), adapter)?;
        // The adapter's buffer allocation must fit the identity's declared
        // ceiling — an over-limit allocation is a contract violation, not a
        // detail to inherit silently.
        if ack.allocated_buffer_frames > request.adapter_identity.max_buffer_frames {
            return Err(malformed(
                "checkpoint adapter ack exceeds the configured buffer-frame ceiling",
            ));
        }
    }
    let (first, clean) = match state {
        AcquisitionState::FirstFrameObserved { first_frame, .. } => (Some(first_frame), None),
        AcquisitionState::ContinuityVerified {
            first_frame,
            continuity,
            ..
        } => (Some(first_frame), Some(continuity)),
        AcquisitionState::Degraded {
            first_frame,
            last_continuity,
            degradation,
            last_windowed_degradation,
            ..
        } => {
            degradation.verify(source, device, adapter)?;
            if let Some(window) = last_windowed_degradation {
                window.verify(request)?;
                if !has_gap || window.degradation != **degradation || first_frame.is_none() {
                    return Err(malformed(
                        "checkpoint loses a windowed gap or its retained custody",
                    ));
                }
                if let Some(clean) = last_continuity {
                    if clean.window_end_seq >= window.window_start_seq {
                        return Err(malformed(
                            "checkpoint gap overlaps retained clean continuity",
                        ));
                    }
                } else if let Some(first) = first_frame
                    && window.window_start_seq < first.sequence_number
                {
                    return Err(malformed("checkpoint gap precedes the first frame"));
                }
            }
            (first_frame.as_ref(), last_continuity.as_ref())
        }
        _ => (None, None),
    };
    if let Some(first) = first {
        first.verify(source, device, adapter)?;
    }
    if let Some(clean) = clean {
        let Some(first) = first else {
            return Err(malformed("checkpoint continuity lacks first-frame custody"));
        };
        clean.verify(source, device, adapter)?;
        if clean.window_start_seq < first.sequence_number {
            return Err(malformed("checkpoint continuity precedes the first frame"));
        }
    }
    Ok(())
}

fn encode_optional<T: CanonicalEncode>(value: Option<&T>, encoder: &mut CanonicalEncoder) {
    encoder.bool(value.is_some());
    if let Some(value) = value {
        value.encode_canonical(encoder);
    }
}

fn decode_optional<T: CanonicalDecode>(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Option<Box<T>>, ContractError> {
    if decoder.bool()? {
        Ok(Some(Box::new(T::decode_canonical(decoder)?)))
    } else {
        Ok(None)
    }
}

// The request is encoded once. verify_state checks that every nested state retains it exactly.
fn encode_state(state: &AcquisitionState, encoder: &mut CanonicalEncoder) {
    state.kind().encode_canonical(encoder);
    match state {
        AcquisitionState::Requested(_) => {}
        AcquisitionState::Authenticated { auth, .. } => auth.encode_canonical(encoder),
        AcquisitionState::AdapterAccepted { auth, ack, .. } => {
            auth.encode_canonical(encoder);
            ack.encode_canonical(encoder);
        }
        AcquisitionState::FirstFrameObserved {
            auth,
            ack,
            first_frame,
            ..
        } => {
            auth.encode_canonical(encoder);
            ack.encode_canonical(encoder);
            first_frame.encode_canonical(encoder);
        }
        AcquisitionState::ContinuityVerified {
            auth,
            ack,
            first_frame,
            continuity,
            ..
        } => {
            auth.encode_canonical(encoder);
            ack.encode_canonical(encoder);
            first_frame.encode_canonical(encoder);
            continuity.encode_canonical(encoder);
        }
        AcquisitionState::Degraded {
            auth,
            ack,
            first_frame,
            last_continuity,
            degradation,
            last_windowed_degradation,
            ..
        } => {
            auth.encode_canonical(encoder);
            ack.encode_canonical(encoder);
            encode_optional(first_frame.as_deref(), encoder);
            encode_optional(last_continuity.as_deref(), encoder);
            degradation.encode_canonical(encoder);
            encode_optional(last_windowed_degradation.as_deref(), encoder);
        }
        AcquisitionState::Failed {
            failure,
            prior_state,
            ..
        } => {
            failure.encode_canonical(encoder);
            prior_state.encode_canonical(encoder);
        }
        AcquisitionState::Cancelled {
            quiescence,
            prior_state,
            ..
        } => {
            quiescence.encode_canonical(encoder);
            prior_state.encode_canonical(encoder);
        }
        AcquisitionState::Indeterminate {
            witness,
            prior_state,
            ..
        } => {
            witness.encode_canonical(encoder);
            encode_state(prior_state, encoder);
        }
    }
}

fn decode_state(
    decoder: &mut CanonicalDecoder<'_>,
    request: &AcquisitionRequest,
    depth: usize,
) -> Result<AcquisitionState, ContractError> {
    if depth > MAX_STATE_DEPTH {
        return Err(ContractError::NonCanonicalOrdering);
    }
    let kind = AcquisitionStateKind::decode_canonical(decoder)?;
    let request = Box::new(request.clone());
    Ok(match kind {
        AcquisitionStateKind::Requested => AcquisitionState::Requested(request),
        AcquisitionStateKind::Authenticated => AcquisitionState::Authenticated {
            request,
            auth: AuthReceipt::decode_canonical(decoder)?,
        },
        AcquisitionStateKind::AdapterAccepted => AcquisitionState::AdapterAccepted {
            request,
            auth: AuthReceipt::decode_canonical(decoder)?,
            ack: AdapterAck::decode_canonical(decoder)?,
        },
        AcquisitionStateKind::FirstFrameObserved => AcquisitionState::FirstFrameObserved {
            request,
            auth: AuthReceipt::decode_canonical(decoder)?,
            ack: AdapterAck::decode_canonical(decoder)?,
            first_frame: Box::new(FirstFrameWitness::decode_canonical(decoder)?),
        },
        AcquisitionStateKind::ContinuityVerified => AcquisitionState::ContinuityVerified {
            request,
            auth: AuthReceipt::decode_canonical(decoder)?,
            ack: AdapterAck::decode_canonical(decoder)?,
            first_frame: Box::new(FirstFrameWitness::decode_canonical(decoder)?),
            continuity: Box::new(ContinuityWitness::decode_canonical(decoder)?),
        },
        AcquisitionStateKind::Degraded => AcquisitionState::Degraded {
            request,
            auth: AuthReceipt::decode_canonical(decoder)?,
            ack: AdapterAck::decode_canonical(decoder)?,
            first_frame: decode_optional(decoder)?,
            last_continuity: decode_optional(decoder)?,
            degradation: Box::new(DegradationEvidence::decode_canonical(decoder)?),
            last_windowed_degradation: decode_optional(decoder)?,
        },
        AcquisitionStateKind::Failed => AcquisitionState::Failed {
            request,
            failure: FailureWitness::decode_canonical(decoder)?,
            prior_state: AcquisitionStateKind::decode_canonical(decoder)?,
        },
        AcquisitionStateKind::Cancelled => AcquisitionState::Cancelled {
            request,
            quiescence: QuiescenceReceipt::decode_canonical(decoder)?,
            prior_state: AcquisitionStateKind::decode_canonical(decoder)?,
        },
        AcquisitionStateKind::Indeterminate => {
            let witness = Box::new(IndeterminateWitness::decode_canonical(decoder)?);
            let prior_state = Box::new(decode_state(decoder, &request, depth + 1)?);
            AcquisitionState::Indeterminate {
                request,
                witness,
                prior_state,
            }
        }
    })
}

fn decode_session(bytes: &[u8]) -> Result<AcquisitionSession, ContractError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != AcquisitionSession::CHECKPOINT_SCHEMA {
        return Err(ContractError::InvalidIdentifier);
    }
    let request = AcquisitionRequest::decode_canonical(&mut decoder)?;
    let has_windowed_gap = decoder.bool()?;
    let state = decode_state(&mut decoder, &request, 0)?;
    let count = decoder.u32()? as usize;
    if count == 0 || count > MAX_HISTORY_LEN {
        return Err(ContractError::NonCanonicalOrdering);
    }
    let mut history = Vec::with_capacity(count);
    for _ in 0..count {
        history.push(AcquisitionTransitionRecord::decode_canonical(&mut decoder)?);
    }
    decoder.ensure_finished()?;
    Ok(AcquisitionSession {
        state,
        history,
        has_windowed_gap,
    })
}

#[cfg(test)]
mod tests;
