#![forbid(unsafe_code)]
//! Deterministic zero-Serde canonical binary codecs for projection schema records.

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, EffectState, EventId, EventKind, EventState, ObligationId,
    ObligationState, OperationId, SensorId, StreamId, TimestampNs,
};

use crate::schema::{
    CoverageStatus, DoctorScrubReceipt, FollowCommitSummary, FootageAdapterKind, GraphEdgeKey,
    ProjectedCoverageState, ProjectedEventSummary, ProjectedFootageImport, ProjectedHold,
    ProjectedIndeterminateEffect, ProjectedObligation, ProjectedPrivacyMask, ProjectedRevisionRef,
    ProjectedSensorLiveness, ProjectionAnchor, ScrubVerdict, SensorLivenessStatus, ZSetEdgeDelta,
};

/// Maximum vector length admitted during canonical decoding to guard against OOM on corrupt bytes.
pub(crate) const MAX_DECODE_VEC_LEN: usize = 1_048_576;

pub(crate) fn encode_vec_with<T>(
    items: &[T],
    encoder: &mut CanonicalEncoder,
    mut f: impl FnMut(&T, &mut CanonicalEncoder),
) {
    encoder.u64(items.len() as u64);
    for item in items {
        f(item, encoder);
    }
}

pub(crate) fn decode_vec_with<T>(
    decoder: &mut CanonicalDecoder<'_>,
    mut f: impl FnMut(&mut CanonicalDecoder<'_>) -> Result<T, ContractError>,
) -> Result<Vec<T>, ContractError> {
    let len_u64 = decoder.u64()?;
    let len = usize::try_from(len_u64).map_err(|_| ContractError::InvalidDigest)?;
    if len > MAX_DECODE_VEC_LEN {
        return Err(ContractError::InvalidDigest);
    }
    let mut out = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        out.push(f(decoder)?);
    }
    Ok(out)
}

pub(crate) fn encode_opt_digest(value: Option<ContentDigest>, encoder: &mut CanonicalEncoder) {
    match value {
        Some(digest) => {
            encoder.bool(true);
            encoder.digest(digest);
        }
        None => encoder.bool(false),
    }
}

pub(crate) fn decode_opt_digest(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Option<ContentDigest>, ContractError> {
    if decoder.bool()? {
        Ok(Some(decoder.digest()?))
    } else {
        Ok(None)
    }
}

pub(crate) fn decode_event_state(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<EventState, ContractError> {
    EventState::from_u8(decoder.u8()?).map_err(|_| ContractError::InvalidIdentifier)
}

pub(crate) fn decode_event_kind(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<EventKind, ContractError> {
    EventKind::from_u8(decoder.u8()?).map_err(|_| ContractError::InvalidIdentifier)
}

impl CanonicalEncode for ProjectionAnchor {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.commit_sequence);
        encoder.digest(self.authority_root);
        encoder.digest(self.history_root);
        encoder.digest(self.high_water_digest);
    }
}

impl CanonicalDecode for ProjectionAnchor {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            commit_sequence: decoder.u64()?,
            authority_root: decoder.digest()?,
            history_root: decoder.digest()?,
            high_water_digest: decoder.digest()?,
        })
    }
}

impl CanonicalEncode for ScrubVerdict {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.to_tag());
    }
}

impl CanonicalDecode for ScrubVerdict {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.u8()?).ok_or(ContractError::InvalidIdentifier)
    }
}

impl CanonicalEncode for DoctorScrubReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.scrubbed_at_ns.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.first_seq);
        encoder.u64(self.last_seq);
        encoder.u64(self.verified_objects);
        encoder.u64(self.verified_packs);
        encoder.u32(self.verified_fraction_ppm);
        self.verdict.encode_canonical(encoder);
    }
}

impl CanonicalDecode for DoctorScrubReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let receipt = Self {
            scrubbed_at_ns: TimestampNs::decode_canonical(decoder)?,
            anchor: ProjectionAnchor::decode_canonical(decoder)?,
            first_seq: decoder.u64()?,
            last_seq: decoder.u64()?,
            verified_objects: decoder.u64()?,
            verified_packs: decoder.u64()?,
            verified_fraction_ppm: decoder.u32()?,
            verdict: ScrubVerdict::decode_canonical(decoder)?,
        };
        receipt
            .validate()
            .map_err(|_| ContractError::InvalidIdentifier)?;
        Ok(receipt)
    }
}

impl CanonicalEncode for ProjectedEventSummary {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.event_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.u8(self.state.to_u8());
        encoder.u8(self.kind.to_u8());
        encode_vec_with(&self.zones, encoder, |z, enc| enc.text(z));
        encode_vec_with(&self.sensor_ids, encoder, |s, enc| s.encode_canonical(enc));
        self.interval.encode_canonical(encoder);
        encoder.digest(self.event_root);
        encoder.digest(self.revision_digest);
        encoder.u64(self.committed_sequence);
        encoder.bool(self.corroborated);
        encoder.bool(self.tamper_open);
        encoder.u64(self.payload_bytes);
    }
}

impl CanonicalDecode for ProjectedEventSummary {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            event_id: EventId::decode_canonical(decoder)?,
            revision: decoder.u64()?,
            state: decode_event_state(decoder)?,
            kind: decode_event_kind(decoder)?,
            zones: decode_vec_with(decoder, |dec| dec.text().map(ToOwned::to_owned))?,
            sensor_ids: decode_vec_with(decoder, SensorId::decode_canonical)?,
            interval: CaptureInterval::decode_canonical(decoder)?,
            event_root: decoder.digest()?,
            revision_digest: decoder.digest()?,
            committed_sequence: decoder.u64()?,
            corroborated: decoder.bool()?,
            tamper_open: decoder.bool()?,
            payload_bytes: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for ProjectedRevisionRef {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.event_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.u8(self.state.to_u8());
        encoder.digest(self.event_root);
        encoder.digest(self.revision_digest);
        encode_opt_digest(self.supersedes, encoder);
        encoder.u64(self.committed_sequence);
        encoder.u64(self.payload_bytes);
    }
}

impl CanonicalDecode for ProjectedRevisionRef {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            event_id: EventId::decode_canonical(decoder)?,
            revision: decoder.u64()?,
            state: decode_event_state(decoder)?,
            event_root: decoder.digest()?,
            revision_digest: decoder.digest()?,
            supersedes: decode_opt_digest(decoder)?,
            committed_sequence: decoder.u64()?,
            payload_bytes: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for CoverageStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.to_tag());
    }
}

impl CanonicalDecode for CoverageStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.u8()?).ok_or(ContractError::InvalidIdentifier)
    }
}

impl CanonicalEncode for ProjectedCoverageState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.sensor_id.encode_canonical(encoder);
        encoder.text(&self.zone_id);
        encoder.digest(self.latest_witness_digest);
        encoder.u64(self.generation);
        self.window.encode_canonical(encoder);
        self.status.encode_canonical(encoder);
        encoder.u32(self.active_gaps);
        encoder.u32(self.health_conflicts);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedCoverageState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            sensor_id: SensorId::decode_canonical(decoder)?,
            zone_id: decoder.text()?.to_owned(),
            latest_witness_digest: decoder.digest()?,
            generation: decoder.u64()?,
            window: CaptureInterval::decode_canonical(decoder)?,
            status: CoverageStatus::decode_canonical(decoder)?,
            active_gaps: decoder.u32()?,
            health_conflicts: decoder.u32()?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for FootageAdapterKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.to_tag());
    }
}

impl CanonicalDecode for FootageAdapterKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.u8()?).ok_or(ContractError::InvalidIdentifier)
    }
}

impl CanonicalEncode for ProjectedFootageImport {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.import_id);
        self.adapter_kind.encode_canonical(encoder);
        self.sensor_id.encode_canonical(encoder);
        self.stream_id.encode_canonical(encoder);
        self.capture_interval.encode_canonical(encoder);
        encoder.digest(self.manifest_digest);
        encoder.u64(self.capsule_count);
        encoder.u64(self.total_bytes);
        encoder.text(&self.adapter_id);
        encoder.text(&self.adapter_generation);
        encoder.bool(self.completed);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedFootageImport {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            import_id: decoder.digest()?,
            adapter_kind: FootageAdapterKind::decode_canonical(decoder)?,
            sensor_id: SensorId::decode_canonical(decoder)?,
            stream_id: StreamId::decode_canonical(decoder)?,
            capture_interval: CaptureInterval::decode_canonical(decoder)?,
            manifest_digest: decoder.digest()?,
            capsule_count: decoder.u64()?,
            total_bytes: decoder.u64()?,
            adapter_id: decoder.text()?.to_owned(),
            adapter_generation: decoder.text()?.to_owned(),
            completed: decoder.bool()?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for ProjectedHold {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.hold_id);
        encoder.text(&self.scope);
        encoder.digest(self.target_digest);
        encoder.bool(self.active);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedHold {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            hold_id: decoder.text()?.to_owned(),
            scope: decoder.text()?.to_owned(),
            target_digest: decoder.digest()?,
            active: decoder.bool()?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for ProjectedPrivacyMask {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.sensor_id.encode_canonical(encoder);
        encoder.u64(self.generation);
        encoder.digest(self.policy_digest);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedPrivacyMask {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            sensor_id: SensorId::decode_canonical(decoder)?,
            generation: decoder.u64()?,
            policy_digest: decoder.digest()?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for ProjectedObligation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.obligation_id.encode_canonical(encoder);
        self.operation_id.encode_canonical(encoder);
        encoder.text(&self.terminal_predicate);
        self.state.encode_canonical(encoder);
        encode_opt_digest(self.proof_digest, encoder);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedObligation {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            obligation_id: ObligationId::decode_canonical(decoder)?,
            operation_id: OperationId::decode_canonical(decoder)?,
            terminal_predicate: decoder.text()?.to_owned(),
            state: ObligationState::decode_canonical(decoder)?,
            proof_digest: decode_opt_digest(decoder)?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for ProjectedIndeterminateEffect {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.operation_id.encode_canonical(encoder);
        match &self.obligation_id {
            Some(id) => {
                encoder.bool(true);
                id.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.effect_state.encode_canonical(encoder);
        encoder.text(&self.reason);
        encoder.digest(self.record_digest);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedIndeterminateEffect {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let operation_id = OperationId::decode_canonical(decoder)?;
        let obligation_id = if decoder.bool()? {
            Some(ObligationId::decode_canonical(decoder)?)
        } else {
            None
        };
        Ok(Self {
            operation_id,
            obligation_id,
            effect_state: EffectState::decode_canonical(decoder)?,
            reason: decoder.text()?.to_owned(),
            record_digest: decoder.digest()?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for SensorLivenessStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.to_tag());
    }
}

impl CanonicalDecode for SensorLivenessStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_tag(decoder.u8()?).ok_or(ContractError::InvalidIdentifier)
    }
}

impl CanonicalEncode for ProjectedSensorLiveness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.sensor_id.encode_canonical(encoder);
        self.state.encode_canonical(encoder);
        self.last_seen_ns.encode_canonical(encoder);
        self.observed_at_ns.encode_canonical(encoder);
        encoder.u64(self.generation);
        encoder.digest(self.record_digest);
        encoder.u64(self.committed_sequence);
    }
}

impl CanonicalDecode for ProjectedSensorLiveness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            sensor_id: SensorId::decode_canonical(decoder)?,
            state: SensorLivenessStatus::decode_canonical(decoder)?,
            last_seen_ns: TimestampNs::decode_canonical(decoder)?,
            observed_at_ns: TimestampNs::decode_canonical(decoder)?,
            generation: decoder.u64()?,
            record_digest: decoder.digest()?,
            committed_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for GraphEdgeKey {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.relation);
        encoder.text(&self.source);
        encoder.text(&self.target);
    }
}

impl CanonicalDecode for GraphEdgeKey {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            relation: decoder.text()?.to_owned(),
            source: decoder.text()?.to_owned(),
            target: decoder.text()?.to_owned(),
        })
    }
}

impl CanonicalEncode for ZSetEdgeDelta {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.key.encode_canonical(encoder);
        encoder.u64(self.weight as u64);
        encoder.u64(self.commit_sequence);
    }
}

impl CanonicalDecode for ZSetEdgeDelta {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            key: GraphEdgeKey::decode_canonical(decoder)?,
            weight: decoder.u64()? as i64,
            commit_sequence: decoder.u64()?,
        })
    }
}

impl CanonicalEncode for FollowCommitSummary {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.commit_sequence);
        self.batch_id.encode_canonical(encoder);
        encoder.digest(self.authority_root);
        encode_vec_with(&self.families, encoder, |s, enc| enc.text(s));
        encode_vec_with(&self.changed_events, encoder, |id, enc| {
            id.encode_canonical(enc);
        });
        encode_vec_with(&self.changed_sensors, encoder, |id, enc| {
            id.encode_canonical(enc);
        });
        encode_vec_with(&self.changed_imports, encoder, |d, enc| enc.digest(*d));
        encode_vec_with(&self.changed_obligations, encoder, |id, enc| {
            id.encode_canonical(enc);
        });
        encode_vec_with(&self.zset_deltas, encoder, |d, enc| {
            d.encode_canonical(enc);
        });
    }
}

impl CanonicalDecode for FollowCommitSummary {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            commit_sequence: decoder.u64()?,
            batch_id: BatchId::decode_canonical(decoder)?,
            authority_root: decoder.digest()?,
            families: decode_vec_with(decoder, |dec| dec.text().map(ToOwned::to_owned))?,
            changed_events: decode_vec_with(decoder, EventId::decode_canonical)?,
            changed_sensors: decode_vec_with(decoder, SensorId::decode_canonical)?,
            changed_imports: decode_vec_with(decoder, |dec| dec.digest())?,
            changed_obligations: decode_vec_with(decoder, ObligationId::decode_canonical)?,
            zset_deltas: decode_vec_with(decoder, ZSetEdgeDelta::decode_canonical)?,
        })
    }
}
