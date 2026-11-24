#![forbid(unsafe_code)]
//! Canonical zero-Serde binary codecs for [`ProjectionRecordPayload`] (`FSPP` v1).

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContractError, EffectState, EventId, ObjectId, ObligationId, ObligationState, OperationId,
    SensorId, StreamId, TimestampNs,
};

use crate::payloads::{
    CoverageWitnessPayload, DeletionTarget, DeletionTombstonePayload, EffectOutcomePayload,
    EventRevisionPayload, EvidenceHoldPayload, FootageImportPayload, GraphEdgeDeltaPayload,
    ObligationPayload, PrivacyMaskPayload, ProjectionRecordPayload, SensorLivenessPayload,
    SensorTamperPayload,
};
use crate::schema::{CoverageStatus, FootageAdapterKind, GraphEdgeKey, SensorLivenessStatus};
use crate::schema_codec::{
    decode_event_kind, decode_event_state, decode_opt_digest, decode_vec_with, encode_opt_digest,
    encode_vec_with,
};

impl CanonicalEncode for ProjectionRecordPayload {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::EventRevision(p) => {
                encoder.u8(1);
                p.event_id.encode_canonical(encoder);
                encoder.u64(p.revision);
                encoder.u8(p.state.to_u8());
                encoder.u8(p.kind.to_u8());
                encode_vec_with(&p.zones, encoder, |z, enc| enc.text(z));
                encode_vec_with(&p.sensor_ids, encoder, |s, enc| s.encode_canonical(enc));
                p.interval.encode_canonical(encoder);
                encoder.digest(p.event_root);
                encode_opt_digest(p.supersedes, encoder);
                encoder.bool(p.corroborated);
                encoder.bool(p.tamper_open);
            }
            Self::SensorTamper(p) => {
                encoder.u8(2);
                p.event_id.encode_canonical(encoder);
                encoder.bool(p.tamper_open);
            }
            Self::CoverageWitness(p) => {
                encoder.u8(3);
                p.sensor_id.encode_canonical(encoder);
                encoder.text(&p.zone_id);
                p.window.encode_canonical(encoder);
                p.status.encode_canonical(encoder);
                encoder.u32(p.active_gaps);
                encoder.u32(p.health_conflicts);
            }
            Self::FootageImport(p) => {
                encoder.u8(4);
                encoder.digest(p.import_id);
                p.adapter_kind.encode_canonical(encoder);
                p.sensor_id.encode_canonical(encoder);
                p.stream_id.encode_canonical(encoder);
                p.capture_interval.encode_canonical(encoder);
                encoder.digest(p.manifest_digest);
                encoder.u64(p.capsule_count);
                encoder.u64(p.total_bytes);
                encoder.text(&p.adapter_id);
                encoder.text(&p.adapter_generation);
                encoder.bool(p.completed);
            }
            Self::EvidenceHold(p) => {
                encoder.u8(5);
                encoder.text(&p.hold_id);
                encoder.text(&p.scope);
                encoder.digest(p.target_digest);
                encoder.bool(p.active);
            }
            Self::PrivacyMask(p) => {
                encoder.u8(6);
                p.sensor_id.encode_canonical(encoder);
                encoder.digest(p.policy_digest);
            }
            Self::Obligation(p) => {
                encoder.u8(7);
                p.obligation_id.encode_canonical(encoder);
                p.operation_id.encode_canonical(encoder);
                encoder.text(&p.terminal_predicate);
                p.state.encode_canonical(encoder);
                encode_opt_digest(p.proof_digest, encoder);
            }
            Self::EffectOutcome(p) => {
                encoder.u8(8);
                p.operation_id.encode_canonical(encoder);
                match &p.obligation_id {
                    Some(id) => {
                        encoder.bool(true);
                        id.encode_canonical(encoder);
                    }
                    None => encoder.bool(false),
                }
                p.effect_state.encode_canonical(encoder);
                encoder.text(&p.reason);
            }
            Self::SensorLiveness(p) => {
                encoder.u8(9);
                p.sensor_id.encode_canonical(encoder);
                p.state.encode_canonical(encoder);
                p.last_seen_ns.encode_canonical(encoder);
                p.observed_at_ns.encode_canonical(encoder);
            }
            Self::DeletionTombstone(p) => {
                encoder.u8(10);
                match &p.target {
                    DeletionTarget::Object(id) => {
                        encoder.u8(1);
                        id.encode_canonical(encoder);
                    }
                    DeletionTarget::Event(id) => {
                        encoder.u8(2);
                        id.encode_canonical(encoder);
                    }
                    DeletionTarget::FootageImport(id) => {
                        encoder.u8(3);
                        encoder.digest(*id);
                    }
                    DeletionTarget::Coverage { sensor_id, zone_id } => {
                        encoder.u8(4);
                        sensor_id.encode_canonical(encoder);
                        encoder.text(zone_id);
                    }
                }
            }
            Self::GraphEdgeDelta(p) => {
                encoder.u8(11);
                encode_vec_with(&p.edge_deltas, encoder, |(k, w), enc| {
                    k.encode_canonical(enc);
                    enc.u64(*w as u64);
                });
            }
        }
    }
}

impl CanonicalDecode for ProjectionRecordPayload {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::EventRevision(EventRevisionPayload {
                event_id: EventId::decode_canonical(decoder)?,
                revision: decoder.u64()?,
                state: decode_event_state(decoder)?,
                kind: decode_event_kind(decoder)?,
                zones: decode_vec_with(decoder, |dec| dec.text().map(ToOwned::to_owned))?,
                sensor_ids: decode_vec_with(decoder, SensorId::decode_canonical)?,
                interval: CaptureInterval::decode_canonical(decoder)?,
                event_root: decoder.digest()?,
                supersedes: decode_opt_digest(decoder)?,
                corroborated: decoder.bool()?,
                tamper_open: decoder.bool()?,
            })),
            2 => Ok(Self::SensorTamper(SensorTamperPayload {
                event_id: EventId::decode_canonical(decoder)?,
                tamper_open: decoder.bool()?,
            })),
            3 => Ok(Self::CoverageWitness(CoverageWitnessPayload {
                sensor_id: SensorId::decode_canonical(decoder)?,
                zone_id: decoder.text()?.to_owned(),
                window: CaptureInterval::decode_canonical(decoder)?,
                status: CoverageStatus::decode_canonical(decoder)?,
                active_gaps: decoder.u32()?,
                health_conflicts: decoder.u32()?,
            })),
            4 => Ok(Self::FootageImport(FootageImportPayload {
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
            })),
            5 => Ok(Self::EvidenceHold(EvidenceHoldPayload {
                hold_id: decoder.text()?.to_owned(),
                scope: decoder.text()?.to_owned(),
                target_digest: decoder.digest()?,
                active: decoder.bool()?,
            })),
            6 => Ok(Self::PrivacyMask(PrivacyMaskPayload {
                sensor_id: SensorId::decode_canonical(decoder)?,
                policy_digest: decoder.digest()?,
            })),
            7 => Ok(Self::Obligation(ObligationPayload {
                obligation_id: ObligationId::decode_canonical(decoder)?,
                operation_id: OperationId::decode_canonical(decoder)?,
                terminal_predicate: decoder.text()?.to_owned(),
                state: ObligationState::decode_canonical(decoder)?,
                proof_digest: decode_opt_digest(decoder)?,
            })),
            8 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let obligation_id = if decoder.bool()? {
                    Some(ObligationId::decode_canonical(decoder)?)
                } else {
                    None
                };
                Ok(Self::EffectOutcome(EffectOutcomePayload {
                    operation_id,
                    obligation_id,
                    effect_state: EffectState::decode_canonical(decoder)?,
                    reason: decoder.text()?.to_owned(),
                }))
            }
            9 => Ok(Self::SensorLiveness(SensorLivenessPayload {
                sensor_id: SensorId::decode_canonical(decoder)?,
                state: SensorLivenessStatus::decode_canonical(decoder)?,
                last_seen_ns: TimestampNs::decode_canonical(decoder)?,
                observed_at_ns: TimestampNs::decode_canonical(decoder)?,
            })),
            10 => {
                let target = match decoder.u8()? {
                    1 => DeletionTarget::Object(ObjectId::decode_canonical(decoder)?),
                    2 => DeletionTarget::Event(EventId::decode_canonical(decoder)?),
                    3 => DeletionTarget::FootageImport(decoder.digest()?),
                    4 => DeletionTarget::Coverage {
                        sensor_id: SensorId::decode_canonical(decoder)?,
                        zone_id: decoder.text()?.to_owned(),
                    },
                    _ => return Err(ContractError::InvalidIdentifier),
                };
                Ok(Self::DeletionTombstone(DeletionTombstonePayload { target }))
            }
            11 => Ok(Self::GraphEdgeDelta(GraphEdgeDeltaPayload {
                edge_deltas: decode_vec_with(decoder, |dec| {
                    Ok((GraphEdgeKey::decode_canonical(dec)?, dec.u64()? as i64))
                })?,
            })),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}
