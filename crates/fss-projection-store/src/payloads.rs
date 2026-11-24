#![forbid(unsafe_code)]
//! Typed canonical projection payloads and content-addressed [`PayloadResolver`] implementations.

mod codec;
mod resolver;

use fss_core::{
    CanonicalDecode, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, CoverageContinuity, CoverageWitness, EffectState, EventHypothesis, EventId,
    EventKind, EventState, ObjectId, Obligation, ObligationId, ObligationState, OperationId,
    SensorId, StreamId, TimestampNs,
};

use crate::error::ProjectionError;
use crate::schema::{
    CoverageStatus, FAMILY_ALERT_EFFECT_OUTCOME, FAMILY_COVERAGE_WITNESS,
    FAMILY_DELETION_TOMBSTONE, FAMILY_EFFECT_OUTCOME, FAMILY_EVENT_REVISION, FAMILY_EVIDENCE_HOLD,
    FAMILY_FILE_IMPORT, FAMILY_FOOTAGE_IMPORT, FAMILY_GRAPH_EDGE, FAMILY_HTTP_IMPORT,
    FAMILY_OBLIGATION, FAMILY_PRIVACY_MASK_POLICY, FAMILY_RTSP_IMPORT, FAMILY_SENSOR_LIVENESS,
    FAMILY_SENSOR_TAMPER_STATUS, FAMILY_TUTK_IMPORT, FootageAdapterKind, GraphEdgeKey,
    SensorLivenessStatus,
};

pub use resolver::{
    InMemoryPayloadResolver, NoopPayloadResolver, PackReaderPayloadResolver,
    PackStorePayloadResolver, PayloadResolver,
};

/// Binary magic header for canonical [`ProjectionRecordPayload`] blobs (`FSPP`).
pub const PROJECTION_PAYLOAD_MAGIC: [u8; 4] = *b"FSPP";
/// Supported binary format version for [`ProjectionRecordPayload`].
pub const PROJECTION_PAYLOAD_VERSION: u16 = 1;

/// Payload for an `event_revision` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRevisionPayload {
    /// Stable event lineage identity.
    pub event_id: EventId,
    /// Monotonic 1-based revision number.
    pub revision: u64,
    /// Event lifecycle state.
    pub state: EventState,
    /// Event semantic kind.
    pub kind: EventKind,
    /// Spatial zone identifiers.
    pub zones: Vec<String>,
    /// Contributing sensor identifiers.
    pub sensor_ids: Vec<SensorId>,
    /// Conservative event capture interval.
    pub interval: CaptureInterval,
    /// Publication root digest.
    pub event_root: ContentDigest,
    /// Superseded prior revision digest (`None` for revision `1`).
    pub supersedes: Option<ContentDigest>,
    /// Whether independent corroboration is established.
    pub corroborated: bool,
    /// Whether an open sensor-tamper report exists.
    pub tamper_open: bool,
}

/// Payload for a `sensor_tamper_status` delta targeting an event lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorTamperPayload {
    /// Target event lineage.
    pub event_id: EventId,
    /// Whether tamper remains open (`true`) or has been retired (`false`).
    pub tamper_open: bool,
}

/// Payload for a `coverage_witness` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageWitnessPayload {
    /// Sensor providing or losing coverage.
    pub sensor_id: SensorId,
    /// Spatial zone identifier.
    pub zone_id: String,
    /// Witness validity window.
    pub window: CaptureInterval,
    /// Explicit epistemic coverage status.
    pub status: CoverageStatus,
    /// Count of active declared gaps.
    pub active_gaps: u32,
    /// Count of unresolved health conflicts.
    pub health_conflicts: u32,
}

/// Payload for a unified footage import (`Rtsp`, `Http`, `File`, or `Tutk`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FootageImportPayload {
    /// Stable import identity.
    pub import_id: ContentDigest,
    /// Ingress adapter protocol family.
    pub adapter_kind: FootageAdapterKind,
    /// Originating sensor identity.
    pub sensor_id: SensorId,
    /// Logical stream generation identity.
    pub stream_id: StreamId,
    /// Source-native conservative capture interval.
    pub capture_interval: CaptureInterval,
    /// Digest of the canonical import manifest.
    pub manifest_digest: ContentDigest,
    /// Retained capsule count.
    pub capsule_count: u64,
    /// Total source payload bytes.
    pub total_bytes: u64,
    /// Admitted adapter identifier.
    pub adapter_id: String,
    /// Immutable adapter generation.
    pub adapter_generation: String,
    /// Whether the import completed cleanly.
    pub completed: bool,
}

/// Payload for an `evidence_hold` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceHoldPayload {
    /// Stable hold identifier.
    pub hold_id: String,
    /// Scope protected by this hold.
    pub scope: String,
    /// Content digest of the protected target root.
    pub target_digest: ContentDigest,
    /// True while active; false when explicitly released.
    pub active: bool,
}

/// Payload for a `privacy_mask_policy` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyMaskPayload {
    /// Target sensor identity.
    pub sensor_id: SensorId,
    /// Digest of the approved privacy mask policy.
    pub policy_digest: ContentDigest,
}

/// Payload for an `obligation` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationPayload {
    /// Stable obligation identifier.
    pub obligation_id: ObligationId,
    /// Owning operation identifier.
    pub operation_id: OperationId,
    /// Terminal predicate description.
    pub terminal_predicate: String,
    /// Obligation lifecycle state.
    pub state: ObligationState,
    /// Proof digest when terminal.
    pub proof_digest: Option<ContentDigest>,
}

/// Payload for an `effect_outcome` / `alert_effect_outcome` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectOutcomePayload {
    /// Effect operation identifier.
    pub operation_id: OperationId,
    /// Associated obligation identifier, if any.
    pub obligation_id: Option<ObligationId>,
    /// Current effect lifecycle state.
    pub effect_state: EffectState,
    /// Bounded reason or transition note.
    pub reason: String,
}

/// Payload for a `sensor_liveness` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorLivenessPayload {
    /// Sensor identity.
    pub sensor_id: SensorId,
    /// Observed liveness status.
    pub state: SensorLivenessStatus,
    /// Last observation/heartbeat timestamp.
    pub last_seen_ns: TimestampNs,
    /// Timestamp when this evaluation was recorded.
    pub observed_at_ns: TimestampNs,
}

/// Target entity removed or retracted by a `deletion_tombstone` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeletionTarget {
    /// Tombstone by ledger `ObjectId` (resolved through the object-to-entity map).
    Object(ObjectId),
    /// Tombstone a specific event lineage.
    Event(EventId),
    /// Tombstone a specific footage import.
    FootageImport(ContentDigest),
    /// Tombstone a specific `(sensor_id, zone_id)` coverage entry.
    Coverage {
        /// Sensor identifier.
        sensor_id: SensorId,
        /// Zone identifier.
        zone_id: String,
    },
}

/// Payload for a `deletion_tombstone` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionTombstonePayload {
    /// Target entity being tombstoned.
    pub target: DeletionTarget,
}

/// Payload for an explicit `graph_edge` Z-set delta (`ALG-ZSET-001`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphEdgeDeltaPayload {
    /// Signed multiplicity changes `(edge_key, delta_weight)`.
    pub edge_deltas: Vec<(GraphEdgeKey, i64)>,
}

/// Canonical tagged union of all projection-ingestable object payloads (`FSPP` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionRecordPayload {
    /// Event revision summary.
    EventRevision(EventRevisionPayload),
    /// Event lineage sensor-tamper open/retired update.
    SensorTamper(SensorTamperPayload),
    /// Coverage witness update.
    CoverageWitness(CoverageWitnessPayload),
    /// Unified footage import (`Rtsp`, `Http`, `File`, `Tutk`).
    FootageImport(FootageImportPayload),
    /// Evidence retention hold create/release.
    EvidenceHold(EvidenceHoldPayload),
    /// Per-sensor privacy mask policy generation.
    PrivacyMask(PrivacyMaskPayload),
    /// Durable effect obligation state.
    Obligation(ObligationPayload),
    /// Effect lifecycle outcome (indeterminate tracking / resolution).
    EffectOutcome(EffectOutcomePayload),
    /// Retained sensor liveness state.
    SensorLiveness(SensorLivenessPayload),
    /// Deletion tombstone retracting an entity and its Z-set graph edges.
    DeletionTombstone(DeletionTombstonePayload),
    /// Explicit incremental Z-set graph edge delta.
    GraphEdgeDelta(GraphEdgeDeltaPayload),
}

impl ProjectionRecordPayload {
    /// Encodes this payload into verified `FSPP` v1 canonical bytes.
    pub fn encode_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        let body = encoder.finish_checked()?;
        let mut out = Vec::with_capacity(6 + body.len());
        out.extend_from_slice(&PROJECTION_PAYLOAD_MAGIC);
        out.extend_from_slice(&PROJECTION_PAYLOAD_VERSION.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes verified `FSPP` v1 canonical bytes into a [`ProjectionRecordPayload`].
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() < 6 || bytes[0..4] != PROJECTION_PAYLOAD_MAGIC {
            return Err(ContractError::InvalidDigest);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != PROJECTION_PAYLOAD_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        Self::from_canonical_bytes(&bytes[6..])
    }
}

/// Returns true if `family` is a recognized projection-materialized family requiring payload decoding.
#[must_use]
pub fn is_projected_family(family: &str) -> bool {
    matches!(
        family,
        FAMILY_EVENT_REVISION
            | FAMILY_SENSOR_TAMPER_STATUS
            | FAMILY_COVERAGE_WITNESS
            | FAMILY_FILE_IMPORT
            | FAMILY_FOOTAGE_IMPORT
            | FAMILY_RTSP_IMPORT
            | FAMILY_HTTP_IMPORT
            | FAMILY_TUTK_IMPORT
            | FAMILY_EVIDENCE_HOLD
            | FAMILY_PRIVACY_MASK_POLICY
            | FAMILY_OBLIGATION
            | FAMILY_ALERT_EFFECT_OUTCOME
            | FAMILY_EFFECT_OUTCOME
            | FAMILY_SENSOR_LIVENESS
            | FAMILY_DELETION_TOMBSTONE
            | FAMILY_GRAPH_EDGE
    )
}

/// Decodes verified payload bytes for `family`, supporting both `FSPP` v1 payloads and
/// canonical `fss-core` records (`EventHypothesis`, `CoverageWitness`, `Obligation`).
pub(crate) fn decode_delta_payload(
    family: &str,
    object_id: &ObjectId,
    validity: CaptureInterval,
    payload_digest: ContentDigest,
    bytes: &[u8],
) -> Result<ProjectionRecordPayload, ProjectionError> {
    if bytes.len() >= 6 && bytes[0..4] == PROJECTION_PAYLOAD_MAGIC {
        return ProjectionRecordPayload::decode_bytes(bytes).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: family.to_owned(),
                detail: err.to_string(),
            }
        });
    }
    match family {
        FAMILY_EVENT_REVISION => {
            let hypothesis = EventHypothesis::from_canonical_bytes(bytes).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: family.to_owned(),
                    detail: err.to_string(),
                }
            })?;
            let corroborated = matches!(
                hypothesis.state,
                EventState::Corroborated
                    | EventState::Adjudicated
                    | EventState::AlertDelivered
                    | EventState::Resolved
            );
            Ok(ProjectionRecordPayload::EventRevision(
                EventRevisionPayload {
                    event_id: hypothesis.event_id,
                    revision: hypothesis.revision,
                    state: hypothesis.state,
                    kind: hypothesis.kind,
                    zones: hypothesis.zone_ids,
                    sensor_ids: Vec::new(),
                    interval: hypothesis.interval,
                    event_root: payload_digest,
                    supersedes: hypothesis.supersedes,
                    corroborated,
                    tamper_open: false,
                },
            ))
        }
        FAMILY_COVERAGE_WITNESS => {
            let witness = CoverageWitness::from_canonical_bytes(bytes).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: family.to_owned(),
                    detail: err.to_string(),
                }
            })?;
            let status = if witness.certifies_absence() {
                CoverageStatus::Covered
            } else if witness.continuity == CoverageContinuity::Gapped {
                CoverageStatus::NotObservable
            } else {
                CoverageStatus::Stale
            };
            let zone_id = witness
                .authorized_domain
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| "default".to_owned());
            let sensor_id = SensorId::parse(object_id.as_str()).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: family.to_owned(),
                    detail: err.to_string(),
                }
            })?;
            Ok(ProjectionRecordPayload::CoverageWitness(
                CoverageWitnessPayload {
                    sensor_id,
                    zone_id,
                    window: validity,
                    status,
                    active_gaps: u32::from(witness.continuity == CoverageContinuity::Gapped),
                    health_conflicts: 0,
                },
            ))
        }
        FAMILY_OBLIGATION => {
            let ob = Obligation::from_canonical_bytes(bytes).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: family.to_owned(),
                    detail: err.to_string(),
                }
            })?;
            Ok(ProjectionRecordPayload::Obligation(ObligationPayload {
                obligation_id: ob.obligation_id,
                operation_id: ob.operation_id,
                terminal_predicate: ob.terminal_predicate,
                state: ob.state,
                proof_digest: ob.proof_digest,
            }))
        }
        _ => Err(ProjectionError::InvalidPayload {
            family: family.to_owned(),
            detail: "unrecognized binary payload header (expected FSPP v1)".to_owned(),
        }),
    }
}
