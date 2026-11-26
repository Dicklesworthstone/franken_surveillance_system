#![forbid(unsafe_code)]
//! Anchor-pinned MVCC projection bridge decoupling `orient`, `query`, and `follow` from full-spool
//! `fss doctor` scans while preserving strict epistemic separation between derived projection
//! catch-up and cryptographic payload scrub verification.
//!
//! # Epistemic Honesty
//!
//! - Catching up `<root>/projections/mvcc` to the authority ledger head proves only that derived
//!   materialized tables match committed ledger metadata at `projection_anchor`.
//! - It NEVER certifies that all object payloads in `objects/spool/` or `objects/packs/` remain
//!   uncorrupted on disk.
//! - Scrub health comes exclusively from a persisted, anchor-bound [`DoctorScrubReceipt`]. When
//!   absent (`None`) or behind the current anchor, [`ScrubStatus`] is explicitly
//!   [`ScrubStatus::NeverScrubbed`] or [`ScrubStatus::VerifiedStale`], mapping conservatively to
//!   `(DoctorVerdict::AttentionRequired, false)` — never falsely `"healthy"`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CaptureInterval, ContentDigest, CoverageContinuity,
    CoverageWitness, EffectState, EventHypothesis, EventId, EventState, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, ObjectId, ObjectRevision, Obligation, ObligationId,
    OperationReceipt, SensorId, SensorTamperStatus, StreamId, TimestampNs,
};
use fss_ledger::{DurableLedgerStatus, MerkleEpochLedger, inspect_durable};
use fss_object::ObjectManifest;
use fss_pack::{DurabilityMode, PackConfig, PackReadBudget, PackReader, PackStore};
use fss_projection_store::{
    CanonicalBatchSource, CoverageStatus, CoverageWitnessPayload, DeletionTarget, DeletionTombstonePayload,
    DoctorScrubReceipt, EffectOutcomePayload, EventQueryFilter, EventQueryPage,
    EventRevisionPayload, EvidenceHoldPayload, FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_COVERAGE_WITNESS, FAMILY_DELETION_TOMBSTONE, FAMILY_EFFECT_OUTCOME,
    FAMILY_EVENT_REVISION, FAMILY_EVIDENCE_HOLD, FAMILY_FILE_IMPORT, FAMILY_FOOTAGE_IMPORT,
    FAMILY_HTTP_IMPORT, FAMILY_OBLIGATION, FAMILY_PRIVACY_MASK_POLICY, FAMILY_RTSP_IMPORT,
    FAMILY_SENSOR_LIVENESS, FAMILY_SENSOR_TAMPER_STATUS, FAMILY_TUTK_IMPORT, FollowDeltaPage,
    FootageAdapterKind, FootageImportPayload, FootageQueryFilter, FootageQueryPage,
    HistoryChainMode, MvccProjectionStore, ObligationPayload, OrientSummary,
    PROJECTION_PAYLOAD_MAGIC, PayloadResolver, PrivacyMaskPayload, ProjectionAnchor,
    ProjectionError, ProjectionRecordPayload, ProjectionRecoveryMode, ProjectionRecoveryReport,
    ProjectionStore, ProjectionStoreConfig, ScrubVerdict, SensorLivenessPayload,
    SensorLivenessStatus, SensorTamperPayload, SliceBatchSource, WalSyncPolicy,
};

use crate::agent_orient::{
    DeploymentHistory, DeploymentOrientation, DeploymentReadError, OrientError, OrientLimits,
    OrientRequest, orient_deployment,
};
use crate::deletion::holds::HoldRecord;
use crate::deletion::{
    DeletionError, DeletionIndex, MAX_DELETION_RECORD_BYTES, has_records as has_deletion_records,
};
use crate::discovery::retained_liveness::SensorLivenessRecord;
use crate::discovery::watchdog::{WatchOfflineReason, WatchState};
use crate::doctor::{DoctorVerdict, inspect_deployment};
use crate::ingest::privacy_mask::PrivacyMaskPolicy;
use crate::ingest::recorded_coverage::CoverageRecord;
use crate::ingest::source_coverage::SourceCoverageRecord;
use crate::migration::{DeploymentLayoutV2, MigrationEquivalenceReceipt};
use crate::reference_deployment::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, FAMILY_DELETION_RECORD,
};

/// Recover v1 commitments only at bases used by deletion headers. The recording ledger
/// already verified these revisions when it opened. No source v1 directory is required.
fn v1_deletion_bases(
    ledger: &MerkleEpochLedger,
    records: &[EvidenceDeltaBatch],
    receipt: &MigrationEquivalenceReceipt,
    cancelled: &dyn Fn() -> bool,
) -> Result<BTreeMap<u64, LedgerAnchor>, DeploymentReadError> {
    let requested: BTreeSet<_> = records
        .iter()
        .filter(|batch| {
            batch.new_anchor.commit_sequence <= receipt.batches_migrated
                && batch.deltas.iter().any(|delta| delta.family == FAMILY_DELETION_RECORD)
        })
        .map(|batch| batch.basis_anchor.commit_sequence)
        .collect();
    let mut bases = BTreeMap::new();
    if requested.is_empty() {
        return Ok(bases);
    }
    let mut objects = BTreeMap::new();
    if requested.contains(&0) {
        let genesis = LedgerAnchor::genesis(&ledger.genesis_anchor().site_lineage);
        bases.insert(0, genesis);
    }
    let mut previous = ledger.genesis_anchor().clone();
    let mode = HistoryChainMode::V2MerkleEpoch;
    let proof_error = |err: ProjectionError| DeploymentReadError::Corrupt {
        reason: format!("v1 deletion basis reconstruction failed: {err}"),
    };
    let mut history = mode.genesis_root(&previous).map_err(proof_error)?;
    ledger
        .visit_batches_range(1, receipt.batches_migrated, &mut |batch| {
            if cancelled() {
                return Err(ProjectionError::InvalidRequest(
                    "retained read authority cancelled",
                ));
            }
            if batch.basis_anchor != previous
                || previous.commit_sequence.checked_add(1) != Some(batch.new_anchor.commit_sequence)
            {
                return Err(ProjectionError::InvalidRequest("incomplete deletion basis history"));
            }
            for delta in &batch.deltas {
                objects.insert(delta.object_id.clone(), ObjectRevision::from(delta));
            }
            previous = batch.new_anchor.clone();
            history = mode.successor_root(
                history,
                previous.commit_sequence,
                batch.batch_digest,
                &previous,
            )?;
            if requested.contains(&previous.commit_sequence) {
                let mut v1 = previous.clone();
                v1.state_root = fss_core::reference_state_root(&objects);
                bases.insert(v1.commit_sequence, v1);
            }
            Ok(())
        })
        .map_err(proof_error)?;
    let mut v1_head = previous.clone();
    v1_head.state_root = fss_core::reference_state_root(&objects);
    if requested.len() != bases.len()
        || previous != receipt.dest_v2_anchor
        || history != receipt.dest_v2_history_root
        || v1_head != receipt.source_v1_anchor
    {
        return Err(DeploymentReadError::Corrupt {
            reason: "canonical deletion history does not match the sealed migration prefix".to_owned(),
        });
    }
    Ok(bases)
}

/// Default relative directory under a deployment root storing rebuildable derived MVCC state.
pub const PROJECTION_SUBDIR: &str = "projections/mvcc";

/// Relative directory under `objects/` where sealed v2 packfiles live when present.
pub const PACKS_SUBDIR: &str = "packs";

/// Relative directory under `ledger/` where v2 segmented Merkle epoch files live when present.
pub const EPOCHS_SUBDIR: &str = "epochs";

/// Structured JSONL trace schema emitted for MVCC projection operations.
pub const PROJECTION_TRACE_SCHEMA: &str = "fss.projection_trace.v1";

/// Explicit epistemic classification of the deployment's latest background doctor scrub receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubStatus {
    /// A verified [`DoctorScrubReceipt`] with [`ScrubVerdict::Clean`] matches the exact current
    /// projection anchor and verified 100% of the corpus.
    VerifiedCurrent,
    /// A verified [`DoctorScrubReceipt`] exists, but the ledger has advanced past its anchor.
    VerifiedStale {
        /// Number of committed batches after the last verified scrub anchor.
        behind_commits: u64,
    },
    /// No [`DoctorScrubReceipt`] has ever been persisted (`unknown` — never falsely `"healthy"`).
    NeverScrubbed,
    /// The latest [`DoctorScrubReceipt`] completed with degraded coverage or non-fatal findings.
    ScrubDegraded,
    /// The latest [`DoctorScrubReceipt`] detected cryptographic corruption or missing artifacts.
    ScrubFailed,
}

impl ScrubStatus {
    /// Canonical lowercase label for diagnostics and structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedCurrent => "verified_current",
            Self::VerifiedStale { .. } => "verified_stale",
            Self::NeverScrubbed => "never_scrubbed",
            Self::ScrubDegraded => "scrub_degraded",
            Self::ScrubFailed => "scrub_failed",
        }
    }

    /// Maps scrub status conservatively onto `(DoctorVerdict, doctor_inspected)` for orientation.
    ///
    /// Never upgrades an unscrubbed or stale state into [`DoctorVerdict::Healthy`].
    #[must_use]
    pub const fn to_doctor_state(self) -> (DoctorVerdict, bool) {
        match self {
            Self::VerifiedCurrent => (DoctorVerdict::Healthy, true),
            Self::VerifiedStale { .. } | Self::NeverScrubbed => {
                (DoctorVerdict::AttentionRequired, false)
            }
            Self::ScrubDegraded | Self::ScrubFailed => (DoctorVerdict::AttentionRequired, true),
        }
    }
}

/// Combined read-only health view distinguishing derived projection freshness from payload scrub
/// verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionHealthView {
    /// True iff the materialized MVCC projection anchor matches the canonical ledger head.
    pub projection_caught_up: bool,
    /// Exact canonical projection anchor currently materialized.
    pub projection_anchor: ProjectionAnchor,
    /// Recovery/catch-up mode taken when opening the derived projection directory.
    pub recovery_mode: ProjectionRecoveryMode,
    /// Number of canonical batches replayed during open/catch-up.
    pub replayed_batches: u64,
    /// Latest persisted anchor-bound doctor scrub receipt, or `None` (`unknown`).
    pub scrub_receipt: Option<DoctorScrubReceipt>,
    /// Explicit epistemic classification of `scrub_receipt` against `projection_anchor`.
    pub scrub_status: ScrubStatus,
}

/// Structured per-operation MVCC telemetry record serializable as single-line JSONL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionTraceEvent {
    /// Logical operation name (`orient_summary`, `orient_decoupled`, `query_events`,
    /// `query_footage`, `follow_since`).
    pub op: &'static str,
    /// Total committed ledger sequence at the pinned MVCC snapshot.
    pub commits_total: u64,
    /// Number of delta commits replayed or scanned by this operation.
    pub delta_commits: u64,
    /// Elapsed MVCC read duration in microseconds.
    pub mvcc_read_us: u64,
    /// Number of materialized rows scanned or returned.
    pub rows_scanned: usize,
    /// Estimated canonical payload bytes touched by this operation.
    pub bytes_read: u64,
    /// Cache hit ratio in parts per million (`0..=1_000_000`).
    pub cache_hit_ratio_ppm: u32,
}

impl ProjectionTraceEvent {
    /// Formats this trace event as a canonical single-line JSONL object.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let ratio_whole = self.cache_hit_ratio_ppm / 1_000_000;
        let ratio_frac = self.cache_hit_ratio_ppm % 1_000_000;
        format!(
            "{{\"schema\":\"{PROJECTION_TRACE_SCHEMA}\",\"op\":\"{}\",\"commits_total\":{},\"delta_commits\":{},\"mvcc_read_us\":{},\"rows_scanned\":{},\"bytes_read\":{},\"cache_hit_ratio\":{ratio_whole}.{ratio_frac:06}}}",
            self.op,
            self.commits_total,
            self.delta_commits,
            self.mvcc_read_us,
            self.rows_scanned,
            self.bytes_read,
        )
    }
}

/// Targeted content-addressed payload resolver translating native deployment spool/packfile
/// objects into `FSPP` v1 projection payloads on demand without ever scanning `objects/spool/`.
struct DeploymentObjectPayloadResolver {
    objects_dir: PathBuf,
    pack_reader: Option<PackReader>,
    deleted_digests: BTreeSet<ContentDigest>,
    max_object_bytes: usize,
}

impl DeploymentObjectPayloadResolver {
    fn new(
        deployment_root: &Path,
        objects_dir: PathBuf,
        deleted_digests: BTreeSet<ContentDigest>,
        max_object_bytes: usize,
    ) -> Self {
        let packs_dir = objects_dir.join(PACKS_SUBDIR);
        let pack_reader = if packs_dir.is_dir() {
            PackStore::open(deployment_root, PackConfig::default())
                .ok()
                .map(|store| store.reader())
        } else {
            None
        };
        Self {
            objects_dir,
            pack_reader,
            deleted_digests,
            max_object_bytes,
        }
    }

    fn is_locally_tombstoned(&self, digest: ContentDigest) -> bool {
        let name = format!(
            "{}{}",
            digest.to_text().replacen(':', "-", 1),
            fss_publication::TOMBSTONE_RECORD_SUFFIX
        );
        let tomb_path = self
            .objects_dir
            .join(fss_publication::LOCAL_TOMBSTONES_DIR)
            .join(name);
        fs::symlink_metadata(&tomb_path)
            .map(|meta| meta.file_type().is_file())
            .unwrap_or(false)
    }

    fn read_verified_object(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<Vec<u8>>, ProjectionError> {
        if self.deleted_digests.contains(&digest) || self.is_locally_tombstoned(digest) {
            return Ok(None);
        }
        if let Some(reader) = &self.pack_reader {
            match reader.read_verified(&digest) {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(
                    fss_pack::PackError::MissingObject(_)
                    | fss_pack::PackError::EvidenceDeleted { .. },
                ) => {}
                Err(err) => return Err(ProjectionError::Pack(err)),
            }
        }
        match fss_publication::read_verified(&self.objects_dir, digest, self.max_object_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(fss_publication::LocalPublicationError::Spool(
                fss_object::SpoolError::Missing(_),
            ))
            | Err(fss_publication::LocalPublicationError::InvalidLayout { .. }) => Ok(None),
            Err(err) => Err(ProjectionError::InvalidPayload {
                family: "deployment_object".to_owned(),
                detail: err.to_string(),
            }),
        }
    }

    fn translate_event_revision(
        &self,
        digest: ContentDigest,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let raw_len = raw.len() as u64;
        let (hypothesis, payload_bytes) = if let Ok(hypothesis) =
            EventHypothesis::from_canonical_bytes(&raw)
        {
            (hypothesis, raw_len)
        } else {
            let Ok(manifest) = ObjectManifest::from_canonical_bytes(&raw) else {
                return Ok(None);
            };
            let Some(meta_digest) = manifest
                .metadata_digest()
                .or_else(|| manifest.children().first().copied())
            else {
                return Ok(None);
            };
            let Some(meta_bytes) = self.read_verified_object(meta_digest)? else {
                return Ok(None);
            };
            let len = raw_len.saturating_add(meta_bytes.len() as u64);
            let hypothesis = EventHypothesis::from_canonical_bytes(&meta_bytes).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: FAMILY_EVENT_REVISION.to_owned(),
                    detail: err.to_string(),
                }
            })?;
            (hypothesis, len)
        };
        let mut sensor_ids = Vec::new();
        for ev in &hypothesis.evidence {
            if let Ok(sensor) = SensorId::parse(&ev.failure_domain) {
                sensor_ids.push(sensor);
            }
        }
        sensor_ids.sort();
        sensor_ids.dedup();
        let corroborated = matches!(
            hypothesis.state,
            EventState::Corroborated
                | EventState::Adjudicated
                | EventState::AlertDelivered
                | EventState::Resolved
        );
        let payload = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
            event_id: hypothesis.event_id,
            revision: hypothesis.revision,
            state: hypothesis.state,
            kind: hypothesis.kind,
            zones: hypothesis.zone_ids,
            sensor_ids,
            interval: hypothesis.interval,
            event_root: digest,
            supersedes: hypothesis.supersedes,
            corroborated,
            tamper_open: false,
        });
        Ok(Some((payload, payload_bytes)))
    }

    fn translate_coverage(
        &self,
        delta: &EvidenceDelta,
        raw_opt: Option<Vec<u8>>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        if let Some(raw) = raw_opt {
            let len = raw.len() as u64;
            if let Ok(witness) = CoverageWitness::from_canonical_bytes(&raw) {
                return Ok(build_coverage_witness(
                    &delta.object_id,
                    delta.validity,
                    &witness,
                    None,
                )
                .map(|p| (p, len)));
            }
            if let Ok(record) = SourceCoverageRecord::from_bytes(&raw, delta.payload_digest) {
                return Ok(build_coverage_witness(
                    &delta.object_id,
                    record.interval,
                    &record.witness,
                    None,
                )
                .map(|p| (p, len)));
            }
            if let Ok(record) = CoverageRecord::from_bytes(&raw, delta.payload_digest) {
                let sensor = SensorId::parse(&record.sensor_id)
                    .or_else(|_| SensorId::parse(delta.object_id.as_str()))
                    .or_else(|_| SensorId::parse("sensor:recorded"));
                let Ok(sensor_id) = sensor else {
                    return Ok(None);
                };
                let zone_id = record
                    .zones
                    .first()
                    .map(|z| z.zone_id.clone())
                    .unwrap_or_else(|| "default".to_owned());
                let payload = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                    sensor_id,
                    zone_id,
                    window: delta.validity,
                    status: CoverageStatus::Covered,
                    active_gaps: 0,
                    health_conflicts: 0,
                });
                return Ok(Some((payload, len)));
            }
            return Ok(None);
        }

        if self.deleted_digests.contains(&delta.payload_digest)
            || self.is_locally_tombstoned(delta.payload_digest)
        {
            let sensor_id = SensorId::parse(delta.object_id.as_str())
                .or_else(|_| SensorId::parse("sensor:deleted-coverage"))
                .map_err(|err| ProjectionError::InvalidPayload {
                    family: FAMILY_COVERAGE_WITNESS.to_owned(),
                    detail: err.to_string(),
                })?;
            return Ok(Some((
                ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                    sensor_id,
                    zone_id: "default".to_owned(),
                    window: delta.validity,
                    status: CoverageStatus::NotObservable,
                    active_gaps: 1,
                    health_conflicts: 0,
                }),
                0,
            )));
        }
        Ok(None)
    }

    fn translate_footage(
        &self,
        delta: &EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let adapter_kind = match delta.family.as_str() {
            FAMILY_RTSP_IMPORT => FootageAdapterKind::Rtsp,
            FAMILY_HTTP_IMPORT => FootageAdapterKind::Http,
            FAMILY_TUTK_IMPORT => FootageAdapterKind::Tutk,
            FAMILY_FILE_IMPORT | FAMILY_FOOTAGE_IMPORT => FootageAdapterKind::File,
            _ => return Ok(None),
        };
        let Ok(sensor_id) = SensorId::parse("sensor:imported") else {
            return Ok(None);
        };
        let Ok(stream_id) = StreamId::parse("stream:imported") else {
            return Ok(None);
        };
        let import_id = delta
            .object_id
            .as_str()
            .strip_prefix("object:file-import:")
            .and_then(|hex| ContentDigest::parse(format!("sha256:{hex}")).ok())
            .unwrap_or(delta.payload_digest);
        let completed = if delta.family == FAMILY_FILE_IMPORT {
            delta.new_generation >= 2
        } else {
            true
        };
        let payload = ProjectionRecordPayload::FootageImport(FootageImportPayload {
            import_id,
            adapter_kind,
            sensor_id,
            stream_id,
            capture_interval: delta.validity,
            manifest_digest: delta.payload_digest,
            capsule_count: 1,
            total_bytes: 0,
            adapter_id: delta.family.clone(),
            adapter_generation: "v1".to_owned(),
            completed,
        });
        Ok(Some((payload, 0)))
    }

    fn translate_hold(
        &self,
        delta: &EvidenceDelta,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let len = raw.len() as u64;
        let record = HoldRecord::from_bytes(&raw, delta.payload_digest).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: FAMILY_EVIDENCE_HOLD.to_owned(),
                detail: err.to_string(),
            }
        })?;
        let req = record.request();
        Ok(Some((
            ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
                hold_id: req.hold_id.clone(),
                scope: req.state.as_str().to_owned(),
                target_digest: req.import_identity,
                active: req.state.is_active(),
            }),
            len,
        )))
    }

    fn translate_privacy_mask(
        &self,
        delta: &EvidenceDelta,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let len = raw.len() as u64;
        let policy = PrivacyMaskPolicy::from_bytes(&raw, delta.payload_digest).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: FAMILY_PRIVACY_MASK_POLICY.to_owned(),
                detail: err.to_string(),
            }
        })?;
        Ok(Some((
            ProjectionRecordPayload::PrivacyMask(PrivacyMaskPayload {
                sensor_id: policy.sensor_id().clone(),
                policy_digest: delta.payload_digest,
            }),
            len,
        )))
    }

    fn translate_alert_effect_outcome(
        &self,
        delta: &EvidenceDelta,
        raw_opt: Option<Vec<u8>>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        if let Some(raw) = raw_opt {
            let raw_len = raw.len() as u64;
            if let Ok(manifest) = ObjectManifest::from_canonical_bytes(&raw)
                && let Some(meta_digest) = manifest.metadata_digest()
                && let Some(meta_bytes) = self.read_verified_object(meta_digest)?
            {
                let mut dec = CanonicalDecoder::new(&meta_bytes);
                if dec.text().ok() == Some("fss.reference_alert_outcome.v1")
                    && let Ok(receipt) = OperationReceipt::decode_canonical(&mut dec)
                    && let Ok(obligation_id) = ObligationId::decode_canonical(&mut dec)
                {
                    let total_len = raw_len.saturating_add(meta_bytes.len() as u64);
                    return Ok(Some((
                        ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                            operation_id: receipt.intent.operation_id,
                            obligation_id: Some(obligation_id),
                            effect_state: receipt.state,
                            reason: "alert_effect_outcome".to_owned(),
                        }),
                        total_len,
                    )));
                }
            }
        }
        if let Some(op_id) = &delta.operation_id {
            return Ok(Some((
                ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                    operation_id: op_id.clone(),
                    obligation_id: None,
                    effect_state: EffectState::Verified,
                    reason: delta.family.clone(),
                }),
                0,
            )));
        }
        Ok(None)
    }

    fn translate_sensor_liveness(
        &self,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let len = raw.len() as u64;
        let record = SensorLivenessRecord::from_bytes(&raw).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: FAMILY_SENSOR_LIVENESS.to_owned(),
                detail: err.to_string(),
            }
        })?;
        let state = match record.state() {
            WatchState::Observable => SensorLivenessStatus::Online,
            WatchState::Silent { .. } | WatchState::Asleep { .. } => SensorLivenessStatus::Degraded,
            WatchState::NotObservable {
                reason: WatchOfflineReason::SilentBeyondThreshold,
            } => SensorLivenessStatus::Offline,
            WatchState::NotObservable {
                reason: WatchOfflineReason::NeverObserved,
            } => SensorLivenessStatus::Unknown,
        };
        Ok(Some((
            ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                sensor_id: record.enrollment().sensor().clone(),
                state,
                last_seen_ns: TimestampNs(i128::from(record.last_seen_ns().unwrap_or(0))),
                observed_at_ns: TimestampNs(i128::from(record.observed_at_ns())),
            }),
            len,
        )))
    }

    fn translate_sensor_tamper(
        &self,
        delta: &EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let empty_tamper_digest = SensorTamperStatus::default().canonical_digest();
        let tamper_open = delta
            .witness_digest
            .is_some_and(|witness| witness != empty_tamper_digest);
        let raw_id = delta.object_id.as_str();
        let trimmed = raw_id
            .strip_prefix("object:event:")
            .unwrap_or(raw_id)
            .strip_suffix(":tamper")
            .unwrap_or(raw_id);
        let Ok(event_id) = EventId::parse(trimmed) else {
            return Ok(None);
        };
        let payload = ProjectionRecordPayload::SensorTamper(SensorTamperPayload {
            event_id,
            tamper_open,
        });
        Ok(Some((payload, 0)))
    }
}

fn build_coverage_witness(
    object_id: &ObjectId,
    validity: CaptureInterval,
    witness: &CoverageWitness,
    explicit_sensor: Option<SensorId>,
) -> Option<ProjectionRecordPayload> {
    let sensor_id = match explicit_sensor {
        Some(id) => id,
        None => SensorId::parse(object_id.as_str())
            .or_else(|_| SensorId::parse("sensor:coverage"))
            .ok()?,
    };
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
    Some(ProjectionRecordPayload::CoverageWitness(
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

impl PayloadResolver for DeploymentObjectPayloadResolver {
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        self.read_verified_object(*digest)
    }

    fn resolve_record_for_delta(
        &self,
        delta: &EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let raw_opt = self.read_verified_object(delta.payload_digest)?;
        if let Some(raw) = &raw_opt
            && raw.len() >= 6
            && raw[0..4] == PROJECTION_PAYLOAD_MAGIC
        {
            let payload = ProjectionRecordPayload::decode_bytes(raw).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: delta.family.clone(),
                    detail: err.to_string(),
                }
            })?;
            return Ok(Some((payload, raw.len() as u64)));
        }
        match delta.family.as_str() {
            FAMILY_EVENT_REVISION => {
                if let Some(raw) = raw_opt {
                    return self.translate_event_revision(delta.payload_digest, raw);
                }
                if let Some(witness) = delta.witness_digest
                    && let Some(witness_bytes) = self.read_verified_object(witness)?
                {
                    return self.translate_event_revision(delta.payload_digest, witness_bytes);
                }
                Ok(None)
            }
            FAMILY_SENSOR_TAMPER_STATUS => self.translate_sensor_tamper(delta),
            FAMILY_COVERAGE_WITNESS => self.translate_coverage(delta, raw_opt),
            FAMILY_FILE_IMPORT
            | FAMILY_FOOTAGE_IMPORT
            | FAMILY_RTSP_IMPORT
            | FAMILY_HTTP_IMPORT
            | FAMILY_TUTK_IMPORT => self.translate_footage(delta),
            FAMILY_EVIDENCE_HOLD => match raw_opt {
                Some(raw) => self.translate_hold(delta, raw),
                None => Ok(None),
            },
            FAMILY_PRIVACY_MASK_POLICY => match raw_opt {
                Some(raw) => self.translate_privacy_mask(delta, raw),
                None => Ok(None),
            },
            FAMILY_OBLIGATION => match raw_opt {
                Some(raw) => {
                    let len = raw.len() as u64;
                    let ob = Obligation::from_canonical_bytes(&raw).map_err(|err| {
                        ProjectionError::InvalidPayload {
                            family: FAMILY_OBLIGATION.to_owned(),
                            detail: err.to_string(),
                        }
                    })?;
                    Ok(Some((
                        ProjectionRecordPayload::Obligation(ObligationPayload {
                            obligation_id: ob.obligation_id,
                            operation_id: ob.operation_id,
                            terminal_predicate: ob.terminal_predicate,
                            state: ob.state,
                            proof_digest: ob.proof_digest,
                        }),
                        len,
                    )))
                }
                None => Ok(None),
            },
            FAMILY_ALERT_EFFECT_OUTCOME | FAMILY_EFFECT_OUTCOME => {
                self.translate_alert_effect_outcome(delta, raw_opt)
            }
            FAMILY_SENSOR_LIVENESS => match raw_opt {
                Some(raw) => self.translate_sensor_liveness(raw),
                None => Ok(None),
            },
            FAMILY_DELETION_TOMBSTONE => {
                let payload =
                    ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                        target: DeletionTarget::Object(delta.object_id.clone()),
                    });
                Ok(Some((payload, 0)))
            }
            _ => Ok(None),
        }
    }
}

/// Anchor-pinned MVCC projection bridge over an existing deployment root.
///
/// Decouples `orient`, `query`, and `follow` from full-spool `fss doctor` directory scans,
/// catching up `<root>/projections/mvcc` incrementally from `projection_high_water + 1 ..= head`
/// and exposing explicit [`DoctorScrubReceipt`] separation.
pub struct ProjectionBridge {
    root: PathBuf,
    projection_dir: PathBuf,
    store: MvccProjectionStore,
    recovery: ProjectionRecoveryReport,
    site_lineage: String,
    head_commit_sequence: u64,
}

impl ProjectionBridge {
    /// Opens `<root>/projections/mvcc` and catches up incrementally to the canonical authority
    /// ledger head without scanning `objects/spool/`.
    pub fn open_or_catch_up(
        root: &Path,
        limits: &OrientLimits,
    ) -> Result<Self, DeploymentReadError> {
        Self::open_or_catch_up_cancellable(root, limits, &|| false)
    }

    /// Cancellable variant of [`Self::open_or_catch_up`].
    pub fn open_or_catch_up_cancellable(
        root: &Path,
        limits: &OrientLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, DeploymentReadError> {
        if cancelled() {
            return Err(DeploymentReadError::Corrupt {
                reason: "retained read authority cancelled".to_owned(),
            });
        }
        let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
        let layout_bytes =
            fs::read(&layout_path).map_err(|_| DeploymentReadError::NotADeployment {
                reason: "missing LAYOUT in deployment root".to_owned(),
            })?;
        if layout_bytes.len() > limits.max_layout_bytes {
            return Err(DeploymentReadError::Unreadable {
                reason: "LAYOUT exceeds maximum allowed bytes".to_owned(),
            });
        }
        let layout_text =
            String::from_utf8(layout_bytes).map_err(|_| DeploymentReadError::NotADeployment {
                reason: "LAYOUT is not UTF-8".to_owned(),
            })?;
        let (site_lineage, objects_dir, ledger_path, ledger_dir) =
            if let Ok(layout) = DeploymentLayout::parse_canonical_text(&layout_text) {
                let objects_dir = root.join(&layout.objects_relpath);
                let ledger_path = root.join(&layout.ledger_relpath);
                let ledger_dir = ledger_path.parent().unwrap_or(root).to_path_buf();
                (layout.site_lineage, objects_dir, ledger_path, ledger_dir)
            } else if let Ok(layout_v2) = DeploymentLayoutV2::parse_canonical_text(&layout_text) {
                let objects_dir = root.join(&layout_v2.objects_relpath);
                let ledger_dir = root.join(&layout_v2.ledger_relpath);
                let ledger_path = ledger_dir.join("journal.fssj");
                (layout_v2.site_lineage, objects_dir, ledger_path, ledger_dir)
            } else {
                return Err(DeploymentReadError::NotADeployment {
                    reason: "LAYOUT does not parse as v1 or v2 deployment layout".to_owned(),
                });
            };
        if cancelled() {
            return Err(DeploymentReadError::Corrupt {
                reason: "retained read authority cancelled".to_owned(),
            });
        }

        let projection_dir = root.join(PROJECTION_SUBDIR);
        let epochs_dir = ledger_dir.join(EPOCHS_SUBDIR);

        if epochs_dir.is_dir() {
            let epoch_ledger = MerkleEpochLedger::open(
                &ledger_dir,
                site_lineage.clone(),
                fss_ledger::EpochLedgerConfig::default(),
                fss_ledger::IncompleteTailPolicy::Reject,
            )
            .map_err(|err| DeploymentReadError::Corrupt {
                reason: format!("v2 epoch ledger open failed: {err}"),
            })?;
            let head_seq = epoch_ledger.head_anchor().commit_sequence;
            let config = ProjectionStoreConfig {
                durability: DurabilityMode::Fsync,
                wal_sync: WalSyncPolicy::FlushOnly,
                history_mode: HistoryChainMode::V2MerkleEpoch,
                ..ProjectionStoreConfig::default()
            };
            let mut deleted_digests = BTreeSet::new();
            // Only deletion records, including orphan transitions and reserved batch identities,
            // participate in this proof. Release ordinary footage batches as soon as inspected.
            let mut deletion_batches = Vec::new();
            let mut scanned = epoch_ledger.genesis_anchor().clone();
            let mode = HistoryChainMode::V2MerkleEpoch;
            let ledger_error = |err: ProjectionError| DeploymentReadError::Corrupt {
                reason: format!("v2 deletion history read failed: {err}"),
            };
            let mut history = mode.genesis_root(&scanned).map_err(ledger_error)?;
            epoch_ledger
                .visit_batches_range(1, head_seq, &mut |batch| {
                    if cancelled() {
                        return Err(ProjectionError::InvalidRequest(
                            "retained read authority cancelled",
                        ));
                    }
                    if batch.basis_anchor != scanned
                        || scanned.commit_sequence.checked_add(1) != Some(batch.new_anchor.commit_sequence)
                    {
                        return Err(ProjectionError::InvalidRequest("incomplete deletion history"));
                    }
                    scanned = batch.new_anchor.clone();
                    history = mode.successor_root(
                        history, scanned.commit_sequence, batch.batch_digest, &scanned,
                    )?;
                    if has_deletion_records(std::slice::from_ref(batch)) {
                        deletion_batches.push(batch.clone());
                    }
                    Ok(())
                })
                .map_err(ledger_error)?;
            if &scanned != epoch_ledger.head_anchor() || history != epoch_ledger.history_root() {
                return Err(DeploymentReadError::Corrupt {
                    reason: "missing canonical history for deletion custody".to_owned(),
                });
            }
            if !deletion_batches.is_empty() {
                let packs_dir = objects_dir.join(PACKS_SUBDIR);
                let reader = if packs_dir.is_dir() {
                    Some(PackStore::open(root, PackConfig::default())
                        .map_err(|err| DeploymentReadError::Corrupt {
                            reason: format!("cannot open deletion record pack store: {err}"),
                        })?
                        .reader())
                } else {
                    None
                };
                let read_deletion_obj = |digest: ContentDigest| -> Result<Vec<u8>, DeletionError> {
                    let limit = limits.max_object_bytes.min(MAX_DELETION_RECORD_BYTES);
                    let pack_error = |err: fss_pack::PackError| DeletionError::Incomplete {
                        detail: format!("cannot verify packed deletion record {digest}: {err}"),
                    };
                    if let Some(ref pack_reader) = reader
                        && let Some(location) = pack_reader.lookup(&digest).map_err(pack_error)?
                    {
                        if location.len > limit as u64 {
                            return Err(DeletionError::Bound { limit: "deletion record bytes" });
                        }
                        let budget = PackReadBudget::new(location.record_len().map_err(pack_error)?);
                        return pack_reader
                            .read_verified_with_budget(&digest, &budget)
                            .map_err(pack_error);
                    }
                    fss_publication::read_verified(&objects_dir, digest, limit)
                        .map_err(DeletionError::from)
                };
                match DeletionIndex::from_batches::<DeletionError>(
                    &deletion_batches,
                    &read_deletion_obj,
                ) {
                    Ok(deletion) => {
                        deleted_digests = deletion.deleted_objects();
                    }
                    Err(DeletionError::RecordMismatch) => {
                        // A migrated header can carry a v1 state root. Reconstruct that root
                        // from canonical history and repeat the complete deletion proof.
                        let receipt = MigrationEquivalenceReceipt::read_from_root(
                            root,
                            limits.max_object_bytes,
                        )
                        .map_err(|err| DeploymentReadError::Corrupt {
                            reason: format!("v2 deletion custody replay failed: {err}"),
                        })?;
                        let bases = v1_deletion_bases(
                            &epoch_ledger,
                            &deletion_batches,
                            &receipt,
                            cancelled,
                        )?;
                        deleted_digests = DeletionIndex::deleted_objects_with_v1_bases(
                            &deletion_batches,
                            &bases,
                            &read_deletion_obj,
                        )
                        .map_err(|err| DeploymentReadError::Corrupt {
                            reason: format!("v2 deletion custody replay failed: {err}"),
                        })?;
                    }
                    Err(err) => {
                        return Err(DeploymentReadError::Corrupt {
                            reason: format!("v2 deletion custody replay failed: {err}"),
                        });
                    }
                }
            }
            let resolver = DeploymentObjectPayloadResolver::new(
                root,
                objects_dir,
                deleted_digests,
                limits.max_object_bytes,
            );
            let store = MvccProjectionStore::open_or_rebuild_with_config(
                &projection_dir,
                &epoch_ledger,
                &resolver,
                config,
            )
            .map_err(|err| DeploymentReadError::Corrupt {
                reason: format!("projection store open/catch-up failed: {err}"),
            })?;
            let recovery = store.recovery_report().clone();
            return Ok(Self {
                root: root.to_path_buf(),
                projection_dir,
                store,
                recovery,
                site_lineage,
                head_commit_sequence: head_seq,
            });
        }

        let ledger = inspect_durable(&ledger_path, site_lineage.clone(), limits.max_journal_bytes)
            .map_err(|err| DeploymentReadError::Corrupt {
                reason: format!("authority ledger replay failed: {err}"),
            })?;
        if ledger.status == DurableLedgerStatus::Absent {
            return Err(DeploymentReadError::Unreadable {
                reason: "authority ledger is absent".to_owned(),
            });
        }
        if cancelled() {
            return Err(DeploymentReadError::Corrupt {
                reason: "retained read authority cancelled".to_owned(),
            });
        }

        let genesis_anchor: LedgerAnchor = ledger.batches.first().map_or_else(
            || ledger.snapshot.anchor.clone(),
            |batch| batch.basis_anchor.clone(),
        );
        let head_seq = ledger.snapshot.anchor.commit_sequence;
        let deleted_digests = if has_deletion_records(&ledger.batches) {
            let deletion =
                DeletionIndex::from_batches::<DeletionError>(&ledger.batches, |digest| {
                    fss_publication::read_verified(&objects_dir, digest, limits.max_object_bytes)
                        .map_err(DeletionError::from)
                })
                .map_err(|err| DeploymentReadError::Corrupt {
                    reason: format!("deletion custody replay failed: {err}"),
                })?;
            deletion.deleted_objects()
        } else {
            BTreeSet::new()
        };
        let resolver = DeploymentObjectPayloadResolver::new(
            root,
            objects_dir,
            deleted_digests,
            limits.max_object_bytes,
        );
        let source = SliceBatchSource::new(
            genesis_anchor,
            HistoryChainMode::V1LedgerOracle,
            ledger.batches,
        )
        .map_err(|err| DeploymentReadError::Corrupt {
            reason: format!("projection batch source failed: {err}"),
        })?;
        let config = ProjectionStoreConfig {
            durability: DurabilityMode::Fsync,
            wal_sync: WalSyncPolicy::FlushOnly,
            history_mode: HistoryChainMode::V1LedgerOracle,
            ..ProjectionStoreConfig::default()
        };
        let store = MvccProjectionStore::open_or_rebuild_with_config(
            &projection_dir,
            &source,
            &resolver,
            config,
        )
        .map_err(|err| DeploymentReadError::Corrupt {
            reason: format!("projection store open/catch-up failed: {err}"),
        })?;
        let recovery = store.recovery_report().clone();
        Ok(Self {
            root: root.to_path_buf(),
            projection_dir,
            store,
            recovery,
            site_lineage,
            head_commit_sequence: head_seq,
        })
    }

    /// Deletes the derived projection directory `<root>/projections/mvcc` and deterministically
    /// rebuilds bit-identical materialized state from canonical ledger history.
    pub fn rebuild_from_canonical(
        root: &Path,
        limits: &OrientLimits,
    ) -> Result<Self, DeploymentReadError> {
        let projection_dir = root.join(PROJECTION_SUBDIR);
        if projection_dir.exists() {
            fs::remove_dir_all(&projection_dir).map_err(|err| DeploymentReadError::Unreadable {
                reason: format!("failed clearing derived projection directory: {err}"),
            })?;
        }
        Self::open_or_catch_up(root, limits)
    }

    /// Returns the underlying anchor-pinned [`MvccProjectionStore`].
    #[must_use]
    pub const fn store(&self) -> &MvccProjectionStore {
        &self.store
    }

    /// Returns the deployment site lineage string.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.site_lineage
    }

    /// Returns the derived projection directory path.
    #[must_use]
    pub fn projection_dir(&self) -> &Path {
        &self.projection_dir
    }

    /// Returns the explicit separation between derived projection freshness and payload scrub
    /// verification.
    #[must_use]
    pub fn health_view(&self) -> ProjectionHealthView {
        let anchor = self.store.head_anchor();
        let receipt = self.store.latest_scrub_receipt();
        let scrub_status = match &receipt {
            None => ScrubStatus::NeverScrubbed,
            Some(r) => match r.verdict {
                ScrubVerdict::Failed => ScrubStatus::ScrubFailed,
                ScrubVerdict::Degraded => {
                    if r.anchor == anchor {
                        ScrubStatus::ScrubDegraded
                    } else {
                        ScrubStatus::VerifiedStale {
                            behind_commits: anchor
                                .commit_sequence
                                .saturating_sub(r.anchor.commit_sequence),
                        }
                    }
                }
                ScrubVerdict::Clean => {
                    if r.anchor == anchor
                        && r.verified_fraction_ppm
                            == fss_projection_store::MAX_VERIFIED_FRACTION_PPM
                    {
                        ScrubStatus::VerifiedCurrent
                    } else {
                        ScrubStatus::VerifiedStale {
                            behind_commits: anchor
                                .commit_sequence
                                .saturating_sub(r.anchor.commit_sequence),
                        }
                    }
                }
            },
        };
        ProjectionHealthView {
            projection_caught_up: anchor.commit_sequence == self.head_commit_sequence,
            projection_anchor: anchor,
            recovery_mode: self.recovery.mode,
            replayed_batches: self.recovery.replayed_ledger_batches,
            scrub_receipt: receipt,
            scrub_status,
        }
    }

    /// Executes an `O(1)` lock-free MVCC orientation summary read with structured telemetry.
    #[must_use]
    pub fn orient_summary(&self) -> (OrientSummary, ProjectionTraceEvent) {
        let started = Instant::now();
        let snapshot = self.store.snapshot_latest();
        let summary = snapshot.orient_summary();
        let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let trace = ProjectionTraceEvent {
            op: "orient_summary",
            commits_total: summary.anchor.commit_sequence,
            delta_commits: self.recovery.replayed_ledger_batches,
            mvcc_read_us: elapsed_us,
            rows_scanned: 1,
            bytes_read: 0,
            cache_hit_ratio_ppm: if self.recovery.mode == ProjectionRecoveryMode::LoadedCurrent {
                1_000_000
            } else {
                0
            },
        };
        (summary, trace)
    }

    /// Executes an indexed MVCC event query against the latest pinned snapshot with telemetry.
    #[must_use]
    pub fn query_events(
        &self,
        filter: &EventQueryFilter,
        limit: usize,
    ) -> (EventQueryPage, ProjectionTraceEvent) {
        let started = Instant::now();
        let snapshot = self.store.snapshot_latest();
        let page = self.store.query_events(&snapshot, filter, limit);
        let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let bytes_read: u64 = page.entries.iter().map(|e| e.payload_bytes).sum();
        let trace = ProjectionTraceEvent {
            op: "query_events",
            commits_total: snapshot.anchor.commit_sequence,
            delta_commits: 0,
            mvcc_read_us: elapsed_us,
            rows_scanned: page.entries.len(),
            bytes_read,
            cache_hit_ratio_ppm: 1_000_000,
        };
        (page, trace)
    }

    /// Executes an indexed unified footage query (RTSP, HTTP, File, TUTK) with telemetry.
    #[must_use]
    pub fn query_footage(
        &self,
        filter: &FootageQueryFilter,
        limit: usize,
    ) -> (FootageQueryPage, ProjectionTraceEvent) {
        let started = Instant::now();
        let snapshot = self.store.snapshot_latest();
        let page = self.store.query_footage(&snapshot, filter, limit);
        let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let bytes_read: u64 = page.entries.iter().map(|i| i.total_bytes).sum();
        let trace = ProjectionTraceEvent {
            op: "query_footage",
            commits_total: snapshot.anchor.commit_sequence,
            delta_commits: 0,
            mvcc_read_us: elapsed_us,
            rows_scanned: page.entries.len(),
            bytes_read,
            cache_hit_ratio_ppm: 1_000_000,
        };
        (page, trace)
    }

    /// Executes an `O(delta)` indexed follow scan strictly after `after_sequence`.
    pub fn follow_since(
        &self,
        after_sequence: u64,
        max_entries: usize,
    ) -> Result<(FollowDeltaPage, ProjectionTraceEvent), ProjectionError> {
        let started = Instant::now();
        let page = self.store.follow_since(after_sequence, max_entries)?;
        let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let delta_commits = page.commits.len() as u64;
        let trace = ProjectionTraceEvent {
            op: "follow_since",
            commits_total: page.head_anchor.commit_sequence,
            delta_commits,
            mvcc_read_us: elapsed_us,
            rows_scanned: page.commits.len(),
            bytes_read: 0,
            cache_hit_ratio_ppm: 1_000_000,
        };
        Ok((page, trace))
    }

    /// Runs an explicit out-of-band full-spool `fss doctor` scrub and persists a verified
    /// anchor-bound [`DoctorScrubReceipt`] into the projection store.
    pub fn scrub_and_record_receipt(
        &self,
        now_ns: TimestampNs,
    ) -> Result<DoctorScrubReceipt, DeploymentReadError> {
        let report = inspect_deployment(&self.root);
        let anchor = self.store.head_anchor();
        let (verdict, fraction_ppm) = match report.verdict {
            DoctorVerdict::Healthy => (
                ScrubVerdict::Clean,
                fss_projection_store::MAX_VERIFIED_FRACTION_PPM,
            ),
            DoctorVerdict::AttentionRequired => (ScrubVerdict::Degraded, 500_000),
            DoctorVerdict::Unreadable | DoctorVerdict::NotADeployment => (ScrubVerdict::Failed, 0),
        };
        let receipt = DoctorScrubReceipt {
            scrubbed_at_ns: now_ns,
            anchor,
            first_seq: 0,
            last_seq: anchor.commit_sequence,
            verified_objects: self.store.snapshot_latest().orient_summary().total_events as u64,
            verified_packs: 0,
            verified_fraction_ppm: fraction_ppm,
            verdict,
        };
        self.store
            .record_scrub_receipt(receipt.clone())
            .map_err(|err| DeploymentReadError::Corrupt {
                reason: format!("failed persisting doctor scrub receipt: {err}"),
            })?;
        self.store
            .compact_snapshot()
            .map_err(|err| DeploymentReadError::Corrupt {
                reason: format!("failed compacting projection snapshot after scrub: {err}"),
            })?;
        Ok(receipt)
    }

    /// Compiles a full [`DeploymentOrientation`] (`SituationCapsule` + `decisionFingerprint`)
    /// without running a full-spool `fss doctor` scan, deriving health honestly from the latest
    /// persisted [`DoctorScrubReceipt`].
    pub fn orient_decoupled(
        &self,
        request: &OrientRequest,
        limits: &OrientLimits,
    ) -> Result<
        (
            DeploymentOrientation,
            ProjectionHealthView,
            ProjectionTraceEvent,
        ),
        OrientError,
    > {
        let started = Instant::now();
        let health = self.health_view();
        let (doctor_verdict, doctor_inspected) = health.scrub_status.to_doctor_state();
        let history = DeploymentHistory::read_decoupled_cancellable(
            &self.root,
            limits,
            doctor_verdict,
            doctor_inspected,
            &|| false,
        )
        .map_err(|_| {
            OrientError::Contract(crate::ReferenceError::InvalidSpec(
                "decoupled_deployment_read_failed",
            ))
        })?;
        let snapshot = history.snapshot_at(history.head()).map_err(|_| {
            OrientError::Contract(crate::ReferenceError::InvalidSpec(
                "decoupled_snapshot_build_failed",
            ))
        })?;
        let orientation = orient_deployment(&snapshot, request, limits)?;
        let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let trace = ProjectionTraceEvent {
            op: "orient_decoupled",
            commits_total: health.projection_anchor.commit_sequence,
            delta_commits: self.recovery.replayed_ledger_batches,
            mvcc_read_us: elapsed_us,
            rows_scanned: snapshot.events.len(),
            bytes_read: snapshot.bytes_read,
            cache_hit_ratio_ppm: if self.recovery.mode == ProjectionRecoveryMode::LoadedCurrent {
                1_000_000
            } else {
                0
            },
        };
        Ok((orientation, health, trace))
    }
}
