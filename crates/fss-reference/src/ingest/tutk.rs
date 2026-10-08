//! Owner-authorized TUTK/IOTC NEW-protocol (magic `0xCC51`) live adapter.
//!
//! Maps the sans-IO `fss-tutk` session onto FSS packet truth per the
//! comprehensive plan §8.4/§8.5: an acquisition lifecycle
//! (`Requested → Authenticated → AdapterAccepted → FirstFrameObserved →
//! ContinuityVerified`, with Degraded/Failed/Cancelled/Indeterminate
//! branches), source-byte custody capsules (`SensorCapsule` per reassembled
//! access unit, codec passthrough — never transcoded), per-frame timing and
//! continuity on the capsule itself, and `EvidenceDelta` batches committed to
//! a `ReferenceLedger`. Audio is privacy-gated: never requested and always
//! dropped unless explicitly enabled.
//!
//! Sans-IO like the session beneath it: the owner pumps datagrams and time
//! in and takes datagrams out. Payload custody (access-unit bytes and
//! canonical capsule encodings) lives in a digest-keyed store the owner can
//! spill to durable publication; batch children pin exactly those digests.

use std::collections::BTreeMap;

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CapsuleId, CaptureInterval, ClockBasis,
    ContentDigest, ContractError, EvidenceDelta, ObjectId, Plane, ReferenceLedger, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectManifest};
use fss_tutk::session::{
    AssembledFrame, PhaseName, SessionConfig, SessionEvent, SessionStats, TutkSession,
};

use super::file_adapter::{FileImportManifest, SegmentSpan};
use super::file_publication::FilePublicationPlan;
use crate::{ReferenceDeployment, ReplayCx};

/// Uniform custody chunk size for the acquisition seal (1 MiB).
pub const SEAL_CHUNK_BYTES: u64 = 1024 * 1024;
/// Maximum sealed input size (bound on the one-pass concatenation).
pub const SEAL_MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;

/// Audio capture policy (privacy default: disabled — video only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AudioPolicy {
    /// Never request audio; drop any audio packets the camera sends anyway.
    #[default]
    Disabled,
    /// Request and retain audio.
    Enabled,
}

/// Adapter limits (all bounded, all explicit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TutkIngestLimits {
    /// Max deltas per committed batch.
    pub max_batch_deltas: usize,
    /// Consecutive gapless frames before ContinuityVerified.
    pub continuity_window: u32,
}

impl Default for TutkIngestLimits {
    fn default() -> Self {
        Self {
            max_batch_deltas: 64,
            continuity_window: 8,
        }
    }
}

/// Acquisition lifecycle state (plan §8.5) with transition witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquisitionState {
    /// Stream requested; session in flight.
    Requested,
    /// K-command challenge-response accepted by the camera; witness is the
    /// digest of the exact K10003 payload bytes (the auth receipt).
    Authenticated { auth_receipt: ContentDigest },
    /// Camera accepted the stream start (K10011); witness is the digest of
    /// the exact K10011 payload bytes (the adapter ACK).
    AdapterAccepted { accept_digest: ContentDigest },
    /// First source-linked frame reassembled; witness is its capsule id.
    FirstFrameObserved { capsule_id: CapsuleId },
    /// `window_frames` consecutive frames arrived without a continuity gap.
    ContinuityVerified { window_frames: u32 },
    /// Running with explicit degradation (drops, resyncs, evictions).
    Degraded { reason: String },
    /// Terminal failure with a concrete reason.
    Failed { reason: String },
    /// Cancelled by the owner.
    Cancelled,
    /// Timeout after dispatch; outcome unknown until readback (plan §8.6).
    Indeterminate { reason: String },
}


/// Adapter errors (typed, non-secret-bearing).
#[derive(Debug)]
pub enum TutkIngestError {
    /// Session construction refused (bad uid/enr/mac shape).
    SessionConfig,
    /// fss-core contract violation.
    Contract(ContractError),
    /// Acquisition seal failure (typed, non-secret-bearing detail).
    Seal(String),
}

impl core::fmt::Display for TutkIngestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TutkIngestError::SessionConfig => write!(f, "invalid session configuration"),
            TutkIngestError::Contract(e) => write!(f, "contract error: {e}"),
            TutkIngestError::Seal(detail) => write!(f, "seal error: {detail}"),
        }
    }
}

impl std::error::Error for TutkIngestError {}

impl From<ContractError> for TutkIngestError {
    fn from(e: ContractError) -> Self {
        TutkIngestError::Contract(e)
    }
}

/// Adapter configuration.
#[derive(Debug, Clone)]
pub struct TutkIngestConfig {
    /// Underlying session configuration (uid/enr/mac/seed).
    pub session: SessionConfig,
    /// Sensor identity stamped on every capsule.
    pub sensor_id: SensorId,
    /// Stream generation identity stamped on every capsule.
    pub stream_id: StreamId,
    /// Site lineage for the reference ledger.
    pub site_lineage: String,
    /// Audio policy (drives the session request and the drop gate).
    pub audio: AudioPolicy,
    /// Adapter limits.
    pub limits: TutkIngestLimits,
    /// Known-good `(model, firmware)` compatibility tuples (plan §8.8);
    /// forwarded to the session, which fails closed on anything else.
    pub known_tuples: Vec<(String, String)>,
}

/// Monotone adapter counters (drops always visible).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestStats {
    pub capsules_committed: u64,
    pub batches_committed: u64,
    pub gaps: u64,
    pub degraded_transitions: u64,
}

/// The TUTK live adapter: session → custody capsules → ledger batches.
pub struct TutkIngest {
    session: TutkSession,
    audio: AudioPolicy,
    limits: TutkIngestLimits,
    sensor_id: SensorId,
    stream_id: StreamId,
    state: AcquisitionState,
    ledger: ReferenceLedger,
    custody: BTreeMap<ContentDigest, Vec<u8>>,
    pending: Vec<(EvidenceDelta, ContentDigest)>,
    acquisition_hex: String,
    acquisition_identity: ContentDigest,
    capsule_seq: u64,
    batch_seq: u64,
    consecutive_gapless: u32,
    last_session_stats: SessionStats,
    stats: IngestStats,
    failed: bool,
    au_records: Vec<AuRecord>,
    codec_format: Option<String>,
    sealed: Option<AcquisitionSeal>,
}

/// One accumulated access unit for the acquisition seal.
struct AuRecord {
    digest: ContentDigest,
    len: u64,
    capture: CaptureInterval,
    keyframe: bool,
    gap_before: bool,
    capsule_id: CapsuleId,
}

/// Receipt of a sealed acquisition: the file-import-shaped custody contract
/// downstream tooling (`RetainedFileImport`, recorded decode, watch) opens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionSeal {
    /// Import identity (the acquisition digest).
    pub import_identity: ContentDigest,
    /// Digest of the FileImportManifest bytes.
    pub manifest_digest: ContentDigest,
    /// Published fi- slot root.
    pub import_root: ContentDigest,
    /// The committed manifest batch.
    pub manifest_batch: BatchId,
    /// Capsules sealed.
    pub capsule_count: usize,
    /// Total sealed media bytes.
    pub input_bytes: u64,
}

impl TutkIngest {
    /// Construct the adapter and queue the first discovery request.
    pub fn new(mut cfg: TutkIngestConfig) -> Result<Self, TutkIngestError> {
        cfg.session.audio = matches!(cfg.audio, AudioPolicy::Enabled);
        cfg.session.known_tuples = cfg.known_tuples.clone();
        let session = TutkSession::new(cfg.session.clone()).ok_or(TutkIngestError::SessionConfig)?;
        let sid = session.session_id();
        let mut id_material = b"tutk-acquisition".to_vec();
        id_material.extend_from_slice(cfg.session.uid.as_bytes());
        id_material.extend_from_slice(&sid);
        let acquisition_identity = ContentDigest::sha256(&id_material);
        let acquisition_hex: String = acquisition_identity
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let ledger = ReferenceLedger::new(cfg.site_lineage.clone());
        Ok(Self {
            session,
            audio: cfg.audio,
            limits: cfg.limits,
            sensor_id: cfg.sensor_id,
            stream_id: cfg.stream_id,
            state: AcquisitionState::Requested,
            ledger,
            custody: BTreeMap::new(),
            pending: Vec::new(),
            acquisition_hex,
            acquisition_identity,
            capsule_seq: 0,
            batch_seq: 0,
            consecutive_gapless: 0,
            last_session_stats: SessionStats::default(),
            stats: IngestStats::default(),
            failed: false,
            au_records: Vec::new(),
            codec_format: None,
            sealed: None,
        })
    }

    /// Current acquisition state.
    #[must_use]
    pub fn state(&self) -> &AcquisitionState {
        &self.state
    }

    /// The reference ledger (batches accumulate as frames commit).
    #[must_use]
    pub fn ledger(&self) -> &ReferenceLedger {
        &self.ledger
    }

    /// Payload custody bytes by digest (AU bytes and capsule encodings).
    #[must_use]
    pub fn custody(&self, digest: &ContentDigest) -> Option<&[u8]> {
        self.custody.get(digest).map(Vec::as_slice)
    }

    /// Monotone adapter counters.
    #[must_use]
    pub fn stats(&self) -> IngestStats {
        self.stats
    }

    /// Session phase (discovery/dtls/login/kauth/stream-start/streaming).
    #[must_use]
    pub fn session_phase(&self) -> PhaseName {
        self.session.phase()
    }

    /// Take the next datagram to send to the camera.
    pub fn poll_send(&mut self) -> Option<Vec<u8>> {
        self.session.poll_send()
    }

    /// Feed one received datagram (caller-owned IO), then pump events.
    pub fn feed_datagram(&mut self, data: &[u8], now_ns: u64) {
        self.session.feed_datagram(data, now_ns);
        self.pump(now_ns);
    }

    /// Session-level monotone counters (video frames, audio drops, gaps).
    #[must_use]
    pub fn session_stats(&self) -> SessionStats {
        self.session.stats()
    }
    pub fn advance(&mut self, now_ns: u64) {
        self.session.advance(now_ns);
        self.pump(now_ns);
    }

    /// Cancel the acquisition (owner intent; plan §8.5 Cancelled branch).
    pub fn cancel(&mut self) {
        self.session.close();
        self.state = AcquisitionState::Cancelled;
    }

    /// Drain session events into state transitions, capsules, and batches.
    pub fn pump(&mut self, now_ns: u64) {
        while let Some(ev) = self.session.poll_event() {
            self.handle_event(ev, now_ns);
        }
        self.note_degradation();
    }

    /// Commit any pending capsule deltas as a final batch.
    pub fn flush(&mut self) -> Result<(), TutkIngestError> {
        self.commit_pending()
    }

    /// Seal the acquisition into the durable deployment as a decodable
    /// file-import-shaped custody contract (RetainedFileImport-compatible):
    /// stage every custody payload, commit the capsule batches, publish the
    /// fi- slot root, and commit the manifest batch that moves the import to
    /// generation 2 (complete). The input is the exact received AU byte
    /// stream — truthful live acquisition, never a fabricated file.
    pub fn seal_acquisition(
        &mut self,
        deployment: &mut ReferenceDeployment,
        adapter_generation: &str,
        cx: &ReplayCx,
    ) -> Result<AcquisitionSeal, TutkIngestError> {
        if let Some(seal) = &self.sealed {
            return Ok(seal.clone());
        }
        if self.au_records.is_empty() {
            return Err(TutkIngestError::Seal(
                "no frames observed; nothing to seal".to_string(),
            ));
        }
        self.flush()?;

        let import_identity = self.acquisition_identity;
        let hex: String = import_identity
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        // Input = the exact received AU stream, concatenated once (bounded).
        let total: u64 = self.au_records.iter().map(|au| au.len).sum();
        if total > SEAL_MAX_INPUT_BYTES {
            return Err(TutkIngestError::Seal(format!(
                "acquisition exceeds seal bound ({total} > {SEAL_MAX_INPUT_BYTES} bytes)"
            )));
        }
        let mut stream = Vec::with_capacity(total as usize);
        for au in &self.au_records {
            let bytes = self.custody.get(&au.digest).ok_or_else(|| {
                TutkIngestError::Seal(format!("custody missing AU {}", au.digest))
            })?;
            stream.extend_from_slice(bytes);
        }
        let input_bytes = stream.len() as u64;
        let input_sha256 = ContentDigest::sha256(&stream);
        // Uniform custody chunks of the stream (the file-import contract);
        // segment spans reference byte ranges inside it.
        let chunk_size = SEAL_CHUNK_BYTES as usize;
        let mut ordered_chunks = Vec::new();
        let mut chunk_slices: Vec<(ContentDigest, &[u8])> = Vec::new();
        for chunk in stream.chunks(chunk_size) {
            let digest = ContentDigest::sha256(chunk);
            ordered_chunks.push(digest);
            chunk_slices.push((digest, chunk));
        }

        let mut dedup = ordered_chunks.clone();
        dedup.sort();
        dedup.dedup();
        let custody_manifest = ObjectManifest::new("custody", dedup, None)
            .map_err(|e| TutkIngestError::Seal(format!("custody manifest: {e}")))?;
        let custody_manifest_bytes = custody_manifest.canonical_bytes();
        let custody_manifest_digest = ContentDigest::sha256(&custody_manifest_bytes);

        // Segment spans: one per AU, covering every input byte exactly once.
        let mut spans = Vec::with_capacity(self.au_records.len());
        let mut offset = 0u64;
        for (index, au) in self.au_records.iter().enumerate() {
            spans.push(SegmentSpan {
                segment_index: index,
                offset,
                len: au.len,
                segment_sha256: au.digest,
                capsule_id: au.capsule_id.clone(),
                gap_before: au.gap_before,
            });
            offset += au.len;
        }

        let capsule_ids: Vec<CapsuleId> =
            self.au_records.iter().map(|au| au.capsule_id.clone()).collect();
        let limits_digest = self.limits_digest();
        let mut import_manifest = FileImportManifest {
            input_sha256,
            input_bytes,
            format: self
                .codec_format
                .clone()
                .unwrap_or_else(|| "annexb".to_string()),
            detector_evidence: "tutk_newprotocol_live_acquisition:session_port_adopted".to_string(),
            chunk_bytes: SEAL_CHUNK_BYTES,
            ordered_chunks: ordered_chunks.clone(),
            segment_spans: spans,
            omission_spans: Vec::new(),
            capsule_ids,
            limits_digest,
            adapter_id: "ADP-WYZE-V4-LAB-001".to_string(),
            adapter_generation: adapter_generation.to_string(),
            part_roots: Vec::new(),
            capture_time_label: "unknown".to_string(),
        };

        let closure_bound = deployment
            .limits()
            .manifest_children_max
            .min(deployment.limits().batch_entries_max)
            .min(MAX_MANIFEST_CHILDREN);
        let encoding_digests: Vec<ContentDigest> = self
            .ledger
            .batches()
            .iter()
            .flat_map(|b| {
                b.deltas
                    .iter()
                    .filter_map(|d| (d.family == "sensor_capsule").then_some(d.payload_digest))
            })
            .collect();
        let publication = FilePublicationPlan::new(
            import_identity,
            ordered_chunks
                .iter()
                .copied()
                .chain(std::iter::once(custody_manifest_digest))
                .chain(encoding_digests.iter().copied()),
            closure_bound,
        )
        .map_err(|e| TutkIngestError::Seal(format!("publication plan: {e}")))?;
        import_manifest.part_roots = publication.part_roots();
        let slot_manifest = publication
            .root_manifest(&import_manifest)
            .map_err(|e| TutkIngestError::Seal(format!("slot manifest: {e}")))?;
        let manifest_bytes = import_manifest.canonical_bytes();
        let manifest_digest = import_manifest.canonical_digest();

        // Stage every custody payload and verify before any publish.
        for (_, slice) in &chunk_slices {
            deployment
                .publisher_mut()
                .stage_object(slice)
                .map_err(|e| TutkIngestError::Seal(format!("stage chunk: {e}")))?;
        }
        for au in &self.au_records {
            let bytes = self.custody.get(&au.digest).expect("checked above");
            deployment
                .publisher_mut()
                .stage_object(bytes)
                .map_err(|e| TutkIngestError::Seal(format!("stage AU: {e}")))?;
        }
        deployment
            .publisher_mut()
            .stage_object(&custody_manifest_bytes)
            .map_err(|e| TutkIngestError::Seal(format!("stage custody manifest: {e}")))?;
        for digest in &encoding_digests {
            let bytes = self.custody.get(digest).ok_or_else(|| {
                TutkIngestError::Seal(format!("custody missing encoding {digest}"))
            })?;
            deployment
                .publisher_mut()
                .stage_object(bytes)
                .map_err(|e| TutkIngestError::Seal(format!("stage encoding: {e}")))?;
        }
        deployment
            .publisher_mut()
            .stage_object(&manifest_bytes)
            .map_err(|e| TutkIngestError::Seal(format!("stage manifest: {e}")))?;
        for (digest, _) in &chunk_slices {
            deployment
                .publisher_mut()
                .verify_object(*digest)
                .map_err(|e| TutkIngestError::Seal(format!("verify chunk: {e}")))?;
        }
        for au in &self.au_records {
            deployment
                .publisher_mut()
                .verify_object(au.digest)
                .map_err(|e| TutkIngestError::Seal(format!("verify AU: {e}")))?;
        }
        deployment
            .publisher_mut()
            .verify_object(custody_manifest_digest)
            .map_err(|e| TutkIngestError::Seal(format!("verify custody manifest: {e}")))?;
        deployment
            .publisher_mut()
            .verify_object(manifest_digest)
            .map_err(|e| TutkIngestError::Seal(format!("verify manifest: {e}")))?;
        for digest in &encoding_digests {
            deployment
                .publisher_mut()
                .verify_object(*digest)
                .map_err(|e| TutkIngestError::Seal(format!("verify encoding: {e}")))?;
        }

        // Commit the capsule batches (idempotent per batch identity).
        for batch in self.ledger.batches().to_vec() {
            deployment
                .append_batch(
                    batch.batch_id.clone(),
                    batch.deltas.clone(),
                    batch.children.clone(),
                    cx,
                )
                .map_err(|e| TutkIngestError::Seal(format!("append capsule batch: {e}")))?;
        }

        let overall_validity = {
            let first = self.au_records.first().expect("nonempty");
            let last = self.au_records.last().expect("nonempty");
            CaptureInterval::new(first.capture.earliest, last.capture.latest)
                .map_err(TutkIngestError::Contract)?
        };
        // Manifest completion: init batch (gen 1), then manifest batch
        // (gen 1->2 complete + manifest gen 1) — the durable ledger admits one
        // transition per object per batch.
        let import_object_id = ObjectId::parse(format!("object:file-import:{hex}"))
            .map_err(TutkIngestError::Contract)?;
        let manifest_object_id = ObjectId::parse(format!("object:file-import-manifest:{hex}"))
            .map_err(TutkIngestError::Contract)?;
        deployment
            .append_batch(
                BatchId::parse(format!("batch:file-import:{hex}:c{}", self.ledger.batches().len()))
                    .map_err(TutkIngestError::Contract)?,
                vec![EvidenceDelta {
                    delta_id: format!("delta:file-import:{hex}:init"),
                    family: "file_import".to_string(),
                    object_id: import_object_id.clone(),
                    prior_generation: None,
                    new_generation: 1,
                    validity: overall_validity,
                    plane: Plane::Authority,
                    payload_digest: custody_manifest_digest,
                    witness_digest: None,
                    operation_id: None,
                }],
                vec![custody_manifest_digest],
                cx,
            )
            .map_err(|e| TutkIngestError::Seal(format!("append init batch: {e}")))?;

        // Publish the fi- slot root (root-last).
        let import_root = deployment
            .publisher_mut()
            .stage_manifest(publication.slot(), &slot_manifest)
            .map_err(|e| TutkIngestError::Seal(format!("stage slot manifest: {e}")))?;
        if publication.parts().is_empty() {
            deployment
                .publish_and_commit(publication.slot(), &slot_manifest, overall_validity, cx)
                .map_err(|e| TutkIngestError::Seal(format!("publish root: {e}")))?;
        } else {
            publication
                .publish(deployment, &import_manifest, overall_validity, cx)
                .map_err(|e| TutkIngestError::Seal(format!("publish parts: {e}")))?;
        }

        let deltas = vec![
            EvidenceDelta {
                delta_id: format!("delta:file-import:{hex}:complete"),
                family: "file_import".to_string(),
                object_id: import_object_id,
                prior_generation: Some(1),
                new_generation: 2,
                validity: overall_validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(import_root),
                operation_id: None,
            },
            EvidenceDelta {
                delta_id: format!("delta:manifest:{hex}"),
                family: "file_import_manifest".to_string(),
                object_id: manifest_object_id,
                prior_generation: None,
                new_generation: 1,
                validity: overall_validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(import_root),
                operation_id: None,
            },
        ];
        let manifest_batch = BatchId::parse(format!("batch:file-import:{hex}:manifest"))
            .map_err(TutkIngestError::Contract)?;
        deployment
            .append_batch(
                manifest_batch.clone(),
                deltas,
                vec![manifest_digest, import_root],
                cx,
            )
            .map_err(|e| TutkIngestError::Seal(format!("append manifest batch: {e}")))?;

        let seal = AcquisitionSeal {
            import_identity,
            manifest_digest,
            import_root,
            manifest_batch,
            capsule_count: self.au_records.len(),
            input_bytes,
        };
        self.sealed = Some(seal.clone());
        Ok(seal)
    }

    /// Canonical digest of the adapter limits applied to this acquisition.
    fn limits_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.tutk_ingest.limits.v1");
        encoder.u64(self.limits.max_batch_deltas as u64);
        encoder.u32(self.limits.continuity_window);
        ContentDigest::sha256(&encoder.finish())
    }

    fn handle_event(&mut self, ev: SessionEvent, now_ns: u64) {
        if self.failed {
            return;
        }
        match ev {
            SessionEvent::DiscoveryComplete { .. } | SessionEvent::DtlsEstablished => {}
            SessionEvent::LoginAccepted { .. } => {}
            SessionEvent::KAuthComplete { camera_info } => {
                let auth_receipt = ContentDigest::sha256(camera_info.as_bytes());
                self.state = AcquisitionState::Authenticated { auth_receipt };
            }
            SessionEvent::StreamStarted { payload } => {
                // Plan §8.5: the adapter-acceptance witness is the digest of
                // the camera's exact K10011 acceptance payload bytes.
                let accept_digest = ContentDigest::sha256(&payload);
                self.state = AcquisitionState::AdapterAccepted { accept_digest };
            }
            SessionEvent::Frame(frame) => {
                if let Err(e) = self.record_frame(frame, now_ns) {
                    self.state = AcquisitionState::Failed {
                        reason: e.to_string(),
                    };
                    self.failed = true;
                }
            }
            SessionEvent::LoginRejected { response_type } => {
                self.state = AcquisitionState::Failed {
                    reason: format!("camera rejected AV login (type 0x{response_type:02x})"),
                };
                self.failed = true;
            }
            SessionEvent::KAuthRejected { connection_res } => {
                self.state = AcquisitionState::Failed {
                    reason: format!("k-auth refused (connectionRes={connection_res})"),
                };
                self.failed = true;
            }
            SessionEvent::KAuthQuarantined {
                model,
                firmware,
                detail,
            } => {
                // Plan §8.8: unknown tuples fail closed. Terminal, witnessed,
                // and no stream was ever started.
                self.state = AcquisitionState::Failed {
                    reason: format!(
                        "firmware-drift quarantine: model={model} firmware={firmware} ({detail})"
                    ),
                };
                self.failed = true;
            }
            SessionEvent::Failed { stage, reason } => {
                // Plan §8.6: a timeout after dispatch is indeterminate until
                // readback; all other stage failures are terminal failures.
                if stage == "stream-start" && reason.contains("deadline") {
                    self.state = AcquisitionState::Indeterminate {
                        reason: format!("{stage}: {reason}"),
                    };
                } else {
                    self.state = AcquisitionState::Failed {
                        reason: format!("{stage}: {reason}"),
                    };
                }
                self.failed = true;
                let _ = self.commit_pending();
            }
        }
    }

    fn record_frame(&mut self, frame: AssembledFrame, _now_ns: u64) -> Result<(), TutkIngestError> {
        let seq = self.capsule_seq;
        let capsule_id = CapsuleId::parse(format!(
            "capsule:tutk:{}:{:06}",
            self.acquisition_hex, seq
        ))?;
        let capture = CaptureInterval {
            earliest: TimestampNs(frame.first_recv_ns as i128),
            latest: TimestampNs(frame.last_recv_ns as i128),
        };
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: capsule_id.clone(),
            sensor_id: self.sensor_id.clone(),
            stream_id: self.stream_id.clone(),
            sequence: seq,
            capture,
            receive_time: TimestampNs(frame.last_recv_ns as i128),
            clock_basis: ClockBasis::HostMonotonic,
            source: &frame.au,
            frame_count: 1,
            gap_before: frame.gap_before,
        })?;
        self.capsule_seq += 1;
        if self.codec_format.is_none() {
            self.codec_format = frame.info.as_ref().map(|fi| match fi.codec {
                fss_tutk::av::Codec::Hevc => "hevc".to_string(),
                _ => "annexb".to_string(),
            });
        }
        self.au_records.push(AuRecord {
            digest: capsule.source_digest,
            len: frame.au.len() as u64,
            capture: capsule.capture,
            keyframe: frame.info.as_ref().is_some_and(|fi| fi.is_keyframe),
            gap_before: frame.gap_before,
            capsule_id: capsule.capsule_id.clone(),
        });

        // Custody: AU source bytes + canonical capsule encoding, digest-pinned.
        let au_digest = capsule.source_digest;
        self.custody.entry(au_digest).or_insert_with(|| frame.au.clone());
        let mut encoder = CanonicalEncoder::new();
        capsule.encode_canonical(&mut encoder);
        let encoding = encoder.finish();
        let encoding_digest = ContentDigest::sha256(&encoding);
        self.custody.entry(encoding_digest).or_insert(encoding);

        let delta = EvidenceDelta {
            delta_id: format!("delta:capsule:{}", capsule.capsule_id.as_str()),
            family: "sensor_capsule".to_string(),
            object_id: ObjectId::parse(format!(
                "object:capsule:{}",
                capsule.capsule_id.as_str()
            ))?,
            prior_generation: None,
            new_generation: 1,
            validity: capsule.capture,
            plane: Plane::Authority,
            payload_digest: encoding_digest,
            witness_digest: Some(au_digest),
            operation_id: None,
        };
        self.pending.push((delta, encoding_digest));

        // Lifecycle transitions with witnesses.
        self.state = match &self.state {
            AcquisitionState::AdapterAccepted { .. }
            | AcquisitionState::Authenticated { .. }
            | AcquisitionState::Requested => AcquisitionState::FirstFrameObserved {
                capsule_id: capsule_id.clone(),
            },
            s => s.clone(),
        };
        if frame.gap_before {
            self.consecutive_gapless = 0;
            self.stats.gaps += 1;
        } else {
            self.consecutive_gapless += 1;
            if matches!(
                self.state,
                AcquisitionState::FirstFrameObserved { .. } | AcquisitionState::Degraded { .. }
            ) && self.consecutive_gapless >= self.limits.continuity_window
            {
                self.state = AcquisitionState::ContinuityVerified {
                    window_frames: self.consecutive_gapless,
                };
            }
        }
        if self.pending.len() >= self.limits.max_batch_deltas {
            self.commit_pending()?;
        }
        Ok(())
    }

    fn commit_pending(&mut self) -> Result<(), TutkIngestError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let batch_id = BatchId::parse(format!(
            "batch:file-import:{}:c{}",
            self.acquisition_hex, self.batch_seq
        ))?;
        self.batch_seq += 1;
        let entries = std::mem::take(&mut self.pending);
        let batch = self.ledger.prepare_batch(
            batch_id,
            entries.iter().map(|(d, _)| d.clone()).collect(),
            entries.iter().map(|(_, c)| *c),
        )?;
        self.ledger.append(batch)?;
        self.stats.batches_committed += 1;
        self.stats.capsules_committed += entries.len() as u64;
        Ok(())
    }

    fn note_degradation(&mut self) {
        let s = self.session.stats();
        let fresh_resync = s.resync_bytes > self.last_session_stats.resync_bytes;
        let fresh_evict = s.pending_frames_dropped > self.last_session_stats.pending_frames_dropped;
        let fresh_drop = s.events_dropped > self.last_session_stats.events_dropped;
        self.last_session_stats = s;
        if (fresh_resync || fresh_evict || fresh_drop)
            && matches!(
                self.state,
                AcquisitionState::FirstFrameObserved { .. }
                    | AcquisitionState::ContinuityVerified { .. }
            )
        {
            let reason = if fresh_evict {
                "reassembly eviction under memory bound"
            } else if fresh_drop {
                "event queue backpressure drop"
            } else {
                "stream resync after undecodable bytes"
            };
            self.state = AcquisitionState::Degraded {
                reason: reason.to_string(),
            };
            self.stats.degraded_transitions += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(audio: AudioPolicy) -> TutkIngestConfig {
        TutkIngestConfig {
            session: SessionConfig {
                uid: "SIMCAMSIMCAMSIMCAM11".to_string(),
                enr: "sim-enr-16byte!!".to_string(),
                mac: "00AA11BB22CC".to_string(),
                audio: matches!(audio, AudioPolicy::Enabled),
                psk_truncated: false,
                seed: 42,
                known_tuples: vec![("SIM-CAM".to_string(), "9.99.0.SIM".to_string())],
            },
            sensor_id: SensorId::parse("sensor:tutk:sim:01").unwrap(),
            stream_id: StreamId::parse("stream:tutk:sim:01").unwrap(),
            site_lineage: "site:lab:tutk".to_string(),
            audio,
            limits: TutkIngestLimits::default(),
            known_tuples: vec![("SIM-CAM".to_string(), "9.99.0.SIM".to_string())],
        }
    }
    #[test]
    fn quarantine_is_terminal_with_tuple_witness() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.handle_event(
            SessionEvent::KAuthQuarantined {
                model: "HL_CAM4".into(),
                firmware: "9.99.9.UNKNOWN".into(),
                detail: "tuple not in owner allowlist".into(),
            },
            10,
        );
        match ing.state() {
            AcquisitionState::Failed { reason } => {
                assert!(reason.contains("quarantine"), "reason: {reason}");
                assert!(reason.contains("9.99.9.UNKNOWN"), "reason: {reason}");
            }
            s => panic!("expected Failed, got {s:?}"),
        }
        assert_eq!(ing.stats().capsules_committed, 0);
    }


    #[test]
    fn constructs_and_queues_discovery() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        assert!(matches!(ing.state(), AcquisitionState::Requested));
        assert!(matches!(ing.session_phase(), PhaseName::Discovery));
        let first = ing.poll_send().expect("discovery packet queued");
        assert_eq!(&first[0..2], &0xCC51u16.to_le_bytes());
        assert!(ing.poll_send().is_none());
    }

    #[test]
    fn cancel_is_terminal_and_honest() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.cancel();
        assert!(matches!(ing.state(), AcquisitionState::Cancelled));
    }
    fn frame(seq_no: u32, au: &[u8], first: u64, last: u64, gap: bool) -> AssembledFrame {
        AssembledFrame {
            channel: 0x05,
            frame_no: seq_no,
            au: au.to_vec(),
            info: None,
            first_recv_ns: first,
            last_recv_ns: last,
            packets: 2,
            gap_before: gap,
        }
    }

    fn sealed_ingest(frames: u32) -> TutkIngest {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.handle_event(
            SessionEvent::KAuthComplete {
                camera_info: r#"{"connectionRes":"1"}"#.to_string(),
            },
            1_000,
        );
        ing.handle_event(
            SessionEvent::StreamStarted {
                payload: b"k10011".to_vec(),
            },
            1_100,
        );
        for i in 0..frames {
            let au: Vec<u8> = (0..32 + i as usize).map(|b| (b * 7 + i as usize) as u8).collect();
            ing.handle_event(
                SessionEvent::Frame(frame(i, &au, 2_000 + i as u64 * 33, 2_010 + i as u64 * 33, false)),
                2_010 + i as u64 * 33,
            );
        }
        ing
    }

    fn test_cx(root: &std::path::Path) -> ReplayCx {
        let authority = fss_core::region::ContextAuthority::new_root(
            fss_core::region::RootAuthoritySpec {
                trace_id: "trace:tutk-seal-test".to_owned(),
                operation_id: fss_core::OperationId::parse("operation:tutk-seal-test").unwrap(),
                principal: "principal:tutk-seal-test".to_owned(),
                capabilities: vec!["ADP-REPLAY-001".to_owned()],
                deadline: None,
                priority: 10,
                budgets: fss_core::BudgetVector::builder()
                    .bytes(64 * 1024 * 1024)
                    .storage_operations(4096)
                    .build()
                    .unwrap(),
                privacy_scope: "privacy:test".to_owned(),
                retention_scope: "retention:test".to_owned(),
                anchor_universe: ContentDigest::sha256(b"site:tutk-seal-test"),
                generation: 1,
            },
        )
        .unwrap();
        ReplayCx::from_context_authority(&authority, root).unwrap()
    }

    #[test]
    fn seal_produces_retained_openable_import() {
        let dir = std::env::temp_dir().join(format!("fss-tutk-seal-{}", std::process::id()));
        let root = dir.join("deployment");
        std::fs::create_dir_all(&root).unwrap();
        let cx = test_cx(&root);
        let mut deployment =
            ReferenceDeployment::open(&root, "site:tutk-seal-test", &cx).unwrap();
        let mut ing = sealed_ingest(6);
        let seal = ing
            .seal_acquisition(&mut deployment, "SIM-CAM/9.99.0.SIM", &cx)
            .unwrap();
        assert_eq!(seal.capsule_count, 6);
        assert!(seal.input_bytes > 0);

        // The sealed acquisition opens exactly like a file import.
        let retained = crate::ingest::retained::RetainedFileImport::open(
            &deployment,
            seal.import_identity,
            crate::ingest::retained::RetainedReadLimits::default(),
            &cx,
        );
        assert!(retained.is_ok(), "retained open failed: {:?}", retained.err());

        // Segment spans cover every input byte exactly once.
        let manifest = retained.unwrap().manifest().clone();
        assert_eq!(manifest.input_bytes, seal.input_bytes);
        let mut covered = 0u64;
        for (i, span) in manifest.segment_spans.iter().enumerate() {
            assert_eq!(span.segment_index, i);
            assert_eq!(span.offset, covered);
            covered += span.len;
        }
        assert_eq!(covered, manifest.input_bytes);
        assert_eq!(manifest.capsule_ids.len(), 6);
        assert_eq!(manifest.adapter_id, "ADP-WYZE-V4-LAB-001");
        assert!(matches!(manifest.format.as_str(), "annexb" | "hevc"));

        // Seal is idempotent.
        let again = ing
            .seal_acquisition(&mut deployment, "SIM-CAM/9.99.0.SIM", &cx)
            .unwrap();
        assert_eq!(seal, again);
    }
    #[test]
    fn seal_refuses_empty_acquisition() {
        let dir = std::env::temp_dir().join(format!("fss-tutk-seal-empty-{}", std::process::id()));
        let root = dir.join("deployment");
        std::fs::create_dir_all(&root).unwrap();
        let cx = test_cx(&root);
        let mut deployment =
            ReferenceDeployment::open(&root, "site:tutk-seal-test", &cx).unwrap();
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        let e = ing
            .seal_acquisition(&mut deployment, "SIM-CAM/9.99.0.SIM", &cx)
            .unwrap_err();
        assert!(matches!(e, TutkIngestError::Seal(_)), "{e:?}");
    }

    #[test]
    fn lifecycle_reaches_continuity_verified_with_witnesses() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.handle_event(
            SessionEvent::KAuthComplete {
                camera_info: r#"{"connectionRes":"1"}"#.to_string(),
            },
            1_000,
        );
        let auth = match ing.state() {
            AcquisitionState::Authenticated { auth_receipt } => *auth_receipt,
            s => panic!("expected Authenticated, got {s:?}"),
        };
        assert_eq!(auth, ContentDigest::sha256(br#"{"connectionRes":"1"}"#));
        ing.handle_event(
            SessionEvent::StreamStarted {
                payload: b"k10011-ack".to_vec(),
            },
            1_100,
        );
        assert!(matches!(
            ing.state(),
            AcquisitionState::AdapterAccepted { .. }
        ));
        for i in 0..8u32 {
            ing.handle_event(
                SessionEvent::Frame(frame(i, &[0xAA; 64], 2_000 + i as u64 * 33, 2_010 + i as u64 * 33, false)),
                2_010 + i as u64 * 33,
            );
        }
        assert!(
            matches!(ing.state(), AcquisitionState::ContinuityVerified { window_frames: 8 }),
            "state: {:?}",
            ing.state()
        );
        ing.flush().unwrap();
        let batches = ing.ledger().batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].deltas.len(), 8);
        assert!(batches[0]
            .deltas
            .iter()
            .all(|d| d.family == "sensor_capsule" && d.plane == Plane::Authority));
        assert!(batches[0].is_canonically_ordered());
        let first_delta = &batches[0].deltas[0];
        let au_digest = first_delta.witness_digest.expect("au witness digest");
        assert_eq!(ing.custody(&au_digest).unwrap(), &[0xAA; 64]);
        assert!(ing.custody(&first_delta.payload_digest).is_some());
        assert_eq!(ing.stats().capsules_committed, 8);
    }

    #[test]
    fn gap_resets_window_and_marks_capsule() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        for i in 0..3u32 {
            ing.handle_event(
                SessionEvent::Frame(frame(i, &[1; 16], 100 * i as u64, 105 * i as u64 + 1, false)),
                100,
            );
        }
        ing.handle_event(
            SessionEvent::Frame(frame(3, &[2; 16], 400, 405, true)),
            405,
        );
        for i in 4..7u32 {
            ing.handle_event(
                SessionEvent::Frame(frame(i, &[3; 16], 100 * i as u64, 100 * i as u64 + 5, false)),
                100 * i as u64,
            );
        }
        assert!(matches!(
            ing.state(),
            AcquisitionState::FirstFrameObserved { .. }
        ));
        ing.flush().unwrap();
        let deltas = &ing.ledger().batches()[0].deltas;
        assert_eq!(deltas.len(), 7);
        assert_eq!(ing.stats().gaps, 1);
    }

    #[test]
    fn batches_split_at_limit_and_flush() {
        let mut c = cfg(AudioPolicy::Disabled);
        c.limits.max_batch_deltas = 2;
        let mut ing = TutkIngest::new(c).unwrap();
        for i in 0..3u32 {
            ing.handle_event(
                SessionEvent::Frame(frame(i, &[i as u8; 8], 10 * i as u64, 10 * i as u64 + 1, false)),
                10,
            );
        }
        assert_eq!(ing.ledger().batches().len(), 1, "first pair auto-commits");
        ing.flush().unwrap();
        let batches = ing.ledger().batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].deltas.len(), 2);
        assert_eq!(batches[1].deltas.len(), 1);
        assert_eq!(
            batches[1].basis_anchor.commit_sequence,
            batches[0].new_anchor.commit_sequence
        );
    }

    #[test]
    fn session_failure_is_terminal_and_flushes() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.handle_event(
            SessionEvent::Frame(frame(0, &[9; 8], 10, 11, false)),
            11,
        );
        ing.handle_event(
            SessionEvent::Failed {
                stage: "dtls",
                reason: "alert received".to_string(),
            },
            12,
        );
        assert!(matches!(ing.state(), AcquisitionState::Failed { .. }));
        assert_eq!(ing.ledger().batches().len(), 1, "pending flushed on failure");
    }

    #[test]
    fn post_dispatch_timeout_is_indeterminate() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.handle_event(
            SessionEvent::Failed {
                stage: "stream-start",
                reason: "phase deadline exceeded".to_string(),
            },
            12,
        );
        assert!(matches!(ing.state(), AcquisitionState::Indeterminate { .. }));
    }

    #[test]
    fn login_rejection_is_failure_with_type() {
        let mut ing = TutkIngest::new(cfg(AudioPolicy::Disabled)).unwrap();
        ing.handle_event(SessionEvent::LoginRejected { response_type: 0x20 }, 10);
        match ing.state() {
            AcquisitionState::Failed { reason } => assert!(reason.contains("0x20")),
            s => panic!("expected Failed, got {s:?}"),
        }
    }
}
