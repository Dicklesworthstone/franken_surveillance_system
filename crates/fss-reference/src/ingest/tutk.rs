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
use fss_tutk::session::{
    AssembledFrame, PhaseName, SessionConfig, SessionEvent, SessionStats, TutkSession,
};

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
}

/// Adapter errors (typed, non-secret-bearing).
#[derive(Debug)]
pub enum TutkIngestError {
    /// Session construction refused (bad uid/enr/mac shape).
    SessionConfig,
    /// fss-core contract violation.
    Contract(ContractError),
}

impl core::fmt::Display for TutkIngestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TutkIngestError::SessionConfig => write!(f, "invalid session configuration"),
            TutkIngestError::Contract(e) => write!(f, "contract error: {e}"),
        }
    }
}

impl std::error::Error for TutkIngestError {}

impl From<ContractError> for TutkIngestError {
    fn from(e: ContractError) -> Self {
        TutkIngestError::Contract(e)
    }
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
    capsule_seq: u64,
    batch_seq: u64,
    consecutive_gapless: u32,
    last_session_stats: SessionStats,
    stats: IngestStats,
    failed: bool,
}

impl TutkIngest {
    /// Construct the adapter and queue the first discovery request.
    pub fn new(mut cfg: TutkIngestConfig) -> Result<Self, TutkIngestError> {
        cfg.session.audio = matches!(cfg.audio, AudioPolicy::Enabled);
        let session = TutkSession::new(cfg.session.clone()).ok_or(TutkIngestError::SessionConfig)?;
        let sid = session.session_id();
        let mut id_material = b"tutk-acquisition".to_vec();
        id_material.extend_from_slice(cfg.session.uid.as_bytes());
        id_material.extend_from_slice(&sid);
        let acquisition_hex = ContentDigest::sha256(&id_material).to_string();
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
            capsule_seq: 0,
            batch_seq: 0,
            consecutive_gapless: 0,
            last_session_stats: SessionStats::default(),
            stats: IngestStats::default(),
            failed: false,
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
            "batch:tutk:{}:c{}",
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
            },
            sensor_id: SensorId::parse("sensor:tutk:sim:01").unwrap(),
            stream_id: StreamId::parse("stream:tutk:sim:01").unwrap(),
            site_lineage: "site:lab:tutk".to_string(),
            audio,
            limits: TutkIngestLimits::default(),
        }
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
