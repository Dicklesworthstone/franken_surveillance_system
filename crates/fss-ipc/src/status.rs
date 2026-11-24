#![forbid(unsafe_code)]
//! Live daemon telemetry status types with deterministic canonical encoding (zero Serde).

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, ErrorId,
};

/// Maximum camera status rows permitted inside one [`LiveDaemonStatus`] response.
pub const MAX_CAMERAS_IN_STATUS: usize = 1024;

/// Maximum length of a camera identifier on the wire.
pub const MAX_CAMERA_ID_BYTES: usize = 128;

/// Live per-camera telemetry reported in [`LiveDaemonStatus`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraLiveStatus {
    /// Stable configured camera identifier.
    pub camera_id: String,
    /// Whether the camera worker is actively running.
    pub running: bool,
    /// Observed ingest frame rate in milli-FPS (e.g., `30_000` = `30.000 FPS`).
    pub fps_milli: u32,
    /// Cumulative reconnect count since daemon start.
    pub reconnect_count: u64,
    /// Current pending frame/packet queue depth.
    pub queue_depth: u32,
    /// Cumulative frames ingested since daemon start.
    pub frames_ingested: u64,
}

impl CanonicalEncode for CameraLiveStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.camera_id);
        encoder.bool(self.running);
        encoder.u32(self.fps_milli);
        encoder.u64(self.reconnect_count);
        encoder.u32(self.queue_depth);
        encoder.u64(self.frames_ingested);
    }
}

impl CanonicalDecode for CameraLiveStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let camera_id = decoder.text()?.to_owned();
        if camera_id.is_empty() || camera_id.len() > MAX_CAMERA_ID_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            camera_id,
            running: decoder.bool()?,
            fps_milli: decoder.u32()?,
            reconnect_count: decoder.u64()?,
            queue_depth: decoder.u32()?,
            frames_ingested: decoder.u64()?,
        })
    }
}

/// Local ring-buffer storage watermark reported in [`LiveDaemonStatus`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingWatermarkStatus {
    /// Bytes currently occupied in the retention ring.
    pub used_bytes: u64,
    /// Configured capacity of the retention ring in bytes.
    pub capacity_bytes: u64,
    /// Integer occupancy percentage clamped to `0..=100`.
    pub watermark_percent: u8,
}

impl CanonicalEncode for RingWatermarkStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.used_bytes);
        encoder.u64(self.capacity_bytes);
        encoder.u8(self.watermark_percent);
    }
}

impl CanonicalDecode for RingWatermarkStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let used_bytes = decoder.u64()?;
        let capacity_bytes = decoder.u64()?;
        let watermark_percent = decoder.u8()?;
        if watermark_percent > 100 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            used_bytes,
            capacity_bytes,
            watermark_percent,
        })
    }
}

/// Active storage-integrity scrub status reported by the local daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveScrubStatus {
    /// No scrub is running.
    Idle,
    /// A scrub pass is actively verifying objects.
    Running {
        /// Number of objects verified so far.
        checked_objects: u64,
        /// Total objects scheduled in this scrub pass.
        total_objects: u64,
    },
    /// The latest scrub pass completed.
    Completed {
        /// Total objects verified.
        checked_objects: u64,
        /// Total integrity anomalies observed.
        anomalies_found: u64,
    },
    /// The latest scrub pass failed with a stable error identifier.
    Failed {
        /// Stable failure error identity.
        error_id: ErrorId,
    },
}

impl CanonicalEncode for ActiveScrubStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Idle => encoder.tag(1),
            Self::Running {
                checked_objects,
                total_objects,
            } => {
                encoder.tag(2);
                encoder.u64(*checked_objects);
                encoder.u64(*total_objects);
            }
            Self::Completed {
                checked_objects,
                anomalies_found,
            } => {
                encoder.tag(3);
                encoder.u64(*checked_objects);
                encoder.u64(*anomalies_found);
            }
            Self::Failed { error_id } => {
                encoder.tag(4);
                error_id.encode_canonical(encoder);
            }
        }
    }
}

impl CanonicalDecode for ActiveScrubStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => Ok(Self::Idle),
            2 => Ok(Self::Running {
                checked_objects: decoder.u64()?,
                total_objects: decoder.u64()?,
            }),
            3 => Ok(Self::Completed {
                checked_objects: decoder.u64()?,
                anomalies_found: decoder.u64()?,
            }),
            4 => Ok(Self::Failed {
                error_id: ErrorId::decode_canonical(decoder)?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Structured live status snapshot returned for `IpcRequest::QueryLiveStatus`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveDaemonStatus {
    /// Correlated client request identifier.
    pub request_id: u64,
    /// Daemon process uptime in milliseconds.
    pub daemon_uptime_ms: u64,
    /// Current authoritative ledger head commit sequence.
    pub head_commit_sequence: u64,
    /// Current authoritative history root digest.
    pub history_root: ContentDigest,
    /// Current authoritative state root digest.
    pub state_root: ContentDigest,
    /// Active authenticated IPC client connections.
    pub active_connections: u32,
    /// Optional per-camera live telemetry (populated when `include_cameras == true`).
    pub cameras: Vec<CameraLiveStatus>,
    /// Optional retention ring watermark (populated when `include_ring == true`).
    pub ring: Option<RingWatermarkStatus>,
    /// Current storage scrub status.
    pub scrub: ActiveScrubStatus,
}

impl CanonicalEncode for LiveDaemonStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.request_id);
        encoder.u64(self.daemon_uptime_ms);
        encoder.u64(self.head_commit_sequence);
        encoder.digest(self.history_root);
        encoder.digest(self.state_root);
        encoder.u32(self.active_connections);
        encoder.u32(self.cameras.len() as u32);
        for cam in &self.cameras {
            cam.encode_canonical(encoder);
        }
        match &self.ring {
            Some(ring) => {
                encoder.bool(true);
                ring.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.scrub.encode_canonical(encoder);
    }
}

impl CanonicalDecode for LiveDaemonStatus {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let request_id = decoder.u64()?;
        let daemon_uptime_ms = decoder.u64()?;
        let head_commit_sequence = decoder.u64()?;
        let history_root = decoder.digest()?;
        let state_root = decoder.digest()?;
        let active_connections = decoder.u32()?;
        let cam_count = decoder.u32()? as usize;
        if cam_count > MAX_CAMERAS_IN_STATUS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut cameras = Vec::with_capacity(cam_count);
        for _ in 0..cam_count {
            cameras.push(CameraLiveStatus::decode_canonical(decoder)?);
        }
        let ring = if decoder.bool()? {
            Some(RingWatermarkStatus::decode_canonical(decoder)?)
        } else {
            None
        };
        let scrub = ActiveScrubStatus::decode_canonical(decoder)?;
        Ok(Self {
            request_id,
            daemon_uptime_ms,
            head_commit_sequence,
            history_root,
            state_root,
            active_connections,
            cameras,
            ring,
            scrub,
        })
    }
}
