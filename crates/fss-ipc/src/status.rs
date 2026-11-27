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
    /// Recent ring admission rate in milli-FPS, over the last ten completed 100 ms
    /// host-receive-time buckets. Disconnected sources report zero.
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

/// The recorded capture window with the earliest capture end on one camera.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OldestRetentionWindow {
    /// Earliest capture time in nanoseconds on the recording's clock.
    pub capture_start_ns: i128,
    /// Latest capture time in nanoseconds on the recording's clock.
    pub capture_end_ns: i128,
    /// Capture end plus the effective retention duration, with saturating arithmetic.
    pub age_deadline_ns: i128,
    /// Whether the last assessment found a hold, event, obligation, or catalog pin.
    pub known_pin: bool,
}

/// Time-policy forecast for a single configured camera at the last storage assessment.
/// Capacity can reclaim an eligible recording earlier, while pins can defer reclamation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraRetentionForecast {
    /// Configured source identifier.
    pub camera_id: String,
    /// Daemon assessment time in nanoseconds.
    pub assessed_at_ns: i128,
    /// Effective duration used by the retention planner.
    pub retain_hot_ns: u64,
    /// Effective cap on this camera's accounted bytes.
    pub max_sensor_bytes: u64,
    /// Number of retained camera recording windows.
    pub retained_windows: u64,
    /// Accounted source media bytes in those windows.
    pub retained_bytes: u64,
    /// Oldest retained recording, absent when this camera has none.
    pub oldest: Option<OldestRetentionWindow>,
}

impl CanonicalEncode for CameraRetentionForecast {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.camera_id);
        encoder.i128(self.assessed_at_ns);
        encoder.u64(self.retain_hot_ns);
        encoder.u64(self.max_sensor_bytes);
        encoder.u64(self.retained_windows);
        encoder.u64(self.retained_bytes);
        encoder.bool(self.oldest.is_some());
        if let Some(window) = &self.oldest {
            encoder.i128(window.capture_start_ns);
            encoder.i128(window.capture_end_ns);
            encoder.i128(window.age_deadline_ns);
            encoder.bool(window.known_pin);
        }
    }
}

impl CanonicalDecode for CameraRetentionForecast {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let camera_id = decoder.text()?;
        if camera_id.is_empty() || camera_id.len() > MAX_CAMERA_ID_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        let camera_id = camera_id.to_owned();
        let assessed_at_ns = decoder.i128()?;
        let retain_hot_ns = decoder.u64()?;
        let max_sensor_bytes = decoder.u64()?;
        let retained_windows = decoder.u64()?;
        let retained_bytes = decoder.u64()?;
        let oldest = if decoder.bool()? {
            let window = OldestRetentionWindow {
                capture_start_ns: decoder.i128()?,
                capture_end_ns: decoder.i128()?,
                age_deadline_ns: decoder.i128()?,
                known_pin: decoder.bool()?,
            };
            if window.capture_start_ns > window.capture_end_ns
                || window.age_deadline_ns
                    != window
                        .capture_end_ns
                        .saturating_add(i128::from(retain_hot_ns))
            {
                return Err(ContractError::InvalidIdentifier);
            }
            Some(window)
        } else {
            None
        };
        if oldest.is_some() != (retained_windows > 0)
            || (retained_windows == 0 && retained_bytes != 0)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            camera_id,
            assessed_at_ns,
            retain_hot_ns,
            max_sensor_bytes,
            retained_windows,
            retained_bytes,
            oldest,
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
