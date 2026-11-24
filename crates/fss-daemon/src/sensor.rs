#![forbid(unsafe_code)]
//! Single-session camera drivers, deterministic jittered exponential backoff, and network adapter
//! supervision for `SensorRegion`.
//!
//! Semantic plane: `"authority"`.

use std::sync::Arc;

use fss_core::{CanonicalEncoder, ContentDigest, SensorId, StreamId};
use fss_pack::MediaCodec;
use fss_reference::ingest::model_pool::FramePixelInput;
use fss_reference::ingest::osd_mask::ImageRect;

use crate::manifest::{CameraAdapterKind, CameraManifestEntry};
use crate::ring::RingMetered;
pub use crate::sensor_network::NetworkAdapterDriver;
pub use crate::sensor_synthetic::{
    SyntheticCameraControl, SyntheticCameraDriver, SyntheticFrameSpec,
};

/// Canonical digest domain for deterministic reconnect backoff jitter.
pub const DAEMON_BACKOFF_JITTER_DOMAIN: &str = "fss.daemon.backoff_jitter.v1";

/// Optional synthetic detection proposal attached to a lab/CI synthetic camera frame.
#[derive(Clone, Debug, PartialEq)]
pub struct SyntheticDetectionHint {
    /// Proposed class label (e.g., `"person"`).
    pub class_label: String,
    /// Uncalibrated score in parts per million (`0..=1_000_000`).
    pub score_ppm: u32,
    /// Optional image-space foot-point `[u, v]` for ground-plane homography matching.
    pub foot_px: Option<[f64; 2]>,
    /// Logical zone identifier override (`None` uses the camera's primary zone).
    pub zone_id: Option<String>,
    /// Camera-local track identifier (`>= 1`).
    pub track_id: u64,
}

/// Immutable source-bound camera frame shared zero-copy across ring consumers.
#[derive(Clone, Debug)]
pub struct CameraFrame {
    /// Originating camera sensor identifier.
    pub sensor_id: SensorId,
    /// Monotonic stream generation ordinal (`1`-based; increments on every reconnect).
    pub stream_generation: u64,
    /// Logical stream identifier bound to `stream_generation`.
    pub stream_id: StreamId,
    /// Per-generation strictly increasing frame sequence (`1`-based).
    pub sequence: u64,
    /// Camera media clock (RTP/PTS) timestamp in nanoseconds.
    pub media_pts_ns: i128,
    /// Host receive timestamp in nanoseconds.
    pub host_receive_ns: i128,
    /// Bounded network + pipeline RTT/jitter envelope in nanoseconds.
    pub rtt_jitter_ns: u64,
    /// Bounded host node clock uncertainty in nanoseconds.
    pub node_clock_uncertainty_ns: u64,
    /// Encoded video codec for `FSMC` media chunk custody.
    pub codec: MediaCodec,
    /// True if this frame is a random-access keyframe (IDR/IRAP/intra JPEG).
    pub is_keyframe: bool,
    /// True if an upstream continuity gap occurred immediately before this frame.
    pub discontinuity_before: bool,
    /// Decoded dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Raw encoded access-unit bytes retained in `FSMC` custody.
    pub encoded_payload: Vec<u8>,
    /// Decoded pixel buffer untouched by OSD motion masking.
    pub pixels: FramePixelInput,
    /// Exact SHA-256 digest of `encoded_payload`.
    pub source_digest: ContentDigest,
    /// Primary spatial zone observed by this camera.
    pub zone_id: String,
    /// Optional deterministic detection hints for synthetic replay frames.
    pub synthetic_detections: Vec<SyntheticDetectionHint>,
}

impl RingMetered for CameraFrame {
    fn ring_bytes(&self) -> usize {
        self.encoded_payload
            .len()
            .saturating_add(self.pixels.as_bytes().len())
            .saturating_add(128)
    }

    fn frame_sequence(&self) -> u64 {
        self.sequence
    }
}

/// Typed cause of an upstream camera session drop or fault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensorDisconnectReason {
    /// Underlying TCP/UDP/P2P transport dropped or peer refused connection.
    NetworkDrop,
    /// Camera authentication failed (vault secret rejected or expired).
    AuthFailure,
    /// Device firmware or codec parameter generation changed mid-stream.
    FirmwareChanged,
    /// Upstream camera stopped delivering packets beyond `stall_timeout_ms`.
    StalledPackets,
    /// Operator explicitly stopped the camera via bounded IPC control.
    OperatorStopped,
    /// Adapter-specific non-secret transport failure.
    DriverError(String),
}

impl SensorDisconnectReason {
    /// Returns a stable non-secret label for telemetry, coverage witnesses, and logs.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::NetworkDrop => "network_drop",
            Self::AuthFailure => "auth_failure",
            Self::FirmwareChanged => "firmware_changed",
            Self::StalledPackets => "stalled_packets",
            Self::OperatorStopped => "operator_stopped",
            Self::DriverError(_) => "driver_error",
        }
    }
}

/// Outcome returned by one non-blocking [`SensorDriver::poll_frame`] step.
#[derive(Clone, Debug)]
pub enum SensorDriverEvent {
    /// One new frame arrived from the active upstream session.
    Frame(Arc<CameraFrame>),
    /// Session is healthy, but no new frame arrived on this poll.
    Idle,
    /// Upstream session dropped or faulted; supervisor must emit an explicit `CoverageGap`.
    Disconnected(SensorDisconnectReason),
}

/// Lifecycle state of one supervised camera inside `fss-daemon`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorState {
    /// Connecting initial upstream session.
    Connecting,
    /// Single upstream session active and delivering frames.
    Streaming,
    /// Disconnected with explicit `not_observable` coverage gap; waiting for backoff window.
    GapBackoff,
    /// Explicitly stopped by operator bounded control.
    Stopped,
    /// Draining during daemon shutdown.
    Draining,
}

impl SensorState {
    /// Returns the canonical lowercase telemetry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Streaming => "streaming",
            Self::GapBackoff => "gap_backoff",
            Self::Stopped => "stopped",
            Self::Draining => "draining",
        }
    }
}

/// Single-upstream-session camera acquisition driver interface.
pub trait SensorDriver: Send {
    /// Opens the camera's single upstream session for `generation`.
    fn connect(&mut self, generation: u64) -> Result<(), SensorDisconnectReason>;
    /// Polls one frame or disconnect transition from the active upstream session.
    fn poll_frame(&mut self, now_ns: i128) -> SensorDriverEvent;
    /// Closes the active upstream session cleanly.
    fn disconnect(&mut self);
    /// Returns the current active upstream session count (MUST ALWAYS be `0` or `1`).
    fn active_session_count(&self) -> u32;
    /// Returns cumulative upstream connections opened across all generations.
    fn total_connections(&self) -> u64;
    /// Returns the camera adapter kind served by this driver.
    fn adapter_kind(&self) -> CameraAdapterKind;
    /// Propagates hot-reloaded manifest configuration (`primary_zone`, `auth_realm`, RTSP options)
    /// into the live driver so subsequent frames and reconnects use the updated parameters.
    fn update_manifest_entry(&mut self, _entry: &CameraManifestEntry) {}
}

/// Deterministic jittered exponential reconnect backoff bounded inside `[min_ms, max_ms]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackoffSchedule {
    sensor_id: String,
    min_ms: u64,
    max_ms: u64,
    attempt: u32,
}

impl BackoffSchedule {
    /// Constructs a validated deterministic backoff schedule.
    #[must_use]
    pub fn new(sensor_id: impl Into<String>, min_ms: u64, max_ms: u64) -> Self {
        let lo = min_ms.max(1);
        let hi = max_ms.max(lo);
        Self {
            sensor_id: sensor_id.into(),
            min_ms: lo,
            max_ms: hi,
            attempt: 0,
        }
    }

    /// Computes the next deterministic jittered delay in milliseconds and advances `attempt`.
    pub fn next_delay_ms(&mut self) -> u64 {
        let shift = self.attempt.min(30);
        let exp = self.min_ms.saturating_mul(1_u64 << shift).min(self.max_ms);
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(DAEMON_BACKOFF_JITTER_DOMAIN);
        enc.text(&self.sensor_id);
        enc.u32(self.attempt);
        let digest = ContentDigest::sha256(&enc.finish());
        let raw = u16::from_be_bytes([digest.bytes()[0], digest.bytes()[1]]);
        let jitter_span = (exp / 5).max(1);
        let offset = u64::from(raw) % (jitter_span.saturating_mul(2).saturating_add(1));
        let jittered = exp
            .saturating_sub(jitter_span)
            .saturating_add(offset)
            .clamp(self.min_ms, self.max_ms);
        self.attempt = self.attempt.saturating_add(1);
        jittered
    }

    /// Resets the backoff exponent after a healthy session recovers.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Returns the number of consecutive failed reconnect attempts.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// Builds the default single-session [`SensorDriver`] for a manifest camera entry.
#[must_use]
pub fn default_driver_for_camera(entry: &CameraManifestEntry) -> Box<dyn SensorDriver> {
    match entry.adapter {
        CameraAdapterKind::Synthetic => {
            let ctrl = SyntheticCameraControl::new(entry.sensor_id.clone());
            Box::new(SyntheticCameraDriver::new(entry, ctrl))
        }
        CameraAdapterKind::Rtsp
        | CameraAdapterKind::Tutk
        | CameraAdapterKind::UniFiProtect
        | CameraAdapterKind::OnvifHttp => Box::new(NetworkAdapterDriver::new(entry)),
    }
}

/// Draws a filled axis-aligned rectangle onto a row-major 8-bit luma plane.
pub fn draw_rect_luma(buf: &mut [u8], dims: [u32; 2], rect: ImageRect, val: u8) {
    let w = dims[0] as usize;
    let h = dims[1] as usize;
    let x0 = (rect.x as usize).min(w);
    let y0 = (rect.y as usize).min(h);
    let x1 = (rect.x as usize).saturating_add(rect.width as usize).min(w);
    let y1 = (rect.y as usize)
        .saturating_add(rect.height as usize)
        .min(h);
    for y in y0..y1 {
        let row = y.saturating_mul(w);
        if let Some(slice) = buf.get_mut(row + x0..row + x1) {
            slice.fill(val);
        }
    }
}

pub(crate) fn sanitize_stream_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(32));
    for ch in raw.chars().take(32) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "cam".to_owned()
    } else {
        out
    }
}

pub(crate) fn unreachable_stream_id() -> StreamId {
    loop {
        if let Ok(id) = StreamId::parse("stream:default") {
            return id;
        }
    }
}
