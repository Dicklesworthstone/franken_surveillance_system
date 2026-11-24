#![forbid(unsafe_code)]
//! Deterministic in-process synthetic replay camera driver and fault-injection controller.
//!
//! Semantic plane: `"authority"`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_pack::MediaCodec;
use fss_reference::ingest::model_pool::FramePixelInput;
use fss_reference::ingest::osd_mask::ImageRect;

use crate::manifest::{CameraAdapterKind, CameraManifestEntry};
use crate::sensor::{
    CameraFrame, SensorDisconnectReason, SensorDriver, SensorDriverEvent, SyntheticDetectionHint,
    draw_rect_luma, sanitize_stream_segment, unreachable_stream_id,
};

/// Scripted action queued into a [`SyntheticCameraControl`] for deterministic fault/motion tests.
#[derive(Clone, Debug)]
pub enum SyntheticFrameSpec {
    /// Quiescent background frame (matches baseline luma `32`).
    Quiescent {
        /// Whether this frame is a codec keyframe.
        is_keyframe: bool,
    },
    /// Frame with pixel changes strictly inside `osd_rect` (tests OSD ignore masking).
    OsdOnlyTick {
        /// Rectangle modified inside the camera's OSD ignore zone.
        osd_rect: ImageRect,
        /// Pixel intensity toggled inside `osd_rect`.
        luma_value: u8,
        /// Whether this frame is a codec keyframe.
        is_keyframe: bool,
    },
    /// Active motion frame drawing a high-contrast rectangle outside OSD regions.
    MotionBurst {
        /// Foreground motion rectangle drawn onto the luma plane.
        motion_rect: ImageRect,
        /// Luma intensity drawn inside `motion_rect`.
        luma_value: u8,
        /// Optional extra payload bytes appended to exercise ring byte limits / pack rotation.
        extra_payload_bytes: usize,
        /// Whether this frame is a codec keyframe.
        is_keyframe: bool,
        /// Synthetic detection hints passed downstream if Stage-1 + Stage-2 admit this frame.
        detections: Vec<SyntheticDetectionHint>,
    },
    /// Emit an immediate upstream disconnect event on the next poll.
    Disconnect(SensorDisconnectReason),
    /// Produce `Idle` (no packets) to exercise stall timeout detection.
    Stall,
}

/// Thread-safe handle allowing tests and lab scenarios to control a [`SyntheticCameraDriver`].
#[derive(Debug)]
pub struct SyntheticCameraControl {
    sensor_id: SensorId,
    offline: AtomicBool,
    offline_reason: Mutex<SensorDisconnectReason>,
    active_sessions: AtomicU32,
    peak_sessions: AtomicU32,
    total_connections: AtomicU64,
    current_generation: AtomicU64,
    queue: Mutex<VecDeque<SyntheticFrameSpec>>,
    default_extra_payload_bytes: AtomicU64,
}

impl SyntheticCameraControl {
    /// Creates a new online synthetic camera controller.
    #[must_use]
    pub fn new(sensor_id: SensorId) -> Arc<Self> {
        Arc::new(Self {
            sensor_id,
            offline: AtomicBool::new(false),
            offline_reason: Mutex::new(SensorDisconnectReason::NetworkDrop),
            active_sessions: AtomicU32::new(0),
            peak_sessions: AtomicU32::new(0),
            total_connections: AtomicU64::new(0),
            current_generation: AtomicU64::new(0),
            queue: Mutex::new(VecDeque::new()),
            default_extra_payload_bytes: AtomicU64::new(0),
        })
    }

    /// Returns the target camera's sensor identifier.
    #[must_use]
    pub const fn sensor_id(&self) -> &SensorId {
        &self.sensor_id
    }

    /// Enqueues a scripted frame or fault event to be emitted on the next poll.
    pub fn push_spec(&self, spec: SyntheticFrameSpec) {
        if let Ok(mut guard) = self.queue.lock() {
            guard.push_back(spec);
        }
    }

    /// Enqueues a standard motion burst with one detection hint.
    pub fn inject_motion(
        &self,
        motion_rect: ImageRect,
        class_label: impl Into<String>,
        score_ppm: u32,
        foot_px: Option<[f64; 2]>,
        track_id: u64,
    ) {
        self.push_spec(SyntheticFrameSpec::MotionBurst {
            motion_rect,
            luma_value: 235,
            extra_payload_bytes: 0,
            is_keyframe: true,
            detections: vec![SyntheticDetectionHint {
                class_label: class_label.into(),
                score_ppm,
                foot_px,
                zone_id: None,
                track_id,
            }],
        });
    }

    /// Marks the camera offline and queues an immediate disconnect so active streams drop cleanly.
    pub fn kill_camera(&self, reason: SensorDisconnectReason) {
        if let Ok(mut guard) = self.offline_reason.lock() {
            *guard = reason.clone();
        }
        self.offline.store(true, Ordering::Release);
        if let Ok(mut guard) = self.queue.lock() {
            guard.push_front(SyntheticFrameSpec::Disconnect(reason));
        }
    }

    /// Restores camera availability so the next backoff reconnect attempt succeeds.
    pub fn restore_camera(&self) {
        self.offline.store(false, Ordering::Release);
    }

    /// Configures default encoded payload padding bytes for generated frames.
    pub fn set_default_extra_payload_bytes(&self, bytes: u64) {
        self.default_extra_payload_bytes
            .store(bytes, Ordering::Release);
    }

    /// Returns currently open upstream sessions (`0` or `1`).
    #[must_use]
    pub fn active_session_count(&self) -> u32 {
        self.active_sessions.load(Ordering::Acquire)
    }

    /// Returns peak concurrent upstream sessions ever observed (`<= 1`).
    #[must_use]
    pub fn peak_concurrent_sessions(&self) -> u32 {
        self.peak_sessions.load(Ordering::Acquire)
    }

    /// Returns cumulative connect calls completed across all reconnect generations.
    #[must_use]
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Acquire)
    }

    /// Returns the most recently connected stream generation (`0` if never connected).
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.current_generation.load(Ordering::Acquire)
    }
}

/// Deterministic in-process camera driver used by `adapter: "synthetic"` and lab/CI suites.
pub struct SyntheticCameraDriver {
    sensor_id: SensorId,
    primary_zone: String,
    dimensions: [u32; 2],
    control: Arc<SyntheticCameraControl>,
    connected: bool,
    generation: u64,
    sequence: u64,
    discontinuity_next: bool,
    last_default_tick_ns: Option<i128>,
}

impl SyntheticCameraDriver {
    /// Creates a deterministic synthetic driver backed by `control`.
    #[must_use]
    pub fn new(entry: &CameraManifestEntry, control: Arc<SyntheticCameraControl>) -> Self {
        Self {
            sensor_id: entry.sensor_id.clone(),
            primary_zone: entry.primary_zone.clone(),
            dimensions: entry.dimensions,
            control,
            connected: false,
            generation: 0,
            sequence: 0,
            discontinuity_next: false,
            last_default_tick_ns: None,
        }
    }
}

impl SensorDriver for SyntheticCameraDriver {
    fn connect(&mut self, generation: u64) -> Result<(), SensorDisconnectReason> {
        if self.connected {
            self.disconnect();
        }
        if self.control.offline.load(Ordering::Acquire) {
            let reason = self
                .control
                .offline_reason
                .lock()
                .map(|g| g.clone())
                .unwrap_or(SensorDisconnectReason::NetworkDrop);
            return Err(reason);
        }
        let now_active = self.control.active_sessions.fetch_add(1, Ordering::AcqRel) + 1;
        self.control
            .peak_sessions
            .fetch_max(now_active, Ordering::AcqRel);
        self.control
            .total_connections
            .fetch_add(1, Ordering::AcqRel);
        self.control
            .current_generation
            .store(generation, Ordering::Release);
        self.connected = true;
        self.generation = generation;
        self.sequence = 0;
        self.discontinuity_next = generation > 1;
        Ok(())
    }

    fn poll_frame(&mut self, now_ns: i128) -> SensorDriverEvent {
        if !self.connected {
            return SensorDriverEvent::Disconnected(SensorDisconnectReason::NetworkDrop);
        }
        let next_spec = self
            .control
            .queue
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front());

        if let Some(SyntheticFrameSpec::Disconnect(reason)) = next_spec {
            self.disconnect();
            return SensorDriverEvent::Disconnected(reason);
        }
        if self.control.offline.load(Ordering::Acquire) {
            let reason = self
                .control
                .offline_reason
                .lock()
                .map(|g| g.clone())
                .unwrap_or(SensorDisconnectReason::NetworkDrop);
            self.disconnect();
            return SensorDriverEvent::Disconnected(reason);
        }
        if matches!(next_spec, Some(SyntheticFrameSpec::Stall)) {
            return SensorDriverEvent::Idle;
        }
        if next_spec.is_none() {
            if self.last_default_tick_ns == Some(now_ns) {
                return SensorDriverEvent::Idle;
            }
            self.last_default_tick_ns = Some(now_ns);
        }

        self.sequence = self.sequence.saturating_add(1);
        let pixel_count = (self.dimensions[0] as usize).saturating_mul(self.dimensions[1] as usize);
        let mut luma = vec![32_u8; pixel_count];
        let mut is_keyframe = self.sequence == 1 || self.sequence.is_multiple_of(8);
        let mut detections = Vec::new();
        let mut extra_payload = self
            .control
            .default_extra_payload_bytes
            .load(Ordering::Acquire) as usize;

        match next_spec {
            Some(SyntheticFrameSpec::Quiescent { is_keyframe: kf }) => {
                is_keyframe = kf;
            }
            Some(SyntheticFrameSpec::OsdOnlyTick {
                osd_rect,
                luma_value,
                is_keyframe: kf,
            }) => {
                draw_rect_luma(&mut luma, self.dimensions, osd_rect, luma_value);
                is_keyframe = kf;
            }
            Some(SyntheticFrameSpec::MotionBurst {
                motion_rect,
                luma_value,
                extra_payload_bytes,
                is_keyframe: kf,
                detections: dets,
            }) => {
                draw_rect_luma(&mut luma, self.dimensions, motion_rect, luma_value);
                extra_payload = extra_payload.max(extra_payload_bytes);
                is_keyframe = kf;
                detections = dets;
            }
            Some(SyntheticFrameSpec::Disconnect(_) | SyntheticFrameSpec::Stall) | None => {}
        }

        let mut encoded_payload = Vec::with_capacity(32 + luma.len() + extra_payload);
        encoded_payload.extend_from_slice(b"FSSA");
        encoded_payload.extend_from_slice(&self.generation.to_be_bytes());
        encoded_payload.extend_from_slice(&self.sequence.to_be_bytes());
        encoded_payload.extend_from_slice(&luma);
        if extra_payload > 0 {
            let fill_byte = ((self.sequence & 0xff) as u8) ^ 0x5a;
            encoded_payload.resize(
                encoded_payload.len().saturating_add(extra_payload),
                fill_byte,
            );
        }
        let source_digest = ContentDigest::sha256(&encoded_payload);
        let stream_name = format!(
            "stream:{}:g{}",
            sanitize_stream_segment(self.sensor_id.as_str()),
            self.generation
        );
        let stream_id = StreamId::parse(stream_name).unwrap_or_else(|_| unreachable_stream_id());
        let discontinuity_before = self.discontinuity_next;
        self.discontinuity_next = false;

        SensorDriverEvent::Frame(Arc::new(CameraFrame {
            sensor_id: self.sensor_id.clone(),
            stream_generation: self.generation,
            stream_id,
            sequence: self.sequence,
            media_pts_ns: now_ns.saturating_sub(5_000_000),
            host_receive_ns: now_ns,
            rtt_jitter_ns: 4_000_000,
            node_clock_uncertainty_ns: 1_000_000,
            codec: MediaCodec::H264,
            is_keyframe,
            discontinuity_before,
            dimensions: self.dimensions,
            encoded_payload,
            pixels: FramePixelInput::Luma { pixels: luma },
            source_digest,
            zone_id: self.primary_zone.clone(),
            synthetic_detections: detections,
        }))
    }

    fn disconnect(&mut self) {
        if self.connected {
            self.connected = false;
            self.control.active_sessions.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn active_session_count(&self) -> u32 {
        self.control.active_session_count()
    }

    fn total_connections(&self) -> u64 {
        self.control.total_connections()
    }

    fn adapter_kind(&self) -> CameraAdapterKind {
        CameraAdapterKind::Synthetic
    }
}
