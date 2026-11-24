#![forbid(unsafe_code)]
//! Two-stage motion-gated cascade with explicit OSD ignore masking and periodic keyframe sentinel
//! sweeps (`TwoStageCascade`).
//!
//! Stage 1 applies strictly caller-supplied [`ImageRect`] OSD ignore regions on a scratch copy of
//! the frame's luma plane (never mutating source pixels and never auto-activating any candidate
//! rectangle), runs deterministic running-mean background subtraction ([`ForegroundDetector`]),
//! and optionally runs [`HealthScreen`] on the unmasked luma plane.
//!
//! Quiescent streams skip Stage-2 ML on non-keyframes (and inter-sentinel keyframes), while
//! explicitly tagging every skipped frame with an [`UnsampledReason`] so no absence claim is ever
//! fabricated. Periodic sentinel sweeps fire every `sentinel_interval_frames` to detect slow or
//! camouflaged targets that defeat frame-to-frame motion subtraction.

use std::collections::BTreeMap;
use std::sync::Arc;

use fss_core::{CaptureInterval, ContentDigest, SensorId};

use super::ModelPoolError;
use super::receipt::{CameraPriorityTier, Stage1Telemetry, StageDecision, UnsampledReason};
use crate::ReplayCx;
use crate::ingest::foreground::{ForegroundConfig, ForegroundDetector};
use crate::ingest::osd_mask::{
    ImageRect, ignore_regions_digest, mask_ignore_regions_for_foreground, validate_ignore_regions,
    validate_ignore_regions_in_bounds,
};
use crate::ingest::sensor_health::{HealthFrame, HealthScreen};

/// Hard ceiling on simultaneous streams managed by one [`TwoStageCascade`].
pub const MAX_POOL_STREAMS: usize = 64;

/// Per-stream motion state governing adaptive keyframe throttling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamActivityState {
    /// Stream shows no active Stage-1 foreground motion; non-keyframes may be skipped.
    Quiescent,
    /// Stream is experiencing active motion or inside its post-motion hold window.
    Active,
}

/// Immutable baseline reference frame retained per stream for two-frame activity models.
#[derive(Clone, Debug)]
pub struct ReferenceFramePixels {
    /// Pixel dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Number of channels (`1` for luma, `3` for packed RGB).
    pub channels: usize,
    /// Immutable pixel bytes copied from the stream's baseline frame.
    pub bytes: Vec<u8>,
}

/// Pixel buffer supplied for one stream frame.
#[derive(Clone, Debug)]
pub enum FramePixelInput {
    /// Row-major 8-bit grayscale luma (`width * height` bytes).
    Luma {
        /// Packed luma samples.
        pixels: Vec<u8>,
    },
    /// Row-major packed 8-bit RGB (`width * height * 3` bytes).
    Rgb {
        /// Packed RGB samples.
        pixels: Vec<u8>,
    },
}

impl FramePixelInput {
    /// Number of channels (`1` for luma, `3` for RGB).
    #[must_use]
    pub const fn channels(&self) -> usize {
        match self {
            Self::Luma { .. } => 1,
            Self::Rgb { .. } => 3,
        }
    }

    /// Raw slice of underlying pixel bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Luma { pixels } | Self::Rgb { pixels } => pixels,
        }
    }

    /// Validates byte length against `dimensions = [width, height]`.
    pub fn validate(&self, dimensions: [u32; 2]) -> Result<usize, ModelPoolError> {
        let count = (dimensions[0] as usize)
            .checked_mul(dimensions[1] as usize)
            .filter(|&n| n > 0 && n <= 4_194_304)
            .ok_or(ModelPoolError::InvalidInput(
                "frame dimensions out of bounds",
            ))?;
        let expected = count
            .checked_mul(self.channels())
            .ok_or(ModelPoolError::InvalidInput(
                "frame pixel byte count overflow",
            ))?;
        if self.as_bytes().len() != expected {
            return Err(ModelPoolError::InvalidInput(
                "frame pixel byte length does not match dimensions",
            ));
        }
        Ok(count)
    }

    /// Writes a deterministic 8-bit luma plane into `out` without mutating original RGB custody.
    pub fn extract_luma_into(&self, out: &mut Vec<u8>) {
        out.clear();
        match self {
            Self::Luma { pixels } => out.extend_from_slice(pixels),
            Self::Rgb { pixels } => {
                out.reserve(pixels.len() / 3);
                for rgb in pixels.as_chunks::<3>().0 {
                    let y = (299_u32 * u32::from(rgb[0])
                        + 587_u32 * u32::from(rgb[1])
                        + 114_u32 * u32::from(rgb[2])
                        + 500)
                        / 1000;
                    out.push(y.min(255) as u8);
                }
            }
        }
    }

    /// Materializes a packed RGB buffer (copying RGB directly or replicating luma into R=G=B).
    #[must_use]
    pub fn to_rgb_bytes(&self) -> Vec<u8> {
        match self {
            Self::Rgb { pixels } => pixels.clone(),
            Self::Luma { pixels } => {
                let mut rgb = Vec::with_capacity(pixels.len().saturating_mul(3));
                for &y in pixels {
                    rgb.push(y);
                    rgb.push(y);
                    rgb.push(y);
                }
                rgb
            }
        }
    }
}

/// One source-bound camera frame submitted into an inference pool epoch.
#[derive(Clone, Debug)]
pub struct StreamFrameInput {
    /// Registered camera sensor identity.
    pub sensor_id: SensorId,
    /// Strictly increasing frame sequence within the stream.
    pub frame_sequence: u64,
    /// Conservative source capture interval.
    pub capture_interval: CaptureInterval,
    /// Immutable source payload SHA-256 digest.
    pub source_digest: ContentDigest,
    /// Frame dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Whether this frame is a codec keyframe (IDR/IRAP/intra JPEG).
    pub is_keyframe: bool,
    /// Decoded pixel bytes (untouched by OSD motion masking).
    pub pixels: FramePixelInput,
}

/// Explicit per-stream registration binding geometry, priority, and optional OSD ignore rectangles.
#[derive(Clone, Debug)]
pub struct StreamRegistration {
    /// Camera sensor identity.
    pub sensor_id: SensorId,
    /// Deterministic stream ordinal used in canonical `(stream_order, frame_sequence, sensor_id)`
    /// sorting.
    pub stream_order: u32,
    /// Fair-share priority tier.
    pub priority: CameraPriorityTier,
    /// Fixed decoded dimensions `[width, height]` for this stream.
    pub dimensions: [u32; 2],
    /// Strictly caller-supplied OSD ignore rectangles (empty by default; never auto-activated).
    pub ignore_regions: Vec<ImageRect>,
}

/// Immutable policy governing Stage-1 motion gating, quiescent keyframe throttling, and periodic
/// sentinel sweeps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CascadePolicyConfig {
    /// Deterministic foreground background-subtraction parameters (dimensions are overridden per
    /// registered stream).
    pub foreground: ForegroundConfig,
    /// Minimum foreground pixels outside OSD ignore masks required to declare motion (in addition
    /// to any connected region box passing `minimum_region_pixels`).
    pub min_foreground_pixels_trigger: usize,
    /// Periodic keyframe sentinel interval (`>= 1`). When `quiescent_keyframe_only` is `true`,
    /// counts quiescent keyframes between sentinel sweeps; otherwise counts quiescent frames.
    pub sentinel_interval_frames: u64,
    /// Number of frames a stream stays `Active` after motion ceases before returning to `Quiescent`.
    pub post_motion_hold_frames: u32,
    /// When `true`, quiescent streams bypass Stage-1 and Stage-2 on non-keyframes, recording
    /// [`UnsampledReason::QuiescentNonKeyframe`].
    pub quiescent_keyframe_only: bool,
    /// When `true`, the very first keyframe that initializes a stream's baseline also triggers an
    /// initial sentinel sweep.
    pub sentinel_on_first_keyframe: bool,
    /// When `true`, Stage 1 additionally runs [`HealthScreen`] on unmasked luma.
    pub enable_sensor_health: bool,
    /// Cumulative luma sample ceiling per stream when `enable_sensor_health` is enabled.
    pub health_max_samples_per_stream: u64,
}

impl CascadePolicyConfig {
    /// Sensible default policy for `width x height` streams with periodic keyframe sentinels.
    #[must_use]
    pub fn default_for_dimensions(dimensions: [u32; 2]) -> Self {
        Self {
            foreground: ForegroundConfig {
                base_threshold: 25,
                threshold_sigma: 2,
                learning_rate_num: 16,
                learning_rate_den: 256,
                minimum_region_pixels: 8,
                dimensions,
            },
            min_foreground_pixels_trigger: 8,
            sentinel_interval_frames: 10,
            post_motion_hold_frames: 2,
            quiescent_keyframe_only: true,
            sentinel_on_first_keyframe: false,
            enable_sensor_health: false,
            health_max_samples_per_stream: 64 * 1024 * 1024,
        }
    }

    /// Validates numeric policy bounds.
    pub fn validate(&self) -> Result<(), ModelPoolError> {
        self.foreground.validate()?;
        if self.min_foreground_pixels_trigger == 0 {
            return Err(ModelPoolError::InvalidConfig(
                "min_foreground_pixels_trigger must be positive",
            ));
        }
        if self.sentinel_interval_frames == 0 {
            return Err(ModelPoolError::InvalidConfig(
                "sentinel_interval_frames must be positive",
            ));
        }
        if self.enable_sensor_health && self.health_max_samples_per_stream == 0 {
            return Err(ModelPoolError::InvalidConfig(
                "health_max_samples_per_stream must be positive when sensor health is enabled",
            ));
        }
        Ok(())
    }
}

/// Deterministic Stage-1 classification produced for one submitted frame.
#[derive(Clone, Debug)]
pub struct Stage1Decision {
    /// Deterministic stream ordinal.
    pub stream_order: u32,
    /// Monotonic frame sequence within the stream.
    pub frame_sequence: u64,
    /// Camera sensor identity.
    pub sensor_id: SensorId,
    /// Stream priority tier.
    pub priority: CameraPriorityTier,
    /// Immutable source payload digest.
    pub source_digest: ContentDigest,
    /// Conservative source capture interval.
    pub capture_interval: CaptureInterval,
    /// Whether this frame was flagged as a codec keyframe.
    pub is_keyframe: bool,
    /// Stage-1 decision (`MotionTriggered`, `SentinelSweep`, or `QuiescentSkipped`).
    pub stage_decision: StageDecision,
    /// Typed unsampled gap reason when `stage_decision == StageDecision::QuiescentSkipped`.
    pub unsampled_reason: Option<UnsampledReason>,
    /// Stage-1 pixel/OSD/health telemetry.
    pub telemetry: Stage1Telemetry,
    /// Baseline reference frame for two-frame activity models.
    pub reference_pixels: Option<Arc<ReferenceFramePixels>>,
}

struct StreamCascadeState {
    stream_order: u32,
    priority: CameraPriorityTier,
    dimensions: [u32; 2],
    ignore_regions: Vec<ImageRect>,
    ignore_regions_digest: ContentDigest,
    foreground: ForegroundDetector,
    health_screen: Option<HealthScreen>,
    source_generation: ContentDigest,
    activity_state: StreamActivityState,
    hold_remaining: u32,
    quiescent_ticks_since_sentinel: u64,
    baseline_established: bool,
    reference_pixels: Option<Arc<ReferenceFramePixels>>,
    luma_scratch: Vec<u8>,
    masked_scratch: Vec<u8>,
}

/// Stateful per-stream Stage-1 motion, OSD-mask, and keyframe-sentinel gate.
pub struct TwoStageCascade {
    policy: CascadePolicyConfig,
    streams: BTreeMap<SensorId, StreamCascadeState>,
}

impl TwoStageCascade {
    /// Creates an empty two-stage cascade with a validated policy.
    pub fn new(policy: CascadePolicyConfig) -> Result<Self, ModelPoolError> {
        policy.validate()?;
        Ok(Self {
            policy,
            streams: BTreeMap::new(),
        })
    }

    /// Returns the immutable cascade policy.
    #[must_use]
    pub const fn policy(&self) -> &CascadePolicyConfig {
        &self.policy
    }

    /// Registers a camera stream with its exact dimensions, priority, and strictly caller-supplied
    /// OSD ignore rectangles.
    pub fn register_stream(&mut self, reg: StreamRegistration) -> Result<(), ModelPoolError> {
        if self.streams.len() >= MAX_POOL_STREAMS && !self.streams.contains_key(&reg.sensor_id) {
            return Err(ModelPoolError::InvalidConfig(
                "registered stream count exceeds MAX_POOL_STREAMS",
            ));
        }
        let canonical_regions = validate_ignore_regions(&reg.ignore_regions)?;
        validate_ignore_regions_in_bounds(&canonical_regions, reg.dimensions)?;
        let regions_digest = ignore_regions_digest(&canonical_regions);
        let fg_config = ForegroundConfig {
            dimensions: reg.dimensions,
            ..self.policy.foreground.clone()
        };
        let foreground = ForegroundDetector::new(fg_config)?;
        let health_screen = if self.policy.enable_sensor_health {
            Some(HealthScreen::with_frame_limit(
                self.policy.health_max_samples_per_stream,
                65_536,
            )?)
        } else {
            None
        };
        let source_generation = ContentDigest::sha256(reg.sensor_id.as_str().as_bytes());
        self.streams.insert(
            reg.sensor_id,
            StreamCascadeState {
                stream_order: reg.stream_order,
                priority: reg.priority,
                dimensions: reg.dimensions,
                ignore_regions: canonical_regions,
                ignore_regions_digest: regions_digest,
                foreground,
                health_screen,
                source_generation,
                activity_state: StreamActivityState::Quiescent,
                hold_remaining: 0,
                quiescent_ticks_since_sentinel: 0,
                baseline_established: false,
                reference_pixels: None,
                luma_scratch: Vec::new(),
                masked_scratch: Vec::new(),
            },
        );
        Ok(())
    }

    /// Returns the deterministic `(stream_order, priority)` for a registered stream.
    pub fn stream_metadata(
        &self,
        sensor_id: &SensorId,
    ) -> Result<(u32, CameraPriorityTier), ModelPoolError> {
        let state = self
            .streams
            .get(sensor_id)
            .ok_or_else(|| ModelPoolError::UnknownStream(sensor_id.as_str().to_owned()))?;
        Ok((state.stream_order, state.priority))
    }

    /// Current quiescence/activity state of a registered stream.
    pub fn stream_activity_state(
        &self,
        sensor_id: &SensorId,
    ) -> Result<StreamActivityState, ModelPoolError> {
        let state = self
            .streams
            .get(sensor_id)
            .ok_or_else(|| ModelPoolError::UnknownStream(sensor_id.as_str().to_owned()))?;
        Ok(state.activity_state)
    }

    /// Evaluates Stage-1 motion/OSD-mask/sentinel gating for one frame in stream sequence order.
    pub fn evaluate_stage1(
        &mut self,
        frame: &StreamFrameInput,
        replay_cx: Option<&ReplayCx>,
    ) -> Result<Stage1Decision, ModelPoolError> {
        let pixel_count = frame.pixels.validate(frame.dimensions)?;
        let state = self
            .streams
            .get_mut(&frame.sensor_id)
            .ok_or_else(|| ModelPoolError::UnknownStream(frame.sensor_id.as_str().to_owned()))?;
        if frame.dimensions != state.dimensions {
            return Err(ModelPoolError::InvalidInput(
                "frame dimensions do not match registered stream dimensions",
            ));
        }

        // Capture immutable baseline reference frame on the very first frame seen for this stream.
        if state.reference_pixels.is_none() {
            state.reference_pixels = Some(Arc::new(ReferenceFramePixels {
                dimensions: frame.dimensions,
                channels: frame.pixels.channels(),
                bytes: frame.pixels.as_bytes().to_vec(),
            }));
        }

        // Fast-path adaptive keyframe throttling: while quiescent and baseline is established,
        // non-keyframes bypass pixel subtraction and ML entirely while recording an explicit gap.
        if self.policy.quiescent_keyframe_only
            && state.baseline_established
            && state.activity_state == StreamActivityState::Quiescent
            && !frame.is_keyframe
        {
            return Ok(Stage1Decision {
                stream_order: state.stream_order,
                frame_sequence: frame.frame_sequence,
                sensor_id: frame.sensor_id.clone(),
                priority: state.priority,
                source_digest: frame.source_digest,
                capture_interval: frame.capture_interval,
                is_keyframe: false,
                stage_decision: StageDecision::QuiescentSkipped,
                unsampled_reason: Some(UnsampledReason::QuiescentNonKeyframe),
                telemetry: Stage1Telemetry {
                    foreground_pixels: 0,
                    foreground_box_count: 0,
                    osd_ignore_regions_digest: state.ignore_regions_digest,
                    osd_ignore_region_count: state.ignore_regions.len(),
                    health_findings_count: 0,
                    work_units: 1,
                },
                reference_pixels: state.reference_pixels.clone(),
            });
        }

        // Extract deterministic luma without mutating original source pixels.
        frame.pixels.extract_luma_into(&mut state.luma_scratch);

        // Optional sensor-health check runs on the unmasked luma plane.
        let mut health_findings_count = 0_usize;
        if let (Some(screen), Some(cx)) = (state.health_screen.as_mut(), replay_cx) {
            let obs = screen.observe(
                HealthFrame {
                    source_generation: state.source_generation,
                    segment: frame.frame_sequence,
                    capsule_digest: frame.source_digest,
                    capture: frame.capture_interval,
                    dimensions: frame.dimensions,
                    gap_before: false,
                    pixels: &state.luma_scratch,
                },
                cx,
            )?;
            health_findings_count = obs.findings.len();
        }

        // Apply caller-supplied OSD ignore regions ONLY to the scratch copy for foreground motion.
        mask_ignore_regions_for_foreground(
            &state.luma_scratch,
            frame.dimensions,
            &state.ignore_regions,
            &mut state.masked_scratch,
        );
        let fg = state.foreground.observe(
            &state.masked_scratch,
            frame.dimensions[0],
            frame.dimensions[1],
        )?;
        let stage1_work = (pixel_count as u64).saturating_mul(2).max(1);

        let motion_detected = !fg.baseline_initialized
            && (!fg.boxes.is_empty()
                || fg.foreground_pixels >= self.policy.min_foreground_pixels_trigger);

        let (stage_decision, unsampled_reason) = if fg.baseline_initialized {
            state.baseline_established = true;
            state.activity_state = StreamActivityState::Quiescent;
            state.hold_remaining = 0;
            state.quiescent_ticks_since_sentinel = 0;
            if self.policy.sentinel_on_first_keyframe && frame.is_keyframe {
                (StageDecision::SentinelSweep, None)
            } else {
                let reason = if frame.is_keyframe {
                    UnsampledReason::SentinelIntervalSkip
                } else {
                    UnsampledReason::QuiescentNonKeyframe
                };
                (StageDecision::QuiescentSkipped, Some(reason))
            }
        } else if motion_detected {
            state.activity_state = StreamActivityState::Active;
            state.hold_remaining = self.policy.post_motion_hold_frames;
            state.quiescent_ticks_since_sentinel = 0;
            (StageDecision::MotionTriggered, None)
        } else {
            // No motion detected on this frame.
            if state.activity_state == StreamActivityState::Active {
                if state.hold_remaining > 0 {
                    state.hold_remaining -= 1;
                }
                if state.hold_remaining == 0 {
                    state.activity_state = StreamActivityState::Quiescent;
                }
            }

            let counts_toward_sentinel = !self.policy.quiescent_keyframe_only || frame.is_keyframe;
            if counts_toward_sentinel {
                state.quiescent_ticks_since_sentinel =
                    state.quiescent_ticks_since_sentinel.saturating_add(1);
                if state.quiescent_ticks_since_sentinel >= self.policy.sentinel_interval_frames {
                    state.quiescent_ticks_since_sentinel = 0;
                    (StageDecision::SentinelSweep, None)
                } else {
                    let reason = if frame.is_keyframe {
                        UnsampledReason::SentinelIntervalSkip
                    } else {
                        UnsampledReason::QuiescentNonKeyframe
                    };
                    (StageDecision::QuiescentSkipped, Some(reason))
                }
            } else {
                (
                    StageDecision::QuiescentSkipped,
                    Some(UnsampledReason::QuiescentNonKeyframe),
                )
            }
        };

        Ok(Stage1Decision {
            stream_order: state.stream_order,
            frame_sequence: frame.frame_sequence,
            sensor_id: frame.sensor_id.clone(),
            priority: state.priority,
            source_digest: frame.source_digest,
            capture_interval: frame.capture_interval,
            is_keyframe: frame.is_keyframe,
            stage_decision,
            unsampled_reason,
            telemetry: Stage1Telemetry {
                foreground_pixels: fg.foreground_pixels,
                foreground_box_count: fg.boxes.len(),
                osd_ignore_regions_digest: state.ignore_regions_digest,
                osd_ignore_region_count: state.ignore_regions.len(),
                health_findings_count,
                work_units: stage1_work,
            },
            reference_pixels: state.reference_pixels.clone(),
        })
    }
}
