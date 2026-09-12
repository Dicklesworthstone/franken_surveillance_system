#![forbid(unsafe_code)]
//! Deterministic virtual encoded-camera fixture generator (FSS-014).
//!
//! Produces deterministic, seeded video frame fixtures with explicit codec, container,
//! keyframe cadence, and typed variants (corrupt, truncated, stale-firmware).
//! Each fixture binds to an exact, validated [`SensorCapsuleV1`] retaining source custody,
//! enforcing the non-negotiable invariant that a decoded frame is never "retained evidence"
//! without source custody or explicit omission (INV-003, INV-011, INV-034).
//!
//! Implements [`SequencedPacket`] for seamless composition with [`crate::PacketFaultInjector`].

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind,
    CapsuleDecodeError, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, ContinuityState,
    ContractError, CredentialMethod, DecodeState, DeviceCapabilities, DeviceClass,
    DeviceGeneration, DeviceId, DeviceIdentity, ExplicitOmission, FirmwareGeneration,
    IntegrityWitness, IsolationMode, MediaDescriptor, MediaKind, PrivacyDescriptor,
    PublicationDescriptor, PublicationState, RedactionState, SENSOR_CAPSULE_SCHEMA,
    SensorCapsuleV1, SensorId, SourceCustody, SourceId, SourceIdentity, SourceKind,
    StreamGeneration, StreamId, TimestampNs,
};

use crate::{DeterministicFaultPrng, SequencedPacket};

/// Maximum frames generated in a single fixture session.
pub const MAX_FIXTURE_FRAMES: u32 = 65_536;

/// Maximum payload bytes per encoded frame fixture.
pub const MAX_FIXTURE_PAYLOAD_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum keyframe cadence (GOP size).
pub const MAX_KEYFRAME_CADENCE: u32 = 600;

/// Minimum keyframe cadence.
pub const MIN_KEYFRAME_CADENCE: u32 = 1;

/// Maximum frame width in pixels.
pub const MAX_FRAME_WIDTH: u32 = 8_192; // 8K

/// Maximum frame height in pixels.
pub const MAX_FRAME_HEIGHT: u32 = 4_320; // 8K

/// Video compression format designations for encoded camera fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoCodec {
    /// ITU-T H.264 / AVC.
    H264,
    /// ITU-T H.265 / HEVC.
    H265,
    /// AOMedia Video 1.
    Av1,
    /// Google VP9.
    Vp9,
}

impl VideoCodec {
    /// Canonical codec string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::H265 => "h265",
            Self::Av1 => "av1",
            Self::Vp9 => "vp9",
        }
    }
}

/// Container format designations for encoded camera fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerFormat {
    /// ISO Base Media File Format (MP4).
    Mp4,
    /// Matroska (MKV).
    Mkv,
    /// Raw Annex-B byte stream.
    RawAnnexB,
}

impl ContainerFormat {
    /// Canonical container format string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mp4 => "mp4",
            Self::Mkv => "mkv",
            Self::RawAnnexB => "raw",
        }
    }
}

/// Structural frame encoding type in the group of pictures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameType {
    /// Intra-coded keyframe (IDR / keyframe).
    Keyframe,
    /// Inter-coded predictive delta frame (P-frame).
    Delta,
}

/// Typed variants of an encoded camera fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodedFixtureKind {
    /// Valid, nominally encoded frame payload.
    Nominal,
    /// Corrupted payload with mutated byte at `byte_offset`.
    Corrupt {
        /// Offset within payload where mutation occurred.
        byte_offset: usize,
        /// Description of the corruption mutation.
        mutation: String,
    },
    /// Truncated payload shortened to `truncated_len` bytes.
    Truncated {
        /// Actual truncated byte length.
        truncated_len: usize,
        /// Nominal expected byte length.
        expected_len: usize,
    },
    /// Frame generated under a deprecated or stale firmware fingerprint.
    StaleFirmware {
        /// The stale firmware fingerprint observed.
        stale_fingerprint: String,
        /// The expected current firmware fingerprint.
        expected_fingerprint: String,
    },
}

/// Specification for deterministic encoded-camera fixture generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedCameraSpec {
    /// Base capture session identity.
    pub capture_id: CapsuleId,
    /// Stable configured sensor identity.
    pub sensor_id: SensorId,
    /// Physical or virtual device identity.
    pub device_id: DeviceId,
    /// Streaming source identity.
    pub source_id: SourceId,
    /// Deterministic generator seed.
    pub seed: u64,
    /// Total number of frames to generate.
    pub frame_count: u32,
    /// Nominal payload bytes per encoded frame.
    pub frame_bytes: usize,
    /// Earliest timestamp of frame 1 in nanoseconds.
    pub start_ns: i128,
    /// Nominal interval between successive frames in nanoseconds.
    pub period_ns: u64,
    /// Conservative uncertainty added to earliest timestamp.
    pub uncertainty_ns: u64,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Video compression codec.
    pub codec: VideoCodec,
    /// Media container format.
    pub container: ContainerFormat,
    /// Keyframe cadence (number of frames per GOP).
    pub keyframe_cadence: u32,
    /// Active firmware fingerprint string.
    pub firmware_fingerprint: String,
}

impl EncodedCameraSpec {
    /// Constructs and validates a new encoded camera specification.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capture_id: CapsuleId,
        sensor_id: SensorId,
        device_id: DeviceId,
        source_id: SourceId,
        seed: u64,
        frame_count: u32,
        frame_bytes: usize,
        start_ns: i128,
        period_ns: u64,
        uncertainty_ns: u64,
        width: u32,
        height: u32,
        codec: VideoCodec,
        container: ContainerFormat,
        keyframe_cadence: u32,
        firmware_fingerprint: String,
    ) -> Result<Self, EncodedFixtureError> {
        let spec = Self {
            capture_id,
            sensor_id,
            device_id,
            source_id,
            seed,
            frame_count,
            frame_bytes,
            start_ns,
            period_ns,
            uncertainty_ns,
            width,
            height,
            codec,
            container,
            keyframe_cadence,
            firmware_fingerprint,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validates all parameters against hard bounds.
    pub fn validate(&self) -> Result<(), EncodedFixtureError> {
        if self.frame_count == 0 {
            return Err(EncodedFixtureError::ZeroFrameCount);
        }
        if self.frame_count > MAX_FIXTURE_FRAMES {
            return Err(EncodedFixtureError::FrameCountExceedsBound {
                requested: self.frame_count,
                max: MAX_FIXTURE_FRAMES,
            });
        }
        if self.frame_bytes == 0 {
            return Err(EncodedFixtureError::ZeroPayloadBytes);
        }
        if self.frame_bytes > MAX_FIXTURE_PAYLOAD_BYTES {
            return Err(EncodedFixtureError::PayloadBytesExceedsBound {
                requested: self.frame_bytes,
                max: MAX_FIXTURE_PAYLOAD_BYTES,
            });
        }
        if self.keyframe_cadence == 0 {
            return Err(EncodedFixtureError::ZeroKeyframeCadence);
        }
        if self.keyframe_cadence > MAX_KEYFRAME_CADENCE {
            return Err(EncodedFixtureError::KeyframeCadenceExceedsBound {
                requested: self.keyframe_cadence,
                max: MAX_KEYFRAME_CADENCE,
            });
        }
        if self.width == 0 {
            return Err(EncodedFixtureError::ZeroDimension("width"));
        }
        if self.width > MAX_FRAME_WIDTH {
            return Err(EncodedFixtureError::DimensionExceedsBound {
                field: "width",
                requested: self.width,
                max: MAX_FRAME_WIDTH,
            });
        }
        if self.height == 0 {
            return Err(EncodedFixtureError::ZeroDimension("height"));
        }
        if self.height > MAX_FRAME_HEIGHT {
            return Err(EncodedFixtureError::DimensionExceedsBound {
                field: "height",
                requested: self.height,
                max: MAX_FRAME_HEIGHT,
            });
        }
        if self.period_ns == 0 {
            return Err(EncodedFixtureError::InvalidSpec(
                "period_ns must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Errors produced during encoded fixture generation or validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodedFixtureError {
    /// Frame count is 0.
    ZeroFrameCount,
    /// Frame count exceeds [`MAX_FIXTURE_FRAMES`].
    FrameCountExceedsBound {
        /// Requested frame count.
        requested: u32,
        /// Hard maximum.
        max: u32,
    },
    /// Payload bytes is 0.
    ZeroPayloadBytes,
    /// Payload bytes exceeds [`MAX_FIXTURE_PAYLOAD_BYTES`].
    PayloadBytesExceedsBound {
        /// Requested payload bytes.
        requested: usize,
        /// Hard maximum.
        max: usize,
    },
    /// Keyframe cadence is 0.
    ZeroKeyframeCadence,
    /// Keyframe cadence exceeds [`MAX_KEYFRAME_CADENCE`].
    KeyframeCadenceExceedsBound {
        /// Requested cadence.
        requested: u32,
        /// Hard maximum.
        max: u32,
    },
    /// Dimension is 0.
    ZeroDimension(&'static str),
    /// Dimension exceeds hard maximum.
    DimensionExceedsBound {
        /// Field name ("width" or "height").
        field: &'static str,
        /// Requested dimension.
        requested: u32,
        /// Hard maximum.
        max: u32,
    },
    /// Generic specification error.
    InvalidSpec(&'static str),
    /// Core contract error.
    Contract(ContractError),
    /// Sensor capsule validation failure.
    CapsuleError(CapsuleDecodeError),
    /// Arithmetic overflow in timing or indexing.
    ArithmeticOverflow,
}

impl fmt::Display for EncodedFixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroFrameCount => write!(f, "frame count must be non-zero"),
            Self::FrameCountExceedsBound { requested, max } => {
                write!(f, "frame count {requested} exceeds maximum bound {max}")
            }
            Self::ZeroPayloadBytes => write!(f, "payload bytes must be non-zero"),
            Self::PayloadBytesExceedsBound { requested, max } => {
                write!(f, "payload bytes {requested} exceeds maximum bound {max}")
            }
            Self::ZeroKeyframeCadence => write!(f, "keyframe cadence must be non-zero"),
            Self::KeyframeCadenceExceedsBound { requested, max } => {
                write!(
                    f,
                    "keyframe cadence {requested} exceeds maximum bound {max}"
                )
            }
            Self::ZeroDimension(name) => write!(f, "{name} must be non-zero"),
            Self::DimensionExceedsBound {
                field,
                requested,
                max,
            } => {
                write!(f, "{field} {requested} exceeds maximum bound {max}")
            }
            Self::InvalidSpec(msg) => write!(f, "invalid specification: {msg}"),
            Self::Contract(err) => write!(f, "contract error: {err}"),
            Self::CapsuleError(err) => write!(f, "capsule validation error: {err}"),
            Self::ArithmeticOverflow => {
                write!(f, "arithmetic overflow in encoded fixture generator")
            }
        }
    }
}

impl std::error::Error for EncodedFixtureError {}

impl From<ContractError> for EncodedFixtureError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// One virtual encoded video frame fixture bound to an exact [`SensorCapsuleV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedFrameFixture {
    /// Validated sensor capsule v1 carrying custody and exact identity bindings.
    pub capsule: SensorCapsuleV1,
    /// Specific typed fixture variant.
    pub fixture_kind: EncodedFixtureKind,
    /// Group-of-pictures frame structure type.
    pub frame_type: FrameType,
    /// Compression format.
    pub codec: VideoCodec,
    /// Media container format.
    pub container: ContainerFormat,
    /// Encoded payload bytes.
    pub payload: Vec<u8>,
    /// SHA-256 digest of payload bytes.
    pub payload_digest: ContentDigest,
}

impl SequencedPacket for EncodedFrameFixture {
    fn sequence(&self) -> u64 {
        self.capsule.sequence
    }

    fn sensor_id(&self) -> &SensorId {
        &self.capsule.sensor_id
    }

    fn capture_interval(&self) -> Option<CaptureInterval> {
        Some(self.capsule.capture_interval)
    }

    fn content_digest(&self) -> Option<ContentDigest> {
        Some(self.payload_digest)
    }
}

/// Deterministic generator for virtual encoded-camera fixtures.
#[derive(Clone, Debug)]
pub struct EncodedCameraGenerator {
    spec: EncodedCameraSpec,
    variants: BTreeMap<u64, EncodedFixtureKind>,
    source_identity: SourceIdentity,
    device_identity: DeviceIdentity,
    adapter_identity: AdapterIdentity,
    stream_id: StreamId,
    adapter_id: AdapterId,
}

impl EncodedCameraGenerator {
    /// Constructs a generator producing nominal fixtures from `spec`.
    pub fn new(spec: EncodedCameraSpec) -> Result<Self, EncodedFixtureError> {
        Self::with_variants(spec, BTreeMap::new())
    }

    /// Constructs a generator with pre-configured variant rules for specific sequences.
    pub fn with_variants(
        spec: EncodedCameraSpec,
        variants: BTreeMap<u64, EncodedFixtureKind>,
    ) -> Result<Self, EncodedFixtureError> {
        spec.validate()?;

        let adapter_id = AdapterId::parse("adapter:rtsp-pure-rust-01")?;
        let adapter_gen = AdapterGeneration::parse("gen:adapter:rtsp-rust-v1")?;
        let adapter_identity = AdapterIdentity {
            adapter_id: adapter_id.clone(),
            generation: adapter_gen,
            adapter_kind: AdapterKind::Rtsp,
            protocol_profile: "rtsp:1.0:tcp".to_string(),
            isolation_mode: IsolationMode::NativePureRust,
            credential_method: CredentialMethod::Token,
            capabilities: AdapterCapabilities::STREAMING.union(AdapterCapabilities::TIME_SYNC),
            max_bandwidth_bytes_per_sec: 100_000_000,
            max_buffer_frames: 32,
            request_timeout_ns: 5_000_000_000,
        };
        adapter_identity.verify()?;

        let dev_gen = DeviceGeneration::parse("gen:dev:2026-09-11:rev1")?;
        let fw_gen = FirmwareGeneration::parse("gen:firmware:v1-production-active")?;
        let device_identity = DeviceIdentity {
            device_id: spec.device_id.clone(),
            generation: dev_gen,
            manufacturer: "Axis".to_string(),
            model: "P3245-V".to_string(),
            hardware_revision: "HW-2.0".to_string(),
            firmware_version: fw_gen,
            application_version: None,
            model_generation: None,
            device_class: DeviceClass::Camera,
            capabilities: DeviceCapabilities::OPTICAL_ZOOM,
            failure_domain: "power:poe-switch-1".to_string(),
        };
        device_identity.verify()?;

        let stream_id = StreamId::parse("stream:cam-main-video")?;
        let stream_gen = StreamGeneration::parse("gen:stream:1080p30-encoded")?;
        let source_identity = SourceIdentity {
            source_id: spec.source_id.clone(),
            device_id: spec.device_id.clone(),
            adapter_id: adapter_id.clone(),
            source_kind: SourceKind::PhysicalSensor,
            media_kind: MediaKind::Video,
            channel: "video_main".to_string(),
            nominal_clock_basis: ClockBasis::HostMonotonic,
            stream_generation: stream_gen,
            failure_domain: "net:vlan-10/switch-1".to_string(),
            is_live: true,
        };
        source_identity.verify()?;

        Ok(Self {
            spec,
            variants,
            source_identity,
            device_identity,
            adapter_identity,
            stream_id,
            adapter_id,
        })
    }

    /// Injects a corruption variant for the specified 1-based sequence.
    pub fn inject_corrupt(
        &mut self,
        sequence: u64,
        byte_offset: usize,
        mutation: impl Into<String>,
    ) {
        self.variants.insert(
            sequence,
            EncodedFixtureKind::Corrupt {
                byte_offset,
                mutation: mutation.into(),
            },
        );
    }

    /// Injects a truncation variant for the specified 1-based sequence.
    pub fn inject_truncated(
        &mut self,
        sequence: u64,
        truncated_len: usize,
    ) -> Result<(), EncodedFixtureError> {
        if truncated_len >= self.spec.frame_bytes {
            return Err(EncodedFixtureError::InvalidSpec(
                "truncated_len must be strictly less than frame_bytes",
            ));
        }
        self.variants.insert(
            sequence,
            EncodedFixtureKind::Truncated {
                truncated_len,
                expected_len: self.spec.frame_bytes,
            },
        );
        Ok(())
    }

    /// Injects a stale firmware variant for the specified 1-based sequence.
    pub fn inject_stale_firmware(&mut self, sequence: u64, stale_fingerprint: impl Into<String>) {
        self.variants.insert(
            sequence,
            EncodedFixtureKind::StaleFirmware {
                stale_fingerprint: stale_fingerprint.into(),
                expected_fingerprint: self.spec.firmware_fingerprint.clone(),
            },
        );
    }

    /// Generates all frames declared in the specification.
    pub fn generate_all(&self) -> Result<Vec<EncodedFrameFixture>, EncodedFixtureError> {
        let mut fixtures = Vec::with_capacity(self.spec.frame_count as usize);
        for seq in 1..=u64::from(self.spec.frame_count) {
            fixtures.push(self.generate_frame(seq)?);
        }
        Ok(fixtures)
    }

    /// Generates a single 1-based sequence frame fixture.
    pub fn generate_frame(
        &self,
        sequence: u64,
    ) -> Result<EncodedFrameFixture, EncodedFixtureError> {
        if sequence == 0 || sequence > u64::from(self.spec.frame_count) {
            return Err(EncodedFixtureError::InvalidSpec("sequence out of bounds"));
        }

        let is_keyframe = (sequence - 1).is_multiple_of(u64::from(self.spec.keyframe_cadence));
        let frame_type = if is_keyframe {
            FrameType::Keyframe
        } else {
            FrameType::Delta
        };

        let variant = self
            .variants
            .get(&sequence)
            .cloned()
            .unwrap_or(EncodedFixtureKind::Nominal);

        let mut payload = self.generate_raw_payload(sequence, frame_type);

        let decode_state = match &variant {
            EncodedFixtureKind::Nominal => DecodeState::Verified,
            EncodedFixtureKind::Corrupt {
                byte_offset,
                mutation: _,
            } => {
                if !payload.is_empty() {
                    let idx = byte_offset % payload.len();
                    payload[idx] ^= 0xff;
                }
                DecodeState::ConcealedErrors
            }
            EncodedFixtureKind::Truncated { truncated_len, .. } => {
                payload.truncate(*truncated_len);
                DecodeState::Failed
            }
            EncodedFixtureKind::StaleFirmware { .. } => DecodeState::Verified,
        };

        let firmware_fp = match &variant {
            EncodedFixtureKind::StaleFirmware {
                stale_fingerprint, ..
            } => stale_fingerprint.clone(),
            _ => self.spec.firmware_fingerprint.clone(),
        };

        let payload_digest = ContentDigest::sha256(&payload);

        let offset_steps = sequence
            .checked_sub(1)
            .ok_or(EncodedFixtureError::ArithmeticOverflow)?;
        let step_delta = i128::from(offset_steps)
            .checked_mul(i128::from(self.spec.period_ns))
            .ok_or(EncodedFixtureError::ArithmeticOverflow)?;
        let earliest_ns = self
            .spec
            .start_ns
            .checked_add(step_delta)
            .ok_or(EncodedFixtureError::ArithmeticOverflow)?;
        let latest_ns = earliest_ns
            .checked_add(i128::from(self.spec.uncertainty_ns))
            .ok_or(EncodedFixtureError::ArithmeticOverflow)?;

        let capture_interval =
            CaptureInterval::new(TimestampNs(earliest_ns), TimestampNs(latest_ns))?;

        let custody = SourceCustody::Retained {
            source_digest: payload_digest,
            source_bytes: payload.len() as u64,
            storage_handle: format!("store://cas/sha256/feed-seg-{:04}", sequence),
        };

        let capsule_id_str = format!("{}:seq{:04}", self.spec.capture_id.as_str(), sequence);
        let capsule_id = CapsuleId::parse(capsule_id_str)?;

        let mut capsule = SensorCapsuleV1 {
            schema: SENSOR_CAPSULE_SCHEMA.to_string(),
            capsule_id,
            source_id: self.spec.source_id.clone(),
            device_id: self.spec.device_id.clone(),
            adapter_id: self.adapter_id.clone(),
            sensor_id: self.spec.sensor_id.clone(),
            stream_id: self.stream_id.clone(),
            source_identity: self.source_identity.clone(),
            device_identity: self.device_identity.clone(),
            adapter_identity: self.adapter_identity.clone(),
            sequence,
            capture_interval,
            capture_uncertainty_reason: "conservative_capture_window".to_string(),
            receive_time_ns: TimestampNs(earliest_ns.saturating_add(2_000_000)),
            clock_basis: ClockBasis::HostMonotonic,
            custody,
            omission: ExplicitOmission::None,
            media: MediaDescriptor {
                kind: MediaKind::Video,
                codec: self.spec.codec.as_str().to_string(),
                container: Some(self.spec.container.as_str().to_string()),
                width: Some(self.spec.width),
                height: Some(self.spec.height),
                source_bytes: payload.len() as u64,
                frame_count: 1,
                source_digest: Some(payload_digest),
                proxy_digest: None,
            },
            integrity: IntegrityWitness {
                metadata_digest: ContentDigest::sha256(b"placeholder"),
                continuity: ContinuityState::Verified,
                decode: decode_state,
                firmware_fingerprint: Some(firmware_fp),
            },
            privacy: PrivacyDescriptor {
                mask_generation: None,
                redaction_state: RedactionState::NotRequired,
                retention_class: "standard_retention_30d".to_string(),
            },
            publication: PublicationDescriptor {
                state: PublicationState::Published,
                root_digest: ContentDigest::sha256(b"merkle-root-virtual-fixture"),
                ledger_revision: Some(sequence),
            },
        };

        capsule
            .seal_metadata_digest()
            .map_err(EncodedFixtureError::CapsuleError)?;
        capsule
            .verify()
            .map_err(EncodedFixtureError::CapsuleError)?;

        Ok(EncodedFrameFixture {
            capsule,
            fixture_kind: variant,
            frame_type,
            codec: self.spec.codec,
            container: self.spec.container,
            payload,
            payload_digest,
        })
    }

    fn generate_raw_payload(&self, sequence: u64, frame_type: FrameType) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.spec.frame_bytes);

        match self.spec.codec {
            VideoCodec::H264 => match frame_type {
                FrameType::Keyframe => {
                    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x28]);
                }
                FrameType::Delta => {
                    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0xe0]);
                }
            },
            VideoCodec::H265 => match frame_type {
                FrameType::Keyframe => {
                    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x40, 0x01]);
                }
                FrameType::Delta => {
                    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x02, 0x01]);
                }
            },
            VideoCodec::Av1 => match frame_type {
                FrameType::Keyframe => {
                    bytes.extend_from_slice(&[0x12, 0x00, 0x0a, 0x0a]);
                }
                FrameType::Delta => {
                    bytes.extend_from_slice(&[0x0a, 0x0a]);
                }
            },
            VideoCodec::Vp9 => match frame_type {
                FrameType::Keyframe => {
                    bytes.extend_from_slice(&[0x82, 0x49, 0x83, 0x42]);
                }
                FrameType::Delta => {
                    bytes.extend_from_slice(&[0x80, 0x01]);
                }
            },
        }

        let mut prng = DeterministicFaultPrng::new(
            self.spec
                .seed
                .wrapping_add(sequence.wrapping_mul(0x517c_c1b7_2722_0a95)),
        );

        while bytes.len() < self.spec.frame_bytes {
            let val = prng.next_u64();
            for b in val.to_be_bytes() {
                if bytes.len() == self.spec.frame_bytes {
                    break;
                }
                bytes.push(b);
            }
        }

        bytes
    }
}
