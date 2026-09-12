#![forbid(unsafe_code)]
//! Source, device, and adapter identity schemas and contracts (FSS-005).
//!
//! Provides deterministic reference models for physical and virtual sensors, devices,
//! and adapters with stable identifiers, hard bounds, explicit authority, and canonical
//! encoding. Generation changes produce new identities and never overwrite in-place.

use core::fmt;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::ids::{
    AdapterGeneration, AdapterId, AppGeneration, DeviceGeneration, DeviceId, FirmwareGeneration,
    ModelGeneration, SourceId, StreamGeneration,
};
use crate::{ClockBasis, ContentDigest, ContractError};

/// Classification of physical and virtual sensor hardware devices.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DeviceClass {
    /// Dedicated imaging sensor (camera, PTZ, thermal).
    Camera = 1,
    /// Dedicated audio capture device.
    Microphone = 2,
    /// Multi-sensor environmental or telemetry node.
    SensorNode = 3,
    /// Network video recorder or aggregation bridge.
    NvrBridge = 4,
    /// Pure software or simulated virtual device.
    VirtualDevice = 5,
    /// Deterministic qualification fixture or synthetic oracle.
    SyntheticFixture = 6,
}

impl DeviceClass {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::SensorNode => "sensor_node",
            Self::NvrBridge => "nvr_bridge",
            Self::VirtualDevice => "virtual_device",
            Self::SyntheticFixture => "synthetic_fixture",
        }
    }

    /// Parses a device class from string, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "camera" => Ok(Self::Camera),
            "microphone" => Ok(Self::Microphone),
            "sensor_node" => Ok(Self::SensorNode),
            "nvr_bridge" => Ok(Self::NvrBridge),
            "virtual_device" => Ok(Self::VirtualDevice),
            "synthetic_fixture" => Ok(Self::SyntheticFixture),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for DeviceClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for DeviceClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Camera),
            2 => Ok(Self::Microphone),
            3 => Ok(Self::SensorNode),
            4 => Ok(Self::NvrBridge),
            5 => Ok(Self::VirtualDevice),
            6 => Ok(Self::SyntheticFixture),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Bitfield of device capabilities.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceCapabilities(pub u32);

impl DeviceCapabilities {
    /// Empty capability set.
    pub const NONE: Self = Self(0);
    /// Pan-tilt-zoom motor control.
    pub const PTZ: Self = Self(1 << 0);
    /// Optical zoom lens.
    pub const OPTICAL_ZOOM: Self = Self(1 << 1);
    /// Thermal or radiometric imaging capability.
    pub const THERMAL: Self = Self(1 << 2);
    /// Audio input stream capture.
    pub const AUDIO_CAPTURE: Self = Self(1 << 3);
    /// Infrared or low-light night vision illumination.
    pub const NIGHT_VISION: Self = Self(1 << 4);
    /// On-device edge motion detection.
    pub const MOTION_TRIGGER: Self = Self(1 << 5);
    /// Hardware PTP/synchronized capture timestamping.
    pub const HARDWARE_TIMESTAMPING: Self = Self(1 << 6);

    /// Mask of all defined device capability bits (bits 0..=6).
    pub const ALL: Self = Self(0x7F);

    /// Validates and constructs capabilities from raw bits, returning an error if undefined bits are set.
    pub const fn from_bits(bits: u32) -> Result<Self, ContractError> {
        if (bits & !Self::ALL.0) != 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self(bits))
    }

    /// Constructs capabilities from raw bits, truncating any undefined bits.
    #[must_use]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Returns true if only defined capability bits are set.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        (self.0 & !Self::ALL.0) == 0
    }

    /// Returns the raw bits value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns true if all flags in `other` are set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combines capabilities with bitwise OR.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true if any flag in `other` is set in `self`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl CanonicalEncode for DeviceCapabilities {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.0);
    }
}

impl CanonicalDecode for DeviceCapabilities {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let bits = decoder.u32()?;
        Self::from_bits(bits)
    }
}

/// Origin class of an evidence source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SourceKind {
    /// First-party physical sensor feed.
    PhysicalSensor = 1,
    /// Software simulation fixture.
    VirtualFixture = 2,
    /// Downstream aggregation bridge or NVR proxy.
    BridgeOrNvr = 3,
    /// Sealed offline imported archive.
    ImportedArchive = 4,
    /// Deterministic laboratory test oracle.
    SyntheticOracle = 5,
}

impl SourceKind {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PhysicalSensor => "physical_sensor",
            Self::VirtualFixture => "virtual_fixture",
            Self::BridgeOrNvr => "bridge_or_nvr",
            Self::ImportedArchive => "imported_archive",
            Self::SyntheticOracle => "synthetic_oracle",
        }
    }

    /// Parses a source kind from string, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "physical_sensor" => Ok(Self::PhysicalSensor),
            "virtual_fixture" => Ok(Self::VirtualFixture),
            "bridge_or_nvr" => Ok(Self::BridgeOrNvr),
            "imported_archive" => Ok(Self::ImportedArchive),
            "synthetic_oracle" => Ok(Self::SyntheticOracle),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for SourceKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for SourceKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::PhysicalSensor),
            2 => Ok(Self::VirtualFixture),
            3 => Ok(Self::BridgeOrNvr),
            4 => Ok(Self::ImportedArchive),
            5 => Ok(Self::SyntheticOracle),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Payload media domain of an evidence stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MediaKind {
    /// Moving image sequence (video).
    Video = 1,
    /// Acoustic waveform (audio).
    Audio = 2,
    /// Discrete still photograph.
    Image = 3,
    /// Structured sensor telemetry, metrics, or events.
    Metadata = 4,
    /// Interleaved or synchronized multi-modal stream.
    Compound = 5,
}

impl MediaKind {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Image => "image",
            Self::Metadata => "metadata",
            Self::Compound => "compound",
        }
    }

    /// Parses a media kind from string, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "video" => Ok(Self::Video),
            "audio" => Ok(Self::Audio),
            "image" => Ok(Self::Image),
            "metadata" => Ok(Self::Metadata),
            "compound" => Ok(Self::Compound),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for MediaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for MediaKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for MediaKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Video),
            2 => Ok(Self::Audio),
            3 => Ok(Self::Image),
            4 => Ok(Self::Metadata),
            5 => Ok(Self::Compound),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Protocol classification of a device adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AdapterKind {
    /// USB Video Class driver.
    Uvc = 1,
    /// Real-Time Streaming Protocol driver.
    Rtsp = 2,
    /// ONVIF Profile T (advanced video streaming).
    OnvifProfileT = 3,
    /// ONVIF Profile M (metadata and analytics).
    OnvifProfileM = 4,
    /// Local or network file archive reader.
    FileArchive = 5,
    /// Synthetic virtual simulator.
    VirtualSimulated = 6,
}

impl AdapterKind {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uvc => "uvc",
            Self::Rtsp => "rtsp",
            Self::OnvifProfileT => "onvif_profile_t",
            Self::OnvifProfileM => "onvif_profile_m",
            Self::FileArchive => "file_archive",
            Self::VirtualSimulated => "virtual_simulated",
        }
    }

    /// Parses an adapter kind from string, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "uvc" => Ok(Self::Uvc),
            "rtsp" => Ok(Self::Rtsp),
            "onvif_profile_t" => Ok(Self::OnvifProfileT),
            "onvif_profile_m" => Ok(Self::OnvifProfileM),
            "file_archive" => Ok(Self::FileArchive),
            "virtual_simulated" => Ok(Self::VirtualSimulated),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for AdapterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for AdapterKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for AdapterKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Uvc),
            2 => Ok(Self::Rtsp),
            3 => Ok(Self::OnvifProfileT),
            4 => Ok(Self::OnvifProfileM),
            5 => Ok(Self::FileArchive),
            6 => Ok(Self::VirtualSimulated),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Execution isolation mode for device adapter drivers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum IsolationMode {
    /// Native pure-Rust in-process driver.
    NativePureRust = 1,
    /// Sealed laboratory process with explicit boundary pipes.
    SealedLaboratoryProcess = 2,
}

impl IsolationMode {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativePureRust => "native_pure_rust",
            Self::SealedLaboratoryProcess => "sealed_laboratory_process",
        }
    }

    /// Parses an isolation mode from string, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "native_pure_rust" => Ok(Self::NativePureRust),
            "sealed_laboratory_process" => Ok(Self::SealedLaboratoryProcess),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for IsolationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for IsolationMode {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for IsolationMode {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::NativePureRust),
            2 => Ok(Self::SealedLaboratoryProcess),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Authentication and credential method used by an adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CredentialMethod {
    /// No authentication required.
    None = 1,
    /// Device-local hardware secret or symmetric key.
    LocalSecret = 2,
    /// HTTP basic authentication over secure transport.
    BasicAuth = 3,
    /// HTTP/RTSP digest authentication.
    DigestAuth = 4,
    /// Mutual TLS with client certificate.
    MutualTls = 5,
    /// Bearer or vendor OAuth token.
    Token = 6,
}

impl CredentialMethod {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LocalSecret => "local_secret",
            Self::BasicAuth => "basic_auth",
            Self::DigestAuth => "digest_auth",
            Self::MutualTls => "mutual_tls",
            Self::Token => "token",
        }
    }

    /// Parses a credential method from string, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "none" => Ok(Self::None),
            "local_secret" => Ok(Self::LocalSecret),
            "basic_auth" => Ok(Self::BasicAuth),
            "digest_auth" => Ok(Self::DigestAuth),
            "mutual_tls" => Ok(Self::MutualTls),
            "token" => Ok(Self::Token),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for CredentialMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for CredentialMethod {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for CredentialMethod {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::None),
            2 => Ok(Self::LocalSecret),
            3 => Ok(Self::BasicAuth),
            4 => Ok(Self::DigestAuth),
            5 => Ok(Self::MutualTls),
            6 => Ok(Self::Token),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Bitfield of adapter capabilities.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdapterCapabilities(pub u32);

impl AdapterCapabilities {
    /// Empty capability set.
    pub const NONE: Self = Self(0);
    /// Continuous media stream acquisition.
    pub const STREAMING: Self = Self(1 << 0);
    /// PTZ motor control commands.
    pub const PTZ_CONTROL: Self = Self(1 << 1);
    /// Local network device discovery.
    pub const DEVICE_DISCOVERY: Self = Self(1 << 2);
    /// Still image frame snapshot acquisition.
    pub const SNAPSHOT: Self = Self(1 << 3);
    /// Bidirectional talk-back audio transport.
    pub const TWO_WAY_AUDIO: Self = Self(1 << 4);
    /// Hardware decoding assistance.
    pub const HARDWARE_DECODE_ASSIST: Self = Self(1 << 5);
    /// Clock synchronization (NTP/PTP/RTCP).
    pub const TIME_SYNC: Self = Self(1 << 6);
    /// Health telemetry and diagnostic metrics.
    pub const TELEMETRY: Self = Self(1 << 7);

    /// Mask of all defined adapter capability bits (bits 0..=7).
    pub const ALL: Self = Self(0xFF);

    /// Validates and constructs capabilities from raw bits, returning an error if undefined bits are set.
    pub const fn from_bits(bits: u32) -> Result<Self, ContractError> {
        if (bits & !Self::ALL.0) != 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self(bits))
    }

    /// Constructs capabilities from raw bits, truncating any undefined bits.
    #[must_use]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Returns true if only defined capability bits are set.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        (self.0 & !Self::ALL.0) == 0
    }

    /// Returns the raw bits value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns true if all flags in `other` are set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combines capabilities with bitwise OR.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true if any flag in `other` is set in `self`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl CanonicalEncode for AdapterCapabilities {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.0);
    }
}

impl CanonicalDecode for AdapterCapabilities {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let bits = decoder.u32()?;
        Self::from_bits(bits)
    }
}

/// Immutable device identity binding exact hardware, firmware, and model generation.
///
/// A change in firmware, hardware revision, or generation produces a distinct canonical
/// identity and fingerprint. Revisions never overwrite existing identities in-place.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceIdentity {
    /// Stable device identifier.
    pub device_id: DeviceId,
    /// Subsystem configuration generation.
    pub generation: DeviceGeneration,
    /// Hardware manufacturer name.
    pub manufacturer: String,
    /// Hardware model designation.
    pub model: String,
    /// Hardware board or revision code.
    pub hardware_revision: String,
    /// Active firmware build generation.
    pub firmware_version: FirmwareGeneration,
    /// Optional vendor application or agent release generation.
    pub application_version: Option<AppGeneration>,
    /// Optional model package generation bound to this device.
    pub model_generation: Option<ModelGeneration>,
    /// Device classification.
    pub device_class: DeviceClass,
    /// Declared hardware capabilities.
    pub capabilities: DeviceCapabilities,
    /// Independent physical failure domain descriptor.
    pub failure_domain: String,
}

impl DeviceIdentity {
    /// Schema identity constant.
    pub const SCHEMA: &'static str = "fss.device_identity.v1";
    /// Maximum byte length for general string fields.
    pub const MAX_STR_LEN: usize = 128;
    /// Maximum byte length for version string fields.
    pub const MAX_VERSION_LEN: usize = 64;

    /// Validates field invariants and hard bounds.
    pub fn verify(&self) -> Result<(), ContractError> {
        if self.manufacturer.is_empty() || self.manufacturer.len() > Self::MAX_STR_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.model.is_empty() || self.model.len() > Self::MAX_STR_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.hardware_revision.is_empty() || self.hardware_revision.len() > Self::MAX_VERSION_LEN
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if !self.capabilities.is_valid() {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.failure_domain.is_empty() || self.failure_domain.len() > Self::MAX_STR_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// Computes the domain-separated canonical digest of this device identity.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Creates a new device identity with an updated generation.
    ///
    /// Monotonically transitions to a strictly newer configuration generation.
    /// Attempting to transition to an older or identical generation fails closed with
    /// [`ContractError::GenerationConflict`].
    pub fn transition_generation(
        &self,
        new_generation: DeviceGeneration,
    ) -> Result<Self, ContractError> {
        if new_generation <= self.generation {
            return Err(ContractError::GenerationConflict);
        }
        let mut next = self.clone();
        next.generation = new_generation;
        next.verify()?;
        Ok(next)
    }

    /// Returns true if this device belongs to the same hardware family as `other`.
    #[must_use]
    pub fn is_same_hardware(&self, other: &Self) -> bool {
        self.device_id == other.device_id
            && self.manufacturer == other.manufacturer
            && self.model == other.model
            && self.hardware_revision == other.hardware_revision
    }
}

impl fmt::Display for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.device_id, self.generation, self.manufacturer, self.model
        )
    }
}

impl CanonicalEncode for DeviceIdentity {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.device_id.encode_canonical(encoder);
        self.generation.encode_canonical(encoder);
        encoder.text(&self.manufacturer);
        encoder.text(&self.model);
        encoder.text(&self.hardware_revision);
        self.firmware_version.encode_canonical(encoder);
        match &self.application_version {
            Some(app) => {
                encoder.bool(true);
                app.encode_canonical(encoder);
            }
            None => {
                encoder.bool(false);
            }
        }
        match &self.model_generation {
            Some(mg) => {
                encoder.bool(true);
                mg.encode_canonical(encoder);
            }
            None => {
                encoder.bool(false);
            }
        }
        self.device_class.encode_canonical(encoder);
        self.capabilities.encode_canonical(encoder);
        encoder.text(&self.failure_domain);
    }
}

impl CanonicalDecode for DeviceIdentity {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let device_id = DeviceId::decode_canonical(decoder)?;
        let generation = DeviceGeneration::decode_canonical(decoder)?;
        let manufacturer = decoder.text()?.to_string();
        let model = decoder.text()?.to_string();
        let hardware_revision = decoder.text()?.to_string();
        let firmware_version = FirmwareGeneration::decode_canonical(decoder)?;
        let application_version = if decoder.bool()? {
            Some(AppGeneration::decode_canonical(decoder)?)
        } else {
            None
        };
        let model_generation = if decoder.bool()? {
            Some(ModelGeneration::decode_canonical(decoder)?)
        } else {
            None
        };
        let device_class = DeviceClass::decode_canonical(decoder)?;
        let capabilities = DeviceCapabilities::decode_canonical(decoder)?;
        let failure_domain = decoder.text()?.to_string();

        let identity = Self {
            device_id,
            generation,
            manufacturer,
            model,
            hardware_revision,
            firmware_version,
            application_version,
            model_generation,
            device_class,
            capabilities,
            failure_domain,
        };
        identity.verify()?;
        Ok(identity)
    }
}

/// Immutable evidence source identity binding source, device, adapter, and clock basis.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceIdentity {
    /// Stable evidence source identifier.
    pub source_id: SourceId,
    /// Physical or virtual device owning this stream.
    pub device_id: DeviceId,
    /// Adapter driver managing stream acquisition.
    pub adapter_id: AdapterId,
    /// Origin classification of this source.
    pub source_kind: SourceKind,
    /// Media domain of the captured stream.
    pub media_kind: MediaKind,
    /// Logical channel identifier (e.g. "main", "sub", "ch0").
    pub channel: String,
    /// Nominal capture timestamping clock reference.
    pub nominal_clock_basis: ClockBasis,
    /// Active stream configuration generation.
    pub stream_generation: StreamGeneration,
    /// Independent physical failure domain descriptor.
    pub failure_domain: String,
    /// True if this source represents a live real-time capture feed.
    pub is_live: bool,
}

impl SourceIdentity {
    /// Schema identity constant.
    pub const SCHEMA: &'static str = "fss.source_identity.v1";
    /// Maximum byte length for general string fields.
    pub const MAX_STR_LEN: usize = 128;
    /// Maximum byte length for channel name.
    pub const MAX_CHANNEL_LEN: usize = 64;

    /// Validates field invariants and hard bounds.
    pub fn verify(&self) -> Result<(), ContractError> {
        if self.channel.is_empty() || self.channel.len() > Self::MAX_CHANNEL_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.failure_domain.is_empty() || self.failure_domain.len() > Self::MAX_STR_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// Computes the domain-separated canonical digest of this source identity.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Creates a new source identity with an updated stream generation.
    ///
    /// Monotonically transitions to a strictly newer stream generation.
    /// Attempting to transition to an older or identical generation fails closed with
    /// [`ContractError::GenerationConflict`].
    pub fn transition_stream_generation(
        &self,
        new_generation: StreamGeneration,
    ) -> Result<Self, ContractError> {
        if new_generation <= self.stream_generation {
            return Err(ContractError::GenerationConflict);
        }
        let mut next = self.clone();
        next.stream_generation = new_generation;
        next.verify()?;
        Ok(next)
    }
}

impl fmt::Display for SourceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.source_id, self.channel, self.stream_generation, self.device_id
        )
    }
}

impl CanonicalEncode for SourceIdentity {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.source_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.adapter_id.encode_canonical(encoder);
        self.source_kind.encode_canonical(encoder);
        self.media_kind.encode_canonical(encoder);
        encoder.text(&self.channel);
        self.nominal_clock_basis.encode_canonical(encoder);
        self.stream_generation.encode_canonical(encoder);
        encoder.text(&self.failure_domain);
        encoder.bool(self.is_live);
    }
}

impl CanonicalDecode for SourceIdentity {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let source_id = SourceId::decode_canonical(decoder)?;
        let device_id = DeviceId::decode_canonical(decoder)?;
        let adapter_id = AdapterId::decode_canonical(decoder)?;
        let source_kind = SourceKind::decode_canonical(decoder)?;
        let media_kind = MediaKind::decode_canonical(decoder)?;
        let channel = decoder.text()?.to_string();
        let nominal_clock_basis = ClockBasis::decode_canonical(decoder)?;
        let stream_generation = StreamGeneration::decode_canonical(decoder)?;
        let failure_domain = decoder.text()?.to_string();
        let is_live = decoder.bool()?;

        let identity = Self {
            source_id,
            device_id,
            adapter_id,
            source_kind,
            media_kind,
            channel,
            nominal_clock_basis,
            stream_generation,
            failure_domain,
            is_live,
        };
        identity.verify()?;
        Ok(identity)
    }
}

/// Immutable adapter identity binding adapter kind, protocol, credentials, and capabilities.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdapterIdentity {
    /// Stable adapter identifier.
    pub adapter_id: AdapterId,
    /// Adapter software generation.
    pub generation: AdapterGeneration,
    /// Driver protocol kind.
    pub adapter_kind: AdapterKind,
    /// Exact protocol profile specification (e.g. "uvc:1.5", "rtsp:rfc2326").
    pub protocol_profile: String,
    /// Process isolation mode.
    pub isolation_mode: IsolationMode,
    /// Credential authentication method.
    pub credential_method: CredentialMethod,
    /// Declared adapter capabilities.
    pub capabilities: AdapterCapabilities,
    /// Upper bandwidth capacity bound in bytes per second.
    pub max_bandwidth_bytes_per_sec: u64,
    /// Maximum ring buffer frame depth.
    pub max_buffer_frames: u32,
    /// Driver request timeout in nanoseconds.
    pub request_timeout_ns: u64,
}

impl AdapterIdentity {
    /// Schema identity constant.
    pub const SCHEMA: &'static str = "fss.adapter_identity.v1";
    /// Maximum byte length for protocol profile string.
    pub const MAX_STR_LEN: usize = 128;

    /// Validates field invariants and hard bounds.
    pub fn verify(&self) -> Result<(), ContractError> {
        if self.protocol_profile.is_empty() || self.protocol_profile.len() > Self::MAX_STR_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if !self.capabilities.is_valid() {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.max_bandwidth_bytes_per_sec == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.max_buffer_frames == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.request_timeout_ns == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// Computes the domain-separated canonical digest of this adapter identity.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::SCHEMA)
    }

    /// Creates a new adapter identity with an updated generation.
    ///
    /// Monotonically transitions to a strictly newer configuration generation.
    /// Attempting to transition to an older or identical generation fails closed with
    /// [`ContractError::GenerationConflict`].
    pub fn transition_generation(
        &self,
        new_generation: AdapterGeneration,
    ) -> Result<Self, ContractError> {
        if new_generation <= self.generation {
            return Err(ContractError::GenerationConflict);
        }
        let mut next = self.clone();
        next.generation = new_generation;
        next.verify()?;
        Ok(next)
    }

    /// Verifies standards-first compliance under NEG-002.
    ///
    /// Fail-closed rules:
    /// 1. Security boundary integrity: Prohibits scanning, auth bypass, credential theft, persistence, or evasion.
    /// 2. Standards claims (ONVIF, RTSP, UVC) must not rely on marketing, box claims,
    ///    cloud viewing, datasheets, or consumer app presence, and must cite a qualifying specification or gate.
    /// 3. Proprietary/vendor/app-automation paths cannot use `IsolationMode::NativePureRust`
    ///    as a production native driver without authorized lab isolation (`IsolationMode::SealedLaboratoryProcess`).
    /// 4. Vendor tokens must be explicitly scoped to single device/account and cannot run under ambient/global credentials.
    pub fn verify_standards_compliance(&self) -> Result<(), StandardsComplianceError> {
        let profile_raw_lower = self.protocol_profile.to_ascii_lowercase();
        let profile_normalized = profile_raw_lower.replace(['_', '-'], " ");
        let id_raw_lower = self.adapter_id.as_str().to_ascii_lowercase();
        let id_normalized = id_raw_lower.replace(['_', '-'], " ");

        // Rule 0 (Defect 6): Security boundary verification
        for sec_viol in &[
            "credential theft",
            "credential harvesting",
            "auth bypass",
            "authentication bypass",
            "bypass auth",
            "third party account",
            "broad scanning",
            "subnet scan",
            "network scan",
            "port scan",
            "ip sweep",
            "persistence on vendor",
            "device persistence",
            "backdoor",
            "evasion",
        ] {
            if profile_raw_lower.contains(sec_viol)
                || profile_normalized.contains(sec_viol)
                || id_raw_lower.contains(sec_viol)
                || id_normalized.contains(sec_viol)
            {
                return Err(StandardsComplianceError::SecurityBoundaryViolation {
                    detail: format!(
                        "adapter '{}' or protocol profile '{}' contains prohibited security boundary violation '{sec_viol}'",
                        self.adapter_id, self.protocol_profile
                    ),
                });
            }
        }

        // Rule 1 (Defect 2): Reject marketing / app presence / consumer box claims
        for forbidden in &[
            "marketing",
            "advertised",
            "advertising",
            "inferred",
            "app presence",
            "packaging",
            "retail packaging",
            "consumer box",
            "box claim",
            "cloud viewing",
            "community forum",
            "promotional",
            "datasheet",
            "spec sheet",
            "press release",
            "ad copy",
            "app store",
            "unverified",
        ] {
            if profile_raw_lower.contains(forbidden)
                || profile_normalized.contains(forbidden)
                || id_raw_lower.contains(forbidden)
                || id_normalized.contains(forbidden)
            {
                return Err(StandardsComplianceError::UnverifiedStandardsClaim {
                    detail: format!(
                        "protocol profile '{}' contains forbidden marketing/app-presence indicator '{forbidden}'",
                        self.protocol_profile
                    ),
                });
            }
        }

        // Rule 2 (Defect 1 & 8): Qualifying evidence/spec reference requirement for standards claims
        match self.adapter_kind {
            AdapterKind::OnvifProfileT => {
                let has_spec = [
                    "profile t", "profile-t", "profile_t", "onvif profile t", "gate 030", "gate-030", "test onvif", "conformance", "proof",
                ]
                .iter()
                .any(|&s| profile_raw_lower.contains(s) || profile_normalized.contains(s));
                if !has_spec {
                    return Err(StandardsComplianceError::UnverifiedStandardsClaim {
                        detail: format!(
                            "adapter '{}' claims OnvifProfileT without qualifying profile/specification reference in '{}'",
                            self.adapter_id, self.protocol_profile
                        ),
                    });
                }
            }
            AdapterKind::Rtsp => {
                let has_spec = [
                    "rfc2326", "rfc 2326", "rfc7826", "rfc 7826", "rfc3550", "rfc 3550", "gate 030", "gate-030", "test rtsp", "proof",
                ]
                .iter()
                .any(|&s| profile_raw_lower.contains(s) || profile_normalized.contains(s));
                if !has_spec {
                    return Err(StandardsComplianceError::UnverifiedStandardsClaim {
                        detail: format!(
                            "adapter '{}' claims Rtsp without qualifying RFC or gate reference in '{}'",
                            self.adapter_id, self.protocol_profile
                        ),
                    });
                }
            }
            AdapterKind::Uvc => {
                let has_spec = ["uvc", "uac", "gate 020", "gate-020", "test uvc", "proof"]
                    .iter()
                    .any(|&s| profile_raw_lower.contains(s) || profile_normalized.contains(s));
                if !has_spec {
                    return Err(StandardsComplianceError::UnverifiedStandardsClaim {
                        detail: format!(
                            "adapter '{}' claims Uvc without qualifying specification or gate reference in '{}'",
                            self.adapter_id, self.protocol_profile
                        ),
                    });
                }
            }
            _ => {}
        }

        // Rule 3 (Defect 3 & 4): Proprietary paths cannot claim NativePureRust
        let is_proprietary = [
            "wyze", "aosu", "dji", "ring", "nest", "blink", "arlo", "eufy", "tuya",
            "reolink", "kasa", "tapo", "ezviz", "imou", "proprietary", "closed source",
            "vendor cloud", "private protocol", "vendor protocol", "screen capture",
            "app automation", "ui automation", "reverse engineered", "reverse engineering",
            "cloud bridge", "lab", "vendor",
        ]
        .iter()
        .any(|&p| {
            id_raw_lower.contains(p)
                || id_normalized.contains(p)
                || profile_raw_lower.contains(p)
                || profile_normalized.contains(p)
        });

        if is_proprietary && self.isolation_mode == IsolationMode::NativePureRust {
            return Err(StandardsComplianceError::ProprietaryNativePromotion {
                detail: format!(
                    "adapter '{}' is proprietary/vendor path but specifies NativePureRust; NEG-002 requires SealedLaboratoryProcess isolation",
                    self.adapter_id
                ),
            });
        }

        // Rule 4 (Defect 5 & 8): Vendor token scoping
        if self.credential_method == CredentialMethod::Token {
            if self.isolation_mode == IsolationMode::NativePureRust {
                return Err(StandardsComplianceError::UnscopedVendorToken {
                    detail: format!(
                        "adapter '{}' uses vendor token authentication without process boundary isolation",
                        self.adapter_id
                    ),
                });
            }

            // Even in SealedLaboratoryProcess, ambient/global/unscoped tokens are forbidden
            let is_unscoped = [
                "global", "ambient", "multi device", "all devices", "unscoped", "*",
            ]
            .iter()
            .any(|&u| {
                profile_raw_lower.contains(u)
                    || profile_normalized.contains(u)
                    || id_raw_lower.contains(u)
                    || id_normalized.contains(u)
            });
            if is_unscoped {
                return Err(StandardsComplianceError::UnscopedVendorToken {
                    detail: format!(
                        "adapter '{}' uses ambient, global, or unscoped vendor token in profile '{}'",
                        self.adapter_id, self.protocol_profile
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Standards-first camera access compliance error (NEG-002).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StandardsComplianceError {
    /// Standards claim (ONVIF/RTSP) inferred from marketing or app presence rather than qualifying evidence.
    UnverifiedStandardsClaim {
        /// Diagnostic detail describing the unverified standards claim.
        detail: String,
    },
    /// Proprietary/vendor path registered as native pure Rust production driver rather than sealed laboratory process.
    ProprietaryNativePromotion {
        /// Diagnostic detail describing the illegal proprietary promotion.
        detail: String,
    },
    /// Vendor token/credential unscoped or escaping adapter capability boundary.
    UnscopedVendorToken {
        /// Diagnostic detail describing the unscoped vendor token usage.
        detail: String,
    },
    /// Security boundary violation (broad scanning, auth bypass, credential theft, persistence, evasion).
    SecurityBoundaryViolation {
        /// Diagnostic detail describing the security boundary violation.
        detail: String,
    },
}

impl fmt::Display for StandardsComplianceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnverifiedStandardsClaim { detail } => {
                write!(f, "NEG-002 unverified standards claim: {detail}")
            }
            Self::ProprietaryNativePromotion { detail } => {
                write!(f, "NEG-002 proprietary native promotion: {detail}")
            }
            Self::UnscopedVendorToken { detail } => {
                write!(f, "NEG-002 unscoped vendor token: {detail}")
            }
            Self::SecurityBoundaryViolation { detail } => {
                write!(f, "NEG-002 security boundary violation: {detail}")
            }
        }
    }
}

impl std::error::Error for StandardsComplianceError {}

impl fmt::Display for AdapterIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.adapter_id, self.protocol_profile, self.generation
        )
    }
}

impl CanonicalEncode for AdapterIdentity {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.adapter_id.encode_canonical(encoder);
        self.generation.encode_canonical(encoder);
        self.adapter_kind.encode_canonical(encoder);
        encoder.text(&self.protocol_profile);
        self.isolation_mode.encode_canonical(encoder);
        self.credential_method.encode_canonical(encoder);
        self.capabilities.encode_canonical(encoder);
        encoder.u64(self.max_bandwidth_bytes_per_sec);
        encoder.u32(self.max_buffer_frames);
        encoder.u64(self.request_timeout_ns);
    }
}

impl CanonicalDecode for AdapterIdentity {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let adapter_id = AdapterId::decode_canonical(decoder)?;
        let generation = AdapterGeneration::decode_canonical(decoder)?;
        let adapter_kind = AdapterKind::decode_canonical(decoder)?;
        let protocol_profile = decoder.text()?.to_string();
        let isolation_mode = IsolationMode::decode_canonical(decoder)?;
        let credential_method = CredentialMethod::decode_canonical(decoder)?;
        let capabilities = AdapterCapabilities::decode_canonical(decoder)?;
        let max_bandwidth_bytes_per_sec = decoder.u64()?;
        let max_buffer_frames = decoder.u32()?;
        let request_timeout_ns = decoder.u64()?;

        let identity = Self {
            adapter_id,
            generation,
            adapter_kind,
            protocol_profile,
            isolation_mode,
            credential_method,
            capabilities,
            max_bandwidth_bytes_per_sec,
            max_buffer_frames,
            request_timeout_ns,
        };
        identity.verify()?;
        Ok(identity)
    }
}
