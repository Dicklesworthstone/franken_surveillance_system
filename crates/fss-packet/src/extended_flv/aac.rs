#![forbid(unsafe_code)]
//! Bounded, source-preserving AAC views for structurally framed FLV audio tags.
//!
//! This profile supports two-byte AAC-LC AudioSpecificConfig records and the
//! five-byte form explicitly declaring SBR absent, with indexed rates and
//! explicit channel configurations. Other extensions, program configuration
//! elements, explicit rates, and other object types are refused. A raw access
//! unit is not proof of decodability, sender identity, continuity, or capture time.

use std::{fmt, ops::Range};

use super::Tag;

const FLV_TAG_HEADER: usize = 11;
const AAC_HEADER: usize = 2;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum length of a complete configuration admitted by this profile.
pub const MAX_SUPPORTED_CONFIGURATION_BYTES: usize = 5;
const RATES: [u32; 13] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
    7_350,
];

/// Caller-selected upper bound on one AAC tag body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum configuration or compressed-access-unit bytes, at most 4 MiB.
    pub max_body_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES,
        }
    }
}

/// Payload-free parsing refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The requested body limit is zero or exceeds the absolute ceiling.
    InvalidLimits,
    /// The source tag is not a standard FLV audio tag.
    NotAudio,
    /// The tag lacks an audio header or AAC packet type.
    TruncatedHeader,
    /// The source audio format or AAC packet type is outside this profile.
    UnsupportedPacket,
    /// An AAC configuration or access unit contains no body bytes.
    EmptyBody,
    /// The bounded body size was exceeded.
    BodyLimit,
    /// The requested interpretation does not match the packet type.
    WrongPacketType,
    /// This profile does not interpret the configuration's complete framing.
    UnsupportedConfiguration,
    /// The configuration is not AAC-LC, object type 2.
    UnsupportedObjectType,
    /// The sample rate is reserved or explicitly encoded outside this profile.
    UnsupportedSampleRate,
    /// A program-configured, reserved, or unsupported channel layout was supplied.
    UnsupportedChannelConfiguration,
    /// A core-coder dependency or GA extension requires a wider profile.
    UnsupportedGaFlags,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV AAC refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// FLV AAC packet type. Neither variant authenticates the sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    /// MPEG-4 AudioSpecificConfig bytes.
    Configuration,
    /// Raw compressed AAC data; its codec validity is not established here.
    Raw,
}

/// One AAC tag borrowing its exact original FLV framing and payload.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AudioTag<'a> {
    source: &'a [u8],
    timestamp_ms: u32,
    sender_header: u8,
    packet_type: PacketType,
}
impl fmt::Debug for AudioTag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AudioTag")
            .field("source_bytes", &self.source.len())
            .field("timestamp_ms", &self.timestamp_ms)
            .field("packet_type", &self.packet_type)
            .finish_non_exhaustive()
    }
}
impl<'a> AudioTag<'a> {
    /// Interpret a previously structurally parsed FLV tag under a finite bound.
    pub fn parse(tag: Tag<'a>, limits: Limits) -> Result<Self, Error> {
        if !(1..=MAX_BODY_BYTES).contains(&limits.max_body_bytes) {
            return Err(Error::InvalidLimits);
        }
        if tag.kind() != 8 {
            return Err(Error::NotAudio);
        }
        let payload = tag.payload();
        if payload.len() < AAC_HEADER {
            return Err(Error::TruncatedHeader);
        }
        if payload[0] >> 4 != 10 {
            return Err(Error::UnsupportedPacket);
        }
        let packet_type = match payload[1] {
            0 => PacketType::Configuration,
            1 => PacketType::Raw,
            _ => return Err(Error::UnsupportedPacket),
        };
        let body_len = payload.len() - AAC_HEADER;
        if body_len == 0 {
            return Err(Error::EmptyBody);
        }
        if body_len > limits.max_body_bytes {
            return Err(Error::BodyLimit);
        }
        Ok(Self {
            source: tag.wire_bytes(),
            timestamp_ms: tag.timestamp_ms(),
            sender_header: payload[0],
            packet_type,
        })
    }

    /// Exact original tag, including header and previous-tag-size field.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.source
    }
    /// Sender-supplied FLV sound-format header; its low bits are not trusted.
    pub fn sender_header(self) -> u8 {
        self.sender_header
    }
    /// Wrapping camera-provided milliseconds, not authenticated capture time.
    pub fn timestamp_ms(self) -> u32 {
        self.timestamp_ms
    }
    /// Sender-supplied AAC packet kind.
    pub fn packet_type(self) -> PacketType {
        self.packet_type
    }
    /// Exact AAC body range relative to the original complete tag.
    pub fn body_range(self) -> Range<usize> {
        FLV_TAG_HEADER + AAC_HEADER..self.source.len() - 4
    }
    /// Borrow the exact original AAC body, without decoding or copying it.
    pub fn body(self) -> &'a [u8] {
        &self.source[self.body_range()]
    }
    /// Interpret a complete supported AAC-LC configuration.
    pub fn configuration(self) -> Result<Configuration<'a>, Error> {
        if self.packet_type != PacketType::Configuration {
            return Err(Error::WrongPacketType);
        }
        Configuration::parse_at(
            self.body(),
            self.body_range(),
            ConfigurationOrigin::AudioTag,
        )
    }
}

/// The coordinate system for a configuration's source range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationOrigin {
    /// The range is relative to the complete original FLV audio tag.
    AudioTag,
    /// The range is relative to the caller-supplied configuration byte slice.
    ExplicitBytes,
}

/// Interpreted AAC-LC configuration and its source-relative byte range.
#[derive(Clone, Eq, PartialEq)]
pub struct Configuration<'a> {
    bytes: &'a [u8],
    source_range: Range<usize>,
    origin: ConfigurationOrigin,
    sample_rate: u32,
    channel_configuration: u8,
    channels: u8,
    frame_samples: u16,
}
impl fmt::Debug for Configuration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Configuration")
            .field("origin", &self.origin)
            .field("sample_rate", &self.sample_rate)
            .field("channel_configuration", &self.channel_configuration)
            .field("channels", &self.channels)
            .field("frame_samples", &self.frame_samples)
            .finish_non_exhaustive()
    }
}
impl<'a> Configuration<'a> {
    /// Parse explicitly supplied AudioSpecificConfig bytes without fabricating
    /// an FLV tag. The caller must bind these bytes to the sample's actual
    /// connection and configuration epoch before using them for media output.
    /// This function establishes neither provenance nor camera identity.
    pub fn parse_explicit(body: &'a [u8]) -> Result<Self, Error> {
        Self::parse_at(body, 0..body.len(), ConfigurationOrigin::ExplicitBytes)
    }

    fn parse_at(
        body: &'a [u8],
        source_range: Range<usize>,
        origin: ConfigurationOrigin,
    ) -> Result<Self, Error> {
        // 0x2b7 (11 bits), AOT_SBR=5 (5 bits), sbrPresentFlag=0,
        // followed by seven zero padding bits. Active SBR and any unknown
        // extension or nonzero trailing bits must not be treated as AAC-LC.
        if body.len() != 2 && !(body.len() == MAX_SUPPORTED_CONFIGURATION_BYTES && body[2..] == [0x56, 0xe5, 0x00]) {
            return Err(Error::UnsupportedConfiguration);
        }
        if body[0] >> 3 != 2 {
            return Err(Error::UnsupportedObjectType);
        }
        let rate_index = usize::from((body[0] & 7) << 1 | body[1] >> 7);
        let sample_rate = *RATES.get(rate_index).ok_or(Error::UnsupportedSampleRate)?;
        let channel_configuration = (body[1] >> 3) & 15;
        let channels = match channel_configuration {
            1..=6 => channel_configuration,
            7 => 8,
            _ => return Err(Error::UnsupportedChannelConfiguration),
        };
        if body[1] & 3 != 0 {
            return Err(Error::UnsupportedGaFlags);
        }
        Ok(Configuration {
            bytes: body,
            source_range,
            origin,
            sample_rate,
            channel_configuration,
            channels,
            frame_samples: if body[1] & 4 == 0 { 1024 } else { 960 },
        })
    }
    /// Exact original configuration bytes, regardless of source.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Configuration range in the coordinate system returned by [`Self::origin`].
    pub fn source_range(&self) -> Range<usize> {
        self.source_range.clone()
    }
    /// Distinguish a source tag from caller-supplied configuration bytes.
    pub fn origin(&self) -> ConfigurationOrigin {
        self.origin
    }
    /// Indexed AAC sample rate from the supplied configuration.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
    /// Original MPEG-4 channel-configuration index.
    pub fn channel_configuration(&self) -> u8 {
        self.channel_configuration
    }
    /// Channel count represented by the supported configuration index.
    pub fn channels(&self) -> u8 {
        self.channels
    }
    /// Samples per AAC-LC frame; this does not validate a raw tag's contents.
    pub fn frame_samples(&self) -> u16 {
        self.frame_samples
    }
}
