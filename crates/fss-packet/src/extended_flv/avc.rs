//! Bounded, source-preserving AVC video payload views for FLV tags.
//!
//! This parses framing and basic AVCDecoderConfigurationRecord structure, not
//! H.264 slice syntax or decoding. Offsets always address the complete original
//! tag passed by the caller. No sender authenticity, source continuity, complete
//! picture, capture-time mapping, or retention is established here.

use std::{fmt, ops::Range};

use super::Tag;

const FLV_TAG_HEADER: usize = 11;
const AVC_VIDEO_HEADER: usize = 5;
const BODY_START: usize = FLV_TAG_HEADER + AVC_VIDEO_HEADER;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_PARAMETER_SETS: usize = 256;
const MAX_NALS: usize = 65_536;
const MAX_NAL_BYTES: usize = 4 * 1024 * 1024;

/// Independent resource limits for a configuration or video tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum AVC configuration bytes, at most 256 KiB.
    pub max_config_bytes: usize,
    /// Maximum SPS and PPS entries combined, at most 256.
    pub max_parameter_sets: usize,
    /// Maximum NAL units in one video tag, at most 65536.
    pub max_nals: usize,
    /// Maximum individual NAL length, at most 4 MiB.
    pub max_nal_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_config_bytes: MAX_CONFIG_BYTES,
            max_parameter_sets: MAX_PARAMETER_SETS,
            max_nals: MAX_NALS,
            max_nal_bytes: MAX_NAL_BYTES,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<(), Error> {
        if !(7..=MAX_CONFIG_BYTES).contains(&self.max_config_bytes)
            || !(2..=MAX_PARAMETER_SETS).contains(&self.max_parameter_sets)
            || !(1..=MAX_NALS).contains(&self.max_nals)
            || !(1..=MAX_NAL_BYTES).contains(&self.max_nal_bytes)
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// Payload-free refusals; no source bytes are included in errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Limits are zero, inconsistent, or exceed implementation ceilings.
    InvalidLimits,
    /// The supplied tag is not a video tag.
    NotVideo,
    /// The complete video tag lacks its five-byte AVC video header.
    TruncatedVideoHeader,
    /// The video codec is not AVC or the AVC packet type is unsupported.
    UnsupportedVideo,
    /// The operation does not match the AVC packet type.
    WrongPacketType,
    /// An AVC configuration exceeds a declared byte or parameter-set limit.
    ConfigurationLimit,
    /// Configuration framing, reserved bits, or parameter-set types are invalid.
    InvalidConfiguration,
    /// A NAL length, count, header, or sample boundary is invalid or over budget.
    InvalidNalUnits,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended FLV AVC refusal: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Supported AVC packet types in one FLV video tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    /// Decoder configuration record containing SPS/PPS entries.
    Configuration,
    /// One length-prefixed NAL sample; picture completeness is not implied.
    NalUnits,
    /// AVC end-of-sequence marker.
    EndOfSequence,
}

/// AVC video header and original tag. The sender's frame-type nibble is metadata.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VideoTag<'a> {
    source: &'a [u8],
    timestamp_ms: u32,
    frame_type: u8,
    packet_type: PacketType,
    composition_ms: i32,
}

impl<'a> VideoTag<'a> {
    /// Parse the AVC header of a previously structurally validated video tag.
    pub fn parse(tag: Tag<'a>) -> Result<Self, Error> {
        if tag.kind() != 9 {
            return Err(Error::NotVideo);
        }
        let payload = tag.payload();
        if payload.len() < AVC_VIDEO_HEADER {
            return Err(Error::TruncatedVideoHeader);
        }
        if payload[0] & 0x0f != 7 {
            return Err(Error::UnsupportedVideo);
        }
        let packet_type = match payload[1] {
            0 => PacketType::Configuration,
            1 => PacketType::NalUnits,
            2 => PacketType::EndOfSequence,
            _ => return Err(Error::UnsupportedVideo),
        };
        let raw =
            (i32::from(payload[2]) << 16) | (i32::from(payload[3]) << 8) | i32::from(payload[4]);
        let composition_ms = if raw & 0x80_0000 != 0 {
            raw - 0x100_0000
        } else {
            raw
        };
        Ok(Self {
            source: tag.wire_bytes(),
            timestamp_ms: tag.timestamp_ms(),
            frame_type: payload[0] >> 4,
            packet_type,
            composition_ms,
        })
    }

    /// Exact source tag, including FLV header and back-reference.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.source
    }
    /// Camera-provided frame-type nibble; it is not a random-access proof.
    pub fn frame_type(self) -> u8 {
        self.frame_type
    }
    /// Type of the AVC packet carried by this tag.
    pub fn packet_type(self) -> PacketType {
        self.packet_type
    }
    /// Wrapping source media timestamp in milliseconds, not capture or UTC time.
    pub fn timestamp_ms(self) -> u32 {
        self.timestamp_ms
    }
    /// Signed presentation-minus-decode offset in milliseconds.
    pub fn composition_offset_ms(self) -> i32 {
        self.composition_ms
    }
    /// Exact AVC body range relative to the complete original tag.
    pub fn body_range(self) -> Range<usize> {
        BODY_START..self.source.len() - 4
    }
    /// Original AVC body. Its meaning depends on [`Self::packet_type`].
    pub fn body(self) -> &'a [u8] {
        &self.source[self.body_range()]
    }

    /// Parse a configuration packet, including all SPS/PPS framing before returning.
    pub fn configuration(self, limits: Limits) -> Result<Configuration<'a>, Error> {
        limits.validate()?;
        if self.packet_type != PacketType::Configuration {
            return Err(Error::WrongPacketType);
        }
        let body = self.body();
        if body.len() > limits.max_config_bytes {
            return Err(Error::ConfigurationLimit);
        }
        if body.len() < 7 || body[0] != 1 || body[4] & 0xfc != 0xfc || body[5] & 0xe0 != 0xe0 {
            return Err(Error::InvalidConfiguration);
        }
        let width = match body[4] & 3 {
            0 => 1,
            1 => 2,
            3 => 4,
            _ => return Err(Error::InvalidConfiguration),
        };
        let sps_count = usize::from(body[5] & 0x1f);
        if sps_count == 0 {
            return Err(Error::InvalidConfiguration);
        }
        let sps_start = BODY_START + 6;
        let mut cursor = sps_start;
        walk_sets(self.source, &mut cursor, sps_count, 7, limits)?;
        let body_end = self.source.len() - 4;
        let pps_count = usize::from(
            *self
                .source
                .get(cursor)
                .filter(|_| cursor < body_end)
                .ok_or(Error::InvalidConfiguration)?,
        );
        cursor += 1;
        if pps_count == 0 {
            return Err(Error::InvalidConfiguration);
        }
        if sps_count + pps_count > limits.max_parameter_sets {
            return Err(Error::ConfigurationLimit);
        }
        let pps_start = cursor;
        walk_sets(self.source, &mut cursor, pps_count, 8, limits)?;
        Ok(Configuration {
            source: self.source,
            width,
            sps_start,
            sps_count,
            pps_start,
            pps_count,
            extension_start: cursor,
        })
    }

    /// Validate every length-prefixed NAL before exposing any of them.
    ///
    /// The owner must bind the supplied configuration to the same camera,
    /// stream generation, and configuration epoch; this method cannot do so.
    pub fn nal_units(
        self,
        configuration: &Configuration<'_>,
        limits: Limits,
    ) -> Result<NalUnits<'a>, Error> {
        limits.validate()?;
        if self.packet_type != PacketType::NalUnits {
            return Err(Error::WrongPacketType);
        }
        let end = self.source.len() - 4;
        let mut cursor = BODY_START;
        let mut count = 0_usize;
        let mut has_idr_type = false;
        while cursor < end {
            let (start, next) = sample_nal(
                self.source,
                cursor,
                end,
                configuration.width,
                limits.max_nal_bytes,
            )?;
            count += 1;
            if count > limits.max_nals {
                return Err(Error::InvalidNalUnits);
            }
            has_idr_type |= self.source[start] & 0x1f == 5;
            cursor = next;
        }
        if count == 0 {
            return Err(Error::InvalidNalUnits);
        }
        Ok(NalUnits {
            source: self.source,
            width: configuration.width,
            count,
            has_idr_type,
        })
    }
}

impl fmt::Debug for VideoTag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoTag")
            .field("tag_bytes", &self.source.len())
            .field("timestamp_ms", &self.timestamp_ms)
            .field("frame_type", &self.frame_type)
            .field("packet_type", &self.packet_type)
            .field("composition_ms", &self.composition_ms)
            .finish()
    }
}

fn walk_sets(
    source: &[u8],
    cursor: &mut usize,
    count: usize,
    kind: u8,
    limits: Limits,
) -> Result<(), Error> {
    let end = source.len() - 4;
    for _ in 0..count {
        let length_end = cursor
            .checked_add(2)
            .filter(|&n| n <= end)
            .ok_or(Error::InvalidConfiguration)?;
        let len = usize::from(u16::from_be_bytes([source[*cursor], source[*cursor + 1]]));
        let next = length_end
            .checked_add(len)
            .filter(|&n| n <= end)
            .ok_or(Error::InvalidConfiguration)?;
        if len == 0 || source[length_end] & 0x80 != 0 || source[length_end] & 0x1f != kind {
            return Err(Error::InvalidConfiguration);
        }
        if len > limits.max_nal_bytes {
            return Err(Error::ConfigurationLimit);
        }
        *cursor = next;
    }
    Ok(())
}

/// Validated AVC configuration framing with borrowed original parameter sets.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Configuration<'a> {
    source: &'a [u8],
    width: usize,
    sps_start: usize,
    sps_count: usize,
    pps_start: usize,
    pps_count: usize,
    extension_start: usize,
}

impl<'a> Configuration<'a> {
    /// Exact original AVCDecoderConfigurationRecord, including uninterpreted extensions.
    pub fn wire_bytes(self) -> &'a [u8] {
        &self.source[BODY_START..self.source.len() - 4]
    }
    /// Length-field width, one of 1, 2 or 4 bytes.
    pub fn nal_length_bytes(self) -> usize {
        self.width
    }
    /// Source-linked SPS entries. Framing does not establish H.264 syntax validity.
    pub fn sps(self) -> ParameterSets<'a> {
        ParameterSets {
            source: self.source,
            cursor: self.sps_start,
            remaining: self.sps_count,
        }
    }
    /// Source-linked PPS entries. Framing does not establish SPS/PPS compatibility.
    pub fn pps(self) -> ParameterSets<'a> {
        ParameterSets {
            source: self.source,
            cursor: self.pps_start,
            remaining: self.pps_count,
        }
    }
    /// Remaining original bytes after PPS entries; extension syntax is not parsed.
    pub fn extension(self) -> &'a [u8] {
        &self.source[self.extension_start..self.source.len() - 4]
    }
}

impl fmt::Debug for Configuration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Configuration")
            .field("nal_length_bytes", &self.width)
            .field("sps_count", &self.sps_count)
            .field("pps_count", &self.pps_count)
            .field("extension_bytes", &self.extension().len())
            .finish()
    }
}

/// A NAL's exact byte range and bytes in the original complete tag.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceNal<'a> {
    range: Range<usize>,
    source: &'a [u8],
}

impl<'a> SourceNal<'a> {
    /// Offset range into the complete original tag; excludes length prefix.
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
    /// Exact original NAL bytes.
    pub fn bytes(&self) -> &'a [u8] {
        &self.source[self.range.clone()]
    }
}

impl fmt::Debug for SourceNal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceNal")
            .field("range", &self.range)
            .finish()
    }
}

/// Allocation-free traversal of already-validated SPS or PPS entries.
pub struct ParameterSets<'a> {
    source: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for ParameterSets<'a> {
    type Item = SourceNal<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([
            *self.source.get(self.cursor)?,
            *self.source.get(self.cursor + 1)?,
        ]));
        let start = self.cursor.checked_add(2)?;
        let end = start.checked_add(len)?;
        self.source.get(start..end)?;
        self.cursor = end;
        self.remaining -= 1;
        Some(SourceNal {
            range: start..end,
            source: self.source,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ParameterSets<'_> {}

fn sample_nal(
    source: &[u8],
    cursor: usize,
    end: usize,
    width: usize,
    max_nal: usize,
) -> Result<(usize, usize), Error> {
    let start = cursor
        .checked_add(width)
        .filter(|&n| n <= end)
        .ok_or(Error::InvalidNalUnits)?;
    let mut len = 0_usize;
    for &byte in &source[cursor..start] {
        len = len * 256 + usize::from(byte);
    }
    let next = start
        .checked_add(len)
        .filter(|&n| n <= end)
        .ok_or(Error::InvalidNalUnits)?;
    if len == 0 || len > max_nal || source[start] & 0x80 != 0 {
        return Err(Error::InvalidNalUnits);
    }
    Ok((start, next))
}

/// An entirely validated NAL-length walk over one original video tag.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NalUnits<'a> {
    source: &'a [u8],
    width: usize,
    count: usize,
    has_idr_type: bool,
}

impl<'a> NalUnits<'a> {
    /// Number of source NAL units.
    pub fn len(self) -> usize {
        self.count
    }
    /// Always false for an admitted NAL sample.
    pub fn is_empty(self) -> bool {
        false
    }
    /// Whether a NAL header reported type 5; not proof of a decodable IDR picture.
    pub fn contains_idr_nal_type(self) -> bool {
        self.has_idr_type
    }
    /// Source-linked NALs in original order.
    pub fn iter(self) -> NalIter<'a> {
        NalIter {
            units: self,
            cursor: BODY_START,
            remaining: self.count,
        }
    }
}

impl fmt::Debug for NalUnits<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NalUnits")
            .field("count", &self.count)
            .field("contains_idr_type", &self.has_idr_type)
            .finish()
    }
}

/// Allocation-free traversal of an already-validated NAL sample.
pub struct NalIter<'a> {
    units: NalUnits<'a>,
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for NalIter<'a> {
    type Item = SourceNal<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (start, end) = sample_nal(
            self.units.source,
            self.cursor,
            self.units.source.len() - 4,
            self.units.width,
            MAX_NAL_BYTES,
        )
        .ok()?;
        self.cursor = end;
        self.remaining -= 1;
        Some(SourceNal {
            range: start..end,
            source: self.units.source,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for NalIter<'_> {}
