use std::{fmt, ops::Range};

use crate::error::{PacketError, PacketLimits, be16, be32, span};

/// Contributing-source word size in bytes.
const CSRC_BYTES: usize = 4;

/// An uninterpreted, length-validated RTP header extension.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HeaderExtension<'a> {
    /// Profile-specific extension identifier; not an authentication claim.
    pub profile: u16,
    /// Exact extension bytes, excluding its four-byte preamble.
    pub bytes: &'a [u8],
}

impl fmt::Debug for HeaderExtension<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderExtension")
            .field("profile", &self.profile)
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A validated, zero-allocation RTP v2 view borrowing its complete source packet.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtpPacket<'a> {
    bytes: &'a [u8],
    payload_start: usize,
    payload_end: usize,
    extension: Option<HeaderExtension<'a>>,
}

impl<'a> RtpPacket<'a> {
    /// Validate all CSRC, extension, and padding spans before exposing any payload.
    pub fn parse(bytes: &'a [u8], limits: PacketLimits) -> Result<Self, PacketError> {
        limits.check(bytes)?;
        let fixed = span(bytes, 0, 12)?;
        if fixed[0] >> 6 != 2 {
            return Err(PacketError::Version);
        }
        let mut offset = 12 + usize::from(fixed[0] & 0x0f) * 4;
        span(bytes, 0, offset)?;
        let extension = if fixed[0] & 0x10 != 0 {
            let header = span(bytes, offset, 4)?;
            let length = usize::from(be16(&header[2..])) * 4;
            if length > limits.max_extension_bytes {
                return Err(PacketError::ExtensionLimit);
            }
            offset += 4;
            let extension = HeaderExtension {
                profile: be16(header),
                bytes: span(bytes, offset, length)?,
            };
            offset += length;
            Some(extension)
        } else {
            None
        };
        let mut end = bytes.len();
        if fixed[0] & 0x20 != 0 {
            let padding = usize::from(bytes[bytes.len() - 1]);
            if padding == 0 || padding > end - offset {
                return Err(PacketError::Padding);
            }
            end -= padding;
        }
        Ok(Self {
            bytes,
            payload_start: offset,
            payload_end: end,
            extension,
        })
    }

    /// Exact source bytes, including headers, extensions, and padding.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Negotiated payload type number; the caller owns its codec interpretation.
    pub fn payload_type(self) -> u8 {
        self.bytes[1] & 0x7f
    }

    /// Profile-specific marker bit, not a generic keyframe/completeness claim.
    pub fn marker(self) -> bool {
        self.bytes[1] & 0x80 != 0
    }

    /// Raw wrapping sequence number.
    pub fn sequence(self) -> u16 {
        be16(&self.bytes[2..4])
    }

    /// Raw wrapping media-clock timestamp, not a wall-clock timestamp.
    pub fn timestamp(self) -> u32 {
        be32(&self.bytes[4..8])
    }

    /// Synchronization-source identifier, not proof of sender identity.
    pub fn ssrc(self) -> u32 {
        be32(&self.bytes[8..12])
    }

    /// Contributing sources in wire order, without allocation.
    pub fn csrcs(self) -> impl ExactSizeIterator<Item = u32> + 'a {
        let end = 12 + usize::from(self.bytes[0] & 0x0f) * 4;
        self.bytes[12..end]
            .as_chunks::<CSRC_BYTES>()
            .0
            .iter()
            .map(|word| be32(word))
    }

    /// Profile-specific extension, retained without interpreting untrusted text.
    pub fn extension(self) -> Option<HeaderExtension<'a>> {
        self.extension
    }

    /// Payload range into `wire_bytes`, excluding packet padding.
    pub fn payload_range(self) -> Range<usize> {
        self.payload_start..self.payload_end
    }

    /// Encoded payload; parsing this packet does not validate its codec.
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.payload_range()]
    }

    /// Exact number of validated trailing padding bytes.
    pub fn padding_len(self) -> usize {
        self.bytes.len() - self.payload_end
    }
}

impl fmt::Debug for RtpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtpPacket")
            .field("ssrc", &self.ssrc())
            .field("sequence", &self.sequence())
            .field("timestamp", &self.timestamp())
            .field("payload_type", &self.payload_type())
            .field("marker", &self.marker())
            .field("payload_bytes", &self.payload().len())
            .finish_non_exhaustive()
    }
}
