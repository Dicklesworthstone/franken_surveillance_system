use std::fmt;

/// Hard input/work ceilings, checked before any packet traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketLimits {
    /// Maximum complete datagram bytes (at most one MiB).
    pub max_packet_bytes: usize,
    /// Maximum opaque RTP extension bytes (at most 262,140).
    pub max_extension_bytes: usize,
    /// Maximum RTCP packets in one datagram (at most 256).
    pub max_rtcp_packets: usize,
}

impl Default for PacketLimits {
    fn default() -> Self {
        Self {
            max_packet_bytes: 65_535,
            max_extension_bytes: 16_384,
            max_rtcp_packets: 64,
        }
    }
}

impl PacketLimits {
    /// Reject invalid or unbounded policies rather than silently widening them.
    pub fn validate(self) -> Result<(), PacketError> {
        if !(12..=1_048_576).contains(&self.max_packet_bytes)
            || self.max_extension_bytes > 262_140
            || !(1..=256).contains(&self.max_rtcp_packets)
        {
            return Err(PacketError::InvalidLimits);
        }
        Ok(())
    }

    pub(crate) fn check(self, bytes: &[u8]) -> Result<(), PacketError> {
        self.validate()?;
        if bytes.len() > self.max_packet_bytes {
            return Err(PacketError::ByteLimit);
        }
        Ok(())
    }
}

/// Stable, payload-free packet refusal categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    /// Policy is zero, contradictory, or above the implementation hard ceiling.
    InvalidLimits,
    /// Complete datagram exceeds the caller's byte ceiling.
    ByteLimit,
    /// A declared header, item, or payload span is not present.
    Truncated,
    /// The packet is not RTP/RTCP version two.
    Version,
    /// RTP extension exceeds its independent ceiling.
    ExtensionLimit,
    /// Padding is zero-sized, overlong, misplaced, or misaligned.
    Padding,
    /// RTCP compound packet count exceeds the caller's ceiling.
    PacketCount,
    /// Conventional compound framing lacks a report or its sender's CNAME.
    Compound,
    /// An RTCP sender/receiver report has an impossible declared layout.
    Report,
    /// An RTCP source-description chunk is malformed.
    SourceDescription,
    /// An RTCP goodbye source/reason layout is malformed.
    Goodbye,
    /// An RTCP application packet lacks its mandatory fixed fields.
    Application,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLimits => "invalid packet limits",
            Self::ByteLimit => "packet byte budget exceeded",
            Self::Truncated => "truncated packet field",
            Self::Version => "unsupported RTP/RTCP version",
            Self::ExtensionLimit => "RTP extension budget exceeded",
            Self::Padding => "invalid packet padding",
            Self::PacketCount => "RTCP packet budget exceeded",
            Self::Compound => "invalid conventional RTCP compound",
            Self::Report => "invalid RTCP report layout",
            Self::SourceDescription => "invalid RTCP source description",
            Self::Goodbye => "invalid RTCP goodbye layout",
            Self::Application => "invalid RTCP application layout",
        };
        f.write_str(message)
    }
}

impl std::error::Error for PacketError {}

pub(crate) fn span(bytes: &[u8], start: usize, len: usize) -> Result<&[u8], PacketError> {
    let end = start.checked_add(len).ok_or(PacketError::Truncated)?;
    bytes.get(start..end).ok_or(PacketError::Truncated)
}

pub(crate) fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub(crate) fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
