use std::{fmt, slice::Iter};

use crate::error::{PacketError, PacketLimits, be16, be32, span};

/// Whether conventional compound RTCP or explicitly negotiated reduced-size framing is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtcpMode {
    /// Require a leading SR/RR and an SDES CNAME for that report's sender.
    Compound,
    /// Permit independently framed reports; negotiation belongs to the session owner.
    ReducedSize,
}

/// Raw NTP fixed-point time. Era and clock trust must be established externally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtpTimestamp {
    /// Unsigned seconds within an NTP era.
    pub seconds: u32,
    /// Fractional seconds in units of 2^-32 seconds.
    pub fraction: u32,
}

impl NtpTimestamp {
    /// Middle 32 bits used by RTCP LSR/DLSR, without guessing an NTP era.
    pub fn middle_32(self) -> u32 {
        (self.seconds << 16) | (self.fraction >> 16)
    }
}

/// Validated wire sender report; its clock mapping is a sender assertion, not capture truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderReport {
    /// Claimed synchronization source.
    pub ssrc: u32,
    /// Sender's NTP timestamp.
    pub ntp: NtpTimestamp,
    /// Corresponding media-clock timestamp.
    pub rtp_timestamp: u32,
    /// Sender packet counter, modulo 2^32.
    pub packet_count: u32,
    /// Sender payload-octet counter, modulo 2^32.
    pub octet_count: u32,
}

/// One reception-report block, preserving signed cumulative loss and raw clock units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceptionReport {
    /// Source to which this report block refers.
    pub ssrc: u32,
    /// Fraction lost since the preceding report, in units of 1/256.
    pub fraction_lost: u8,
    /// Signed 24-bit cumulative loss; duplicates can make this negative.
    pub cumulative_lost: i32,
    /// Extended highest sequence number, modulo 2^32.
    pub extended_highest_sequence: u32,
    /// Interarrival jitter in the negotiated RTP clock's units.
    pub jitter: u32,
    /// Middle 32 bits of the last received sender report's NTP timestamp.
    pub last_sender_report: u32,
    /// Delay since that report in units of 1/65,536 seconds.
    pub delay_since_last_sender_report: u32,
}

/// Fully validated borrowed RTCP datagram. No valid prefix escapes a malformed suffix.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtcpCompound<'a> {
    bytes: &'a [u8],
    packet_count: usize,
}

impl<'a> RtcpCompound<'a> {
    /// Validate every packet, declared report/item count, and padding boundary first.
    pub fn parse(
        bytes: &'a [u8],
        limits: PacketLimits,
        mode: RtcpMode,
    ) -> Result<Self, PacketError> {
        limits.check(bytes)?;
        if bytes.is_empty() {
            return Err(PacketError::Compound);
        }
        let mut offset = 0;
        let mut count = 0;
        let mut first_sender = None;
        let mut cname_seen = false;
        while offset < bytes.len() {
            if count == limits.max_rtcp_packets {
                return Err(PacketError::PacketCount);
            }
            let header = span(bytes, offset, 4)?;
            if header[0] >> 6 != 2 {
                return Err(PacketError::Version);
            }
            let length = (usize::from(be16(&header[2..])) + 1) * 4;
            let raw = span(bytes, offset, length)?;
            let mut content_end = length;
            if header[0] & 0x20 != 0 {
                let padding = usize::from(raw[length - 1]);
                if offset + length != bytes.len()
                    || padding == 0
                    || padding % 4 != 0
                    || padding > length - 4
                {
                    return Err(PacketError::Padding);
                }
                content_end -= padding;
            }
            let packet = RtcpPacket {
                bytes: raw,
                content_end,
            };
            if count == 0 && matches!(packet.packet_type(), 200 | 201) {
                first_sender = Some(be32(span(raw, 4, 4)?));
            } else if count == 0 && mode == RtcpMode::Compound {
                return Err(PacketError::Compound);
            }
            cname_seen |= validate_packet(packet, first_sender)?;
            count += 1;
            offset += length;
        }
        if mode == RtcpMode::Compound && !cname_seen {
            return Err(PacketError::Compound);
        }
        Ok(Self {
            bytes,
            packet_count: count,
        })
    }

    /// Complete original bytes, not a reconstructed compound.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Number of fully validated packets.
    pub fn packet_count(self) -> usize {
        self.packet_count
    }

    /// Iterate without allocation or exposing an unvalidated suffix.
    pub fn packets(self) -> RtcpPackets<'a> {
        RtcpPackets {
            remaining: self.bytes,
            count: self.packet_count,
        }
    }
}

impl fmt::Debug for RtcpCompound<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcpCompound")
            .field("byte_len", &self.bytes.len())
            .field("packet_count", &self.packet_count)
            .finish_non_exhaustive()
    }
}

/// Iterator over already validated RTCP packets.
#[derive(Clone)]
pub struct RtcpPackets<'a> {
    remaining: &'a [u8],
    count: usize,
}

impl<'a> Iterator for RtcpPackets<'a> {
    type Item = RtcpPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        let length = (usize::from(be16(&self.remaining[2..4])) + 1) * 4;
        let bytes = &self.remaining[..length];
        let content_end = if bytes[0] & 0x20 != 0 {
            length - usize::from(bytes[length - 1])
        } else {
            length
        };
        self.remaining = &self.remaining[length..];
        self.count -= 1;
        Some(RtcpPacket { bytes, content_end })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}

impl ExactSizeIterator for RtcpPackets<'_> {}
impl std::iter::FusedIterator for RtcpPackets<'_> {}

/// One validated RTCP packet. Unknown packet types remain opaque, not successful operations.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtcpPacket<'a> {
    bytes: &'a [u8],
    content_end: usize,
}

impl<'a> RtcpPacket<'a> {
    /// Complete packet bytes, including any final padding.
    pub fn wire_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Raw packet type, including unknown extension types.
    pub fn packet_type(self) -> u8 {
        self.bytes[1]
    }

    /// Five-bit report/source count, or profile-specific subtype.
    pub fn count(self) -> u8 {
        self.bytes[0] & 0x1f
    }

    /// Validated packet body, excluding common header and padding.
    pub fn body(self) -> &'a [u8] {
        &self.bytes[4..self.content_end]
    }

    /// Interpret a sender report only when the packet type is SR.
    pub fn sender_report(self) -> Option<SenderReport> {
        if self.packet_type() != 200 {
            return None;
        }
        Some(SenderReport {
            ssrc: be32(&self.bytes[4..8]),
            ntp: NtpTimestamp {
                seconds: be32(&self.bytes[8..12]),
                fraction: be32(&self.bytes[12..16]),
            },
            rtp_timestamp: be32(&self.bytes[16..20]),
            packet_count: be32(&self.bytes[20..24]),
            octet_count: be32(&self.bytes[24..28]),
        })
    }

    /// Iterate declared SR/RR reception blocks; other packet types yield no blocks.
    pub fn report_blocks(self) -> ReportBlocks<'a> {
        let start = match self.packet_type() {
            200 => 28,
            201 => 8,
            _ => {
                return ReportBlocks {
                    chunks: self.bytes[..0].as_chunks::<24>().0.iter(),
                };
            }
        };
        let end = start + usize::from(self.count()) * 24;
        ReportBlocks {
            chunks: self.bytes[start..end].as_chunks::<24>().0.iter(),
        }
    }

    /// Preserve profile-specific report extensions without misreading them as blocks.
    pub fn report_extension(self) -> Option<&'a [u8]> {
        let start = match self.packet_type() {
            200 => 28,
            201 => 8,
            _ => return None,
        } + usize::from(self.count()) * 24;
        Some(&self.bytes[start..self.content_end])
    }
}

impl fmt::Debug for RtcpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcpPacket")
            .field("packet_type", &self.packet_type())
            .field("count", &self.count())
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Allocation-free iterator over validated reception reports.
#[derive(Clone)]
pub struct ReportBlocks<'a> {
    chunks: Iter<'a, [u8; 24]>,
}

impl Iterator for ReportBlocks<'_> {
    type Item = ReceptionReport;

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.chunks.next()?;
        let lost = i32::from_be_bytes([0, b[5], b[6], b[7]]);
        let cumulative_lost = if lost & 0x80_0000 != 0 {
            lost | !0xff_ffff
        } else {
            lost
        };
        Some(ReceptionReport {
            ssrc: be32(&b[0..4]),
            fraction_lost: b[4],
            cumulative_lost,
            extended_highest_sequence: be32(&b[8..12]),
            jitter: be32(&b[12..16]),
            last_sender_report: be32(&b[16..20]),
            delay_since_last_sender_report: be32(&b[20..24]),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.chunks.size_hint()
    }
}

impl ExactSizeIterator for ReportBlocks<'_> {}
impl std::iter::FusedIterator for ReportBlocks<'_> {}

fn validate_packet(packet: RtcpPacket<'_>, sender: Option<u32>) -> Result<bool, PacketError> {
    let content = &packet.bytes[..packet.content_end];
    let count = usize::from(packet.count());
    match packet.packet_type() {
        200 | 201 => {
            let fixed = if packet.packet_type() == 200 { 28 } else { 8 };
            let minimum = fixed + count * 24;
            if content.len() < minimum || !(content.len() - minimum).is_multiple_of(4) {
                return Err(PacketError::Report);
            }
        }
        202 => return validate_sdes(packet.body(), count, sender),
        203 => {
            let offset = 4 + count * 4;
            span(content, 0, offset).map_err(|_| PacketError::Goodbye)?;
            if offset < content.len() {
                let end = offset + 1 + usize::from(content[offset]);
                let aligned = (end + 3) & !3;
                if end > content.len()
                    || aligned != content.len()
                    || content[end..].iter().any(|byte| *byte != 0)
                {
                    return Err(PacketError::Goodbye);
                }
            }
        }
        204 if content.len() < 12 => return Err(PacketError::Application),
        _ => {}
    }
    Ok(false)
}

fn validate_sdes(body: &[u8], count: usize, sender: Option<u32>) -> Result<bool, PacketError> {
    let mut offset = 0;
    let mut cname = false;
    for _ in 0..count {
        let source = span(body, offset, 4).map_err(|_| PacketError::SourceDescription)?;
        let ssrc = be32(source);
        offset += 4;
        loop {
            let kind = *body.get(offset).ok_or(PacketError::SourceDescription)?;
            offset += 1;
            if kind == 0 {
                let aligned = (offset + 3) & !3;
                let pad = span(body, offset, aligned - offset)
                    .map_err(|_| PacketError::SourceDescription)?;
                if pad.iter().any(|byte| *byte != 0) {
                    return Err(PacketError::SourceDescription);
                }
                offset = aligned;
                break;
            }
            let length = usize::from(*body.get(offset).ok_or(PacketError::SourceDescription)?);
            offset += 1;
            span(body, offset, length).map_err(|_| PacketError::SourceDescription)?;
            if kind == 1 && length != 0 && sender == Some(ssrc) {
                cname = true;
            }
            offset += length;
        }
    }
    if offset != body.len() {
        return Err(PacketError::SourceDescription);
    }
    Ok(cname)
}
