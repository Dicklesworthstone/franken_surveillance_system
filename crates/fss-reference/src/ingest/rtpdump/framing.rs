#![forbid(unsafe_code)]
//! Bounded recorded RTP framing. Capture addresses and timestamps grant no authority.
//!
//! No sockets, credentials, ambient clock, or packet mutation. The caller retains
//! the complete original file, including malformed/truncated records and RTCP.

use std::ops::Range;

/// Independent bounds for a borrowed, already-read file snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpDumpLimits {
    /// Maximum snapshot bytes; never more than 512 MiB.
    pub max_input_bytes: usize,
    /// Maximum complete record headers examined; never more than 65,536.
    pub max_records: usize,
    /// Maximum captured bytes in one record; at most 65,527 (u16 record length minus header).
    pub max_packet_bytes: usize,
}
impl Default for RtpDumpLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_records: 65_536,
            max_packet_bytes: 65_527,
        }
    }
}
impl RtpDumpLimits {
    /// Refuse unsupported policies rather than silently widen or clamp them.
    pub fn validate(self) -> Result<(), RtpDumpError> {
        if !(1..=512 * 1024 * 1024).contains(&self.max_input_bytes)
            || !(1..=65_536).contains(&self.max_records)
            || !(1..=65_527).contains(&self.max_packet_bytes)
        {
            return Err(RtpDumpError::new(RtpDumpFault::Configuration, 0..0));
        }
        Ok(())
    }
}

/// Payload-free format failure. No address, path, timestamp text, or media is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpDumpFault {
    /// Invalid caller-supplied limits.
    Configuration,
    /// Input, record count, or captured packet bytes exceeded an explicit limit.
    Limit,
    /// Missing/invalid version-one rtptools header or nonnumeric port.
    Header,
    /// Incomplete text/binary file header.
    TruncatedHeader,
    /// Incomplete eight-byte record prefix.
    TruncatedRecordHeader,
    /// Incomplete captured packet at end of file.
    TruncatedRecord,
    /// Declared record length is less than eight, or plen contradicts captured bytes.
    RecordLength,
    /// No further parsing after a framing failure; retain and inspect the original.
    Stopped,
}

/// Exact affected source span. The complete caller-owned input remains available on every error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpDumpError {
    /// Stable reason, safe to log.
    pub fault: RtpDumpFault,
    /// Bytes implicated in this refusal, including the unparsed terminal suffix.
    pub span: Range<usize>,
}
impl RtpDumpError {
    fn new(fault: RtpDumpFault, span: Range<usize>) -> Self {
        Self { fault, span }
    }
}
impl std::fmt::Display for RtpDumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rtpdump refusal: {:?} at {}..{}",
            self.fault, self.span.start, self.span.end
        )
    }
}
impl std::error::Error for RtpDumpError {}

/// The record's plen discriminator is authoritative only for its container kind,
/// not for packet validity, transport authenticity, or decoded completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpDumpKind {
    /// Full RTP datagram. The packet kernel must still validate it.
    Rtp,
    /// RTCP (plen == 0), including when packet bytes resemble RTP.
    Rtcp,
    /// Snaplen-limited RTP: preserve but never submit partial data to the packet kernel.
    CapturedPrefix,
}

/// Borrowed original record. Debug exposes offsets/counts only, never its packet bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct RtpDumpRecord<'a> {
    index: usize,
    span: Range<usize>,
    packet_span: Range<usize>,
    offset_ms: u32,
    original_len: u16,
    kind: RtpDumpKind,
    packet: &'a [u8],
}
impl<'a> RtpDumpRecord<'a> {
    /// Zero-based file record number; not an RTP sequence.
    pub fn index(&self) -> usize {
        self.index
    }
    /// Whole record prefix and captured packet bytes in the original file.
    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }
    /// Captured datagram bytes in the original file (excluding the record prefix).
    pub fn packet_span(&self) -> Range<usize> {
        self.packet_span.clone()
    }
    /// Exact original captured bytes, never reconstructed or repacketized.
    pub fn packet(&self) -> &'a [u8] {
        self.packet
    }
    /// Untrusted capture-relative milliseconds; not FSS receive time, DTS, or capture truth.
    pub fn offset_ms(&self) -> u32 {
        self.offset_ms
    }
    /// Full RTP length declared by the recorder; zero is the RTCP discriminator.
    pub fn original_len(&self) -> u16 {
        self.original_len
    }
    /// Container kind, prior to packet validation.
    pub fn kind(&self) -> RtpDumpKind {
        self.kind
    }
}
impl std::fmt::Debug for RtpDumpRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtpDumpRecord")
            .field("index", &self.index)
            .field("span", &self.span)
            .field("kind", &self.kind)
            .field("packet_bytes", &self.packet.len())
            .finish()
    }
}

/// Allocation-free record reader over an immutable borrowed snapshot.
///
/// A valid record boundary is required for progress. Malformed/truncated framing
/// stops at the exact suffix; no scanning for plausible RTP headers can silently
/// resurrect bytes after a bad length. Valid capture-truncated records are instead
/// surfaced individually so later independently framed records remain available.
pub struct RtpDumpReader<'a> {
    input: &'a [u8],
    limits: RtpDumpLimits,
    header_end: usize,
    cursor: usize,
    records: usize,
    stopped: bool,
}
impl<'a> RtpDumpReader<'a> {
    /// Validate bounded text header and the standard sixteen-byte network-endian preamble.
    /// The address/port and preamble timestamp are retained only in the caller's
    /// original bytes, not promoted into a network target or trusted time mapping.
    pub fn new(input: &'a [u8], limits: RtpDumpLimits) -> Result<Self, RtpDumpError> {
        limits.validate()?;
        if input.len() > limits.max_input_bytes {
            return Err(RtpDumpError::new(RtpDumpFault::Limit, 0..input.len()));
        }
        let line_end = input
            .iter()
            .take(257)
            .position(|b| *b == b'\n')
            .ok_or_else(|| {
                RtpDumpError::new(
                    if input.len() > 256 {
                        RtpDumpFault::Header
                    } else {
                        RtpDumpFault::TruncatedHeader
                    },
                    0..input.len().min(257),
                )
            })?;
        if line_end > 255 {
            return Err(RtpDumpError::new(RtpDumpFault::Header, 0..line_end + 1));
        }
        let line = input[..line_end]
            .strip_suffix(b"\r")
            .unwrap_or(&input[..line_end]);
        let endpoint = line
            .strip_prefix(b"#!rtpplay1.0 ")
            .ok_or_else(|| RtpDumpError::new(RtpDumpFault::Header, 0..line_end + 1))?;
        let valid_endpoint = endpoint
            .iter()
            .rposition(|b| *b == b'/')
            .is_some_and(|slash| {
                let (host, port) = (&endpoint[..slash], &endpoint[slash + 1..]);
                !host.is_empty()
                    && host
                        .iter()
                        .all(|b| b.is_ascii_graphic() && !matches!(*b, b'@' | b'/' | b'\\'))
                    && !port.is_empty()
                    && port.len() <= 5
                    && port.iter().all(u8::is_ascii_digit)
                    && port
                        .iter()
                        .fold(0_u32, |n, b| n * 10 + u32::from(*b - b'0'))
                        <= u32::from(u16::MAX)
            });
        if !valid_endpoint {
            return Err(RtpDumpError::new(RtpDumpFault::Header, 0..line_end + 1));
        }
        let header_end = line_end + 1 + 16;
        if input.len() < header_end {
            return Err(RtpDumpError::new(
                RtpDumpFault::TruncatedHeader,
                0..input.len(),
            ));
        }
        let preamble = &input[line_end + 1..header_end];
        let micros = u32::from_be_bytes([preamble[4], preamble[5], preamble[6], preamble[7]]);
        if micros >= 1_000_000 {
            return Err(RtpDumpError::new(
                RtpDumpFault::Header,
                line_end + 1..header_end,
            ));
        }
        Ok(Self {
            input,
            limits,
            header_end,
            cursor: header_end,
            records: 0,
            stopped: false,
        })
    }
    /// Original text and binary header range; no endpoint is exposed by Debug.
    pub fn header_span(&self) -> Range<usize> {
        0..self.header_end
    }
    /// End of the last completely framed record, or start of the refused suffix.
    pub fn consumed_bytes(&self) -> usize {
        self.cursor
    }
    /// Complete records returned (including RTCP and snaplen-truncated packets).
    pub fn records_read(&self) -> usize {
        self.records
    }
    /// Read one original record, yielding None only at clean EOF.
    pub fn next_record(&mut self) -> Result<Option<RtpDumpRecord<'a>>, RtpDumpError> {
        if self.stopped {
            return Err(RtpDumpError::new(
                RtpDumpFault::Stopped,
                self.cursor..self.input.len(),
            ));
        }
        if self.cursor == self.input.len() {
            return Ok(None);
        }
        let at = self.cursor;
        let fault = if self.records == self.limits.max_records {
            Some(RtpDumpFault::Limit)
        } else if self.input.len() - at < 8 {
            Some(RtpDumpFault::TruncatedRecordHeader)
        } else {
            None
        };
        if let Some(fault) = fault {
            return self.stop(fault);
        }
        let h = &self.input[at..at + 8];
        let length = usize::from(u16::from_be_bytes([h[0], h[1]]));
        let original_len = u16::from_be_bytes([h[2], h[3]]);
        if length < 8 {
            return self.stop(RtpDumpFault::RecordLength);
        }
        let captured = length - 8;
        if captured > self.limits.max_packet_bytes {
            return self.stop(RtpDumpFault::Limit);
        }
        if original_len != 0 && captured > usize::from(original_len) {
            return self.stop(RtpDumpFault::RecordLength);
        }
        if length > self.input.len() - at {
            return self.stop(RtpDumpFault::TruncatedRecord);
        }
        let kind = if original_len == 0 {
            RtpDumpKind::Rtcp
        } else if captured < usize::from(original_len) {
            RtpDumpKind::CapturedPrefix
        } else {
            RtpDumpKind::Rtp
        };
        let record = RtpDumpRecord {
            index: self.records,
            span: at..at + length,
            packet_span: at + 8..at + length,
            offset_ms: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            original_len,
            kind,
            packet: &self.input[at + 8..at + length],
        };
        self.records += 1;
        self.cursor += length;
        Ok(Some(record))
    }
    fn stop<T>(&mut self, fault: RtpDumpFault) -> Result<T, RtpDumpError> {
        self.stopped = true;
        Err(RtpDumpError::new(fault, self.cursor..self.input.len()))
    }
}
impl std::fmt::Debug for RtpDumpReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtpDumpReader")
            .field("input_bytes", &self.input.len())
            .field("cursor", &self.cursor)
            .field("records", &self.records)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}
