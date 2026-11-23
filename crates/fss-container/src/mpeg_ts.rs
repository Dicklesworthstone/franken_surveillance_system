#![forbid(unsafe_code)]
//! Bounded, source-preserving AVC/HEVC MPEG-2 transport stream extraction.
//!
//! This finite-file profile admits explicitly selected 188-byte TS or 192-byte
//! M2TS framing, one selected program and
//! video PID, single-section current PAT/PMT tables, and MPEG-2 video PES headers
//! with optional PTS/DTS. Tables must precede the selected video. Their CRCs,
//! repeats, packet continuity, adaptation bounds and complete PES lengths are
//! checked before returning any extraction. Exact duplicate packets are admitted
//! once; their bytes remain in the original source, not in the elementary stream.
//! Changed tables, discontinuities, scrambling, multi-section tables, adaptation
//! extensions and other optional PES header grammars are explicit refusals.
//!
//! The PMT declares the codec; this module does not validate NALs, establish
//! access-unit boundaries, or certify a complete picture. In particular, a PES
//! is **not** a frame. PTS/DTS remain wrapping 33-bit 90 kHz media-clock values;
//! they are neither unwrapped nor promoted to capture time. Original byte spans
//! exclude all generated data: elementary output is an exact concatenation of
//! selected transport payload bytes after removing PES headers.
//! M2TS's four-byte prefixes remain opaque original custody: they neither
//! participate in transport continuity nor establish capture or media time.
//!
//! Grammar: ITU-T H.222.0 §§2.4.3.2–2.4.3.7 and 2.4.4 (PAT/PMT), with the
//! MPEG-2 CRC polynomial in Annex A. RFC 2250 §2 also specifies 188-byte transport
//! packet framing. This is deliberately a bounded subset, not a full broadcast
//! receiver or a claim of lossless camera coverage.

use crate::video_codec::VideoCodec;
use std::ops::Range;

/// Canonical, reconstructible extraction commitments and original-byte verification.
pub mod receipt;

/// MPEG-2 transport packet size, excluding any explicitly selected outer framing.
pub const TS_PACKET_BYTES: usize = 188;
/// M2TS packet size: four opaque prefix bytes followed by one MPEG-2 TS packet.
pub const M2TS_PACKET_BYTES: usize = 192;
const MAX_INPUT: usize = 512 * 1024 * 1024;
const MAX_OUTPUT: usize = 256 * 1024 * 1024;
const MAX_PACKETS: usize = MAX_INPUT / TS_PACKET_BYTES;
const MAX_SECTION: usize = 1024;
const PID_COUNT: usize = 8192;

/// Explicit physical framing for a finite file; no probing, resynchronization or clock trust.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TsFraming {
    /// Standard 188-byte transport packets, with sync at each packet's first byte.
    #[default]
    Ts188,
    /// 192-byte M2TS packets, each with an opaque four-byte arrival-time prefix.
    /// The prefix is retained as source data and excluded from elementary payloads.
    M2ts192,
}

impl TsFraming {
    /// Exact physical packet stride in the original source, including any prefix.
    pub const fn packet_bytes(self) -> usize {
        match self {
            Self::Ts188 => TS_PACKET_BYTES,
            Self::M2ts192 => M2TS_PACKET_BYTES,
        }
    }

    /// Bytes before each TS sync byte; these remain opaque original custody.
    pub const fn prefix_bytes(self) -> usize {
        self.packet_bytes() - TS_PACKET_BYTES
    }
}

/// Explicit selection; omitted values require exactly one eligible choice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TsSelection {
    /// Nonzero PAT program number. Multiple programs require this selection.
    pub program: Option<u16>,
    /// AVC/HEVC elementary PID in the selected PMT.
    pub video_pid: Option<u16>,
}

/// Independent hard-capped input, work, reassembly and output limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TsLimits {
    /// At most 512 MiB of original transport bytes.
    pub max_input_bytes: usize,
    /// Transport packets inspected, including unselected PIDs and duplicates.
    pub max_packets: usize,
    /// Completed PAT/PMT sections inspected, including repeated sections.
    pub max_psi_sections: usize,
    /// Selected PES packets, at most 65536.
    pub max_pes: usize,
    /// Bytes in one reassembled PES, including its header; at most 64 MiB.
    pub max_pes_bytes: usize,
    /// Retained original payload spans, at most the hard packet ceiling.
    pub max_payload_spans: usize,
    /// Extracted elementary bytes, at most 256 MiB.
    pub max_elementary_bytes: usize,
}

impl Default for TsLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 * 1024 * 1024,
            max_packets: 128 * 1024 * 1024 / TS_PACKET_BYTES,
            max_psi_sections: 4096,
            max_pes: 16_384,
            max_pes_bytes: 16 * 1024 * 1024,
            max_payload_spans: 1_048_576,
            max_elementary_bytes: 128 * 1024 * 1024,
        }
    }
}

impl TsLimits {
    /// Reject invalid limits rather than silently widening owner policy.
    pub fn validate(self) -> Result<(), TsError> {
        if !(1..=MAX_INPUT).contains(&self.max_input_bytes)
            || !(1..=MAX_PACKETS).contains(&self.max_packets)
            || !(1..=65_536).contains(&self.max_psi_sections)
            || !(1..=65_536).contains(&self.max_pes)
            || !(9..=64 * 1024 * 1024).contains(&self.max_pes_bytes)
            || !(1..=MAX_PACKETS).contains(&self.max_payload_spans)
            || !(1..=MAX_OUTPUT).contains(&self.max_elementary_bytes)
        {
            return Err(TsError::Configuration);
        }
        Ok(())
    }
}

/// Payload-free, deterministic refusal categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TsError {
    /// Invalid selection or owner limits.
    Configuration,
    /// Incomplete packet, table section, or declared PES length.
    Truncated,
    /// Invalid packet header, adaptation field, or stuffing.
    Packet,
    /// A transport-error indicator was observed.
    TransportError,
    /// Transport/PES scrambling or a selected conditional-access descriptor.
    Scrambled,
    /// A transport discontinuity was explicitly indicated.
    Discontinuity,
    /// Missing/reordered packets or a conflicting/excessive duplicate.
    Continuity,
    /// Invalid PAT/PMT syntax, pointer, descriptor or section identity.
    Psi,
    /// A PAT or PMT MPEG-2 CRC failed.
    Checksum,
    /// Requested selection absent or default selection ambiguous.
    Selection,
    /// PAT or selected PMT changed during this finite input.
    ProgramChanged,
    /// A valid but unadmitted grammar/profile was encountered.
    Unsupported,
    /// Invalid PES header, timestamp, framing or selected video start.
    Pes,
    /// PAT/PMT missing or selected video preceded the admitted tables.
    MissingTables,
    /// No selected video elementary bytes were present.
    MissingVideo,
    /// An input, output, reassembly, count or arithmetic ceiling was reached.
    Limit,
    /// A bounded allocation failed.
    Allocation,
    /// Owner checkpoint cancelled the extraction.
    Cancelled,
    /// Invalid, corrupt or source-mismatched extraction receipt.
    Receipt,
}

impl std::fmt::Display for TsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MPEG-TS extraction refusal: {self:?}")
    }
}
impl std::error::Error for TsError {}

/// Exact mapping of copied elementary bytes to immutable original source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TsPayloadSpan {
    /// Absolute byte range in the original transport file.
    pub source: Range<usize>,
    /// Equal-length byte range in the extracted elementary stream.
    pub elementary: Range<usize>,
    /// Index into [`MpegTsVideo::pes`].
    pub pes: usize,
}

/// A PES boundary, without any assertion that it is a codec access unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TsPes {
    /// Contiguous elementary bytes contributed by this PES.
    pub elementary: Range<usize>,
    /// Indices into [`MpegTsVideo::payload_spans`].
    pub source_spans: Range<usize>,
    /// Optional raw, wrapping 33-bit presentation timestamp in 90 kHz ticks.
    pub pts: Option<u64>,
    /// Optional raw, wrapping 33-bit decoding timestamp in 90 kHz ticks.
    pub dts: Option<u64>,
}

/// Complete bounded extraction with immutable source custody mappings.
#[derive(Debug)]
pub struct MpegTsVideo<'a> {
    source: &'a [u8],
    framing: TsFraming,
    selection: TsSelection,
    limits: TsLimits,
    codec: VideoCodec,
    program: u16,
    video_pid: u16,
    pcr_pid: u16,
    packets_inspected: usize,
    psi_sections_inspected: usize,
    duplicate_packets: usize,
    pes: Vec<TsPes>,
    spans: Vec<TsPayloadSpan>,
    elementary: Vec<u8>,
}

impl<'a> MpegTsVideo<'a> {
    /// Extract a finite, complete 188-byte transport file under explicit resource bounds.
    pub fn parse(
        source: &'a [u8],
        selection: TsSelection,
        limits: TsLimits,
    ) -> Result<Self, TsError> {
        Self::parse_with_checkpoint(source, selection, limits, &mut || Ok(()))
    }

    /// Check the owner cancellation budget before each packet and each PES copy.
    pub fn parse_with_checkpoint(
        source: &'a [u8],
        selection: TsSelection,
        limits: TsLimits,
        checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
    ) -> Result<Self, TsError> {
        Self::parse_framed_with_checkpoint(source, TsFraming::Ts188, selection, limits, checkpoint)
    }

    /// Extract a complete file using the caller's explicit physical packet framing.
    /// All returned source offsets refer to the original file, including M2TS prefixes.
    pub fn parse_framed(
        source: &'a [u8],
        framing: TsFraming,
        selection: TsSelection,
        limits: TsLimits,
    ) -> Result<Self, TsError> {
        Self::parse_framed_with_checkpoint(source, framing, selection, limits, &mut || Ok(()))
    }

    /// Explicit framing with owner cancellation before each packet and each PES copy.
    pub fn parse_framed_with_checkpoint(
        source: &'a [u8],
        framing: TsFraming,
        selection: TsSelection,
        limits: TsLimits,
        checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
    ) -> Result<Self, TsError> {
        limits.validate()?;
        if selection.program == Some(0) || selection.video_pid.is_some_and(|pid| !media_pid(pid)) {
            return Err(TsError::Configuration);
        }
        checkpoint()?;
        if source.len() > limits.max_input_bytes
            || source.len() / framing.packet_bytes() > limits.max_packets
        {
            return Err(TsError::Limit);
        }
        if source.is_empty() || !source.len().is_multiple_of(framing.packet_bytes()) {
            return Err(TsError::Truncated);
        }

        let mut pat = None;
        let mut pmt = None;
        let mut pat_section = Vec::new();
        let mut pmt_section = Vec::new();
        let mut pat_psi = SectionAssembler::new();
        let mut pmt_psi = SectionAssembler::new();
        let mut pat_continuity = Continuity::default();
        let mut pmt_continuity = Continuity::default();
        let mut video_continuity = Continuity::default();
        let mut first_payload = [usize::MAX; PID_COUNT];
        let mut psi_sections = 0usize;
        let mut duplicates = 0usize;
        let mut pes = PesAssembler::default();
        let mut output = Extraction::default();

        for packet_start in (0..source.len()).step_by(framing.packet_bytes()) {
            checkpoint()?;
            // Keep offsets in original-file coordinates. Only the 188-byte TS packet
            // participates in continuity, so changing an opaque prefix cannot turn an
            // exact retransmission into a conflicting transport duplicate.
            let offset = packet_start + framing.prefix_bytes();
            let packet = Packet::parse(source, offset)?;
            if packet.payload.is_some() {
                first_payload[usize::from(packet.pid)] =
                    first_payload[usize::from(packet.pid)].min(offset);
            }
            let continuity = if packet.pid == 0 {
                Some(&mut pat_continuity)
            } else if pat.is_some_and(|table: Pat| table.pmt_pid == packet.pid) {
                Some(&mut pmt_continuity)
            } else if pmt.is_some_and(|table: Pmt| table.video_pid == packet.pid) {
                Some(&mut video_continuity)
            } else {
                None
            };
            if let Some(continuity) = continuity
                && continuity.observe(source, &packet, offset)?
            {
                duplicates += 1;
                continue;
            }
            let Some(payload) = packet.payload else {
                continue;
            };
            if packet.pid == 0 {
                pat_psi.feed(&source[payload], packet.start, &mut |section| {
                    inspect_section(&mut psi_sections, limits)?;
                    let table = parse_pat(section, selection)?;
                    remember_table(&mut pat_section, section)?;
                    pat = Some(table);
                    Ok(())
                })?;
            } else if let Some(pat) = pat
                && packet.pid == pat.pmt_pid
            {
                pmt_psi.feed(&source[payload], packet.start, &mut |section| {
                    inspect_section(&mut psi_sections, limits)?;
                    let table = parse_pmt(section, pat, selection)?;
                    remember_table(&mut pmt_section, section)?;
                    if pmt.is_none() && first_payload[usize::from(table.video_pid)] != usize::MAX {
                        return Err(TsError::MissingTables);
                    }
                    pmt = Some(table);
                    Ok(())
                })?;
            } else if pmt.is_some_and(|table| table.video_pid == packet.pid) {
                if packet.start {
                    if !pes.bytes.is_empty() {
                        pes.finish(&mut output, limits, checkpoint)?;
                    }
                    if output.pes.len() >= limits.max_pes {
                        return Err(TsError::Limit);
                    }
                    pes.started = true;
                }
                pes.append(source, payload, &output, limits)?;
            }
        }
        pat_psi.finish()?;
        pmt_psi.finish()?;
        let pat = pat.ok_or(TsError::MissingTables)?;
        let pmt = pmt.ok_or(TsError::MissingTables)?;
        if !pes.bytes.is_empty() {
            pes.finish(&mut output, limits, checkpoint)?;
        }
        if output.elementary.is_empty() {
            return Err(TsError::MissingVideo);
        }
        Ok(Self {
            source,
            framing,
            selection,
            limits,
            codec: pmt.codec,
            program: pat.program,
            video_pid: pmt.video_pid,
            pcr_pid: pmt.pcr_pid,
            packets_inspected: source.len() / framing.packet_bytes(),
            psi_sections_inspected: psi_sections,
            duplicate_packets: duplicates,
            pes: output.pes,
            spans: output.spans,
            elementary: output.elementary,
        })
    }

    /// Original immutable transport bytes, including all nonvideo structure.
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    /// Explicit physical framing admitted by the parser.
    pub fn framing(&self) -> TsFraming {
        self.framing
    }
    /// Exact selection policy admitted by the parser.
    pub fn selection(&self) -> TsSelection {
        self.selection
    }
    /// Exact resource ceilings admitted by the parser.
    pub fn limits(&self) -> TsLimits {
        self.limits
    }
    /// Codec declared by the selected PMT; elementary syntax is validated downstream.
    pub fn codec(&self) -> VideoCodec {
        self.codec
    }
    /// Selected nonzero program number.
    pub fn program(&self) -> u16 {
        self.program
    }
    /// Selected AVC/HEVC elementary PID.
    pub fn video_pid(&self) -> u16 {
        self.video_pid
    }
    /// Declared PCR PID, or 0x1fff when absent. No clock trust is implied.
    pub fn pcr_pid(&self) -> u16 {
        self.pcr_pid
    }
    /// All inspected physical packets, including ignored PIDs and duplicates.
    pub fn packets_inspected(&self) -> usize {
        self.packets_inspected
    }
    /// All completed selected PSI sections, including repeated tables.
    pub fn psi_sections_inspected(&self) -> usize {
        self.psi_sections_inspected
    }
    /// Exact duplicate packets checked and omitted from elementary extraction.
    pub fn duplicate_packets(&self) -> usize {
        self.duplicate_packets
    }
    /// PES boundaries and raw media timestamps, never inferred picture boundaries.
    pub fn pes(&self) -> &[TsPes] {
        &self.pes
    }
    /// Monotonic, nonoverlapping source spans covering every elementary output byte.
    pub fn payload_spans(&self) -> &[TsPayloadSpan] {
        &self.spans
    }
    /// Exact reassembled elementary bytes; no start codes or parameter sets are invented.
    pub fn elementary_stream(&self) -> &[u8] {
        &self.elementary
    }
    /// Transfer the bounded elementary allocation after callers retain any needed maps.
    pub fn into_elementary_stream(self) -> Vec<u8> {
        self.elementary
    }
    /// Smallest contiguous original range enclosing a nonempty elementary range.
    ///
    /// The envelope can also contain transport/PES headers, duplicates and other
    /// PIDs. Use [`Self::payload_spans`] when exact copied bytes are required.
    pub fn source_envelope(&self, elementary: Range<usize>) -> Result<Range<usize>, TsError> {
        if elementary.start >= elementary.end || elementary.end > self.elementary.len() {
            return Err(TsError::Configuration);
        }
        let first = self
            .spans
            .partition_point(|span| span.elementary.end <= elementary.start);
        let after = self
            .spans
            .partition_point(|span| span.elementary.start < elementary.end);
        let first = self.spans.get(first).ok_or(TsError::Pes)?;
        let last = self
            .spans
            .get(after.checked_sub(1).ok_or(TsError::Pes)?)
            .ok_or(TsError::Pes)?;
        Ok(
            first.source.start + elementary.start - first.elementary.start
                ..last.source.start + elementary.end - last.elementary.start,
        )
    }
}

// Geometric growth keeps many small PES packets linear in aggregate work,
// while never requesting a capacity above the owner's independent ceiling.
fn reserve_bounded<T>(
    values: &mut Vec<T>,
    additional: usize,
    maximum: usize,
) -> Result<(), TsError> {
    let needed = values.len().checked_add(additional).ok_or(TsError::Limit)?;
    if needed > maximum {
        return Err(TsError::Limit);
    }
    if needed > values.capacity() {
        let target = needed.max(values.capacity().saturating_mul(2).min(maximum));
        values
            .try_reserve_exact(target - values.len())
            .map_err(|_| TsError::Allocation)?;
    }
    Ok(())
}

fn media_pid(pid: u16) -> bool {
    (0x10..0x1fff).contains(&pid)
}

struct Packet {
    pid: u16,
    start: bool,
    counter: u8,
    payload: Option<Range<usize>>,
}

impl Packet {
    fn parse(source: &[u8], offset: usize) -> Result<Self, TsError> {
        let bytes = &source[offset..offset + TS_PACKET_BYTES];
        if bytes[0] != 0x47 {
            return Err(TsError::Packet);
        }
        if bytes[1] & 0x80 != 0 {
            return Err(TsError::TransportError);
        }
        if bytes[3] & 0xc0 != 0 {
            return Err(TsError::Scrambled);
        }
        let pid = (u16::from(bytes[1] & 0x1f) << 8) | u16::from(bytes[2]);
        let control = (bytes[3] >> 4) & 3;
        if control == 0 || (pid == 0x1fff && control != 1) {
            return Err(TsError::Packet);
        }
        let mut cursor = 4;
        if control & 2 != 0 {
            let length = usize::from(bytes[4]);
            if (control == 2 && length != 183) || (control == 3 && length > 182) {
                return Err(TsError::Packet);
            }
            let end = 5 + length;
            cursor = end;
            if length > 0 {
                let flags = bytes[5];
                if flags & 0x80 != 0 {
                    return Err(TsError::Discontinuity);
                }
                let mut field = 6usize;
                for flag in [0x10, 0x08] {
                    if flags & flag != 0 {
                        let clock = bytes
                            .get(field..field + 6)
                            .filter(|_| field + 6 <= end)
                            .ok_or(TsError::Packet)?;
                        let extension = (u16::from(clock[4] & 1) << 8) | u16::from(clock[5]);
                        if clock[4] & 0x7e != 0x7e || extension >= 300 {
                            return Err(TsError::Packet);
                        }
                        field += 6;
                    }
                }
                if flags & 0x04 != 0 {
                    field += 1;
                }
                if flags & 0x02 != 0 {
                    if field >= end {
                        return Err(TsError::Packet);
                    }
                    field += 1 + usize::from(bytes[field]);
                }
                if flags & 0x01 != 0 {
                    return Err(TsError::Unsupported);
                }
                if field > end || bytes[field..end].iter().any(|byte| *byte != 0xff) {
                    return Err(TsError::Packet);
                }
            }
        }
        let payload = (control & 1 != 0).then_some(offset + cursor..offset + TS_PACKET_BYTES);
        let start = bytes[1] & 0x40 != 0;
        if start && payload.is_none() {
            return Err(TsError::Packet);
        }
        Ok(Self {
            pid,
            start,
            counter: bytes[3] & 0x0f,
            payload,
        })
    }
}

#[derive(Default)]
struct Continuity {
    previous: Option<(u8, usize, bool)>,
    duplicated: bool,
}

impl Continuity {
    /// True means one verified exact duplicate, whose payload must not be copied twice.
    fn observe(&mut self, source: &[u8], packet: &Packet, offset: usize) -> Result<bool, TsError> {
        let has_payload = packet.payload.is_some();
        if let Some((counter, previous, previous_payload)) = self.previous {
            if has_payload && packet.counter == counter {
                if !previous_payload
                    || self.duplicated
                    || source[previous..previous + TS_PACKET_BYTES]
                        != source[offset..offset + TS_PACKET_BYTES]
                {
                    return Err(TsError::Continuity);
                }
                self.duplicated = true;
                return Ok(true);
            }
            let expected = if has_payload {
                (counter + 1) & 0x0f
            } else {
                counter
            };
            if packet.counter != expected {
                return Err(TsError::Continuity);
            }
        }
        self.previous = Some((packet.counter, offset, has_payload));
        self.duplicated = false;
        Ok(false)
    }
}

struct SectionAssembler {
    bytes: [u8; MAX_SECTION],
    len: usize,
}

impl SectionAssembler {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_SECTION],
            len: 0,
        }
    }
    fn feed(
        &mut self,
        payload: &[u8],
        start: bool,
        complete: &mut dyn FnMut(&[u8]) -> Result<(), TsError>,
    ) -> Result<(), TsError> {
        if start {
            let pointer = usize::from(*payload.first().ok_or(TsError::Psi)?);
            if pointer + 1 >= payload.len() || payload[pointer + 1] == 0xff {
                return Err(TsError::Psi);
            }
            let prefix = &payload[1..1 + pointer];
            if self.len != 0 {
                self.consume(prefix, false, complete)?;
                if self.len != 0 {
                    return Err(TsError::Truncated);
                }
            } else if prefix.iter().any(|byte| *byte != 0xff) {
                return Err(TsError::Psi);
            }
            self.consume(&payload[1 + pointer..], true, complete)
        } else {
            self.consume(payload, false, complete)
        }
    }
    fn consume(
        &mut self,
        mut bytes: &[u8],
        allow_new: bool,
        complete: &mut dyn FnMut(&[u8]) -> Result<(), TsError>,
    ) -> Result<(), TsError> {
        while !bytes.is_empty() {
            if self.len == 0 {
                if bytes[0] == 0xff {
                    return if bytes.iter().all(|byte| *byte == 0xff) {
                        Ok(())
                    } else {
                        Err(TsError::Psi)
                    };
                }
                if !allow_new {
                    return Err(TsError::Psi);
                }
            }
            let needed = if self.len < 3 {
                3
            } else {
                self.section_size()?
            };
            let count = (needed - self.len).min(bytes.len());
            self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
            self.len += count;
            bytes = &bytes[count..];
            if self.len >= 3 && self.len == self.section_size()? {
                complete(&self.bytes[..self.len])?;
                self.len = 0;
            }
        }
        Ok(())
    }
    fn section_size(&self) -> Result<usize, TsError> {
        let length = (usize::from(self.bytes[1] & 0x0f) << 8) | usize::from(self.bytes[2]);
        if self.bytes[1] & 0xf0 != 0xb0 || !(9..=1021).contains(&length) {
            return Err(TsError::Psi);
        }
        Ok(3 + length)
    }
    fn finish(&self) -> Result<(), TsError> {
        if self.len == 0 {
            Ok(())
        } else {
            Err(TsError::Truncated)
        }
    }
}

fn inspect_section(count: &mut usize, limits: TsLimits) -> Result<(), TsError> {
    if *count >= limits.max_psi_sections {
        return Err(TsError::Limit);
    }
    *count += 1;
    Ok(())
}

fn remember_table(previous: &mut Vec<u8>, section: &[u8]) -> Result<(), TsError> {
    if previous.is_empty() {
        previous
            .try_reserve_exact(section.len())
            .map_err(|_| TsError::Allocation)?;
        previous.extend_from_slice(section);
    } else if previous != section {
        return Err(TsError::ProgramChanged);
    }
    Ok(())
}

fn table_header(section: &[u8], table_id: u8) -> Result<(), TsError> {
    if section.len() < 12 || section[0] != table_id || section[5] & 0xc0 != 0xc0 {
        return Err(TsError::Psi);
    }
    if mpeg_crc(section) != 0 {
        return Err(TsError::Checksum);
    }
    if section[5] & 1 == 0 || section[6] != 0 || section[7] != 0 {
        return Err(TsError::Unsupported);
    }
    Ok(())
}

fn mpeg_crc(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[derive(Clone, Copy)]
struct Pat {
    program: u16,
    pmt_pid: u16,
}

fn parse_pat(section: &[u8], selection: TsSelection) -> Result<Pat, TsError> {
    table_header(section, 0)?;
    let entries = &section[8..section.len() - 4];
    if !entries.len().is_multiple_of(4) {
        return Err(TsError::Psi);
    }
    let mut selected = None;
    let mut programs = [0u16; 253];
    let mut pids = [0u16; 253];
    for (index, entry) in entries.as_chunks::<4>().0.iter().enumerate() {
        let program = u16::from_be_bytes([entry[0], entry[1]]);
        let pid = (u16::from(entry[2] & 0x1f) << 8) | u16::from(entry[3]);
        if entry[2] & 0xe0 != 0xe0
            || !media_pid(pid)
            || programs[..index].contains(&program)
            || pids[..index].contains(&pid)
        {
            return Err(TsError::Psi);
        }
        programs[index] = program;
        pids[index] = pid;
        if program != 0 && selection.program.is_none_or(|wanted| wanted == program) {
            if selected.is_some() {
                return Err(TsError::Selection);
            }
            selected = Some(Pat {
                program,
                pmt_pid: pid,
            });
        }
    }
    selected.ok_or(TsError::Selection)
}

#[derive(Clone, Copy)]
struct Pmt {
    codec: VideoCodec,
    video_pid: u16,
    pcr_pid: u16,
}

fn parse_pmt(section: &[u8], pat: Pat, selection: TsSelection) -> Result<Pmt, TsError> {
    table_header(section, 2)?;
    if section.len() < 16
        || u16::from_be_bytes([section[3], section[4]]) != pat.program
        || section[8] & 0xe0 != 0xe0
        || section[10] & 0xf0 != 0xf0
    {
        return Err(TsError::Psi);
    }
    let pcr_pid = (u16::from(section[8] & 0x1f) << 8) | u16::from(section[9]);
    if pcr_pid != 0x1fff && (!media_pid(pcr_pid) || pcr_pid == pat.pmt_pid) {
        return Err(TsError::Psi);
    }
    let end = section.len() - 4;
    let info_length = (usize::from(section[10] & 0x0f) << 8) | usize::from(section[11]);
    let mut cursor = 12 + info_length;
    descriptors(
        section
            .get(12..cursor)
            .filter(|_| cursor <= end)
            .ok_or(TsError::Psi)?,
        true,
    )?;
    let mut selected = None;
    let mut pids = [0u16; 202];
    let mut count = 0;
    while cursor < end {
        if end - cursor < 5 {
            return Err(TsError::Psi);
        }
        let header = &section[cursor..cursor + 5];
        let pid = (u16::from(header[1] & 0x1f) << 8) | u16::from(header[2]);
        let length = (usize::from(header[3] & 0x0f) << 8) | usize::from(header[4]);
        if header[1] & 0xe0 != 0xe0
            || header[3] & 0xf0 != 0xf0
            || !media_pid(pid)
            || pid == pat.pmt_pid
            || pids[..count].contains(&pid)
            || count == pids.len()
        {
            return Err(TsError::Psi);
        }
        pids[count] = pid;
        count += 1;
        let codec = match header[0] {
            0x1b => Some(VideoCodec::Avc),
            0x24 => Some(VideoCodec::Hevc),
            _ => None,
        };
        let eligible = codec.is_some() && selection.video_pid.is_none_or(|wanted| wanted == pid);
        cursor += 5;
        descriptors(
            section
                .get(cursor..cursor + length)
                .filter(|_| cursor + length <= end)
                .ok_or(TsError::Psi)?,
            eligible,
        )?;
        cursor += length;
        if let Some(codec) = codec.filter(|_| eligible) {
            if selected.is_some() {
                return Err(TsError::Selection);
            }
            selected = Some(Pmt {
                codec,
                video_pid: pid,
                pcr_pid,
            });
        }
    }
    selected.ok_or(TsError::Selection)
}

fn descriptors(mut bytes: &[u8], reject_ca: bool) -> Result<(), TsError> {
    while !bytes.is_empty() {
        if bytes.len() < 2 || usize::from(bytes[1]) > bytes.len() - 2 {
            return Err(TsError::Psi);
        }
        if reject_ca && bytes[0] == 9 {
            return Err(TsError::Scrambled);
        }
        bytes = &bytes[2 + usize::from(bytes[1])..];
    }
    Ok(())
}

#[derive(Default)]
struct Extraction {
    pes: Vec<TsPes>,
    spans: Vec<TsPayloadSpan>,
    elementary: Vec<u8>,
}

#[derive(Default)]
struct PesAssembler {
    started: bool,
    bytes: Vec<u8>,
    sources: Vec<Range<usize>>,
}

impl PesAssembler {
    fn append(
        &mut self,
        source: &[u8],
        payload: Range<usize>,
        output: &Extraction,
        limits: TsLimits,
    ) -> Result<(), TsError> {
        if !self.started {
            return Err(TsError::Pes);
        }
        let next = self
            .bytes
            .len()
            .checked_add(payload.len())
            .ok_or(TsError::Limit)?;
        if next > limits.max_pes_bytes
            || output.spans.len().saturating_add(self.sources.len()) >= limits.max_payload_spans
        {
            return Err(TsError::Limit);
        }
        reserve_bounded(&mut self.bytes, payload.len(), limits.max_pes_bytes)?;
        reserve_bounded(&mut self.sources, 1, limits.max_payload_spans)?;
        self.bytes.extend_from_slice(&source[payload.clone()]);
        self.sources.push(payload);
        if self.bytes.len() >= 6 {
            if self.bytes[..3] != [0, 0, 1] || !(0xe0..=0xef).contains(&self.bytes[3]) {
                return Err(TsError::Pes);
            }
            let length = usize::from(u16::from_be_bytes([self.bytes[4], self.bytes[5]]));
            if length != 0 && self.bytes.len() > 6 + length {
                return Err(TsError::Pes);
            }
        }
        Ok(())
    }
    fn finish(
        &mut self,
        output: &mut Extraction,
        limits: TsLimits,
        checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
    ) -> Result<(), TsError> {
        checkpoint()?;
        let (header, pts, dts) = pes_header(&self.bytes)?;
        let count = self.bytes.len() - header;
        let end = output
            .elementary
            .len()
            .checked_add(count)
            .ok_or(TsError::Limit)?;
        if count == 0 {
            return Err(TsError::Pes);
        }
        if end > limits.max_elementary_bytes || output.pes.len() >= limits.max_pes {
            return Err(TsError::Limit);
        }
        reserve_bounded(&mut output.elementary, count, limits.max_elementary_bytes)?;
        reserve_bounded(
            &mut output.spans,
            self.sources.len(),
            limits.max_payload_spans,
        )?;
        reserve_bounded(&mut output.pes, 1, limits.max_pes)?;
        let base = output.elementary.len();
        let span_start = output.spans.len();
        let mut position = 0;
        for source in &self.sources {
            checkpoint()?;
            let start = position.max(header);
            let after = position + source.len();
            if start < after {
                let target = base + start - header..base + after - header;
                output.spans.push(TsPayloadSpan {
                    source: source.start + start - position..source.end,
                    elementary: target,
                    pes: output.pes.len(),
                });
                output
                    .elementary
                    .extend_from_slice(&self.bytes[start..after]);
            }
            position = after;
        }
        output.pes.push(TsPes {
            elementary: base..end,
            source_spans: span_start..output.spans.len(),
            pts,
            dts,
        });
        self.bytes.clear();
        self.sources.clear();
        self.started = false;
        Ok(())
    }
}

fn pes_header(bytes: &[u8]) -> Result<(usize, Option<u64>, Option<u64>), TsError> {
    if bytes.len() < 9 {
        return Err(TsError::Truncated);
    }
    let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if length != 0 && bytes.len() != 6 + length {
        return Err(TsError::Truncated);
    }
    if bytes[6] & 0xc0 != 0x80 {
        return Err(TsError::Pes);
    }
    if bytes[6] & 0x30 != 0 {
        return Err(TsError::Scrambled);
    }
    if bytes[7] & 0x3f != 0 {
        return Err(TsError::Unsupported);
    }
    let header = 9 + usize::from(bytes[8]);
    if header > bytes.len() {
        return Err(TsError::Truncated);
    }
    let (pts, dts, used) = match bytes[7] >> 6 {
        0 => (None, None, 9),
        2 if header >= 14 => (Some(timestamp(&bytes[9..14], 2)?), None, 14),
        3 if header >= 19 => (
            Some(timestamp(&bytes[9..14], 3)?),
            Some(timestamp(&bytes[14..19], 1)?),
            19,
        ),
        _ => return Err(TsError::Pes),
    };
    if bytes[used..header].iter().any(|byte| *byte != 0xff) {
        return Err(TsError::Pes);
    }
    Ok((header, pts, dts))
}

fn timestamp(bytes: &[u8], prefix: u8) -> Result<u64, TsError> {
    if bytes[0] >> 4 != prefix || bytes[0] & 1 == 0 || bytes[2] & 1 == 0 || bytes[4] & 1 == 0 {
        return Err(TsError::Pes);
    }
    Ok((u64::from((bytes[0] >> 1) & 7) << 30)
        | (u64::from(bytes[1]) << 22)
        | (u64::from(bytes[2] >> 1) << 15)
        | (u64::from(bytes[3]) << 7)
        | u64::from(bytes[4] >> 1))
}

#[cfg(test)]
#[path = "mpeg_ts/framing_tests.rs"]
mod framing_tests;

#[cfg(test)]
mod tests {
    use super::*;
    const AVC: &[u8] = include_bytes!("../../fss-codec-h264/tests/fixtures/baseline_i64.h264");
    const HEVC: &[u8] =
        include_bytes!("../../fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265");
    const AVC_TS: &[u8] = include_bytes!("../tests/fixtures/avc_i64.ts");
    const HEVC_TS: &[u8] = include_bytes!("../tests/fixtures/hevc_i64.ts");
    const PMT_PID: u16 = 0x1000;
    const VIDEO_PID: u16 = 0x100;

    fn refresh_crc(bytes: &mut Vec<u8>, existing: bool) {
        if existing {
            bytes.truncate(bytes.len() - 4);
        }
        let length = bytes.len() + 1;
        bytes[1] = 0xb0 | ((length >> 8) as u8);
        bytes[2] = length as u8;
        let crc = mpeg_crc(bytes);
        bytes.extend_from_slice(&crc.to_be_bytes());
    }
    fn section(table: u8, extension: u16, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            table,
            0xb0,
            0,
            (extension >> 8) as u8,
            extension as u8,
            0xc1,
            0,
            0,
        ];
        bytes.extend_from_slice(content);
        refresh_crc(&mut bytes, false);
        bytes
    }
    fn pat(programs: &[(u16, u16)]) -> Vec<u8> {
        let mut content = Vec::new();
        for &(program, pid) in programs {
            content.extend_from_slice(&program.to_be_bytes());
            content.extend_from_slice(&(0xe000 | pid).to_be_bytes());
        }
        section(0, 1, &content)
    }
    fn pmt(program: u16, videos: &[(u8, u16)]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&(0xe000 | videos[0].1).to_be_bytes());
        content.extend_from_slice(&[0xf0, 0]);
        for &(stream_type, pid) in videos {
            content.push(stream_type);
            content.extend_from_slice(&(0xe000 | pid).to_be_bytes());
            content.extend_from_slice(&[0xf0, 0]);
        }
        section(2, program, &content)
    }
    fn packet(pid: u16, start: bool, counter: u8, payload: &[u8]) -> Vec<u8> {
        assert!(!payload.is_empty() && payload.len() <= 184);
        let mut bytes = vec![0xff; TS_PACKET_BYTES];
        bytes[0] = 0x47;
        bytes[1] = (pid >> 8) as u8 | if start { 0x40 } else { 0 };
        bytes[2] = pid as u8;
        bytes[3] = if payload.len() == 184 { 0x10 } else { 0x30 } | (counter & 15);
        if payload.len() < 184 {
            bytes[4] = (183 - payload.len()) as u8;
            if bytes[4] > 0 {
                bytes[5] = 0;
            }
        }
        bytes[TS_PACKET_BYTES - payload.len()..].copy_from_slice(payload);
        bytes
    }
    fn packetize(pid: u16, bytes: &[u8], counter: u8, first: usize) -> Vec<u8> {
        let mut output = Vec::new();
        let first = first.min(bytes.len());
        output.extend(packet(pid, true, counter, &bytes[..first]));
        for (index, chunk) in bytes[first..].chunks(184).enumerate() {
            output.extend(packet(
                pid,
                false,
                counter.wrapping_add(index as u8).wrapping_add(1),
                chunk,
            ));
        }
        output
    }
    fn psi(pid: u16, section: &[u8], counter: u8) -> Vec<u8> {
        let mut payload = vec![0];
        payload.extend_from_slice(section);
        packetize(pid, &payload, counter, 184)
    }
    fn encoded_timestamp(value: u64, prefix: u8) -> [u8; 5] {
        [
            (prefix << 4) | (((value >> 30) as u8 & 7) << 1) | 1,
            (value >> 22) as u8,
            (((value >> 15) as u8 & 127) << 1) | 1,
            (value >> 7) as u8,
            ((value as u8 & 127) << 1) | 1,
        ]
    }
    fn pes_bytes(video: &[u8], pts: Option<u64>, dts: Option<u64>, bounded: bool) -> Vec<u8> {
        let mut bytes = vec![0, 0, 1, 0xe0, 0, 0, 0x80, 0, 0];
        if let Some(pts) = pts {
            bytes[7] = if dts.is_some() { 0xc0 } else { 0x80 };
            bytes.extend_from_slice(&encoded_timestamp(pts, if dts.is_some() { 3 } else { 2 }));
            if let Some(dts) = dts {
                bytes.extend_from_slice(&encoded_timestamp(dts, 1));
            }
            bytes[8] = (bytes.len() - 9) as u8;
        }
        bytes.extend_from_slice(video);
        if bounded {
            let length = u16::try_from(bytes.len() - 6).unwrap().to_be_bytes();
            bytes[4..6].copy_from_slice(&length);
        }
        bytes
    }
    fn tables(stream_type: u8) -> Vec<u8> {
        let mut bytes = psi(0, &pat(&[(1, PMT_PID)]), 0);
        bytes.extend(psi(PMT_PID, &pmt(1, &[(stream_type, VIDEO_PID)]), 0));
        bytes
    }
    fn stream(video: &[u8], stream_type: u8) -> Vec<u8> {
        let mut bytes = tables(stream_type);
        bytes.extend(packetize(
            VIDEO_PID,
            &pes_bytes(video, Some(90_000), None, true),
            0,
            184,
        ));
        bytes
    }
    fn parse(bytes: &[u8]) -> Result<MpegTsVideo<'_>, TsError> {
        MpegTsVideo::parse(bytes, TsSelection::default(), TsLimits::default())
    }
    fn assert_map(video: &MpegTsVideo<'_>) {
        let mut copied = Vec::new();
        let mut source_end = 0;
        for span in video.payload_spans() {
            assert_eq!(span.elementary.start, copied.len());
            assert_eq!(span.source.len(), span.elementary.len());
            assert!(span.source.start >= source_end);
            assert!(!span.source.is_empty());
            assert_eq!(
                &video.source()[span.source.clone()],
                &video.elementary_stream()[span.elementary.clone()]
            );
            assert!(
                video.pes()[span.pes]
                    .elementary
                    .contains(&span.elementary.start)
            );
            copied.extend_from_slice(&video.source()[span.source.clone()]);
            source_end = span.source.end;
        }
        assert_eq!(copied, video.elementary_stream());
        for (index, pes) in video.pes().iter().enumerate() {
            assert!(
                video.payload_spans()[pes.source_spans.clone()]
                    .iter()
                    .all(|span| span.pes == index)
            );
        }
    }

    #[test]
    fn standard_crc_check_vector() {
        assert_eq!(mpeg_crc(b"123456789"), 0x0376_e6e7);
        assert_eq!(mpeg_crc(&pat(&[(1, PMT_PID)])), 0);
    }
    #[test]
    fn independent_offline_muxed_avc_and_hevc_preserve_original_spans() {
        for (bytes, codec, size) in [
            (AVC_TS, VideoCodec::Avc, 3647),
            (HEVC_TS, VideoCodec::Hevc, 3436),
        ] {
            let video = parse(bytes).unwrap();
            assert_eq!(video.codec(), codec);
            assert_eq!(video.program(), 1);
            assert_eq!(video.video_pid(), VIDEO_PID);
            assert_eq!(video.pcr_pid(), VIDEO_PID);
            assert_eq!(video.packets_inspected(), 24);
            assert_eq!(video.elementary_stream().len(), size);
            assert!(video.psi_sections_inspected() >= 2);
            assert!(video.pes().iter().all(|pes| pes.pts.is_some()));
            assert_map(&video);
        }
    }
    #[test]
    fn real_codec_bytes_cross_pes_and_transport_boundaries_without_invention() {
        for (elementary, stream_type, codec) in
            [(AVC, 0x1b, VideoCodec::Avc), (HEVC, 0x24, VideoCodec::Hevc)]
        {
            let mut bytes = tables(stream_type);
            let mut counter = 14u8;
            for (index, piece) in elementary.chunks(251).enumerate() {
                let payload = pes_bytes(piece, Some(index as u64 * 3600), None, index % 2 == 0);
                let packets = packetize(
                    VIDEO_PID,
                    &payload,
                    counter,
                    if index == 0 { 2 } else { 184 },
                );
                counter = counter.wrapping_add((packets.len() / TS_PACKET_BYTES) as u8) & 15;
                bytes.extend(packets);
            }
            let video = parse(&bytes).unwrap();
            assert_eq!(video.codec(), codec);
            assert_eq!(video.elementary_stream(), elementary);
            assert_eq!(video.pes().len(), elementary.len().div_ceil(251));
            assert_map(&video);
            assert_eq!(video.into_elementary_stream(), elementary);
        }
    }
    #[test]
    fn timestamps_remain_raw_wrapping_media_values() {
        let mut bytes = tables(0x1b);
        bytes.extend(packetize(
            VIDEO_PID,
            &pes_bytes(
                &AVC[..17],
                Some((1u64 << 33) - 1),
                Some((1u64 << 33) - 3),
                true,
            ),
            0,
            12,
        ));
        bytes.extend(packetize(
            VIDEO_PID,
            &pes_bytes(&AVC[17..31], Some(5), Some(1), false),
            2,
            184,
        ));
        let video = parse(&bytes).unwrap();
        assert_eq!(
            (video.pes()[0].pts, video.pes()[0].dts),
            (Some((1u64 << 33) - 1), Some((1u64 << 33) - 3))
        );
        assert_eq!((video.pes()[1].pts, video.pes()[1].dts), (Some(5), Some(1)));
        assert_eq!(video.elementary_stream(), &AVC[..31]);
    }
    #[test]
    fn psi_headers_and_pes_headers_can_span_packets() {
        let mut bytes = Vec::new();
        for (pid, section) in [
            (0, pat(&[(1, PMT_PID)])),
            (PMT_PID, pmt(1, &[(0x24, VIDEO_PID)])),
        ] {
            let mut payload = vec![0];
            payload.extend(section);
            bytes.extend(packetize(pid, &payload, 15, 2));
        }
        bytes.extend(packetize(
            VIDEO_PID,
            &pes_bytes(HEVC, Some(7), Some(3), true),
            15,
            1,
        ));
        let video = parse(&bytes).unwrap();
        assert_eq!(video.elementary_stream(), HEVC);
        assert_map(&video);
    }
    #[test]
    fn psi_pointer_completes_previous_section_before_next_section() {
        let section = pat(&[(1, PMT_PID)]);
        let mut first = vec![0];
        first.extend_from_slice(&section[..7]);
        let mut bytes = packet(0, true, 0, &first);
        let mut following = vec![(section.len() - 7) as u8];
        following.extend_from_slice(&section[7..]);
        following.extend_from_slice(&section);
        following.extend_from_slice(&[0xff; 3]);
        bytes.extend(packet(0, true, 1, &following));
        bytes.extend(psi(PMT_PID, &pmt(1, &[(0x1b, VIDEO_PID)]), 0));
        bytes.extend(packetize(
            VIDEO_PID,
            &pes_bytes(AVC, None, None, true),
            0,
            184,
        ));
        let video = parse(&bytes).unwrap();
        assert_eq!(video.psi_sections_inspected(), 3);
        assert_eq!(video.elementary_stream(), AVC);
    }
    #[test]
    fn crc_failures_are_refused_for_both_selected_tables() {
        for offset in [0, TS_PACKET_BYTES] {
            let mut bytes = stream(AVC, 0x1b);
            bytes[offset + TS_PACKET_BYTES - 1] ^= 1;
            assert_eq!(parse(&bytes).unwrap_err(), TsError::Checksum);
        }
    }
    #[test]
    fn exact_duplicate_is_checked_once_and_not_copied_twice() {
        let original = stream(AVC, 0x1b);
        let start = 2 * TS_PACKET_BYTES;
        let mut bytes = original[..start + TS_PACKET_BYTES].to_vec();
        bytes.extend_from_slice(&original[start..start + TS_PACKET_BYTES]);
        bytes.extend_from_slice(&original[start + TS_PACKET_BYTES..]);
        let video = parse(&bytes).unwrap();
        assert_eq!(video.duplicate_packets(), 1);
        assert_eq!(video.elementary_stream(), AVC);
        assert_map(&video);
        let mut excessive = bytes[..start + 2 * TS_PACKET_BYTES].to_vec();
        excessive.extend_from_slice(&original[start..start + TS_PACKET_BYTES]);
        excessive.extend_from_slice(&original[start + TS_PACKET_BYTES..]);
        assert_eq!(parse(&excessive).unwrap_err(), TsError::Continuity);
        bytes[start + 2 * TS_PACKET_BYTES - 1] ^= 1;
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Continuity);
    }
    #[test]
    fn packet_loss_reordering_and_counter_wrap_are_checked() {
        let original = stream(AVC, 0x1b);
        let mut missing = original[..3 * TS_PACKET_BYTES].to_vec();
        missing.extend_from_slice(&original[4 * TS_PACKET_BYTES..]);
        assert_eq!(parse(&missing).unwrap_err(), TsError::Continuity);
        let mut reordered = original.clone();
        reordered[3 * TS_PACKET_BYTES..4 * TS_PACKET_BYTES]
            .copy_from_slice(&original[4 * TS_PACKET_BYTES..5 * TS_PACKET_BYTES]);
        assert_eq!(parse(&reordered).unwrap_err(), TsError::Continuity);
        assert_eq!(parse(&original).unwrap().elementary_stream(), AVC);
    }
    #[test]
    fn adaptation_only_pcr_packets_do_not_increment_continuity() {
        let original = stream(AVC, 0x1b);
        let mut adaptation = vec![0xff; TS_PACKET_BYTES];
        adaptation[..12].copy_from_slice(&[0x47, 1, 0, 0x20, 183, 0x10, 0, 0, 0, 0, 0x7e, 0]);
        let mut bytes = original[..3 * TS_PACKET_BYTES].to_vec();
        bytes.extend_from_slice(&adaptation);
        bytes.extend_from_slice(&original[3 * TS_PACKET_BYTES..]);
        assert_eq!(parse(&bytes).unwrap().elementary_stream(), AVC);
        bytes[3 * TS_PACKET_BYTES + 3] = 0x21;
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Continuity);
    }
    #[test]
    fn transport_errors_scrambling_discontinuity_and_bad_adaptation_refuse() {
        let original = stream(&AVC[..20], 0x1b);
        let offset = 2 * TS_PACKET_BYTES;
        for (index, mask, error) in [
            (1, 0x80, TsError::TransportError),
            (3, 0x80, TsError::Scrambled),
            (5, 0x80, TsError::Discontinuity),
            (5, 0x01, TsError::Unsupported),
        ] {
            let mut bytes = original.clone();
            bytes[offset + index] |= mask;
            assert_eq!(parse(&bytes).unwrap_err(), error);
        }
        let mut bytes = original.clone();
        bytes[offset + 4] = 183;
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Packet);
        let mut bytes = original;
        bytes[offset + 6] = 0;
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Packet);
    }
    #[test]
    fn selected_video_requires_preceding_complete_tables_and_a_pes_start() {
        let original = stream(AVC, 0x1b);
        let mut late = original[2 * TS_PACKET_BYTES..3 * TS_PACKET_BYTES].to_vec();
        late.extend_from_slice(&original[..2 * TS_PACKET_BYTES]);
        late.extend_from_slice(&original[3 * TS_PACKET_BYTES..]);
        assert_eq!(parse(&late).unwrap_err(), TsError::MissingTables);
        assert_eq!(
            parse(&original[2 * TS_PACKET_BYTES..]).unwrap_err(),
            TsError::MissingTables
        );
        let mut missing_start = original;
        missing_start[2 * TS_PACKET_BYTES + 1] &= !0x40;
        assert_eq!(parse(&missing_start).unwrap_err(), TsError::Pes);
        assert_eq!(parse(&tables(0x1b)).unwrap_err(), TsError::MissingVideo);
    }
    #[test]
    fn ambiguous_program_and_video_selections_require_explicit_choices() {
        let mut bytes = psi(0, &pat(&[(1, PMT_PID), (2, PMT_PID + 1)]), 0);
        bytes.extend(psi(
            PMT_PID + 1,
            &pmt(2, &[(0x24, VIDEO_PID), (0x1b, VIDEO_PID + 1)]),
            0,
        ));
        bytes.extend(packetize(
            VIDEO_PID,
            &pes_bytes(HEVC, None, None, true),
            0,
            184,
        ));
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Selection);
        let selected = TsSelection {
            program: Some(2),
            video_pid: Some(VIDEO_PID),
        };
        let video = MpegTsVideo::parse(&bytes, selected, TsLimits::default()).unwrap();
        assert_eq!(video.codec(), VideoCodec::Hevc);
        assert_eq!(video.program(), 2);
        assert_eq!(video.elementary_stream(), HEVC);
        assert_eq!(
            MpegTsVideo::parse(
                &bytes,
                TsSelection {
                    program: Some(2),
                    video_pid: None
                },
                TsLimits::default()
            )
            .unwrap_err(),
            TsError::Selection
        );
    }
    #[test]
    fn changed_tables_future_tables_and_multisection_tables_refuse() {
        for pid in [0, PMT_PID] {
            let mut bytes = stream(AVC, 0x1b);
            let mut changed = if pid == 0 {
                pat(&[(1, PMT_PID)])
            } else {
                pmt(1, &[(0x1b, VIDEO_PID)])
            };
            changed[5] += 2;
            refresh_crc(&mut changed, true);
            bytes.extend(psi(pid, &changed, 1));
            assert_eq!(parse(&bytes).unwrap_err(), TsError::ProgramChanged);
        }
        for (index, value) in [(5, 0xc0), (6, 1), (7, 1)] {
            let mut table = pat(&[(1, PMT_PID)]);
            table[index] = value;
            refresh_crc(&mut table, true);
            assert_eq!(parse(&psi(0, &table, 0)).unwrap_err(), TsError::Unsupported);
        }
    }
    #[test]
    fn selected_conditional_access_and_malformed_descriptors_refuse() {
        let mut table = pmt(1, &[(0x1b, VIDEO_PID)]);
        table[16] = 2;
        table.splice(17..17, [9, 0]);
        refresh_crc(&mut table, true);
        let mut bytes = psi(0, &pat(&[(1, PMT_PID)]), 0);
        bytes.extend(psi(PMT_PID, &table, 0));
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Scrambled);
        table[18] = 255;
        refresh_crc(&mut table, true);
        let mut bytes = psi(0, &pat(&[(1, PMT_PID)]), 0);
        bytes.extend(psi(PMT_PID, &table, 0));
        assert_eq!(parse(&bytes).unwrap_err(), TsError::Psi);
    }
    #[test]
    fn truncated_packets_tables_and_declared_pes_lengths_refuse() {
        let original = stream(AVC, 0x1b);
        assert_eq!(
            parse(&original[..original.len() - 1]).unwrap_err(),
            TsError::Truncated
        );
        assert_eq!(
            parse(&original[..original.len() - TS_PACKET_BYTES]).unwrap_err(),
            TsError::Truncated
        );
        let section = pat(&[(1, PMT_PID)]);
        let mut payload = vec![0];
        payload.extend_from_slice(&section[..10]);
        assert_eq!(
            parse(&packet(0, true, 0, &payload)).unwrap_err(),
            TsError::Truncated
        );
        let mut trailing = original;
        trailing.extend(packet(0, true, 1, &payload));
        assert_eq!(parse(&trailing).unwrap_err(), TsError::Truncated);
    }
    #[test]
    fn timestamp_markers_header_lengths_and_pes_flags_are_checked() {
        let original = pes_bytes(&AVC[..20], Some(123), Some(122), true);
        for (index, value, expected) in [
            (9, 0x20, TsError::Pes),
            (11, 0, TsError::Pes),
            (8, 255, TsError::Truncated),
            (7, 0x40, TsError::Pes),
            (7, 0xc1, TsError::Unsupported),
            (6, 0xb0, TsError::Scrambled),
        ] {
            let mut payload = original.clone();
            payload[index] = value;
            let mut bytes = tables(0x1b);
            bytes.extend(packetize(VIDEO_PID, &payload, 0, 184));
            assert_eq!(parse(&bytes).unwrap_err(), expected);
        }
    }
    #[test]
    fn all_resource_limits_and_cancellation_are_enforced() {
        let original = stream(AVC, 0x1b);
        let baseline = TsLimits::default();
        for limits in [
            TsLimits {
                max_input_bytes: original.len() - 1,
                ..baseline
            },
            TsLimits {
                max_packets: 1,
                ..baseline
            },
            TsLimits {
                max_psi_sections: 1,
                ..baseline
            },
            TsLimits {
                max_pes_bytes: 9,
                ..baseline
            },
            TsLimits {
                max_payload_spans: 1,
                ..baseline
            },
            TsLimits {
                max_elementary_bytes: 1,
                ..baseline
            },
        ] {
            assert_eq!(
                MpegTsVideo::parse(&original, TsSelection::default(), limits).unwrap_err(),
                TsError::Limit
            );
        }
        let mut two = original.clone();
        let count = original.len() / TS_PACKET_BYTES - 2;
        two.extend(packetize(
            VIDEO_PID,
            &pes_bytes(&AVC[..20], None, None, true),
            count as u8 & 15,
            184,
        ));
        assert_eq!(
            MpegTsVideo::parse(
                &two,
                TsSelection::default(),
                TsLimits {
                    max_pes: 1,
                    ..baseline
                }
            )
            .unwrap_err(),
            TsError::Limit
        );
        for stop in [0, 2, original.len() / TS_PACKET_BYTES + 2] {
            let mut calls = 0;
            let result = MpegTsVideo::parse_with_checkpoint(
                &original,
                TsSelection::default(),
                baseline,
                &mut || {
                    if calls == stop {
                        return Err(TsError::Cancelled);
                    }
                    calls += 1;
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err(), TsError::Cancelled);
        }
        assert_eq!(
            MpegTsVideo::parse(
                &original,
                TsSelection {
                    program: Some(0),
                    video_pid: None
                },
                baseline
            )
            .unwrap_err(),
            TsError::Configuration
        );
        assert_eq!(
            MpegTsVideo::parse(
                &original,
                TsSelection::default(),
                TsLimits {
                    max_packets: MAX_PACKETS + 1,
                    ..baseline
                }
            )
            .unwrap_err(),
            TsError::Configuration
        );
    }
    #[test]
    fn interleaved_audio_and_null_packets_remain_original_source_only() {
        let original = stream(AVC, 0x1b);
        let mut bytes = original[..3 * TS_PACKET_BYTES].to_vec();
        bytes.extend(packet(VIDEO_PID + 1, true, 7, &[0x55; 184]));
        bytes.extend(packet(0x1fff, false, 13, &[0xff; 184]));
        bytes.extend_from_slice(&original[3 * TS_PACKET_BYTES..]);
        let video = parse(&bytes).unwrap();
        assert_eq!(video.elementary_stream(), AVC);
        assert_eq!(
            video.packets_inspected(),
            original.len() / TS_PACKET_BYTES + 2
        );
        assert_map(&video);
        let first = &video.payload_spans()[0];
        let second = &video.payload_spans()[1];
        assert!(second.source.start - first.source.end >= 2 * TS_PACKET_BYTES);
    }
    #[test]
    fn invalid_psi_pointers_and_all_retained_fixture_prefixes_are_bounded() {
        for payload in [vec![255, 0], vec![0, 0xff], vec![1, 0, 0]] {
            assert_eq!(
                parse(&packet(0, true, 0, &payload)).unwrap_err(),
                TsError::Psi
            );
        }
        for fixture in [AVC_TS, HEVC_TS] {
            for end in 0..fixture.len() {
                if let Ok(video) = parse(&fixture[..end]) {
                    assert_map(&video);
                }
            }
        }
    }

    #[test]
    fn source_envelopes_include_only_required_original_extents() {
        let bytes = stream(AVC, 0x1b);
        let video = parse(&bytes).unwrap();
        let first = &video.payload_spans()[0];
        let second = &video.payload_spans()[1];
        let range = first.elementary.end - 2..second.elementary.start + 3;
        let envelope = video.source_envelope(range.clone()).unwrap();
        assert_eq!(envelope, first.source.end - 2..second.source.start + 3);
        assert!(envelope.len() > range.len());
        assert_eq!(
            video.source_envelope(0..1).unwrap(),
            first.source.start..first.source.start + 1
        );
        let last = video.payload_spans().last().unwrap();
        let end = video.elementary_stream().len();
        assert_eq!(
            video.source_envelope(end - 1..end).unwrap(),
            last.source.end - 1..last.source.end
        );
        assert_eq!(
            video.source_envelope(0..0).unwrap_err(),
            TsError::Configuration
        );
        assert_eq!(
            video.source_envelope(0..end + 1).unwrap_err(),
            TsError::Configuration
        );
    }
}
