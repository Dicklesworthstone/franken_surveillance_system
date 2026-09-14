#![forbid(unsafe_code)]
//! Deterministic synthetic media fixture generation for H.264 Annex-B and rtpdump.
//!
//! Note on media decodability: all generated payloads have structurally valid
//! NAL syntax, synthetic slice payloads, and packet framing; pictures are not decodable.

pub mod h264;
pub mod rtpdump;
pub mod rtsp;

pub use h264::{
    H264AnnexBStream, H264FixtureParams, NalUnitSpan, SyntheticNal, build_h264_manifest_json,
    generate_h264_annexb,
};
pub use rtpdump::{
    RD_HDR_LEN, RD_PKT_HDR_LEN, RTPDUMP_MAGIC_HEADER, RtpdumpFixture, RtpdumpPacketDesc,
    RtpdumpParams, build_rtp_manifest_json, generate_rtpdump_clean, generate_rtpdump_duplicate,
    generate_rtpdump_large_gap, generate_rtpdump_loss, generate_rtpdump_reorder,
    generate_rtpdump_ssrc_reset, generate_rtpdump_truncated_last_record,
};
pub use rtsp::{
    DEFAULT_RTCP_CNAME, DEFAULT_RTSP_CLOCK_RATE_HZ, DEFAULT_RTSP_INITIAL_SEQUENCE,
    DEFAULT_RTSP_MTU, DEFAULT_RTSP_PAYLOAD_TYPE, DEFAULT_RTSP_SESSION_ID, DEFAULT_RTSP_SSRC,
    DEFAULT_RTSP_STREAM_URI, RTSP_TRANSCRIPT_MAGIC_HEADER, RtspSenderReportDesc,
    RtspTranscriptFixture, RtspTranscriptParams, TranscriptDirection, TranscriptRecord,
    build_compound_rtcp_sr, build_rtcp_sdes_cname, build_rtcp_sender_report,
    build_rtsp_manifest_json, encode_interleaved_frame, generate_transcript_auth_required,
    generate_transcript_bad_content_length, generate_transcript_clean,
    generate_transcript_get_parameter_keepalive, generate_transcript_interleave_split,
    generate_transcript_rtcp_rsize, generate_transcript_session_timeout,
    generate_transcript_sr_absent, parse_transcript, serialize_transcript,
};

use std::fmt;

/// Canonical schema identifier for media fixture manifests.
pub const MEDIA_FIXTURE_MANIFEST_SCHEMA: &str = "fss.media_fixture.manifest.v1";

/// Mandatory disclaimer note present in all media fixture manifests.
pub const MEDIA_FIXTURE_NOTE: &str = "structurally valid NAL syntax; pictures are not decodable";

/// Expected packet sequence classification under RFC 3550 A.1 continuity rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExpectedSequenceClass {
    /// Initial unconfirmed packet waiting for two sequential arrivals.
    Probation,
    /// Second sequential packet establishing stream baseline.
    Baseline,
    /// In-order arrival advancing highest admitted sequence.
    Advanced,
    /// Previously missing packet arriving out of order within history window.
    Reordered,
    /// Already observed sequence number within history window.
    Duplicate,
    /// Packet strictly older than admitted baseline.
    BeforeBaseline,
    /// Gap exceeding forward jump threshold (>= 3000).
    DiscontinuitySuspected,
    /// Consecutive discontinuous packets requiring epoch restart.
    RestartRequired,
}

impl ExpectedSequenceClass {
    /// String representation matching fss-packet SequenceClass variant names.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Probation => "Probation",
            Self::Baseline => "Baseline",
            Self::Advanced => "Advanced",
            Self::Reordered => "Reordered",
            Self::Duplicate => "Duplicate",
            Self::BeforeBaseline => "BeforeBaseline",
            Self::DiscontinuitySuspected => "DiscontinuitySuspected",
            Self::RestartRequired => "RestartRequired",
        }
    }

    /// Parses string representation back into variant.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Probation" => Some(Self::Probation),
            "Baseline" => Some(Self::Baseline),
            "Advanced" => Some(Self::Advanced),
            "Reordered" => Some(Self::Reordered),
            "Duplicate" => Some(Self::Duplicate),
            "BeforeBaseline" => Some(Self::BeforeBaseline),
            "DiscontinuitySuspected" => Some(Self::DiscontinuitySuspected),
            "RestartRequired" => Some(Self::RestartRequired),
            _ => None,
        }
    }
}

/// Errors occurring during media fixture synthesis or parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediaFixtureError {
    /// Invalid parameter supplied to generator.
    InvalidParam(&'static str),
    /// Buffer overflow during bitstream synthesis.
    BufferOverflow,
    /// Input stream truncated unexpectedly.
    TruncatedData,
    /// Digest mismatch during self-verification.
    DigestMismatch {
        /// Expected hex-encoded digest string.
        expected: String,
        /// Observed actual hex-encoded digest string.
        actual: String,
    },
    /// String formatting error during manifest generation.
    FormattingError,
}

impl fmt::Display for MediaFixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParam(p) => write!(f, "invalid media fixture parameter: {p}"),
            Self::BufferOverflow => write!(f, "buffer overflow during media synthesis"),
            Self::TruncatedData => write!(f, "unexpected truncated media data"),
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "fixture digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::FormattingError => write!(f, "error formatting media fixture manifest JSON"),
        }
    }
}

impl std::error::Error for MediaFixtureError {}

/// Lightweight, deterministic SplitMix64 pseudo-random generator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicMediaPrng {
    state: u64,
}

impl DeterministicMediaPrng {
    /// Constructs a PRNG seeded with the given value.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9e37_79b9_7f4a_7c15),
        }
    }

    /// Generates the next pseudo-random 64-bit unsigned integer.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Generates the next pseudo-random 32-bit unsigned integer.
    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    /// Generates the next pseudo-random 16-bit unsigned integer.
    pub fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }

    /// Generates the next pseudo-random 8-bit unsigned integer.
    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// Fills destination slice with deterministic bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let val = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&val[..len]);
        }
    }
}

/// Bit-oriented writer for constructing H.264 slice and parameter headers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    bits_in_byte: u8,
}

impl BitWriter {
    /// Constructs an empty bit writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a single bit (0 or 1).
    pub fn write_bit(&mut self, bit: u8) {
        self.current_byte = (self.current_byte << 1) | (bit & 1);
        self.bits_in_byte += 1;
        if self.bits_in_byte == 8 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.bits_in_byte = 0;
        }
    }

    /// Appends `num_bits` from the least significant bits of `val`.
    pub fn write_bits(&mut self, val: u64, num_bits: u8) {
        for i in (0..num_bits).rev() {
            let bit = ((val >> i) & 1) as u8;
            self.write_bit(bit);
        }
    }

    /// Encodes an unsigned integer as an Exp-Golomb bit sequence (ue(v)).
    pub fn write_ue(&mut self, val: u32) {
        if val == 0 {
            self.write_bit(1);
        } else {
            let val_plus_1 = val + 1;
            let bit_len = 32 - val_plus_1.leading_zeros();
            let zeros = (bit_len - 1) as u8;
            for _ in 0..zeros {
                self.write_bit(0);
            }
            self.write_bits(val_plus_1 as u64, bit_len as u8);
        }
    }

    /// Encodes a signed integer as a Signed Exp-Golomb bit sequence (se(v)).
    pub fn write_se(&mut self, val: i32) {
        let code_num = if val <= 0 {
            (-val as u32).wrapping_mul(2)
        } else {
            (val as u32).wrapping_mul(2).wrapping_sub(1)
        };
        self.write_ue(code_num);
    }

    /// Writes rbsp_trailing_bits (a single 1 bit followed by zero bits to byte align).
    pub fn write_rbsp_trailing_bits(&mut self) {
        self.write_bit(1);
        while self.bits_in_byte != 0 {
            self.write_bit(0);
        }
    }

    /// Consumes the writer and returns the finalized byte vector.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        if self.bits_in_byte != 0 {
            self.current_byte <<= 8 - self.bits_in_byte;
            self.bytes.push(self.current_byte);
        }
        self.bytes
    }
}

/// Converts an RBSP slice into NAL wire bytes with 0x03 emulation prevention bytes.
///
/// Prepend `nal_header` at byte 0, then scans RBSP bytes. Whenever two consecutive
/// 0x00 bytes are followed by a byte <= 0x03, an emulation prevention byte (0x03)
/// is inserted between the zeros and the third byte.
#[must_use]
pub fn rbsp_to_nal_wire(nal_header: u8, rbsp: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(rbsp.len() + 1 + (rbsp.len() / 32) + 4);
    wire.push(nal_header);
    let mut zero_count = 0usize;
    for &b in rbsp {
        if zero_count >= 2 && b <= 3 {
            wire.push(0x03);
            zero_count = 0;
        }
        wire.push(b);
        if b == 0x00 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }
    wire
}

/// Removes emulation prevention bytes (0x03) from NAL wire bytes, returning
/// the NAL header and the unescaped raw RBSP byte vector.
#[must_use]
pub fn nal_wire_to_rbsp(wire: &[u8]) -> (u8, Vec<u8>) {
    if wire.is_empty() {
        return (0, Vec::new());
    }
    let nal_header = wire[0];
    let payload = &wire[1..];
    let mut rbsp = Vec::with_capacity(payload.len());
    let mut i = 0;
    while i < payload.len() {
        if i + 2 < payload.len()
            && payload[i] == 0x00
            && payload[i + 1] == 0x00
            && payload[i + 2] == 0x03
            && (i + 3 >= payload.len() || payload[i + 3] <= 0x03)
        {
            rbsp.push(0x00);
            rbsp.push(0x00);
            i += 3;
        } else {
            rbsp.push(payload[i]);
            i += 1;
        }
    }
    (nal_header, rbsp)
}
