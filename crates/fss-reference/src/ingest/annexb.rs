//! Bounded H.264 Annex-B elementary-stream splitter with exact source spans.
//!
//! A recorded `.h264` file is an Annex-B elementary byte stream consisting of
//! 3-byte (`0x000001`) and 4-byte (`0x00000001`) start codes, NAL units, and
//! emulation-prevention bytes.
//!
//! Exact byte spans into the original source buffer are recorded without copying
//! or reallocating the stream. Emulation-prevention bytes are retained for exact
//! source custody. Access units are grouped deterministically per H.264 7.4.1.2.3.

use std::fmt;

use crate::adapter_replay::ReplayCx;

/// Default maximum stream size: 16 MiB.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum NAL unit size: 8 MiB (matching fss-packet H264Limits).
pub const DEFAULT_MAX_NAL_BYTES: usize = 8 * 1024 * 1024;

/// Hard ceiling for maximum NAL unit size: 16 MiB (matching fss-packet H264Limits ceiling).
pub const CEILING_MAX_NAL_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum NAL count: 65,536.
pub const DEFAULT_MAX_NALS: usize = 65_536;

/// Default maximum Access Unit count: 16,384.
pub const DEFAULT_MAX_AUS: usize = 16_384;

/// Checkpoint frequency: 1 MiB scanned.
const CHECKPOINT_INTERVAL_BYTES: usize = 1024 * 1024;

/// Scratch buffer size for decoding Exp-Golomb `ue(v)` fields from slice headers.
const RBSP_SCRATCH_SIZE: usize = 64;

/// Exact byte span in the source elementary stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SourceSpan {
    /// Byte offset in the original byte slice.
    pub offset: usize,
    /// Byte length in the original byte slice.
    pub len: usize,
}

impl SourceSpan {
    /// Creates a new source span.
    #[must_use]
    pub const fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }

    /// Returns the end byte offset (exclusive).
    #[must_use]
    pub const fn end(&self) -> usize {
        self.offset.saturating_add(self.len)
    }

    /// Returns `true` if this span has length 0.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Parsed H.264 NAL unit with exact source byte spans and header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnexBNal {
    /// Exact byte span of the preceding start code (3 or 4 bytes).
    pub start_code_span: SourceSpan,
    /// Exact byte span of the NAL unit itself in the original byte slice.
    /// Emulation-prevention bytes are retained for source custody.
    pub nal_span: SourceSpan,
    /// Forbidden zero bit (must be 0; non-zero triggers [`AnnexBError::ForbiddenBitSet`]).
    pub forbidden_zero_bit: u8,
    /// NAL reference IDC (2 bits, 0..=3).
    pub nal_ref_idc: u8,
    /// NAL unit type (5 bits, 0..=31).
    pub nal_unit_type: u8,
}

impl AnnexBNal {
    /// Returns the combined source span covering the start code and the NAL unit.
    #[must_use]
    pub const fn full_span(&self) -> SourceSpan {
        SourceSpan::new(
            self.start_code_span.offset,
            self.start_code_span.len.saturating_add(self.nal_span.len),
        )
    }

    /// Returns `true` if this NAL unit belongs to the Video Coding Layer (types 1..=5).
    #[must_use]
    pub const fn is_vcl(&self) -> bool {
        self.nal_unit_type >= 1 && self.nal_unit_type <= 5
    }

    /// Returns `true` if this NAL is an IDR slice (type 5).
    #[must_use]
    pub const fn is_idr(&self) -> bool {
        self.nal_unit_type == 5
    }

    /// Returns `true` if this NAL is a Sequence Parameter Set (type 7).
    #[must_use]
    pub const fn is_sps(&self) -> bool {
        self.nal_unit_type == 7
    }

    /// Returns `true` if this NAL is a Picture Parameter Set (type 8).
    #[must_use]
    pub const fn is_pps(&self) -> bool {
        self.nal_unit_type == 8
    }

    /// Returns `true` if this NAL is an Access Unit Delimiter (type 9).
    #[must_use]
    pub const fn is_aud(&self) -> bool {
        self.nal_unit_type == 9
    }

    /// Returns `true` if this NAL is Supplemental Enhancement Information (type 6).
    #[must_use]
    pub const fn is_sei(&self) -> bool {
        self.nal_unit_type == 6
    }
}

/// Grouped Access Unit per H.264 7.4.1.2.3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnexBAccessUnit {
    /// Source span covering this access unit.
    pub span: SourceSpan,
    /// Indices of NAL units in [`AnnexBScan::nals`] belonging to this access unit.
    pub nal_indices: Vec<usize>,
    /// Whether an IDR slice (type 5) is present in this access unit.
    pub is_idr: bool,
    /// Whether a Sequence Parameter Set (type 7) is present in this access unit.
    pub has_sps: bool,
    /// Whether a Picture Parameter Set (type 8) is present in this access unit.
    pub has_pps: bool,
    /// Count of VCL slice NAL units (types 1..=5) in this access unit.
    pub slice_count: usize,
    /// Typed flag indicating the access unit contains slices but no preceding SPS and PPS
    /// have been observed in the stream.
    pub undecodable_without_parameter_sets: bool,
}

/// Operational bounds for H.264 Annex-B scanning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnexBLimits {
    /// Maximum allowed stream size in bytes before refusal.
    pub max_input_bytes: usize,
    /// Maximum allowed size of a single NAL unit in bytes including header.
    pub max_nal_bytes: usize,
    /// Maximum allowed number of NAL units in the stream before refusal.
    pub max_nals: usize,
    /// Maximum allowed number of Access Units in the stream before refusal.
    pub max_aus: usize,
    /// Maximum allowed leading unparsed bytes before the first start code before refusal.
    pub max_leading_garbage_bytes: usize,
}

impl Default for AnnexBLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_nal_bytes: DEFAULT_MAX_NAL_BYTES,
            max_nals: DEFAULT_MAX_NALS,
            max_aus: DEFAULT_MAX_AUS,
            max_leading_garbage_bytes: 0,
        }
    }
}

impl AnnexBLimits {
    /// Sets the maximum input bytes.
    #[must_use]
    pub const fn with_max_input_bytes(mut self, max: usize) -> Self {
        self.max_input_bytes = max;
        self
    }

    /// Sets the maximum NAL unit bytes.
    #[must_use]
    pub const fn with_max_nal_bytes(mut self, max: usize) -> Self {
        self.max_nal_bytes = max;
        self
    }

    /// Sets the maximum NAL count.
    #[must_use]
    pub const fn with_max_nals(mut self, max: usize) -> Self {
        self.max_nals = max;
        self
    }

    /// Sets the maximum Access Unit count.
    #[must_use]
    pub const fn with_max_aus(mut self, max: usize) -> Self {
        self.max_aus = max;
        self
    }

    /// Sets the maximum tolerated leading garbage bytes before the first start code.
    #[must_use]
    pub const fn with_max_leading_garbage_bytes(mut self, max: usize) -> Self {
        self.max_leading_garbage_bytes = max;
        self
    }
}

/// Result of an Annex-B elementary stream scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnexBScan {
    /// Parsed NAL units in stream order.
    pub nals: Vec<AnnexBNal>,
    /// Access units grouped per H.264 7.4.1.2.3.
    pub access_units: Vec<AnnexBAccessUnit>,
    /// Inter-NAL padding spans (trailing_zero_8bits preceding start codes or stream end).
    pub padding_spans: Vec<SourceSpan>,
    /// Omission spans (e.g. tolerated leading unparsed bytes).
    pub omission_spans: Vec<SourceSpan>,
    /// Raw source spans for Sequence Parameter Sets (type 7).
    pub sps_spans: Vec<SourceSpan>,
    /// Raw source spans for Picture Parameter Sets (type 8).
    pub pps_spans: Vec<SourceSpan>,
    /// Source spans for unsupported extension NAL units (e.g. subset SPS type 15, slice extension type 20).
    pub unsupported_extension_spans: Vec<SourceSpan>,
    /// Name of the Access Unit grouping rule (e.g. `"first_mb_in_slice_heuristic"`).
    pub au_grouping: &'static str,
    /// Total bytes scanned.
    pub total_bytes: usize,
}

impl AnnexBScan {
    /// Returns the number of parsed NAL units.
    #[must_use]
    pub fn nal_count(&self) -> usize {
        self.nals.len()
    }

    /// Returns the number of grouped Access Units.
    #[must_use]
    pub fn au_count(&self) -> usize {
        self.access_units.len()
    }

    /// Returns `true` if any Access Unit in the scan contains an IDR slice.
    #[must_use]
    pub fn has_idr(&self) -> bool {
        self.access_units.iter().any(|au| au.is_idr)
    }

    /// Returns `true` if at least one SPS NAL was scanned.
    #[must_use]
    pub fn has_sps(&self) -> bool {
        !self.sps_spans.is_empty()
    }

    /// Returns `true` if at least one PPS NAL was scanned.
    #[must_use]
    pub fn has_pps(&self) -> bool {
        !self.pps_spans.is_empty()
    }
}

/// Deterministic typed errors for Annex-B stream splitting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnnexBError {
    /// Input byte slice is empty.
    EmptyInput,
    /// No Annex-B start code (`0x000001` or `0x00000001`) found.
    NoStartCode,
    /// Forbidden zero bit in NAL unit header is set to 1.
    ForbiddenBitSet {
        /// NAL index in stream.
        nal: usize,
        /// Byte offset of the NAL header.
        offset: usize,
    },
    /// NAL unit size exceeds configured limit.
    NalTooLarge {
        /// Byte offset of NAL unit.
        offset: usize,
        /// Observed NAL unit length.
        len: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Total NAL unit count exceeds configured limit.
    TooManyNals {
        /// Observed count.
        count: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Total Access Unit count exceeds configured limit.
    TooManyAccessUnits {
        /// Observed count.
        count: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Stream ended abruptly inside a NAL unit or without NAL payload.
    TruncatedNal {
        /// Byte offset where truncation occurred.
        offset: usize,
    },
    /// Stream truncated inside a start code prefix.
    TruncatedStartCode {
        /// Byte offset where truncation occurred.
        offset: usize,
    },
    /// Stream truncated inside slice header (cannot read `first_mb_in_slice`).
    TruncatedSliceHeader {
        /// Byte offset of the NAL unit.
        offset: usize,
    },
    /// Leading unparsed data before first start code exceeds limit.
    LeadingGarbage {
        /// Length of leading unparsed data.
        len: usize,
    },
    /// Trailing unparsed data at stream end.
    TrailingGarbage {
        /// Byte offset where trailing data begins.
        offset: usize,
        /// Length of trailing data.
        len: usize,
    },
    /// Unparsed non-zero data between NAL units.
    Garbage {
        /// Byte offset of garbage data.
        offset: usize,
        /// Length of garbage data.
        len: usize,
    },
    /// Zero-length NAL unit between consecutive start codes.
    ZeroLengthNal {
        /// Byte offset where zero-length NAL occurs.
        offset: usize,
    },
    /// Total input size exceeds configured limit.
    InputTooLarge {
        /// Observed input length.
        len: usize,
        /// Maximum allowed limit.
        max: usize,
    },
    /// Cooperative cancellation requested via [`ReplayCx`].
    Cancelled,
    /// Malformed emulation prevention sequence (e.g. `0x000003` followed by byte > 3 or EOF).
    MalformedEmulationPrevention {
        /// Byte offset of malformed sequence.
        offset: usize,
    },
    /// Malformed Exp-Golomb `ue(v)` code word in slice header.
    MalformedSliceHeader {
        /// Byte offset of the NAL unit.
        offset: usize,
        /// Detail explanation.
        detail: &'static str,
    },
}

impl fmt::Display for AnnexBError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "Annex-B elementary stream input is empty"),
            Self::NoStartCode => write!(f, "no Annex-B start code found in input stream"),
            Self::ForbiddenBitSet { nal, offset } => {
                write!(
                    f,
                    "NAL unit {nal} at byte offset {offset} has forbidden_zero_bit set"
                )
            }
            Self::NalTooLarge { offset, len, max } => {
                write!(
                    f,
                    "NAL unit at offset {offset} with length {len} exceeds limit of {max} bytes"
                )
            }
            Self::TooManyNals { count, max } => {
                write!(f, "NAL count {count} exceeds limit of {max}")
            }
            Self::TooManyAccessUnits { count, max } => {
                write!(f, "access unit count {count} exceeds limit of {max}")
            }
            Self::TruncatedNal { offset } => {
                write!(f, "stream truncated inside NAL unit at offset {offset}")
            }
            Self::TruncatedStartCode { offset } => {
                write!(
                    f,
                    "stream truncated inside start code prefix at offset {offset}"
                )
            }
            Self::TruncatedSliceHeader { offset } => {
                write!(f, "stream truncated inside slice header at offset {offset}")
            }
            Self::LeadingGarbage { len } => {
                write!(
                    f,
                    "stream begins with {len} bytes of unparsed leading data before first start code"
                )
            }
            Self::TrailingGarbage { offset, len } => {
                write!(
                    f,
                    "stream ends with {len} bytes of unparsed trailing data at offset {offset}"
                )
            }
            Self::Garbage { offset, len } => {
                write!(
                    f,
                    "encountered {len} bytes of unparsed data at offset {offset}"
                )
            }
            Self::ZeroLengthNal { offset } => {
                write!(f, "zero-length NAL unit encountered at offset {offset}")
            }
            Self::InputTooLarge { len, max } => {
                write!(f, "input size {len} bytes exceeds limit of {max} bytes")
            }
            Self::Cancelled => {
                write!(f, "Annex-B scanning cancelled via execution context")
            }
            Self::MalformedEmulationPrevention { offset } => {
                write!(
                    f,
                    "malformed emulation prevention sequence at offset {offset}"
                )
            }
            Self::MalformedSliceHeader { offset, detail } => {
                write!(f, "malformed slice header at offset {offset}: {detail}")
            }
        }
    }
}

impl std::error::Error for AnnexBError {}

/// Scans an Annex-B elementary stream, enforcing operational bounds, cancellation checkpoints,
/// and exact byte coverage.
pub fn split_annexb(
    bytes: &[u8],
    limits: AnnexBLimits,
    cx: &ReplayCx,
) -> Result<AnnexBScan, AnnexBError> {
    if bytes.is_empty() {
        return Err(AnnexBError::EmptyInput);
    }
    if bytes.len() > limits.max_input_bytes {
        return Err(AnnexBError::InputTooLarge {
            len: bytes.len(),
            max: limits.max_input_bytes,
        });
    }

    if cx.is_cancelled() {
        cx.drain_and_finalize();
        return Err(AnnexBError::Cancelled);
    }

    // Step 1: Locate the first start code.
    let first_sc3 = match find_start_code(bytes, 0) {
        Some(pos) => pos,
        None => return Err(AnnexBError::NoStartCode),
    };

    let (mut cur_sc_offset, mut cur_sc_len) = if first_sc3 > 0 && bytes[first_sc3 - 1] == 0x00 {
        (first_sc3 - 1, 4)
    } else {
        (first_sc3, 3)
    };

    let mut omission_spans = Vec::new();
    let mut padding_spans = Vec::new();

    // Check bytes prior to the first start code.
    if cur_sc_offset > 0 {
        let mut all_zeros = true;
        for &b in &bytes[..cur_sc_offset] {
            if b != 0x00 {
                all_zeros = false;
                break;
            }
        }
        if all_zeros {
            // Preceding zero bytes are leading_zero_8bits per ITU-T H.264 B.1.1
            padding_spans.push(SourceSpan::new(0, cur_sc_offset));
        } else {
            // Non-zero leading garbage
            let garbage_len = cur_sc_offset;
            if garbage_len > limits.max_leading_garbage_bytes {
                return Err(AnnexBError::LeadingGarbage { len: garbage_len });
            }
            omission_spans.push(SourceSpan::new(0, garbage_len));
        }
    }

    let mut nals = Vec::new();
    let mut cur_nal_start = cur_sc_offset.saturating_add(cur_sc_len);
    let mut next_checkpoint = CHECKPOINT_INTERVAL_BYTES;

    // Step 2: Iterate through start codes and delineate NAL units.
    loop {
        if cur_nal_start >= next_checkpoint {
            if cx.is_cancelled() {
                cx.drain_and_finalize();
                return Err(AnnexBError::Cancelled);
            }
            next_checkpoint = next_checkpoint.saturating_add(CHECKPOINT_INTERVAL_BYTES);
        }

        let next_sc3_opt = find_start_code(bytes, cur_nal_start);
        match next_sc3_opt {
            Some(next_sc3) => {
                let (next_sc_offset, next_sc_len) =
                    if next_sc3 > cur_nal_start && bytes[next_sc3 - 1] == 0x00 {
                        (next_sc3 - 1, 4)
                    } else {
                        (next_sc3, 3)
                    };

                if cur_nal_start == next_sc_offset {
                    return Err(AnnexBError::ZeroLengthNal {
                        offset: cur_nal_start,
                    });
                }

                // Check for trailing_zero_8bits padding before next start code
                let mut pad_start = next_sc_offset;
                while pad_start > cur_nal_start && bytes[pad_start - 1] == 0x00 {
                    pad_start -= 1;
                }

                if pad_start == cur_nal_start {
                    // All bytes between start codes were zeros: no NAL payload/header
                    return Err(AnnexBError::ZeroLengthNal {
                        offset: cur_nal_start,
                    });
                }

                let nal_len = pad_start.saturating_sub(cur_nal_start);
                if pad_start < next_sc_offset {
                    padding_spans.push(SourceSpan::new(
                        pad_start,
                        next_sc_offset.saturating_sub(pad_start),
                    ));
                }

                let nal = validate_and_create_nal(
                    bytes,
                    cur_sc_offset,
                    cur_sc_len,
                    cur_nal_start,
                    nal_len,
                    nals.len(),
                    limits.max_nal_bytes,
                )?;
                nals.push(nal);

                if nals.len() > limits.max_nals {
                    return Err(AnnexBError::TooManyNals {
                        count: nals.len(),
                        max: limits.max_nals,
                    });
                }

                cur_sc_offset = next_sc_offset;
                cur_sc_len = next_sc_len;
                cur_nal_start = next_sc_offset.saturating_add(next_sc_len);
            }
            None => {
                // Final NAL unit in the stream
                if cur_nal_start >= bytes.len() {
                    return Err(AnnexBError::TruncatedNal {
                        offset: cur_nal_start,
                    });
                }

                let mut pad_start = bytes.len();
                while pad_start > cur_nal_start && bytes[pad_start - 1] == 0x00 {
                    pad_start -= 1;
                }

                if pad_start == cur_nal_start {
                    return Err(AnnexBError::TruncatedNal {
                        offset: cur_nal_start,
                    });
                }

                let nal_len = pad_start.saturating_sub(cur_nal_start);
                if pad_start < bytes.len() {
                    padding_spans.push(SourceSpan::new(
                        pad_start,
                        bytes.len().saturating_sub(pad_start),
                    ));
                }

                let nal = validate_and_create_nal(
                    bytes,
                    cur_sc_offset,
                    cur_sc_len,
                    cur_nal_start,
                    nal_len,
                    nals.len(),
                    limits.max_nal_bytes,
                )?;
                nals.push(nal);

                if nals.len() > limits.max_nals {
                    return Err(AnnexBError::TooManyNals {
                        count: nals.len(),
                        max: limits.max_nals,
                    });
                }

                break;
            }
        }
    }

    if cx.is_cancelled() {
        cx.drain_and_finalize();
        return Err(AnnexBError::Cancelled);
    }

    // Step 3: Access unit grouping per H.264 7.4.1.2.3.
    let access_units = group_access_units(bytes, &nals, limits.max_aus)?;

    // Step 4: Catalog SPS, PPS, and unsupported extension spans.
    let mut sps_spans = Vec::new();
    let mut pps_spans = Vec::new();
    let mut unsupported_extension_spans = Vec::new();
    for nal in &nals {
        if nal.is_sps() {
            sps_spans.push(nal.nal_span);
        } else if nal.is_pps() {
            pps_spans.push(nal.nal_span);
        } else if nal.nal_unit_type == 15 || nal.nal_unit_type == 20 {
            unsupported_extension_spans.push(nal.nal_span);
        }
    }

    Ok(AnnexBScan {
        nals,
        access_units,
        padding_spans,
        omission_spans,
        sps_spans,
        pps_spans,
        unsupported_extension_spans,
        au_grouping: "first_mb_in_slice_heuristic",
        total_bytes: bytes.len(),
    })
}

/// Searches for the 3-byte start code prefix `[0x00, 0x00, 0x01]` starting from `from`.
fn find_start_code(bytes: &[u8], from: usize) -> Option<usize> {
    if from >= bytes.len() {
        return None;
    }
    let mut i = from;
    while i.saturating_add(2) < bytes.len() {
        if bytes[i] == 0x00 && bytes[i + 1] == 0x00 && bytes[i + 2] == 0x01 {
            return Some(i);
        }
        i = i.saturating_add(1);
    }
    None
}

/// Validates NAL size, header forbidden bit, and emulation-prevention constraints.
fn validate_and_create_nal(
    bytes: &[u8],
    sc_offset: usize,
    sc_len: usize,
    nal_offset: usize,
    nal_len: usize,
    nal_idx: usize,
    max_nal_bytes: usize,
) -> Result<AnnexBNal, AnnexBError> {
    if nal_len > max_nal_bytes {
        return Err(AnnexBError::NalTooLarge {
            offset: nal_offset,
            len: nal_len,
            max: max_nal_bytes,
        });
    }

    if nal_len == 0 {
        return Err(AnnexBError::ZeroLengthNal { offset: nal_offset });
    }

    let header_byte = bytes[nal_offset];
    let forbidden_zero_bit = (header_byte >> 7) & 1;
    if forbidden_zero_bit != 0 {
        return Err(AnnexBError::ForbiddenBitSet {
            nal: nal_idx,
            offset: nal_offset,
        });
    }

    let nal_ref_idc = (header_byte >> 5) & 0x03;
    let nal_unit_type = header_byte & 0x1F;

    // Validate emulation prevention in payload
    let payload = &bytes[nal_offset.saturating_add(1)..nal_offset.saturating_add(nal_len)];
    validate_emulation_prevention(payload, nal_offset.saturating_add(1))?;

    Ok(AnnexBNal {
        start_code_span: SourceSpan::new(sc_offset, sc_len),
        nal_span: SourceSpan::new(nal_offset, nal_len),
        forbidden_zero_bit: 0,
        nal_ref_idc,
        nal_unit_type,
    })
}

/// Validates emulation prevention sequences in a NAL payload per H.264 7.3.1.
fn validate_emulation_prevention(payload: &[u8], base_offset: usize) -> Result<(), AnnexBError> {
    let mut i: usize = 0;
    while i.saturating_add(2) < payload.len() {
        if payload[i] == 0x00 && payload[i + 1] == 0x00 {
            let third = payload[i + 2];
            if third == 0x03 {
                // Emulation prevention byte. Must be followed by 0x00, 0x01, 0x02, or 0x03.
                if i.saturating_add(3) >= payload.len() {
                    return Err(AnnexBError::MalformedEmulationPrevention {
                        offset: base_offset.saturating_add(i),
                    });
                }
                let fourth = payload[i + 3];
                if fourth > 0x03 {
                    return Err(AnnexBError::MalformedEmulationPrevention {
                        offset: base_offset.saturating_add(i),
                    });
                }
                // Valid emulation prevention sequence: skip past the 0x03 byte
                i = i.saturating_add(3);
                continue;
            } else if third == 0x00 {
                // If followed by 0x03 (e.g. 00 00 00 03), a valid emulation prevention
                // sequence begins at the next byte (i + 1).
                if i.saturating_add(3) < payload.len() && payload[i + 3] == 0x03 {
                    i = i.saturating_add(1);
                    continue;
                }
                return Err(AnnexBError::MalformedEmulationPrevention {
                    offset: base_offset.saturating_add(i),
                });
            } else if third == 0x01 || third == 0x02 {
                // Forbidden unescaped sequence within NAL payload
                return Err(AnnexBError::MalformedEmulationPrevention {
                    offset: base_offset.saturating_add(i),
                });
            }
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// State tracking for assembling an Access Unit during grouping.
struct AuAccumulator {
    nal_indices: Vec<usize>,
    has_vcl: bool,
    is_idr: bool,
    has_sps: bool,
    has_pps: bool,
    slice_count: usize,
    first_sc_offset: usize,
}

/// Groups parsed NAL units into Access Units per H.264 7.4.1.2.3.
fn group_access_units(
    bytes: &[u8],
    nals: &[AnnexBNal],
    max_aus: usize,
) -> Result<Vec<AnnexBAccessUnit>, AnnexBError> {
    let mut aus: Vec<AnnexBAccessUnit> = Vec::new();
    let mut current_au: Option<AuAccumulator> = None;
    let mut stream_has_sps = false;
    let mut stream_has_pps = false;

    for (nal_idx, nal) in nals.iter().enumerate() {
        let first_mb = if nal.is_vcl() {
            Some(decode_first_mb_in_slice(bytes, nal)?)
        } else {
            None
        };

        let starts_new_au = match &current_au {
            None => true,
            Some(builder) => {
                if nal.is_aud() {
                    true
                } else if builder.has_vcl {
                    if nal.is_vcl() {
                        first_mb == Some(0)
                    } else {
                        // SPS, PPS, SEI, 14..=18, or end markers after a VCL NAL start a new AU
                        nal.is_sps()
                            || nal.is_pps()
                            || nal.is_sei()
                            || (14..=18).contains(&nal.nal_unit_type)
                            || nal.nal_unit_type == 10
                            || nal.nal_unit_type == 11
                    }
                } else {
                    false
                }
            }
        };

        if starts_new_au {
            if let Some(builder) = current_au.take() {
                let au_end = nal.start_code_span.offset;
                let au_len = au_end.saturating_sub(builder.first_sc_offset);
                if builder.has_sps {
                    stream_has_sps = true;
                }
                if builder.has_pps {
                    stream_has_pps = true;
                }
                let undecodable = builder.slice_count > 0 && (!stream_has_sps || !stream_has_pps);

                aus.push(AnnexBAccessUnit {
                    span: SourceSpan::new(builder.first_sc_offset, au_len),
                    nal_indices: builder.nal_indices,
                    is_idr: builder.is_idr,
                    has_sps: builder.has_sps,
                    has_pps: builder.has_pps,
                    slice_count: builder.slice_count,
                    undecodable_without_parameter_sets: undecodable,
                });

                if aus.len() > max_aus {
                    return Err(AnnexBError::TooManyAccessUnits {
                        count: aus.len(),
                        max: max_aus,
                    });
                }
            }

            current_au = Some(AuAccumulator {
                nal_indices: vec![nal_idx],
                has_vcl: nal.is_vcl(),
                is_idr: nal.is_idr(),
                has_sps: nal.is_sps(),
                has_pps: nal.is_pps(),
                slice_count: if nal.is_vcl() { 1 } else { 0 },
                first_sc_offset: nal.start_code_span.offset,
            });
        } else if let Some(ref mut builder) = current_au {
            builder.nal_indices.push(nal_idx);
            if nal.is_vcl() {
                builder.has_vcl = true;
                builder.slice_count = builder.slice_count.saturating_add(1);
            }
            if nal.is_idr() {
                builder.is_idr = true;
            }
            if nal.is_sps() {
                builder.has_sps = true;
            }
            if nal.is_pps() {
                builder.has_pps = true;
            }
        }
    }

    if let Some(builder) = current_au.take() {
        let au_end = bytes.len();
        let au_len = au_end.saturating_sub(builder.first_sc_offset);
        if builder.has_sps {
            stream_has_sps = true;
        }
        if builder.has_pps {
            stream_has_pps = true;
        }
        let undecodable = builder.slice_count > 0 && (!stream_has_sps || !stream_has_pps);

        aus.push(AnnexBAccessUnit {
            span: SourceSpan::new(builder.first_sc_offset, au_len),
            nal_indices: builder.nal_indices,
            is_idr: builder.is_idr,
            has_sps: builder.has_sps,
            has_pps: builder.has_pps,
            slice_count: builder.slice_count,
            undecodable_without_parameter_sets: undecodable,
        });

        if aus.len() > max_aus {
            return Err(AnnexBError::TooManyAccessUnits {
                count: aus.len(),
                max: max_aus,
            });
        }
    }

    Ok(aus)
}

/// Decodes `first_mb_in_slice` using bounded `ue(v)` Exp-Golomb reader over unescaped RBSP prefix.
fn decode_first_mb_in_slice(bytes: &[u8], nal: &AnnexBNal) -> Result<u64, AnnexBError> {
    if nal.nal_span.len < 2 {
        return Err(AnnexBError::TruncatedSliceHeader {
            offset: nal.nal_span.offset,
        });
    }

    let payload_start = nal.nal_span.offset.saturating_add(1);
    let payload_end = nal.nal_span.offset.saturating_add(nal.nal_span.len);
    let payload = &bytes[payload_start..payload_end];

    let mut scratch = [0u8; RBSP_SCRATCH_SIZE];
    let rbsp_len = extract_rbsp_prefix(payload, &mut scratch, nal.nal_span.offset)?;

    let mut reader = BitReader::new(&scratch[..rbsp_len], nal.nal_span.offset);
    reader.read_ue()
}

/// Unescapes up to `scratch.len()` bytes of RBSP into `scratch`, removing emulation-prevention `0x03`.
fn extract_rbsp_prefix(
    payload: &[u8],
    scratch: &mut [u8],
    nal_offset: usize,
) -> Result<usize, AnnexBError> {
    let mut read_idx: usize = 0;
    let mut write_idx: usize = 0;
    let mut zero_count: usize = 0;

    while read_idx < payload.len() && write_idx < scratch.len() {
        let b = payload[read_idx];
        if zero_count >= 2 && b == 0x03 {
            if read_idx.saturating_add(1) >= payload.len() {
                return Err(AnnexBError::MalformedEmulationPrevention {
                    offset: nal_offset.saturating_add(read_idx),
                });
            }
            let next = payload[read_idx + 1];
            if next > 0x03 {
                return Err(AnnexBError::MalformedEmulationPrevention {
                    offset: nal_offset.saturating_add(read_idx),
                });
            }
            read_idx = read_idx.saturating_add(1);
            zero_count = 0;
            continue;
        }

        scratch[write_idx] = b;
        write_idx = write_idx.saturating_add(1);
        read_idx = read_idx.saturating_add(1);

        if b == 0x00 {
            zero_count = zero_count.saturating_add(1);
        } else {
            zero_count = 0;
        }
    }
    Ok(write_idx)
}

/// Bounded bit-level reader for Exp-Golomb syntax elements.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
    nal_offset: usize,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8], nal_offset: usize) -> Self {
        Self {
            data,
            bit_pos: 0,
            nal_offset,
        }
    }

    fn read_bit(&mut self) -> Result<u8, AnnexBError> {
        let byte_idx = self.bit_pos / 8;
        let bit_idx = 7 - (self.bit_pos % 8);
        if byte_idx >= self.data.len() {
            return Err(AnnexBError::TruncatedSliceHeader {
                offset: self.nal_offset,
            });
        }
        let bit = (self.data[byte_idx] >> bit_idx) & 1;
        self.bit_pos = self.bit_pos.saturating_add(1);
        Ok(bit)
    }

    fn read_ue(&mut self) -> Result<u64, AnnexBError> {
        let mut leading_zeros = 0usize;
        while self.read_bit()? == 0 {
            leading_zeros = leading_zeros.saturating_add(1);
            if leading_zeros > 31 {
                return Err(AnnexBError::MalformedSliceHeader {
                    offset: self.nal_offset,
                    detail: "ue(v) leading zero count exceeds 31",
                });
            }
        }
        if leading_zeros == 0 {
            return Ok(0);
        }
        let mut val = 0u64;
        for _ in 0..leading_zeros {
            val = (val << 1) | (u64::from(self.read_bit()?));
        }
        let base = (1u64 << leading_zeros).saturating_sub(1);
        base.checked_add(val)
            .ok_or(AnnexBError::MalformedSliceHeader {
                offset: self.nal_offset,
                detail: "ue(v) value overflowed u64",
            })
    }
}
