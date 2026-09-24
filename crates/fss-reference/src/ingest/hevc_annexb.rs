#![forbid(unsafe_code)]
//! Bounded H.265/HEVC Annex-B elementary-stream splitter with exact source spans.
//!
//! Framing (start codes, trailing zero padding, emulation-prevention validation, NAL and input
//! bounds) is the codec-neutral pass shared with the H.264 splitter in [`super::annexb`]. Only the
//! header interpretation and the access-unit rule differ.
//!
//! Every NAL unit carries the two-byte H.265 header (7.3.1.2): `forbidden_zero_bit`,
//! `nal_unit_type` (6 bits), `nuh_layer_id` (6 bits) and `nuh_temporal_id_plus1` (3 bits, never
//! zero). Access units follow H.265 7.4.2.4.4: once the current access unit holds a slice
//! segment, the next access unit starts at
//!
//! * an access unit delimiter (type 35), which always opens an access unit;
//! * a VPS, SPS, PPS or prefix SEI (types 32, 33, 34, 39), or a type reserved/unspecified for
//!   that position (41..=44, 48..=55);
//! * a slice segment (types 0..=9, 16..=21) whose `first_slice_segment_in_pic_flag` is 1.
//!
//! Suffix SEI (40), filler data (38) and other slice segments of the same picture stay in the
//! current access unit. An end-of-sequence (36) or end-of-bitstream (37) NAL closes it. Parameter
//! sets and prefix SEI that precede the first slice segment therefore travel with the picture
//! they precede, so each retained segment is exactly one coded picture plus its prefix NAL units.
//! Emulation-prevention bytes are retained for exact source custody.

use crate::adapter_replay::ReplayCx;
use crate::ingest::annexb::{AnnexBError, AnnexBLimits, SourceSpan, scan_nal_units};

/// Name of the access-unit grouping rule recorded by [`HevcScan::au_grouping`].
pub const HEVC_AU_GROUPING: &str = "h265_7.4.2.4.4_first_slice_segment_in_pic";

const NAL_VPS: u8 = 32;
const NAL_SPS: u8 = 33;
const NAL_PPS: u8 = 34;
const NAL_AUD: u8 = 35;
const NAL_EOS: u8 = 36;
const NAL_EOB: u8 = 37;
const NAL_PREFIX_SEI: u8 = 39;

/// One H.265 NAL unit with its exact source spans and two-byte header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcNal {
    /// Exact byte span of the preceding start code (3 or 4 bytes).
    pub start_code_span: SourceSpan,
    /// Exact byte span of the NAL unit (header included, emulation prevention retained).
    pub nal_span: SourceSpan,
    /// `nal_unit_type` (0..=63).
    pub nal_unit_type: u8,
    /// `nuh_layer_id` (0..=63). Non-zero layers are retained; the decoder refuses them.
    pub layer_id: u8,
    /// `nuh_temporal_id_plus1` (1..=7).
    pub temporal_id_plus1: u8,
    /// `first_slice_segment_in_pic_flag` of a slice segment NAL unit; `None` otherwise.
    pub first_slice_segment_in_pic: Option<bool>,
}

impl HevcNal {
    /// Whether this NAL unit is a coded slice segment (types 0..=9 and 16..=21).
    #[must_use]
    pub const fn is_slice_segment(&self) -> bool {
        is_slice_segment_type(self.nal_unit_type)
    }
    /// Whether this NAL unit is a slice segment of an IRAP picture (BLA, IDR or CRA).
    #[must_use]
    pub const fn is_irap(&self) -> bool {
        self.nal_unit_type >= 16 && self.nal_unit_type <= 21
    }
    /// Whether this NAL unit is a slice segment of an IDR picture.
    #[must_use]
    pub const fn is_idr(&self) -> bool {
        self.nal_unit_type == 19 || self.nal_unit_type == 20
    }
    /// Combined span of the start code and the NAL unit.
    #[must_use]
    pub const fn full_span(&self) -> SourceSpan {
        SourceSpan::new(
            self.start_code_span.offset,
            self.start_code_span.len.saturating_add(self.nal_span.len),
        )
    }
}

const fn is_slice_segment_type(nal_unit_type: u8) -> bool {
    nal_unit_type <= 9 || (nal_unit_type >= 16 && nal_unit_type <= 21)
}

/// One H.265 access unit (one coded picture and its non-VCL NAL units).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcAccessUnit {
    /// Source span from the first NAL's start code to the next access unit (or stream end).
    pub span: SourceSpan,
    /// Indices into [`HevcScan::nals`].
    pub nal_indices: Vec<usize>,
    /// `nal_unit_type` of the picture's slice segments, when the access unit has any.
    pub picture_nal_unit_type: Option<u8>,
    /// Whether the picture is an IRAP picture (BLA, IDR or CRA).
    pub is_irap: bool,
    /// Whether the picture is an IDR picture.
    pub is_idr: bool,
    /// Whether a VPS is present in this access unit.
    pub has_vps: bool,
    /// Whether an SPS is present in this access unit.
    pub has_sps: bool,
    /// Whether a PPS is present in this access unit.
    pub has_pps: bool,
    /// Number of slice segment NAL units.
    pub slice_segment_count: usize,
    /// The access unit has slice segments but the stream has not yet carried a VPS, SPS and PPS.
    pub undecodable_without_parameter_sets: bool,
}

/// Result of an H.265 Annex-B scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcScan {
    /// NAL units in stream order.
    pub nals: Vec<HevcNal>,
    /// Access units per H.265 7.4.2.4.4.
    pub access_units: Vec<HevcAccessUnit>,
    /// `trailing_zero_8bits` / `leading_zero_8bits` spans.
    pub padding_spans: Vec<SourceSpan>,
    /// Tolerated unparsed leading bytes.
    pub omission_spans: Vec<SourceSpan>,
    /// Access-unit grouping rule, [`HEVC_AU_GROUPING`].
    pub au_grouping: &'static str,
    /// Total bytes scanned.
    pub total_bytes: usize,
}

/// Scans an H.265 Annex-B elementary stream under the same bounds as the H.264 splitter.
///
/// # Errors
/// Every framing refusal of [`super::annexb::split_annexb`], plus
/// [`AnnexBError::InvalidHevcNalHeader`] for a NAL unit shorter than two bytes or with
/// `nuh_temporal_id_plus1 == 0`, [`AnnexBError::TruncatedSliceHeader`] for a slice segment
/// without payload, [`AnnexBError::TooManyAccessUnits`], and [`AnnexBError::NoHevcPicture`] for
/// a stream without any slice segment.
pub fn split_hevc_annexb(
    bytes: &[u8],
    limits: AnnexBLimits,
    cx: &ReplayCx,
) -> Result<HevcScan, AnnexBError> {
    let framed = scan_nal_units(bytes, limits, cx)?;
    if cx.checkpoint("pre_au_grouping").is_err() {
        return Err(AnnexBError::Cancelled);
    }
    let mut nals = Vec::with_capacity(framed.nals.len());
    for (index, nal) in framed.nals.iter().enumerate() {
        let offset = nal.nal_span.offset;
        let header = bytes
            .get(offset..nal.nal_span.end())
            .filter(|nal_bytes| nal_bytes.len() >= 2)
            .ok_or(AnnexBError::InvalidHevcNalHeader { nal: index, offset })?;
        let nal_unit_type = (header[0] >> 1) & 0x3f;
        let layer_id = ((header[0] & 1) << 5) | (header[1] >> 3);
        let temporal_id_plus1 = header[1] & 0x07;
        if temporal_id_plus1 == 0 {
            return Err(AnnexBError::InvalidHevcNalHeader { nal: index, offset });
        }
        // Byte 2 cannot be an emulation-prevention byte: `nuh_temporal_id_plus1` makes byte 1
        // non-zero, so no `00 00 03` sequence ends there.
        let first_slice_segment_in_pic = if is_slice_segment_type(nal_unit_type) {
            let first = header
                .get(2)
                .ok_or(AnnexBError::TruncatedSliceHeader { offset })?;
            Some(first & 0x80 != 0)
        } else {
            None
        };
        nals.push(HevcNal {
            start_code_span: nal.start_code_span,
            nal_span: nal.nal_span,
            nal_unit_type,
            layer_id,
            temporal_id_plus1,
            first_slice_segment_in_pic,
        });
    }
    if !nals.iter().any(HevcNal::is_slice_segment) {
        return Err(AnnexBError::NoHevcPicture);
    }
    let access_units = group_access_units(bytes.len(), &nals, limits.max_aus, cx)?;
    Ok(HevcScan {
        nals,
        access_units,
        padding_spans: framed.padding_spans,
        omission_spans: framed.omission_spans,
        au_grouping: HEVC_AU_GROUPING,
        total_bytes: bytes.len(),
    })
}

struct Builder {
    first_offset: usize,
    nal_indices: Vec<usize>,
    picture_nal_unit_type: Option<u8>,
    has_vps: bool,
    has_sps: bool,
    has_pps: bool,
    slice_segment_count: usize,
    ended: bool,
}

impl Builder {
    fn new(nal: &HevcNal, index: usize) -> Self {
        let mut builder = Self {
            first_offset: nal.start_code_span.offset,
            nal_indices: Vec::new(),
            picture_nal_unit_type: None,
            has_vps: false,
            has_sps: false,
            has_pps: false,
            slice_segment_count: 0,
            ended: false,
        };
        builder.push(nal, index);
        builder
    }

    fn push(&mut self, nal: &HevcNal, index: usize) {
        self.nal_indices.push(index);
        match nal.nal_unit_type {
            NAL_VPS => self.has_vps = true,
            NAL_SPS => self.has_sps = true,
            NAL_PPS => self.has_pps = true,
            NAL_EOS | NAL_EOB => self.ended = true,
            _ => {}
        }
        if nal.is_slice_segment() {
            self.slice_segment_count = self.slice_segment_count.saturating_add(1);
            self.picture_nal_unit_type.get_or_insert(nal.nal_unit_type);
        }
    }

    /// H.265 7.4.2.4.4: does `nal` open a new access unit after this one?
    fn ends_before(&self, nal: &HevcNal) -> bool {
        if self.ended || nal.nal_unit_type == NAL_AUD {
            return true;
        }
        if self.slice_segment_count == 0 {
            return false;
        }
        match nal.first_slice_segment_in_pic {
            Some(first) => first,
            None => matches!(
                nal.nal_unit_type,
                NAL_VPS | NAL_SPS | NAL_PPS | NAL_PREFIX_SEI | 41..=44 | 48..=55
            ),
        }
    }
}

struct StreamParameterSets {
    vps: bool,
    sps: bool,
    pps: bool,
}

fn finish(
    builder: Builder,
    end: usize,
    seen: &mut StreamParameterSets,
    access_units: &mut Vec<HevcAccessUnit>,
    max_aus: usize,
) -> Result<(), AnnexBError> {
    seen.vps |= builder.has_vps;
    seen.sps |= builder.has_sps;
    seen.pps |= builder.has_pps;
    if access_units.len() >= max_aus {
        return Err(AnnexBError::TooManyAccessUnits {
            count: access_units.len().saturating_add(1),
            max: max_aus,
        });
    }
    let picture = builder.picture_nal_unit_type;
    access_units.push(HevcAccessUnit {
        span: SourceSpan::new(
            builder.first_offset,
            end.saturating_sub(builder.first_offset),
        ),
        nal_indices: builder.nal_indices,
        picture_nal_unit_type: picture,
        is_irap: picture.is_some_and(|t| (16..=21).contains(&t)),
        is_idr: picture.is_some_and(|t| t == 19 || t == 20),
        has_vps: builder.has_vps,
        has_sps: builder.has_sps,
        has_pps: builder.has_pps,
        slice_segment_count: builder.slice_segment_count,
        undecodable_without_parameter_sets: builder.slice_segment_count > 0
            && !(seen.vps && seen.sps && seen.pps),
    });
    Ok(())
}

fn group_access_units(
    stream_len: usize,
    nals: &[HevcNal],
    max_aus: usize,
    cx: &ReplayCx,
) -> Result<Vec<HevcAccessUnit>, AnnexBError> {
    let mut access_units = Vec::new();
    let mut seen = StreamParameterSets {
        vps: false,
        sps: false,
        pps: false,
    };
    let mut current: Option<Builder> = None;
    for (index, nal) in nals.iter().enumerate() {
        if cx.checkpoint("au_grouping").is_err() {
            return Err(AnnexBError::Cancelled);
        }
        if let Some(builder) = current.as_mut().filter(|builder| !builder.ends_before(nal)) {
            builder.push(nal, index);
            continue;
        }
        if let Some(builder) = current.take() {
            finish(
                builder,
                nal.start_code_span.offset,
                &mut seen,
                &mut access_units,
                max_aus,
            )?;
        }
        current = Some(Builder::new(nal, index));
    }
    if let Some(builder) = current {
        finish(builder, stream_len, &mut seen, &mut access_units, max_aus)?;
    }
    Ok(access_units)
}

#[cfg(test)]
mod tests;
