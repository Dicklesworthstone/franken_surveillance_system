//! Streaming decoder: parameter-set store, picture assembly from slices,
//! reference list construction, sliding-window marking and output.

use std::sync::Arc;

use fss_packet::avc::{AvcSps, AvcSyntaxLimits};

use crate::bits::BitReader;
use crate::deblock::deblock_frame;
use crate::macroblock::{
    MbInfo, PictureState, RefEntry, SliceContext, SliceInfo, decode_slice_data,
};
use crate::params::{PicParams, SeqParams, parse_pps, parse_sps};
use crate::picture::{Frame, Picture, PictureMeta};
use crate::rbsp::{NalPayload, rbsp_from_ebsp, stop_bit_position};
use crate::slice::{SliceHeader, SliceKind, parse_slice_header, parse_slice_prefix};
use crate::{DecodeError, UnsupportedFeature};

/// Owner-narrowable decode budgets. Every limit is checked before the
/// allocation or work it bounds; exceeding one is [`DecodeError::Limit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderLimits {
    /// Maximum coded luma width (before cropping), at most 16,384.
    pub max_width: u32,
    /// Maximum coded luma height (before cropping), at most 16,384.
    pub max_height: u32,
    /// Maximum macroblocks per picture, at most 1,048,576.
    pub max_macroblocks: u32,
    /// Maximum pictures this decoder will ever decode (lifetime work bound).
    pub max_pictures: u64,
    /// Maximum bytes of one NAL unit including its header, at most 16 MiB.
    pub max_nal_bytes: usize,
    /// Maximum slices in one picture, at most 65,535.
    pub max_slices_per_picture: u32,
    /// Maximum `max_num_ref_frames` an SPS may declare, at most 16.
    pub max_reference_frames: u32,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_width: 4_096,
            max_height: 2_304,
            max_macroblocks: 36_864,
            max_pictures: u64::MAX,
            max_nal_bytes: 8 * 1_024 * 1_024,
            max_slices_per_picture: 1_024,
            max_reference_frames: 16,
        }
    }
}

impl DecoderLimits {
    fn validate(&self) -> Result<(), DecodeError> {
        if !(16..=16_384).contains(&self.max_width)
            || !(16..=16_384).contains(&self.max_height)
            || !(1..=1_048_576).contains(&self.max_macroblocks)
            || self.max_pictures == 0
            || !(2..=16 * 1_024 * 1_024).contains(&self.max_nal_bytes)
            || !(1..=65_535).contains(&self.max_slices_per_picture)
            || self.max_reference_frames > 16
        {
            return Err(DecodeError::Limit);
        }
        Ok(())
    }

    fn syntax_limits(&self) -> AvcSyntaxLimits {
        let defaults = AvcSyntaxLimits::default();
        AvcSyntaxLimits {
            max_nal_bytes: self.max_nal_bytes,
            max_parameter_set_bytes: defaults.max_parameter_set_bytes.min(self.max_nal_bytes),
            max_width: self.max_width,
            max_height: self.max_height,
            max_luma_samples: u64::from(self.max_macroblocks) * 256,
            max_reference_frames: self.max_reference_frames,
            max_slice_identity_bits: defaults.max_slice_identity_bits,
        }
    }
}

/// One short-term reference frame.
struct RefFrame {
    id: u64,
    frame_num: u32,
    frame: Arc<Frame>,
}

/// A picture whose slices are still arriving.
struct Pending {
    first: SliceHeader,
    sps: SeqParams,
    frame: Frame,
    infos: Vec<MbInfo>,
    slices: Vec<SliceInfo>,
    next_mb: u32,
    poc: i32,
}

/// Streaming Constrained-Baseline H.264 decoder.
///
/// Feed NAL units (without start codes) with [`Decoder::decode_nal`], or
/// Annex-B bytes with [`Decoder::decode_annex_b`]. A picture is returned as
/// soon as its last macroblock is decoded, in decode order (which equals
/// output order for the admitted tool set: no B slices, and POC type 0
/// streams must have increasing POC or they are refused).
///
/// Error discipline: any error inside a picture discards that picture and
/// puts the decoder in a "wait for IDR" state, so later P pictures can
/// never silently predict from the wrong reference. Parameter-set errors
/// leave previously stored parameter sets untouched.
pub struct Decoder {
    limits: DecoderLimits,
    syntax_limits: AvcSyntaxLimits,
    sps: Vec<Option<(AvcSps, SeqParams)>>,
    pps: Vec<Option<PicParams>>,
    active_sps: Option<SeqParams>,
    dpb: Vec<RefFrame>,
    pending: Option<Pending>,
    need_idr: bool,
    prev_ref_frame_num: u32,
    prev_poc_msb: i32,
    prev_poc_lsb: i32,
    prev_frame_num: u32,
    prev_frame_num_offset: i64,
    last_poc: Option<i32>,
    pictures: u64,
    next_ref_id: u64,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("limits", &self.limits)
            .field("pictures", &self.pictures)
            .field("references", &self.dpb.len())
            .field("pending", &self.pending.is_some())
            .field("need_idr", &self.need_idr)
            .finish_non_exhaustive()
    }
}

impl Decoder {
    /// Creates a decoder with validated limits.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when a limit is zero or above its ceiling.
    pub fn new(limits: DecoderLimits) -> Result<Self, DecodeError> {
        limits.validate()?;
        Ok(Self {
            limits,
            syntax_limits: limits.syntax_limits(),
            sps: (0..32).map(|_| None).collect(),
            pps: (0..256).map(|_| None).collect(),
            active_sps: None,
            dpb: Vec::new(),
            pending: None,
            need_idr: true,
            prev_ref_frame_num: 0,
            prev_poc_msb: 0,
            prev_poc_lsb: 0,
            prev_frame_num: 0,
            prev_frame_num_offset: 0,
            last_poc: None,
            pictures: 0,
            next_ref_id: 0,
        })
    }

    /// Pictures decoded (and returned) so far.
    #[must_use]
    pub const fn pictures_decoded(&self) -> u64 {
        self.pictures
    }

    /// Decodes one NAL unit (header byte included, no start code). Returns
    /// a picture when this NAL completed one.
    ///
    /// Non-VCL NAL units other than SPS/PPS (SEI, AUD, end of sequence,
    /// filler, extensions) are accepted and ignored, as are redundant
    /// slices (`redundant_pic_cnt > 0`).
    ///
    /// # Errors
    /// Any [`DecodeError`]; see the type-level error discipline.
    pub fn decode_nal(&mut self, nal: &[u8]) -> Result<Option<Picture>, DecodeError> {
        if nal.len() > self.limits.max_nal_bytes {
            return Err(DecodeError::Limit);
        }
        let (header, payload) = NalPayload::new(nal).split_header()?;
        match header.unit_type {
            7 => self.store_sps(nal, payload).map(|()| None),
            8 => self.store_pps(nal, payload).map(|()| None),
            1 | 5 => {
                let result = self.decode_slice(header, payload);
                if result.is_err() {
                    self.pending = None;
                    self.need_idr = true;
                }
                result
            }
            2..=4 => Err(DecodeError::Unsupported(
                UnsupportedFeature::DataPartitioning,
            )),
            _ => Ok(None),
        }
    }

    /// Decodes every NAL unit of an Annex-B byte stream (one or more
    /// access units) and returns the completed pictures in decode order.
    /// Stops at the first error; pictures completed earlier in the same
    /// call are then not returned (feed NAL units individually with
    /// [`Self::decode_nal`] to keep them).
    ///
    /// # Errors
    /// The first [`DecodeError`] encountered.
    pub fn decode_annex_b(&mut self, bytes: &[u8]) -> Result<Vec<Picture>, DecodeError> {
        let mut pictures = Vec::new();
        for nal in annex_b_nal_units(bytes) {
            if let Some(picture) = self.decode_nal(nal)? {
                pictures.push(picture);
            }
        }
        Ok(pictures)
    }

    /// Ends the stream. A picture still missing macroblocks is discarded.
    ///
    /// # Errors
    /// [`DecodeError::IncompletePicture`] when slices were missing.
    pub fn finish(&mut self) -> Result<(), DecodeError> {
        if self.pending.take().is_some() {
            self.need_idr = true;
            return Err(DecodeError::IncompletePicture);
        }
        Ok(())
    }

    fn store_sps(&mut self, nal: &[u8], payload: &[u8]) -> Result<(), DecodeError> {
        // fss-packet custody admission first (bounds, profile, VUI).
        let admitted = fss_packet::avc::parse_sps(nal, self.syntax_limits)?;
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let params = parse_sps(&rbsp)?;
        if params.coded_width() > self.limits.max_width
            || params.coded_height() > self.limits.max_height
            || params.mbs() > self.limits.max_macroblocks
            || params.max_num_ref_frames > self.limits.max_reference_frames
        {
            return Err(DecodeError::Limit);
        }
        let slot = self
            .sps
            .get_mut(usize::from(params.id))
            .ok_or(DecodeError::Malformed)?;
        *slot = Some((admitted, params));
        Ok(())
    }

    fn store_pps(&mut self, nal: &[u8], payload: &[u8]) -> Result<(), DecodeError> {
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let params = parse_pps(&rbsp)?;
        let (admitted_sps, _) = self
            .sps
            .get(usize::from(params.sps_id))
            .and_then(Option::as_ref)
            .ok_or(DecodeError::MissingParameterSet)?;
        fss_packet::avc::parse_pps(nal, admitted_sps, self.syntax_limits)?;
        let slot = self
            .pps
            .get_mut(usize::from(params.id))
            .ok_or(DecodeError::Malformed)?;
        *slot = Some(params);
        Ok(())
    }

    fn decode_slice(
        &mut self,
        nal: crate::rbsp::NalHeader,
        payload: &[u8],
    ) -> Result<Option<Picture>, DecodeError> {
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let stop = stop_bit_position(&rbsp)?;
        let mut reader = BitReader::new(&rbsp, stop);
        let prefix = parse_slice_prefix(&mut reader)?;
        let pps = self
            .pps
            .get(usize::from(prefix.pps_id))
            .and_then(Option::as_ref)
            .ok_or(DecodeError::MissingParameterSet)?
            .clone();
        let sps = self
            .sps
            .get(usize::from(pps.sps_id))
            .and_then(Option::as_ref)
            .ok_or(DecodeError::MissingParameterSet)?
            .1
            .clone();
        let header = parse_slice_header(&mut reader, nal, prefix, &sps, &pps)?;
        if header.redundant_pic_cnt > 0 {
            return Ok(None);
        }

        if header.first_mb == 0 {
            if self.pending.is_some() {
                return Err(DecodeError::IncompletePicture);
            }
            self.start_picture(&header, &sps)?;
        }
        let pending = self.pending.as_mut().ok_or(DecodeError::Unsupported(
            UnsupportedFeature::ArbitrarySliceOrder,
        ))?;
        let first = &pending.first;
        if header.frame_num != first.frame_num
            || header.idr != first.idr
            || (header.nal_ref_idc == 0) != (first.nal_ref_idc == 0)
            || header.idr_pic_id != first.idr_pic_id
            || header.poc_lsb != first.poc_lsb
            || pending.sps != sps
        {
            return Err(DecodeError::Malformed);
        }
        if header.first_mb < pending.next_mb {
            return Err(DecodeError::Malformed);
        }
        if header.first_mb > pending.next_mb {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::ArbitrarySliceOrder,
            ));
        }
        if pending.slices.len() >= self.limits.max_slices_per_picture as usize {
            return Err(DecodeError::Limit);
        }
        pending.slices.push(SliceInfo {
            disable_deblocking_filter_idc: header.disable_deblocking_filter_idc,
            filter_offset_a: header.filter_offset_a,
            filter_offset_b: header.filter_offset_b,
            chroma_qp_offset: [
                pps.chroma_qp_index_offset,
                pps.second_chroma_qp_index_offset,
            ],
        });
        let slice_num = u16::try_from(pending.slices.len()).map_err(|_| DecodeError::Limit)?;

        // RefPicList0 (8.2.4.2.1): short-term frames by descending
        // FrameNumWrap, truncated to num_ref_idx_l0_active.
        let max_frame_num = 1i64 << sps.log2_max_frame_num;
        let mut order: Vec<&RefFrame> = self.dpb.iter().collect();
        let wrap = |f: &RefFrame| {
            let n = i64::from(f.frame_num);
            if n > i64::from(header.frame_num) {
                n - max_frame_num
            } else {
                n
            }
        };
        order.sort_by_key(|f| std::cmp::Reverse(wrap(f)));
        let ref_list: Vec<RefEntry<'_>> = if header.kind == SliceKind::P {
            order
                .iter()
                .take(header.num_ref_idx_l0_active as usize)
                .map(|f| RefEntry {
                    id: f.id,
                    frame: &f.frame,
                })
                .collect()
        } else {
            Vec::new()
        };

        let ctx = SliceContext {
            header: &header,
            sps: &sps,
            pps: &pps,
            slice_num,
            ref_list: &ref_list,
        };
        let mut state = PictureState {
            frame: &mut pending.frame,
            infos: &mut pending.infos,
        };
        let decoded = decode_slice_data(&mut reader, &ctx, &mut state)?;
        pending.next_mb += decoded;
        if pending.next_mb < sps.mbs() {
            return Ok(None);
        }
        let pending = self.pending.take().ok_or(DecodeError::Malformed)?;
        self.finish_picture(pending).map(Some)
    }

    fn start_picture(&mut self, header: &SliceHeader, sps: &SeqParams) -> Result<(), DecodeError> {
        if self.pictures >= self.limits.max_pictures {
            return Err(DecodeError::Limit);
        }
        if sps.coded_width() > self.limits.max_width
            || sps.coded_height() > self.limits.max_height
            || sps.mbs() > self.limits.max_macroblocks
        {
            return Err(DecodeError::Limit);
        }
        let max_frame_num = 1u32 << sps.log2_max_frame_num;
        if header.idr {
            if header.frame_num != 0 {
                return Err(DecodeError::Malformed);
            }
            self.dpb.clear();
            self.prev_ref_frame_num = 0;
            self.prev_poc_msb = 0;
            self.prev_poc_lsb = 0;
            self.prev_frame_num = 0;
            self.prev_frame_num_offset = 0;
            self.last_poc = None;
            self.active_sps = Some(sps.clone());
        } else {
            if self.need_idr {
                return Err(DecodeError::MissingReference);
            }
            if self.active_sps.as_ref() != Some(sps) {
                // An SPS may only change at an IDR picture.
                return Err(DecodeError::Malformed);
            }
            if header.frame_num != self.prev_ref_frame_num
                && header.frame_num != (self.prev_ref_frame_num + 1) % max_frame_num
            {
                return Err(DecodeError::FrameNumGap);
            }
        }
        let poc = self.picture_order_count(header, sps)?;
        if let Some(last) = self.last_poc
            && poc <= last
        {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::OutputReordering,
            ));
        }
        let width = usize::try_from(sps.coded_width()).map_err(|_| DecodeError::Limit)?;
        let height = usize::try_from(sps.coded_height()).map_err(|_| DecodeError::Limit)?;
        let mbs = usize::try_from(sps.mbs()).map_err(|_| DecodeError::Limit)?;
        let frame = Frame::new(width, height)?;
        let mut infos = Vec::new();
        infos
            .try_reserve_exact(mbs)
            .map_err(|_| DecodeError::Limit)?;
        infos.resize(mbs, MbInfo::EMPTY);
        self.need_idr = false;
        self.pending = Some(Pending {
            first: header.clone(),
            sps: sps.clone(),
            frame,
            infos,
            slices: Vec::new(),
            next_mb: 0,
            poc,
        });
        Ok(())
    }

    /// Picture order count (8.2.1) for POC types 0 and 2; updates the
    /// "previous picture" state as the picture is started.
    fn picture_order_count(
        &mut self,
        header: &SliceHeader,
        sps: &SeqParams,
    ) -> Result<i32, DecodeError> {
        match sps.poc_type {
            0 => {
                let max_lsb = 1i32 << sps.log2_max_poc_lsb;
                let lsb = i32::try_from(header.poc_lsb).map_err(|_| DecodeError::Malformed)?;
                let (prev_msb, prev_lsb) = (self.prev_poc_msb, self.prev_poc_lsb);
                // Checked: a hostile stream can walk the MSB towards i32
                // overflow in ~2^15 pictures; that is refused, not wrapped.
                let msb = if lsb < prev_lsb && prev_lsb - lsb >= max_lsb / 2 {
                    prev_msb.checked_add(max_lsb)
                } else if lsb > prev_lsb && lsb - prev_lsb > max_lsb / 2 {
                    prev_msb.checked_sub(max_lsb)
                } else {
                    Some(prev_msb)
                }
                .ok_or(DecodeError::Limit)?;
                if header.nal_ref_idc != 0 {
                    self.prev_poc_msb = msb;
                    self.prev_poc_lsb = lsb;
                }
                let top = msb.checked_add(lsb).ok_or(DecodeError::Malformed)?;
                let bottom = top
                    .checked_add(header.delta_poc_bottom)
                    .ok_or(DecodeError::Malformed)?;
                Ok(top.min(bottom))
            }
            2 => {
                let max_frame_num = 1i64 << sps.log2_max_frame_num;
                let offset = if header.idr {
                    0
                } else if self.prev_frame_num > header.frame_num {
                    self.prev_frame_num_offset + max_frame_num
                } else {
                    self.prev_frame_num_offset
                };
                self.prev_frame_num_offset = offset;
                self.prev_frame_num = header.frame_num;
                let absolute = offset + i64::from(header.frame_num);
                let poc = if header.idr {
                    0
                } else if header.nal_ref_idc == 0 {
                    2 * absolute - 1
                } else {
                    2 * absolute
                };
                i32::try_from(poc).map_err(|_| DecodeError::Limit)
            }
            _ => Err(DecodeError::Unsupported(UnsupportedFeature::PocType1)),
        }
    }

    fn finish_picture(&mut self, mut pending: Pending) -> Result<Picture, DecodeError> {
        let width_mbs = usize::try_from(pending.sps.width_mbs).map_err(|_| DecodeError::Limit)?;
        deblock_frame(
            &mut pending.frame,
            &pending.infos,
            &pending.slices,
            width_mbs,
        );
        let header = &pending.first;
        let meta = PictureMeta {
            frame_num: header.frame_num,
            poc: pending.poc,
            idr: header.idr,
            reference: header.nal_ref_idc != 0,
            decode_index: self.pictures,
        };
        let picture = Picture::from_frame(&pending.frame, pending.sps.crop, meta)?;
        if header.nal_ref_idc != 0 {
            // Sliding-window marking (8.2.5.3): drop the short-term frame
            // with the smallest FrameNumWrap while the window is full.
            let capacity = pending.sps.max_num_ref_frames.max(1) as usize;
            let max_frame_num = 1i64 << pending.sps.log2_max_frame_num;
            let current = i64::from(header.frame_num);
            while self.dpb.len() >= capacity {
                let oldest = self
                    .dpb
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, f)| {
                        let n = i64::from(f.frame_num);
                        if n > current { n - max_frame_num } else { n }
                    })
                    .map(|(index, _)| index)
                    .ok_or(DecodeError::Malformed)?;
                self.dpb.remove(oldest);
            }
            self.dpb.push(RefFrame {
                id: self.next_ref_id,
                frame_num: header.frame_num,
                frame: Arc::new(pending.frame),
            });
            self.next_ref_id += 1;
            self.prev_ref_frame_num = header.frame_num;
        }
        self.last_poc = Some(pending.poc);
        self.pictures += 1;
        Ok(picture)
    }
}

/// Iterator over the NAL units of an Annex-B byte stream (start codes
/// `00 00 01` / `00 00 00 01` removed). Zero bytes preceding a start code
/// (`trailing_zero_8bits`, the 4-byte form's leading zero) are stripped
/// from the previous unit; bytes before the first start code are skipped;
/// empty units are skipped.
#[must_use]
pub fn annex_b_nal_units(bytes: &[u8]) -> AnnexBUnits<'_> {
    AnnexBUnits {
        bytes,
        position: find_start(bytes, 0),
    }
}

/// See [`annex_b_nal_units`].
#[derive(Clone, Debug)]
pub struct AnnexBUnits<'a> {
    bytes: &'a [u8],
    /// Index just after the next start code, if any.
    position: Option<usize>,
}

fn find_start(bytes: &[u8], from: usize) -> Option<usize> {
    let tail = bytes.get(from..)?;
    tail.windows(3)
        .position(|w| w == [0, 0, 1])
        .map(|index| from + index + 3)
}

impl<'a> Iterator for AnnexBUnits<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            let start = self.position?;
            let next = find_start(self.bytes, start);
            let end = next.map_or(self.bytes.len(), |n| n - 3);
            self.position = next;
            let mut unit = self.bytes.get(start..end)?;
            while let [rest @ .., 0] = unit {
                unit = rest;
            }
            if !unit.is_empty() {
                return Some(unit);
            }
        }
    }
}
