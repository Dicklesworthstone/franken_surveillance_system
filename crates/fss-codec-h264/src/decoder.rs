//! Streaming decoder: parameter-set store, picture assembly from slices,
//! picture order count (8.2.1), reference list construction and
//! modification (8.2.4), reference picture marking (8.2.5) and the
//! decoded picture buffer's output (bumping) process (C.4).

use std::collections::VecDeque;
use std::sync::Arc;

use fss_packet::avc::{AvcSps, AvcSyntaxLimits};

use crate::bits::BitReader;
use crate::deblock::deblock_frame;
use crate::macroblock::{
    MbInfo, PictureState, RefEntry, SliceContext, SliceInfo, WeightMode, decode_slice_data,
};
use crate::params::{PicParams, SeqParams, parse_pps, parse_sps, resolve_scaling};
use crate::picture::{Frame, Picture, PictureMeta};
use crate::rbsp::{NalPayload, rbsp_from_ebsp, stop_bit_position};
use crate::slice::{
    Mmco, RefListModification, RefPicMarking, SliceHeader, SliceKind, parse_slice_header,
    parse_slice_prefix,
};
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

/// Reference marking of a stored frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Marking {
    Unused,
    Short,
    /// Long-term with its `LongTermFrameIdx`.
    Long(u32),
}

/// One frame in the decoded picture buffer.
struct DpbFrame {
    id: u64,
    frame: Arc<Frame>,
    motion: Arc<Vec<MbInfo>>,
    frame_num: u32,
    poc: i32,
    marking: Marking,
    /// Still waiting for output ("needed for output").
    waiting: bool,
    crop: [u32; 4],
    meta: PictureMeta,
}

impl DpbFrame {
    const fn is_short(&self) -> bool {
        matches!(self.marking, Marking::Short)
    }
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
    /// POC type 0 `PicOrderCntMsb` / lsb, type 2 `FrameNumOffset`.
    poc_msb: i32,
    frame_num_offset: i64,
}

/// Streaming H.264 decoder (Constrained Baseline and Main profile,
/// progressive 8-bit 4:2:0).
///
/// Feed NAL units (without start codes) with [`Decoder::decode_nal`], or
/// Annex-B bytes with [`Decoder::decode_annex_b`]. Pictures are returned in
/// output (display) order: the decoded picture buffer holds pictures until
/// the stream's reorder depth (VUI `max_num_reorder_frames`, or the level's
/// DPB size when absent; zero for POC type 2) allows them out, exactly as
/// the output process of Annex C. Call [`Decoder::finish`] at the end of the
/// stream to flush the remaining pictures.
///
/// Error discipline: any error inside a picture discards that picture and
/// puts the decoder in a "wait for IDR" state, so later pictures can never
/// silently predict from the wrong reference. Parameter-set errors leave
/// previously stored parameter sets untouched.
pub struct Decoder {
    limits: DecoderLimits,
    syntax_limits: AvcSyntaxLimits,
    sps: Vec<Option<(AvcSps, SeqParams)>>,
    pps: Vec<Option<PicParams>>,
    active_sps: Option<SeqParams>,
    dpb: Vec<DpbFrame>,
    output: VecDeque<Picture>,
    pending: Option<Pending>,
    need_idr: bool,
    max_long_term_frame_idx: Option<u32>,
    prev_ref_frame_num: u32,
    prev_poc_msb: i32,
    prev_poc_lsb: i32,
    prev_frame_num: u32,
    prev_frame_num_offset: i64,
    pictures: u64,
    next_ref_id: u64,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("limits", &self.limits)
            .field("pictures", &self.pictures)
            .field("buffered", &self.dpb.len())
            .field("queued_output", &self.output.len())
            .field("pending", &self.pending.is_some())
            .field("need_idr", &self.need_idr)
            .finish_non_exhaustive()
    }
}

/// Slice-level reference lists as DPB indices (`None` = no picture).
type IndexLists = [Vec<Option<usize>>; 2];

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
            output: VecDeque::new(),
            pending: None,
            need_idr: true,
            max_long_term_frame_idx: None,
            prev_ref_frame_num: 0,
            prev_poc_msb: 0,
            prev_poc_lsb: 0,
            prev_frame_num: 0,
            prev_frame_num_offset: 0,
            pictures: 0,
            next_ref_id: 0,
        })
    }

    /// Pictures decoded so far (in decode order; some may still be held for
    /// output reordering).
    #[must_use]
    pub const fn pictures_decoded(&self) -> u64 {
        self.pictures
    }

    /// Decodes one NAL unit (header byte included, no start code) and
    /// returns the next picture in output order, if one is ready. When a
    /// NAL makes several pictures ready at once (an IDR flushing the
    /// buffer), the others are returned by [`Self::next_output`] or later
    /// calls.
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
            7 => self.store_sps(nal, payload)?,
            8 => self.store_pps(nal, payload)?,
            1 | 5 => {
                if let Err(err) = self.decode_slice(header, payload) {
                    self.pending = None;
                    self.need_idr = true;
                    return Err(err);
                }
            }
            2..=4 => {
                return Err(DecodeError::Unsupported(
                    UnsupportedFeature::DataPartitioning,
                ));
            }
            _ => {}
        }
        Ok(self.output.pop_front())
    }

    /// The next picture already released for output, if any.
    pub fn next_output(&mut self) -> Option<Picture> {
        self.output.pop_front()
    }

    /// Decodes every NAL unit of an Annex-B byte stream (one or more
    /// access units) and returns the pictures released for output, in
    /// output order. Pictures still held for reordering are returned by
    /// [`Self::finish`]. Stops at the first error; pictures released
    /// earlier in the same call are then not returned (feed NAL units
    /// individually with [`Self::decode_nal`] to keep them).
    ///
    /// # Errors
    /// The first [`DecodeError`] encountered.
    pub fn decode_annex_b(&mut self, bytes: &[u8]) -> Result<Vec<Picture>, DecodeError> {
        let mut pictures = Vec::new();
        for nal in annex_b_nal_units(bytes) {
            if let Some(picture) = self.decode_nal(nal)? {
                pictures.push(picture);
            }
            pictures.extend(self.output.drain(..));
        }
        Ok(pictures)
    }

    /// Ends the stream: releases every picture still held in the decoded
    /// picture buffer, in output order (together with any already-released
    /// pictures not yet taken). A picture still missing macroblocks is
    /// discarded.
    ///
    /// # Errors
    /// [`DecodeError::IncompletePicture`] when slices were missing; the
    /// flushed pictures then stay available through [`Self::next_output`].
    pub fn finish(&mut self) -> Result<Vec<Picture>, DecodeError> {
        let incomplete = self.pending.take().is_some();
        self.flush_output()?;
        if incomplete {
            self.need_idr = true;
            return Err(DecodeError::IncompletePicture);
        }
        Ok(self.output.drain(..).collect())
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
    ) -> Result<(), DecodeError> {
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
            return Ok(());
        }
        if pps.entropy_coding_mode {
            // The CABAC engine consumes the rbsp_stop_one_bit itself.
            reader = reader.with_bit_limit(stop + 1);
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
            || header.delta_poc_bottom != first.delta_poc_bottom
            || header.marking != first.marking
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
        let poc = pending.poc;

        let index_lists =
            build_ref_lists(&self.dpb, &header, &sps, poc, self.max_long_term_frame_idx)?;
        let entries: [Vec<Option<RefEntry<'_>>>; 2] = [0, 1].map(|list| {
            index_lists[list]
                .iter()
                .map(|slot| {
                    slot.and_then(|i| self.dpb.get(i)).map(|f| RefEntry {
                        id: f.id,
                        frame: &f.frame,
                        motion: &f.motion,
                        poc: f.poc,
                        long_term: matches!(f.marking, Marking::Long(_)),
                    })
                })
                .collect()
        });
        let weights = weight_mode(&header, &pps, &entries, poc);
        let scaling = resolve_scaling(&sps, &pps);
        let ctx = SliceContext {
            header: &header,
            sps: &sps,
            pps: &pps,
            slice_num,
            lists: [&entries[0], &entries[1]],
            poc,
            scaling: &scaling,
            weights: &weights,
        };
        let mut state = PictureState {
            frame: &mut pending.frame,
            infos: &mut pending.infos,
        };
        let decoded = decode_slice_data(&mut reader, &ctx, &mut state)?;
        pending.next_mb += decoded;
        if pending.next_mb < sps.mbs() {
            return Ok(());
        }
        let pending = self.pending.take().ok_or(DecodeError::Malformed)?;
        self.finish_picture(pending)
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
            // C.4.4: prior pictures are output (in POC order) and the
            // buffer is emptied before an IDR picture is decoded.
            self.flush_output()?;
            self.dpb.clear();
            self.max_long_term_frame_idx = None;
            self.prev_ref_frame_num = 0;
            self.prev_poc_msb = 0;
            self.prev_poc_lsb = 0;
            self.prev_frame_num = 0;
            self.prev_frame_num_offset = 0;
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
        let (poc, poc_msb, frame_num_offset) = self.picture_order_count(header, sps)?;
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
            poc_msb,
            frame_num_offset,
        });
        Ok(())
    }

    /// Picture order count (8.2.1) for POC types 0 and 2. Returns
    /// `(PicOrderCnt, PicOrderCntMsb, FrameNumOffset)`; the "previous
    /// picture" state is updated when the picture completes.
    fn picture_order_count(
        &self,
        header: &SliceHeader,
        sps: &SeqParams,
    ) -> Result<(i32, i32, i64), DecodeError> {
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
                let top = msb.checked_add(lsb).ok_or(DecodeError::Malformed)?;
                let bottom = top
                    .checked_add(header.delta_poc_bottom)
                    .ok_or(DecodeError::Malformed)?;
                Ok((top.min(bottom), msb, 0))
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
                let absolute = offset + i64::from(header.frame_num);
                let poc = if header.idr {
                    0
                } else if header.nal_ref_idc == 0 {
                    2 * absolute - 1
                } else {
                    2 * absolute
                };
                Ok((
                    i32::try_from(poc).map_err(|_| DecodeError::Limit)?,
                    0,
                    offset,
                ))
            }
            _ => Err(DecodeError::Unsupported(UnsupportedFeature::PocType1)),
        }
    }

    fn finish_picture(&mut self, mut pending: Pending) -> Result<(), DecodeError> {
        let width_mbs = usize::try_from(pending.sps.width_mbs).map_err(|_| DecodeError::Limit)?;
        deblock_frame(
            &mut pending.frame,
            &pending.infos,
            &pending.slices,
            width_mbs,
        );
        let header = pending.first.clone();
        let sps = &pending.sps;
        let reference = header.nal_ref_idc != 0;
        let (current_marking, mmco5) = if reference {
            self.mark_references(&header, sps)?
        } else {
            (Marking::Unused, false)
        };
        let mut poc = pending.poc;
        let mut frame_num = header.frame_num;
        if mmco5 {
            // 8.2.1: after MMCO 5 the picture's POC is relative to itself
            // (a frame's is then 0) and its frame_num is inferred 0. All
            // earlier pictures are output first (C.4.4).
            self.flush_output()?;
            poc = 0;
            frame_num = 0;
            if sps.poc_type == 0 {
                // TopFieldOrderCnt - Min(Top, Bottom) after the reset.
                self.prev_poc_msb = 0;
                self.prev_poc_lsb = header.delta_poc_bottom.saturating_neg().max(0);
            }
            self.prev_frame_num_offset = 0;
            self.prev_frame_num = 0;
        } else {
            if reference && sps.poc_type == 0 {
                self.prev_poc_msb = pending.poc_msb;
                self.prev_poc_lsb = i32::try_from(header.poc_lsb).unwrap_or(0);
            }
            self.prev_frame_num_offset = pending.frame_num_offset;
            self.prev_frame_num = header.frame_num;
        }
        if reference {
            self.prev_ref_frame_num = frame_num;
        }
        let meta = PictureMeta {
            frame_num: header.frame_num,
            poc,
            idr: header.idr,
            reference,
            decode_index: self.pictures,
        };
        self.pictures += 1;
        let current = DpbFrame {
            id: self.next_ref_id,
            frame: Arc::new(pending.frame),
            motion: Arc::new(pending.infos),
            frame_num,
            poc,
            marking: current_marking,
            waiting: true,
            crop: pending.sps.crop,
            meta,
        };
        self.next_ref_id += 1;
        self.store_and_output(current, &pending.sps)
    }

    /// Reference picture marking (8.2.5) of the picture just decoded:
    /// updates the markings of stored frames and returns the current
    /// picture's marking and whether MMCO 5 occurred.
    fn mark_references(
        &mut self,
        header: &SliceHeader,
        sps: &SeqParams,
    ) -> Result<(Marking, bool), DecodeError> {
        let max_frame_num = 1i64 << sps.log2_max_frame_num;
        let current = i64::from(header.frame_num);
        let pic_num = |f: &DpbFrame| -> i64 {
            let n = i64::from(f.frame_num);
            if n > current { n - max_frame_num } else { n }
        };
        let mut marking = Marking::Short;
        let mut mmco5 = false;
        match &header.marking {
            RefPicMarking::Idr { long_term, .. } => {
                for f in &mut self.dpb {
                    f.marking = Marking::Unused;
                }
                if *long_term {
                    self.max_long_term_frame_idx = Some(0);
                    marking = Marking::Long(0);
                } else {
                    self.max_long_term_frame_idx = None;
                }
            }
            RefPicMarking::None | RefPicMarking::SlidingWindow => {
                let capacity = sps.max_num_ref_frames.max(1) as usize;
                let used = self
                    .dpb
                    .iter()
                    .filter(|f| f.marking != Marking::Unused)
                    .count();
                if used >= capacity {
                    let oldest = self
                        .dpb
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.is_short())
                        .min_by_key(|(_, f)| pic_num(f))
                        .map(|(index, _)| index)
                        .ok_or(DecodeError::Malformed)?;
                    if let Some(f) = self.dpb.get_mut(oldest) {
                        f.marking = Marking::Unused;
                    }
                }
            }
            RefPicMarking::Adaptive(ops) => {
                for op in ops {
                    match *op {
                        Mmco::UnmarkShortTerm(diff) => {
                            let target = current - i64::from(diff) - 1;
                            for f in &mut self.dpb {
                                if f.is_short() && pic_num(f) == target {
                                    f.marking = Marking::Unused;
                                }
                            }
                        }
                        Mmco::UnmarkLongTerm(num) => {
                            for f in &mut self.dpb {
                                if f.marking == Marking::Long(num) {
                                    f.marking = Marking::Unused;
                                }
                            }
                        }
                        Mmco::ShortTermToLongTerm(diff, idx) => {
                            let target = current - i64::from(diff) - 1;
                            if self.max_long_term_frame_idx.is_none_or(|max| idx > max) {
                                return Err(DecodeError::Malformed);
                            }
                            let found = self
                                .dpb
                                .iter()
                                .position(|f| f.is_short() && pic_num(f) == target);
                            if let Some(found) = found {
                                for (index, f) in self.dpb.iter_mut().enumerate() {
                                    if index != found && f.marking == Marking::Long(idx) {
                                        f.marking = Marking::Unused;
                                    }
                                }
                                if let Some(f) = self.dpb.get_mut(found) {
                                    f.marking = Marking::Long(idx);
                                }
                            }
                        }
                        Mmco::MaxLongTermFrameIdx(plus1) => {
                            self.max_long_term_frame_idx = plus1.checked_sub(1);
                            for f in &mut self.dpb {
                                if let Marking::Long(idx) = f.marking
                                    && self.max_long_term_frame_idx.is_none_or(|max| idx > max)
                                {
                                    f.marking = Marking::Unused;
                                }
                            }
                        }
                        Mmco::UnmarkAll => {
                            for f in &mut self.dpb {
                                f.marking = Marking::Unused;
                            }
                            self.max_long_term_frame_idx = None;
                            mmco5 = true;
                        }
                        Mmco::CurrentToLongTerm(idx) => {
                            if self.max_long_term_frame_idx.is_none_or(|max| idx > max) {
                                return Err(DecodeError::Malformed);
                            }
                            for f in &mut self.dpb {
                                if f.marking == Marking::Long(idx) {
                                    f.marking = Marking::Unused;
                                }
                            }
                            marking = Marking::Long(idx);
                        }
                    }
                }
            }
        }
        let used = self
            .dpb
            .iter()
            .filter(|f| f.marking != Marking::Unused)
            .count();
        if used + 1 > sps.max_num_ref_frames.max(1) as usize {
            return Err(DecodeError::Malformed);
        }
        Ok((marking, mmco5))
    }

    /// Stores the decoded picture and runs the output ("bumping") process
    /// of C.4.5: pictures leave in increasing POC order when the buffer is
    /// full or more than the reorder depth are waiting.
    fn store_and_output(&mut self, current: DpbFrame, sps: &SeqParams) -> Result<(), DecodeError> {
        self.dpb
            .retain(|f| f.waiting || f.marking != Marking::Unused);
        let capacity = sps.max_dpb_frames() as usize;
        let reorder = sps.max_num_reorder_frames.unwrap_or(if sps.poc_type == 2 {
            0
        } else {
            sps.max_dpb_frames()
        }) as usize;
        while self.dpb.len() >= capacity {
            let lowest_waiting = self.dpb.iter().filter(|f| f.waiting).map(|f| f.poc).min();
            match lowest_waiting {
                None => {
                    if current.marking == Marking::Unused {
                        // C.4.5.2: a non-reference picture that finds no
                        // free buffer is output directly.
                        return self.output_frame(&current);
                    }
                    return Err(DecodeError::Malformed);
                }
                Some(lowest) if current.marking == Marking::Unused && current.poc < lowest => {
                    return self.output_frame(&current);
                }
                Some(_) => self.bump()?,
            }
        }
        self.dpb.push(current);
        while self.dpb.iter().filter(|f| f.waiting).count() > reorder {
            self.bump()?;
        }
        Ok(())
    }

    /// Outputs the waiting picture with the smallest POC and drops it from
    /// the buffer when it is no longer used for reference.
    fn bump(&mut self) -> Result<(), DecodeError> {
        let index = self
            .dpb
            .iter()
            .enumerate()
            .filter(|(_, f)| f.waiting)
            .min_by_key(|(_, f)| f.poc)
            .map(|(index, _)| index)
            .ok_or(DecodeError::Malformed)?;
        let frame = self.dpb.get_mut(index).ok_or(DecodeError::Malformed)?;
        frame.waiting = false;
        let picture = Picture::from_frame(&frame.frame, frame.crop, frame.meta)?;
        self.output.push_back(picture);
        if self
            .dpb
            .get(index)
            .is_some_and(|f| f.marking == Marking::Unused)
        {
            self.dpb.remove(index);
        }
        Ok(())
    }

    fn output_frame(&mut self, frame: &DpbFrame) -> Result<(), DecodeError> {
        let picture = Picture::from_frame(&frame.frame, frame.crop, frame.meta)?;
        self.output.push_back(picture);
        Ok(())
    }

    /// Outputs every waiting picture in POC order.
    fn flush_output(&mut self) -> Result<(), DecodeError> {
        while self.dpb.iter().any(|f| f.waiting) {
            self.bump()?;
        }
        Ok(())
    }
}

/// `PicNum` of a short-term frame relative to the current `frame_num`.
fn short_pic_num(frame: &DpbFrame, current: u32, max_frame_num: i64) -> i64 {
    let n = i64::from(frame.frame_num);
    if frame.frame_num > current {
        n - max_frame_num
    } else {
        n
    }
}

/// Initial reference lists (8.2.4.2) plus modification (8.2.4.3), as DPB
/// indices, each of the active length.
fn build_ref_lists(
    dpb: &[DpbFrame],
    header: &SliceHeader,
    sps: &SeqParams,
    poc: i32,
    max_long_term_frame_idx: Option<u32>,
) -> Result<IndexLists, DecodeError> {
    let max_frame_num = 1i64 << sps.log2_max_frame_num;
    let short: Vec<usize> = (0..dpb.len())
        .filter(|&i| dpb.get(i).is_some_and(DpbFrame::is_short))
        .collect();
    let mut long: Vec<(u32, usize)> = dpb
        .iter()
        .enumerate()
        .filter_map(|(i, f)| match f.marking {
            Marking::Long(idx) => Some((idx, i)),
            _ => None,
        })
        .collect();
    long.sort_unstable();
    let long_order: Vec<usize> = long.iter().map(|&(_, i)| i).collect();
    let frame_of = |i: usize| dpb.get(i);
    let mut lists: IndexLists = [Vec::new(), Vec::new()];
    match header.kind {
        SliceKind::I => return Ok(lists),
        SliceKind::P => {
            let mut order = short.clone();
            order.sort_by_key(|&i| {
                std::cmp::Reverse(
                    frame_of(i).map_or(0, |f| short_pic_num(f, header.frame_num, max_frame_num)),
                )
            });
            order.extend(&long_order);
            lists[0] = order.into_iter().map(Some).collect();
        }
        SliceKind::B => {
            let poc_of = |i: &usize| frame_of(*i).map_or(0, |f| f.poc);
            let mut before: Vec<usize> =
                short.iter().copied().filter(|i| poc_of(i) < poc).collect();
            let mut after: Vec<usize> = short.iter().copied().filter(|i| poc_of(i) > poc).collect();
            before.sort_by_key(|i| std::cmp::Reverse(poc_of(i)));
            after.sort_by_key(poc_of);
            let mut l0 = before.clone();
            l0.extend(&after);
            l0.extend(&long_order);
            let mut l1 = after;
            l1.extend(&before);
            l1.extend(&long_order);
            if l1.len() > 1 && l1 == l0 {
                l1.swap(0, 1);
            }
            lists[0] = l0.into_iter().map(Some).collect();
            lists[1] = l1.into_iter().map(Some).collect();
        }
    }
    let counts = [
        header.num_ref_idx_l0_active as usize,
        header.num_ref_idx_l1_active as usize,
    ];
    for (list, count) in counts.into_iter().enumerate() {
        lists[list].resize(count, None);
        modify_list(
            &mut lists[list],
            &header.modifications[list],
            dpb,
            header.frame_num,
            max_frame_num,
            max_long_term_frame_idx,
        )?;
    }
    Ok(lists)
}

/// `ref_pic_list_modification()` processing (8.2.4.3).
fn modify_list(
    list: &mut Vec<Option<usize>>,
    ops: &[RefListModification],
    dpb: &[DpbFrame],
    current: u32,
    max_frame_num: i64,
    max_long_term_frame_idx: Option<u32>,
) -> Result<(), DecodeError> {
    let count = list.len();
    let current_num = i64::from(current);
    let mut pred = current_num;
    for (ref_idx, op) in ops.iter().enumerate() {
        if ref_idx >= count {
            return Err(DecodeError::Malformed);
        }
        let target = match *op {
            RefListModification::ShortTermSubtract(d) | RefListModification::ShortTermAdd(d) => {
                let abs = i64::from(d) + 1;
                let mut no_wrap = if matches!(op, RefListModification::ShortTermSubtract(_)) {
                    pred - abs
                } else {
                    pred + abs
                };
                if no_wrap < 0 {
                    no_wrap += max_frame_num;
                } else if no_wrap >= max_frame_num {
                    no_wrap -= max_frame_num;
                }
                pred = no_wrap;
                let pic_num = if no_wrap > current_num {
                    no_wrap - max_frame_num
                } else {
                    no_wrap
                };
                dpb.iter()
                    .position(|f| {
                        f.is_short() && short_pic_num(f, current, max_frame_num) == pic_num
                    })
                    .ok_or(DecodeError::MissingReference)?
            }
            RefListModification::LongTerm(num) => {
                if max_long_term_frame_idx.is_none_or(|max| num > max) {
                    return Err(DecodeError::Malformed);
                }
                dpb.iter()
                    .position(|f| f.marking == Marking::Long(num))
                    .ok_or(DecodeError::MissingReference)?
            }
        };
        list.insert(ref_idx, Some(target));
        if let Some(duplicate) = list
            .iter()
            .enumerate()
            .skip(ref_idx + 1)
            .find(|(_, slot)| **slot == Some(target))
            .map(|(index, _)| index)
        {
            list.remove(duplicate);
        }
        list.truncate(count);
    }
    Ok(())
}

/// Weighted-prediction mode of a slice (8.4.2.3), with the implicit
/// weights of 8.4.2.3.1 precomputed for every reference pair.
fn weight_mode(
    header: &SliceHeader,
    pps: &PicParams,
    lists: &[Vec<Option<RefEntry<'_>>>; 2],
    poc: i32,
) -> WeightMode {
    if let Some(table) = &header.weights {
        return WeightMode::Explicit(table.clone());
    }
    if header.kind != SliceKind::B || pps.weighted_bipred_idc != 2 {
        return WeightMode::Default;
    }
    let len_l1 = lists[1].len();
    let mut weights = Vec::with_capacity(lists[0].len() * len_l1);
    for pic0 in &lists[0] {
        for pic1 in &lists[1] {
            let pair = match (pic0, pic1) {
                (Some(p0), Some(p1)) if !p0.long_term && !p1.long_term => {
                    let td = p1.poc.saturating_sub(p0.poc).clamp(-128, 127);
                    if td == 0 {
                        (32, 32)
                    } else {
                        let tb = poc.saturating_sub(p0.poc).clamp(-128, 127);
                        let tx = (16_384 + (td / 2).abs()) / td;
                        let scale = ((tb * tx + 32) >> 6).clamp(-1024, 1023);
                        let w1 = scale >> 2;
                        if (-64..=128).contains(&w1) {
                            (64 - w1, w1)
                        } else {
                            (32, 32)
                        }
                    }
                }
                _ => (32, 32),
            };
            weights.push(pair);
        }
    }
    WeightMode::Implicit { weights, len_l1 }
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
