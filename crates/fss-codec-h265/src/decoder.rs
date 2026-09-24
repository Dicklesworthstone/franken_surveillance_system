//! Streaming decoder: parameter-set store, picture assembly from slice
//! segments, picture order count (clause 8.3.1), reference picture set
//! marking (clause 8.3.2) and the decoded picture buffer's output order.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::ctu::{PicState, SliceDecoder, SliceInputs};
use crate::nal::{NalHeader, rbsp_from_ebsp, stop_bit_position, unit_type};
use crate::params::{MAX_DPB, Pps, Sps, parse_pps, parse_sps, parse_vps_id};
use crate::picture::{Frame, Picture, PictureMeta};
use crate::residual::Scans;
use crate::slice::{SliceHeader, SliceType, parse_slice_header};
use crate::tables::transform_matrix;
use crate::{DecodeError, UnsupportedFeature};

/// Owner-narrowable decode budgets. Every limit is checked before the
/// allocation or work it bounds; exceeding one is [`DecodeError::Limit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderLimits {
    /// Maximum coded luma width (before cropping), at most 16,384.
    pub max_width: u32,
    /// Maximum coded luma height (before cropping), at most 16,384.
    pub max_height: u32,
    /// Maximum luma samples per picture, at most 2^28.
    pub max_luma_samples: u64,
    /// Maximum pictures this decoder will ever decode (lifetime work bound).
    pub max_pictures: u64,
    /// Maximum bytes of one NAL unit including its header, at most 16 MiB.
    pub max_nal_bytes: usize,
    /// Maximum slice segments in one picture, at most 65,535.
    pub max_slices_per_picture: u32,
    /// Maximum `sps_max_dec_pic_buffering_minus1 + 1` an SPS may declare,
    /// at most 16.
    pub max_dpb_pictures: u32,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_width: 4_096,
            max_height: 2_304,
            max_luma_samples: 4_096 * 2_304,
            max_pictures: u64::MAX,
            max_nal_bytes: 8 * 1_024 * 1_024,
            max_slices_per_picture: 1_024,
            max_dpb_pictures: 16,
        }
    }
}

impl DecoderLimits {
    fn validate(&self) -> Result<(), DecodeError> {
        if !(8..=16_384).contains(&self.max_width)
            || !(8..=16_384).contains(&self.max_height)
            || !(64..=(1 << 28)).contains(&self.max_luma_samples)
            || self.max_pictures == 0
            || !(3..=16 * 1_024 * 1_024).contains(&self.max_nal_bytes)
            || !(1..=65_535).contains(&self.max_slices_per_picture)
            || !(1..=16).contains(&self.max_dpb_pictures)
        {
            return Err(DecodeError::Limit);
        }
        Ok(())
    }
}

/// Reference marking of a stored picture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Marking {
    Unused,
    Short,
}

/// One picture in the decoded picture buffer.
struct DpbPicture {
    frame: Arc<Frame>,
    poc: i32,
    marking: Marking,
    /// "Needed for output".
    waiting: bool,
    crop: [u32; 4],
    meta: PictureMeta,
}

/// A picture whose slice segments are still arriving.
struct Pending {
    sps: Arc<Sps>,
    pps: Arc<Pps>,
    state: PicState,
    poc: i32,
    nal: NalHeader,
    output: bool,
    slices: u32,
}

/// Streaming H.265 decoder (Main profile, 8-bit 4:2:0).
///
/// Feed NAL units (without start codes) with [`Decoder::decode_nal`], or
/// Annex-B bytes with [`Decoder::decode_annex_b`]. Pictures are returned in
/// output (display) order: the decoded picture buffer holds pictures until
/// the stream's reorder depth (`sps_max_num_reorder_pics`) or buffer size
/// (`sps_max_dec_pic_buffering_minus1 + 1`) releases them, and an IDR or
/// BLA picture releases every earlier picture. Call [`Decoder::finish`] at
/// the end of the stream to flush the remaining pictures.
///
/// Error discipline: any error inside a picture discards that picture and
/// puts the decoder in a "wait for an IRAP picture" state, so later
/// pictures never predict from a damaged reference. Parameter-set errors
/// leave previously stored parameter sets untouched.
pub struct Decoder {
    limits: DecoderLimits,
    vps: [bool; 16],
    sps: Vec<Option<Arc<Sps>>>,
    pps: Vec<Option<Arc<Pps>>>,
    dpb: Vec<DpbPicture>,
    output: VecDeque<Picture>,
    pending: Option<Pending>,
    /// Slices of a skipped (RASL) picture are ignored until the next
    /// picture starts.
    skipping: bool,
    need_irap: bool,
    /// The next CRA starts a new coded video sequence (stream start or
    /// after an end-of-sequence NAL unit).
    first_after_eos: bool,
    /// NoRaslOutputFlag of the most recent IRAP picture.
    irap_no_rasl_output: bool,
    /// `PicOrderCntVal` of prevTid0Pic.
    prev_tid0_poc: i32,
    pictures: u64,
    scans: Scans,
    matrix: Box<[[i32; 32]; 32]>,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("limits", &self.limits)
            .field("pictures", &self.pictures)
            .field("buffered", &self.dpb.len())
            .field("queued_output", &self.output.len())
            .field("pending", &self.pending.is_some())
            .field("need_irap", &self.need_irap)
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
            vps: [false; 16],
            sps: (0..16).map(|_| None).collect(),
            pps: (0..64).map(|_| None).collect(),
            dpb: Vec::new(),
            output: VecDeque::new(),
            pending: None,
            skipping: false,
            need_irap: true,
            first_after_eos: true,
            irap_no_rasl_output: true,
            prev_tid0_poc: 0,
            pictures: 0,
            scans: Scans::new(),
            matrix: Box::new(transform_matrix()),
        })
    }

    /// Pictures decoded so far (in decode order; some may still be held for
    /// output reordering).
    #[must_use]
    pub const fn pictures_decoded(&self) -> u64 {
        self.pictures
    }

    /// Decodes one NAL unit (two-byte header included, no start code) and
    /// returns the next picture in output order, if one is ready. When a
    /// NAL makes several pictures ready at once, the others are returned by
    /// [`Self::next_output`] or later calls.
    ///
    /// SEI, access unit delimiters, filler data and reserved NAL unit types
    /// are accepted and ignored.
    ///
    /// # Errors
    /// Any [`DecodeError`]; see the type-level error discipline.
    pub fn decode_nal(&mut self, nal: &[u8]) -> Result<Option<Picture>, DecodeError> {
        if nal.len() > self.limits.max_nal_bytes {
            return Err(DecodeError::Limit);
        }
        let (header, payload) = NalHeader::split(nal)?;
        if header.layer_id > 0 {
            return Err(DecodeError::Unsupported(UnsupportedFeature::MultiLayer));
        }
        match header.unit_type {
            unit_type::VPS => self.store_vps(payload)?,
            unit_type::SPS => self.store_sps(payload)?,
            unit_type::PPS => self.store_pps(payload)?,
            unit_type::EOS | unit_type::EOB => {
                self.finish_pending()?;
                self.first_after_eos = true;
            }
            0..=9 | 16..=21 => {
                if let Err(err) = self.decode_slice(header, payload) {
                    self.pending = None;
                    self.need_irap = true;
                    return Err(err);
                }
            }
            _ => {}
        }
        Ok(self.output.pop_front())
    }

    /// The next picture already released for output, if any.
    pub fn next_output(&mut self) -> Option<Picture> {
        self.output.pop_front()
    }

    /// Decodes every NAL unit of an Annex-B byte stream and returns the
    /// pictures released for output, in output order. Pictures still held
    /// for reordering are returned by [`Self::finish`]. Stops at the first
    /// error; pictures released earlier in the same call are then not
    /// returned (feed NAL units individually with [`Self::decode_nal`] to
    /// keep them).
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
    /// pictures not yet taken).
    ///
    /// # Errors
    /// [`DecodeError::IncompletePicture`] when a picture was missing slice
    /// segments (it is discarded); the flushed pictures then stay available
    /// through [`Self::next_output`].
    pub fn finish(&mut self) -> Result<Vec<Picture>, DecodeError> {
        let incomplete = self.finish_pending().is_err();
        self.flush_output(false)?;
        if incomplete {
            self.need_irap = true;
            return Err(DecodeError::IncompletePicture);
        }
        Ok(self.output.drain(..).collect())
    }

    fn store_vps(&mut self, payload: &[u8]) -> Result<(), DecodeError> {
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let id = parse_vps_id(&rbsp)?;
        self.vps[usize::from(id)] = true;
        Ok(())
    }

    fn store_sps(&mut self, payload: &[u8]) -> Result<(), DecodeError> {
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let sps = parse_sps(&rbsp)?;
        if sps.width > self.limits.max_width
            || sps.height > self.limits.max_height
            || sps.luma_samples() > self.limits.max_luma_samples
            || sps.max_dec_pic_buffering > self.limits.max_dpb_pictures
        {
            return Err(DecodeError::Limit);
        }
        if !self.vps[usize::from(sps.vps_id)] {
            return Err(DecodeError::MissingParameterSet);
        }
        let id = usize::from(sps.id);
        self.sps[id] = Some(Arc::new(sps));
        Ok(())
    }

    fn store_pps(&mut self, payload: &[u8]) -> Result<(), DecodeError> {
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let pps = parse_pps(&rbsp)?;
        let id = usize::from(pps.id);
        self.pps[id] = Some(Arc::new(pps));
        Ok(())
    }

    fn lookup(&self, pps_id: u8) -> Option<(&Pps, &Sps)> {
        let pps = self.pps.get(usize::from(pps_id))?.as_deref()?;
        let sps = self.sps.get(usize::from(pps.sps_id))?.as_deref()?;
        Some((pps, sps))
    }

    fn decode_slice(&mut self, nal: NalHeader, payload: &[u8]) -> Result<(), DecodeError> {
        let rbsp = rbsp_from_ebsp(payload, self.limits.max_nal_bytes)?;
        let stop = stop_bit_position(&rbsp)?;
        let header = parse_slice_header(&rbsp, stop, nal, |id| self.lookup(id))?;
        if header.first_slice_in_pic {
            self.finish_pending()?;
            self.skipping = false;
            if !self.start_picture(nal, &header)? {
                self.skipping = true;
                return Ok(());
            }
        } else if self.skipping {
            return Ok(());
        }
        let mut pending = self.pending.take().ok_or(DecodeError::IncompletePicture)?;
        if header.pps_id != pending.pps.id || nal.unit_type != pending.nal.unit_type {
            return Err(DecodeError::Malformed);
        }
        pending.slices += 1;
        if pending.slices > self.limits.max_slices_per_picture {
            return Err(DecodeError::Limit);
        }
        if header.slice_type != SliceType::I {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::InterPrediction,
            ));
        }
        if !header.deblocking_disabled || header.sao_luma || header.sao_chroma {
            return Err(DecodeError::Unsupported(UnsupportedFeature::LoopFilter));
        }
        let (sps, pps) = (Arc::clone(&pending.sps), Arc::clone(&pending.pps));
        let inputs = SliceInputs {
            sps: &sps,
            pps: &pps,
            header: &header,
            scans: &self.scans,
            matrix: &self.matrix,
        };
        SliceDecoder::new(&inputs, &mut pending.state, &rbsp, stop + 1)?.decode()?;
        if pending.state.complete() {
            self.finish_picture(pending)
        } else {
            self.pending = Some(pending);
            Ok(())
        }
    }

    /// Starts a new picture from its first slice segment header. Returns
    /// `false` when the picture is skipped (RASL pictures of an IRAP
    /// picture that starts a coded video sequence).
    fn start_picture(&mut self, nal: NalHeader, header: &SliceHeader) -> Result<bool, DecodeError> {
        let pps = self
            .pps
            .get(usize::from(header.pps_id))
            .and_then(Clone::clone)
            .ok_or(DecodeError::MissingParameterSet)?;
        let sps = self
            .sps
            .get(usize::from(pps.sps_id))
            .and_then(Clone::clone)
            .ok_or(DecodeError::MissingParameterSet)?;
        pps.validate(&sps)?;
        if self.pictures >= self.limits.max_pictures {
            return Err(DecodeError::Limit);
        }
        if nal.is_irap() {
            self.irap_no_rasl_output = nal.is_idr() || nal.is_bla() || self.first_after_eos;
            self.first_after_eos = false;
            self.need_irap = false;
        } else if nal.is_rasl() && self.irap_no_rasl_output {
            return Ok(false);
        } else if self.need_irap {
            return Err(DecodeError::MissingReference);
        }
        if !header.long_term.is_empty() {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::LongTermReference,
            ));
        }
        let poc = self.picture_order_count(nal, header, &sps);
        // A new coded video sequence releases (or, with
        // no_output_of_prior_pics_flag, discards) every earlier picture.
        if nal.is_irap() && self.irap_no_rasl_output {
            self.flush_output(header.no_output_of_prior_pics)?;
        }
        self.mark_references(nal, header, poc)?;
        let state = PicState::new(&sps)?;
        self.pending = Some(Pending {
            sps,
            pps,
            state,
            poc,
            nal,
            output: header.pic_output,
            slices: 0,
        });
        Ok(true)
    }

    /// Clause 8.3.1.
    fn picture_order_count(&mut self, nal: NalHeader, header: &SliceHeader, sps: &Sps) -> i32 {
        let max_lsb = 1i32 << sps.log2_max_poc_lsb;
        let lsb = header.poc_lsb as i32;
        let msb = if nal.is_irap() && self.irap_no_rasl_output {
            0
        } else {
            let prev_lsb = self.prev_tid0_poc.rem_euclid(max_lsb);
            let prev_msb = self.prev_tid0_poc - prev_lsb;
            if lsb < prev_lsb && prev_lsb - lsb >= max_lsb / 2 {
                prev_msb + max_lsb
            } else if lsb > prev_lsb && lsb - prev_lsb > max_lsb / 2 {
                prev_msb - max_lsb
            } else {
                prev_msb
            }
        };
        let poc = msb + lsb;
        let radl_or_rasl = (6..=9).contains(&nal.unit_type);
        if nal.temporal_id == 0 && !radl_or_rasl && !nal.is_sub_layer_non_reference() {
            self.prev_tid0_poc = poc;
        }
        poc
    }

    /// Reference picture set marking (clause 8.3.2): pictures named by the
    /// current RPS stay short-term references; all others become unused.
    fn mark_references(
        &mut self,
        nal: NalHeader,
        header: &SliceHeader,
        poc: i32,
    ) -> Result<(), DecodeError> {
        if nal.is_irap() && self.irap_no_rasl_output {
            for picture in &mut self.dpb {
                picture.marking = Marking::Unused;
            }
        }
        let mut keep: Vec<i32> = Vec::new();
        if let Some(rps) = &header.st_rps {
            keep.extend(rps.delta_s0.iter().chain(&rps.delta_s1).map(|d| poc + d));
        }
        for picture in &mut self.dpb {
            if picture.marking == Marking::Short && !keep.contains(&picture.poc) {
                picture.marking = Marking::Unused;
            }
        }
        self.dpb
            .retain(|picture| picture.waiting || picture.marking != Marking::Unused);
        if self.dpb.len() >= MAX_DPB {
            return Err(DecodeError::Limit);
        }
        Ok(())
    }

    /// Completes the pending picture if its slices are all present.
    fn finish_pending(&mut self) -> Result<(), DecodeError> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        if !pending.state.complete() {
            self.need_irap = true;
            return Err(DecodeError::IncompletePicture);
        }
        self.finish_picture(pending)
    }

    fn finish_picture(&mut self, pending: Pending) -> Result<(), DecodeError> {
        let meta = PictureMeta {
            poc: pending.poc,
            nal_type: pending.nal.unit_type,
            decode_index: self.pictures,
        };
        self.pictures += 1;
        self.dpb.push(DpbPicture {
            frame: Arc::new(pending.state.frame),
            poc: pending.poc,
            marking: Marking::Short,
            waiting: pending.output,
            crop: pending.sps.crop,
            meta,
        });
        // Output ("bumping") as the oracle's decoder does it: while more
        // pictures wait than the reorder depth allows, or the buffer holds
        // more pictures than sps_max_dec_pic_buffering, release the one with
        // the smallest picture order count.
        let reorder = pending.sps.max_num_reorder as usize;
        let capacity = pending.sps.max_dec_pic_buffering as usize;
        loop {
            let waiting = self.dpb.iter().filter(|p| p.waiting).count();
            if waiting == 0 || (waiting <= reorder && self.dpb.len() <= capacity) {
                break;
            }
            self.bump()?;
        }
        Ok(())
    }

    /// Outputs the waiting picture with the smallest picture order count.
    fn bump(&mut self) -> Result<(), DecodeError> {
        let Some(index) = self
            .dpb
            .iter()
            .enumerate()
            .filter(|(_, p)| p.waiting)
            .min_by_key(|(_, p)| p.poc)
            .map(|(i, _)| i)
        else {
            return Ok(());
        };
        let picture = &mut self.dpb[index];
        picture.waiting = false;
        let out = Picture::from_frame(&picture.frame, picture.crop, picture.meta)?;
        self.output.push_back(out);
        if picture.marking == Marking::Unused {
            self.dpb.remove(index);
        }
        Ok(())
    }

    /// Releases (or discards) every waiting picture.
    fn flush_output(&mut self, discard: bool) -> Result<(), DecodeError> {
        if discard {
            for picture in &mut self.dpb {
                picture.waiting = false;
            }
        }
        while self.dpb.iter().any(|p| p.waiting) {
            self.bump()?;
        }
        self.dpb
            .retain(|picture| picture.marking != Marking::Unused);
        Ok(())
    }
}

/// Splits an Annex-B byte stream on `00 00 01` start codes, dropping the
/// leading/trailing zero bytes around each NAL unit.
#[must_use]
pub fn annex_b_nal_units(bytes: &[u8]) -> AnnexBUnits<'_> {
    AnnexBUnits {
        bytes,
        position: find_start(bytes, 0),
    }
}

fn find_start(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 3 <= bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            return Some(i + 3);
        }
        i += 1;
    }
    None
}

/// Iterator over the NAL units of an Annex-B byte stream.
#[derive(Debug)]
pub struct AnnexBUnits<'a> {
    bytes: &'a [u8],
    position: Option<usize>,
}

impl<'a> Iterator for AnnexBUnits<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            let start = self.position?;
            let next = find_start(self.bytes, start);
            let mut end = next.map_or(self.bytes.len(), |n| n - 3);
            self.position = next;
            while end > start && self.bytes[end - 1] == 0 {
                end -= 1;
            }
            if end > start {
                return Some(&self.bytes[start..end]);
            }
        }
    }
}
