//! Slice data and macroblock layer (clauses 7.3.4, 7.3.5) for CAVLC I and
//! P slices, with reconstruction: intra prediction, inter prediction,
//! motion-vector prediction (8.4.1), residual scaling and transforms.
//!
//! Per-macroblock state is kept in raster 4x4 order (`y4 * 4 + x4`);
//! `luma4x4BlkIdx` order is used only where the syntax is ordered by it.

use crate::DecodeError;
use crate::bits::BitReader;
use crate::cavlc::context_nc;
use crate::inter::{self, Block};
use crate::intra::{self, Neighbors4x4, Neighbors16x16, NeighborsChroma};
use crate::params::{PicParams, SeqParams};
use crate::picture::Frame;
use crate::residual::{ResidualKind, decode_coefficients};
use crate::slice::{SliceHeader, SliceKind};
use crate::transform::{
    ZIGZAG_4X4, add_residual, chroma_dc_inverse, chroma_qp, dequantize_4x4, inverse_transform_4x4,
    luma_dc_inverse,
};

/// `luma4x4BlkIdx` -> raster 4x4 index (clause 6.4.3 inverse scan).
const BLK_TO_RASTER: [usize; 16] = [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];
/// Raster 4x4 index -> `luma4x4BlkIdx`.
const RASTER_TO_BLK: [usize; 16] = [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];

/// coded_block_pattern mapping for Intra_4x4 macroblocks (Table 9-4).
const CBP_INTRA: [u8; 48] = [
    47, 31, 15, 0, 23, 27, 29, 30, 7, 11, 13, 14, 39, 43, 45, 46, 16, 3, 5, 10, 12, 19, 21, 26, 28,
    35, 37, 42, 44, 1, 2, 4, 8, 17, 18, 20, 24, 6, 9, 22, 25, 32, 33, 34, 36, 40, 38, 41,
];
/// coded_block_pattern mapping for Inter macroblocks (Table 9-4).
const CBP_INTER: [u8; 48] = [
    0, 16, 1, 2, 4, 8, 32, 3, 5, 10, 12, 15, 47, 7, 11, 13, 14, 6, 9, 31, 35, 37, 42, 44, 33, 34,
    36, 40, 39, 43, 45, 46, 17, 18, 20, 24, 19, 21, 26, 28, 23, 27, 29, 30, 22, 25, 38, 41,
];

/// Motion vector bounds (Table A-1 / clause 8.4.1: horizontal
/// [-2048, 2047.75] luma samples; the loosest level's vertical range
/// [-512, 511.75]) in quarter-sample units. Larger vectors are non-conforming.
const MV_X_RANGE: std::ops::RangeInclusive<i32> = -8192..=8191;
const MV_Y_RANGE: std::ops::RangeInclusive<i32> = -2048..=2047;

/// Macroblock prediction family for neighbour and deblocking rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MbKind {
    Intra4x4,
    Intra16x16,
    Pcm,
    Inter,
}

/// Decoded state of one macroblock that later macroblocks and the
/// deblocking filter consult.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MbInfo {
    /// 0 = not decoded yet; otherwise the 1-based slice number.
    pub slice: u16,
    pub kind: MbKind,
    /// QP_Y for deblocking (0 for I_PCM, clause 8.7.2.2).
    pub qp: u8,
    /// Intra4x4PredMode per raster 4x4 block (Intra4x4 only).
    pub intra4x4: [u8; 16],
    /// Luma TotalCoeff per raster 4x4 block (AC count for Intra16x16).
    pub nz: [u8; 16],
    /// Chroma AC TotalCoeff per raster 2x2 block, [Cb, Cr].
    pub nz_chroma: [[u8; 4]; 2],
    /// List-0 motion vector per raster 4x4 block (quarter samples).
    pub mv: [[i32; 2]; 16],
    /// List-0 reference index per raster 4x4 block (-1 = none).
    pub ref_idx: [i8; 16],
    /// Identity of the referenced picture per raster 4x4 block.
    pub ref_pic: [u64; 16],
}

impl MbInfo {
    pub const EMPTY: Self = Self {
        slice: 0,
        kind: MbKind::Inter,
        qp: 0,
        intra4x4: [2; 16],
        nz: [0; 16],
        nz_chroma: [[0; 4]; 2],
        mv: [[0; 2]; 16],
        ref_idx: [-1; 16],
        ref_pic: [u64::MAX; 16],
    };

    pub const fn is_intra(&self) -> bool {
        !matches!(self.kind, MbKind::Inter)
    }
}

/// Per-slice parameters the deblocking filter needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SliceInfo {
    pub disable_deblocking_filter_idc: u8,
    pub filter_offset_a: i32,
    pub filter_offset_b: i32,
    pub chroma_qp_offset: [i32; 2],
}

/// One entry of RefPicList0.
pub(crate) struct RefEntry<'a> {
    pub id: u64,
    pub frame: &'a Frame,
}

/// Everything slice-invariant the macroblock layer needs.
pub(crate) struct SliceContext<'a> {
    pub header: &'a SliceHeader,
    pub sps: &'a SeqParams,
    pub pps: &'a PicParams,
    pub slice_num: u16,
    pub ref_list: &'a [RefEntry<'a>],
}

/// Mutable picture under construction.
pub(crate) struct PictureState<'a> {
    pub frame: &'a mut Frame,
    pub infos: &'a mut [MbInfo],
}

/// Neighbour motion data: `None` = partition not available; intra or
/// unused -> `Some((-1, [0, 0]))`.
type MotionNeighbour = Option<(i8, [i32; 2])>;

struct MbDecoder<'s, 'p, 'r> {
    ctx: &'s SliceContext<'s>,
    pic: &'p mut PictureState<'r>,
    width_mbs: usize,
    addr: usize,
    mbx: usize,
    mby: usize,
    info: MbInfo,
    /// 4x4 blocks of the current macroblock whose motion is already set.
    done: u16,
}

/// Decodes `slice_data()` for one slice into the picture.
///
/// Returns the number of macroblocks decoded (including skipped ones).
///
/// # Errors
/// Malformed on syntax errors, overlapping or out-of-picture macroblocks;
/// MissingReference for list-0 indices without a reference picture.
pub(crate) fn decode_slice_data(
    reader: &mut BitReader<'_>,
    ctx: &SliceContext<'_>,
    pic: &mut PictureState<'_>,
) -> Result<u32, DecodeError> {
    let total = ctx.sps.mbs();
    let width_mbs = usize::try_from(ctx.sps.width_mbs).map_err(|_| DecodeError::Limit)?;
    let mut addr = ctx.header.first_mb;
    let mut qp = ctx.header.qp;
    let mut decoded = 0u32;
    loop {
        if ctx.header.kind == SliceKind::P {
            let skip_run = reader.ue(total)?;
            if skip_run > total - addr {
                return Err(DecodeError::Malformed);
            }
            for _ in 0..skip_run {
                let mut mb = MbDecoder::new(ctx, pic, width_mbs, addr)?;
                mb.decode_skip(qp)?;
                mb.commit();
                addr += 1;
                decoded += 1;
            }
            if skip_run > 0 && reader.exhausted() {
                break;
            }
        }
        if addr >= total {
            return Err(DecodeError::Malformed);
        }
        let mut mb = MbDecoder::new(ctx, pic, width_mbs, addr)?;
        mb.decode(reader, &mut qp)?;
        mb.commit();
        addr += 1;
        decoded += 1;
        if reader.exhausted() {
            break;
        }
    }
    Ok(decoded)
}

impl<'s, 'p, 'r> MbDecoder<'s, 'p, 'r> {
    fn new(
        ctx: &'s SliceContext<'s>,
        pic: &'p mut PictureState<'r>,
        width_mbs: usize,
        addr: u32,
    ) -> Result<Self, DecodeError> {
        let addr = usize::try_from(addr).map_err(|_| DecodeError::Limit)?;
        match pic.infos.get(addr) {
            Some(existing) if existing.slice == 0 => {}
            // Already decoded (overlapping slices) or outside the picture.
            _ => return Err(DecodeError::Malformed),
        }
        let mut info = MbInfo::EMPTY;
        info.slice = ctx.slice_num;
        Ok(Self {
            ctx,
            pic,
            width_mbs,
            addr,
            mbx: addr % width_mbs,
            mby: addr / width_mbs,
            info,
            done: 0,
        })
    }

    fn commit(self) {
        if let Some(slot) = self.pic.infos.get_mut(self.addr) {
            *slot = self.info;
        }
    }

    // ----- neighbour availability (clause 6.4.x) -----

    /// Neighbouring macroblock at a macroblock offset, if it is inside the
    /// picture and in the current slice (hence already decoded).
    fn neighbour_mb(&self, dx: isize, dy: isize) -> Option<&MbInfo> {
        let x = self.mbx.checked_add_signed(dx)?;
        let y = self.mby.checked_add_signed(dy)?;
        if x >= self.width_mbs {
            return None;
        }
        let mb = self.pic.infos.get(y * self.width_mbs + x)?;
        (mb.slice == self.ctx.slice_num && (dy < 0 || dx < 0)).then_some(mb)
    }

    /// Availability for Intra prediction: constrained_intra_pred hides
    /// inter-coded neighbours.
    fn intra_available(&self, dx: isize, dy: isize) -> bool {
        self.neighbour_mb(dx, dy)
            .is_some_and(|mb| !self.ctx.pps.constrained_intra_pred || mb.is_intra())
    }

    // ----- macroblock_layer -----

    fn decode(&mut self, reader: &mut BitReader<'_>, qp: &mut i32) -> Result<(), DecodeError> {
        let is_p = self.ctx.header.kind == SliceKind::P;
        let mb_type = reader.ue(if is_p { 30 } else { 25 })?;
        let intra_type = if is_p {
            if mb_type < 5 {
                return self.decode_inter(reader, mb_type, qp);
            }
            mb_type - 5
        } else {
            mb_type
        };
        match intra_type {
            0 => self.decode_intra4x4(reader, qp),
            1..=24 => self.decode_intra16x16(reader, intra_type - 1, qp),
            _ => self.decode_pcm(reader),
        }
    }

    fn read_qp_delta(reader: &mut BitReader<'_>, qp: &mut i32) -> Result<(), DecodeError> {
        let delta = reader.se_range(-26, 25)?;
        *qp = (*qp + delta + 52) % 52;
        Ok(())
    }

    fn set_qp(&mut self, qp: i32) -> Result<(), DecodeError> {
        self.info.qp = u8::try_from(qp).map_err(|_| DecodeError::Malformed)?;
        Ok(())
    }

    fn decode_pcm(&mut self, reader: &mut BitReader<'_>) -> Result<(), DecodeError> {
        while !reader.byte_aligned() {
            if reader.bit()? != 0 {
                return Err(DecodeError::Malformed);
            }
        }
        self.info.kind = MbKind::Pcm;
        // The running QP_Y is unchanged (mb_qp_delta absent, inferred 0);
        // the deblocking filter treats an I_PCM macroblock as qP = 0.
        self.info.qp = 0;
        self.info.nz = [16; 16];
        self.info.nz_chroma = [[16; 4]; 2];
        let stride = self.pic.frame.width;
        for y in 0..16 {
            for x in 0..16 {
                let value = u8::try_from(reader.uint(8)?).map_err(|_| DecodeError::Malformed)?;
                let index = (self.mby * 16 + y) * stride + self.mbx * 16 + x;
                *self
                    .pic
                    .frame
                    .y
                    .get_mut(index)
                    .ok_or(DecodeError::Malformed)? = value;
            }
        }
        let cstride = self.pic.frame.chroma_width();
        for component in 0..2 {
            for y in 0..8 {
                for x in 0..8 {
                    let value =
                        u8::try_from(reader.uint(8)?).map_err(|_| DecodeError::Malformed)?;
                    let index = (self.mby * 8 + y) * cstride + self.mbx * 8 + x;
                    let plane = if component == 0 {
                        &mut self.pic.frame.cb
                    } else {
                        &mut self.pic.frame.cr
                    };
                    *plane.get_mut(index).ok_or(DecodeError::Malformed)? = value;
                }
            }
        }
        Ok(())
    }

    // ----- intra 4x4 -----

    fn predicted_intra4x4_mode(&self, raster: usize) -> u8 {
        let (x4, y4) = (raster % 4, raster / 4);
        // Mode of a neighbouring block, or None if unavailable. Non-I4x4
        // (and constrained-hidden inter) neighbours contribute DC (2).
        let left = if x4 > 0 {
            Some(self.info.intra4x4[raster - 1])
        } else {
            self.neighbour_mb(-1, 0)
                .map(|mb| Self::mode_of(mb, y4 * 4 + 3))
        };
        let above = if y4 > 0 {
            Some(self.info.intra4x4[raster - 4])
        } else {
            self.neighbour_mb(0, -1)
                .map(|mb| Self::mode_of(mb, 12 + x4))
        };
        match (left, above) {
            (Some(a), Some(b)) => a.min(b),
            _ => 2,
        }
    }

    fn mode_of(mb: &MbInfo, raster: usize) -> u8 {
        if mb.kind == MbKind::Intra4x4 {
            mb.intra4x4[raster]
        } else {
            // Inter with constrained_intra_pred sets dcPredModePredictedFlag;
            // every other non-I4x4 case uses mode 2. Both yield DC.
            2
        }
    }

    fn decode_intra4x4(
        &mut self,
        reader: &mut BitReader<'_>,
        qp: &mut i32,
    ) -> Result<(), DecodeError> {
        self.info.kind = MbKind::Intra4x4;
        for &raster in &BLK_TO_RASTER {
            let predicted = self.predicted_intra4x4_mode(raster);
            let mode = if reader.flag()? {
                predicted
            } else {
                let rem = u8::try_from(reader.uint(3)?).map_err(|_| DecodeError::Malformed)?;
                if rem < predicted { rem } else { rem + 1 }
            };
            self.info.intra4x4[raster] = mode;
        }
        let chroma_mode = u8::try_from(reader.ue(3)?).map_err(|_| DecodeError::Malformed)?;
        let cbp_code = usize::try_from(reader.ue(47)?).map_err(|_| DecodeError::Malformed)?;
        let cbp = CBP_INTRA[cbp_code];
        if cbp != 0 {
            Self::read_qp_delta(reader, qp)?;
        }
        self.set_qp(*qp)?;
        let luma = self.read_luma_4x4_residual(reader, cbp & 15)?;
        let chroma = self.read_chroma_residual(reader, cbp >> 4)?;

        // Reconstruct in decoding order: each block's prediction uses the
        // reconstructed samples of the blocks before it.
        for &raster in &BLK_TO_RASTER {
            let neighbours = self.intra4x4_neighbours(raster);
            let pred = intra::predict_4x4(self.info.intra4x4[raster], &neighbours)?;
            let (px, py) = self.luma_origin(raster);
            self.write_luma_block(px, py, &pred);
            if self.info.nz[raster] != 0 {
                let mut block = luma[raster];
                dequantize_4x4(&mut block, *qp, false);
                let residual = inverse_transform_4x4(&block);
                add_residual(
                    &mut self.pic.frame.y,
                    self.pic.frame.width,
                    px,
                    py,
                    &residual,
                );
            }
        }
        self.reconstruct_chroma(chroma_mode, &chroma, *qp)
    }

    fn luma_origin(&self, raster: usize) -> (usize, usize) {
        (
            self.mbx * 16 + (raster % 4) * 4,
            self.mby * 16 + (raster / 4) * 4,
        )
    }

    fn write_luma_block(&mut self, px: usize, py: usize, pred: &[u8; 16]) {
        let stride = self.pic.frame.width;
        for y in 0..4 {
            let start = (py + y) * stride + px;
            if let Some(row) = self.pic.frame.y.get_mut(start..start + 4) {
                row.copy_from_slice(&pred[y * 4..y * 4 + 4]);
            }
        }
    }

    fn intra4x4_neighbours(&self, raster: usize) -> Neighbors4x4 {
        let (x4, y4) = (raster % 4, raster / 4);
        let (px, py) = self.luma_origin(raster);
        let stride = self.pic.frame.width;
        let plane = &self.pic.frame.y;
        let top_ok = y4 > 0 || self.intra_available(0, -1);
        let left_ok = x4 > 0 || self.intra_available(-1, 0);
        let corner_ok = match (x4 > 0, y4 > 0) {
            (true, true) => true,
            (false, true) => self.intra_available(-1, 0),
            (true, false) => self.intra_available(0, -1),
            (false, false) => self.intra_available(-1, -1),
        };
        let top_right_ok = if y4 == 0 {
            if x4 < 3 {
                self.intra_available(0, -1)
            } else {
                self.intra_available(1, -1)
            }
        } else {
            x4 < 3 && RASTER_TO_BLK[raster - 4 + 1] < RASTER_TO_BLK[raster]
        };
        let sample = |x: usize, y: usize| plane.get(y * stride + x).copied().unwrap_or(0);
        let top = top_ok.then(|| {
            let mut t = [0u8; 8];
            for (i, value) in t.iter_mut().enumerate().take(4) {
                *value = sample(px + i, py - 1);
            }
            for i in 4..8 {
                t[i] = if top_right_ok {
                    sample(px + i, py - 1)
                } else {
                    t[3]
                };
            }
            t
        });
        let left = left_ok.then(|| std::array::from_fn(|i| sample(px - 1, py + i)));
        let top_left = corner_ok.then(|| sample(px - 1, py - 1));
        Neighbors4x4 {
            top,
            left,
            top_left,
        }
    }

    // ----- intra 16x16 -----

    fn decode_intra16x16(
        &mut self,
        reader: &mut BitReader<'_>,
        type_index: u32,
        qp: &mut i32,
    ) -> Result<(), DecodeError> {
        self.info.kind = MbKind::Intra16x16;
        let pred_mode = u8::try_from(type_index % 4).map_err(|_| DecodeError::Malformed)?;
        let cbp_chroma = u8::try_from((type_index / 4) % 3).map_err(|_| DecodeError::Malformed)?;
        let cbp_luma_all = type_index >= 12;
        let chroma_mode = u8::try_from(reader.ue(3)?).map_err(|_| DecodeError::Malformed)?;
        Self::read_qp_delta(reader, qp)?;
        self.set_qp(*qp)?;

        // DC: nC of luma4x4BlkIdx 0.
        let mut dc_scan = [0i32; 16];
        let nc = self.luma_nc(0);
        decode_coefficients(reader, ResidualKind::Max16, nc, &mut dc_scan)?;
        let mut ac = [[0i32; 16]; 16];
        for &raster in &BLK_TO_RASTER {
            if cbp_luma_all {
                let mut scan = [0i32; 16];
                let nc = self.luma_nc(raster);
                let total = decode_coefficients(reader, ResidualKind::Max15, nc, &mut scan)?;
                self.info.nz[raster] = total;
                for (k, &value) in scan.iter().take(15).enumerate() {
                    ac[raster][ZIGZAG_4X4[k + 1]] = value;
                }
            }
        }
        let chroma = self.read_chroma_residual(reader, cbp_chroma)?;

        let neighbours = self.intra16x16_neighbours();
        let pred = intra::predict_16x16(pred_mode, &neighbours)?;
        let stride = self.pic.frame.width;
        for y in 0..16 {
            let start = (self.mby * 16 + y) * stride + self.mbx * 16;
            if let Some(row) = self.pic.frame.y.get_mut(start..start + 16) {
                row.copy_from_slice(&pred[y * 16..y * 16 + 16]);
            }
        }
        let mut dc_raster = [0i32; 16];
        for (k, &value) in dc_scan.iter().enumerate() {
            dc_raster[ZIGZAG_4X4[k]] = value;
        }
        let dc = luma_dc_inverse(&dc_raster, *qp);
        for raster in 0..16 {
            let mut block = ac[raster];
            dequantize_4x4(&mut block, *qp, true);
            block[0] = dc[raster];
            if block.iter().all(|&c| c == 0) {
                continue;
            }
            let residual = inverse_transform_4x4(&block);
            let (px, py) = self.luma_origin(raster);
            add_residual(&mut self.pic.frame.y, stride, px, py, &residual);
        }
        self.reconstruct_chroma(chroma_mode, &chroma, *qp)
    }

    fn intra16x16_neighbours(&self) -> Neighbors16x16 {
        let stride = self.pic.frame.width;
        let (px, py) = (self.mbx * 16, self.mby * 16);
        let plane = &self.pic.frame.y;
        let sample = |x: usize, y: usize| plane.get(y * stride + x).copied().unwrap_or(0);
        Neighbors16x16 {
            top: self
                .intra_available(0, -1)
                .then(|| std::array::from_fn(|i| sample(px + i, py - 1))),
            left: self
                .intra_available(-1, 0)
                .then(|| std::array::from_fn(|i| sample(px - 1, py + i))),
            top_left: self.intra_available(-1, -1).then(|| sample(px - 1, py - 1)),
        }
    }

    // ----- residual syntax -----

    /// nC for a luma block (raster index) of the current macroblock.
    fn luma_nc(&self, raster: usize) -> i32 {
        let (x4, y4) = (raster % 4, raster / 4);
        let left = if x4 > 0 {
            Some(self.info.nz[raster - 1])
        } else {
            self.neighbour_mb(-1, 0).map(|mb| mb.nz[y4 * 4 + 3])
        };
        let above = if y4 > 0 {
            Some(self.info.nz[raster - 4])
        } else {
            self.neighbour_mb(0, -1).map(|mb| mb.nz[12 + x4])
        };
        context_nc(left, above)
    }

    fn chroma_nc(&self, component: usize, blk: usize) -> i32 {
        let (x, y) = (blk % 2, blk / 2);
        let left = if x > 0 {
            Some(self.info.nz_chroma[component][blk - 1])
        } else {
            self.neighbour_mb(-1, 0)
                .map(|mb| mb.nz_chroma[component][y * 2 + 1])
        };
        let above = if y > 0 {
            Some(self.info.nz_chroma[component][blk - 2])
        } else {
            self.neighbour_mb(0, -1)
                .map(|mb| mb.nz_chroma[component][2 + x])
        };
        context_nc(left, above)
    }

    /// residual_luma for 4x4-transform macroblocks (not Intra16x16):
    /// returns raster-ordered coefficient blocks, TotalCoeff in `info.nz`.
    fn read_luma_4x4_residual(
        &mut self,
        reader: &mut BitReader<'_>,
        cbp_luma: u8,
    ) -> Result<[[i32; 16]; 16], DecodeError> {
        let mut blocks = [[0i32; 16]; 16];
        for (blk, &raster) in BLK_TO_RASTER.iter().enumerate() {
            if cbp_luma & (1 << (blk / 4)) == 0 {
                self.info.nz[raster] = 0;
                continue;
            }
            let mut scan = [0i32; 16];
            let nc = self.luma_nc(raster);
            let total = decode_coefficients(reader, ResidualKind::Max16, nc, &mut scan)?;
            self.info.nz[raster] = total;
            for (k, &value) in scan.iter().enumerate() {
                blocks[raster][ZIGZAG_4X4[k]] = value;
            }
        }
        Ok(blocks)
    }

    /// residual chroma (4:2:0): DC then AC; returns per component
    /// `[dc(4), ac raster blocks(4 x 16)]`.
    fn read_chroma_residual(
        &mut self,
        reader: &mut BitReader<'_>,
        cbp_chroma: u8,
    ) -> Result<ChromaResidual, DecodeError> {
        let mut out = ChromaResidual::default();
        if cbp_chroma > 2 {
            return Err(DecodeError::Malformed);
        }
        if cbp_chroma & 3 != 0 {
            for dc in &mut out.dc {
                let mut scan = [0i32; 16];
                decode_coefficients(reader, ResidualKind::ChromaDC, -1, &mut scan)?;
                dc.copy_from_slice(&scan[..4]);
            }
        }
        if cbp_chroma & 2 != 0 {
            for component in 0..2 {
                for blk in 0..4 {
                    let mut scan = [0i32; 16];
                    let nc = self.chroma_nc(component, blk);
                    let total = decode_coefficients(reader, ResidualKind::Max15, nc, &mut scan)?;
                    self.info.nz_chroma[component][blk] = total;
                    for (k, &value) in scan.iter().take(15).enumerate() {
                        out.ac[component][blk][ZIGZAG_4X4[k + 1]] = value;
                    }
                }
            }
        }
        Ok(out)
    }

    // ----- chroma reconstruction -----

    fn reconstruct_chroma(
        &mut self,
        mode: u8,
        residual: &ChromaResidual,
        qp: i32,
    ) -> Result<(), DecodeError> {
        let cstride = self.pic.frame.chroma_width();
        let (px, py) = (self.mbx * 8, self.mby * 8);
        let top_ok = self.intra_available(0, -1);
        let left_ok = self.intra_available(-1, 0);
        let corner_ok = self.intra_available(-1, -1);
        for component in 0..2 {
            let plane = if component == 0 {
                &self.pic.frame.cb
            } else {
                &self.pic.frame.cr
            };
            let sample = |x: usize, y: usize| plane.get(y * cstride + x).copied().unwrap_or(0);
            let neighbours = NeighborsChroma {
                top: top_ok.then(|| std::array::from_fn(|i| sample(px + i, py - 1))),
                left: left_ok.then(|| std::array::from_fn(|i| sample(px - 1, py + i))),
                top_left: corner_ok.then(|| sample(px - 1, py - 1)),
            };
            let pred = intra::predict_chroma(mode, &neighbours)?;
            let plane = if component == 0 {
                &mut self.pic.frame.cb
            } else {
                &mut self.pic.frame.cr
            };
            for y in 0..8 {
                let start = (py + y) * cstride + px;
                if let Some(row) = plane.get_mut(start..start + 8) {
                    row.copy_from_slice(&pred[y * 8..y * 8 + 8]);
                }
            }
        }
        self.add_chroma_residual(residual, qp);
        Ok(())
    }

    fn add_chroma_residual(&mut self, residual: &ChromaResidual, qp: i32) {
        let cstride = self.pic.frame.chroma_width();
        let (px, py) = (self.mbx * 8, self.mby * 8);
        for component in 0..2 {
            let offset = if component == 0 {
                self.ctx.pps.chroma_qp_index_offset
            } else {
                self.ctx.pps.second_chroma_qp_index_offset
            };
            let qpc = chroma_qp(qp, offset);
            let dc = chroma_dc_inverse(&residual.dc[component], qpc);
            let plane = if component == 0 {
                &mut self.pic.frame.cb
            } else {
                &mut self.pic.frame.cr
            };
            for blk in 0..4 {
                let mut block = residual.ac[component][blk];
                dequantize_4x4(&mut block, qpc, true);
                block[0] = dc[blk];
                if block.iter().all(|&c| c == 0) {
                    continue;
                }
                let out = inverse_transform_4x4(&block);
                add_residual(plane, cstride, px + (blk % 2) * 4, py + (blk / 2) * 4, &out);
            }
        }
    }

    // ----- inter -----

    fn decode_skip(&mut self, qp: i32) -> Result<(), DecodeError> {
        self.info.kind = MbKind::Inter;
        self.set_qp(qp)?;
        // 8.4.1.1: zero vector when A or B is unavailable or either has
        // refIdx 0 with a zero vector; otherwise 16x16 median prediction.
        let a = self.motion_neighbour(-1, 0);
        let b = self.motion_neighbour(0, -1);
        let zero = match (a, b) {
            (Some(a), Some(b)) => (a.0 == 0 && a.1 == [0, 0]) || (b.0 == 0 && b.1 == [0, 0]),
            _ => true,
        };
        let mv = if zero {
            [0, 0]
        } else {
            self.predict_mv(0, 0, 16, 0, Shape::Other)
        };
        self.apply_partition(0, 0, 16, 16, 0, mv)?;
        Ok(())
    }

    fn decode_inter(
        &mut self,
        reader: &mut BitReader<'_>,
        mb_type: u32,
        qp: &mut i32,
    ) -> Result<(), DecodeError> {
        self.info.kind = MbKind::Inter;
        let num_ref = self.ctx.header.num_ref_idx_l0_active;
        let read_ref = |reader: &mut BitReader<'_>| -> Result<i8, DecodeError> {
            if num_ref > 1 {
                i8::try_from(reader.te(num_ref - 1)?).map_err(|_| DecodeError::Malformed)
            } else {
                Ok(0)
            }
        };
        let read_mvd = |reader: &mut BitReader<'_>| -> Result<[i32; 2], DecodeError> {
            Ok([
                reader.se_range(-32_768, 32_767)?,
                reader.se_range(-32_768, 32_767)?,
            ])
        };
        if mb_type < 3 {
            let parts: &[(usize, usize, usize, usize, Shape)] = match mb_type {
                0 => &[(0, 0, 16, 16, Shape::Other)],
                1 => &[
                    (0, 0, 16, 8, Shape::P16x8Top),
                    (0, 8, 16, 8, Shape::P16x8Bottom),
                ],
                _ => &[
                    (0, 0, 8, 16, Shape::P8x16Left),
                    (8, 0, 8, 16, Shape::P8x16Right),
                ],
            };
            let mut refs = [0i8; 2];
            for slot in refs.iter_mut().take(parts.len()) {
                *slot = read_ref(reader)?;
            }
            let mut mvds = [[0i32; 2]; 2];
            for slot in mvds.iter_mut().take(parts.len()) {
                *slot = read_mvd(reader)?;
            }
            for (index, &(x, y, w, h, shape)) in parts.iter().enumerate() {
                let mvp = self.predict_mv(x, y, w, refs[index], shape);
                let mv = [mvp[0] + mvds[index][0], mvp[1] + mvds[index][1]];
                self.apply_partition(x, y, w, h, refs[index], mv)?;
            }
        } else {
            let mut sub_types = [0u32; 4];
            for slot in &mut sub_types {
                *slot = reader.ue(3)?;
            }
            let mut refs = [0i8; 4];
            if mb_type == 3 {
                for slot in &mut refs {
                    *slot = read_ref(reader)?;
                }
            }
            let mut mvds = [[[0i32; 2]; 4]; 4];
            for (sub, sub_type) in sub_types.iter().enumerate() {
                let count = match sub_type {
                    0 => 1,
                    1 | 2 => 2,
                    _ => 4,
                };
                for slot in mvds[sub].iter_mut().take(count) {
                    *slot = read_mvd(reader)?;
                }
            }
            for (sub, &sub_type) in sub_types.iter().enumerate() {
                let (ox, oy) = ((sub % 2) * 8, (sub / 2) * 8);
                let parts: &[(usize, usize, usize, usize)] = match sub_type {
                    0 => &[(0, 0, 8, 8)],
                    1 => &[(0, 0, 8, 4), (0, 4, 8, 4)],
                    2 => &[(0, 0, 4, 8), (4, 0, 4, 8)],
                    _ => &[(0, 0, 4, 4), (4, 0, 4, 4), (0, 4, 4, 4), (4, 4, 4, 4)],
                };
                for (index, &(x, y, w, h)) in parts.iter().enumerate() {
                    let (x, y) = (ox + x, oy + y);
                    let mvp = self.predict_mv(x, y, w, refs[sub], Shape::Other);
                    let mvd = mvds[sub][index];
                    self.apply_partition(
                        x,
                        y,
                        w,
                        h,
                        refs[sub],
                        [mvp[0] + mvd[0], mvp[1] + mvd[1]],
                    )?;
                }
            }
        }

        let cbp_code = usize::try_from(reader.ue(47)?).map_err(|_| DecodeError::Malformed)?;
        let cbp = CBP_INTER[cbp_code];
        if cbp != 0 {
            Self::read_qp_delta(reader, qp)?;
        }
        self.set_qp(*qp)?;
        let luma = self.read_luma_4x4_residual(reader, cbp & 15)?;
        let chroma = self.read_chroma_residual(reader, cbp >> 4)?;
        let stride = self.pic.frame.width;
        for (raster, coefficients) in luma.iter().enumerate() {
            if self.info.nz[raster] == 0 {
                continue;
            }
            let mut block = *coefficients;
            dequantize_4x4(&mut block, *qp, false);
            let residual = inverse_transform_4x4(&block);
            let (px, py) = self.luma_origin(raster);
            add_residual(&mut self.pic.frame.y, stride, px, py, &residual);
        }
        self.add_chroma_residual(&chroma, *qp);
        Ok(())
    }

    /// Stores a partition's motion, then writes its prediction samples.
    fn apply_partition(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        ref_idx: i8,
        mv: [i32; 2],
    ) -> Result<(), DecodeError> {
        if !MV_X_RANGE.contains(&mv[0]) || !MV_Y_RANGE.contains(&mv[1]) {
            return Err(DecodeError::Malformed);
        }
        let reference = usize::try_from(ref_idx)
            .ok()
            .and_then(|i| self.ctx.ref_list.get(i))
            .ok_or(DecodeError::MissingReference)?;
        for by in (y / 4)..((y + h) / 4) {
            for bx in (x / 4)..((x + w) / 4) {
                let raster = by * 4 + bx;
                self.info.mv[raster] = mv;
                self.info.ref_idx[raster] = ref_idx;
                self.info.ref_pic[raster] = reference.id;
                self.done |= 1 << raster;
            }
        }
        let block = Block {
            x: self.mbx * 16 + x,
            y: self.mby * 16 + y,
            width: w,
            height: h,
        };
        inter::predict_block(reference.frame, self.pic.frame, block, mv);
        Ok(())
    }

    /// Motion data of the 4x4 block covering MB-relative luma (x, y).
    fn motion_neighbour(&self, x: isize, y: isize) -> MotionNeighbour {
        let from_mb = |mb: &MbInfo, raster: usize| -> (i8, [i32; 2]) {
            if mb.is_intra() {
                (-1, [0, 0])
            } else {
                (mb.ref_idx[raster], mb.mv[raster])
            }
        };
        match (x, y) {
            (x, y) if x < 0 && y < 0 => self.neighbour_mb(-1, -1).map(|mb| from_mb(mb, 15)),
            (x, y) if x < 0 => {
                let row = usize::try_from(y).ok()? / 4;
                self.neighbour_mb(-1, 0).map(|mb| from_mb(mb, row * 4 + 3))
            }
            (x, y) if y < 0 => {
                let col = usize::try_from(x).ok()? / 4;
                if col >= 4 {
                    self.neighbour_mb(1, -1).map(|mb| from_mb(mb, 12))
                } else {
                    self.neighbour_mb(0, -1).map(|mb| from_mb(mb, 12 + col))
                }
            }
            (x, y) => {
                let (col, row) = (usize::try_from(x).ok()? / 4, usize::try_from(y).ok()? / 4);
                if col >= 4 || row >= 4 {
                    return None;
                }
                let raster = row * 4 + col;
                (self.done & (1 << raster) != 0)
                    .then(|| (self.info.ref_idx[raster], self.info.mv[raster]))
            }
        }
    }

    /// Luma motion-vector prediction (clause 8.4.1.3).
    fn predict_mv(&self, x: usize, y: usize, w: usize, ref_idx: i8, shape: Shape) -> [i32; 2] {
        let (xi, yi, wi) = (as_isize(x), as_isize(y), as_isize(w));
        let a = self.motion_neighbour(xi - 1, yi);
        let b = self.motion_neighbour(xi, yi - 1);
        let c = self
            .motion_neighbour(xi + wi, yi - 1)
            .or_else(|| self.motion_neighbour(xi - 1, yi - 1));
        let unpack = |n: MotionNeighbour| n.unwrap_or((-1, [0, 0]));
        match shape {
            Shape::P16x8Top if unpack(b).0 == ref_idx => return unpack(b).1,
            Shape::P16x8Bottom if unpack(a).0 == ref_idx => return unpack(a).1,
            Shape::P8x16Left if unpack(a).0 == ref_idx => return unpack(a).1,
            Shape::P8x16Right if unpack(c).0 == ref_idx => return unpack(c).1,
            _ => {}
        }
        let (a, b, c) = if b.is_none() && c.is_none() && a.is_some() {
            (a, a, a)
        } else {
            (a, b, c)
        };
        let (a, b, c) = (unpack(a), unpack(b), unpack(c));
        let matches = [a.0 == ref_idx, b.0 == ref_idx, c.0 == ref_idx];
        match matches {
            [true, false, false] => a.1,
            [false, true, false] => b.1,
            [false, false, true] => c.1,
            _ => [
                median(a.1[0], b.1[0], c.1[0]),
                median(a.1[1], b.1[1], c.1[1]),
            ],
        }
    }
}

fn as_isize(value: usize) -> isize {
    isize::try_from(value).unwrap_or(isize::MAX)
}

fn median(a: i32, b: i32, c: i32) -> i32 {
    a.max(b).min(a.min(b).max(c))
}

/// Partition shapes with directional motion-vector prediction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    P16x8Top,
    P16x8Bottom,
    P8x16Left,
    P8x16Right,
    Other,
}

/// Parsed chroma residual of one macroblock.
#[derive(Default)]
struct ChromaResidual {
    dc: [[i32; 4]; 2],
    ac: [[[i32; 16]; 4]; 2],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbp_tables_are_permutations() {
        for table in [CBP_INTRA, CBP_INTER] {
            let mut seen = [false; 48];
            for &value in &table {
                assert!(!seen[usize::from(value)]);
                seen[usize::from(value)] = true;
            }
        }
    }

    #[test]
    fn block_index_maps_are_inverse() {
        for blk in 0..16 {
            assert_eq!(RASTER_TO_BLK[BLK_TO_RASTER[blk]], blk);
        }
        // luma4x4BlkIdx 5 is the top-right 4x4 of the top-right 8x8 block.
        assert_eq!(BLK_TO_RASTER[5], 3);
        assert_eq!(BLK_TO_RASTER[10], 12);
    }

    #[test]
    fn median_of_three() {
        assert_eq!(median(1, 5, 3), 3);
        assert_eq!(median(-4, -4, 9), -4);
        assert_eq!(median(7, 2, 2), 2);
    }
}
