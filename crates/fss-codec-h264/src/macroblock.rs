//! Slice data and macroblock layer (clauses 7.3.4, 7.3.5) for I, P and B
//! slices under CAVLC or CABAC, with reconstruction: intra prediction
//! (4x4, 8x8, 16x16), inter prediction with weighting, motion-vector and
//! direct-mode prediction (8.4.1), residual scaling and transforms.
//!
//! Parsing is shared between the two entropy coders through the
//! [`SyntaxReader`] trait: this module owns the syntax *structure* and all
//! neighbour/context state; `mb_cavlc` and `mb_cabac` own how each syntax
//! element is coded.
//!
//! Per-macroblock state is kept in raster 4x4 order (`y4 * 4 + x4`);
//! `luma4x4BlkIdx` order is used only where the syntax is ordered by it.
//! Reference indices are per 8x8 quadrant (`b8 = (y4 / 2) * 2 + x4 / 2`).

use crate::DecodeError;
use crate::bits::BitReader;
use crate::inter;
use crate::intra::{self, Neighbors4x4, Neighbors8x8, Neighbors16x16, NeighborsChroma};
use crate::mb_cabac::CabacReader;
use crate::mb_cavlc::CavlcReader;
use crate::params::{PicParams, ScalingMatrix, SeqParams};
use crate::picture::Frame;
use crate::slice::{PredWeightTable, SliceHeader, SliceKind};
use crate::transform::{
    ZIGZAG_4X4, ZIGZAG_8X8, add_residual, add_residual_8x8, chroma_dc_inverse_scaled, chroma_qp,
    dequantize_4x4_scaled, dequantize_8x8, inverse_transform_4x4, inverse_transform_8x8,
    luma_dc_inverse_scaled,
};

/// `luma4x4BlkIdx` -> raster 4x4 index (clause 6.4.3 inverse scan).
pub(crate) const BLK_TO_RASTER: [usize; 16] =
    [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];
/// Raster 4x4 index -> `luma4x4BlkIdx`.
pub(crate) const RASTER_TO_BLK: [usize; 16] =
    [0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15];

/// Motion vector bounds (Table A-1 / clause 8.4.1: horizontal
/// [-2048, 2047.75] luma samples; the loosest level's vertical range
/// [-512, 511.75]) in quarter-sample units. Larger vectors are non-conforming.
const MV_X_RANGE: std::ops::RangeInclusive<i32> = -8192..=8191;
const MV_Y_RANGE: std::ops::RangeInclusive<i32> = -2048..=2047;

/// 8x8 quadrant of a raster 4x4 block.
pub(crate) const fn b8_of(raster: usize) -> usize {
    (raster / 8) * 2 + (raster % 4) / 2
}

/// Macroblock prediction family for neighbour and deblocking rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MbKind {
    Intra4x4,
    Intra8x8,
    Intra16x16,
    Pcm,
    Inter,
}

/// Decoded state of one macroblock that later macroblocks, the deblocking
/// filter, CABAC context selection and co-located (direct) prediction of
/// later pictures consult.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MbInfo {
    /// 0 = not decoded yet; otherwise the 1-based slice number.
    pub slice: u16,
    pub kind: MbKind,
    /// P_Skip or B_Skip.
    pub skip: bool,
    /// B_Skip or B_Direct_16x16.
    pub direct16: bool,
    /// Quadrants predicted in direct mode (bit per `b8`).
    pub direct8: u8,
    pub transform_8x8: bool,
    /// QP_Y for deblocking (0 for I_PCM, clause 8.7.2.2).
    pub qp: u8,
    /// coded_block_pattern: luma in bits 0..=3, chroma (0..=2) in bits 4..=5.
    pub cbp: u8,
    pub chroma_pred_mode: u8,
    /// coded_block_flag of the DC blocks: bit 0 luma (Intra16x16), 1 Cb, 2 Cr.
    pub coded_dc: u8,
    /// Intra4x4PredMode (or Intra8x8PredMode, replicated) per raster 4x4.
    pub intra4x4: [u8; 16],
    /// Luma TotalCoeff per raster 4x4 block (AC count for Intra16x16; the
    /// 8x8 block count, replicated, for CABAC 8x8 blocks).
    pub nz: [u8; 16],
    /// Chroma AC TotalCoeff per raster 2x2 block, [Cb, Cr].
    pub nz_chroma: [[u8; 4]; 2],
    /// Motion vectors per list per raster 4x4 block (quarter samples).
    pub mv: [[[i16; 2]; 16]; 2],
    /// |mvd| per list per raster 4x4 block, saturated (CABAC contexts).
    pub mvd: [[[u8; 2]; 16]; 2],
    /// Reference index per list per 8x8 quadrant (-1 = list unused).
    pub ref_idx: [[i8; 4]; 2],
    /// Identity of the referenced picture per list per quadrant.
    pub ref_pic: [[u64; 4]; 2],
}

/// Reference identity meaning "no picture".
pub(crate) const NO_PICTURE: u64 = u64::MAX;

impl MbInfo {
    pub const EMPTY: Self = Self {
        slice: 0,
        kind: MbKind::Inter,
        skip: false,
        direct16: false,
        direct8: 0,
        transform_8x8: false,
        qp: 0,
        cbp: 0,
        chroma_pred_mode: 0,
        coded_dc: 0,
        intra4x4: [2; 16],
        nz: [0; 16],
        nz_chroma: [[0; 4]; 2],
        mv: [[[0; 2]; 16]; 2],
        mvd: [[[0; 2]; 16]; 2],
        ref_idx: [[-1; 4]; 2],
        ref_pic: [[NO_PICTURE; 4]; 2],
    };

    pub const fn is_intra(&self) -> bool {
        !matches!(self.kind, MbKind::Inter)
    }

    /// Whether the transform block containing raster 4x4 block `blk` has
    /// non-zero coefficients (deblocking bS 2, clause 8.7.2.1).
    pub fn has_coefficients(&self, blk: usize) -> bool {
        if self.transform_8x8 {
            let b8 = b8_of(blk);
            let base = (b8 / 2) * 8 + (b8 % 2) * 2;
            [base, base + 1, base + 4, base + 5]
                .iter()
                .any(|&k| self.nz[k] != 0)
        } else {
            self.nz[blk] != 0
        }
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

/// One entry of RefPicList0/1.
pub(crate) struct RefEntry<'a> {
    pub id: u64,
    pub frame: &'a Frame,
    /// Macroblock motion of the reference (co-located prediction).
    pub motion: &'a [MbInfo],
    /// PicOrderCnt of the frame.
    pub poc: i32,
    pub long_term: bool,
}

/// Weighted sample prediction mode of a slice (clause 8.4.2.3).
pub(crate) enum WeightMode {
    Default,
    Explicit(PredWeightTable),
    /// Implicit bi-prediction weights `(w0, w1)` indexed by
    /// `ref_idx_l0 * len_l1 + ref_idx_l1`.
    Implicit {
        weights: Vec<(i32, i32)>,
        len_l1: usize,
    },
}

/// Everything slice-invariant the macroblock layer needs.
pub(crate) struct SliceContext<'a> {
    pub header: &'a SliceHeader,
    pub sps: &'a SeqParams,
    pub pps: &'a PicParams,
    pub slice_num: u16,
    /// RefPicList0 and RefPicList1; `None` = "no reference picture".
    pub lists: [&'a [Option<RefEntry<'a>>]; 2],
    /// PicOrderCnt of the current picture.
    pub poc: i32,
    pub scaling: &'a ScalingMatrix,
    pub weights: &'a WeightMode,
}

/// Mutable picture under construction.
pub(crate) struct PictureState<'a> {
    pub frame: &'a mut Frame,
    pub infos: &'a mut [MbInfo],
}

/// Neighbour motion data: `None` = partition not available; intra or
/// list unused -> `Some((-1, [0, 0]))`.
type MotionNeighbour = Option<(i8, [i32; 2])>;

/// Prediction list usage of a partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pred {
    L0,
    L1,
    Bi,
}

impl Pred {
    const fn uses(self, list: usize) -> bool {
        match self {
            Self::L0 => list == 0,
            Self::L1 => list == 1,
            Self::Bi => true,
        }
    }
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

/// Macroblock partitioning of non-8x8 inter types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Partitioning {
    P16x16,
    P16x8,
    P8x16,
}

/// Semantics of `mb_type` (Tables 7-11, 7-13, 7-14).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MbType {
    INxN,
    I16x16 {
        pred: u8,
        cbp: u8,
    },
    Pcm,
    Inter {
        part: Partitioning,
        preds: [Pred; 2],
    },
    Sub8x8 {
        ref0: bool,
    },
    Direct16,
}

fn intra_type(raw: u32) -> Result<MbType, DecodeError> {
    match raw {
        0 => Ok(MbType::INxN),
        1..=24 => {
            let t = raw - 1;
            let pred = u8::try_from(t % 4).map_err(|_| DecodeError::Malformed)?;
            let chroma = u8::try_from((t / 4) % 3).map_err(|_| DecodeError::Malformed)?;
            let luma = if t >= 12 { 15 } else { 0 };
            Ok(MbType::I16x16 {
                pred,
                cbp: luma | (chroma << 4),
            })
        }
        25 => Ok(MbType::Pcm),
        _ => Err(DecodeError::Malformed),
    }
}

impl MbType {
    fn from_raw(kind: SliceKind, raw: u32) -> Result<Self, DecodeError> {
        use Pred::{Bi, L0, L1};
        match kind {
            SliceKind::I => intra_type(raw),
            SliceKind::P => match raw {
                0 => Ok(Self::Inter {
                    part: Partitioning::P16x16,
                    preds: [L0, L0],
                }),
                1 => Ok(Self::Inter {
                    part: Partitioning::P16x8,
                    preds: [L0, L0],
                }),
                2 => Ok(Self::Inter {
                    part: Partitioning::P8x16,
                    preds: [L0, L0],
                }),
                3 => Ok(Self::Sub8x8 { ref0: false }),
                4 => Ok(Self::Sub8x8 { ref0: true }),
                _ => intra_type(raw - 5),
            },
            SliceKind::B => match raw {
                0 => Ok(Self::Direct16),
                1..=3 => Ok(Self::Inter {
                    part: Partitioning::P16x16,
                    preds: [[L0, L1, Bi][raw as usize - 1]; 2],
                }),
                4..=21 => {
                    const PAIRS: [[Pred; 2]; 9] = [
                        [L0, L0],
                        [L1, L1],
                        [L0, L1],
                        [L1, L0],
                        [L0, Bi],
                        [L1, Bi],
                        [Bi, L0],
                        [Bi, L1],
                        [Bi, Bi],
                    ];
                    let k = raw as usize - 4;
                    Ok(Self::Inter {
                        part: if k.is_multiple_of(2) {
                            Partitioning::P16x8
                        } else {
                            Partitioning::P8x16
                        },
                        preds: PAIRS[k / 2],
                    })
                }
                22 => Ok(Self::Sub8x8 { ref0: false }),
                _ => intra_type(raw - 23),
            },
        }
    }
}

/// Sub-macroblock partitioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubShape {
    S8x8,
    S8x4,
    S4x8,
    S4x4,
}

impl SubShape {
    /// (x, y, w, h) of each sub-partition relative to the 8x8 quadrant.
    const fn parts(self) -> &'static [(usize, usize, usize, usize)] {
        match self {
            Self::S8x8 => &[(0, 0, 8, 8)],
            Self::S8x4 => &[(0, 0, 8, 4), (0, 4, 8, 4)],
            Self::S4x8 => &[(0, 0, 4, 8), (4, 0, 4, 8)],
            Self::S4x4 => &[(0, 0, 4, 4), (4, 0, 4, 4), (0, 4, 4, 4), (4, 4, 4, 4)],
        }
    }
}

/// Semantics of `sub_mb_type` (Tables 7-17, 7-18).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SubMb {
    direct: bool,
    pred: Pred,
    shape: SubShape,
}

impl SubMb {
    fn from_raw(kind: SliceKind, raw: u32) -> Result<Self, DecodeError> {
        use Pred::{Bi, L0, L1};
        use SubShape::{S4x4, S4x8, S8x4, S8x8};
        let (direct, pred, shape) = match (kind, raw) {
            (SliceKind::P, 0) => (false, L0, S8x8),
            (SliceKind::P, 1) => (false, L0, S8x4),
            (SliceKind::P, 2) => (false, L0, S4x8),
            (SliceKind::P, 3) => (false, L0, S4x4),
            (SliceKind::B, 0) => (true, Bi, S8x8),
            (SliceKind::B, 1) => (false, L0, S8x8),
            (SliceKind::B, 2) => (false, L1, S8x8),
            (SliceKind::B, 3) => (false, Bi, S8x8),
            (SliceKind::B, 4) => (false, L0, S8x4),
            (SliceKind::B, 5) => (false, L0, S4x8),
            (SliceKind::B, 6) => (false, L1, S8x4),
            (SliceKind::B, 7) => (false, L1, S4x8),
            (SliceKind::B, 8) => (false, Bi, S8x4),
            (SliceKind::B, 9) => (false, Bi, S4x8),
            (SliceKind::B, 10) => (false, L0, S4x4),
            (SliceKind::B, 11) => (false, L1, S4x4),
            (SliceKind::B, 12) => (false, Bi, S4x4),
            _ => return Err(DecodeError::Malformed),
        };
        Ok(Self {
            direct,
            pred,
            shape,
        })
    }
}

/// A residual block handed to the entropy decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidualBlock {
    /// Intra16x16 luma DC (ctxBlockCat 0).
    LumaDc,
    /// Intra16x16 luma AC of a raster 4x4 block (ctxBlockCat 1).
    LumaAc(usize),
    /// Luma 4x4 block, raster index (ctxBlockCat 2).
    Luma4x4(usize),
    /// Chroma DC of Cb (0) or Cr (1) (ctxBlockCat 3).
    ChromaDc(usize),
    /// Chroma AC of component, raster 2x2 block (ctxBlockCat 4).
    ChromaAc(usize, usize),
    /// Luma 8x8 block `b8` (ctxBlockCat 5, CABAC only).
    Luma8x8(usize),
}

impl ResidualBlock {
    pub(crate) const fn max_coeff(self) -> usize {
        match self {
            Self::LumaDc | Self::Luma4x4(_) => 16,
            Self::LumaAc(_) | Self::ChromaAc(..) => 15,
            Self::ChromaDc(_) => 4,
            Self::Luma8x8(_) => 64,
        }
    }
}

/// How each syntax element is coded (CAVLC or CABAC). Methods that need
/// neighbour context receive the macroblock decoder read-only.
pub(crate) trait SyntaxReader {
    fn is_cabac(&self) -> bool;
    /// Raw, slice-relative `mb_type`.
    fn mb_type(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<u32, DecodeError>;
    /// Raw `sub_mb_type`.
    fn sub_mb_type(&mut self, kind: SliceKind) -> Result<u32, DecodeError>;
    fn transform_8x8_flag(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<bool, DecodeError>;
    /// Final Intra4x4/8x8 prediction mode given the predicted mode.
    fn intra_pred_mode(&mut self, predicted: u8) -> Result<u8, DecodeError>;
    fn chroma_pred_mode(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<u8, DecodeError>;
    /// `ref_idx_lX` for the partition whose top-left 4x4 is `raster`.
    fn ref_idx(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        list: usize,
        raster: usize,
        count: u32,
    ) -> Result<i8, DecodeError>;
    /// One `mvd_lX` component for the partition whose top-left 4x4 is `raster`.
    fn mvd(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        list: usize,
        raster: usize,
        component: usize,
    ) -> Result<i32, DecodeError>;
    /// coded_block_pattern; `intra_nxn` selects the Intra_4x4/8x8 mapping.
    fn cbp(&mut self, mb: &MbDecoder<'_, '_, '_>, intra_nxn: bool) -> Result<u8, DecodeError>;
    fn qp_delta(&mut self) -> Result<i32, DecodeError>;
    /// Records that the macroblock carried no mb_qp_delta.
    fn no_qp_delta(&mut self);
    /// Decodes one residual block into `out` (scan order, `max_coeff`
    /// entries) and returns the number of non-zero coefficients.
    fn residual(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        block: ResidualBlock,
        out: &mut [i32; 64],
    ) -> Result<u8, DecodeError>;
    /// Reads the 384 I_PCM samples (alignment included).
    fn pcm(&mut self) -> Result<[u8; 384], DecodeError>;
}

/// Decoder state of one macroblock.
pub(crate) struct MbDecoder<'s, 'p, 'r> {
    pub(crate) ctx: &'s SliceContext<'s>,
    pic: &'p mut PictureState<'r>,
    width_mbs: usize,
    addr: usize,
    mbx: usize,
    mby: usize,
    pub(crate) info: MbInfo,
    /// Per list, 4x4 blocks of the current macroblock whose motion is set.
    done: [u16; 2],
}

/// Decodes `slice_data()` for one slice into the picture.
///
/// Returns the number of macroblocks decoded (including skipped ones).
///
/// # Errors
/// Malformed on syntax errors, overlapping or out-of-picture macroblocks;
/// MissingReference for indices without a reference picture.
pub(crate) fn decode_slice_data(
    reader: &mut BitReader<'_>,
    ctx: &SliceContext<'_>,
    pic: &mut PictureState<'_>,
) -> Result<u32, DecodeError> {
    if ctx.pps.entropy_coding_mode {
        decode_slice_cabac(reader, ctx, pic)
    } else {
        decode_slice_cavlc(reader, ctx, pic)
    }
}

fn decode_slice_cavlc(
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
        if ctx.header.kind != SliceKind::I {
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
        let mut syntax = CavlcReader::new(reader);
        mb.decode_layer(&mut syntax, &mut qp)?;
        mb.commit();
        addr += 1;
        decoded += 1;
        if reader.exhausted() {
            break;
        }
    }
    Ok(decoded)
}

fn decode_slice_cabac(
    reader: &mut BitReader<'_>,
    ctx: &SliceContext<'_>,
    pic: &mut PictureState<'_>,
) -> Result<u32, DecodeError> {
    let total = ctx.sps.mbs();
    let width_mbs = usize::try_from(ctx.sps.width_mbs).map_err(|_| DecodeError::Limit)?;
    // cabac_alignment_one_bit.
    while !reader.byte_aligned() {
        if reader.bit()? != 1 {
            return Err(DecodeError::Malformed);
        }
    }
    let mut syntax = CabacReader::new(reader, ctx.header)?;
    let mut addr = ctx.header.first_mb;
    let mut qp = ctx.header.qp;
    let mut decoded = 0u32;
    loop {
        if addr >= total {
            return Err(DecodeError::Malformed);
        }
        let mut mb = MbDecoder::new(ctx, pic, width_mbs, addr)?;
        if ctx.header.kind != SliceKind::I && syntax.skip_flag(&mb)? {
            mb.decode_skip(qp)?;
            syntax.no_qp_delta();
        } else {
            mb.decode_layer(&mut syntax, &mut qp)?;
        }
        mb.commit();
        addr += 1;
        decoded += 1;
        if syntax.end_of_slice()? {
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
            done: [0; 2],
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
    pub(crate) fn neighbour_mb(&self, dx: isize, dy: isize) -> Option<&MbInfo> {
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

    /// The 4x4 block left of raster block `raster` (in this or the left
    /// macroblock) as (macroblock info, raster index).
    pub(crate) fn left_block(&self, raster: usize) -> Option<(&MbInfo, usize)> {
        if !raster.is_multiple_of(4) {
            Some((&self.info, raster - 1))
        } else {
            self.neighbour_mb(-1, 0).map(|mb| (mb, raster + 3))
        }
    }

    /// The 4x4 block above raster block `raster`.
    pub(crate) fn above_block(&self, raster: usize) -> Option<(&MbInfo, usize)> {
        if raster >= 4 {
            Some((&self.info, raster - 4))
        } else {
            self.neighbour_mb(0, -1).map(|mb| (mb, raster + 12))
        }
    }

    /// The chroma 4x4 block left of 2x2-raster block `blk`.
    pub(crate) fn left_chroma(&self, blk: usize) -> Option<(&MbInfo, usize)> {
        if !blk.is_multiple_of(2) {
            Some((&self.info, blk - 1))
        } else {
            self.neighbour_mb(-1, 0).map(|mb| (mb, blk + 1))
        }
    }

    /// The chroma 4x4 block above 2x2-raster block `blk`.
    pub(crate) fn above_chroma(&self, blk: usize) -> Option<(&MbInfo, usize)> {
        if blk >= 2 {
            Some((&self.info, blk - 2))
        } else {
            self.neighbour_mb(0, -1).map(|mb| (mb, blk + 2))
        }
    }

    /// Whether the current macroblock is intra (for context rules that
    /// depend on it before `info.kind` is final, callers set kind first).
    pub(crate) fn current_is_intra(&self) -> bool {
        self.info.is_intra()
    }

    // ----- macroblock_layer -----

    fn decode_layer<R: SyntaxReader>(
        &mut self,
        r: &mut R,
        qp: &mut i32,
    ) -> Result<(), DecodeError> {
        let raw = r.mb_type(self)?;
        let mb_type = MbType::from_raw(self.ctx.header.kind, raw)?;
        let mut transform_8x8 = false;
        let mut no_sub_below_8x8 = true;
        let cbp;
        match mb_type {
            MbType::Pcm => return self.decode_pcm(r),
            MbType::INxN => {
                self.info.kind = MbKind::Intra4x4;
                if self.ctx.pps.transform_8x8_mode {
                    transform_8x8 = r.transform_8x8_flag(self)?;
                }
                self.info.kind = if transform_8x8 {
                    MbKind::Intra8x8
                } else {
                    MbKind::Intra4x4
                };
                self.info.transform_8x8 = transform_8x8;
                self.read_intra_modes(r, transform_8x8)?;
                self.info.chroma_pred_mode = r.chroma_pred_mode(self)?;
                cbp = r.cbp(self, true)?;
            }
            MbType::I16x16 { pred, cbp: coded } => {
                self.info.kind = MbKind::Intra16x16;
                self.info.intra4x4 = [pred; 16];
                self.info.chroma_pred_mode = r.chroma_pred_mode(self)?;
                cbp = coded;
            }
            MbType::Inter { part, preds } => {
                self.info.kind = MbKind::Inter;
                self.read_inter_partitions(r, part, preds)?;
                cbp = r.cbp(self, false)?;
            }
            MbType::Direct16 => {
                self.info.kind = MbKind::Inter;
                self.info.direct16 = true;
                self.apply_direct(0b1111)?;
                no_sub_below_8x8 = self.ctx.sps.direct_8x8_inference;
                cbp = r.cbp(self, false)?;
            }
            MbType::Sub8x8 { ref0 } => {
                self.info.kind = MbKind::Inter;
                no_sub_below_8x8 = self.read_sub_partitions(r, ref0)?;
                cbp = r.cbp(self, false)?;
            }
        }
        self.info.cbp = cbp;
        let is_i16 = matches!(mb_type, MbType::I16x16 { .. });
        if cbp & 15 != 0
            && self.ctx.pps.transform_8x8_mode
            && !matches!(mb_type, MbType::INxN | MbType::I16x16 { .. })
            && no_sub_below_8x8
        {
            transform_8x8 = r.transform_8x8_flag(self)?;
            self.info.transform_8x8 = transform_8x8;
        }
        let mut residual = Residual::default();
        if cbp != 0 || is_i16 {
            let delta = r.qp_delta()?;
            if !(-26..=25).contains(&delta) {
                return Err(DecodeError::Malformed);
            }
            *qp = (*qp + delta + 52) % 52;
            self.set_qp(*qp)?;
            self.read_residual(r, is_i16, &mut residual)?;
        } else {
            r.no_qp_delta();
            self.set_qp(*qp)?;
        }
        match self.info.kind {
            MbKind::Intra4x4 => self.reconstruct_intra4x4(&residual, *qp)?,
            MbKind::Intra8x8 => self.reconstruct_intra8x8(&residual, *qp)?,
            MbKind::Intra16x16 => self.reconstruct_intra16x16(&residual, *qp)?,
            MbKind::Inter => {
                self.predict_inter()?;
                self.add_luma_residual(&residual, *qp, false);
            }
            MbKind::Pcm => {}
        }
        if self.info.is_intra() {
            self.predict_chroma_intra()?;
        }
        self.add_chroma_residual(&residual, *qp);
        Ok(())
    }

    fn set_qp(&mut self, qp: i32) -> Result<(), DecodeError> {
        self.info.qp = u8::try_from(qp).map_err(|_| DecodeError::Malformed)?;
        Ok(())
    }

    fn decode_pcm<R: SyntaxReader>(&mut self, r: &mut R) -> Result<(), DecodeError> {
        let samples = r.pcm()?;
        r.no_qp_delta();
        self.info.kind = MbKind::Pcm;
        // The running QP_Y is unchanged (mb_qp_delta absent, inferred 0);
        // the deblocking filter treats an I_PCM macroblock as qP = 0.
        self.info.qp = 0;
        self.info.nz = [16; 16];
        self.info.nz_chroma = [[16; 4]; 2];
        self.info.cbp = 0x2F;
        self.info.coded_dc = 0b111;
        let stride = self.pic.frame.width;
        for y in 0..16 {
            let start = (self.mby * 16 + y) * stride + self.mbx * 16;
            let row = self
                .pic
                .frame
                .y
                .get_mut(start..start + 16)
                .ok_or(DecodeError::Malformed)?;
            row.copy_from_slice(&samples[y * 16..y * 16 + 16]);
        }
        let cstride = self.pic.frame.chroma_width();
        for component in 0..2 {
            let plane = if component == 0 {
                &mut self.pic.frame.cb
            } else {
                &mut self.pic.frame.cr
            };
            for y in 0..8 {
                let start = (self.mby * 8 + y) * cstride + self.mbx * 8;
                let source = 256 + component * 64 + y * 8;
                plane
                    .get_mut(start..start + 8)
                    .ok_or(DecodeError::Malformed)?
                    .copy_from_slice(&samples[source..source + 8]);
            }
        }
        Ok(())
    }

    // ----- intra prediction modes -----

    /// predIntra4x4PredMode / predIntra8x8PredMode for the 4x4 block at
    /// `raster` (for 8x8 blocks, the top-left 4x4 of the 8x8).
    fn predicted_intra_mode(&self, raster: usize) -> u8 {
        let constrained = self.ctx.pps.constrained_intra_pred;
        let mode = |n: Option<(&MbInfo, usize)>| -> Option<u8> {
            let (mb, blk) = n?;
            match mb.kind {
                MbKind::Intra4x4 | MbKind::Intra8x8 => Some(mb.intra4x4[blk]),
                MbKind::Inter if constrained => None,
                _ => Some(2),
            }
        };
        match (
            mode(self.left_block(raster)),
            mode(self.above_block(raster)),
        ) {
            (Some(a), Some(b)) => a.min(b),
            _ => 2,
        }
    }

    fn read_intra_modes<R: SyntaxReader>(
        &mut self,
        r: &mut R,
        transform_8x8: bool,
    ) -> Result<(), DecodeError> {
        if transform_8x8 {
            for b8 in 0..4 {
                let raster = (b8 / 2) * 8 + (b8 % 2) * 2;
                let predicted = self.predicted_intra_mode(raster);
                let mode = r.intra_pred_mode(predicted)?;
                for k in [raster, raster + 1, raster + 4, raster + 5] {
                    self.info.intra4x4[k] = mode;
                }
            }
        } else {
            for &raster in &BLK_TO_RASTER {
                let predicted = self.predicted_intra_mode(raster);
                self.info.intra4x4[raster] = r.intra_pred_mode(predicted)?;
            }
        }
        Ok(())
    }

    // ----- inter partitions -----

    fn read_inter_partitions<R: SyntaxReader>(
        &mut self,
        r: &mut R,
        part: Partitioning,
        preds: [Pred; 2],
    ) -> Result<(), DecodeError> {
        let parts: &[(usize, usize, usize, usize, Shape)] = match part {
            Partitioning::P16x16 => &[(0, 0, 16, 16, Shape::Other)],
            Partitioning::P16x8 => &[
                (0, 0, 16, 8, Shape::P16x8Top),
                (0, 8, 16, 8, Shape::P16x8Bottom),
            ],
            Partitioning::P8x16 => &[
                (0, 0, 8, 16, Shape::P8x16Left),
                (8, 0, 8, 16, Shape::P8x16Right),
            ],
        };
        let counts = self.ref_counts();
        let mut refs = [[-1i8; 2]; 2];
        for list in 0..2 {
            for (index, &(x, y, w, h, _)) in parts.iter().enumerate() {
                if !preds[index].uses(list) {
                    continue;
                }
                let raster = (y / 4) * 4 + x / 4;
                let value = if counts[list] > 1 {
                    r.ref_idx(self, list, raster, counts[list])?
                } else {
                    0
                };
                refs[list][index] = value;
                self.store_ref(list, x, y, w, h, value)?;
            }
        }
        for (list, list_refs) in refs.iter().enumerate() {
            for (index, &(x, y, w, h, shape)) in parts.iter().enumerate() {
                if !preds[index].uses(list) {
                    self.set_motion(list, (x, y, w, h), -1, [0, 0])?;
                    continue;
                }
                let raster = (y / 4) * 4 + x / 4;
                let mvd = [r.mvd(self, list, raster, 0)?, r.mvd(self, list, raster, 1)?];
                self.store_mvd(list, x, y, w, h, mvd);
                let mvp = self.predict_mv(list, x, y, w, list_refs[index], shape);
                let mv = [mvp[0] + mvd[0], mvp[1] + mvd[1]];
                self.set_motion(list, (x, y, w, h), list_refs[index], mv)?;
            }
        }
        Ok(())
    }

    /// Returns `noSubMbPartSizeLessThan8x8Flag`.
    fn read_sub_partitions<R: SyntaxReader>(
        &mut self,
        r: &mut R,
        ref0: bool,
    ) -> Result<bool, DecodeError> {
        let kind = self.ctx.header.kind;
        let mut subs = [SubMb {
            direct: false,
            pred: Pred::L0,
            shape: SubShape::S8x8,
        }; 4];
        let mut no_sub_below_8x8 = true;
        let mut direct_mask = 0u8;
        for (b8, sub) in subs.iter_mut().enumerate() {
            *sub = SubMb::from_raw(kind, r.sub_mb_type(kind)?)?;
            if sub.direct {
                direct_mask |= 1 << b8;
                if !self.ctx.sps.direct_8x8_inference {
                    no_sub_below_8x8 = false;
                }
            } else if sub.shape != SubShape::S8x8 {
                no_sub_below_8x8 = false;
            }
        }
        let direct = if direct_mask != 0 {
            self.info.direct8 = direct_mask;
            Some(self.derive_direct()?)
        } else {
            None
        };
        if let Some(direct) = &direct {
            for b8 in 0..4 {
                if direct_mask & (1 << b8) != 0 {
                    for list in 0..2 {
                        self.info.ref_idx[list][b8] = direct.ref_idx[list][b8];
                    }
                }
            }
        }
        let counts = self.ref_counts();
        let mut refs = [[-1i8; 4]; 2];
        for list in 0..2 {
            for (b8, sub) in subs.iter().enumerate() {
                if sub.direct || !sub.pred.uses(list) {
                    continue;
                }
                let (x, y) = ((b8 % 2) * 8, (b8 / 2) * 8);
                let value = if counts[list] > 1 && !ref0 {
                    r.ref_idx(self, list, (y / 4) * 4 + x / 4, counts[list])?
                } else {
                    0
                };
                refs[list][b8] = value;
                self.store_ref(list, x, y, 8, 8, value)?;
            }
        }
        for (list, list_refs) in refs.iter().enumerate() {
            for (b8, sub) in subs.iter().enumerate() {
                let (ox, oy) = ((b8 % 2) * 8, (b8 / 2) * 8);
                if sub.direct {
                    if let Some(direct) = &direct {
                        self.apply_direct_quadrant(direct, list, b8)?;
                    }
                    continue;
                }
                if !sub.pred.uses(list) {
                    self.set_motion(list, (ox, oy, 8, 8), -1, [0, 0])?;
                    continue;
                }
                for &(x, y, w, h) in sub.shape.parts() {
                    let (x, y) = (ox + x, oy + y);
                    let raster = (y / 4) * 4 + x / 4;
                    let mvd = [r.mvd(self, list, raster, 0)?, r.mvd(self, list, raster, 1)?];
                    self.store_mvd(list, x, y, w, h, mvd);
                    let mvp = self.predict_mv(list, x, y, w, list_refs[b8], Shape::Other);
                    let mv = [mvp[0] + mvd[0], mvp[1] + mvd[1]];
                    self.set_motion(list, (x, y, w, h), list_refs[b8], mv)?;
                }
            }
        }
        Ok(no_sub_below_8x8)
    }

    fn ref_counts(&self) -> [u32; 2] {
        [
            self.ctx.header.num_ref_idx_l0_active,
            self.ctx.header.num_ref_idx_l1_active,
        ]
    }

    fn reference(&self, list: usize, ref_idx: i8) -> Result<&'s RefEntry<'s>, DecodeError> {
        usize::try_from(ref_idx)
            .ok()
            .and_then(|i| self.ctx.lists[list].get(i))
            .and_then(Option::as_ref)
            .ok_or(DecodeError::MissingReference)
    }

    /// Records a partition's reference index (and picture identity) for
    /// every quadrant it covers.
    fn store_ref(
        &mut self,
        list: usize,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        ref_idx: i8,
    ) -> Result<(), DecodeError> {
        let id = if ref_idx >= 0 {
            self.reference(list, ref_idx)?.id
        } else {
            NO_PICTURE
        };
        for by in (y / 8)..((y + h).div_ceil(8)) {
            for bx in (x / 8)..((x + w).div_ceil(8)) {
                self.info.ref_idx[list][by * 2 + bx] = ref_idx;
                self.info.ref_pic[list][by * 2 + bx] = id;
            }
        }
        Ok(())
    }

    fn store_mvd(&mut self, list: usize, x: usize, y: usize, w: usize, h: usize, mvd: [i32; 2]) {
        let abs = mvd.map(|v| u8::try_from(v.unsigned_abs().min(255)).unwrap_or(u8::MAX));
        for by in (y / 4)..((y + h) / 4) {
            for bx in (x / 4)..((x + w) / 4) {
                self.info.mvd[list][by * 4 + bx] = abs;
            }
        }
    }

    /// Stores a partition's final motion for one list and marks it decoded.
    fn set_motion(
        &mut self,
        list: usize,
        (x, y, w, h): (usize, usize, usize, usize),
        ref_idx: i8,
        mv: [i32; 2],
    ) -> Result<(), DecodeError> {
        if !MV_X_RANGE.contains(&mv[0]) || !MV_Y_RANGE.contains(&mv[1]) {
            return Err(DecodeError::Malformed);
        }
        let packed = [
            i16::try_from(mv[0]).map_err(|_| DecodeError::Malformed)?,
            i16::try_from(mv[1]).map_err(|_| DecodeError::Malformed)?,
        ];
        self.store_ref(list, x, y, w, h, ref_idx)?;
        for by in (y / 4)..((y + h) / 4) {
            for bx in (x / 4)..((x + w) / 4) {
                let raster = by * 4 + bx;
                self.info.mv[list][raster] = packed;
                self.done[list] |= 1 << raster;
            }
        }
        Ok(())
    }

    /// Motion data of the 4x4 block covering MB-relative luma (x, y).
    fn motion_neighbour(&self, list: usize, x: isize, y: isize) -> MotionNeighbour {
        let from_mb = |mb: &MbInfo, raster: usize| -> (i8, [i32; 2]) {
            if mb.is_intra() {
                (-1, [0, 0])
            } else {
                let mv = mb.mv[list][raster];
                (
                    mb.ref_idx[list][b8_of(raster)],
                    [i32::from(mv[0]), i32::from(mv[1])],
                )
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
                (self.done[list] & (1 << raster) != 0).then(|| from_mb(&self.info, raster))
            }
        }
    }

    /// Luma motion-vector prediction (clause 8.4.1.3).
    fn predict_mv(
        &self,
        list: usize,
        x: usize,
        y: usize,
        w: usize,
        ref_idx: i8,
        shape: Shape,
    ) -> [i32; 2] {
        let (xi, yi, wi) = (as_isize(x), as_isize(y), as_isize(w));
        let a = self.motion_neighbour(list, xi - 1, yi);
        let b = self.motion_neighbour(list, xi, yi - 1);
        let c = self
            .motion_neighbour(list, xi + wi, yi - 1)
            .or_else(|| self.motion_neighbour(list, xi - 1, yi - 1));
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

    // ----- skipped macroblocks and direct prediction -----

    fn decode_skip(&mut self, qp: i32) -> Result<(), DecodeError> {
        self.info.kind = MbKind::Inter;
        self.info.skip = true;
        self.set_qp(qp)?;
        if self.ctx.header.kind == SliceKind::B {
            self.info.direct16 = true;
            self.apply_direct(0b1111)?;
        } else {
            // 8.4.1.1: zero vector when A or B is unavailable or either has
            // refIdx 0 with a zero vector; otherwise 16x16 median prediction.
            let a = self.motion_neighbour(0, -1, 0);
            let b = self.motion_neighbour(0, 0, -1);
            let zero = match (a, b) {
                (Some(a), Some(b)) => (a.0 == 0 && a.1 == [0, 0]) || (b.0 == 0 && b.1 == [0, 0]),
                _ => true,
            };
            let mv = if zero {
                [0, 0]
            } else {
                self.predict_mv(0, 0, 0, 16, 0, Shape::Other)
            };
            self.set_motion(0, (0, 0, 16, 16), 0, mv)?;
            self.set_motion(1, (0, 0, 16, 16), -1, [0, 0])?;
        }
        self.predict_inter()
    }

    /// Direct prediction of the quadrants in `mask` (B_Skip,
    /// B_Direct_16x16).
    fn apply_direct(&mut self, mask: u8) -> Result<(), DecodeError> {
        self.info.direct8 |= mask;
        let direct = self.derive_direct()?;
        for list in 0..2 {
            for b8 in 0..4 {
                if mask & (1 << b8) != 0 {
                    self.apply_direct_quadrant(&direct, list, b8)?;
                }
            }
        }
        Ok(())
    }

    fn apply_direct_quadrant(
        &mut self,
        direct: &DirectMotion,
        list: usize,
        b8: usize,
    ) -> Result<(), DecodeError> {
        let (ox, oy) = ((b8 % 2) * 8, (b8 / 2) * 8);
        let ref_idx = direct.ref_idx[list][b8];
        for (k, &(x, y)) in [(0, 0), (4, 0), (0, 4), (4, 4)].iter().enumerate() {
            let (x, y) = (ox + x, oy + y);
            let mv = if ref_idx < 0 {
                [0, 0]
            } else {
                direct.mv[list][b8][k]
            };
            self.set_motion(list, (x, y, 4, 4), ref_idx, mv)?;
        }
        Ok(())
    }

    /// Direct-mode motion (clause 8.4.1.2) for all four quadrants.
    fn derive_direct(&self) -> Result<DirectMotion, DecodeError> {
        let col = self.ctx.lists[1]
            .first()
            .and_then(Option::as_ref)
            .ok_or(DecodeError::MissingReference)?;
        let col_mb = col
            .motion
            .get(self.addr)
            .ok_or(DecodeError::MissingReference)?;
        let inference = self.ctx.sps.direct_8x8_inference;
        // Co-located motion per quadrant and 4x4: (refIdxCol, mvCol, refPicCol).
        let colocated = |b8: usize, k: usize| -> (i8, [i32; 2], u64) {
            let raster = if inference {
                [0, 3, 12, 15][b8]
            } else {
                (b8 / 2) * 8 + (b8 % 2) * 2 + [0, 1, 4, 5][k]
            };
            if col_mb.is_intra() {
                return (-1, [0, 0], NO_PICTURE);
            }
            let cb8 = b8_of(raster);
            let list = usize::from(col_mb.ref_idx[0][cb8] < 0);
            let mv = col_mb.mv[list][raster];
            (
                col_mb.ref_idx[list][cb8],
                [i32::from(mv[0]), i32::from(mv[1])],
                col_mb.ref_pic[list][cb8],
            )
        };
        let mut out = DirectMotion {
            ref_idx: [[-1; 4]; 2],
            mv: [[[[0; 2]; 4]; 4]; 2],
        };
        if self.ctx.header.direct_spatial {
            // 8.4.1.2.2: reference indices from the neighbours of the MB.
            let mut refs = [-1i8; 2];
            for (list, slot) in refs.iter_mut().enumerate() {
                let a = self.motion_neighbour(list, -1, 0).map_or(-1, |n| n.0);
                let b = self.motion_neighbour(list, 0, -1).map_or(-1, |n| n.0);
                let c = self
                    .motion_neighbour(list, 16, -1)
                    .or_else(|| self.motion_neighbour(list, -1, -1))
                    .map_or(-1, |n| n.0);
                *slot = min_positive(a, min_positive(b, c));
            }
            let zero_prediction = refs[0] < 0 && refs[1] < 0;
            if zero_prediction {
                refs = [0, 0];
            }
            let mut mvp = [[0i32; 2]; 2];
            for list in 0..2 {
                if !zero_prediction && refs[list] >= 0 {
                    mvp[list] = self.predict_mv(list, 0, 0, 16, refs[list], Shape::Other);
                }
            }
            let l1_short = !col.long_term;
            for b8 in 0..4 {
                for list in 0..2 {
                    out.ref_idx[list][b8] = refs[list];
                }
                // colZeroFlag per 4x4 of the quadrant.
                let col_zero: [bool; 4] = std::array::from_fn(|k| {
                    let (ref_col, mv_col, _) = colocated(b8, k);
                    l1_short
                        && ref_col == 0
                        && (-1..=1).contains(&mv_col[0])
                        && (-1..=1).contains(&mv_col[1])
                });
                for (list, (&ref_idx, &predicted)) in refs.iter().zip(&mvp).enumerate() {
                    out.mv[list][b8] = col_zero.map(|zero| {
                        if zero_prediction || ref_idx < 0 || (ref_idx == 0 && zero) {
                            [0, 0]
                        } else {
                            predicted
                        }
                    });
                }
            }
        } else {
            // 8.4.1.2.3: temporal direct.
            let pic1 = col;
            for b8 in 0..4 {
                for k in 0..4 {
                    let (ref_col, mv_col, pic_col) = colocated(b8, k);
                    let ref_l0 = if ref_col < 0 {
                        0
                    } else {
                        let index = self.ctx.lists[0]
                            .iter()
                            .position(|entry| entry.as_ref().is_some_and(|e| e.id == pic_col))
                            .ok_or(DecodeError::MissingReference)?;
                        i8::try_from(index).map_err(|_| DecodeError::Malformed)?
                    };
                    let pic0 = self.reference(0, ref_l0)?;
                    let td = pic1.poc.saturating_sub(pic0.poc).clamp(-128, 127);
                    let (mv0, mv1) = if pic0.long_term || td == 0 {
                        (mv_col, [0, 0])
                    } else {
                        let tb = self.ctx.poc.saturating_sub(pic0.poc).clamp(-128, 127);
                        let tx = (16_384 + (td / 2).abs()) / td;
                        let scale = ((tb * tx + 32) >> 6).clamp(-1024, 1023);
                        let mv0 = mv_col.map(|v| (scale * v + 128) >> 8);
                        (mv0, [mv0[0] - mv_col[0], mv0[1] - mv_col[1]])
                    };
                    // Reference indices are per quadrant; with direct 8x8
                    // inference (or a uniform co-located quadrant) every
                    // 4x4 agrees. A quadrant whose 4x4 blocks map to
                    // different list-0 indices cannot be represented.
                    if k > 0 && out.ref_idx[0][b8] != ref_l0 {
                        return Err(DecodeError::Malformed);
                    }
                    out.ref_idx[0][b8] = ref_l0;
                    out.ref_idx[1][b8] = 0;
                    out.mv[0][b8][k] = mv0;
                    out.mv[1][b8][k] = mv1;
                }
            }
        }
        Ok(out)
    }

    // ----- residual syntax -----

    fn read_residual<R: SyntaxReader>(
        &mut self,
        r: &mut R,
        is_i16: bool,
        residual: &mut Residual,
    ) -> Result<(), DecodeError> {
        let cbp = self.info.cbp;
        let mut scan = [0i32; 64];
        if is_i16 {
            let count = r.residual(self, ResidualBlock::LumaDc, &mut scan)?;
            if count > 0 {
                self.info.coded_dc |= 1;
            }
            for (k, &value) in scan.iter().take(16).enumerate() {
                residual.luma_dc[ZIGZAG_4X4[k]] = value;
            }
        }
        for b8 in 0..4 {
            if cbp & (1 << b8) == 0 {
                continue;
            }
            if self.info.transform_8x8 {
                residual.coded8[b8] = true;
                if r.is_cabac() {
                    let count = r.residual(self, ResidualBlock::Luma8x8(b8), &mut scan)?;
                    let base = (b8 / 2) * 8 + (b8 % 2) * 2;
                    for k in [base, base + 1, base + 4, base + 5] {
                        self.info.nz[k] = count;
                    }
                    for (k, &value) in scan.iter().enumerate() {
                        residual.luma8[b8][ZIGZAG_8X8[k]] = value;
                    }
                } else {
                    for i4 in 0..4 {
                        let raster = BLK_TO_RASTER[b8 * 4 + i4];
                        let count = r.residual(self, ResidualBlock::Luma4x4(raster), &mut scan)?;
                        self.info.nz[raster] = count;
                        for (k, &value) in scan.iter().take(16).enumerate() {
                            residual.luma8[b8][ZIGZAG_8X8[4 * k + i4]] = value;
                        }
                    }
                }
            } else {
                for i4 in 0..4 {
                    let raster = BLK_TO_RASTER[b8 * 4 + i4];
                    if is_i16 {
                        let count = r.residual(self, ResidualBlock::LumaAc(raster), &mut scan)?;
                        self.info.nz[raster] = count;
                        for (k, &value) in scan.iter().take(15).enumerate() {
                            residual.luma[raster][ZIGZAG_4X4[k + 1]] = value;
                        }
                    } else {
                        let count = r.residual(self, ResidualBlock::Luma4x4(raster), &mut scan)?;
                        self.info.nz[raster] = count;
                        for (k, &value) in scan.iter().take(16).enumerate() {
                            residual.luma[raster][ZIGZAG_4X4[k]] = value;
                        }
                    }
                }
            }
        }
        let cbp_chroma = cbp >> 4;
        if cbp_chroma > 2 {
            return Err(DecodeError::Malformed);
        }
        if cbp_chroma != 0 {
            for component in 0..2 {
                let count = r.residual(self, ResidualBlock::ChromaDc(component), &mut scan)?;
                if count > 0 {
                    self.info.coded_dc |= 2 << component;
                }
                residual.chroma_dc[component].copy_from_slice(&scan[..4]);
            }
        }
        if cbp_chroma == 2 {
            for component in 0..2 {
                for blk in 0..4 {
                    let count =
                        r.residual(self, ResidualBlock::ChromaAc(component, blk), &mut scan)?;
                    self.info.nz_chroma[component][blk] = count;
                    for (k, &value) in scan.iter().take(15).enumerate() {
                        residual.chroma_ac[component][blk][ZIGZAG_4X4[k + 1]] = value;
                    }
                }
            }
        }
        Ok(())
    }

    // ----- intra reconstruction -----

    fn luma_origin(&self, raster: usize) -> (usize, usize) {
        (
            self.mbx * 16 + (raster % 4) * 4,
            self.mby * 16 + (raster / 4) * 4,
        )
    }

    fn write_luma(&mut self, px: usize, py: usize, size: usize, pred: &[u8]) {
        let stride = self.pic.frame.width;
        for y in 0..size {
            let start = (py + y) * stride + px;
            if let (Some(row), Some(source)) = (
                self.pic.frame.y.get_mut(start..start + size),
                pred.get(y * size..y * size + size),
            ) {
                row.copy_from_slice(source);
            }
        }
    }

    fn reconstruct_intra4x4(&mut self, residual: &Residual, qp: i32) -> Result<(), DecodeError> {
        let weights = self.ctx.scaling.list4x4[0];
        for &raster in &BLK_TO_RASTER {
            let neighbours = self.intra4x4_neighbours(raster);
            let pred = intra::predict_4x4(self.info.intra4x4[raster], &neighbours)?;
            let (px, py) = self.luma_origin(raster);
            self.write_luma(px, py, 4, &pred);
            if self.info.nz[raster] != 0 {
                let mut block = residual.luma[raster];
                dequantize_4x4_scaled(&mut block, qp, &weights, false);
                let out = inverse_transform_4x4(&block);
                add_residual(&mut self.pic.frame.y, self.pic.frame.width, px, py, &out);
            }
        }
        Ok(())
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

    fn reconstruct_intra8x8(&mut self, residual: &Residual, qp: i32) -> Result<(), DecodeError> {
        let weights = self.ctx.scaling.list8x8[0];
        for b8 in 0..4 {
            let raster = (b8 / 2) * 8 + (b8 % 2) * 2;
            let neighbours = self.intra8x8_neighbours(b8);
            let pred = intra::predict_8x8(self.info.intra4x4[raster], &neighbours)?;
            let (px, py) = self.luma_origin(raster);
            self.write_luma(px, py, 8, &pred);
            if residual.coded8[b8] {
                let mut block = residual.luma8[b8];
                dequantize_8x8(&mut block, qp, &weights);
                let out = inverse_transform_8x8(&block);
                add_residual_8x8(&mut self.pic.frame.y, self.pic.frame.width, px, py, &out);
            }
        }
        Ok(())
    }

    fn intra8x8_neighbours(&self, b8: usize) -> Neighbors8x8 {
        let (x8, y8) = (b8 % 2, b8 / 2);
        let (px, py) = (self.mbx * 16 + x8 * 8, self.mby * 16 + y8 * 8);
        let stride = self.pic.frame.width;
        let plane = &self.pic.frame.y;
        let top_ok = y8 > 0 || self.intra_available(0, -1);
        let left_ok = x8 > 0 || self.intra_available(-1, 0);
        let corner_ok = match (x8 > 0, y8 > 0) {
            (true, true) => true,
            (false, true) => self.intra_available(-1, 0),
            (true, false) => self.intra_available(0, -1),
            (false, false) => self.intra_available(-1, -1),
        };
        let top_right_ok = match b8 {
            0 => self.intra_available(0, -1),
            1 => self.intra_available(1, -1),
            2 => true,
            _ => false,
        };
        let sample = |x: usize, y: usize| plane.get(y * stride + x).copied().unwrap_or(0);
        let top = top_ok.then(|| {
            let mut t = [0u8; 16];
            for (i, value) in t.iter_mut().enumerate().take(8) {
                *value = sample(px + i, py - 1);
            }
            for i in 8..16 {
                t[i] = if top_right_ok {
                    sample(px + i, py - 1)
                } else {
                    t[7]
                };
            }
            t
        });
        let left = left_ok.then(|| std::array::from_fn(|i| sample(px - 1, py + i)));
        let top_left = corner_ok.then(|| sample(px - 1, py - 1));
        Neighbors8x8 {
            top,
            left,
            top_left,
        }
    }

    fn reconstruct_intra16x16(&mut self, residual: &Residual, qp: i32) -> Result<(), DecodeError> {
        let neighbours = self.intra16x16_neighbours();
        let pred = intra::predict_16x16(self.info.intra4x4[0], &neighbours)?;
        let (px, py) = (self.mbx * 16, self.mby * 16);
        self.write_luma(px, py, 16, &pred);
        let weights = self.ctx.scaling.list4x4[0];
        let dc = luma_dc_inverse_scaled(&residual.luma_dc, qp, weights[0]);
        let stride = self.pic.frame.width;
        for raster in 0..16 {
            let mut block = residual.luma[raster];
            dequantize_4x4_scaled(&mut block, qp, &weights, true);
            block[0] = dc[raster];
            if block.iter().all(|&c| c == 0) {
                continue;
            }
            let out = inverse_transform_4x4(&block);
            let (px, py) = self.luma_origin(raster);
            add_residual(&mut self.pic.frame.y, stride, px, py, &out);
        }
        Ok(())
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

    fn predict_chroma_intra(&mut self) -> Result<(), DecodeError> {
        let cstride = self.pic.frame.chroma_width();
        let (px, py) = (self.mbx * 8, self.mby * 8);
        let top_ok = self.intra_available(0, -1);
        let left_ok = self.intra_available(-1, 0);
        let corner_ok = self.intra_available(-1, -1);
        let mode = self.info.chroma_pred_mode;
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
        Ok(())
    }

    // ----- residual reconstruction -----

    fn add_luma_residual(&mut self, residual: &Residual, qp: i32, intra: bool) {
        let stride = self.pic.frame.width;
        if self.info.transform_8x8 {
            let weights = self.ctx.scaling.list8x8[usize::from(!intra)];
            for b8 in 0..4 {
                if !residual.coded8[b8] {
                    continue;
                }
                let mut block = residual.luma8[b8];
                dequantize_8x8(&mut block, qp, &weights);
                let out = inverse_transform_8x8(&block);
                let (px, py) = self.luma_origin((b8 / 2) * 8 + (b8 % 2) * 2);
                add_residual_8x8(&mut self.pic.frame.y, stride, px, py, &out);
            }
            return;
        }
        let weights = self.ctx.scaling.list4x4[if intra { 0 } else { 3 }];
        for raster in 0..16 {
            if self.info.nz[raster] == 0 {
                continue;
            }
            let mut block = residual.luma[raster];
            dequantize_4x4_scaled(&mut block, qp, &weights, false);
            let out = inverse_transform_4x4(&block);
            let (px, py) = self.luma_origin(raster);
            add_residual(&mut self.pic.frame.y, stride, px, py, &out);
        }
    }

    fn add_chroma_residual(&mut self, residual: &Residual, qp: i32) {
        let cstride = self.pic.frame.chroma_width();
        let (px, py) = (self.mbx * 8, self.mby * 8);
        let intra = self.info.is_intra();
        for component in 0..2 {
            let offset = if component == 0 {
                self.ctx.pps.chroma_qp_index_offset
            } else {
                self.ctx.pps.second_chroma_qp_index_offset
            };
            let weights = self.ctx.scaling.list4x4[1 + component + if intra { 0 } else { 3 }];
            let qpc = chroma_qp(qp, offset);
            let dc = chroma_dc_inverse_scaled(&residual.chroma_dc[component], qpc, weights[0]);
            let plane = if component == 0 {
                &mut self.pic.frame.cb
            } else {
                &mut self.pic.frame.cr
            };
            for blk in 0..4 {
                let mut block = residual.chroma_ac[component][blk];
                dequantize_4x4_scaled(&mut block, qpc, &weights, true);
                block[0] = dc[blk];
                if block.iter().all(|&c| c == 0) {
                    continue;
                }
                let out = inverse_transform_4x4(&block);
                add_residual(plane, cstride, px + (blk % 2) * 4, py + (blk / 2) * 4, &out);
            }
        }
    }

    // ----- inter prediction -----

    /// Writes the inter prediction of the whole macroblock from its stored
    /// motion, 4x4 block by 4x4 block (sample values depend only on the
    /// position, vector and reference, so the block granularity is exact).
    fn predict_inter(&mut self) -> Result<(), DecodeError> {
        for raster in 0..16 {
            let b8 = b8_of(raster);
            let mut preds: [Option<inter::BlockPrediction>; 2] = [None, None];
            let mut refs = [-1i8; 2];
            for (list, slot) in preds.iter_mut().enumerate() {
                let ref_idx = self.info.ref_idx[list][b8];
                if ref_idx < 0 {
                    continue;
                }
                refs[list] = ref_idx;
                let reference = self.reference(list, ref_idx)?;
                let mv = self.info.mv[list][raster];
                let (x, y) = self.luma_origin(raster);
                *slot = Some(inter::predict_4x4(
                    reference.frame,
                    x,
                    y,
                    [i32::from(mv[0]), i32::from(mv[1])],
                ));
            }
            let combined = match (&preds[0], &preds[1]) {
                (Some(p0), Some(p1)) => self.weigh_bi(p0, p1, refs),
                (Some(p), None) => self.weigh_single(p, 0, refs[0]),
                (None, Some(p)) => self.weigh_single(p, 1, refs[1]),
                (None, None) => return Err(DecodeError::Malformed),
            };
            let (x, y) = self.luma_origin(raster);
            inter::write_prediction(self.pic.frame, x, y, &combined);
        }
        Ok(())
    }

    fn weigh_single(
        &self,
        p: &inter::BlockPrediction,
        list: usize,
        ref_idx: i8,
    ) -> inter::BlockPrediction {
        match self.ctx.weights {
            WeightMode::Explicit(table) => {
                let entry = usize::try_from(ref_idx)
                    .ok()
                    .and_then(|i| table.lists[list].get(i));
                match entry {
                    Some(entry) => inter::weight_single(
                        p,
                        [entry.luma, entry.chroma[0], entry.chroma[1]],
                        [table.luma_log2_denom, table.chroma_log2_denom],
                    ),
                    None => *p,
                }
            }
            _ => *p,
        }
    }

    fn weigh_bi(
        &self,
        p0: &inter::BlockPrediction,
        p1: &inter::BlockPrediction,
        refs: [i8; 2],
    ) -> inter::BlockPrediction {
        let r0 = usize::try_from(refs[0]).unwrap_or(0);
        let r1 = usize::try_from(refs[1]).unwrap_or(0);
        match self.ctx.weights {
            WeightMode::Default => inter::average(p0, p1),
            WeightMode::Explicit(table) => match (table.lists[0].get(r0), table.lists[1].get(r1)) {
                (Some(e0), Some(e1)) => inter::weight_bi(
                    p0,
                    p1,
                    [
                        (e0.luma, e1.luma),
                        (e0.chroma[0], e1.chroma[0]),
                        (e0.chroma[1], e1.chroma[1]),
                    ],
                    [table.luma_log2_denom, table.chroma_log2_denom],
                ),
                _ => inter::average(p0, p1),
            },
            WeightMode::Implicit { weights, len_l1 } => {
                let (w0, w1) = weights.get(r0 * len_l1 + r1).copied().unwrap_or((32, 32));
                inter::weight_bi(p0, p1, [((w0, 0), (w1, 0)); 3], [5, 5])
            }
        }
    }
}

/// Direct-mode motion of the four quadrants: reference index per list per
/// quadrant, vectors per list per quadrant per 4x4 (in quadrant raster).
struct DirectMotion {
    ref_idx: [[i8; 4]; 2],
    mv: [[[[i32; 2]; 4]; 4]; 2],
}

/// Parsed residual coefficients of one macroblock (raster order).
struct Residual {
    luma_dc: [i32; 16],
    luma: [[i32; 16]; 16],
    luma8: [[i32; 64]; 4],
    coded8: [bool; 4],
    chroma_dc: [[i32; 4]; 2],
    chroma_ac: [[[i32; 16]; 4]; 2],
}

impl Default for Residual {
    fn default() -> Self {
        Self {
            luma_dc: [0; 16],
            luma: [[0; 16]; 16],
            luma8: [[0; 64]; 4],
            coded8: [false; 4],
            chroma_dc: [[0; 4]; 2],
            chroma_ac: [[[0; 16]; 4]; 2],
        }
    }
}

fn as_isize(value: usize) -> isize {
    isize::try_from(value).unwrap_or(isize::MAX)
}

fn median(a: i32, b: i32, c: i32) -> i32 {
    a.max(b).min(a.min(b).max(c))
}

/// `MinPositive(x, y)` (equation 8-186).
const fn min_positive(x: i8, y: i8) -> i8 {
    if x >= 0 && y >= 0 {
        if x < y { x } else { y }
    } else if x > y {
        x
    } else {
        y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_index_maps_are_inverse() {
        for blk in 0..16 {
            assert_eq!(RASTER_TO_BLK[BLK_TO_RASTER[blk]], blk);
        }
        // luma4x4BlkIdx 5 is the top-right 4x4 of the top-right 8x8 block.
        assert_eq!(BLK_TO_RASTER[5], 3);
        assert_eq!(BLK_TO_RASTER[10], 12);
        assert_eq!(b8_of(3), 1);
        assert_eq!(b8_of(12), 2);
        assert_eq!(b8_of(10), 3);
    }

    #[test]
    fn median_of_three() {
        assert_eq!(median(1, 5, 3), 3);
        assert_eq!(median(-4, -4, 9), -4);
        assert_eq!(median(7, 2, 2), 2);
    }

    #[test]
    fn min_positive_follows_8_186() {
        assert_eq!(min_positive(2, 1), 1);
        assert_eq!(min_positive(-1, 3), 3);
        assert_eq!(min_positive(4, -1), 4);
        assert_eq!(min_positive(-1, -1), -1);
        assert_eq!(min_positive(0, 5), 0);
    }

    /// Table 7-14 spot checks: B mb_type 12 is B_L0_Bi_16x8, 17 is
    /// B_Bi_L0_8x16, 22 is B_8x8, 23 is the first intra type (I_NxN).
    #[test]
    fn b_mb_type_table() {
        assert_eq!(
            MbType::from_raw(SliceKind::B, 12).ok(),
            Some(MbType::Inter {
                part: Partitioning::P16x8,
                preds: [Pred::L0, Pred::Bi]
            })
        );
        assert_eq!(
            MbType::from_raw(SliceKind::B, 17).ok(),
            Some(MbType::Inter {
                part: Partitioning::P8x16,
                preds: [Pred::Bi, Pred::L0]
            })
        );
        assert_eq!(
            MbType::from_raw(SliceKind::B, 22).ok(),
            Some(MbType::Sub8x8 { ref0: false })
        );
        assert_eq!(MbType::from_raw(SliceKind::B, 23).ok(), Some(MbType::INxN));
        assert_eq!(MbType::from_raw(SliceKind::B, 48).ok(), Some(MbType::Pcm));
        assert!(MbType::from_raw(SliceKind::B, 49).is_err());
        assert_eq!(
            SubMb::from_raw(SliceKind::B, 9).ok(),
            Some(SubMb {
                direct: false,
                pred: Pred::Bi,
                shape: SubShape::S4x8
            })
        );
        assert!(SubMb::from_raw(SliceKind::P, 4).is_err());
    }
}
