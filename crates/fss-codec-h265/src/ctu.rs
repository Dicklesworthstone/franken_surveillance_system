//! Slice segment data (ITU-T H.265 clauses 7.3.8.1..7.3.8.12): the CTU
//! loop with wavefront context synchronisation, the coding quadtree,
//! coding units, PCM samples, the transform tree and transform units, and
//! the reconstruction of intra-coded blocks.

use crate::DecodeError;
use crate::bits::BitReader;
use crate::cabac::{Contexts, SliceCabac, init_contexts};
use crate::cabac_tables::{
    ABS_MVD_GREATER0_FLAG, ABS_MVD_GREATER1_FLAG, CBF_CB_CR, CBF_LUMA, CU_QP_DELTA,
    CU_TRANSQUANT_BYPASS_FLAG, INTER_PRED_IDC, INTRA_CHROMA_PRED_MODE, MERGE_FLAG, MERGE_IDX,
    MVP_LX_FLAG, NO_RESIDUAL_DATA_FLAG, PART_MODE, PRED_MODE_FLAG, PREV_INTRA_LUMA_PRED_FLAG,
    REF_IDX_L0, SKIP_FLAG, SPLIT_CODING_UNIT_FLAG, SPLIT_TRANSFORM_FLAG,
};
use crate::inter::{self, Block, ColMv, ColPic, MvContext, MvField, PartMode, PbGeometry, RefList};
use crate::intra;
use crate::params::{Pps, ScalingList, Sps};
use crate::picture::Frame;
use crate::residual::{ResidualParams, Scans, residual_coding};
use crate::slice::{SliceHeader, SliceType};
use crate::tables::chroma_qp;
use crate::transform::{inverse_transform, scale, transform_skip};

/// Flat scaling factors (`m[x][y] = 16`).
static FLAT: [u8; 1024] = [16; 1024];

/// Per-4x4 (minimum transform block) decoding state of the current picture.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BlockInfo {
    /// Slice tag (1-based) once the block is reconstructed; 0 before.
    pub slice: u16,
    /// `CuPredMode == MODE_INTRA`.
    pub intra: bool,
    /// Luma intra mode for most-probable-mode derivation (`INTRA_DC` for
    /// non-intra and PCM blocks).
    pub ipm: u8,
    /// `CtDepth`.
    pub ct_depth: u8,
    /// `QpY` of the covering coding unit.
    pub qp_y: i8,
    /// `cu_skip_flag`.
    pub skip: bool,
    /// Motion of inter-coded blocks (`pred == 0` otherwise).
    pub mv: MvField,
}

/// Decoding state of the picture being reconstructed.
pub(crate) struct PicState {
    pub frame: Frame,
    /// Width of the 4x4 grid.
    pub w4: usize,
    /// Height of the 4x4 grid.
    pub h4: usize,
    pub info: Vec<BlockInfo>,
    /// Slice tag per CTB (raster order); 0 = not decoded.
    pub ctb_slice: Vec<u16>,
    /// Number of slice segments started in this picture.
    pub slice_count: u16,
    /// Next CTB address (raster) a slice segment must start at.
    pub next_ctb: u32,
    /// Reference picture order counts and long-term flags of each slice
    /// (by slice tag - 1), for the motion stored with the picture.
    pub slice_refs: Vec<[Vec<(i32, bool)>; 2]>,
}

impl PicState {
    pub fn new(sps: &Sps) -> Result<Self, DecodeError> {
        let width = sps.width as usize;
        let height = sps.height as usize;
        let frame = Frame::new(width, height)?;
        let (w4, h4) = (width.div_ceil(4), height.div_ceil(4));
        let mut info = Vec::new();
        info.try_reserve_exact(w4 * h4)
            .map_err(|_| DecodeError::Limit)?;
        info.resize(w4 * h4, BlockInfo::default());
        let ctbs = (sps.ctb_width() * sps.ctb_height()) as usize;
        Ok(Self {
            frame,
            w4,
            h4,
            info,
            ctb_slice: vec![0; ctbs],
            slice_count: 0,
            next_ctb: 0,
            slice_refs: Vec::new(),
        })
    }

    /// Per-4x4 motion with reference order counts, stored with the
    /// decoded picture for temporal motion vector prediction.
    pub fn col_motion(&self) -> Vec<ColMv> {
        self.info
            .iter()
            .map(|b| {
                let mut col = ColMv {
                    pred: b.mv.pred,
                    mv: b.mv.mv,
                    ..ColMv::default()
                };
                if let Some(refs) = self.slice_refs.get(usize::from(b.slice).wrapping_sub(1)) {
                    for list in 0..2 {
                        if b.mv.uses(list) {
                            let (poc, lt) = refs[list]
                                .get(b.mv.ref_idx[list] as usize)
                                .copied()
                                .unwrap_or((0, false));
                            col.ref_poc[list] = poc;
                            col.ref_lt[list] = lt;
                        }
                    }
                } else {
                    col.pred = 0;
                }
                col
            })
            .collect()
    }

    /// Whether every CTB has been decoded.
    pub fn complete(&self) -> bool {
        self.ctb_slice.iter().all(|&tag| tag != 0)
    }

    fn at(&self, x: usize, y: usize) -> &BlockInfo {
        &self.info[(y >> 2) * self.w4 + (x >> 2)]
    }

    /// Applies `f` to every 4x4 unit of the square luma block.
    fn fill(&mut self, x0: usize, y0: usize, size: usize, f: impl FnMut(&mut BlockInfo)) {
        self.fill_rect(x0, y0, size, size, f);
    }

    /// Applies `f` to every 4x4 unit of the luma rectangle.
    fn fill_rect(
        &mut self,
        x0: usize,
        y0: usize,
        w: usize,
        h: usize,
        mut f: impl FnMut(&mut BlockInfo),
    ) {
        let x_end = (x0 + w).div_ceil(4).min(self.w4);
        let y_end = (y0 + h).div_ceil(4).min(self.h4);
        for y in y0 >> 2..y_end {
            for x in x0 >> 2..x_end {
                f(&mut self.info[y * self.w4 + x]);
            }
        }
    }
}

/// Coding-unit state shared by its prediction and transform units.
#[derive(Clone, Copy, Debug, Default)]
struct CuState {
    x0: usize,
    y0: usize,
    log2: u32,
    transquant_bypass: bool,
    /// `CuPredMode == MODE_INTRA`.
    intra: bool,
    /// `CtDepth`.
    depth: u32,
    part_mode: Option<PartMode>,
    /// `merge_flag` of the first prediction unit.
    merge_first: bool,
    intra_split: bool,
    max_trafo_depth: u32,
    /// Luma intra modes of the (up to four) prediction blocks.
    luma_modes: [u8; 4],
    /// Chroma intra mode (4:2:0 has one per CU).
    chroma_mode: u8,
}

/// Position of one transform tree node.
#[derive(Clone, Copy, Debug)]
struct TreeNode {
    x0: usize,
    y0: usize,
    /// Parent node origin (`xBase`, `yBase`).
    x_base: usize,
    y_base: usize,
    log2: u32,
    depth: u32,
    blk_idx: usize,
}

impl TreeNode {
    const fn root(x0: usize, y0: usize, log2: u32) -> Self {
        Self {
            x0,
            y0,
            x_base: x0,
            y_base: y0,
            log2,
            depth: 0,
            blk_idx: 0,
        }
    }
}

/// Read-only inputs shared by every slice segment of a picture.
pub(crate) struct SliceInputs<'a> {
    pub sps: &'a Sps,
    pub pps: &'a Pps,
    pub header: &'a SliceHeader,
    pub scans: &'a Scans,
    pub matrix: &'a [[i32; 32]; 32],
    /// `PicOrderCntVal` of the current picture.
    pub poc: i32,
    /// `RefPicList0` / `RefPicList1` of the slice.
    pub refs: &'a [RefList; 2],
    /// The collocated picture when temporal MV prediction is enabled.
    pub col: Option<&'a ColPic>,
}

/// Decodes one slice segment's CTUs into `pic`.
pub(crate) struct SliceDecoder<'a, 'b> {
    sps: &'a Sps,
    pps: &'a Pps,
    header: &'a SliceHeader,
    scans: &'a Scans,
    matrix: &'a [[i32; 32]; 32],
    poc: i32,
    refs: &'a [RefList; 2],
    col: Option<&'a ColPic>,
    pic: &'b mut PicState,
    cabac: SliceCabac<'a>,
    init_type: usize,
    scaling: Option<&'a ScalingList>,
    slice_tag: u16,
    /// `QpY` of the current coding unit.
    qp_y: i32,
    /// `QpY` of the last coding unit decoded (the qPY_PREV source).
    last_qp: i32,
    /// `qPY_PRED` of the current quantization group.
    qg_pred: i32,
    is_cu_qp_delta_coded: bool,
    cu_qp_delta: i32,
    /// Contexts stored after CTU 1 of a row (wavefront synchronisation),
    /// with that row's index.
    wpp_saved: Option<(usize, Box<Contexts>)>,
    levels: Vec<i32>,
    cu: CuState,
}

impl<'a, 'b> SliceDecoder<'a, 'b> {
    /// Prepares decoding of the slice segment whose RBSP is `rbsp`; the
    /// slice data is bounded to `data_bit_limit` bits (just past the
    /// `rbsp_stop_one_bit`, which the arithmetic decoder consumes).
    pub fn new(
        inputs: &SliceInputs<'a>,
        pic: &'b mut PicState,
        rbsp: &'a [u8],
        data_bit_limit: usize,
    ) -> Result<Self, DecodeError> {
        let header = inputs.header;
        let init_type = match (header.slice_type, header.cabac_init) {
            (SliceType::I, _) => 0,
            (SliceType::P, false) | (SliceType::B, true) => 1,
            (SliceType::P, true) | (SliceType::B, false) => 2,
        };
        let mut reader = BitReader::new(rbsp, data_bit_limit);
        reader.skip(header.data_bit_offset)?;
        let cabac = SliceCabac::new(reader, init_contexts(init_type, header.slice_qp)?)?;
        let scaling = if inputs.sps.scaling_list_enabled {
            inputs
                .pps
                .scaling_list
                .as_ref()
                .or(inputs.sps.scaling_list.as_ref())
        } else {
            None
        };
        pic.slice_count = pic.slice_count.checked_add(1).ok_or(DecodeError::Limit)?;
        let slice_tag = pic.slice_count;
        pic.slice_refs.push(std::array::from_fn(|list| {
            let refs = &inputs.refs[list];
            refs.pocs
                .iter()
                .copied()
                .zip(refs.long_term.iter().copied())
                .collect()
        }));
        Ok(Self {
            sps: inputs.sps,
            pps: inputs.pps,
            header,
            scans: inputs.scans,
            matrix: inputs.matrix,
            poc: inputs.poc,
            refs: inputs.refs,
            col: inputs.col,
            pic,
            cabac,
            init_type,
            scaling,
            slice_tag,
            qp_y: header.slice_qp,
            last_qp: header.slice_qp,
            qg_pred: header.slice_qp,
            is_cu_qp_delta_coded: false,
            cu_qp_delta: 0,
            wpp_saved: None,
            levels: vec![0; 32 * 32],
            cu: CuState::default(),
        })
    }

    /// `slice_segment_data()` (clause 7.3.8.1).
    pub fn decode(mut self) -> Result<(), DecodeError> {
        let ctb_w = self.sps.ctb_width() as usize;
        let total = ctb_w * self.sps.ctb_height() as usize;
        let start = self.header.segment_address as usize;
        if start != self.pic.next_ctb as usize {
            return Err(if start > self.pic.next_ctb as usize {
                DecodeError::IncompletePicture
            } else {
                DecodeError::Malformed
            });
        }
        let log2 = self.sps.ctb_log2;
        let wpp = self.pps.entropy_coding_sync;
        let mut addr = start;
        loop {
            let (cx, cy) = (addr % ctb_w, addr / ctb_w);
            if wpp && cx == 0 && addr != start {
                self.cabac.restart_engine()?;
                // Synchronise from the CTU above-right when it lies in this
                // slice (clause 9.3.1); otherwise start from the initial
                // context values.
                let above_right =
                    cy > 0 && ctb_w > 1 && self.pic.ctb_slice[addr + 1 - ctb_w] == self.slice_tag;
                match self.wpp_saved.take() {
                    Some((row, saved)) if above_right && row + 1 == cy => self.cabac.ctx = *saved,
                    _ => self.cabac.ctx = init_contexts(self.init_type, self.header.slice_qp)?,
                }
            }
            if wpp && cx == 0 {
                // First quantization group of a CTB row (clause 8.6.1).
                self.last_qp = self.header.slice_qp;
            }
            self.pic.ctb_slice[addr] = self.slice_tag;
            self.coding_quadtree(cx << log2, cy << log2, log2, 0)?;
            let end_of_slice = self.cabac.terminate()? == 1;
            if wpp && cx == 1 {
                self.wpp_saved = Some((cy, Box::new(self.cabac.ctx)));
            }
            addr += 1;
            if end_of_slice {
                break;
            }
            if addr >= total {
                return Err(DecodeError::Malformed);
            }
            if wpp && addr.is_multiple_of(ctb_w) && self.cabac.terminate()? != 1 {
                // end_of_subset_one_bit must be 1.
                return Err(DecodeError::Malformed);
            }
        }
        // The terminating bin consumed the rbsp_stop_one_bit: nothing of
        // the slice data may remain.
        if !self.cabac.reader.exhausted() {
            return Err(DecodeError::Malformed);
        }
        self.pic.next_ctb = u32::try_from(addr).map_err(|_| DecodeError::Limit)?;
        Ok(())
    }

    /// Neighbour availability for context selection and mode prediction:
    /// inside the picture and in a CTB of the current slice.
    fn available(&self, x: isize, y: isize) -> bool {
        if x < 0 || y < 0 || x >= self.sps.width as isize || y >= self.sps.height as isize {
            return false;
        }
        let log2 = self.sps.ctb_log2;
        let ctb = (y as usize >> log2) * self.sps.ctb_width() as usize + (x as usize >> log2);
        self.pic.ctb_slice[ctb] == self.slice_tag
    }

    fn log2_min_cu_qp_delta(&self) -> u32 {
        self.sps.ctb_log2 - self.pps.diff_cu_qp_delta_depth
    }

    /// `coding_quadtree()` (clause 7.3.8.4).
    fn coding_quadtree(
        &mut self,
        x0: usize,
        y0: usize,
        log2: u32,
        depth: u32,
    ) -> Result<(), DecodeError> {
        let size = 1usize << log2;
        let (width, height) = (self.sps.width as usize, self.sps.height as usize);
        let split = if x0 + size <= width && y0 + size <= height && log2 > self.sps.min_cb_log2 {
            let mut ctx = 0;
            let (xi, yi) = (x0 as isize, y0 as isize);
            if self.available(xi - 1, yi) && u32::from(self.pic.at(x0 - 1, y0).ct_depth) > depth {
                ctx += 1;
            }
            if self.available(xi, yi - 1) && u32::from(self.pic.at(x0, y0 - 1).ct_depth) > depth {
                ctx += 1;
            }
            self.cabac.flag(SPLIT_CODING_UNIT_FLAG + ctx)?
        } else {
            log2 > self.sps.min_cb_log2
        };
        if self.pps.cu_qp_delta_enabled && log2 >= self.log2_min_cu_qp_delta() {
            self.is_cu_qp_delta_coded = false;
            self.cu_qp_delta = 0;
            self.start_quantization_group(x0, y0);
        }
        if split {
            let half = size / 2;
            for (x, y) in [
                (x0, y0),
                (x0 + half, y0),
                (x0, y0 + half),
                (x0 + half, y0 + half),
            ] {
                if x < width && y < height {
                    self.coding_quadtree(x, y, log2 - 1, depth + 1)?;
                }
            }
            Ok(())
        } else {
            self.coding_unit(x0, y0, log2, depth)
        }
    }

    /// `qPY_PRED` of the quantization group at `(xq, yq)` (clause 8.6.1).
    fn start_quantization_group(&mut self, xq: usize, yq: usize) {
        let prev = self.last_qp;
        let mask = (1usize << self.sps.ctb_log2) - 1;
        let qp_a = if xq & mask != 0 {
            i32::from(self.pic.at(xq - 1, yq).qp_y)
        } else {
            prev
        };
        let qp_b = if yq & mask != 0 {
            i32::from(self.pic.at(xq, yq - 1).qp_y)
        } else {
            prev
        };
        self.qg_pred = (qp_a + qp_b + 1) >> 1;
    }

    /// `QpY` from the group prediction and `CuQpDeltaVal` (equation 8-283).
    fn update_qp(&mut self) {
        self.qp_y = if self.pps.cu_qp_delta_enabled {
            (self.qg_pred + self.cu_qp_delta + 52).rem_euclid(52)
        } else {
            self.header.slice_qp
        };
    }

    /// `coding_unit()` (clause 7.3.8.5).
    fn coding_unit(
        &mut self,
        x0: usize,
        y0: usize,
        log2: u32,
        depth: u32,
    ) -> Result<(), DecodeError> {
        let size = 1usize << log2;
        self.cu = CuState {
            x0,
            y0,
            log2,
            depth,
            intra: true,
            ..CuState::default()
        };
        self.update_qp();
        if self.pps.transquant_bypass_enabled {
            self.cu.transquant_bypass = self.cabac.flag(CU_TRANSQUANT_BYPASS_FLAG)?;
        }
        let mut skip = false;
        if self.header.slice_type != SliceType::I {
            let (xi, yi) = (x0 as isize, y0 as isize);
            let mut ctx = 0;
            if self.available(xi - 1, yi) && self.pic.at(x0 - 1, y0).skip {
                ctx += 1;
            }
            if self.available(xi, yi - 1) && self.pic.at(x0, y0 - 1).skip {
                ctx += 1;
            }
            skip = self.cabac.flag(SKIP_FLAG + ctx)?;
        }
        if skip {
            self.cu.intra = false;
            self.cu.part_mode = Some(PartMode::Part2Nx2N);
            self.prediction_unit(x0, y0, size, size, 0, true)?;
        } else if self.header.slice_type == SliceType::I || self.cabac.flag(PRED_MODE_FLAG)? {
            self.intra_coding_unit(x0, y0, log2)?;
        } else {
            self.cu.intra = false;
            let part = self.inter_part_mode(log2)?;
            self.cu.part_mode = Some(part);
            for (i, (bx, by, bw, bh)) in part.blocks(size).into_iter().enumerate() {
                self.prediction_unit(x0 + bx, y0 + by, bw, bh, i, false)?;
            }
            let rqt_root_cbf = if part == PartMode::Part2Nx2N && self.cu.merge_first {
                true
            } else {
                self.cabac.flag(NO_RESIDUAL_DATA_FLAG)?
            };
            if rqt_root_cbf {
                self.cu.max_trafo_depth = self.sps.max_th_depth_inter;
                self.transform_tree(TreeNode::root(x0, y0, log2), [false, false])?;
            }
        }
        let qp = self.qp_y as i8;
        let depth = depth as u8;
        self.pic.fill(x0, y0, size, |b| {
            b.ct_depth = depth;
            b.qp_y = qp;
            b.skip = skip;
        });
        self.last_qp = self.qp_y;
        Ok(())
    }

    /// The intra branch of `coding_unit()`: part mode, PCM or intra modes,
    /// and the transform tree.
    fn intra_coding_unit(&mut self, x0: usize, y0: usize, log2: u32) -> Result<(), DecodeError> {
        // part_mode for intra: "1" = PART_2Nx2N, "0" = PART_NxN, present
        // only at the minimum coding block size.
        let nxn = log2 == self.sps.min_cb_log2 && !self.cabac.flag(PART_MODE)?;
        self.cu.intra_split = nxn;
        let pcm = match self.sps.pcm {
            Some(pcm) if !nxn && (pcm.log2_min..=pcm.log2_max).contains(&log2) => {
                self.cabac.terminate()? == 1
            }
            _ => false,
        };
        if pcm {
            self.pcm_sample(x0, y0, log2)
        } else {
            self.intra_modes(x0, y0, log2, nxn)?;
            self.cu.max_trafo_depth = self.sps.max_th_depth_intra + u32::from(nxn);
            self.transform_tree(TreeNode::root(x0, y0, log2), [false, false])
        }
    }

    /// `part_mode` of an inter coding unit (clause 9.3.3.7, Table 9-43).
    fn inter_part_mode(&mut self, log2: u32) -> Result<PartMode, DecodeError> {
        if self.cabac.flag(PART_MODE)? {
            return Ok(PartMode::Part2Nx2N);
        }
        if log2 == self.sps.min_cb_log2 {
            if self.cabac.flag(PART_MODE + 1)? {
                return Ok(PartMode::Part2NxN);
            }
            if log2 == 3 || self.cabac.flag(PART_MODE + 2)? {
                return Ok(PartMode::PartNx2N);
            }
            return Ok(PartMode::PartNxN);
        }
        if !self.sps.amp_enabled {
            return Ok(if self.cabac.flag(PART_MODE + 1)? {
                PartMode::Part2NxN
            } else {
                PartMode::PartNx2N
            });
        }
        let horizontal = self.cabac.flag(PART_MODE + 1)?;
        if self.cabac.flag(PART_MODE + 3)? {
            return Ok(if horizontal {
                PartMode::Part2NxN
            } else {
                PartMode::PartNx2N
            });
        }
        let second = self.cabac.bypass()? == 1;
        Ok(match (horizontal, second) {
            (true, false) => PartMode::Part2NxnU,
            (true, true) => PartMode::Part2NxnD,
            (false, false) => PartMode::PartnLx2N,
            (false, true) => PartMode::PartnRx2N,
        })
    }

    /// Motion of a neighbouring prediction block, when it is available
    /// (inside the picture, already decoded, in this slice) and inter coded.
    fn pu_neighbour(&self, x: isize, y: isize) -> Option<MvField> {
        if x < 0 || y < 0 || x >= self.sps.width as isize || y >= self.sps.height as isize {
            return None;
        }
        let info = self.pic.at(x as usize, y as usize);
        (info.slice == self.slice_tag && info.mv.pred != 0).then_some(info.mv)
    }

    /// `prediction_unit()` (clause 7.3.8.6) with motion derivation (clause
    /// 8.5.3.2) and motion-compensated prediction (clause 8.5.3.3).
    fn prediction_unit(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        part_idx: usize,
        skip: bool,
    ) -> Result<(), DecodeError> {
        let merge = skip || self.cabac.flag(MERGE_FLAG)?;
        if part_idx == 0 {
            self.cu.merge_first = merge;
        }
        let pb = PbGeometry {
            x,
            y,
            w,
            h,
            part_idx,
            cu_x: self.cu.x0,
            cu_y: self.cu.y0,
            cu_log2: self.cu.log2,
            part_mode: self.cu.part_mode.unwrap_or(PartMode::Part2Nx2N),
        };
        let ctx = MvContext {
            poc: self.poc,
            slice_type: self.header.slice_type,
            refs: self.refs,
            col: self.col,
            temporal_mvp: self.header.temporal_mvp,
            collocated_from_l0: self.header.collocated_from_l0,
            max_num_merge_cand: self.header.max_num_merge_cand,
            num_ref_idx: self.header.num_ref_idx,
            log2_parallel_merge_level: self.pps.log2_parallel_merge_level,
            width: self.sps.width as usize,
            height: self.sps.height as usize,
            ctb_log2: self.sps.ctb_log2,
            w4: self.pic.w4,
        };
        let field = if merge {
            let max = self.header.max_num_merge_cand as usize;
            let mut idx = 0usize;
            if max > 1 && self.cabac.flag(MERGE_IDX)? {
                idx = 1;
                while idx < max - 1 && self.cabac.bypass()? == 1 {
                    idx += 1;
                }
            }
            ctx.merge(&pb, idx, |xn, yn| self.pu_neighbour(xn, yn))
        } else {
            let pred = if self.header.slice_type == SliceType::B {
                if w + h != 12 && self.cabac.flag(INTER_PRED_IDC + self.cu.depth as usize)? {
                    3
                } else if self.cabac.flag(INTER_PRED_IDC + 4)? {
                    2
                } else {
                    1
                }
            } else {
                1
            };
            let mut syntax = [(0usize, [0i16; 2], 0usize); 2];
            for (list, entry) in syntax.iter_mut().enumerate() {
                if pred & (1 << list) == 0 {
                    continue;
                }
                let count = self.header.num_ref_idx[list] as usize;
                let ref_idx = if count > 1 { self.ref_idx(count)? } else { 0 };
                let mvd = if list == 1 && self.header.mvd_l1_zero && pred == 3 {
                    [0, 0]
                } else {
                    self.mvd_coding()?
                };
                let mvp_flag = usize::from(self.cabac.flag(MVP_LX_FLAG)?);
                *entry = (ref_idx, mvd, mvp_flag);
            }
            let mut field = MvField {
                pred,
                mv: [[0; 2]; 2],
                ref_idx: [-1, -1],
            };
            for (list, &(ref_idx, mvd, mvp_flag)) in syntax.iter().enumerate() {
                if pred & (1 << list) == 0 {
                    continue;
                }
                let mvp = ctx.amvp(&pb, list, ref_idx, mvp_flag, |xn, yn| {
                    self.pu_neighbour(xn, yn)
                });
                field.mv[list] = [mvp[0].wrapping_add(mvd[0]), mvp[1].wrapping_add(mvd[1])];
                field.ref_idx[list] = i8::try_from(ref_idx).map_err(|_| DecodeError::Malformed)?;
            }
            field
        };
        let tag = self.slice_tag;
        self.pic.fill_rect(x, y, w, h, |b| {
            b.slice = tag;
            b.intra = false;
            b.ipm = intra::DC;
            b.mv = field;
        });
        let weights = self.header.weights.as_ref();
        inter::predict(
            &mut self.pic.frame,
            self.refs,
            &field,
            Block { x, y, w, h },
            weights,
        )
        .ok_or(DecodeError::MissingReference)
    }

    /// `ref_idx_lX` (truncated Rice, cMax = count - 1; two context-coded
    /// bins, the rest bypass). Both lists share the contexts.
    fn ref_idx(&mut self, count: usize) -> Result<usize, DecodeError> {
        let max = count - 1;
        let mut idx = 0;
        while idx < max.min(2) && self.cabac.flag(REF_IDX_L0 + idx)? {
            idx += 1;
        }
        if idx == 2 {
            while idx < max && self.cabac.bypass()? == 1 {
                idx += 1;
            }
        }
        Ok(idx)
    }

    /// `mvd_coding()` (clause 7.3.8.9).
    fn mvd_coding(&mut self) -> Result<[i16; 2], DecodeError> {
        let greater0 = [
            self.cabac.flag(ABS_MVD_GREATER0_FLAG)?,
            self.cabac.flag(ABS_MVD_GREATER0_FLAG)?,
        ];
        let mut greater1 = [false; 2];
        for (flag, &g0) in greater1.iter_mut().zip(&greater0) {
            // The oracle's context layout keeps abs_mvd_greater1_flag at the
            // second slot of its two-context block (Table 9-4: one context).
            *flag = g0 && self.cabac.flag(ABS_MVD_GREATER1_FLAG + 1)?;
        }
        let mut mvd = [0i16; 2];
        for (component, value) in mvd.iter_mut().enumerate() {
            if !greater0[component] {
                continue;
            }
            let mut magnitude: i64 = 1;
            if greater1[component] {
                // abs_mvd_minus2: first-order exp-Golomb (EG1).
                let mut k = 1u32;
                let mut base: i64 = 0;
                while self.cabac.bypass()? == 1 {
                    base += 1 << k;
                    k += 1;
                    if k > 16 {
                        return Err(DecodeError::Malformed);
                    }
                }
                magnitude = base + i64::from(self.cabac.bypass_bits(k)?) + 2;
            }
            let negative = self.cabac.bypass()? == 1;
            let signed = if negative { -magnitude } else { magnitude };
            *value = i16::try_from(signed).map_err(|_| DecodeError::Malformed)?;
        }
        Ok(mvd)
    }

    /// `prev_intra_luma_pred_flag` / `mpm_idx` / `rem_intra_luma_pred_mode`
    /// and `intra_chroma_pred_mode` with the derivations of clauses 8.4.2
    /// and 8.4.3.
    fn intra_modes(
        &mut self,
        x0: usize,
        y0: usize,
        log2: u32,
        nxn: bool,
    ) -> Result<(), DecodeError> {
        let parts = if nxn { 4 } else { 1 };
        let pb = (1usize << log2) >> usize::from(nxn);
        let mut prev = [false; 4];
        for flag in prev.iter_mut().take(parts) {
            *flag = self.cabac.flag(PREV_INTRA_LUMA_PRED_FLAG)?;
        }
        for (i, &prev_flag) in prev.iter().enumerate().take(parts) {
            let (xp, yp) = (x0 + pb * (i & 1), y0 + pb * (i >> 1));
            let candidates = self.mpm_candidates(xp, yp);
            let mode = if prev_flag {
                let mut idx = 0;
                while idx < 2 && self.cabac.bypass()? == 1 {
                    idx += 1;
                }
                candidates[idx]
            } else {
                let mut mode = self.cabac.bypass_bits(5)? as u8;
                let mut sorted = candidates;
                sorted.sort_unstable();
                for candidate in sorted {
                    if mode >= candidate {
                        mode += 1;
                    }
                }
                mode
            };
            self.cu.luma_modes[i] = mode;
            self.pic.fill(xp, yp, pb, |b| {
                b.intra = true;
                b.ipm = mode;
            });
        }
        let chroma_syntax = if self.cabac.flag(INTRA_CHROMA_PRED_MODE)? {
            self.cabac.bypass_bits(2)? as u8
        } else {
            4
        };
        let luma = self.cu.luma_modes[0];
        self.cu.chroma_mode = if chroma_syntax == 4 {
            luma
        } else {
            let mode = [intra::PLANAR, 26, 10, intra::DC][usize::from(chroma_syntax)];
            if mode == luma { 34 } else { mode }
        };
        Ok(())
    }

    /// `candModeList` (clause 8.4.2).
    fn mpm_candidates(&self, xp: usize, yp: usize) -> [u8; 3] {
        let (xi, yi) = (xp as isize, yp as isize);
        let neighbour = |available: bool, x: usize, y: usize| {
            if !available {
                return intra::DC;
            }
            let info = self.pic.at(x, y);
            if info.intra { info.ipm } else { intra::DC }
        };
        let a = neighbour(self.available(xi - 1, yi), xp.wrapping_sub(1), yp);
        let ctb_top = (yp >> self.sps.ctb_log2) << self.sps.ctb_log2;
        let b = if yp == 0 || yp - 1 < ctb_top {
            intra::DC
        } else {
            neighbour(self.available(xi, yi - 1), xp, yp - 1)
        };
        if a == b {
            if a < 2 {
                [intra::PLANAR, intra::DC, 26]
            } else {
                [a, 2 + ((a + 29) % 32), 2 + ((a - 2 + 1) % 32)]
            }
        } else {
            let c = if a != intra::PLANAR && b != intra::PLANAR {
                intra::PLANAR
            } else if a != intra::DC && b != intra::DC {
                intra::DC
            } else {
                26
            };
            [a, b, c]
        }
    }

    /// `pcm_sample()` (clause 7.3.8.7): byte-aligned raw samples, then the
    /// arithmetic decoder restarts.
    fn pcm_sample(&mut self, x0: usize, y0: usize, log2: u32) -> Result<(), DecodeError> {
        let pcm = self.sps.pcm.ok_or(DecodeError::Malformed)?;
        let size = 1usize << log2;
        let reader = &mut self.cabac.reader;
        while !reader.byte_aligned() {
            if reader.flag()? {
                return Err(DecodeError::Malformed);
            }
        }
        for c in 0..3 {
            let (depth, n, xc, yc) = if c == 0 {
                (pcm.bit_depth_luma, size, x0, y0)
            } else {
                (pcm.bit_depth_chroma, size / 2, x0 / 2, y0 / 2)
            };
            let stride = self.pic.frame.plane_width(c);
            for y in 0..n {
                for x in 0..n {
                    let value = reader.uint(depth)? << (8 - depth);
                    self.pic.frame.planes[c][(yc + y) * stride + xc + x] = value as u8;
                }
            }
        }
        self.cabac.restart_engine()?;
        let tag = self.slice_tag;
        self.pic.fill(x0, y0, size, |b| {
            b.slice = tag;
            b.intra = true;
            b.ipm = intra::DC;
        });
        Ok(())
    }

    /// Luma intra mode of the transform block at `(x0, y0)`.
    fn luma_mode_at(&self, x0: usize, y0: usize) -> u8 {
        if !self.cu.intra_split {
            return self.cu.luma_modes[0];
        }
        let half = 1usize << (self.cu.log2 - 1);
        let right = usize::from(x0 >= self.cu.x0 + half);
        let lower = usize::from(y0 >= self.cu.y0 + half);
        self.cu.luma_modes[lower * 2 + right]
    }

    /// `transform_tree()` (clause 7.3.8.8).
    fn transform_tree(&mut self, node: TreeNode, parent_cbf: [bool; 2]) -> Result<(), DecodeError> {
        let TreeNode {
            x0,
            y0,
            log2,
            depth,
            ..
        } = node;
        let split = if log2 <= self.sps.max_tb_log2
            && log2 > self.sps.min_tb_log2
            && depth < self.cu.max_trafo_depth
            && !(self.cu.intra_split && depth == 0)
        {
            self.cabac.flag(SPLIT_TRANSFORM_FLAG + 5 - log2 as usize)?
        } else {
            let inter_split = self.sps.max_th_depth_inter == 0
                && !self.cu.intra
                && self.cu.part_mode != Some(PartMode::Part2Nx2N)
                && depth == 0;
            log2 > self.sps.max_tb_log2 || (self.cu.intra_split && depth == 0) || inter_split
        };
        let mut cbf = parent_cbf;
        if log2 > 2 {
            for flag in &mut cbf {
                *flag = (depth == 0 || *flag) && self.cabac.flag(CBF_CB_CR + depth as usize)?;
            }
        }
        if split {
            let half = 1usize << (log2 - 1);
            for (i, (x, y)) in [
                (x0, y0),
                (x0 + half, y0),
                (x0, y0 + half),
                (x0 + half, y0 + half),
            ]
            .into_iter()
            .enumerate()
            {
                let child = TreeNode {
                    x0: x,
                    y0: y,
                    x_base: x0,
                    y_base: y0,
                    log2: log2 - 1,
                    depth: depth + 1,
                    blk_idx: i,
                };
                self.transform_tree(child, cbf)?;
            }
            return Ok(());
        }
        let cbf_luma = if self.cu.intra || depth != 0 || cbf[0] || cbf[1] {
            self.cabac.flag(CBF_LUMA + usize::from(depth == 0))?
        } else {
            true
        };
        self.transform_unit(node, cbf_luma, cbf)
    }

    /// `transform_unit()` (clause 7.3.8.10) with intra reconstruction.
    fn transform_unit(
        &mut self,
        node: TreeNode,
        cbf_luma: bool,
        cbf_chroma: [bool; 2],
    ) -> Result<(), DecodeError> {
        let TreeNode {
            x0,
            y0,
            x_base,
            y_base,
            log2,
            blk_idx,
            ..
        } = node;
        let intra = self.cu.intra;
        let luma_mode = self.luma_mode_at(x0, y0);
        if intra {
            self.predict_intra(0, x0, y0, log2, luma_mode);
        }
        if (cbf_luma || cbf_chroma[0] || cbf_chroma[1])
            && self.pps.cu_qp_delta_enabled
            && !self.is_cu_qp_delta_coded
        {
            let delta = self.cu_qp_delta_abs()?;
            let delta = if delta > 0 && self.cabac.bypass()? == 1 {
                -delta
            } else {
                delta
            };
            if !(-26..=25).contains(&delta) {
                return Err(DecodeError::Malformed);
            }
            self.is_cu_qp_delta_coded = true;
            self.cu_qp_delta = delta;
            self.update_qp();
        }
        if cbf_luma {
            let scan = if intra {
                scan_idx_for(luma_mode, log2, 3)
            } else {
                0
            };
            self.residual_block(0, x0, y0, log2, scan)?;
        }
        let tag = self.slice_tag;
        self.pic.fill(x0, y0, 1 << log2, |b| b.slice = tag);
        let chroma = if log2 > 2 {
            Some((x0 / 2, y0 / 2, log2 - 1))
        } else if blk_idx == 3 {
            Some((x_base / 2, y_base / 2, 2))
        } else {
            None
        };
        if let Some((xc, yc, log2c)) = chroma {
            let mode = self.cu.chroma_mode;
            for c in 1..=2usize {
                if intra {
                    self.predict_intra(c, xc, yc, log2c, mode);
                }
                if cbf_chroma[c - 1] {
                    let scan = if intra {
                        scan_idx_for(mode, log2c, 2)
                    } else {
                        0
                    };
                    self.residual_block(c, xc, yc, log2c, scan)?;
                }
            }
        }
        Ok(())
    }

    /// `cu_qp_delta_abs` (clause 9.3.3.10): TU prefix (cMax 5, first bin
    /// context 0, others context 1) and an EG0 suffix.
    fn cu_qp_delta_abs(&mut self) -> Result<i32, DecodeError> {
        let mut prefix = 0;
        while prefix < 5 && self.cabac.flag(CU_QP_DELTA + usize::from(prefix > 0))? {
            prefix += 1;
        }
        if prefix < 5 {
            return Ok(prefix);
        }
        let mut k = 0u32;
        let mut value = 0i32;
        while self.cabac.bypass()? == 1 {
            value += 1 << k;
            k += 1;
            if k > 16 {
                return Err(DecodeError::Malformed);
            }
        }
        value += self.cabac.bypass_bits(k)? as i32;
        Ok(prefix + value)
    }

    /// Parses one residual block and adds the reconstructed residual to
    /// the prediction already in the frame.
    fn residual_block(
        &mut self,
        c: usize,
        x: usize,
        y: usize,
        log2: u32,
        scan_idx: u8,
    ) -> Result<(), DecodeError> {
        let n = 1usize << log2;
        let mut levels = std::mem::take(&mut self.levels);
        levels[..n * n].fill(0);
        let bypass = self.cu.transquant_bypass;
        let params = ResidualParams {
            log2,
            c_idx: c,
            scan_idx,
            sign_hiding: self.pps.sign_data_hiding && !bypass,
            transform_skip_allowed: self.pps.transform_skip_enabled && !bypass && log2 == 2,
        };
        let result = residual_coding(&mut self.cabac, self.scans, params, &mut levels);
        let skip = match result {
            Ok(skip) => skip,
            Err(err) => {
                self.levels = levels;
                return Err(err);
            }
        };
        if !bypass {
            let qp = if c == 0 {
                self.qp_y
            } else {
                let offset = if c == 1 {
                    self.pps.cb_qp_offset + self.header.cb_qp_offset
                } else {
                    self.pps.cr_qp_offset + self.header.cr_qp_offset
                };
                chroma_qp((self.qp_y + offset).clamp(0, 57))
            };
            let matrix_id = c + if self.cu.intra { 0 } else { 3 };
            let factors = match self.scaling {
                Some(list) => list.factors(log2 as usize - 2, matrix_id),
                None => &FLAT[..],
            };
            scale(&mut levels, log2, qp, factors);
            if skip {
                transform_skip(&mut levels, log2);
            } else {
                let dst = self.cu.intra && c == 0 && log2 == 2;
                inverse_transform(&mut levels, log2, dst, self.matrix);
            }
        }
        let stride = self.pic.frame.plane_width(c);
        let plane = &mut self.pic.frame.planes[c];
        for row in 0..n {
            let line = &mut plane[(y + row) * stride + x..(y + row) * stride + x + n];
            for (sample, &residual) in line.iter_mut().zip(&levels[row * n..(row + 1) * n]) {
                *sample = (i32::from(*sample) + residual).clamp(0, 255) as u8;
            }
        }
        self.levels = levels;
        Ok(())
    }

    /// Intra prediction of one `2^log2` block of component `c` at
    /// component coordinates `(x, y)` (clause 8.4.4.2).
    fn predict_intra(&mut self, c: usize, x: usize, y: usize, log2: u32, mode: u8) {
        let n = 1usize << log2;
        let shift = usize::from(c > 0);
        let (pw, ph) = (
            self.pic.frame.plane_width(c) as isize,
            self.pic.frame.plane_height(c) as isize,
        );
        let constrained = self.pps.constrained_intra_pred;
        let mut samples = [0u8; 4 * 32 + 1];
        let mut available = [false; 4 * 32 + 1];
        let len = 4 * n + 1;
        let stride = pw as usize;
        for i in 0..len {
            let (dx, dy) = if i < 2 * n {
                (-1, (2 * n - 1 - i) as isize)
            } else if i == 2 * n {
                (-1, -1)
            } else {
                ((i - 2 * n - 1) as isize, -1)
            };
            let (px, py) = (x as isize + dx, y as isize + dy);
            if px < 0 || py < 0 || px >= pw || py >= ph {
                continue;
            }
            let info = self.pic.at((px as usize) << shift, (py as usize) << shift);
            if info.slice == self.slice_tag && (!constrained || info.intra) {
                available[i] = true;
                samples[i] = self.pic.frame.planes[c][py as usize * stride + px as usize];
            }
        }
        intra::substitute(&mut samples[..len], &available[..len]);
        let refs = intra::filter(
            &samples[..len],
            n,
            mode,
            c == 0,
            self.sps.strong_intra_smoothing,
        );
        let mut block = [0u8; 32 * 32];
        intra::predict(&refs, n, mode, c == 0, &mut block);
        let plane = &mut self.pic.frame.planes[c];
        for row in 0..n {
            let start = (y + row) * stride + x;
            plane[start..start + n].copy_from_slice(&block[row * n..(row + 1) * n]);
        }
    }
}

/// `scanIdx` of an intra block (clause 7.4.9.11): mode-dependent for
/// blocks up to `2^max_log2` (8x8 luma, 4x4 chroma in 4:2:0); modes
/// 6..=14 scan vertically, 22..=30 horizontally.
fn scan_idx_for(mode: u8, log2: u32, max_log2: u32) -> u8 {
    if log2 > max_log2 {
        return 0;
    }
    match mode {
        6..=14 => 2,
        22..=30 => 1,
        _ => 0,
    }
}
