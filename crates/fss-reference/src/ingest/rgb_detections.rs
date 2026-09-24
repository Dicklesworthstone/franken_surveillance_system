#![forbid(unsafe_code)]
//! Actual RGB tensor heads -> source-space, privacy-screened detector proposals.
//!
//! Layout, class vocabulary, box units and score arithmetic are frozen inputs, not
//! guesses based on tensor contents or a model-family name. All selected head rows
//! are validated before a successful result. NMS is class-aware on outward-rounded
//! source boxes. Every row and every threshold-passing candidate has an outcome.
//! These are uncalibrated model proposals, never identity, coverage or effect authority.

use super::detections::BOX_SUBPIXELS;
use super::rgb_inference::{RgbInference, RgbSourceBinding};
use crate::ScalarExecCx;
use crate::preprocess::ResizeGeometry;
use crate::scalar_executor::deterministic_sigmoid_f32;
use fss_core::{CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm, Sha256Hasher};
use std::collections::BTreeSet;

/// Complete dense head bound; accommodates an 8,400-row head without truncation.
pub const MAX_RGB_HEAD_ROWS: usize = 32_768;
/// Complete threshold-passing, source/privacy-admissible candidate bound before NMS.
pub const MAX_RGB_CANDIDATES: usize = 4096;
/// Complete NMS survivor bound. Exceeding it refuses rather than selecting top-k.
pub const MAX_RGB_DETECTIONS: usize = 256;
const MAX_CLASSES: usize = 256;

/// Exact rank-three tensor axis order. Batch size must be one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadLayout {
    /// `[1, rows, fields]` contiguous row records.
    Rows,
    /// `[1, fields, rows]` contiguous field planes.
    Channels,
}
/// Box representation on the model input grid, before reversal of resize/padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadBoxes {
    /// Pixel-edge left/top/right/bottom.
    PixelCorners,
    /// Pixel-edge center x/y and positive width/height.
    PixelCenterSize,
    /// Corners divided by the full model input width/height, including padding.
    NormalizedCorners,
    /// Center/size divided by full model input width/height, including padding.
    NormalizedCenterSize,
}
/// Explicit scalar score interpretation, separately selectable for objectness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadScore {
    /// Each source value must be finite and in `[0,1]`.
    Probability,
    /// Apply the existing deterministic scalar sigmoid to each finite logit.
    Logit,
}
/// Whether a row can produce one or several class hypotheses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadClasses {
    /// Largest combined score; exact ties choose the lowest class index.
    Best,
    /// Every class whose combined score reaches the inclusive threshold.
    MultiLabel,
}

/// Complete immutable head semantics. No anchor/stride/DFL or class is inferred.
#[derive(Clone, Debug)]
pub struct RgbDetectionSpec {
    /// Exact RGB graph/weights/preprocessing identity, not a model name.
    pub model: ContentDigest,
    /// Declared finite F32 output to interpret; other outputs remain in the inference.
    pub output_port: String,
    /// Ordered unique labels supplied with the converted model.
    pub labels: Vec<String>,
    /// Tensor axis order; each row has four box fields followed by scores.
    pub layout: HeadLayout,
    /// Already-decoded box representation. Raw anchor/DFL heads are not accepted.
    pub boxes: HeadBoxes,
    /// Class score rule; sigmoid is never implicitly applied twice.
    pub class_score: HeadScore,
    /// Some adds one objectness field after the four box fields. Combine in F32
    /// as objectness * class score; None means class scores alone.
    pub objectness: Option<HeadScore>,
    /// Explicit single- or multiple-class emission rule.
    pub classes: HeadClasses,
    /// Inclusive combined-score threshold, in millionths.
    pub minimum_score_ppm: u32,
    /// Suppress same-class boxes only when quantized source IoU strictly exceeds this.
    pub nms_iou_ppm: u32,
    /// Complete row, pre-NMS candidate and survivor ceilings, respectively.
    pub maximum_rows: usize,
    /// No pre-NMS score-ranked truncation occurs at this ceiling.
    pub maximum_candidates: usize,
    /// No post-NMS score-ranked truncation occurs at this ceiling.
    pub maximum_detections: usize,
}
/// Validated, versioned interpretation bound to one model and numerical algorithm.
#[derive(Debug)]
pub struct RgbDetectionContract {
    spec: RgbDetectionSpec,
    digest: ContentDigest,
}
impl RgbDetectionContract {
    /// Freeze the complete head program. This is not model activation or approval.
    pub fn new(spec: RgbDetectionSpec) -> Result<Self, RgbDetectionError> {
        let name_ok = |s: &str| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control);
        if spec.model.algorithm() != DigestAlgorithm::Sha256
            || spec.model.bytes() == [0; 32]
            || !name_ok(&spec.output_port)
            || spec.labels.is_empty()
            || spec.labels.len() > MAX_CLASSES
            || spec.labels.iter().any(|s| !name_ok(s))
            || spec.labels.iter().collect::<BTreeSet<_>>().len() != spec.labels.len()
            || spec.minimum_score_ppm > 1_000_000
            || spec.nms_iou_ppm > 1_000_000
            || !(1..=MAX_RGB_HEAD_ROWS).contains(&spec.maximum_rows)
            || !(1..=MAX_RGB_CANDIDATES).contains(&spec.maximum_candidates)
            || !(1..=MAX_RGB_DETECTIONS).contains(&spec.maximum_detections)
            || spec.maximum_detections > spec.maximum_candidates
        {
            return Err(RgbDetectionError::InvalidContract);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.rgb-detection-contract.reference.v1:full-footprint:source-q256-nms");
        // Pin this implementation too; a source fingerprint is not binary qualification.
        e.digest(ContentDigest::sha256(include_bytes!("rgb_detections.rs")));
        e.digest(spec.model);
        e.text(&spec.output_port);
        e.u64(spec.labels.len() as u64);
        for label in &spec.labels {
            e.text(label);
        }
        e.u8(match spec.layout {
            HeadLayout::Rows => 0,
            HeadLayout::Channels => 1,
        });
        e.u8(match spec.boxes {
            HeadBoxes::PixelCorners => 0,
            HeadBoxes::PixelCenterSize => 1,
            HeadBoxes::NormalizedCorners => 2,
            HeadBoxes::NormalizedCenterSize => 3,
        });
        e.u8(score_tag(spec.class_score));
        e.u8(spec.objectness.map_or(0, |s| score_tag(s) + 1));
        e.u8(match spec.classes {
            HeadClasses::Best => 0,
            HeadClasses::MultiLabel => 1,
        });
        e.u32(spec.minimum_score_ppm);
        e.u32(spec.nms_iou_ppm);
        e.u32(BOX_SUBPIXELS);
        for n in [
            spec.maximum_rows,
            spec.maximum_candidates,
            spec.maximum_detections,
        ] {
            e.u64(n as u64);
        }
        Ok(Self {
            digest: ContentDigest::sha256(&e.finish_checked()?),
            spec,
        })
    }
    /// Frozen model, labels, score arithmetic, geometry and bounds.
    pub fn spec(&self) -> &RgbDetectionSpec {
        &self.spec
    }
    /// Semantic program identity, independent of a successful call's work allowance.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}
fn score_tag(score: HeadScore) -> u8 {
    match score {
        HeadScore::Probability => 0,
        HeadScore::Logit => 1,
    }
}

/// Refusal returns no partial proposals and does not mutate inference or source state.
#[derive(Debug)]
pub enum RgbDetectionError {
    /// Invalid frozen interpretation or limits.
    InvalidContract,
    /// Wrong model, head shape/port, nonfinite/invalid score or nonpositive box.
    InvalidOutput,
    /// Exact source mask identity, values or dimensions did not match.
    MaskMismatch,
    /// Complete output, allocation or caller scratch reservation exceeded.
    Limit,
    /// Shared deterministic operation allowance exhausted; used work is not refunded.
    BudgetExceeded,
    /// Owner cancellation observed before returning the complete result.
    Cancelled,
    /// A shared canonical encoding failed.
    Contract(ContractError),
}
impl From<ContractError> for RgbDetectionError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}
impl std::fmt::Display for RgbDetectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidContract => "invalid RGB detection contract",
            Self::InvalidOutput => "RGB output does not satisfy dense head contract",
            Self::MaskMismatch => "RGB detection source permission mismatch",
            Self::Limit => "RGB detection complete-output or scratch bound",
            Self::BudgetExceeded => "RGB detection work allowance exhausted",
            Self::Cancelled => "RGB detection owner cancelled",
            Self::Contract(_) => "RGB detection encoding failed",
        })
    }
}
impl std::error::Error for RgbDetectionError {}

/// Cumulative operations and per-call logical scratch ceiling, not wall time or peak RSS.
#[derive(Debug)]
pub struct RgbDetectionBudget {
    remaining: u64,
    used: u64,
    maximum_scratch_bytes: usize,
}
impl RgbDetectionBudget {
    /// Reserve score/mask/geometry/sort/NMS/hash work. Scratch covers logical vectors,
    /// excluding caller-owned tensors, allocator overhead and a small encoder header.
    pub fn new(units: u64, maximum_scratch_bytes: usize) -> Self {
        Self {
            remaining: units,
            used: 0,
            maximum_scratch_bytes,
        }
    }
    /// Units spent, including work before refused results.
    pub fn used(&self) -> u64 {
        self.used
    }
    /// Unspent allowance; retry does not replenish it.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    fn charge(&mut self, units: u64, cx: &ScalarExecCx) -> Result<(), RgbDetectionError> {
        cx.checkpoint("rgb-detections:work")
            .map_err(|_| RgbDetectionError::Cancelled)?;
        if units > self.remaining {
            return Err(RgbDetectionError::BudgetExceeded);
        }
        self.remaining -= units;
        self.used += units;
        Ok(())
    }
}

/// Why a complete head row did not supply source-space candidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadRowDisposition {
    /// No selected class reached the inclusive score threshold.
    BelowThreshold,
    /// A valid positive model-space box had no intersection with the non-padding image.
    OutsideImage,
    /// At least one touched source pixel is denied. No partially private box is promoted.
    PrivateFootprint,
    /// Number of emitted class candidates before NMS, not independent corroboration.
    Candidates(usize),
}
/// One outcome per source row, retaining skipped rows without inventing detections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadRowDecision {
    /// Original row in the declared tensor layout.
    pub row: usize,
    /// Complete geometry/privacy/score disposition.
    pub disposition: HeadRowDisposition,
}
/// One uncalibrated class/box hypothesis derived from actual model output.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RgbDetection {
    row: usize,
    class_index: usize,
    score: f32,
    bounds: [u32; 4],
    clipped: bool,
}
impl RgbDetection {
    /// Original dense output row; repeated across labels only under MultiLabel.
    pub fn row(&self) -> usize {
        self.row
    }
    /// Index in the contract's frozen label vocabulary.
    pub fn class_index(&self) -> usize {
        self.class_index
    }
    /// Combined F32 score, not a calibrated threat or identity probability.
    pub fn score(&self) -> f32 {
        self.score
    }
    /// Source-grid half-open XYXY, outward-rounded to 1/256-pixel units.
    pub fn bounds(&self) -> [u32; 4] {
        self.bounds
    }
    /// Model box exceeded the actual non-padding image; retained bounds were clipped.
    pub fn clipped(&self) -> bool {
        self.clipped
    }
}
/// Every admitted pre-NMS candidate survives in the report, including suppressed ones.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RgbCandidateDecision {
    /// Source-linked candidate, in descending score then row/class order.
    pub detection: RgbDetection,
    /// Index of its retained suppressor in this report's candidates. None means retained.
    pub suppressed_by: Option<usize>,
}
/// Immutable complete detector projection; keep the inference to hydrate original tensors.
#[derive(Debug)]
pub struct RgbDetectionReport {
    digest: ContentDigest,
    inference: ContentDigest,
    contract: ContentDigest,
    source: RgbSourceBinding,
    geometry: ResizeGeometry,
    rows: Vec<HeadRowDecision>,
    candidates: Vec<RgbCandidateDecision>,
    detections: Vec<RgbDetection>,
}
impl RgbDetectionReport {
    /// Versioned derivation fingerprint, not a durable ledger publication or source custody.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact inference identity retaining all original output tensors.
    pub fn inference_identity(&self) -> ContentDigest {
        self.inference
    }
    /// Exact postprocessing contract, including labels and score/selection rules.
    pub fn contract_digest(&self) -> ContentDigest {
        self.contract
    }
    /// Original camera/clock/capture/calibration/mask declaration without reinterpretation.
    pub fn source(&self) -> RgbSourceBinding {
        self.source
    }
    /// Exact resize and padding geometry actually used by inference.
    pub fn geometry(&self) -> ResizeGeometry {
        self.geometry
    }
    /// One outcome for every selected head row, including privacy and padding exclusions.
    pub fn rows(&self) -> &[HeadRowDecision] {
        &self.rows
    }
    /// All pre-NMS candidates and stable suppressor links.
    pub fn candidates(&self) -> &[RgbCandidateDecision] {
        &self.candidates
    }
    /// All retained class-aware NMS proposals, never top-k truncated.
    pub fn detections(&self) -> &[RgbDetection] {
        &self.detections
    }
}

/// Interpret an opaque, actually executed RGB inference, not caller-supplied detections.
///
/// A mask must be supplied again and match the inference's exact source mask. All
/// touched source pixels must be allowed; masking input pixels alone does not make
/// hallucinated boxes over denied regions valid. This check does not certify visibility.
/// No successful result is returned until every row, NMS decision and final cancel poll
/// completes. Empty results do not prove absence or continuous coverage.
pub fn project_rgb_detections(
    inference: &RgbInference,
    contract: &RgbDetectionContract,
    allowed: &[u8],
    budget: &mut RgbDetectionBudget,
    cx: &ScalarExecCx,
) -> Result<RgbDetectionReport, RgbDetectionError> {
    budget.charge(1, cx)?;
    if inference.model_digest() != contract.spec.model {
        return Err(RgbDetectionError::InvalidOutput);
    }
    let tensor = inference
        .outputs()
        .get(&contract.spec.output_port)
        .ok_or(RgbDetectionError::InvalidOutput)?;
    let g = inference.geometry();
    let parts = decode_head(
        tensor.shape(),
        tensor.values(),
        g,
        allowed,
        inference.source().permission_mask,
        contract,
        budget,
        cx,
    )?;
    let mut hash = Sha256Hasher::new();
    let mut e = CanonicalEncoder::new();
    e.text("fss.rgb-detection-result.reference.v1");
    e.digest(contract.digest());
    e.digest(inference.identity());
    e.digest(inference.output_digest());
    for n in [
        g.source_width,
        g.source_height,
        g.target_width,
        g.target_height,
        g.image_width,
        g.image_height,
        g.left,
        g.top,
    ] {
        e.u64(n as u64);
    }
    e.u64(parts.rows.len() as u64);
    e.u64(parts.candidates.len() as u64);
    budget.charge(512, cx)?;
    hash.update(&e.finish_checked()?);
    for row in &parts.rows {
        budget.charge(32, cx)?;
        let (tag, count) = match row.disposition {
            HeadRowDisposition::BelowThreshold => (0, 0),
            HeadRowDisposition::OutsideImage => (1, 0),
            HeadRowDisposition::PrivateFootprint => (2, 0),
            HeadRowDisposition::Candidates(n) => (3, n),
        };
        hash.update(&(row.row as u64).to_le_bytes());
        hash.update(&[tag]);
        hash.update(&(count as u64).to_le_bytes());
    }
    for candidate in &parts.candidates {
        budget.charge(64, cx)?;
        let d = candidate.detection;
        hash.update(&(d.row as u64).to_le_bytes());
        hash.update(&(d.class_index as u64).to_le_bytes());
        hash.update(&d.score.to_bits().to_le_bytes());
        for v in d.bounds {
            hash.update(&v.to_le_bytes());
        }
        hash.update(&[u8::from(d.clipped)]);
        hash.update(
            &candidate
                .suppressed_by
                .map_or(u64::MAX, |i| i as u64)
                .to_le_bytes(),
        );
    }
    let digest = ContentDigest::new(
        DigestAlgorithm::Sha256,
        hash.finalize().map_err(|_| RgbDetectionError::Limit)?,
    );
    budget.charge(0, cx)?;
    Ok(RgbDetectionReport {
        digest,
        inference: inference.identity(),
        contract: contract.digest(),
        source: inference.source(),
        geometry: g,
        rows: parts.rows,
        candidates: parts.candidates,
        detections: parts.detections,
    })
}

struct Parts {
    rows: Vec<HeadRowDecision>,
    candidates: Vec<RgbCandidateDecision>,
    detections: Vec<RgbDetection>,
}
#[allow(clippy::too_many_arguments)]
fn decode_head(
    shape: &[usize],
    values: &[f32],
    g: ResizeGeometry,
    allowed: &[u8],
    mask: [u8; 32],
    contract: &RgbDetectionContract,
    budget: &mut RgbDetectionBudget,
    cx: &ScalarExecCx,
) -> Result<Parts, RgbDetectionError> {
    budget.charge(1, cx)?;
    let s = &contract.spec;
    let fields = 4 + usize::from(s.objectness.is_some()) + s.labels.len();
    if shape.len() != 3 || shape[0] != 1 {
        return Err(RgbDetectionError::InvalidOutput);
    }
    let (rows, width) = match s.layout {
        HeadLayout::Rows => (shape[1], shape[2]),
        HeadLayout::Channels => (shape[2], shape[1]),
    };
    if width != fields {
        return Err(RgbDetectionError::InvalidOutput);
    }
    if rows > s.maximum_rows {
        return Err(RgbDetectionError::Limit);
    }
    if rows * fields != values.len() || !valid_geometry(g) {
        return Err(RgbDetectionError::InvalidOutput);
    }
    let pixels = g.source_width * g.source_height;
    if allowed.len() != pixels {
        return Err(RgbDetectionError::MaskMismatch);
    }
    let prefix_len = (g.source_width + 1) * (g.source_height + 1);
    let scratch = prefix_len * 4
        + rows * std::mem::size_of::<HeadRowDecision>()
        + s.maximum_candidates
            * (std::mem::size_of::<RgbDetection>() + std::mem::size_of::<RgbCandidateDecision>())
        + s.maximum_detections * std::mem::size_of::<RgbDetection>();
    if scratch > budget.maximum_scratch_bytes {
        return Err(RgbDetectionError::Limit);
    }
    budget.charge(pixels as u64, cx)?;
    if ContentDigest::sha256(allowed).bytes() != mask {
        return Err(RgbDetectionError::MaskMismatch);
    }
    let prefix = permission_prefix(allowed, g.source_width, g.source_height, budget, cx)?;
    let mut decisions = reserve(rows)?;
    let mut proposed = reserve(s.maximum_candidates)?;
    for row in 0..rows {
        budget.charge(64 + fields as u64 * 32, cx)?;
        let at = |field: usize| {
            values[match s.layout {
                HeadLayout::Rows => row * fields + field,
                HeadLayout::Channels => field * rows + row,
            }]
        };
        let raw = [at(0), at(1), at(2), at(3)];
        let bounds = model_box(raw, s.boxes, g)?;
        let objectness = match s.objectness {
            Some(rule) => probability(at(4), rule)?,
            None => 1.0,
        };
        let offset = 4 + usize::from(s.objectness.is_some());
        let mut scores = [0.0_f32; MAX_CLASSES];
        let mut best = 0;
        let mut best_score = -1.0;
        for (class, slot) in scores.iter_mut().enumerate().take(s.labels.len()) {
            *slot = objectness * probability(at(offset + class), s.class_score)?;
            if *slot > best_score {
                best = class;
                best_score = *slot;
            }
        }
        let passes = |class: usize| {
            (s.classes == HeadClasses::MultiLabel || class == best)
                && f64::from(scores[class]) * 1_000_000.0 >= f64::from(s.minimum_score_ppm)
        };
        let selected = (0..s.labels.len()).filter(|&c| passes(c)).count();
        let disposition = if selected == 0 {
            HeadRowDisposition::BelowThreshold
        } else if let Some(mapped) = g.source_box(bounds) {
            let q = f64::from(BOX_SUBPIXELS);
            let b = [
                (mapped[0] * q).floor() as u32,
                (mapped[1] * q).floor() as u32,
                (mapped[2] * q).ceil() as u32,
                (mapped[3] * q).ceil() as u32,
            ];
            if !fully_allowed(&prefix, g.source_width, b) {
                HeadRowDisposition::PrivateFootprint
            } else {
                let clipped = bounds[0] < g.left as f64
                    || bounds[1] < g.top as f64
                    || bounds[2] > (g.left + g.image_width) as f64
                    || bounds[3] > (g.top + g.image_height) as f64;
                if proposed.len() + selected > s.maximum_candidates {
                    return Err(RgbDetectionError::Limit);
                }
                for (class, score) in scores.iter().copied().enumerate().take(s.labels.len()) {
                    if passes(class) {
                        proposed.push(RgbDetection {
                            row,
                            class_index: class,
                            score,
                            bounds: b,
                            clipped,
                        });
                    }
                }
                HeadRowDisposition::Candidates(selected)
            }
        } else {
            HeadRowDisposition::OutsideImage
        };
        decisions.push(HeadRowDecision { row, disposition });
    }
    // Total ordering removes platform-dependent equal-score permutations. Unstable
    // sorting requires no auxiliary candidate-sized allocation; work is reserved first.
    budget.charge((proposed.len() as u64).pow(2) + 1, cx)?;
    proposed.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then(a.row.cmp(&b.row))
            .then(a.class_index.cmp(&b.class_index))
    });
    let mut candidates: Vec<RgbCandidateDecision> = reserve(proposed.len())?;
    let mut detections = reserve(s.maximum_detections)?;
    for detection in proposed {
        let mut suppressed_by = None;
        for (i, prior) in candidates.iter().enumerate() {
            budget.charge(1, cx)?;
            if prior.suppressed_by.is_none()
                && prior.detection.class_index == detection.class_index
                && suppresses(prior.detection.bounds, detection.bounds, s.nms_iou_ppm)
            {
                suppressed_by = Some(i);
                break;
            }
        }
        if suppressed_by.is_none() {
            if detections.len() == s.maximum_detections {
                return Err(RgbDetectionError::Limit);
            }
            detections.push(detection);
        }
        candidates.push(RgbCandidateDecision {
            detection,
            suppressed_by,
        });
    }
    budget.charge(0, cx)?;
    Ok(Parts {
        rows: decisions,
        candidates,
        detections,
    })
}
fn valid_geometry(g: ResizeGeometry) -> bool {
    [
        g.source_width,
        g.source_height,
        g.target_width,
        g.target_height,
    ]
    .iter()
    .all(|n| (1..=4096).contains(n))
        && g.source_width * g.source_height <= 4_194_304
        && g.image_width > 0
        && g.image_height > 0
        && g.left
            .checked_add(g.image_width)
            .is_some_and(|n| n <= g.target_width)
        && g.top
            .checked_add(g.image_height)
            .is_some_and(|n| n <= g.target_height)
}
fn probability(v: f32, rule: HeadScore) -> Result<f32, RgbDetectionError> {
    if !v.is_finite() {
        return Err(RgbDetectionError::InvalidOutput);
    }
    let score = match rule {
        HeadScore::Probability => v,
        HeadScore::Logit => deterministic_sigmoid_f32(v),
    };
    if !(0.0..=1.0).contains(&score) {
        return Err(RgbDetectionError::InvalidOutput);
    }
    Ok(if score == 0.0 { 0.0 } else { score })
}
fn model_box(
    raw: [f32; 4],
    encoding: HeadBoxes,
    g: ResizeGeometry,
) -> Result<[f64; 4], RgbDetectionError> {
    if raw.iter().any(|v| !v.is_finite()) {
        return Err(RgbDetectionError::InvalidOutput);
    }
    let mut b = raw.map(f64::from);
    if matches!(
        encoding,
        HeadBoxes::NormalizedCorners | HeadBoxes::NormalizedCenterSize
    ) {
        b[0] *= g.target_width as f64;
        b[2] *= g.target_width as f64;
        b[1] *= g.target_height as f64;
        b[3] *= g.target_height as f64;
    }
    if matches!(
        encoding,
        HeadBoxes::PixelCenterSize | HeadBoxes::NormalizedCenterSize
    ) {
        if b[2] <= 0.0 || b[3] <= 0.0 {
            return Err(RgbDetectionError::InvalidOutput);
        }
        b = [
            b[0] - b[2] * 0.5,
            b[1] - b[3] * 0.5,
            b[0] + b[2] * 0.5,
            b[1] + b[3] * 0.5,
        ];
    }
    if b[0] >= b[2] || b[1] >= b[3] {
        return Err(RgbDetectionError::InvalidOutput);
    }
    Ok(b)
}
fn reserve<T>(n: usize) -> Result<Vec<T>, RgbDetectionError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| RgbDetectionError::Limit)?;
    Ok(v)
}
fn permission_prefix(
    allowed: &[u8],
    w: usize,
    h: usize,
    budget: &mut RgbDetectionBudget,
    cx: &ScalarExecCx,
) -> Result<Vec<u32>, RgbDetectionError> {
    let stride = w + 1;
    let count = stride * (h + 1);
    budget.charge(count as u64, cx)?;
    let mut prefix = reserve(count)?;
    prefix.resize(count, 0_u32);
    for y in 0..h {
        budget.charge(w as u64 * 4, cx)?;
        let mut sum = 0;
        for x in 0..w {
            let v = allowed[y * w + x];
            if v > 1 {
                return Err(RgbDetectionError::MaskMismatch);
            }
            sum += u32::from(v);
            prefix[(y + 1) * stride + x + 1] = prefix[y * stride + x + 1] + sum;
        }
    }
    Ok(prefix)
}
fn fully_allowed(prefix: &[u32], w: usize, b: [u32; 4]) -> bool {
    let stride = w + 1;
    let [x0, y0, x1, y1] = [
        b[0] / BOX_SUBPIXELS,
        b[1] / BOX_SUBPIXELS,
        b[2].div_ceil(BOX_SUBPIXELS),
        b[3].div_ceil(BOX_SUBPIXELS),
    ]
    .map(|v| v as usize);
    let count = prefix[y1 * stride + x1] + prefix[y0 * stride + x0]
        - prefix[y0 * stride + x1]
        - prefix[y1 * stride + x0];
    count as usize == (x1 - x0) * (y1 - y0)
}
fn suppresses(a: [u32; 4], b: [u32; 4], threshold: u32) -> bool {
    let area = |r: [u32; 4]| u64::from(r[2] - r[0]) * u64::from(r[3] - r[1]);
    let intersection = u64::from(a[2].min(b[2]).saturating_sub(a[0].max(b[0])))
        * u64::from(a[3].min(b[3]).saturating_sub(a[1].max(b[1])));
    let union = area(a) + area(b) - intersection;
    u128::from(intersection) * 1_000_000 > u128::from(union) * u128::from(threshold)
}

/// Native JPEG inference ownership with exact postprocessing resume and retirement.
pub mod pipeline;

#[cfg(test)]
mod tests;
