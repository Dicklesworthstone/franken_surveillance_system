#![forbid(unsafe_code)]
//! Explicit detector-output interpretation over retained, exact model runs.
//!
//! Rows are [x1,y1,x2,y2,score,class] or [cx,cy,width,height,score,class], as declared
//! by the operator, never inferred from tensor values. Labels and scores are uncalibrated
//! model proposals. An empty result is not absence, identity, coverage, or effect authority.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use super::inference::RecordedInference;
use super::recorded_decode::{RecordedDecodeRequest, RecordedFrame};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor,
    SensorCapsule,
};

/// Coordinates are outward-rounded onto this many subpixels per coded-image pixel.
pub const BOX_SUBPIXELS: u32 = 256;
/// Maximum rows examined in one complete detector output.
pub const MAX_DETECTION_ROWS: usize = 4096;
/// Maximum returned proposals; excess is an explicit refusal, never a hidden top-k cut.
pub const MAX_DETECTIONS: usize = 256;

/// Explicit row-coordinate representation, not an inferred model-family convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoxEncoding {
    /// Half-open left, top, right, bottom boundaries.
    Xyxy,
    /// Center x, center y, width, height.
    CenterSize,
}

/// Coordinate units before the recorded subpixel quantization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinateSpace {
    /// Coded image pixels, before any orientation or calibration transform.
    Pixels,
    /// Unit interval relative to the full coded image; no letterbox or crop reversal.
    Normalized,
}

/// Parameters for an exact model-output contract.
#[derive(Clone, Debug)]
pub struct DetectionSpec {
    /// Independently chosen immutable model object, including weights and preprocessing.
    pub model_digest: ContentDigest,
    /// One F32 output port with shape [N,6] or [1,N,6].
    pub output_port: String,
    /// Ordered, unique class labels; the sixth field is an integer index into this table.
    pub labels: Vec<String>,
    /// Interpretation of the first four fields.
    pub encoding: BoxEncoding,
    /// Units of the first four fields.
    pub coordinates: CoordinateSpace,
    /// Inclusive score threshold in millionths, applied to scores already in [0,1].
    pub minimum_score_ppm: u32,
    /// Class-aware suppression when quantized-box IoU is strictly greater than this fraction.
    pub nms_iou_ppm: u32,
    /// Row admission ceiling; cannot exceed MAX_DETECTION_ROWS.
    pub maximum_rows: usize,
    /// Survivor admission ceiling; cannot exceed MAX_DETECTIONS.
    pub maximum_detections: usize,
}

/// Immutable output interpretation and suppression policy. This is not model admission.
#[derive(Clone, Debug)]
pub struct DetectionContract {
    spec: DetectionSpec,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

/// Typed non-disclosing failure. No error returns a partial set of proposals.
#[derive(Debug)]
pub enum DetectionError {
    /// Missing or ambiguous model, output, label or threshold contract.
    InvalidContract,
    /// Wrong tensor shape, malformed row, nonfinite number, range or class index.
    InvalidOutput,
    /// A hard or caller-supplied bound would be exceeded.
    Limit,
    /// Cumulative owner work allowance is exhausted.
    BudgetExceeded,
    /// The existing owner context was cancelled.
    Cancelled,
    /// Canonical encoding failed.
    Contract(ContractError),
    /// Retained evidence could not be recovered or validated.
    Source(Box<dyn Error>),
}
impl fmt::Display for DetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidContract => "invalid detector output contract",
            Self::InvalidOutput => "model output does not satisfy detector contract",
            Self::Limit => "detector bound exceeded",
            Self::BudgetExceeded => "detector work budget exhausted",
            Self::Cancelled => "detector owner cancelled",
            Self::Contract(_) => "invalid detector canonical encoding",
            Self::Source(_) => "retained detector source unavailable",
        })
    }
}
impl Error for DetectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(e) => Some(e),
            Self::Source(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<ContractError> for DetectionError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
fn source_error<E: Error + 'static>(error: E) -> DetectionError {
    DetectionError::Source(Box::new(error))
}
fn checkpoint(cx: &ReplayCx) -> Result<(), DetectionError> {
    cx.checkpoint("recorded_detections:work")
        .map_err(|_| DetectionError::Cancelled)
}

impl DetectionContract {
    /// Freezes the exact model/output interpretation, including all selection limits.
    pub fn new(spec: DetectionSpec) -> Result<Self, DetectionError> {
        let valid_name = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        };
        if spec.model_digest.algorithm() != DigestAlgorithm::Sha256
            || !valid_name(&spec.output_port)
            || spec.labels.is_empty()
            || spec.labels.len() > 256
            || spec.labels.iter().any(|label| !valid_name(label))
            || spec.labels.iter().collect::<BTreeSet<_>>().len() != spec.labels.len()
            || spec.minimum_score_ppm > 1_000_000
            || spec.nms_iou_ppm > 1_000_000
            || spec.maximum_rows == 0
            || spec.maximum_rows > MAX_DETECTION_ROWS
            || spec.maximum_detections == 0
            || spec.maximum_detections > MAX_DETECTIONS
        {
            return Err(DetectionError::InvalidContract);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.recorded_detection_contract.v1");
        e.digest(spec.model_digest);
        e.text(&spec.output_port);
        e.u64(spec.labels.len() as u64);
        for label in &spec.labels {
            e.text(label);
        }
        e.u8(match spec.encoding {
            BoxEncoding::Xyxy => 0,
            BoxEncoding::CenterSize => 1,
        });
        e.u8(match spec.coordinates {
            CoordinateSpace::Pixels => 0,
            CoordinateSpace::Normalized => 1,
        });
        e.u32(BOX_SUBPIXELS);
        e.u32(spec.minimum_score_ppm);
        e.u32(spec.nms_iou_ppm);
        e.u64(spec.maximum_rows as u64);
        e.u64(spec.maximum_detections as u64);
        let bytes = e.finish_checked()?;
        Ok(Self {
            digest: ContentDigest::sha256(&bytes),
            spec,
            bytes,
        })
    }
    /// Complete immutable policy identity; labels and thresholds are not ambient settings.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Canonical contract bytes for a proof-bearing report.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    /// Ordered output class labels; none constitutes physical identity.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.spec.labels
    }
}

/// A caller-owned cumulative allowance shared across frame projections.
#[derive(Debug)]
pub struct DetectionBudget {
    remaining: u64,
    used: u64,
}
impl DetectionBudget {
    /// One unit per row validated and per same-class IoU comparison, including failed work.
    #[must_use]
    pub fn new(units: u64) -> Self {
        Self {
            remaining: units,
            used: 0,
        }
    }
    /// Units consumed so far. Retrying does not restore these units.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }
    /// Remaining owner-granted units.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    fn charge(&mut self) -> Result<(), DetectionError> {
        if self.remaining == 0 {
            return Err(DetectionError::BudgetExceeded);
        }
        self.remaining -= 1;
        self.used += 1;
        Ok(())
    }
}

/// Half-open coded-image bounds at 1/256 pixel precision, with positive area.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuantizedBox {
    coordinates: [u32; 4],
}
impl QuantizedBox {
    /// Left, top, right, bottom in BOX_SUBPIXELS units per coded-image pixel.
    #[must_use]
    pub fn coordinates(&self) -> [u32; 4] {
        self.coordinates
    }
    fn area(self) -> u64 {
        u64::from(self.coordinates[2] - self.coordinates[0])
            * u64::from(self.coordinates[3] - self.coordinates[1])
    }
    fn overlap(self, other: Self) -> (u64, u64) {
        let a = self.coordinates;
        let b = other.coordinates;
        let width = a[2].min(b[2]).saturating_sub(a[0].max(b[0]));
        let height = a[3].min(b[3]).saturating_sub(a[1].max(b[1]));
        let intersection = u64::from(width) * u64::from(height);
        (intersection, self.area() + other.area() - intersection)
    }
}

/// One uncalibrated detector proposal, preserving its original tensor row.
#[derive(Clone, Debug, PartialEq)]
pub struct Detection {
    row: usize,
    class_index: usize,
    score: f32,
    bounds: QuantizedBox,
}
impl Detection {
    /// Stable source row, before filtering or suppression.
    #[must_use]
    pub fn row(&self) -> usize {
        self.row
    }
    /// Index into the contract's ordered labels.
    #[must_use]
    pub fn class_index(&self) -> usize {
        self.class_index
    }
    /// Uncalibrated original score, not probability of a real-world threat.
    #[must_use]
    pub fn score(&self) -> f32 {
        self.score
    }
    /// Quantized source-coordinate bounds, not a person identity or calibrated location.
    #[must_use]
    pub fn bounds(&self) -> QuantizedBox {
        self.bounds
    }
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.u64(self.row as u64);
        e.u64(self.class_index as u64);
        e.u32(self.score.to_bits());
        for value in self.bounds.coordinates {
            e.u32(value);
        }
    }
}

fn quantize(
    row: &[f32],
    spec: &DetectionSpec,
    dimensions: [u32; 2],
) -> Result<Detection, DetectionError> {
    if row.len() != 6
        || row.iter().any(|v| !v.is_finite())
        || !(0.0..=1.0).contains(&row[4])
        || row[5] < 0.0
        || row[5] >= spec.labels.len() as f32
        || row[5].fract() != 0.0
    {
        return Err(DetectionError::InvalidOutput);
    }
    let mut b = [
        f64::from(row[0]),
        f64::from(row[1]),
        f64::from(row[2]),
        f64::from(row[3]),
    ];
    if spec.encoding == BoxEncoding::CenterSize {
        if b[2] <= 0.0 || b[3] <= 0.0 {
            return Err(DetectionError::InvalidOutput);
        }
        b = [
            b[0] - b[2] / 2.0,
            b[1] - b[3] / 2.0,
            b[0] + b[2] / 2.0,
            b[1] + b[3] / 2.0,
        ];
    }
    if spec.coordinates == CoordinateSpace::Normalized {
        if b.iter().any(|v| !(0.0..=1.0).contains(v)) {
            return Err(DetectionError::InvalidOutput);
        }
        b[0] *= f64::from(dimensions[0]);
        b[2] *= f64::from(dimensions[0]);
        b[1] *= f64::from(dimensions[1]);
        b[3] *= f64::from(dimensions[1]);
    }
    if b[0] < 0.0
        || b[1] < 0.0
        || b[0] >= b[2]
        || b[1] >= b[3]
        || b[2] > f64::from(dimensions[0])
        || b[3] > f64::from(dimensions[1])
    {
        return Err(DetectionError::InvalidOutput);
    }
    let scale = f64::from(BOX_SUBPIXELS);
    let coordinates = [
        (b[0] * scale).floor() as u32,
        (b[1] * scale).floor() as u32,
        (b[2] * scale).ceil() as u32,
        (b[3] * scale).ceil() as u32,
    ];
    Ok(Detection {
        row: 0,
        class_index: row[5] as usize,
        score: if row[4] == 0.0 { 0.0 } else { row[4] },
        bounds: QuantizedBox { coordinates },
    })
}

fn decode_rows(
    contract: &DetectionContract,
    dimensions: [u32; 2],
    values: &[f32],
    budget: &mut DetectionBudget,
    mut check: impl FnMut() -> Result<(), DetectionError>,
) -> Result<(Vec<Detection>, usize, usize), DetectionError> {
    check()?;
    if dimensions.contains(&0)
        || dimensions.iter().any(|d| *d > 4096)
        || !values.len().is_multiple_of(6)
        || values.len() / 6 > contract.spec.maximum_rows
    {
        return Err(DetectionError::Limit);
    }
    let mut candidates = Vec::new();
    let mut below_threshold = 0;
    for (index, row) in values.as_chunks::<6>().0.iter().enumerate() {
        check()?;
        budget.charge()?;
        // Validate even rows that would be below threshold: malformed output is not no detection.
        let mut detection = quantize(row, &contract.spec, dimensions)?;
        detection.row = index;
        if f64::from(detection.score) * 1_000_000.0 < f64::from(contract.spec.minimum_score_ppm) {
            below_threshold += 1;
        } else {
            candidates.push(detection);
        }
    }
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.row.cmp(&b.row)));
    let mut selected: Vec<Detection> = Vec::new();
    let mut suppressed = 0;
    for candidate in candidates {
        check()?;
        let mut duplicate = false;
        for previous in &selected {
            if previous.class_index != candidate.class_index {
                continue;
            }
            check()?;
            budget.charge()?;
            let (intersection, union) = previous.bounds.overlap(candidate.bounds);
            if u128::from(intersection) * 1_000_000
                > u128::from(union) * u128::from(contract.spec.nms_iou_ppm)
            {
                duplicate = true;
                break;
            }
        }
        if duplicate {
            suppressed += 1;
        } else {
            if selected.len() == contract.spec.maximum_detections {
                return Err(DetectionError::Limit);
            }
            selected.push(candidate);
        }
    }
    check()?;
    Ok((selected, below_threshold, suppressed))
}

/// Complete, deterministic, proof-linked detector projection from one exact retained run.
/// Private fields prevent arbitrary tensor rows being passed to downstream tracking as evidence.
#[derive(Clone, Debug)]
pub struct DetectionFrame {
    contract: DetectionContract,
    run: ContentDigest,
    run_receipt: ContentDigest,
    output_digest: ContentDigest,
    frame_root: ContentDigest,
    frame_receipt: ContentDigest,
    anchor: LedgerAnchor,
    import_identity: ContentDigest,
    segment: u64,
    capsule: SensorCapsule,
    dimensions: [u32; 2],
    detections: Vec<Detection>,
    rows: usize,
    filtered: usize,
    suppressed: usize,
    work_units: u64,
}
impl DetectionFrame {
    /// Reads verified retained inference and frame objects without executing a model or changing authority.
    pub fn read(
        deployment: &ReferenceDeployment,
        run_id: ContentDigest,
        source: &RecordedDecodeRequest,
        contract: &DetectionContract,
        budget: &mut DetectionBudget,
        cx: &ReplayCx,
    ) -> Result<Self, DetectionError> {
        checkpoint(cx)?;
        let run = RecordedInference::open(deployment, run_id, source, cx).map_err(source_error)?;
        let frame = RecordedFrame::open(deployment, source, cx).map_err(source_error)?;
        Self::derive(&run, &frame, contract, budget, cx)
    }
    /// Projects immutable, already verified objects. Use `read` when current custody must be revalidated.
    pub fn derive(
        run: &RecordedInference,
        frame: &RecordedFrame,
        contract: &DetectionContract,
        budget: &mut DetectionBudget,
        cx: &ReplayCx,
    ) -> Result<Self, DetectionError> {
        checkpoint(cx)?;
        if run.frame_root() != frame.publication_root()
            || run.model().digest() != contract.spec.model_digest
        {
            return Err(DetectionError::InvalidContract);
        }
        let port = run
            .model()
            .graph()
            .find_output(&contract.spec.output_port)
            .ok_or(DetectionError::InvalidContract)?;
        let rows = match port.shape().dims() {
            [rows, 6] | [1, rows, 6] => *rows,
            _ => return Err(DetectionError::InvalidOutput),
        };
        let values = run
            .outputs()
            .get(&contract.spec.output_port)
            .ok_or(DetectionError::InvalidOutput)?;
        if rows > contract.spec.maximum_rows || rows.checked_mul(6) != Some(values.len()) {
            return Err(DetectionError::Limit);
        }
        let before = budget.used();
        let (detections, filtered, suppressed) = decode_rows(
            contract,
            frame.receipt().dimensions(),
            values,
            budget,
            || checkpoint(cx),
        )?;
        Ok(Self {
            contract: contract.clone(),
            run: run.identity(),
            run_receipt: ContentDigest::sha256(&run.receipt_bytes().map_err(source_error)?),
            output_digest: ContentDigest::sha256(run.output_bytes()),
            frame_root: frame.publication_root(),
            frame_receipt: frame.receipt().digest().map_err(source_error)?,
            anchor: run.authority_anchor().clone(),
            import_identity: frame.receipt().import_identity(),
            segment: frame.receipt().segment_index(),
            capsule: frame.receipt().capsule().clone(),
            dimensions: frame.receipt().dimensions(),
            rows,
            detections,
            filtered,
            suppressed,
            work_units: budget.used() - before,
        })
    }
    /// Deterministic internal projection bytes. This is a read result, not an authority commit or activation certificate.
    pub fn encoded(&self) -> Result<Vec<u8>, DetectionError> {
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSDETS1");
        e.u32(1);
        e.text("fss.recorded_detections.v1");
        e.bytes(self.contract.encoded());
        e.digest(self.run);
        e.digest(self.run_receipt);
        e.digest(self.output_digest);
        e.digest(self.frame_root);
        e.digest(self.frame_receipt);
        self.anchor.encode_canonical(&mut e);
        e.digest(self.import_identity);
        e.u64(self.segment);
        self.capsule.encode_canonical(&mut e);
        e.u32(self.dimensions[0]);
        e.u32(self.dimensions[1]);
        e.u64(self.rows as u64);
        e.u64(self.filtered as u64);
        e.u64(self.suppressed as u64);
        e.u64(self.work_units);
        e.u64(self.detections.len() as u64);
        for detection in &self.detections {
            detection.encode(&mut e);
        }
        Ok(e.finish_checked()?)
    }
    /// Identity of this complete source-linked projection.
    pub fn digest(&self) -> Result<ContentDigest, DetectionError> {
        Ok(ContentDigest::sha256(&self.encoded()?))
    }
    /// Surviving proposals in descending score order, with row-index tie breaks.
    #[must_use]
    pub fn detections(&self) -> &[Detection] {
        &self.detections
    }
    /// Frozen class/coordinate/threshold contract.
    #[must_use]
    pub fn contract(&self) -> &DetectionContract {
        &self.contract
    }
    /// Original conservative source metadata, not a newly inferred timestamp.
    #[must_use]
    pub fn capsule(&self) -> &SensorCapsule {
        &self.capsule
    }
    /// Source import identity.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Source segment index.
    #[must_use]
    pub fn segment_index(&self) -> u64 {
        self.segment
    }
    /// Coded image dimensions.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// Exact model invocation identity.
    #[must_use]
    pub fn run_identity(&self) -> ContentDigest {
        self.run
    }
    /// Exact decoded-frame publication root.
    #[must_use]
    pub fn frame_root(&self) -> ContentDigest {
        self.frame_root
    }
    /// Total input rows, below-threshold rows, and duplicate-suppressed rows.
    #[must_use]
    pub fn counts(&self) -> [usize; 3] {
        [self.rows, self.filtered, self.suppressed]
    }
    /// Deterministic work units for this projection, not elapsed time.
    #[must_use]
    pub fn work_units(&self) -> u64 {
        self.work_units
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn Error>>;
    fn spec() -> DetectionSpec {
        DetectionSpec {
            model_digest: ContentDigest::sha256(b"model"),
            output_port: "detections".into(),
            labels: vec!["vehicle".into(), "animal".into()],
            encoding: BoxEncoding::Xyxy,
            coordinates: CoordinateSpace::Pixels,
            minimum_score_ppm: 500_000,
            nms_iou_ppm: 500_000,
            maximum_rows: MAX_DETECTION_ROWS,
            maximum_detections: MAX_DETECTIONS,
        }
    }
    fn decode(values: &[f32]) -> Result<(Vec<Detection>, usize, usize), DetectionError> {
        decode_rows(
            &DetectionContract::new(spec())?,
            [100, 100],
            values,
            &mut DetectionBudget::new(1_000_000),
            || Ok(()),
        )
    }
    #[test]
    fn suppression_is_class_aware_and_ties_keep_original_row() -> TestResult {
        let (items, below, suppressed) = decode(&[
            0., 0., 10., 10., 0.9, 0., 0., 0., 10., 10., 0.9, 0., 0., 0., 10., 10., 0.9, 1., 20.,
            20., 30., 30., 0.1, 0.,
        ])?;
        assert_eq!((below, suppressed), (1, 1));
        assert_eq!(
            items.iter().map(Detection::row).collect::<Vec<_>>(),
            vec![0, 2]
        );
        Ok(())
    }
    #[test]
    fn nms_threshold_is_strict_and_score_threshold_inclusive() -> TestResult {
        let mut s = spec();
        s.nms_iou_ppm = 1_000_000;
        let (items, _, suppressed) = decode_rows(
            &DetectionContract::new(s)?,
            [100, 100],
            &[0., 0., 10., 10., 0.5, 0., 0., 0., 10., 10., 0.5, 0.],
            &mut DetectionBudget::new(10),
            || Ok(()),
        )?;
        assert_eq!(items.len(), 2);
        assert_eq!(suppressed, 0);
        Ok(())
    }
    #[test]
    fn touching_boxes_are_not_suppressed_at_zero_iou_threshold() -> TestResult {
        let mut s = spec();
        s.nms_iou_ppm = 0;
        let (items, _, _) = decode_rows(
            &DetectionContract::new(s)?,
            [100, 100],
            &[0., 0., 10., 10., 0.7, 0., 10., 0., 20., 10., 0.6, 0.],
            &mut DetectionBudget::new(10),
            || Ok(()),
        )?;
        assert_eq!(items.len(), 2);
        Ok(())
    }
    #[test]
    fn normalized_center_size_has_explicit_outward_quantization() -> TestResult {
        let mut s = spec();
        s.encoding = BoxEncoding::CenterSize;
        s.coordinates = CoordinateSpace::Normalized;
        let (items, _, _) = decode_rows(
            &DetectionContract::new(s)?,
            [100, 80],
            &[0.5, 0.5, 0.5, 0.5, 1., 1.],
            &mut DetectionBudget::new(10),
            || Ok(()),
        )?;
        assert_eq!(items[0].bounds().coordinates(), [6400, 5120, 19200, 15360]);
        Ok(())
    }
    #[test]
    fn invalid_rows_fail_even_below_score_threshold() {
        for (index, bad) in [
            (0, f32::NAN),
            (1, f32::INFINITY),
            (0, -1.),
            (2, 101.),
            (2, 0.),
            (4, 1.01),
            (5, 0.5),
            (5, 2.),
        ] {
            let mut row = [0., 0., 10., 10., 0.1, 0.];
            row[index] = bad;
            assert!(matches!(decode(&row), Err(DetectionError::InvalidOutput)));
        }
    }
    #[test]
    fn malformed_lengths_and_dimensions_are_refused() -> TestResult {
        let c = DetectionContract::new(spec())?;
        assert!(decode(&[0.; 5]).is_err());
        for dimensions in [[0, 100], [4097, 1]] {
            assert!(
                decode_rows(
                    &c,
                    dimensions,
                    &[],
                    &mut DetectionBudget::new(10),
                    || Ok(())
                )
                .is_err()
            );
        }
        Ok(())
    }
    #[test]
    fn capacity_never_silently_truncates_valid_detections() -> TestResult {
        let mut s = spec();
        s.maximum_detections = 1;
        let c = DetectionContract::new(s)?;
        assert!(matches!(
            decode_rows(
                &c,
                [100, 100],
                &[0., 0., 10., 10., 0.9, 0., 20., 20., 30., 30., 0.8, 0.],
                &mut DetectionBudget::new(10),
                || Ok(())
            ),
            Err(DetectionError::Limit)
        ));
        Ok(())
    }
    #[test]
    fn shared_budget_counts_validation_and_suppression_without_refunds() -> TestResult {
        let c = DetectionContract::new(spec())?;
        let mut b = DetectionBudget::new(3);
        let rows = [0., 0., 10., 10., 0.9, 0., 0., 0., 10., 10., 0.8, 0.];
        decode_rows(&c, [100, 100], &rows, &mut b, || Ok(()))?;
        assert_eq!(b.used(), 3);
        assert_eq!(b.remaining(), 0);
        assert!(matches!(
            decode_rows(&c, [100, 100], &rows, &mut b, || Ok(())),
            Err(DetectionError::BudgetExceeded)
        ));
        Ok(())
    }
    #[test]
    fn cancellation_never_returns_partial_detections() -> TestResult {
        let c = DetectionContract::new(spec())?;
        let mut checks = 0;
        let mut b = DetectionBudget::new(10);
        let result = decode_rows(
            &c,
            [100, 100],
            &[0., 0., 10., 10., 1., 0., 20., 20., 30., 30., 1., 0.],
            &mut b,
            || {
                checks += 1;
                if checks >= 3 {
                    Err(DetectionError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Err(DetectionError::Cancelled)));
        assert_eq!(b.used(), 1);
        Ok(())
    }
    #[test]
    fn empty_output_and_all_filtered_output_remain_distinct() -> TestResult {
        let (empty, below, _) = decode(&[])?;
        assert!(empty.is_empty());
        assert_eq!(below, 0);
        let (empty, below, _) = decode(&[0., 0., 10., 10., 0.1, 0.])?;
        assert!(empty.is_empty());
        assert_eq!(below, 1);
        Ok(())
    }
    #[test]
    fn contract_identity_binds_labels_model_and_thresholds() -> TestResult {
        let first = DetectionContract::new(spec())?.digest();
        let mut changed = spec();
        changed.labels.swap(0, 1);
        assert_ne!(DetectionContract::new(changed)?.digest(), first);
        let mut changed = spec();
        changed.model_digest = ContentDigest::sha256(b"other model");
        assert_ne!(DetectionContract::new(changed)?.digest(), first);
        let mut changed = spec();
        changed.minimum_score_ppm += 1;
        assert_ne!(DetectionContract::new(changed)?.digest(), first);
        Ok(())
    }
    #[test]
    fn invalid_contracts_are_not_normalized_silently() {
        let mut s = spec();
        s.labels[1] = s.labels[0].clone();
        assert!(DetectionContract::new(s).is_err());
        let mut s = spec();
        s.maximum_rows = 0;
        assert!(DetectionContract::new(s).is_err());
        let mut s = spec();
        s.minimum_score_ppm = 1_000_001;
        assert!(DetectionContract::new(s).is_err());
        let mut s = spec();
        s.labels[0] = "untrusted\nlabel".into();
        assert!(DetectionContract::new(s).is_err());
    }
}
