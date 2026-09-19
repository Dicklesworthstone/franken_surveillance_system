#![forbid(unsafe_code)]
//! Bounded frame-to-frame pixel-change measurements over verified recorded luma.
//!
//! This is a cheap perception gate, not a person detector or a calibrated threat policy.
//! A negative result means only that these two images did not cross the supplied thresholds.
//! Missing coverage, recording changes and decoder/geometry changes reset the baseline instead
//! of manufacturing zero motion. Every measurement names its exact decoded evidence roots.

use std::collections::BTreeSet;
use std::fmt;
use fss_core::{CanonicalEncode, CanonicalEncoder, CaptureInterval, CapsuleId, ContentDigest};
use crate::ReplayCx;
use super::recorded_decode::{ComponentInterpretation, RecordedFrame};

/// Caller-selected measurement thresholds; no calibration or learned policy is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelChangeConfig {
    /// A sample changes when its absolute luma difference is at least this nonzero value.
    pub minimum_delta: u8,
    /// Minimum count of changed samples required for a candidate, in addition to the fraction.
    pub minimum_changed_pixels: u64,
    /// Minimum changed fraction in parts per million; checked by exact integer cross-products.
    pub minimum_changed_fraction_ppm: u32,
}
impl PixelChangeConfig {
    /// Checks bounded, non-degenerate thresholds before accepting any image.
    pub fn validate(self) -> Result<(), PixelChangeError> {
        if self.minimum_delta == 0 || self.minimum_changed_pixels == 0
            || self.minimum_changed_pixels > 4_194_304 || self.minimum_changed_fraction_ppm > 1_000_000
        { return Err(PixelChangeError::InvalidConfig); }
        Ok(())
    }
    /// Identity of the exact threshold configuration, not an effect-authorizing policy.
    #[must_use]
    pub fn digest(self) -> ContentDigest { self.canonical_digest("fss.pixel_change_config.v1") }
}
impl CanonicalEncode for PixelChangeConfig {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u8(self.minimum_delta); e.u64(self.minimum_changed_pixels); e.u32(self.minimum_changed_fraction_ppm);
    }
}

/// Why no comparison was made. Multiple simultaneous invalidators are preserved.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PixelChangeReset {
    /// No image has established a baseline in this detector instance.
    NoPredecessor,
    /// A different immutable recording was selected; continuity is not inferred between imports.
    RecordingChanged,
    /// Sensor or stream generation differs.
    SourceChanged,
    /// A source gap or nonconsecutive segment/sequence interrupts the pair.
    SourceGap,
    /// Coded image dimensions changed.
    DimensionsChanged,
    /// Decoder identity or source component interpretation changed.
    InterpretationChanged,
}
impl PixelChangeReset {
    /// Stable non-disclosing reason for an unperformed comparison.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoPredecessor => "no_predecessor", Self::RecordingChanged => "recording_changed",
            Self::SourceChanged => "source_changed", Self::SourceGap => "source_gap",
            Self::DimensionsChanged => "dimensions_changed", Self::InterpretationChanged => "interpretation_changed",
        }
    }
}

/// Half-open coded-image bounds containing all above-threshold samples; not an object box.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelChangeBounds {
    /// Left inclusive column.
    pub left: u32,
    /// Top inclusive row.
    pub top: u32,
    /// Right exclusive column.
    pub right: u32,
    /// Bottom exclusive row.
    pub bottom: u32,
}

/// Measured differences for one complete comparable pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PixelChangeStatistics {
    /// Number of compared pixels.
    pub compared_pixels: u64,
    /// Samples whose absolute difference meets the configured threshold.
    pub changed_pixels: u64,
    /// Sum of all absolute sample differences, including subthreshold differences.
    pub absolute_difference_sum: u64,
    /// Largest absolute sample difference.
    pub maximum_difference: u8,
    /// Bounding rectangle over changed samples, or none when the changed set is empty.
    pub changed_bounds: Option<PixelChangeBounds>,
    /// Whether both configured count and exact fraction thresholds were met.
    pub candidate: bool,
}

/// Derived measurement, never a coverage witness, event adjudication or alert authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PixelChangeObservation {
    /// Exact current decoded publication, with retained source and codec provenance.
    pub frame_root: ContentDigest,
    /// Exact predecessor actually compared; absent on a baseline reset.
    pub predecessor_root: Option<ContentDigest>,
    /// Original source capsule identity.
    pub capsule_id: CapsuleId,
    /// Original conservative capture interval, not a reconstructed frame timestamp.
    pub capture: CaptureInterval,
    /// Exact threshold configuration used.
    pub configuration_digest: ContentDigest,
    /// All reasons no comparison was admissible.
    pub reset_reasons: BTreeSet<PixelChangeReset>,
    /// Absent for a reset, never coerced to a zero-change measurement.
    pub statistics: Option<PixelChangeStatistics>,
}

/// Explicit detector refusals. Failed pushes never advance the previous-frame baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelChangeError {
    /// Thresholds are invalid.
    InvalidConfig,
    /// Input length or dimensions violate the canonical luma bounds.
    InvalidImage,
    /// The same recording was read backwards or a segment was substituted at the same position.
    OutOfOrder,
    /// The cumulative pixel-comparison ceiling would be exceeded.
    BudgetExceeded,
    /// Owner cancellation was observed; partial comparison statistics are not returned.
    Cancelled,
}
impl fmt::Display for PixelChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid pixel-change thresholds",
            Self::InvalidImage => "invalid pixel-change image bounds",
            Self::OutOfOrder => "pixel-change source is out of order",
            Self::BudgetExceeded => "pixel-change comparison budget exhausted",
            Self::Cancelled => "pixel-change comparison cancelled",
        })
    }
}
impl std::error::Error for PixelChangeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Basis {
    import: ContentDigest, segment: u64, sequence: u64, sensor: String, stream: String,
    gap: bool, dimensions: [u32; 2], decoder: [u8; 32], interpretation: ComponentInterpretation,
}
impl Basis {
    fn of(frame: &RecordedFrame) -> Self {
        let receipt = frame.receipt();
        let capsule = receipt.capsule();
        Self {
            import: receipt.import_identity(), segment: receipt.segment_index(), sequence: capsule.sequence,
            sensor: capsule.sensor_id.as_str().to_owned(), stream: capsule.stream_id.as_str().to_owned(),
            gap: capsule.gap_before, dimensions: receipt.dimensions(), decoder: receipt.codec().decoder,
            interpretation: receipt.codec().interpretation,
        }
    }
}
fn resets(previous: Option<&Basis>, current: &Basis) -> BTreeSet<PixelChangeReset> {
    let mut result = BTreeSet::new();
    let Some(previous) = previous else {
        result.insert(PixelChangeReset::NoPredecessor);
        if current.gap { result.insert(PixelChangeReset::SourceGap); }
        return result;
    };
    if previous.import != current.import { result.insert(PixelChangeReset::RecordingChanged); }
    if previous.sensor != current.sensor || previous.stream != current.stream { result.insert(PixelChangeReset::SourceChanged); }
    if current.gap || previous.segment.checked_add(1) != Some(current.segment)
        || previous.sequence.checked_add(1) != Some(current.sequence)
    { result.insert(PixelChangeReset::SourceGap); }
    if previous.dimensions != current.dimensions { result.insert(PixelChangeReset::DimensionsChanged); }
    if previous.decoder != current.decoder || previous.interpretation != current.interpretation {
        result.insert(PixelChangeReset::InterpretationChanged);
    }
    result
}

/// Streaming cheap-perception gate. Retains at most one prior bounded luma image and one result.
/// Duplicate delivery of the same frame is idempotent; comparison work is charged cumulatively.
#[derive(Debug)]
pub struct PixelChangeDetector {
    config: PixelChangeConfig,
    maximum_comparisons: u64,
    used: u64,
    previous: Option<RecordedFrame>,
    last_observation: Option<PixelChangeObservation>,
}
impl PixelChangeDetector {
    /// Creates a detector with explicit thresholds and a cumulative comparison allowance.
    pub fn new(config: PixelChangeConfig, maximum_comparisons: u64) -> Result<Self, PixelChangeError> {
        config.validate()?;
        Ok(Self { config, maximum_comparisons, used: 0, previous: None, last_observation: None })
    }
    /// Pixel comparisons actually charged, including rows processed before a cancellation.
    #[must_use]
    pub fn comparisons_used(&self) -> u64 { self.used }
    /// Remaining cumulative allowance; not reset by gaps or recording changes.
    #[must_use]
    pub fn comparisons_remaining(&self) -> u64 { self.maximum_comparisons - self.used }
    /// Accepts a verified frame. Comparisons stop at every row on owner cancellation.
    /// A gap resets the baseline and returns an explicit unmeasured state, not `candidate=false`.
    pub fn push(&mut self, frame: &RecordedFrame, cx: &ReplayCx) -> Result<PixelChangeObservation, PixelChangeError> {
        let mut check = || cx.checkpoint("pixel_change:row").map_err(|_| PixelChangeError::Cancelled);
        check()?;
        if self.previous.as_ref().is_some_and(|previous| previous == frame) {
            return self.last_observation.clone().ok_or(PixelChangeError::InvalidImage);
        }
        let current_basis = Basis::of(frame);
        let previous_basis = self.previous.as_ref().map(Basis::of);
        if previous_basis.as_ref().is_some_and(|previous| previous.import == current_basis.import
            && current_basis.segment <= previous.segment)
        { return Err(PixelChangeError::OutOfOrder); }
        let reset_reasons = resets(previous_basis.as_ref(), &current_basis);
        let mut predecessor_root = None;
        let statistics = if reset_reasons.is_empty() {
            let previous = self.previous.as_ref().ok_or(PixelChangeError::InvalidImage)?;
            predecessor_root = Some(previous.publication_root());
            Some(compare_pixels(previous.pixels(), frame.pixels(), current_basis.dimensions,
                self.config, self.maximum_comparisons, &mut self.used, &mut check)?)
        } else { None };
        check()?;
        let observation = PixelChangeObservation {
            frame_root: frame.publication_root(), predecessor_root,
            capsule_id: frame.receipt().capsule().capsule_id.clone(),
            capture: frame.receipt().capsule().capture, configuration_digest: self.config.digest(),
            reset_reasons, statistics,
        };
        self.previous = Some(frame.clone());
        self.last_observation = Some(observation.clone());
        Ok(observation)
    }
}

fn compare_pixels(
    previous: &[u8], current: &[u8], dimensions: [u32; 2], config: PixelChangeConfig,
    maximum: u64, used: &mut u64, check: &mut impl FnMut() -> Result<(), PixelChangeError>,
) -> Result<PixelChangeStatistics, PixelChangeError> {
    config.validate()?;
    let [width, height] = dimensions;
    let count = u64::from(width) * u64::from(height);
    if width == 0 || height == 0 || width > 4096 || height > 4096 || count > 4_194_304
        || previous.len() as u64 != count || current.len() as u64 != count
    { return Err(PixelChangeError::InvalidImage); }
    if used.checked_add(count).is_none_or(|next| next > maximum) { return Err(PixelChangeError::BudgetExceeded); }
    let mut changed = 0_u64;
    let mut sum = 0_u64;
    let mut maximum_difference = 0_u8;
    let mut bounds: Option<PixelChangeBounds> = None;
    for row in 0..height {
        check()?;
        *used += u64::from(width);
        let start = row as usize * width as usize;
        for column in 0..width {
            let index = start + column as usize;
            let delta = previous[index].abs_diff(current[index]);
            sum += u64::from(delta);
            maximum_difference = maximum_difference.max(delta);
            if delta < config.minimum_delta { continue; }
            changed += 1;
            match &mut bounds {
                Some(bounds) => {
                    bounds.left = bounds.left.min(column); bounds.top = bounds.top.min(row);
                    bounds.right = bounds.right.max(column + 1); bounds.bottom = bounds.bottom.max(row + 1);
                }
                None => bounds = Some(PixelChangeBounds { left: column, top: row, right: column + 1, bottom: row + 1 }),
            }
        }
    }
    Ok(PixelChangeStatistics {
        compared_pixels: count, changed_pixels: changed, absolute_difference_sum: sum,
        maximum_difference, changed_bounds: bounds,
        candidate: changed >= config.minimum_changed_pixels
            && changed * 1_000_000 >= count * u64::from(config.minimum_changed_fraction_ppm),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn config() -> PixelChangeConfig {
        PixelChangeConfig { minimum_delta: 20, minimum_changed_pixels: 2, minimum_changed_fraction_ppm: 333_333 }
    }
    #[test]
    fn exact_threshold_counts_bounds_and_fraction() -> TestResult {
        let previous = [10; 6]; let current = [10, 30, 10, 10, 10, 50]; let mut used = 0;
        let measured = compare_pixels(&previous, &current, [3, 2], config(), 6, &mut used, &mut || Ok(()))?;
        assert_eq!(measured.changed_pixels, 2); assert_eq!(measured.absolute_difference_sum, 60);
        assert_eq!(measured.maximum_difference, 40); assert!(measured.candidate); assert_eq!(used, 6);
        assert_eq!(measured.changed_bounds, Some(PixelChangeBounds { left: 1, top: 0, right: 3, bottom: 2 }));
        let stricter = PixelChangeConfig { minimum_changed_fraction_ppm: 333_334, ..config() };
        assert!(!compare_pixels(&previous, &current, [3, 2], stricter, 6, &mut 0, &mut || Ok(()))?.candidate);
        Ok(())
    }
    #[test]
    fn unchanged_images_have_measured_zero_not_a_reset() -> TestResult {
        let measured = compare_pixels(&[7; 6], &[7; 6], [3, 2], config(), 6, &mut 0, &mut || Ok(()))?;
        assert_eq!(measured.changed_pixels, 0); assert_eq!(measured.changed_bounds, None); assert!(!measured.candidate);
        Ok(())
    }
    #[test]
    fn cumulative_budget_refuses_before_work_and_counts_cancelled_rows() {
        let mut used = 1;
        assert_eq!(compare_pixels(&[0; 6], &[255; 6], [3, 2], config(), 6, &mut used, &mut || Ok(())), Err(PixelChangeError::BudgetExceeded));
        assert_eq!(used, 1);
        let mut rows = 0;
        let mut check = || { rows += 1; if rows == 2 { Err(PixelChangeError::Cancelled) } else { Ok(()) } };
        assert_eq!(compare_pixels(&[0; 6], &[255; 6], [3, 2], config(), 20, &mut used, &mut check), Err(PixelChangeError::Cancelled));
        assert_eq!(used, 4);
    }
    #[test]
    fn malformed_dimensions_and_degenerate_thresholds_fail() {
        for dimensions in [[0, 1], [1, 0], [4097, 1], [2, 2]] {
            assert_eq!(compare_pixels(&[0], &[0], dimensions, config(), 10, &mut 0, &mut || Ok(())), Err(PixelChangeError::InvalidImage));
        }
        assert!(PixelChangeDetector::new(PixelChangeConfig { minimum_delta: 0, ..config() }, 100).is_err());
        assert!(PixelChangeDetector::new(PixelChangeConfig { minimum_changed_pixels: 0, ..config() }, 100).is_err());
        assert!(PixelChangeDetector::new(PixelChangeConfig { minimum_changed_fraction_ppm: 1_000_001, ..config() }, 100).is_err());
    }
    fn basis() -> Basis {
        Basis { import: ContentDigest::sha256(b"import"), segment: 0, sequence: 0,
            sensor: "sensor:a".to_owned(), stream: "stream:a".to_owned(), gap: false,
            dimensions: [3, 2], decoder: [1; 32], interpretation: ComponentInterpretation::Grayscale }
    }
    #[test]
    fn gaps_and_all_simultaneous_invalidations_are_retained() {
        let previous = basis(); let mut current = previous.clone(); current.segment = 1; current.sequence = 1;
        assert!(resets(Some(&previous), &current).is_empty());
        current.gap = true; current.dimensions = [2, 3]; current.decoder = [2; 32];
        current.sensor = "sensor:b".to_owned(); current.import = ContentDigest::sha256(b"other import");
        assert_eq!(resets(Some(&previous), &current), BTreeSet::from([
            PixelChangeReset::RecordingChanged, PixelChangeReset::SourceChanged,
            PixelChangeReset::SourceGap, PixelChangeReset::DimensionsChanged, PixelChangeReset::InterpretationChanged,
        ]));
        assert_eq!(resets(None, &current), BTreeSet::from([PixelChangeReset::NoPredecessor, PixelChangeReset::SourceGap]));
    }
    #[test]
    fn skipped_and_overflowing_sequence_never_imply_continuity() {
        let previous = basis(); let mut current = previous.clone(); current.segment = 2; current.sequence = 2;
        assert!(resets(Some(&previous), &current).contains(&PixelChangeReset::SourceGap));
        let mut previous = previous; previous.segment = u64::MAX; previous.sequence = u64::MAX;
        current.segment = 0; current.sequence = 0;
        assert!(resets(Some(&previous), &current).contains(&PixelChangeReset::SourceGap));
    }
}
