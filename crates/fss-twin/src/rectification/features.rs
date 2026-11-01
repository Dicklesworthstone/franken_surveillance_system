#![forbid(unsafe_code)]
//! Source luma to pinhole feature evidence, using the existing native owners.

use super::{RawGrayFrame, RawLocalizationError, RectificationPlan, RectificationReceipt};
use crate::localization::native::{ExtractedFrame, ExtractionOptions, extract_gray};
use fss_geometry::WorkBudget;

/// Complete source correction and native feature selection, without calibration authority.
/// The source exposure is unchanged; its corrected image is a derivative of the same frame.
#[derive(Debug)]
pub struct RectifiedFeatures {
    /// Exact source, sampling map, output domain and projected privacy footprint.
    pub rectification: RectificationReceipt,
    /// Actual pinhole feature coordinates/descriptors and complete selection accounting.
    pub result: ExtractedFrame,
}

/// Rectify admitted raw luma and extract features only from fully allowed support.
///
/// The immutable plan determines the corrected pixel domain. Every positive-weight source
/// interpolation tap must be allowed, then the native extractor excludes any descriptor
/// footprint touching unavailable output. Source correction and feature extraction share one
/// work allowance; exhaustion or cancellation returns no usable partial feature set.
pub fn extract_raw_features(
    plan: &RectificationPlan,
    source: &RawGrayFrame<'_>,
    options: ExtractionOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<RectifiedFeatures, RawLocalizationError> {
    budget.charge(0)?;
    let frame = plan.apply(source, budget)?;
    let image = frame.as_gray_image(budget)?;
    let result = extract_gray(&image, options, budget)?;
    budget.charge(0)?;
    Ok(RectifiedFeatures {
        rectification: frame.receipt(),
        result,
    })
}
