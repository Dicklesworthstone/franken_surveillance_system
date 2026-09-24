#![forbid(unsafe_code)]
//! Source luma -> pinhole pixels -> existing atlas matching and camera-pose search.

use super::{RawGrayFrame, RectificationError, RectificationPlan, RectificationReceipt};
use crate::PropertyTwin;
use crate::localization::native::{
    ImageLocalization, ImageLocalizationOptions, localize_gray_frame,
};
use crate::localization::{LocalizationAtlas, LocalizationCamera, LocalizationError};
use fss_geometry::{GeometryError, WorkBudget};

/// Which existing stage refused the composed operation. Neither stage may publish
/// an apparently successful prefix on cancellation or exhausted work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawLocalizationError {
    /// Source mode, lens admission, source-mask, or resampling failure.
    Rectification(RectificationError),
    /// Atlas, feature extraction or pose-search boundary failure.
    Localization(LocalizationError),
}
impl From<RectificationError> for RawLocalizationError {
    fn from(error: RectificationError) -> Self {
        Self::Rectification(error)
    }
}
impl From<LocalizationError> for RawLocalizationError {
    fn from(error: LocalizationError) -> Self {
        Self::Localization(error)
    }
}
impl From<GeometryError> for RawLocalizationError {
    fn from(error: GeometryError) -> Self {
        Self::Rectification(error.into())
    }
}
impl std::fmt::Display for RawLocalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rectification(error) => write!(f, "source rectification failed: {error}"),
            Self::Localization(error) => write!(f, "rectified localization failed: {error}"),
        }
    }
}
impl std::error::Error for RawLocalizationError {}

/// Coupled source derivation and actual pixel-to-pose result. Camera candidates
/// remain unactivated; image corrections do not create independent observations.
#[derive(Debug)]
pub struct RectifiedLocalization {
    /// Complete source exposure, mask, lens/map and derived-image bindings.
    pub rectification: RectificationReceipt,
    /// Selected features, correspondence decisions and retained geometric outcome.
    pub result: ImageLocalization,
}

/// Rectify decoded source pixels and localize using the plan's target intrinsics.
///
/// The caller cannot attach a mismatching pinhole model to the computed image:
/// its camera and image-domain identity come exclusively from the immutable plan.
/// Source exposure reuse is refused before resampling, even if crop, mask, range
/// or pixel bytes differ from the atlas derivative. No query-to-map matches,
/// calibration defaults, reference images or camera activations are manufactured.
pub fn localize_raw_frame(
    atlas: &LocalizationAtlas,
    twin: &PropertyTwin,
    plan: &RectificationPlan,
    source: &RawGrayFrame<'_>,
    options: ImageLocalizationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<RectifiedLocalization, RawLocalizationError> {
    budget.charge(0)?;
    if atlas.twin_digest() != twin.digest() {
        return Err(LocalizationError::BasisMismatch.into());
    }
    for reference in atlas.references() {
        budget.charge(1)?;
        if reference.frame.identity().exposure == source.identity().exposure {
            return Err(LocalizationError::ReferenceExposure.into());
        }
    }
    let frame = plan.apply(source, budget)?;
    let camera = LocalizationCamera {
        intrinsics: plan.spec().target,
        image_domain: plan.output_domain(),
    };
    let image = frame.as_gray_image(budget)?;
    let result = localize_gray_frame(atlas, twin, &image, camera, options, budget)?;
    budget.charge(0)?;
    Ok(RectifiedLocalization {
        rectification: frame.receipt(),
        result,
    })
}
