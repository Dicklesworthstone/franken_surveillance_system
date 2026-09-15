#![forbid(unsafe_code)]
//! Image-to-map matching followed by an ambiguity-preserving focal-length pose scan.

use fss_geometry::{FocalPoseScan,FocalScanOptions,GeometryError,WorkBudget,scan_camera_focal_length};
use crate::PropertyTwin;
use crate::localization::{FeatureFrame,LocalizationAtlas,LocalizationError,MatchOptions,MatchReport};

#[derive(Debug)]
pub enum FocalLocalizationOutcome {
    InsufficientMatches { found: usize, required: usize },
    Scan(FocalPoseScan),
}
#[derive(Debug)]
pub struct FocalLocalization {
    pub matches: MatchReport,
    pub outcome: FocalLocalizationOutcome,
}

/// Match the current image to the imported property once, then evaluate the complete
/// caller-declared focal family over those exact correspondences. No focal sample is
/// silently chosen as calibration authority.
pub fn localize_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,query:&FeatureFrame,
    expected_image_domain:[u8;32],matching:MatchOptions,scan:FocalScanOptions,
    budget:&mut WorkBudget<'_>)->Result<FocalLocalization,LocalizationError>{
    budget.charge(0)?;
    if expected_image_domain==[0;32] || query.identity().image_domain!=expected_image_domain {
        return Err(LocalizationError::BasisMismatch);
    }
    if atlas.references().iter().any(|r|r.frame.identity().exposure==query.identity().exposure){
        return Err(LocalizationError::ReferenceExposure);
    }
    let matches=atlas.match_frame(twin,query,matching,budget)?;
    let required=6.max(scan.pose.minimum_inliers);
    let outcome=if matches.correspondences.len()<required {
        FocalLocalizationOutcome::InsufficientMatches{found:matches.correspondences.len(),required}
    } else {
        match scan_camera_focal_length(twin.basis(),query.identity().dimensions,&matches.correspondences,scan,budget){
            Ok(result)=>FocalLocalizationOutcome::Scan(result),
            Err(error @ (GeometryError::Cancelled|GeometryError::BudgetExhausted|GeometryError::LimitExceeded))=>return Err(error.into()),
            Err(error)=>return Err(LocalizationError::Geometry(error)),
        }
    };
    budget.charge(0)?;
    Ok(FocalLocalization{matches,outcome})
}
