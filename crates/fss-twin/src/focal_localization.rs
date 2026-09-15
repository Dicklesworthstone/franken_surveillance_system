#![forbid(unsafe_code)]
//! Raw/native image or feature-frame matching followed by an ambiguity-preserving focal scan.

use fss_geometry::{FocalPoseScan,FocalScanOptions,GeometryError,WorkBudget,scan_camera_focal_length};
use crate::PropertyTwin;
use crate::localization::{FeatureFrame,LocalizationAtlas,LocalizationError,MatchOptions,MatchReport};
use crate::localization::native::{ExtractedFrame,ExtractionOptions,GrayImage,extract_gray};

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
#[derive(Debug)]
pub struct GrayFocalLocalization {
    pub extraction: ExtractedFrame,
    pub localization: FocalLocalization,
}

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

/// Full native-pixel route: extract authorized grayscale features, match them to the
/// property atlas, then scan the caller-declared focal family. No correspondences,
/// focal length, or pose are supplied by this query operation.
pub fn localize_gray_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,image:&GrayImage<'_>,
    expected_image_domain:[u8;32],extraction:ExtractionOptions,matching:MatchOptions,
    scan:FocalScanOptions,budget:&mut WorkBudget<'_>)->Result<GrayFocalLocalization,LocalizationError>{
    budget.charge(0)?;
    if image.identity().image_domain!=expected_image_domain{return Err(LocalizationError::BasisMismatch);}
    let extracted=extract_gray(image,extraction,budget)?;
    let localization=localize_focal_scan(atlas,twin,&extracted.frame,expected_image_domain,matching,scan,budget)?;
    budget.charge(0)?;
    Ok(GrayFocalLocalization{extraction:extracted,localization})
}
