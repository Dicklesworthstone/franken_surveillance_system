#![forbid(unsafe_code)]
//! Raw/native image or feature-frame matching followed by an ambiguity-preserving focal scan.

use fss_geometry::{FocalPoseScan,FocalScanOptions,GeometryError,WorkBudget,scan_camera_focal_length};
use crate::PropertyTwin;
use crate::localization::{FeatureFrame,LocalizationAtlas,LocalizationError,MatchOptions,MatchReport};
use crate::localization::native::{ExtractedFrame,ExtractionOptions,GrayImage,extract_gray};

/// Result of the focal scan: either the ambiguity-preserving scan outcome or a shortfall reason.
#[derive(Debug)]
pub enum FocalLocalizationOutcome {
    /// Too few correspondences were matched to attempt a scan: how many were found and how many the scan required.
    InsufficientMatches {
        /// Correspondence count actually matched for the query image.
        found: usize,
        /// Minimum support count the scan demanded.
        required: usize,
    },
    /// Focal-length pose scan completed over the ambiguity-preserving candidate set.
    Scan(FocalPoseScan),
}
/// A matched query frame plus its focal-scan outcome.
#[derive(Debug)]
pub struct FocalLocalization {
    /// Atlas match report for the query frame.
    pub matches: MatchReport,
    /// Scan result, or the reason no scan was attempted.
    pub outcome: FocalLocalizationOutcome,
}
/// Full native-pixel result: extracted frame plus the feature-level localization it fed.
#[derive(Debug)]
pub struct GrayFocalLocalization {
    /// Extracted grayscale features and identity of the input image.
    pub extraction: ExtractedFrame,
    /// Matching and focal-scan outcome computed from the extracted frame.
    pub localization: FocalLocalization,
}

/// Matches the query frame against the atlas and, when at least `max(6, scan.pose.minimum_inliers)`
/// correspondences exist, runs a focal-length pose scan. Refuses a zero or mismatched
/// `expected_image_domain` and any query exposure shared with an atlas reference frame.
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

/// Caller-declared controls for the gray full-route focal localization: the authorized
/// image-domain identity that the query image must carry, plus the three tuned option sets.
#[derive(Clone, Copy, Debug)]
pub struct GrayFocalScanControls {
    /// Authorized image-domain identity; `[0;32]` is refused as an unset value.
    pub expected_image_domain:[u8;32],
    /// Feature-extraction tuning for the query image.
    pub extraction:ExtractionOptions,
    /// Atlas-matching tuning applied to the extracted features.
    pub matching:MatchOptions,
    /// Caller-declared focal family to scan.
    pub scan:FocalScanOptions,
}

/// Full native-pixel route: extract authorized grayscale features, match them to the
/// property atlas, then scan the caller-declared focal family. No correspondences,
/// focal length, or pose are supplied by this query operation.
pub fn localize_gray_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,image:&GrayImage<'_>,
    controls:GrayFocalScanControls,budget:&mut WorkBudget<'_>)->Result<GrayFocalLocalization,LocalizationError>{
    let GrayFocalScanControls{expected_image_domain,extraction,matching,scan}=controls;
    budget.charge(0)?;
    if image.identity().image_domain!=expected_image_domain{return Err(LocalizationError::BasisMismatch);}
    let extracted=extract_gray(image,extraction,budget)?;
    let localization=localize_focal_scan(atlas,twin,&extracted.frame,expected_image_domain,matching,scan,budget)?;
    budget.charge(0)?;
    Ok(GrayFocalLocalization{extraction:extracted,localization})
}
