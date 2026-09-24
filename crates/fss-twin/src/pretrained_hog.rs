#![forbid(unsafe_code)]
//! Explicit local loading of a real pretrained candidate, without OpenCV at runtime.
//!
//! This is an immutable replay/shadow asset, NOT a model activation, qualification,
//! canonical model-package publication, calibrated probability or effect grant.
//! The source export and redistribution license are retained beside the weights.

use crate::hog::{HOG_PARAMETERS, HogError, HogModel, hog_recipe_digest};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;

/// Exact unchanged upstream F32LE coefficients, including the intercept.
pub const OPENCV_PEOPLE_WEIGHTS_SHA256: [u8; 32] = [
    0xcb, 0x21, 0x98, 0x95, 0x2e, 0xaa, 0x5b, 0xc7, 0xe4, 0x3d, 0x95, 0x0b, 0x9f, 0x2a, 0xa1, 0x96,
    0x65, 0x28, 0x06, 0x3c, 0x72, 0x95, 0xc7, 0x26, 0x21, 0x33, 0xe7, 0xfa, 0x0d, 0x3d, 0x56, 0x4c,
];
/// Exact retained export, license and usage-boundary record.
pub const OPENCV_PEOPLE_PROVENANCE_SHA256: [u8; 32] = [
    0x23, 0x06, 0xcd, 0x7d, 0x3a, 0x0a, 0x48, 0xf6, 0xcc, 0xb9, 0x56, 0xab, 0x4d, 0x67, 0x93, 0x79,
    0x31, 0xf8, 0x1b, 0x5e, 0x9c, 0x49, 0x88, 0x30, 0xe6, 0xdb, 0xdb, 0xe6, 0x78, 0xdb, 0xbb, 0xc5,
];
/// Exact redistribution license distributed with the source binary.
pub const OPENCV_PEOPLE_LICENSE_SHA256: [u8; 32] = [
    0xeb, 0x3c, 0x41, 0x47, 0xe0, 0xa4, 0x31, 0x0c, 0x85, 0x0d, 0x5c, 0xf0, 0x1b, 0xe0, 0xe7, 0x89,
    0x18, 0x89, 0x94, 0xfd, 0xa2, 0x03, 0xb3, 0x8e, 0xd8, 0xee, 0x25, 0xaf, 0xd6, 0x8a, 0x76, 0x76,
];
/// Native feature recipe against which this candidate's smoke checks were made.
pub const OPENCV_PEOPLE_RECIPE_SHA256: [u8; 32] = [
    0xcc, 0x63, 0xaa, 0x36, 0x80, 0x16, 0x83, 0xf2, 0x1d, 0xa3, 0x15, 0x23, 0xc7, 0x1a, 0xc3, 0xe0,
    0x28, 0xa0, 0xae, 0x0a, 0x00, 0xf5, 0xc0, 0x8c, 0xe1, 0xa9, 0x99, 0xe1, 0xd0, 0x33, 0xba, 0xd6,
];

const WEIGHTS: &[u8; HOG_PARAMETERS * 4] = include_bytes!("../models/opencv_people/weights.f32le");
const PROVENANCE: &str = include_str!("../models/opencv_people/provenance.json");
const LICENSE: &str = include_str!("../models/opencv_people/LICENSE.txt");

/// Borrow the exact public pretrained bytes for independently retained local custody.
/// Merely accessing these coefficients grants no authority over sensor imagery.
pub fn opencv_people_weights() -> &'static [u8] {
    WEIGHTS
}
/// Borrow the unchanged source/provenance record; its digest is not authentication.
pub fn opencv_people_provenance() -> &'static str {
    PROVENANCE
}
/// Required redistribution license, available without a foreign framework.
pub fn opencv_people_license() -> &'static str {
    LICENSE
}

/// Explicitly select the bundled trained candidate. No default model, network, file
/// reads, foreign runtime, synthesized weights or silent recipe conversion is used.
/// Every call verifies the immutable assets before delegating to the ordinary loader.
/// A changed recipe fails closed: it needs a new candidate and differential evidence.
pub fn load_opencv_people_candidate(budget: &mut WorkBudget<'_>) -> Result<HogModel, HogError> {
    budget.charge((PROVENANCE.len() + LICENSE.len() + 512) as u64)?;
    if hog_recipe_digest() != OPENCV_PEOPLE_RECIPE_SHA256 {
        return Err(HogError::InvalidInput);
    }
    if ContentDigest::sha256(PROVENANCE.as_bytes()).bytes() != OPENCV_PEOPLE_PROVENANCE_SHA256
        || ContentDigest::sha256(LICENSE.as_bytes()).bytes() != OPENCV_PEOPLE_LICENSE_SHA256
    {
        return Err(HogError::DigestMismatch);
    }
    HogModel::from_f32_le(
        WEIGHTS,
        OPENCV_PEOPLE_WEIGHTS_SHA256,
        OPENCV_PEOPLE_PROVENANCE_SHA256,
        budget,
    )
}
