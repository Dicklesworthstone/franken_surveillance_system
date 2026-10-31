#![forbid(unsafe_code)]
//! Pure native JPEG -> masked descriptors -> two-view geometry over exact source bytes.

use fss_cli::scene_rig::SceneRig;
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits, DecodeReceipt, decode_luma};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::PropertyTwin;
use fss_twin::feature_association::{FeatureAssociation, FeatureView, associate_features};
use fss_twin::localization::ImageIdentity;
use fss_twin::localization::native::{FeatureSelection, GrayImage, extract_gray};

use super::super::{Result, fail, input_error};
use super::input::{Mask, Query, View};

pub(super) struct Image<'a> {
    pub bytes: &'a [u8],
    pub mask: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
pub(super) struct Diagnostics {
    pub camera: u64,
    pub decode: DecodeReceipt,
    pub selection: FeatureSelection,
}

pub(super) struct Analysis {
    pub association: FeatureAssociation,
    pub diagnostics: [Diagnostics; 2],
}

fn extract(
    rig: &SceneRig,
    query: &Query,
    view: View,
    image: Image<'_>,
    cancelled: &(dyn Fn() -> bool + Sync),
    work: &mut WorkBudget<'_>,
) -> Result<(FeatureView, Diagnostics)> {
    let row = rig
        .camera(view.camera)
        .ok_or_else(|| input_error("unknown matching camera"))?;
    if row.privacy_domain != query.matching.privacy_domain
        || row.camera.clock != query.matching.clock
    {
        return Err(input_error(
            "matching camera privacy or clock differs from the query",
        ));
    }
    match (view.mask, image.mask) {
        (Mask::AllAllowed, None) | (Mask::File(_), Some(_)) => {}
        _ => {
            return Err(input_error(
                "mask file presence differs from its explicit query policy",
            ));
        }
    }
    work.charge(0)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let mut decode_work = DecodeBudget::with_cancellation_probe(work.remaining(), cancelled);
    let decoded = decode_luma(
        image.bytes,
        view.source_digest.bytes(),
        view.interpretation,
        DecodeLimits::default(),
        &mut decode_work,
    );
    // Each decoder is capped by the outer remaining allowance, then debits its
    // actual work before any later kernel. Cancellation at this boundary discards
    // the request without a result or cost receipt; no partial pixels can escape.
    work.charge(decode_work.used())
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let decoded = decoded.map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    if decoded.dimensions() != row.camera.intrinsics.dimensions() {
        return Err(input_error(
            "decoded image dimensions differ from the declared rig mode",
        ));
    }
    let mut full_mask = Vec::new();
    let allowed = match view.mask {
        Mask::AllAllowed => {
            work.charge(decoded.pixels().len() as u64)
                .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
            full_mask
                .try_reserve_exact(decoded.pixels().len())
                .map_err(|_| fail("ERR-SCENE-FUSION-LIMIT-001", "mask allocation refused"))?;
            full_mask.resize(decoded.pixels().len(), 1);
            full_mask.as_slice()
        }
        Mask::File(pin) => {
            let bytes = image
                .mask
                .ok_or_else(|| input_error("mask file is missing"))?;
            if bytes.len() != decoded.pixels().len() {
                return Err(input_error("mask must contain one byte per decoded pixel"));
            }
            work.charge(bytes.len() as u64)
                .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
            if ContentDigest::sha256(bytes) != pin {
                return Err(input_error("exact allowed-pixel mask digest differs"));
            }
            bytes
        }
    };
    let decode = decoded.receipt();
    let gray = GrayImage::new(
        ImageIdentity {
            exposure: view.source_digest.bytes(),
            pixels: decode.luma_sha256,
            image_domain: view.image_domain_digest.bytes(),
            dimensions: decoded.dimensions(),
        },
        decoded.pixels(),
        allowed,
        work,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    let extracted = extract_gray(&gray, query.extraction, work)
        .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    let selection = extracted.selection;
    let feature_view = FeatureView {
        frame: extracted.frame,
        camera: row.camera,
        source_digest: view.source_digest.bytes(),
        allowed_mask_digest: selection.mask_digest,
        image_domain_digest: view.image_domain_digest.bytes(),
        mapping_basis: view.mapping_basis.bytes(),
        privacy_domain: row.privacy_domain,
        clock_evidence: query.matching.clock_evidence,
        capture: view.capture,
        sigma_pixels: view.sigma_pixels,
    };
    Ok((
        feature_view,
        Diagnostics {
            camera: view.camera,
            decode,
            selection,
        },
    ))
}

pub(super) fn analyze(
    twin: &PropertyTwin,
    rig: &SceneRig,
    query: &Query,
    images: [Image<'_>; 2],
    cancelled: &(dyn Fn() -> bool + Sync),
    work: &mut WorkBudget<'_>,
) -> Result<Analysis> {
    let [left, right] = images;
    let (left, left_diagnostics) = extract(rig, query, query.views[0], left, cancelled, work)?;
    let (right, right_diagnostics) = extract(rig, query, query.views[1], right, cancelled, work)?;
    let association = associate_features(twin, [&left, &right], query.matching, work)
        .map_err(|e| fail("ERR-SCENE-FUSION-POINT-001", e.to_string()))?;
    let mut diagnostics = [left_diagnostics, right_diagnostics];
    diagnostics.sort_by_key(|row| row.camera);
    Ok(Analysis {
        association,
        diagnostics,
    })
}

#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod tests;
