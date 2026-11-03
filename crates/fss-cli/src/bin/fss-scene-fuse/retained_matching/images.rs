#![forbid(unsafe_code)]
//! Explicit raw-to-pinhole image declarations and pure sealed-owner snapshot checks.
//!
//! Preparation compiles the real native map under the caller's work allowance. Binding does
//! not compile a second map or authenticate custody; it checks the exact spec and receipt
//! supplied by the retained owner against the declaration, original source, and rig camera.

use fss_cli::json_input::Value;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::rectification::{
    LensDistortion, LumaRange, MAX_RECTIFICATION_PIXELS, RectificationError, RectificationPlan,
    RectificationSpec,
};

use super::input::{ResolvedFrame, digest, fields, get, is_pin, real, text, unsigned};
use super::{Result, fail, input_error};

/// One declared interpretation of native decoded source luma. Neither variant activates a lens.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum ImageDeclaration {
    /// Native pixels already belong to this exact pinhole image domain.
    Pinhole(ContentDigest),
    /// Native pixels need the complete declared lens transform before feature extraction.
    Rectified(RectifiedImageDeclaration),
}

/// Source-side model only. Target intrinsics always come from the admitted rig camera.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct RectifiedImageDeclaration {
    pub source_domain: ContentDigest,
    pub lens_basis: ContentDigest,
    pub source_intrinsics: PinholeIntrinsics,
    pub distortion: LensDistortion,
    pub maximum_radius: f64,
    pub luma_range: LumaRange,
}

pub(super) struct PreparedImage {
    pub domain: ContentDigest,
    pub rectifier: Option<RectificationPlan>,
}

impl RectifiedImageDeclaration {
    pub(super) fn spec(self, target: PinholeIntrinsics) -> RectificationSpec {
        RectificationSpec {
            source: self.source_intrinsics,
            target,
            distortion: self.distortion,
            maximum_radius: self.maximum_radius,
            source_domain: self.source_domain.bytes(),
            calibration: self.lens_basis.bytes(),
            range: self.luma_range,
        }
    }
}

fn rectification_error(error: RectificationError) -> super::super::Failure {
    match error {
        RectificationError::Geometry(GeometryError::Cancelled) => fail(
            "ERR-SCENE-FUSION-CANCELLED-001",
            "image preparation cancelled",
        ),
        RectificationError::Limit
        | RectificationError::Geometry(GeometryError::BudgetExhausted) => fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "native image preparation exceeds its allowance",
        ),
        _ => input_error(format!("native image model refused: {error}")),
    }
}

impl ImageDeclaration {
    /// Compile before any selected source is decoded or any JPEG derivative is published.
    pub(super) fn prepare(
        self,
        target: PinholeIntrinsics,
        work: &mut WorkBudget<'_>,
    ) -> Result<PreparedImage> {
        work.charge(0)
            .map_err(|error| rectification_error(RectificationError::Geometry(error)))?;
        match self {
            Self::Pinhole(domain) if is_pin(domain) => Ok(PreparedImage {
                domain,
                rectifier: None,
            }),
            Self::Pinhole(_) => Err(input_error(
                "pinhole image domain must be a nonzero SHA-256",
            )),
            Self::Rectified(raw) => {
                if !is_pin(raw.source_domain) || !is_pin(raw.lens_basis) {
                    return Err(input_error(
                        "raw image domain and lens basis must be nonzero SHA-256",
                    ));
                }
                let plan = RectificationPlan::compile(raw.spec(target), work)
                    .map_err(rectification_error)?;
                Ok(PreparedImage {
                    domain: ContentDigest::new(DigestAlgorithm::Sha256, plan.output_domain()),
                    rectifier: Some(plan),
                })
            }
        }
    }
}

fn coefficients<const N: usize>(value: &Value) -> Result<[f64; N]> {
    let rows = value
        .array()
        .filter(|rows| rows.len() == N)
        .ok_or_else(|| input_error("lens coefficients must have the exact declared arity"))?;
    let mut result = [0.0; N];
    for (output, value) in result.iter_mut().zip(rows) {
        *output = real(value, -100.0, 100.0)?;
    }
    Ok(result)
}

fn distortion(value: &Value) -> Result<LensDistortion> {
    let row = value
        .object()
        .ok_or_else(|| input_error("expected an explicit lens family"))?;
    match text(get(row, "kind")?)? {
        "pinhole" => {
            fields(value, &["kind"])?;
            Ok(LensDistortion::Pinhole)
        }
        "brown_conrady" => {
            let row = fields(value, &["kind", "radial", "tangential"])?;
            Ok(LensDistortion::BrownConrady {
                radial: coefficients(get(row, "radial")?)?,
                tangential: coefficients(get(row, "tangential")?)?,
            })
        }
        "fisheye" => {
            let row = fields(value, &["kind", "coefficients"])?;
            Ok(LensDistortion::Fisheye {
                coefficients: coefficients(get(row, "coefficients")?)?,
            })
        }
        _ => Err(input_error("unsupported explicit lens family")),
    }
}

fn intrinsics(value: &Value) -> Result<PinholeIntrinsics> {
    let row = fields(value, &["width", "height", "fx", "fy", "cx", "cy"])?;
    let width = unsigned(get(row, "width")?, 1, 4096)? as u32;
    let height = unsigned(get(row, "height")?, 1, 4096)? as u32;
    if u64::from(width) * u64::from(height) > MAX_RECTIFICATION_PIXELS as u64 {
        return Err(input_error(
            "raw image dimensions exceed the native pixel bound",
        ));
    }
    PinholeIntrinsics::new(
        width,
        height,
        real(get(row, "fx")?, 1e-6, 1e9)?,
        real(get(row, "fy")?, 1e-6, 1e9)?,
        real(get(row, "cx")?, -1e9, 1e9)?,
        real(get(row, "cy")?, -1e9, 1e9)?,
    )
    .map_err(|_| input_error("invalid raw source intrinsics"))
}

pub(super) fn parse(value: &Value) -> Result<ImageDeclaration> {
    let row = value
        .object()
        .ok_or_else(|| input_error("expected an explicit source image mode"))?;
    match text(get(row, "kind")?)? {
        "pinhole" => {
            let row = fields(value, &["kind", "image_domain_digest"])?;
            Ok(ImageDeclaration::Pinhole(digest(get(
                row,
                "image_domain_digest",
            )?)?))
        }
        "rectified" => {
            let row = fields(
                value,
                &[
                    "kind",
                    "source_domain_digest",
                    "lens_basis",
                    "source_intrinsics",
                    "distortion",
                    "maximum_radius",
                    "luma_range",
                ],
            )?;
            Ok(ImageDeclaration::Rectified(RectifiedImageDeclaration {
                source_domain: digest(get(row, "source_domain_digest")?)?,
                lens_basis: digest(get(row, "lens_basis")?)?,
                source_intrinsics: intrinsics(get(row, "source_intrinsics")?)?,
                distortion: distortion(get(row, "distortion")?)?,
                maximum_radius: real(get(row, "maximum_radius")?, 1e-6, 64.0)?,
                luma_range: match text(get(row, "luma_range")?)? {
                    "full" => LumaRange::Full,
                    "video" => LumaRange::Video,
                    _ => return Err(input_error("luma range must be explicitly full or video")),
                },
            }))
        }
        _ => Err(input_error("unsupported source image mode")),
    }
}

/// Bind an immutable source-owner result without trusting query-authored corrected pixels.
pub(super) fn bind(
    declaration: ImageDeclaration,
    target: PinholeIntrinsics,
    resolved: &ResolvedFrame<'_>,
) -> Result<ContentDigest> {
    let output = resolved.frame.identity();
    let invalid =
        || input_error("native image derivation differs from its exact source or rig binding");
    match (declaration, resolved.rectification) {
        (ImageDeclaration::Pinhole(domain), None) => {
            if resolved.dimensions != target.dimensions()
                || output.dimensions != resolved.dimensions
                || output.pixels != resolved.luma.bytes()
                || output.image_domain != domain.bytes()
            {
                return Err(invalid());
            }
            Ok(domain)
        }
        (ImageDeclaration::Rectified(raw), Some((spec, receipt))) => {
            let pixels = (output.dimensions[0] as usize)
                .checked_mul(output.dimensions[1] as usize)
                .filter(|count| *count > 0 && *count <= MAX_RECTIFICATION_PIXELS)
                .ok_or_else(invalid)?;
            let coverage = receipt.coverage;
            if spec != raw.spec(target)
                || resolved.dimensions != spec.source.dimensions()
                || output.dimensions != target.dimensions()
                || receipt.source.dimensions != resolved.dimensions
                || receipt.source.row_stride != resolved.dimensions[0]
                || receipt.source.exposure != resolved.exposure.bytes()
                || receipt.source.storage != resolved.luma.bytes()
                || receipt.source.image_domain != spec.source_domain
                || receipt.source.calibration != spec.calibration
                || receipt.source.range != spec.range
                || receipt.output != output
                || output.exposure != resolved.exposure.bytes()
                || receipt.allowed_mask != resolved.allowed_mask_digest
                || [
                    receipt.source.allowed_mask,
                    receipt.map_digest,
                    output.pixels,
                    output.image_domain,
                    receipt.allowed_mask,
                ]
                .contains(&[0; 32])
                || coverage
                    .mapped
                    .checked_add(coverage.outside_lens_domain)
                    .and_then(|count| count.checked_add(coverage.outside_source))
                    != Some(pixels)
                || receipt.allowed_pixels.checked_add(receipt.privacy_rejected)
                    != Some(coverage.mapped)
                || resolved.frame.features().len() > receipt.allowed_pixels
            {
                return Err(invalid());
            }
            Ok(ContentDigest::new(
                DigestAlgorithm::Sha256,
                output.image_domain,
            ))
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
#[path = "images_tests.rs"]
mod tests;
