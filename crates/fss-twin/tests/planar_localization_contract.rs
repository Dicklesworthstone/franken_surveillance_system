#![forbid(unsafe_code)]
//! Planar localization contracts under fixed intrinsics and map geometry.
mod common;

use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, PoseSolverOptions, WorkBudget};
use fss_twin::localization::native::*;
use fss_twin::localization::*;
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
fn texture() -> Vec<u8> {
    let mut state = 1973_u32;
    (0..96 * 96)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            20 + ((state >> 16) % 180) as u8
        })
        .collect()
}
fn identity(exposure: u8, pixels: &[u8]) -> ImageIdentity {
    ImageIdentity {
        exposure: [exposure; 32],
        pixels: ContentDigest::sha256(pixels).bytes(),
        image_domain: [3; 32],
        dimensions: [96, 96],
    }
}
fn rotate(pixels: &[u8]) -> Vec<u8> {
    let mut output = vec![0; pixels.len()];
    for y in 0..96 {
        for x in 0..96 {
            output[x * 96 + 95 - y] = pixels[y * 96 + x];
        }
    }
    output
}
fn atlas(
    twin: &fss_twin::PropertyTwin,
    pixels: &[u8],
    mask: &[u8],
    budget: &mut WorkBudget<'_>,
) -> Result<LocalizationAtlas, Box<dyn Error>> {
    let reference_image = GrayImage::new(identity(1, pixels), pixels, mask, budget)?;
    let extraction = ExtractionOptions {
        maximum_features: 200,
        ..ExtractionOptions::default()
    };
    let reference = extract_gray(&reference_image, extraction, budget)?.frame;
    let mut landmarks = Vec::new();
    let mut bindings = Vec::new();
    for (i, f) in reference.features().iter().enumerate() {
        let id = i as u64 + 1;
        landmarks.push(AtlasLandmark {
            id,
            physical_group: id,
            feature: 0,
            world: [(f.pixel[0] - 48.0) * 0.1, (f.pixel[1] - 48.0) * 0.1, 8.0],
            evidence: [4; 32],
            error: None,
        });
        bindings.push(AtlasBinding {
            landmark: id,
            reference: 1,
            image_feature: f.id,
        });
    }
    Ok(LocalizationAtlas::new(
        twin,
        landmarks,
        vec![AtlasReference {
            id: 1,
            frame: reference,
        }],
        bindings,
        budget,
    )?)
}
fn camera() -> Result<LocalizationCamera, GeometryError> {
    Ok(LocalizationCamera {
        intrinsics: PinholeIntrinsics::new(96, 96, 80.0, 80.0, 48.0, 48.0)?,
        image_domain: [3; 32],
    })
}
fn options() -> ImageLocalizationOptions {
    ImageLocalizationOptions {
        extraction: ExtractionOptions {
            maximum_features: 200,
            ..ExtractionOptions::default()
        },
        matching: MatchOptions {
            maximum_distance: 0,
            ..MatchOptions::default()
        },
        solving: PoseSolverOptions {
            ransac_trials: 0,
            ..PoseSolverOptions::default()
        },
    }
}

#[test]
fn actual_rotated_query_pixels_localize_against_a_coplanar_atlas() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let pixels = texture();
    let query_pixels = rotate(&pixels);
    let mask = vec![1; pixels.len()];
    let mut budget = WorkBudget::new(1_000_000_000);
    let atlas = atlas(&twin, &pixels, &mask, &mut budget)?;
    let query = GrayImage::new(
        identity(2, &query_pixels),
        &query_pixels,
        &mask,
        &mut budget,
    )?;
    let result = localize_gray_frame(&atlas, &twin, &query, camera()?, options(), &mut budget)?;
    assert!(result.localization.matches.correspondences.len() >= 8);
    let LocalizationOutcome::Candidates(search) = result.localization.outcome else {
        return Err("planar image did not localize".into());
    };
    let support = search
        .planar_support()
        .ok_or("adaptive solver did not report planar admission")?;
    assert!(support.maximum_off_plane < 1e-10);
    let expected = [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]];
    let best = &search.candidates()[0];
    for (a, b) in best
        .pose()
        .rotation()
        .iter()
        .flatten()
        .zip(expected.iter().flatten())
    {
        assert!((a - b).abs() < 1e-4);
    }
    assert!(best.pose().center().iter().all(|x| x.abs() < 1e-4));
    assert!(best.rms_px() < 1e-4);
    Ok(())
}

#[test]
fn planar_localization_keeps_reference_reuse_and_cancellation_guards() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let pixels = texture();
    let mask = vec![1; pixels.len()];
    let mut budget = WorkBudget::new(1_000_000_000);
    let atlas = atlas(&twin, &pixels, &mask, &mut budget)?;
    let reused = GrayImage::new(identity(1, &pixels), &pixels, &mask, &mut budget)?;
    assert!(matches!(
        localize_gray_frame(&atlas, &twin, &reused, camera()?, options(), &mut budget),
        Err(LocalizationError::ReferenceExposure)
    ));
    let query_pixels = rotate(&pixels);
    let query = GrayImage::new(
        identity(2, &query_pixels),
        &query_pixels,
        &mask,
        &mut budget,
    )?;
    let flag = AtomicBool::new(true);
    assert!(matches!(
        localize_gray_frame(
            &atlas,
            &twin,
            &query,
            camera()?,
            options(),
            &mut WorkBudget::cancellable(1_000_000_000, &flag)
        ),
        Err(LocalizationError::Geometry(GeometryError::Cancelled))
    ));
    Ok(())
}

#[test]
fn masked_query_regions_remain_unavailable_in_the_planar_route() -> Test {
    let twin = common::twin(&[0.0], None)?;
    let pixels = texture();
    let allowed = vec![1; pixels.len()];
    let mut budget = WorkBudget::new(1_000_000_000);
    let atlas = atlas(&twin, &pixels, &allowed, &mut budget)?;
    let query_pixels = rotate(&pixels);
    let denied = vec![0; pixels.len()];
    let query = GrayImage::new(
        identity(2, &query_pixels),
        &query_pixels,
        &denied,
        &mut budget,
    )?;
    let result = localize_gray_frame(&atlas, &twin, &query, camera()?, options(), &mut budget)?;
    assert!(result.localization.matches.correspondences.is_empty());
    assert!(!matches!(
        result.localization.outcome,
        LocalizationOutcome::Candidates(_)
    ));
    Ok(())
}
