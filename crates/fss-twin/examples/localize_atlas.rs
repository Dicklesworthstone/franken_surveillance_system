#![forbid(unsafe_code)]
//! Explicit owner-run file harness: imported twin + archived atlas + decoded frame -> pose.
//! This is not a new fss/1 command, detector, calibration activation, or live service.

#[path = "localize_atlas/config.rs"]
mod config;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::{
    ImportExpectation, ImportLimits,
    atlas_archive::{ArchiveExpectation, MAX_ATLAS_BYTES, decode_atlas},
    import_twin,
    localization::{
        ImageIdentity, LocalizationCamera, LocalizationOutcome,
        native::{GrayImage, ImageLocalizationOptions, descriptor_domain, localize_gray_frame},
    },
    rectification::{RawFrameIdentity, RawGrayFrame, RectificationPlan, localize_raw_frame},
};
use std::{
    error::Error,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err("input file exceeds bound".into());
    }
    Ok(bytes)
}
fn member(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = Path::new(name);
    if name.is_empty()
        || name.chars().any(|c| matches!(c, '\\' | ':' | '\0'))
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err("file must be a relative member of the config directory".into());
    }
    let resolved = root.join(path).canonicalize()?;
    if !resolved.starts_with(root) {
        return Err("file escapes config directory".into());
    }
    Ok(resolved)
}
fn hash(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let digest = ContentDigest::parse(format!("sha256:{value}"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("invalid SHA-256 identity".into());
    }
    Ok(digest.bytes())
}
fn hex(value: [u8; 32]) -> String {
    value.iter().map(|x| format!("{x:02x}")).collect()
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let path =
        PathBuf::from(args.next().ok_or("expected one config file argument")?).canonicalize()?;
    if args.next().is_some() {
        return Err("expected only one config file".into());
    }
    let root = path.parent().ok_or("config has no directory")?;
    let bytes = read_bounded(&path, 16 * 1024)?;
    let settings = config::Config::parse(std::str::from_utf8(&bytes)?)?;
    let value = |key: &str| settings.value(key);
    let file = |key: &str, limit| -> Result<Vec<u8>, Box<dyn Error>> {
        read_bounded(&member(root, value(key)?)?, limit)
    };
    let work: u64 = value("work_units")?.parse()?;
    if work == 0 {
        return Err("work allowance must be positive".into());
    }
    let mut budget = WorkBudget::new(work);
    let source_k = settings.source_intrinsics()?;
    // Validate the optional lens path before accessing property or image members.
    let rectification = settings.rectification(source_k)?;
    let twin_bytes = file("twin", 64 * 1024 * 1024)?;
    let twin = import_twin(
        &twin_bytes,
        ImportExpectation {
            package_sha256: hash(value("twin_sha256")?)?,
            source_scene_sha256: hash(value("source_scene_sha256")?)?,
            basis: GeometryBasis::new(1, 1)?,
        },
        ImportLimits::default(),
        &mut budget,
    )?;
    let archive_bytes = file("atlas", MAX_ATLAS_BYTES)?;
    let archived = decode_atlas(
        &archive_bytes,
        &twin,
        ArchiveExpectation {
            package: hash(value("atlas_sha256")?)?,
            provenance: hash(value("provenance_sha256")?)?,
            descriptor: descriptor_domain(),
        },
        &mut budget,
    )?;
    let pixels = file(
        "query",
        if rectification.is_some() {
            64 * 1024 * 1024
        } else {
            4_194_304
        },
    )?;
    let allowed = file("allowed_mask", 4_194_304)?;
    let exposure = hash(value("exposure_sha256")?)?;
    let source_domain = hash(value("image_domain_sha256")?)?;
    let source_pixels = hash(value("query_sha256")?)?;
    let source_mask = hash(value("mask_sha256")?)?;
    let (result, rectified) = if let Some((spec, row_stride)) = rectification {
        let plan = RectificationPlan::compile(spec, &mut budget)?;
        let source = RawGrayFrame::new(
            RawFrameIdentity {
                exposure,
                storage: source_pixels,
                allowed_mask: source_mask,
                image_domain: source_domain,
                calibration: spec.calibration,
                dimensions: source_k.dimensions(),
                row_stride,
                range: spec.range,
            },
            &pixels,
            &allowed,
            &mut budget,
        )?;
        let outcome = localize_raw_frame(
            archived.atlas(),
            &twin,
            &plan,
            &source,
            ImageLocalizationOptions::default(),
            &mut budget,
        )?;
        (outcome.result, Some(outcome.rectification))
    } else {
        budget.charge(allowed.len() as u64)?;
        if ContentDigest::sha256(&allowed).bytes() != source_mask {
            return Err("query privacy-mask identity differs".into());
        }
        let identity = ImageIdentity {
            exposure,
            pixels: source_pixels,
            image_domain: source_domain,
            dimensions: source_k.dimensions(),
        };
        let image = GrayImage::new(identity, &pixels, &allowed, &mut budget)?;
        (
            localize_gray_frame(
                archived.atlas(),
                &twin,
                &image,
                LocalizationCamera {
                    intrinsics: source_k,
                    image_domain: identity.image_domain,
                },
                ImageLocalizationOptions::default(),
                &mut budget,
            )?,
            None,
        )
    };
    // Nothing from a partially failed pipeline is emitted as a successful receipt.
    if let Some(receipt) = rectified {
        println!(
            "{{\"schema\":\"fss.rectified-localization-rehearsal/1\",\"exposure_sha256\":\"{}\",\"source_sha256\":\"{}\",\"source_domain_sha256\":\"{}\",\"calibration_sha256\":\"{}\",\"source_mask_sha256\":\"{}\",\"output_sha256\":\"{}\",\"output_domain_sha256\":\"{}\",\"output_mask_sha256\":\"{}\",\"map_sha256\":\"{}\",\"allowed_pixels\":{},\"privacy_rejected\":{},\"outside_source\":{},\"outside_lens_domain\":{}}}",
            hex(receipt.source.exposure),
            hex(receipt.source.storage),
            hex(receipt.source.image_domain),
            hex(receipt.source.calibration),
            hex(receipt.source.allowed_mask),
            hex(receipt.output.pixels),
            hex(receipt.output.image_domain),
            hex(receipt.allowed_mask),
            hex(receipt.map_digest),
            receipt.allowed_pixels,
            receipt.privacy_rejected,
            receipt.coverage.outside_source,
            receipt.coverage.outside_lens_domain
        );
    }
    println!(
        "{{\"schema\":\"fss.atlas-localization-rehearsal/1\",\"selected_features\":{},\"omitted_features\":{},\"matched_landmarks\":{},\"work_units\":{}}}",
        result.selection.selected,
        result.selection.omitted,
        result.localization.matches.correspondences.len(),
        budget.used()
    );
    match result.localization.outcome {
        LocalizationOutcome::InsufficientMatches => {
            println!("{{\"status\":\"UNLOCALIZED_INSUFFICIENT_MATCHES\"}}")
        }
        LocalizationOutcome::GeometricFailure(_) => {
            println!("{{\"status\":\"UNLOCALIZED_GEOMETRY\"}}")
        }
        LocalizationOutcome::Candidates(search) => {
            for (index, candidate) in search.candidates().iter().enumerate() {
                println!(
                    "{{\"status\":\"CANDIDATE_NOT_ACTIVATED\",\"candidate\":{},\"center\":{:?},\"world_to_camera_rotation\":{:?},\"inliers\":{},\"rms_px\":{}}}",
                    index,
                    candidate.pose().center(),
                    candidate.pose().rotation(),
                    candidate.inlier_landmarks().len(),
                    candidate.rms_px()
                );
            }
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("localize_atlas failed: {error}");
        std::process::exit(2);
    }
}
