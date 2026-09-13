#![forbid(unsafe_code)]
//! Explicit owner-run file harness: imported twin + archived atlas + raw frame -> pose.
//! This is not a new fss/1 command, detector, calibration activation, or live service.

use std::{collections::BTreeMap, error::Error, fs::File, io::Read, path::{Component, Path, PathBuf}};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryBasis, PinholeIntrinsics, WorkBudget};
use fss_twin::{ImportExpectation, ImportLimits, import_twin,
    atlas_archive::{ArchiveExpectation, MAX_ATLAS_BYTES, decode_atlas},
    localization::{ImageIdentity, LocalizationCamera, LocalizationOutcome,
        native::{GrayImage, ImageLocalizationOptions, descriptor_domain, localize_gray_frame}}};

const KEYS: [&str; 19] = ["twin", "twin_sha256", "source_scene_sha256", "atlas", "atlas_sha256",
    "provenance_sha256", "query", "allowed_mask", "query_sha256", "mask_sha256", "exposure_sha256",
    "image_domain_sha256", "width", "height", "fx", "fy", "cx", "cy", "work_units"];

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max { return Err("input file exceeds bound".into()); }
    Ok(bytes)
}
fn member(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = Path::new(name);
    if name.is_empty() || name.chars().any(|c| matches!(c, '\\' | ':' | '\0')) || path.is_absolute()
        || path.components().any(|c| !matches!(c, Component::Normal(_) | Component::CurDir)) {
        return Err("file must be a relative member of the config directory".into());
    }
    let resolved = root.join(path).canonicalize()?;
    if !resolved.starts_with(root) { return Err("file escapes config directory".into()); }
    Ok(resolved)
}
fn hash(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let digest = ContentDigest::parse(format!("sha256:{value}"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("invalid SHA-256 identity".into());
    }
    Ok(digest.bytes())
}
fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config = PathBuf::from(args.next().ok_or("expected one config file argument")?).canonicalize()?;
    if args.next().is_some() { return Err("expected only one config file".into()); }
    let root = config.parent().ok_or("config has no directory")?;
    let bytes = read_bounded(&config, 16 * 1024)?;
    let text = std::str::from_utf8(&bytes)?;
    let mut values = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let (key, value) = line.split_once('=').ok_or("invalid config row")?;
        let (key, value) = (key.trim(), value.trim());
        if !KEYS.contains(&key) || value.is_empty() || values.insert(key, value).is_some() {
            return Err("unknown, empty, or duplicate config field".into());
        }
    }
    if values.len() != KEYS.len() { return Err("missing config field".into()); }
    let value = |key: &str| -> Result<&str, Box<dyn Error>> {
        values.get(key).copied().ok_or_else(|| "missing config field".into())
    };
    let file = |key: &str, limit| -> Result<Vec<u8>, Box<dyn Error>> {
        read_bounded(&member(root, value(key)?)?, limit)
    };
    let work: u64 = value("work_units")?.parse()?;
    if work == 0 { return Err("work allowance must be positive".into()); }
    let mut budget = WorkBudget::new(work);
    let twin_bytes = file("twin", 64 * 1024 * 1024)?;
    let twin = import_twin(&twin_bytes, ImportExpectation {
        package_sha256: hash(value("twin_sha256")?)?, source_scene_sha256: hash(value("source_scene_sha256")?)?,
        basis: GeometryBasis::new(1, 1)?,
    }, ImportLimits::default(), &mut budget)?;
    let archive_bytes = file("atlas", MAX_ATLAS_BYTES)?;
    let archived = decode_atlas(&archive_bytes, &twin, ArchiveExpectation {
        package: hash(value("atlas_sha256")?)?, provenance: hash(value("provenance_sha256")?)?, descriptor: descriptor_domain(),
    }, &mut budget)?;
    let pixels = file("query", 4_194_304)?; let allowed = file("allowed_mask", 4_194_304)?;
    budget.charge(allowed.len() as u64)?;
    if ContentDigest::sha256(&allowed).bytes() != hash(value("mask_sha256")?)? {
        return Err("query privacy-mask identity differs".into());
    }
    let width: u32 = value("width")?.parse()?; let height: u32 = value("height")?.parse()?;
    let k = PinholeIntrinsics::new(width, height, value("fx")?.parse()?, value("fy")?.parse()?,
        value("cx")?.parse()?, value("cy")?.parse()?)?;
    let identity = ImageIdentity { exposure: hash(value("exposure_sha256")?)?, pixels: hash(value("query_sha256")?)?,
        image_domain: hash(value("image_domain_sha256")?)?, dimensions: [width, height] };
    let image = GrayImage::new(identity, &pixels, &allowed, &mut budget)?;
    let result = localize_gray_frame(archived.atlas(), &twin, &image,
        LocalizationCamera { intrinsics: k, image_domain: identity.image_domain },
        ImageLocalizationOptions::default(), &mut budget)?;
    println!("{{\"schema\":\"fss.atlas-localization-rehearsal/1\",\"selected_features\":{},\"omitted_features\":{},\"matched_landmarks\":{},\"work_units\":{}}}",
        result.selection.selected, result.selection.omitted, result.localization.matches.correspondences.len(), budget.used());
    match result.localization.outcome {
        LocalizationOutcome::InsufficientMatches => println!("{{\"status\":\"UNLOCALIZED_INSUFFICIENT_MATCHES\"}}"),
        LocalizationOutcome::GeometricFailure(_) => println!("{{\"status\":\"UNLOCALIZED_GEOMETRY\"}}"),
        LocalizationOutcome::Candidates(search) => {
            for (index, candidate) in search.candidates().iter().enumerate() {
                println!("{{\"status\":\"CANDIDATE_NOT_ACTIVATED\",\"candidate\":{},\"center\":{:?},\"world_to_camera_rotation\":{:?},\"inliers\":{},\"rms_px\":{}}}",
                    index, candidate.pose().center(), candidate.pose().rotation(), candidate.inlier_landmarks().len(), candidate.rms_px());
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
