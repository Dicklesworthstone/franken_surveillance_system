#![forbid(unsafe_code)]
//! Optional detector-cascade options shared by `fss-event watch` and `fss-event corroborate`.
//!
//! `--detector-package PATH --detector-digest sha256:HEX --detector-max-inferences N` load a
//! digest-pinned detector package (verified before parsing) and run it only on the frames the
//! cheap foreground + Kalman gate selected. Without these options nothing changes.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::ingest::detector_cascade::{
    CascadeConfig, MAX_CASCADE_FRAMES_PER_TRACK, MAX_CASCADE_INFERENCES,
};
use fss_reference::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use fss_reference::{ReplayCx, ScalarExecCx};

use super::RunResult;

/// Options owned by the detector cascade.
pub(super) const OPTIONS: &[&str] = &[
    "--detector-package",
    "--detector-digest",
    "--detector-max-inferences",
    "--detector-frames-per-track",
    "--detector-min-iou-ppm",
    "--detector-minimum-score-ppm",
];

/// Parsed cascade request; the package is loaded and verified only in `load`.
#[derive(Debug)]
pub(super) struct DetectorOptions {
    package: PathBuf,
    digest: ContentDigest,
    pub(super) config: CascadeConfig,
}

fn find<'a>(values: &'a [(String, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn number<T: std::str::FromStr>(value: &str, key: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid numeric value for {key}"))
}

/// `Ok(None)` when no detector option is present; every cascade option requires the package,
/// its digest and an explicit inference budget.
pub(super) fn parse(values: &[(String, String)]) -> Result<Option<DetectorOptions>, String> {
    if !values.iter().any(|(k, _)| OPTIONS.contains(&k.as_str())) {
        return Ok(None);
    }
    let package = find(values, "--detector-package")
        .ok_or("--detector-package is required with any detector option")?;
    let digest_text = find(values, "--detector-digest")
        .ok_or("--detector-digest sha256:HEX is required with --detector-package")?;
    let digest = ContentDigest::parse(digest_text)
        .map_err(|_| "invalid digest for --detector-digest".to_owned())?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err("--detector-digest requires SHA-256".to_owned());
    }
    let max = find(values, "--detector-max-inferences")
        .ok_or("--detector-max-inferences N (1..64) is required with --detector-package")?;
    let defaults = CascadeConfig::default();
    let config = CascadeConfig {
        max_inferences: number(max, "--detector-max-inferences")?,
        frames_per_track: match find(values, "--detector-frames-per-track") {
            Some(v) => number(v, "--detector-frames-per-track")?,
            None => defaults.frames_per_track,
        },
        minimum_association_iou_ppm: match find(values, "--detector-min-iou-ppm") {
            Some(v) => number(v, "--detector-min-iou-ppm")?,
            None => defaults.minimum_association_iou_ppm,
        },
        minimum_score_ppm: match find(values, "--detector-minimum-score-ppm") {
            Some(v) => Some(number(v, "--detector-minimum-score-ppm")?),
            None => None,
        },
    };
    config.validate().map_err(|_| {
        format!(
            "detector cascade bounds: max inferences 1..{MAX_CASCADE_INFERENCES}, frames per track \
             1..{MAX_CASCADE_FRAMES_PER_TRACK}, IoU and score 0..1000000 ppm"
        )
    })?;
    Ok(Some(DetectorOptions {
        package: PathBuf::from(package),
        digest,
        config,
    }))
}

fn read_package(path: &Path) -> RunResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RGB_PACKAGE_BYTES as u64 {
        return Err(io::Error::other(
            "detector package must be a bounded regular file, not a symlink",
        )
        .into());
    }
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_RGB_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads and verifies the package; a digest mismatch is refused before parsing.
pub(super) fn load(
    options: &DetectorOptions,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> RunResult<RgbDetectorPackage> {
    let bytes = read_package(&options.package)?;
    Ok(RgbDetectorPackage::load(
        &bytes,
        options.digest,
        1 << 36,
        cx,
        scalar,
    )?)
}
