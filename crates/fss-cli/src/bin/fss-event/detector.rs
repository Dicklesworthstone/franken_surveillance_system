#![forbid(unsafe_code)]
//! Optional detector-cascade options shared by `fss-event watch` and `fss-event corroborate`.
//!
//! `--detector-package PATH --detector-digest sha256:HEX --detector-max-inferences N` load a
//! digest-pinned detector package (verified before parsing) and run it only on the frames the
//! cheap foreground + Kalman gate selected. Without these options nothing changes.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fss_cli::event_fusion::{
    EventFusionError, EventFusionProfile, EventFusionReport, MAX_PROFILE_BYTES, MAX_REPORT_BYTES,
};
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

/// Explicit analysis-only options. Callers must opt in to these separately from cascade
/// options so an unwired command cannot silently ignore a requested calibration.
pub(super) const FUSION_OPTIONS: &[&str] = &["--fusion-profile", "--fusion-digest"];

#[derive(Debug)]
struct FusionOptions {
    profile: PathBuf,
    digest: ContentDigest,
}

/// Parsed cascade request; the package is loaded and verified only in `load`.
#[derive(Debug)]
pub(super) struct DetectorOptions {
    package: PathBuf,
    digest: ContentDigest,
    pub(super) config: CascadeConfig,
    fusion: Option<FusionOptions>,
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
    if !values
        .iter()
        .any(|(k, _)| OPTIONS.contains(&k.as_str()) || FUSION_OPTIONS.contains(&k.as_str()))
    {
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
    let fusion = match (
        find(values, "--fusion-profile"),
        find(values, "--fusion-digest"),
    ) {
        (None, None) => None,
        (Some(profile), Some(value)) => {
            let digest = ContentDigest::parse(value)
                .map_err(|_| "invalid digest for --fusion-digest".to_owned())?;
            if profile.is_empty() || digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err("fusion requires a profile path and a SHA-256 digest".to_owned());
            }
            Some(FusionOptions {
                profile: PathBuf::from(profile),
                digest,
            })
        }
        _ => {
            return Err(
                "--fusion-profile and --fusion-digest sha256:HEX are required together".to_owned(),
            );
        }
    };
    Ok(Some(DetectorOptions {
        package: PathBuf::from(package),
        digest,
        config,
        fusion,
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

/// Keep the exact verified archive alongside the package for whole-recording replay custody.
/// The ordinary short-window loader and its output remain unchanged.
pub(super) fn load_with_archive(
    options: &DetectorOptions,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> RunResult<(RgbDetectorPackage, Vec<u8>)> {
    cx.checkpoint("long_watch_detector:package_read")?;
    let bytes = read_package(&options.package)?;
    let package = RgbDetectorPackage::load(&bytes, options.digest, 1 << 36, cx, scalar)?;
    Ok((package, bytes))
}

/// Refuse unsupported sources and authority changes before any profile or media I/O.
/// The same check is repeated by command execution, not only by its parser.
pub(super) fn check_fusion_mode(
    options: Option<&DetectorOptions>,
    short_entry: bool,
    authority_write: bool,
) -> Result<(), String> {
    if options.is_none_or(|options| options.fusion.is_none()) {
        return Ok(());
    }
    if !short_entry {
        return Err(
            "calibrated fusion supports short entry analysis, not dwell or streaming".to_owned(),
        );
    }
    if authority_write {
        return Err(
            "calibrated fusion is read-only; publish events or retain coverage/health in a separate invocation"
                .to_owned(),
        );
    }
    Ok(())
}

/// Short entry, sampled dwell and complete whole-recording watch/dwell have explicit adapters.
/// Incremental checkpoints are incomplete temporal scans and cannot produce class advice.
/// Reuse the read-only authority gate without broadening corroborate's admission.
pub(super) fn check_watch_fusion_mode(
    options: Option<&DetectorOptions>,
    supported_window: bool,
    authority_write: bool,
) -> Result<(), String> {
    if !supported_window && options.is_some_and(|options| options.fusion.is_some()) {
        return Err(
            "calibrated watch fusion requires a complete analysis; incremental dwell is unsupported"
                .to_owned(),
        );
    }
    check_fusion_mode(options, true, authority_write)
}

/// Read one bounded regular profile under the caller's authority, then verify its exact digest
/// before JSON parsing. No profile means no additional I/O or change to the old command path.
pub(super) fn load_fusion(
    options: Option<&DetectorOptions>,
    cx: &ReplayCx,
) -> RunResult<Option<EventFusionProfile>> {
    let Some(options) = options.and_then(|options| options.fusion.as_ref()) else {
        return Ok(None);
    };
    cx.checkpoint("event_fusion:profile_read")?;
    let metadata =
        fs::symlink_metadata(&options.profile).map_err(|_| EventFusionError::Profile)?;
    if !metadata.file_type().is_file() {
        return Err(EventFusionError::Profile.into());
    }
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        return Err(EventFusionError::Limit.into());
    }
    let file = fs::File::open(&options.profile).map_err(|_| EventFusionError::Profile)?;
    let opened = file.metadata().map_err(|_| EventFusionError::Profile)?;
    if !opened.file_type().is_file() {
        return Err(EventFusionError::Profile.into());
    }
    if opened.len() > MAX_PROFILE_BYTES as u64 {
        return Err(EventFusionError::Limit.into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| EventFusionError::Profile)?;
    cx.checkpoint("event_fusion:profile_verify")?;
    Ok(Some(EventFusionProfile::from_json(&bytes, options.digest)?))
}

/// Append the full derived advice without rewriting the native report, its proposal identities,
/// or its approval commands. Both objects are trusted native serializers, never caller JSON.
pub(super) fn with_fusion(
    native: String,
    fusion: Option<&EventFusionReport>,
) -> Result<String, EventFusionError> {
    match fusion {
        None => Ok(native),
        Some(fusion) => join_fusion(&native, &fusion.to_json()?),
    }
}

fn join_fusion(native: &str, advice: &str) -> Result<String, EventFusionError> {
    let parent = native
        .trim_end()
        .strip_suffix('}')
        .filter(|parent| parent.starts_with('{'))
        .ok_or(EventFusionError::Evidence)?;
    let separator = if parent.trim_end() == "{" { "" } else { "," };
    let key = "\"calibrated_class_advice\":";
    // Include the final brace and command's trailing newline in the complete output bound.
    let size = parent
        .len()
        .checked_add(separator.len())
        .and_then(|n| n.checked_add(key.len()))
        .and_then(|n| n.checked_add(advice.len()))
        .and_then(|n| n.checked_add(2))
        .ok_or(EventFusionError::Limit)?;
    if size > MAX_REPORT_BYTES {
        return Err(EventFusionError::Limit);
    }
    Ok(format!("{parent}{separator}{key}{advice}}}"))
}

#[cfg(test)]
mod fusion_tests {
    use super::*;

    fn values(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let digest = ContentDigest::sha256(b"profile fixture").to_text();
        let mut values = vec![
            ("--detector-package".to_owned(), "model.fss".to_owned()),
            ("--detector-digest".to_owned(), digest),
            ("--detector-max-inferences".to_owned(), "1".to_owned()),
        ];
        values.extend(
            extra
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        );
        values
    }

    fn calibrated() -> DetectorOptions {
        let digest = ContentDigest::sha256(b"profile fixture").to_text();
        parse(&values(&[
            ("--fusion-profile", "profile.json"),
            ("--fusion-digest", &digest),
        ]))
        .unwrap()
        .unwrap()
    }

    #[test]
    fn fusion_profile_requires_both_pins_and_a_detector() {
        for extra in [
            vec![("--fusion-profile", "profile.json")],
            vec![("--fusion-digest", "bad")],
        ] {
            assert!(parse(&values(&extra)).is_err());
        }
        assert!(parse(&[("--fusion-profile".to_owned(), "profile.json".to_owned())]).is_err());
        assert!(
            parse(&values(&[
                ("--fusion-profile", "profile.json"),
                ("--fusion-digest", "bad"),
            ]))
            .is_err()
        );
        assert!(calibrated().fusion.is_some());
        assert!(parse(&values(&[])).unwrap().unwrap().fusion.is_none());
        assert!(parse(&[]).unwrap().is_none());
    }

    #[test]
    fn fusion_refuses_unsupported_modes_and_authority_changes() {
        let options = calibrated();
        assert!(check_fusion_mode(Some(&options), true, false).is_ok());
        assert!(check_fusion_mode(Some(&options), false, false).is_err());
        assert!(check_fusion_mode(Some(&options), true, true).is_err());
        let plain = parse(&values(&[])).unwrap().unwrap();
        assert!(check_fusion_mode(Some(&plain), false, true).is_ok());
        assert!(check_fusion_mode(None, false, true).is_ok());
    }

    #[test]
    fn fusion_join_preserves_native_fields_and_complete_advice() {
        assert_eq!(
            join_fusion(
                r#"{"proposal":"original","coverage":{"state":"gap"}}"#,
                r#"{"effect_authority":false,"candidates":[]}"#,
            )
            .unwrap(),
            r#"{"proposal":"original","coverage":{"state":"gap"},"calibrated_class_advice":{"effect_authority":false,"candidates":[]}}"#,
        );
        assert_eq!(
            join_fusion("{}", "{}").unwrap(),
            r#"{"calibrated_class_advice":{}}"#,
        );
        assert_eq!(join_fusion("[]", "{}"), Err(EventFusionError::Evidence));
        let original = "old bytes\n".to_owned();
        assert_eq!(with_fusion(original.clone(), None).unwrap(), original);
    }

    #[test]
    fn fusion_join_prices_the_whole_report_including_newline() {
        let fixed = join_fusion("{}", "{}").unwrap().len() + 1;
        let advice = format!("{{{}}}", " ".repeat(MAX_REPORT_BYTES - fixed));
        assert_eq!(join_fusion("{}", &advice).unwrap().len() + 1, MAX_REPORT_BYTES);
        assert_eq!(
            join_fusion("{}", &(advice + " ")),
            Err(EventFusionError::Limit),
        );
    }
}
