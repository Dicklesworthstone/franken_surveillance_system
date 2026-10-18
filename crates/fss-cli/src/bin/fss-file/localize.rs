#![forbid(unsafe_code)]
//! Owner-pinned retained recording -> native luma -> unactivated camera-pose candidates.

use super::{ParseResult, RunResult, Values, malformed, number, text, value, write_new};
use fss_cli::agent_json as json;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryBasis, PinholeIntrinsics, WorkBudget};
use fss_reference::ingest::recorded_decode::h264::{DecoderLimits, RecordedH264Request};
use fss_reference::ingest::recorded_decode::h265::{DecoderLimits as H265Limits, RecordedH265Request};
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest,
};
use fss_reference::ingest::twin_localization::{
    RecordedImageMode, RecordedLocalization, RecordedLocalizationPlan, RecordedLocalizationSource,
    localize_recorded_frame,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::atlas_archive::{ArchiveExpectation, MAX_ATLAS_BYTES, decode_atlas};
use fss_twin::localization::native::{ImageLocalizationOptions, descriptor_domain};
use fss_twin::localization::{LocalizationCamera, LocalizationOutcome};
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationSpec};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct Action {
    identity: ContentDigest,
    segment: usize,
    first: Option<usize>,
    count: Option<usize>,
    interpretation: ComponentInterpretation,
    read_limits: RetainedReadLimits,
    decode_limits: DecodeLimits,
    twin_path: PathBuf,
    twin_expected: ImportExpectation,
    atlas_path: PathBuf,
    atlas_expected: ArchiveExpectation,
    image: RecordedImageMode,
    options: ImageLocalizationOptions,
    decode_work: u64,
    geometry_work: u64,
    report: PathBuf,
    receipt: Option<PathBuf>,
}
impl Action {
    pub(super) fn identity(&self) -> ContentDigest { self.identity }
}

pub(super) fn accepts_option(command: &str, option: &str) -> bool {
    command == "localize" && matches!(option,
        "--segment" | "--range-start" | "--range-count" | "--interpretation"
        | "--max-pixels" | "--max-dimension" | "--work-units" | "--geometry-work-units"
        | "--twin" | "--twin-sha256" | "--scene-sha256" | "--property" | "--revision"
        | "--atlas" | "--atlas-sha256" | "--atlas-provenance-sha256"
        | "--image-mode" | "--camera" | "--image-domain" | "--source-camera"
        | "--distortion" | "--maximum-radius" | "--calibration-sha256" | "--luma-range"
        | "--feature-threshold" | "--maximum-features" | "--ransac-trials"
        | "--report-out" | "--receipt-out")
}
fn digest(values: &Values, key: &str) -> ParseResult<[u8; 32]> {
    let d = ContentDigest::parse(text(values, key)?).map_err(|_| malformed("invalid digest"))?;
    if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
        return Err(malformed("nonzero sha256 identities required"));
    }
    Ok(d.bytes())
}
fn list(values: &Values, key: &str, count: usize) -> ParseResult<Vec<f64>> {
    let parts: Vec<_> = text(values, key)?.split(',').collect();
    if parts.len() != count { return Err(malformed("wrong number of comma-separated values")); }
    parts.into_iter().map(|p| {
        let v: f64 = p.parse().map_err(|_| malformed("invalid numeric list"))?;
        if !v.is_finite() { return Err(malformed("finite numeric values required")); }
        Ok(v)
    }).collect()
}
fn camera(values: &Values, key: &str) -> ParseResult<PinholeIntrinsics> {
    let p = list(values, key, 6)?;
    if !(1.0..=4096.0).contains(&p[0]) || !(1.0..=4096.0).contains(&p[1])
        || p[0].fract() != 0.0 || p[1].fract() != 0.0
    { return Err(malformed("camera grid must have integer dimensions in 1..4096")); }
    PinholeIntrinsics::new(p[0] as u32, p[1] as u32, p[2], p[3], p[4], p[5])
        .map_err(|_| malformed("invalid camera intrinsics"))
}
pub(super) fn parse(identity: ContentDigest, read_limits: RetainedReadLimits, values: &Values)
    -> ParseResult<Action>
{
    let interpretation = match text(values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err(malformed("interpretation must be gray or ycbcr")),
    };
    let target = camera(values, "--camera")?;
    let image_domain = digest(values, "--image-domain")?;
    let raw_keys = ["--source-camera", "--distortion", "--maximum-radius",
        "--calibration-sha256", "--luma-range"];
    let image = match text(values, "--image-mode")? {
        "pinhole" => {
            if raw_keys.iter().any(|key| values.contains_key(*key)) {
                return Err(malformed("raw lens options require --image-mode raw"));
            }
            RecordedImageMode::Pinhole(LocalizationCamera { intrinsics: target, image_domain })
        }
        "raw" => {
            let distortion = text(values, "--distortion")?;
            let parts: Vec<_> = distortion.split(',').collect();
            let nums: Result<Vec<f64>, _> = parts.iter().skip(1).map(|p| p.parse::<f64>()).collect();
            let nums = nums.map_err(|_| malformed("invalid lens coefficients"))?;
            if nums.iter().any(|v| !v.is_finite()) { return Err(malformed("finite lens coefficients required")); }
            let distortion = match (parts[0], nums.as_slice()) {
                ("pinhole", []) => LensDistortion::Pinhole,
                ("brown", [k1, k2, k3, p1, p2]) => LensDistortion::BrownConrady {
                    radial: [*k1, *k2, *k3], tangential: [*p1, *p2],
                },
                ("fisheye", [a, b, c, d]) => LensDistortion::Fisheye { coefficients: [*a, *b, *c, *d] },
                _ => return Err(malformed("distortion: pinhole, brown,k1,k2,k3,p1,p2, or fisheye,k1,k2,k3,k4")),
            };
            let maximum_radius = number(values, "--maximum-radius", None)?;
            if !(1e-6..=64.0).contains(&maximum_radius) { return Err(malformed("invalid lens domain radius")); }
            RecordedImageMode::Raw(RectificationSpec {
                source: camera(values, "--source-camera")?, target, distortion, maximum_radius,
                source_domain: image_domain, calibration: digest(values, "--calibration-sha256")?,
                range: match text(values, "--luma-range")? {
                    "full" => LumaRange::Full, "video" => LumaRange::Video,
                    _ => return Err(malformed("luma range must be full or video")),
                },
            })
        }
        _ => return Err(malformed("image mode must be explicitly pinhole or raw")),
    };
    let defaults = DecodeLimits::default();
    let decode_limits = DecodeLimits {
        maximum_dimension: number(values, "--max-dimension", Some(defaults.maximum_dimension))?,
        maximum_pixels: number(values, "--max-pixels", Some(defaults.maximum_pixels))?,
        maximum_bytes: defaults.maximum_bytes.min(read_limits.max_segment_bytes as usize),
        maximum_markers: defaults.maximum_markers,
    };
    if decode_limits.maximum_dimension == 0 || decode_limits.maximum_dimension > 4096
        || decode_limits.maximum_pixels == 0 || decode_limits.maximum_pixels > 4_194_304
    { return Err(malformed("codec bounds: dimension 1..4096, pixels 1..4194304")); }
    let segment: usize = number(values, "--segment", None)?;
    let first: Option<usize> = values.contains_key("--range-start").then(|| number(values, "--range-start", None)).transpose()?;
    let count: Option<usize> = values.contains_key("--range-count").then(|| number(values, "--range-count", None)).transpose()?;
    match (first, count) {
        (None, None) => {}
        (Some(first), Some(count)) if count > 0 && count <= 1024 && segment >= first
            && first.checked_add(count).is_some_and(|end| segment < end) => {}
        _ => return Err(malformed("supply both range bounds (count 1..1024), containing selected segment")),
    }
    let mut options = ImageLocalizationOptions::default();
    options.extraction.threshold = number(values, "--feature-threshold", Some(options.extraction.threshold))?;
    options.extraction.maximum_features = number(values, "--maximum-features", Some(options.extraction.maximum_features))?;
    options.solving.ransac_trials = number(values, "--ransac-trials", Some(options.solving.ransac_trials))?;
    if !(1..=254).contains(&options.extraction.threshold)
        || !(1..=512).contains(&options.extraction.maximum_features) || options.solving.ransac_trials > 1024
    { return Err(malformed("feature threshold 1..254, features 1..512, RANSAC trials 0..1024")); }
    let decode_work = number(values, "--work-units", Some(100_000_000))?;
    let geometry_work = number(values, "--geometry-work-units", Some(2_000_000_000))?;
    if decode_work == 0 || geometry_work == 0 { return Err(malformed("positive work budgets required")); }
    Ok(Action {
        identity, segment, first, count, interpretation, read_limits, decode_limits,
        twin_path: value(values, "--twin")?.into(),
        twin_expected: ImportExpectation {
            package_sha256: digest(values, "--twin-sha256")?,
            source_scene_sha256: digest(values, "--scene-sha256")?,
            basis: GeometryBasis::new(number(values, "--property", None)?, number(values, "--revision", None)?)
                .map_err(|_| malformed("invalid geometry basis"))?,
        },
        atlas_path: value(values, "--atlas")?.into(),
        atlas_expected: ArchiveExpectation {
            package: digest(values, "--atlas-sha256")?,
            provenance: digest(values, "--atlas-provenance-sha256")?, descriptor: descriptor_domain(),
        },
        image, options, decode_work, geometry_work,
        report: value(values, "--report-out")?.into(),
        receipt: values.get("--receipt-out").map(PathBuf::from),
    })
}

fn read(path: &Path, maximum: usize, cx: &ReplayCx) -> RunResult<Vec<u8>> {
    cx.checkpoint("file_localize:input")?;
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(std::io::Error::other("localization inputs must be regular files").into());
    }
    let file = File::open(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(std::io::Error::other("localization input byte limit exceeded").into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    cx.checkpoint("file_localize:input_complete")?;
    if bytes.len() > maximum {
        return Err(std::io::Error::other("localization input grew past its byte limit").into());
    }
    Ok(bytes)
}
fn source(a: &Action, format: &str) -> RunResult<RecordedLocalizationSource> {
    let l = a.decode_limits;
    if format == "mjpeg" {
        if a.first.is_some() { return Err(std::io::Error::other("JPEG localization selects one segment; no video range").into()); }
        return Ok(RecordedLocalizationSource::Jpeg(RecordedDecodeRequest {
            import_identity: a.identity, segment_index: a.segment, interpretation: a.interpretation,
            read_limits: a.read_limits, decode_limits: l,
        }));
    }
    let first_segment = a.first.ok_or_else(|| std::io::Error::other("video localization requires --range-start and --range-count"))?;
    let segment_count = a.count.ok_or_else(|| std::io::Error::other("missing video range length"))?;
    Ok(match format {
        "annexb" | "mp4avc" | "mkvavc" => RecordedLocalizationSource::H264 {
            segment: a.segment,
            request: RecordedH264Request {
                import_identity: a.identity, first_segment, segment_count, interpretation: a.interpretation,
                read_limits: a.read_limits,
                decoder_limits: DecoderLimits {
                    max_width: l.maximum_dimension, max_height: l.maximum_dimension,
                    max_macroblocks: u32::try_from(l.maximum_pixels / 256)?,
                    max_pictures: segment_count as u64, max_nal_bytes: l.maximum_bytes,
                    ..DecoderLimits::default()
                },
            },
        },
        "hevc" | "mp4hevc" | "mkvhevc" => RecordedLocalizationSource::H265 {
            segment: a.segment,
            request: RecordedH265Request {
                import_identity: a.identity, first_segment, segment_count, interpretation: a.interpretation,
                read_limits: a.read_limits,
                decoder_limits: H265Limits {
                    max_width: l.maximum_dimension, max_height: l.maximum_dimension,
                    max_luma_samples: l.maximum_pixels as u64, max_pictures: segment_count as u64,
                    max_nal_bytes: l.maximum_bytes, ..H265Limits::default()
                },
            },
        },
        _ => return Err(std::io::Error::other("unsupported retained localization media").into()),
    })
}
fn report(result: &RecordedLocalization, twin: [u8; 32], atlas: [u8; 32], package: [u8; 32]) -> String {
    let b = result.source();
    let count = &result.result().selection;
    let (outcome, reason, candidates) = match &result.result().localization.outcome {
        LocalizationOutcome::InsufficientMatches => ("insufficient_matches", None, Vec::new()),
        LocalizationOutcome::GeometricFailure(error) => ("geometric_failure", Some(error.to_string()), Vec::new()),
        LocalizationOutcome::Candidates(search) => ("candidates", None, search.candidates().iter().map(|c| {
            json::object(&[
                ("center", format!("{:?}", c.pose().center())),
                ("rotation", format!("{:?}", c.pose().rotation())),
                ("rms_px", c.rms_px().to_string()),
                ("inlier_landmarks", format!("{:?}", c.inlier_landmarks())),
            ])
        }).collect()),
    };
    let digest = |v: [u8; 32]| json::string(&ContentDigest::new(DigestAlgorithm::Sha256, v).to_text());
    let rectification = result.rectification().map_or_else(|| "null".to_owned(), |r| json::object(&[
        ("map_digest", digest(r.map_digest)), ("output_domain", digest(r.output.image_domain)),
        ("output_pixels", digest(r.output.pixels)), ("allowed_pixels", r.allowed_pixels.to_string()),
        ("privacy_rejected", r.privacy_rejected.to_string()),
        ("outside_source", r.coverage.outside_source.to_string()),
        ("outside_lens_domain", r.coverage.outside_lens_domain.to_string()),
    ]));
    json::object(&[
        ("operation", json::string("retained_twin_localization")), ("outcome", json::string(outcome)),
        ("reason", json::optional_string(reason.as_deref())), ("calibration_activated", "false".to_owned()),
        ("coverage_certified", "false".to_owned()), ("receipt_digest", json::string(&result.digest().to_text())),
        ("import_identity", json::string(&b.import_identity.to_text())),
        ("import_root", json::string(&b.import_root.to_text())), ("source_anchor", json::evidence_anchor(&b.source_anchor)),
        ("capsule", json::string(&b.capsule.to_text())), ("encoded_source", json::string(&b.encoded_source.to_text())),
        ("exposure", json::string(&b.exposure.to_text())), ("decoded_luma", json::string(&b.luma.to_text())),
        ("decode_receipt", json::string(&b.decode_receipt.to_text())), ("codec", json::string(b.codec)),
        ("segment", b.segment.to_string()), ("range_start", b.range_start.to_string()), ("range_count", b.range_count.to_string()),
        ("privacy_mask_binding", json::string(&b.mask_binding.to_text())),
        ("privacy_mask_policy", b.mask_policy.map_or_else(|| "null".to_owned(), |d| json::string(&d.to_text()))),
        ("twin", digest(twin)), ("atlas", digest(atlas)), ("atlas_package", digest(package)),
        ("tested_centers", count.tested_centers.to_string()), ("selected_features", count.selected.to_string()),
        ("omitted_features", count.omitted.to_string()),
        ("matched_landmarks", result.result().localization.matches.correspondences.len().to_string()),
        ("geometry_work_units", result.geometry_work().to_string()), ("rectification", rectification),
        ("candidates", json::array(&candidates)),
    ])
}
pub(super) fn run(
    action: &Action, retained: &RetainedFileImport, deployment: &mut ReferenceDeployment,
    root: &Path, cx: &ReplayCx, out: &mut impl Write,
) -> RunResult<()> {
    let source = source(action, &retained.manifest().format)?;
    let mut geometry = WorkBudget::new(action.geometry_work);
    let limits = ImportLimits::default();
    let twin = import_twin(&read(&action.twin_path, limits.bytes, cx)?, action.twin_expected, limits, &mut geometry)?;
    let atlas = decode_atlas(&read(&action.atlas_path, MAX_ATLAS_BYTES, cx)?, &twin, action.atlas_expected, &mut geometry)?;
    let result = localize_recorded_frame(deployment, &source, RecordedLocalizationPlan {
        twin: &twin, atlas: atlas.atlas(), image: action.image, options: action.options,
    }, &mut DecodeBudget::new(action.decode_work), &mut RecordedVideoDecodeBudget::new(action.decode_work),
        &mut geometry, cx)?;
    let report = report(&result, twin.digest(), atlas.atlas().digest(), atlas.package());
    if let Some(path) = &action.receipt { write_new(path, result.encoded(), root, cx)?; }
    write_new(&action.report, report.as_bytes(), root, cx)?;
    writeln!(out, "localization_receipt={}", result.digest())?;
    writeln!(out, "localization_report={report}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    const PIN: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn arguments() -> Vec<OsString> {
        [
            "localize", "--root", "/unused", "--site", "site:localize-cli",
            "--import-id", PIN, "--segment", "2", "--interpretation", "gray",
            "--twin", "owner.fsstwin", "--twin-sha256", PIN, "--scene-sha256", PIN,
            "--property", "1", "--revision", "1", "--atlas", "owner.fssatlas",
            "--atlas-sha256", PIN, "--atlas-provenance-sha256", PIN,
            "--image-mode", "pinhole", "--camera", "96,96,80,80,48,48",
            "--image-domain", PIN, "--report-out", "pose.json",
        ].into_iter().map(OsString::from).collect()
    }
    fn replace(args: &mut [OsString], key: &str, value: &str) {
        let at = args.iter().position(|arg| arg == key).expect("fixture option");
        args[at + 1] = value.into();
    }
    fn remove(args: &mut Vec<OsString>, key: &str) {
        let at = args.iter().position(|arg| arg == key).expect("fixture option");
        args.drain(at..at + 2);
    }
    fn append(args: &mut Vec<OsString>, key: &str, value: &str) {
        args.push(key.into());
        args.push(value.into());
    }
    fn parse_command(args: &[OsString]) -> Action {
        let options = super::super::parse(args)
            .expect("admitted complete localization command")
            .expect("localization action, not help");
        let super::super::Action::Localize(action) = options.action else {
            panic!("localize must dispatch to retained twin localization");
        };
        *action
    }
    fn raw_arguments() -> Vec<OsString> {
        let mut args = arguments();
        replace(&mut args, "--image-mode", "raw");
        for (key, value) in [
            ("--source-camera", "96,96,80,80,48,48"),
            ("--distortion", "brown,-0.1,0.001,0.0001,0.001,-0.001"),
            ("--maximum-radius", "1"),
            ("--calibration-sha256", PIN),
            ("--luma-range", "full"),
        ] { append(&mut args, key, value); }
        args
    }

    #[test]
    fn complete_pinhole_command_dispatches_exact_retained_source_and_owner_pins() {
        let action = parse_command(&arguments());
        assert_eq!(action.identity().bytes(), [0x11; 32]);
        assert_eq!(action.segment, 2);
        assert_eq!((action.first, action.count), (None, None));
        assert_eq!(action.twin_expected.package_sha256, [0x11; 32]);
        assert_eq!(action.twin_expected.source_scene_sha256, [0x11; 32]);
        assert_eq!(action.atlas_expected.package, [0x11; 32]);
        assert_eq!(action.atlas_expected.provenance, [0x11; 32]);
        assert_eq!(action.atlas_expected.descriptor, descriptor_domain());
        assert_eq!(action.report, PathBuf::from("pose.json"));
        assert!(action.receipt.is_none());
        let RecordedImageMode::Pinhole(camera) = action.image else {
            panic!("explicit pinhole image mode");
        };
        assert_eq!(camera.intrinsics.dimensions(), [96, 96]);
        assert_eq!(camera.image_domain, [0x11; 32]);
        let RecordedLocalizationSource::Jpeg(request) = source(&action, "mjpeg").expect("JPEG selection") else {
            panic!("JPEG source must use native retained JPEG decoding");
        };
        assert_eq!(request.import_identity, action.identity());
        assert_eq!(request.segment_index, 2);
        assert_eq!(request.interpretation, ComponentInterpretation::Grayscale);
        // The command cannot infer the video dependencies of a selected picture.
        assert!(source(&action, "annexb").is_err());
        assert!(source(&action, "hevc").is_err());
        for required in ["--image-mode", "--image-domain", "--camera", "--report-out"] {
            let mut args = arguments();
            remove(&mut args, required);
            assert!(super::super::parse(&args).is_err(), "missing {required}");
        }
        for (key, value) in [
            ("--source-camera", "96,96,80,80,48,48"), ("--distortion", "pinhole"),
            ("--maximum-radius", "1"), ("--calibration-sha256", PIN), ("--luma-range", "full"),
        ] {
            let mut args = arguments();
            append(&mut args, key, value);
            assert!(super::super::parse(&args).is_err(), "{key} requires explicit raw mode");
        }
    }

    #[test]
    fn raw_command_requires_a_complete_lens_model_and_declared_sample_range() {
        let action = parse_command(&raw_arguments());
        let RecordedImageMode::Raw(spec) = action.image else { panic!("explicit raw image mode"); };
        assert_eq!(spec.source.dimensions(), [96, 96]);
        assert_eq!(spec.target.dimensions(), [96, 96]);
        assert_eq!(spec.source_domain, [0x11; 32]);
        assert_eq!(spec.calibration, [0x11; 32]);
        assert_eq!(spec.range, LumaRange::Full);
        assert!(matches!(spec.distortion, LensDistortion::BrownConrady { .. }));
        for required in [
            "--source-camera", "--distortion", "--maximum-radius", "--calibration-sha256", "--luma-range",
        ] {
            let mut args = raw_arguments();
            remove(&mut args, required);
            assert!(super::super::parse(&args).is_err(), "missing {required}");
        }
        let mut args = raw_arguments();
        replace(&mut args, "--distortion", "fisheye,0,0,0,0");
        replace(&mut args, "--luma-range", "video");
        let RecordedImageMode::Raw(spec) = parse_command(&args).image else { panic!("raw image mode"); };
        assert_eq!(spec.range, LumaRange::Video);
        assert!(matches!(spec.distortion, LensDistortion::Fisheye { coefficients: [0.0, 0.0, 0.0, 0.0] }));
    }

    #[test]
    fn bounded_video_ranges_are_explicit_containing_and_codec_specific() {
        for (first, count) in [
            (Some("0"), None), (None, Some("3")), (Some("0"), Some("0")),
            (Some("0"), Some("1025")), (Some("3"), Some("2")), (Some("0"), Some("2")),
        ] {
            let mut args = arguments();
            if let Some(first) = first { append(&mut args, "--range-start", first); }
            if let Some(count) = count { append(&mut args, "--range-count", count); }
            assert!(super::super::parse(&args).is_err(), "range {first:?}/{count:?}");
        }
        let mut overflow = arguments();
        replace(&mut overflow, "--segment", &usize::MAX.to_string());
        append(&mut overflow, "--range-start", &usize::MAX.to_string());
        append(&mut overflow, "--range-count", "1");
        assert!(super::super::parse(&overflow).is_err(), "overflowing exclusive range end");

        let mut args = arguments();
        replace(&mut args, "--interpretation", "ycbcr");
        append(&mut args, "--range-start", "1");
        append(&mut args, "--range-count", "2");
        let action = parse_command(&args);
        assert_eq!((action.first, action.count, action.segment), (Some(1), Some(2), 2));
        assert!(source(&action, "mjpeg").is_err(), "JPEG cannot ignore video range bounds");
        for format in ["annexb", "mp4avc", "mkvavc"] {
            let RecordedLocalizationSource::H264 { request, segment } =
                source(&action, format).expect("AVC range dispatch") else { panic!("AVC decoder"); };
            assert_eq!((request.first_segment, request.segment_count, segment), (1, 2, 2));
            assert_eq!(request.import_identity, action.identity());
            assert_eq!(request.interpretation, ComponentInterpretation::YCbCr);
        }
        for format in ["hevc", "mp4hevc", "mkvhevc"] {
            let RecordedLocalizationSource::H265 { request, segment } =
                source(&action, format).expect("HEVC range dispatch") else { panic!("HEVC decoder"); };
            assert_eq!((request.first_segment, request.segment_count, segment), (1, 2, 2));
            assert_eq!(request.import_identity, action.identity());
        }
        assert!(source(&action, "unknown").is_err());
    }

    #[test]
    fn malformed_cameras_lens_models_and_unpinned_map_identities_are_refused() {
        for invalid in [
            "0,96,80,80,48,48", "4097,96,80,80,48,48", "96.5,96,80,80,48,48",
            "96,96,0,80,48,48", "96,96,NaN,80,48,48", "96,96,80,80,48",
        ] {
            let mut args = arguments();
            replace(&mut args, "--camera", invalid);
            assert!(super::super::parse(&args).is_err(), "camera {invalid}");
        }
        for key in [
            "--twin-sha256", "--scene-sha256", "--atlas-sha256",
            "--atlas-provenance-sha256", "--image-domain",
        ] {
            for invalid in [ZERO, "sha256:bad", "unknown:1111"] {
                let mut args = arguments();
                replace(&mut args, key, invalid);
                assert!(super::super::parse(&args).is_err(), "{key} {invalid}");
            }
        }
        for (key, invalid) in [
            ("--source-camera", "96,96,-1,80,48,48"),
            ("--calibration-sha256", ZERO), ("--maximum-radius", "NaN"),
            ("--maximum-radius", "65"), ("--luma-range", "guess"),
            ("--distortion", "brown,0,0,0,0"), ("--distortion", "fisheye,0,0,0,NaN"),
            ("--distortion", "automatic"),
        ] {
            let mut args = raw_arguments();
            replace(&mut args, key, invalid);
            assert!(super::super::parse(&args).is_err(), "{key} {invalid}");
        }
    }
}
