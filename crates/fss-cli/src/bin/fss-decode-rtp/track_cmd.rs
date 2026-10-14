#![forbid(unsafe_code)]
//! Bounded operator presentation for source-witnessed native RTP tracking.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_reference::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use fss_reference::ingest::rtpdump::detect::RtpDetectionRequest;
use fss_reference::ingest::rtpdump::recovery::checked_decode::RtpCustodyDecodeLimits;
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::inspect_rtp_import;
use fss_reference::ingest::rtpdump::track::{
    RtpPackageTracker, RtpTrackReset, RtpTrackedFrame, RtpTrackingLimits, RtpTrackingRequest,
    RtpTrackingStats, RtpTrackingStep,
};
use fss_reference::ingest::tracker::{TrackStatus, TrackerConfig};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::pgm_stream::private_output::PrivateOutputPath;
use super::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity, Options,
    ParseResult, Result, failure,
};

const REPORT_DOMAIN: &str = "fss.retained_rtp_tracking_report.v1";
const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;

#[path = "trajectory_cmd.rs"]
mod trajectory_cmd;

#[derive(Debug)]
struct TrackOptions {
    base: Options,
    settings: TrackSettings,
}
#[derive(Debug)]
struct TrackSettings {
    package: PathBuf,
    package_digest: ContentDigest,
    class_index: usize,
    minimum_score_ppm: Option<u32>,
    tracker: TrackerConfig,
    max_track_frames: usize,
    report: Option<PathBuf>,
    max_report_bytes: u64,
}

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    if let Some(exit) = trajectory_cmd::dispatch(args) {
        return Some(exit);
    }
    if args.first().and_then(|v| v.to_str()) != Some("track") {
        return None;
    }
    Some(match parse(args) {
        Err((id, reason)) => {
            eprintln!("{id}: {reason}");
            ExitCode::from(2)
        }
        Ok(TrackOptions { base, settings }) => {
            let mut out = io::stdout().lock();
            let result = super::run_with(base, &mut out, |base, root, cx, out| {
                execute(base, &settings, root, cx, out)
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "tracking_complete=false\ntracking_report_complete=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}

fn parse(args: &[OsString]) -> ParseResult<TrackOptions> {
    let parsed = parse_native(args)?;
    if parsed.settings.report.is_none() {
        return Err((ERR_CLI_MISSING_VALUE, "required option absent"));
    }
    Ok(parsed)
}

fn parse_native(args: &[OsString]) -> ParseResult<TrackOptions> {
    let mut native = vec![OsString::from("decode")];
    let mut values = BTreeMap::new();
    let mut at = 1;
    while at < args.len() {
        let key = args[at]
            .to_str()
            .ok_or((ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        let value = args
            .get(at + 1)
            .ok_or((ERR_CLI_MISSING_VALUE, "option needs a value"))?;
        if [
            "--package",
            "--package-sha256",
            "--class-index",
            "--minimum-score-ppm",
            "--track-min-hits",
            "--track-max-misses",
            "--track-iou-ppm",
            "--max-track-frames",
            "--report-out",
            "--max-report-bytes",
        ]
        .contains(&key)
        {
            if values.insert(key.to_owned(), value.clone()).is_some() {
                return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate tracking option"));
            }
        } else {
            native.extend([args[at].clone(), value.clone()]);
        }
        at += 2;
    }
    let base = super::parse(&native)?
        .ok_or((ERR_CLI_MISSING_VALUE, "native decode options required"))?;
    if base.custody_read_bytes.is_none() {
        return Err((ERR_CLI_MALFORMED_VALUE, "tracking requires --custody current"));
    }
    if base.output.is_some() {
        return Err((ERR_CLI_UNKNOWN_OPTION, "tracking does not export pixels"));
    }
    let package = PathBuf::from(super::required(&values, "--package")?);
    let package_digest = super::digest(&values, "--package-sha256")?;
    if package_digest.algorithm() != fss_core::DigestAlgorithm::Sha256 {
        return Err((ERR_CLI_MALFORMED_VALUE, "package identity must use SHA-256"));
    }
    let class_index = super::number(&values, "--class-index", usize::MAX)?;
    if class_index == usize::MAX {
        return Err((ERR_CLI_MISSING_VALUE, "explicit --class-index required"));
    }
    let minimum_score_ppm = if values.contains_key("--minimum-score-ppm") {
        let score = super::number(&values, "--minimum-score-ppm", 0_u32)?;
        if score > 1_000_000 {
            return Err((ERR_CLI_MALFORMED_VALUE, "minimum score must be 0..1000000 ppm"));
        }
        Some(score)
    } else {
        None
    };
    let iou_ppm = super::number(&values, "--track-iou-ppm", 100_000_u32)?;
    if iou_ppm > 1_000_000 {
        return Err((ERR_CLI_MALFORMED_VALUE, "tracking IoU must be 0..1000000 ppm"));
    }
    let tracker = TrackerConfig {
        min_hits: super::number(&values, "--track-min-hits", 2_u32)?,
        max_misses: super::number(&values, "--track-max-misses", 2_u32)?,
        iou_threshold: f64::from(iou_ppm) / 1_000_000.0,
        process_noise: 1.0,
        measurement_noise: 1.0,
    };
    tracker
        .validate()
        .map_err(|_| (ERR_CLI_MALFORMED_VALUE, "invalid tracker numerical policy"))?;
    let max_track_frames =
        super::number(&values, "--max-track-frames", base.decode.decode.max_groups)?;
    if !(1..=1024).contains(&max_track_frames) {
        return Err((ERR_CLI_MALFORMED_VALUE, "tracking frame ceiling must be 1..1024"));
    }
    let max_report_bytes = super::number(&values, "--max-report-bytes", 32 * 1024 * 1024)?;
    if !(1..=MAX_REPORT_BYTES).contains(&max_report_bytes) {
        return Err((ERR_CLI_MALFORMED_VALUE, "tracking report allowance exceeds profile"));
    }
    Ok(TrackOptions {
        base,
        settings: TrackSettings {
            package,
            package_digest,
            class_index,
            minimum_score_ppm,
            tracker,
            max_track_frames,
            report: values.get("--report-out").map(PathBuf::from),
            max_report_bytes,
        },
    })
}

fn execute(
    base: &Options,
    settings: &TrackSettings,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    let report = settings.report.as_deref().ok_or_else(|| failure("report output required"))?;
    let destination = PrivateOutputPath::prepare(report, root, cx)?;
    let scalar = ScalarExecCx::new();
    let result = execute_inner(base, settings, root, cx, &scalar, &destination, out);
    scalar.drain_and_finalize();
    result
}

fn execute_inner(
    base: &Options,
    settings: &TrackSettings,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    destination: &PrivateOutputPath,
    out: &mut impl Write,
) -> Result<()> {
    let bytes = read_package(&settings.package)?;
    let package = RgbDetectorPackage::load(
        &bytes,
        settings.package_digest,
        1 << 36,
        cx,
        scalar,
    )?;
    let label = package
        .spec()
        .labels
        .get(settings.class_index)
        .ok_or_else(|| failure("selected class is outside the verified package vocabulary"))?;
    let deployment = ReferenceDeployment::reopen(root, &base.site, cx)?;
    let retained = inspect_rtp_import(base.source_root, 1, base.policy, cx, &deployment)?;
    let parameters = base
        .parameters
        .or(retained.h264_parameters(cx)?.unique_pair())
        .ok_or_else(|| failure("select an exact in-source SPS/PPS pair"))?;
    let request = tracking_request(base, settings, parameters)?;
    let mut owner = RtpPackageTracker::new(&retained, &package, request, &deployment, cx, scalar)?;
    let recipe = owner.recipe();
    let header = format!(
        concat!(
            "{{\"type\":\"header\",\"format\":\"{}\",\"source_root\":\"{}\",",
            "\"package_sha256\":\"{}\",\"class_index\":{},\"class_label\":\"{}\",",
            "\"tracking_recipe\":\"{}\",\"sps\":\"{}\",\"pps\":\"{}\",",
            "\"time_unit\":\"observed_frame_step\",\"identity_authority\":false,",
            "\"absence_certifiable\":false,\"effect_authority\":false}}\n"
        ),
        REPORT_DOMAIN,
        retained.root(),
        settings.package_digest,
        settings.class_index,
        fss_cli::escape_json_str(label),
        recipe,
        parameters[0],
        parameters[1],
    );
    let mut report = ReportWriter::new(destination.create(cx)?, settings.max_report_bytes);
    let mut check = || destination.check(cx);
    report.record(header.as_bytes(), &mut check)?;
    let analysis = (|| -> Result<()> {
        loop {
            match owner.step(&deployment, cx, scalar)? {
                RtpTrackingStep::Frame(frame) => {
                    report.record(frame_json(&frame).as_bytes(), &mut check)?;
                    for observation in frame.observations() {
                        let detection = frame
                            .detected()
                            .detections()
                            .detections()
                            .get(observation.detection_index)
                            .ok_or_else(|| failure("tracking observation references missing detection"))?;
                        let [x1, y1, x2, y2] = detection.bounds();
                        let row = format!(
                            concat!(
                                "{{\"type\":\"observation\",\"frame_sha256\":\"{}\",",
                                "\"track_identity\":\"{}\",\"local_id\":{},\"detection_index\":{},",
                                "\"status\":\"{}\",\"hits\":{},\"score_bits\":{},",
                                "\"bounds_q256\":[{},{},{},{}]}}\n"
                            ),
                            frame.digest(),
                            observation.identity,
                            observation.local_id,
                            observation.detection_index,
                            status_name(observation.status),
                            observation.hits,
                            detection.score().to_bits(),
                            x1,
                            y1,
                            x2,
                            y2,
                        );
                        report.record(row.as_bytes(), &mut check)?;
                    }
                }
                RtpTrackingStep::Progress { event, effect } => {
                    let event = fss_cli::escape_json_str(&format!("{event:?}"));
                    let effect = fss_cli::escape_json_str(&format!("{effect:?}"));
                    let row = format!(
                        "{{\"type\":\"source_progress\",\"event\":\"{event}\",\"effect\":\"{effect}\"}}\n"
                    );
                    report.record(row.as_bytes(), &mut check)?;
                }
                RtpTrackingStep::Ended(stats) => {
                    if !stats.complete() {
                        return Err(failure("RTP tracking ended with incomplete source or analysis"));
                    }
                    break;
                }
            }
        }
        Ok(())
    })();
    let stats = owner.stats();
    write_stats(stats, out)?;
    let summary = summary_json(stats, analysis.is_ok() && stats.complete(), recipe);
    let finish = (|| -> Result<(ContentDigest, u64)> {
        report.record(summary.as_bytes(), &mut check)?;
        report.writer.flush()?;
        destination.sync(&report.writer, cx)?;
        Ok((
            ContentDigest::new(DigestAlgorithm::Sha256, report.hash.finalize()?),
            report.bytes,
        ))
    })();
    analysis?;
    let (digest, bytes) = finish?;
    writeln!(
        out,
        "tracking_complete=true\ntracking_report_complete=true\ntracking_report_bytes={bytes}\ntracking_report_sha256={digest}\ntracking_recipe={recipe}"
    )?;
    Ok(())
}

// Presentation-independent native request. JSON reports and portable transcripts must not
// evolve different source, privacy, numerical or lifetime tracking admissions.
fn tracking_request(
    base: &Options,
    settings: &TrackSettings,
    parameters: [ContentDigest; 2],
) -> Result<RtpTrackingRequest> {
    let mut detection = RtpDetectionRequest::new(RetainedRtpDecodeRequest {
        parameters,
        ..base.decode
    });
    detection.custody = RtpCustodyDecodeLimits {
        max_source_bytes: base.policy.max_source_bytes,
        max_records: base.policy.max_records,
        max_object_bytes: base.policy.max_object_bytes,
        max_read_bytes: base
            .custody_read_bytes
            .ok_or_else(|| failure("current custody required"))?,
        max_steps: base.steps,
        ..RtpCustodyDecodeLimits::default()
    };
    detection.minimum_score_ppm = settings.minimum_score_ppm;
    let mut limits = RtpTrackingLimits::default();
    limits.max_frames = settings.max_track_frames;
    Ok(RtpTrackingRequest {
        detection,
        class_index: settings.class_index,
        tracker: settings.tracker.clone(),
        limits,
    })
}

fn read_package(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RGB_PACKAGE_BYTES as u64 {
        return Err(failure("tracking package must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RGB_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RGB_PACKAGE_BYTES {
        return Err(failure("tracking package exceeds the package ceiling"));
    }
    Ok(bytes)
}

fn frame_json(frame: &RtpTrackedFrame) -> String {
    let source = frame.detected().source();
    let predecessor = frame
        .predecessor()
        .map_or_else(|| "null".to_owned(), |digest| format!("\"{digest}\""));
    format!(
        concat!(
            "{{\"type\":\"frame\",\"tracking_sha256\":\"{}\",\"predecessor\":{},",
            "\"detector_sha256\":\"{}\",\"frame_receipt\":\"{}\",\"output_index\":{},",
            "\"source_group\":{},\"decoder_epoch\":{},\"association_epoch\":{},",
            "\"reset\":\"{}\",\"active_tracks\":{},\"observations\":{}}}\n"
        ),
        frame.digest(),
        predecessor,
        frame.detected().digest(),
        frame.detected().receipt().digest(),
        source.output_index,
        source.group,
        source.decoder_epoch,
        frame.epoch(),
        reset_name(frame.reset()),
        frame.active_tracks(),
        frame.observations().len(),
    )
}

fn reset_name(reset: Option<RtpTrackReset>) -> &'static str {
    match reset {
        None => "none",
        Some(RtpTrackReset::Baseline) => "baseline",
        Some(RtpTrackReset::SourceGap) => "source_gap",
        Some(RtpTrackReset::DisplayGap) => "display_gap",
        Some(RtpTrackReset::ProjectionChanged) => "projection_changed",
    }
}
fn status_name(status: TrackStatus) -> &'static str {
    match status {
        TrackStatus::Tentative => "tentative",
        TrackStatus::Confirmed => "confirmed",
        TrackStatus::Lost => "lost",
    }
}

fn summary_json(stats: RtpTrackingStats, complete: bool, recipe: ContentDigest) -> String {
    format!(
        concat!(
            "{{\"type\":\"summary\",\"complete\":{},\"tracking_recipe\":\"{}\",",
            "\"tracking_frames\":{},\"assignments_reserved\":{},\"assignment_work_reserved\":{},",
            "\"resets\":{},\"failures\":{},\"detector_frames\":{},\"native_frames\":{},",
            "\"native_refusals\":{},\"native_complete\":{},\"identity_authority\":false,",
            "\"absence_certifiable\":false,\"effect_authority\":false}}\n"
        ),
        complete,
        recipe,
        stats.frames,
        stats.assignments_reserved,
        stats.assignment_work_reserved,
        stats.resets,
        stats.failures,
        stats.detection.frames,
        stats.detection.native.frames,
        stats.detection.native.refusals,
        stats.detection.native.complete(),
    )
}
fn write_stats(stats: RtpTrackingStats, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "tracking_frames={}\ntracking_assignments_reserved={}\ntracking_assignment_work_reserved={}\ntracking_resets={}\ntracking_failures={}",
        stats.frames,
        stats.assignments_reserved,
        stats.assignment_work_reserved,
        stats.resets,
        stats.failures,
    )?;
    writeln!(
        out,
        "detector_frames={}\ndetector_proposals={}\ncustody_read_bytes={}\nframe_receipt_bytes={}\nidentity_authority=false\nabsence_certifiable=false\neffect_authority=false",
        stats.detection.frames,
        stats.detection.proposals,
        stats.detection.custody_read_bytes,
        stats.detection.receipt_bytes,
    )?;
    super::statistics(stats.detection.native, out)
}

struct ReportWriter<W> {
    writer: W,
    hash: Sha256Hasher,
    maximum: u64,
    bytes: u64,
    failed: bool,
}
impl<W: Write> ReportWriter<W> {
    fn new(writer: W, maximum: u64) -> Self {
        Self {
            writer,
            hash: Sha256Hasher::new(),
            maximum,
            bytes: 0,
            failed: false,
        }
    }
    fn record(&mut self, row: &[u8], check: &mut impl FnMut() -> io::Result<()>) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("tracking report is fenced"));
        }
        let result = (|| {
            check()?;
            if row.len() > 4096 || row.len() as u64 > self.maximum.saturating_sub(self.bytes) {
                return Err(io::Error::other("tracking report allowance exhausted"));
            }
            let mut at = 0;
            let mut interruptions = 0;
            while at < row.len() {
                check()?;
                match self.writer.write(&row[at..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(count) if count <= row.len() - at => {
                        self.hash.update(&row[at..at + count]);
                        self.bytes += count as u64;
                        at += count;
                        interruptions = 0;
                    }
                    Ok(_) => return Err(io::Error::other("writer exceeded supplied slice")),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                        interruptions += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        let mut out: Vec<OsString> =
            ["track", "--root", "unused", "--site", "site:track", "--source-root"]
                .into_iter()
                .map(OsString::from)
                .collect();
        out.push(ContentDigest::sha256(b"root").to_string().into());
        out.extend(extra.iter().map(|value| OsString::from(*value)));
        out
    }
    fn valid<'a>(digest: &'a str) -> Vec<&'a str> {
        vec![
            "--custody",
            "current",
            "--package",
            "model.fmpk",
            "--package-sha256",
            digest,
            "--class-index",
            "0",
            "--report-out",
            "tracks.jsonl",
        ]
    }

    #[test]
    fn explicit_package_class_custody_and_report_are_required() -> Result<()> {
        let digest = ContentDigest::sha256(b"package").to_string();
        let required = valid(&digest);
        let parsed = parse(&args(&required)).map_err(|(_, reason)| failure(reason))?;
        assert_eq!(parsed.settings.class_index, 0);
        for key in [
            "--custody",
            "--package",
            "--package-sha256",
            "--class-index",
            "--report-out",
        ] {
            let filtered: Vec<_> = required
                .chunks_exact(2)
                .filter(|pair| pair[0] != key)
                .flatten()
                .copied()
                .collect();
            assert!(parse(&args(&filtered)).is_err(), "missing {key}");
        }
        Ok(())
    }

    #[test]
    fn invalid_policy_or_pixel_output_is_rejected() {
        let digest = ContentDigest::sha256(b"package").to_string();
        for extra in [
            vec!["--output", "pixels.pgm"],
            vec!["--track-min-hits", "0"],
            vec!["--track-iou-ppm", "1000001"],
            vec!["--max-track-frames", "0"],
            vec!["--minimum-score-ppm", "1000001"],
        ] {
            let mut all = valid(&digest);
            all.extend(extra);
            assert!(parse(&args(&all)).is_err());
        }
    }
}
