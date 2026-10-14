#![forbid(unsafe_code)]
//! Bounded operator presentation for verified neural detection over retained native RTP.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_reference::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use fss_reference::ingest::rtpdump::detect::{
    RtpDetectedFrame, RtpDetectionRequest, RtpDetectionStats, RtpDetectionStep, RtpPackageDetector,
};
use fss_reference::ingest::rtpdump::recovery::checked_decode::RtpCustodyDecodeLimits;
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::inspect_rtp_import;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::pgm_stream::private_output::PrivateOutputPath;
use super::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity, Options,
    ParseResult, Result, failure,
};

const REPORT_DOMAIN: &str = "fss.retained_rtp_detection_report.v1";
const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
struct DetectOptions {
    base: Options,
    settings: DetectSettings,
}
#[derive(Debug)]
struct DetectSettings {
    package: PathBuf,
    package_digest: ContentDigest,
    minimum_score_ppm: Option<u32>,
    report: PathBuf,
    max_report_bytes: u64,
}

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    if args.first().and_then(|value| value.to_str()) != Some("detect") {
        return None;
    }
    Some(match parse(args) {
        Err((id, reason)) => {
            eprintln!("{id}: {reason}");
            ExitCode::from(2)
        }
        Ok(DetectOptions { base, settings }) => {
            let mut out = io::stdout().lock();
            let result = super::run_with(base, &mut out, |base, root, cx, out| {
                execute(base, &settings, root, cx, out)
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "detection_complete=false\ndetection_report_complete=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}

fn parse(args: &[OsString]) -> ParseResult<DetectOptions> {
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
            "--minimum-score-ppm",
            "--report-out",
            "--max-report-bytes",
        ]
        .contains(&key)
        {
            if values.insert(key.to_owned(), value.clone()).is_some() {
                return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate detection option"));
            }
        } else {
            native.extend([args[at].clone(), value.clone()]);
        }
        at += 2;
    }
    let base = super::parse(&native)?
        .ok_or((ERR_CLI_MISSING_VALUE, "native decode options required"))?;
    if base.custody_read_bytes.is_none() {
        return Err((ERR_CLI_MALFORMED_VALUE, "detection requires --custody current"));
    }
    if base.output.is_some() {
        return Err((ERR_CLI_UNKNOWN_OPTION, "detection does not export pixels"));
    }
    let package = PathBuf::from(super::required(&values, "--package")?);
    let package_digest = super::digest(&values, "--package-sha256")?;
    if package_digest.algorithm() != fss_core::DigestAlgorithm::Sha256 {
        return Err((ERR_CLI_MALFORMED_VALUE, "package identity must use SHA-256"));
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
    let max_report_bytes = super::number(&values, "--max-report-bytes", 32 * 1024 * 1024)?;
    if !(1..=MAX_REPORT_BYTES).contains(&max_report_bytes) {
        return Err((ERR_CLI_MALFORMED_VALUE, "detection report allowance exceeds profile"));
    }
    Ok(DetectOptions {
        base,
        settings: DetectSettings {
            package,
            package_digest,
            minimum_score_ppm,
            report: PathBuf::from(super::required(&values, "--report-out")?),
            max_report_bytes,
        },
    })
}

fn execute(
    base: &Options,
    settings: &DetectSettings,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    let destination = PrivateOutputPath::prepare(&settings.report, root, cx)?;
    let scalar = ScalarExecCx::new();
    let result = execute_inner(base, settings, root, cx, &scalar, &destination, out);
    scalar.drain_and_finalize();
    result
}

fn execute_inner(
    base: &Options,
    settings: &DetectSettings,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    destination: &PrivateOutputPath,
    out: &mut impl Write,
) -> Result<()> {
    let package_bytes = read_package(&settings.package)?;
    let package =
        RgbDetectorPackage::load(&package_bytes, settings.package_digest, 1 << 36, cx, scalar)?;
    let deployment = ReferenceDeployment::reopen(root, &base.site, cx)?;
    let retained = inspect_rtp_import(base.source_root, 1, base.policy, cx, &deployment)?;
    let parameters = base
        .parameters
        .or(retained.h264_parameters(cx)?.unique_pair())
        .ok_or_else(|| failure("select an exact in-source SPS/PPS pair"))?;
    let mut request = RtpDetectionRequest::new(RetainedRtpDecodeRequest {
        parameters,
        ..base.decode
    });
    request.custody = RtpCustodyDecodeLimits {
        max_source_bytes: base.policy.max_source_bytes,
        max_records: base.policy.max_records,
        max_object_bytes: base.policy.max_object_bytes,
        max_read_bytes: base
            .custody_read_bytes
            .ok_or_else(|| failure("current custody required"))?,
        max_steps: base.steps,
        ..RtpCustodyDecodeLimits::default()
    };
    request.minimum_score_ppm = settings.minimum_score_ppm;
    request.analysis.max_frames = base.decode.decode.max_groups;
    let mut owner = RtpPackageDetector::new(&retained, &package, request, &deployment, cx, scalar)?;
    let recipe = owner.recipe();
    let header = format!(
        concat!(
            "{{\"type\":\"header\",\"format\":\"{}\",\"source_root\":\"{}\",",
            "\"package_sha256\":\"{}\",\"detection_recipe\":\"{}\",\"sps\":\"{}\",\"pps\":\"{}\",",
            "\"capture_time_class\":\"unknown\",\"calibrated_probability\":false,",
            "\"absence_certifiable\":false,\"effect_authority\":false}}\n"
        ),
        REPORT_DOMAIN,
        retained.root(),
        settings.package_digest,
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
                RtpDetectionStep::Frame(frame) => {
                    report.record(frame_json(&frame).as_bytes(), &mut check)?;
                    for (index, detection) in frame.detections().detections().iter().enumerate() {
                        let label = package
                            .spec()
                            .labels
                            .get(detection.class_index())
                            .ok_or_else(|| failure("detector class is outside verified vocabulary"))?;
                        let [x1, y1, x2, y2] = detection.bounds();
                        let row = format!(
                            concat!(
                                "{{\"type\":\"proposal\",\"frame_sha256\":\"{}\",\"index\":{},",
                                "\"row\":{},\"class_index\":{},\"label\":\"{}\",\"score_bits\":{},",
                                "\"bounds_q256\":[{},{},{},{}],\"clipped\":{}}}\n"
                            ),
                            frame.digest(),
                            index,
                            detection.row(),
                            detection.class_index(),
                            fss_cli::escape_json_str(label),
                            detection.score().to_bits(),
                            x1,
                            y1,
                            x2,
                            y2,
                            detection.clipped(),
                        );
                        report.record(row.as_bytes(), &mut check)?;
                    }
                }
                RtpDetectionStep::Progress { .. } => {}
                RtpDetectionStep::Ended(stats) => {
                    if !stats.complete() {
                        return Err(failure("RTP detection ended with incomplete source or analysis"));
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
        "detection_complete=true\ndetection_report_complete=true\ndetection_report_bytes={bytes}\ndetection_report_sha256={digest}\ndetection_recipe={recipe}"
    )?;
    Ok(())
}

fn read_package(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RGB_PACKAGE_BYTES as u64 {
        return Err(failure("detection package must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RGB_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RGB_PACKAGE_BYTES {
        return Err(failure("detection package exceeds the package ceiling"));
    }
    Ok(bytes)
}

fn frame_json(frame: &RtpDetectedFrame) -> String {
    let source = frame.source();
    format!(
        concat!(
            "{{\"type\":\"frame\",\"detection_sha256\":\"{}\",\"frame_receipt\":\"{}\",",
            "\"output_index\":{},\"source_group\":{},\"decoder_epoch\":{},\"rtp_timestamp\":{},",
            "\"capture_earliest_ns\":\"{}\",\"capture_latest_ns\":\"{}\",",
            "\"dimensions\":[{},{}],\"privacy_binding\":\"{}\",\"privacy_policy\":{},",
            "\"head_rows\":{},\"head_candidates\":{},\"proposals\":{}}}\n"
        ),
        frame.digest(),
        frame.receipt().digest(),
        source.output_index,
        source.group,
        source.decoder_epoch,
        source.rtp_timestamp,
        source.capture.earliest.0,
        source.capture.latest.0,
        source.dimensions[0],
        source.dimensions[1],
        source.privacy,
        source
            .policy
            .map_or_else(|| "null".to_owned(), |digest| format!("\"{digest}\"")),
        frame.detections().rows().len(),
        frame.detections().candidates().len(),
        frame.detections().detections().len(),
    )
}

fn summary_json(stats: RtpDetectionStats, complete: bool, recipe: ContentDigest) -> String {
    format!(
        concat!(
            "{{\"type\":\"summary\",\"complete\":{},\"detection_recipe\":\"{}\",",
            "\"attempts\":{},\"frames\":{},\"proposals\":{},\"failures\":{},",
            "\"native_frames\":{},\"native_refusals\":{},\"native_complete\":{},",
            "\"custody_read_bytes\":{},\"receipt_bytes\":{},\"execution_macs\":{},",
            "\"calibrated_probability\":false,\"absence_certifiable\":false,\"effect_authority\":false}}\n"
        ),
        complete,
        recipe,
        stats.attempts,
        stats.frames,
        stats.proposals,
        stats.failures,
        stats.native.frames,
        stats.native.refusals,
        stats.native.complete(),
        stats.custody_read_bytes,
        stats.receipt_bytes,
        stats.execution_macs,
    )
}
fn write_stats(stats: RtpDetectionStats, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "detection_attempts={}\ndetection_frames={}\ndetection_proposals={}\ndetection_failures={}\ndetection_execution_macs={}",
        stats.attempts, stats.frames, stats.proposals, stats.failures, stats.execution_macs
    )?;
    writeln!(
        out,
        "custody_read_bytes={}\nframe_receipt_bytes={}\ncalibrated_probability=false\nabsence_certifiable=false\neffect_authority=false",
        stats.custody_read_bytes, stats.receipt_bytes
    )?;
    super::statistics(stats.native, out)
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
            return Err(io::Error::other("detection report is fenced"));
        }
        let result = (|| {
            check()?;
            if row.len() > 4096 || row.len() as u64 > self.maximum.saturating_sub(self.bytes) {
                return Err(io::Error::other("detection report allowance exhausted"));
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
        let mut output: Vec<OsString> =
            ["detect", "--root", "unused", "--site", "site:detect", "--source-root"]
                .into_iter()
                .map(OsString::from)
                .collect();
        output.push(ContentDigest::sha256(b"root").to_string().into());
        output.extend(extra.iter().map(|value| OsString::from(*value)));
        output
    }
    fn valid<'a>(digest: &'a str) -> Vec<&'a str> {
        vec![
            "--custody",
            "current",
            "--package",
            "model.fmpk",
            "--package-sha256",
            digest,
            "--report-out",
            "detections.jsonl",
        ]
    }

    #[test]
    fn explicit_package_current_custody_and_report_are_required() -> Result<()> {
        let digest = ContentDigest::sha256(b"package").to_string();
        let required = valid(&digest);
        let parsed = parse(&args(&required)).map_err(|(_, reason)| failure(reason))?;
        assert_eq!(parsed.settings.minimum_score_ppm, None);
        for key in ["--custody", "--package", "--package-sha256", "--report-out"] {
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
    fn invalid_score_report_bound_and_pixel_output_refuse() {
        let digest = ContentDigest::sha256(b"package").to_string();
        for extra in [
            vec!["--output", "pixels.pgm"],
            vec!["--minimum-score-ppm", "1000001"],
            vec!["--max-report-bytes", "0"],
        ] {
            let mut all = valid(&digest);
            all.extend(extra);
            assert!(parse(&args(&all)).is_err());
        }
    }
}
