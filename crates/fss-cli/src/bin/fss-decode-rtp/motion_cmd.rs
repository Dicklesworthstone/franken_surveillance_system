#![forbid(unsafe_code)]
//! Bounded operator candidate measurements over the shared custody-checked RTP analyzer.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_reference::ingest::pixel_change::PixelChangeConfig;
use fss_reference::ingest::pixel_change::rtp::{
    RtpMotionAnalyzer, RtpMotionRequest, RtpMotionStats, RtpMotionStep, RtpPixelChangeObservation,
};
use fss_reference::ingest::rtpdump::decode::RtpDecodeEffect;
use fss_reference::ingest::rtpdump::recovery::checked_decode::RtpCustodyDecodeLimits;
use fss_reference::ingest::rtpdump::recovery::decode::{
    RetainedRtpDecodeRequest, RetainedRtpEvent,
};
use fss_reference::ingest::rtpdump::recovery::inspect_rtp_import;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::pgm_stream::private_output::PrivateOutputPath;
use super::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity, Options,
    ParseResult, Result, failure,
};

const REPORT_DOMAIN: &str = "fss.retained_rtp_motion_report.v1";
const MAX_REPORT: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
struct MotionOptions {
    base: Options,
    settings: MotionSettings,
}

#[derive(Debug)]
struct MotionSettings {
    thresholds: PixelChangeConfig,
    comparisons: u64,
    path: PathBuf,
    maximum: u64,
}

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    if args.first().and_then(|a| a.to_str()) != Some("motion") {
        return None;
    }
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Some(
            match io::stdout().lock().write_all(super::HELP.as_bytes()) {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
            },
        );
    }
    Some(match parse(args) {
        Err((id, reason)) => {
            eprintln!("{id}: {reason}");
            ExitCode::from(2)
        }
        Ok(options) => {
            let MotionOptions { base, settings } = options;
            let mut out = io::stdout().lock();
            let result = super::run_with(base, &mut out, |base, root, cx, out| {
                execute(base, &settings, root, cx, out)
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "motion_complete=false\nmotion_report_complete=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}

fn parse(args: &[OsString]) -> ParseResult<MotionOptions> {
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
            "--pixel-delta",
            "--minimum-changed-pixels",
            "--minimum-changed-ppm",
            "--max-comparisons",
            "--report-out",
            "--max-report-bytes",
        ]
        .contains(&key)
        {
            if values.insert(key.to_owned(), value.clone()).is_some() {
                return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate motion option"));
            }
        } else {
            native.extend([args[at].clone(), value.clone()]);
        }
        at += 2;
    }
    let base =
        super::parse(&native)?.ok_or((ERR_CLI_MISSING_VALUE, "native decode options required"))?;
    if base.custody_read_bytes.is_none() {
        return Err((ERR_CLI_MALFORMED_VALUE, "motion requires --custody current"));
    }
    if base.output.is_some() {
        return Err((
            ERR_CLI_UNKNOWN_OPTION,
            "motion exports measurements, not pixels; use --report-out",
        ));
    }
    // These operating thresholds must be chosen by the caller, not silently calibrated here.
    super::required(&values, "--pixel-delta")?;
    super::required(&values, "--minimum-changed-pixels")?;
    let thresholds = PixelChangeConfig {
        minimum_delta: super::number(&values, "--pixel-delta", 0)?,
        minimum_changed_pixels: super::number(&values, "--minimum-changed-pixels", 0)?,
        minimum_changed_fraction_ppm: super::number(&values, "--minimum-changed-ppm", 0)?,
    };
    thresholds
        .validate()
        .map_err(|_| (ERR_CLI_MALFORMED_VALUE, "invalid pixel-change thresholds"))?;
    let comparisons = super::number(&values, "--max-comparisons", 64_000_000)?;
    let maximum = super::number(&values, "--max-report-bytes", 16 * 1024 * 1024)?;
    if !(1..=MAX_REPORT).contains(&maximum) {
        return Err((
            ERR_CLI_MALFORMED_VALUE,
            "motion report allowance exceeds the command profile",
        ));
    }
    let path = PathBuf::from(super::required(&values, "--report-out")?);
    Ok(MotionOptions {
        base,
        settings: MotionSettings {
            thresholds,
            comparisons,
            path,
            maximum,
        },
    })
}

fn execute(
    base: &Options,
    settings: &MotionSettings,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    let thresholds = settings.thresholds;
    let comparisons = settings.comparisons;
    let maximum = settings.maximum;
    let path = &settings.path;
    // Validate the output destination before any decode, but create no file on failed admission.
    let destination = PrivateOutputPath::prepare(path, root, cx)?;
    let deployment = ReferenceDeployment::reopen(root, &base.site, cx)?;
    let retained = inspect_rtp_import(base.source_root, 1, base.policy, cx, &deployment)?;
    let parameters = base
        .parameters
        .or(retained.h264_parameters(cx)?.unique_pair())
        .ok_or_else(|| {
            failure("select an exact in-source SPS/PPS pair; no unambiguous pair exists")
        })?;
    let mut request = RtpMotionRequest::new(
        RetainedRtpDecodeRequest {
            parameters,
            ..base.decode
        },
        thresholds,
        comparisons,
    );
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
    let mut analyzer = RtpMotionAnalyzer::open(&retained, request, &deployment, cx)?;
    let header = format!(
        concat!(
            "{{\"type\":\"header\",\"format\":\"{}\",\"source_root\":\"{}\",",
            "\"source_sha256\":\"{}\",\"configuration_digest\":\"{}\",",
            "\"sps\":\"{}\",\"pps\":\"{}\",\"minimum_delta\":{},\"minimum_changed_pixels\":{},",
            "\"minimum_changed_fraction_ppm\":{},\"maximum_comparisons\":{},",
            "\"custody_mode\":\"current\",\"capture_time_class\":\"unknown\",",
            "\"absence_certifiable\":false,\"effect_authority\":false,\"decode_published\":false}}\n"
        ),
        REPORT_DOMAIN,
        retained.root(),
        retained.report().input_digest(),
        thresholds.digest(),
        parameters[0],
        parameters[1],
        thresholds.minimum_delta,
        thresholds.minimum_changed_pixels,
        thresholds.minimum_changed_fraction_ppm,
        comparisons
    );
    if header.len() as u64 > maximum {
        return Err(failure("motion report header exceeds allowance"));
    }
    let mut report = ReportWriter::new(destination.create(cx)?, maximum);
    let mut check = || destination.check(cx);
    report.record(header.as_bytes(), &mut check)?;
    let analysis = (|| -> Result<()> {
        loop {
            match analyzer.step(&deployment, cx)? {
                RtpMotionStep::Observation(observation) => {
                    report.record(observation_json(&observation).as_bytes(), &mut check)?;
                }
                RtpMotionStep::Progress { event, effect } => {
                    let row = match effect {
                        RtpDecodeEffect::Refused {
                            retired_groups,
                            awaiting_idr,
                            resumed_group,
                            error,
                        } => {
                            let resumed =
                                resumed_group.map_or_else(|| "null".to_owned(), |v| v.to_string());
                            let reason = fss_cli::escape_json_str(&format!("{error:?}"));
                            Some(format!(
                                "{{\"type\":\"decode_refused\",\"reason\":\"{reason}\",\"retired_groups\":{retired_groups},\"awaiting_idr\":{awaiting_idr},\"resumed_group\":{resumed}}}\n"
                            ))
                        }
                        RtpDecodeEffect::WaitingForIdr { group } => Some(format!(
                            "{{\"type\":\"waiting_for_idr\",\"source_group\":{group}}}\n"
                        )),
                        _ => None,
                    };
                    let row = row.or_else(|| match event {
                        RetainedRtpEvent::RecordRefused { .. }
                        | RetainedRtpEvent::FramingRefused
                        | RetainedRtpEvent::ReceiverRefused => {
                            let reason = fss_cli::escape_json_str(&format!("{event:?}"));
                            Some(format!(
                                "{{\"type\":\"receiver_refused\",\"reason\":\"{reason}\"}}\n"
                            ))
                        }
                        _ => None,
                    });
                    if let Some(row) = row {
                        report.record(row.as_bytes(), &mut check)?;
                    }
                }
                RtpMotionStep::Ended(stats) => {
                    if !stats.complete() {
                        return Err(failure(
                            "RTP motion analysis is incomplete; source gaps are not quietness",
                        ));
                    }
                    break;
                }
            }
        }
        Ok(())
    })();
    let stats = analyzer.stats();
    // Summary retains actual work even when the report quota or native analysis failed.
    write_stats(stats, out)?;
    let complete = analysis.is_ok() && stats.complete();
    let summary = summary_json(stats, complete);
    // A fenced/over-budget writer cannot report a shorter prefix as complete. Owner cancellation
    // also refuses this write; previously delivered historical rows are not retroactively changed.
    let finish = (|| -> Result<(ContentDigest, u64)> {
        report.record(summary.as_bytes(), &mut check)?;
        check()?;
        report.writer.flush()?;
        destination.sync(&report.writer, cx)?;
        Ok((
            ContentDigest::new(DigestAlgorithm::Sha256, report.hash.finalize()?),
            report.bytes,
        ))
    })();
    analysis?;
    let (digest, report_bytes) = finish?;
    writeln!(
        out,
        "motion_complete=true\nmotion_report_complete=true\nmotion_report_bytes={}\nmotion_report_sha256={digest}",
        report_bytes
    )?;
    Ok(())
}

fn observation_json(o: &RtpPixelChangeObservation) -> String {
    let predecessor = o
        .predecessor_receipt
        .map_or_else(|| "null".to_owned(), |d| format!("\"{d}\""));
    let resets = o
        .reset_reasons
        .iter()
        .map(|r| format!("\"{}\"", r.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let comparison = o.statistics.as_ref().map_or_else(|| "null".to_owned(), |s| {
        let bounds = s.changed_bounds.map_or_else(|| "null".to_owned(), |b|
            format!("[{},{},{},{}]", b.left, b.top, b.right, b.bottom));
        format!("{{\"compared_pixels\":{},\"changed_pixels\":{},\"absolute_difference_sum\":{},\"maximum_difference\":{},\"changed_bounds_half_open\":{bounds},\"candidate\":{}}}",
            s.compared_pixels, s.changed_pixels, s.absolute_difference_sum, s.maximum_difference, s.candidate)
    });
    format!(
        concat!(
            "{{\"type\":\"observation\",\"observation_sha256\":\"{}\",\"source_root\":\"{}\",",
            "\"frame_receipt\":\"{}\",\"predecessor_receipt\":{},\"recipe\":\"{}\",",
            "\"output_index\":{},\"source_group\":{},\"decoder_epoch\":{},\"rtp_timestamp\":{},",
            "\"capture_earliest_ns\":\"{}\",\"capture_latest_ns\":\"{}\",\"dimensions\":[{},{}],",
            "\"mask_binding\":\"{}\",\"configuration_digest\":\"{}\",\"reset_reasons\":[{}],\"comparison\":{}}}\n"
        ),
        o.digest(),
        o.source_root,
        o.frame_receipt,
        predecessor,
        o.recipe,
        o.output_index,
        o.source_group,
        o.decoder_epoch,
        o.rtp_timestamp,
        o.capture.earliest.0,
        o.capture.latest.0,
        o.dimensions[0],
        o.dimensions[1],
        o.mask_binding,
        o.configuration_digest,
        resets,
        comparison
    )
}
fn summary_json(s: RtpMotionStats, complete: bool) -> String {
    format!(
        concat!(
            "{{\"type\":\"summary\",\"complete\":{},\"observations\":{},",
            "\"measured_pairs\":{},\"candidate_pairs\":{},\"baseline_resets\":{},",
            "\"pixel_comparisons\":{},\"records_visited\":{},\"native_frames\":{},",
            "\"refused_steps\":{},\"skipped_groups\":{},\"native_complete\":{},",
            "\"custody_read_bytes\":{},\"receipt_bytes\":{},\"steps\":{},\"analyzer_failures\":{},",
            "\"analysis_ended\":{},\"absence_certifiable\":false,\"effect_authority\":false}}\n"
        ),
        complete,
        s.observations,
        s.measured_pairs,
        s.candidate_pairs,
        s.resets,
        s.comparisons,
        s.decode.records,
        s.decode.frames,
        s.decode.refusals,
        s.decode.skipped_groups,
        s.decode.complete(),
        s.custody_read_bytes,
        s.receipt_bytes,
        s.steps,
        s.failures,
        s.ended
    )
}
fn write_stats(s: RtpMotionStats, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "motion_observations={}\nmotion_measured_pairs={}\nmotion_candidate_pairs={}\nmotion_baseline_resets={}\nmotion_pixel_comparisons={}",
        s.observations, s.measured_pairs, s.candidate_pairs, s.resets, s.comparisons
    )?;
    writeln!(
        out,
        "custody_read_bytes={}\nframe_receipt_bytes={}\nmotion_steps={}\nmotion_failures={}\nabsence_certifiable=false\neffect_authority=false\ndecode_published=false",
        s.custody_read_bytes, s.receipt_bytes, s.steps, s.failures
    )?;
    super::statistics(s.decode, out)
}

// One bounded line at a time, independently admitted before any byte of the line is written.
// A sink failure fences the writer; interrupted writes and cancellation never spin unboundedly.
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
            return Err(io::Error::other("motion report is fenced"));
        }
        let result = (|| {
            check()?;
            if row.len() > 4096 || row.len() as u64 > self.maximum.saturating_sub(self.bytes) {
                return Err(io::Error::other("motion report allowance exhausted"));
            }
            let mut at = 0;
            let mut interruptions = 0;
            while at < row.len() {
                check()?;
                match self.writer.write(&row[at..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) if n <= row.len() - at => {
                        self.hash.update(&row[at..at + n]);
                        self.bytes += n as u64;
                        at += n;
                        interruptions = 0;
                    }
                    Ok(_) => return Err(io::Error::other("writer exceeded supplied slice")),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                        interruptions += 1
                    }
                    Err(e) => return Err(e),
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
        let mut out: Vec<OsString> = [
            "motion",
            "--root",
            "unused",
            "--site",
            "site:motion",
            "--source-root",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        out.push(ContentDigest::sha256(b"root").to_string().into());
        out.extend(extra.iter().map(OsString::from));
        out
    }
    const VALID: &[&str] = &[
        "--custody",
        "current",
        "--pixel-delta",
        "20",
        "--minimum-changed-pixels",
        "2",
        "--report-out",
        "motion.jsonl",
    ];
    #[test]
    fn motion_admission_requires_explicit_thresholds_custody_and_report() -> Result<()> {
        let parsed = parse(&args(VALID)).map_err(|(_, s)| failure(s))?;
        assert_eq!(parsed.settings.thresholds.minimum_delta, 20);
        assert_eq!(parsed.settings.comparisons, 64_000_000);
        for key in [
            "--pixel-delta",
            "--minimum-changed-pixels",
            "--report-out",
            "--custody",
        ] {
            let filtered: Vec<_> = VALID
                .chunks_exact(2)
                .filter(|p| p[0] != key)
                .flatten()
                .copied()
                .collect();
            assert!(parse(&args(&filtered)).is_err());
        }
        Ok(())
    }
    #[test]
    fn duplicate_or_malformed_motion_options_refuse() {
        for extra in [
            vec!["--pixel-delta", "1"],
            vec!["--output", "pixels.pgm"],
            vec!["--minimum-changed-ppm", "1000001"],
            vec!["--max-report-bytes", "0"],
            vec!["--max-report-bytes", "67108865"],
            vec!["--max-comparisons", "-1"],
            vec!["--unknown", "x"],
        ] {
            let mut all = VALID.to_vec();
            all.extend(extra);
            assert!(parse(&args(&all)).is_err());
        }
    }
    #[test]
    fn zero_comparison_budget_admits_only_a_baseline_without_resetting_decode_limits() -> Result<()>
    {
        let mut all = VALID.to_vec();
        all.extend(["--max-comparisons", "0", "--max-steps", "9"]);
        let parsed = parse(&args(&all)).map_err(|(_, s)| failure(s))?;
        assert_eq!(parsed.settings.comparisons, 0);
        assert_eq!(parsed.base.steps, 9);
        Ok(())
    }
    struct Short {
        bytes: Vec<u8>,
        failure: Option<usize>,
    }
    impl Write for Short {
        fn write(&mut self, row: &[u8]) -> io::Result<usize> {
            if self.failure.is_some_and(|max| self.bytes.len() >= max) {
                return Err(io::Error::other("sink failure"));
            }
            let n = row.len().min(7).min(
                self.failure
                    .map_or(usize::MAX, |max| max - self.bytes.len()),
            );
            self.bytes.extend_from_slice(&row[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn report_short_writes_and_whole_record_allowance_preserve_digest() -> Result<()> {
        let mut w = ReportWriter::new(
            Short {
                bytes: Vec::new(),
                failure: None,
            },
            13,
        );
        let row = b"test-record\n";
        w.record(row, &mut || Ok(()))?;
        assert_eq!(w.writer.bytes, row);
        assert_eq!(
            w.hash.clone().finalize()?,
            ContentDigest::sha256(row).bytes()
        );
        assert!(w.record(row, &mut || Ok(())).is_err());
        assert_eq!(w.writer.bytes, row);
        assert!(w.record(b"a", &mut || Ok(())).is_err());
        Ok(())
    }
    #[test]
    fn cancelled_and_failed_report_writes_are_terminal() {
        let mut w = ReportWriter::new(
            Short {
                bytes: Vec::new(),
                failure: Some(8),
            },
            100,
        );
        assert!(w.record(b"longer-than-eight\n", &mut || Ok(())).is_err());
        assert_eq!(w.bytes, 8);
        assert!(w.record(b"x", &mut || Ok(())).is_err());
        let mut w = ReportWriter::new(Vec::new(), 100);
        assert!(
            w.record(b"no\n", &mut || Err(io::Error::other("cancelled")))
                .is_err()
        );
        assert_eq!(w.bytes, 0);
        assert!(w.record(b"no\n", &mut || Ok(())).is_err());
    }
}
