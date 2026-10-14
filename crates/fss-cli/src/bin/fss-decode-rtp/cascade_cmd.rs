#![forbid(unsafe_code)]
//! Explicit sampling over the same native custody, verified package and private report owners.

use super::*;
use super::super::{number, required};
use fss_cli::agent_json::{object, string};
use fss_reference::ingest::activity::{ActivityPolicy, SamplingReason};
use fss_reference::ingest::pixel_change::PixelChangeConfig;
use fss_reference::ingest::rtpdump::detect::cascade::{
    RtpCascadeFrame, RtpCascadeRequest, RtpCascadeStats, RtpCascadeStep,
    RtpComparisonUnavailable, RtpDetectionCascade,
};

const FORMAT: &str = "fss.retained_rtp_cascade_report.v1";

struct CascadeOptions {
    detector: DetectOptions,
    sampling: Settings,
}
#[derive(Clone, Debug)]
struct Settings {
    policy: ActivityPolicy,
    comparisons: u64,
    baseline_bytes: usize,
    decision_bytes: u64,
    inference_frames: usize,
    required: Vec<(usize, ContentDigest)>,
}

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    if args.first().and_then(|value| value.to_str()) != Some("cascade") {
        return None;
    }
    Some(match parse(args) {
        Err((id, reason)) => {
            eprintln!("{id}: {reason}");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
        Ok(options) => {
            let mut out = io::stdout().lock();
            let CascadeOptions { detector, sampling } = options;
            let DetectOptions { base, settings } = detector;
            let result = super::super::run_with(base, &mut out, |base, root, cx, out| {
                execute(base, &settings, &sampling, root, cx, out)
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "sampling_complete=false\ncascade_report_complete=false\nall_frames_inferred=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}

fn parse(args: &[OsString]) -> ParseResult<CascadeOptions> {
    if args.len() > 257 || args.len() % 2 != 1
        || args.iter().any(|value| value.as_encoded_bytes().len() > 4096)
    {
        return Err((ERR_CLI_MALFORMED_VALUE, "bounded paired cascade options required"));
    }
    let mut native = vec![OsString::from("detect")];
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or((ERR_CLI_INVALID_UNICODE, "UTF-8 option required"))?;
        if [
            "--pixel-delta", "--minimum-changed-pixels", "--minimum-changed-ppm",
            "--sentinel-stride", "--post-activity-frames", "--max-comparisons",
            "--max-baseline-bytes", "--max-sampling-bytes", "--max-inference-frames",
            "--required-frames",
        ].contains(&key) {
            if values.insert(key.to_owned(), pair[1].clone()).is_some() {
                return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate cascade option"));
            }
        } else {
            native.extend_from_slice(pair);
        }
    }
    // The existing detector parser remains the sole package/custody/output admission owner.
    let detector = super::parse(&native)?;
    for key in ["--pixel-delta", "--minimum-changed-pixels", "--sentinel-stride"] {
        required(&values, key)?;
    }
    let policy = ActivityPolicy {
        change: PixelChangeConfig {
            minimum_delta: number(&values, "--pixel-delta", 0)?,
            minimum_changed_pixels: number(&values, "--minimum-changed-pixels", 0)?,
            minimum_changed_fraction_ppm: number(&values, "--minimum-changed-ppm", 0)?,
        },
        sentinel_stride: number(&values, "--sentinel-stride", 0)?,
        post_activity_frames: number(&values, "--post-activity-frames", 0)?,
    };
    policy.validate().map_err(|_| (ERR_CLI_MALFORMED_VALUE, "invalid explicit sampling policy"))?;
    let baseline_bytes = number(&values, "--max-baseline-bytes", 4_194_304)?;
    let decision_bytes = number(&values, "--max-sampling-bytes", 16 * 1024 * 1024)?;
    let inference_frames = number(&values, "--max-inference-frames",
        detector.base.decode.decode.max_groups.min(1024))?;
    if baseline_bytes > 4_194_304 || !(4096..=64 * 1024 * 1024).contains(&decision_bytes)
        || !(1..=1024).contains(&inference_frames)
    {
        return Err((ERR_CLI_MALFORMED_VALUE, "cascade allowance exceeds its bounded profile"));
    }
    let mut required_frames = BTreeMap::new();
    if let Some(value) = values.get("--required-frames") {
        let value = value.to_str().ok_or((ERR_CLI_INVALID_UNICODE, "UTF-8 inclusion map required"))?;
        for entry in value.split(',') {
            let (index, digest) = entry.split_once('=')
                .ok_or((ERR_CLI_MALFORMED_VALUE, "required frames use INDEX=sha256:HEX"))?;
            if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
                return Err((ERR_CLI_MALFORMED_VALUE, "unsigned required-frame position required"));
            }
            let index = index.parse::<usize>().ok().filter(|index| *index < 4096)
                .ok_or((ERR_CLI_MALFORMED_VALUE, "required-frame position exceeds native profile"))?;
            let digest = ContentDigest::parse(digest)
                .map_err(|_| (ERR_CLI_MALFORMED_VALUE, "exact inclusion basis required"))?;
            if digest.algorithm() != DigestAlgorithm::Sha256
                || required_frames.insert(index, digest).is_some()
            {
                return Err((ERR_CLI_MALFORMED_VALUE, "duplicate position or non-SHA256 inclusion basis"));
            }
        }
    }
    Ok(CascadeOptions {
        detector,
        sampling: Settings {
            policy,
            comparisons: number(&values, "--max-comparisons", 64_000_000)?,
            baseline_bytes,
            decision_bytes,
            inference_frames,
            required: required_frames.into_iter().collect(),
        },
    })
}

fn execute(
    base: &Options,
    settings: &DetectSettings,
    sampling: &Settings,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    let destination = PrivateOutputPath::prepare(&settings.report, root, cx)?;
    let scalar = ScalarExecCx::new();
    let result = execute_inner(base, (settings, sampling), root, cx, &scalar, &destination, out);
    scalar.drain_and_finalize();
    result
}

fn execute_inner(
    base: &Options,
    settings: (&DetectSettings, &Settings),
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    destination: &PrivateOutputPath,
    out: &mut impl Write,
) -> Result<()> {
    let (settings, sampling) = settings;
    cx.checkpoint("rtp_cascade_cli:package")?;
    let bytes = read_package(&settings.package)?;
    cx.checkpoint("rtp_cascade_cli:package")?;
    let package = RgbDetectorPackage::load(&bytes, settings.package_digest, 1 << 36, cx, scalar)?;
    let deployment = ReferenceDeployment::reopen(root, &base.site, cx)?;
    let retained = inspect_rtp_import(base.source_root, 1, base.policy, cx, &deployment)?;
    let parameters = base.parameters.or(retained.h264_parameters(cx)?.unique_pair())
        .ok_or_else(|| failure("select an exact in-source SPS/PPS pair"))?;
    let mut detection = RtpDetectionRequest::new(RetainedRtpDecodeRequest { parameters, ..base.decode });
    detection.custody = RtpCustodyDecodeLimits {
        max_source_bytes: base.policy.max_source_bytes,
        max_records: base.policy.max_records,
        max_object_bytes: base.policy.max_object_bytes,
        max_read_bytes: base.custody_read_bytes.ok_or_else(|| failure("current custody required"))?,
        max_steps: base.steps,
        ..RtpCustodyDecodeLimits::default()
    };
    detection.minimum_score_ppm = settings.minimum_score_ppm;
    detection.analysis.max_frames = sampling.inference_frames;
    let mut request = RtpCascadeRequest::new(detection, sampling.policy, sampling.comparisons);
    request.max_baseline_bytes = sampling.baseline_bytes;
    request.max_decision_bytes = sampling.decision_bytes;
    request.required_frames = sampling.required.clone();
    let mut owner = RtpDetectionCascade::new(&retained, &package, request, &deployment, cx, scalar)?;
    let recipe = owner.recipe();
    let header = object(&[
        ("type", string("header")), ("format", string(FORMAT)),
        ("source_root", string(&retained.root().to_text())),
        ("package_sha256", string(&settings.package_digest.to_text())),
        ("cascade_recipe", string(&recipe.to_text())),
        ("policy", string(&sampling.policy.digest().to_text())),
        ("sps", string(&parameters[0].to_text())), ("pps", string(&parameters[1].to_text())),
        ("minimum_delta", sampling.policy.change.minimum_delta.to_string()),
        ("minimum_changed_pixels", sampling.policy.change.minimum_changed_pixels.to_string()),
        ("minimum_changed_fraction_ppm", sampling.policy.change.minimum_changed_fraction_ppm.to_string()),
        ("sentinel_stride", sampling.policy.sentinel_stride.to_string()),
        ("post_activity_frames", sampling.policy.post_activity_frames.to_string()),
        ("maximum_comparisons", sampling.comparisons.to_string()),
        ("maximum_baseline_bytes", sampling.baseline_bytes.to_string()),
        ("maximum_sampling_bytes", sampling.decision_bytes.to_string()),
        ("maximum_inference_frames", sampling.inference_frames.to_string()),
        ("required_frame_count", sampling.required.len().to_string()),
        ("custody_mode", string("current")), ("capture_time_class", string("unknown")),
        ("skip_interpretation", string("model_not_executed:not_empty_detections")),
        ("calibrated_probability", "false".into()),
        ("absence_certifiable", "false".into()), ("effect_authority", "false".into()),
    ]) + "\n";
    if header.len() > 4096 || header.len() as u64 > settings.max_report_bytes {
        return Err(failure("cascade header exceeds the report allowance"));
    }
    let mut report = ReportWriter::new(destination.create(cx)?, settings.max_report_bytes);
    let mut check = || destination.check(cx);
    report.record(header.as_bytes(), &mut check)?;
    let analysis = (|| -> Result<()> {
        loop {
            match owner.step(&deployment, cx, scalar)? {
                RtpCascadeStep::Frame(frame) => {
                    report.record(sampling_json(&frame).as_bytes(), &mut check)?;
                    if let Some(detected) = frame.detection() {
                        write_frame(detected, &package, &mut report, &mut check)?;
                    }
                }
                RtpCascadeStep::Progress { event, effect } => {
                    let row = object(&[
                        ("type", string("source_progress")),
                        ("event", string(&format!("{event:?}"))),
                        ("effect", string(&format!("{effect:?}"))),
                    ]) + "\n";
                    report.record(row.as_bytes(), &mut check)?;
                }
                RtpCascadeStep::Ended(stats) => {
                    if !stats.complete() {
                        return Err(failure("sampling ended with incomplete source, selected inference or required-frame coverage"));
                    }
                    break;
                }
            }
        }
        Ok(())
    })();
    let stats = owner.stats();
    write_stats(stats.detection, out)?;
    writeln!(out, "sampling_frames={}\nsampling_selected={}\nsampling_skipped={}\nsampling_comparisons={}\nunobserved_required_frames={}",
        stats.delivered, stats.selected, stats.skipped, stats.comparisons, stats.unobserved_required)?;
    let summary = summary_json(stats, analysis.is_ok() && stats.complete(), recipe);
    let finished = (|| -> Result<(ContentDigest, u64)> {
        report.record(summary.as_bytes(), &mut check)?;
        report.writer.flush()?;
        destination.sync(&report.writer, cx)?;
        Ok((ContentDigest::new(DigestAlgorithm::Sha256, report.hash.finalize()?), report.bytes))
    })();
    analysis?;
    let (digest, bytes) = finished?;
    writeln!(out, "sampling_complete=true\ncascade_report_complete=true\nall_frames_inferred={}\ncascade_report_bytes={bytes}\ncascade_report_sha256={digest}\ncascade_recipe={recipe}", stats.exhaustive())?;
    Ok(())
}

fn digest_json(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".into(), |digest| string(&digest.to_text()))
}
fn sampling_json(frame: &RtpCascadeFrame) -> String {
    let decision = frame.decision();
    let observed = decision.observation();
    let reasons = decision.reasons().iter().map(|reason| string(match reason {
        SamplingReason::FirstFrame => "first_frame",
        SamplingReason::ComparisonReset => "comparison_reset",
        SamplingReason::PixelChange => "pixel_change",
        SamplingReason::Sentinel => "sentinel",
        SamplingReason::ActivityHold => "activity_hold",
        SamplingReason::Required => "required",
        SamplingReason::ComparisonBudgetFloor => "comparison_budget_floor",
    })).collect::<Vec<_>>();
    let resets = observed.reset_reasons.iter().map(|r| string(r.as_str())).collect::<Vec<_>>();
    let measurement = observed.statistics.as_ref().map_or_else(|| "null".into(), |s| object(&[
        ("compared_pixels", s.compared_pixels.to_string()),
        ("changed_pixels", s.changed_pixels.to_string()),
        ("absolute_difference_sum", s.absolute_difference_sum.to_string()),
        ("maximum_difference", s.maximum_difference.to_string()),
        ("candidate", s.candidate.to_string()),
    ]));
    let hex = decision.bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    object(&[
        ("type", string("sampling")), ("result_sha256", string(&frame.digest().to_text())),
        ("decision_sha256", string(&decision.digest().to_text())),
        ("decision_hex", string(&hex)), ("predecessor", digest_json(decision.predecessor())),
        ("frame_receipt", string(&frame.receipt().digest().to_text())),
        ("source_root", string(&observed.source_root.to_text())),
        ("output_index", observed.output_index.to_string()),
        ("source_group", observed.source_group.to_string()),
        ("decoder_epoch", observed.decoder_epoch.to_string()),
        ("selected", decision.selected().to_string()),
        ("model_executed", frame.detection().is_some().to_string()),
        ("detection_sha256", digest_json(frame.detection().map(RtpDetectedFrame::digest))),
        ("required_basis", digest_json(decision.required_basis())),
        ("reasons", format!("[{}]", reasons.join(","))),
        ("reset_reasons", format!("[{}]", resets.join(","))),
        ("comparison_unavailable", match decision.comparison_unavailable() {
            None => "null".into(),
            Some(RtpComparisonUnavailable::WorkBudget) => string("work_budget"),
            Some(RtpComparisonUnavailable::BaselineLimit) => string("baseline_limit"),
        }),
        ("measurement", measurement), ("absence_certifiable", "false".into()),
    ]) + "\n"
}
fn summary_json(stats: RtpCascadeStats, complete: bool, recipe: ContentDigest) -> String {
    object(&[
        ("type", string("summary")), ("format", string(FORMAT)),
        ("cascade_recipe", string(&recipe.to_text())),
        ("sampling_complete", complete.to_string()),
        ("all_frames_inferred", (complete && stats.exhaustive()).to_string()),
        ("considered", stats.considered.to_string()), ("delivered", stats.delivered.to_string()),
        ("selected", stats.selected.to_string()), ("skipped", stats.skipped.to_string()),
        ("unobserved_required", stats.unobserved_required.to_string()),
        ("comparisons", stats.comparisons.to_string()),
        ("comparison_fallbacks", stats.comparison_fallbacks.to_string()),
        ("decision_bytes", stats.decision_bytes.to_string()),
        ("last_result", digest_json(stats.last_result)),
        ("native_frames", stats.detection.native.frames.to_string()),
        ("native_refusals", stats.detection.native.refusals.to_string()),
        ("native_complete", stats.detection.native.complete().to_string()),
        ("inference_attempts", stats.detection.attempts.to_string()),
        ("inferred_frames", stats.detection.frames.to_string()),
        ("failures", stats.detection.failures.to_string()),
        ("color_pixels", stats.detection.color_pixels.to_string()),
        ("preprocess_work", stats.detection.preprocess_work.to_string()),
        ("execution_macs", stats.detection.execution_macs.to_string()),
        ("tensor_bytes", stats.detection.tensor_bytes.to_string()),
        ("detection_work", stats.detection.detection_work.to_string()),
        ("custody_read_bytes", stats.detection.custody_read_bytes.to_string()),
        ("receipt_bytes", stats.detection.receipt_bytes.to_string()),
        ("absence_certifiable", "false".into()), ("effect_authority", "false".into()),
    ]) + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<OsString> {
        let digest = ContentDigest::sha256(b"test-package").to_text();
        let mut values = vec![
            "--custody", "current", "--package", "model.fmpk", "--package-sha256",
            &digest, "--report-out", "cascade.jsonl",
        ];
        values.extend(["--pixel-delta", "255", "--minimum-changed-pixels", "4194304", "--sentinel-stride", "2"]);
        values.extend(extra.iter().copied());
        let mut args: Vec<OsString> = [
            "cascade", "--root", "unused", "--site", "site:cascade", "--source-root",
        ].into_iter().map(OsString::from).collect();
        args.push(ContentDigest::sha256(b"root").to_text().into());
        args.extend(values.into_iter().map(OsString::from));
        args
    }
    #[test]
    fn sampling_is_explicit_bounded_and_never_default_detection() -> Result<()> {
        let parsed = parse(&args(&[])).map_err(|(_, reason)| failure(reason))?;
        assert_eq!(parsed.sampling.policy.sentinel_stride, 2);
        for key in ["--pixel-delta", "--minimum-changed-pixels", "--sentinel-stride"] {
            let mut input = args(&[]);
            let at = input.iter().position(|v| v == key).ok_or_else(|| failure("fixture option"))?;
            drop(input.drain(at..at + 2));
            assert!(parse(&input).is_err());
        }
        assert!(super::super::parse(&args(&[])).is_err());
        for extra in [
            vec!["--sentinel-stride", "4"], vec!["--post-activity-frames", "257"],
            vec!["--max-baseline-bytes", "4194305"], vec!["--max-sampling-bytes", "4095"],
            vec!["--max-inference-frames", "0"], vec!["--output", "forbidden.pgm"],
        ] {
            assert!(parse(&args(&extra)).is_err());
        }
        Ok(())
    }
    #[test]
    fn required_positions_are_canonical_inclusion_constraints_not_authority() -> Result<()> {
        let digest = ContentDigest::sha256(b"required-basis").to_text();
        let left = format!("3={digest},1={digest}");
        let right = format!("1={digest},3={digest}");
        let a = parse(&args(&["--required-frames", &left])).map_err(|(_, reason)| failure(reason))?;
        let b = parse(&args(&["--required-frames", &right])).map_err(|(_, reason)| failure(reason))?;
        assert_eq!(a.sampling.required, b.sampling.required);
        for value in [format!("1={digest},1={digest}"), format!("4096={digest}"), format!("-1={digest}"), String::new()] {
            assert!(parse(&args(&["--required-frames", &value])).is_err());
        }
        Ok(())
    }
}
