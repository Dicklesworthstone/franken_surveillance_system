#![forbid(unsafe_code)]
//! Exact offline import/analysis argv from the typed selected prefix and native import receipt.

use std::ffi::OsString;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_reference::KernelBackend;
use fss_reference::ingest::http_import::HttpImportRequest;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;

use super::plan::Options;
use super::{PATH, SOURCE};

fn push(args: &mut Vec<String>, key: &str, value: impl ToString) {
    args.extend([key.to_owned(), value.to_string()]);
}

pub(super) fn import(
    options: &Options,
    request: &HttpImportRequest,
) -> Result<Vec<String>, &'static str> {
    let a = &options.analysis;
    let hint = request.capture_hint.ok_or(SOURCE)?;
    let mut args = Vec::new();
    for (key, value) in [
        ("--archive", a.archive.to_str().ok_or(PATH)?.to_owned()),
        ("--root", a.root.to_str().ok_or(PATH)?.to_owned()),
        ("--site", a.site.clone()),
        ("--principal", a.principal.clone()),
        (
            "--source",
            ContentDigest::new(DigestAlgorithm::Sha256, request.source.stream.source).to_text(),
        ),
        ("--generation", request.source.stream.generation.to_string()),
        (
            "--receive-clock",
            ContentDigest::new(DigestAlgorithm::Sha256, request.source.receive_clock).to_text(),
        ),
        (
            "--retention-evidence",
            ContentDigest::new(DigestAlgorithm::Sha256, request.source.retention_evidence)
                .to_text(),
        ),
        ("--head", request.pin.head.to_text()),
        ("--reads", request.pin.reads.to_string()),
        ("--bytes", request.pin.bytes.to_string()),
        ("--sensor-id", request.sensor.as_str().to_owned()),
        ("--stream-id", request.stream.as_str().to_owned()),
        ("--receive-time-ns", request.receive_time.0.to_string()),
        ("--capture-start-ns", hint.start_ns.0.to_string()),
        ("--capture-uncertainty-ns", hint.uncertainty_ns.to_string()),
        ("--fps", hint.assumed_fps.to_string()),
        ("--max-frames", request.max_frames.to_string()),
        ("--max-source-bytes", request.max_bytes.to_string()),
        ("--max-work", a.work.to_string()),
        ("--max-framing-work", a.framing.to_string()),
        ("--timeout-ms", a.timeout_ms.to_string()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ] {
        push(&mut args, key, value);
    }
    let parsed =
        super::import_plan::Options::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())?;
    if parsed.request.digest().map_err(|error| error.stable_id())?
        != request.digest().map_err(|error| error.stable_id())?
        || parsed.root != a.root
        || parsed.archive != a.archive
        || parsed.principal != a.principal
        || parsed.site != a.site
        || parsed.work != a.work
        || parsed.framing != a.framing
        || parsed.timeout_ms != a.timeout_ms
        || parsed.approve.is_some()
    {
        return Err(SOURCE);
    }
    push(&mut args, "--approve", parsed.approval()?);
    args.insert(0, "fss-import-http".to_owned());
    Ok(args)
}

pub(super) fn analyze(
    options: &Options,
    import: ContentDigest,
) -> Result<Vec<String>, &'static str> {
    let a = &options.analysis;
    let p = &a.plan;
    let l = &a.limits.sentinel;
    let mut args = vec!["fss-infer".to_owned(), "package-detect".to_owned()];
    for (key, value) in [
        ("--root", a.root.to_str().ok_or(PATH)?.to_owned()),
        ("--site", a.site.clone()),
        ("--principal", a.principal.clone()),
        ("--import-id", import.to_text()),
        ("--first-segment", "0".into()),
        ("--frames", options.prefix_frames.ok_or(SOURCE)?.to_string()),
        ("--package", a.package.to_str().ok_or(PATH)?.to_owned()),
        ("--package-digest", p.package_digest.to_text()),
        (
            "--interpretation",
            match p.interpretation {
                ComponentInterpretation::Grayscale => "gray",
                ComponentInterpretation::YCbCr => "ycbcr",
            }
            .to_owned(),
        ),
        (
            "--kernels",
            match p.backend {
                KernelBackend::OptimizedCpuV1 => "optimized-cpu",
                KernelBackend::ScalarReference => "scalar-reference",
            }
            .to_owned(),
        ),
        ("--threads", a.thread_count.to_string()),
        ("--stream-sentinel", "yes".into()),
        (
            "--sentinel-every-frames",
            p.sampling.every_frames.to_string(),
        ),
        (
            "--sentinel-burst-frames",
            p.sampling.burst_frames.to_string(),
        ),
        (
            "--sentinel-max-inferences",
            p.sampling.max_inferences.to_string(),
        ),
        (
            "--stream-read-bytes",
            l.maximum_source_chunk_bytes.to_string(),
        ),
        ("--stream-pixel-budget", l.maximum_pixel_samples.to_string()),
        ("--max-report-bytes", l.maximum_report_bytes.to_string()),
        ("--max-macs", l.package.run.execution.max_macs.to_string()),
        (
            "--max-tensor-bytes",
            l.package.run.execution.max_bytes.to_string(),
        ),
        (
            "--max-output-bytes",
            l.package.run.maximum_output_bytes.to_string(),
        ),
        ("--retain", "yes".into()),
    ] {
        push(&mut args, key, value);
    }
    if let Some(pixels) = a.frame_pixels {
        push(&mut args, "--max-frame-pixels", pixels);
    }
    if let Some(score) = p.minimum_score_ppm {
        push(&mut args, "--minimum-score-ppm", score);
    }
    Ok(args)
}
