#![forbid(unsafe_code)]
//! Exact argv values from typed pins; no shell escaping, newest-root search or subprocess.

use std::ffi::OsString;

use fss_cli::agent_json::{array, string};
use fss_core::ContentDigest;
use fss_reference::ingest::long_sentinel::retained::MAX_LONG_SENTINEL_METADATA_BYTES;
use fss_reference::ingest::rtsp_import::pages::RtspCatalogPagesImportRequest;

use super::plan::Options;
use super::{PATH, SOURCE};

fn push(args: &mut Vec<String>, key: &str, value: impl ToString) {
    args.extend([key.to_owned(), value.to_string()]);
}

pub(super) fn json(args: &[String]) -> String {
    array(&args.iter().map(|word| string(word)).collect::<Vec<_>>())
}

pub(super) fn import(
    options: &Options,
    request: &RtspCatalogPagesImportRequest,
) -> Result<Vec<String>, &'static str> {
    let mut args = Vec::new();
    let scope = &request.scope;
    for (key, value) in [
        (
            "--archive",
            options.capture.root.to_str().ok_or(PATH)?.to_owned(),
        ),
        ("--root", options.root.to_str().ok_or(PATH)?.to_owned()),
        ("--site", options.site.clone()),
        ("--principal", options.capture.principal.clone()),
        (
            "--catalog-pages",
            request
                .pages
                .iter()
                .map(|page| format!("{}@{}", page.slot.as_str(), page.root.to_text()))
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("--codec", options.capture.codec().to_owned()),
        ("--sensor-id", scope.recording.sensor.as_str().to_owned()),
        ("--stream-id", scope.recording.stream.as_str().to_owned()),
        ("--generation", scope.recording.generation.to_string()),
        ("--anchor", scope.recording.anchor.to_text()),
        ("--receive-clock", scope.recording.receive_clock.to_text()),
        ("--decode-clock", scope.decode_clock.to_text()),
        ("--time-scale", scope.time_scale.to_string()),
        ("--receive-time-ns", request.receive_time.0.to_string()),
        (
            "--capture-start-ns",
            options.capture_origin.start_ns.0.to_string(),
        ),
        (
            "--capture-uncertainty-ns",
            options.capture_origin.uncertainty_ns.to_string(),
        ),
        ("--max-pages", request.max_pages.to_string()),
        ("--max-windows", request.max_windows.to_string()),
        ("--max-frames", request.max_frames.to_string()),
        (
            "--max-original-bytes",
            request.max_original_bytes.to_string(),
        ),
        ("--max-media-bytes", request.max_media_bytes.to_string()),
        ("--max-work", options.work.to_string()),
        ("--timeout-ms", options.timeout_ms.to_string()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ] {
        push(&mut args, key, value);
    }
    // Ask the native parser to prove that the emitted recovery argv denotes precisely the
    // same request. The enclosing approved operation already authorizes this exact import.
    let parsed =
        super::import_plan::Options::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())?;
    if parsed.approve.is_some() || parsed.pages.as_ref() != Some(request) {
        return Err(SOURCE);
    }
    if parsed.preview()?.len() >= super::plan::MAX_OUTPUT_BYTES {
        return Err(super::LIMIT);
    }
    push(&mut args, "--approve", parsed.approval()?.to_text());
    Ok(args)
}

fn common(options: &Options, args: &mut Vec<String>) -> Result<(), &'static str> {
    push(args, "--root", options.root.to_str().ok_or(PATH)?);
    push(args, "--site", &options.site);
    push(args, "--principal", &options.capture.principal);
    push(
        args,
        "--stream-read-bytes",
        options.limits.maximum_source_chunk_bytes,
    );
    push(
        args,
        "--stream-pixel-budget",
        options.limits.maximum_pixel_samples,
    );
    push(
        args,
        "--max-report-bytes",
        options.limits.maximum_report_bytes,
    );
    push(
        args,
        "--max-macs",
        options.limits.package.run.execution.max_macs,
    );
    push(
        args,
        "--max-tensor-bytes",
        options.limits.package.run.execution.max_bytes,
    );
    if let Some(pixels) = options.frame_pixels {
        push(args, "--max-frame-pixels", pixels);
    }
    Ok(())
}

pub(super) fn analyze(
    options: &Options,
    import: ContentDigest,
) -> Result<Vec<String>, &'static str> {
    let mut args = vec!["package-detect".to_owned()];
    common(options, &mut args)?;
    push(&mut args, "--import-id", import.to_text());
    push(&mut args, "--first-segment", 0);
    push(&mut args, "--frames", options.capture.stop_after_pictures);
    push(
        &mut args,
        "--package",
        options.package.to_str().ok_or(PATH)?,
    );
    push(
        &mut args,
        "--package-digest",
        options.package_digest.to_text(),
    );
    push(&mut args, "--interpretation", "ycbcr");
    push(&mut args, "--kernels", options.backend_name());
    push(&mut args, "--threads", options.thread_count);
    push(&mut args, "--stream-sentinel", "yes");
    push(
        &mut args,
        "--sentinel-every-frames",
        options.sampling.every_frames,
    );
    push(
        &mut args,
        "--sentinel-burst-frames",
        options.sampling.burst_frames,
    );
    push(
        &mut args,
        "--sentinel-max-inferences",
        options.sampling.max_inferences,
    );
    push(&mut args, "--retain", "yes");
    if let Some(score) = options.minimum_score_ppm {
        push(&mut args, "--minimum-score-ppm", score);
    }
    Ok(args)
}

pub(super) fn replay(
    options: &Options,
    report: ContentDigest,
) -> Result<Vec<String>, &'static str> {
    let mut args = vec!["sentinel-replay".to_owned()];
    common(options, &mut args)?;
    push(&mut args, "--report-digest", report.to_text());
    push(
        &mut args,
        "--max-metadata-bytes",
        MAX_LONG_SENTINEL_METADATA_BYTES,
    );
    Ok(args)
}
