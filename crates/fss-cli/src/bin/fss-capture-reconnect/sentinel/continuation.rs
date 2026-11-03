#![forbid(unsafe_code)]
//! Exact argv from native identities; never a subprocess or a parsed transcript.

use fss_cli::agent_json::{array, object, string};
use fss_core::ContentDigest;
use fss_reference::http_reconnect_history::ReconnectHistoryPin;
use fss_reference::ingest::long_sentinel::retained::MAX_LONG_SENTINEL_METADATA_BYTES;

use super::PATH;
use super::analysis_plan::Options;

pub(super) fn argv(args: &[String]) -> String {
    array(&args.iter().map(|arg| string(arg)).collect::<Vec<_>>())
}

pub(super) fn pin(pin: ReconnectHistoryPin) -> String {
    object(&[
        ("session", string(&pin.session.to_text())),
        ("root", string(&pin.root.to_text())),
        ("connections", pin.connections.to_string()),
    ])
}

pub(super) fn replay(
    options: &Options,
    report: ContentDigest,
) -> Result<Vec<String>, &'static str> {
    let l = &options.limits.sentinel;
    let mut args = vec!["fss-infer".to_owned(), "sentinel-replay".into()];
    for (key, value) in [
        ("--root", options.root.to_str().ok_or(PATH)?.to_owned()),
        ("--site", options.site.clone()),
        ("--principal", options.principal.clone()),
        ("--report-digest", report.to_text()),
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
            "--max-metadata-bytes",
            MAX_LONG_SENTINEL_METADATA_BYTES.to_string(),
        ),
    ] {
        args.extend([key.to_owned(), value]);
    }
    if let Some(pixels) = options.frame_pixels {
        args.extend(["--max-frame-pixels".to_owned(), pixels.to_string()]);
    }
    Ok(args)
}
