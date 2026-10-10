#![forbid(unsafe_code)]
//! Whole-recording corroboration with explicit per-camera aggregate reservations.

use std::io::Write;
use std::path::Path;

pub(super) use fss_reference::ingest::recorded_corroboration::streaming::LongCorroborationLimits;
use fss_reference::ingest::recorded_corroboration::streaming::LongCorroborationReport;
use fss_reference::ingest::recorded_watch::WatchLimits;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{CorroborateAction, RunResult, export, number};

pub(super) const BUDGET_OPTIONS: &[&str] = &[
    "--stream-read-bytes",
    "--stream-pixel-budget",
    "--stream-assignment-work",
    "--stream-trace-bytes",
];

pub(super) fn limits(
    values: &[(String, String)],
    enabled: bool,
    decode: WatchLimits,
) -> Result<Option<LongCorroborationLimits>, String> {
    if !enabled {
        if values
            .iter()
            .any(|(key, _)| BUDGET_OPTIONS.contains(&key.as_str()))
        {
            return Err("aggregate corroboration budgets require --stream-corroborate".to_owned());
        }
        return Ok(None);
    }
    if values
        .iter()
        .any(|(key, _)| super::super::detector::OPTIONS.contains(&key.as_str()))
    {
        return Err("--stream-corroborate does not admit detector-package options".to_owned());
    }
    if values.iter().any(|(key, _)| {
        key == "--retain-coverage"
            || key.starts_with("--visibility-")
            || key.starts_with("--scene-")
            || key.starts_with("--calibration")
    }) {
        return Err(
            "--stream-corroborate does not admit coverage, visibility, scene or calibration options"
                .to_owned(),
        );
    }
    let defaults = LongCorroborationLimits::default();
    let limits = LongCorroborationLimits {
        decode,
        maximum_source_chunk_bytes: number(
            values,
            "--stream-read-bytes",
            defaults.maximum_source_chunk_bytes,
        )?,
        maximum_pixel_samples: number(
            values,
            "--stream-pixel-budget",
            defaults.maximum_pixel_samples,
        )?,
        maximum_assignment_work: number(
            values,
            "--stream-assignment-work",
            defaults.maximum_assignment_work,
        )?,
        maximum_trace_bytes: number(values, "--stream-trace-bytes", defaults.maximum_trace_bytes)?,
    };
    limits.validate().map_err(|error| error.to_string())?;
    Ok(Some(limits))
}

pub(super) fn run(
    action: &CorroborateAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    limits: &LongCorroborationLimits,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let analyze = if action.health_screen.is_some() {
        LongCorroborationReport::analyze_screened
    } else {
        LongCorroborationReport::analyze
    };
    let mut report = analyze(
        deployment,
        &action.plan,
        action.recovery,
        limits,
        &action.dependencies,
        cx,
    )?;
    // Check the whole bounded projection, including exact rerun commands, before event writes.
    report.to_json(
        deployment.current_anchor().commit_sequence,
        Some(&action.rerun),
    )?;
    if !action.approvals.is_empty() {
        report.publish(deployment, &action.approvals, cx)?;
    }
    let json = format!(
        "{}\n",
        report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&action.rerun)
        )?
    );
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}
