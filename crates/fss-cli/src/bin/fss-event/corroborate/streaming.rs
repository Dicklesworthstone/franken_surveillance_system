#![forbid(unsafe_code)]
//! Whole-recording corroboration with explicit per-camera aggregate reservations.

use std::io::Write;
use std::path::Path;

use fss_cli::agent_json::string;
use fss_cli::event_fusion::{EventFusionError, EventFusionReport};
use fss_core::ContentDigest;
use fss_reference::ingest::historical_health::{
    HistoricalHealthDiagnostic, HistoricalHealthRetention,
};
use fss_reference::ingest::long_watch::LongWatchDetector;
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_corroboration::CorroborationError;
pub(super) use fss_reference::ingest::recorded_corroboration::streaming::LongCorroborationLimits;
use fss_reference::ingest::recorded_corroboration::streaming::{
    LongCorroborationGeometry, LongCorroborationReport,
};
use fss_reference::ingest::recorded_watch::WatchLimits;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{CorroborateAction, RunResult, export, number};

const MAX_COMPLETE_REPORT_BYTES: usize = 1024 * 1024;

type CameraDiagnostic<'a> = (&'a str, &'a HistoricalHealthDiagnostic);

/// Match by exact import identity, not by the position of a filtered diagnostic iterator.
/// A screened report must expose both cameras or refuse before any commitment.
fn camera_diagnostics<'a>(
    action: &'a CorroborateAction,
    report: &'a LongCorroborationReport,
) -> RunResult<Vec<CameraDiagnostic<'a>>> {
    if action.health_screen.is_none() {
        if report.health_diagnostics().next().is_some() {
            return Err(CorroborationError::InvalidPlan(
                "unscreened corroboration unexpectedly produced a health diagnostic",
            )
            .into());
        }
        return Ok(Vec::new());
    }
    if report.health_diagnostics().count() != action.plan.cameras.len() {
        return Err(CorroborationError::InvalidPlan(
            "screened corroboration requires one historical health diagnostic per camera",
        )
        .into());
    }
    action
        .plan
        .cameras
        .iter()
        .map(|camera| {
            let mut matches = report.health_diagnostics().filter(|diagnostic| {
                diagnostic.record().import_identity() == camera.import_identity
            });
            let diagnostic = matches.next().ok_or(CorroborationError::InvalidPlan(
                "camera has no matching historical health diagnostic",
            ))?;
            if matches.next().is_some() {
                return Err(CorroborationError::InvalidPlan(
                    "camera has ambiguous historical health diagnostics",
                )
                .into());
            }
            Ok((camera.name.as_str(), diagnostic))
        })
        .collect()
}

fn selected_diagnostic<'a>(
    diagnostics: &[CameraDiagnostic<'a>],
    approval: ContentDigest,
) -> RunResult<&'a HistoricalHealthDiagnostic> {
    let mut matches = diagnostics
        .iter()
        .map(|(_, diagnostic)| *diagnostic)
        .filter(|diagnostic| diagnostic.approval_digest() == approval);
    let selected = matches
        .next()
        .ok_or(CorroborationError::StaleApproval(approval))?;
    if matches.next().is_some() {
        return Err(CorroborationError::InvalidPlan(
            "health approval must select exactly one camera diagnostic",
        )
        .into());
    }
    Ok(selected)
}

fn with_diagnostics(
    report: String,
    diagnostics: &[CameraDiagnostic<'_>],
    retention: Option<&HistoricalHealthRetention>,
    rerun: &str,
) -> RunResult<String> {
    let report = if diagnostics.is_empty() {
        report
    } else {
        let entries = diagnostics
            .iter()
            .map(|(camera, diagnostic)| -> RunResult<String> {
                let selected = retention
                    .filter(|retained| retained.record_digest == diagnostic.record_digest());
                let diagnostic = super::super::health::diagnostic_json(diagnostic, selected, rerun);
                let prefix = diagnostic
                    .strip_suffix('}')
                    .ok_or("invalid historical health diagnostic framing")?;
                Ok(format!("{prefix},\"camera\":{}}}", string(camera)))
            })
            .collect::<RunResult<Vec<_>>>()?;
        let prefix = report
            .strip_suffix('}')
            .ok_or("invalid whole-recording corroboration report framing")?;
        format!("{prefix},\"historical_health\":[{}]}}", entries.join(","))
    };
    if report
        .len()
        .checked_add(1)
        .is_none_or(|bytes| bytes > MAX_COMPLETE_REPORT_BYTES)
    {
        return Err(
            "complete corroboration and historical health report exceeds byte bound".into(),
        );
    }
    Ok(report)
}

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
    if values.iter().any(|(key, _)| key == "--retain-coverage") {
        return Err(
            "--stream-corroborate does not produce coverage or absence witnesses".to_owned(),
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
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    // Hash and parse the exact profile before geometry, source or model work. Absence of
    // a profile leaves the original path untouched; every authority write was refused above.
    let fusion_profile = super::super::detector::load_fusion(action.cascade.as_ref(), cx)?;
    let geometry = if action.geometry_requested {
        let (poses, mut sources, calibration, _, record) = super::resolve_poses(action)?;
        if let Some(calibration) = calibration {
            super::apply_adoptions(action, deployment, calibration, &mut sources, cx)?;
        }
        let archive = match (calibration, record) {
            (Some(digest), Some(record)) => Some((digest, record.encode()?)),
            (None, None) => None,
            _ => {
                return Err(
                    CorroborationError::InvalidPlan("resolved calibration is incomplete").into(),
                );
            }
        };
        let scene = action
            .mesh
            .as_ref()
            .map(|mesh| -> RunResult<_> {
                Ok((
                    mesh.package,
                    mesh.source_scene,
                    super::read_scene_mesh(&mesh.path)?,
                ))
            })
            .transpose()?;
        Some(LongCorroborationGeometry::new(
            &action.plan,
            action.policy,
            poses,
            super::retained_provenance(&sources, calibration),
            archive,
            scene,
        )?)
    } else {
        None
    };
    // The exact archive is verified once, before opening either recording. It survives only
    // this owned invocation unless an exact approved candidate retains it for cold replay.
    let package = match &action.cascade {
        Some(options) => Some(super::super::detector::load_with_archive(
            options, cx, scalar,
        )?),
        None => None,
    };
    let detector = match (&action.cascade, &package) {
        (Some(options), Some((package, archive))) => Some(LongWatchDetector::new(
            package,
            archive,
            options.config,
            PackageDetectLimits::default(),
            scalar,
        )?),
        _ => None,
    };
    let mut report = if let Some(geometry) = &geometry {
        LongCorroborationReport::analyze_with_geometry(
            deployment,
            &action.plan,
            action.recovery,
            limits,
            &action.dependencies,
            action.health_screen.is_some(),
            detector.as_ref(),
            geometry,
            cx,
        )?
    } else {
        match &detector {
            Some(detector) => LongCorroborationReport::analyze_with_detector(
                deployment,
                &action.plan,
                action.recovery,
                limits,
                &action.dependencies,
                action.health_screen.is_some(),
                detector,
                cx,
            )?,
            None => {
                let analyze = if action.health_screen.is_some() {
                    LongCorroborationReport::analyze_screened
                } else {
                    LongCorroborationReport::analyze
                };
                analyze(
                    deployment,
                    &action.plan,
                    action.recovery,
                    limits,
                    &action.dependencies,
                    cx,
                )?
            }
        }
    };
    let fusion = match (&fusion_profile, &package) {
        (Some(profile), Some((package, _))) => Some(EventFusionReport::long_corroborate(
            &report, package, profile, deployment, cx,
        )?),
        (None, _) => None,
        _ => return Err(EventFusionError::Scope.into()),
    };
    // Check every camera proposal and the complete post-retention shape before any write.
    // A selected health receipt is independent of paired candidates or their publication gate.
    let selection = {
        let diagnostics = camera_diagnostics(action, &report)?;
        let selected = action
            .retain_health
            .map(|approval| selected_diagnostic(&diagnostics, approval))
            .transpose()?;
        let maximal_retention = selected.map(|diagnostic| {
            let mut ledger_anchor = deployment.current_anchor().clone();
            ledger_anchor.commit_sequence = u64::MAX;
            HistoricalHealthRetention {
                record_digest: diagnostic.record_digest(),
                provenance_root: diagnostic.provenance_root(),
                ledger_anchor,
                already_retained: true,
            }
        });
        let sequence = if diagnostics.is_empty() {
            deployment.current_anchor().commit_sequence
        } else {
            u64::MAX
        };
        let preview = with_diagnostics(
            report.to_json(sequence, Some(&action.rerun))?,
            &diagnostics,
            maximal_retention.as_ref(),
            &action.rerun,
        )?;
        super::super::detector::with_fusion(preview, fusion.as_ref())?;
        selected.map(|diagnostic| (diagnostic.record_digest(), diagnostic.approval_digest()))
    };
    let retention = if let Some((record_digest, approval)) = selection {
        let diagnostic = report
            .health_diagnostics()
            .find(|diagnostic| diagnostic.record_digest() == record_digest)
            .ok_or(CorroborationError::InvalidPlan(
                "selected historical health diagnostic disappeared",
            ))?;
        Some(diagnostic.retain(deployment, approval, cx)?)
    } else {
        if !action.approvals.is_empty() {
            report.publish(deployment, &action.approvals, cx)?;
        }
        None
    };
    let native_json = with_diagnostics(
        report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&action.rerun),
        )?,
        &camera_diagnostics(action, &report)?,
        retention.as_ref(),
        &action.rerun,
    )?;
    let complete = super::super::detector::with_fusion(native_json, fusion.as_ref())?;
    if fusion.is_some() {
        let checked = report.revalidate_derived_sources(deployment, cx);
        cx.checkpoint("event_fusion:long_corroboration_delivery")?;
        checked.map_err(|error| match error {
            CorroborationError::Conflict => EventFusionError::StaleBasis,
            _ => EventFusionError::Evidence,
        })?;
    }
    let json = format!("{complete}\n");
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}
