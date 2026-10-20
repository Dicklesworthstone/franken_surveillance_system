#![forbid(unsafe_code)]
//! Operator scheduling and exact cold continuation for the native incremental dwell owner.

use super::*;
use fss_cli::event_fusion::{EventFusionProfile, MAX_REPORT_BYTES};
use fss_reference::ingest::long_dwell::LongDwellDetector;
use fss_reference::ingest::long_dwell::incremental::{
    DwellCheckpointPin, DwellHealthWork, DwellRestoreLimits, DwellWork, PreparedIncrementalDwell,
    RetainedDwellCheckpoint,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct StepOptions {
    step_frames: usize,
    checkpoint: Option<DwellCheckpointPin>,
    restore_maximum_frames: usize,
}

impl StepOptions {
    /// Syntax-level admission only; the retained native prefix must still prove completeness.
    pub(super) const fn has_checkpoint(self) -> bool {
        self.checkpoint.is_some()
    }
}

pub(super) fn parse(
    values: &[(String, String)],
    stream_dwell: bool,
    health_screen: bool,
) -> Result<Option<StepOptions>, String> {
    let has = |key: &str| values.iter().any(|(name, _)| name == key);
    let keys = [
        "--dwell-step-frames",
        "--dwell-checkpoint",
        "--dwell-checkpoint-root",
        "--dwell-restore-max-frames",
    ];
    if !keys.iter().any(|key| has(key)) {
        return Ok(None);
    }
    if !stream_dwell || !has("--dwell-step-frames") {
        return Err(
            "incremental options require --stream-dwell and --dwell-step-frames".to_owned(),
        );
    }
    if has("--retain-health") || has("--retain-coverage") {
        return Err("incremental dwell excludes sensor-health and coverage retention".to_owned());
    }
    if health_screen && (has("--fusion-profile") || has("--fusion-digest")) {
        return Err("calibrated incremental dwell excludes sensor-health screening".to_owned());
    }
    let step_frames = number(values, "--dwell-step-frames", 0_usize)?;
    if !(1..=MAX_LONG_DWELL_FRAMES).contains(&step_frames) {
        return Err("dwell step frames must be 1..65536".to_owned());
    }
    let checkpoint = match (has("--dwell-checkpoint"), has("--dwell-checkpoint-root")) {
        (false, false) => None,
        (true, true) => Some(DwellCheckpointPin {
            record_digest: digest(text(values, "--dwell-checkpoint")?, "--dwell-checkpoint")?,
            provenance_root: digest(
                text(values, "--dwell-checkpoint-root")?,
                "--dwell-checkpoint-root",
            )?,
        }),
        _ => {
            return Err("cold dwell resume requires both checkpoint body and root pins".to_owned());
        }
    };
    let restore_maximum_frames = number(values, "--dwell-restore-max-frames", 0_usize)?;
    if checkpoint.is_some() {
        if !has("--dwell-restore-max-frames")
            || !(1..=MAX_LONG_DWELL_FRAMES).contains(&restore_maximum_frames)
        {
            return Err(
                "cold dwell resume requires explicit --dwell-restore-max-frames 1..65536"
                    .to_owned(),
            );
        }
    } else if has("--dwell-restore-max-frames") {
        return Err("restore admission requires an exact dwell checkpoint".to_owned());
    }
    if (has("--fusion-profile") || has("--fusion-digest")) && checkpoint.is_none() {
        return Err(
            "calibrated fusion: incremental dwell is unsupported without an exact completed checkpoint"
                .to_owned(),
        );
    }
    Ok(Some(StepOptions {
        step_frames,
        checkpoint,
        restore_maximum_frames,
    }))
}

fn json(value: &str) -> String {
    format!("\"{}\"", fss_cli::escape_json_str(value))
}

pub(super) fn run(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let options = action.incremental.ok_or(WatchError::Conflict)?;
    // Syntax admission never proves completeness or grants checkpoint/event authority.
    super::super::detector::check_watch_fusion_mode(
        action.cascade.as_ref(),
        options.has_checkpoint(),
        !action.approvals.is_empty()
            || action.retain_health.is_some()
            || action.retain_coverage.is_some(),
    )?;
    if action.retain_health.is_some() || action.retain_coverage.is_some() {
        return Err(WatchError::InvalidPlan(
            "incremental dwell excludes sensor-health and coverage retention",
        )
        .into());
    }
    if action.health_screen
        && action
            .cascade
            .as_ref()
            .is_some_and(|options| options.has_fusion())
    {
        return Err(WatchError::InvalidPlan(
            "calibrated incremental dwell excludes sensor-health screening",
        )
        .into());
    }
    // Both preparation and checkpoint opening read source custody. Admit the bounded,
    // exact profile and temporal scope before either source owner or the model is touched.
    let fusion_profile = super::super::detector::load_fusion(action.cascade.as_ref(), cx)?;
    if fusion_profile
        .as_ref()
        .is_some_and(|profile| profile.long_dwell_analysis_root().is_none())
    {
        return Err(EventFusionError::Scope.into());
    }
    let count = match action.segment_count {
        Some(count) => count,
        None => {
            let source =
                RetainedFileImport::open(deployment, action.import, limits.decode.read_limits, cx)?;
            source
                .manifest()
                .segment_spans
                .len()
                .checked_sub(action.first_segment)
                .filter(|count| (1..=MAX_LONG_DWELL_FRAMES).contains(count))
                .ok_or(WatchError::InvalidPlan(
                    "select a nonempty incremental dwell range of at most 65536 segments",
                ))?
        }
    };
    let rule = action
        .dwell
        .ok_or(WatchError::InvalidPlan("incremental dwell requires a rule"))?;
    let prepare = if action.health_screen {
        PreparedIncrementalDwell::new_screened
    } else {
        PreparedIncrementalDwell::new
    };
    let prepared = prepare(
        deployment,
        WatchPlan {
            import_identity: action.import,
            interpretation: action.interpretation,
            first_segment: action.first_segment,
            segment_count: count,
            zones: action.zones.clone(),
            detector: action.detector,
            tracker: action.tracker,
        },
        rule,
        action.options,
        *limits,
        cx,
    )?;
    let restore = DwellRestoreLimits {
        maximum_prefix_frames: options.restore_maximum_frames,
        execution: *limits,
    };
    let saved = options
        .checkpoint
        .map(|pin| RetainedDwellCheckpoint::open(deployment, pin, &restore, cx))
        .transpose()?;
    if let Some(saved) = &saved
        && saved.prepared().request_digest()? != prepared.request_digest()?
    {
        return Err(WatchError::InvalidPlan(
            "checkpoint source, dwell rule, privacy or resource recipe changed",
        )
        .into());
    }
    if let Some(profile) = &fusion_profile {
        return run_completed_fusion(
            action,
            deployment,
            root,
            saved.as_ref().ok_or(EventFusionError::Scope)?,
            &restore,
            profile,
            cx,
            scalar,
            out,
        );
    }
    let prefix = saved
        .as_ref()
        .map_or(0, |checkpoint| checkpoint.prefix_work().source_positions);
    if prefix.saturating_add(options.step_frames) < count && !action.approvals.is_empty() {
        return Err(WatchError::InvalidPlan(
            "an incomplete incremental dwell range cannot publish events",
        )
        .into());
    }
    let mut running = match &saved {
        Some(saved) => saved.resume(deployment, &restore, cx)?,
        None => prepared.start()?,
    };
    let work = running.advance(deployment, options.step_frames, cx)?;
    let restoration = running.restoration_work();
    let health = match (running.health_work(), running.restoration_health_work()) {
        (None, None) => None,
        (Some(logical), Some(restoration)) => Some(HealthProgress {
            logical,
            restoration,
        }),
        _ => return Err(WatchError::Conflict.into()),
    };
    let complete = running.complete();
    let pin = running.retain(deployment, cx)?;
    let continuation = continuation_command(action, pin, work.source_positions)?;
    let event_report = if complete {
        let mut report = running.finish(deployment, cx)?;
        if let Some(options) = &action.cascade {
            // The temporal checkpoint above remains usable if verification or the terminal
            // classifier refuses. Partial steps never open the package or run the model.
            let (package, archive) =
                super::super::detector::load_with_archive(options, cx, scalar)?;
            let detector = LongDwellDetector::new(
                &package,
                &archive,
                options.config,
                PackageDetectLimits::default(),
                scalar,
            )?;
            // The completed native report owns the original scan's remaining allowances.
            // Classification never creates a fresh foreground/tracker or whole-scan budget.
            report.classify_with_detector(deployment, &detector, cx)?;
        }
        // Existing owner validates every approval and source/privacy witness before any event.
        if !action.approvals.is_empty() {
            report.publish(deployment, &action.approvals, cx)?;
        }
        Some(report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&continuation),
        )?)
    } else {
        None
    };
    let output = render_progress(
        action,
        Progress {
            pin,
            work,
            restoration,
            health,
            prefix,
            count,
            complete,
            continuation,
            event_report,
        },
        1024 * 1024 + 16 * 1024,
    )?;
    if let Some(path) = &action.report_out {
        export(path, output.as_bytes(), root, cx)?;
    }
    out.write_all(output.as_bytes())?;
    Ok(())
}

fn continuation_command(
    action: &WatchAction,
    pin: DwellCheckpointPin,
    source_positions: usize,
) -> RunResult<String> {
    let command = format!(
        "{} --dwell-checkpoint {} --dwell-checkpoint-root {} --dwell-restore-max-frames {}",
        action.rerun, pin.record_digest, pin.provenance_root, source_positions,
    );
    if command.len() > 8192 {
        return Err(
            WatchError::InvalidPlan("incremental continuation exceeds command bound").into(),
        );
    }
    Ok(command)
}

/// Screening uses its own native sample allowance; it is not folded into foreground work.
struct HealthProgress {
    logical: DwellHealthWork,
    restoration: DwellHealthWork,
}

/// Rendering shares the existing progress schema without changing ordinary scheduling output.
struct Progress {
    pin: DwellCheckpointPin,
    work: DwellWork,
    restoration: DwellWork,
    health: Option<HealthProgress>,
    prefix: usize,
    count: usize,
    complete: bool,
    continuation: String,
    event_report: Option<String>,
}

fn render_progress(
    action: &WatchAction,
    progress: Progress,
    maximum_bytes: usize,
) -> RunResult<String> {
    let Progress {
        pin,
        work,
        restoration,
        health,
        prefix,
        count,
        complete,
        continuation,
        event_report,
    } = progress;
    let mut output = format!(
        concat!(
            "{{\"schema\":\"fss.incremental_dwell_progress.v1\",\"status\":{},",
            "\"checkpoint_digest\":{},\"checkpoint_root\":{},\"analysis_complete\":{},",
            "\"next_segment\":{},\"remaining_segments\":{},\"new_source_positions\":{},",
            "\"logical_scan_work\":{},\"cold_restoration_work\":{},",
            "\"cold_restoration_replays_prefix\":true,\"continuation_command\":{},",
            "\"checkpoint_is_event\":false,\"absence_certifiable\":false,\"alert_authorized\":false"
        ),
        json(if complete { "complete" } else { "checkpointed" }),
        json(&pin.record_digest.to_text()),
        json(&pin.provenance_root.to_text()),
        complete,
        action.first_segment + work.source_positions,
        count - work.source_positions,
        work.source_positions - prefix,
        work.to_json(),
        restoration.to_json(),
        json(&continuation),
    );
    if let Some(health) = health {
        output.push_str(&format!(
            concat!(
                ",\"sensor_health_policy\":{},\"sensor_health_policy_digest\":{},",
                "\"sensor_health_stage\":{},\"logical_health_scan_work\":{{",
                "\"frames_screened\":{},\"samples_screened\":{}}},",
                "\"cold_health_restoration_work\":{{\"frames_screened\":{},\"samples_screened\":{}}}"
            ),
            json(HEALTH_POLICY_NAME),
            json(&fss_reference::ingest::sensor_health::policy_digest().to_text()),
            json(if complete { "complete" } else { "screening" }),
            health.logical.frames_screened,
            health.logical.samples_screened,
            health.restoration.frames_screened,
            health.restoration.samples_screened,
        ));
    }
    if let Some(options) = &action.cascade {
        output.push_str(&format!(
            concat!(
                ",\"detector_stage\":{},\"detector_request\":{{",
                "\"max_inferences\":{},\"frames_per_track\":{},",
                "\"minimum_association_iou_ppm\":{},\"minimum_score_ppm\":{}}}"
            ),
            json(if complete {
                "complete"
            } else {
                "deferred_until_complete"
            }),
            options.config.max_inferences,
            options.config.frames_per_track,
            options.config.minimum_association_iou_ppm,
            options
                .config
                .minimum_score_ppm
                .map_or_else(|| "null".to_owned(), |score| score.to_string()),
        ));
    }
    if let Some(report) = event_report {
        output.push_str(",\"event_report\":");
        output.push_str(&report);
    }
    output.push_str("}\n");
    if output.len() > maximum_bytes {
        return Err(WatchError::Limit.into());
    }
    Ok(output)
}

/// A complete checkpoint supplies an immutable temporal result, not permission to append
/// another prefix or publish an event. The shared deployment borrow preserves that boundary.
#[allow(clippy::too_many_arguments)]
fn run_completed_fusion(
    action: &WatchAction,
    deployment: &ReferenceDeployment,
    root: &Path,
    saved: &RetainedDwellCheckpoint,
    restore: &DwellRestoreLimits,
    profile: &EventFusionProfile,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    super::super::detector::check_watch_fusion_mode(
        action.cascade.as_ref(),
        true,
        !action.approvals.is_empty()
            || action.retain_health.is_some()
            || action.retain_coverage.is_some(),
    )?;
    if action.health_screen || saved.prepared().screened() {
        return Err(WatchError::InvalidPlan(
            "calibrated incremental dwell excludes sensor-health screening",
        )
        .into());
    }
    // Tolerated decode refusals still consume positions. A step which could finish a partial
    // prefix is insufficient: advice cannot advance or retain any new temporal work.
    let count = saved.prepared().plan().segment_count;
    if saved.prefix_work().source_positions != count {
        return Err(WatchError::InvalidPlan(
            "calibrated incremental dwell requires an already complete checkpoint",
        )
        .into());
    }
    let options = action.cascade.as_ref().ok_or(EventFusionError::Scope)?;
    // Refuse a bad archive before paying for complete cold-prefix reconstruction.
    let (package, archive) = super::super::detector::load_with_archive(options, cx, scalar)?;
    let detector = LongDwellDetector::new(
        &package,
        &archive,
        options.config,
        PackageDetectLimits::default(),
        scalar,
    )?;
    let running = saved.resume(deployment, restore, cx)?;
    let work = running.work();
    let restoration = running.restoration_work();
    let pin = saved.pin();
    let continuation = continuation_command(action, pin, work.source_positions)?;
    let mut report = running.finish(deployment, cx)?;
    report.classify_with_detector(deployment, &detector, cx)?;
    let fusion = EventFusionReport::long_dwell(&report, &package, profile, deployment, cx)?;
    let event_report = super::super::detector::with_fusion(
        report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&continuation),
        )?,
        Some(&fusion),
    )?;
    // The inner join is bounded too, but the progress metadata and final newline are part
    // of the delivered document and must fit the same complete-output admission.
    let output = render_progress(
        action,
        Progress {
            pin,
            work,
            restoration,
            health: None,
            prefix: work.source_positions,
            count,
            complete: true,
            continuation,
            event_report: Some(event_report),
        },
        MAX_REPORT_BYTES,
    )?;
    report.revalidate_derived_source(deployment, cx)?;
    cx.checkpoint("incremental_dwell_fusion:output")?;
    if let Some(path) = &action.report_out {
        export(path, output.as_bytes(), root, cx)?;
    }
    report.revalidate_derived_source(deployment, cx)?;
    cx.checkpoint("incremental_dwell_fusion:stdout")?;
    out.write_all(output.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn incremental_admission_is_explicit_and_refuses_incompatible_modes() {
        let base = values(&[("--dwell-step-frames", "128")]);
        assert!(parse(&base, true, false).unwrap().is_some());
        assert!(parse(&base, false, false).is_err());
        assert!(parse(&base, true, true).unwrap().is_some());
        let mut classifier = base.clone();
        let detector_digest = ContentDigest::sha256(b"classifier package").to_text();
        classifier.extend(values(&[
            ("--detector-package", "/deferred/package"),
            ("--detector-digest", &detector_digest),
            ("--detector-max-inferences", "1"),
        ]));
        assert!(parse(&classifier, true, false).unwrap().is_some());
        for field in ["--fusion-profile", "--fusion-digest"] {
            let mut fusion = classifier.clone();
            fusion.push((field.to_owned(), "not-opened".to_owned()));
            assert!(parse(&fusion, true, false).is_err());
            assert!(parse(&fusion, true, true).is_err());
        }
        for n in ["0", "65537"] {
            assert!(parse(&values(&[("--dwell-step-frames", n)]), true, false).is_err());
        }
    }

    #[test]
    fn cold_resume_requires_both_pins_and_separate_prefix_work_admission() {
        let digest = ContentDigest::sha256(b"checkpoint").to_text();
        let mut v = values(&[
            ("--dwell-step-frames", "128"),
            ("--dwell-checkpoint", &digest),
        ]);
        assert!(parse(&v, true, false).is_err());
        v.push(("--dwell-checkpoint-root".into(), digest));
        assert!(parse(&v, true, false).is_err());
        v.push(("--dwell-restore-max-frames".into(), "127".into()));
        assert!(parse(&v, true, false).unwrap().is_some());
        assert!(
            parse(
                &values(&[("--dwell-restore-max-frames", "127")]),
                true,
                false
            )
            .is_err()
        );
    }
}
