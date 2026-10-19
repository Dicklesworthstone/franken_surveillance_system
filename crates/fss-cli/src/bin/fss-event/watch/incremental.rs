#![forbid(unsafe_code)]
//! Operator scheduling and exact cold continuation for the native incremental dwell owner.

use super::*;
use fss_reference::ingest::long_dwell::incremental::{
    DwellCheckpointPin, DwellRestoreLimits, PreparedIncrementalDwell, RetainedDwellCheckpoint,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct StepOptions {
    step_frames: usize,
    checkpoint: Option<DwellCheckpointPin>,
    restore_maximum_frames: usize,
}

pub(super) fn parse(
    values: &[(String, String)],
    stream_dwell: bool,
    health_screen: bool,
    detector: bool,
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
    if health_screen || detector {
        return Err(
            "incremental dwell currently excludes classifier and sensor-health modes".to_owned(),
        );
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
    out: &mut impl Write,
) -> RunResult<()> {
    let options = action.incremental.ok_or(WatchError::Conflict)?;
    if action.health_screen
        || action.cascade.is_some()
        || action.retain_health.is_some()
        || action.retain_coverage.is_some()
    {
        return Err(WatchError::InvalidPlan(
            "incremental dwell currently excludes classifiers, sensor-health and coverage retention",
        ).into());
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
    let prepared = PreparedIncrementalDwell::new(
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
    let complete = running.complete();
    let pin = running.retain(deployment, cx)?;
    let continuation = format!(
        "{} --dwell-checkpoint {} --dwell-checkpoint-root {} --dwell-restore-max-frames {}",
        action.rerun, pin.record_digest, pin.provenance_root, work.source_positions,
    );
    if continuation.len() > 8192 {
        return Err(
            WatchError::InvalidPlan("incremental continuation exceeds command bound").into(),
        );
    }
    let event_report = if complete {
        let mut report = running.finish(deployment, cx)?;
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
    if let Some(report) = event_report {
        output.push_str(",\"event_report\":");
        output.push_str(&report);
    }
    output.push_str("}\n");
    if output.len() > 1024 * 1024 + 16 * 1024 {
        return Err(WatchError::Limit.into());
    }
    if let Some(path) = &action.report_out {
        export(path, output.as_bytes(), root, cx)?;
    }
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
        assert!(parse(&base, true, false, false).unwrap().is_some());
        assert!(parse(&base, false, false, false).is_err());
        assert!(parse(&base, true, true, false).is_err());
        assert!(parse(&base, true, false, true).is_err());
        for n in ["0", "65537"] {
            assert!(parse(&values(&[("--dwell-step-frames", n)]), true, false, false).is_err());
        }
    }

    #[test]
    fn cold_resume_requires_both_pins_and_separate_prefix_work_admission() {
        let digest = ContentDigest::sha256(b"checkpoint").to_text();
        let mut v = values(&[
            ("--dwell-step-frames", "128"),
            ("--dwell-checkpoint", &digest),
        ]);
        assert!(parse(&v, true, false, false).is_err());
        v.push(("--dwell-checkpoint-root".into(), digest));
        assert!(parse(&v, true, false, false).is_err());
        v.push(("--dwell-restore-max-frames".into(), "127".into()));
        assert!(parse(&v, true, false, false).unwrap().is_some());
        assert!(
            parse(
                &values(&[("--dwell-restore-max-frames", "127")]),
                true,
                false,
                false
            )
            .is_err()
        );
    }
}
