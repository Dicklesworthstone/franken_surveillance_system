#![forbid(unsafe_code)]
//! Measured residual monitoring from exact retained native localization, with separate approval.

use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::ingest::calibration_monitor::{
    MonitorError, MonitorRequest, MonitorStatus, preview_monitor, replay_monitor, retain_monitor,
};
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::site_calibration::{MAX_CALIBRATION_BYTES, MAX_OBSERVATION_BYTES};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{CalibrationAction, RunResult, quote, sha256};

#[derive(Debug)]
enum Input {
    Observe {
        calibration: PathBuf,
        calibration_digest: ContentDigest,
        camera_handle: u64,
        adoption_digest: ContentDigest,
        camera_input: PathBuf,
        localization: ContentDigest,
        localization_root: ContentDigest,
        localization_receipt: ContentDigest,
        approve: Option<ContentDigest>,
    },
    Replay {
        identity: ContentDigest,
        root: ContentDigest,
        receipt: ContentDigest,
    },
}

#[derive(Debug)]
pub(super) struct Action {
    input: Input,
    decode_work: u64,
    geometry_work: u64,
}

pub(super) fn accepts(operation: &str, key: &str) -> bool {
    matches!(operation, "monitor" | "monitor-replay")
        && (matches!(key, "--work-units" | "--geometry-work-units")
            || (operation == "monitor"
                && matches!(
                    key,
                    "--calibration"
                        | "--calibration-digest"
                        | "--camera-handle"
                        | "--adoption-digest"
                        | "--camera-input"
                        | "--localization-id"
                        | "--localization-root"
                        | "--localization-receipt"
                        | "--approve"
                ))
            || (operation == "monitor-replay"
                && matches!(
                    key,
                    "--monitor-id" | "--expected-root" | "--expected-receipt"
                )))
}

pub(super) fn parse(operation: &str, values: &[(String, String)]) -> Result<Action, String> {
    let optional = |key: &str| {
        values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let text = |key: &str| optional(key).ok_or_else(|| format!("required option {key}"));
    let digest = |key: &str| -> Result<ContentDigest, String> {
        let d = sha256(text(key)?, key)?;
        if d.bytes() == [0; 32] {
            return Err(format!("{key} requires a nonzero SHA-256 pin"));
        }
        Ok(d)
    };
    let number = |key: &str, fallback: u64| -> Result<u64, String> {
        optional(key).map_or(Ok(fallback), |value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{key} requires a positive unsigned integer"))
        })
    };
    let input = if operation == "monitor" {
        Input::Observe {
            calibration: PathBuf::from(text("--calibration")?),
            calibration_digest: digest("--calibration-digest")?,
            camera_handle: text("--camera-handle")?
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or("--camera-handle requires a nonzero unsigned integer")?,
            adoption_digest: digest("--adoption-digest")?,
            camera_input: PathBuf::from(text("--camera-input")?),
            localization: digest("--localization-id")?,
            localization_root: digest("--localization-root")?,
            localization_receipt: digest("--localization-receipt")?,
            approve: optional("--approve")
                .map(|_| digest("--approve"))
                .transpose()?,
        }
    } else {
        Input::Replay {
            identity: digest("--monitor-id")?,
            root: digest("--expected-root")?,
            receipt: digest("--expected-receipt")?,
        }
    };
    Ok(Action {
        input,
        decode_work: number("--work-units", 100_000_000)?,
        geometry_work: number("--geometry-work-units", 2_000_000_000)?,
    })
}

pub(super) fn run(
    action: &Action,
    context: &CalibrationAction,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> RunResult<String> {
    let mut jpeg = DecodeBudget::new(action.decode_work);
    let mut video = RecordedVideoDecodeBudget::new(action.decode_work);
    let mut geometry = WorkBudget::new(action.geometry_work);
    let report = match &action.input {
        Input::Observe {
            calibration,
            calibration_digest,
            camera_handle,
            adoption_digest,
            camera_input,
            localization,
            localization_root,
            localization_receipt,
            approve,
        } => {
            cx.checkpoint("calibration_monitor_cli:read")?;
            let bytes = super::super::calibrate::read_bounded(
                calibration,
                MAX_CALIBRATION_BYTES,
                "site calibration",
            )?;
            let input = super::super::calibrate::read_bounded(
                camera_input,
                MAX_OBSERVATION_BYTES,
                "original camera calibration input",
            )?;
            cx.checkpoint("calibration_monitor_cli:read_complete")?;
            let request = MonitorRequest {
                calibration_bytes: &bytes,
                calibration_digest: *calibration_digest,
                camera_handle: *camera_handle,
                adoption_digest: *adoption_digest,
                camera_input: &input,
                localization_identity: *localization,
                localization_root: *localization_root,
                localization_receipt: *localization_receipt,
            };
            match approve {
                None => preview_monitor(
                    deployment,
                    &request,
                    &mut jpeg,
                    &mut video,
                    &mut geometry,
                    cx,
                )?,
                Some(approval) => retain_monitor(
                    deployment,
                    &request,
                    *approval,
                    &mut jpeg,
                    &mut video,
                    &mut geometry,
                    cx,
                )?,
            }
        }
        Input::Replay {
            identity,
            root,
            receipt,
        } => replay_monitor(
            deployment,
            *identity,
            *root,
            *receipt,
            &mut jpeg,
            &mut video,
            &mut geometry,
            cx,
        )?,
    };
    let mut json = report.to_json()?;
    if json.pop() != Some('}') {
        return Err(MonitorError::Custody("monitor report envelope").into());
    }
    let command = |text: String| format!("\"{}\"", fss_cli::escape_json_str(&text));
    let approve = if report.status() == MonitorStatus::Proposed {
        command(format!("{} --approve {}", context.rerun, report.approval()))
    } else {
        "null".to_owned()
    };
    let replay = if report.status() == MonitorStatus::Proposed {
        "null".to_owned()
    } else {
        command(format!(
            "fss-event calibration monitor-replay --root {} --site {} --principal {} --monitor-id {} --expected-root {} --expected-receipt {} --work-units {} --geometry-work-units {}",
            quote(&context.root.to_string_lossy()),
            quote(&context.site),
            quote(&context.principal),
            report.identity(),
            report.publication_root()?,
            report.digest(),
            action.decode_work,
            action.geometry_work,
        ))
    };
    json.push_str(&format!(
        ",\"approve_command\":{approve},\"replay_command\":{replay},\"jpeg_work_units\":{},\"video_work_units\":{},\"total_geometry_work_units\":{},\"authority_sequence\":{}}}",
        jpeg.used(), video.used(), geometry.used(), deployment.current_anchor().commit_sequence,
    ));
    Ok(json)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    const PIN: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    fn args(operation: &str) -> Vec<OsString> {
        let mut values = vec![operation, "--root", "/unused", "--site", "site:monitor"];
        if operation == "monitor" {
            values.extend([
                "--calibration",
                "/unused/calibration",
                "--calibration-digest",
                PIN,
                "--camera-handle",
                "21",
                "--adoption-digest",
                PIN,
                "--camera-input",
                "/unused/original-camera-input",
                "--localization-id",
                PIN,
                "--localization-root",
                PIN,
                "--localization-receipt",
                PIN,
            ]);
        } else {
            values.extend([
                "--monitor-id",
                PIN,
                "--expected-root",
                PIN,
                "--expected-receipt",
                PIN,
            ]);
        }
        values.into_iter().map(OsString::from).collect()
    }
    #[test]
    fn monitor_requires_every_source_and_frozen_baseline_pin() -> Result<(), String> {
        let values = args("monitor");
        assert!(super::super::parse(&values).is_ok());
        for key in [
            "--calibration-digest",
            "--adoption-digest",
            "--camera-input",
            "--localization-id",
            "--localization-root",
            "--localization-receipt",
        ] {
            let mut missing = values.clone();
            let index = missing
                .iter()
                .position(|arg| arg == key)
                .ok_or_else(|| format!("missing test option {key}"))?;
            drop(missing.drain(index..index + 2));
            assert!(super::super::parse(&missing).is_err(), "{key}");
        }
        for key in ["--work-units", "--geometry-work-units"] {
            let mut zero = values.clone();
            zero.extend([key.into(), "0".into()]);
            assert!(super::super::parse(&zero).is_err(), "{key}");
        }
        Ok(())
    }
    #[test]
    fn cold_replay_accepts_no_external_geometry_override_or_retention_approval()
    -> Result<(), String> {
        let values = args("monitor-replay");
        assert!(super::super::parse(&values).is_ok());
        for key in [
            "--calibration",
            "--camera-input",
            "--localization-id",
            "--approve",
            "--bind",
        ] {
            let mut changed = values.clone();
            changed.extend([key.into(), PIN.into()]);
            assert!(super::super::parse(&changed).is_err(), "{key}");
        }
        for key in ["--monitor-id", "--expected-root", "--expected-receipt"] {
            let mut missing = values.clone();
            let index = missing
                .iter()
                .position(|arg| arg == key)
                .ok_or_else(|| format!("missing test option {key}"))?;
            drop(missing.drain(index..index + 2));
            assert!(super::super::parse(&missing).is_err(), "{key}");
        }
        Ok(())
    }
}
