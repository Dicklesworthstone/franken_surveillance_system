#![forbid(unsafe_code)]
//! `fss-event calibration`: owner adoption of a site calibration per camera, retained as
//! deployment authority (fss-x8j0v follow-up).
//!
//! `adopt` reads the calibration file named by `--calibration` and verifies it against the pinned
//! `--calibration-digest` before anything else. Each `--bind NAME:SENSOR` adopts that calibrated
//! camera for a retained sensor. Without `--approve` it previews: it prints every proposed
//! receipt and the exact approval digest over the calibration, the bindings and each camera's
//! current retained adoption, and writes nothing. With `--approve DIGEST` it retains exactly that
//! adoption, one `twin_localization_receipt` authority delta per camera in one batch; a stale or
//! wrong approval is refused before any write, and an exact rerun writes nothing. `show` prints
//! every adopted camera's current receipt and history. `invalidate` withdraws one exact current
//! adoption with a separately retained owner approval. Recovery requires a new calibration
//! digest and a newer camera generation. These commands retain owner authority, not a physical
//! observation of the camera. `monitor` separately measures the frozen adopted pose against
//! exact retained native localization evidence; `monitor-replay` reproduces an approved result
//! from custody. Both expose a bounded observation, never automatic adoption or withdrawal.

#[path = "calibration/monitor.rs"]
mod monitor;

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId, SensorId};
use fss_reference::ingest::calibration_adoption::{
    ADOPTION_CLAIM, AdoptionStatus, CalibrationSubject, MAX_ADOPTION_CAMERAS, adopt,
    preview_adoption, state_json,
};
use fss_reference::ingest::calibration_invalidation::{
    INVALIDATION_CLAIM, InvalidationReason, InvalidationRequest, InvalidationStatus, invalidate,
    preview_invalidation,
};
use fss_reference::ingest::site_calibration::{MAX_CALIBRATION_BYTES, SiteCalibration};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{RunResult, export};

/// What the command does.
#[derive(Debug)]
enum Operation {
    Adopt {
        path: PathBuf,
        digest: ContentDigest,
        bindings: Vec<(String, SensorId)>,
        approve: Option<ContentDigest>,
    },
    Invalidate {
        request: InvalidationRequest,
        approve: Option<ContentDigest>,
    },
    Monitor(monitor::Action),
    Show,
}

/// Fully parsed request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct CalibrationAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    operation: Operation,
    report_out: Option<PathBuf>,
    rerun: String,
}

fn quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn sha256(value: &str, key: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(digest)
}

fn binding(value: &str) -> Result<(String, SensorId), String> {
    let usage = "binding must be NAME:SENSOR (a calibrated camera name and a retained sensor id)";
    let (name, sensor) = value.split_once(':').ok_or(usage)?;
    if !fss_reference::ingest::site_calibration::valid_camera_name(name) {
        return Err(usage.to_owned());
    }
    Ok((name.to_owned(), SensorId::parse(sensor).map_err(|_| usage)?))
}

/// Parses the arguments after `calibration`.
pub(super) fn parse(args: &[OsString]) -> Result<CalibrationAction, String> {
    if args.len() > 64 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("calibration request exceeds its argument bounds".to_owned());
    }
    let operation = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("calibration requires adopt, invalidate, monitor, monitor-replay or show")?;
    if !matches!(
        operation,
        "adopt" | "invalidate" | "monitor" | "monitor-replay" | "show"
    ) {
        return Err(
            "calibration requires adopt, invalidate, monitor, monitor-replay or show".to_owned(),
        );
    }
    let mut values: Vec<(String, String)> = Vec::new();
    let mut bindings: Vec<(String, SensorId)> = Vec::new();
    let mut rerun = vec![
        "fss-event".to_owned(),
        "calibration".to_owned(),
        operation.to_owned(),
    ];
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let argument = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?
            .to_str()
            .ok_or_else(|| format!("{key} requires a UTF-8 value"))?;
        if argument.is_empty() || argument.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        let allowed = matches!(key, "--root" | "--site" | "--principal" | "--report-out")
            || monitor::accepts(operation, key)
            || (operation == "adopt"
                && matches!(key, "--calibration" | "--calibration-digest" | "--approve"))
            || (operation == "invalidate"
                && matches!(
                    key,
                    "--camera-handle"
                        | "--adoption-digest"
                        | "--reason"
                        | "--evidence"
                        | "--approve"
                ));
        if key == "--bind" && operation == "adopt" {
            if bindings.len() == MAX_ADOPTION_CAMERAS {
                return Err("at most 16 --bind".to_owned());
            }
            bindings.push(binding(argument)?);
        } else if !allowed {
            return Err("unknown or inapplicable option".to_owned());
        } else if values.iter().any(|(k, _)| k == key) {
            return Err(format!("duplicate {key}"));
        } else {
            values.push((key.to_owned(), argument.to_owned()));
        }
        if key != "--approve" && key != "--report-out" {
            rerun.push(quote(key));
            rerun.push(quote(argument));
        }
        index += 2;
    }
    let text = |key: &str| -> Result<&str, String> {
        values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| format!("required option {key}"))
    };
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal =
        text("--principal").map_or_else(|_| "principal:local-operator".to_owned(), str::to_owned);
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let operation = if operation == "adopt" {
        if bindings.is_empty() {
            return Err("at least one --bind NAME:SENSOR is required".to_owned());
        }
        Operation::Adopt {
            path: PathBuf::from(text("--calibration")?),
            digest: sha256(text("--calibration-digest")?, "--calibration-digest")?,
            bindings,
            approve: match text("--approve") {
                Ok(value) => Some(sha256(value, "--approve")?),
                Err(_) => None,
            },
        }
    } else if operation == "invalidate" {
        let camera_handle = text("--camera-handle")?
            .parse::<u64>()
            .ok()
            .filter(|handle| *handle != 0)
            .ok_or("--camera-handle must be a nonzero unsigned integer")?;
        Operation::Invalidate {
            request: InvalidationRequest {
                camera_handle,
                adoption_digest: sha256(text("--adoption-digest")?, "--adoption-digest")?,
                reason: InvalidationReason::parse(text("--reason")?)
                    .map_err(|error| error.to_string())?,
                evidence: match text("--evidence") {
                    Ok(value) => Some(sha256(value, "--evidence")?),
                    Err(_) => None,
                },
            },
            approve: match text("--approve") {
                Ok(value) => Some(sha256(value, "--approve")?),
                Err(_) => None,
            },
        }
    } else if matches!(operation, "monitor" | "monitor-replay") {
        Operation::Monitor(monitor::parse(operation, &values)?)
    } else {
        Operation::Show
    };
    Ok(CalibrationAction {
        root: PathBuf::from(text("--root")?),
        site,
        principal,
        operation,
        report_out: values
            .iter()
            .find(|(k, _)| k == "--report-out")
            .map(|(_, v)| PathBuf::from(v)),
        rerun: rerun.join(" "),
    })
}

/// Previews, adopts, withdraws or shows, and prints the JSON report.
pub(super) fn run(
    action: &CalibrationAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let json = match &action.operation {
        Operation::Show => state_json(deployment)?,
        Operation::Monitor(monitor) => monitor::run(monitor, action, deployment, cx)?,
        Operation::Invalidate { request, approve } => {
            let invalidation = match approve {
                None => preview_invalidation(deployment, request)?,
                Some(approval) => invalidate(deployment, request, *approval, cx)?,
            };
            let command = if invalidation.status == InvalidationStatus::Proposed {
                format!(
                    "\"{} --approve {}\"",
                    fss_cli::escape_json_str(&action.rerun),
                    invalidation.approval
                )
            } else {
                "null".to_owned()
            };
            format!(
                concat!(
                    "{{\"format\":\"fss.calibration_invalidation_report.v1\",",
                    "\"status\":\"{}\",\"approval_digest\":\"{}\",",
                    "\"approve_command\":{},\"receipt\":{},\"claim\":\"{}\",",
                    "\"authority_sequence\":{}}}"
                ),
                invalidation.status.as_str(),
                invalidation.approval,
                command,
                invalidation.receipt.to_json(),
                INVALIDATION_CLAIM,
                deployment.current_anchor().commit_sequence
            )
        }
        Operation::Adopt {
            path,
            digest,
            bindings,
            approve,
        } => {
            // Verified against the pinned digest before the deployment is consulted.
            let bytes = super::calibrate::read_bounded(path, MAX_CALIBRATION_BYTES, "calibration")?;
            let (calibration, identity) = SiteCalibration::decode(&bytes, Some(*digest))?;
            let subject = CalibrationSubject::from_calibration(&calibration, identity);
            let adoption = match approve {
                None => preview_adoption(deployment, &subject, bindings)?,
                Some(approval) => adopt(deployment, &subject, bindings, *approval, cx)?,
            };
            let command = match adoption.status() {
                AdoptionStatus::Proposed => format!(
                    "\"{} --approve {}\"",
                    fss_cli::escape_json_str(&action.rerun),
                    adoption.approval
                ),
                AdoptionStatus::Retained | AdoptionStatus::AlreadyCurrent => "null".to_owned(),
            };
            let cameras: Vec<String> = adoption
                .cameras
                .iter()
                .map(|camera| {
                    format!(
                        "{{\"status\":\"{}\",\"receipt\":{},\"supersedes_current\":{}}}",
                        camera.status.as_str(),
                        camera.receipt.to_json(),
                        match (&camera.current, camera.status) {
                            (
                                Some(current),
                                AdoptionStatus::Proposed | AdoptionStatus::Retained,
                            ) => {
                                format!("\"{}\"", current.digest)
                            }
                            _ => "null".to_owned(),
                        }
                    )
                })
                .collect();
            format!(
                concat!(
                    "{{\"format\":\"fss.calibration_adoption.v1\",\"status\":\"{}\",",
                    "\"calibration_digest\":\"{}\",\"approval_digest\":\"{}\",",
                    "\"approve_command\":{},\"cameras\":[{}],\"claim\":\"{}\",",
                    "\"authority_sequence\":{}}}"
                ),
                adoption.status().as_str(),
                adoption.calibration_digest,
                adoption.approval,
                command,
                cameras.join(","),
                ADOPTION_CLAIM,
                deployment.current_anchor().commit_sequence
            )
        }
    };
    let json = format!("{json}\n");
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}
