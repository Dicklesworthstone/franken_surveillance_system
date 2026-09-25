#![forbid(unsafe_code)]
//! `fss-event privacy-mask`: owner-declared per-sensor privacy masks (GOAL-009).
//!
//! `declare` without `--approve` previews: it prints the canonical policy digest and the exact
//! approval digest over the sensor's current retained policy, and writes nothing. With
//! `--approve DIGEST` it retains exactly that declaration as the sensor's next policy
//! generation (a `privacy_mask_policy` authority delta); a stale or wrong approval is refused
//! before any write, and an exact rerun writes nothing. `show` prints the sensor's current
//! binding. There is no unmasked-access override.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId, SensorId};
use fss_reference::ingest::privacy_mask::{
    MAX_MASK_REGIONS, MaskDeclarationStatus, PrivacyMaskPolicy, current_mask, declare_mask,
    preview_mask,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{RunResult, export};

/// What the command does.
#[derive(Debug)]
enum Operation {
    Declare {
        resolution: [u32; 2],
        rectangles: Vec<[u32; 4]>,
        approve: Option<ContentDigest>,
    },
    Show,
}

/// Fully parsed request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct PrivacyMaskAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    sensor: SensorId,
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

fn rectangle(value: &str) -> Result<[u32; 4], String> {
    let parts: Vec<u32> = value
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| "rectangle must be four unsigned integers X,Y,W,H")?;
    let [x, y, w, h] = parts[..] else {
        return Err("rectangle must be four unsigned integers X,Y,W,H".to_owned());
    };
    Ok([x, y, w, h])
}

fn resolution(value: &str) -> Result<[u32; 2], String> {
    let (w, h) = value
        .split_once('x')
        .ok_or("resolution must be WIDTHxHEIGHT in decoded pixels")?;
    Ok([
        w.parse().map_err(|_| "invalid resolution width")?,
        h.parse().map_err(|_| "invalid resolution height")?,
    ])
}

/// Parses the arguments after `privacy-mask`.
pub(super) fn parse(args: &[OsString]) -> Result<PrivacyMaskAction, String> {
    let operation = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("privacy-mask requires declare or show")?;
    if !matches!(operation, "declare" | "show") {
        return Err("privacy-mask requires declare or show".to_owned());
    }
    let mut values: Vec<(String, String)> = Vec::new();
    let mut rectangles = Vec::new();
    let mut rerun = vec![
        "fss-event".to_owned(),
        "privacy-mask".to_owned(),
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
        let allowed = matches!(
            key,
            "--root" | "--site" | "--principal" | "--sensor" | "--report-out"
        ) || (operation == "declare" && matches!(key, "--resolution" | "--approve"));
        if key == "--rect" && operation == "declare" {
            if rectangles.len() == MAX_MASK_REGIONS {
                return Err("at most 32 rectangles".to_owned());
            }
            rectangles.push(rectangle(argument)?);
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
    let sensor = SensorId::parse(text("--sensor")?).map_err(|_| "invalid sensor ID")?;
    let operation = if operation == "declare" {
        if rectangles.is_empty() {
            return Err("at least one --rect X,Y,W,H is required".to_owned());
        }
        let approve = match text("--approve") {
            Ok(value) => {
                let digest =
                    ContentDigest::parse(value).map_err(|_| "invalid digest for --approve")?;
                if digest.algorithm() != DigestAlgorithm::Sha256 {
                    return Err("--approve requires SHA-256".to_owned());
                }
                Some(digest)
            }
            Err(_) => None,
        };
        Operation::Declare {
            resolution: resolution(text("--resolution")?)?,
            rectangles,
            approve,
        }
    } else {
        Operation::Show
    };
    Ok(PrivacyMaskAction {
        root: PathBuf::from(text("--root")?),
        site,
        principal,
        sensor,
        operation,
        report_out: values
            .iter()
            .find(|(k, _)| k == "--report-out")
            .map(|(_, v)| PathBuf::from(v)),
        rerun: rerun.join(" "),
    })
}

fn optional(value: Option<String>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| format!("\"{v}\""))
}

/// Previews, declares or shows, and prints the JSON report.
pub(super) fn run(
    action: &PrivacyMaskAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let json = match &action.operation {
        Operation::Show => {
            let binding = current_mask(deployment, &action.sensor)?;
            format!(
                "{{\"format\":\"fss.privacy_mask_state.v1\",\"sensor_id\":\"{}\",\"privacy_mask\":{},\"authority_sequence\":{}}}",
                action.sensor,
                binding.to_json(),
                deployment.current_anchor().commit_sequence
            )
        }
        Operation::Declare {
            resolution,
            rectangles,
            approve,
        } => {
            let policy = PrivacyMaskPolicy::new(action.sensor.clone(), *resolution, rectangles)?;
            let declaration = match approve {
                None => preview_mask(deployment, &policy)?,
                Some(approval) => declare_mask(deployment, &policy, *approval, cx)?,
            };
            let command = match declaration.status {
                MaskDeclarationStatus::Proposed => optional(Some(format!(
                    "{} --approve {}",
                    action.rerun, declaration.approval
                ))),
                MaskDeclarationStatus::Retained | MaskDeclarationStatus::AlreadyCurrent => {
                    "null".to_owned()
                }
            };
            let regions: Vec<String> = policy
                .regions()
                .iter()
                .map(|r| format!("[{},{},{},{}]", r.x(), r.y(), r.width(), r.height()))
                .collect();
            format!(
                "{{\"format\":\"fss.privacy_mask_declaration.v1\",\"sensor_id\":\"{}\",\"status\":\"{}\",\"policy_digest\":\"{}\",\"approval_digest\":\"{}\",\"approve_command\":{command},\"generation\":{},\"replaces\":{},\"stream_resolution\":[{},{}],\"masked_rectangles\":[{}],\"applied_redaction_transform\":\"{}\",\"privacy_mask\":{},\"unmasked_access\":\"refused\",\"authority_sequence\":{}}}",
                action.sensor,
                declaration.status.as_str(),
                declaration.policy_digest,
                declaration.approval,
                declaration
                    .generation
                    .map_or_else(|| "null".to_owned(), |g| g.to_string()),
                optional(declaration.replaces.map(|d| d.to_text())),
                resolution[0],
                resolution[1],
                regions.join(","),
                fss_reference::ingest::privacy_mask::mask_transform().as_str(),
                current_mask(deployment, &action.sensor)?.to_json(),
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
