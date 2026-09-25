#![forbid(unsafe_code)]
//! `fss-event hold`: owner-placed deletion holds (authority; PRIVACY.md 8.1).
//!
//! `place` without `--approve` previews: it prints the canonical hold record, its identity and
//! the exact approval over the current authority head, and writes nothing. With `--approve` it
//! retains exactly that hold (`deletion_hold` generation 1); a stale approval is refused before
//! any write and re-presenting the approval that placed a hold writes nothing. `release` works
//! the same way and records the release (generation 2); the placement is never erased. `list`
//! prints every hold with its state on the deployment's evidence clock (not wall time).

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use fss_cli::escape_json_str;
use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::deletion::holds::{
    HoldRegistry, HoldRequest, HoldScope, HoldStatus, RetainedHold, hold_registry, place_hold,
    preview_hold, preview_release, release_hold,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::RunResult;

const CLOCK: &str = "deployment_evidence_clock_not_wall_time";

/// What the command does.
#[derive(Debug)]
enum Operation {
    Place {
        request: HoldRequest,
        approve: Option<ContentDigest>,
    },
    Release {
        hold_id: ContentDigest,
        approve: Option<ContentDigest>,
    },
    List,
}

/// Fully parsed request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct HoldAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    operation: Operation,
    /// Option pairs other than `--approve`, for the printed rerun command.
    rerun: Vec<(String, String)>,
}

fn sha256(value: &str, key: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(digest)
}

/// Parses the arguments after `hold`.
pub(super) fn parse(args: &[OsString]) -> Result<HoldAction, String> {
    let operation = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("hold requires place, release or list")?;
    if !matches!(operation, "place" | "release" | "list") {
        return Err("hold requires place, release or list".to_owned());
    }
    let mut values: Vec<(String, String)> = Vec::new();
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
        let allowed = matches!(key, "--root" | "--site" | "--principal")
            || (operation == "place"
                && matches!(
                    key,
                    "--scope" | "--reason" | "--expires-at-ns" | "--approve"
                ))
            || (operation == "release" && matches!(key, "--hold-id" | "--approve"));
        if !allowed {
            return Err("unknown or inapplicable option".to_owned());
        }
        if values.iter().any(|(k, _)| k == key) {
            return Err(format!("duplicate {key}"));
        }
        values.push((key.to_owned(), argument.to_owned()));
        index += 2;
    }
    let find = |key: &str| {
        values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let text = |key: &str| find(key).ok_or_else(|| format!("required option {key}"));
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = find("--principal")
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let approve = find("--approve")
        .map(|value| sha256(value, "--approve"))
        .transpose()?;
    let operation = match operation {
        "place" => {
            let expires_at_ns = find("--expires-at-ns")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0 && value.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or("--expires-at-ns requires a positive decimal integer (ns)")
                })
                .transpose()?;
            Operation::Place {
                request: HoldRequest {
                    scope: HoldScope::parse(text("--scope")?).map_err(|e| e.to_string())?,
                    reason: text("--reason")?.to_owned(),
                    expires_at_ns,
                    principal: principal.clone(),
                },
                approve,
            }
        }
        "release" => Operation::Release {
            hold_id: sha256(text("--hold-id")?, "--hold-id")?,
            approve,
        },
        _ => Operation::List,
    };
    Ok(HoldAction {
        root: PathBuf::from(text("--root")?),
        site,
        principal,
        operation,
        rerun: values
            .into_iter()
            .filter(|(key, _)| key != "--approve")
            .collect(),
    })
}

fn quote(text: &str) -> String {
    format!("\"{}\"", escape_json_str(text))
}

fn quote_arg(argument: &str) -> String {
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

fn approve_command(action: &HoldAction, verb: &str, approval: ContentDigest) -> String {
    let mut command = format!("fss-event hold {verb}");
    let mut pairs = action.rerun.clone();
    if !pairs.iter().any(|(key, _)| key == "--principal") {
        pairs.push(("--principal".to_owned(), action.principal.clone()));
    }
    for (key, value) in pairs {
        command.push(' ');
        command.push_str(&key);
        command.push(' ');
        command.push_str(&quote_arg(&value));
    }
    command.push_str(&format!(" --approve {approval}"));
    quote(&command)
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

fn hold_json(hold: &RetainedHold) -> String {
    let request = &hold.record.request;
    let (release, released_by) = hold.release.as_ref().map_or_else(
        || ("null".to_owned(), "null".to_owned()),
        |(digest, record)| (quote(&digest.to_text()), quote(&record.principal)),
    );
    format!(
        "{{\"hold_id\":\"{}\",\"scope\":{},\"scope_kind\":\"{}\",\"reason\":{},\"expires_at_ns\":{},\"placed_by\":{},\"placed_at_sequence\":{},\"state\":\"{}\",\"release_record\":{release},\"released_by\":{released_by}}}",
        hold.hold_id,
        quote(&request.scope.text()),
        request.scope.kind(),
        quote(&request.reason),
        optional_u64(request.expires_at_ns),
        quote(&request.principal),
        hold.record.basis_sequence,
        hold.state.as_str(),
    )
}

/// JSON list of every hold of `registry`, for `hold list` and `delete plan`.
pub(super) fn registry_json(registry: &HoldRegistry) -> String {
    let holds: Vec<String> = registry.holds.iter().map(hold_json).collect();
    let unreadable: Vec<String> = registry.unreadable.iter().map(|o| quote(o)).collect();
    format!(
        "\"evidence_clock_ns\":{},\"clock\":\"{CLOCK}\",\"holds\":[{}],\"unreadable\":[{}]",
        registry.evidence_clock_ns,
        holds.join(","),
        unreadable.join(",")
    )
}

/// Places, releases or lists holds, and prints the JSON report.
pub(super) fn run(
    action: &HoldAction,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let json = match &action.operation {
        Operation::List => format!(
            "{{\"format\":\"fss.deletion_hold_list.v1\",\"site_lineage\":{},{},\"writes\":\"none\"}}\n",
            quote(deployment.site_lineage()),
            registry_json(&hold_registry(deployment))
        ),
        Operation::Place { request, approve } => {
            let placement = match approve {
                None => preview_hold(deployment, request)?,
                Some(approval) => place_hold(deployment, request, *approval, cx)?,
            };
            let command = if placement.status == HoldStatus::Proposed {
                approve_command(action, "place", placement.approval)
            } else {
                "null".to_owned()
            };
            let request = &placement.record.request;
            format!(
                "{{\"format\":\"fss.deletion_hold.v1\",\"operation\":\"place\",\"status\":\"{}\",\"hold_id\":\"{}\",\"scope\":{},\"scope_kind\":\"{}\",\"reason\":{},\"expires_at_ns\":{},\"principal\":{},\"basis_sequence\":{},\"evidence_clock_ns\":{},\"clock\":\"{CLOCK}\",\"approval_digest\":\"{}\",\"approve_command\":{command},\"blocks\":\"delete plan and delete commit of every import it covers while active\",\"writes\":\"{}\"}}\n",
                placement.status.as_str(),
                placement.hold_id,
                quote(&request.scope.text()),
                request.scope.kind(),
                quote(&request.reason),
                optional_u64(request.expires_at_ns),
                quote(&request.principal),
                placement.record.basis_sequence,
                placement.evidence_clock_ns,
                placement.approval,
                if placement.status == HoldStatus::Retained {
                    "deletion_hold_generation_1"
                } else {
                    "none"
                },
            )
        }
        Operation::Release { hold_id, approve } => {
            let release = match approve {
                None => preview_release(deployment, *hold_id, &action.principal)?,
                Some(approval) => {
                    release_hold(deployment, *hold_id, &action.principal, *approval, cx)?
                }
            };
            let (approval, command) = match (&release.release, release.status) {
                (Some((_, approval)), HoldStatus::Proposed) => (
                    quote(&approval.to_text()),
                    approve_command(action, "release", *approval),
                ),
                (Some((_, approval)), _) => (quote(&approval.to_text()), "null".to_owned()),
                (None, _) => ("null".to_owned(), "null".to_owned()),
            };
            format!(
                "{{\"format\":\"fss.deletion_hold_release.v1\",\"operation\":\"release\",\"status\":\"{}\",\"hold\":{},\"evidence_clock_ns\":{},\"clock\":\"{CLOCK}\",\"approval_digest\":{approval},\"approve_command\":{command},\"placement_record\":\"retained\",\"writes\":\"{}\"}}\n",
                release.status.as_str(),
                hold_json(&release.hold),
                release.evidence_clock_ns,
                if release.status == HoldStatus::Retained {
                    "deletion_hold_generation_2"
                } else {
                    "none"
                },
            )
        }
    };
    out.write_all(json.as_bytes())?;
    Ok(())
}
