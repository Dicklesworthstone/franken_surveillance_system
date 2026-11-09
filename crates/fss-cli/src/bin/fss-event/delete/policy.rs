#![forbid(unsafe_code)]
//! Exact local policy adoption and inspection, separate from deletion approval.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_core::region::ContextAuthority;
use fss_core::{PrincipalId, SensorId};
use fss_reference::deletion::retention::policy::{
    PolicyChangeRequest, PolicyOutcome, PolicyReceipt, RetentionPolicyRecord, commit_policy_change,
    list_policies, preview_policy_change,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{
    DeleteAction, Operation, RunResult, attested_time, findings, quote, quote_arg, retention_json,
    sha256,
};

pub(super) fn parse(args: &[OsString]) -> Result<DeleteAction, String> {
    let command = args
        .first()
        .and_then(|arg| arg.to_str())
        .ok_or("policy command required")?;
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0]
            .to_str()
            .ok_or("policy option names require UTF-8")?;
        let value = pair
            .get(1)
            .and_then(|arg| arg.to_str())
            .ok_or("policy option requires a value")?;
        let allowed = matches!(key, "--root" | "--site" | "--principal" | "--sensor-id")
            || command != "policy-show"
                && matches!(
                    key,
                    "--state"
                        | "--retain-for-ns"
                        | "--max-retained-source-bytes"
                        | "--expected-policy"
                        | "--attested-now-ns"
                        | "--reason"
                )
            || command == "policy-commit" && key == "--approve";
        if !allowed
            || value.is_empty()
            || value.starts_with("--")
            || values.insert(key, value).is_some()
        {
            return Err("unknown, duplicate or incomplete retention policy option".to_owned());
        }
    }
    let text = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("required option {key}"))
    };
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .copied()
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let operation = if command == "policy-show" {
        Operation::PolicyShow(
            values
                .get("--sensor-id")
                .map(|value| SensorId::parse(*value))
                .transpose()
                .map_err(|_| "invalid sensor ID")?,
        )
    } else {
        let request = PolicyChangeRequest {
            sensor: SensorId::parse(text("--sensor-id")?).map_err(|_| "invalid sensor ID")?,
            enabled: match text("--state")? {
                "enabled" => true,
                "disabled" => false,
                _ => return Err("--state requires enabled or disabled".to_owned()),
            },
            retain_for_ns: text("--retain-for-ns")?
                .parse()
                .map_err(|_| "positive retention nanoseconds required")?,
            max_retained_source_bytes: values
                .get("--max-retained-source-bytes")
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|_| "nonnegative source bytes required")?,
            expected_policy: match text("--expected-policy")? {
                "none" => None,
                value => Some(sha256(value, "--expected-policy")?),
            },
            attested_now: attested_time(text("--attested-now-ns")?)?,
            reason: text("--reason")?.to_owned(),
        };
        request.validate().map_err(|error| error.to_string())?;
        if command == "policy-commit" {
            Operation::PolicyCommit {
                request,
                approve: sha256(text("--approve")?, "--approve")?,
            }
        } else {
            Operation::PolicyPlan(request)
        }
    };
    Ok(DeleteAction {
        root: PathBuf::from(text("--root")?),
        site,
        principal,
        operation,
        retention: None,
    })
}

fn record_json(record: &RetentionPolicyRecord) -> String {
    let request = record.request();
    format!(
        "{{\"format\":\"{}\",\"policy_digest\":\"{}\",\"sensor_id\":{},\"state\":\"{}\",\"generation\":\"{}\",\"retain_for_ns\":\"{}\",\"max_retained_source_bytes\":{},\"predecessor\":{},\"principal\":{},\"site\":{},\"basis_sequence\":\"{}\",\"basis_state_root\":\"{}\",\"attested_now\":{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\"}},\"reason\":{},\"affected_selection_digest\":\"{}\",\"affected_plan_digest\":{},\"automatic_deletion_authorized\":false}}",
        fss_reference::deletion::retention::policy::POLICY_DOMAIN,
        record.digest(),
        quote(request.sensor.as_str()),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
        record.generation(),
        request.retain_for_ns,
        request
            .max_retained_source_bytes
            .map_or_else(|| "null".to_owned(), |bytes| quote(&bytes.to_string())),
        request
            .expected_policy
            .map_or_else(|| "null".to_owned(), |digest| quote(&digest.to_text())),
        quote(record.principal()),
        quote(record.site()),
        record.basis().commit_sequence,
        record.basis().state_root,
        request.attested_now.earliest.0,
        request.attested_now.latest.0,
        quote(&request.reason),
        record.affected_selection(),
        record
            .affected_plan()
            .map_or_else(|| "null".to_owned(), |digest| quote(&digest.to_text()))
    )
}

fn command(action: &DeleteAction, receipt: &PolicyReceipt) -> String {
    let request = receipt.record.request();
    let budget = request
        .max_retained_source_bytes
        .map_or_else(String::new, |bytes| {
            format!(" --max-retained-source-bytes {bytes}")
        });
    let predecessor = request
        .expected_policy
        .map_or_else(|| "none".to_owned(), |digest| digest.to_text());
    quote(&format!(
        "fss-event delete policy-commit --root {} --site {} --principal {} --sensor-id {} --state {} --retain-for-ns {}{budget} --expected-policy {predecessor} --attested-now-ns {}:{} --reason {} --approve {}",
        quote_arg(&action.root.to_string_lossy()),
        quote_arg(&action.site),
        quote_arg(&action.principal),
        quote_arg(request.sensor.as_str()),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
        request.retain_for_ns,
        request.attested_now.earliest.0,
        request.attested_now.latest.0,
        quote_arg(&request.reason),
        receipt.record.approval()
    ))
}

pub(super) fn run(
    action: &DeleteAction,
    deployment: &mut ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> RunResult<String> {
    let receipt = match &action.operation {
        Operation::PolicyPlan(request) => {
            preview_policy_change(deployment, request, authority, cx)?
        }
        Operation::PolicyCommit { request, approve } => {
            commit_policy_change(deployment, request, *approve, authority, cx)?
        }
        Operation::PolicyShow(sensor) => {
            let records = list_policies(deployment, authority, cx)?;
            let records: Vec<_> = records
                .iter()
                .filter(|record| {
                    sensor
                        .as_ref()
                        .is_none_or(|sensor| &record.request().sensor == sensor)
                })
                .map(record_json)
                .collect();
            return Ok(format!(
                "{{\"format\":\"fss.retention_policy_cli.v1\",\"operation\":\"show\",\"policies\":[{}],\"writes\":\"none\",\"automatic_deletion_authorized\":false}}\n",
                records.join(",")
            ));
        }
        _ => return Err(std::io::Error::other("invalid retention policy operation").into()),
    };
    // The full inventory projection is read-only preview output. After a committed
    // change, report the bounded record and its retained impact identities only.
    let affected = match receipt
        .affected
        .as_ref()
        .filter(|_| receipt.outcome == PolicyOutcome::Proposed)
    {
        Some(affected) => {
            let (imports, bytes, blockers) =
                affected
                    .deletion
                    .as_ref()
                    .map_or((0, 0, "[]".to_owned()), |plan| {
                        (
                            plan.imports.len(),
                            plan.deletable_bytes(),
                            findings(&plan.blockers),
                        )
                    });
            format!(
                "{{\"selection\":{},\"selected_imports\":{imports},\"quoted_local_deletable_bytes\":\"{bytes}\",\"blockers\":{blockers},\"deletion_authorized\":false}}",
                retention_json(&affected.assessment.selection)
            )
        }
        None => "null".to_owned(),
    };
    let approve = if receipt.outcome == PolicyOutcome::Proposed {
        command(action, &receipt)
    } else {
        "null".to_owned()
    };
    Ok(format!(
        "{{\"format\":\"fss.retention_policy_cli.v1\",\"outcome\":\"{}\",\"policy\":{},\"approval_digest\":\"{}\",\"approve_command\":{approve},\"settings_impact_if_enabled\":{affected},\"writes\":\"{}\",\"media_deleted\":false,\"automatic_deletion_authorized\":false}}\n",
        receipt.outcome.as_str(),
        record_json(&receipt.record),
        receipt.record.approval(),
        if receipt.outcome == PolicyOutcome::Committed {
            "policy_revision"
        } else {
            "none"
        }
    ))
}
