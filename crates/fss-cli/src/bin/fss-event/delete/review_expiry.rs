#![forbid(unsafe_code)]
//! Exact, one-shot expiry cleanup of retained review derivatives, preserving source custody.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_core::{PrincipalId, SensorId};
use fss_reference::deletion::review_expiry::{
    ReviewExpiryRequest, ReviewExpirySelection, assess_review_expiry, commit_review_expiry,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{
    DeleteAction, Operation, RunResult, attested_time, completion_json, findings, plan_json, quote,
    sha256,
};

pub(super) fn parse(args: &[OsString]) -> Result<DeleteAction, String> {
    let command = args
        .first()
        .and_then(|argument| argument.to_str())
        .ok_or("explicit review expiry command required")?;
    let commit = match command {
        "review-expiry-plan" => false,
        "review-expiry-commit" => true,
        _ => return Err("unknown review expiry command".into()),
    };
    if args.len() > 15 || args.len() % 2 != 1 {
        return Err("review expiry argument bound exceeded or option value missing".into());
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0]
            .to_str()
            .ok_or("review expiry option names require UTF-8")?;
        let value = &pair[1];
        let allowed = matches!(
            key,
            "--root" | "--site" | "--principal" | "--sensor-id" | "--attested-now-ns"
        ) || commit && matches!(key, "--plan" | "--approve");
        if !allowed
            || value.is_empty()
            || value.as_encoded_bytes().len() > 4096
            || value.to_str().is_some_and(|value| value.starts_with("--"))
            || values.insert(key, value).is_some()
        {
            return Err("unknown, duplicate or incomplete review expiry option".into());
        }
    }
    let text = |key: &str| {
        values
            .get(key)
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("required UTF-8 option {key}"))
    };
    let root = PathBuf::from(*values.get("--root").ok_or("required option --root")?);
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = match values.get("--principal") {
        Some(_) => text("--principal")?,
        None => "principal:local-operator",
    }
    .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let sensor = SensorId::parse(text("--sensor-id")?).map_err(|_| "invalid sensor ID")?;
    let now_text = text("--attested-now-ns")?;
    let now = attested_time(now_text)?;
    if format!("{}:{}", now.earliest.0, now.latest.0) != now_text {
        return Err("attested time requires canonical signed decimal nanoseconds".into());
    }
    let request = ReviewExpiryRequest::new(sensor, now).map_err(|error| error.to_string())?;
    let operation = if commit {
        Operation::ReviewExpiryCommit {
            request,
            plan: sha256(text("--plan")?, "--plan")?,
            approve: sha256(text("--approve")?, "--approve")?,
        }
    } else {
        Operation::ReviewExpiryPlan(request)
    };
    Ok(DeleteAction {
        root,
        site,
        principal,
        operation,
        retention: None,
    })
}

pub(super) fn selection_json(selection: &ReviewExpirySelection) -> String {
    let request = selection.request();
    let now = request.attested_now();
    let candidates: Vec<String> = selection
        .candidates()
        .iter()
        .map(|candidate| {
            let witness = candidate
                .closure_witness()
                .map_or_else(|| "null".to_owned(), |digest| quote(&digest.to_text()));
            format!(
                "{{\"review_root\":\"{}\",\"record_digest\":\"{}\",\"source_import_identity\":\"{}\",\"expires_at_ns\":\"{}\",\"disposition\":\"{}\",\"trial_plan_digest\":{witness},\"blockers\":{}}}",
                candidate.root(),
                candidate.record_digest(),
                candidate.import_identity(),
                candidate.expires_at().0,
                candidate.disposition().as_str(),
                findings(candidate.blockers())
            )
        })
        .collect();
    let roots: Vec<String> = selection
        .roots()
        .iter()
        .map(|root| quote(&root.to_text()))
        .collect();
    format!(
        "{{\"format\":\"fss.review_expiry_selection.v1\",\"sensor_id\":{},\"attested_now\":{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\"}},\"time_provenance\":\"owner_assertion_not_observed_clock\",\"eligibility\":\"grant_expiry_not_after_earliest_attested_now\",\"candidates\":[{}],\"selected_review_roots\":[{}],\"source_imports_selected\":false,\"holds_released\":false,\"automatic_deletion_authorized\":false}}",
        quote(request.sensor().as_str()),
        now.earliest.0,
        now.latest.0,
        candidates.join(","),
        roots.join(",")
    )
}

pub(super) fn run(
    action: &DeleteAction,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> RunResult<String> {
    match &action.operation {
        Operation::ReviewExpiryPlan(request) => {
            let assessment = assess_review_expiry(deployment, request, cx)?;
            let status = match &assessment.deletion {
                Some(plan) if !plan.blockers.is_empty() => "blocked",
                Some(_) => "planned",
                None if assessment
                    .selection
                    .candidates()
                    .iter()
                    .any(|candidate| !candidate.blockers().is_empty()) =>
                {
                    "blocked"
                }
                None => "nothing_eligible",
            };
            let plan = match &assessment.deletion {
                Some(plan) => plan_json(action, plan)?,
                None => "null".to_owned(),
            };
            Ok(format!(
                "{{\"format\":\"fss.review_expiry_preview.v1\",\"status\":\"{status}\",\"selection\":{},\"deletion_plan\":{},\"original_evidence_selected\":false,\"writes\":\"none\",\"qualification\":\"implemented_not_qualified\"}}\n",
                selection_json(&assessment.selection),
                plan.trim()
            ))
        }
        Operation::ReviewExpiryCommit {
            request,
            plan,
            approve,
        } => {
            let receipt =
                commit_review_expiry(deployment, request, *plan, *approve, &action.principal, cx)?;
            Ok(completion_json(&receipt))
        }
        _ => Err(std::io::Error::other("invalid review expiry operation").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(command: &str) -> Vec<OsString> {
        [
            command,
            "--root",
            "must-not-open",
            "--site",
            "site:review-expiry",
            "--sensor-id",
            "sensor:front",
            "--attested-now-ns",
            "100:120",
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }

    #[test]
    fn expiry_actions_require_exact_request_and_commit_approval_before_io() -> Result<(), String> {
        let action = parse(&arguments("review-expiry-plan"))?;
        assert_eq!(
            action.operation.capabilities(),
            vec![super::super::CAP_DELETE_PREPARE]
        );
        assert!(
            matches!(action.operation, Operation::ReviewExpiryPlan(request)
            if request.sensor().as_str() == "sensor:front"
                && request.attested_now().earliest.0 == 100
                && request.attested_now().latest.0 == 120)
        );
        let mut commit = arguments("review-expiry-commit");
        assert!(parse(&commit).is_err());
        commit.extend([
            "--plan".into(),
            fss_core::ContentDigest::sha256(b"plan").to_text().into(),
        ]);
        assert!(parse(&commit).is_err());
        commit.extend([
            "--approve".into(),
            fss_core::ContentDigest::sha256(b"approval")
                .to_text()
                .into(),
        ]);
        assert!(matches!(
            parse(&commit)?.operation,
            Operation::ReviewExpiryCommit { .. }
        ));
        Ok(())
    }

    #[test]
    fn expiry_rejects_ambiguous_time_legacy_scopes_and_duplicate_options() {
        for value in [
            "120:100",
            "100:120:130",
            "100",
            "+100:120",
            "0100:120",
            "NaN:120",
        ] {
            let mut args = arguments("review-expiry-plan");
            args[8] = value.into();
            assert!(parse(&args).is_err(), "{value}");
        }
        for (key, value) in [
            ("--sensor-id", "sensor:other"),
            ("--import-id", "arbitrary"),
            ("--retain-for-ns", "10"),
            ("--policy", "arbitrary"),
            ("--approve", "arbitrary"),
        ] {
            let mut args = arguments("review-expiry-plan");
            args.extend([key.into(), value.into()]);
            assert!(parse(&args).is_err(), "{key}");
        }
        let mut missing = arguments("review-expiry-plan");
        missing.pop();
        assert!(parse(&missing).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn expiry_preserves_non_utf8_root_path() -> Result<(), String> {
        use std::os::unix::ffi::OsStringExt;
        let mut args = arguments("review-expiry-plan");
        args[2] = OsString::from_vec(b"root-\xff".to_vec());
        assert_eq!(parse(&args)?.root.as_os_str(), args[2]);
        Ok(())
    }
}
