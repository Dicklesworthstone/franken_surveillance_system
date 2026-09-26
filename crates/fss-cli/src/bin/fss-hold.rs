#![forbid(unsafe_code)]
//! Local evidence preservation: indefinite holds, minimum deadlines and approved release/expiry.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CaptureInterval, ContentDigest, DigestAlgorithm, OperationId, PrincipalId, TimestampNs};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldError, HoldOutcome, HoldRecord, HoldRequest,
    HoldState, RetentionReadiness, commit_hold, list_holds, preview_hold,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

const HELP: &str = "fss-hold <place|release|retain|expire|list|due> --root DIR --site SITE [--principal ID]\n\
  place/release: --hold-id ID --import-id sha256:HEX --reason TEXT [--approve sha256:HEX]\n\
  retain: --hold-id ID --import-id sha256:HEX --reason TEXT --until-ns NS [--approve DIGEST]\n\
  expire: same identity, --reason TEXT --until-ns NS --attested-now-ns EARLIEST:LATEST [--approve DIGEST]\n\
  due: --attested-now-ns EARLIEST:LATEST; read-only evaluation of every current hold.\n\
  Deadlines and time attestations are signed Unix nanoseconds. Earliest must reach the original\n\
  deadline before expiry can be approved; overlapping uncertainty refuses expiry. The supplied\n\
  bounds are an OWNER ASSERTION, not an authenticated clock. No media timestamp or system-clock\n\
  sample is silently substituted. Eligibility never releases a hold. Ordinary release cannot\n\
  bypass a deadline; expiry has a separate approval and never deletes bytes.\n\
  Without --approve: preview the exact record and approval digest; no retention change.\n\
  Rerun with that approval to commit. Any intervening authority change requires a new preview.\n\
  Exact retries of the current request are idempotent. A release needs its own fresh approval.\n\
  Holds preserve a retained import's current and future derivative closure, including shared\n\
  evidence reached by another import's deletion. Holds never expire automatically; terminal IDs\n\
  cannot be reused. Release and expiry never delete bytes. List includes terminal records.\n\
  Requires an existing owner-authorized local deployment. The local process supplies retention\n\
  capabilities; --principal is an audit identity, not remote authentication or privilege escalation.\n\
  No new mutation is permitted during an incomplete deletion. No backup, remote-replica,\n\
  filesystem-tamper protection, custody certification, or legal-compliance claim. Do not put\n\
  secrets or media content in --reason. JSON describes reference semantics, not qualification.\n";

type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    request: Option<HoldRequest>,
    approval: Option<ContentDigest>,
    attested_now: Option<CaptureInterval>,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values.get(key).ok_or_else(|| format!("required option {key}"))?
        .to_str().ok_or_else(|| format!("{key} requires UTF-8"))
}

fn digest(value: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(value).map_err(|_| "expected sha256:HEX".to_owned())?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err("only SHA-256 identities are supported".to_owned());
    }
    Ok(parsed)
}

fn timestamp(value: &str) -> Result<TimestampNs, String> {
    value.parse::<i128>().map(TimestampNs).map_err(|_| "expected signed integer Unix nanoseconds".to_owned())
}

fn time_bounds(value: &str) -> Result<CaptureInterval, String> {
    let (first, last) = value.split_once(':').ok_or("expected EARLIEST:LATEST time bounds")?;
    CaptureInterval::new(timestamp(first)?, timestamp(last)?)
        .map_err(|_| "time bounds require EARLIEST <= LATEST".to_owned())
}

fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 19 { return Err("too many arguments".to_owned()); }
    let action = args.first().and_then(|v| v.to_str()).ok_or("expected place, release, retain, expire, list or due")?;
    if !["place", "release", "retain", "expire", "list", "due"].contains(&action) {
        return Err("expected place, release, retain, expire, list or due".to_owned());
    }
    let mut values = BTreeMap::new();
    let mut i = 1;
    while i < args.len() {
        let key = args[i].to_str().ok_or("option names require UTF-8")?;
        let allowed = ["--root", "--site", "--principal"].contains(&key)
            || (!["list", "due"].contains(&action)
                && ["--hold-id", "--import-id", "--reason", "--approve"].contains(&key))
            || (["retain", "expire"].contains(&action) && key == "--until-ns")
            || (["expire", "due"].contains(&action) && key == "--attested-now-ns");
        if !allowed { return Err(format!("unknown or inapplicable option {key}")); }
        let value = args.get(i + 1).ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate option {key}"));
        }
        i += 2;
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage".to_owned())?;
    let principal = match values.get("--principal") {
        Some(_) => text(&values, "--principal")?,
        None => "principal:local-operator",
    }.to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal identity".to_owned())?;
    if site.len() > 256 || principal.len() > 256 {
        return Err("site and principal are limited to 256 bytes".to_owned());
    }
    let attested_now = if ["expire", "due"].contains(&action) {
        Some(time_bounds(text(&values, "--attested-now-ns")?)?)
    } else {
        None
    };
    let request = match action {
        "list" | "due" => None,
        _ => {
            let request = HoldRequest {
                hold_id: text(&values, "--hold-id")?.to_owned(),
                import_identity: digest(text(&values, "--import-id")?)?,
                state: match action {
                    "place" => HoldState::Held,
                    "release" => HoldState::Released,
                    "retain" => HoldState::Until { not_before: timestamp(text(&values, "--until-ns")?)? },
                    "expire" => HoldState::Expired {
                        not_before: timestamp(text(&values, "--until-ns")?)?,
                        attested_now: attested_now.ok_or("expiry requires an explicit time attestation")?,
                    },
                    _ => return Err("invalid hold operation".to_owned()),
                },
                reason: text(&values, "--reason")?.to_owned(),
            };
            request.validate().map_err(|e| e.to_string())?;
            Some(request)
        }
    };
    let approval = values.get("--approve").map(|_| text(&values, "--approve").and_then(digest)).transpose()?;
    Ok(Options { root, site, principal, request, approval, attested_now })
}

fn time_assertion(bounds: CaptureInterval) -> String {
    object(&[
        ("earliest_ns", string(&bounds.earliest.0.to_string())),
        ("latest_ns", string(&bounds.latest.0.to_string())),
        ("coordinate", string("unix_nanoseconds")),
        ("provenance", string("operator_assertion_not_authenticated_clock")),
    ])
}

fn deadline(state: HoldState) -> Option<String> {
    state.not_before().map(|not_before| object(&[
        ("not_before_ns", string(&not_before.0.to_string())),
        ("expiry_time_assertion", state.attested_now().map_or_else(|| "null".into(), time_assertion)),
        ("automatic_expiry", "false".into()),
    ]))
}

fn record(value: &HoldRecord) -> String {
    let state = value.request().state;
    let mut fields = vec![
        ("format", string(state.record_domain())),
        ("hold_id", string(&value.request().hold_id)),
        ("import_identity", string(&value.request().import_identity.to_text())),
        ("state", string(value.request().state.as_str())),
        ("reason", string(&value.request().reason)),
        ("principal", string(value.principal())),
        ("site", string(value.site())),
        ("basis", evidence_anchor(value.basis())),
        ("record_digest", string(&value.digest().to_text())),
        ("predecessor", value.predecessor().map_or_else(|| "null".into(), |d| string(&d.to_text()))),
        ("scope", string("retained_import_current_and_future_derivative_closure")),
        ("expiration", string(match state {
            HoldState::Held | HoldState::Released => "none_explicit_release_required",
            HoldState::Until { .. } => "deadline_requires_approved_expiry",
            HoldState::Expired { .. } => "expired_by_approved_time_assertion",
        })),
    ];
    if let Some(deadline) = deadline(state) {
        fields.push(("retention_deadline", deadline));
    }
    object(&fields)
}

/// Readiness is derived from explicit inputs at one authority head. No mutation or approval
/// digest is produced. Indefinite and terminal holds stay visible, not silently filtered out.
fn due_report(values: &[HoldRecord], attested_now: CaptureInterval) -> Result<String, HoldError> {
    let mut records = Vec::with_capacity(values.len());
    let mut eligible = 0_usize;
    for value in values {
        let state = value.request().state;
        let readiness = state.readiness(attested_now)?;
        if readiness == RetentionReadiness::EligibleForExpiry { eligible += 1; }
        records.push(object(&[
            ("record", record(value)),
            ("time_readiness", string(readiness.as_str())),
            ("deletion_blocking", state.is_active().to_string()),
        ]));
    }
    Ok(object(&[
        ("status", string("retention_evaluated")),
        ("authority_changed", "false".into()),
        ("time_assertion", time_assertion(attested_now)),
        ("active_holds", values.iter().filter(|r| r.request().state.is_active()).count().to_string()),
        ("eligible_for_expiry", eligible.to_string()),
        ("eligibility_is_not_approval", "true".into()),
        ("records", array(&records)),
    ]))
}

fn run(options: &Options) -> RunResult<String> {
    // The ReplayCx constructor may create its root. Refuse missing/foreign roots before it.
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?.file_type().is_file()
    {
        return Err(io::Error::other("an existing regular deployment root and LAYOUT are required").into());
    }
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned(), CAP_HOLD_PREPARE.to_owned()];
    if options.approval.is_some() { capabilities.push(CAP_HOLD_COMMIT.to_owned()); }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:hold-cli".into(),
        operation_id: OperationId::parse("operation:hold-cli")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(8 * 1024 * 1024).storage_operations(8192).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = run_with(options, &authority, &cx);
    cx.drain_and_finalize();
    result
}

fn run_with(options: &Options, authority: &ContextAuthority, cx: &ReplayCx) -> RunResult<String> {
    let mut deployment = ReferenceDeployment::open(&options.root, &options.site, cx)?;
    let detail = match &options.request {
        None => {
            let values = list_holds(&deployment, authority, cx)?;
            match options.attested_now {
                Some(now) => due_report(&values, now)?,
                None => {
                    let active = values.iter().filter(|r| r.request().state.is_active()).count();
                    let records: Vec<_> = values.iter().map(record).collect();
                    object(&[("status", string("listed")), ("active_holds", active.to_string()), ("records", array(&records))])
                }
            }
        }
        Some(request) => {
            let receipt = match options.approval {
                None => preview_hold(&deployment, request, authority, cx)?,
                Some(approval) => commit_hold(&mut deployment, request, approval, authority, cx)?,
            };
            object(&[
                ("status", string(receipt.outcome.as_str())),
                ("authority_changed", (receipt.outcome == HoldOutcome::Committed).to_string()),
                ("approval_digest", string(&receipt.record.approval().to_text())),
                ("record", record(&receipt.record)),
            ])
        }
    };
    Ok(object(&[
        ("format", string("fss.evidence_hold_cli.v1")),
        ("site", string(&options.site)),
        ("anchor", evidence_anchor(deployment.current_anchor())),
        ("result", detail),
        ("deletion_performed", "false".into()),
        ("hold_registry", string("enforced_import_closure_v1")),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        print!("{HELP}");
        return ExitCode::from(ExitIdentity::SUCCESS.code);
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-hold --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&options) {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let id = error.downcast_ref::<HoldError>().map_or(ERR_CLI_RUNTIME_FAILURE, HoldError::stable_id);
            eprintln!("{id}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(action: &str) -> Vec<OsString> {
        [action, "--root", "/existing", "--site", "site:hold", "--hold-id", "incident",
            "--import-id", &ContentDigest::sha256(b"import").to_text(), "--reason", "Preserve evidence"]
            .into_iter().map(OsString::from).collect()
    }

    #[test]
    fn changes_require_explicit_approval_and_release_is_distinct() -> Result<(), String> {
        let place = parse(&args("place"))?;
        assert!(place.approval.is_none());
        assert_eq!(place.request.ok_or("missing placement")?.state, HoldState::Held);
        assert_eq!(parse(&args("release"))?.request.ok_or("missing release")?.state, HoldState::Released);
        Ok(())
    }

    #[test]
    fn duplicate_unknown_and_list_mutations_are_refused() {
        for suffix in [vec!["--reason", "Other"], vec!["--force", "yes"], vec!["--approve"]] {
            let mut values = args("place");
            values.extend(suffix.into_iter().map(OsString::from));
            assert!(parse(&values).is_err());
        }
        let mut list = args("list");
        assert!(parse(&list).is_err());
        list.truncate(5);
        assert!(parse(&list).is_ok());
    }

    #[test]
    fn malformed_scope_and_approval_are_refused_before_open() {
        for (index, value) in [(6, "../id"), (8, "no-digest"), (10, "line\nbreak"), (4, "site with space")] {
            let mut values = args("place");
            values[index] = value.into();
            assert!(parse(&values).is_err());
        }
        let mut values = args("place");
        values.extend([OsString::from("--approve"), OsString::from("bad")]);
        assert!(parse(&values).is_err());
    }

    #[test]
    fn explicit_approval_is_preserved_exactly() -> Result<(), String> {
        let approval = ContentDigest::sha256(b"approved");
        let mut values = args("place");
        values.extend([OsString::from("--approve"), OsString::from(approval.to_text())]);
        assert_eq!(parse(&values)?.approval, Some(approval));
        Ok(())
    }

    fn deadline_args(action: &str, bounds: Option<&str>) -> Vec<OsString> {
        let mut values = args(action);
        values.extend(["--until-ns", "10"].into_iter().map(OsString::from));
        if let Some(bounds) = bounds {
            values.extend(["--attested-now-ns", bounds].into_iter().map(OsString::from));
        }
        values
    }

    #[test]
    fn retain_and_expire_preserve_explicit_deadlines_and_do_not_approve() -> Result<(), String> {
        let retained = parse(&deadline_args("retain", None))?;
        assert!(retained.approval.is_none());
        assert_eq!(retained.request.ok_or("missing retain")?.state, HoldState::Until { not_before: TimestampNs(10) });
        let expired = parse(&deadline_args("expire", Some("10:12")))?;
        assert!(expired.approval.is_none());
        assert_eq!(expired.request.ok_or("missing expiry")?.state, HoldState::Expired {
            not_before: TimestampNs(10), attested_now: time_bounds("10:12")?,
        });
        assert!(parse(&args("retain")).is_err());
        assert!(parse(&deadline_args("expire", None)).is_err());
        Ok(())
    }

    #[test]
    fn premature_uncertain_and_inverted_expiry_is_refused_before_open() {
        for bounds in ["8:9", "9:10", "9:12", "12:10", "", "10", "10:", ":12", "10:12:13", "1e2:200"] {
            assert!(parse(&deadline_args("expire", Some(bounds))).is_err(), "{bounds}");
        }
    }

    #[test]
    fn due_requires_time_but_never_accepts_mutation_arguments() -> Result<(), String> {
        let mut values: Vec<_> = ["due", "--root", "/existing", "--site", "site:hold"]
            .into_iter().map(OsString::from).collect();
        assert!(parse(&values).is_err());
        values.extend(["--attested-now-ns", "9:11"].into_iter().map(OsString::from));
        let due = parse(&values)?;
        assert!(due.request.is_none());
        assert!(due.approval.is_none());
        assert_eq!(due.attested_now, Some(time_bounds("9:11")?));
        for suffix in [["--until-ns", "10"], ["--approve", "bad"], ["--hold-id", "some-id"]] {
            let mut changed = values.clone();
            changed.extend(suffix.into_iter().map(OsString::from));
            assert!(parse(&changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn deadline_options_cannot_leak_into_legacy_actions_or_repeat() {
        for action in ["place", "release", "list"] {
            assert!(parse(&deadline_args(action, None)).is_err());
            let mut values = args(action);
            values.extend(["--attested-now-ns", "10:12"].into_iter().map(OsString::from));
            assert!(parse(&values).is_err());
        }
        for suffix in [["--until-ns", "11"], ["--attested-now-ns", "11:12"]] {
            let mut values = deadline_args("expire", Some("10:12"));
            values.extend(suffix.into_iter().map(OsString::from));
            assert!(parse(&values).is_err());
        }
    }

    #[test]
    fn signed_128_bit_times_are_parsed_and_rendered_without_json_precision_loss() -> Result<(), String> {
        let low = i128::MIN.to_string();
        let high = i128::MAX.to_string();
        let bounds = time_bounds(&format!("{low}:{high}"))?;
        let json = time_assertion(bounds);
        assert!(json.contains(&format!("\"earliest_ns\":\"{low}\"")));
        assert!(json.contains(&format!("\"latest_ns\":\"{high}\"")));
        assert!(json.contains("operator_assertion_not_authenticated_clock"));
        assert!(timestamp(&format!("{high}0")).is_err());
        assert!(timestamp("1.5").is_err());
        assert!(deadline(HoldState::Held).is_none());
        let json = deadline(HoldState::Until { not_before: TimestampNs(i128::MAX) }).ok_or("missing deadline")?;
        assert!(json.contains(&format!("\"not_before_ns\":\"{high}\"")));
        assert!(json.contains("\"automatic_expiry\":false"));
        Ok(())
    }

    #[test]
    fn fully_specified_expiry_keeps_principal_approval_and_clock_assertion() -> Result<(), String> {
        let approval = ContentDigest::sha256(b"expiry approval");
        let mut values = deadline_args("expire", Some("10:12"));
        values.extend([OsString::from("--principal"), OsString::from("principal:owner"),
            OsString::from("--approve"), OsString::from(approval.to_text())]);
        assert_eq!(values.len(), 19);
        let parsed = parse(&values)?;
        assert_eq!(parsed.principal, "principal:owner");
        assert_eq!(parsed.approval, Some(approval));
        assert_eq!(parsed.attested_now, Some(time_bounds("10:12")?));
        Ok(())
    }

}
