#![forbid(unsafe_code)]
//! Local operator evidence preservation: preview, exact commit, explicit release, and listing.

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
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldError, HoldOutcome, HoldRecord, HoldRequest,
    HoldState, commit_hold, list_holds, preview_hold,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

const HELP: &str = "fss-hold <place|release|list> --root DIR --site SITE [--principal ID]\n\
  place/release: --hold-id ID --import-id sha256:HEX --reason TEXT [--approve sha256:HEX]\n\
  Without --approve: preview the exact record and approval digest; no retention change.\n\
  Rerun with that approval to commit. Any intervening authority change requires a new preview.\n\
  Exact retries of the current request are idempotent. A release needs its own fresh approval.\n\
  Holds preserve a retained import's current and future derivative closure, including shared\n\
  evidence reached by another import's deletion. Holds never expire automatically; released IDs\n\
  cannot be reused. Release never deletes bytes. List includes held and released IDs.\n\
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

fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 15 { return Err("too many arguments".to_owned()); }
    let action = args.first().and_then(|v| v.to_str()).ok_or("expected place, release or list")?;
    if !["place", "release", "list"].contains(&action) {
        return Err("expected place, release or list".to_owned());
    }
    let mut values = BTreeMap::new();
    let mut i = 1;
    while i < args.len() {
        let key = args[i].to_str().ok_or("option names require UTF-8")?;
        let allowed = ["--root", "--site", "--principal"].contains(&key)
            || (action != "list" && ["--hold-id", "--import-id", "--reason", "--approve"].contains(&key));
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
    let request = match action {
        "list" => None,
        _ => {
            let request = HoldRequest {
                hold_id: text(&values, "--hold-id")?.to_owned(),
                import_identity: digest(text(&values, "--import-id")?)?,
                state: if action == "place" { HoldState::Held } else { HoldState::Released },
                reason: text(&values, "--reason")?.to_owned(),
            };
            request.validate().map_err(|e| e.to_string())?;
            Some(request)
        }
    };
    let approval = values.get("--approve").map(|_| text(&values, "--approve").and_then(digest)).transpose()?;
    Ok(Options { root, site, principal, request, approval })
}

fn record(value: &HoldRecord) -> String {
    object(&[
        ("format", string("fss.evidence_hold.v1")),
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
        ("expiration", string("none_explicit_release_required")),
    ])
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
            let active = values.iter().filter(|r| r.request().state == HoldState::Held).count();
            let records: Vec<_> = values.iter().map(record).collect();
            object(&[("status", string("listed")), ("active_holds", active.to_string()), ("records", array(&records))])
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
}
