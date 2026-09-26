#![forbid(unsafe_code)]
//! Local operator event review; exact core transitions, no alert or retention effects.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::event::MAX_EVENT_ID_LEN;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, EventId, OperationId, PrincipalId};
use fss_reference::event_review::{
    CAP_REVIEW_COMMIT, CAP_REVIEW_PREPARE, ReviewDisposition, ReviewError, ReviewPreview,
    ReviewRecord, ReviewRequest, commit_review, preview_review, read_current_review,
    read_review_event,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

const HELP: &str = "fss-review <show|investigate|resolve|reject> --root DIR --site SITE --event-id ID\n\
  [--principal ID]\n\
  investigate/resolve/reject additionally require:\n\
    --expected-revision sha256:HEX --reason TEXT [--approve sha256:HEX]\n\
  show reads the current event and, when present, its verified operator review.\n\
  Without --approve, a change is only previewed; review the successor and approval digest.\n\
  Repeat that exact command with --approve to publish; exact committed retries write nothing.\n\
  Core transitions are enforced: resolve is not a direct transition from corroborated.\n\
  Source evidence, classification, probability and uncertainty are never rewritten.\n\
  Operator feedback is an assertion, not verified ground truth or new sensor support.\n\
  New reviews are blocked by any outstanding deployment effect; review never reconciles it.\n\
  No alert dispatch, deletion, retention change, model execution or implicit intermediate state.\n\
  Existing owner-authorized local deployment only; principal is an audit label, not login.\n\
  Do not include secrets or unnecessary personal data in the retained reason.\n";

type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    event: EventId,
    request: Option<ReviewRequest>,
    approval: Option<ContentDigest>,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}
fn digest(text: &str) -> Result<ContentDigest, String> {
    let value = ContentDigest::parse(text).map_err(|_| "expected sha256:HEX".to_owned())?;
    if value.algorithm() != DigestAlgorithm::Sha256 {
        return Err("only SHA-256 is supported".into());
    }
    Ok(value)
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 15 {
        return Err("too many arguments".into());
    }
    let action = args
        .first()
        .and_then(|s| s.to_str())
        .ok_or("expected show, investigate, resolve or reject")?;
    let disposition = if action == "show" {
        None
    } else {
        Some(ReviewDisposition::parse(action).map_err(|e| e.to_string())?)
    };
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let allowed = ["--root", "--site", "--principal", "--event-id"].contains(&key)
            || (disposition.is_some()
                && ["--expected-revision", "--reason", "--approve"].contains(&key));
        if !allowed {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
        index += 2;
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site")?;
    let principal = if values.contains_key("--principal") {
        text(&values, "--principal")?
    } else {
        "principal:local-operator"
    }
    .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    if site.len() > 256 || principal.len() > 256 {
        return Err("site or principal exceeds 256 bytes".into());
    }
    let event =
        EventId::parse(text(&values, "--event-id")?).map_err(|_| "invalid event identity")?;
    if event.as_str().len() > MAX_EVENT_ID_LEN {
        return Err("event identity exceeds bound".into());
    }
    let request = disposition
        .map(|disposition| -> Result<ReviewRequest, String> {
            let request = ReviewRequest {
                event_id: event.clone(),
                expected_revision: digest(text(&values, "--expected-revision")?)?,
                disposition,
                reason: text(&values, "--reason")?.to_owned(),
            };
            request.validate().map_err(|e| e.to_string())?;
            Ok(request)
        })
        .transpose()?;
    let approval = values
        .get("--approve")
        .map(|_| text(&values, "--approve").and_then(digest))
        .transpose()?;
    Ok(Options {
        root,
        site,
        principal,
        event,
        request,
        approval,
    })
}

fn record_json(record: &ReviewRecord) -> String {
    object(&[
        ("format", string("fss.operator_event_review.v1")),
        ("record_digest", string(&record.digest().to_text())),
        ("event_id", string(record.request().event_id.as_str())),
        (
            "expected_revision",
            string(&record.request().expected_revision.to_text()),
        ),
        ("disposition", string(record.request().disposition.as_str())),
        ("reason", string(&record.request().reason)),
        ("principal", string(record.principal())),
        ("site", string(record.site())),
        (
            "predecessor_event_root",
            string(&record.previous_event_root().to_text()),
        ),
        (
            "predecessor_anchor",
            evidence_anchor(record.previous_anchor()),
        ),
        ("evidence_class", string("assertion")),
        ("verified_ground_truth", "false".into()),
        ("sensor_support_added", "false".into()),
    ])
}
fn review_json(review: &ReviewPreview, status: &str, published: bool) -> String {
    object(&[
        ("status", string(status)),
        ("published", published.to_string()),
        ("approval_digest", string(&review.approval().to_text())),
        (
            "revision_digest",
            string(&review.event().revision_digest().to_text()),
        ),
        (
            "provenance_root",
            string(&review.provenance_root().to_text()),
        ),
        ("record", record_json(review.record())),
        ("event", review.event().to_canonical_json()),
    ])
}

fn run(options: &Options) -> RunResult<String> {
    // ReplayCx may create its root: reject absent/symlink/foreign layouts first.
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing regular deployment and LAYOUT required").into());
    }
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned(), CAP_REVIEW_PREPARE.to_owned()];
    if options.approval.is_some() {
        capabilities.push(CAP_REVIEW_COMMIT.to_owned());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-cli".into(),
        operation_id: OperationId::parse("operation:review-cli")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = run_with(options, &authority, &cx);
    cx.drain_and_finalize();
    result
}
fn run_with(options: &Options, authority: &ContextAuthority, cx: &ReplayCx) -> RunResult<String> {
    let mut deployment = ReferenceDeployment::open(&options.root, &options.site, cx)?;
    let result = match &options.request {
        None => {
            let (event, receipt) = read_review_event(&deployment, &options.event, authority, cx)?;
            let review = read_current_review(&deployment, &options.event, authority, cx)?;
            let allowed: Vec<_> = [
                ReviewDisposition::Investigate,
                ReviewDisposition::Resolve,
                ReviewDisposition::Reject,
            ]
            .into_iter()
            .filter(|d| d.allowed_from(event.state))
            .map(|d| string(d.as_str()))
            .collect();
            object(&[
                ("status", string("read_verified")),
                ("event", event.to_canonical_json()),
                (
                    "revision_digest",
                    string(&event.revision_digest().to_text()),
                ),
                ("event_root", string(&receipt.event_root.to_text())),
                ("event_anchor", evidence_anchor(&receipt.authority_anchor)),
                ("core_permitted_dispositions", array(&allowed)),
                ("dispositions_are_authorized", "false".into()),
                ("outstanding_effects_rechecked_on_preview", "true".into()),
                (
                    "review",
                    review
                        .as_ref()
                        .map_or_else(|| "null".into(), |r| record_json(r.record())),
                ),
                (
                    "review_status",
                    string(if review.is_some() {
                        "verified_current_review"
                    } else {
                        "not_an_operator_review"
                    }),
                ),
                (
                    "open_sensor_tamper",
                    receipt.lineage_tamper_status.has_open_tamper().to_string(),
                ),
            ])
        }
        Some(request) => match options.approval {
            None => {
                let review = preview_review(&deployment, request, authority, cx)?;
                review_json(
                    &review,
                    if review.already_published() {
                        "already_published"
                    } else {
                        "proposed"
                    },
                    false,
                )
            }
            Some(approval) => {
                let receipt = commit_review(&mut deployment, request, approval, authority, cx)?;
                review_json(
                    &receipt.review,
                    if receipt.published {
                        "published"
                    } else {
                        "already_published"
                    },
                    receipt.published,
                )
            }
        },
    };
    Ok(object(&[
        ("format", string("fss.operator_event_review_cli.v1")),
        ("site", string(&options.site)),
        ("anchor", evidence_anchor(deployment.current_anchor())),
        ("result", result),
        ("effects_performed", "false".into()),
        ("source_evidence_rewritten", "false".into()),
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
        Ok(value) => value,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-review --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&options) {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let id = error
                .downcast_ref::<ReviewError>()
                .map_or(ERR_CLI_RUNTIME_FAILURE, ReviewError::stable_id);
            eprintln!("{id}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments(action: &str) -> Vec<OsString> {
        [
            action,
            "--root",
            "/existing",
            "--site",
            "site:review",
            "--event-id",
            "event:test",
            "--expected-revision",
            &ContentDigest::sha256(b"revision").to_text(),
            "--reason",
            "Reviewed the evidence",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn explicit_revision_and_separate_approval_are_required() -> Result<(), String> {
        for action in ["reject", "resolve", "investigate"] {
            let options = parse(&arguments(action))?;
            assert!(options.approval.is_none());
            assert!(options.request.is_some());
        }
        let mut args = arguments("reject");
        args.drain(7..9);
        assert!(parse(&args).is_err());
        Ok(())
    }
    #[test]
    fn show_rejects_mutations_and_duplicate_or_unknown_options_fail() {
        assert!(parse(&arguments("show")).is_err());
        assert!(parse(&arguments("show")[..7]).is_ok());
        for suffix in [
            vec!["--force", "yes"],
            vec!["--reason", "Other"],
            vec!["--approve"],
        ] {
            let mut args = arguments("reject");
            args.extend(suffix.into_iter().map(OsString::from));
            assert!(parse(&args).is_err());
        }
    }
    #[test]
    fn altered_scope_or_unbounded_reason_is_rejected() {
        for (index, value) in [(4, "bad site"), (6, ""), (8, "bad"), (10, "line\nbreak")] {
            let mut args = arguments("reject");
            args[index] = value.into();
            assert!(parse(&args).is_err());
        }
        let mut args = arguments("reject");
        args[10] = "x".repeat(513).into();
        assert!(parse(&args).is_err());
        assert!(parse(&arguments("corroborate")).is_err());
    }
    #[test]
    fn approval_and_principal_survive_parsing_exactly() -> Result<(), String> {
        let expected = ContentDigest::sha256(b"approval");
        let mut args = arguments("resolve");
        args.extend(
            [
                "--principal",
                "principal:owner",
                "--approve",
                &expected.to_text(),
            ]
            .into_iter()
            .map(OsString::from),
        );
        let options = parse(&args)?;
        assert_eq!(options.approval, Some(expected));
        assert_eq!(options.principal, "principal:owner");
        Ok(())
    }
}
