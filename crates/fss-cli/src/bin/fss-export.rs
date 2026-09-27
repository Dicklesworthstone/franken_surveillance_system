#![forbid(unsafe_code)]
//! Local operator adapter for approval-gated redacted P5 event exports.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, EventId, OperationId, PrincipalId, TimestampNs,
};
use fss_reference::evidence_export::{
    CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EventExportRequest, ExportError, commit_export,
    preview_export, read_export,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

const HELP: &str = "fss-export event --root DIR --site SITE --event-id ID \
  --expected-revision sha256:HEX --recipient ID --purpose TEXT --expires-at-ns I128 \
  [--principal ID] [--approve sha256:HEX]\n\
Without --approve this is a read-only preview. Review approval_digest, export_root and package.\n\
Repeat the exact request with --approve to publish the redacted export root and authority record.\n\
The fixed profile exports event state/class/time, evidence/model digests and decision fingerprints.\n\
It never exports raw media, source/device identities, zone/track IDs, failure-domain plaintext,\n\
model tensors, or the live archive namespace. There is no override or include-all option.\n\
expires-at-ns is retained policy metadata; this reference has no trusted wall clock or auto-delete.\n\
Publication is local only. No email/upload/provider dispatch occurs.\n\
fss-export show --root DIR --site SITE --export-root sha256:HEX [--principal ID]\n\
show verifies the committed reserved authority delta, root manifest and redacted record after restart.\n";

type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    request: EventExportRequest,
    approval: Option<ContentDigest>,
}

#[derive(Debug)]
struct ShowOptions {
    root: PathBuf,
    site: String,
    principal: String,
    export_root: ContentDigest,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values.get(key).ok_or_else(|| format!("required option {key}"))?
        .to_str().ok_or_else(|| format!("{key} requires UTF-8"))
}
fn digest(value: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| "expected sha256:HEX".to_owned())?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required".into());
    }
    Ok(digest)
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 19 || args.first().and_then(|v| v.to_str()) != Some("event") {
        return Err("expected bounded 'event' export command".into());
    }
    let allowed = [
        "--root", "--site", "--principal", "--event-id", "--expected-revision",
        "--recipient", "--purpose", "--expires-at-ns", "--approve",
    ];
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) { return Err(format!("unknown option {key}")); }
        let value = args.get(index + 1).ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
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
        .map_err(|_| "invalid site lineage")?;
    let principal = values.get("--principal")
        .map(|_| text(&values, "--principal"))
        .transpose()?
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let event_id = EventId::parse(text(&values, "--event-id")?)
        .map_err(|_| "invalid event identity")?;
    let expected_revision = digest(text(&values, "--expected-revision")?)?;
    let expires_at = text(&values, "--expires-at-ns")?.parse::<i128>()
        .map_err(|_| "--expires-at-ns requires signed decimal i128")?;
    let request = EventExportRequest {
        event_id,
        expected_revision,
        recipient: text(&values, "--recipient")?.to_owned(),
        purpose: text(&values, "--purpose")?.to_owned(),
        expires_at: TimestampNs(expires_at),
    };
    request.validate().map_err(|e| e.to_string())?;
    let approval = values.get("--approve")
        .map(|_| text(&values, "--approve").and_then(digest))
        .transpose()?;
    Ok(Options { root, site, principal, request, approval })
}

fn parse_show(args: &[OsString]) -> Result<ShowOptions, String> {
    if args.len() > 9 || args.first().and_then(|v| v.to_str()) != Some("show") {
        return Err("expected bounded 'show' export command".into());
    }
    let allowed = ["--root", "--site", "--principal", "--export-root"];
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) { return Err(format!("unknown option {key}")); }
        let value = args.get(index + 1).ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
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
        .map_err(|_| "invalid site lineage")?;
    let principal = values.get("--principal")
        .map(|_| text(&values, "--principal"))
        .transpose()?
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    Ok(ShowOptions {
        root,
        site,
        principal,
        export_root: digest(text(&values, "--export-root")?)?,
    })
}

fn run_show(options: &ShowOptions) -> RunResult<String> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?.file_type().is_file()
    {
        return Err(io::Error::other("existing regular deployment and LAYOUT required").into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:export-show-cli".into(),
        operation_id: OperationId::parse("operation:export-show-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".to_owned(), CAP_EXPORT_PREPARE.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:redacted-event-export-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = (|| -> RunResult<String> {
        let deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let (record, anchor) = read_export(&deployment, options.export_root, &authority, &cx)?;
        Ok(object(&[
            ("format", string("fss.evidence_export_cli.v1")),
            ("site", string(&options.site)),
            ("status", string("verified_committed_export")),
            ("export_root", string(&options.export_root.to_text())),
            ("record_digest", string(&record.digest().to_text())),
            ("authority_anchor", evidence_anchor(&anchor)),
            ("package", record.to_redacted_json()),
            ("external_transport_performed", "false".into()),
            ("raw_media_read", "false".into()),
            ("qualification", string("implemented_not_qualified")),
        ]))
    })();
    cx.drain_and_finalize();
    result
}

fn run(options: &Options) -> RunResult<String> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?.file_type().is_file()
    {
        return Err(io::Error::other("existing regular deployment and LAYOUT required").into());
    }
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned(), CAP_EXPORT_PREPARE.to_owned()];
    if options.approval.is_some() { capabilities.push(CAP_EXPORT_COMMIT.to_owned()); }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:export-cli".into(),
        operation_id: OperationId::parse("operation:export-cli")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:redacted-event-export-v1".into(),
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
    let (status, published, approval, root, record_digest, package, commit_anchor) =
        match options.approval {
            None => {
                let preview = preview_export(&deployment, &options.request, authority, cx)?;
                (
                    if preview.already_committed() { "already_committed" } else { "proposed" },
                    false,
                    preview.approval(),
                    preview.root(),
                    preview.record().digest(),
                    preview.record().to_redacted_json(),
                    deployment.current_anchor().clone(),
                )
            }
            Some(approval) => {
                let receipt = commit_export(&mut deployment, &options.request, approval, authority, cx)?;
                (
                    if receipt.published { "published" } else { "already_committed" },
                    receipt.published,
                    receipt.preview.approval(),
                    receipt.preview.root(),
                    receipt.preview.record().digest(),
                    receipt.preview.record().to_redacted_json(),
                    receipt.anchor,
                )
            }
        };
    Ok(object(&[
        ("format", string("fss.evidence_export_cli.v1")),
        ("site", string(&options.site)),
        ("status", string(status)),
        ("published", published.to_string()),
        ("approval_digest", string(&approval.to_text())),
        ("export_root", string(&root.to_text())),
        ("record_digest", string(&record_digest.to_text())),
        ("authority_anchor", evidence_anchor(&commit_anchor)),
        ("package", package),
        ("external_transport_performed", "false".into()),
        ("raw_media_read", "false".into()),
        ("expiry_enforcement", string("metadata_only_no_trusted_clock")),
        ("qualification", string("implemented_not_qualified")),
    ]))
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        print!("{HELP}");
        return ExitCode::from(ExitIdentity::SUCCESS.code);
    }
    if args.first().and_then(|v| v.to_str()) == Some("show") {
        let options = match parse_show(&args) {
            Ok(v) => v,
            Err(reason) => {
                eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-export --help");
                return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
            }
        };
        return match run_show(&options) {
            Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
            },
            Err(error) => {
                let id = error.downcast_ref::<ExportError>()
                    .map_or(ERR_CLI_RUNTIME_FAILURE, ExportError::stable_id);
                eprintln!("{id}: {error}");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        };
    }
    let options = match parse(&args) {
        Ok(v) => v,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-export --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&options) {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let id = error.downcast_ref::<ExportError>()
                .map_or(ERR_CLI_RUNTIME_FAILURE, ExportError::stable_id);
            eprintln!("{id}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<OsString> {
        [
            "event", "--root", "/existing", "--site", "site:export", "--event-id", "event:test",
            "--expected-revision", &ContentDigest::sha256(b"revision").to_text(),
            "--recipient", "recipient:insurer-case-7", "--purpose", "Owner incident review",
            "--expires-at-ns", "1000",
        ].into_iter().map(OsString::from).collect()
    }
    #[test]
    fn exact_revision_recipient_purpose_and_expiry_are_required() -> Result<(), String> {
        let options = parse(&arguments())?;
        assert!(options.approval.is_none());
        assert_eq!(options.request.recipient, "recipient:insurer-case-7");
        for key in ["--expected-revision", "--recipient", "--purpose", "--expires-at-ns"] {
            let mut args = arguments();
            let at = args.iter().position(|v| v == key).expect("key");
            args.drain(at..=at + 1);
            assert!(parse(&args).is_err(), "accepted missing {key}");
        }
        Ok(())
    }
    #[test]
    fn approval_is_separate_and_unknown_or_duplicate_options_fail() -> Result<(), String> {
        let approval = ContentDigest::sha256(b"approval");
        let mut args = arguments();
        args.extend(["--approve".into(), approval.to_text().into()]);
        assert_eq!(parse(&args)?.approval, Some(approval));
        let mut duplicate = arguments();
        duplicate.extend(["--purpose".into(), "other".into()]);
        assert!(parse(&duplicate).is_err());
        let mut unknown = arguments();
        unknown.extend(["--include-raw".into(), "yes".into()]);
        assert!(parse(&unknown).is_err());
        Ok(())
    }
    #[test]
    fn include_all_or_raw_media_escape_hatches_do_not_exist() {
        for key in ["--raw", "--include-all", "--include-media", "--include-identities", "--force"] {
            let mut args = arguments();
            args.extend([key.into(), "yes".into()]);
            assert!(parse(&args).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn show_requires_only_exact_export_root_and_read_scope() -> Result<(), String> {
        let root = ContentDigest::sha256(b"export");
        let args = [
            "show", "--root", "/existing", "--site", "site:export",
            "--export-root", &root.to_text(),
        ].into_iter().map(OsString::from).collect::<Vec<_>>();
        let options = parse_show(&args)?;
        assert_eq!(options.export_root, root);
        let mut bad = args.clone();
        bad.extend(["--approve".into(), root.to_text().into()]);
        assert!(parse_show(&bad).is_err());
        Ok(())
    }
}
