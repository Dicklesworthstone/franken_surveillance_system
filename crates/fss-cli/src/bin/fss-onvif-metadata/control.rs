#![forbid(unsafe_code)]
//! Cold control discovery and independently approved cleanup of a retained subscription.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
};
use fss_reference::onvif::control::{
    ControlKind, MAX_CATALOG_RECORDS, RetainedCreateIntent, RetainedRenewIntent, RetainedRenewal,
    RetainedSubscription, RetainedUnsubscribe, list_control,
};
use fss_reference::onvif::pullpoint::{self, CaptureReport, SubscriptionState};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES};
use super::capture::{self, ControlReceipts, Owner, plan::Plan};
use super::{
    ARGUMENT_ERROR, INPUT_ERROR, LIMIT_ERROR, REPORT_LIMIT, admission, clean_absolute, digest,
    optional_digest, runtime, text,
};

const HELP: &str = "fss-onvif-metadata control <list|inspect|unsubscribe> [options]
  list: --root ABSOLUTE_DIR --site SITE [--principal ID] [--max-records 64]
  inspect: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --kind intent|created|unsubscribed|renew-intent|renewed --control-id sha256:HEX
           [--expected-root sha256:HEX]
  unsubscribe: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --subscription-id sha256:HEX --expected-root sha256:HEX
           --sensor SENSOR --device-generation sha256:HEX
           --profile-generation sha256:HEX --profile TOKEN
           --peer IP:PORT --authority HOST[:PORT] --events-path /onvif/events
           --service-root /onvif --generation N --receive-origin-ns N
           --owner-authorized yes --plaintext yes --unsubscribe yes
           [--timeout-ms 30000] [--max-steps 100000]
           [--credential-file /PRIVATE_FILE --auth-realm EXACT_REALM]
           [--legacy-md5 yes] [--legacy-no-qop yes]

list and inspect cold-verify exact local custody and disclose hashes only.
list either returns every admitted record or refuses; its ceiling is 1024 records.
Verified native deletions are omitted. Empty output proves no remote absence.
An intent alone leaves dispatch and result unknown; it never authorizes Create retry.
A renewal intent alone also leaves its remote result unknown; it never authorizes retry.
Retained responses are historical observations, not current remote state.
unsubscribe requires a fresh, explicit owner request with the original independent pins.
It performs only Unsubscribe against the retained scoped endpoint; it never creates or polls.
The expected root is mandatory for cleanup. The current receive origin must follow the
retained Create interval. Fresh cleanup authority is distinct from the retained approval.
Known terminal receipts survive late refusal and output failure; incomplete cleanup exits 1.
";

enum ColdAction {
    List {
        max_records: usize,
    },
    Inspect {
        kind: ControlKind,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
    },
}

struct ColdOptions {
    root: PathBuf,
    site: String,
    principal: String,
    approval: ContentDigest,
    action: ColdAction,
}

fn parse_cold(args: &[OsString]) -> Result<ColdOptions, &'static str> {
    if args.is_empty()
        || args.len() > 19
        || args.len() % 2 != 1
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let listing = match args[0].to_str() {
        Some("list") => true,
        Some("inspect") => false,
        _ => return Err(ARGUMENT_ERROR),
    };
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        let common = matches!(key, "--root" | "--site" | "--principal");
        let specific = if listing {
            key == "--max-records"
        } else {
            matches!(key, "--kind" | "--control-id" | "--expected-root")
        };
        if (!common && !specific) || values.insert(key.to_owned(), pair[1].clone()).is_some() {
            return Err(ARGUMENT_ERROR);
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or(ARGUMENT_ERROR)?);
    if !clean_absolute(&root) {
        return Err(ARGUMENT_ERROR);
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| ARGUMENT_ERROR)?;
    if site.len() > 256 {
        return Err(ARGUMENT_ERROR);
    }
    let principal = values
        .get("--principal")
        .map_or(Ok("operator:local-onvif-metadata"), |v| {
            v.to_str().ok_or(ARGUMENT_ERROR)
        })?
        .to_owned();
    if principal.is_empty() || principal.len() > 256 || principal.chars().any(char::is_control) {
        return Err(ARGUMENT_ERROR);
    }
    let action = if listing {
        let max_records = values.get("--max-records").map_or(Ok(64), |v| {
            v.to_str()
                .ok_or(ARGUMENT_ERROR)?
                .parse::<usize>()
                .map_err(|_| ARGUMENT_ERROR)
        })?;
        if !(1..=MAX_CATALOG_RECORDS).contains(&max_records) {
            return Err(ARGUMENT_ERROR);
        }
        ColdAction::List { max_records }
    } else {
        let kind = match text(&values, "--kind")? {
            "intent" => ControlKind::CreateIntent,
            "created" => ControlKind::Created,
            "unsubscribed" => ControlKind::Unsubscribed,
            "renew-intent" => ControlKind::RenewIntent,
            "renewed" => ControlKind::Renewed,
            _ => return Err(ARGUMENT_ERROR),
        };
        ColdAction::Inspect {
            kind,
            identity: digest(text(&values, "--control-id")?)?,
            expected_root: optional_digest(&values, "--expected-root")?,
        }
    };
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.onvif_control_cold_request.v1");
    for arg in args {
        encoder.bytes(arg.as_encoded_bytes());
    }
    encoder.text(&principal);
    let approval = ContentDigest::sha256(&encoder.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
    Ok(ColdOptions {
        root,
        site,
        principal,
        approval,
        action,
    })
}

fn existing(root: &Path, scope: &runtime::Scope<'_, '_>) -> Result<(), &'static str> {
    for (path, directory) in [(root.to_path_buf(), true), (root.join("LAYOUT"), false)] {
        scope.input()?;
        let metadata = fs::symlink_metadata(path).map_err(|_| INPUT_ERROR)?;
        if (directory && !metadata.file_type().is_dir())
            || (!directory && !metadata.file_type().is_file())
        {
            return Err(INPUT_ERROR);
        }
    }
    Ok(())
}

fn cold(options: ColdOptions) -> Result<String, &'static str> {
    let records = match options.action {
        ColdAction::List { max_records } => max_records as u64,
        ColdAction::Inspect { .. } => 1,
    };
    let bytes = (records + 1) * 4 * 1024 * 1024;
    let operations = capture::storage_allowance(2 * records + 2);
    let request = runtime::Request {
        approval: options.approval,
        principal: options.principal.clone(),
        timeout_ns: 60_000_000_000,
        bytes,
        network_bytes: 0,
        storage_operations: operations,
        network: false,
        // The existing deployment owner may finish its own local recovery while opening.
        write: true,
        secrets: false,
    };
    runtime::run(request, |scope| {
        existing(&options.root, scope)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-control-cold".into(),
            operation_id: OperationId::parse("operation:onvif-control-cold")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: options.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(bytes)
                .storage_operations(operations)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:explicit-control-inspection".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ARGUMENT_ERROR)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = (|| {
            let deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?;
            let mut out = String::new();
            macro_rules! line {
                ($($arg:tt)*) => { writeln!(&mut out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
            }
            line!("values_disclosed=false");
            line!("current_remote_state=unknown");
            line!("automatic_create_retry_safe=false");
            match &options.action {
                ColdAction::List { max_records } => {
                    let records =
                        list_control(&deployment, *max_records, &cx).map_err(|e| e.code())?;
                    line!("operation=control_list");
                    line!("catalog_complete=true");
                    line!("records={}", records.len());
                    for (index, record) in records.iter().enumerate() {
                        line!("record.{index}.kind={}", kind_name(record.kind));
                        line!("record.{index}.identity={}", record.identity);
                        line!("record.{index}.publication_root={}", record.root);
                        line!("record.{index}.intent_identity={}", record.intent_identity);
                        line!(
                            "record.{index}.authority_sequence={}",
                            record.authority_sequence
                        );
                        if let Some(identity) = record.subscription_identity {
                            line!("record.{index}.subscription_identity={identity}");
                        }
                        if let Some(identity) = record.renewal_intent_identity {
                            line!("record.{index}.renewal_intent_identity={identity}");
                        }
                    }
                }
                ColdAction::Inspect {
                    kind,
                    identity,
                    expected_root,
                } => {
                    line!("operation=control_inspect");
                    line!("kind={}", kind_name(*kind));
                    line!("identity={identity}");
                    match kind {
                        ControlKind::CreateIntent => {
                            let value = RetainedCreateIntent::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=create_intent_prepared");
                            line!("remote_dispatch=unknown");
                        }
                        ControlKind::Created => {
                            let value = RetainedSubscription::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("intent_identity={}", value.intent_identity());
                            line!("source_sha256={}", value.source_digest());
                            line!("source_bytes={}", value.source_bytes());
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=create_response_retained");
                            line!("safe_next=explicit_unsubscribe_with_fresh_owner_pins");
                        }
                        ControlKind::Unsubscribed => {
                            let value = RetainedUnsubscribe::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("subscription_identity={}", value.subscription_identity());
                            line!("source_sha256={}", value.source_digest());
                            line!("source_bytes={}", value.source_bytes());
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=unsubscribe_success_retained");
                        }
                        ControlKind::RenewIntent => {
                            let value = RetainedRenewIntent::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("renewal_index={}", value.binding().renewal_index);
                            line!("subscription_identity={}", value.subscription().identity());
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=renew_intent_prepared");
                            line!("remote_dispatch=unknown");
                            line!("automatic_renew_retry_safe=false");
                        }
                        ControlKind::Renewed => {
                            let value =
                                RetainedRenewal::open(&deployment, *identity, *expected_root, &cx)
                                    .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("renewal_intent_identity={}", value.intent().identity());
                            line!(
                                "subscription_identity={}",
                                value.intent().subscription().identity()
                            );
                            line!("source_sha256={}", value.source_digest());
                            line!("source_bytes={}", value.source_bytes());
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=renew_response_retained");
                            line!("lease_confirmed={}", value.lease().is_some());
                            line!("http_status={}", value.binding().http_status);
                            line!(
                                "completion_time_observed={}",
                                value.binding().completed_ns.is_some()
                            );
                            line!("automatic_renew_retry_safe=false");
                        }
                    }
                    line!("custody_verified=true");
                }
            }
            if out.len() > REPORT_LIMIT {
                return Err(LIMIT_ERROR);
            }
            Ok(out)
        })();
        let refusal = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        refusal.map_or(result, Err)
    })
}

fn kind_name(kind: ControlKind) -> &'static str {
    match kind {
        ControlKind::CreateIntent => "intent",
        ControlKind::Created => "created",
        ControlKind::Unsubscribed => "unsubscribed",
        ControlKind::RenewIntent => "renew-intent",
        ControlKind::Renewed => "renewed",
    }
}

fn cleanup_options(
    args: &[OsString],
) -> Result<(Plan, ContentDigest, ContentDigest), &'static str> {
    if args.len() > 68 || args.len() % 2 != 0 {
        return Err(ARGUMENT_ERROR);
    }
    let mut remaining = Vec::new();
    let mut identity = None;
    let mut expected_root = None;
    for pair in args.chunks_exact(2) {
        match pair[0].to_str() {
            Some("--subscription-id") if identity.is_none() => {
                identity = Some(digest(pair[1].to_str().ok_or(ARGUMENT_ERROR)?)?);
            }
            Some("--expected-root") if expected_root.is_none() => {
                expected_root = Some(digest(pair[1].to_str().ok_or(ARGUMENT_ERROR)?)?);
            }
            Some("--subscription-id" | "--expected-root") => return Err(ARGUMENT_ERROR),
            _ => remaining.extend_from_slice(pair),
        }
    }
    let identity = identity.ok_or(ARGUMENT_ERROR)?;
    let expected_root = expected_root.ok_or(ARGUMENT_ERROR)?;
    Ok((
        Plan::parse_cleanup(&remaining, identity, expected_root)?,
        identity,
        expected_root,
    ))
}

fn verify_current_pins(plan: &Plan, retained: &RetainedSubscription) -> Result<(), &'static str> {
    let prior = retained.binding();
    let current = &plan.config.events;
    if plan.sensor != prior.source.sensor_id
        || plan.device_generation != prior.source.device_generation
        || plan.profile_generation != prior.source.profile_generation
        || plan.profile != prior.source.profile_token
        || plan.config.service_root != prior.service_root
        || current.peer() != prior.events.peer()
        || current.authority() != prior.events.authority()
        || current.target() != prior.events.target()
        || current.generation() != prior.events.generation()
        || plan.receive_origin_ns < retained.receive_interval().latest.0
    {
        return Err(ARGUMENT_ERROR);
    }
    Ok(())
}

fn unsubscribe(args: &[OsString]) -> Result<(String, bool), &'static str> {
    let (plan, identity, expected_root) = cleanup_options(args)?;
    let network = 2 * (plan.config.limits.request_bytes + plan.config.limits.wire_bytes) as u64;
    let bytes = 16 * 1024 * 1024;
    let mut controls = ControlReceipts::default();
    let mut observed = None::<CaptureReport>;
    let mut error = None;
    let request = runtime::Request {
        approval: plan.approval,
        principal: plan.principal.clone(),
        timeout_ns: plan.config.deadline_ns,
        bytes: network + bytes + MAX_CREDENTIAL_BYTES as u64 + 65536,
        network_bytes: network,
        storage_operations: capture::storage_allowance(4) + u64::from(plan.config.max_steps) * 64,
        network: true,
        write: true,
        secrets: true,
    };
    let result = runtime::run(request, |scope| {
        existing(&plan.root, scope)?;
        let authority = capture::storage_authority(&plan, bytes, 4)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, plan.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = (|| {
            let deployment = RefCell::new(
                ReferenceDeployment::open(&plan.root, &plan.site, &cx)
                    .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?,
            );
            let retained = RetainedSubscription::open(
                &deployment.borrow(),
                identity,
                Some(expected_root),
                &cx,
            )
            .map_err(|e| e.code())?;
            verify_current_pins(&plan, &retained)?;
            let subscription = retained.subscription().clone();
            let create_message_id = retained.binding().message_id.clone();
            controls.created = Some(retained);
            let check = || capture::secret_check(scope);
            let credentials = plan
                .credentials
                .as_ref()
                .map(|path| CredentialLease::load(path, &check))
                .transpose()
                .map_err(|e| capture::secret_error(e).code())?;
            let entropy = Some(Entropy::open(&check).map_err(|e| capture::secret_error(e).code())?);
            let owner = Owner {
                scope,
                plan: &plan,
                credentials: credentials.as_ref(),
                entropy: RefCell::new(entropy),
            };
            // The original receipt is evidence only. Owner supplies the current route,
            // fresh credentials/entropy, deadline and explicit cleanup approval.
            match pullpoint::unsubscribe_existing(
                &plan.config,
                &owner,
                &subscription,
                &create_message_id,
                |observation| {
                    capture::retain_control(&deployment, &plan, &mut controls, observation, &cx)
                },
            ) {
                Ok(report) => observed = Some(report),
                Err(failure) => {
                    error = Some(failure.error.code());
                    observed = Some(failure.report);
                }
            }
            Ok(())
        })();
        let refusal = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        refusal.map_or(result, Err)
    });
    if let Err(code) = result {
        error = Some(code);
    }
    let cleanup_error = observed.as_ref().and_then(|r| r.cleanup_error);
    let remote_success = observed
        .as_ref()
        .is_some_and(|r| r.subscription_state == SubscriptionState::Unsubscribed);
    let complete = error.is_none()
        && cleanup_error.is_none()
        && remote_success
        && controls.unsubscribed.is_some();
    let mut out = format!(
        "operation=control_unsubscribe\nphase={}\nselected_subscription={identity}\nexpected_root={expected_root}\napproval={}\nvalues_disclosed=false\ncreate_dispatched=false\npolls_dispatched=0\nremote_unsubscribe_success_observed={remote_success}\nerror={}\ncleanup_error={}\n",
        if complete { "completed" } else { "incomplete" },
        plan.approval,
        error.unwrap_or("none"),
        cleanup_error.unwrap_or("none"),
    );
    out.push_str(&controls.report());
    if let Some(report) = observed {
        out.push_str(&format!(
            "http_exchanges={}\nsubscription_state={:?}\n",
            report.exchanges, report.subscription_state
        ));
    } else {
        out.push_str("subscription_state=Unknown\n");
    }
    out.push_str("current_remote_state=unknown\nautomatic_create_retry_safe=false\nsafe_next=control_list_and_inspect_exact_receipts\n");
    if out.len() > 65536 {
        return Err(LIMIT_ERROR);
    }
    Ok((out, complete))
}

pub(super) fn run_args(args: &[OsString]) -> Result<(String, bool), &'static str> {
    if args.is_empty()
        || (args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help")))
    {
        return Ok((HELP.to_owned(), true));
    }
    match args[0].to_str() {
        Some("unsubscribe") => unsubscribe(&args[1..]),
        Some("list" | "inspect") => cold(parse_cold(args)?).map(|report| (report, true)),
        _ => Err(ARGUMENT_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn cold_catalog_bound_is_complete_or_refused() {
        for count in ["0", "1025", "-1", "18446744073709551616"] {
            assert!(
                parse_cold(&args(&[
                    "list",
                    "--root",
                    "/owner",
                    "--site",
                    "site:test",
                    "--max-records",
                    count
                ]))
                .is_err()
            );
        }
        assert!(
            parse_cold(&args(&[
                "list",
                "--root",
                "/owner",
                "--site",
                "site:test",
                "--max-records",
                "1024"
            ]))
            .is_ok()
        );
    }

    #[test]
    fn cold_commands_reject_network_authority_and_inexact_selectors() {
        assert!(
            parse_cold(&args(&[
                "list",
                "--root",
                "/owner",
                "--site",
                "site:test",
                "--subscribe",
                "yes"
            ]))
            .is_err()
        );
        assert!(
            parse_cold(&args(&[
                "inspect",
                "--root",
                "/owner",
                "--site",
                "site:test",
                "--kind",
                "created"
            ]))
            .is_err()
        );
        assert!(
            parse_cold(&args(&[
                "list",
                "--root",
                "/owner",
                "--site",
                "site:test",
                "--root",
                "/other"
            ]))
            .is_err()
        );
    }

    #[test]
    fn cleanup_requires_both_exact_identity_and_root() {
        let hash = ContentDigest::sha256(b"receipt").to_string();
        assert!(cleanup_options(&args(&["--subscription-id", &hash])).is_err());
        assert!(cleanup_options(&args(&["--expected-root", &hash])).is_err());
        assert!(
            cleanup_options(&args(&[
                "--subscription-id",
                &hash,
                "--subscription-id",
                &hash,
                "--expected-root",
                &hash
            ]))
            .is_err()
        );
    }

    #[test]
    fn cold_renewal_kinds_are_exact_and_do_not_grant_network_authority() {
        let identity = ContentDigest::sha256(b"renewal-receipt").to_string();
        for (name, expected) in [
            ("renew-intent", ControlKind::RenewIntent),
            ("renewed", ControlKind::Renewed),
        ] {
            let mut values = args(&[
                "inspect",
                "--root",
                "/owner",
                "--site",
                "site:test",
                "--kind",
                name,
                "--control-id",
                &identity,
            ]);
            assert!(matches!(
                parse_cold(&values).map(|options| options.action),
                Ok(ColdAction::Inspect { kind, .. }) if kind == expected
            ));
            values.extend(args(&["--max-renewals", "1"]));
            assert!(parse_cold(&values).is_err());
        }
    }
}
