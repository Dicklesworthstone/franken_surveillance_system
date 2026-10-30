#![forbid(unsafe_code)]
//! Cold control discovery and independently approved cleanup of a retained subscription.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, TimestampNs,
};
use fss_reference::onvif::capture_operation;
use fss_reference::onvif::control::{
    CleanupStatus, ControlDescriptor, ControlKind, MAX_CATALOG_RECORDS, RetainedCreateIntent,
    RetainedCreateOutcome, RetainedRenewIntent, RetainedRenewal, RetainedSubscription,
    RetainedUnsubscribe, RetainedUnsubscribeIntent, RetainedUnsubscribeOutcome, inspect_cleanup,
    list_control, recover_created,
};
use fss_reference::onvif::pullpoint::{self, CaptureReport, SubscriptionState};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES};
use super::capture::{self, ControlReceipts, Owner, plan::Plan};
use super::{
    ARGUMENT_ERROR, INPUT_ERROR, LIMIT_ERROR, REPORT_LIMIT, admission, clean_absolute, digest,
    optional_digest, runtime, text,
};

const HELP: &str = "fss-onvif-metadata control <list|inspect|recover-created|operation|reconcile-operation|unsubscribe> [options]
  list: --root ABSOLUTE_DIR --site SITE [--principal ID] [--max-records 64]
  inspect: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --kind intent|create-outcome|created|unsubscribed|renew-intent|renewed|unsubscribe-intent|unsubscribe-outcome
           --control-id sha256:HEX
           [--expected-root sha256:HEX]
  recover-created: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --control-id sha256:HEX --expected-root sha256:HEX
           --owner-authorized yes --recover yes
  operation: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --operation-id OPERATION_ID [--minimum-journal-root sha256:HEX]
  reconcile-operation: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --operation-id OPERATION_ID --kind unsubscribed|unsubscribe-outcome
           --control-id sha256:HEX --expected-root sha256:HEX
           --receive-origin-ns N --owner-authorized yes --reconcile yes
           [--minimum-journal-root sha256:HEX]
  unsubscribe: --root ABSOLUTE_DIR --site SITE [--principal ID]
           --subscription-id sha256:HEX --expected-root sha256:HEX
           --expected-control sha256:HEX
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
A renewal or cleanup intent alone leaves its remote result unknown; it never authorizes retry.
Retained responses are historical observations, not current remote state.
recover-created explicitly reconstructs the unchanged Created marker from an exact retained
usable Create outcome. Malformed, uncorrelated, unscoped or untimed replies refuse. It performs
no network work and grants no retry or cleanup authority; use separate fresh cleanup approval.
operation inspects the source-free capture fence by the stable owner ID, without camera
credentials or network access. Every recorded state consumes that ID. An independently
saved --minimum-journal-root must occur in the verified history, detecting rollback past
that pin. An unavailable operation is not proof that no remote subscription exists.
The fence records dispatch intent; use control custody to inspect Create/cleanup outcomes.
New capture operations bind their exact Create intent before dispatch. reconcile-operation
closes such an operation from a selected retained successful cleanup, without credentials,
network access, Create, polling or Unsubscribe. It requires the original owner and a current
receive origin. A successful raw cleanup outcome is sufficient after interrupted marker
publication. Legacy operations without an original intent binding cannot be retrofitted.
Reconciliation preserves the consumed operation ID and never claims current remote state.
unsubscribe requires a fresh, explicit owner request with the original independent pins.
It performs only Unsubscribe against the retained scoped endpoint; it never creates or polls.
Inspect the created record for cleanup_control_witness before approving cleanup. Both the
expected root and expected control witness are mandatory; stale cleanup state refuses dispatch.
A verified prior success returns already_unsubscribed before credentials or network work.
The current receive origin must follow the
retained Create interval. Fresh cleanup authority is distinct from the retained approval.
Known terminal receipts survive late refusal and output failure; incomplete cleanup exits 1.
";

enum ColdAction {
    RecoverCreated {
        identity: ContentDigest,
        root: ContentDigest,
    },
    Operation {
        operation_id: OperationId,
        minimum_journal_root: Option<ContentDigest>,
    },
    ReconcileOperation {
        operation_id: OperationId,
        evidence: capture_operation::CaptureCleanupEvidence,
        receive_origin_ns: i128,
        minimum_journal_root: Option<ContentDigest>,
    },
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
        || args.len() > 27
        || args.len() % 2 != 1
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let command = args[0].to_str().ok_or(ARGUMENT_ERROR)?;
    if !matches!(
        command,
        "list" | "inspect" | "recover-created" | "operation" | "reconcile-operation"
    ) {
        return Err(ARGUMENT_ERROR);
    }
    let listing = command == "list";
    let operation = command == "operation";
    let reconcile = command == "reconcile-operation";
    let recovery = command == "recover-created";
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        let common = matches!(key, "--root" | "--site" | "--principal");
        let specific = if listing {
            key == "--max-records"
        } else if recovery {
            matches!(
                key,
                "--control-id" | "--expected-root" | "--owner-authorized" | "--recover"
            )
        } else if operation {
            matches!(key, "--operation-id" | "--minimum-journal-root")
        } else if reconcile {
            matches!(
                key,
                "--operation-id"
                    | "--minimum-journal-root"
                    | "--kind"
                    | "--control-id"
                    | "--expected-root"
                    | "--receive-origin-ns"
                    | "--owner-authorized"
                    | "--reconcile"
            )
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
    } else if recovery {
        if text(&values, "--owner-authorized")? != "yes" || text(&values, "--recover")? != "yes" {
            return Err(ARGUMENT_ERROR);
        }
        let identity = digest(text(&values, "--control-id")?)?;
        let root = digest(text(&values, "--expected-root")?)?;
        if identity.bytes() == [0; 32] || root.bytes() == [0; 32] {
            return Err(ARGUMENT_ERROR);
        }
        ColdAction::RecoverCreated { identity, root }
    } else if operation || reconcile {
        let minimum_journal_root = optional_digest(&values, "--minimum-journal-root")?;
        if minimum_journal_root.is_some_and(|digest| digest.bytes() == [0; 32]) {
            return Err(ARGUMENT_ERROR);
        }
        let operation_id =
            OperationId::parse(text(&values, "--operation-id")?).map_err(|_| ARGUMENT_ERROR)?;
        if reconcile {
            if text(&values, "--owner-authorized")? != "yes"
                || text(&values, "--reconcile")? != "yes"
            {
                return Err(ARGUMENT_ERROR);
            }
            let identity = digest(text(&values, "--control-id")?)?;
            let root = digest(text(&values, "--expected-root")?)?;
            if identity.bytes() == [0; 32] || root.bytes() == [0; 32] {
                return Err(ARGUMENT_ERROR);
            }
            let evidence = match text(&values, "--kind")? {
                "unsubscribed" => {
                    capture_operation::CaptureCleanupEvidence::Unsubscribed { identity, root }
                }
                "unsubscribe-outcome" => {
                    capture_operation::CaptureCleanupEvidence::Outcome { identity, root }
                }
                _ => return Err(ARGUMENT_ERROR),
            };
            let receive_origin_ns = text(&values, "--receive-origin-ns")?
                .parse::<i128>()
                .map_err(|_| ARGUMENT_ERROR)?;
            ColdAction::ReconcileOperation {
                operation_id,
                evidence,
                receive_origin_ns,
                minimum_journal_root,
            }
        } else {
            ColdAction::Operation {
                operation_id,
                minimum_journal_root,
            }
        }
    } else {
        let kind = match text(&values, "--kind")? {
            "intent" => ControlKind::CreateIntent,
            "create-outcome" => ControlKind::CreateOutcome,
            "created" => ControlKind::Created,
            "unsubscribed" => ControlKind::Unsubscribed,
            "renew-intent" => ControlKind::RenewIntent,
            "renewed" => ControlKind::Renewed,
            "unsubscribe-intent" => ControlKind::UnsubscribeIntent,
            "unsubscribe-outcome" => ControlKind::UnsubscribeOutcome,
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

fn cleanup_report(status: &CleanupStatus) -> String {
    let mut out = format!(
        "cleanup_control_witness={}\ncleanup_attempts={}\ncleanup_success_retained={}\nautomatic_unsubscribe_retry_safe=false\n",
        status.witness,
        status.attempts,
        status.terminal.is_some()
    );
    if let Some(intent) = status.latest_intent {
        out.push_str(&format!(
            "latest_unsubscribe_intent.identity={}\nlatest_unsubscribe_intent.publication_root={}\n",
            intent.identity, intent.root
        ));
    }
    if let Some(terminal) = status.terminal {
        out.push_str(&format!(
            "terminal.kind={}\nterminal.identity={}\nterminal.publication_root={}\nsafe_next=already_unsubscribed_no_dispatch\n",
            kind_name(terminal.kind), terminal.identity, terminal.root
        ));
    } else {
        out.push_str(
            "safe_next=review_cleanup_history_then_explicit_unsubscribe_with_expected_control\n",
        );
    }
    out
}

enum ColdResult {
    Report(String),
    Reconciled(Box<capture_operation::CaptureOperationInspection>),
    Recovered(Box<RetainedSubscription>),
}

pub(super) fn cold(
    args: &[OsString],
    checkpoint: impl Fn(&str) -> Result<(), fss_reference::ReplayAdmissionError>,
) -> Result<(String, bool), &'static str> {
    let options = parse_cold(args)?;
    let records = match options.action {
        ColdAction::List { max_records } => max_records as u64,
        ColdAction::Inspect { .. }
        | ColdAction::RecoverCreated { .. }
        | ColdAction::Operation { .. }
        | ColdAction::ReconcileOperation { .. } => 1,
    };
    let cleanup_history = matches!(
        &options.action,
        ColdAction::Inspect {
            kind: ControlKind::Created,
            ..
        }
    );
    let operation_history = matches!(
        &options.action,
        ColdAction::Operation { .. } | ColdAction::ReconcileOperation { .. }
    );
    let reconciliation = matches!(&options.action, ColdAction::ReconcileOperation { .. });
    let recovery = matches!(&options.action, ColdAction::RecoverCreated { .. });
    let bytes = (records + 1) * 4 * 1024 * 1024
        + if operation_history {
            4 * capture_operation::MAX_JOURNAL_BYTES
        } else {
            0
        }
        + if cleanup_history {
            capture::CLEANUP_READ_BYTES
        } else {
            0
        };
    let operations = capture::storage_allowance(
        2 * records
            + 2
            + if cleanup_history {
                capture::CLEANUP_READ_OPERATIONS
            } else {
                0
            }
            + if reconciliation { 32 } else { 0 }
            + if recovery { 8 } else { 0 },
    );
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
    let work = |scope: &runtime::Scope<'_, '_>| {
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
            .with_admission(|stage| {
                // Additional checkpoints may only narrow the live native owner.
                admission::check(scope)?;
                checkpoint(stage)
            });
        let result = (|| {
            let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?;
            let mut out = String::new();
            macro_rules! line {
                ($($arg:tt)*) => { writeln!(&mut out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
            }
            line!("values_disclosed=false");
            line!("current_remote_state=unknown");
            line!("automatic_create_retry_safe=false");
            match &options.action {
                ColdAction::RecoverCreated { identity, root } => {
                    let outcome =
                        RetainedCreateOutcome::open(&deployment, *identity, Some(*root), &cx)
                            .map_err(|error| error.code())?;
                    let value = recover_created(&mut deployment, &outcome, &cx)
                        .map_err(|error| error.code())?;
                    return Ok(ColdResult::Recovered(Box::new(value)));
                }
                ColdAction::Operation {
                    operation_id,
                    minimum_journal_root,
                } => {
                    let value = capture_operation::inspect(
                        &deployment,
                        operation_id,
                        None,
                        *minimum_journal_root,
                        &cx,
                    )
                    .map_err(|error| error.code())?;
                    line!("operation=control_operation_inspect");
                    line!(
                        "minimum_journal_root_checked={}",
                        minimum_journal_root.is_some()
                    );
                    out.push_str(&capture::operation_report(&value));
                    line!("safe_next=inspect_control_custody_no_create_retry");
                }
                ColdAction::ReconcileOperation {
                    operation_id,
                    evidence,
                    receive_origin_ns,
                    minimum_journal_root,
                } => {
                    let value = capture_operation::reconcile_cleanup(
                        &mut deployment,
                        operation_id,
                        *evidence,
                        *minimum_journal_root,
                        || {
                            let elapsed = scope
                                .now()
                                .map_err(|_| capture_operation::CaptureOperationError::Authority)?;
                            receive_origin_ns
                                .checked_add(i128::from(elapsed))
                                .map(TimestampNs)
                                .ok_or(capture_operation::CaptureOperationError::InvalidBinding)
                        },
                        &cx,
                    )
                    .map_err(|error| error.code())?;
                    // Only the exact durable terminal receipt crosses this boundary.
                    // Render after retirement so late refusal cannot erase it.
                    return Ok(ColdResult::Reconciled(Box::new(value)));
                }
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
                        if let Some(identity) = record.unsubscribe_intent_identity {
                            line!("record.{index}.unsubscribe_intent_identity={identity}");
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
                        ControlKind::CreateOutcome => {
                            let value = RetainedCreateOutcome::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|error| error.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("intent_identity={}", value.intent().identity());
                            line!("source_sha256={}", value.source_digest());
                            line!("source_bytes={}", value.source_bytes());
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=create_response_retained");
                            line!(
                                "scoped_response_observed={}",
                                value.scoped_subscription().is_some()
                            );
                            line!("http_status={}", value.binding().http_status);
                            line!(
                                "completion_time_observed={}",
                                value.binding().completed_ns.is_some()
                            );
                            line!(
                                "safe_next={}",
                                if value.scoped_subscription().is_some() {
                                    "explicit_recover_created_then_review_cleanup"
                                } else {
                                    "owner_device_reconciliation_no_create_retry"
                                }
                            );
                        }
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
                            let cleanup =
                                inspect_cleanup(&deployment, &value, &cx).map_err(|e| e.code())?;
                            out.push_str(&cleanup_report(&cleanup));
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
                        ControlKind::UnsubscribeIntent => {
                            let value = RetainedUnsubscribeIntent::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("subscription_identity={}", value.subscription().identity());
                            line!("expected_control={}", value.binding().expected_control);
                            line!("request_sha256={}", value.binding().request_digest);
                            line!(
                                "authority_sequence={}",
                                value.authority_anchor().commit_sequence
                            );
                            line!("historical_observation=unsubscribe_intent_prepared");
                            line!("remote_dispatch=unknown");
                            line!("automatic_unsubscribe_retry_safe=false");
                        }
                        ControlKind::UnsubscribeOutcome => {
                            let value = RetainedUnsubscribeOutcome::open(
                                &deployment,
                                *identity,
                                *expected_root,
                                &cx,
                            )
                            .map_err(|e| e.code())?;
                            line!("publication_root={}", value.publication_root());
                            line!("unsubscribe_intent_identity={}", value.intent().identity());
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
                            line!("historical_observation=unsubscribe_response_retained");
                            line!("success_observed={}", value.success_observed());
                            line!("http_status={}", value.binding().http_status);
                            line!(
                                "completion_time_observed={}",
                                value.binding().completed_ns.is_some()
                            );
                            line!("automatic_unsubscribe_retry_safe=false");
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
            Ok(ColdResult::Report(out))
        })();
        let refusal = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        match result {
            Ok(value) => Ok((value, refusal)),
            Err(error) => Err(refusal.unwrap_or(error)),
        }
    };
    if reconciliation {
        let completed = runtime::run_committing(request, |scope| {
            let (value, refusal) = work(scope)?;
            match value {
                ColdResult::Reconciled(value) => Ok(runtime::Committed::new((*value, refusal))),
                ColdResult::Report(_) | ColdResult::Recovered(_) => Err(ARGUMENT_ERROR),
            }
        })?;
        let minimum_checked = matches!(
            options.action,
            ColdAction::ReconcileOperation {
                minimum_journal_root: Some(_),
                ..
            }
        );
        Ok(reconciliation_report(completed, minimum_checked))
    } else if recovery {
        let completed = runtime::run_committing(request, |scope| {
            let (value, refusal) = work(scope)?;
            match value {
                ColdResult::Recovered(value) => Ok(runtime::Committed::new((*value, refusal))),
                ColdResult::Report(_) | ColdResult::Reconciled(_) => Err(ARGUMENT_ERROR),
            }
        })?;
        let (value, owner_error) = completed.value;
        let post_commit_error = owner_error.or(completed.post_commit_error);
        let complete = post_commit_error.is_none() && completed.finalization_error.is_none();
        Ok((
            format!(
                "operation=control_recover_created\nphase={}\nidentity={}\npublication_root={}\nintent_identity={}\nsource_sha256={}\nauthority_sequence={}\ncustody_verified=true\nhttp_exchanges=0\ncreate_dispatched=false\npolls_dispatched=0\nunsubscribe_dispatched=false\nvalues_disclosed=false\ncurrent_remote_state=unknown\nautomatic_create_retry_safe=false\npost_commit_error={}\nfinalization_error={}\nsafe_next=inspect_created_then_separately_approve_cleanup\n",
                if complete {
                    "recovered"
                } else {
                    "recovered_with_error"
                },
                value.identity(),
                value.publication_root(),
                value.intent_identity(),
                value.source_digest(),
                value.authority_anchor().commit_sequence,
                post_commit_error.unwrap_or("none"),
                completed.finalization_error.unwrap_or("none"),
            ),
            complete,
        ))
    } else {
        let (value, refusal) = runtime::run(request, work)?;
        if let Some(error) = refusal {
            return Err(error);
        }
        match value {
            ColdResult::Report(out) => Ok((out, true)),
            ColdResult::Reconciled(_) | ColdResult::Recovered(_) => Err(ARGUMENT_ERROR),
        }
    }
}

pub(super) fn reconciliation_report(
    completed: runtime::CommittedCompletion<(
        capture_operation::CaptureOperationInspection,
        Option<&'static str>,
    )>,
    minimum_checked: bool,
) -> (String, bool) {
    let (value, owner_error) = completed.value;
    let post_commit_error = owner_error.or(completed.post_commit_error);
    let complete = post_commit_error.is_none() && completed.finalization_error.is_none();
    let mut out = format!(
        "operation=control_operation_reconcile\nphase={}\nhttp_exchanges=0\ncreate_dispatched=false\npolls_dispatched=0\nunsubscribe_dispatched=false\ncleanup_custody_verified=true\nminimum_journal_root_checked={minimum_checked}\npost_commit_error={}\nfinalization_error={}\nvalues_disclosed=false\ncurrent_remote_state=unknown\nautomatic_create_retry_safe=false\n",
        if complete {
            "verified"
        } else {
            "verified_with_error"
        },
        post_commit_error.unwrap_or("none"),
        completed.finalization_error.unwrap_or("none"),
    );
    out.push_str(&capture::operation_report(&value));
    out.push_str("safe_next=operation_terminal_no_create_retry\n");
    (out, complete)
}

fn kind_name(kind: ControlKind) -> &'static str {
    match kind {
        ControlKind::CreateIntent => "intent",
        ControlKind::CreateOutcome => "create-outcome",
        ControlKind::Created => "created",
        ControlKind::Unsubscribed => "unsubscribed",
        ControlKind::RenewIntent => "renew-intent",
        ControlKind::Renewed => "renewed",
        ControlKind::UnsubscribeIntent => "unsubscribe-intent",
        ControlKind::UnsubscribeOutcome => "unsubscribe-outcome",
    }
}

fn cleanup_options(
    args: &[OsString],
) -> Result<(Plan, ContentDigest, ContentDigest), &'static str> {
    if args.len() > 70 || args.len() % 2 != 0 {
        return Err(ARGUMENT_ERROR);
    }
    let mut remaining = Vec::new();
    let mut identity = None;
    let mut expected_root = None;
    let mut expected_control = None;
    for pair in args.chunks_exact(2) {
        match pair[0].to_str() {
            Some("--subscription-id") if identity.is_none() => {
                identity = Some(digest(pair[1].to_str().ok_or(ARGUMENT_ERROR)?)?);
            }
            Some("--expected-root") if expected_root.is_none() => {
                expected_root = Some(digest(pair[1].to_str().ok_or(ARGUMENT_ERROR)?)?);
            }
            Some("--expected-control") if expected_control.is_none() => {
                expected_control = Some(digest(pair[1].to_str().ok_or(ARGUMENT_ERROR)?)?);
            }
            Some("--subscription-id" | "--expected-root" | "--expected-control") => {
                return Err(ARGUMENT_ERROR);
            }
            _ => remaining.extend_from_slice(pair),
        }
    }
    let identity = identity.ok_or(ARGUMENT_ERROR)?;
    let expected_root = expected_root.ok_or(ARGUMENT_ERROR)?;
    let expected_control = expected_control.ok_or(ARGUMENT_ERROR)?;
    Ok((
        Plan::parse_cleanup(&remaining, identity, expected_root, expected_control)?,
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
    let bytes = 16 * 1024 * 1024 + capture::CLEANUP_READ_BYTES;
    let operations = 6 + capture::CLEANUP_READ_OPERATIONS;
    let mut controls = ControlReceipts::default();
    let mut observed = None::<CaptureReport>;
    let mut error = None;
    let mut current_control = None;
    let mut prior_terminal = None::<ControlDescriptor>;
    let request = runtime::Request {
        approval: plan.approval,
        principal: plan.principal.clone(),
        timeout_ns: plan.config.deadline_ns,
        bytes: network + bytes + MAX_CREDENTIAL_BYTES as u64 + 65536,
        network_bytes: network,
        storage_operations: capture::storage_allowance(operations)
            + u64::from(plan.config.max_steps) * 64,
        network: true,
        write: true,
        secrets: true,
    };
    let result = runtime::run(request, |scope| {
        existing(&plan.root, scope)?;
        let authority = capture::storage_authority(&plan, bytes, operations)?;
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
            let cleanup =
                inspect_cleanup(&deployment.borrow(), &retained, &cx).map_err(|e| e.code())?;
            current_control = Some(cleanup.witness);
            if let Some(terminal) = cleanup.terminal {
                // Current independent pins are checked, but no new effect is needed. A raw
                // correlated success is sufficient even if its final marker was interrupted.
                prior_terminal = Some(terminal);
                controls.created = Some(retained);
                return Ok(());
            }
            if plan.cleanup_expected_control != Some(cleanup.witness) {
                return Err("ERR-ONVIF-METADATA-AUTHORITY-001");
            }
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
                    capture::retain_control(
                        &deployment,
                        &plan,
                        &mut controls,
                        observation,
                        &cx,
                        || scope.now().map_err(capture::context_error),
                    )
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
        && (prior_terminal.is_some() || (remote_success && controls.successful_cleanup()));
    let mut out = format!(
        "operation=control_unsubscribe\nphase={}\nselected_subscription={identity}\nexpected_root={expected_root}\napproval={}\nvalues_disclosed=false\ncreate_dispatched=false\npolls_dispatched=0\nremote_unsubscribe_success_observed={remote_success}\nerror={}\ncleanup_error={}\n",
        if complete && prior_terminal.is_some() {
            "already_unsubscribed"
        } else if complete {
            "completed"
        } else {
            "incomplete"
        },
        plan.approval,
        error.unwrap_or("none"),
        cleanup_error.unwrap_or("none"),
    );
    if let Some(witness) = current_control {
        out.push_str(&format!("cleanup_control_witness={witness}\n"));
    }
    if let Some(expected) = plan.cleanup_expected_control {
        out.push_str(&format!("expected_control={expected}\n"));
    }
    if let Some(terminal) = prior_terminal {
        out.push_str(&format!(
            "previous_unsubscribe_success_retained=true\nterminal.kind={}\nterminal.identity={}\nterminal.publication_root={}\nterminal.authority_sequence={}\nunsubscribe_dispatched=false\nhttp_exchanges=0\n",
            kind_name(terminal.kind), terminal.identity, terminal.root, terminal.authority_sequence
        ));
    }
    out.push_str(&controls.report());
    if let Some(report) = observed {
        out.push_str(&format!(
            "http_exchanges={}\nsubscription_state={:?}\n",
            report.exchanges, report.subscription_state
        ));
    } else if prior_terminal.is_some() {
        out.push_str("subscription_state=Unsubscribed\n");
    } else {
        out.push_str("subscription_state=Unknown\n");
    }
    out.push_str("current_remote_state=unknown\nautomatic_create_retry_safe=false\nautomatic_unsubscribe_retry_safe=false\nsafe_next=control_list_and_inspect_exact_receipts\n");
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
        Some("list" | "inspect" | "recover-created" | "operation" | "reconcile-operation") => {
            cold(args, |_| Ok(()))
        }
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
    fn created_recovery_requires_exact_raw_custody_and_explicit_local_approval() {
        let identity = ContentDigest::sha256(b"raw-create-outcome").to_text();
        let root = ContentDigest::sha256(b"raw-create-root").to_text();
        let valid = args(&[
            "recover-created",
            "--root",
            "/owner",
            "--site",
            "site:test",
            "--control-id",
            &identity,
            "--expected-root",
            &root,
            "--owner-authorized",
            "yes",
            "--recover",
            "yes",
        ]);
        assert!(matches!(
            parse_cold(&valid).map(|options| options.action),
            Ok(ColdAction::RecoverCreated { identity: actual, root: actual_root })
                if actual.to_text() == identity && actual_root.to_text() == root
        ));
        for missing in [
            "--control-id",
            "--expected-root",
            "--owner-authorized",
            "--recover",
        ] {
            let mut changed = vec![valid[0].clone()];
            for pair in valid[1..].chunks_exact(2) {
                if pair[0] != missing {
                    changed.extend_from_slice(pair);
                }
            }
            assert!(parse_cold(&changed).is_err(), "accepted missing {missing}");
        }
        for (flag, value) in [
            ("--owner-authorized", "no"),
            ("--recover", "no"),
            (
                "--control-id",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "--expected-root",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let mut changed = valid.clone();
            let index = changed
                .iter()
                .position(|argument| argument == flag)
                .unwrap();
            changed[index + 1] = value.into();
            assert!(parse_cold(&changed).is_err(), "accepted {flag} {value}");
        }
        for flag in [
            "--peer",
            "--credential-file",
            "--subscribe",
            "--unsubscribe",
            "--kind",
            "--receive-origin-ns",
        ] {
            let mut changed = valid.clone();
            changed.extend(args(&[flag, "not-authorized"]));
            assert!(
                parse_cold(&changed).is_err(),
                "accepted unrelated field {flag}"
            );
        }
        let mut duplicate = valid.clone();
        duplicate.extend(args(&["--expected-root", &root]));
        assert!(parse_cold(&duplicate).is_err());
        let mut changed = valid.clone();
        let index = changed
            .iter()
            .position(|argument| argument == "--expected-root")
            .unwrap();
        changed[index + 1] = ContentDigest::sha256(b"different-root").to_text().into();
        assert_ne!(
            parse_cold(&valid).unwrap().approval,
            parse_cold(&changed).unwrap().approval
        );
    }

    #[test]
    fn reconciliation_requires_exact_terminal_custody_and_fresh_local_approval() {
        let hash = ContentDigest::sha256(b"terminal").to_text();
        let valid = args(&[
            "reconcile-operation",
            "--root",
            "/owner",
            "--site",
            "site:test",
            "--operation-id",
            "operation:fixture",
            "--kind",
            "unsubscribed",
            "--control-id",
            &hash,
            "--expected-root",
            &hash,
            "--receive-origin-ns",
            "30000",
            "--owner-authorized",
            "yes",
            "--reconcile",
            "yes",
        ]);
        assert!(matches!(
            parse_cold(&valid).map(|o| o.action),
            Ok(ColdAction::ReconcileOperation { .. })
        ));
        for missing in [
            "--operation-id",
            "--control-id",
            "--expected-root",
            "--receive-origin-ns",
            "--owner-authorized",
            "--reconcile",
        ] {
            let mut changed = vec![valid[0].clone()];
            for pair in valid[1..].chunks_exact(2) {
                if pair[0] != missing {
                    changed.extend_from_slice(pair);
                }
            }
            assert!(parse_cold(&changed).is_err(), "accepted missing {missing}");
        }
        for (flag, value) in [
            ("--kind", "created"),
            ("--kind", "unsubscribe-intent"),
            ("--owner-authorized", "no"),
            ("--reconcile", "no"),
        ] {
            let mut changed = valid.clone();
            let Some(index) = changed.iter().position(|argument| argument == flag) else {
                panic!("test flag missing");
            };
            changed[index + 1] = value.into();
            assert!(parse_cold(&changed).is_err(), "accepted {flag} {value}");
        }
        for flag in [
            "--peer",
            "--credential-file",
            "--subscribe",
            "--unsubscribe",
        ] {
            let mut changed = valid.clone();
            changed.extend(args(&[flag, "not-authorized"]));
            assert!(
                parse_cold(&changed).is_err(),
                "accepted network/secret field {flag}"
            );
        }
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
    fn cold_attempt_kinds_are_exact_and_do_not_grant_network_authority() {
        let identity = ContentDigest::sha256(b"renewal-receipt").to_string();
        for (name, expected) in [
            ("create-outcome", ControlKind::CreateOutcome),
            ("renew-intent", ControlKind::RenewIntent),
            ("renewed", ControlKind::Renewed),
            ("unsubscribe-intent", ControlKind::UnsubscribeIntent),
            ("unsubscribe-outcome", ControlKind::UnsubscribeOutcome),
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

    #[test]
    fn cleanup_requires_an_exact_reviewed_control_witness() -> Result<(), &'static str> {
        let pin = ContentDigest::sha256(b"selected-control").to_text();
        let mut values = args(&[
            "--root",
            "/owner",
            "--site",
            "site:cleanup",
            "--sensor",
            "sensor:front",
            "--profile",
            "main",
            "--peer",
            "127.0.0.1:8080",
            "--authority",
            "camera.local:8080",
            "--events-path",
            "/onvif/events",
            "--service-root",
            "/onvif",
            "--owner-authorized",
            "yes",
            "--plaintext",
            "yes",
            "--unsubscribe",
            "yes",
            "--receive-origin-ns",
            "100",
            "--device-generation",
            &pin,
            "--profile-generation",
            &pin,
            "--subscription-id",
            &pin,
            "--expected-root",
            &pin,
            "--expected-control",
            &pin,
        ]);
        let (plan, _, _) = cleanup_options(&values)?;
        assert_eq!(plan.cleanup_expected_control, Some(digest(&pin)?));
        let expected = values
            .iter()
            .position(|value| value == "--expected-control")
            .ok_or(ARGUMENT_ERROR)?;
        values[expected + 1] = OsString::from(ContentDigest::sha256(b"changed-state").to_text());
        assert_ne!(cleanup_options(&values)?.0.approval, plan.approval);
        let mut duplicate = values.clone();
        duplicate.extend(args(&["--expected-control", &pin]));
        assert!(cleanup_options(&duplicate).is_err());
        drop(values.drain(expected..expected + 2));
        assert!(cleanup_options(&values).is_err());
        Ok(())
    }

    #[test]
    fn operation_inspection_requires_exact_id_and_only_accepts_its_own_pins() {
        let valid = args(&[
            "operation",
            "--root",
            "/owner",
            "--site",
            "site:test",
            "--operation-id",
            "operation:capture-one",
        ]);
        assert!(matches!(
            parse_cold(&valid).map(|options| options.action),
            Ok(ColdAction::Operation {
                minimum_journal_root: None,
                ..
            }),
        ));
        for (key, value) in [
            (
                "--expected-root",
                "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            ),
            ("--kind", "created"),
            ("--max-records", "1"),
            ("--credential-file", "/secret"),
            ("--operation-id", "operation:duplicate"),
        ] {
            let mut changed = valid.clone();
            changed.extend([OsString::from(key), OsString::from(value)]);
            assert!(parse_cold(&changed).is_err(), "accepted {key}");
        }
        let mut pinned = valid.clone();
        pinned.extend([
            OsString::from("--minimum-journal-root"),
            OsString::from(ContentDigest::sha256(b"independent-journal-pin").to_text()),
        ]);
        assert!(matches!(
            parse_cold(&pinned).map(|options| options.action),
            Ok(ColdAction::Operation {
                minimum_journal_root: Some(_),
                ..
            }),
        ));
        let last = pinned.len() - 1;
        pinned[last] = OsString::from(format!("sha256:{}", "0".repeat(64)));
        assert!(parse_cold(&pinned).is_err());
        assert!(parse_cold(&valid[..valid.len() - 2]).is_err());
    }
}
