#![forbid(unsafe_code)]
//! Request-owned native PullPoint acquisition and durable per-response custody.

mod plan;

use std::cell::RefCell;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_reference::onvif::client::{ClientError, OnvifContext};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpOperation, HttpRoute};
use fss_reference::onvif::metadata::{
    MetadataError, PullPointAcquisition, RetainedMetadata, SourceBinding, retain_pullpoint,
};
use fss_reference::onvif::pullpoint::{self, CaptureReport, RetainedBatch, route_in_service_root};
use fss_reference::rtsp::authentication::{DigestAuthorization, DigestChallenge};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES, SecretError};
use super::{ARGUMENT_ERROR, INPUT_ERROR, LIMIT_ERROR, runtime};
use plan::Plan;

struct Owner<'a, 'scope, 'task> {
    scope: &'a runtime::Scope<'scope, 'task>,
    plan: &'a Plan,
    credentials: Option<&'a CredentialLease>,
    entropy: RefCell<Option<Entropy>>,
}

fn context_error(code: &'static str) -> ClientError {
    match code {
        "ERR-ONVIF-CANCELLED-001" => ClientError::Cancelled,
        "ERR-ONVIF-DEADLINE-001" => ClientError::Deadline,
        "ERR-ONVIF-BUDGET-001" => ClientError::Budget,
        _ => ClientError::Authority,
    }
}
fn denial(code: &'static str) -> HttpDenial {
    match code {
        "ERR-ONVIF-CANCELLED-001" => HttpDenial::Cancelled,
        "ERR-ONVIF-DEADLINE-001" => HttpDenial::Deadline,
        "ERR-ONVIF-BUDGET-001" => HttpDenial::Budget,
        _ => HttpDenial::Unauthorized,
    }
}
fn denied(error: HttpDenial) -> ClientError {
    match error {
        HttpDenial::Cancelled => ClientError::Cancelled,
        HttpDenial::Deadline => ClientError::Deadline,
        HttpDenial::Budget => ClientError::Budget,
        HttpDenial::Unauthorized | HttpDenial::Revoked => ClientError::Authority,
    }
}
fn secret_error(error: SecretError) -> ClientError {
    match error {
        SecretError::Credentials => ClientError::Credentials,
        SecretError::Entropy => ClientError::Entropy,
        SecretError::Deadline => ClientError::Deadline,
        SecretError::Authority | SecretError::Revoked => ClientError::Authority,
    }
}
fn secret_check(scope: &runtime::Scope<'_, '_>) -> Result<(), SecretError> {
    scope
        .admit(RuntimeGrant::AdapterAuth, true)
        .map(|_| ())
        .map_err(|code| {
            if code == "ERR-ONVIF-DEADLINE-001" {
                SecretError::Deadline
            } else {
                SecretError::Authority
            }
        })
}

impl HttpAuthority for Owner<'_, '_, '_> {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        _: HttpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), HttpDenial> {
        let now = self
            .scope
            .admit(RuntimeGrant::AdapterNet, false)
            .map_err(denial)?;
        let approved = &self.plan.config.events;
        if !route.is_event_subscription()
            || route.peer() != approved.peer()
            || route.authority() != approved.authority()
            || route.generation() != approved.generation()
            || route.plaintext_approval() != self.plan.approval
            || !route_in_service_root(route, &self.plan.config.service_root)
            || now_ns > now
            || deadline_ns > self.plan.config.deadline_ns
        {
            return Err(HttpDenial::Unauthorized);
        }
        if now >= deadline_ns {
            return Err(HttpDenial::Deadline);
        }
        if let Some(lease) = self.credentials {
            lease
                .revalidate(&|| secret_check(self.scope))
                .map_err(|error| match error {
                    SecretError::Deadline => HttpDenial::Deadline,
                    SecretError::Revoked | SecretError::Credentials => HttpDenial::Revoked,
                    _ => HttpDenial::Unauthorized,
                })?;
        }
        Ok(())
    }
}

impl OnvifContext for Owner<'_, '_, '_> {
    fn now_ns(&self) -> Result<u64, ClientError> {
        self.scope.now().map_err(context_error)
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        if let Some(lease) = self.credentials {
            lease
                .revalidate(&|| secret_check(self.scope))
                .map_err(secret_error)?;
        }
        self.scope.wait(deadline_ns).map_err(context_error)
    }
    fn event_request_id(&self) -> Result<[u8; 16], ClientError> {
        let check = || secret_check(self.scope);
        let mut entropy = self
            .entropy
            .try_borrow_mut()
            .map_err(|_| ClientError::Entropy)?;
        entropy
            .as_mut()
            .ok_or(ClientError::Entropy)?
            .next(&check)
            .map_err(secret_error)
    }
    fn authorize(
        &self,
        route: &HttpRoute,
        challenge: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        if self.plan.config.auth.is_none() {
            return Err(ClientError::Authority);
        }
        let now = self.now_ns()?;
        self.checkpoint(
            route,
            HttpOperation::Write,
            now,
            self.plan.config.deadline_ns,
        )
        .map_err(denied)?;
        let check = || secret_check(self.scope);
        let lease = self.credentials.ok_or(ClientError::Credentials)?;
        lease.revalidate(&check).map_err(secret_error)?;
        let mut entropy = self
            .entropy
            .try_borrow_mut()
            .map_err(|_| ClientError::Entropy)?;
        let nonce = entropy
            .as_mut()
            .ok_or(ClientError::Entropy)?
            .next(&check)
            .map_err(secret_error)?;
        let credentials = lease.credentials().map_err(secret_error)?;
        let authorization = challenge
            .authorize("POST", route.target(), &credentials, nonce, 1)
            .map_err(ClientError::Authentication)?;
        lease.revalidate(&check).map_err(secret_error)?;
        Ok(authorization)
    }
}

pub(super) fn run_args(args: &[OsString]) -> Result<(String, bool), &'static str> {
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help")) {
        return Ok((plan::HELP.to_owned(), true));
    }
    let plan = Plan::parse(args)?;
    let exchanges = 2 * (u64::from(plan.config.max_pulls) + 2);
    let network =
        exchanges * (plan.config.limits.request_bytes + plan.config.limits.wire_bytes) as u64;
    let retained_allowance = (u64::from(plan.config.max_pulls) + 1) * 4 * 1024 * 1024;
    let mut retained = Vec::<RetainedMetadata>::new();
    let mut capture_report = None::<CaptureReport>;
    let mut capture_error = None;
    let mut subscription_attempted = false;
    let request = runtime::Request {
        approval: plan.approval,
        principal: plan.principal.clone(),
        timeout_ns: plan.config.deadline_ns,
        bytes: network + retained_allowance + MAX_CREDENTIAL_BYTES as u64 + 65536,
        network_bytes: network,
        storage_operations: u64::from(plan.config.max_steps) * 64 + 8192,
        network: true,
        write: true,
        // Every event operation needs a fresh WS-Addressing identity, even without credentials.
        secrets: true,
    };
    let result = runtime::run(request, |scope| {
        let check = || secret_check(scope);
        let credentials = plan
            .credentials
            .as_ref()
            .map(|path| CredentialLease::load(path, &check))
            .transpose()
            .map_err(|error| secret_error(error).code())?;
        let entropy = Some(Entropy::open(&check).map_err(|error| secret_error(error).code())?);
        let owner = Owner {
            scope,
            plan: &plan,
            credentials: credentials.as_ref(),
            entropy: RefCell::new(entropy),
        };
        scope.input()?;
        match fs::symlink_metadata(&plan.root) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Err(INPUT_ERROR),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(INPUT_ERROR),
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-metadata-capture".into(),
            operation_id: OperationId::parse("operation:onvif-metadata-capture")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: plan.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(retained_allowance)
                .storage_operations(8192 + u64::from(plan.config.max_pulls) * 512)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:explicit-metadata-capture".into(),
            anchor_universe: ContentDigest::sha256(plan.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ARGUMENT_ERROR)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, plan.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?;
        let result = (|| {
            scope.output()?;
            let mut deployment = ReferenceDeployment::open(&plan.root, &plan.site, &cx)
                .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?;
            subscription_attempted = true;
            let captured = pullpoint::capture(&plan.config, &owner, |batch| {
                scope.output().map_err(|_| MetadataError::Authority)?;
                let interval = CaptureInterval::new(
                    TimestampNs(
                        plan.receive_origin_ns
                            .checked_add(i128::from(batch.started_ns))
                            .ok_or(MetadataError::InvalidBinding)?,
                    ),
                    TimestampNs(
                        plan.receive_origin_ns
                            .checked_add(i128::from(batch.completed_ns))
                            .ok_or(MetadataError::InvalidBinding)?,
                    ),
                )?;
                let acquisition = PullPointAcquisition {
                    approval: plan.approval,
                    event_route: plan.config.events.digest(),
                    subscription_route: batch.route.digest(),
                    pull_index: batch.pull_index,
                    started_ns: batch.started_ns,
                    completed_ns: batch.completed_ns,
                    client_authenticated: batch.authenticated,
                    subscription_source: ContentDigest::sha256(batch.subscription_response),
                    subscription_source_bytes: batch.subscription_response.len(),
                    subscription_started_ns: batch.subscription_started_ns,
                    subscription_completed_ns: batch.subscription_completed_ns,
                    message_id: batch.message_id.to_owned(),
                    subscription_message_id: batch.subscription_message_id.to_owned(),
                };
                let value = retain_pullpoint(
                    &mut deployment,
                    SourceBinding {
                        sensor_id: plan.sensor.clone(),
                        device_generation: plan.device_generation,
                        profile_generation: plan.profile_generation,
                        profile_token: plan.profile.clone(),
                        receive_interval: interval,
                    },
                    batch.source,
                    acquisition,
                    batch.subscription_response,
                    &cx,
                )?;
                let receipt = RetainedBatch {
                    identity: value.identity(),
                    root: value.publication_root(),
                };
                // This independently owned progress survives a later deadline, failed
                // cleanup or owner finalization refusal. Only definitely committed roots
                // appear here; an indeterminate publication is never reported as absent.
                retained.push(value);
                Ok(receipt)
            });
            match captured {
                Ok(report) => capture_report = Some(report),
                Err(failure) => {
                    capture_error = Some(failure.error.code());
                    capture_report = Some(failure.report);
                }
            }
            Ok(())
        })();
        cx.drain_and_finalize();
        result
    });
    if let Err(code) = result {
        capture_error = Some(code);
    }
    render(
        &plan,
        &retained,
        capture_report.as_ref(),
        capture_error,
        subscription_attempted,
    )
}

fn render(
    plan: &Plan,
    retained: &[RetainedMetadata],
    report: Option<&CaptureReport>,
    error: Option<&'static str>,
    attempted: bool,
) -> Result<(String, bool), &'static str> {
    let mut out = String::new();
    macro_rules! line {
        ($($arg:tt)*) => { writeln!(&mut out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
    }
    let cleanup_error = report.and_then(|report| report.cleanup_error);
    let complete = error.is_none()
        && cleanup_error.is_none()
        && report.is_some_and(|report| {
            matches!(
                report.subscription_state,
                pullpoint::SubscriptionState::Unsubscribed
            )
        });
    line!("operation=capture");
    line!(
        "phase={}",
        if complete { "completed" } else { "incomplete" }
    );
    line!("approval={}", plan.approval);
    line!("source_mode=onvif_pullpoint");
    line!("subscription_scope=device_events");
    line!("profile_attribution_verified=false");
    line!("deadline_scope=network_and_batch_admission");
    line!("server_identity_verified=false");
    line!("transport_encrypted=false");
    line!("vendor_clock_trusted=false");
    line!("coverage_claimed=false");
    line!("absence_claimed=false");
    line!("sensitive_features_enabled=false");
    line!("values_disclosed=false");
    line!("retained_batches={}", retained.len());
    line!("maximum_pulls={}", plan.config.max_pulls);
    line!("error={}", error.unwrap_or("none"));
    line!("cleanup_error={}", cleanup_error.unwrap_or("none"));
    if let Some(report) = report {
        line!("subscription_state={:?}", report.subscription_state);
        line!("stop={:?}", report.stop);
        line!("http_exchanges={}", report.exchanges);
        line!("completed_pulls={}", report.pulls);
        line!("vendor_notifications={}", report.notifications);
        line!(
            "subscription_source_received={}",
            report.subscription_response().is_some()
        );
        line!("subscription_source_retained={}", !retained.is_empty());
        if let Some(source) = report.subscription_response() {
            line!(
                "subscription_source_sha256={}",
                ContentDigest::sha256(source)
            );
            line!("subscription_source_bytes={}", source.len());
        }
        if let Some(message_id) = report.subscription_message_id() {
            line!("subscription_message_id={message_id}");
        }
        if let Some(started) = report.subscription_started_ns() {
            line!("subscription_started_ns={started}");
        }
        if let Some(completed) = report.subscription_completed_ns() {
            line!("subscription_completed_ns={completed}");
        }
    } else {
        line!(
            "subscription_state={}",
            if attempted {
                "Indeterminate"
            } else {
                "NotCreated"
            }
        );
        line!("stop=owner_refused");
    }
    for (index, value) in retained.iter().enumerate() {
        line!("batch.{index}.import_identity={}", value.identity());
        line!(
            "batch.{index}.publication_root={}",
            value.publication_root()
        );
        line!("batch.{index}.source_sha256={}", value.source_digest());
        line!("batch.{index}.source_bytes={}", value.source_bytes());
        line!("batch.{index}.durable_publication=true");
        line!(
            "batch.{index}.notification_count={}",
            value.document().notifications.len()
        );
        line!(
            "batch.{index}.authority_sequence={}",
            value.authority_anchor().commit_sequence
        );
        line!(
            "batch.{index}.received_start_ns={}",
            value.binding().receive_interval.earliest.0
        );
        line!(
            "batch.{index}.received_end_ns={}",
            value.binding().receive_interval.latest.0
        );
    }
    if !retained.is_empty() {
        line!("safe_next=verify_each_exact_import");
    }
    let cleanup_unconfirmed = report.map_or(attempted, |report| {
        matches!(
            report.subscription_state,
            pullpoint::SubscriptionState::Indeterminate | pullpoint::SubscriptionState::Active
        )
    });
    if !complete && cleanup_unconfirmed {
        line!("subscription_reconciliation_required=true");
        line!("automatic_create_retry_safe=false");
    }
    if out.len() > 65536 {
        return Err(LIMIT_ERROR);
    }
    Ok((out, complete))
}
