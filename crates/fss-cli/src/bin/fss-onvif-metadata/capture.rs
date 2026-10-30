#![forbid(unsafe_code)]
//! Request-owned native PullPoint acquisition and durable per-response custody.

#[path = "capture/plan.rs"]
pub(super) mod plan;

#[cfg(test)]
#[path = "capture/operation_tests.rs"]
mod operation_tests;

use std::cell::RefCell;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_reference::onvif::capture_operation::{
    self, CaptureOperationError, CaptureOperationInspection,
};
use fss_reference::onvif::client::{ClientError, OnvifContext};
use fss_reference::onvif::control::{
    CreateIntentBinding, CreateOutcomeBinding, MAX_CATALOG_RECORDS, RenewIntentBinding,
    RenewOutcomeBinding, RetainedCreateIntent, RetainedCreateOutcome, RetainedRenewIntent,
    RetainedRenewal, RetainedSubscription, RetainedUnsubscribe, RetainedUnsubscribeIntent,
    RetainedUnsubscribeOutcome, UnsubscribeBinding, UnsubscribeIntentBinding,
    UnsubscribeOutcomeBinding, inspect_cleanup, prepare_create, prepare_renew, prepare_unsubscribe,
    recover_created, retain_create_outcome, retain_renewal, retain_unsubscribe_outcome,
    retain_unsubscribed,
};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpOperation, HttpRoute};
use fss_reference::onvif::metadata::{
    MetadataError, PullPointAcquisition, RetainedMetadata, SourceBinding, retain_pullpoint,
};
use fss_reference::onvif::pullpoint::{
    self, CaptureReport, PullPointControl, PullPointError, RetainedBatch, RetainedProgress,
    route_in_service_root,
};
use fss_reference::rtsp::authentication::{DigestAuthorization, DigestChallenge};
use fss_reference::{ReferenceDeployment, ReplayAdmission, ReplayCx};

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES, SecretError};
use super::{ARGUMENT_ERROR, INPUT_ERROR, LIMIT_ERROR, admission, runtime};
use plan::Plan;

// Current-state inspection scans at most 1024 small control headers and verifies at most
// 64 cleanup attempts with their parent/source closures. This is a cumulative I/O admission
// ceiling, not an allocation or permission for additional network effects.
pub(super) const CLEANUP_READ_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const CLEANUP_READ_OPERATIONS: u64 = 4 * MAX_CATALOG_RECORDS as u64 + 32;
// Reservation, commitment and terminal reconciliation independently verify durable
// history. This cumulative allowance is separate from source/control custody.
const OPERATION_READ_BYTES: u64 = 8 * capture_operation::MAX_JOURNAL_BYTES;

pub(super) struct Owner<'a, 'scope, 'task> {
    pub(super) scope: &'a runtime::Scope<'scope, 'task>,
    pub(super) plan: &'a Plan,
    pub(super) credentials: Option<&'a CredentialLease>,
    pub(super) entropy: RefCell<Option<Entropy>>,
}

pub(super) fn context_error(code: &'static str) -> ClientError {
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
pub(super) fn secret_error(error: SecretError) -> ClientError {
    match error {
        SecretError::Credentials => ClientError::Credentials,
        SecretError::Entropy => ClientError::Entropy,
        SecretError::Deadline => ClientError::Deadline,
        SecretError::Authority | SecretError::Revoked => ClientError::Authority,
    }
}
pub(super) fn secret_check(scope: &runtime::Scope<'_, '_>) -> Result<(), SecretError> {
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

/// These owned handles outlive request retirement and output failures.
#[derive(Default)]
pub(super) struct ControlReceipts {
    pub(super) operation: Option<CaptureOperationInspection>,
    pub(super) operation_error: Option<&'static str>,
    pub(super) intent: Option<RetainedCreateIntent>,
    pub(super) create_outcome: Option<RetainedCreateOutcome>,
    pub(super) created: Option<RetainedSubscription>,
    pub(super) unsubscribed: Option<RetainedUnsubscribe>,
    pub(super) unsubscribe_intent: Option<RetainedUnsubscribeIntent>,
    pub(super) unsubscribe_outcome: Option<RetainedUnsubscribeOutcome>,
    pub(super) renewal_intents: Vec<RetainedRenewIntent>,
    pub(super) renewal_outcomes: Vec<RetainedRenewal>,
}

/// This is a retained journal snapshot, not a remote-state or capture-success claim.
pub(super) fn operation_report(value: &CaptureOperationInspection) -> String {
    let mut report = format!(
        "capture_operation.internal_id={}\ncapture_operation.journal_root={}\ncapture_operation.snapshot_state={:?}\ncapture_operation.prepared_at_ns={}\ncapture_operation.updated_at_ns={}\ncapture_operation.request_digest={}\ncapture_operation.precondition_digest={}\ncapture_operation.obligation_id={}\ncapture_operation.obligation_state={:?}\ncapture_operation.cleanup_binding_available={}\ncapture_operation.durable_publication=true\ncapture_operation.historical_snapshot=true\ncapture_operation.create_retry_allowed=false\ncapture_operation.remote_dispatch=unknown\n",
        value.internal_operation_id,
        value.journal_root,
        value.receipt.state,
        value.receipt.prepared_at.0,
        value.receipt.updated_at.0,
        value.receipt.intent.request_digest,
        value.receipt.intent.precondition_digest,
        value.obligation_id,
        value.obligation_state,
        value.create_intent.is_some(),
    );
    if let Some(identity) = value.create_intent {
        report.push_str(&format!(
            "capture_operation.create_intent_identity={identity}\n"
        ));
    }
    if let Some(proof) = value.proof_digest {
        report.push_str(&format!("capture_operation.terminal_proof={proof}\n"));
    }
    report
}

impl ControlReceipts {
    fn operation_refused(&mut self, error: CaptureOperationError) -> MetadataError {
        self.operation_error = Some(error.code());
        match error {
            CaptureOperationError::Existing(value) | CaptureOperationError::Conflict(value) => {
                self.operation = Some(*value);
                MetadataError::Authority
            }
            CaptureOperationError::Authority => MetadataError::Authority,
            _ => MetadataError::Custody,
        }
    }

    pub(super) fn successful_cleanup(&self) -> bool {
        self.unsubscribed.is_some()
            || self
                .unsubscribe_outcome
                .as_ref()
                .is_some_and(RetainedUnsubscribeOutcome::success_observed)
    }

    pub(super) fn report(&self) -> String {
        let mut out = String::new();
        if let Some(operation) = &self.operation {
            out.push_str(&operation_report(operation));
        }
        if let Some(code) = self.operation_error {
            out.push_str(&format!(
                "capture_operation.error={code}\nsafe_next=control_operation_inspect\n"
            ));
        }
        for (name, receipt) in [
            (
                "create_intent",
                self.intent
                    .as_ref()
                    .map(|r| (r.identity(), r.publication_root())),
            ),
            (
                "create_outcome",
                self.create_outcome
                    .as_ref()
                    .map(|r| (r.identity(), r.publication_root())),
            ),
            (
                "created_subscription",
                self.created
                    .as_ref()
                    .map(|r| (r.identity(), r.publication_root())),
            ),
            (
                "unsubscribe",
                self.unsubscribed
                    .as_ref()
                    .map(|r| (r.identity(), r.publication_root())),
            ),
            (
                "unsubscribe_intent",
                self.unsubscribe_intent
                    .as_ref()
                    .map(|r| (r.identity(), r.publication_root())),
            ),
            (
                "unsubscribe_outcome",
                self.unsubscribe_outcome
                    .as_ref()
                    .map(|r| (r.identity(), r.publication_root())),
            ),
        ] {
            if let Some((identity, root)) = receipt {
                out.push_str(&format!("{name}.identity={identity}\n{name}.publication_root={root}\n{name}.durable_publication=true\n"));
            }
        }
        if let Some(value) = &self.create_outcome {
            out.push_str(&format!(
                "create_outcome.intent_identity={}\ncreate_outcome.scoped_response_observed={}\ncreate_outcome.http_status={}\ncreate_outcome.completion_time_observed={}\n",
                value.intent().identity(), value.scoped_subscription().is_some(),
                value.binding().http_status, value.binding().completed_ns.is_some()
            ));
        }
        if let Some(value) = &self.unsubscribe_outcome {
            out.push_str(&format!(
                "unsubscribe_outcome.intent_identity={}\nunsubscribe_outcome.success_observed={}\nunsubscribe_outcome.http_status={}\nunsubscribe_outcome.completion_time_observed={}\n",
                value.intent().identity(), value.success_observed(), value.binding().http_status,
                value.binding().completed_ns.is_some()
            ));
        }
        for (index, value) in self.renewal_intents.iter().enumerate() {
            out.push_str(&format!(
                "renewal_intent.{index}.identity={}\nrenewal_intent.{index}.publication_root={}\nrenewal_intent.{index}.durable_publication=true\n",
                value.identity(), value.publication_root()
            ));
        }
        for (index, value) in self.renewal_outcomes.iter().enumerate() {
            out.push_str(&format!(
                "renewal_outcome.{index}.identity={}\nrenewal_outcome.{index}.publication_root={}\nrenewal_outcome.{index}.intent_identity={}\nrenewal_outcome.{index}.durable_publication=true\nrenewal_outcome.{index}.lease_confirmed={}\n",
                value.identity(), value.publication_root(), value.intent().identity(), value.lease().is_some()
            ));
        }
        out
    }
}

pub(super) fn interval(
    plan: &Plan,
    started_ns: u64,
    completed_ns: u64,
) -> Result<CaptureInterval, MetadataError> {
    if completed_ns < started_ns {
        return Err(MetadataError::InvalidBinding);
    }
    Ok(CaptureInterval::new(
        TimestampNs(
            plan.receive_origin_ns
                .checked_add(i128::from(started_ns))
                .ok_or(MetadataError::InvalidBinding)?,
        ),
        TimestampNs(
            plan.receive_origin_ns
                .checked_add(i128::from(completed_ns))
                .ok_or(MetadataError::InvalidBinding)?,
        ),
    )?)
}

pub(super) fn progress<G: ReplayAdmission>(
    cx: &ReplayCx<G>,
    receipt: RetainedBatch,
) -> RetainedProgress {
    RetainedProgress {
        receipt,
        stop: cx
            .admission_refusal()
            .map(|error| PullPointError::Client(context_error(admission::code(error)))),
    }
}

pub(super) fn retain_control<G: ReplayAdmission>(
    deployment: &RefCell<ReferenceDeployment>,
    plan: &Plan,
    receipts: &mut ControlReceipts,
    observation: PullPointControl<'_>,
    cx: &ReplayCx<G>,
    mut commit_now_ns: impl FnMut() -> Result<u64, ClientError>,
) -> Result<RetainedProgress, MetadataError> {
    let mut deployment = deployment
        .try_borrow_mut()
        .map_err(|_| MetadataError::Authority)?;
    let (receipt, dispatch_allowed) = match observation {
        PullPointControl::CreateIntent {
            events,
            service_root,
            message_id,
            started_ns,
            lifetime_seconds,
        } => {
            let create = CreateIntentBinding {
                source: SourceBinding {
                    sensor_id: plan.sensor.clone(),
                    device_generation: plan.device_generation,
                    profile_generation: plan.profile_generation,
                    profile_token: plan.profile.clone(),
                    receive_interval: interval(plan, started_ns, started_ns)?,
                },
                events: events.clone(),
                service_root: service_root.to_owned(),
                message_id: message_id.to_owned(),
                started_ns,
                lifetime_seconds,
            };
            // Reserve the stable owner operation before retaining a fresh wire intent.
            // Every existing journal state consumes the ID; only this live guard may
            // commit once, after exact Create intent custody and before network I/O.
            let operation = if let Some(binding) = &plan.operation {
                let now = interval(plan, started_ns, started_ns)?.earliest;
                let guard = capture_operation::reserve_for_create(
                    &mut deployment,
                    binding,
                    &create,
                    now,
                    cx,
                )
                .map_err(|error| receipts.operation_refused(error))?;
                receipts.operation = Some(guard.prepared().clone());
                Some(guard)
            } else {
                None
            };
            let value = prepare_create(&mut deployment, create, cx)?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            let dispatch_allowed = value.newly_prepared();
            receipts.intent = Some(value);
            if dispatch_allowed {
                if let Some(guard) = operation {
                    // Preparation uses the observed request start; commitment needs
                    // a fresh observation after custody work, never a fabricated tick.
                    let observed_now = commit_now_ns().map_err(|_| MetadataError::Authority)?;
                    let now = interval(plan, started_ns, observed_now)?.latest;
                    let committed = guard
                        .commit_with_intent(
                            &mut deployment,
                            receipts.intent.as_ref().ok_or(MetadataError::Custody)?,
                            now,
                            cx,
                        )
                        .map_err(|error| receipts.operation_refused(error))?;
                    receipts.operation = Some(committed);
                }
            }
            (receipt, dispatch_allowed)
        }
        PullPointControl::CreateOutcome {
            source,
            message_id,
            started_ns,
            completed_ns,
            authenticated,
            http_status,
            soap_content_type,
        } => {
            let intent = receipts.intent.as_ref().ok_or(MetadataError::Custody)?;
            if intent.binding().message_id != message_id
                || intent.binding().started_ns != started_ns
            {
                return Err(MetadataError::Custody);
            }
            let value = retain_create_outcome(
                &mut deployment,
                intent,
                CreateOutcomeBinding {
                    completed_ns,
                    client_authenticated: authenticated,
                    http_status,
                    soap_content_type,
                },
                source,
                cx,
            )?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            receipts.create_outcome = Some(value);
            (receipt, true)
        }
        PullPointControl::Created {
            source,
            message_id,
            started_ns,
            completed_ns,
            authenticated,
        } => {
            let outcome = receipts
                .create_outcome
                .as_ref()
                .ok_or(MetadataError::Custody)?;
            let intent = receipts.intent.as_ref().ok_or(MetadataError::Custody)?;
            if outcome.intent().identity() != intent.identity()
                || outcome.intent().publication_root() != intent.publication_root()
                || outcome.intent().binding().message_id != message_id
                || outcome.intent().binding().started_ns != started_ns
                || outcome.binding().completed_ns != Some(completed_ns)
                || outcome.binding().client_authenticated != authenticated
                || outcome.source() != source
                || outcome.scoped_subscription().is_none()
            {
                return Err(MetadataError::Custody);
            }
            let value = recover_created(&mut deployment, outcome, cx)?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            receipts.created = Some(value);
            (receipt, true)
        }
        PullPointControl::UnsubscribeIntent {
            route,
            message_id,
            create_message_id,
            request_digest,
            started_ns,
        } => {
            let created = receipts.created.as_ref().ok_or(MetadataError::Custody)?;
            let expected_control = match plan.cleanup_expected_control {
                Some(expected) => expected,
                None => inspect_cleanup(&deployment, created, cx)?.witness,
            };
            let value = prepare_unsubscribe(
                &mut deployment,
                created,
                UnsubscribeIntentBinding {
                    route: route.clone(),
                    create_message_id: create_message_id.to_owned(),
                    message_id: message_id.to_owned(),
                    request_digest,
                    started_ns,
                    receive_time: interval(plan, started_ns, started_ns)?.earliest,
                    expected_control,
                },
                cx,
            )?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            let dispatch_allowed = value.newly_prepared();
            receipts.unsubscribe_intent = Some(value);
            (receipt, dispatch_allowed)
        }
        PullPointControl::UnsubscribeOutcome {
            route,
            source,
            message_id,
            started_ns,
            completed_ns,
            authenticated,
            http_status,
            soap_content_type,
        } => {
            let intent = receipts
                .unsubscribe_intent
                .as_ref()
                .ok_or(MetadataError::Custody)?;
            if intent.binding().message_id != message_id
                || intent.binding().started_ns != started_ns
                || intent.binding().route.digest() != route.digest()
            {
                return Err(MetadataError::Custody);
            }
            let value = retain_unsubscribe_outcome(
                &mut deployment,
                intent,
                UnsubscribeOutcomeBinding {
                    completed_ns,
                    client_authenticated: authenticated,
                    http_status,
                    soap_content_type,
                },
                source,
                cx,
            )?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            receipts.unsubscribe_outcome = Some(value);
            (receipt, true)
        }
        PullPointControl::Unsubscribed {
            route,
            source,
            message_id,
            started_ns,
            completed_ns,
            authenticated,
        } => {
            let value = retain_unsubscribed(
                &mut deployment,
                receipts.created.as_ref().ok_or(MetadataError::Custody)?,
                UnsubscribeBinding {
                    route: route.clone(),
                    message_id: message_id.to_owned(),
                    started_ns,
                    completed_ns,
                    receive_interval: interval(plan, started_ns, completed_ns)?,
                    client_authenticated: authenticated,
                },
                source,
                cx,
            )?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            receipts.unsubscribed = Some(value);
            if let Some(binding) = &plan.operation {
                let evidence = capture_operation::CaptureCleanupEvidence::Unsubscribed {
                    identity: receipt.identity,
                    root: receipt.root,
                };
                let reconciled = capture_operation::reconcile_cleanup(
                    &mut deployment,
                    &binding.operation_id,
                    evidence,
                    None,
                    || {
                        let observed =
                            commit_now_ns().map_err(|_| CaptureOperationError::Authority)?;
                        let now = plan
                            .receive_origin_ns
                            .checked_add(i128::from(observed))
                            .ok_or(CaptureOperationError::InvalidBinding)?;
                        Ok(TimestampNs(now))
                    },
                    cx,
                )
                .map_err(|error| receipts.operation_refused(error))?;
                receipts.operation = Some(reconciled);
            }
            (receipt, true)
        }
        PullPointControl::RenewIntent {
            route,
            message_id,
            started_ns,
            lifetime_seconds,
            renewal_index,
        } => {
            let value = prepare_renew(
                &mut deployment,
                receipts.created.as_ref().ok_or(MetadataError::Custody)?,
                RenewIntentBinding {
                    route: route.clone(),
                    message_id: message_id.to_owned(),
                    started_ns,
                    receive_time: interval(plan, started_ns, started_ns)?.earliest,
                    lifetime_seconds,
                    renewal_index,
                },
                cx,
            )?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            let dispatch_allowed = value.newly_prepared();
            receipts.renewal_intents.push(value);
            (receipt, dispatch_allowed)
        }
        PullPointControl::Renewed {
            source,
            message_id,
            completed_ns,
            authenticated,
            http_status,
            soap_content_type,
        } => {
            let intent = receipts
                .renewal_intents
                .last()
                .ok_or(MetadataError::Custody)?;
            if intent.binding().message_id != message_id {
                return Err(MetadataError::Custody);
            }
            let value = retain_renewal(
                &mut deployment,
                intent,
                RenewOutcomeBinding {
                    completed_ns,
                    client_authenticated: authenticated,
                    http_status,
                    soap_content_type,
                },
                source,
                cx,
            )?;
            let receipt = RetainedBatch {
                identity: value.identity(),
                root: value.publication_root(),
            };
            receipts.renewal_outcomes.push(value);
            (receipt, true)
        }
    };
    let mut result = progress(cx, receipt);
    // Existing storage proves an old intent; it never grants a new remote dispatch.
    if !dispatch_allowed && result.stop.is_none() {
        result.stop = Some(PullPointError::Retention(MetadataError::Authority));
    }
    Ok(result)
}

pub(super) fn storage_allowance(operations: u64) -> u64 {
    operations * super::STORAGE_CHECKPOINT_ALLOWANCE
}

pub(super) fn storage_authority(
    plan: &Plan,
    bytes: u64,
    operations: u64,
) -> Result<ContextAuthority, &'static str> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:onvif-metadata-control".into(),
        operation_id: OperationId::parse("operation:onvif-metadata-control")
            .map_err(|_| ARGUMENT_ERROR)?,
        principal: plan.principal.clone(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(bytes)
            .storage_operations(storage_allowance(operations))
            .build()
            .map_err(|_| LIMIT_ERROR)?,
        privacy_scope: "privacy:owner-private-vendor-metadata".into(),
        retention_scope: "retention:explicit-metadata-control".into(),
        anchor_universe: ContentDigest::sha256(plan.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| ARGUMENT_ERROR)
}

pub(super) fn run_args(args: &[OsString]) -> Result<(String, bool), &'static str> {
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help")) {
        return Ok((plan::HELP.to_owned(), true));
    }
    let plan = Plan::parse(args)?;
    let exchanges =
        2 * (u64::from(plan.config.max_pulls) + u64::from(plan.config.max_renewals) + 2);
    let network =
        exchanges * (plan.config.limits.request_bytes + plan.config.limits.wire_bytes) as u64;
    let publications =
        u64::from(plan.config.max_pulls) + 2 * u64::from(plan.config.max_renewals) + 6;
    let operations =
        publications + CLEANUP_READ_OPERATIONS + if plan.operation.is_some() { 16 } else { 0 };
    let retained_allowance = publications * 4 * 1024 * 1024
        + CLEANUP_READ_BYTES
        + if plan.operation.is_some() {
            OPERATION_READ_BYTES
        } else {
            0
        };
    let mut retained = Vec::<RetainedMetadata>::new();
    let mut controls = ControlReceipts::default();
    let mut capture_report = None::<CaptureReport>;
    let mut capture_error = None;
    let mut subscription_attempted = false;
    let request = runtime::Request {
        approval: plan.approval,
        principal: plan.principal.clone(),
        timeout_ns: plan.config.deadline_ns,
        bytes: network + retained_allowance + MAX_CREDENTIAL_BYTES as u64 + 65536,
        network_bytes: network,
        storage_operations: storage_allowance(operations) + u64::from(plan.config.max_steps) * 64,
        network: true,
        write: true,
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
        let authority = storage_authority(&plan, retained_allowance, operations)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, plan.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = (|| {
            scope.output()?;
            let deployment = RefCell::new(
                ReferenceDeployment::open(&plan.root, &plan.site, &cx)
                    .map_err(|_| "ERR-ONVIF-METADATA-PUBLICATION-001")?,
            );
            subscription_attempted = true;
            let captured = pullpoint::capture_with_progress(
                &plan.config,
                &owner,
                |observation| {
                    retain_control(&deployment, &plan, &mut controls, observation, &cx, || {
                        scope.now().map_err(context_error)
                    })
                },
                |batch| {
                    scope.output().map_err(|_| MetadataError::Authority)?;
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
                    let mut owner_deployment = deployment
                        .try_borrow_mut()
                        .map_err(|_| MetadataError::Authority)?;
                    let value = retain_pullpoint(
                        &mut owner_deployment,
                        SourceBinding {
                            sensor_id: plan.sensor.clone(),
                            device_generation: plan.device_generation,
                            profile_generation: plan.profile_generation,
                            profile_token: plan.profile.clone(),
                            receive_interval: interval(
                                &plan,
                                batch.started_ns,
                                batch.completed_ns,
                            )?,
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
                    retained.push(value);
                    Ok(progress(&cx, receipt))
                },
            );
            match captured {
                Ok(report) => capture_report = Some(report),
                Err(failure) => {
                    capture_error = Some(controls.operation_error.unwrap_or(failure.error.code()));
                    capture_report = Some(failure.report);
                }
            }
            Ok(())
        })();
        let owner_error = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        owner_error.map_or(result, Err)
    });
    if let Err(code) = result {
        capture_error = Some(code);
    }
    render(
        &plan,
        &retained,
        &controls,
        capture_report.as_ref(),
        capture_error,
        subscription_attempted,
    )
}

fn render(
    plan: &Plan,
    retained: &[RetainedMetadata],
    controls: &ControlReceipts,
    report: Option<&CaptureReport>,
    error: Option<&'static str>,
    attempted: bool,
) -> Result<(String, bool), &'static str> {
    let mut out = String::new();
    macro_rules! line {
        ($($arg:tt)*) => { writeln!(&mut out, $($arg)*).map_err(|_| LIMIT_ERROR)? };
    }
    let cleanup_error = report.and_then(|report| report.cleanup_error);
    let complete = controls.successful_cleanup()
        && error.is_none()
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
    line!("operation_fence_enabled={}", plan.operation.is_some());
    if let Some(binding) = &plan.operation {
        line!(
            "capture_operation.requested_internal_id={}",
            capture_operation::operation_key(&plan.site, &binding.operation_id)
                .map_err(|_| ARGUMENT_ERROR)?
        );
    }
    line!("subscription_scope=device_events");
    line!("profile_attribution_verified=false");
    line!("deadline_scope=network_and_cooperative_storage_checkpoints");
    line!("server_identity_verified=false");
    line!("transport_encrypted=false");
    line!("vendor_clock_trusted=false");
    line!("coverage_claimed=false");
    line!("absence_claimed=false");
    line!("current_remote_state=unknown");
    line!("automatic_create_retry_safe=false");
    line!("automatic_renew_retry_safe=false");
    line!("automatic_unsubscribe_retry_safe=false");
    line!("sensitive_features_enabled=false");
    line!("values_disclosed=false");
    out.push_str(&controls.report());
    line!("retained_batches={}", retained.len());
    line!("maximum_pulls={}", plan.config.max_pulls);
    line!("maximum_renewals={}", plan.config.max_renewals);
    line!(
        "retained_renewal_intents={}",
        controls.renewal_intents.len()
    );
    line!(
        "retained_renewal_outcomes={}",
        controls.renewal_outcomes.len()
    );
    line!("error={}", error.unwrap_or("none"));
    line!("cleanup_error={}", cleanup_error.unwrap_or("none"));
    if let Some(report) = report {
        line!("subscription_state={:?}", report.subscription_state);
        line!("stop={:?}", report.stop);
        line!("http_exchanges={}", report.exchanges);
        line!("completed_pulls={}", report.pulls);
        line!("completed_renewals={}", report.renewals);
        line!("vendor_notifications={}", report.notifications);
        line!(
            "subscription_source_received={}",
            report.subscription_response().is_some()
        );
        line!(
            "subscription_source_retained={}",
            controls.create_outcome.is_some() || controls.created.is_some() || !retained.is_empty()
        );
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
        line!("safe_next=verify_each_exact_import_and_inspect_control_receipts");
    }
    let cleanup_unconfirmed = report.map_or(attempted, |report| {
        matches!(
            report.subscription_state,
            pullpoint::SubscriptionState::Indeterminate | pullpoint::SubscriptionState::Active
        )
    });
    if !complete && cleanup_unconfirmed {
        line!("subscription_reconciliation_required=true");
        let next = if controls.created.is_some() {
            "control_list_then_inspect_then_explicit_unsubscribe"
        } else if let Some(outcome) = &controls.create_outcome {
            if outcome.scoped_subscription().is_some() {
                "control_inspect_create_outcome_then_explicit_recover_created"
            } else {
                "control_inspect_create_outcome_then_owner_device_reconciliation"
            }
        } else {
            "control_inspect_intent_then_owner_device_reconciliation_no_create_retry"
        };
        line!("safe_next={next}");
    }
    if out.len() > 65536 {
        return Err(LIMIT_ERROR);
    }
    Ok((out, complete))
}
