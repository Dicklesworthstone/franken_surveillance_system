#![forbid(unsafe_code)]
//! Shared native custody owner for session-backed retained supervision.
//!
//! The companion CLI and AOP-006 execute the same finite evaluator. Recovery cannot register
//! a subscription, substitute a recipe, refill work, disclose a report or grant source access.

use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm, LedgerAnchor, PrincipalId};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::agent_session::checkpoint::journal::supervision::{
    PendingSupervisionDelivery, SupervisionDetectionSourcePin, SupervisionRegistration,
    SupervisionSourcePin,
};
use fss_reference::deployment_session::supervision::{
    GuardedSupervisionDelivery, SupervisionAction, SupervisionAdapterError, SupervisionEvaluation,
    SupervisionEvaluator, SupervisionRecoveryBinding, SupervisionRecoveryBoundary,
    SupervisionRecoveryControl, SupervisionRecoveryRequest, SupervisionSessionBinding,
    SupervisionSessionBoundary, SupervisionSessionControl, SupervisionSessionDelivery,
    SupervisionSessionError, SupervisionSessionFailure, SupervisionSessionOutcome,
    SupervisionSessionRequest, SupervisionValidation, recover_supervision_registration,
    supervise_existing_session, supervise_existing_session_at, supervise_session,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{
    MAX_RETAINED_SUPERVISOR_PLAN_BYTES, RETAINED_DETECTION_REPORT_SCHEMA,
    RETAINED_DETECTION_REQUEST_SCHEMA, RETAINED_DISCOVERY_REPORT_SCHEMA,
    RETAINED_DISCOVERY_REQUEST_SCHEMA, RetainedDetectionRequest, RetainedDetectionSource,
    RetainedDiscoveryRequest, RetainedDiscoverySource, RetainedSupervisorError,
    RetainedSupervisorPlan, revalidate_detection_sources, revalidate_retained_discovery_sources,
    run_discovered_detection_supervisor, run_discovered_retained_supervisor,
};
use crate::ERR_CLI_RUNTIME_FAILURE;
use crate::json_input;

const ENVELOPE_BYTES: usize = 16 * 1024;

/// The immutable registered configuration selects its native owner; source identities never
/// cross between event discovery and direct detector discovery.
#[derive(Clone, Debug)]
pub enum NativeSupervisionRequest {
    /// Published package-event discovery.
    Event(RetainedDiscoveryRequest),
    /// Native detector-record discovery without a fabricated event.
    Detection(RetainedDetectionRequest),
}

impl NativeSupervisionRequest {
    pub fn template(&self) -> &RetainedSupervisorPlan {
        match self {
            Self::Event(request) => request.template(),
            Self::Detection(request) => request.template(),
        }
    }

    pub fn digest(&self) -> ContentDigest {
        match self {
            Self::Event(request) => request.digest(),
            Self::Detection(request) => request.digest(),
        }
    }

    pub fn for_authority(
        &self,
        authority: ContentDigest,
    ) -> std::result::Result<Self, RetainedSupervisorError> {
        match self {
            Self::Event(request) => request.for_authority(authority).map(Self::Event),
            Self::Detection(request) => request.for_authority(authority).map(Self::Detection),
        }
    }

    pub fn for_window_prefix(
        &self,
        count: usize,
    ) -> std::result::Result<Self, RetainedSupervisorError> {
        match self {
            Self::Event(request) => request.for_window_prefix(count).map(Self::Event),
            Self::Detection(request) => request.for_window_prefix(count).map(Self::Detection),
        }
    }

    pub const fn report_schema(&self) -> &'static str {
        match self {
            Self::Event(_) => RETAINED_DISCOVERY_REPORT_SCHEMA,
            Self::Detection(_) => RETAINED_DETECTION_REPORT_SCHEMA,
        }
    }

    pub const fn report_authority_field(&self) -> &'static str {
        match self {
            Self::Event(_) => "expected_authority_root",
            Self::Detection(_) => "authority_state_root",
        }
    }

    /// Select only a known native dialect after checking the complete stored configuration.
    /// Each existing strict owner then validates its full schema and all immutable limits.
    pub fn from_configuration(
        bytes: &[u8],
        expected: ContentDigest,
    ) -> std::result::Result<Self, RetainedSupervisorError> {
        if bytes.is_empty() || bytes.len() > MAX_RETAINED_SUPERVISOR_PLAN_BYTES {
            return Err(RetainedSupervisorError::Limit(
                "stored native configuration bytes",
            ));
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(RetainedSupervisorError::Plan(
                "stored native configuration byte digest",
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| RetainedSupervisorError::Plan("stored native configuration UTF-8"))?;
        let document = crate::json_input::parse(text)
            .map_err(|_| RetainedSupervisorError::Plan("stored native configuration JSON"))?;
        let schema = document
            .object()
            .and_then(|fields| fields.get("schema"))
            .and_then(crate::json_input::Value::text);
        match schema {
            Some(RETAINED_DISCOVERY_REQUEST_SCHEMA) => {
                RetainedDiscoveryRequest::from_json(bytes, expected).map(Self::Event)
            }
            Some(RETAINED_DETECTION_REQUEST_SCHEMA) => {
                RetainedDetectionRequest::from_json(bytes, expected).map(Self::Detection)
            }
            _ => Err(RetainedSupervisorError::Plan(
                "stored native configuration schema",
            )),
        }
    }
}

fn runtime_error(error: impl std::fmt::Display) -> SupervisionAdapterError {
    SupervisionAdapterError {
        identity: ERR_CLI_RUNTIME_FAILURE,
        reason: error.to_string(),
    }
}

fn source_error(error: RetainedSupervisorError) -> SupervisionAdapterError {
    SupervisionAdapterError {
        identity: error.stable_id(),
        reason: error.to_string(),
    }
}

struct RecoveryControl<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a SupervisionRecoveryRequest,
    limits: OrientLimits,
    cx: &'a ReplayCx,
    boundaries: u32,
}

impl SupervisionRecoveryControl for RecoveryControl<'_> {
    fn admit_recovery(
        &mut self,
        binding: &SupervisionRecoveryBinding<'_>,
        _: SupervisionRecoveryBoundary,
    ) -> std::result::Result<(), SupervisionAdapterError> {
        if binding.root() != self.root
            || binding.principal() != self.principal
            || binding.request() != self.request
            || binding.limits() != &self.limits
            || self.cx.root_dir() != self.root
        {
            return Err(runtime_error("supervision recovery binding differs"));
        }
        self.boundaries = self
            .boundaries
            .checked_add(1)
            .ok_or_else(|| runtime_error("supervision recovery boundary budget exhausted"))?;
        if self.boundaries > 16 {
            return Err(runtime_error(
                "supervision recovery boundary budget exhausted",
            ));
        }
        self.cx
            .checkpoint("retained_supervisor_session:recover")
            .map_err(runtime_error)
    }
}

pub fn scoped_request(
    original: &NativeSupervisionRequest,
    authority: ContentDigest,
    count: Option<u32>,
) -> std::result::Result<NativeSupervisionRequest, SupervisionAdapterError> {
    let request = match count {
        Some(count) => original
            .for_window_prefix(count as usize)
            .map_err(source_error)?,
        None => original.clone(),
    };
    request.for_authority(authority).map_err(source_error)
}

/// Admit the exact complete report before publication, then repeat the same check on release.
/// This prevents a successfully stored report from being permanently unrenderable on retry.
pub fn checked_payload<'a>(
    payload: &'a [u8],
    expected_root: ContentDigest,
    request_digest: ContentDigest,
    report_receipt: ContentDigest,
    payload_digest: ContentDigest,
    expected_schema: &str,
    authority_field: &str,
) -> std::result::Result<&'a str, SupervisionAdapterError> {
    let text = std::str::from_utf8(payload).map_err(runtime_error)?;
    let parsed = json_input::parse_retained_supervisor_report(text).map_err(runtime_error)?;
    let fields = parsed
        .object()
        .ok_or_else(|| runtime_error("stored report must be an object"))?;
    let value = |key| fields.get(key).and_then(json_input::Value::text);
    if value("schema") != Some(expected_schema)
        || value("receipt_digest") != Some(report_receipt.to_text().as_str())
        || value(authority_field) != Some(expected_root.to_text().as_str())
        || value("request_digest") != Some(request_digest.to_text().as_str())
        || ContentDigest::sha256(payload) != payload_digest
    {
        return Err(runtime_error("complete retained report binding differs"));
    }
    Ok(text)
}

/// Local OS/root access is explicit; durable grants and leases remain owned by the session.
/// Every operation is additionally admitted through the invocation's owned ReplayCx.
struct NativeEvaluator<'a> {
    root: &'a Path,
    site: &'a str,
    principal: &'a PrincipalId,
    command: &'a SupervisionSessionRequest,
    request: &'a NativeSupervisionRequest,
    limits: OrientLimits,
    cx: &'a ReplayCx,
    boundaries: u32,
}

impl NativeEvaluator<'_> {
    fn admit_scope(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
    ) -> std::result::Result<(), SupervisionAdapterError> {
        if binding.root() != self.root
            || binding.principal() != self.principal
            || binding.request() != self.command
            || binding.limits() != &self.limits
            || self.cx.root_dir() != self.root
            || binding.active_window_count().is_some_and(|count| {
                count == 0 || count as usize > self.request.template().spec().windows.len()
            })
            || matches!(self.command.action,
                SupervisionAction::ConfigureSchedule { total_windows }
                    if total_windows as usize != self.request.template().spec().windows.len())
        {
            return Err(runtime_error("supervision operation binding differs"));
        }
        self.boundaries = self
            .boundaries
            .checked_add(1)
            .ok_or_else(|| runtime_error("supervision boundary budget exhausted"))?;
        if self.boundaries > 24 {
            return Err(runtime_error("supervision boundary budget exhausted"));
        }
        self.cx
            .checkpoint("retained_supervisor_session:admit")
            .map_err(runtime_error)
    }
}

impl SupervisionSessionControl for NativeEvaluator<'_> {
    fn admit_session(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        _: SupervisionSessionBoundary,
    ) -> std::result::Result<(), SupervisionAdapterError> {
        self.admit_scope(binding)
    }
}

impl SupervisionEvaluator for NativeEvaluator<'_> {
    fn evaluate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
    ) -> std::result::Result<SupervisionEvaluation, SupervisionAdapterError> {
        self.admit_scope(binding)?;
        let request = scoped_request(
            self.request,
            anchor.state_root,
            binding.active_window_count(),
        )?;
        // The deployment owner has already committed and pinned the full-cap reservation.
        let mut deployment =
            ReferenceDeployment::open(self.root, self.site, self.cx).map_err(runtime_error)?;
        let evaluation = match &request {
            NativeSupervisionRequest::Event(request) => {
                let report = run_discovered_retained_supervisor(&mut deployment, request, self.cx)
                    .map_err(source_error)?;
                let sources = report
                    .source_inventory()
                    .map_err(source_error)?
                    .into_iter()
                    .map(|source| SupervisionSourcePin {
                        event_id: source.event_id,
                        event_root: source.event_root,
                        source_verified: source.source_verified,
                        health_digest: source.health_digest,
                    })
                    .collect();
                SupervisionEvaluation {
                    basis: report.supervision().basis().clone(),
                    payload: report.to_json().map_err(source_error)?.into_bytes(),
                    report_receipt: report.digest(),
                    sources,
                    detection_sources: Vec::new(),
                }
            }
            NativeSupervisionRequest::Detection(request) => {
                let report = run_discovered_detection_supervisor(&mut deployment, request, self.cx)
                    .map_err(source_error)?;
                let detection_sources = report
                    .source_inventory()
                    .map_err(source_error)?
                    .into_iter()
                    .map(|source| SupervisionDetectionSourcePin {
                        report_digest: source.report_digest,
                        record_digest: source.record_digest,
                        detection_root: source.detection_root,
                        source_verified: source.source_verified,
                        health_digest: source.health_digest,
                    })
                    .collect();
                SupervisionEvaluation {
                    basis: report.basis().clone(),
                    payload: report.to_json().map_err(source_error)?.into_bytes(),
                    report_receipt: report.digest(),
                    sources: Vec::new(),
                    detection_sources,
                }
            }
        };
        if evaluation
            .payload
            .len()
            .checked_add(ENVELOPE_BYTES)
            .is_none_or(|len| len > self.command.registration.max_report_bytes)
        {
            return Err(source_error(RetainedSupervisorError::Limit(
                "complete session report bytes",
            )));
        }
        checked_payload(
            &evaluation.payload,
            anchor.state_root,
            request.digest(),
            evaluation.report_receipt,
            ContentDigest::sha256(&evaluation.payload),
            request.report_schema(),
            request.report_authority_field(),
        )?;
        Ok(evaluation)
    }

    fn revalidate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
        pending: &PendingSupervisionDelivery,
    ) -> std::result::Result<SupervisionValidation, SupervisionAdapterError> {
        self.admit_scope(binding)?;
        if pending
            .payload_len()
            .checked_add(ENVELOPE_BYTES)
            .is_none_or(|len| len > self.command.registration.max_report_bytes)
        {
            return Err(source_error(RetainedSupervisorError::Limit(
                "complete session report bytes",
            )));
        }
        // A pending report's health digest binds its originally selected rows. Future schedule
        // advancement must never enlarge that historical inventory during release or ACK.
        let request = scoped_request(
            self.request,
            anchor.state_root,
            pending.active_window_count(),
        )?;
        match &request {
            NativeSupervisionRequest::Event(_)
                if !pending.detection_source_inventory().is_empty() =>
            {
                return Err(runtime_error(
                    "event discovery cannot validate native detector source pins",
                ));
            }
            NativeSupervisionRequest::Detection(_) if !pending.source_inventory().is_empty() => {
                return Err(runtime_error(
                    "direct detection cannot validate package-event source pins",
                ));
            }
            _ => {}
        }
        let mut deployment =
            ReferenceDeployment::open(self.root, self.site, self.cx).map_err(runtime_error)?;
        match &request {
            NativeSupervisionRequest::Event(request) => {
                let sources: Vec<_> = pending
                    .source_inventory()
                    .iter()
                    .map(|source| RetainedDiscoverySource {
                        event_id: source.event_id.clone(),
                        event_root: source.event_root,
                        source_verified: source.source_verified,
                        health_digest: source.health_digest,
                    })
                    .collect();
                let validation = revalidate_retained_discovery_sources(
                    &mut deployment,
                    request,
                    &sources,
                    self.cx,
                )
                .map_err(source_error)?;
                Ok(SupervisionValidation {
                    basis: validation.basis().clone(),
                    receipt: validation.digest(),
                    reserved_bytes: validation.reserved_bytes(),
                    read_attempts: validation.read_attempts(),
                })
            }
            NativeSupervisionRequest::Detection(request) => {
                let sources: Vec<_> = pending
                    .detection_source_inventory()
                    .iter()
                    .map(|source| RetainedDetectionSource {
                        report_digest: source.report_digest,
                        record_digest: source.record_digest,
                        detection_root: source.detection_root,
                        source_verified: source.source_verified,
                        health_digest: source.health_digest,
                    })
                    .collect();
                let validation =
                    revalidate_detection_sources(&mut deployment, request, &sources, self.cx)
                        .map_err(source_error)?;
                Ok(SupervisionValidation {
                    basis: validation.basis().clone(),
                    receipt: validation.digest(),
                    reserved_bytes: validation.reserved_bytes(),
                    read_attempts: validation.read_attempts(),
                })
            }
        }
    }
}

/// Recover an existing exact recipe under its live owner, without reserving or disclosing source.
/// The stored configuration is admitted by the original strict native parser after recovery.
pub fn recover_native_supervision(
    root: &Path,
    principal: &PrincipalId,
    request: &SupervisionRecoveryRequest,
    cx: &ReplayCx,
) -> Result<(NativeSupervisionRequest, SupervisionRegistration), SupervisionSessionError> {
    let limits = OrientLimits {
        max_journal_bytes: 32 * 1024 * 1024,
        ..OrientLimits::default()
    };
    let mut control = RecoveryControl {
        root,
        principal,
        request,
        limits,
        cx,
        boundaries: 0,
    };
    let registration =
        recover_supervision_registration(root, principal, request, &limits, &mut control)?;
    let native = NativeSupervisionRequest::from_configuration(
        &registration.configuration,
        registration.configuration_digest,
    )
    .map_err(|error| SupervisionSessionError::Evaluation(source_error(error)))?;
    Ok((native, registration))
}

/// Run exactly one registered action through the shared session and source owners.
/// `existing_only` is mandatory for recovered callers: an absent subscription never re-registers.
/// All stored bounds, the recipe bytes and native profile are compared before native work.
pub fn execute_native_supervision(
    root: &Path,
    principal: &PrincipalId,
    command: &SupervisionSessionRequest,
    request: &NativeSupervisionRequest,
    existing_only: bool,
    cx: &ReplayCx,
) -> Result<SupervisionSessionDelivery, SupervisionSessionFailure> {
    let orient_limits = native_session_limits(command, request)?;
    let mut evaluator = NativeEvaluator {
        root,
        site: &request.template().spec().site_lineage,
        principal,
        command,
        request,
        limits: orient_limits,
        cx,
        boundaries: 0,
    };
    if existing_only {
        supervise_existing_session(root, principal, command, &orient_limits, &mut evaluator)
            .map_err(|failure| *failure)
    } else {
        supervise_session(root, principal, command, &orient_limits, &mut evaluator)
            .map_err(|failure| *failure)
    }
}

/// Existing native work with an explicit pre-work state, enforced under the journal lock.
/// The sealed result lets a later case citation prove that the guard was actually consumed.
pub fn execute_native_supervision_at(
    root: &Path,
    principal: &PrincipalId,
    command: &SupervisionSessionRequest,
    request: &NativeSupervisionRequest,
    expected_subscription_state: ContentDigest,
    cx: &ReplayCx,
) -> Result<GuardedSupervisionDelivery, SupervisionSessionFailure> {
    let orient_limits = native_session_limits(command, request)?;
    let mut evaluator = NativeEvaluator {
        root,
        site: &request.template().spec().site_lineage,
        principal,
        command,
        request,
        limits: orient_limits,
        cx,
        boundaries: 0,
    };
    supervise_existing_session_at(
        root,
        principal,
        command,
        expected_subscription_state,
        &orient_limits,
        &mut evaluator,
    )
    .map_err(|failure| *failure)
}

fn native_session_limits(
    command: &SupervisionSessionRequest,
    request: &NativeSupervisionRequest,
) -> Result<OrientLimits, SupervisionSessionFailure> {
    let limits = request.template().spec().limits;
    let valid = NativeSupervisionRequest::from_configuration(
        &command.registration.configuration,
        command.registration.configuration_digest,
    )
    .is_ok_and(|stored| stored.digest() == request.digest())
        && command.registration.max_read_bytes == limits.max_read_bytes
        && command.registration.max_read_attempts == limits.max_read_attempts
        && command.registration.max_report_bytes == limits.max_report_bytes;
    if !valid {
        return Err(SupervisionSessionFailure {
            error: SupervisionSessionError::InvalidRequest,
            head: None,
            attempts_reserved: 0,
            acknowledged: None,
            discarded: None,
            configured_windows: None,
            advanced: None,
            journal_may_have_changed: false,
        });
    }
    Ok(OrientLimits {
        max_journal_bytes: limits.max_journal_bytes,
        ..OrientLimits::default()
    })
}

/// Parse only the exact already released historical report, never an unvalidated journal payload.
/// Metadata-only actions have no report. The owning native dialect and every custody identity
/// are rechecked before a transport-specific decision projection can inspect the JSON tree.
pub fn released_report(
    delivery: &SupervisionSessionDelivery,
    original: &NativeSupervisionRequest,
) -> Result<Option<json_input::Value>, SupervisionAdapterError> {
    let SupervisionSessionOutcome::Report {
        payload, pending, ..
    } = &delivery.outcome
    else {
        return Ok(None);
    };
    let request = scoped_request(
        original,
        pending.anchor().state_root,
        pending.active_window_count(),
    )?;
    let text = checked_payload(
        payload,
        pending.anchor().state_root,
        request.digest(),
        pending.report_receipt(),
        pending.payload_digest(),
        request.report_schema(),
        request.report_authority_field(),
    )?;
    json_input::parse_retained_supervisor_report(text)
        .map(Some)
        .map_err(runtime_error)
}
