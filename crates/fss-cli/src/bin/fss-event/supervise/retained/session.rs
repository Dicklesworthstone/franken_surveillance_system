#![forbid(unsafe_code)]
//! Existing session-journal composition for finite native supervision and exact pending delivery.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use fss_cli::agent_json::{object, string};
use fss_cli::json_input;
use fss_cli::supervisor::retained::{
    RetainedDetectionSource, RetainedDiscoverySource, RetainedSupervisorError,
    revalidate_detection_sources, revalidate_retained_discovery_sources,
    run_discovered_detection_supervisor, run_discovered_retained_supervisor,
};
use fss_cli::{ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, LedgerAnchor, PrincipalId, SessionId,
};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::agent_session::checkpoint::journal::supervision::{
    MAX_SUPERVISION_WINDOWS, PendingSupervisionDelivery, SupervisionDetectionSourcePin,
    SupervisionRegistration, SupervisionSourcePin,
};
use fss_reference::deployment_session::supervision::{
    SupervisionAction, SupervisionAdapterError, SupervisionEvaluation, SupervisionEvaluator,
    SupervisionRecoveryBinding, SupervisionRecoveryBoundary, SupervisionRecoveryControl,
    SupervisionRecoveryRequest, SupervisionSessionBinding, SupervisionSessionBoundary,
    SupervisionSessionControl, SupervisionSessionDelivery, SupervisionSessionError,
    SupervisionSessionOutcome, SupervisionSessionRequest, SupervisionValidation,
    recover_supervision_registration, supervise_existing_session, supervise_session,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{Failure, InputPlan, NativeRequest, Options, Result};

const SCHEMA: &str = "fss.retained_supervisor_session_report.v1";
const RECEIPT_DOMAIN: &str = "fss.retained_supervisor_session_receipt.v1";
const ENVELOPE_BYTES: usize = 16 * 1024;

/// Inert CLI intent; actual admission belongs to the existing session and native source owners.
pub(super) struct SessionOptions {
    session: SessionId,
    subscription: String,
    expected_root: ContentDigest,
    maximum_attempts: Option<u32>,
    action: SupervisionAction,
    configure_schedule: bool,
    resume: bool,
}

fn digest(values: &BTreeMap<String, OsString>, key: &str) -> Result<ContentDigest> {
    let value = ContentDigest::parse(super::text(values, key)?).map_err(Failure::malformed)?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(Failure::malformed(format!(
            "{key} requires a nonzero SHA-256 digest"
        )));
    }
    Ok(value)
}

pub(super) fn parse(values: &BTreeMap<String, OsString>) -> Result<Option<SessionOptions>> {
    if ![
        "--session",
        "--subscription",
        "--authority-root",
        "--max-poll-attempts",
        "--acknowledge",
        "--discard",
        "--inspect",
        "--schedule",
        "--advance-window",
        "--after-receipt",
        "--resume",
    ]
    .iter()
    .any(|flag| values.contains_key(*flag))
    {
        return Ok(None);
    }
    if values.contains_key("--advance-window") != values.contains_key("--after-receipt") {
        return Err(Failure::malformed(
            "--advance-window and --after-receipt are required together",
        ));
    }
    if [
        "--acknowledge",
        "--discard",
        "--inspect",
        "--schedule",
        "--advance-window",
    ]
    .iter()
    .filter(|flag| values.contains_key(**flag))
    .count()
        > 1
    {
        return Err(Failure::malformed(
            "--acknowledge, --discard, --inspect, --schedule and --advance-window are mutually exclusive",
        ));
    }
    let configure_schedule = values.contains_key("--schedule");
    let resume = values.contains_key("--resume");
    if resume
        && (super::text(values, "--resume")? != "yes"
            || configure_schedule
            || values.contains_key("--max-poll-attempts"))
    {
        return Err(Failure::malformed(
            "--resume requires yes and the stored configuration and lifetime ceiling; --schedule and --max-poll-attempts cannot be supplied",
        ));
    }
    if configure_schedule && super::text(values, "--schedule")? != "yes" {
        return Err(Failure::malformed("--schedule requires yes"));
    }
    let session =
        SessionId::parse(super::text(values, "--session")?).map_err(Failure::malformed)?;
    let subscription = super::text(values, "--subscription")?;
    fss_core::validate_id(subscription).map_err(Failure::malformed)?;
    let expected_root = digest(values, "--authority-root")?;
    let maximum_attempts = if resume {
        None
    } else {
        Some(
            super::text(values, "--max-poll-attempts")?
                .parse::<u32>()
                .map_err(Failure::malformed)?,
        )
    };
    let action = if values.contains_key("--inspect") {
        if super::text(values, "--inspect")? != "yes" {
            return Err(Failure::malformed("--inspect requires yes"));
        }
        SupervisionAction::Inspect
    } else if values.contains_key("--advance-window") {
        let index = super::text(values, "--advance-window")?
            .parse::<u32>()
            .map_err(Failure::malformed)?;
        if !(1..MAX_SUPERVISION_WINDOWS).contains(&index) {
            return Err(Failure::malformed(
                "--advance-window requires a next zero-based index from 1 through 31",
            ));
        }
        SupervisionAction::Advance {
            target_count: index + 1,
            after_receipt: digest(values, "--after-receipt")?,
        }
    } else if values.contains_key("--acknowledge") {
        SupervisionAction::Acknowledge(digest(values, "--acknowledge")?)
    } else if values.contains_key("--discard") {
        SupervisionAction::Discard(digest(values, "--discard")?)
    } else {
        SupervisionAction::Poll
    };
    Ok(Some(SessionOptions {
        session,
        subscription: subscription.to_owned(),
        expected_root,
        maximum_attempts,
        action,
        configure_schedule,
        resume,
    }))
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

/// Recover the original native request through the live session owner. This never exposes a
/// pending payload and never reserves source work; the separate existing-only action does that.
pub(super) fn recover(
    options: &Options,
    session: &SessionOptions,
    cx: &ReplayCx,
) -> Result<InputPlan> {
    if !session.resume || session.maximum_attempts.is_some() || session.configure_schedule {
        return Err(Failure::malformed(
            "stored supervision recovery requires --resume yes",
        ));
    }
    let principal = PrincipalId::parse(&options.principal).map_err(Failure::malformed)?;
    let request = SupervisionRecoveryRequest {
        session_id: session.session.clone(),
        subscription_id: session.subscription.clone(),
        expected_authority_root: session.expected_root,
    };
    let limits = OrientLimits {
        max_journal_bytes: 32 * 1024 * 1024,
        ..OrientLimits::default()
    };
    let mut control = RecoveryControl {
        root: &options.root,
        principal: &principal,
        request: &request,
        limits,
        cx,
        boundaries: 0,
    };
    let registration = recover_supervision_registration(
        &options.root,
        &principal,
        &request,
        &limits,
        &mut control,
    )
    .map_err(|error| Failure {
        exit: ExitIdentity::RUNTIME_FAILURE.code,
        identity: match &error {
            SupervisionSessionError::Denied(error) | SupervisionSessionError::Evaluation(error) => {
                error.identity
            }
            SupervisionSessionError::ChangedAuthority | SupervisionSessionError::StaleAuthority => {
                RetainedSupervisorError::Authority.stable_id()
            }
            _ => ERR_CLI_RUNTIME_FAILURE,
        },
        reason: format!(
            "{error}; journal_may_have_changed=true; no_native_attempt_reserved_by_recovery=true"
        ),
    })?;
    let discovery = NativeRequest::from_configuration(
        &registration.configuration,
        registration.configuration_digest,
    )
    .map_err(Failure::malformed)?;
    Ok(InputPlan::Discover {
        request: discovery,
        bytes: registration.configuration.clone(),
        registration: Some(registration),
    })
}

fn scoped_request(
    original: &NativeRequest,
    authority: ContentDigest,
    count: Option<u32>,
) -> std::result::Result<NativeRequest, SupervisionAdapterError> {
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
fn checked_payload<'a>(
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
    request: &'a NativeRequest,
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
            NativeRequest::Event(request) => {
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
            NativeRequest::Detection(request) => {
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
            NativeRequest::Event(_) if !pending.detection_source_inventory().is_empty() => {
                return Err(runtime_error(
                    "event discovery cannot validate native detector source pins",
                ));
            }
            NativeRequest::Detection(_) if !pending.source_inventory().is_empty() => {
                return Err(runtime_error(
                    "direct detection cannot validate package-event source pins",
                ));
            }
            _ => {}
        }
        let mut deployment =
            ReferenceDeployment::open(self.root, self.site, self.cx).map_err(runtime_error)?;
        match &request {
            NativeRequest::Event(request) => {
                let sources: Vec<_> = pending
                    .source_inventory()
                    .iter()
                    .map(|source| RetainedDiscoverySource {
                        event_id: source.event_id.clone(),
                        event_root: source.event_root,
                        source_verified: source.source_verified,
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
            NativeRequest::Detection(request) => {
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

fn optional_digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| string(&value.to_text()))
}

fn validation_json(validation: Option<&SupervisionValidation>) -> String {
    validation.map_or_else(
        || "null".to_owned(),
        |validation| {
            object(&[
                (
                    "current_authority_root",
                    string(&validation.basis.state_root.to_text()),
                ),
                ("receipt_digest", string(&validation.receipt.to_text())),
                ("reserved_bytes", validation.reserved_bytes.to_string()),
                ("read_attempts", validation.read_attempts.to_string()),
                ("complete_current_catalog", "false".to_owned()),
                ("effects_authorized", "false".to_owned()),
                ("supports_absence_claim", "false".to_owned()),
            ])
        },
    )
}

fn envelope_receipt(unsigned: &str) -> std::result::Result<ContentDigest, SupervisionAdapterError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(RECEIPT_DOMAIN);
    // A complete bounded report can exceed the canonical text-field limit. Bytes have
    // the identical length-prefixed encoding without imposing that unrelated string cap.
    encoder.bytes(unsigned.as_bytes());
    Ok(ContentDigest::sha256(
        &encoder.finish_checked().map_err(runtime_error)?,
    ))
}

fn render(
    delivery: &SupervisionSessionDelivery,
    original: &NativeRequest,
) -> std::result::Result<String, SupervisionAdapterError> {
    let (
        status,
        payload,
        delivery_receipt,
        report_receipt,
        report_root,
        payload_digest,
        replayed,
        validation,
        acknowledged,
        discarded,
    ) = match &delivery.outcome {
        SupervisionSessionOutcome::ScheduleConfigured => (
            "scheduled",
            "null".to_owned(),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
        ),
        SupervisionSessionOutcome::WindowAdvanced => (
            "advanced",
            "null".to_owned(),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
        ),
        SupervisionSessionOutcome::Inspected => {
            let pending = delivery.subscription.pending();
            (
                "inspected",
                "null".to_owned(),
                pending.map(PendingSupervisionDelivery::receipt),
                pending.map(PendingSupervisionDelivery::report_receipt),
                pending.map(|pending| pending.anchor().state_root),
                pending.map(PendingSupervisionDelivery::payload_digest),
                false,
                None,
                None,
                None,
            )
        }
        SupervisionSessionOutcome::Report {
            payload,
            pending,
            replayed,
            validation,
        } => {
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
            (
                "pending",
                text.to_owned(),
                Some(pending.receipt()),
                Some(pending.report_receipt()),
                Some(pending.anchor().state_root),
                Some(pending.payload_digest()),
                *replayed,
                validation.as_ref(),
                None,
                None,
            )
        }
        SupervisionSessionOutcome::Acknowledged {
            receipt,
            validation,
        } => (
            "acknowledged",
            "null".to_owned(),
            Some(*receipt),
            None,
            None,
            None,
            false,
            validation.as_ref(),
            Some(*receipt),
            None,
        ),
        SupervisionSessionOutcome::Discarded(receipt) => (
            "discarded",
            "null".to_owned(),
            Some(*receipt),
            None,
            None,
            None,
            false,
            None,
            None,
            Some(*receipt),
        ),
    };
    let state = &delivery.subscription;
    let mut fields = vec![
        ("schema", string(SCHEMA)),
        ("session_id", string(delivery.session.session_id.as_str())),
        (
            "subscription_id",
            string(&state.registration().subscription_id),
        ),
        (
            "configuration_digest",
            string(&state.registration().configuration_digest.to_text()),
        ),
        ("state", string(status)),
        (
            "current_authority_root",
            string(&delivery.head.anchor.state_root.to_text()),
        ),
        (
            "current_ledger_root",
            string(&delivery.head.ledger_root.to_text()),
        ),
        (
            "current_effect_root",
            string(&delivery.head.effect_root.to_text()),
        ),
        ("journal_root", string(&delivery.journal_root.to_text())),
        ("subscription_digest", string(&state.digest().to_text())),
        ("delivery_receipt", optional_digest(delivery_receipt)),
        ("report_receipt", optional_digest(report_receipt)),
        ("report_authority_root", optional_digest(report_root)),
        ("payload_digest", optional_digest(payload_digest)),
        ("report_is_historical", (status == "pending").to_string()),
        ("replayed", replayed.to_string()),
        ("source_validation", validation_json(validation)),
        (
            "pending_receipt",
            optional_digest(state.pending().map(PendingSupervisionDelivery::receipt)),
        ),
        ("acknowledged", optional_digest(acknowledged)),
        ("discarded", optional_digest(discarded)),
        (
            "last_acknowledged",
            optional_digest(state.last_acknowledged()),
        ),
        ("last_discarded", optional_digest(state.last_discarded())),
        ("attempts_reserved", state.attempts_reserved().to_string()),
        (
            "maximum_attempts",
            state.registration().maximum_attempts.to_string(),
        ),
        ("reserved_bytes", state.reserved_bytes().to_string()),
        (
            "reserved_read_attempts",
            state.reserved_read_attempts().to_string(),
        ),
        (
            "reservation_accounting",
            string("full_native_read_caps_before_each_attempt_without_refund"),
        ),
        (
            "open_recovery_and_filesystem_metadata_included",
            "false".to_owned(),
        ),
        ("effects_authorized", "false".to_owned()),
        ("supports_absence_claim", "false".to_owned()),
    ];
    if let Some(schedule) = state.schedule() {
        let count = schedule.active_window_count();
        let declared = &original.template().spec().windows;
        if count == 0
            || count > schedule.total_windows()
            || schedule.total_windows() as usize != declared.len()
        {
            return Err(runtime_error(
                "stored schedule differs from the immutable native windows",
            ));
        }
        let advance = schedule.last_advance().map_or_else(
            || "null".to_owned(),
            |advance| {
                object(&[
                    (
                        "target_window_index",
                        (advance.target_count() - 1).to_string(),
                    ),
                    ("target_window_count", advance.target_count().to_string()),
                    ("after_receipt", string(&advance.after_receipt().to_text())),
                    ("receipt_digest", string(&advance.receipt().to_text())),
                ])
            },
        );
        fields.extend([
            ("scheduled", "true".to_owned()),
            ("active_window_index", (count - 1).to_string()),
            ("active_window_count", count.to_string()),
            ("total_windows", schedule.total_windows().to_string()),
            (
                "active_end_ns",
                string(&declared[count as usize - 1].end_ns.to_string()),
            ),
            (
                "all_windows_active",
                (count == schedule.total_windows()).to_string(),
            ),
            (
                "report_window_count",
                state
                    .pending()
                    .and_then(PendingSupervisionDelivery::active_window_count)
                    .map_or_else(|| "null".to_owned(), |value| value.to_string()),
            ),
            (
                "last_terminal_receipt",
                optional_digest(schedule.resolved_receipt()),
            ),
            (
                "last_terminal_acknowledged",
                schedule
                    .resolved_acknowledged()
                    .map_or_else(|| "null".to_owned(), |value| value.to_string()),
            ),
            ("last_advance", advance),
        ]);
    }
    fields.push(("report", payload));
    let unsigned = object(&fields);
    let receipt = envelope_receipt(&unsigned)?;
    fields.push(("receipt_digest", string(&receipt.to_text())));
    let rendered = object(&fields);
    if rendered.len() > state.registration().max_report_bytes {
        return Err(source_error(RetainedSupervisorError::Limit(
            "complete session report bytes",
        )));
    }
    Ok(rendered)
}

pub(super) fn run(
    options: &Options,
    session: &SessionOptions,
    discovery: &NativeRequest,
    bytes: &[u8],
    recovered: Option<&SupervisionRegistration>,
    cx: &ReplayCx,
) -> Result<String> {
    let limits = discovery.template().spec().limits;
    let registration = match (session.resume, recovered) {
        (true, Some(registration)) => {
            if registration.session_id != session.session
                || registration.subscription_id != session.subscription
                || registration.configuration.as_slice() != bytes
                || registration.configuration_digest != ContentDigest::sha256(bytes)
                || registration.max_read_bytes != limits.max_read_bytes
                || registration.max_read_attempts != limits.max_read_attempts
                || registration.max_report_bytes != limits.max_report_bytes
            {
                return Err(Failure::malformed(
                    "stored supervision registration differs from its native configuration",
                ));
            }
            registration.clone()
        }
        (false, None) => SupervisionRegistration {
            session_id: session.session.clone(),
            subscription_id: session.subscription.clone(),
            configuration: bytes.to_vec(),
            configuration_digest: ContentDigest::sha256(bytes),
            max_read_bytes: limits.max_read_bytes,
            max_read_attempts: limits.max_read_attempts,
            maximum_attempts: session
                .maximum_attempts
                .ok_or_else(|| Failure::malformed("required lifetime attempt ceiling"))?,
            max_report_bytes: limits.max_report_bytes,
        },
        _ => {
            return Err(Failure::malformed(
                "supervision input mode differs from its stored registration",
            ));
        }
    };
    registration.validate().map_err(Failure::malformed)?;
    let action = if session.configure_schedule {
        SupervisionAction::ConfigureSchedule {
            total_windows: u32::try_from(discovery.template().spec().windows.len())
                .map_err(Failure::malformed)?,
        }
    } else {
        session.action
    };
    let command = SupervisionSessionRequest {
        registration,
        expected_authority_root: session.expected_root,
        action,
    };
    let principal = PrincipalId::parse(&options.principal).map_err(Failure::malformed)?;
    let orient_limits = OrientLimits {
        max_journal_bytes: limits.max_journal_bytes,
        ..OrientLimits::default()
    };
    let mut control = NativeEvaluator {
        root: &options.root,
        site: &options.site,
        principal: &principal,
        command: &command,
        request: discovery,
        limits: orient_limits,
        cx,
        boundaries: 0,
    };
    let delivery = if session.resume {
        supervise_existing_session(
            &options.root,
            &principal,
            &command,
            &orient_limits,
            &mut control,
        )
    } else {
        supervise_session(
            &options.root,
            &principal,
            &command,
            &orient_limits,
            &mut control,
        )
    };
    match delivery {
        Ok(delivery) => render(&delivery, discovery).map_err(|error| Failure {
            exit: ExitIdentity::RUNTIME_FAILURE.code,
            identity: error.identity,
            reason: format!(
                "{}; journal_may_have_changed=true; attempts_reserved={}",
                error.reason,
                delivery.subscription.attempts_reserved()
            ),
        }),
        Err(failure) => {
            let identity = match &failure.error {
                SupervisionSessionError::Denied(error)
                | SupervisionSessionError::Evaluation(error) => error.identity,
                SupervisionSessionError::ChangedAuthority
                | SupervisionSessionError::StaleAuthority => {
                    RetainedSupervisorError::Authority.stable_id()
                }
                _ => ERR_CLI_RUNTIME_FAILURE,
            };
            Err(Failure {
                exit: ExitIdentity::RUNTIME_FAILURE.code,
                identity,
                reason: format!(
                    "{}; journal_may_have_changed={}; attempts_reserved={}; acknowledged={}; discarded={}; configured_windows={}; advanced={}",
                    failure.error,
                    failure.journal_may_have_changed,
                    failure.attempts_reserved,
                    failure
                        .acknowledged
                        .map_or_else(|| "none".to_owned(), |value| value.to_text()),
                    failure
                        .discarded
                        .map_or_else(|| "none".to_owned(), |value| value.to_text()),
                    failure
                        .configured_windows
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    failure
                        .advanced
                        .map_or_else(|| "none".to_owned(), |value| value.to_text()),
                ),
            })
        }
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn pending_report_release_keeps_event_and_detection_authority_dialects_distinct()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let authority = ContentDigest::sha256(b"exact historical authority");
        let request = ContentDigest::sha256(b"exact scoped request");
        let receipt = ContentDigest::sha256(b"complete historical report receipt");
        let profiles = [
            (
                "fss.retained_supervisor_discovery_report.v1",
                "expected_authority_root",
            ),
            (
                "fss.retained_detection_discovery_report.v1",
                "authority_state_root",
            ),
        ];
        for (index, (schema, authority_field)) in profiles.iter().enumerate() {
            let payload = object(&[
                ("schema", string(schema)),
                (*authority_field, string(&authority.to_text())),
                ("request_digest", string(&request.to_text())),
                ("receipt_digest", string(&receipt.to_text())),
            ]);
            let payload_digest = ContentDigest::sha256(payload.as_bytes());
            assert_eq!(
                checked_payload(
                    payload.as_bytes(),
                    authority,
                    request,
                    receipt,
                    payload_digest,
                    schema,
                    authority_field,
                )?,
                payload
            );
            let (other_schema, other_authority_field) = profiles[1 - index];
            assert!(
                checked_payload(
                    payload.as_bytes(),
                    authority,
                    request,
                    receipt,
                    payload_digest,
                    other_schema,
                    authority_field,
                )
                .is_err(),
                "one native report dialect cannot release another dialect's payload"
            );
            assert!(
                checked_payload(
                    payload.as_bytes(),
                    authority,
                    request,
                    receipt,
                    payload_digest,
                    schema,
                    other_authority_field,
                )
                .is_err(),
                "authority must come from this report's exact field"
            );
        }
        Ok(())
    }

    #[test]
    fn report_envelope_receipt_preserves_legacy_small_encoding()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let unsigned = object(&[("state", string("pending")), ("report", "null".to_owned())]);
        let mut legacy = CanonicalEncoder::new();
        legacy.text(RECEIPT_DOMAIN);
        legacy.text(&unsigned);
        let expected = ContentDigest::sha256(&legacy.finish_checked()?);
        assert_eq!(envelope_receipt(&unsigned)?, expected);
        Ok(())
    }

    #[test]
    fn report_envelope_receipt_accepts_bounded_payload_above_text_field_limit()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let rows = vec!["0"; 40_000].join(",");
        let unsigned = object(&[
            ("state", string("pending")),
            ("report", format!("[{rows}]")),
        ]);
        assert!(unsigned.len() > 65_536 && unsigned.len() < 2 * 1024 * 1024);
        assert!(json_input::parse_retained_supervisor_report(&unsigned).is_ok());
        let mut legacy = CanonicalEncoder::new();
        legacy.text(RECEIPT_DOMAIN);
        legacy.text(&unsigned);
        assert!(legacy.finish_checked().is_err());
        let receipt = envelope_receipt(&unsigned)?;
        assert_eq!(receipt.algorithm(), DigestAlgorithm::Sha256);
        assert_eq!(receipt, envelope_receipt(&unsigned)?);
        Ok(())
    }
}
