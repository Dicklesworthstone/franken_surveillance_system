#![forbid(unsafe_code)]
//! Idempotent durable effect machine, explicit escalation policies, and secret-free JSONL audit
//! records for outbound TLS 1.3 notifications.
//!
//! Enforces `Prepared -> Committed -> AdapterAccepted | Indeterminate | Failed -> Observed ->
//! Verified`. Never resends `Indeterminate` operations; escalation prepares a distinct child
//! operation with a new `operation_id`, new `idempotency_key`, and explicit parent lineage.

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, EffectIntent, EffectJournal,
    EffectState, IdempotencyKey, ObligationId, OperationId, OperationReceipt, TimestampNs,
};
use fss_vault::{EntropySource, SecretAccessCx, SecretStore};

use crate::DurableEffectJournal;

use super::relays::{NtfyTarget, PushoverTarget, dispatch_ntfy, dispatch_pushover};
use super::smtp::{SmtpTlsTarget, dispatch_smtp_tls};
use super::webhook::{HttpsWebhookTarget, dispatch_https_webhook};
use super::{
    DeliveryReceipt, DnsResolver, ERR_NOTIFY_ESCALATION_001, ERR_NOTIFY_INDETERMINATE_001,
    ERR_NOTIFY_TRANSPORT_001, NOTIFY_EFFECT_REQUEST_DOMAIN, NOTIFY_ESCALATION_LINEAGE_DOMAIN,
    NOTIFY_ESCALATION_POLICY_DOMAIN, NotifyDeadlineCx, NotifyError, NotifyLimits, NotifyPayload,
    encode_hex_lower, push_json_str,
};

/// Stable effect class for production TLS notification dispatch intents.
pub const NOTIFY_EFFECT_CLASS: &str = "notify.tls_dispatch";
/// Stable terminal predicate for outbound notification obligations.
pub const NOTIFY_TERMINAL_PREDICATE: &str = "notification delivery independently reconciled";

/// Abstraction over in-memory [`EffectJournal`] and crash-safe [`DurableEffectJournal`].
pub trait NotifyEffectStore {
    /// Looks up an operation receipt by identity.
    fn get_operation(&self, operation_id: &OperationId) -> Option<&OperationReceipt>;
    /// Durably prepares a new effect intent and its obligation.
    fn prepare_effect(
        &mut self,
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: String,
        now: TimestampNs,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably transitions `Prepared -> Committed` before touching any network socket.
    fn commit_effect(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably transitions `Committed -> AdapterAccepted` binding the delivery observation digest.
    fn accept_effect(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        observation_digest: ContentDigest,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably transitions `Committed -> Failed` with a canonical pre-send failure proof.
    fn fail_effect(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        failure_proof: ContentDigest,
        error_code: String,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably marks an operation `Indeterminate` after post-write ambiguity.
    fn mark_effect_indeterminate(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        reason: String,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably transitions `AdapterAccepted | Indeterminate -> Observed` with independent proof.
    fn observe_effect(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        proof_digest: ContentDigest,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably reconciles `Observed -> Verified` using independent terminal proof.
    fn verify_effect(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        proof_digest: ContentDigest,
    ) -> Result<OperationReceipt, NotifyError>;
    /// Durably reconciles `Indeterminate -> Failed` using explicit failure proof.
    fn reconcile_effect_failed(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        proof_digest: ContentDigest,
        reason: String,
    ) -> Result<OperationReceipt, NotifyError>;
}

macro_rules! impl_notify_effect_store {
    ($ty:ty) => {
        impl NotifyEffectStore for $ty {
            fn get_operation(&self, id: &OperationId) -> Option<&OperationReceipt> {
                self.operation(id)
            }
            fn prepare_effect(
                &mut self,
                intent: EffectIntent,
                ob: ObligationId,
                pred: String,
                now: TimestampNs,
            ) -> Result<OperationReceipt, NotifyError> {
                self.prepare(intent, ob, pred, now).cloned().map_err(|e| {
                    NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, format!("prepare failed: {e}"))
                })
            }
            fn commit_effect(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
            ) -> Result<OperationReceipt, NotifyError> {
                self.transition(id, EffectState::Committed, now, None, None)
                    .cloned()
                    .map_err(|e| {
                        NotifyError::pre_send(
                            ERR_NOTIFY_TRANSPORT_001,
                            format!("commit failed: {e}"),
                        )
                    })
            }
            fn accept_effect(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
                obs: ContentDigest,
            ) -> Result<OperationReceipt, NotifyError> {
                self.transition(id, EffectState::AdapterAccepted, now, Some(obs), None)
                    .cloned()
                    .map_err(|e| NotifyError::indeterminate(format!("accept failed: {e}")))
            }
            fn fail_effect(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
                proof: ContentDigest,
                code: String,
            ) -> Result<OperationReceipt, NotifyError> {
                self.transition(id, EffectState::Failed, now, Some(proof), Some(code))
                    .cloned()
                    .map_err(|e| {
                        NotifyError::pre_send(
                            ERR_NOTIFY_TRANSPORT_001,
                            format!("fail transition failed: {e}"),
                        )
                    })
            }
            fn mark_effect_indeterminate(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
                reason: String,
            ) -> Result<OperationReceipt, NotifyError> {
                self.mark_indeterminate(id, now, reason)
                    .cloned()
                    .map_err(|e| {
                        NotifyError::indeterminate(format!("mark_indeterminate failed: {e}"))
                    })
            }
            fn observe_effect(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
                proof: ContentDigest,
            ) -> Result<OperationReceipt, NotifyError> {
                self.transition(id, EffectState::Observed, now, Some(proof), None)
                    .cloned()
                    .map_err(|e| {
                        NotifyError::pre_send(
                            ERR_NOTIFY_TRANSPORT_001,
                            format!("observe failed: {e}"),
                        )
                    })
            }
            fn verify_effect(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
                proof: ContentDigest,
            ) -> Result<OperationReceipt, NotifyError> {
                self.reconcile_verified(id, proof, now)
                    .cloned()
                    .map_err(|e| {
                        NotifyError::pre_send(
                            ERR_NOTIFY_TRANSPORT_001,
                            format!("verify failed: {e}"),
                        )
                    })
            }
            fn reconcile_effect_failed(
                &mut self,
                id: &OperationId,
                now: TimestampNs,
                proof: ContentDigest,
                reason: String,
            ) -> Result<OperationReceipt, NotifyError> {
                self.reconcile_failed(id, proof, now, reason)
                    .cloned()
                    .map_err(|e| {
                        NotifyError::pre_send(
                            ERR_NOTIFY_TRANSPORT_001,
                            format!("reconcile_failed error: {e}"),
                        )
                    })
            }
        }
    };
}

impl_notify_effect_store!(EffectJournal);
impl_notify_effect_store!(DurableEffectJournal);

/// Concrete outbound notification channel target dispatched through the durable effect machine.
#[derive(Clone, Debug)]
pub enum NotificationChannelTarget<'a> {
    /// HMAC-SHA256 signed HTTPS webhook target.
    HttpsWebhook(&'a HttpsWebhookTarget),
    /// TLS 1.3 ntfy relay target.
    Ntfy(&'a NtfyTarget),
    /// TLS 1.3 Pushover relay target.
    Pushover(&'a PushoverTarget),
    /// SMTP-over-TLS (`SMTPS` or `STARTTLS`) email target.
    SmtpTls(&'a SmtpTlsTarget),
}

impl NotificationChannelTarget<'_> {
    /// Returns the canonical non-secret route digest of this channel target.
    #[must_use]
    pub const fn route_digest(&self) -> ContentDigest {
        match self {
            Self::HttpsWebhook(t) => t.route_digest,
            Self::Ntfy(t) => t.route_digest,
            Self::Pushover(t) => t.route_digest,
            Self::SmtpTls(t) => t.route_digest,
        }
    }

    /// Returns the target identifier label.
    #[must_use]
    pub fn target_id(&self) -> &str {
        match self {
            Self::HttpsWebhook(t) => &t.target_id,
            Self::Ntfy(t) => &t.target_id,
            Self::Pushover(t) => &t.target_id,
            Self::SmtpTls(t) => &t.target_id,
        }
    }
}

/// Result of executing one prepared notification operation through the durable effect machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchedNotification {
    /// Updated durable operation receipt (`AdapterAccepted`).
    pub operation_receipt: OperationReceipt,
    /// Complete secret-free delivery receipt and observation.
    pub delivery_receipt: DeliveryReceipt,
    /// Secret-free structured JSONL audit record.
    pub audit_record: DeliveryAuditRecord,
}

/// Prepares a notification effect intent durably in `Prepared` state (no network I/O).
pub fn prepare_notification_effect<S: NotifyEffectStore>(
    store: &mut S,
    payload: &NotifyPayload,
    route_digest: ContentDigest,
    precondition_digest: ContentDigest,
    obligation_id: ObligationId,
    prepared_at: TimestampNs,
) -> Result<OperationReceipt, NotifyError> {
    let intent = EffectIntent::new(
        payload.operation_id.clone(),
        payload.idempotency_key.clone(),
        NOTIFY_EFFECT_CLASS,
        compute_notification_request_digest(payload, route_digest),
        precondition_digest,
    )
    .map_err(|e| {
        NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("invalid EffectIntent: {e}"),
        )
    })?;
    store.prepare_effect(
        intent,
        obligation_id,
        NOTIFY_TERMINAL_PREDICATE.to_owned(),
        prepared_at,
    )
}

/// Executes a prepared notification strictly following `Prepared -> Committed ->
/// AdapterAccepted | Indeterminate | Failed`, refusing silent resends on `Indeterminate`.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_prepared_notification<S: NotifyEffectStore>(
    store: &mut S,
    target: NotificationChannelTarget<'_>,
    payload: &NotifyPayload,
    vault: &dyn SecretStore,
    secret_cx: &SecretAccessCx,
    dns: &dyn DnsResolver,
    deadline: &NotifyDeadlineCx,
    limits: NotifyLimits,
    entropy: &mut dyn EntropySource,
) -> Result<DispatchedNotification, NotifyError> {
    let existing = store
        .get_operation(&payload.operation_id)
        .ok_or_else(|| {
            NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "operation_id not prepared")
        })?
        .clone();

    match existing.state {
        EffectState::Indeterminate | EffectState::Committed => {
            return Err(NotifyError::indeterminate(format!(
                "refusing automatic resend of {} operation '{}'",
                existing.state.as_str(),
                payload.operation_id.as_str()
            )));
        }
        EffectState::AdapterAccepted | EffectState::Observed | EffectState::Verified => {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                format!(
                    "operation '{}' already {}; duplicate dispatch refused",
                    payload.operation_id.as_str(),
                    existing.state.as_str()
                ),
            ));
        }
        EffectState::Failed | EffectState::Cancelled => {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                format!(
                    "operation '{}' is terminal ({})",
                    payload.operation_id.as_str(),
                    existing.state.as_str()
                ),
            ));
        }
        EffectState::Prepared => {}
    }

    let expected_req = compute_notification_request_digest(payload, target.route_digest());
    if existing.intent.request_digest != expected_req
        || existing.intent.idempotency_key != payload.idempotency_key
    {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            "payload/route does not match prepared EffectIntent",
        ));
    }

    let committed = store.commit_effect(
        &payload.operation_id,
        monotonic_next(existing.updated_at, deadline.now()),
    )?;
    let outcome_at = monotonic_next(committed.updated_at, deadline.now());

    let dispatch_result = match target {
        NotificationChannelTarget::HttpsWebhook(t) => {
            dispatch_https_webhook(t, payload, vault, secret_cx, dns, deadline, limits, entropy)
        }
        NotificationChannelTarget::Ntfy(t) => {
            dispatch_ntfy(t, payload, vault, secret_cx, dns, deadline, limits, entropy)
        }
        NotificationChannelTarget::Pushover(t) => {
            dispatch_pushover(t, payload, vault, secret_cx, dns, deadline, limits, entropy)
        }
        NotificationChannelTarget::SmtpTls(t) => {
            dispatch_smtp_tls(t, payload, vault, secret_cx, dns, deadline, limits, entropy)
        }
    };

    match dispatch_result {
        Ok(delivery_receipt) => {
            let op_receipt = store.accept_effect(
                &payload.operation_id,
                outcome_at,
                delivery_receipt.observation.observation_digest,
            )?;
            let audit_record =
                DeliveryAuditRecord::from_accepted(&op_receipt, &delivery_receipt, None);
            Ok(DispatchedNotification {
                operation_receipt: op_receipt,
                delivery_receipt,
                audit_record,
            })
        }
        Err(err) => {
            if err.is_pre_send_failure() {
                let _ = store.fail_effect(
                    &payload.operation_id,
                    outcome_at,
                    existing.intent.failure_proof(err.code),
                    err.code.to_owned(),
                );
            } else {
                let _ = store.mark_effect_indeterminate(
                    &payload.operation_id,
                    outcome_at,
                    ERR_NOTIFY_INDETERMINATE_001.to_owned(),
                );
            }
            Err(err)
        }
    }
}

/// Reconciles an accepted or indeterminate notification to `Verified` using explicit proof.
pub fn reconcile_notification_verified<S: NotifyEffectStore>(
    store: &mut S,
    operation_id: &OperationId,
    reconciliation_proof: ContentDigest,
    observed_at: TimestampNs,
    verified_at: TimestampNs,
) -> Result<OperationReceipt, NotifyError> {
    let op = store
        .get_operation(operation_id)
        .ok_or_else(|| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "operation not found"))?
        .clone();
    if matches!(
        op.state,
        EffectState::AdapterAccepted | EffectState::Indeterminate
    ) {
        let obs = store.observe_effect(
            operation_id,
            monotonic_next(op.updated_at, observed_at),
            reconciliation_proof,
        )?;
        return store.verify_effect(
            operation_id,
            monotonic_next(obs.updated_at, verified_at),
            reconciliation_proof,
        );
    }
    if op.state == EffectState::Observed {
        return store.verify_effect(
            operation_id,
            monotonic_next(op.updated_at, verified_at),
            reconciliation_proof,
        );
    }
    Err(NotifyError::pre_send(
        ERR_NOTIFY_TRANSPORT_001,
        format!("cannot reconcile '{}' to verified", op.state.as_str()),
    ))
}

/// Operator-approved policy authorizing explicit child-operation fallback escalation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscalationPolicy {
    /// Stable policy identifier.
    pub policy_id: String,
    /// Primary channel identifier.
    pub primary_channel: String,
    /// Ordered bounded list of authorized fallback channel identifiers (`1..=8`).
    pub fallback_channels: Vec<String>,
    /// Explicit positive duration in nanoseconds before an unacknowledged alert may escalate.
    pub ack_deadline_ns: u64,
    /// Whether proven primary failure (`EffectState::Failed`) authorizes fallback escalation.
    pub escalate_on_failed: bool,
    /// Whether missing acknowledgement past `ack_deadline_ns` authorizes fallback escalation.
    pub escalate_on_unacknowledged: bool,
    /// Non-zero SHA-256 digest proving explicit operator approval of this escalation policy.
    pub operator_approval_digest: ContentDigest,
}

impl EscalationPolicy {
    /// Validates bounds and explicit operator approval on this escalation policy.
    pub fn validate(&self) -> Result<(), NotifyError> {
        if self.policy_id.is_empty() || self.policy_id.len() > 128 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "escalation policy_id invalid",
            ));
        }
        if self.primary_channel.is_empty()
            || self.fallback_channels.is_empty()
            || self.fallback_channels.len() > 8
        {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "escalation requires primary + 1..=8 fallbacks",
            ));
        }
        if self
            .fallback_channels
            .iter()
            .any(|c| c.is_empty() || c == &self.primary_channel)
        {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "fallbacks must be distinct from primary",
            ));
        }
        if self.ack_deadline_ns == 0 || self.ack_deadline_ns > 86_400_000_000_000 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "ack_deadline_ns outside 1ns..=24h",
            ));
        }
        if self.operator_approval_digest.algorithm() != DigestAlgorithm::Sha256
            || self.operator_approval_digest.bytes() == [0_u8; 32]
        {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "missing non-zero operator_approval_digest",
            ));
        }
        Ok(())
    }

    /// Computes the canonical digest of this policy under [`NOTIFY_ESCALATION_POLICY_DOMAIN`].
    #[must_use]
    pub fn policy_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_ESCALATION_POLICY_DOMAIN);
        enc.text(&self.policy_id);
        enc.text(&self.primary_channel);
        enc.u64(self.fallback_channels.len() as u64);
        for fb in &self.fallback_channels {
            enc.text(fb);
        }
        enc.u64(self.ack_deadline_ns);
        enc.bool(self.escalate_on_failed);
        enc.bool(self.escalate_on_unacknowledged);
        enc.digest(self.operator_approval_digest);
        ContentDigest::sha256(&enc.finish())
    }
}

/// Explicit typed reason justifying preparation of a fallback child operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscalationReason {
    /// Primary operation reached terminal `EffectState::Failed` with failure proof.
    PrimaryFailed {
        /// Failure error code recorded on the parent receipt.
        failure_code: String,
        /// Failure proof digest recorded on the parent receipt.
        failure_proof: ContentDigest,
    },
    /// Primary operation remained unacknowledged past `ack_deadline_ns`.
    AckDeadlineExpired {
        /// Timestamp when the parent reached its last non-verified state.
        parent_updated_at_ns: TimestampNs,
        /// Policy acknowledgement deadline duration in nanoseconds.
        ack_deadline_ns: u64,
        /// Explicit timestamp at which deadline expiry was evaluated.
        evaluated_at_ns: TimestampNs,
    },
}

impl EscalationReason {
    /// Returns the stable machine-readable reason tag.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PrimaryFailed { .. } => "primary_failed",
            Self::AckDeadlineExpired { .. } => "ack_deadline_expired",
        }
    }
}

/// Immutable parent-to-child fallback escalation lineage record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscalationLineage {
    /// Unmodified parent operation identity.
    pub parent_operation_id: OperationId,
    /// Distinct child fallback operation identity.
    pub child_operation_id: OperationId,
    /// Distinct child fallback idempotency key.
    pub child_idempotency_key: IdempotencyKey,
    /// Distinct child fallback obligation identity.
    pub child_obligation_id: ObligationId,
    /// Target fallback channel name.
    pub fallback_channel: String,
    /// Zero-based index inside `EscalationPolicy::fallback_channels`.
    pub step_index: u32,
    /// Explicit verified reason for escalation.
    pub reason: EscalationReason,
    /// Canonical digest of the authorizing [`EscalationPolicy`].
    pub policy_digest: ContentDigest,
    /// Canonical lineage digest under [`NOTIFY_ESCALATION_LINEAGE_DOMAIN`].
    pub lineage_digest: ContentDigest,
}

/// Prepared distinct fallback operation paired with its explicit [`EscalationLineage`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedEscalation {
    /// Durable prepared receipt for the NEW child operation (parent remains untouched).
    pub child_receipt: OperationReceipt,
    /// Updated payload bound to the child's distinct `operation_id`, `idempotency_key`, and channel.
    pub child_payload: NotifyPayload,
    /// Explicit parent-to-child escalation lineage.
    pub lineage: EscalationLineage,
}

/// Evaluates `policy` against `parent_operation_id` and prepares a DISTINCT child fallback
/// operation without mutating or resending the parent operation.
#[allow(clippy::too_many_arguments)]
pub fn prepare_escalation<S: NotifyEffectStore>(
    store: &mut S,
    policy: &EscalationPolicy,
    parent_operation_id: &OperationId,
    parent_payload: &NotifyPayload,
    fallback_step_index: usize,
    fallback_route_digest: ContentDigest,
    now: TimestampNs,
) -> Result<PreparedEscalation, NotifyError> {
    policy.validate()?;
    let fallback_channel = policy
        .fallback_channels
        .get(fallback_step_index)
        .ok_or_else(|| {
            NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "fallback_step_index out of range",
            )
        })?
        .clone();
    let parent = store
        .get_operation(parent_operation_id)
        .ok_or_else(|| {
            NotifyError::pre_send(ERR_NOTIFY_ESCALATION_001, "parent operation not found")
        })?
        .clone();

    let reason = match parent.state {
        EffectState::Verified => {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                "parent already verified",
            ));
        }
        EffectState::Failed => {
            if !policy.escalate_on_failed {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_ESCALATION_001,
                    "escalate_on_failed disabled",
                ));
            }
            EscalationReason::PrimaryFailed {
                failure_code: parent
                    .error_code
                    .clone()
                    .unwrap_or_else(|| ERR_NOTIFY_TRANSPORT_001.to_owned()),
                failure_proof: parent
                    .result_digest
                    .unwrap_or_else(|| parent.intent.failure_proof(ERR_NOTIFY_TRANSPORT_001)),
            }
        }
        EffectState::AdapterAccepted | EffectState::Indeterminate | EffectState::Observed => {
            if !policy.escalate_on_unacknowledged {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_ESCALATION_001,
                    "escalate_on_unacknowledged disabled",
                ));
            }
            if now.0
                < parent
                    .updated_at
                    .0
                    .saturating_add(i128::from(policy.ack_deadline_ns))
            {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_ESCALATION_001,
                    "ack_deadline_ns not yet expired",
                ));
            }
            EscalationReason::AckDeadlineExpired {
                parent_updated_at_ns: parent.updated_at,
                ack_deadline_ns: policy.ack_deadline_ns,
                evaluated_at_ns: now,
            }
        }
        EffectState::Prepared | EffectState::Committed | EffectState::Cancelled => {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_ESCALATION_001,
                format!("parent state '{}' ineligible", parent.state.as_str()),
            ));
        }
    };

    let policy_digest = policy.policy_digest();
    let step_u32 = u32::try_from(fallback_step_index)
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_ESCALATION_001, "step overflow"))?;
    let mut id_enc = CanonicalEncoder::new();
    id_enc.text(NOTIFY_ESCALATION_LINEAGE_DOMAIN);
    parent_operation_id.encode_canonical(&mut id_enc);
    id_enc.text(&fallback_channel);
    id_enc.u32(step_u32);
    id_enc.digest(policy_digest);
    id_enc.text(reason.as_str());
    let suffix = &encode_hex_lower(&ContentDigest::sha256(&id_enc.finish()).bytes())[..16];

    let child_op =
        OperationId::parse(format!("op:notify:esc{step_u32}:{suffix}")).map_err(|_| {
            NotifyError::pre_send(ERR_NOTIFY_ESCALATION_001, "invalid child operation_id")
        })?;
    let child_idem = IdempotencyKey::parse(format!("idempotency:notify:esc{step_u32}:{suffix}"))
        .map_err(|_| {
            NotifyError::pre_send(ERR_NOTIFY_ESCALATION_001, "invalid child idempotency_key")
        })?;
    let child_ob = ObligationId::parse(format!("obligation:notify:esc{step_u32}:{suffix}"))
        .map_err(|_| {
            NotifyError::pre_send(ERR_NOTIFY_ESCALATION_001, "invalid child obligation_id")
        })?;

    let mut lin_enc = CanonicalEncoder::new();
    lin_enc.text(NOTIFY_ESCALATION_LINEAGE_DOMAIN);
    parent_operation_id.encode_canonical(&mut lin_enc);
    child_op.encode_canonical(&mut lin_enc);
    child_idem.encode_canonical(&mut lin_enc);
    child_ob.encode_canonical(&mut lin_enc);
    lin_enc.text(&fallback_channel);
    lin_enc.u32(step_u32);
    lin_enc.text(reason.as_str());
    lin_enc.digest(policy_digest);
    let lineage_digest = ContentDigest::sha256(&lin_enc.finish());

    let lineage = EscalationLineage {
        parent_operation_id: parent_operation_id.clone(),
        child_operation_id: child_op.clone(),
        child_idempotency_key: child_idem.clone(),
        child_obligation_id: child_ob.clone(),
        fallback_channel: fallback_channel.clone(),
        step_index: step_u32,
        reason,
        policy_digest,
        lineage_digest,
    };
    let mut child_payload = parent_payload.clone();
    child_payload.operation_id = child_op;
    child_payload.idempotency_key = child_idem;
    child_payload.channel = fallback_channel;
    let child_receipt = prepare_notification_effect(
        store,
        &child_payload,
        fallback_route_digest,
        lineage_digest,
        child_ob,
        now,
    )?;
    Ok(PreparedEscalation {
        child_receipt,
        child_payload,
        lineage,
    })
}

/// Secret-free JSONL audit record capturing notification delivery and escalation linkage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryAuditRecord {
    /// Operation identity.
    pub operation_id: String,
    /// Idempotency key.
    pub idempotency_key: String,
    /// Relay kind (`"https_webhook"`, `"ntfy"`, `"pushover"`, `"smtp_tls"`).
    pub relay_kind: String,
    /// Recorded effect state string.
    pub effect_state: String,
    /// DNS resolution witness digest.
    pub dns_resolution_digest: Option<ContentDigest>,
    /// Verified peer leaf certificate SPKI SHA-256 digest.
    pub tls_peer_spki_sha256: Option<ContentDigest>,
    /// Canonical delivery observation digest.
    pub observation_digest: Option<ContentDigest>,
    /// Optional non-secret error code.
    pub error_code: Option<String>,
    /// Optional parent operation identity when created via escalation.
    pub parent_operation_id: Option<String>,
    /// Optional escalation reason tag.
    pub escalation_reason: Option<String>,
}

impl DeliveryAuditRecord {
    /// Builds an audit record from an accepted delivery receipt and optional escalation lineage.
    #[must_use]
    pub fn from_accepted(
        op: &OperationReceipt,
        delivery: &DeliveryReceipt,
        lineage: Option<&EscalationLineage>,
    ) -> Self {
        Self {
            operation_id: op.intent.operation_id.as_str().to_owned(),
            idempotency_key: op.intent.idempotency_key.as_str().to_owned(),
            relay_kind: delivery.observation.relay_kind.clone(),
            effect_state: op.state.as_str().to_owned(),
            dns_resolution_digest: Some(delivery.observation.dns_receipt.resolution_digest),
            tls_peer_spki_sha256: Some(delivery.observation.tls_peer_spki_sha256),
            observation_digest: Some(delivery.observation.observation_digest),
            error_code: None,
            parent_operation_id: lineage.map(|l| l.parent_operation_id.as_str().to_owned()),
            escalation_reason: lineage.map(|l| l.reason.as_str().to_owned()),
        }
    }

    /// Builds a secret-free audit record from a failed or indeterminate delivery attempt.
    #[must_use]
    pub fn from_error(
        op: &OperationReceipt,
        relay_kind: &str,
        err: &NotifyError,
        lineage: Option<&EscalationLineage>,
    ) -> Self {
        Self {
            operation_id: op.intent.operation_id.as_str().to_owned(),
            idempotency_key: op.intent.idempotency_key.as_str().to_owned(),
            relay_kind: relay_kind.to_owned(),
            effect_state: op.state.as_str().to_owned(),
            dns_resolution_digest: err.dns_receipt.as_ref().map(|d| d.resolution_digest),
            tls_peer_spki_sha256: None,
            observation_digest: None,
            error_code: Some(err.code.to_owned()),
            parent_operation_id: lineage.map(|l| l.parent_operation_id.as_str().to_owned()),
            escalation_reason: lineage.map(|l| l.reason.as_str().to_owned()),
        }
    }

    /// Serializes this audit record as a single compact secret-free JSONL line (no Serde).
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("{\"operation_id\":");
        push_json_str(&mut out, &self.operation_id);
        out.push_str(",\"idempotency_key\":");
        push_json_str(&mut out, &self.idempotency_key);
        out.push_str(",\"relay_kind\":");
        push_json_str(&mut out, &self.relay_kind);
        out.push_str(",\"effect_state\":");
        push_json_str(&mut out, &self.effect_state);
        for (k, v) in [
            (
                "dns_resolution_digest",
                self.dns_resolution_digest.map(ContentDigest::to_text),
            ),
            (
                "tls_peer_spki_sha256",
                self.tls_peer_spki_sha256.map(ContentDigest::to_text),
            ),
            (
                "observation_digest",
                self.observation_digest.map(ContentDigest::to_text),
            ),
            ("error_code", self.error_code.clone()),
            ("parent_operation_id", self.parent_operation_id.clone()),
            ("escalation_reason", self.escalation_reason.clone()),
        ] {
            if let Some(val) = v {
                out.push_str(&format!(",\"{k}\":"));
                push_json_str(&mut out, &val);
            }
        }
        out.push('}');
        out
    }
}

fn compute_notification_request_digest(
    payload: &NotifyPayload,
    route_digest: ContentDigest,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(NOTIFY_EFFECT_REQUEST_DOMAIN);
    payload.operation_id.encode_canonical(&mut enc);
    payload.idempotency_key.encode_canonical(&mut enc);
    enc.digest(payload.event_root);
    enc.digest(payload.event_revision_digest);
    enc.text(&payload.channel);
    enc.digest(route_digest);
    enc.bool(payload.visual_attachment.is_some());
    if let Some(vis) = &payload.visual_attachment {
        enc.digest(vis.receipt_digest);
    }
    ContentDigest::sha256(&enc.finish())
}

fn monotonic_next(previous: TimestampNs, candidate: TimestampNs) -> TimestampNs {
    if candidate > previous {
        candidate
    } else {
        TimestampNs(previous.0.saturating_add(1))
    }
}
