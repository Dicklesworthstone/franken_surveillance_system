#![forbid(unsafe_code)]
//! Pure exact alert operation/approval identities. No function here grants an effect.
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, EffectIntent, IdempotencyKey,
    ObligationId, OperationId, OperationReceipt,
};

const OPERATION_DOMAIN: &str = "fss.cli_alert_operation.v1";
const PLAN_APPROVAL_DOMAIN: &str = "fss.cli_alert_plan_approval.v1";
/// Exact local evidence retention approved by a dispatch, including untrusted response bytes.
pub const WIRE_RETENTION_POLICY: &str = "local-root-last-exact-http-wire-v1";
const DISPATCH_APPROVAL_DOMAIN: &str = "fss.cli_alert_dispatch_approval.v2";

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// The deterministic identities of one alert: one per (event revision, relay route).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertIdentities {
    /// Effect operation identity.
    pub operation: OperationId,
    /// Idempotency key.
    pub idempotency: IdempotencyKey,
    /// Terminal-proof obligation identity.
    pub obligation: ObligationId,
}

/// Derives the alert identities of `event_revision` sent over `route`.
pub fn alert_identities(
    event_revision: ContentDigest,
    route: ContentDigest,
) -> Result<AlertIdentities, ContractError> {
    let mut e = CanonicalEncoder::new();
    e.text(OPERATION_DOMAIN);
    e.digest(event_revision);
    e.digest(route);
    let key = hex(ContentDigest::sha256(&e.finish()));
    Ok(AlertIdentities {
        operation: OperationId::parse(format!("operation:alert:{key}"))?,
        idempotency: IdempotencyKey::parse(format!("idempotency:alert:{key}"))?,
        obligation: ObligationId::parse(format!("obligation:alert:{key}"))?,
    })
}

/// Exact approval identity of a plan: its effect intent, obligation, channel, relay route and the
/// approving principal. Time-independent, so a dry run and the later preparation agree.
#[must_use]
pub(crate) fn plan_approval_parts(
    intent: &EffectIntent,
    obligation: &ObligationId,
    channel: &str,
    event_root: ContentDigest,
    event_revision: ContentDigest,
    route: ContentDigest,
    principal: &str,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(PLAN_APPROVAL_DOMAIN);
    intent.encode_canonical(&mut e);
    obligation.encode_canonical(&mut e);
    e.text(channel);
    e.digest(event_root);
    e.digest(event_revision);
    e.digest(route);
    e.text(principal);
    ContentDigest::sha256(&e.finish())
}

/// Exact approval identity of one dispatch: the plan approval, the durable prepared record, the
/// explicit deadline, principal, and exact local wire-retention policy. Version two prevents
/// an older approval from silently authorizing the additional retained byte footprint.
#[must_use]
pub fn dispatch_approval_digest(
    plan: ContentDigest,
    operation: &OperationReceipt,
    deadline_ms: u64,
    principal: &str,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(DISPATCH_APPROVAL_DOMAIN);
    e.text(WIRE_RETENTION_POLICY);
    e.digest(plan);
    operation.intent.encode_canonical(&mut e);
    e.text(operation.state.as_str());
    e.i128(operation.prepared_at.0);
    e.text(&operation.authority.principal);
    e.text(&operation.authority.capability);
    e.u64(deadline_ms);
    e.text(principal);
    ContentDigest::sha256(&e.finish())
}

// Exercise the actual core-only disclosure owner together with these identities. This test-only
// path keeps standalone native validation faithful without replacing any production dependency.
#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "../../../fss-reference/src/alert/webhook/profile.rs"]
mod webhook_profile;
