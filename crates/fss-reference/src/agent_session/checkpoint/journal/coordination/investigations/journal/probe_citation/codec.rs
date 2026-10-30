#![forbid(unsafe_code)]
//! Small additive citation framing; retained native payload and source inventory stay in their owner.

use super::*;
use crate::agent_session::checkpoint::journal::supervision::{
    MAX_SUPERVISION_ATTEMPTS, MAX_SUPERVISION_REPORT_BYTES, MAX_SUPERVISION_WINDOWS,
};

pub(super) fn encode_target(target: &ProbeCitationTarget, e: &mut CanonicalEncoder) {
    e.text(&target.case_id);
    e.digest(target.expected);
    e.text(&target.hypothesis);
    e.bool(target.contradicts);
}

pub(super) fn encode_custody(custody: &ProbeCustody, e: &mut CanonicalEncoder) {
    let pin = &custody.native;
    pin.principal.encode_canonical(e);
    pin.session.encode_canonical(e);
    e.text(&pin.subscription);
    for value in [
        pin.configuration,
        pin.supervisions,
        pin.subscription_state,
        pin.checkpoint,
        pin.command,
        pin.pending,
        pin.report,
        pin.payload,
    ] {
        e.digest(value);
    }
    e.u64(pin.payload_bytes);
    pin.report_anchor.encode_canonical(e);
    e.u32(pin.attempts_reserved);
    e.bool(pin.active_window_count.is_some());
    if let Some(count) = pin.active_window_count {
        e.u32(count);
    }
    e.bool(pin.replayed);
    e.i128(pin.observed_at.0);
    e.digest(custody.native_root);
    e.digest(custody.request);
    e.text(&custody.native_hypothesis);
    e.text(&custody.privacy_class);
    custody.head.anchor.encode_canonical(e);
    e.digest(custody.head.ledger_root);
    e.digest(custody.head.effect_root);
    e.i128(custody.head.observed_at.0);
    e.bool(custody.validation.is_some());
    if let Some(validation) = &custody.validation {
        validation.basis.encode_canonical(e);
        e.digest(validation.receipt);
        e.u64(validation.reserved_bytes);
        e.u64(validation.read_attempts);
    }
}

pub(super) fn validate_custody(custody: &ProbeCustody) -> Result<(), DurableSessionError> {
    let pin = &custody.native;
    let historical = &pin.report_anchor;
    let current = &custody.head.anchor;
    if pin.principal.as_str().len() > 128
        || pin.session.as_str().len() > 128
        || pin.subscription.is_empty()
        || pin.subscription.len() > 128
        || fss_core::validate_id(&pin.subscription).is_err()
        || custody.native_hypothesis.is_empty()
        || custody.native_hypothesis.len() > 128
        || fss_core::validate_id(&custody.native_hypothesis).is_err()
        || custody.privacy_class != NATIVE_PRIVACY
        || pin.payload_bytes == 0
        || pin.payload_bytes > MAX_SUPERVISION_REPORT_BYTES as u64
        || pin.attempts_reserved == 0
        || pin.attempts_reserved > MAX_SUPERVISION_ATTEMPTS
        || pin
            .active_window_count
            .is_some_and(|count| !(1..=MAX_SUPERVISION_WINDOWS).contains(&count))
        || pin.observed_at.0 < 0
        || custody.head.observed_at != pin.observed_at
        || pin.replayed != custody.validation.is_some()
        || historical.site_lineage.len() > 512
        || current.site_lineage.len() > 512
        || historical.site_lineage != current.site_lineage
        || historical.ledger_epoch != current.ledger_epoch
        || historical.adapter_registry_epoch != current.adapter_registry_epoch
        || historical.schema_epoch != current.schema_epoch
        || historical.policy_epoch != current.policy_epoch
        || historical.privacy_epoch != current.privacy_epoch
        || (!pin.replayed && historical != current)
        // DeploymentHistory::roots_at uses SHA-256 zero for a verified empty journal.
        // Preserve those exact history roots; content/proof identities below remain nonzero.
        || custody.head.ledger_root.algorithm() != DigestAlgorithm::Sha256
        || custody.head.effect_root.algorithm() != DigestAlgorithm::Sha256
        || [
            pin.configuration,
            pin.supervisions,
            pin.subscription_state,
            pin.checkpoint,
            pin.command,
            pin.pending,
            pin.report,
            pin.payload,
            custody.native_root,
            custody.request,
            historical.state_root,
            current.state_root,
        ]
        .into_iter()
        .any(|digest| !sha(digest))
        || custody.validation.as_ref().is_some_and(|validation| {
            validation.basis != *current
                || !sha(validation.receipt)
                || validation.reserved_bytes > 1024 * 1024 * 1024
                || validation.read_attempts > 100_000
        })
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

pub(super) fn encode(
    receipt: &ProbeCitationReceipt,
    after: ContentDigest,
) -> Result<Vec<u8>, DurableSessionError> {
    receipt
        .target
        .validate()
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    validate_custody(&receipt.custody)?;
    let mut e = CanonicalEncoder::new();
    e.text(RECORD);
    encode_target(&receipt.target, &mut e);
    receipt.custody.encode_canonical(&mut e);
    e.digest(receipt.revision.digest());
    e.digest(after);
    e.digest(receipt.digest());
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

type Decoded = (
    ProbeCitationTarget,
    ProbeCustody,
    ContentDigest,
    ContentDigest,
    ContentDigest,
);

pub(super) fn decode(bytes: &[u8]) -> Result<Decoded, DurableSessionError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != RECORD {
        return Err(DurableSessionError::InvalidHistory);
    }
    let target = ProbeCitationTarget {
        case_id: text(&mut d, 128)?,
        expected: d.digest()?,
        hypothesis: text(&mut d, 128)?,
        contradicts: d.bool()?,
    };
    target
        .validate()
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    let native = ProbeStatePin {
        principal: PrincipalId::parse(text(&mut d, 128)?)?,
        session: SessionId::parse(text(&mut d, 128)?)?,
        subscription: text(&mut d, 128)?,
        configuration: d.digest()?,
        supervisions: d.digest()?,
        subscription_state: d.digest()?,
        checkpoint: d.digest()?,
        command: d.digest()?,
        pending: d.digest()?,
        report: d.digest()?,
        payload: d.digest()?,
        payload_bytes: d.u64()?,
        report_anchor: anchor(&mut d)?,
        attempts_reserved: d.u32()?,
        active_window_count: if d.bool()? { Some(d.u32()?) } else { None },
        replayed: d.bool()?,
        observed_at: TimestampNs(d.i128()?),
    };
    let native_root = d.digest()?;
    let request = d.digest()?;
    let native_hypothesis = text(&mut d, 128)?;
    let privacy_class = text(&mut d, 256)?;
    let head = SupervisionSessionHead {
        anchor: anchor(&mut d)?,
        ledger_root: d.digest()?,
        effect_root: d.digest()?,
        observed_at: TimestampNs(d.i128()?),
    };
    let validation = if d.bool()? {
        Some(SupervisionValidation {
            basis: anchor(&mut d)?,
            receipt: d.digest()?,
            reserved_bytes: d.u64()?,
            read_attempts: d.u64()?,
        })
    } else {
        None
    };
    let custody = ProbeCustody {
        native,
        native_root,
        request,
        native_hypothesis,
        privacy_class,
        head,
        validation,
    };
    validate_custody(&custody)?;
    let revision = d.digest()?;
    let after = d.digest()?;
    let receipt = d.digest()?;
    if [revision, after, receipt]
        .into_iter()
        .any(|digest| !sha(digest))
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    d.ensure_finished()?;
    Ok((target, custody, revision, after, receipt))
}

fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, DurableSessionError> {
    let value = d.text()?;
    if value.is_empty() || value.len() > maximum {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(value.to_owned())
}

fn anchor(d: &mut CanonicalDecoder<'_>) -> Result<LedgerAnchor, DurableSessionError> {
    let value = LedgerAnchor::decode_canonical(d)?;
    if value.site_lineage.len() > 512 {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(value)
}
