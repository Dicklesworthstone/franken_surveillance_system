#![forbid(unsafe_code)]
//! Atomic, exactly approved session revocation witnesses. The witness and the retained closure
//! tombstone share one journal commit; neither represents cancellation of an external effect.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    LedgerAnchor, PrincipalId, SessionId, TimestampNs,
};

use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
    ReferenceSessionError, ReferenceSessionStore,
};

/// Additive private session command; an older reader must refuse, never lose the tombstone.
pub const SESSION_CANCELLATION_RECORD_KIND: u16 = 0x5343;
/// Private canonical request domain, not a new public response schema.
pub const SESSION_CANCELLATION_PLAN_DOMAIN: &str = "fss.reference_session_cancellation_plan.v1";
const RECORD_DOMAIN: &str = "fss.reference_session_cancellation.v1";
const MAX_ITEMS: usize = 256;
const MAX_BYTES: usize = 128 * 1024;

/// Exact revocation scope. Retained plans and obligations are preserved, not finalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCancellationPlan {
    /// Session identity whose future authority will be revoked.
    pub session_id: SessionId,
    /// Owner approving the revocation.
    pub principal: PrincipalId,
    /// Exact retained session authority before the transition.
    pub session_digest: ContentDigest,
    /// Complete session checkpoint before the transition.
    pub checkpoint_digest: ContentDigest,
    /// Complete journal predecessor, including workspace and coordination state.
    pub journal_root: ContentDigest,
    /// Deployment authority position when the request was prepared.
    pub basis_anchor: LedgerAnchor,
    /// Authority-journal prefix bound by the preview.
    pub authority_root: ContentDigest,
    /// Effect-journal prefix bound by the preview.
    pub effect_root: ContentDigest,
    /// Evidence-clock time, never a wall-clock lease extension.
    pub observed_at: TimestampNs,
    /// Complete bounded outstanding obligation inventory at the preview's position.
    pub unresolved_obligations: Vec<String>,
    /// Complete bounded active plan inventory for the owned mission at that position.
    pub retained_plans: Vec<String>,
}

impl SessionCancellationPlan {
    /// This digest identifies the entire request. It does not grant cancellation authority.
    pub fn approval_digest(&self) -> Result<ContentDigest, DurableSessionError> {
        let bytes = self.encode()?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode(&self) -> Result<Vec<u8>, DurableSessionError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SESSION_CANCELLATION_PLAN_DOMAIN);
        self.session_id.encode_canonical(&mut encoder);
        self.principal.encode_canonical(&mut encoder);
        encoder.digest(self.session_digest);
        encoder.digest(self.checkpoint_digest);
        encoder.digest(self.journal_root);
        self.basis_anchor.encode_canonical(&mut encoder);
        encoder.digest(self.authority_root);
        encoder.digest(self.effect_root);
        encoder.i128(self.observed_at.0);
        for items in [&self.unresolved_obligations, &self.retained_plans] {
            if items.len() > MAX_ITEMS
                || items.iter().any(|item| item.is_empty() || item.len() > 256)
                || items.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(DurableSessionError::CapacityExceeded);
            }
            encoder.u32(items.len() as u32);
            for item in items {
                encoder.text(item);
            }
        }
        let bytes = encoder.finish_checked()?;
        if bytes.len() > MAX_BYTES {
            return Err(DurableSessionError::CapacityExceeded);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DurableSessionError> {
        if bytes.len() > MAX_BYTES {
            return Err(DurableSessionError::CapacityExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != SESSION_CANCELLATION_PLAN_DOMAIN {
            return Err(DurableSessionError::InvalidHistory);
        }
        let plan = Self {
            session_id: SessionId::parse(decoder.text()?)?,
            principal: PrincipalId::parse(decoder.text()?)?,
            session_digest: decoder.digest()?,
            checkpoint_digest: decoder.digest()?,
            journal_root: decoder.digest()?,
            basis_anchor: LedgerAnchor::decode_canonical(&mut decoder)?,
            authority_root: decoder.digest()?,
            effect_root: decoder.digest()?,
            observed_at: TimestampNs(decoder.i128()?),
            unresolved_obligations: decode_items(&mut decoder)?,
            retained_plans: decode_items(&mut decoder)?,
        };
        decoder.ensure_finished()?;
        if plan.encode()? != bytes {
            return Err(DurableSessionError::InvalidHistory);
        }
        Ok(plan)
    }
}

fn decode_items(decoder: &mut CanonicalDecoder<'_>) -> Result<Vec<String>, DurableSessionError> {
    let count = decoder.u32()? as usize;
    if count > MAX_ITEMS {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let item = decoder.text()?;
        if item.is_empty() || item.len() > 256 {
            return Err(DurableSessionError::InvalidHistory);
        }
        items.push(item.to_owned());
    }
    Ok(items)
}

/// Durable proof of only the session-authority transition, with the original exact request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCancellationReceipt {
    /// Approved immutable request, retained even when later session records are appended.
    pub plan: SessionCancellationPlan,
    /// Exact journal root of this cancellation commit, not a later inspection head.
    pub journal_root: ContentDigest,
    /// Exact session checkpoint after clearing aliases and retaining the tombstone.
    pub checkpoint_digest: ContentDigest,
}

fn record_bytes(
    plan: &SessionCancellationPlan,
    checkpoint: ContentDigest,
) -> Result<Vec<u8>, DurableSessionError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(RECORD_DOMAIN);
    encoder.bytes(&plan.encode()?);
    encoder.digest(plan.approval_digest()?);
    encoder.digest(checkpoint);
    Ok(encoder.finish_checked()?)
}

fn decode_record(
    bytes: &[u8],
    root: ContentDigest,
) -> Result<SessionCancellationReceipt, DurableSessionError> {
    if bytes.len() > MAX_BYTES + 256 {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != RECORD_DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let plan = SessionCancellationPlan::decode(decoder.bytes()?)?;
    if decoder.digest()? != plan.approval_digest()? {
        return Err(DurableSessionError::InvalidHistory);
    }
    let checkpoint_digest = decoder.digest()?;
    decoder.ensure_finished()?;
    if record_bytes(&plan, checkpoint_digest)? != bytes {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(SessionCancellationReceipt {
        plan,
        journal_root: root,
        checkpoint_digest,
    })
}

fn apply(
    memory: &mut ReferenceSessionStore,
    plan: &SessionCancellationPlan,
    predecessor: ContentDigest,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if predecessor != plan.journal_root
        || memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != plan.checkpoint_digest
    {
        return Err(DurableSessionError::RootMismatch);
    }
    let entry = memory
        .sessions
        .get(&plan.session_id)
        .ok_or(DurableSessionError::Session(
            ReferenceSessionError::Unavailable,
        ))?;
    if entry.closed
        || entry.session.principal_id != plan.principal
        || entry.session.session_digest() != plan.session_digest
        || entry.session.current_anchor.site_lineage != plan.basis_anchor.site_lineage
        || plan.observed_at.0 < entry.last_observed_at.0
        || plan.observed_at.0 >= entry.session.expires_at_ns
    {
        return Err(DurableSessionError::Session(
            ReferenceSessionError::Unavailable,
        ));
    }
    memory
        .close(&plan.principal, &plan.session_id, plan.observed_at)
        .map_err(DurableSessionError::Session)
}

impl DurableSessionStore {
    /// The native owner has already admitted fresh cancellation authority and exact approval.
    /// This append atomically retains the request and revokes the session; no claim, workspace,
    /// follow descriptor, plan or external effect is erased or silently marked terminal.
    pub(crate) fn cancel_session_authority(
        &mut self,
        plan: &SessionCancellationPlan,
    ) -> Result<SessionCancellationReceipt, DurableSessionError> {
        self.preflight()?;
        let mut memory = self.memory.clone();
        apply(&mut memory, plan, self.committed_root(), self.limits)?;
        let checkpoint = memory.checkpoint(self.limits.max_checkpoint_bytes)?;
        let checkpoint_digest = checkpoint.digest();
        let bytes = record_bytes(plan, checkpoint_digest)?;
        self.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: None,
            record: Some((SESSION_CANCELLATION_RECORD_KIND, bytes)),
        })?;
        Ok(SessionCancellationReceipt {
            plan: plan.clone(),
            journal_root: self.committed_root(),
            checkpoint_digest,
        })
    }
}

/// Only use after full bounded journal replay. This does not admit an actor or a new request.
pub(crate) fn retained_receipt(
    report: &fss_ledger::RecoveryReport,
    principal: &PrincipalId,
    session: &SessionId,
) -> Result<Option<SessionCancellationReceipt>, DurableSessionError> {
    let mut found = None;
    for record in report.records() {
        if record.kind() != SESSION_CANCELLATION_RECORD_KIND {
            continue;
        }
        let receipt = decode_record(record.payload(), record.root())?;
        if receipt.plan.session_id == *session && receipt.plan.principal == *principal {
            if found.replace(receipt).is_some() {
                return Err(DurableSessionError::InvalidHistory);
            }
        }
    }
    Ok(found)
}

pub(super) fn replay_command(
    bytes: &[u8],
    memory: &mut ReferenceSessionStore,
    predecessor: ContentDigest,
    root: ContentDigest,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    let receipt = decode_record(bytes, root)?;
    apply(memory, &receipt.plan, predecessor, limits)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    if memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != receipt.checkpoint_digest {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
