#![forbid(unsafe_code)]
//! Exact, bounded checkpoints for the reference session authority.
//!
//! Checkpoint bytes are private authority state, not an agent response. The caller must protect
//! them and pin their digest in trusted custody. A checksum supplied alongside an untrusted file
//! does not authenticate it or prevent rollback. Recovery never follows a `latest` alias.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    AgentSession, AgentSessionParams, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, ContentDigest, ContractBasis, ContractError, LedgerAnchor, MissionId,
    PrincipalId, SessionId, TimestampNs,
};

use super::{ReferenceSessionLimits, ReferenceSessionStore, ResolvedSessionHandle, SessionEntry};

/// Crash-classifying, journal-backed session lifecycle and delivery.
pub mod journal;

/// Private reference checkpoint format; not a replacement for the public session schema.
pub const SESSION_CHECKPOINT_FORMAT: &str = "fss.reference_session_checkpoint.v1";
/// Hard allocation/admission ceiling, even when the caller supplies a larger budget.
pub const MAX_SESSION_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;

/// A canonical snapshot containing tombstones, symbol identities, clock watermarks, and charges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCheckpoint {
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl SessionCheckpoint {
    /// Exact bytes to place into protected custody.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact content identity to retain independently of the checkpoint bytes.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Recovery failures deliberately exclude principal, symbol, and subject identities.
#[derive(Debug)]
pub enum SessionCheckpointError {
    /// Caller or format capacity was exceeded; no partial state is returned.
    CapacityExceeded,
    /// Bytes did not match the independently pinned checkpoint identity.
    IntegrityMismatch,
    /// Checkpoint version is not supported; no implicit migration is attempted.
    UnsupportedFormat,
    /// Decoded records violate session-store invariants.
    InvalidState,
    /// Canonical data was malformed, noncanonical, or truncated.
    Contract(ContractError),
}

impl fmt::Display for SessionCheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CapacityExceeded => "session checkpoint capacity exceeded",
            Self::IntegrityMismatch => "session checkpoint identity mismatch",
            Self::UnsupportedFormat => "unsupported session checkpoint format",
            Self::InvalidState => "invalid session checkpoint state",
            Self::Contract(_) => "malformed session checkpoint",
        })
    }
}

impl std::error::Error for SessionCheckpointError {}

impl From<ContractError> for SessionCheckpointError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl ReferenceSessionStore {
    /// Seals exact state without changing lease times, grants, or spent-token accounting.
    ///
    /// Failed reads can advance clock watermarks or close expired sessions, so owners must
    /// checkpoint those mutations too. This method performs no I/O and grants no authority.
    pub fn checkpoint(
        &self,
        max_bytes: usize,
    ) -> Result<SessionCheckpoint, SessionCheckpointError> {
        let mut output = BoundedCheckpoint {
            bytes: Vec::new(),
            limit: max_bytes.min(MAX_SESSION_CHECKPOINT_BYTES),
        };
        output.field(|encoder| encoder.text(SESSION_CHECKPOINT_FORMAT))?;
        for limit in limit_values(self.limits) {
            output.count(limit)?;
        }
        if self.sessions.len() > self.limits.max_sessions {
            return Err(SessionCheckpointError::CapacityExceeded);
        }
        output.count(self.sessions.len())?;
        for (id, entry) in &self.sessions {
            if id != &entry.session.session_id {
                return Err(SessionCheckpointError::InvalidState);
            }
            validate_entry(entry, self.limits)?;
            // Bound variable-sized session fields before asking the core encoder to allocate.
            let (count, bytes) = grant_size(&entry.session)?;
            let overhead = count
                .checked_mul(8)
                .and_then(|value| value.checked_add(bytes));
            if overhead.is_none_or(|value| value > output.limit) {
                return Err(SessionCheckpointError::CapacityExceeded);
            }
            output.blob(&entry.session.try_canonical_bytes()?)?;
            output.field(|encoder| encoder.digest(entry.opening_digest))?;
            let basis_bytes = entry.basis.try_canonical_bytes()?;
            if ContractBasis::from_canonical_bytes(&basis_bytes)? != entry.basis {
                return Err(SessionCheckpointError::InvalidState);
            }
            output.blob(&basis_bytes)?;
            output.field(|encoder| {
                encoder.u64(entry.next_slot);
                encoder.u64(entry.spent_tokens);
                encoder.i128(entry.last_observed_at.0);
                encoder.bool(entry.closed);
            })?;
            output.count(entry.symbols.len())?;
            for (slot, symbol) in &entry.symbols {
                output.field(|encoder| {
                    encoder.u64(*slot);
                    encoder.text(&symbol.handle_id);
                    encoder.digest(symbol.descriptor_digest);
                    encoder.digest(symbol.subject_digest);
                })?;
            }
        }
        Ok(SessionCheckpoint {
            digest: ContentDigest::sha256(&output.bytes),
            bytes: output.bytes,
        })
    }

    /// Restores an exact, independently pinned checkpoint under current runtime ceilings.
    ///
    /// Stored limits cannot exceed `ceilings` and are never silently widened. No state is
    /// returned on failure. Catalog availability and principal grants are still checked on
    /// every later resolve/hydration; a restored alias is not an authority shortcut.
    pub fn restore_checkpoint(
        bytes: &[u8],
        expected_digest: ContentDigest,
        ceilings: ReferenceSessionLimits,
        max_bytes: usize,
    ) -> Result<Self, SessionCheckpointError> {
        if bytes.len() > max_bytes.min(MAX_SESSION_CHECKPOINT_BYTES) {
            return Err(SessionCheckpointError::CapacityExceeded);
        }
        if ContentDigest::sha256(bytes) != expected_digest {
            return Err(SessionCheckpointError::IntegrityMismatch);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != SESSION_CHECKPOINT_FORMAT {
            return Err(SessionCheckpointError::UnsupportedFormat);
        }
        let limits = ReferenceSessionLimits {
            max_sessions: bounded_count(&mut decoder, ceilings.max_sessions)?,
            max_symbols_per_session: bounded_count(&mut decoder, ceilings.max_symbols_per_session)?,
            max_grants_per_session: bounded_count(&mut decoder, ceilings.max_grants_per_session)?,
            max_grant_bytes_per_session: bounded_count(
                &mut decoder,
                ceilings.max_grant_bytes_per_session,
            )?,
        };
        let count = bounded_count(&mut decoder, limits.max_sessions)?;
        let mut sessions = BTreeMap::new();
        for _ in 0..count {
            let session = decode_session(decoder.bytes()?, limits)?;
            if sessions
                .last_key_value()
                .is_some_and(|(id, _)| id >= &session.session_id)
            {
                return Err(SessionCheckpointError::InvalidState);
            }
            let opening_digest = decoder.digest()?;
            let basis_bytes = decoder.bytes()?;
            let basis = ContractBasis::from_canonical_bytes(basis_bytes)?;
            if basis.try_canonical_bytes()? != basis_bytes {
                return Err(SessionCheckpointError::InvalidState);
            }
            let next_slot = decoder.u64()?;
            let spent_tokens = decoder.u64()?;
            let last_observed_at = TimestampNs(decoder.i128()?);
            let closed = decoder.bool()?;
            let symbol_count = bounded_count(&mut decoder, limits.max_symbols_per_session)?;
            let mut symbols = BTreeMap::new();
            for _ in 0..symbol_count {
                let slot = decoder.u64()?;
                if symbols
                    .last_key_value()
                    .is_some_and(|(previous, _)| previous >= &slot)
                {
                    return Err(SessionCheckpointError::InvalidState);
                }
                symbols.insert(
                    slot,
                    ResolvedSessionHandle {
                        handle_id: decoder.text()?.to_owned(),
                        descriptor_digest: decoder.digest()?,
                        subject_digest: decoder.digest()?,
                    },
                );
            }
            let entry = SessionEntry {
                session,
                opening_digest,
                basis,
                symbols,
                next_slot,
                spent_tokens,
                last_observed_at,
                closed,
            };
            validate_entry(&entry, limits)?;
            sessions.insert(entry.session.session_id.clone(), entry);
        }
        decoder.ensure_finished()?;
        Ok(Self { sessions, limits })
    }
}

fn limit_values(limits: ReferenceSessionLimits) -> [usize; 4] {
    [
        limits.max_sessions,
        limits.max_symbols_per_session,
        limits.max_grants_per_session,
        limits.max_grant_bytes_per_session,
    ]
}

fn grant_size(session: &AgentSession) -> Result<(usize, usize), SessionCheckpointError> {
    let count = session
        .capabilities
        .len()
        .checked_add(session.privacy_scope.len());
    let bytes = session
        .capabilities
        .iter()
        .chain(&session.privacy_scope)
        .try_fold(0_usize, |sum, value| sum.checked_add(value.len()));
    match (count, bytes) {
        (Some(count), Some(bytes)) => Ok((count, bytes)),
        _ => Err(SessionCheckpointError::CapacityExceeded),
    }
}

fn validate_entry(
    entry: &SessionEntry,
    limits: ReferenceSessionLimits,
) -> Result<(), SessionCheckpointError> {
    let (grants, bytes) = grant_size(&entry.session)?;
    if grants > limits.max_grants_per_session
        || bytes > limits.max_grant_bytes_per_session
        || entry.symbols.len() > limits.max_symbols_per_session
    {
        return Err(SessionCheckpointError::CapacityExceeded);
    }
    if entry.basis.semantic_protocol != "fss/1"
        || entry.session.token_budget == 0
        || entry.session.expires_at_ns <= entry.session.created_at_ns
        || entry.last_observed_at.0 < entry.session.created_at_ns
        || entry.spent_tokens > entry.session.token_budget
        || (entry.closed && !entry.symbols.is_empty())
        || (!entry.closed && entry.last_observed_at.0 >= entry.session.expires_at_ns)
    {
        return Err(SessionCheckpointError::InvalidState);
    }
    if !entry.closed {
        let count = u64::try_from(entry.symbols.len())
            .map_err(|_| SessionCheckpointError::CapacityExceeded)?;
        if entry.next_slot != count {
            return Err(SessionCheckpointError::InvalidState);
        }
    }
    for (index, (slot, symbol)) in entry.symbols.iter().enumerate() {
        let expected = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1));
        if expected != Some(*slot) || *slot > entry.next_slot || symbol.handle_id.is_empty() {
            return Err(SessionCheckpointError::InvalidState);
        }
    }
    Ok(())
}

fn bounded_count(
    decoder: &mut CanonicalDecoder<'_>,
    ceiling: usize,
) -> Result<usize, SessionCheckpointError> {
    let value =
        usize::try_from(decoder.u64()?).map_err(|_| SessionCheckpointError::CapacityExceeded)?;
    if value > ceiling {
        return Err(SessionCheckpointError::CapacityExceeded);
    }
    Ok(value)
}

fn decode_grants(
    decoder: &mut CanonicalDecoder<'_>,
    remaining_count: &mut usize,
    remaining_bytes: &mut usize,
) -> Result<BTreeSet<String>, SessionCheckpointError> {
    let count =
        usize::try_from(decoder.u32()?).map_err(|_| SessionCheckpointError::CapacityExceeded)?;
    *remaining_count = remaining_count
        .checked_sub(count)
        .ok_or(SessionCheckpointError::CapacityExceeded)?;
    let mut grants = BTreeSet::new();
    for _ in 0..count {
        let value = decoder.text()?;
        *remaining_bytes = remaining_bytes
            .checked_sub(value.len())
            .ok_or(SessionCheckpointError::CapacityExceeded)?;
        if grants
            .last()
            .is_some_and(|previous: &String| previous.as_str() >= value)
        {
            return Err(SessionCheckpointError::InvalidState);
        }
        grants.insert(value.to_owned());
    }
    Ok(grants)
}

fn decode_session(
    bytes: &[u8],
    limits: ReferenceSessionLimits,
) -> Result<AgentSession, SessionCheckpointError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != AgentSession::SCHEMA {
        return Err(SessionCheckpointError::UnsupportedFormat);
    }
    let session_id = SessionId::parse(decoder.text()?)?;
    let mission_id = MissionId::parse(decoder.text()?)?;
    let principal_id = PrincipalId::parse(decoder.text()?)?;
    let mut count = limits.max_grants_per_session;
    let mut budget = limits.max_grant_bytes_per_session;
    let capabilities = decode_grants(&mut decoder, &mut count, &mut budget)?;
    let privacy_scope = decode_grants(&mut decoder, &mut count, &mut budget)?;
    let current_anchor = LedgerAnchor::decode_canonical(&mut decoder)?;
    let view_id = decoder.text()?.to_owned();
    let token_budget = decoder.u64()?;
    let symbol_table_generation = decoder.u64()?;
    let fingerprint = if decoder.bool()? {
        Some(decoder.digest()?)
    } else {
        None
    };
    let session = AgentSession::new(AgentSessionParams {
        session_id,
        mission_id,
        principal_id,
        capabilities,
        privacy_scope,
        current_anchor,
        view_id,
        token_budget,
        symbol_table_generation,
        last_acknowledged_situation_fingerprint: fingerprint,
        created_at_ns: decoder.i128()?,
        expires_at_ns: decoder.i128()?,
    })?;
    decoder.ensure_finished()?;
    // Reject alternative spellings accepted by a nested decoder, rather than normalizing them.
    if session.try_canonical_bytes()? != bytes {
        return Err(SessionCheckpointError::InvalidState);
    }
    Ok(session)
}

struct BoundedCheckpoint {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedCheckpoint {
    fn append(&mut self, bytes: &[u8]) -> Result<(), SessionCheckpointError> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > self.limit)
        {
            return Err(SessionCheckpointError::CapacityExceeded);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn field(
        &mut self,
        write: impl FnOnce(&mut CanonicalEncoder),
    ) -> Result<(), SessionCheckpointError> {
        let mut encoder = CanonicalEncoder::new();
        write(&mut encoder);
        self.append(&encoder.finish_checked()?)
    }

    fn count(&mut self, count: usize) -> Result<(), SessionCheckpointError> {
        let count = u64::try_from(count).map_err(|_| SessionCheckpointError::CapacityExceeded)?;
        self.field(|encoder| encoder.u64(count))
    }

    fn blob(&mut self, bytes: &[u8]) -> Result<(), SessionCheckpointError> {
        self.count(bytes.len())?;
        self.append(bytes)
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
