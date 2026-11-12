#![forbid(unsafe_code)]

use fss_core::{
    BudgetQuantitiesSpec, BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContextAuthority, RuntimeGrant, TimestampNs,
};

use super::{RecordingReplayContextError, RecordingReplayContextRequest, ReplayTimeReadLimits};

/// A borrowed owner-issued grant for one exact replay request and finite read allowances.
///
/// This type has no implicit/default grant and cannot be constructed from an audit principal,
/// a historical receipt or `CAP-AGENT-QUERY-001` alone. The caller supplies real current
/// `CAP-READ-MEDIA-001` authority and its explicit deadline clock. The native owner additionally
/// checks its cancellation callback throughout I/O. This per-query grant does not disclose
/// source bytes, authorize effects or turn the historical source scope into deployment membership.
pub struct ReplaySourceReadPermit<'a> {
    authority: &'a ContextAuthority,
    now: &'a (dyn Fn() -> TimestampNs + Sync),
    query: ContentDigest,
    limits: ReplayTimeReadLimits,
    digest: ContentDigest,
}

impl<'a> ReplaySourceReadPermit<'a> {
    /// Narrow current query+media-read authority to exact source pins and query read ceilings.
    /// All validation is pure and precedes filesystem access.
    pub fn authorize(
        authority: &'a ContextAuthority,
        request: &RecordingReplayContextRequest,
        limits: ReplayTimeReadLimits,
        now: &'a (dyn Fn() -> TimestampNs + Sync),
    ) -> Result<Self, RecordingReplayContextError> {
        let query = request.replay.digest().map_err(|error| {
            RecordingReplayContextError::Replay(super::ReplayTimeReadError::Query(error))
        })?;
        limits
            .validate()
            .map_err(RecordingReplayContextError::Replay)?;
        authority
            .validate()
            .map_err(|_| RecordingReplayContextError::Unauthorized)?;
        let (bytes, calls) = read_allowance(limits)?;
        let allowance = BudgetVector::from_quantities(BudgetQuantitiesSpec {
            bytes,
            storage_operations: calls,
            ..BudgetQuantitiesSpec::ZERO
        });
        if !authority.budgets.is_valid()
            || !allowance.fits_within(authority.budgets)
            || authority.principal != request.principal.as_str()
            || authority.anchor_universe != request.replay.scope.recording.anchor
            || authority.generation != request.replay.scope.recording.generation
            || !authority.has_capability(RuntimeGrant::AgentQuery.as_str())
            || !authority.has_capability(RuntimeGrant::ReadMedia.as_str())
        {
            return Err(RecordingReplayContextError::Unauthorized);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.agent_recording_replay_query.source_permit.v1");
        request.principal.encode_canonical(&mut e);
        e.digest(query);
        e.digest(authority.anchor_universe);
        e.u64(authority.generation);
        e.text(RuntimeGrant::AgentQuery.as_str());
        e.text(RuntimeGrant::ReadMedia.as_str());
        e.text(&authority.privacy_scope);
        e.text(&authority.retention_scope);
        for bound in [limits.metadata, limits.originals] {
            for value in [
                bound.max_catalogue_entries,
                bound.max_objects,
                bound.max_edges,
                bound.max_object_bytes,
            ] {
                e.u64(value as u64);
            }
            e.u64(bound.max_read_bytes);
            e.u64(bound.max_io_calls);
        }
        let permit = Self {
            authority,
            now,
            query,
            limits,
            digest: ContentDigest::sha256(&e.finish()),
        };
        permit.check_current()?;
        Ok(permit)
    }

    /// Stable semantic source grant identity. Process IDs, trace/operation labels and actual
    /// clock readings are excluded; cancellation/deadline remain checked execution conditions.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub(super) fn check(
        &self,
        request: &RecordingReplayContextRequest,
        limits: ReplayTimeReadLimits,
        query: ContentDigest,
    ) -> Result<(), RecordingReplayContextError> {
        if self.query != query
            || self.limits != limits
            || self.authority.principal != request.principal.as_str()
            || self.authority.anchor_universe != request.replay.scope.recording.anchor
            || self.authority.generation != request.replay.scope.recording.generation
        {
            return Err(RecordingReplayContextError::Unauthorized);
        }
        self.check_current()
    }

    pub(super) fn check_current(&self) -> Result<(), RecordingReplayContextError> {
        if self.authority.cancellation_reason.is_some()
            || self
                .authority
                .deadline
                .is_some_and(|deadline| (self.now)() >= deadline)
        {
            Err(RecordingReplayContextError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

pub(super) fn read_allowance(
    limits: ReplayTimeReadLimits,
) -> Result<(u64, u64), RecordingReplayContextError> {
    let bytes = limits
        .metadata
        .max_read_bytes
        .checked_add(limits.originals.max_read_bytes)
        .ok_or(RecordingReplayContextError::InvalidRequest)?;
    let calls = limits
        .metadata
        .max_io_calls
        .checked_add(limits.originals.max_io_calls)
        .ok_or(RecordingReplayContextError::InvalidRequest)?;
    Ok((bytes, calls))
}
