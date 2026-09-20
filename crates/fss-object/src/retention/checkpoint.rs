#![forbid(unsafe_code)]
//! Canonical retention metadata recovery, without restoring source bytes or inventing authority.
//!
//! The owner must protect the checkpoint and pin its root independently. Recovery requires the
//! current exact custody state and accepted policy. This is not a disk transaction or permission
//! to restore an old checkpoint and old source copies after deletion. No payload is serialized.

use fss_core::{CanonicalDecoder, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use super::*;

/// Maximum canonical checkpoint bytes; lower per-operation ceilings may be supplied.
pub const MAX_RETENTION_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
const FORMAT: &str = "fss.reference_retention_checkpoint.v1";

/// Exact metadata bytes and the root the trusted runtime must retain independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionCheckpoint {
    bytes: Vec<u8>,
    digest: ContentDigest,
}
impl RetentionCheckpoint {
    /// Private retention/hold/receipt metadata for protected persistence, never source payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    /// Exact root; receiving this alongside untrusted bytes does not authenticate them.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest { self.digest }
}

/// Recovery bounds, including the additional source-custody clone made for the returned owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionRecoveryBudget {
    /// Input and canonical output byte ceiling, capped by the private format.
    pub max_checkpoint_bytes: usize,
    /// Maximum source payload bytes cloned from supplied current custody.
    pub max_custody_bytes: u64,
}

impl RetentionStore {
    /// Encodes rules, dependencies, active/released holds, tombstones and exact retry receipts.
    /// A low output ceiling refuses the operation rather than dropping protection or history.
    pub fn checkpoint(&self, max_bytes: usize) -> Result<RetentionCheckpoint, RetentionError> {
        self.validate_recovered_metadata()?;
        let mut e = CanonicalEncoder::new();
        e.text(FORMAT); e.bytes(&self.encode_state()?);
        e.u64(self.receipts.len() as u64);
        for receipt in self.receipts.values() { receipt.encode_checkpoint(&mut e); }
        let bytes = e.finish_checked()?;
        if bytes.len() > max_bytes.min(MAX_RETENTION_CHECKPOINT_BYTES) {
            return Err(RetentionError::CapacityExceeded);
        }
        Ok(RetentionCheckpoint { digest: ContentDigest::sha256(&bytes), bytes })
    }

    /// Restores metadata ONLY against independently pinned bytes, accepted policy and CURRENT
    /// exact custody. Missing, additional, corrupt, resurrected or differently tombstoned objects
    /// cause refusal. Failed recovery never mutates the supplied custody owner.
    ///
    /// The returned reference owner receives an explicitly bounded clone of custody; it performs
    /// no I/O and authenticates no principal. Runtime grants must still authorize future writes.
    /// Supplying both an old root and old custody is outside the independently pinned-root contract.
    pub fn restore_checkpoint(bytes: &[u8], expected_digest: ContentDigest,
        expected_policy: ContentDigest, custody: &InMemoryObjectStore, ceilings: RetentionLimits,
        budget: RetentionRecoveryBudget) -> Result<Self, RetentionError>
    {
        if bytes.len() > budget.max_checkpoint_bytes.min(MAX_RETENTION_CHECKPOINT_BYTES) {
            return Err(RetentionError::CapacityExceeded);
        }
        if ContentDigest::sha256(bytes) != expected_digest { return Err(RetentionError::StalePlan); }
        if custody.total_bytes() > budget.max_custody_bytes {
            return Err(RetentionError::StagingBudgetExceeded);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != FORMAT { return Err(RetentionError::InvalidRecord); }
        let state_bytes = d.bytes()?;
        let mut state = CanonicalDecoder::new(state_bytes);
        if state.text()? != "fss.reference_retention_state.v1" { return Err(RetentionError::InvalidRecord); }
        let policy = state.digest()?;
        if policy != expected_policy { return Err(RetentionError::Unauthorized); }
        let revision = state.u64()?;
        let limits = RetentionLimits {
            max_entries: count(&mut state, ceilings.max_entries.min(MAX_RETENTION_ENTRIES))?,
            max_edges: count(&mut state, ceilings.max_edges.min(MAX_RETENTION_EDGES))?,
            max_holds: count(&mut state, ceilings.max_holds.min(MAX_RETENTION_HOLDS))?,
            max_receipts: count(&mut state, ceilings.max_receipts.min(MAX_RETENTION_RECEIPTS))?,
        };
        let object_limits = ObjectLimits::new(count(&mut state, usize::MAX)?, state.u64()?);
        if object_limits != custody.limits() { return Err(RetentionError::InvalidRecord); }
        let last_commit_at = if state.bool()? { Some(TimestampNs(state.i128()?)) } else { None };
        let mut entries = BTreeMap::new(); let mut edges = 0_usize;
        for _ in 0..count(&mut state, limits.max_entries)? {
            let digest = state.digest()?;
            require_next(entries.last_key_value().map(|(key, _)| *key), digest)?;
            let rule = RetentionRule { retain_until: TimestampNs(state.i128()?), reason: text(&mut state)? };
            let payload_bytes = state.u64()?; let manifest = state.bool()?;
            if payload_bytes > crate::MAX_OBJECT_BYTES as u64 { return Err(RetentionError::InvalidRecord); }
            let n = count(&mut state, limits.max_edges.saturating_sub(edges))?;
            edges += n;
            let mut dependencies = BTreeSet::new();
            for _ in 0..n {
                let dependency = state.digest()?;
                require_next(dependencies.last().copied(), dependency)?;
                dependencies.insert(dependency);
            }
            let deleted_by = if state.bool()? { Some(state.digest()?) } else { None };
            entries.insert(digest, Entry { rule, dependencies, bytes: payload_bytes, manifest, deleted_by });
        }
        let mut holds = BTreeMap::new();
        for _ in 0..count(&mut state, limits.max_holds)? {
            let id = text(&mut state)?;
            if holds.last_key_value().is_some_and(|(prior, _)| prior >= &id) {
                return Err(RetentionError::InvalidRecord);
            }
            holds.insert(id, Hold { subject: state.digest()?, witness: state.digest()?,
                released_by: if state.bool()? { Some(state.digest()?) } else { None } });
        }
        state.ensure_finished()?;
        let mut receipts = BTreeMap::new(); let mut total_deleted = 0;
        for _ in 0..count(&mut d, limits.max_receipts)? {
            let receipt = DeletionReceipt::decode_checkpoint(&mut d, entries.len() - total_deleted)?;
            total_deleted += receipt.deleted().len();
            let key = receipt.plan_digest();
            require_next(receipts.last_key_value().map(|(key, _)| *key), key)?;
            receipts.insert(key, receipt);
        }
        d.ensure_finished()?;
        let restored = Self { custody: custody.clone(), policy, limits, entries, holds, receipts,
            revision, last_commit_at };
        restored.validate_recovered_metadata()?;
        // Refuse alternate encodings, dropped fields and normalized-but-different metadata.
        if restored.encode_state()? != state_bytes
            || restored.checkpoint(budget.max_checkpoint_bytes)?.as_bytes() != bytes
        { return Err(RetentionError::InvalidRecord); }
        Ok(restored)
    }

    fn validate_recovered_metadata(&self) -> Result<(), RetentionError> {
        self.verify_live_graph()?;
        let mutations = self.entries.len() + self.holds.len() + self.receipts.len()
            + self.holds.values().filter(|hold| hold.released_by.is_some()).count();
        if self.revision != mutations as u64 { return Err(RetentionError::InvalidRecord); }
        let mut incoming = BTreeMap::new(); let mut dependents: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut live_bytes = 0_u64;
        for (digest, entry) in &self.entries {
            if !valid_text(&entry.rule.reason) { return Err(RetentionError::InvalidRecord); }
            if entry.deleted_by.is_none() {
                live_bytes = live_bytes.checked_add(entry.bytes).ok_or(RetentionError::CapacityExceeded)?;
            }
            incoming.insert(*digest, entry.dependencies.len());
            for dependency in &entry.dependencies {
                if !self.entries.contains_key(dependency) { return Err(RetentionError::InvalidRecord); }
                dependents.entry(*dependency).or_default().push(*digest);
            }
        }
        if live_bytes != self.custody.total_bytes() { return Err(RetentionError::InvalidRecord); }
        let mut ready: Vec<_> = incoming.iter().filter_map(|(key, count)| (*count == 0).then_some(*key)).collect();
        let mut visited = 0;
        while let Some(digest) = ready.pop() {
            visited += 1;
            if let Some(children) = dependents.get(&digest) {
                for child in children {
                    let count = incoming.get_mut(child).ok_or(RetentionError::InvalidRecord)?;
                    *count = count.checked_sub(1).ok_or(RetentionError::InvalidRecord)?;
                    if *count == 0 { ready.push(*child); }
                }
            }
        }
        if visited != self.entries.len() { return Err(RetentionError::InvalidRecord); }
        for (id, hold) in &self.holds {
            if !valid_text(id) || !self.entries.contains_key(&hold.subject)
                || !self.entries.contains_key(&hold.witness)
            { return Err(RetentionError::InvalidRecord); }
            if let Some(released) = hold.released_by {
                if !self.entries.contains_key(&released) { return Err(RetentionError::InvalidRecord); }
            } else { self.live_entry(hold.subject)?; self.live_entry(hold.witness)?; }
        }
        let mut deleted = BTreeSet::new(); let mut latest_time = None;
        let generation = Generation::parse_positive(1)?;
        for (plan, receipt) in &self.receipts {
            if *plan != receipt.plan_digest() || receipt.policy() != self.policy
                || !self.entries.contains_key(&receipt.witness())
            { return Err(RetentionError::InvalidRecord); }
            let mut released_bytes = 0_u64;
            for digest in receipt.deleted() {
                let entry = self.entries.get(digest).ok_or(RetentionError::InvalidRecord)?;
                if !deleted.insert(*digest) || entry.deleted_by != Some(*plan)
                    || receipt.committed_at() < entry.rule.retain_until
                { return Err(RetentionError::InvalidRecord); }
                let expected = TombstoneRecord::new(ObjectId::parse(format!("object:retention:{digest}"))?,
                    generation.next()?, generation, TombstoneReason::Deleted, Some(receipt.witness()), *digest)?;
                if self.custody.tombstone_record(*digest) != Some(&expected) {
                    return Err(RetentionError::InvalidRecord);
                }
                released_bytes = released_bytes.checked_add(entry.bytes).ok_or(RetentionError::CapacityExceeded)?;
            }
            if released_bytes != receipt.released_bytes() { return Err(RetentionError::InvalidRecord); }
            latest_time = Some(latest_time.map_or(receipt.committed_at(), |time: TimestampNs| time.max(receipt.committed_at())));
        }
        if self.entries.iter().any(|(digest, entry)| entry.deleted_by.is_some() != deleted.contains(digest))
            || latest_time != self.last_commit_at
        { return Err(RetentionError::InvalidRecord); }
        Ok(())
    }
}

fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize, RetentionError> {
    let count = usize::try_from(d.u64()?).map_err(|_| RetentionError::CapacityExceeded)?;
    if count > maximum { return Err(RetentionError::CapacityExceeded); }
    Ok(count)
}
fn text(d: &mut CanonicalDecoder<'_>) -> Result<String, RetentionError> {
    let value = d.text()?;
    if !valid_text(value) { return Err(RetentionError::InvalidRecord); }
    Ok(value.to_owned())
}
fn require_next(prior: Option<ContentDigest>, next: ContentDigest) -> Result<(), RetentionError> {
    if prior.is_some_and(|value| value >= next) { return Err(RetentionError::InvalidRecord); }
    Ok(())
}

#[cfg(test)]
mod tests;
