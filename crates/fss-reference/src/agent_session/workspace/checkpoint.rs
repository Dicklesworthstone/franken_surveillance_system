#![forbid(unsafe_code)]
//! Bounded recovery of complete workspace history under an independently trusted root.
//!
//! Checkpoints contain private cognition and authorization metadata. Protect their custody; a
//! digest supplied beside an untrusted file does not authenticate it or prevent rollback. Recovery
//! restores no session, lease, capability, or privacy grant. Every later access still goes through
//! the live session authority. The format is private reference storage, not public schema JSON.

use fss_core::{BudgetVector, CanonicalDecode, CanonicalDecoder};

use super::*;

/// Versioned private workspace checkpoint format.
pub const WORKSPACE_CHECKPOINT_FORMAT: &str = "fss.reference_workspace_checkpoint.v1";
/// Hard bound including history framing and stored limits.
pub const MAX_WORKSPACE_CHECKPOINT_BYTES: usize = 2 * MAX_WORKSPACE_HISTORY_BYTES;

/// Exact private bytes and the identity to retain independently in trusted custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCheckpoint {
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl WorkspaceCheckpoint {
    /// Canonical bytes for protected persistence, not an agent response.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Identity that must be pinned independently of the checkpoint itself.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Recovery failures return no partially restored store or private record identifiers.
#[derive(Debug)]
pub enum WorkspaceCheckpointError {
    /// The snapshot does not match the independently pinned content identity.
    IntegrityMismatch,
    /// The private format requires an explicit migration.
    UnsupportedFormat,
    /// Capacity, ordering, identity, or transition invariants were violated.
    InvalidHistory,
    /// An input/allocation/record ceiling would be exceeded.
    CapacityExceeded,
    /// Canonical decoding or a nested contract failed.
    Contract(ContractError),
    /// A retained workspace transition failed its normal write validation.
    Workspace(WorkspaceError),
}

impl fmt::Display for WorkspaceCheckpointError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::IntegrityMismatch => "workspace checkpoint identity mismatch",
            Self::UnsupportedFormat => "unsupported workspace checkpoint format",
            Self::InvalidHistory => "invalid workspace checkpoint history",
            Self::CapacityExceeded => "workspace checkpoint capacity exceeded",
            Self::Contract(_) => "malformed workspace checkpoint",
            Self::Workspace(_) => "invalid retained workspace transition",
        })
    }
}

impl std::error::Error for WorkspaceCheckpointError {}

impl From<ContractError> for WorkspaceCheckpointError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<WorkspaceError> for WorkspaceCheckpointError {
    fn from(value: WorkspaceError) -> Self {
        Self::Workspace(value)
    }
}

impl ReferenceWorkspaceStore {
    /// Seals every immutable revision, including superseded decisions and invalidated actions.
    /// Refuses insufficient storage instead of truncating history or dropping obligations.
    pub fn checkpoint(&self, max_bytes: usize) -> Result<WorkspaceCheckpoint, WorkspaceCheckpointError> {
        let mut output = BoundedOutput {
            bytes: Vec::new(),
            limit: max_bytes.min(MAX_WORKSPACE_CHECKPOINT_BYTES),
        };
        output.field(|encoder| encoder.text(WORKSPACE_CHECKPOINT_FORMAT))?;
        for limit in limit_values(self.limits) {
            output.count(limit)?;
        }
        output.count(self.histories.len())?;
        for (session, history) in &self.histories {
            output.field(|encoder| session.encode_canonical(encoder))?;
            output.count(history.len())?;
            for revision in history {
                output.count(revision.bytes.len())?;
                output.append(&revision.bytes)?;
            }
        }
        Ok(WorkspaceCheckpoint {
            digest: ContentDigest::sha256(&output.bytes),
            bytes: output.bytes,
        })
    }

    /// Restores only an exact trusted checkpoint. All histories are checked before returning any
    /// state: limits, sorted identities, contiguous revisions, predecessor roots, preservation,
    /// rebase invalidations, and canonical byte equality. No session authority is restored here.
    pub fn restore_checkpoint(
        bytes: &[u8],
        expected_digest: ContentDigest,
        ceilings: WorkspaceLimits,
        max_bytes: usize,
    ) -> Result<Self, WorkspaceCheckpointError> {
        if bytes.len() > max_bytes.min(MAX_WORKSPACE_CHECKPOINT_BYTES) {
            return Err(WorkspaceCheckpointError::CapacityExceeded);
        }
        if ContentDigest::sha256(bytes) != expected_digest {
            return Err(WorkspaceCheckpointError::IntegrityMismatch);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != WORKSPACE_CHECKPOINT_FORMAT {
            return Err(WorkspaceCheckpointError::UnsupportedFormat);
        }
        let ceilings = ceilings.bounded();
        let limits = WorkspaceLimits {
            max_workspaces: count(&mut decoder, ceilings.max_workspaces)?,
            max_revisions_per_workspace: count(&mut decoder, ceilings.max_revisions_per_workspace)?,
            max_revision_bytes: count(&mut decoder, ceilings.max_revision_bytes)?,
            max_history_bytes: count(&mut decoder, ceilings.max_history_bytes)?,
        };
        let histories = count(&mut decoder, limits.max_workspaces)?;
        let mut store = Self::with_limits(limits);
        for _ in 0..histories {
            let session = SessionId::parse(text(&mut decoder, 256)?)?;
            if store.histories.last_key_value().is_some_and(|(id, _)| id >= &session) {
                return Err(WorkspaceCheckpointError::InvalidHistory);
            }
            let revisions = count(&mut decoder, limits.max_revisions_per_workspace)?;
            if revisions == 0 {
                return Err(WorkspaceCheckpointError::InvalidHistory);
            }
            let mut history: Vec<WorkspaceRevision> = Vec::new();
            for _ in 0..revisions {
                let raw = decoder.bytes()?;
                if raw.len() > limits.max_revision_bytes {
                    return Err(WorkspaceCheckpointError::CapacityExceeded);
                }
                let total = store.retained_bytes.checked_add(raw.len())
                    .filter(|total| *total <= limits.max_history_bytes)
                    .ok_or(WorkspaceCheckpointError::CapacityExceeded)?;
                let revision = decode_revision(raw, limits)?;
                if revision.capsule.session_id != session {
                    return Err(WorkspaceCheckpointError::InvalidHistory);
                }
                let previous = history.last();
                if let Some(old) = previous {
                    if old.basis != revision.basis
                        || old.mission_id != revision.mission_id
                        || old.capsule.principal != revision.capsule.principal
                        || old.capability_scope != revision.capability_scope
                        || old.privacy_scope != revision.privacy_scope
                    {
                        return Err(WorkspaceCheckpointError::InvalidHistory);
                    }
                }
                let request = WorkspaceWrite {
                    expected_head: revision.parent,
                    capsule: revision.capsule.clone(),
                    mode: if revision.rebase_from.is_some() {
                        WorkspaceWriteMode::Rebase
                    } else {
                        WorkspaceWriteMode::Advance
                    },
                };
                if validate_successor(previous, &request)? != revision.rebase_from {
                    return Err(WorkspaceCheckpointError::InvalidHistory);
                }
                let expected_actions = if revision.rebase_from.is_some() {
                    previous.map_or(&[][..], |old| old.capsule.next_actions.as_slice())
                } else {
                    &[][..]
                };
                if revision.invalidated_actions != expected_actions {
                    return Err(WorkspaceCheckpointError::InvalidHistory);
                }
                store.retained_bytes = total;
                history.push(revision);
            }
            store.histories.insert(session, history);
        }
        decoder.ensure_finished()?;
        // Reject alternate spellings even if a nested decoder accepts them.
        if store.checkpoint(max_bytes)?.as_bytes() != bytes {
            return Err(WorkspaceCheckpointError::InvalidHistory);
        }
        Ok(store)
    }
}

fn limit_values(limits: WorkspaceLimits) -> [usize; 4] {
    [limits.max_workspaces, limits.max_revisions_per_workspace,
        limits.max_revision_bytes, limits.max_history_bytes]
}

fn count(decoder: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize, WorkspaceCheckpointError> {
    let result = usize::try_from(decoder.u64()?).map_err(|_| WorkspaceCheckpointError::CapacityExceeded)?;
    if result > maximum {
        return Err(WorkspaceCheckpointError::CapacityExceeded);
    }
    Ok(result)
}

fn text<'a>(decoder: &mut CanonicalDecoder<'a>, maximum: usize) -> Result<&'a str, WorkspaceCheckpointError> {
    let result = decoder.text()?;
    if result.len() > maximum {
        return Err(WorkspaceCheckpointError::CapacityExceeded);
    }
    Ok(result)
}

fn strings(decoder: &mut CanonicalDecoder<'_>, maximum: usize, wide_count: bool) -> Result<Vec<String>, WorkspaceCheckpointError> {
    let length = if wide_count {
        count(decoder, maximum)?
    } else {
        let length = usize::try_from(decoder.u32()?).map_err(|_| WorkspaceCheckpointError::CapacityExceeded)?;
        if length > maximum { return Err(WorkspaceCheckpointError::CapacityExceeded); }
        length
    };
    let mut result = Vec::new();
    for _ in 0..length {
        result.push(text(decoder, MAX_ITEM_BYTES)?.to_owned());
    }
    Ok(result)
}

fn decode_revision(bytes: &[u8], limits: WorkspaceLimits) -> Result<WorkspaceRevision, WorkspaceCheckpointError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != REVISION_DOMAIN {
        return Err(WorkspaceCheckpointError::UnsupportedFormat);
    }
    let basis = ContractBasis::decode_canonical(&mut decoder)?;
    if basis.semantic_protocol != "fss/1" {
        return Err(WorkspaceCheckpointError::InvalidHistory);
    }
    let mission_id = MissionId::parse(text(&mut decoder, 256)?)?;
    let capability_scope = decode_scopes(&mut decoder)?;
    let privacy_scope = decode_scopes(&mut decoder)?;
    let parent = if decoder.bool()? { Some(decoder.digest()?) } else { None };
    let rebase_from = if decoder.bool()? {
        Some(LedgerAnchor::decode_canonical(&mut decoder)?)
    } else {
        None
    };
    let invalidated_actions = strings(&mut decoder, MAX_ITEMS, true)?;
    let capsule = decode_capsule(&mut decoder)?;
    validate_capsule(&capsule, limits.max_revision_bytes)?;
    if capsule.capability_projection.iter().any(|cap| !capability_scope.contains(cap)) {
        return Err(WorkspaceCheckpointError::InvalidHistory);
    }
    decoder.ensure_finished()?;
    let revision = WorkspaceRevision {
        capsule, basis, mission_id, capability_scope, privacy_scope, parent, rebase_from, invalidated_actions,
        bytes: bytes.to_vec(), digest: ContentDigest::sha256(bytes),
    };
    if encode_revision(&revision)? != bytes {
        return Err(WorkspaceCheckpointError::InvalidHistory);
    }
    Ok(revision)
}

fn decode_scopes(decoder: &mut CanonicalDecoder<'_>) -> Result<BTreeSet<String>, WorkspaceCheckpointError> {
    let scopes = count(decoder, MAX_ITEMS)?;
    let mut result = BTreeSet::new();
    for _ in 0..scopes {
        let scope = text(decoder, MAX_ITEM_BYTES)?;
        if result.last().is_some_and(|prior: &String| prior.as_str() >= scope) {
            return Err(WorkspaceCheckpointError::InvalidHistory);
        }
        result.insert(scope.to_owned());
    }
    Ok(result)
}

fn decode_capsule(decoder: &mut CanonicalDecoder<'_>) -> Result<SessionCapsule, WorkspaceCheckpointError> {
    if decoder.text()? != SessionCapsule::SCHEMA {
        return Err(WorkspaceCheckpointError::UnsupportedFormat);
    }
    let session_id = SessionId::parse(text(decoder, 256)?)?;
    let revision = decoder.u64()?;
    let principal = text(decoder, 256)?.to_owned();
    let capability_projection = strings(decoder, MAX_ITEMS, false)?;
    let objective_digest = text(decoder, 256)?.to_owned();
    let base_anchor = LedgerAnchor::decode_canonical(decoder)?;
    let current_anchor = LedgerAnchor::decode_canonical(decoder)?;
    let situation_capsule_digest = text(decoder, 256)?.to_owned();
    let active_hypotheses = strings(decoder, MAX_ITEMS, false)?;
    let assumptions = strings(decoder, MAX_ITEMS, false)?;
    let unknowns = strings(decoder, MAX_ITEMS, false)?;
    let not_observable_domains = strings(decoder, MAX_ITEMS, false)?;
    let epistemic_debt = strings(decoder, 1024, false)?;
    let open_obligations = strings(decoder, MAX_ITEMS, false)?;
    let budget_ledger = BudgetVector::decode_canonical(decoder)?;
    let bookmark_count = usize::try_from(decoder.u32()?).map_err(|_| WorkspaceCheckpointError::CapacityExceeded)?;
    if bookmark_count > MAX_ITEMS { return Err(WorkspaceCheckpointError::CapacityExceeded); }
    let mut bookmarked_evidence = Vec::new();
    for _ in 0..bookmark_count { bookmarked_evidence.push(decoder.digest()?); }
    let next_actions = strings(decoder, MAX_ITEMS, false)?;
    let decision_digest = text(decoder, 256)?.to_owned();
    Ok(SessionCapsule::new(SessionCapsuleParams {
        session_id, revision, principal, capability_projection, objective_digest, base_anchor,
        current_anchor, situation_capsule_digest, active_hypotheses, assumptions, unknowns,
        not_observable_domains, epistemic_debt, open_obligations, budget_ledger,
        bookmarked_evidence, next_actions, decision_digest,
    })?)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedOutput {
    fn append(&mut self, bytes: &[u8]) -> Result<(), WorkspaceCheckpointError> {
        if self.bytes.len().checked_add(bytes.len()).is_none_or(|n| n > self.limit) {
            return Err(WorkspaceCheckpointError::CapacityExceeded);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn field(&mut self, write: impl FnOnce(&mut CanonicalEncoder)) -> Result<(), WorkspaceCheckpointError> {
        let mut encoder = CanonicalEncoder::new();
        write(&mut encoder);
        self.append(&encoder.finish_checked()?)
    }

    fn count(&mut self, value: usize) -> Result<(), WorkspaceCheckpointError> {
        let value = u64::try_from(value).map_err(|_| WorkspaceCheckpointError::CapacityExceeded)?;
        self.field(|encoder| encoder.u64(value))
    }
}
