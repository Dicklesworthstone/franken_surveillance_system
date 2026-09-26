#![forbid(unsafe_code)]
//! Immutable history prefixes use the existing root-last and canonical reachability publisher.
use super::*;
use crate::ReferenceDeployment;
use crate::ingest::rgb_archive::{RgbArchiveAuthority, RgbArchiveLimits, restore_rgb_evidence};
use crate::ingest::rgb_evidence::RgbEvidenceBudget;
use fss_core::LedgerAnchor;
use fss_publication::{PublishCancellation, PublishCutPoint, RootLedgerReceipt, RootLedgerState,
    ROOT_REACHABILITY_FAMILY, ROOT_REACHABILITY_OBJECT_PREFIX};
use std::collections::BTreeMap;

/// Original archives have their own independent authority; these operations cover replay
/// configuration and ordered pin metadata, never model activation or event publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryOperation {
    /// Read and discover exact stored history under the current canonical anchor.
    Read,
    /// Retain a complete immutable derived history prefix.
    Retain,
}
/// Explicit live policy adapter. There is no permissive default and a digest grants nothing.
pub trait HistoryAuthority {
    /// Check the current principal, exact session, operation, privacy and retention scope.
    fn permits(&self, operation: HistoryOperation, session: ContentDigest) -> bool;
}
/// Metadata and source-closed evidence permissions are deliberately independent.
#[derive(Clone, Copy)]
pub struct HistoryAccess<'a> {
    /// Current history read/write authority.
    pub history: &'a dyn HistoryAuthority,
    /// Current original JPEG/model/permission disclosure authority.
    pub evidence: &'a dyn RgbArchiveAuthority,
}
/// Independent storage/scan ceilings, not enlarged by stored metadata.
#[derive(Clone, Copy, Debug)]
pub struct HistoryLimits {
    /// At most this many deltas are inspected in the existing ordered ledger; 1..=262144.
    pub maximum_ledger_deltas: usize,
    /// Maximum allocation the attached spool can perform per read; 1 KiB..=64 MiB.
    pub maximum_spool_object_bytes: usize,
    /// Existing per-frame archive read bounds.
    pub archive: RgbArchiveLimits,
}
impl Default for HistoryLimits {
    fn default() -> Self {
        Self { maximum_ledger_deltas: 65_536, maximum_spool_object_bytes: 64 * 1024 * 1024,
            archive: RgbArchiveLimits::default() }
    }
}
/// Anchor-pinned recovery. A durable-but-unledgered candidate is never returned as committed.
/// Explicitly publish its exact tip to reconcile it; reading alone performs no repair.
#[derive(Clone, Debug)]
pub struct HistoryRecovery {
    /// Existing authoritative observation point used for discovery.
    pub anchor: LedgerAnchor,
    /// Latest complete, gap-free ledgered prefix, if any; not executed inference.
    pub committed: Option<HttpRgbHistory>,
    /// Next durable candidate missing its reachability batch, if present.
    pub pending: Option<HttpRgbHistory>,
}
fn authorize(id: ContentDigest, operation: HistoryOperation, auth: &dyn HistoryAuthority, cx: &ReplayCx) -> Result<()> {
    checkpoint(cx)?;
    if !auth.permits(operation, id) { return Err(HistoryError::Denied); }
    Ok(())
}
fn admit(d: &ReferenceDeployment, limits: HistoryLimits) -> Result<()> {
    if limits.maximum_ledger_deltas == 0 || limits.maximum_ledger_deltas > 262_144
        || !(1024..=64 * 1024 * 1024).contains(&limits.maximum_spool_object_bytes)
        || d.publisher().limits().spool.max_object_bytes > limits.maximum_spool_object_bytes
    { return Err(HistoryError::Limit); }
    if d.publisher().is_poisoned() { return Err(HistoryError::Unavailable); }
    Ok(())
}
fn catalog(d: &ReferenceDeployment, id: ContentDigest, limits: HistoryLimits, auth: &dyn HistoryAuthority, work: &mut WorkBudget<'_>, cx: &ReplayCx) -> Result<BTreeMap<usize, ContentDigest>> {
    admit(d, limits)?;
    authorize(id, HistoryOperation::Read, auth, cx)?;
    let prefix = format!("{}{}", ROOT_REACHABILITY_OBJECT_PREFIX, super::prefix(id)?);
    let mut rows = BTreeMap::new();
    let mut scanned = 0_usize;
    for batch in d.ledger().batches() {
        scanned = scanned.checked_add(batch.deltas.len()).ok_or(HistoryError::Limit)?;
        if scanned > limits.maximum_ledger_deltas { return Err(HistoryError::Limit); }
        work.charge(1 + batch.deltas.len() as u64).map_err(backend)?;
        authorize(id, HistoryOperation::Read, auth, cx)?;
        for delta in &batch.deltas {
            let Some(suffix) = delta.object_id.as_str().strip_prefix(&prefix) else { continue; };
            if suffix.len() != 4 { return Err(HistoryError::Mismatch); }
            let revision = usize::from_str_radix(suffix, 16).map_err(backend)?;
            if revision > MAX_HISTORY_FRAMES + 1 || format!("{revision:04x}") != suffix { return Err(HistoryError::Mismatch); }
            // Deletion/retraction is not absence and must never permit generation-one resurrection.
            if delta.family != ROOT_REACHABILITY_FAMILY || delta.new_generation != 1 {
                return Err(HistoryError::Unavailable);
            }
            if rows.insert(revision, delta.payload_digest).is_some() { return Err(HistoryError::Conflict); }
        }
    }
    if rows.keys().copied().ne(0..rows.len()) { return Err(HistoryError::Mismatch); }
    Ok(rows)
}
fn read(d: &ReferenceDeployment, id: ContentDigest, object: ContentDigest, maximum: usize, auth: &dyn HistoryAuthority, work: &mut WorkBudget<'_>, cx: &ReplayCx) -> Result<Vec<u8>> {
    authorize(id, HistoryOperation::Read, auth, cx)?;
    work.charge(d.publisher().limits().max_tombstones as u64 + d.publisher().limits().spool.max_object_bytes as u64 * 2).map_err(backend)?;
    if d.publisher().tombstones().any(|v| *v == object) { return Err(HistoryError::Unavailable); }
    let bytes = d.publisher().spool().read(object).map_err(backend)?;
    if bytes.len() > maximum { return Err(HistoryError::Limit); }
    if ContentDigest::sha256(&bytes) != object { return Err(HistoryError::Mismatch); }
    authorize(id, HistoryOperation::Read, auth, cx)?;
    Ok(bytes)
}
fn load(d: &ReferenceDeployment, id: ContentDigest, root: ContentDigest, revision: usize, auth: &dyn HistoryAuthority, work: &mut WorkBudget<'_>, cx: &ReplayCx) -> Result<HttpRgbHistory> {
    let config = HttpRgbHistoryConfig::decode(&read(d, id, id, MAX_CONFIG_BYTES, auth, work, cx)?, id, work)?;
    let bytes = read(d, id, root, MAX_HISTORY_BYTES, auth, work, cx)?;
    let manifest = ObjectManifest::from_canonical_bytes(&bytes).map_err(backend)?;
    if manifest.root() != root || manifest.kind() != KIND { return Err(HistoryError::Mismatch); }
    let metadata = manifest.metadata_digest().ok_or(HistoryError::Mismatch)?;
    let history = HttpRgbHistory::decode(&read(d, id, metadata, MAX_HISTORY_BYTES, auth, work, cx)?, config)?;
    if history.tip()?.revision != revision as u64 || history.manifest()? != manifest { return Err(HistoryError::Mismatch); }
    Ok(history)
}

/// Recover configuration and every committed frame pin from an exact session identity.
/// Every expected prefix must be present, durable and ledgered, with the same content prefix.
/// Reads are bounded and side-effect-free; a pending candidate stays explicitly pending.
pub fn read_latest_history(d: &mut ReferenceDeployment, id: ContentDigest, limits: HistoryLimits, auth: &dyn HistoryAuthority, work: &mut WorkBudget<'_>, cx: &ReplayCx) -> Result<HistoryRecovery> {
    let rows = catalog(d, id, limits, auth, work, cx)?;
    let committed = if let Some((&revision, &root)) = rows.last_key_value() {
        let history = load(d, id, root, revision, auth, work, cx)?;
        for (&n, &root) in &rows {
            authorize(id, HistoryOperation::Read, auth, cx)?;
            work.charge(limits.maximum_ledger_deltas as u64 + MAX_HISTORY_BYTES as u64).map_err(backend)?;
            let expected = history.at_revision(n)?;
            if expected.tip()?.root != root { return Err(HistoryError::Mismatch); }
            match d.ledgered_publisher().state(&slot(id, n)?).map_err(backend)? {
                RootLedgerState::Ledgered { root: actual, .. } if actual == root => {}
                _ => return Err(HistoryError::Unavailable),
            }
            if read(d, id, root, MAX_HISTORY_BYTES, auth, work, cx)? != expected.manifest()?.canonical_bytes()
                || read(d, id, ContentDigest::sha256(&expected.record()?), MAX_HISTORY_BYTES, auth, work, cx)? != expected.record()?
            { return Err(HistoryError::Mismatch); }
        }
        Some(history)
    } else { None };
    let next = rows.len();
    let pending = if next <= MAX_HISTORY_FRAMES + 1 {
        work.charge(limits.maximum_ledger_deltas as u64).map_err(backend)?;
        match d.ledgered_publisher().state(&slot(id, next)?).map_err(backend)? {
            RootLedgerState::PendingLedger(candidate) => {
                if committed.as_ref().is_some_and(HttpRgbHistory::is_complete) { return Err(HistoryError::Conflict); }
                let history = load(d, id, candidate.root, next, auth, work, cx)?;
                if let Some(prior) = &committed {
                    if history.at_revision(next - 1)?.tip()? != prior.tip()? { return Err(HistoryError::Mismatch); }
                }
                Some(history)
            }
            RootLedgerState::Absent => None,
            // Staged/visible/poisoned work is not durable recovery; use the publisher's explicit recovery path.
            _ => return Err(HistoryError::NotReady),
        }
    } else { None };
    authorize(id, HistoryOperation::Read, auth, cx)?;
    Ok(HistoryRecovery { anchor: d.current_anchor().clone(), committed, pending })
}

impl HttpRgbHistory {
    /// Publish this exact complete prefix in the existing canonical ledger. The predecessor is
    /// re-read under the exclusive deployment owner before any write. Repeated older prefixes
    /// return AlreadyLedgered only if their exact content still matches and custody is intact.
    /// New frame archives must already be durably ledgered. No model execution or repair occurs.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(&self, expected: HttpRgbHistoryTip, d: &mut ReferenceDeployment, access: HistoryAccess<'_>, limits: HistoryLimits,
        copy: &mut RgbEvidenceBudget, work: &mut WorkBudget<'_>, cx: &ReplayCx) -> Result<RootLedgerReceipt> {
        let tip = self.tip()?;
        if tip != expected { return Err(HistoryError::Mismatch); }
        authorize(tip.session, HistoryOperation::Retain, access.history, cx)?;
        let recovery = read_latest_history(d, tip.session, limits, access.history, work, cx)?;
        let mut already = false;
        match &recovery.committed {
            Some(current) if current.tip()?.revision >= tip.revision => {
                if current.at_revision(tip.revision as usize)?.tip()? != tip { return Err(HistoryError::Conflict); }
                already = true;
            }
            Some(current) => {
                if tip.revision != current.tip()?.revision + 1 || current.is_complete()
                    || self.at_revision(tip.revision as usize - 1)?.tip()? != current.tip()?
                { return Err(HistoryError::Conflict); }
            }
            None if tip.revision != 0 => return Err(HistoryError::Conflict),
            None => {}
        }
        if !already && recovery.pending.as_ref().is_some_and(|p| p.tip().ok() != Some(tip)) { return Err(HistoryError::Conflict); }
        // Current derived-original custody must hold even for a retry; archive restore never repairs.
        for pin in &self.frames {
            authorize(tip.session, HistoryOperation::Retain, access.history, cx)?;
            restore_rgb_evidence(d, pin.archive, limits.archive, access.evidence, copy, work, cx).map_err(backend)?;
        }
        let manifest = self.manifest()?;
        let record = self.record()?;
        for object in manifest.children().iter().copied().chain([tip.root, ContentDigest::sha256(&record)]) {
            work.charge(d.publisher().limits().max_tombstones as u64 + 1).map_err(backend)?;
            if d.publisher().tombstones().any(|v| *v == object) { return Err(HistoryError::Unavailable); }
        }
        if !already {
            for bytes in [self.config.encoded(), record.as_slice()] {
                authorize(tip.session, HistoryOperation::Retain, access.history, cx)?;
                work.charge(bytes.len() as u64 * 3).map_err(backend)?;
                if d.stage_payload(bytes).map_err(backend)? != ContentDigest::sha256(bytes) { return Err(HistoryError::Mismatch); }
            }
        }
        authorize(tip.session, HistoryOperation::Retain, access.history, cx)?;
        let gate = Gate { id: tip.session, auth: access.history, cx };
        // The existing publisher returns successful commit even after late optional cancellation.
        d.ledgered_publisher().publish_and_commit_cancellable(&slot(tip.session, tip.revision as usize)?, &manifest,
            self.config.spec().validity, &gate).map_err(backend)
    }
}
struct Gate<'a> { id: ContentDigest, auth: &'a dyn HistoryAuthority, cx: &'a ReplayCx }
impl PublishCancellation for Gate<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.cx.checkpoint("http-rgb-history:publish").is_err() || !self.auth.permits(HistoryOperation::Retain, self.id)
    }
}
