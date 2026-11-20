#![forbid(unsafe_code)]
//! Independently retained, inactive cross-store source binding.
//!
//! The record binds two currently owned local stores and a verified copied
//! source. It does not activate a worker, discover all candidate switches,
//! authenticate a camera, prove storage independence, or provide crash recovery.
//! Callers retain both stores, the original pending input, and the switch.

use super::{FreshStoreCopy, FreshStorePending, Input, Parts, Retirement, valid_input};
use crate::unifi_direct::{archive, source_batch, source_evidence};
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm,
};
use fss_geometry::WorkBudget;
use fss_publication::RootLedgerOutcome;
use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, PinRetainedEffectJournal};
use std::{fmt, path::Path};

const DOMAIN: &str = "fss.unifi-direct.source-cross-store-switch.v1";
const MAX_RECORD: usize = 1024;

/// Exact local claims retained by a candidate cross-store transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Immutable source publication scope.
    pub scope: ContentDigest,
    /// Caller-bound camera claim, not independently authenticated identity.
    pub camera: ContentDigest,
    /// Source root last confirmed by the predecessor and copied to the successor.
    pub seed: archive::UnknownTimePin,
    /// Original pending input copied and confirmed in the successor.
    pub pending: archive::UnknownTimePin,
    /// Domain-separated digest of the predecessor's local path spelling.
    pub old_path: ContentDigest,
    /// Domain-separated digest of the successor's local path spelling.
    pub new_path: ContentDigest,
    /// Domain-separated digest of the predecessor's current ledger anchor.
    pub old_ledger: ContentDigest,
    /// Domain-separated digest of the successor's current ledger anchor.
    pub new_ledger: ContentDigest,
    /// Predecessor journal and keeper heads, respectively.
    pub old_journal: EffectJournalPin,
    /// Predecessor keeper head.
    pub old_keeper: EffectJournalPin,
    /// Successor journal head that confirms the copied seed.
    pub seed_journal: EffectJournalPin,
    /// Successor current journal head.
    pub new_journal: EffectJournalPin,
    /// Successor current keeper head.
    pub new_keeper: EffectJournalPin,
}

/// Payload-free refusal to prepare or verify a candidate binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Local owners, pins, candidate, or retention claims do not match.
    Preconditions,
    /// The explicit work allowance or a cancellation checkpoint refused work.
    WorkOrCancelled,
    /// A source graph could not be read or did not match the supplied camera claim.
    Source,
    /// The switch store or independent pin custody needs reconciliation.
    Switch,
    /// Canonical switch encoding or decoding was invalid.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source cross-store binding refused: {self:?}")
    }
}
impl std::error::Error for Error {}

fn valid(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
}
fn path_digest(path: &Path) -> Result<ContentDigest, Error> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(Error::Preconditions);
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.unifi-direct.source-store-path.v1");
    encoder.bytes(bytes);
    Ok(ContentDigest::sha256(
        &encoder.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
fn encode(binding: Binding) -> Result<Vec<u8>, Error> {
    if !valid(binding.scope)
        || !valid(binding.camera)
        || !valid(binding.seed.root)
        || !valid(binding.pending.root)
        || !valid(binding.seed.retention)
        || binding.seed.retention != binding.pending.retention
        || binding.seed == binding.pending
        || binding.old_path == binding.new_path
        || ![
            binding.old_path,
            binding.new_path,
            binding.old_ledger,
            binding.new_ledger,
        ]
        .into_iter()
        .all(valid)
    {
        return Err(Error::Encoding);
    }
    let mut out = CanonicalEncoder::new();
    out.text(DOMAIN);
    for value in [
        binding.scope,
        binding.camera,
        binding.seed.root,
        binding.seed.retention,
        binding.pending.root,
        binding.pending.retention,
        binding.old_path,
        binding.new_path,
        binding.old_ledger,
        binding.new_ledger,
    ] {
        out.digest(value);
    }
    for pin in [
        binding.old_journal,
        binding.old_keeper,
        binding.seed_journal,
        binding.new_journal,
        binding.new_keeper,
    ] {
        if pin.sequence == 0 || !valid(pin.root) {
            return Err(Error::Encoding);
        }
        out.u64(pin.sequence);
        out.digest(pin.root);
    }
    let bytes = out.finish_checked().map_err(|_| Error::Encoding)?;
    if bytes.len() > MAX_RECORD {
        return Err(Error::Encoding);
    }
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Binding, Error> {
    if bytes.len() > MAX_RECORD {
        return Err(Error::Encoding);
    }
    let mut input = CanonicalDecoder::new(bytes);
    if input.text().map_err(|_| Error::Encoding)? != DOMAIN {
        return Err(Error::Encoding);
    }
    let scope = input.digest().map_err(|_| Error::Encoding)?;
    let camera = input.digest().map_err(|_| Error::Encoding)?;
    let seed = archive::UnknownTimePin {
        root: input.digest().map_err(|_| Error::Encoding)?,
        retention: input.digest().map_err(|_| Error::Encoding)?,
    };
    let pending = archive::UnknownTimePin {
        root: input.digest().map_err(|_| Error::Encoding)?,
        retention: input.digest().map_err(|_| Error::Encoding)?,
    };
    let old_path = input.digest().map_err(|_| Error::Encoding)?;
    let new_path = input.digest().map_err(|_| Error::Encoding)?;
    let old_ledger = input.digest().map_err(|_| Error::Encoding)?;
    let new_ledger = input.digest().map_err(|_| Error::Encoding)?;
    let mut pin = || -> Result<EffectJournalPin, Error> {
        Ok(EffectJournalPin {
            sequence: input.u64().map_err(|_| Error::Encoding)?,
            root: input.digest().map_err(|_| Error::Encoding)?,
        })
    };
    let binding = Binding {
        scope,
        camera,
        seed,
        pending,
        old_path,
        new_path,
        old_ledger,
        new_ledger,
        old_journal: pin()?,
        old_keeper: pin()?,
        seed_journal: pin()?,
        new_journal: pin()?,
        new_keeper: pin()?,
    };
    input.ensure_finished().map_err(|_| Error::Encoding)?;
    if encode(binding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(binding)
}

fn candidate(
    input: &Input,
    next: &Parts,
    camera: ContentDigest,
) -> Result<archive::UnknownTimePin, Error> {
    if !valid_input(input, next) {
        return Err(Error::Preconditions);
    }
    match input {
        Input::Original {
            record,
            key,
            disposition,
            camera_claim,
        } if *camera_claim == camera => source_evidence::Prepared::new(
            record,
            *key,
            *disposition,
            camera,
            next.retention,
            next.max_source_bytes,
        )
        .map(|p| archive::UnknownTimePin::from_source_plan(&p))
        .map_err(|_| Error::Preconditions),
        Input::Recovered(source) if source.camera_claim() == camera => {
            Ok(archive::UnknownTimePin::from_source_plan(
                &source_evidence::Prepared::from_recovered(source),
            ))
        }
        Input::Batch {
            batch,
            key,
            camera_claim,
        } if *camera_claim == camera => source_batch::Prepared::from_items(
            batch.items(),
            *key,
            camera,
            next.retention,
            batch.bytes(),
        )
        .map(|p| archive::UnknownTimePin::from_source_batch(&p))
        .map_err(|_| Error::Preconditions),
        _ => Err(Error::Preconditions),
    }
}

fn check_source(
    parts: &mut Parts,
    pin: archive::UnknownTimePin,
    camera: ContentDigest,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
) -> Result<(), Error> {
    let source = archive::read_unknown_time_source_graph(
        &mut parts.deployment,
        pin,
        read,
        parts.limits,
        work,
        &parts.replay,
    )
    .map_err(|_| Error::Source)?;
    let matches = match source {
        archive::RecoveredSourceGraph::Single(source) => {
            source.camera_claim() == camera
                && archive::UnknownTimePin::from_source_plan(
                    &source_evidence::Prepared::from_recovered(&source),
                ) == pin
        }
        archive::RecoveredSourceGraph::Batch(source) => {
            source.camera_claim == camera
                && source_batch::Prepared::from_recovered(source)
                    .ok()
                    .is_some_and(|p| archive::UnknownTimePin::from_source_batch(&p) == pin)
        }
    };
    if matches { Ok(()) } else { Err(Error::Source) }
}

fn verify(
    old: &mut Retirement,
    next: &mut Parts,
    copied: &FreshStoreCopy,
    pending: &FreshStorePending,
    camera: ContentDigest,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
    expect_fenced: bool,
) -> Result<Binding, Error> {
    old.parts
        .replay
        .checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    next.replay
        .checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    let input = old.pending.as_ref().ok_or(Error::Preconditions)?;
    if old.fenced != expect_fenced
        || !valid(camera)
        || !old.parts.journal.locally_settled(&old.parts.keeper)
        || !next.journal.locally_settled(&next.keeper)
        || old.parts.journal.confirmed() != Some(copied.pin)
        || pending.seed != copied.pin
        || old.parts.journal.anchor() != copied.predecessor_journal
        || old.parts.keeper.anchor() != copied.predecessor_keeper
        || next.journal.confirmed() != Some(pending.pending)
        || next.journal.anchor() != pending.successor_journal
        || next.keeper.anchor() != pending.successor_keeper
        || old.parts.journal.scope() != next.journal.scope()
        || old.parts.retention != next.retention
        || copied.pin.retention != next.retention
        || pending.pending.retention != next.retention
        || old.parts.deployment.root() == next.deployment.root()
        || old.parts.deployment.site_lineage() != next.deployment.site_lineage()
        || pending.receipt.outcome != RootLedgerOutcome::Committed
        || pending.receipt.root != pending.pending.root
        || &pending.receipt.anchor != next.deployment.current_anchor()
        || old.parts.deployment.publisher().is_poisoned()
        || next.deployment.publisher().is_poisoned()
        || !old
            .parts
            .authority
            .permits(copied.pin.retention, copied.pin.root)
        || !next
            .authority
            .permits(copied.pin.retention, copied.pin.root)
        || !next
            .authority
            .permits(pending.pending.retention, pending.pending.root)
    {
        return Err(Error::Preconditions);
    }
    let bytes = u64::try_from(input.bytes_len())
        .ok()
        .and_then(|n| n.checked_mul(2))
        .ok_or(Error::WorkOrCancelled)?;
    work.charge(bytes).map_err(|_| Error::WorkOrCancelled)?;
    if candidate(input, next, camera)? != pending.pending {
        return Err(Error::Preconditions);
    }
    let prefix = next
        .journal
        .confirmed_page(copied.successor_journal, 0, 1, &next.replay)
        .map_err(|_| Error::Preconditions)?;
    if prefix.entries.len() != 1
        || prefix.entries[0].pin != copied.pin
        || prefix.has_more
        || prefix.pending.is_some()
    {
        return Err(Error::Preconditions);
    }
    if let Some(custody) = &mut old.rollover_custody {
        custody
            .check(&old.parts.journal, &old.parts.keeper, &old.parts.replay)
            .map_err(|_| Error::Preconditions)?;
    }
    check_source(&mut old.parts, copied.pin, camera, read, work)?;
    check_source(next, copied.pin, camera, read, work)?;
    check_source(next, pending.pending, camera, read, work)?;
    if !old
        .parts
        .authority
        .permits(copied.pin.retention, copied.pin.root)
        || !next
            .authority
            .permits(copied.pin.retention, copied.pin.root)
        || !next
            .authority
            .permits(pending.pending.retention, pending.pending.root)
    {
        return Err(Error::Preconditions);
    }
    let binding = Binding {
        scope: old.parts.journal.scope(),
        camera,
        seed: copied.pin,
        pending: pending.pending,
        old_path: path_digest(old.parts.deployment.root())?,
        new_path: path_digest(next.deployment.root())?,
        old_ledger: old
            .parts
            .deployment
            .current_anchor()
            .canonical_digest(DOMAIN),
        new_ledger: next.deployment.current_anchor().canonical_digest(DOMAIN),
        old_journal: old.parts.journal.anchor(),
        old_keeper: old.parts.keeper.anchor(),
        seed_journal: copied.successor_journal,
        new_journal: next.journal.anchor(),
        new_keeper: next.keeper.anchor(),
    };
    encode(binding)?;
    Ok(binding)
}

/// Both stores held exclusively while a candidate switch is prepared.
#[must_use = "retain both stores and any indeterminate switch"]
pub struct Staged<'a> {
    old: &'a mut Retirement,
    next: &'a mut Parts,
    copied: &'a FreshStoreCopy,
    pending: &'a FreshStorePending,
    read: &'a dyn archive::ReadAuthority,
    binding: Binding,
    spent: bool,
}
impl<'a> Staged<'a> {
    /// Verify both owned stores and the still-held input before staging.
    /// Blocking storage I/O must run on a region-owned drained worker.
    pub fn begin(
        old: &'a mut Retirement,
        next: &'a mut Parts,
        copied: &'a FreshStoreCopy,
        pending: &'a FreshStorePending,
        camera: ContentDigest,
        read: &'a dyn archive::ReadAuthority,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self, Error> {
        let binding = verify(old, next, copied, pending, camera, read, work, false)?;
        Ok(Self {
            old,
            next,
            copied,
            pending,
            read,
            binding,
            spent: false,
        })
    }
    /// Candidate metadata; it grants no authority and does not identify a device.
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// Revalidate, append once, retain and read back one switch record.
    /// Any failure after append may be indeterminate; never retry this stage.
    pub fn commit(
        mut self,
        mut switch: PinRetainedEffectJournal,
        work: &mut WorkBudget<'_>,
    ) -> Result<Retained<'a>, CommitFailure<'a>> {
        let before = (|| {
            if self.spent || switch.head().is_some() || !switch.records().is_empty() {
                return Err(Error::Preconditions);
            }
            if verify(
                self.old,
                self.next,
                self.copied,
                self.pending,
                self.binding.camera,
                self.read,
                work,
                false,
            )? != self.binding
            {
                return Err(Error::Preconditions);
            }
            let bytes = encode(self.binding)?;
            switch
                .reserve_capacity(1, bytes.len())
                .map_err(|_| Error::Switch)?;
            self.old
                .parts
                .replay
                .checkpoint("unifi-source-cross-store")
                .map_err(|_| Error::WorkOrCancelled)?;
            self.next
                .replay
                .checkpoint("unifi-source-cross-store")
                .map_err(|_| Error::WorkOrCancelled)?;
            Ok(bytes)
        })();
        let bytes = match before {
            Ok(bytes) => bytes,
            Err(reason) => {
                return Err(CommitFailure {
                    stage: self,
                    switch,
                    reason,
                    indeterminate: false,
                });
            }
        };
        self.spent = true;
        // Once append is attempted, a panic or ambiguous result must also
        // prevent a new stage from being created with the same old owner.
        self.old.fenced = true;
        let after = (|| {
            let head = switch.append(None, &bytes).map_err(|_| Error::Switch)?;
            if switch.verify_retained_head().map_err(|_| Error::Switch)? != head
                || switch.records().len() != 1
                || switch.records()[0] != bytes
            {
                return Err(Error::Switch);
            }
            if verify(
                self.old,
                self.next,
                self.copied,
                self.pending,
                self.binding.camera,
                self.read,
                work,
                true,
            )? != self.binding
            {
                return Err(Error::Preconditions);
            }
            Ok(head)
        })();
        match after {
            Ok(head) => {
                self.old.fenced = false;
                Ok(Retained {
                    stage: self,
                    switch,
                    head,
                })
            }
            Err(reason) => Err(CommitFailure {
                stage: self,
                switch,
                reason,
                indeterminate: true,
            }),
        }
    }
}

/// Failure returns both store borrows and exact switch custody.
#[must_use = "preserve the returned stores and reconcile an indeterminate switch"]
pub struct CommitFailure<'a> {
    stage: Staged<'a>,
    switch: PinRetainedEffectJournal,
    /// Failure classification.
    pub reason: Error,
    /// True means append may have happened; no retry is authorized.
    pub indeterminate: bool,
}
impl<'a> CommitFailure<'a> {
    /// Return the original owner and switch; an indeterminate stage is spent.
    pub fn into_parts(self) -> (Staged<'a>, PinRetainedEffectJournal) {
        (self.stage, self.switch)
    }
}

/// A retained candidate switch. It is not an activated successor.
#[must_use = "retain both source stores and the switch for recovery"]
pub struct Retained<'a> {
    stage: Staged<'a>,
    switch: PinRetainedEffectJournal,
    head: EffectJournalPin,
}
impl<'a> Retained<'a> {
    /// Exact retained switch head.
    pub fn head(&self) -> EffectJournalPin {
        self.head
    }
    /// Binding named by that head.
    pub fn binding(&self) -> Binding {
        self.stage.binding
    }
    /// Return both borrowed stores and switch custody, without activating them.
    pub fn into_parts(self) -> (&'a mut Retirement, &'a mut Parts, PinRetainedEffectJournal) {
        (self.stage.old, self.stage.next, self.switch)
    }
}

/// Inspect one already opened and reconciled retained switch. This verifies its
/// record and pin, not the stores, candidate inventory, or active lineage.
pub fn inspect(
    switch: &mut PinRetainedEffectJournal,
    expected_scope: ContentDigest,
    work: &mut WorkBudget<'_>,
    cx: &crate::ReplayCx,
) -> Result<(Binding, EffectJournalPin), Error> {
    cx.checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    if switch.records().len() != 1 || switch.records()[0].len() > MAX_RECORD {
        return Err(Error::Switch);
    }
    let charge = u64::try_from(switch.records()[0].len())
        .ok()
        .and_then(|v| v.checked_mul(16))
        .ok_or(Error::WorkOrCancelled)?;
    work.charge(charge).map_err(|_| Error::WorkOrCancelled)?;
    let head = switch.verify_retained_head().map_err(|_| Error::Switch)?;
    let binding = decode(&switch.records()[0])?;
    if binding.scope != expected_scope
        || switch.verify_retained_head().map_err(|_| Error::Switch)? != head
    {
        return Err(Error::Switch);
    }
    cx.checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    Ok((binding, head))
}

/// Failure to reconcile one already-confirmed source after reopening.
#[derive(Debug)]
pub enum ReplayError {
    /// The journal, keeper, source or retention policy was not the exact expected state.
    Preconditions,
    /// The original source graph could not be read under current authority.
    Read(archive::Error),
    /// Replay failed or may have taken effect; reconcile its exact journal state.
    Publication(archive::UnknownTimePublishError),
    /// A receipt exists but the replay did not match the prior ledger and heads.
    AfterPublication {
        /// Actual receipt retained for reconciliation.
        receipt: Box<fss_publication::RootLedgerReceipt>,
    },
}
impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Preconditions => "source replay preconditions refused",
            Self::Read(_) => "source replay read refused",
            Self::Publication(_) => "source replay publication requires reconciliation",
            Self::AfterPublication { .. } => "source replay receipt requires reconciliation",
        })
    }
}
impl std::error::Error for ReplayError {}

/// Reconcile the exact confirmed source of one reopened store.
///
/// The caller must independently retain the expected journal and keeper heads
/// and execute this blocking I/O on a region-owned drained worker. The original
/// graph is re-read, reconstructed, and replayed through the existing anchored
/// publication path. This clears only the journal's exact replay obligation;
/// it does not choose or activate a cross-store switch. Any uncertain failure
/// retains the store and possible receipt for inspection, without automatic retry.
pub fn replay_reopened_store(
    parts: &mut Parts,
    expected: archive::UnknownTimePin,
    camera: ContentDigest,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
) -> Result<fss_publication::RootLedgerReceipt, ReplayError> {
    if !valid(camera)
        || parts.journal.pending().is_some()
        || parts.journal.confirmed() != Some(expected)
        || parts.journal.replay_pin() != Some(expected)
        || parts.keeper.target() != parts.journal.anchor()
        || expected.retention != parts.retention
        || parts.deployment.publisher().is_poisoned()
        || !parts.authority.permits(expected.retention, expected.root)
        || !read.permits(expected.retention, expected.root)
    {
        return Err(ReplayError::Preconditions);
    }
    let journal_head = parts.journal.anchor();
    let keeper_head = parts.keeper.anchor();
    let ledger = parts.deployment.current_anchor().clone();
    let recovered = archive::read_unknown_time_source_graph(
        &mut parts.deployment,
        expected,
        read,
        parts.limits,
        work,
        &parts.replay,
    )
    .map_err(ReplayError::Read)?;
    let receipt = match recovered {
        archive::RecoveredSourceGraph::Single(source) => {
            if source.camera_claim() != camera {
                return Err(ReplayError::Preconditions);
            }
            let plan = source_evidence::Prepared::from_recovered(&source);
            if archive::UnknownTimePin::from_source_plan(&plan) != expected {
                return Err(ReplayError::Preconditions);
            }
            archive::publish_unknown_time_source_anchored(
                &plan,
                &mut parts.deployment,
                parts.authority.as_ref(),
                parts.limits,
                work,
                &parts.replay,
                &mut parts.journal,
                &mut parts.keeper,
            )
        }
        archive::RecoveredSourceGraph::Batch(source) => {
            if source.camera_claim != camera {
                return Err(ReplayError::Preconditions);
            }
            let plan = source_batch::Prepared::from_recovered(source)
                .map_err(|_| ReplayError::Preconditions)?;
            if archive::UnknownTimePin::from_source_batch(&plan) != expected {
                return Err(ReplayError::Preconditions);
            }
            archive::publish_unknown_time_source_batch_anchored(
                &plan,
                &mut parts.deployment,
                parts.authority.as_ref(),
                parts.limits,
                work,
                &parts.replay,
                &mut parts.journal,
                &mut parts.keeper,
            )
        }
    }
    .map_err(ReplayError::Publication)?;
    if receipt.outcome != RootLedgerOutcome::AlreadyLedgered
        || receipt.root != expected.root
        || receipt.anchor != ledger
        || parts.deployment.current_anchor() != &ledger
        || parts.journal.anchor() != journal_head
        || parts.keeper.anchor() != keeper_head
        || !parts.journal.locally_settled(&parts.keeper)
    {
        return Err(ReplayError::AfterPublication {
            receipt: Box::new(receipt),
        });
    }
    Ok(receipt)
}

/// Revalidate two explicitly reopened stores against an inspected switch claim.
///
/// This performs blocking reads and belongs on a region-owned drained worker.
/// The caller supplies the separately retained switch, its expected head, both
/// store locations and independently retained minimum heads. This rechecks the
/// switch around the exact store heads and source graphs, but does not provide
/// an atomic cross-store snapshot or prove inventory coverage, absence of
/// competing switches, device identity, or activation authority. No original
/// in-memory pending input is required.
pub fn verify_reopened_stores(
    binding: Binding,
    switch_head: EffectJournalPin,
    switch: &mut PinRetainedEffectJournal,
    old: &mut Parts,
    next: &mut Parts,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
) -> Result<(), Error> {
    fn check(binding: Binding, old: &Parts, next: &Parts) -> Result<(), Error> {
        encode(binding)?;
        if !old.journal.locally_settled(&old.keeper)
            || !next.journal.locally_settled(&next.keeper)
            || old.journal.scope() != binding.scope
            || next.journal.scope() != binding.scope
            || old.journal.confirmed() != Some(binding.seed)
            || next.journal.confirmed() != Some(binding.pending)
            || old.journal.anchor() != binding.old_journal
            || old.keeper.anchor() != binding.old_keeper
            || next.journal.anchor() != binding.new_journal
            || next.keeper.anchor() != binding.new_keeper
            || old.retention != binding.seed.retention
            || next.retention != binding.pending.retention
            || old.deployment.site_lineage() != next.deployment.site_lineage()
            || path_digest(old.deployment.root())? != binding.old_path
            || path_digest(next.deployment.root())? != binding.new_path
            || old.deployment.current_anchor().canonical_digest(DOMAIN) != binding.old_ledger
            || next.deployment.current_anchor().canonical_digest(DOMAIN) != binding.new_ledger
            || old.deployment.publisher().is_poisoned()
            || next.deployment.publisher().is_poisoned()
            || !old
                .authority
                .permits(binding.seed.retention, binding.seed.root)
            || !next
                .authority
                .permits(binding.seed.retention, binding.seed.root)
            || !next
                .authority
                .permits(binding.pending.retention, binding.pending.root)
        {
            return Err(Error::Preconditions);
        }
        Ok(())
    }
    old.replay
        .checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    next.replay
        .checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    if inspect(switch, binding.scope, work, &next.replay)? != (binding, switch_head) {
        return Err(Error::Switch);
    }
    check(binding, old, next)?;
    let prefix = next
        .journal
        .confirmed_page(binding.seed_journal, 0, 1, &next.replay)
        .map_err(|_| Error::Preconditions)?;
    if prefix.entries.len() != 1
        || prefix.entries[0].pin != binding.seed
        || prefix.has_more
        || prefix.pending.is_some()
    {
        return Err(Error::Preconditions);
    }
    check_source(old, binding.seed, binding.camera, read, work)?;
    check_source(next, binding.seed, binding.camera, read, work)?;
    check_source(next, binding.pending, binding.camera, read, work)?;
    old.replay
        .checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    next.replay
        .checkpoint("unifi-source-cross-store")
        .map_err(|_| Error::WorkOrCancelled)?;
    check(binding, old, next)?;
    if inspect(switch, binding.scope, work, &next.replay)? != (binding, switch_head) {
        return Err(Error::Switch);
    }
    Ok(())
}
