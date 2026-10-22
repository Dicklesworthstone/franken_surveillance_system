#![forbid(unsafe_code)]
//! Immutable root-last storage and exact selected-prefix verification, with no mutable head.

use std::path::Path;

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::ObjectManifest;
use fss_publication::{
    LocalInspection, WriterDetectionOptions, inspect_with_io, read_verified_with_io,
};
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, SlotName,
};

use super::plan::MAX_PLAN_BYTES;
use super::read_io::{NoLockTable, ReadAllowance, ReadIo, check_read};
use super::record::{CampaignRecord, KIND, MAX_RECORD_BYTES};
use super::{
    CampaignAttemptHistory, CampaignAuthority, CampaignHistoryError as Error,
    CampaignHistoryLimits, CampaignOperation, CampaignPin, CampaignPlan, CampaignTerminal,
    HistoryState, MAX_CAMPAIGN_RECORDS, Result, STAGE_CAMPAIGN_RELEASE, check,
};
use crate::ReplayCx;

fn probe(cancel: &dyn PublishCancellation) -> Result<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        Err(Error::Denied)
    } else {
        Ok(())
    }
}

pub(super) fn slot(approval: ContentDigest, sequence: u32) -> Result<SlotName> {
    if !super::sha(approval) || !(1..=MAX_CAMPAIGN_RECORDS).contains(&sequence) {
        return Err(Error::Configuration);
    }
    let hex = approval
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    SlotName::parse(&format!("fssrtch1-{hex}-{sequence}")).map_err(|_| Error::Configuration)
}

pub(super) fn publisher_bound(
    local: LocalPublicationLimits,
    limits: CampaignHistoryLimits,
) -> Result<()> {
    limits.validate()?;
    local.validate().map_err(|_| Error::Configuration)?;
    if local.spool.max_object_bytes > limits.maximum_spool_object_bytes
        || local.max_scan_entries > limits.maximum_scan_roots
        || local.spool.max_scan_entries > limits.maximum_scan_roots
        || local.max_roots > limits.maximum_scan_roots
        || local.max_tombstones > limits.maximum_scan_roots
    {
        return Err(Error::Limit);
    }
    Ok(())
}

pub(super) fn require_empty(
    publisher: &LocalRootPublisher,
    approval: ContentDigest,
    limits: CampaignHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<()> {
    publisher_bound(publisher.limits(), limits)?;
    if publisher.is_poisoned() {
        return Err(Error::NotDurable);
    }
    probe(cancel)?;
    work.charge(limits.maximum_scan_roots as u64 + 1024)?;
    // A history destination with deletion evidence is never silently reused as a fresh campaign.
    if publisher.tombstones().next().is_some() {
        return Err(Error::Occupied);
    }
    for sequence in 1..=MAX_CAMPAIGN_RECORDS {
        probe(cancel)?;
        work.charge(limits.maximum_scan_roots as u64 + 256)?;
        let name = slot(approval, sequence)?;
        if publisher.root(&name).is_some() || publisher.is_broken_slot(&name) {
            return Err(Error::Occupied);
        }
        let temp = LocalRootPublisher::root_temp_path(&name);
        for (index, path) in publisher.orphaned_temps().enumerate() {
            if index >= limits.maximum_scan_roots {
                return Err(Error::Limit);
            }
            if path == temp {
                return Err(Error::Occupied);
            }
        }
    }
    probe(cancel)
}

pub(super) fn publish(
    publisher: &mut LocalRootPublisher,
    plan: &CampaignPlan,
    record: &CampaignRecord,
    limits: CampaignHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<()> {
    publisher_bound(publisher.limits(), limits)?;
    probe(cancel)?;
    let plan_bytes = plan.canonical_bytes()?;
    let metadata = record.encode()?;
    let metadata_digest = ContentDigest::sha256(&metadata);
    let manifest = record.manifest()?;
    let expected = record.pin(manifest.root());
    if record.plan != ContentDigest::sha256(&plan_bytes)
        || record.approval != plan.approval
        || record.limits != limits
    {
        return Err(Error::Mismatch);
    }
    // Publication itself rereads the required manifest closure; reserve its complete worst-case
    // read/hash cost in the same account used to reverify the prior prefix, before staging.
    work.charge(
        8192 + (plan_bytes.len() as u64 + metadata.len() as u64) * 8
            + (u64::from(record.sequence) * 2 + 1) * limits.maximum_spool_object_bytes as u64 * 4
            + limits.maximum_scan_roots as u64,
    )?;
    if publisher.tombstones().any(|digest| {
        *digest == expected.root || *digest == record.plan || *digest == metadata_digest
    }) {
        return Err(Error::Tombstoned);
    }
    let name = slot(record.approval, record.sequence)?;
    if publisher.is_broken_slot(&name) {
        return Err(Error::NotDurable);
    }
    if publisher
        .root(&name)
        .is_some_and(|root| root.root != expected.root)
    {
        return Err(Error::Occupied);
    }
    probe(cancel)?;
    if publisher
        .stage_object(&plan_bytes)
        .map_err(|_| Error::Storage)?
        != record.plan
    {
        return Err(Error::Storage);
    }
    probe(cancel)?;
    if publisher
        .stage_object(&metadata)
        .map_err(|_| Error::Storage)?
        != metadata_digest
    {
        return Err(Error::Storage);
    }
    probe(cancel)?;
    // Only this in-memory pending transition can reach here after a failed append. The native
    // publisher verifies exact temp bytes before discarding them; a cold fresh writer refuses.
    publisher
        .discard_orphaned_root_temp_for(&name, &manifest)
        .map_err(|_| Error::Storage)?;
    probe(cancel)?;
    work.charge(0)?;
    let receipt = publisher
        .publish_cancellable(&name, &manifest, cancel)
        .map_err(|_| {
            if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
                Error::Denied
            } else {
                Error::Storage
            }
        })?;
    if receipt.root != expected.root || receipt.claims.local != LocalPublicationState::Durable {
        return Err(Error::NotDurable);
    }
    // A durable receipt is final even if cancellation is requested immediately afterward.
    Ok(())
}

enum Source<'a> {
    Live(&'a LocalRootPublisher),
    Cold {
        root: &'a Path,
        local: LocalPublicationLimits,
        inspection: LocalInspection,
    },
}
impl Source<'_> {
    fn root(&self) -> &Path {
        match self {
            Self::Live(publisher) => publisher.root_dir(),
            Self::Cold { root, .. } => root,
        }
    }
    fn local(&self) -> LocalPublicationLimits {
        match self {
            Self::Live(publisher) => publisher.limits(),
            Self::Cold { local, .. } => *local,
        }
    }
    fn selected_root(&self, pin: CampaignPin) -> Result<()> {
        let name = slot(pin.approval, pin.records)?;
        let root = match self {
            Self::Live(publisher) => {
                if publisher.is_poisoned() || publisher.is_broken_slot(&name) {
                    return Err(Error::NotDurable);
                }
                let root = publisher.root(&name).ok_or(Error::NotDurable)?;
                if root.state != LocalPublicationState::Durable {
                    return Err(Error::NotDurable);
                }
                root
            }
            Self::Cold { inspection, .. } => {
                if inspection.is_broken_slot(&name) {
                    return Err(Error::Metadata);
                }
                inspection.root(&name).ok_or(Error::NotDurable)?
            }
        };
        if root.root != pin.root {
            return Err(Error::Mismatch);
        }
        Ok(())
    }
    fn tombstoned(&self, digest: ContentDigest) -> bool {
        match self {
            Self::Live(publisher) => publisher.tombstones().any(|item| *item == digest),
            Self::Cold { inspection, .. } => inspection.report.tombstones.contains(&digest),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        digest: ContentDigest,
        maximum: usize,
        expected: CampaignPin,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
        bytes: &ReadAllowance,
        plan: Option<&CampaignPlan>,
        operation: CampaignOperation,
    ) -> Result<Vec<u8>> {
        access(authority, expected, self.root(), cx, plan, operation)?;
        work.charge(self.local().max_tombstones as u64 + 128)?;
        if self.tombstoned(digest) {
            return Err(Error::Tombstoned);
        }
        let result = match self {
            Self::Live(publisher) => {
                let bound = publisher.limits().spool.max_object_bytes as u64;
                work.charge(bound * 4 + 256)?;
                bytes.reserve(bound)?;
                let raw = publisher.spool().read(digest).map_err(|_| Error::Storage)?;
                bytes.settle(bound, raw.len() as u64);
                if raw.len() > maximum {
                    return Err(Error::Limit);
                }
                raw.to_vec()
            }
            Self::Cold { root, .. } => {
                let io = ReadIo::new(expected, root, authority, cx, work, bytes);
                let raw = read_verified_with_io(
                    root,
                    digest,
                    maximum.min(self.local().spool.max_object_bytes),
                    &io,
                );
                let failure = io.error();
                drop(io);
                raw.map_err(|_| failure.unwrap_or(Error::Storage))?
            }
        };
        work.charge(result.len() as u64 * 2 + 128)?;
        if result.len() > maximum || ContentDigest::sha256(&result) != digest {
            return Err(Error::Metadata);
        }
        access(authority, expected, self.root(), cx, plan, operation)?;
        work.charge(0)?;
        Ok(result)
    }
}

fn access(
    authority: &dyn CampaignAuthority,
    expected: CampaignPin,
    root: &Path,
    cx: &ReplayCx,
    plan: Option<&CampaignPlan>,
    operation: CampaignOperation,
) -> Result<()> {
    if let Some(plan) = plan {
        check(authority, operation, plan, root, cx)?;
    }
    if operation == CampaignOperation::Read {
        check_read(authority, expected, root, cx)?;
    }
    if cx.root_dir() != root || !cx.io_authority().is_valid() || cx.is_cancelled() {
        return Err(Error::Denied);
    }
    Ok(())
}

/// Verified immutable metadata prefix. Native bindings remain recorded observations, and there
/// is no acquisition/resume method. Start-only tails preserve explicitly unknown native outcomes.
#[derive(Debug)]
pub struct VerifiedCampaignHistory {
    pin: CampaignPin,
    pub(super) plan: CampaignPlan,
    pub(super) state: HistoryState,
    writer_limits: CampaignHistoryLimits,
    retained_metadata_bytes: u64,
    durability_resynced: bool,
    possibly_stale: bool,
}
impl VerifiedCampaignHistory {
    /// Verify exactly the independently selected root through an already-held live publisher.
    pub fn load(
        publisher: &LocalRootPublisher,
        expected: CampaignPin,
        limits: CampaignHistoryLimits,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        load_live(publisher, expected, limits, authority, cx, work, None)
    }

    /// Inspect existing bytes only: no locks, directory creation, repair, fsync, or reacquisition.
    /// The complete bounded publication scan and all selected reads share one work/byte account.
    /// Missing roots fail without creating them. The result observes visibility, not fresh fsync.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect(
        root: &Path,
        expected: CampaignPin,
        limits: CampaignHistoryLimits,
        local_limits: LocalPublicationLimits,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        expected.validate()?;
        publisher_bound(local_limits, limits)?;
        if expected.records > limits.maximum_records {
            return Err(Error::Limit);
        }
        check_read(authority, expected, root, cx)?;
        work.charge(2048)?;
        let bytes = ReadAllowance::new(limits.maximum_metadata_bytes);
        let io = ReadIo::new(expected, root, authority, cx, work, &bytes);
        let inspected = inspect_with_io(
            &io,
            root,
            local_limits,
            Some(&NoLockTable),
            WriterDetectionOptions::default(),
        );
        let failure = io.error();
        drop(io);
        // The common classifier may represent a failed underlying read as a broken object.
        // A current denial/budget refusal must remain that refusal, never corruption or success.
        if let Some(error) = failure {
            return Err(error);
        }
        let inspection = inspected.map_err(|_| failure.unwrap_or(Error::Storage))?;
        if inspection.missing_layout || inspection.spool_over_capacity {
            return Err(Error::NotDurable);
        }
        let source = Source::Cold {
            root,
            local: local_limits,
            inspection,
        };
        load_source(source, expected, limits, authority, cx, work, &bytes, None)
    }

    /// The independent selected pin, never a discovered latest head.
    pub const fn pin(&self) -> CampaignPin {
        self.pin
    }
    /// Exact frozen acquisition plan verified against the selected pin and current owner.
    pub fn plan(&self) -> &CampaignPlan {
        &self.plan
    }
    /// Original frozen retention bounds, verified equal across every selected transition.
    /// Reader limits remain independently supplied and can be narrower when sufficient.
    pub const fn writer_limits(&self) -> CampaignHistoryLimits {
        self.writer_limits
    }
    /// Exact canonical plan plus selected record/manifest bytes already charged to the writer's
    /// immutable metadata ceiling. Restart continuation carries this forward instead of resetting
    /// storage accounting.
    pub const fn retained_metadata_bytes(&self) -> u64 {
        self.retained_metadata_bytes
    }
    /// Every selected start in order, including failed, empty and unknown-outcome attempts.
    pub fn attempts(&self) -> &[CampaignAttemptHistory] {
        &self.state.attempts
    }
    /// Separate selected controller terminal, absent for every unterminated selected prefix.
    pub fn terminal(&self) -> Option<&CampaignTerminal> {
        self.state.terminal.as_ref()
    }
    /// True only for the already-held live publisher, never for strictly read-only inspection.
    pub const fn durability_resynced(&self) -> bool {
        self.durability_resynced
    }
    /// Whether concurrent writer state was unknown or possibly active during the read-only scan.
    pub const fn possibly_stale(&self) -> bool {
        self.possibly_stale
    }
}

pub(super) fn load_live(
    publisher: &LocalRootPublisher,
    expected: CampaignPin,
    limits: CampaignHistoryLimits,
    authority: &dyn CampaignAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    approved_plan: Option<&CampaignPlan>,
) -> Result<VerifiedCampaignHistory> {
    expected.validate()?;
    publisher_bound(publisher.limits(), limits)?;
    if expected.records > limits.maximum_records {
        return Err(Error::Limit);
    }
    let operation = if approved_plan.is_some() {
        CampaignOperation::Retain
    } else {
        CampaignOperation::Read
    };
    access(
        authority,
        expected,
        publisher.root_dir(),
        cx,
        approved_plan,
        operation,
    )?;
    let bytes = ReadAllowance::new(limits.maximum_metadata_bytes);
    load_source(
        Source::Live(publisher),
        expected,
        limits,
        authority,
        cx,
        work,
        &bytes,
        approved_plan,
    )
}

#[allow(clippy::too_many_arguments)]
fn load_source(
    source: Source<'_>,
    expected: CampaignPin,
    limits: CampaignHistoryLimits,
    authority: &dyn CampaignAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    bytes: &ReadAllowance,
    approved_plan: Option<&CampaignPlan>,
) -> Result<VerifiedCampaignHistory> {
    let operation = if approved_plan.is_some() {
        CampaignOperation::Retain
    } else {
        CampaignOperation::Read
    };
    source.selected_root(expected)?;
    let plan_bytes = source.read(
        expected.plan,
        MAX_PLAN_BYTES,
        expected,
        authority,
        cx,
        work,
        bytes,
        approved_plan,
        operation,
    )?;
    work.charge(4096 + plan_bytes.len() as u64 * 4)?;
    let plan = CampaignPlan::decode(&plan_bytes)?;
    let mut retained_metadata_bytes = u64::try_from(plan_bytes.len()).map_err(|_| Error::Limit)?;
    if plan.approval != expected.approval
        || plan.digest()? != expected.plan
        || approved_plan.is_some_and(|approved| approved != &plan)
    {
        return Err(Error::Mismatch);
    }
    access(
        authority,
        expected,
        source.root(),
        cx,
        Some(&plan),
        operation,
    )?;
    work.charge(2048 + u64::from(expected.records) * 4096)?;
    let mut records = Vec::with_capacity(expected.records as usize);
    let mut next = Some(expected);
    let mut writer_limits = None;
    for sequence in (1..=expected.records).rev() {
        let pin = next.ok_or(Error::Mismatch)?;
        pin.validate()?;
        if pin.approval != expected.approval || pin.plan != expected.plan || pin.records != sequence
        {
            return Err(Error::Mismatch);
        }
        source.selected_root(pin)?;
        let raw = source.read(
            pin.root,
            limits.maximum_spool_object_bytes,
            expected,
            authority,
            cx,
            work,
            bytes,
            Some(&plan),
            operation,
        )?;
        work.charge(1024 + raw.len() as u64 * 4)?;
        let manifest = ObjectManifest::from_canonical_bytes(&raw).map_err(|_| Error::Metadata)?;
        if manifest.root() != pin.root || manifest.kind() != KIND {
            return Err(Error::Mismatch);
        }
        let metadata = source.read(
            manifest.metadata_digest().ok_or(Error::Metadata)?,
            MAX_RECORD_BYTES,
            expected,
            authority,
            cx,
            work,
            bytes,
            Some(&plan),
            operation,
        )?;
        work.charge(1024 + metadata.len() as u64 * 4)?;
        let record = CampaignRecord::decode(&metadata)?;
        let raw_len = u64::try_from(raw.len()).map_err(|_| Error::Limit)?;
        let metadata_len = u64::try_from(metadata.len()).map_err(|_| Error::Limit)?;
        retained_metadata_bytes = retained_metadata_bytes
            .checked_add(raw_len)
            .and_then(|total| total.checked_add(metadata_len))
            .ok_or(Error::Limit)?;
        if record.pin(manifest.root()) != pin
            || record.manifest()? != manifest
            || writer_limits.is_some_and(|frozen| record.limits != frozen)
            || (approved_plan.is_some() && record.limits != limits)
            || record.limits.maximum_records < plan.attempts.len() as u32 * 2 + 1
        {
            return Err(Error::Mismatch);
        }
        writer_limits = Some(record.limits);
        next = record.prior;
        records.push((record, pin));
    }
    if next.is_some() {
        return Err(Error::Mismatch);
    }
    let mut state = HistoryState::default();
    for (record, pin) in records.iter().rev() {
        access(
            authority,
            expected,
            source.root(),
            cx,
            Some(&plan),
            operation,
        )?;
        work.charge(4096)?;
        state.advance(&plan, record, *pin)?;
    }
    cx.checkpoint(STAGE_CAMPAIGN_RELEASE)
        .map_err(|_| Error::Denied)?;
    access(
        authority,
        expected,
        source.root(),
        cx,
        Some(&plan),
        operation,
    )?;
    work.charge(0)?;
    let (durability_resynced, possibly_stale) = match &source {
        Source::Live(_) => (true, false),
        Source::Cold { inspection, .. } => (
            false,
            inspection.possibly_stale || inspection.possibly_in_flight,
        ),
    };
    let writer_limits = writer_limits.ok_or(Error::Mismatch)?;
    if retained_metadata_bytes > writer_limits.maximum_metadata_bytes {
        return Err(Error::Limit);
    }
    Ok(VerifiedCampaignHistory {
        pin: expected,
        plan,
        state,
        writer_limits,
        retained_metadata_bytes,
        durability_resynced,
        possibly_stale,
    })
}
