#![forbid(unsafe_code)]
//! Read-only deployment history reader, metadata read budget, and cancellable journal I/O.

use std::fs;
use std::io;
use std::path::Path;

use fss_core::{ContentDigest, EvidenceDeltaBatch, LedgerAnchor};

pub(crate) use super::io_budget::MetadataReadBudget;
pub(super) use super::io_budget::{CancellableHistoryJournal, Reader, ReadonlyPackCatalog};
use super::types::{
    DeploymentReadError, DeploymentSnapshot, HistoryPosition, OrientLimits, corrupt,
};
use crate::doctor::{DoctorVerdict, inspect_deployment, inspect_deployment_cancellable};
use crate::migration::DeploymentLayoutV2;
use crate::reference_deployment::{DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout};

/// Every committed prefix of one deployment root, read once without writing anything under it.
///
/// [`Self::read`] classifies the root with the read-only doctor, parses `LAYOUT` with a bound,
/// replays the committed authority ledger through [`fss_ledger::inspect_durable`] (and recomputes
/// the committed position of every batch with [`fss_ledger::committed_batch_positions`], refusing
/// a ledger whose records do not reproduce), and reads the durable effect journal once with a
/// bound, replaying its committed records. [`Self::snapshot_at`] then compiles the snapshot of any
/// committed position from those records alone: the ledger batches through its commit sequence,
/// the effect records through its record count, and the spool objects those batches name. Both
/// journals are append-only, so the snapshot of an earlier position is the state the root held
/// when that position was its head (the doctor verdict and tail flags describe the files as read
/// now).
#[derive(Clone, Debug)]
pub struct DeploymentHistory {
    pub(super) site_lineage: String,
    pub(super) objects: std::path::PathBuf,
    pub(super) doctor_verdict: DoctorVerdict,
    pub(super) doctor_inspected: bool,
    pub(super) layout_bytes: u64,
    pub(super) layout_digest: ContentDigest,
    pub(super) genesis_anchor: LedgerAnchor,
    pub(super) retained_ledger_snapshot: fss_core::LedgerSnapshot,
    pub(super) batches: Vec<EvidenceDeltaBatch>,
    pub(super) ledger_positions: Vec<fss_ledger::CommittedBatchPosition>,
    pub(super) ledger_tail_uncommitted: bool,
    /// Committed effect-journal bytes (tail excluded), or `None` when the journal is absent.
    pub(super) effect_bytes: Option<Vec<u8>>,
    pub(super) effect_records: Vec<fss_ledger::JournalRecord>,
    pub(super) effect_tail_uncommitted: bool,
    pub(super) limits: OrientLimits,
    pub(super) metadata_budget: Option<MetadataReadBudget>,
    pub(super) pack_catalog: Option<ReadonlyPackCatalog>,
}

impl DeploymentHistory {
    /// Reads the committed history of one deployment root without writing anything under it.
    ///
    /// A missing root, a non-directory, or a root without a parseable `LAYOUT` is
    /// [`DeploymentReadError::NotADeployment`]; an access failure is
    /// [`DeploymentReadError::Unreadable`]; history that fails replay or rehash is
    /// [`DeploymentReadError::Corrupt`]. An incomplete journal tail is not an error: only the
    /// committed prefix is read, and the history records that the tail exists.
    pub fn read(root: &Path, limits: &OrientLimits) -> Result<Self, DeploymentReadError> {
        let doctor_verdict = inspect_deployment(root).verdict;
        match doctor_verdict {
            DoctorVerdict::NotADeployment => {
                return Err(DeploymentReadError::NotADeployment {
                    reason: "the root is missing, is not a directory, or has no valid LAYOUT \
                             (see `fss doctor --json --root <dir>`)"
                        .to_owned(),
                });
            }
            DoctorVerdict::Unreadable => {
                return Err(DeploymentReadError::Unreadable {
                    reason: "the deployment root or its LAYOUT cannot be read".to_owned(),
                });
            }
            DoctorVerdict::Healthy | DoctorVerdict::AttentionRequired => {}
        }
        Self::read_inner(root, limits, doctor_verdict, true, None, None, None)
    }

    /// Reads committed history under a request-owned cancellation probe.
    ///
    /// The doctor and journal capabilities check cancellation before and after each admitted
    /// call. Cancellation is sticky for this read and never produces a successful partial
    /// history. A bounded host call already in progress cannot be preempted. The caller must
    /// classify a stopped request from its cancellation authority, rather than from a health
    /// verdict or an integrity error.
    pub fn read_cancellable(
        root: &Path,
        limits: &OrientLimits,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Self, DeploymentReadError> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let observed = AtomicBool::new(false);
        let stopped = || {
            if observed.load(Ordering::Acquire) || cancelled() {
                observed.store(true, Ordering::Release);
                true
            } else {
                false
            }
        };
        let doctor_verdict = inspect_deployment_cancellable(root, &stopped)
            .ok_or_else(|| corrupt("retained read authority cancelled"))?
            .verdict;
        match doctor_verdict {
            DoctorVerdict::NotADeployment => {
                return Err(DeploymentReadError::NotADeployment {
                    reason: "the root is missing, is not a directory, or has no valid LAYOUT \
                             (see `fss doctor --json --root <dir>`)"
                        .to_owned(),
                });
            }
            DoctorVerdict::Unreadable => {
                return Err(DeploymentReadError::Unreadable {
                    reason: "the deployment root or its LAYOUT cannot be read".to_owned(),
                });
            }
            DoctorVerdict::Healthy | DoctorVerdict::AttentionRequired => {}
        }
        let journal = CancellableHistoryJournal {
            cancelled: &stopped,
        };
        Self::read_inner(
            root,
            limits,
            doctor_verdict,
            true,
            None,
            Some(&stopped),
            Some(&journal),
        )
    }

    /// Reads committed history without performing a full-spool `fss doctor` directory scan,
    /// using an explicit externally supplied `(doctor_verdict, doctor_inspected)` state derived
    /// from an anchor-bound [`fss_projection_store::DoctorScrubReceipt`] (or conservative
    /// `(DoctorVerdict::AttentionRequired, false)` when no current scrub receipt exists).
    pub fn read_decoupled_cancellable(
        root: &Path,
        limits: &OrientLimits,
        doctor_verdict: DoctorVerdict,
        doctor_inspected: bool,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Self, DeploymentReadError> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let observed = AtomicBool::new(false);
        let stopped = || {
            if observed.load(Ordering::Acquire) || cancelled() {
                observed.store(true, Ordering::Release);
                true
            } else {
                false
            }
        };
        if stopped() {
            return Err(corrupt("retained read authority cancelled"));
        }
        let metadata = fs::symlink_metadata(root);
        if stopped() {
            return Err(corrupt("retained read authority cancelled"));
        }
        if !metadata
            .map_err(|_| DeploymentReadError::NotADeployment {
                reason: "the root is missing, is not a directory, or has no valid LAYOUT \
                         (see `fss doctor --json --root <dir>`)"
                    .to_owned(),
            })?
            .file_type()
            .is_dir()
        {
            return Err(DeploymentReadError::NotADeployment {
                reason: "deployment root is not a non-symlink directory".to_owned(),
            });
        }
        let journal = CancellableHistoryJournal {
            cancelled: &stopped,
        };
        Self::read_inner(
            root,
            limits,
            doctor_verdict,
            doctor_inspected,
            None,
            Some(&stopped),
            Some(&journal),
        )
    }

    /// Bounded metadata-only history. Skips the global spool doctor (which hydrates media).
    /// The conservative doctor verdict deliberately does not claim a full health inspection.
    pub(crate) fn read_metadata(
        root: &Path,
        limits: &OrientLimits,
        budget: &MetadataReadBudget,
    ) -> Result<Self, DeploymentReadError> {
        Self::read_metadata_cancellable(root, limits, budget, &|| false)
    }

    /// The borrowed admission is checked before every payload read, including history metadata.
    pub(crate) fn read_metadata_cancellable(
        root: &Path,
        limits: &OrientLimits,
        budget: &MetadataReadBudget,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, DeploymentReadError> {
        if cancelled() {
            budget.fail();
            return Err(corrupt("retained read authority cancelled"));
        }
        let metadata = fs::symlink_metadata(root);
        if cancelled() {
            budget.fail();
            return Err(corrupt("retained read authority cancelled"));
        }
        if !metadata
            .map_err(|_| DeploymentReadError::NotADeployment {
                reason: "missing deployment root".to_owned(),
            })?
            .file_type()
            .is_dir()
        {
            return Err(DeploymentReadError::NotADeployment {
                reason: "deployment root is not a non-symlink directory".to_owned(),
            });
        }
        Self::read_inner(
            root,
            limits,
            DoctorVerdict::AttentionRequired,
            false,
            Some(budget.clone()),
            Some(cancelled),
            None,
        )
    }

    fn read_inner(
        root: &Path,
        limits: &OrientLimits,
        doctor_verdict: DoctorVerdict,
        doctor_inspected: bool,
        budget: Option<MetadataReadBudget>,
        cancelled: Option<&dyn Fn() -> bool>,
        journal_io: Option<&dyn fss_ledger::JournalReadIo>,
    ) -> Result<Self, DeploymentReadError> {
        let mut reader = Reader {
            files_read: 0,
            bytes_read: 0,
            budget: budget.clone(),
            cancelled,
            pack_catalog: None,
        };
        let layout_bytes = reader
            .read_file(
                &root.join(DEPLOYMENT_LAYOUT_FILENAME),
                limits.max_layout_bytes,
            )
            .map_err(|error| DeploymentReadError::Unreadable {
                reason: format!("LAYOUT: {error}"),
            })?
            .ok_or_else(|| DeploymentReadError::NotADeployment {
                reason: "missing LAYOUT".to_owned(),
            })?;
        let layout_len = layout_bytes.len() as u64;
        let layout_digest = ContentDigest::sha256(&layout_bytes);
        let layout_text =
            String::from_utf8(layout_bytes).map_err(|_| DeploymentReadError::NotADeployment {
                reason: "LAYOUT is not UTF-8".to_owned(),
            })?;
        if let Ok(layout_v2) = DeploymentLayoutV2::parse_canonical_text(&layout_text) {
            return Self::read_inner_v2(
                root,
                layout_v2,
                layout_len,
                layout_digest,
                limits,
                doctor_verdict,
                doctor_inspected,
                budget,
                cancelled,
                &mut reader,
            );
        }
        let layout = DeploymentLayout::parse_canonical_text(&layout_text).map_err(|error| {
            DeploymentReadError::NotADeployment {
                reason: format!("LAYOUT does not parse: {error}"),
            }
        })?;
        let site = layout.site_lineage.clone();

        // Metadata-only callers admit all path components before following the descriptor.
        if budget.is_some() {
            for relative in [
                &layout.objects_relpath,
                &layout.ledger_relpath,
                &layout.effects_relpath,
            ] {
                let mut path = root.to_path_buf();
                let components: Vec<_> = Path::new(relative).components().collect();
                for (index, component) in components.iter().enumerate() {
                    path.push(component.as_os_str());
                    let directory =
                        index + 1 < components.len() || relative == &layout.objects_relpath;
                    reader
                        .admit()
                        .map_err(|_| corrupt("retained read authority cancelled"))?;
                    let metadata = fs::symlink_metadata(&path);
                    reader
                        .admit()
                        .map_err(|_| corrupt("retained read authority cancelled"))?;
                    match metadata {
                        Ok(meta)
                            if !meta.file_type().is_symlink()
                                && (!directory || meta.file_type().is_dir()) => {}
                        Err(error) if !directory && error.kind() == io::ErrorKind::NotFound => {}
                        _ => {
                            return Err(corrupt(
                                "deployment metadata path is unavailable or symlinked",
                            ));
                        }
                    }
                }
            }
        }
        let ledger = if budget.is_some() {
            let path = root.join(&layout.ledger_relpath);
            let bytes = reader
                .read_file(&path, limits.max_journal_bytes)
                .map_err(|error| corrupt(format!("authority ledger: {error}")))?
                .ok_or_else(|| corrupt("authority ledger is absent"))?;
            // Replay through the native inspector using the already metered immutable bytes.
            struct BufferedJournal<'a>(&'a [u8]);
            impl fss_ledger::JournalReadIo for BufferedJournal<'_> {
                fn symlink_metadata(
                    &self,
                    _: &Path,
                ) -> io::Result<fss_ledger::JournalFileMetadata> {
                    Ok(fss_ledger::JournalFileMetadata {
                        is_file: true,
                        is_symlink: false,
                        len: self.0.len() as u64,
                    })
                }
                fn read_bounded(&self, _: &Path, maximum: usize) -> io::Result<Vec<u8>> {
                    Ok(self.0[..self.0.len().min(maximum)].to_vec())
                }
            }
            fss_ledger::inspect_durable_with_io(
                &BufferedJournal(&bytes),
                &path,
                site.clone(),
                limits.max_journal_bytes,
            )
        } else if let Some(journal_io) = journal_io {
            fss_ledger::inspect_durable_with_io(
                journal_io,
                root.join(&layout.ledger_relpath),
                site.clone(),
                limits.max_journal_bytes,
            )
        } else {
            fss_ledger::inspect_durable(
                root.join(&layout.ledger_relpath),
                site.clone(),
                limits.max_journal_bytes,
            )
        }
        .map_err(|error| corrupt(format!("authority ledger replay failed: {error}")))?;
        reader
            .admit()
            .map_err(|_| corrupt("retained read authority cancelled"))?;
        if ledger.status == fss_ledger::DurableLedgerStatus::Absent {
            return Err(DeploymentReadError::Unreadable {
                reason: "the authority ledger is missing; retained history cannot be reconstructed from an empty replacement"
                    .to_owned(),
            });
        }
        let ledger_positions = fss_ledger::committed_batch_positions(&ledger).ok_or_else(|| {
            corrupt("authority ledger records do not reproduce their committed positions")
        })?;
        let genesis_anchor = ledger.batches.first().map_or_else(
            || ledger.snapshot.anchor.clone(),
            |batch| batch.basis_anchor.clone(),
        );

        let effects_path = root.join(&layout.effects_relpath);
        let effect_file = reader
            .read_file(&effects_path, limits.max_journal_bytes)
            .map_err(|error| DeploymentReadError::Unreadable {
                reason: format!("effect journal: {error}"),
            })?;
        let (effect_bytes, effect_records, effect_tail_uncommitted) = match effect_file {
            None => (None, Vec::new(), false),
            Some(mut bytes) => {
                let report = fss_ledger::doctor(&bytes).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                let committed = usize::try_from(report.committed_len())
                    .ok()
                    .filter(|len| *len <= bytes.len())
                    .ok_or_else(|| corrupt("durable effect journal committed length overflows"))?;
                bytes.truncate(committed);
                let recovery = fss_ledger::recover_bytes(&bytes).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                // Replaying the complete committed history once validates every record, so every
                // prefix replayed later is a prefix of a valid history.
                crate::durable_effect::replay_records(recovery.records()).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                let tail = report.incomplete_tail().is_some() || report.foreign_range().is_some();
                (Some(bytes), recovery.records().to_vec(), tail)
            }
        };
        reader
            .admit()
            .map_err(|_| corrupt("retained read authority cancelled"))?;
        Ok(Self {
            site_lineage: site,
            objects: root.join(&layout.objects_relpath),
            doctor_verdict,
            doctor_inspected,
            layout_bytes: layout_len,
            layout_digest,
            genesis_anchor,
            retained_ledger_snapshot: ledger.snapshot.clone(),
            batches: ledger.batches.clone(),
            ledger_positions,
            ledger_tail_uncommitted: !ledger.is_clean(),
            effect_bytes,
            effect_records,
            effect_tail_uncommitted,
            limits: *limits,
            metadata_budget: budget,
            pack_catalog: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn read_inner_v2(
        root: &Path,
        layout: DeploymentLayoutV2,
        layout_len: u64,
        layout_digest: ContentDigest,
        limits: &OrientLimits,
        doctor_verdict: DoctorVerdict,
        doctor_inspected: bool,
        budget: Option<MetadataReadBudget>,
        cancelled: Option<&dyn Fn() -> bool>,
        reader: &mut Reader<'_>,
    ) -> Result<Self, DeploymentReadError> {
        let site = layout.site_lineage.clone();
        let ledger_dir = root.join(&layout.ledger_relpath);
        let objects_dir = root.join(&layout.objects_relpath);
        reader
            .admit()
            .map_err(|_| corrupt("retained read authority cancelled"))?;
        let inspected = fss_ledger::inspect_epochs_readonly(&ledger_dir, &site)
            .map_err(|error| corrupt(format!("v2 epoch ledger replay failed: {error}")))?;
        reader
            .admit()
            .map_err(|_| corrupt("retained read authority cancelled"))?;
        let pack_catalog = ReadonlyPackCatalog::scan(&objects_dir);

        let effects_path = root.join(&layout.effects_relpath);
        let effect_file = reader
            .read_file(&effects_path, limits.max_journal_bytes)
            .map_err(|error| DeploymentReadError::Unreadable {
                reason: format!("effect journal: {error}"),
            })?;
        let (effect_bytes, effect_records, effect_tail_uncommitted) = match effect_file {
            None => (None, Vec::new(), false),
            Some(mut bytes) => {
                let report = fss_ledger::doctor(&bytes).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                let committed = usize::try_from(report.committed_len())
                    .ok()
                    .filter(|len| *len <= bytes.len())
                    .ok_or_else(|| corrupt("durable effect journal committed length overflows"))?;
                bytes.truncate(committed);
                let recovery = fss_ledger::recover_bytes(&bytes).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                crate::durable_effect::replay_records(recovery.records()).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                let tail = report.incomplete_tail().is_some() || report.foreign_range().is_some();
                (Some(bytes), recovery.records().to_vec(), tail)
            }
        };
        if cancelled.is_some_and(|c| c()) {
            return Err(corrupt("retained read authority cancelled"));
        }
        let retained_ledger_snapshot = fss_core::LedgerSnapshot {
            anchor: inspected.head_anchor.clone(),
            objects: std::collections::BTreeMap::new(),
        };
        Ok(Self {
            site_lineage: site,
            objects: objects_dir,
            doctor_verdict,
            doctor_inspected,
            layout_bytes: layout_len,
            layout_digest,
            genesis_anchor: inspected.genesis_anchor,
            retained_ledger_snapshot,
            batches: inspected.batches,
            ledger_positions: inspected.positions,
            ledger_tail_uncommitted: inspected.incomplete_tail,
            effect_bytes,
            effect_records,
            effect_tail_uncommitted,
            limits: *limits,
            metadata_budget: budget,
            pack_catalog: Some(pack_catalog),
        })
    }

    pub(crate) fn retained_ledger_snapshot(&self) -> &fss_core::LedgerSnapshot {
        &self.retained_ledger_snapshot
    }

    pub(crate) fn has_uncommitted_tail(&self) -> bool {
        self.ledger_tail_uncommitted || self.effect_tail_uncommitted
    }

    pub(crate) fn metadata_layout_digest(&self) -> ContentDigest {
        self.layout_digest
    }

    /// Site lineage from `LAYOUT`.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.site_lineage
    }

    /// Bounds the history was read under; every snapshot applies them too.
    #[must_use]
    pub const fn limits(&self) -> &OrientLimits {
        &self.limits
    }

    /// Exact source namespace offered to an adjacent-replay caller's I/O authority.
    pub fn replay_objects_root(&self) -> &Path {
        &self.objects
    }

    /// The next retained ledger commit, without hydrating any intervening or future object.
    pub(crate) fn next_ledger_commit(&self, after: u64, through: u64) -> Option<u64> {
        self.batches
            .iter()
            .map(|batch| batch.new_anchor.commit_sequence)
            .find(|sequence| *sequence > after && *sequence <= through)
    }

    /// Exact committed head history for the optional wait's typed custody verification.
    pub(crate) fn batches_through_head(&self) -> &[EvidenceDeltaBatch] {
        &self.batches
    }

    /// One bounded source object for the separately admitted wait custody read. The caller
    /// checks live authority/deadline, committed deletions, and local tombstones at its boundary.
    pub(crate) fn wait_read_object(
        &self,
        digest: ContentDigest,
        maximum: usize,
    ) -> Result<Vec<u8>, fss_publication::LocalPublicationError> {
        // Preserve the owner's typed over-limit distinction for the wait budget response.
        fss_publication::read_verified(
            &self.objects,
            digest,
            maximum.min(self.limits.max_object_bytes),
        )
    }

    /// Targeted availability check: no catalogue scan, lock, hold, or repair. Even malformed
    /// local tombstone markers deny this exact object; they never authorize raw payload reuse.
    pub(crate) fn wait_check_tombstone(
        &self,
        digest: ContentDigest,
    ) -> Result<(), DeploymentReadError> {
        let directory = self.objects.join(fss_publication::LOCAL_TOMBSTONES_DIR);
        match fs::symlink_metadata(&directory) {
            Ok(meta) if meta.file_type().is_dir() => {}
            _ => {
                return Err(corrupt(
                    "source custody tombstone directory is unverifiable",
                ));
            }
        }
        let stem = digest.to_text().replacen(':', "-", 1);
        for suffix in ["", fss_publication::ROOT_INDETERMINATE_SUFFIX] {
            let path = directory.join(format!(
                "{stem}{}{suffix}",
                fss_publication::TOMBSTONE_RECORD_SUFFIX
            ));
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => {
                    return Err(corrupt(format!(
                        "source custody object {digest} is tombstoned or its tombstone state is unverifiable"
                    )));
                }
            }
        }
        Ok(())
    }

    /// One exact publication record under the wait caller's read admission. Pending or
    /// indeterminate replacement of the selected slot cannot be treated as durable custody.
    pub(crate) fn wait_read_publication(
        &self,
        slot: &fss_publication::SlotName,
        maximum: usize,
    ) -> Result<Vec<u8>, DeploymentReadError> {
        self.wait_read_publication_cancellable(slot, maximum, &|| false)
    }

    pub(crate) fn wait_read_publication_cancellable(
        &self,
        slot: &fss_publication::SlotName,
        maximum: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, DeploymentReadError> {
        let directory = self.objects.join(fss_publication::LOCAL_ROOTS_DIR);
        if !fs::symlink_metadata(&directory)
            .map_err(|_| corrupt("source custody root directory is unavailable"))?
            .file_type()
            .is_dir()
        {
            return Err(corrupt("source custody root directory is not a directory"));
        }
        let name = format!("{slot}{}", fss_publication::ROOT_RECORD_SUFFIX);
        for suffix in [
            fss_publication::ROOT_TEMP_SUFFIX,
            fss_publication::ROOT_INDETERMINATE_SUFFIX,
        ] {
            match fs::symlink_metadata(directory.join(format!("{name}{suffix}"))) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => {
                    return Err(corrupt(format!(
                        "source custody publication {slot} is in flight or unverifiable"
                    )));
                }
            }
        }
        Reader {
            files_read: 0,
            bytes_read: 0,
            budget: self.metadata_budget.clone(),
            cancelled: Some(cancelled),
            pack_catalog: self.pack_catalog.as_ref(),
        }
        .read_file(&directory.join(name), maximum)
        .map_err(|_| corrupt(format!("source custody publication {slot} cannot be read")))?
        .ok_or_else(|| corrupt(format!("source custody publication {slot} is missing")))
    }

    /// The committed head: the last ledger batch and every committed effect record.
    #[must_use]
    pub fn head(&self) -> HistoryPosition {
        HistoryPosition {
            commit_sequence: self
                .batches
                .last()
                .map_or(self.genesis_anchor.commit_sequence, |batch| {
                    batch.new_anchor.commit_sequence
                }),
            effect_records: self
                .effect_bytes
                .as_ref()
                .map(|_| self.effect_records.len() as u64),
        }
    }

    /// Ledger batches committed through `commit_sequence`, or `None` when no committed prefix ends
    /// there.
    pub(super) fn ledger_prefix(&self, commit_sequence: u64) -> Option<usize> {
        if commit_sequence == self.genesis_anchor.commit_sequence {
            return Some(0);
        }
        self.batches
            .iter()
            .position(|batch| batch.new_anchor.commit_sequence == commit_sequence)
            .map(|index| index + 1)
    }

    /// Effect records committed in `position`, or `None` when the position names more records
    /// than the journal holds (or a journal that no longer exists).
    pub(super) fn effect_prefix(&self, effect_records: Option<u64>) -> Option<Option<usize>> {
        match effect_records {
            None => Some(None),
            Some(count) => {
                let count = usize::try_from(count).ok()?;
                (self.effect_bytes.is_some() && count <= self.effect_records.len())
                    .then_some(Some(count))
            }
        }
    }

    /// Whether `position` is a committed prefix of this history.
    #[must_use]
    pub fn contains(&self, position: HistoryPosition) -> bool {
        self.ledger_prefix(position.commit_sequence).is_some()
            && self.effect_prefix(position.effect_records).is_some()
    }

    /// The authority anchor, ledger record root, and effect-journal record root at `position`;
    /// `None` when the position is not a committed prefix. Reads nothing.
    #[must_use]
    pub fn roots_at(
        &self,
        position: HistoryPosition,
    ) -> Option<(LedgerAnchor, ContentDigest, ContentDigest)> {
        let batches = self.ledger_prefix(position.commit_sequence)?;
        let effects = self.effect_prefix(position.effect_records)?;
        let zero = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0_u8; 32]);
        let anchor = match batches.checked_sub(1) {
            None => self.genesis_anchor.clone(),
            Some(last) => self.batches.get(last)?.new_anchor.clone(),
        };
        let ledger_root = match batches.checked_sub(1) {
            None => zero,
            Some(last) => self.ledger_positions.get(last)?.record_root,
        };
        let effect_root = match effects.and_then(|count| count.checked_sub(1)) {
            None => zero,
            Some(last) => self.effect_records.get(last)?.root(),
        };
        Some((anchor, ledger_root, effect_root))
    }
}

/// Reads one deployment root at its committed head without writing anything under it.
///
/// A missing root, a non-directory, or a root without a parseable `LAYOUT` is
/// [`DeploymentReadError::NotADeployment`]; an access failure is
/// [`DeploymentReadError::Unreadable`]; history that fails replay or rehash is
/// [`DeploymentReadError::Corrupt`]. An incomplete journal tail is not an error: only the
/// committed prefix is read, and the snapshot records that the tail exists. This is exactly
/// [`DeploymentHistory::snapshot_at`] of [`DeploymentHistory::head`].
pub fn read_deployment(
    root: &Path,
    limits: &OrientLimits,
) -> Result<DeploymentSnapshot, DeploymentReadError> {
    let history = DeploymentHistory::read(root, limits)?;
    history.snapshot_at(history.head())
}

/// Reads the committed head under a request-owned cancellation probe.
///
/// This is the cancellable counterpart of [`read_deployment`], with the same successful
/// snapshot, history position, byte accounting, and semantic identities. A cancellation
/// refusal must be classified by the caller's cancellation authority, not as a corrupt root.
pub fn read_deployment_cancellable(
    root: &Path,
    limits: &OrientLimits,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<DeploymentSnapshot, DeploymentReadError> {
    let history = DeploymentHistory::read_cancellable(root, limits, cancelled)?;
    history.snapshot_at_cancellable(history.head(), cancelled)
}
