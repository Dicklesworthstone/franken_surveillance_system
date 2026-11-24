#![forbid(unsafe_code)]
//! Deployment open, reopen, initialization, and restart reconciliation for [`super::ReferenceDeployment`].

use std::fs;
use std::io;
use std::path::Path;

use fss_ledger::{DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, JournalError};
use fss_publication::LocalRootPublisher;

use super::ReferenceDeployment;
use super::constants::{
    DEPLOYMENT_LAYOUT_FILENAME, RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER, RELATIVE_PATH_OBJECTS,
    STAGE_DEPLOYMENT_OPEN, validate_site_lineage,
};
use super::layout::{
    DeploymentLayout, DeploymentLimits, DeploymentOpenMode, HostLayoutIo, is_skeleton_or_empty,
    require_existing_layout_and_journals, require_journals_or_empty_skeleton, write_layout_atomic,
};
use crate::adapter_replay::{ReplayAdmission, ReplayCx};
use crate::alert::ReferenceAlertProvider;
use crate::durable_effect::{DurableEffectError, DurableEffectJournal};
use crate::error::ReferenceError;

impl ReferenceDeployment {
    /// Opens or reopens a reference deployment with standard publication limits.
    pub fn open(
        root: &Path,
        site_lineage: &str,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, ReferenceError> {
        Self::open_with_limits(root, site_lineage, DeploymentLimits::standard(), cx)
    }

    /// Reopens an existing reference deployment root.
    pub fn reopen(
        root: &Path,
        site_lineage: &str,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, ReferenceError> {
        Self::open(root, site_lineage, cx)
    }

    /// Opens an established deployment for retained-package evaluation without changing effect
    /// states. Local publisher recovery and the exclusive deployment lock still apply. This is
    /// deliberately crate-private: the evaluation wrapper owns the handle and never returns it.
    pub(crate) fn open_existing_without_effect_reconciliation(
        root: &Path,
        site_lineage: &str,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, ReferenceError> {
        Self::open_existing_with_limits_without_effect_reconciliation(
            root,
            site_lineage,
            DeploymentLimits::standard(),
            cx,
        )
    }

    /// Reopens an existing deployment under its exact persisted capacity
    /// limits without reconciling effects. This does not create a deployment.
    pub(crate) fn open_existing_with_limits_without_effect_reconciliation(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, ReferenceError> {
        Self::open_with_mode(
            root,
            site_lineage,
            limits,
            cx,
            &|_: &Path| {},
            DeploymentOpenMode::ExistingWithoutEffectReconciliation,
        )
    }

    /// Opens or reopens a reference deployment with explicit capacity limits.
    pub fn open_with_limits(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, ReferenceError> {
        Self::open_with_after_lock(root, site_lineage, limits, cx, &|_: &Path| {})
    }

    /// [`Self::open_with_limits`] with `after_lock` invoked on `root` right after the deployment
    /// lock is taken and before the authoritative classification under it.
    ///
    /// Crate-internal failure-path seam: a test makes a foreign file appear between the advisory
    /// pre-check and the lock, and proves the classification under the lock refuses it.
    pub(crate) fn open_with_after_lock(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
        after_lock: &dyn Fn(&Path),
    ) -> Result<Self, ReferenceError> {
        Self::open_with_mode(
            root,
            site_lineage,
            limits,
            cx,
            after_lock,
            DeploymentOpenMode::InitializeAndReconcile,
        )
    }

    pub(super) fn open_with_mode(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
        after_lock: &dyn Fn(&Path),
        mode: DeploymentOpenMode,
    ) -> Result<Self, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DEPLOYMENT_OPEN,
            });
        }

        validate_site_lineage(site_lineage)?;

        let root_buf = root.to_path_buf();
        // A regular file, a symlink to one, or a dangling symlink is never a deployment root.
        if fs::symlink_metadata(root).is_ok() && !root.is_dir() {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }
        // Restore writes this guard before populating a fresh directory and removes it only
        // after the copied journals, custody and durable effect fence are complete. LAYOUT
        // alone must never make an interrupted restoration available to ordinary writers.
        match fs::symlink_metadata(root.join(crate::deployment_backup::RESTORE_INCOMPLETE_FILENAME))
        {
            Ok(_) => return Err(ReferenceError::NotADeployment { path: root_buf }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let ledger_path = root.join(RELATIVE_PATH_LEDGER);
        let objects_dir = root.join(RELATIVE_PATH_OBJECTS);
        let effects_path = root.join(RELATIVE_PATH_EFFECTS);
        let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);

        // Advisory pre-check before anything is created, so a foreign directory is refused with
        // zero side effects. The authoritative check is repeated under the deployment lock below.
        match mode {
            DeploymentOpenMode::InitializeAndReconcile => {
                if root.exists() && !layout_path.exists() && !is_skeleton_or_empty(root)? {
                    return Err(ReferenceError::NotADeployment { path: root_buf });
                }
                require_journals_or_empty_skeleton(root)?;
            }
            DeploymentOpenMode::ExistingWithoutEffectReconciliation => {
                require_existing_layout_and_journals(root)?;
            }
        }

        if mode == DeploymentOpenMode::InitializeAndReconcile && !root.exists() {
            fs::create_dir_all(root)?;
        }
        fs::create_dir_all(&objects_dir)?;

        // 1. Open local root publisher first: exclusive lock prevents concurrent access.
        // A second open refused here never touches or mutates either journal.
        let pub_limits = limits.to_publication_limits();
        // Every refusal goes through the typed `From<LocalPublicationError>` mapping: a held lock
        // becomes `DeploymentLocked`, and an overfull bounded directory scan `ScanLimitExceeded`.
        let publisher = LocalRootPublisher::open(&objects_dir, pub_limits)?;
        after_lock(root);

        // Repeat the guard after acquiring the publisher lock so a concurrent restoration
        // cannot become an initializer merely by winning the advisory pre-check race.
        match fs::symlink_metadata(root.join(crate::deployment_backup::RESTORE_INCOMPLETE_FILENAME))
        {
            Ok(_) => return Err(ReferenceError::NotADeployment { path: root_buf }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        // 2. Initialize or verify layout descriptor atomically.
        // Authoritative classification under the lock, before any cleanup or write: a root without
        // LAYOUT must still be empty or a bare deployment skeleton.
        match mode {
            DeploymentOpenMode::InitializeAndReconcile => {
                if !layout_path.exists() && !is_skeleton_or_empty(root)? {
                    return Err(ReferenceError::NotADeployment { path: root_buf });
                }
                require_journals_or_empty_skeleton(root)?;
            }
            DeploymentOpenMode::ExistingWithoutEffectReconciliation => {
                require_existing_layout_and_journals(root)?;
            }
        }
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("LAYOUT.tmp.") {
                fs::remove_file(entry.path())?;
            }
        }
        let limits_digest = limits.canonical_digest()?;
        let layout = if layout_path.exists() {
            let content = fs::read_to_string(&layout_path)?;
            let parsed = DeploymentLayout::parse_canonical_text(&content)?;
            if parsed.site_lineage != site_lineage {
                return Err(ReferenceError::SiteLineageMismatch {
                    expected: site_lineage.to_owned(),
                    actual: parsed.site_lineage,
                });
            }
            if parsed.limits_digest != limits_digest {
                return Err(ReferenceError::LimitsDigestMismatch {
                    expected: limits_digest,
                    actual: parsed.limits_digest,
                });
            }
            parsed
        } else if mode == DeploymentOpenMode::InitializeAndReconcile {
            let new_layout = DeploymentLayout::new(site_lineage, limits_digest);
            write_layout_atomic(root, &new_layout, &HostLayoutIo)?;
            new_layout
        } else {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        };

        if mode == DeploymentOpenMode::InitializeAndReconcile {
            if let Some(parent) = ledger_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Some(parent) = effects_path.parent() {
                fs::create_dir_all(parent)?;
            }
        }

        // 3. Open durable authority ledger: reject incomplete tails on open.
        let ledger = match DurableReferenceLedger::open(
            &ledger_path,
            site_lineage,
            IncompleteTailPolicy::Reject,
        ) {
            Ok(l) => l,
            Err(DurableLedgerError::Journal(JournalError::IncompleteTail { offset })) => {
                return Err(ReferenceError::IncompleteJournalTail {
                    offset,
                    path: ledger_path,
                    next_affordance: format!(
                        "fss-lab recover --root {} --truncate-incomplete-tail ledger",
                        root.display()
                    ),
                });
            }
            Err(other) => return Err(ReferenceError::DurableLedger(Box::new(other))),
        };

        // 4. Open durable effect journal: reject incomplete tails on open.
        let mut effects =
            match DurableEffectJournal::open(&effects_path, IncompleteTailPolicy::Reject) {
                Ok(e) => e,
                Err(DurableEffectError::Journal(JournalError::IncompleteTail { offset })) => {
                    return Err(ReferenceError::IncompleteJournalTail {
                        offset,
                        path: effects_path,
                        next_affordance: format!(
                            "fss-lab recover --root {} --truncate-incomplete-tail effects",
                            root.display()
                        ),
                    });
                }
                Err(other) => return Err(ReferenceError::DurableEffect(Box::new(other))),
            };

        let alert_provider = ReferenceAlertProvider::new(format!("alert:{}", site_lineage));

        // 5. Restart reconciliation (fss-mc9c4): the deployment-owned provider is created empty on
        // every open, so a `Committed` operation found here has no provider record in this
        // process; whatever dispatch it began died with the process that committed it. It becomes
        // explicitly `Indeterminate` (`restart_reconciliation_pending_observation`) and is never
        // re-dispatched. The deployment lock is held, so no live dispatch can own it.
        let restart_reclassified = match mode {
            DeploymentOpenMode::InitializeAndReconcile => effects
                .reclassify_committed_without_provider_record(&alert_provider)
                .map_err(|error| ReferenceError::DurableEffect(Box::new(error)))?,
            DeploymentOpenMode::ExistingWithoutEffectReconciliation => Vec::new(),
        };

        Ok(Self {
            root: root_buf,
            site_lineage: site_lineage.to_owned(),
            limits,
            ledger,
            publisher,
            effects,
            layout,
            alert_provider,
            restart_reclassified,
            injected_ledger_crash: None,
        })
    }
}
