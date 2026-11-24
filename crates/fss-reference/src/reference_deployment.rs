#![forbid(unsafe_code)]
//! Deterministic reference deployment composition.
//!
//! Lifts the composition of [`DurableReferenceLedger`], [`LocalRootPublisher`] (with its owned
//! [`StagingSpool`](fss_object::StagingSpool)), and [`DurableEffectJournal`] into one canonical library
//! type defining a deployment root on disk.

mod batches;
mod constants;
mod dispatch;
mod events;
mod layout;
mod open;
mod recovery;

pub use batches::{ReplayCancellationBridge, StagedManifestHandle};
pub(crate) use constants::publish_cut_point_stage;
pub use constants::{
    DEPLOYMENT_CANCEL_STAGES, DEPLOYMENT_LAYOUT_FILENAME, DEPLOYMENT_LAYOUT_FORMAT_VERSION,
    DEPLOYMENT_LAYOUT_SCHEMA, FAMILY_ACQUISITION_TRANSITION, FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_CALIBRATION_INVALIDATION, FAMILY_COVERAGE_WITNESS, FAMILY_DECODE_RECEIPT,
    FAMILY_DELETION_COMPLETION, FAMILY_DELETION_RECORD, FAMILY_DELETION_TOMBSTONE,
    FAMILY_EVENT_REVISION, FAMILY_EVIDENCE_HOLD, FAMILY_EXECUTOR_MODEL_RESULT, FAMILY_FILE_IMPORT,
    FAMILY_FILE_IMPORT_MANIFEST, FAMILY_MODEL_INVOCATION_RECEIPT, FAMILY_PRIVACY_MASK_POLICY,
    FAMILY_RETENTION_POLICY, FAMILY_SENSOR_CAPSULE, FAMILY_SENSOR_TAMPER_STATUS,
    FAMILY_TWIN_LOCALIZATION_RECEIPT, KNOWN_LEDGER_DELTA_FAMILIES, RELATIVE_PATH_EFFECTS,
    RELATIVE_PATH_LEDGER, RELATIVE_PATH_OBJECTS, STAGE_AFTER_CHILDREN_VERIFIED,
    STAGE_AFTER_MANIFEST_BODY, STAGE_AFTER_ROOT_RENAME, STAGE_AFTER_ROOT_TEMP_WRITE,
    STAGE_APPEND_BATCH, STAGE_COMPILE_SITUATION, STAGE_DEPLOYMENT_OPEN, STAGE_DISPATCH_ALERT,
    STAGE_EVALUATE_POLICY, STAGE_PUBLISH_EVENT, STAGE_PUBLISH_ROOT, STAGE_SEAL_HANDOFF,
    STAGE_STAGE_MANIFEST, STAGE_STAGE_OBJECTS, validate_site_lineage,
};
#[cfg(test)]
use layout::DeploymentOpenMode;
pub use layout::{DeploymentLayout, DeploymentLimits, HostLayoutIo, LayoutIo, write_layout_atomic};
pub(crate) use recovery::find_structurally_valid_record;
pub use recovery::{RecoveryAction, RecoveryReceipt};

use std::path::{Path, PathBuf};

use fss_core::{LedgerAnchor, OperationId};
use fss_ledger::DurableReferenceLedger;
use fss_publication::{LedgerCutPoint, LocalRecoveryReport, LocalRootPublisher};

use crate::alert::ReferenceAlertProvider;
use crate::durable_effect::DurableEffectJournal;
use crate::error::ReferenceError;

/// A unified reference deployment root on disk.
#[derive(Debug)]
pub struct ReferenceDeployment {
    root: PathBuf,
    site_lineage: String,
    limits: DeploymentLimits,
    ledger: DurableReferenceLedger,
    publisher: LocalRootPublisher,
    effects: DurableEffectJournal,
    layout: DeploymentLayout,
    alert_provider: ReferenceAlertProvider,
    /// Operations this open's restart reconciliation moved from `Committed` to `Indeterminate`.
    restart_reclassified: Vec<OperationId>,
    /// One-shot ledger-linkage crash armed by [`Self::inject_ledger_crash_at`] for the next
    /// [`Self::publish_and_commit`]; `None` outside fault-injection runs.
    injected_ledger_crash: Option<LedgerCutPoint>,
}

impl ReferenceDeployment {
    /// Returns the root filesystem path of this deployment.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the site lineage identifier.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.site_lineage
    }

    /// Returns the capacity limits configured for this deployment.
    #[must_use]
    pub const fn limits(&self) -> &DeploymentLimits {
        &self.limits
    }

    /// Returns the read-only deployment layout descriptor.
    #[must_use]
    pub const fn layout_report(&self) -> &DeploymentLayout {
        &self.layout
    }

    /// Returns the publication recovery report observed on open.
    #[must_use]
    pub const fn recovery_report(&self) -> &LocalRecoveryReport {
        self.publisher.recovery_report()
    }

    /// Returns a reference to the durable authority ledger.
    #[must_use]
    pub const fn ledger(&self) -> &DurableReferenceLedger {
        &self.ledger
    }

    /// Returns a mutable reference to the durable authority ledger.
    ///
    /// Test-only and crate-internal: outside callers commit authority only through the guarded
    /// entry points (`append_batch`, `publish_event`, `publish_and_commit`); the in-crate tests use
    /// it to arm journal fault injection.
    #[cfg(test)]
    pub(crate) fn ledger_mut(&mut self) -> &mut DurableReferenceLedger {
        &mut self.ledger
    }

    /// Returns a reference to the local root publisher.
    #[must_use]
    pub const fn publisher(&self) -> &LocalRootPublisher {
        &self.publisher
    }

    /// Returns a mutable reference to the local root publisher.
    pub fn publisher_mut(&mut self) -> &mut LocalRootPublisher {
        &mut self.publisher
    }

    /// Removes exactly the orphaned staging files the spool classified when this deployment
    /// opened (fss-vmau3), under the deployment lock this instance holds for its whole life.
    ///
    /// Delegates to [`LocalRootPublisher::discard_orphaned_staging`], which keeps the spool's
    /// fsync and poison contract: an outcome that cannot be observed is returned as
    /// `LocalPublicationError::Spool(SpoolError::DiscardIndeterminate { .. })` inside
    /// [`ReferenceError::LocalPublication`], and the publisher is then poisoned until a reopen.
    pub fn discard_orphaned_staging(
        &mut self,
    ) -> Result<fss_object::DiscardReceipt, ReferenceError> {
        self.publisher
            .discard_orphaned_staging()
            .map_err(ReferenceError::from)
    }

    /// Returns a reference to the durable effect journal.
    #[must_use]
    pub const fn effects(&self) -> &DurableEffectJournal {
        &self.effects
    }

    /// Returns a mutable reference to the durable effect journal.
    pub fn effects_mut(&mut self) -> &mut DurableEffectJournal {
        &mut self.effects
    }

    /// Returns the durable effect journal mutably together with the authority ledger it must be
    /// checked against, so an alert is prepared against this deployment's own authority (for
    /// example through [`DurableEffectJournal::prepare_alert`]).
    pub fn effects_and_ledger(&mut self) -> (&mut DurableEffectJournal, &DurableReferenceLedger) {
        (&mut self.effects, &self.ledger)
    }

    /// Returns the durable effect journal mutably with the authority ledger and the local root
    /// publisher whose verified spool holds the event revisions, so an alert dispatch (for
    /// example [`crate::webhook::WebhookAttempt`]) revalidates against this deployment's own
    /// authority and reads payloads only through verified custody.
    pub fn effect_dispatch_parts(
        &mut self,
    ) -> (
        &mut DurableEffectJournal,
        &DurableReferenceLedger,
        &LocalRootPublisher,
    ) {
        (&mut self.effects, &self.ledger, &self.publisher)
    }

    /// Operations this open's restart reconciliation reclassified from `Committed` to
    /// `Indeterminate` with reason
    /// [`crate::RESTART_RECONCILIATION_PENDING_OBSERVATION`], in canonical identity order
    /// (fss-mc9c4). Empty when nothing was committed without a provider record.
    #[must_use]
    pub fn restart_reclassified(&self) -> &[OperationId] {
        &self.restart_reclassified
    }

    /// Returns a reference to the deployment-owned simulated alert provider.
    #[must_use]
    pub const fn alert_provider(&self) -> &ReferenceAlertProvider {
        &self.alert_provider
    }

    /// Returns a mutable reference to the deployment-owned simulated alert provider.
    pub fn alert_provider_mut(&mut self) -> &mut ReferenceAlertProvider {
        &mut self.alert_provider
    }

    /// Current canonical authority anchor.
    #[must_use]
    pub fn current_anchor(&self) -> &LedgerAnchor {
        &self.ledger.current().anchor
    }
}

#[cfg(test)]
#[path = "reference_deployment_existing_tests.rs"]
mod existing_open_tests;
