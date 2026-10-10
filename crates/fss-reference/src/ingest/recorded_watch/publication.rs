#![forbid(unsafe_code)]
//! Revalidate an analysis's source and authority before publishing any derived record.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_core::{ContentDigest, SensorId};

use super::{Result, WatchError};
use crate::ingest::privacy_mask::{MaskBinding, current_mask};
use crate::ingest::recorded_decode::RecordedDecodeError;
use crate::ingest::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Ephemeral publication preconditions. These do not alter historical report or proposal bytes.
#[derive(Clone, Debug)]
pub(crate) struct SourcePublicationGuard {
    root: PathBuf,
    site: String,
    principal: String,
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    sensor: SensorId,
    privacy: MaskBinding,
    limits: RetainedReadLimits,
    capsules: BTreeSet<ContentDigest>,
}

impl SourcePublicationGuard {
    pub(crate) fn capture(
        deployment: &ReferenceDeployment,
        source: &RetainedFileImport,
        sensor: &SensorId,
        privacy: &MaskBinding,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Self {
        Self {
            root: deployment.root().to_path_buf(),
            site: deployment.site_lineage().to_owned(),
            principal: cx.io_authority().principal().to_owned(),
            import_identity: source.import_identity(),
            import_root: source.import_root(),
            manifest_digest: source.manifest_digest(),
            sensor: sensor.clone(),
            privacy: privacy.clone(),
            limits,
            capsules: BTreeSet::new(),
        }
    }

    /// Bind every capsule contributing to the analysis, including background and quiet frames.
    pub(crate) fn bind_capsules(&mut self, capsules: impl IntoIterator<Item = ContentDigest>) {
        self.capsules.extend(capsules);
    }

    /// Check every precondition before staging, including on an already-published retry.
    /// Source verification streams at most one chunk and retains the analysis's read ceilings.
    pub(crate) fn revalidate(&self, deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
        cx.checkpoint("recorded_analysis:publication_revalidate")
            .map_err(|_| RecordedDecodeError::Cancelled)?;
        if deployment.root() != self.root.as_path()
            || cx.root_dir() != deployment.root()
            || deployment.site_lineage() != self.site
            || cx.io_authority().principal() != self.principal
        {
            return Err(WatchError::InvalidPlan(
                "analysis publication requires its original deployment and principal",
            ));
        }
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        let privacy = current_mask(deployment, &self.sensor).map_err(RecordedDecodeError::from)?;
        if privacy.digest() != self.privacy.digest()
            || privacy.generation() != self.privacy.generation()
        {
            return Err(WatchError::InvalidPlan(
                "privacy generation changed; recompute the recorded analysis",
            ));
        }
        // Opening checks deletion, the exact completion batch, and root-last custody. Hashing
        // the chunks also catches damage which metadata membership alone cannot establish.
        let source = RetainedFileImport::open(deployment, self.import_identity, self.limits, cx)?;
        if source.import_root() != self.import_root
            || source.manifest_digest() != self.manifest_digest
        {
            return Err(WatchError::Conflict);
        }
        source.verify_source(deployment, self.limits, cx)?;
        // Import membership is metadata-only. A source chunk can remain intact while a
        // selected capsule disappears or is damaged, so check its actual retained payload too.
        for digest in &self.capsules {
            cx.checkpoint("recorded_analysis:publication_capsule")
                .map_err(|_| RecordedDecodeError::Cancelled)?;
            let bytes = deployment
                .publisher()
                .spool()
                .read(*digest)
                .map_err(RecordedDecodeError::from)?;
            if ContentDigest::sha256(&bytes) != *digest {
                return Err(RecordedDecodeError::InvalidReceipt.into());
            }
        }
        Ok(())
    }
}
