#![forbid(unsafe_code)]
//! Read-only access for source-bound derived class fusion, not a publication bypass.

use super::*;

impl LongWatchCandidate {
    /// Identity of the complete native entry record, including its exact analysis closure.
    /// This is not a new event identity or a fusion-generated publication approval.
    pub fn identity(&self) -> ContentDigest {
        ContentDigest::sha256(&self.record)
    }

    /// Original native provenance closure. Advice must not substitute its own graph here.
    pub fn provenance_root(&self) -> ContentDigest {
        self.manifest.root()
    }
}

impl LongWatchReport {
    /// Source-closed analysis graph, distinct from a coverage witness or a durable receipt.
    pub fn analysis_root(&self) -> ContentDigest {
        self.analysis_manifest.root()
    }

    /// Exact retained sensor; labels and command-line aliases do not replace this identity.
    pub fn sensor_id(&self) -> &SensorId {
        &self.sensor
    }

    /// Revalidate a read-only derived use under the original owner, deployment, authority
    /// anchor, source custody and privacy. This performs no repair, staging or publication.
    /// It applies even to a zero-candidate run; stale evidence cannot produce a fresh-looking
    /// empty result. A requested whole-scan health gate also fences class support.
    pub fn revalidate_derived_source(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_watch:derived_source")?;
        if deployment.root() != self.root.as_path()
            || cx.root_dir() != deployment.root()
            || deployment.site_lineage() != self.site
            || cx.io_authority().principal() != self.principal
            || deployment.current_anchor() != &self.basis
        {
            return Err(WatchError::Conflict);
        }
        if self.publication_blocked() {
            return Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED));
        }
        self.publication_guard.revalidate(deployment, cx)?;
        checkpoint(cx, "long_watch:derived_source_checked")
    }
}
