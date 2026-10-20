#![forbid(unsafe_code)]
//! Immutable source access for derived class advice over sampled dwell episodes.

use super::*;

impl LongDwellCandidate {
    /// Exact native episode record, binding its dwell rule and whole-recording analysis.
    pub fn identity(&self) -> ContentDigest {
        ContentDigest::sha256(&self.record)
    }

    /// Native episode provenance; derived advice cannot replace its custody graph.
    pub fn provenance_root(&self) -> ContentDigest {
        self.manifest.root()
    }
}

impl LongDwellReport {
    /// Source-closed analysis graph, never a coverage witness or publication receipt.
    pub fn analysis_root(&self) -> ContentDigest {
        self.analysis_manifest.root()
    }

    /// Retained sensor identity, independent of command-line labels.
    pub fn sensor_id(&self) -> &SensorId {
        &self.sensor
    }

    /// Revalidate a derived read against its original owner, anchor, retained source and
    /// current privacy policy. Requested health screening also fences class support.
    /// This check applies to empty scans and performs no staging, repair or publication.
    pub fn revalidate_derived_source(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_dwell:derived_source")?;
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
        checkpoint(cx, "long_dwell:derived_source_checked")
    }
}
