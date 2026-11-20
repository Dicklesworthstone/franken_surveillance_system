#![forbid(unsafe_code)]
//! Source-closed, read-only access for calibrated whole-recording class advice.

use super::*;

impl LongCorroborationReport {
    /// Exact retained camera identities and complete analysis roots in native camera order.
    ///
    /// These roots bind the whole scans, exclusions and detector outcomes. They are not
    /// coverage witnesses, publication receipts or permission to observe another camera.
    pub fn source_cameras(&self) -> impl ExactSizeIterator<Item = (&CameraSummary, ContentDigest)> {
        self.cameras
            .iter()
            .map(|camera| (&camera.summary, camera.manifest.root()))
    }

    /// Revalidate derived use against the original owner, anchor and BOTH source closures.
    ///
    /// An empty candidate inventory is subject to the same checks. Requested health
    /// screening and geometry currency still fence advice; no custody is repaired and
    /// no model, event, coverage, policy or effect is published by this operation.
    pub fn revalidate_derived_sources(
        &self,
        deployment: &dyn RetainedSource,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_corroboration:derived_sources")?;
        self.revalidate_source_closure(deployment, cx, true)?;
        checkpoint(cx, "long_corroboration:derived_sources_checked")
    }

    /// Revalidate the complete two-camera preview, including quiet and health-degraded scans.
    ///
    /// Diagnostic previews remain readable when health screening blocks event publication.
    /// Both original recordings and every analyzed capsule still require exact custody,
    /// current privacy, the opening authority anchor and any retained geometry dependencies.
    pub fn revalidate_preview_sources(
        &self,
        deployment: &dyn RetainedSource,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_corroboration:preview_sources")?;
        self.revalidate_source_closure(deployment, cx, false)?;
        checkpoint(cx, "long_corroboration:preview_sources_checked")
    }

    fn revalidate_source_closure(
        &self,
        deployment: &dyn RetainedSource,
        cx: &ReplayCx,
        require_healthy: bool,
    ) -> Result<()> {
        if deployment.root() != self.root.as_path()
            || cx.root_dir() != deployment.root()
            || deployment.site_lineage() != self.site
            || cx.io_authority().principal() != self.principal
            || deployment.current_anchor() != &self.basis
        {
            return Err(CorroborationError::Conflict);
        }
        if require_healthy && self.publication_blocked() {
            return Err(CorroborationError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED));
        }
        for camera in &self.cameras {
            camera.publication_guard.revalidate(deployment, cx)?;
        }
        self.check_geometry_current(deployment, cx)
    }
}
