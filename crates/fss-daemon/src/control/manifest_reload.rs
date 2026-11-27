#![forbid(unsafe_code)]
//! Read-only reload preparation bound to the supervisor's trusted source and active generation.
//!
//! Semantic plane: `"authority"`.

use std::path::PathBuf;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_ipc::{IpcResponse, RequestContext};

use super::{ControlPlaneShared, make_refused};
use crate::error::{DaemonError, ERR_DAEMON_CONTROL_APPROVAL_001, ERR_DAEMON_MANIFEST_INVALID_001};
use crate::manifest::SiteManifest;

/// Canonical domain for a reload approval bound to deployment, root, and both generations.
pub const DAEMON_MANIFEST_RELOAD_APPROVAL_DOMAIN: &str = "fss.daemon.manifest_reload_approval.v1";

/// Seals exactly one candidate semantic generation against the active-generation precondition.
/// JSON whitespace is not identity; all parsed manifest fields participate in its canonical digest.
#[must_use]
pub fn manifest_reload_approval_digest(
    deployment_id: &str,
    deployment_root_digest: ContentDigest,
    active_manifest_digest: ContentDigest,
    candidate_manifest_digest: ContentDigest,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(DAEMON_MANIFEST_RELOAD_APPROVAL_DOMAIN);
    encoder.text(deployment_id);
    encoder.digest(deployment_root_digest);
    encoder.digest(active_manifest_digest);
    encoder.digest(candidate_manifest_digest);
    ContentDigest::sha256(&encoder.finish())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ManifestReloadSource {
    path: PathBuf,
    active_manifest_digest: ContentDigest,
}

pub(super) struct ManifestReloadPreview {
    pub(super) active_manifest_digest: ContentDigest,
    pub(super) candidate_manifest_digest: ContentDigest,
    pub(super) approval_digest: ContentDigest,
    source: ManifestReloadSource,
}

impl ControlPlaneShared {
    /// Called by the supervisor before opening IPC. Requests never choose an arbitrary path.
    pub(crate) fn configure_manifest_reload(
        &self,
        path: Option<PathBuf>,
        active_manifest_digest: ContentDigest,
    ) -> Result<(), DaemonError> {
        let mut source =
            self.manifest_reload_source
                .write()
                .map_err(|_| DaemonError::LockPoisoned {
                    component: "manifest reload source",
                })?;
        *source = path.map(|path| ManifestReloadSource {
            path,
            active_manifest_digest,
        });
        Ok(())
    }

    /// Publish only after the supervisor applied the same parsed candidate to every live owner.
    pub(crate) fn publish_active_manifest_digest(
        &self,
        digest: ContentDigest,
    ) -> Result<(), DaemonError> {
        let mut source =
            self.manifest_reload_source
                .write()
                .map_err(|_| DaemonError::LockPoisoned {
                    component: "manifest reload source",
                })?;
        let source = source.as_mut().ok_or_else(|| DaemonError::InvalidConfig {
            detail: "manifest reload source is unavailable".to_owned(),
        })?;
        source.active_manifest_digest = digest;
        Ok(())
    }

    pub(crate) fn expected_manifest_reload_approval(
        &self,
        active_manifest_digest: ContentDigest,
        candidate_manifest_digest: ContentDigest,
    ) -> ContentDigest {
        manifest_reload_approval_digest(
            &self.deployment_id,
            self.deployment_root_digest,
            active_manifest_digest,
            candidate_manifest_digest,
        )
    }

    pub(super) fn read_manifest_reload_preview(
        &self,
        ctx: &RequestContext,
    ) -> Result<ManifestReloadPreview, IpcResponse> {
        self.check_manifest_reload_read(ctx)?;
        let source = self
            .manifest_reload_source
            .read()
            .map_err(|_| {
                make_refused(
                    ctx.request_id,
                    crate::error::ERR_DAEMON_SHUTDOWN_001,
                    "manifest reload source is unavailable",
                    false,
                )
            })?
            .clone()
            .ok_or_else(|| {
                make_refused(
                    ctx.request_id,
                    ERR_DAEMON_MANIFEST_INVALID_001,
                    "no manifest reload source is configured",
                    false,
                )
            })?;
        self.check_manifest_reload_read(ctx)?;
        // This is the same bounded, regular-file, schema-validating loader used at execution.
        // It returns an owned snapshot; no file-backed references survive the read.
        let candidate = SiteManifest::from_file(&source.path);
        self.check_manifest_reload_read(ctx)?;
        let candidate = candidate.map_err(|error| {
            make_refused(
                ctx.request_id,
                error.error_id(),
                "configured manifest reload candidate could not be read or validated",
                false,
            )
        })?;
        let unchanged = self
            .manifest_reload_source
            .read()
            .map_err(|_| {
                make_refused(
                    ctx.request_id,
                    crate::error::ERR_DAEMON_SHUTDOWN_001,
                    "manifest reload source is unavailable",
                    false,
                )
            })?
            .as_ref()
            == Some(&source);
        if !unchanged {
            return Err(make_refused(
                ctx.request_id,
                ERR_DAEMON_CONTROL_APPROVAL_001,
                "active manifest changed while preparing reload; preview again",
                true,
            ));
        }
        let candidate_manifest_digest = candidate.digest();
        Ok(ManifestReloadPreview {
            active_manifest_digest: source.active_manifest_digest,
            candidate_manifest_digest,
            approval_digest: self.expected_manifest_reload_approval(
                source.active_manifest_digest,
                candidate_manifest_digest,
            ),
            source,
        })
    }

    /// Recheck source and active generation after admission's lock was reacquired.
    /// Candidate bytes may still change on disk; execution independently verifies its owned parse.
    pub(super) fn manifest_reload_preview_is_current(
        &self,
        preview: &ManifestReloadPreview,
    ) -> Result<bool, DaemonError> {
        let current =
            self.manifest_reload_source
                .read()
                .map_err(|_| DaemonError::LockPoisoned {
                    component: "manifest reload source",
                })?;
        Ok(current.as_ref() == Some(&preview.source))
    }

    fn check_manifest_reload_read(&self, ctx: &RequestContext) -> Result<(), IpcResponse> {
        if ctx.is_cancelled() {
            return Err(IpcResponse::Cancelled {
                request_id: ctx.request_id,
            });
        }
        if self.is_shutdown_requested() {
            return Err(make_refused(
                ctx.request_id,
                fss_ipc::ERR_IPC_SERVER_SHUTDOWN_001,
                "daemon is draining for shutdown",
                true,
            ));
        }
        Ok(())
    }
}
