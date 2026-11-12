#![forbid(unsafe_code)]
//! Existing-store ownership for operational QSR reads.
//!
//! The deployment handle stays inside this owner: callers receive only a fully verified report.

use std::path::Path;

use fss_core::DigestAlgorithm;

use super::{ContentDigest, PackageZoneError, QsrConfig, QsrError, QsrObservationReport, Result};
use crate::{DeploymentLimits, ReferenceDeployment, ReferenceError, ReplayCx};

impl QsrObservationReport {
    /// Read one retained screened report from an existing deployment with standard capacities.
    ///
    /// The deployment must already exist and exactly match the context root and site. This
    /// constructor cannot initialize a store or reconcile external effects. Prepared, committed
    /// and indeterminate operations and their obligations remain unchanged, even if the report
    /// is refused. The internal deployment handle never escapes to the caller.
    ///
    /// The exclusive local publisher lock and its existing recovery still apply, including
    /// cleanup of stale local staging/layout files. This is an operational retained read, not
    /// the immutable storage boundary required by a canonical `fss/1` read.
    ///
    /// Layout v1 stores only the capacity digest, not the original values. Nonstandard
    /// deployments must use [`Self::open_existing_with_limits`] with their exact original limits.
    pub fn open_existing(
        root: &Path,
        site_lineage: &str,
        report_digest: ContentDigest,
        config: QsrConfig,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::open_existing_with_limits(
            root,
            site_lineage,
            DeploymentLimits::standard(),
            report_digest,
            config,
            cx,
        )
    }

    /// As [`Self::open_existing`], with explicit original deployment capacities.
    ///
    /// The supplied limits must match the persisted layout digest exactly. They are never
    /// substituted, inferred from that digest, or silently widened to open the store.
    pub fn open_existing_with_limits(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        report_digest: ContentDigest,
        config: QsrConfig,
        cx: &ReplayCx,
    ) -> Result<Self> {
        // Reject invalid requests and revoked/mismatched contexts before acquiring the local
        // publisher lock or running its recovery.
        config.validate_shape()?;
        if report_digest.algorithm() != DigestAlgorithm::Sha256 || report_digest.bytes() == [0; 32]
        {
            return Err(QsrError::Invalid("nonzero SHA-256 report required"));
        }
        cx.checkpoint("qsr:open_existing")
            .map_err(|_| QsrError::Cancelled)?;
        if cx.root_dir() != root {
            return Err(QsrError::Invalid("context root does not match deployment"));
        }
        let deployment =
            ReferenceDeployment::open_existing_with_limits_without_effect_reconciliation(
                root,
                site_lineage,
                limits,
                cx,
            )
            .map_err(|error| match error {
                ReferenceError::CancellationRequested { .. } => QsrError::Cancelled,
                error => QsrError::Source(PackageZoneError::Source(Box::new(error))),
            })?;
        Self::open(&deployment, report_digest, config, cx)
    }
}
