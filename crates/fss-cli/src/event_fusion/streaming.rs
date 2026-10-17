#![forbid(unsafe_code)]
//! Calibrated class advice for the complete native whole-recording watch, without rescanning.
//!
//! An analysis root is not coverage. Version-two profiles require an empty coverage set and
//! bind the complete analysis and trained-detector recipe. The native source owner performs
//! custody/privacy/health checks; the existing fusion engine owns all probability arithmetic.

use super::*;
use fss_reference::ingest::long_watch::{LongWatchReport, MAX_LONG_WATCH_CANDIDATES};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;

pub(super) const SCOPE: &str = "whole-recording-watch:source-context-only:v1";
/// Whole-recording candidate ceiling; the shared evidence/output allowances still apply.
pub const MAX_LONG_CANDIDATES: usize = MAX_LONG_WATCH_CANDIDATES;

impl EventFusionProfile {
    /// Explicitly bind a complete whole-recording watch. `plan_digest` names its analysis
    /// digest, `cascade_digest` names its retained detector-recipe digest, and coverage_digests
    /// MUST be empty. The analysis root cannot masquerade as negative-observation coverage.
    /// All calibration tables, policy, prior and owner look-count checks are shared with the
    /// original profile constructor. Default short-window profile identities stay unchanged.
    pub fn for_long_watch(spec: ClassFusionSpec, analysis_root: ContentDigest) -> Result<Self> {
        for identity in [spec.plan_digest, spec.cascade_digest, analysis_root] {
            if identity.algorithm() != fss_core::DigestAlgorithm::Sha256
                || identity.bytes() == [0; 32]
            {
                return Err(EventFusionError::Profile);
            }
        }
        Self::new_scoped(spec, Some(WholeRecordingScope::Watch(analysis_root)))
    }

    /// Exact source-closed analysis root for this scope, never a coverage or custody receipt.
    pub fn long_watch_analysis_root(&self) -> Option<ContentDigest> {
        match self.whole_recording {
            Some(WholeRecordingScope::Watch(root)) => Some(root),
            _ => None,
        }
    }
}

impl EventFusionReport {
    /// Consume only class observations retained by one complete native whole-recording scan.
    /// No inference, pixel decoding, model activation, event publication or alert is performed.
    /// The entire candidate inventory is admitted or refused; omissions and uncalibrated
    /// observations spend the same shared evidence allowance as calibrated scores.
    pub fn long_watch(
        native: &LongWatchReport,
        package: &RgbDetectorPackage,
        profile: &EventFusionProfile,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let recipe = native.detector_recipe().ok_or(EventFusionError::Scope)?;
        let analysis = native.analysis_digest();
        let analysis_root = native.analysis_root();
        let recipe_digest = recipe.digest();
        if profile.long_watch_analysis_root() != Some(analysis_root)
            || !profile.spec.coverage_digests.is_empty()
            || profile.spec.plan_digest != analysis
            || profile.spec.cascade_digest != recipe_digest
        {
            return Err(EventFusionError::Scope);
        }
        recipe.verify_package(package).map_err(|_| EventFusionError::Scope)?;
        revalidate(native, deployment, cx)?;
        let basis = deployment.current_anchor().clone();
        let sensor = native.sensor_id().as_str();
        if profile.spec.calibrations.iter().any(|c| c.sensor != sensor) {
            return Err(EventFusionError::Scope);
        }
        let label = package.spec().labels.get(profile.spec.class_index)
            .ok_or(EventFusionError::Scope)?.clone();
        if label.len() > 192 || label.chars().any(char::is_control) {
            return Err(EventFusionError::Scope);
        }
        admit_inventory(native.candidates().len(), native.candidates().iter()
            .map(|candidate| candidate.class_evidence().len()))?;

        let mut e = CanonicalEncoder::new();
        e.text(RECIPE);
        e.digest(profile.digest());
        e.digest(analysis);
        basis.encode_canonical(&mut e);
        e.text(SCOPE);
        e.digest(analysis_root);
        e.digest(recipe_digest);
        let context = digest(e)?;
        let shared = [
            format!("model:{}", ContentDigest::sha256(
                package.manifest().model_id().as_str().as_bytes())),
            format!("package:{}", package.archive_digest()),
            format!("cascade:{recipe_digest}"),
        ];
        let mut results = Vec::new();
        for candidate in native.candidates() {
            checkpoint(cx)?;
            results.push(fuse_input(
                Input {
                    candidate: candidate.identity(),
                    proposal: candidate.proposal_digest(),
                    provenance: candidate.provenance_root(),
                    sources: vec![Source {
                        sensor,
                        dependency: None,
                        evidence: candidate.class_evidence(),
                    }],
                },
                &label, profile, context, &shared,
            )?);
        }
        results.sort_by_key(|result| result.candidate);
        if results.windows(2).any(|pair| pair[0].candidate == pair[1].candidate) {
            return Err(EventFusionError::Evidence);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.event_class_fusion.report.v1");
        e.digest(context);
        e.u64(results.len() as u64);
        for result in &results {
            e.digest(result.binding_digest);
        }
        revalidate(native, deployment, cx)?;
        if deployment.current_anchor() != &basis {
            return Err(EventFusionError::StaleBasis);
        }
        let report = Self {
            profile: profile.clone(), basis, context,
            package: package.archive_digest(), label, results, digest: digest(e)?,
        };
        // Complete encoding must fit before a caller can disclose any report prefix.
        report.to_json()?;
        checkpoint(cx)?;
        Ok(report)
    }
}

fn revalidate(native: &LongWatchReport, deployment: &ReferenceDeployment, cx: &ReplayCx)
    -> Result<()>
{
    let checked = native.revalidate_derived_source(deployment, cx);
    // Preserve cancellation instead of converting a wrapped source refusal to stale evidence.
    checkpoint(cx)?;
    checked.map_err(|error| match error {
        fss_reference::ingest::recorded_watch::WatchError::Conflict => EventFusionError::StaleBasis,
        _ => EventFusionError::Evidence,
    })
}

fn admit_inventory(candidates: usize, counts: impl Iterator<Item = usize>) -> Result<()> {
    if candidates > MAX_LONG_CANDIDATES {
        return Err(EventFusionError::Limit);
    }
    let mut seen = 0_usize;
    let mut total = 0_usize;
    for count in counts.take(MAX_LONG_CANDIDATES + 1) {
        seen = seen.checked_add(1).ok_or(EventFusionError::Limit)?;
        total = total.checked_add(count.max(1)).ok_or(EventFusionError::Limit)?;
        if seen > candidates || total > MAX_TOTAL_EVIDENCE {
            return Err(EventFusionError::Limit);
        }
    }
    if seen != candidates {
        return Err(EventFusionError::Evidence);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
