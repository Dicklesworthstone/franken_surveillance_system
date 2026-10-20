#![forbid(unsafe_code)]
//! Calibrated class advice over complete native sampled-dwell episodes.

use super::*;
use fss_reference::ingest::long_dwell::LongDwellReport;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;

pub(super) const SCOPE: &str = "whole-recording-dwell:sampled-episode-source-context-only:v1";
/// Complete native episode ceiling; one evidence allowance covers every episode.
pub const MAX_LONG_DWELL_CANDIDATES: usize = fss_reference::ingest::zone_dwell::MAX_DWELL_EPISODES;

impl EventFusionProfile {
    /// Bind a complete sampled-dwell analysis, including its rule and detector recipe.
    /// `plan_digest` is the complete analysis digest, `cascade_digest` is its retained
    /// detector-recipe digest, and coverage must be empty. The source root does not prove
    /// continuous presence or absence. Watch/corroboration profiles cannot enter this scope.
    pub fn for_long_dwell(spec: ClassFusionSpec, analysis_root: ContentDigest) -> Result<Self> {
        for identity in [spec.plan_digest, spec.cascade_digest, analysis_root] {
            if identity.algorithm() != fss_core::DigestAlgorithm::Sha256
                || identity.bytes() == [0; 32]
            {
                return Err(EventFusionError::Profile);
            }
        }
        Self::new_scoped(spec, Some(WholeRecordingScope::Dwell(analysis_root)))
    }

    /// Complete native sampled-dwell analysis root, never a negative-evidence witness.
    pub fn long_dwell_analysis_root(&self) -> Option<ContentDigest> {
        match self.whole_recording {
            Some(WholeRecordingScope::Dwell(root)) => Some(root),
            _ => None,
        }
    }
}

impl EventFusionReport {
    /// Consume the actual class records attached to each complete native dwell episode.
    /// No new inference or temporal association runs here. Scores cannot lengthen an episode,
    /// fill a gap, prove continuous occupancy or make one sensor independent of itself.
    /// Missing/budget-refused records remain explicit; advice never changes an event approval.
    pub fn long_dwell(
        native: &LongDwellReport,
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
        if profile.long_dwell_analysis_root() != Some(analysis_root)
            || !profile.spec.coverage_digests.is_empty()
            || profile.spec.plan_digest != analysis
            || profile.spec.cascade_digest != recipe_digest
        {
            return Err(EventFusionError::Scope);
        }
        recipe
            .verify_package(package)
            .map_err(|_| EventFusionError::Scope)?;
        revalidate(native, deployment, cx)?;
        let basis = deployment.current_anchor().clone();
        let sensor = native.sensor_id().as_str();
        if profile
            .spec
            .calibrations
            .iter()
            .any(|binding| binding.sensor != sensor)
        {
            return Err(EventFusionError::Scope);
        }
        let label = package
            .spec()
            .labels
            .get(profile.spec.class_index)
            .ok_or(EventFusionError::Scope)?
            .clone();
        if label.len() > 192 || label.chars().any(char::is_control) {
            return Err(EventFusionError::Scope);
        }
        admit_inventory(
            native.candidates().len(),
            native
                .candidates()
                .iter()
                .map(|candidate| candidate.class_evidence().len()),
        )?;

        let mut encoder = CanonicalEncoder::new();
        encoder.text(RECIPE);
        encoder.digest(profile.digest());
        encoder.digest(analysis);
        basis.encode_canonical(&mut encoder);
        encoder.text(SCOPE);
        encoder.digest(analysis_root);
        encoder.digest(recipe_digest);
        let context = digest(encoder)?;
        let shared = [
            format!(
                "model:{}",
                ContentDigest::sha256(package.manifest().model_id().as_str().as_bytes())
            ),
            format!("package:{}", package.archive_digest()),
            format!("cascade:{recipe_digest}"),
        ];
        let mut results = Vec::with_capacity(native.candidates().len());
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
                &label,
                profile,
                context,
                &shared,
            )?);
        }
        results.sort_by_key(|result| result.candidate);
        if results
            .windows(2)
            .any(|pair| pair[0].candidate == pair[1].candidate)
        {
            return Err(EventFusionError::Evidence);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.event_class_fusion.report.v1");
        encoder.digest(context);
        encoder.u64(results.len() as u64);
        for result in &results {
            encoder.digest(result.binding_digest);
        }
        revalidate(native, deployment, cx)?;
        if deployment.current_anchor() != &basis {
            return Err(EventFusionError::StaleBasis);
        }
        let report = Self {
            profile: profile.clone(),
            basis,
            context,
            package: package.archive_digest(),
            label,
            results,
            digest: digest(encoder)?,
        };
        report.to_json()?;
        checkpoint(cx)?;
        Ok(report)
    }
}

fn revalidate(
    native: &LongDwellReport,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    let checked = native.revalidate_derived_source(deployment, cx);
    checkpoint(cx)?;
    checked.map_err(|error| match error {
        fss_reference::ingest::recorded_watch::WatchError::Conflict => EventFusionError::StaleBasis,
        _ => EventFusionError::Evidence,
    })
}

fn admit_inventory(candidates: usize, counts: impl Iterator<Item = usize>) -> Result<()> {
    if candidates > MAX_LONG_DWELL_CANDIDATES {
        return Err(EventFusionError::Limit);
    }
    let mut seen = 0_usize;
    let mut total = 0_usize;
    for count in counts.take(MAX_LONG_DWELL_CANDIDATES + 1) {
        seen += 1;
        total = total
            .checked_add(count.max(1))
            .ok_or(EventFusionError::Limit)?;
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
