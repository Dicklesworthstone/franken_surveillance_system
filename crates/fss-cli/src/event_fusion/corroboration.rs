#![forbid(unsafe_code)]
//! Calibrated class advice over both complete, source-closed native camera analyses.

use super::*;
use fss_reference::ingest::recorded_corroboration::CorroborationError;
use fss_reference::ingest::recorded_corroboration::streaming::LongCorroborationReport;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;

pub(super) const SCOPE: &str = "whole-recording-corroboration:two-source-contexts-only:v1";
/// Complete native paired-candidate ceiling. One evidence/output budget covers both cameras.
pub const MAX_LONG_CORROBORATION_CANDIDATES: usize =
    fss_reference::ingest::recorded_corroboration::streaming::MAX_LONG_CORROBORATION_CANDIDATES;

impl EventFusionProfile {
    /// Bind both full camera analyses, in native camera order, without claiming coverage.
    ///
    /// `plan_digest` is the complete paired report's analysis digest; `cascade_digest` is
    /// its retained detector-recipe digest. Roots must be distinct, nonzero SHA-256 values.
    /// An empty coverage set is mandatory. These are owner applicability assertions, not
    /// deployment calibration, independent-verifier qualification or publication approval.
    pub fn for_long_corroboration(
        spec: ClassFusionSpec,
        analysis_roots: [ContentDigest; 2],
    ) -> Result<Self> {
        if analysis_roots[0] == analysis_roots[1]
            || [spec.plan_digest, spec.cascade_digest]
                .iter()
                .chain(analysis_roots.iter())
                .any(|identity| {
                    identity.algorithm() != fss_core::DigestAlgorithm::Sha256
                        || identity.bytes() == [0; 32]
                })
        {
            return Err(EventFusionError::Profile);
        }
        Self::new_scoped(
            spec,
            Some(WholeRecordingScope::Corroboration(analysis_roots)),
        )
    }

    /// Complete per-camera source analysis roots, never negative-evidence witnesses.
    pub fn long_corroboration_analysis_roots(&self) -> Option<[ContentDigest; 2]> {
        match self.whole_recording {
            Some(WholeRecordingScope::Corroboration(roots)) => Some(roots),
            _ => None,
        }
    }
}

impl EventFusionReport {
    /// Fuse only class records attached to actual native whole-recording associations.
    ///
    /// No source is rescanned through perception, no model is run, and no event is changed.
    /// The native owner revalidates both sources, owner/anchor, current privacy, requested
    /// health screens and geometric dependencies before and after advice. The existing
    /// fusion engine alone owns calibration intervals, dependency hulls and counterfactuals.
    pub fn long_corroborate(
        native: &LongCorroborationReport,
        package: &RgbDetectorPackage,
        profile: &EventFusionProfile,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let recipe = native.detector_recipe().ok_or(EventFusionError::Scope)?;
        let cameras: Vec<_> = native.source_cameras().collect();
        let [(first, first_root), (second, second_root)] = cameras.as_slice() else {
            return Err(EventFusionError::Evidence);
        };
        let roots = [*first_root, *second_root];
        if profile.long_corroboration_analysis_roots() != Some(roots)
            || !profile.spec.coverage_digests.is_empty()
            || profile.spec.plan_digest != native.analysis_digest()
            || profile.spec.cascade_digest != recipe.digest()
            || first.sensor_id == second.sensor_id
            || profile.spec.calibrations.iter().any(|binding| {
                binding.sensor != first.sensor_id && binding.sensor != second.sensor_id
            })
        {
            return Err(EventFusionError::Scope);
        }
        recipe
            .verify_package(package)
            .map_err(|_| EventFusionError::Scope)?;
        revalidate(native, deployment, cx)?;
        let basis = deployment.current_anchor().clone();
        let label = package
            .spec()
            .labels
            .get(profile.spec.class_index)
            .ok_or(EventFusionError::Scope)?
            .clone();
        if label.len() > 192 || label.chars().any(char::is_control) {
            return Err(EventFusionError::Scope);
        }
        if native.candidates().len() > MAX_LONG_CORROBORATION_CANDIDATES {
            return Err(EventFusionError::Limit);
        }
        // Preflight the entire paired inventory before computing or disclosing any prefix.
        let mut inputs = Vec::with_capacity(native.candidates().len());
        let mut evidence_count = 0_usize;
        for candidate in native.candidates() {
            let [a, b] = candidate.entries.as_slice() else {
                return Err(EventFusionError::Evidence);
            };
            let mut sources = Vec::with_capacity(2);
            let mut seen_camera = None;
            for &index in [a, b] {
                let entry = native
                    .entries()
                    .get(index)
                    .ok_or(EventFusionError::Evidence)?;
                if seen_camera == Some(entry.camera) {
                    return Err(EventFusionError::Evidence);
                }
                seen_camera = Some(entry.camera);
                let (camera, _) = cameras
                    .get(entry.camera)
                    .ok_or(EventFusionError::Evidence)?;
                evidence_count = evidence_count
                    .checked_add(entry.class_evidence.len().max(1))
                    .filter(|count| *count <= MAX_TOTAL_EVIDENCE)
                    .ok_or(EventFusionError::Limit)?;
                sources.push(Source {
                    sensor: &camera.sensor_id,
                    dependency: Some(&camera.failure_domain),
                    evidence: &entry.class_evidence,
                });
            }
            inputs.push(Input {
                candidate: candidate.identity(),
                proposal: candidate.proposal_digest(),
                provenance: candidate.provenance_root(),
                sources,
            });
        }
        let mut e = CanonicalEncoder::new();
        e.text(RECIPE);
        e.digest(profile.digest());
        e.digest(native.analysis_digest());
        basis.encode_canonical(&mut e);
        e.text(SCOPE);
        for root in roots {
            e.digest(root);
        }
        e.digest(recipe.digest());
        let context = digest(e)?;
        let shared = [
            format!(
                "model:{}",
                ContentDigest::sha256(package.manifest().model_id().as_str().as_bytes())
            ),
            format!("package:{}", package.archive_digest()),
            format!("cascade:{}", recipe.digest()),
        ];
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            checkpoint(cx)?;
            results.push(fuse_input(input, &label, profile, context, &shared)?);
        }
        results.sort_by_key(|result| result.candidate);
        if results
            .windows(2)
            .any(|pair| pair[0].candidate == pair[1].candidate)
        {
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
            profile: profile.clone(),
            basis,
            context,
            package: package.archive_digest(),
            label,
            results,
            digest: digest(e)?,
        };
        report.to_json()?;
        checkpoint(cx)?;
        Ok(report)
    }
}

fn revalidate(
    native: &LongCorroborationReport,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    let checked = native.revalidate_derived_sources(deployment, cx);
    checkpoint(cx)?;
    checked.map_err(|error| match error {
        CorroborationError::Conflict => EventFusionError::StaleBasis,
        _ => EventFusionError::Evidence,
    })
}

#[cfg(test)]
mod tests;
