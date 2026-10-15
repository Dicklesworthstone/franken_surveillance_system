#![forbid(unsafe_code)]
//! Bind calibrated advice to the final coverage, never to a replaced nominal screen.
//!
//! Projection and currency remain owned by `fss-reference`. This adapter only checks
//! exact lineage, chooses the complete immutable set, and uses the existing fusion engine.

use fss_reference::calibrated_coverage::{GuardedCoverageRetentionError, GuardedCoverageSet};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::recorded_coverage::{CoverageRecord, PoseProvenance};

use super::*;

impl EventFusionReport {
    /// Fuse source-linked class evidence from each actual sampled-dwell episode.
    ///
    /// `plan_digest` must pin `DwellReport::analysis_digest`, not the underlying entry
    /// plan: the dwell rule, sample exclusions and complete selection trace are part of
    /// this hypothesis. Coverage pins name the native scan context only and never certify
    /// dwell absence. Entry-only scores and scores from another episode are not borrowed.
    /// The existing engine owns calibration, dependency hulls and optional-stopping rules.
    /// Native proposal/provenance identities and publication authority remain unchanged.
    pub fn dwell(
        native: &fss_reference::ingest::recorded_dwell::DwellReport,
        cascade: &DetectorCascade<'_>,
        profile: &EventFusionProfile,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if native.cascade_digest() != Some(cascade.digest()) {
            return Err(EventFusionError::Scope);
        }
        let checked = native.revalidate_derived_source(deployment, cx);
        checkpoint(cx)?;
        checked.map_err(|_| EventFusionError::Evidence)?;
        let coverage = native.coverage();
        let inputs = native
            .candidates()
            .iter()
            .map(|candidate| Input {
                candidate: candidate.identity(),
                proposal: candidate.proposal_digest(),
                provenance: candidate.provenance_root(),
                sources: vec![Source {
                    sensor: &coverage.sensor_id,
                    dependency: None,
                    evidence: candidate.class_evidence(),
                }],
            })
            .collect();
        let result = Self::analyze(
            native.analysis_digest(),
            &[coverage],
            cascade,
            profile,
            inputs,
            deployment,
            cx,
        )?;
        let checked = native.revalidate_derived_source(deployment, cx);
        checkpoint(cx)?;
        checked.map_err(|_| EventFusionError::Evidence)?;
        Ok(result)
    }

    /// Fuse associated native entries using the complete full-camera screened coverage set.
    ///
    /// The profile must pin the final guarded record digests, not the nominal ones. The
    /// set must have been projected from exactly this run's records in camera order.
    /// Custody, privacy and calibration adoption are revalidated on both sides of fusion,
    /// even for an empty candidate set. No coverage is retained and no event is changed.
    pub fn corroborate_guarded(
        native: &CorroborationReport,
        cascade: &DetectorCascade<'_>,
        profile: &EventFusionProfile,
        guarded: &GuardedCoverageSet,
        read_limits: RetainedReadLimits,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::corroborate_with_coverage(
            native,
            cascade,
            profile,
            Some((guarded, read_limits)),
            deployment,
            cx,
        )
    }

    pub(super) fn corroborate_with_coverage(
        native: &CorroborationReport,
        cascade: &DetectorCascade<'_>,
        profile: &EventFusionProfile,
        guard: Option<(&GuardedCoverageSet, RetainedReadLimits)>,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if native.cascade_digest() != Some(cascade.digest()) {
            return Err(EventFusionError::Scope);
        }
        let coverage = effective_coverage(native.coverage(), guard.map(|(set, _)| set))?;
        revalidate(guard, deployment, cx)?;
        native
            .revalidate_derived_sources(deployment, cx)
            .map_err(|_| EventFusionError::Evidence)?;
        let mut inputs = Vec::new();
        for candidate in native.candidates() {
            let mut sources = Vec::new();
            for &index in &candidate.entries {
                let entry = native
                    .entries()
                    .get(index)
                    .ok_or(EventFusionError::Evidence)?;
                let camera = native
                    .cameras()
                    .get(entry.camera)
                    .ok_or(EventFusionError::Evidence)?;
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
        let result = Self::analyze(
            native.plan_digest(),
            &coverage,
            cascade,
            profile,
            inputs,
            deployment,
            cx,
        )?;
        native
            .revalidate_derived_sources(deployment, cx)
            .map_err(|_| EventFusionError::Evidence)?;
        revalidate(guard, deployment, cx)?;
        checkpoint(cx)?;
        Ok(result)
    }
}

fn effective_coverage<'a>(
    nominal: &'a [CoverageRecord],
    guarded: Option<&'a GuardedCoverageSet>,
) -> Result<Vec<&'a CoverageRecord>> {
    if nominal.is_empty() || nominal.len() > 2 {
        return Err(EventFusionError::Scope);
    }
    match guarded {
        Some(set) => {
            // A matching camera, import or analysis digest alone is not sufficient: time
            // windows, exclusions, privacy and the unscreened companion must also match.
            check_lineage(
                nominal.iter().map(CoverageRecord::digest),
                set.nominal_digests(),
            )?;
            Ok(set.records().iter().collect())
        }
        None => {
            if nominal.iter().any(|record| {
                matches!(
                    record.pose_provenance,
                    Some(PoseProvenance::SiteCalibration { .. })
                )
            }) {
                return Err(EventFusionError::Scope);
            }
            Ok(nominal.iter().collect())
        }
    }
}

fn check_lineage(
    nominal: impl Iterator<Item = ContentDigest>,
    projected_from: &[ContentDigest],
) -> Result<()> {
    if !nominal.eq(projected_from.iter().copied()) {
        return Err(EventFusionError::Scope);
    }
    Ok(())
}

fn revalidate(
    guard: Option<(&GuardedCoverageSet, RetainedReadLimits)>,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    if let Some((set, limits)) = guard {
        let checked = set.revalidate(deployment, limits, cx);
        // Preserve cancellation even when a source read wrapped it in its own typed error.
        checkpoint(cx)?;
        checked.map_err(|error| match error {
            GuardedCoverageRetentionError::Cancelled => EventFusionError::Cancelled,
            _ => EventFusionError::StaleBasis,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_lineage_refuses_reordering_prefixes_duplicates_and_foreign_context() {
        let a = ContentDigest::sha256(b"camera a: complete nominal record");
        let b = ContentDigest::sha256(b"camera b: complete nominal record");
        let foreign = ContentDigest::sha256(b"camera a: different time range");
        assert!(check_lineage([a, b].into_iter(), &[a, b]).is_ok());
        for substituted in [vec![b, a], vec![a], vec![a, a], vec![foreign, b], vec![]] {
            assert_eq!(
                check_lineage([a, b].into_iter(), &substituted),
                Err(EventFusionError::Scope)
            );
        }
        assert_eq!(
            check_lineage([a].into_iter(), &[a, b]),
            Err(EventFusionError::Scope)
        );
    }
}
