#![forbid(unsafe_code)]
//! Retained-source entrypoint and complete bounded JSON projection.

use super::*;
use crate::ingest::historical_health::exposure::HealthExposureState;
use crate::ingest::package_zones::{PackageZoneReport, checkpoint, storage};
use crate::{ReferenceDeployment, ReplayCx};

impl PackageOccupancyReport {
    /// Reopen and exactly reconstruct a retained zone report, project all sampled counts,
    /// then revalidate current source custody, privacy, deletion, principal and ledger head.
    /// No input JSON, inferred tracks, loose model file or source path can substitute for the
    /// retained native owner. The source report's finite screening allowances remain shared
    /// across initial reconstruction and final revalidation.
    pub fn open(
        deployment: &ReferenceDeployment,
        report_digest: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "package_occupancy:open")?;
        let mut source = PackageZoneReport::open(deployment, report_digest, cx)?;
        let health = source.health_exposures().map_or_else(
            || vec![OccupancyHealth::Unassessed; source.frames().len()],
            |exposures| {
                exposures
                    .iter()
                    .map(|e| match e.state() {
                        HealthExposureState::NoMatchingDiagnostic => {
                            OccupancyHealth::NoMatchingDiagnostic
                        }
                        HealthExposureState::ScreenedWithoutFindings => {
                            OccupancyHealth::ScreenedWithoutFindings
                        }
                        HealthExposureState::ScreeningIncomplete => {
                            OccupancyHealth::ScreeningIncomplete
                        }
                        HealthExposureState::Findings => OccupancyHealth::Findings,
                    })
                    .collect()
            },
        );
        let zones_masked = source
            .config()
            .zones
            .iter()
            .map(|zone| {
                source.privacy.policy().is_some_and(|policy| {
                    policy
                        .zone_masking([zone.x, zone.y, zone.width, zone.height])
                        .any()
                })
            })
            .collect::<Vec<_>>();
        let tracks = source
            .analysis()
            .tracks()
            .iter()
            .map(|track| track.identity)
            .collect::<Vec<_>>();
        let samples = project(
            source.frames().len(),
            &zones_masked,
            &tracks,
            source.cells(),
            &health,
            || checkpoint(cx, "package_occupancy:sample"),
        )?;
        let digest = identity(source.digest(), source.provenance_root(), &samples)?;
        let record = source.analysis().retained().record();
        let tracking = source.analysis().config();
        let metadata = json::Source {
            site: &source.site,
            sensor: &record
                .frames
                .first()
                .ok_or(PackageZoneError::Mismatch)?
                .sensor_id,
            zone_report: source.digest(),
            zone_root: source.provenance_root(),
            analysis: source.analysis().digest(),
            detection: record.report_digest,
            import_identity: record.import_identity,
            import_root: record.import_root,
            package: record.package_digest,
            model_id: &record.model_id,
            generation: &record.generation,
            model: record.model_digest,
            contract: record.contract_digest,
            label: source.analysis().label(),
            class_index: source.analysis().class_index(),
            capture_time_label: &source.capture_time_label,
            clock: source.clock,
            privacy: source.privacy.digest(),
            screened: source.requires_health_screening(),
            confirmation_hits: tracking.confirmation_hits,
            maximum_missed_frames: tracking.maximum_missed_frames,
            minimum_iou_ppm: tracking.minimum_iou_ppm,
            zones: &source.config().zones,
            frames: source.frames(),
        };
        let json = json::render(&metadata, digest, &samples)?;
        checkpoint(cx, STAGE_OCCUPANCY_REVALIDATE)?;
        source.revalidate(deployment, cx)?;
        if storage::existing(deployment, &source)?.is_none() {
            return Err(PackageZoneError::Unavailable);
        }
        checkpoint(cx, "package_occupancy:complete")?;
        Ok(Self {
            digest,
            source_report: report_digest,
            samples,
            json,
        })
    }
}
