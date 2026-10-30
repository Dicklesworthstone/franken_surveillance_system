#![forbid(unsafe_code)]
//! One bounded retained diagnostic catalog per complete derivation, never per track or zone.

use super::*;
use crate::ingest::historical_health::exposure::{
    HealthExposure, HealthExposureCatalog, HealthExposureLimits, HealthExposureSource,
    HealthExposureState, HealthExposureUsage,
};
use fss_core::{CanonicalEncode, CanonicalEncoder};
use fss_object::SpoolReadBudgetUsage;
use std::collections::BTreeSet;

// Separate from catalog admission: native retention replays source custody and rereads the
// complete publication closure. The spool reserves envelopes before opening indexed objects,
// including failed reads, so diagnostic verify_object calls cannot escape a per-report bound.
pub(super) const MAX_RETENTION_READ_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_RETENTION_READ_ATTEMPTS: u64 = 65_536;

pub(super) fn support_allowed(exposure: &HealthExposure) -> bool {
    exposure.state() == HealthExposureState::ScreenedWithoutFindings
}

#[derive(Debug)]
pub(super) struct Screening {
    pub exposures: Vec<HealthExposure>,
    pub usage: HealthExposureUsage,
    pub loads: usize,
    pub trace_bytes_verified: usize,
    pub trace_reads: usize,
    pub retention_read_bytes_reserved: u64,
    pub retention_read_attempts: u64,
    limits: HealthExposureLimits,
    revalidation_started: bool,
}

impl Screening {
    pub(super) fn read(
        deployment: &ReferenceDeployment,
        analysis: &PackageAnalysisReport,
        privacy: &MaskBinding,
        limits: HealthExposureLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        let mut catalog = HealthExposureCatalog::read(deployment, limits, cx).map_err(source)?;
        let record = analysis.retained().record();
        let mut exposures = Vec::new();
        exposures
            .try_reserve_exact(record.frames.len())
            .map_err(|_| PackageZoneError::Limit)?;
        let mut positions = BTreeSet::new();
        for frame in &record.frames {
            checkpoint(cx, "package_zones:health")?;
            if !positions.insert(frame.segment) {
                return Err(PackageZoneError::Mismatch);
            }
            exposures.push(
                catalog
                    .assess(
                        &HealthExposureSource {
                            import_identity: record.import_identity,
                            import_root: record.import_root,
                            sensor_id: SensorId::parse(&frame.sensor_id).map_err(source)?,
                            segment: frame.segment,
                            privacy_policy_digest: privacy.policy_digest(),
                            privacy_generation: privacy.generation(),
                        },
                        cx,
                    )
                    .map_err(source)?,
            );
        }
        let traces = exposures
            .iter()
            .flat_map(|exposure| exposure.pins().iter().map(|pin| pin.trace_digest))
            .collect::<BTreeSet<_>>();
        let mut trace_bytes_verified = 0_usize;
        let mut trace_reads = 0_usize;
        for digest in traces {
            checkpoint(cx, "package_zones:health_trace")?;
            if catalog
                .usage()
                .metadata_reads
                .checked_add(trace_reads)
                .is_none_or(|count| count >= limits.maximum_metadata_reads)
            {
                return Err(PackageZoneError::Limit);
            }
            let remaining = limits
                .maximum_metadata_bytes
                .checked_sub(catalog.usage().metadata_bytes_read)
                .and_then(|value| value.checked_sub(trace_bytes_verified))
                .filter(|value| *value > 0)
                .ok_or(PackageZoneError::Limit)?;
            trace_reads = trace_reads.checked_add(1).ok_or(PackageZoneError::Limit)?;
            let bytes = deployment
                .publisher()
                .spool()
                .read_bounded(
                    digest,
                    remaining.min(crate::ingest::long_dwell::MAX_LONG_DWELL_TRACE_BYTES),
                )
                .map_err(source)?;
            if ContentDigest::sha256(&bytes) != digest {
                return Err(PackageZoneError::Mismatch);
            }
            trace_bytes_verified = trace_bytes_verified
                .checked_add(bytes.len())
                .ok_or(PackageZoneError::Limit)?;
        }
        storage::check_scope(deployment, cx)?;
        if catalog.anchor() != deployment.current_anchor() {
            return Err(PackageZoneError::AuthorityChanged);
        }
        Ok(Self {
            exposures,
            usage: catalog.usage(),
            loads: 1,
            trace_bytes_verified,
            trace_reads,
            retention_read_bytes_reserved: 0,
            retention_read_attempts: 0,
            limits,
            revalidation_started: false,
        })
    }

    pub(super) fn delivery_blocked(&self) -> bool {
        self.revalidation_started
    }

    pub(super) fn admit_revalidation(&mut self) -> Result<HealthExposureLimits> {
        if self.revalidation_started {
            return Err(PackageZoneError::Limit);
        }
        fn remaining(maximum: usize, used: usize) -> Result<usize> {
            maximum
                .checked_sub(used)
                .filter(|value| *value > 0)
                .ok_or(PackageZoneError::Limit)
        }
        let limits = HealthExposureLimits {
            maximum_records: remaining(self.limits.maximum_records, self.usage.records_seen)?,
            maximum_metadata_bytes: remaining(
                self.limits.maximum_metadata_bytes,
                self.usage
                    .metadata_bytes_read
                    .checked_add(self.trace_bytes_verified)
                    .ok_or(PackageZoneError::Limit)?,
            )?,
            maximum_metadata_reads: remaining(
                self.limits.maximum_metadata_reads,
                self.usage
                    .metadata_reads
                    .checked_add(self.trace_reads)
                    .ok_or(PackageZoneError::Limit)?,
            )?,
            maximum_history_work: remaining(
                self.limits.maximum_history_work,
                self.usage.history_work_admitted,
            )?,
            maximum_assessment_work: remaining(
                self.limits.maximum_assessment_work,
                self.usage.assessment_work,
            )?,
            maximum_findings: remaining(
                self.limits.maximum_findings,
                self.usage.findings_returned,
            )?,
        };
        limits.validate().map_err(source)?;
        // A failed reconstruction must not refill the consumed allowance on retry.
        self.revalidation_started = true;
        Ok(limits)
    }

    pub(super) fn complete_revalidation(&mut self, current: &Self) -> Result<()> {
        if !self.revalidation_started || self.exposures != current.exposures {
            return Err(PackageZoneError::Mismatch);
        }
        fn add(left: usize, right: usize) -> Result<usize> {
            left.checked_add(right).ok_or(PackageZoneError::Limit)
        }
        let old = self.usage;
        let new = current.usage;
        self.usage = HealthExposureUsage {
            records_seen: add(old.records_seen, new.records_seen)?,
            records_loaded: add(old.records_loaded, new.records_loaded)?,
            deleted_records: add(old.deleted_records, new.deleted_records)?,
            metadata_bytes_read: add(old.metadata_bytes_read, new.metadata_bytes_read)?,
            metadata_reads: add(old.metadata_reads, new.metadata_reads)?,
            history_work_admitted: add(old.history_work_admitted, new.history_work_admitted)?,
            assessment_work: add(old.assessment_work, new.assessment_work)?,
            findings_returned: add(old.findings_returned, new.findings_returned)?,
        };
        self.loads = add(self.loads, current.loads)?;
        self.trace_bytes_verified = add(self.trace_bytes_verified, current.trace_bytes_verified)?;
        self.trace_reads = add(self.trace_reads, current.trace_reads)?;
        self.revalidation_started = false;
        Ok(())
    }

    pub(super) fn begin_retention(
        &self,
        deployment: &mut ReferenceDeployment,
    ) -> Result<SpoolReadBudgetUsage> {
        let before = deployment.publisher().spool().read_budget_usage();
        let bytes = MAX_RETENTION_READ_BYTES
            .checked_sub(self.retention_read_bytes_reserved)
            .ok_or(PackageZoneError::Limit)?;
        let reads = MAX_RETENTION_READ_ATTEMPTS
            .checked_sub(self.retention_read_attempts)
            .ok_or(PackageZoneError::Limit)?;
        let absolute_bytes = before
            .used_bytes
            .checked_add(bytes)
            .ok_or(PackageZoneError::Limit)?;
        let absolute_reads = before
            .used_read_attempts
            .checked_add(reads)
            .ok_or(PackageZoneError::Limit)?;
        // A preexisting tighter spool cap wins. The native owner's cap persists until drop;
        // neither this report nor a later report can reset or widen it.
        deployment
            .publisher_mut()
            .tighten_read_budget(absolute_bytes, absolute_reads)
            .map_err(source)?;
        Ok(before)
    }

    pub(super) fn finish_retention(
        &mut self,
        before: SpoolReadBudgetUsage,
        after: SpoolReadBudgetUsage,
    ) -> Result<()> {
        let bytes = after
            .used_bytes
            .checked_sub(before.used_bytes)
            .ok_or(PackageZoneError::Mismatch)?;
        let reads = after
            .used_read_attempts
            .checked_sub(before.used_read_attempts)
            .ok_or(PackageZoneError::Mismatch)?;
        self.retention_read_bytes_reserved = self
            .retention_read_bytes_reserved
            .checked_add(bytes)
            .filter(|value| *value <= MAX_RETENTION_READ_BYTES)
            .ok_or(PackageZoneError::Limit)?;
        self.retention_read_attempts = self
            .retention_read_attempts
            .checked_add(reads)
            .filter(|value| *value <= MAX_RETENTION_READ_ATTEMPTS)
            .ok_or(PackageZoneError::Limit)?;
        Ok(())
    }

    pub(super) fn children(&self) -> BTreeSet<ContentDigest> {
        self.exposures
            .iter()
            .flat_map(|exposure| {
                exposure
                    .pins()
                    .iter()
                    .flat_map(|pin| [pin.record_digest, pin.provenance_root, pin.trace_digest])
            })
            .collect()
    }

    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.u64(self.exposures.len() as u64);
        for exposure in &self.exposures {
            let source = exposure.source();
            e.digest(source.import_identity);
            e.digest(source.import_root);
            e.text(source.sensor_id.as_str());
            e.u64(source.segment);
            e.bool(source.privacy_policy_digest.is_some());
            if let Some(digest) = source.privacy_policy_digest {
                e.digest(digest);
            }
            e.bool(source.privacy_generation.is_some());
            if let Some(generation) = source.privacy_generation {
                e.u64(generation);
            }
            e.text(exposure.status());
            e.bool(support_allowed(exposure));
            e.bool(exposure.screening_incomplete());
            e.u64(exposure.pins().len() as u64);
            for pin in exposure.pins() {
                e.digest(pin.record_digest);
                e.digest(pin.provenance_root);
                e.digest(pin.trace_digest);
                pin.ledger_anchor.encode_canonical(e);
            }
            e.u64(exposure.findings().len() as u64);
            for finding in exposure.findings() {
                e.digest(finding.diagnostic);
                e.digest(finding.provenance_root);
                e.text(finding.finding.as_str());
                e.u64(finding.finding_first_segment);
                e.u64(finding.finding_last_segment);
                e.u64(finding.withheld_first_segment);
                e.u64(finding.withheld_last_segment);
            }
        }
    }
}
