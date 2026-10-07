#![forbid(unsafe_code)]
//! Bind recorded health measurements to exact coverage source, analysis and zone generations.

use super::super::recorded_coverage::{
    BACKGROUND_WARMUP_FRAMES, CoverageInput, CoverageRecord, CoverageSource, CoverageZoneInput,
    MAX_COVERAGE_ZONES,
};
use super::RecordedHealthSummary;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError};

const DOMAIN: &str = "fss.recorded_sensor_health_coverage.v1";
const ANALYSIS_DOMAIN: &str = "fss.recorded_sensor_health_coverage_analysis.v1";
const PIPELINE_DOMAIN: &str = "fss.recorded_sensor_health_coverage_pipeline.v1";
const ZONE_DOMAIN: &str = "fss.recorded_sensor_health_coverage_zone.v1";
/// Bounded source/zone envelope plus the complete bounded measurement summary.
pub const MAX_RECORDED_HEALTH_COVERAGE_BYTES: usize = super::MAX_RECORDED_HEALTH_BYTES + 8_192;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ZoneBinding {
    geometry: ContentDigest,
    base_pipeline: ContentDigest,
}

/// Immutable receipt behind a version-7 coverage record.
///
/// Source identifiers and the complete raw summary are retained. The enclosing analysis and
/// every zone pipeline must derive from this receipt, so a different screen cannot silently
/// replace measurements while preserving the old analysis or pipeline generation. A later
/// calibration guard binds these derived identities as its own nominal inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedHealthCoverageReceipt {
    source: CoverageSource,
    first_segment: u64,
    last_segment: u64,
    time_label: ContentDigest,
    base_analysis: ContentDigest,
    confirmation_hits: u32,
    zones: Vec<ZoneBinding>,
    summary: RecordedHealthSummary,
}

fn derived(domain: &str, base: ContentDigest, receipt: ContentDigest) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(domain);
    e.digest(base);
    e.digest(receipt);
    ContentDigest::sha256(&e.finish())
}

fn zone_binding(id: &str, geometry: &str) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(ZONE_DOMAIN);
    e.text(id);
    e.text(geometry);
    ContentDigest::sha256(&e.finish())
}

impl RecordedHealthCoverageReceipt {
    pub(crate) fn for_input(
        input: &CoverageInput<'_>,
        summary: &RecordedHealthSummary,
        tracking_restarts: &[usize],
    ) -> Result<Self, ContractError> {
        summary.validate()?;
        if input.zones.is_empty()
            || input.zones.len() > MAX_COVERAGE_ZONES
            || input.sensor_id.len() > 512
            || tracking_restarts.len() > super::MAX_HEALTH_FRAMES
            || input
                .last_segment
                .checked_sub(input.first_segment)
                .is_none_or(|span| span >= super::MAX_HEALTH_FRAMES)
            || input.capture_time_label.len() > 64
            || input
                .zones
                .iter()
                .any(|zone| zone.zone_id.len() > 64 || zone.geometry.len() > 256)
            || summary.import_identity() != input.import_identity
            || summary.import_root() != input.import_root
            || summary.sensor_digest() != ContentDigest::sha256(input.sensor_id.as_bytes())
            || summary.tracking_restart_segments()
                != tracking_restarts
                    .iter()
                    .map(|segment| *segment as u64)
                    .collect::<std::collections::BTreeSet<_>>()
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let source_gaps = input
            .segment_gaps
            .get(input.first_segment..=input.last_segment)
            .ok_or(ContractError::InvalidIdentifier)?
            .iter()
            .enumerate()
            .filter(|(_, gap)| **gap)
            .map(|(offset, _)| (input.first_segment + offset) as u64)
            .collect::<std::collections::BTreeSet<_>>();
        if summary.source_gap_segments() != &source_gaps {
            return Err(ContractError::InvalidIdentifier);
        }
        let receipt = Self {
            source: input.source,
            first_segment: input.first_segment as u64,
            last_segment: input.last_segment as u64,
            time_label: ContentDigest::sha256(input.capture_time_label.as_bytes()),
            base_analysis: input.analysis_digest,
            confirmation_hits: input.confirmation_hits,
            zones: input
                .zones
                .iter()
                .map(|zone| ZoneBinding {
                    geometry: zone_binding(&zone.zone_id, &zone.geometry),
                    base_pipeline: zone.pipeline_generation,
                })
                .collect(),
            summary: summary.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// The original measurement summary; its digest remains unchanged by coverage binding.
    #[must_use]
    pub fn summary(&self) -> &RecordedHealthSummary {
        &self.summary
    }

    /// Identity of the complete source-bound coverage receipt.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    pub(crate) fn analysis_digest(&self) -> ContentDigest {
        derived(ANALYSIS_DOMAIN, self.base_analysis, self.digest())
    }

    pub(crate) fn pipeline_generation(
        &self,
        zone: &CoverageZoneInput,
    ) -> Result<ContentDigest, ContractError> {
        let binding = zone_binding(&zone.zone_id, &zone.geometry);
        let base = self
            .zones
            .iter()
            .find(|entry| entry.geometry == binding)
            .ok_or(ContractError::InvalidIdentifier)?;
        if base.base_pipeline != zone.pipeline_generation {
            return Err(ContractError::DigestMismatch);
        }
        Ok(derived(PIPELINE_DOMAIN, base.base_pipeline, self.digest()))
    }

    /// Display order may differ from retained source indices; index-based capture hints then
    /// cannot certify a contiguous display interval. Measurement and candidate analysis survive.
    #[must_use]
    pub fn capture_order_uncertain(&self) -> bool {
        self.summary
            .observations()
            .windows(2)
            .any(|pair| pair[0].segment >= pair[1].segment)
    }

    /// Frames whose bounded confirmation context stays inside a warmed, admitted epoch.
    /// This independently checks retained witnesses, including the latency before a bad run.
    fn witness_segments(&self) -> std::collections::BTreeSet<u64> {
        let observations = self.summary.observations();
        let restarts = self.summary.tracking_restart_segments();
        let latency = (self.confirmation_hits.max(1) - 1) as usize;
        let mut epoch_start = 0;
        let mut eligible = std::collections::BTreeSet::new();
        for (position, frame) in observations.iter().enumerate() {
            if restarts.contains(&frame.segment) {
                epoch_start = position;
            }
            let end = position.saturating_add(latency);
            if position - epoch_start < BACKGROUND_WARMUP_FRAMES
                || end >= observations.len()
                || self.summary.affected_segments().contains(&frame.segment)
                || self.summary.withdrawn_track_segments().contains(&frame.segment)
                || observations[position + 1..end + 1].iter().any(|future| {
                    restarts.contains(&future.segment)
                        || self.summary.affected_segments().contains(&future.segment)
                        || self.summary.withdrawn_track_segments().contains(&future.segment)
                })
            {
                continue;
            }
            eligible.insert(frame.segment);
        }
        eligible
    }

    /// Explicit limitation attached to each surviving narrow coverage predicate.
    #[must_use]
    pub fn predicate_clause(&self) -> String {
        format!(
            "; visual screening receipt {} withholds suspect runs and dependent tracks \
             (clear screening is not sensor health evidence)",
            self.digest(),
        )
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.summary.validate()?;
        if self.zones.is_empty()
            || self.zones.len() > MAX_COVERAGE_ZONES
            || self.first_segment > self.last_segment
            || self.last_segment - self.first_segment >= super::MAX_HEALTH_FRAMES as u64
            || self.summary.observations().iter().any(|frame| {
                frame.segment < self.first_segment || frame.segment > self.last_segment
            })
            || self.summary.source_gap_segments().iter().any(|segment| {
                *segment < self.first_segment || *segment > self.last_segment
            })
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut geometries = std::collections::BTreeSet::new();
        for zone in &self.zones {
            if !geometries.insert(zone.geometry) {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }
        Ok(())
    }

    /// Recompute source and generation bindings, including composition with a calibration guard.
    pub fn validate_for(&self, record: &CoverageRecord) -> Result<(), ContractError> {
        self.validate()?;
        if record.source != self.source
            || record.import_identity != self.summary.import_identity()
            || record.import_root != self.summary.import_root()
            || ContentDigest::sha256(record.sensor_id.as_bytes()) != self.summary.sensor_digest()
            || record.first_segment != self.first_segment
            || record.last_segment != self.last_segment
            || ContentDigest::sha256(record.capture_time_label.as_bytes()) != self.time_label
            || record.zones.len() != self.zones.len()
        {
            return Err(ContractError::DigestMismatch);
        }
        let guard = record
            .pose_uncertainty
            .as_ref()
            .and_then(|value| value.guard_receipt());
        let actual_analysis =
            guard.map_or(record.analysis_digest, |guard| guard.base_analysis_digest());
        if actual_analysis != self.analysis_digest() {
            return Err(ContractError::DigestMismatch);
        }
        let digest = self.digest();
        let eligible = self.witness_segments();
        for (zone, binding) in record.zones.iter().zip(&self.zones) {
            if zone_binding(&zone.zone_id, &zone.geometry) != binding.geometry {
                return Err(ContractError::DigestMismatch);
            }
            let actual_pipeline = match guard {
                Some(guard) => guard.zone(zone)?.base_pipeline_generation(),
                None => zone.pipeline_generation,
            };
            if actual_pipeline != derived(PIPELINE_DOMAIN, binding.base_pipeline, digest)
                || (self.capture_order_uncertain() && !zone.witnesses.is_empty())
                || zone.witnesses.iter().any(|witness| {
                    self.summary.observations().iter().any(|frame| {
                        frame.segment >= witness.first_segment
                            && frame.segment <= witness.last_segment
                            && !eligible.contains(&frame.segment)
                    })
                })
            {
                return Err(ContractError::CoverageUncertified);
            }
        }
        Ok(())
    }

    /// Complete bounded canonical source and generation binding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.text(self.source.as_str());
        e.u64(self.first_segment);
        e.u64(self.last_segment);
        e.digest(self.time_label);
        e.digest(self.base_analysis);
        e.u32(self.confirmation_hits);
        e.u64(self.zones.len() as u64);
        for zone in &self.zones {
            e.digest(zone.geometry);
            e.digest(zone.base_pipeline);
        }
        e.bytes(&self.summary.to_bytes());
        e.finish()
    }

    /// Decode inside a digest-verified coverage envelope, with strict bounds and roundtrip.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORDED_HEALTH_COVERAGE_BYTES {
            return Err(ContractError::BudgetExhausted);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let source = match d.text()? {
            "watch" => CoverageSource::Watch,
            "corroborate" => CoverageSource::Corroborate,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let first_segment = d.u64()?;
        let last_segment = d.u64()?;
        let time_label = d.digest()?;
        let base_analysis = d.digest()?;
        let confirmation_hits = d.u32()?;
        let count = usize::try_from(d.u64()?).map_err(|_| ContractError::BudgetExhausted)?;
        if count == 0 || count > MAX_COVERAGE_ZONES {
            return Err(ContractError::BudgetExhausted);
        }
        let mut zones = Vec::with_capacity(count);
        for _ in 0..count {
            zones.push(ZoneBinding {
                geometry: d.digest()?,
                base_pipeline: d.digest()?,
            });
        }
        let summary = RecordedHealthSummary::from_bytes(d.bytes()?)?;
        d.ensure_finished()?;
        let receipt = Self {
            source,
            first_segment,
            last_segment,
            time_label,
            base_analysis,
            confirmation_hits,
            zones,
            summary,
        };
        receipt.validate()?;
        if receipt.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering);
        }
        Ok(receipt)
    }

    /// Shared measurement fields stay at the top level; coverage adds its separate receipt digest.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = self.summary.to_json();
        let _ = out.pop();
        out.push_str(&format!(
            ",\"coverage_receipt_digest\":\"{}\",\"coverage_source\":\"{}\",\
             \"base_analysis_digest\":\"{}\",\"confirmation_hits\":{},\"capture_order_uncertain\":{}}}",
            self.digest(),
            self.source.as_str(),
            self.base_analysis,
            self.confirmation_hits,
            self.capture_order_uncertain(),
        ));
        out
    }
}
