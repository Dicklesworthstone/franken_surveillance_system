#![forbid(unsafe_code)]
//! Exact optical-policy custody and validation for recorded tracking/coverage admission.

use super::{
    ADMISSION_POLICY, CanonicalDecoder, CanonicalEncoder, ContractError, MAX_HEALTH_PIXELS,
    OpticalQualityMetrics, OpticalThresholds, RecordedHealthSummary,
};
use crate::ingest::sensor_health::{OPTICAL_QUALITY_DOMAIN, OpticalFinding};
use std::collections::BTreeSet;

const POLICY_DOMAIN: &str = "fss.recorded_sensor_health.optical_policy.v1";
const OPTICAL_ADMISSION: &str = concat!(
    "per-frame-optical-withdrawal:insufficient-resolution-is-degraded:",
    "cost=2*samples+5*interior:whole-analysis-ceiling=frames*7*4194304:",
    "no-health-tamper-absence-or-effect-certification:v1",
);

pub(super) fn policy_bytes(thresholds: OpticalThresholds) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(POLICY_DOMAIN);
    e.bytes(crate::ingest::sensor_health::policy_bytes());
    e.text(OPTICAL_QUALITY_DOMAIN);
    encode_thresholds(&mut e, thresholds);
    e.text(ADMISSION_POLICY);
    e.text(OPTICAL_ADMISSION);
    e.finish()
}

pub(super) fn encode_thresholds(e: &mut CanonicalEncoder, thresholds: OpticalThresholds) {
    e.u64(thresholds.min_laplacian_variance_x1000);
    e.u8(thresholds.glare_luma_min);
    e.u32(thresholds.max_glare_ppm);
}

pub(super) fn decode_thresholds(
    d: &mut CanonicalDecoder<'_>,
) -> Result<OpticalThresholds, ContractError> {
    let thresholds = OpticalThresholds {
        min_laplacian_variance_x1000: d.u64()?,
        glare_luma_min: d.u8()?,
        max_glare_ppm: d.u32()?,
    };
    if thresholds.max_glare_ppm > 1_000_000 {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(thresholds)
}

fn dimensions(dimensions: [u32; 2]) -> Result<(u64, u64), ContractError> {
    let [width, height] = dimensions;
    let samples = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > 4096
        || height > 4096
        || samples > MAX_HEALTH_PIXELS as u64
    {
        return Err(ContractError::InvalidIdentifier);
    }
    let interior = u64::from(width.saturating_sub(2)) * u64::from(height.saturating_sub(2));
    Ok((samples, interior))
}

/// Counts each optical luma hash/glare sample and five scalar reads per interior Laplacian.
pub(super) fn sample_reads(frame_dimensions: [u32; 2]) -> Result<u64, ContractError> {
    let (samples, interior) = dimensions(frame_dimensions)?;
    samples
        .checked_mul(2)
        .and_then(|used| {
            interior
                .checked_mul(5)
                .and_then(|lap| used.checked_add(lap))
        })
        .ok_or(ContractError::BudgetExhausted)
}

pub(super) fn decode_metric(bytes: &[u8]) -> Result<OpticalQualityMetrics, ContractError> {
    if bytes.len() > 1024 {
        return Err(ContractError::BudgetExhausted);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != OPTICAL_QUALITY_DOMAIN {
        return Err(ContractError::InvalidIdentifier);
    }
    let source_generation = d.digest()?;
    let segment = d.u64()?;
    let capsule_digest = d.digest()?;
    let luma_digest = d.digest()?;
    let dimensions = [d.u32()?, d.u32()?];
    let interior_pixels = d.u64()?;
    let laplacian_variance_x1000 = d.u64()?;
    let glare_pixels = d.u64()?;
    let glare_ppm = d.u32()?;
    let thresholds = decode_thresholds(&mut d)?;
    let count = d.u32()?;
    if count > 3 {
        return Err(ContractError::BudgetExhausted);
    }
    let mut findings = Vec::with_capacity(count as usize);
    for _ in 0..count {
        findings.push(match d.text()? {
            "severe_blur" => OpticalFinding::SevereBlur,
            "localized_highlight_glare" => OpticalFinding::LocalizedHighlightGlare,
            "insufficient_resolution" => OpticalFinding::InsufficientResolution,
            _ => return Err(ContractError::InvalidIdentifier),
        });
    }
    d.ensure_finished()?;
    let metric = OpticalQualityMetrics {
        source_generation,
        segment,
        capsule_digest,
        luma_digest,
        dimensions,
        interior_pixels,
        laplacian_variance_x1000,
        glare_pixels,
        glare_ppm,
        thresholds,
        findings,
    };
    validate_metric(&metric)?;
    if metric.canonical_bytes() != bytes {
        return Err(ContractError::NonCanonicalOrdering);
    }
    Ok(metric)
}

fn validate_metric(metric: &OpticalQualityMetrics) -> Result<(), ContractError> {
    let (samples, interior) = dimensions(metric.dimensions)?;
    if metric.thresholds.max_glare_ppm > 1_000_000
        || metric.interior_pixels != interior
        || metric.glare_pixels > samples
        || u64::from(metric.glare_ppm) != metric.glare_pixels * 1_000_000 / samples
        // Each four-neighbour Laplacian is within [-1020, 1020].
        || metric.laplacian_variance_x1000 > 1_040_400_000
        || (interior <= 1 && metric.laplacian_variance_x1000 != 0)
    {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut findings = Vec::new();
    if interior == 0 {
        findings.push(OpticalFinding::InsufficientResolution);
    } else if metric.laplacian_variance_x1000 < metric.thresholds.min_laplacian_variance_x1000 {
        findings.push(OpticalFinding::SevereBlur);
    }
    if metric.glare_ppm >= metric.thresholds.max_glare_ppm {
        findings.push(OpticalFinding::LocalizedHighlightGlare);
    }
    if findings != metric.findings {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// Rederive decisions from retained integer measurements, requiring a one-to-one source binding.
/// This verifies the receipt's consistency; its enclosing source chain supplies custody.
pub(super) fn validate_summary(
    summary: &RecordedHealthSummary,
    affected: &mut BTreeSet<u64>,
) -> Result<(), ContractError> {
    let Some(thresholds) = summary.policy.optical_thresholds() else {
        return if summary.optical_observations.is_empty() && summary.optical_sample_reads == 0 {
            Ok(())
        } else {
            Err(ContractError::InvalidIdentifier)
        };
    };
    if thresholds.max_glare_ppm > 1_000_000
        || summary.optical_observations.len() != summary.observations.len()
    {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut used = 0_u64;
    for (metric, observation) in summary
        .optical_observations
        .iter()
        .zip(&summary.observations)
    {
        validate_metric(metric)?;
        if metric.thresholds != thresholds
            || metric.source_generation != observation.source_generation
            || metric.segment != observation.segment
            || metric.capsule_digest != observation.capsule_digest
            || metric.luma_digest != observation.luma_digest
            || metric.dimensions != observation.dimensions
        {
            return Err(ContractError::InvalidIdentifier);
        }
        used = used
            .checked_add(sample_reads(metric.dimensions)?)
            .ok_or(ContractError::BudgetExhausted)?;
        if !metric.findings.is_empty() {
            affected.insert(metric.segment);
        }
    }
    if used != summary.optical_sample_reads {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

pub(super) fn json_fields(
    summary: &RecordedHealthSummary,
    thresholds: OpticalThresholds,
) -> String {
    let measurements = summary
        .optical_observations
        .iter()
        .map(|metric| {
            let findings = metric
                .findings
                .iter()
                .map(|finding| format!("\"{}\"", finding.as_str()))
                .collect::<Vec<_>>();
            format!(
                concat!(
                    "{{\"segment\":{},\"source_generation\":\"{}\",",
                    "\"capsule_digest\":\"{}\",\"luma_digest\":\"{}\",",
                    "\"measurement_digest\":\"{}\",\"dimensions\":[{},{}],",
                    "\"interior_pixels\":{},\"laplacian_variance_x1000\":{},",
                    "\"glare_pixels\":{},\"glare_ppm\":{},\"findings\":[{}]}}"
                ),
                metric.segment,
                metric.source_generation,
                metric.capsule_digest,
                metric.luma_digest,
                metric.digest(),
                metric.dimensions[0],
                metric.dimensions[1],
                metric.interior_pixels,
                metric.laplacian_variance_x1000,
                metric.glare_pixels,
                metric.glare_ppm,
                findings.join(","),
            )
        })
        .collect::<Vec<_>>();
    format!(
        concat!(
            ",\"optical_thresholds\":{{\"min_laplacian_variance_x1000\":{},",
            "\"glare_luma_min\":{},\"max_glare_ppm\":{}}},",
            "\"optical_sample_reads\":{},\"optical_observations\":[{}]"
        ),
        thresholds.min_laplacian_variance_x1000,
        thresholds.glare_luma_min,
        thresholds.max_glare_ppm,
        summary.optical_sample_reads,
        measurements.join(","),
    )
}

#[cfg(test)]
mod tests;
