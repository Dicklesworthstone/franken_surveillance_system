#![forbid(unsafe_code)]
//! Canonical read identity and bounded, byte-free JSON. No persistence or effect approval.

use fss_core::{CanonicalEncode, CanonicalEncoder, LedgerAnchor};

use super::*;
use crate::ingest::package_detect::json_string as quote;

fn config_bytes(config: &QsrConfig) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.qsr_observation_config.v1");
    e.u64(config.zone_roles.len() as u64);
    for binding in &config.zone_roles {
        e.text(&binding.zone);
        e.text(binding.role.as_str());
    }
    e.u64(config.lane_stages.len() as u64);
    for stage in &config.lane_stages {
        e.text(stage);
    }
    e.finish_checked().map_err(|_| QsrError::Limit)
}
pub(super) fn encode(
    source: &PackageZoneReport,
    config: &QsrConfig,
    observations: &QsrObservations,
) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSQSR01");
    e.u32(1);
    e.text(QSR_OBSERVATION_SCHEMA);
    e.digest(ContentDigest::sha256(QSR_OBSERVATION_POLICY.as_bytes()));
    e.digest(source.digest());
    e.digest(source.provenance_root());
    e.bytes(&config_bytes(config)?);
    e.u64(observations.zones.len() as u64);
    for zone in &observations.zones {
        for n in [
            zone.zone,
            zone.sampled_frames,
            zone.supported_frames,
            zone.unknown_frames,
            zone.frames_with_observed_tracks,
        ] {
            e.u64(n as u64);
        }
        e.bool(zone.maximum_observed_count.is_some());
        if let Some(n) = zone.maximum_observed_count {
            e.u64(n as u64);
        }
        e.u64(zone.observed_tracks.len() as u64);
        for track in &zone.observed_tracks {
            e.digest(*track);
        }
    }
    e.u64(observations.samples.len() as u64);
    for sample in &observations.samples {
        e.u64(sample.zone as u64);
        e.u64(sample.frame as u64);
        e.text(sample.presence.as_str());
        e.bool(sample.masked);
        e.bool(sample.historical_screen_support);
        for n in [
            sample.tentative_tracks,
            sample.boundary_tracks,
            sample.partial_tracks,
            sample.unobserved_tracks,
        ] {
            e.u64(n as u64);
        }
        e.u64(sample.confirmed_tracks.len() as u64);
        for track in &sample.confirmed_tracks {
            e.digest(*track);
        }
    }
    e.u64(observations.dwell.len() as u64);
    for dwell in &observations.dwell {
        e.digest(dwell.track);
        e.u64(dwell.zone as u64);
        for n in [
            dwell.from_frame.ok_or(QsrError::Mismatch)?,
            dwell.at_frame,
            dwell.through_frame,
            dwell.observations,
        ] {
            e.u64(n as u64);
        }
        e.text(
            &dwell
                .minimum_duration_ns
                .ok_or(QsrError::Mismatch)?
                .to_string(),
        );
        e.text(
            &dwell
                .maximum_duration_ns
                .ok_or(QsrError::Mismatch)?
                .to_string(),
        );
    }
    e.u64(observations.lane_transitions.len() as u64);
    for transition in &observations.lane_transitions {
        e.digest(transition.track);
        for n in [
            transition.from_stage,
            transition.to_stage,
            transition.from_frame,
            transition.at_frame,
        ] {
            e.u64(n as u64);
        }
        e.text(&transition.minimum_elapsed_ns.to_string());
        e.text(&transition.maximum_elapsed_ns.to_string());
    }
    e.u64(observations.lane_interruptions.len() as u64);
    for interruption in &observations.lane_interruptions {
        e.digest(interruption.track);
        for n in [
            interruption.from_stage,
            interruption.from_frame,
            interruption.at_frame,
        ] {
            e.u64(n as u64);
        }
        e.text(interruption.reason.as_str());
    }
    let bytes = e.finish_checked().map_err(|_| QsrError::Limit)?;
    if bytes.len() > MAX_QSR_JSON_BYTES {
        return Err(QsrError::Limit);
    }
    Ok(bytes)
}
fn digest(value: ContentDigest) -> String {
    quote(&value.to_text())
}
fn digests(values: &[ContentDigest]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .copied()
            .map(digest)
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn anchor(value: &LedgerAnchor) -> Result<String> {
    let mut e = CanonicalEncoder::new();
    value.encode_canonical(&mut e);
    Ok(format!(
        "{{\"digest\":{},\"site_lineage\":{},\"commit_sequence\":{},\"policy_epoch\":{},\"privacy_epoch\":{}}}",
        digest(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| QsrError::Limit)?
        )),
        quote(&value.site_lineage),
        value.commit_sequence,
        value.policy_epoch,
        value.privacy_epoch
    ))
}
struct Json(String);
impl Json {
    fn push(&mut self, value: &str) -> Result<()> {
        if self
            .0
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > MAX_QSR_JSON_BYTES)
        {
            return Err(QsrError::Limit);
        }
        self.0.push_str(value);
        Ok(())
    }
}
fn sep(index: usize) -> &'static str {
    if index == 0 { "" } else { "," }
}

pub(super) fn json(report: &QsrObservationReport) -> Result<String> {
    let source = &report.source;
    let analysis = source.analysis();
    let record = analysis.retained().record();
    let exposures = source.health_exposures().ok_or(QsrError::Mismatch)?;
    let mut out = Json(String::new());
    out.push(&format!(concat!(
        "{{\"schema\":{},\"operation\":\"read_verified\",\"report_digest\":{},\"policy_digest\":{},\"configuration_digest\":{},",
        "\"source\":{{\"zone_report\":{},\"provenance_root\":{},\"analysis_digest\":{},\"package_report\":{},",
        "\"import_identity\":{},\"import_root\":{},\"package_digest\":{},\"model_id\":{},\"model_generation\":{},",
        "\"contract_digest\":{},\"label\":{},\"class_index\":{},\"privacy_binding\":{},\"source_anchor\":{},\"retention_anchor\":{}}},",
        "\"coverage\":{{\"scope\":\"finite_sampled_source_frames\",\"sampled_frames\":{},\"capture_time_label\":{},\"clock_basis\":{},",
        "\"continuous_coverage_certified\":false,\"absence_certified\":false,\"current_camera_health_established\":false}},",
        "\"interpretation\":{{\"count_unit\":\"confirmed_model_tracks_at_one_sample\",\"detection_quality_measured\":false,",
        "\"physical_identity_established\":false,\"service_or_wait_duration_established\":false,\"effects_authorized\":false}},",
        "\"configuration\":{{\"maximum_sample_gap_ns\":{},\"zone_roles\":["
    ), quote(QSR_OBSERVATION_SCHEMA), digest(report.digest), digest(ContentDigest::sha256(QSR_OBSERVATION_POLICY.as_bytes())),
        digest(ContentDigest::sha256(&config_bytes(&report.config)?)), digest(source.digest()), digest(source.provenance_root()),
        digest(analysis.digest()), digest(record.report_digest), digest(record.import_identity), digest(record.import_root),
        digest(record.package_digest), quote(&record.model_id), quote(&record.generation), digest(record.contract_digest),
        quote(analysis.label()), analysis.class_index(), digest(source.privacy_binding_digest()), anchor(analysis.retained().authority_anchor())?,
        anchor(source.retention_anchor().ok_or(QsrError::Mismatch)?)?, source.frames().len(), quote(source.capture_time_label()),
        quote(source.clock_basis().as_str()), source.config().maximum_sample_gap_ns))?;
    for (index, binding) in report.config.zone_roles.iter().enumerate() {
        out.push(&format!(
            "{}{{\"zone\":{},\"role\":{}}}",
            sep(index),
            quote(&binding.zone),
            quote(binding.role.as_str())
        ))?;
    }
    out.push(&format!(
        "],\"lane_stages\":[{}]}},\"frames\":[",
        report
            .config
            .lane_stages
            .iter()
            .map(|stage| quote(stage))
            .collect::<Vec<_>>()
            .join(",")
    ))?;
    for (index, frame) in source.frames().iter().enumerate() {
        let exposure = exposures.get(index).ok_or(QsrError::Mismatch)?;
        out.push(&format!(concat!(
            "{}{{\"frame\":{},\"segment\":{},\"capsule_digest\":{},\"sensor_id\":{},",
            "\"capture\":{{\"earliest_ns\":{},\"latest_ns\":{}}},\"time_reliable\":{},\"source_boundary\":{},",
            "\"historical_screening\":{},\"screening_incomplete\":{},\"support_allowed\":{},\"diagnostics\":["
        ), sep(index), index, frame.segment, digest(frame.capsule_digest), quote(exposure.source().sensor_id.as_str()),
            quote(&frame.capture.earliest.0.to_string()), quote(&frame.capture.latest.0.to_string()), frame.time_reliable,
            frame.source_boundary, quote(exposure.status()), exposure.screening_incomplete(), source.health_support_allowed(index).ok_or(QsrError::Mismatch)?))?;
        for (pin_index, pin) in exposure.pins().iter().enumerate() {
            out.push(&format!(
                "{}{{\"record_digest\":{},\"provenance_root\":{},\"trace_digest\":{}}}",
                sep(pin_index),
                digest(pin.record_digest),
                digest(pin.provenance_root),
                digest(pin.trace_digest)
            ))?;
        }
        out.push("],\"findings\":[")?;
        for (finding_index, finding) in exposure.findings().iter().enumerate() {
            out.push(&format!("{}{{\"diagnostic\":{},\"finding\":{},\"withheld_first_segment\":{},\"withheld_last_segment\":{}}}",
                sep(finding_index), digest(finding.diagnostic), quote(finding.finding.as_str()), finding.withheld_first_segment, finding.withheld_last_segment))?;
        }
        out.push("]}")?;
    }
    out.push("],\"zones\":[")?;
    for (index, zone) in report.observations.zones.iter().enumerate() {
        out.push(&format!(concat!("{}{{\"zone\":{},\"sampled_frames\":{},\"supported_frames\":{},\"unknown_frames\":{},",
            "\"frames_with_observed_tracks\":{},\"maximum_observed_count\":{},\"observed_tracks\":{}}}"),
            sep(index), zone.zone, zone.sampled_frames, zone.supported_frames, zone.unknown_frames, zone.frames_with_observed_tracks,
            zone.maximum_observed_count.map_or_else(|| "null".into(), |n| n.to_string()), digests(&zone.observed_tracks)))?;
    }
    out.push("],\"samples\":[")?;
    for (index, sample) in report.observations.samples.iter().enumerate() {
        out.push(&format!(concat!("{}{{\"zone\":{},\"frame\":{},\"presence\":{},\"confirmed_track_count\":{},\"confirmed_tracks\":{},",
            "\"masked\":{},\"historical_screen_support\":{},\"tentative_tracks\":{},\"boundary_tracks\":{},\"partial_tracks\":{},\"unobserved_tracks\":{}}}"),
            sep(index), sample.zone, sample.frame, quote(sample.presence.as_str()),
            if sample.presence == QsrPresence::Unknown { "null".into() } else { sample.confirmed_tracks.len().to_string() },
            digests(&sample.confirmed_tracks), sample.masked, sample.historical_screen_support, sample.tentative_tracks,
            sample.boundary_tracks, sample.partial_tracks, sample.unobserved_tracks))?;
    }
    out.push("],\"sampled_dwell\":[")?;
    for (index, dwell) in report.observations.dwell.iter().enumerate() {
        out.push(&format!(concat!("{}{{\"kind\":\"sampled_zone_dwell\",\"track\":{},\"zone\":{},\"from_frame\":{},\"at_frame\":{},",
            "\"through_frame\":{},\"observations\":{},\"minimum_duration_ns\":{},\"maximum_duration_ns\":{}}}"),
            sep(index), digest(dwell.track), dwell.zone, dwell.from_frame.ok_or(QsrError::Mismatch)?, dwell.at_frame,
            dwell.through_frame, dwell.observations, quote(&dwell.minimum_duration_ns.ok_or(QsrError::Mismatch)?.to_string()),
            quote(&dwell.maximum_duration_ns.ok_or(QsrError::Mismatch)?.to_string())))?;
    }
    out.push("],\"lane_transitions\":[")?;
    for (index, transition) in report.observations.lane_transitions.iter().enumerate() {
        out.push(&format!(concat!("{}{{\"kind\":\"observed_lane_stage_transition\",\"track\":{},\"from_stage\":{},\"to_stage\":{},",
            "\"from_frame\":{},\"at_frame\":{},\"minimum_elapsed_ns\":{},\"maximum_elapsed_ns\":{}}}"),
            sep(index), digest(transition.track), transition.from_stage, transition.to_stage, transition.from_frame,
            transition.at_frame, quote(&transition.minimum_elapsed_ns.to_string()), quote(&transition.maximum_elapsed_ns.to_string())))?;
    }
    out.push("],\"lane_interruptions\":[")?;
    for (index, interruption) in report.observations.lane_interruptions.iter().enumerate() {
        out.push(&format!(
            "{}{{\"track\":{},\"from_stage\":{},\"from_frame\":{},\"at_frame\":{},\"reason\":{}}}",
            sep(index),
            digest(interruption.track),
            interruption.from_stage,
            interruption.from_frame,
            interruption.at_frame,
            quote(interruption.reason.as_str())
        ))?;
    }
    out.push("]}\n")?;
    Ok(out.0)
}
