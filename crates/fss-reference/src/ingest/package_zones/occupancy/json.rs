#![forbid(unsafe_code)]
//! Bounded projection of metadata borrowed from the sealed native source report.

use super::*;
use crate::ingest::package_detect::json_string as quote;
use crate::ingest::package_zones::{PackageZone, PackageZoneFrame};
use fss_core::ClockBasis;

/// Private borrowed view populated only by the retained source owner; never deserialized.
pub(super) struct Source<'a> {
    pub site: &'a str,
    pub sensor: &'a str,
    pub zone_report: ContentDigest,
    pub zone_root: ContentDigest,
    pub analysis: ContentDigest,
    pub detection: ContentDigest,
    pub import_identity: ContentDigest,
    pub import_root: ContentDigest,
    pub package: ContentDigest,
    pub model_id: &'a str,
    pub generation: &'a str,
    pub model: ContentDigest,
    pub contract: ContentDigest,
    pub label: &'a str,
    pub class_index: u64,
    pub capture_time_label: &'a str,
    pub clock: ClockBasis,
    pub privacy: ContentDigest,
    pub screened: bool,
    pub confirmation_hits: u32,
    pub maximum_missed_frames: u32,
    pub minimum_iou_ppm: u32,
    pub zones: &'a [PackageZone],
    pub frames: &'a [PackageZoneFrame],
}

fn d(digest: ContentDigest) -> String {
    quote(&digest.to_text())
}
fn append(out: &mut String, value: &str) -> Result<()> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > MAX_PACKAGE_OCCUPANCY_JSON_BYTES)
    {
        return Err(PackageZoneError::Limit);
    }
    out.push_str(value);
    Ok(())
}
pub(super) fn render(
    source: &Source<'_>,
    digest: ContentDigest,
    samples: &[OccupancySample],
) -> Result<String> {
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"schema\":{},\"operation\":\"read_verified\",\"observation_kind\":\"sampled_class_occupancy\",",
                "\"report_digest\":{},\"policy_generation\":1,\"policy_digest\":{},",
                "\"source\":{{\"site\":{},\"sensor_id\":{},\"zone_report\":{},\"zone_provenance_root\":{},",
                "\"analysis_digest\":{},\"detection_report\":{},\"import_identity\":{},\"import_root\":{},",
                "\"package_digest\":{},\"model_id\":{},\"model_generation\":{},\"model_digest\":{},",
                "\"contract_digest\":{},\"label\":{},\"class_index\":{},",
                "\"capture_time_label\":{},\"clock_basis\":{},\"privacy_binding\":{},\"health_screening_required\":{}}},",
                "\"configuration\":{{\"confirmation_hits\":{},\"maximum_missed_frames\":{},\"minimum_iou_ppm\":{},\"zones\":["
            ),
            quote(PACKAGE_OCCUPANCY_REPORT_DOMAIN),
            d(digest),
            d(ContentDigest::sha256(PACKAGE_OCCUPANCY_POLICY.as_bytes())),
            quote(source.site),
            quote(source.sensor),
            d(source.zone_report),
            d(source.zone_root),
            d(source.analysis),
            d(source.detection),
            d(source.import_identity),
            d(source.import_root),
            d(source.package),
            quote(source.model_id),
            quote(source.generation),
            d(source.model),
            d(source.contract),
            quote(source.label),
            source.class_index,
            quote(source.capture_time_label),
            quote(source.clock.as_str()),
            d(source.privacy),
            source.screened,
            source.confirmation_hits,
            source.maximum_missed_frames,
            source.minimum_iou_ppm
        ),
    )?;
    for (index, zone) in source.zones.iter().enumerate() {
        append(
            &mut out,
            &format!(
                "{}{{\"id\":{},\"x\":{},\"y\":{},\"width\":{},\"height\":{},\"margin\":{}}}",
                if index == 0 { "" } else { "," },
                quote(&zone.id),
                zone.x,
                zone.y,
                zone.width,
                zone.height,
                zone.margin
            ),
        )?;
    }
    append(&mut out, "]},\"frames\":[")?;
    for (index, frame) in source.frames.iter().enumerate() {
        append(
            &mut out,
            &format!(
                concat!(
                    "{}{{\"segment\":{},\"capsule_digest\":{},",
                    "\"capture\":{{\"earliest_ns\":{},\"latest_ns\":{}}},\"dimensions\":[{},{}],",
                    "\"time_reliable\":{},\"source_boundary\":{}}}"
                ),
                if index == 0 { "" } else { "," },
                frame.segment,
                d(frame.capsule_digest),
                quote(&frame.capture.earliest.0.to_string()),
                quote(&frame.capture.latest.0.to_string()),
                frame.dimensions[0],
                frame.dimensions[1],
                frame.time_reliable,
                frame.source_boundary
            ),
        )?;
    }
    append(&mut out, "],\"samples\":[")?;
    for (index, row) in samples.iter().enumerate() {
        append(
            &mut out,
            &format!(
                concat!(
                    "{}{{\"frame\":{},\"zone\":{},\"state\":{},\"observed_count\":{},\"health\":{},",
                    "\"confirmed_outside\":{},\"excluded\":{{\"tentative\":{},\"boundary\":{},",
                    "\"partial\":{},\"unobserved\":{},\"masked\":{},\"health\":{}}},\"supporting_tracks\":["
                ),
                if index == 0 { "" } else { "," },
                row.frame,
                row.zone,
                quote(row.state.as_str()),
                row.observed_count
                    .map_or_else(|| "null".into(), |n| n.to_string()),
                quote(row.health.as_str()),
                row.confirmed_outside,
                row.excluded.tentative,
                row.excluded.boundary,
                row.excluded.partial,
                row.excluded.unobserved,
                row.excluded.masked,
                row.excluded.health
            ),
        )?;
        for (index, track) in row.supporting_tracks.iter().enumerate() {
            append(
                &mut out,
                &format!("{}{}", if index == 0 { "" } else { "," }, d(*track)),
            )?;
        }
        append(&mut out, "]}")?;
    }
    append(
        &mut out,
        concat!(
            "],\"semantics\":{\"source_report_retained\":true,\"current_source_revalidated\":true,",
            "\"absence_certified\":false,\"continuous_occupancy_established\":false,",
            "\"population_bound_established\":false,\"person_identity_established\":false,",
            "\"current_camera_health_established\":false,\"detection_quality_qualified\":false,",
            "\"canonical_event_revision\":false,\"effect_authorized\":false},\"coverage_witness\":null,",
            "\"interpretation\":\"Counts are actual confirmed class-selected inside assignments at retained source samples. ",
            "Zero is no positive observation, never absence. Null means privacy or historical health withholds the count. ",
            "Unassessed health preserves the original unscreened policy without asserting camera health. ",
            "Overlapping zones may count the same track; rows and frames must not be summed into unique subjects or durations.\"}\n"
        ),
    )?;
    Ok(out)
}
