#![forbid(unsafe_code)]
//! Independent bounded companion identity and complete byte-free JSON.

use fss_core::{CanonicalEncoder, ContentDigest};

use super::*;
use crate::ingest::package_detect::json_string as quote;
use crate::ingest::qsr_observations::MAX_QSR_JSON_BYTES;

pub(super) fn encode(
    source_qsr: ContentDigest,
    lane_stages: &[String],
    rows: &[QsrLaneTraversal],
) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSQRL01");
    e.u32(1);
    e.text(QSR_LANE_TRAVERSAL_SCHEMA);
    e.digest(ContentDigest::sha256(QSR_LANE_TRAVERSAL_POLICY.as_bytes()));
    e.digest(source_qsr);
    e.u64(lane_stages.len() as u64);
    for stage in lane_stages {
        e.text(stage);
    }
    e.u64(rows.len() as u64);
    for row in rows {
        e.digest(row.track);
        e.text(row.status.as_str());
        e.u64(row.stages.len() as u64);
        for stage in &row.stages {
            e.u64(stage.stage as u64);
            e.u64(stage.frame as u64);
        }
        for n in [
            row.from_frame,
            row.last_observed_frame,
            row.at_frame,
            row.missing_initial_stages,
            row.remaining_stages,
        ] {
            e.u64(n as u64);
        }
        e.text(row.termination.as_str());
        e.text(&row.minimum_elapsed_ns.to_string());
        e.text(&row.maximum_elapsed_ns.to_string());
    }
    let bytes = e.finish_checked().map_err(|_| QsrError::Limit)?;
    if bytes.len() > MAX_QSR_JSON_BYTES {
        return Err(QsrError::Limit);
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn json(
    digest: ContentDigest,
    source_qsr: ContentDigest,
    source_zone: ContentDigest,
    provenance_root: ContentDigest,
    sampled_frames: usize,
    maximum_sample_gap_ns: u64,
    lane_stages: &[String],
    rows: &[QsrLaneTraversal],
) -> Result<String> {
    let mut output = format!(
        concat!(
            "{{\"schema\":{},\"operation\":\"read_verified\",\"report_digest\":{},\"policy_digest\":{},",
            "\"source_qsr_report\":{},\"source_zone_report\":{},\"provenance_root\":{},\"sampled_frames\":{},",
            "\"maximum_sample_gap_ns\":{},\"lane_stages\":[{}],",
            "\"interpretation\":{{\"duration_unit\":\"nanoseconds\",\"duration_basis\":\"observed_endpoint_separation\",",
            "\"physical_identity_established\":false,\"continuous_traversal_established\":false,",
            "\"service_or_wait_duration_established\":false,\"effects_authorized\":false}},",
            "\"summary\":{{\"completed\":{},\"incomplete\":{},\"interrupted\":{}}},\"traversals\":["
        ),
        quote(QSR_LANE_TRAVERSAL_SCHEMA),
        quote(&digest.to_text()),
        quote(&ContentDigest::sha256(QSR_LANE_TRAVERSAL_POLICY.as_bytes()).to_text()),
        quote(&source_qsr.to_text()),
        quote(&source_zone.to_text()),
        quote(&provenance_root.to_text()),
        sampled_frames,
        quote(&maximum_sample_gap_ns.to_string()),
        lane_stages
            .iter()
            .map(|stage| quote(stage))
            .collect::<Vec<_>>()
            .join(","),
        rows.iter()
            .filter(|row| row.status == QsrLaneTraversalStatus::Completed)
            .count(),
        rows.iter()
            .filter(|row| row.status == QsrLaneTraversalStatus::Incomplete)
            .count(),
        rows.iter()
            .filter(|row| row.status == QsrLaneTraversalStatus::Interrupted)
            .count(),
    );
    for (index, row) in rows.iter().enumerate() {
        let stages = row
            .stages
            .iter()
            .map(|stage| format!("{{\"stage\":{},\"frame\":{}}}", stage.stage, stage.frame))
            .collect::<Vec<_>>()
            .join(",");
        let next = format!(
            concat!(
                "{}{{\"track\":{},\"status\":{},\"stages\":[{}],\"from_frame\":{},\"last_observed_frame\":{},",
                "\"at_frame\":{},\"termination\":{},\"missing_initial_stages\":{},\"remaining_stages\":{},",
                "\"minimum_elapsed_ns\":{},\"maximum_elapsed_ns\":{}}}"
            ),
            if index == 0 { "" } else { "," },
            quote(&row.track.to_text()),
            quote(row.status.as_str()),
            stages,
            row.from_frame,
            row.last_observed_frame,
            row.at_frame,
            quote(row.termination.as_str()),
            row.missing_initial_stages,
            row.remaining_stages,
            quote(&row.minimum_elapsed_ns.to_string()),
            quote(&row.maximum_elapsed_ns.to_string()),
        );
        if output
            .len()
            .checked_add(next.len())
            .and_then(|n| n.checked_add(3))
            .is_none_or(|n| n > MAX_QSR_JSON_BYTES)
        {
            return Err(QsrError::Limit);
        }
        output.push_str(&next);
    }
    output.push_str("]}\n");
    if output.len() > MAX_QSR_JSON_BYTES {
        return Err(QsrError::Limit);
    }
    Ok(output)
}
