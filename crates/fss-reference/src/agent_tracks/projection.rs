#![forbid(unsafe_code)]
//! Lossless matched rows and explicit source/model uncertainty inside the canonical envelope.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, EnvelopeEpistemic, EnvelopeProposition,
    KnowledgeState,
};

use super::{MAX_TRACK_QUERY_OBSERVATIONS, TrackObservationRow, TrackQueryError};
use crate::ingest::package_event::{PackageAnalysisReport, types::sample_confirmed};

const MAX_STATEMENT_BYTES: usize = 16_384;
const MAX_PROJECTION_ROWS: usize = 256;

pub(super) fn observations(
    report: &PackageAnalysisReport,
) -> Result<Vec<TrackObservationRow>, TrackQueryError> {
    let total = report.tracks().iter().try_fold(0_usize, |total, track| {
        total
            .checked_add(track.observations.len())
            .ok_or(TrackQueryError::ResultLimit)
    })?;
    if total > MAX_TRACK_QUERY_OBSERVATIONS {
        return Err(TrackQueryError::ResultLimit);
    }
    let frames: BTreeMap<_, _> = report
        .retained()
        .record()
        .frames
        .iter()
        .enumerate()
        .map(|(index, frame)| (frame.segment, (index, frame)))
        .collect();
    if frames.len() != report.retained().record().frames.len() {
        return Err(TrackQueryError::Contract);
    }
    let mut result = Vec::with_capacity(total);
    for track in report.tracks() {
        for (index, observation) in track.observations.iter().enumerate() {
            let (frame_index, frame) = frames
                .get(&observation.segment)
                .filter(|(_, frame)| frame.capsule_digest == observation.capsule_digest)
                .ok_or(TrackQueryError::Contract)?;
            let detection_clipped = match observation.detection {
                Some((row, score, bounds, _)) => Some(
                    frame
                        .detections
                        .iter()
                        .find(|detection| {
                            detection.row == row
                                && detection.class_index == report.class_index()
                                && detection.score_bits == score
                                && detection.bounds == bounds
                        })
                        .ok_or(TrackQueryError::Contract)?
                        .clipped,
                ),
                None => None,
            };
            let mut row = TrackObservationRow {
                row_digest: ContentDigest::sha256(b"unpublished-track-observation"),
                track_identity: track.identity,
                track_id: track.track_id,
                observation_index: index as u64,
                frame_index: *frame_index as u64,
                continuity_epoch: report
                    .boundaries()
                    .partition_point(|boundary| boundary.before_segment <= observation.segment)
                    as u64,
                // This row is borrowed directly from the sealed native report. Use its native
                // rule without repeatedly searching all track identities for every sample.
                sample_confirmed: sample_confirmed(report.config(), index),
                track_ever_confirmed: track.confirmed,
                observation: observation.clone(),
                sensor_id: frame.sensor_id.clone(),
                capture: frame.capture,
                dimensions: frame.dimensions,
                color: frame.color.clone(),
                inference_identity: frame.inference_identity,
                output_digest: frame.output_digest,
                detection_report_digest: frame.detection_report_digest,
                detection_clipped,
            };
            row.row_digest = row_digest(report.digest(), &row);
            result.push(row);
        }
    }
    Ok(result)
}

fn row_digest(analysis: ContentDigest, row: &TrackObservationRow) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_tracks_query.observation.v1");
    e.digest(analysis);
    e.digest(row.track_identity);
    e.u64(row.track_id);
    e.u64(row.observation_index);
    e.u64(row.frame_index);
    e.u64(row.continuity_epoch);
    e.bool(row.sample_confirmed);
    e.bool(row.track_ever_confirmed);
    e.u64(row.observation.segment);
    e.digest(row.observation.capsule_digest);
    for value in row.observation.track_box {
        e.i128(i128::from(value));
    }
    e.bool(row.observation.detection.is_some());
    if let Some((index, score, bounds, iou)) = row.observation.detection {
        e.u64(index);
        e.u32(score);
        for value in bounds {
            e.u32(value);
        }
        e.u32(iou);
    }
    e.text(&row.sensor_id);
    row.capture.encode_canonical(&mut e);
    for value in row.dimensions {
        e.u32(value);
    }
    e.text(&row.color);
    e.digest(row.inference_identity);
    e.digest(row.output_digest);
    e.digest(row.detection_report_digest);
    e.bool(row.detection_clipped.is_some());
    if let Some(clipped) = row.detection_clipped {
        e.bool(clipped);
    }
    ContentDigest::sha256(&e.finish())
}

fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn digest(value: ContentDigest) -> String {
    quote(&value.to_text())
}

fn observation_json(row: &TrackObservationRow) -> String {
    let assigned = match row.observation.detection {
        None => "null".to_owned(),
        Some((index, score, bounds, iou)) => format!(
            "{{\"row\":{index},\"uncalibrated_score_f32_bits\":{score},\"bounds_xyxy_256\":{:?},\"filtered_box_iou_ppm\":{iou},\"clipped\":{}}}",
            bounds,
            row.detection_clipped
                .map_or("null", |value| if value { "true" } else { "false" }),
        ),
    };
    format!(
        "{{\"row_digest\":{},\"track_identity\":{},\"track_id\":{},\"observation_index\":{},\"frame_index\":{},\"continuity_epoch\":{},\"sample_confirmed\":{},\"track_ever_confirmed\":{},\"segment\":{},\"capsule_digest\":{},\"filtered_box_cx_cy_w_h_pixels\":{:?},\"assigned_detection\":{},\"sensor_id\":{},\"capture_earliest_ns\":{},\"capture_latest_ns\":{},\"dimensions\":{:?},\"color\":{},\"inference_identity\":{},\"output_digest\":{},\"detection_report_digest\":{}}}",
        digest(row.row_digest),
        digest(row.track_identity),
        row.track_id,
        row.observation_index,
        row.frame_index,
        row.continuity_epoch,
        row.sample_confirmed,
        row.track_ever_confirmed,
        row.observation.segment,
        digest(row.observation.capsule_digest),
        row.observation.track_box,
        assigned,
        quote(&row.sensor_id),
        row.capture.earliest.0,
        row.capture.latest.0,
        row.dimensions,
        quote(&row.color),
        digest(row.inference_identity),
        digest(row.output_digest),
        digest(row.detection_report_digest),
    )
}

pub(super) fn epistemic(
    report: &PackageAnalysisReport,
    rows: &[TrackObservationRow],
    total: usize,
    position: u64,
    selection: ContentDigest,
) -> Result<EnvelopeEpistemic, TrackQueryError> {
    let remaining = total
        .checked_sub(position as usize + rows.len())
        .ok_or(TrackQueryError::Contract)?;
    let retained = report.retained();
    let record = retained.record();
    let evidence = vec![
        report.digest().to_text(),
        retained.record_digest().to_text(),
        retained.root().to_text(),
    ];
    let mut propositions = Vec::new();
    let mut push = |id: &str, body: String, state: KnowledgeState, evidence: Vec<String>| {
        let statement = format!("Verified native tracks {id}: {body}");
        if statement.len() > MAX_STATEMENT_BYTES || propositions.len() >= MAX_PROJECTION_ROWS {
            return Err(TrackQueryError::ResultLimit);
        }
        propositions.push(EnvelopeProposition {
            id: format!("claim:tracks:{id}"),
            statement,
            state,
            provenance: "derived".into(),
            evidence,
        });
        Ok(())
    };
    let mut anchor = CanonicalEncoder::new();
    anchor.text("fss.agent_tracks_query.source_authority.v1");
    retained.authority_anchor().encode_canonical(&mut anchor);
    push(
        "source",
        format!(
            "{{\"analysis_digest\":{},\"detection_report_digest\":{},\"retained_record_digest\":{},\"retained_root\":{},\"historical_authority_digest\":{},\"import_identity\":{},\"import_root\":{},\"media_format\":{},\"first_segment\":{},\"segment_count\":{},\"source_frame_count\":{}}}",
            digest(report.digest()),
            digest(record.report_digest),
            digest(retained.record_digest()),
            digest(retained.root()),
            digest(ContentDigest::sha256(&anchor.finish())),
            digest(record.import_identity),
            digest(record.import_root),
            quote(&record.media_format),
            record.first_segment,
            record.segment_count,
            record.frames.len(),
        ),
        KnowledgeState::Known,
        evidence.clone(),
    )?;
    push(
        "model",
        format!(
            "{{\"package_digest\":{},\"manifest_digest\":{},\"model_id\":{},\"generation\":{},\"model_digest\":{},\"graph_digest\":{},\"contract_digest\":{},\"selected_label\":{},\"class_index\":{},\"minimum_score_ppm\":{}}}",
            digest(record.package_digest),
            digest(record.manifest_digest),
            quote(&record.model_id),
            quote(&record.generation),
            digest(record.model_digest),
            digest(record.graph_digest),
            digest(record.contract_digest),
            quote(report.label()),
            report.class_index(),
            record.minimum_score_ppm,
        ),
        KnowledgeState::Known,
        evidence.clone(),
    )?;
    let config = report.config();
    push(
        "tracking",
        format!(
            "{{\"algorithm\":{},\"confirmation_hits\":{},\"maximum_missed_frames\":{},\"minimum_iou_ppm\":{},\"observations\":\"actual_matched_only\",\"ordering\":\"native_track_id_then_observation_display_order\"}}",
            quote(crate::ingest::tracker::TRACKER_ALGORITHM),
            config.confirmation_hits,
            config.maximum_missed_frames,
            config.minimum_iou_ppm,
        ),
        KnowledgeState::Known,
        evidence.clone(),
    )?;
    push(
        "selection",
        format!(
            "{{\"track_count\":{},\"total_matched_observations\":{total},\"page_position\":{position},\"page_observations\":{},\"remaining_observations\":{remaining},\"selection_witness\":{}}}",
            report.tracks().len(),
            rows.len(),
            digest(selection),
        ),
        KnowledgeState::Known,
        vec![selection.to_text()],
    )?;
    for (index, frame) in record.frames.iter().enumerate() {
        push(
            &format!("frame:{index}"),
            format!(
                "{{\"frame_index\":{index},\"segment\":{},\"capsule_digest\":{},\"sensor_id\":{},\"capture_earliest_ns\":{},\"capture_latest_ns\":{},\"dimensions\":{:?},\"color\":{},\"inference_identity\":{},\"output_digest\":{},\"detection_report_digest\":{},\"selected_label_detection_count\":{}}}",
                frame.segment,
                digest(frame.capsule_digest),
                quote(&frame.sensor_id),
                frame.capture.earliest.0,
                frame.capture.latest.0,
                frame.dimensions,
                quote(&frame.color),
                digest(frame.inference_identity),
                digest(frame.output_digest),
                digest(frame.detection_report_digest),
                frame
                    .detections
                    .iter()
                    .filter(|row| row.class_index == report.class_index())
                    .count(),
            ),
            KnowledgeState::Known,
            vec![
                retained.record_digest().to_text(),
                frame.capsule_digest.to_text(),
            ],
        )?;
    }
    for (index, boundary) in report.boundaries().iter().enumerate() {
        push(
            &format!("boundary:{index}"),
            format!(
                "{{\"continuity_epoch\":{},\"before_segment\":{},\"source_gap\":{},\"sequence_gap\":{},\"dimensions_changed\":{}}}",
                index + 1,
                boundary.before_segment,
                boundary.source_gap,
                boundary.sequence_gap,
                boundary.dimensions_changed,
            ),
            KnowledgeState::Known,
            evidence.clone(),
        )?;
    }
    if report.boundaries().is_empty() {
        push(
            "boundaries",
            "[]".into(),
            KnowledgeState::Known,
            evidence.clone(),
        )?;
    }
    for (index, row) in rows.iter().enumerate() {
        push(
            &format!("observation:{}", position + index as u64),
            observation_json(row),
            KnowledgeState::Estimated,
            vec![
                row.row_digest.to_text(),
                report.digest().to_text(),
                row.observation.capsule_digest.to_text(),
            ],
        )?;
    }
    if rows.is_empty() {
        push("observations", "[]".into(), KnowledgeState::Known, evidence)?;
    }
    propositions.push(EnvelopeProposition {
        id: "claim:tracks:physical-absence".into(),
        statement: "Physical identity, model accuracy, calibrated confidence and physical absence remain unknown. No matched row, a missed frame or an unconfirmed track is not evidence of physical absence.".into(),
        state: KnowledgeState::Unknown,
        provenance: "derived".into(),
        evidence: Vec::new(),
    });
    Ok(EnvelopeEpistemic {
        propositions,
        assumptions: vec![
            "The exact model-vocabulary label selects retained detections. Scores remain uncalibrated IEEE-754 f32 bits; boxes retain their stated pixel units. A tracking confirmation is an association-policy state, not corroboration or a physical identity.".into(),
            "Only actual native matched observations are returned. Per-sample confirmation preserves tentative history. Predictions, missed frames and unsampled intervals are not synthesized; source boundaries reset motion and confirmation.".into(),
            "Every selected page row is complete. All source-frame metadata and continuity boundaries are retained on each page; remaining matched observations require its exact continuation. Capture intervals are compared without inferring a clock basis or UTC conversion.".into(),
            "The principal is an operator audit label. The separate source-read grant permits internal verification only; no source-media disclosure, model execution, durable publication, event promotion or effects are authorized.".into(),
        ],
        invalidators: vec![
            "Any authority/effect-history advance, source custody failure, deletion or privacy change requires a fresh complete read.".into(),
            "Changing the report, label, tracking recipe, principal, read allowance, privacy/retention scope or page size invalidates the continuation.".into(),
        ],
    })
}
