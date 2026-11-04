#![forbid(unsafe_code)]
//! Explicit evidence-transcript projection without changing historical supervisor JSON or hashes.

use fss_core::{CanonicalEncoder, ContentDigest};

use super::{
    SUPERVISOR_TRANSCRIPT_DOMAIN, SUPERVISOR_TRANSCRIPT_REPORT_SCHEMA, SupervisorReport, array,
    nullable, object, string, unsigned,
};

use crate::fusion_json::fusion_transcript_json;

// Constant-size folding avoids another report-sized receipt buffer. Tags separate the two
// ordered camera inventories; hashes bind exact text without a canonical-text overflow path.
fn fold_transcript_labels(previous: ContentDigest, tag: u8, labels: &[String]) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.digest(previous);
    encoder.tag(tag);
    encoder.u64(labels.len() as u64);
    let mut digest = ContentDigest::sha256(&encoder.finish());
    for label in labels {
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(digest);
        encoder.digest(ContentDigest::sha256(label.as_bytes()));
        digest = ContentDigest::sha256(&encoder.finish());
    }
    digest
}

pub(super) fn report_digest(report: &SupervisorReport) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(SUPERVISOR_TRANSCRIPT_DOMAIN);
    encoder.text(SUPERVISOR_TRANSCRIPT_REPORT_SCHEMA);
    encoder.digest(report.receipt_digest);
    // Do not depend on legacy text encoding to bind the report's context. Every caller string
    // becomes a fixed-size exact-byte hash; the window trajectory is folded one record at a time.
    encoder.digest(ContentDigest::sha256(report.schema.as_bytes()));
    encoder.digest(ContentDigest::sha256(report.site_lineage.as_bytes()));
    encoder.digest(ContentDigest::sha256(report.hypothesis_id.as_bytes()));
    encoder.digest(report.authority_root_at_start);
    encoder.digest(ContentDigest::sha256(
        report.calibration_generation.as_bytes(),
    ));
    encoder.digest(report.calibration_digest);
    encoder.digest(ContentDigest::sha256(report.status.as_bytes()));
    encoder.u64(report.windows_evaluated);
    encoder.u64(report.work_units_consumed);
    encoder.u64(report.work_units_limit);
    match report.corroborated_at_window {
        Some(window) => {
            encoder.bool(true);
            encoder.u64(window);
        }
        None => encoder.bool(false),
    }
    encoder.i128(i128::from(report.final_accumulated_llr.lo()));
    encoder.i128(i128::from(report.final_accumulated_llr.hi()));
    encoder.i128(i128::from(report.supremum_lo_mban));
    encoder.u32(report.ville_false_alarm_bound_ppm);
    encoder.u32(report.threshold_ville_bound_ppm);
    encoder.u32(report.independent_supporting_clusters);
    encoder.u64(report.window_records.len() as u64);
    match &report.cancellation {
        Some(c) => {
            encoder.bool(true);
            encoder.u64(c.requested_at_window);
            encoder.u64(c.drained_in_flight_windows);
            encoder.bool(c.finalized_cleanly);
            encoder.bool(c.zero_orphan_obligations);
            encoder.bool(c.zero_staging_artifacts);
        }
        None => encoder.bool(false),
    }
    let mut digest = ContentDigest::sha256(&encoder.finish());
    for record in &report.window_records {
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(digest);
        encoder.u64(record.window_index);
        encoder.u64(record.timestamp_ns);
        encoder.digest(record.step_outcome.transcript.digest());
        encoder.digest(ContentDigest::sha256(record.decision_label.as_bytes()));
        encoder.digest(ContentDigest::sha256(record.knowledge_state.as_bytes()));
        digest = ContentDigest::sha256(&encoder.finish());
        digest = fold_transcript_labels(digest, 0, &record.degraded_cameras);
        digest = fold_transcript_labels(digest, 1, &record.occluded_cameras);
    }
    digest
}

pub(super) fn report_json(report: &SupervisorReport) -> String {
    let transitions: Vec<String> = report
        .window_records
        .iter()
        .map(|record| {
            object(&[
                ("window_index", unsigned(record.window_index)),
                ("timestamp_ns", unsigned(record.timestamp_ns)),
                (
                    "fusion_transcript",
                    fusion_transcript_json(&record.step_outcome.transcript),
                ),
            ])
        })
        .collect();
    object(&[
        ("schema", string(SUPERVISOR_TRANSCRIPT_REPORT_SCHEMA)),
        ("report", report.to_json()),
        ("fusion_transcripts", array(&transitions)),
        (
            "transcript_digest",
            string(&report.transcript_digest.to_text()),
        ),
    ])
}
