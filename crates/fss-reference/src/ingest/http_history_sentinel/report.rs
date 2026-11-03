#![forbid(unsafe_code)]
//! Complete bounded history projection, preserving native outcomes and explicit sampling gaps.

use fss_core::{ContentDigest, LedgerAnchor};

use super::{
    HTTP_HISTORY_SENTINEL_REPORT_SCHEMA, HttpHistorySentinelConfig,
    HttpHistorySentinelError as Error, HttpHistorySentinelGeneration,
    HttpHistorySentinelReservation, Result,
};
use crate::KernelBackend;
use crate::http_reconnect_history::{BoundaryOutcome, ReconnectHistoryPin};
use crate::ingest::long_dwell::json;
use crate::ingest::long_sentinel::LongSentinelUsage;

/// Exact history/source observations, independent native computations and optional replay handles.
/// This report is neither a new authority journal nor scene coverage, event or effect permission.
#[derive(Debug)]
pub struct HttpHistorySentinelReport {
    pub(super) plan_digest: ContentDigest,
    pub(super) history: ReconnectHistoryPin,
    pub(super) reservation: HttpHistorySentinelReservation,
    pub(super) generations: Vec<HttpHistorySentinelGeneration>,
    pub(super) basis: LedgerAnchor,
    pub(super) usage: LongSentinelUsage,
    pub(super) source_pool_charged: u64,
    pub(super) pixel_pool_charged: u64,
    pub(super) native_report_bytes: usize,
    pub(super) maximum_report_bytes: usize,
    pub(super) source_reads: u64,
    pub(super) source_bytes: u64,
    pub(super) package: ContentDigest,
    pub(super) backend: KernelBackend,
    pub(super) sampling: HttpHistorySentinelConfig,
    pub(super) retain: bool,
}
impl HttpHistorySentinelReport {
    /// Exact processing approval, distinct from capture or future event approvals.
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Independently selected ended-history prefix, never a discovered latest head.
    pub const fn history_pin(&self) -> ReconnectHistoryPin {
        self.history
    }
    /// Every selected native connection in order, including empty, failed and unsampled rows.
    pub fn generations(&self) -> &[HttpHistorySentinelGeneration] {
        &self.generations
    }
    /// Conservative whole-invocation ceilings admitted before I/O.
    pub const fn reservation(&self) -> &HttpHistorySentinelReservation {
        &self.reservation
    }
    /// Actual native source/decode/model/head usage across all completed computations.
    pub const fn usage(&self) -> &LongSentinelUsage {
        &self.usage
    }
    /// Common destination anchor after all imports and before any computation or retention.
    pub fn analysis_basis(&self) -> &LedgerAnchor {
        &self.basis
    }

    /// Complete bounded JSON. No unsampled row, native report or source outcome is truncated.
    pub fn to_json(&self, authority_sequence: u64) -> Result<String> {
        let r = self.reservation;
        let i = r.inference;
        let u = self.usage;
        let mut output = format!(
            concat!(
                "{{\"format\":{},\"plan_digest\":{},\"authority_sequence\":{},",
                "\"history\":{{\"session\":{},\"root\":{},\"connections\":{}}},",
                "\"source_inventory\":{{\"reads\":{},\"bytes\":{}}},",
                "\"analysis_basis_sequence\":{},\"analysis_basis_root\":{},\"package_digest\":{},\"backend\":{},\"backend_generation\":{},\"retention_requested\":{},",
                "\"sampling\":{{\"motion_independent\":true,\"allocation\":\"connection_round_robin_whole_bursts\",",
                "\"every_frames\":{},\"burst_frames\":{},\"max_inferences\":{},\"admitted_inferences\":{},\"unused_inference_allowance\":{},\"native_per_generation_limit\":64}},",
                "\"reservation\":{{\"connections\":{},\"maximum_frames\":{},\"history_verification_bytes\":{},",
                "\"import_original_bytes\":{},\"import_media_bytes\":{},\"destination_verification_bytes\":{},",
                "\"source_chunk_bytes\":{},\"pixel_samples\":{},\"video_encoded_bytes\":{},\"video_coded_luma_capacity\":{},\"video_decode_work_units\":{},",
                "\"jpeg_work_units\":{},\"detection_work_units\":{},\"inferences\":{},\"preprocess_macs\":{},\"execution_macs\":{},\"output_bytes\":{},\"native_report_bytes\":{},\"report_bytes\":{}}},",
                "\"usage\":{{\"source_chunk_bytes\":{},\"pixel_samples\":{},\"video_encoded_bytes\":{},\"video_coded_luma_capacity\":{},\"video_decode_work_units\":{},",
                "\"jpeg_work_units\":{},\"detection_work_units\":{},\"decoded_frames\":{},\"inferences\":{},\"preprocess_work\":{},\"execution_macs\":{},",
                "\"source_pool_charged\":{},\"pixel_pool_charged\":{},\"native_report_bytes\":{}}},",
                "\"processing\":\"offline_exact_history_sentinel\",\"history_verified\":true,\"selected_generation_inventory_complete\":true,",
                "\"latest_history_verified\":false,\"model_outputs\":\"uncalibrated\",\"foreground_gate_required\":false,",
                "\"tracker_continuity_across_bursts\":false,\"tracker_continuity_across_generations\":false,",
                "\"event_publication_authorized\":false,\"absence_certifiable\":false,\"alert_authorized\":false,\"network_resumed\":false,\"generations\":["
            ),
            json(HTTP_HISTORY_SENTINEL_REPORT_SCHEMA),
            json(&self.plan_digest.to_text()),
            authority_sequence,
            json(&self.history.session.to_text()),
            json(&self.history.root.to_text()),
            self.history.connections,
            self.source_reads,
            self.source_bytes,
            self.basis.commit_sequence,
            json(&self.basis.state_root.to_text()),
            json(&self.package.to_text()),
            json(self.backend.stable_id()),
            json(&self.backend.generation().to_text()),
            self.retain,
            self.sampling.every_frames,
            self.sampling.burst_frames,
            self.sampling.max_inferences,
            u.inferences,
            self.sampling.max_inferences - u.inferences,
            r.connections,
            r.maximum_frames,
            r.history_verification_bytes,
            r.import_original_bytes,
            r.import_media_bytes,
            r.destination_verification_bytes,
            i.source_chunk_bytes,
            i.pixel_samples,
            i.video_encoded_bytes,
            i.video_coded_luma_capacity,
            i.video_decode_work_units,
            i.jpeg_work_units,
            i.detection_work_units,
            i.inferences,
            i.preprocess_macs,
            i.execution_macs,
            i.output_bytes,
            i.report_bytes,
            self.maximum_report_bytes,
            u.source_chunk_bytes,
            u.pixel_samples,
            u.video_encoded_bytes,
            u.video_coded_luma_capacity,
            u.video_decode_work_units,
            u.jpeg_work_units,
            u.detection_work_units,
            u.decoded_frames,
            u.inferences,
            u.preprocess_work,
            u.execution_macs,
            self.source_pool_charged,
            self.pixel_pool_charged,
            self.native_report_bytes,
        );
        for (index, generation) in self.generations.iter().enumerate() {
            let row = generation_json(generation);
            let next = output
                .len()
                .checked_add(row.len())
                .and_then(|n| n.checked_add(3))
                .ok_or(Error::Limit)?;
            if next > self.maximum_report_bytes {
                return Err(Error::Limit);
            }
            output
                .try_reserve(row.len() + 1)
                .map_err(|_| Error::Limit)?;
            if index != 0 {
                output.push(',');
            }
            output.push_str(&row);
        }
        output.push_str("]}");
        if output.len() > self.maximum_report_bytes {
            return Err(Error::Limit);
        }
        Ok(output)
    }
}

fn generation_json(generation: &HttpHistorySentinelGeneration) -> String {
    let b = generation.binding();
    let s = generation.source();
    let p = generation.prefix();
    let attempted = match generation.native_outcome() {
        BoundaryOutcome::ConnectFailed { attempted } => attempted.to_string(),
        _ => "null".into(),
    };
    let imported = generation.import().map_or_else(|| "null".into(), |receipt| {
        format!(concat!("{{\"identity\":{},\"root\":{},\"manifest\":{},\"original_proof\":{},\"frames\":{},",
            "\"capture_time_label\":{},\"ending\":{},\"reused\":{}}}"),
            json(&receipt.import_identity.to_text()), json(&receipt.import_root.to_text()),
            json(&receipt.manifest_digest.to_text()), json(&receipt.proof.to_text()), receipt.frames,
            json(receipt.capture_time_label), json(receipt.ending.as_str()), receipt.reused)
    });
    let allocation = generation.allocation();
    let decoded = generation
        .sentinel_report()
        .map_or(0, |r| r.usage().decoded_frames);
    let sampled = generation
        .sentinel_report()
        .map_or(0, |r| r.usage().inferences);
    let unsampled = if let Some(report) = generation.sentinel_report() {
        format!(
            "[{}]",
            report
                .plan()
                .unsampled_ranges()
                .iter()
                .map(|range| {
                    format!(
                        "{{\"first_segment\":{},\"segment_count\":{}}}",
                        range.first_segment, range.segment_count
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        )
    } else if generation.import().is_some() {
        format!(
            "[{{\"first_segment\":0,\"segment_count\":{}}}]",
            allocation.imported_frames
        )
    } else {
        "null".into()
    };
    let retained = generation.retained().map_or_else(|| "null".into(), |r| {
        let children = r.child_reports().iter().map(|d| json(&d.to_text())).collect::<Vec<_>>().join(",");
        format!(concat!("{{\"status\":{},\"report_digest\":{},\"root\":{},\"recipe_digest\":{},\"package_digest\":{},",
            "\"authority_sequence\":{},\"authority_root\":{},\"child_reports\":[{}],\"cold_native_replay_available\":true}}"),
            json(r.status().as_str()), json(&r.report_digest().to_text()), json(&r.root().to_text()),
            json(&r.recipe_digest().to_text()), json(&r.package_digest().to_text()), r.authority_anchor().commit_sequence,
            json(&r.authority_anchor().state_root.to_text()), children)
    });
    format!(
        concat!(
            "{{\"connection\":{},\"generation\":{},\"status\":{},\"native_outcome\":{},\"connect_attempted\":{},",
            "\"source\":{{\"stream_source\":{},\"generation\":{},\"receive_clock\":{},\"retention_evidence\":{}}},",
            "\"prefix\":{{\"scope\":{},\"head\":{},\"reads\":{},\"bytes\":{}}},",
            "\"binding\":{{\"sensor\":{},\"stream\":{},\"receive_time_ns\":{},\"capture_start_ns\":{},\"capture_uncertainty_ns\":{},\"assumed_fps\":{},\"capture_time_label\":\"operator_assumption\"}},",
            "\"imported_frames\":{},\"decoded_frames\":{},\"model_sampled_frames\":{},",
            "\"allocation\":{{\"imported_frames\":{},\"eligible_bursts\":{},\"admitted_bursts\":{},\"admitted_inferences\":{},\"budget_skipped_bursts\":{}}},",
            "\"unsampled_ranges\":{},\"original_http_custody_verified\":true,\"destination_original_custody_verified\":{},",
            "\"quiet_scene_proved\":false,\"import\":{},\"sentinel\":{},\"retained\":{}}}"
        ),
        generation.connection(),
        generation.generation(),
        json(generation.status().as_str()),
        json(generation.native_outcome().as_str()),
        attempted,
        json(&hex(&s.stream.source)),
        s.stream.generation,
        json(&hex(&s.receive_clock)),
        json(&hex(&s.retention_evidence)),
        json(&p.scope.to_text()),
        json(&p.head.to_text()),
        p.reads,
        p.bytes,
        json(b.sensor.as_str()),
        json(b.stream.as_str()),
        json(&b.receive_time.0.to_string()),
        json(&b.capture_hint.start_ns.0.to_string()),
        b.capture_hint.uncertainty_ns,
        b.capture_hint.assumed_fps,
        allocation.imported_frames,
        decoded,
        sampled,
        allocation.imported_frames,
        allocation.eligible_bursts,
        allocation.admitted_bursts,
        allocation.admitted_inferences,
        allocation.budget_skipped_bursts,
        unsampled,
        generation.import().is_some(),
        imported,
        generation.sentinel_report().map_or("null", |r| r.json()),
        retained,
    )
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
