#![forbid(unsafe_code)]
//! Bounded complete campaign projection, retaining native sentinel reports and exact unknowns.

use fss_core::{ContentDigest, LedgerAnchor};

use super::{
    RTSP_CAMPAIGN_SENTINEL_REPORT_SCHEMA, Result, RtspCampaignSentinelAttempt,
    RtspCampaignSentinelConfig, RtspCampaignSentinelError as Error,
    RtspCampaignSentinelReservation,
};
use crate::KernelBackend;
use crate::ingest::long_dwell::json;
use crate::ingest::long_sentinel::LongSentinelUsage;
use crate::ingest::rtsp_selected_watch::RtspWatchSelection;
use crate::rtsp::campaign_history::{CampaignRetryReason, VerifiedCampaignHistory};

/// Exact reverified history, independent native computations and optional native replay handles.
/// This projection is not a new authority record, acquisition checkpoint or scene-coverage proof.
#[derive(Debug)]
pub struct RtspCampaignSentinelReport {
    pub(super) plan_digest: ContentDigest,
    pub(super) history: VerifiedCampaignHistory,
    pub(super) reservation: RtspCampaignSentinelReservation,
    pub(super) attempts: Vec<RtspCampaignSentinelAttempt>,
    pub(super) basis: LedgerAnchor,
    pub(super) usage: LongSentinelUsage,
    pub(super) source_pool_charged: u64,
    pub(super) pixel_pool_charged: u64,
    pub(super) native_report_bytes: usize,
    pub(super) maximum_report_bytes: usize,
    pub(super) package: ContentDigest,
    pub(super) backend: KernelBackend,
    pub(super) sampling: RtspCampaignSentinelConfig,
    pub(super) retain: bool,
}
impl RtspCampaignSentinelReport {
    /// Exact complete operation approval identity.
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Reverified immutable prefix; its recorded observations do not become latest-state proof.
    pub fn history(&self) -> &VerifiedCampaignHistory {
        &self.history
    }
    /// Every selected started attempt in original order, including all unsampled and unknown rows.
    pub fn attempts(&self) -> &[RtspCampaignSentinelAttempt] {
        &self.attempts
    }
    /// Conservative approved whole-operation ceilings, distinct from actual usage.
    pub const fn reservation(&self) -> &RtspCampaignSentinelReservation {
        &self.reservation
    }
    /// Actual native inference/decode/head usage summed across all completed computations.
    pub const fn usage(&self) -> &LongSentinelUsage {
        &self.usage
    }
    /// Common destination anchor after all imports and before any model work or retention.
    pub fn analysis_basis(&self) -> &LedgerAnchor {
        &self.basis
    }

    /// Complete bounded JSON. Native report bytes and per-attempt unknowns are never truncated;
    /// an exceeded ceiling refuses the complete projection without undoing durable native work.
    pub fn to_json(&self, authority_sequence: u64) -> Result<String> {
        let pin = self.history.pin();
        let r = self.reservation;
        let i = r.inference;
        let u = self.usage;
        let terminal = self.history.terminal().map_or_else(
            || "null".into(),
            |t| {
                format!(
                    "{{\"complete\":{},\"error_id\":{}}}",
                    t.complete,
                    optional_text(t.error_id.as_deref())
                )
            },
        );
        let mut output = format!(
            concat!(
                "{{\"format\":{},\"plan_digest\":{},\"authority_sequence\":{},",
                "\"history\":{{\"approval\":{},\"plan\":{},\"root\":{},\"records\":{},\"terminal\":{},",
                "\"planned_attempts\":{},\"selected_started_attempts\":{},\"durability_resynced\":{},\"possibly_stale\":{}}},",
                "\"analysis_basis_sequence\":{},\"analysis_basis_root\":{},\"package_digest\":{},\"backend\":{},\"backend_generation\":{},\"retention_requested\":{},",
                "\"sampling\":{{\"motion_independent\":true,\"allocation\":\"ordinal_round_robin_whole_bursts\",",
                "\"every_frames\":{},\"burst_frames\":{},\"max_inferences\":{},\"admitted_inferences\":{},\"unused_inference_allowance\":{},\"native_per_attempt_limit\":64}},",
                "\"reservation\":{{\"attempts\":{},\"selected_archives\":{},\"history_metadata_bytes\":{},\"source_verification_passes\":{},",
                "\"original_verification_bytes\":{},\"import_original_bytes\":{},\"import_media_bytes\":{},\"maximum_frames\":{},",
                "\"source_chunk_bytes\":{},\"pixel_samples\":{},\"video_encoded_bytes\":{},\"video_coded_luma_capacity\":{},\"video_decode_work_units\":{},",
                "\"jpeg_work_units\":{},\"detection_work_units\":{},\"inferences\":{},\"preprocess_macs\":{},\"execution_macs\":{},\"output_bytes\":{},\"native_report_bytes\":{},\"report_bytes\":{}}},",
                "\"usage\":{{\"source_chunk_bytes\":{},\"pixel_samples\":{},\"video_encoded_bytes\":{},\"video_coded_luma_capacity\":{},\"video_decode_work_units\":{},",
                "\"jpeg_work_units\":{},\"detection_work_units\":{},\"decoded_frames\":{},\"inferences\":{},\"preprocess_work\":{},\"execution_macs\":{},",
                "\"source_pool_charged\":{},\"pixel_pool_charged\":{},\"native_report_bytes\":{}}},",
                "\"processing\":\"offline_exact_campaign_sentinel\",\"campaign_history_verified\":true,\"selected_attempt_inventory_complete\":true,",
                "\"latest_history_verified\":false,\"model_outputs\":\"uncalibrated\",\"foreground_gate_required\":false,",
                "\"tracker_continuity_across_bursts\":false,\"tracker_continuity_across_attempts\":false,",
                "\"event_publication_authorized\":false,\"absence_certifiable\":false,\"alert_authorized\":false,\"network_resumed\":false,\"attempts\":["
            ),
            json(RTSP_CAMPAIGN_SENTINEL_REPORT_SCHEMA),
            json(&self.plan_digest.to_text()),
            authority_sequence,
            json(&pin.approval.to_text()),
            json(&pin.plan.to_text()),
            json(&pin.root.to_text()),
            pin.records,
            terminal,
            self.history.plan().attempts.len(),
            self.attempts.len(),
            self.history.durability_resynced(),
            self.history.possibly_stale(),
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
            r.attempts,
            r.selected_archives,
            r.history_metadata_bytes,
            r.source_verification_passes,
            r.original_verification_bytes,
            r.import_original_bytes,
            r.import_media_bytes,
            r.maximum_frames,
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
        for (index, attempt) in self.attempts.iter().enumerate() {
            let row = attempt_json(attempt);
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

fn optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), json)
}
fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |n| n.to_string())
}
fn optional_digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".into(), |d| json(&d.to_text()))
}

fn attempt_json(attempt: &RtspCampaignSentinelAttempt) -> String {
    let recorded = attempt.recorded();
    let native = recorded.finish.as_ref().and_then(|f| f.native.as_ref());
    let finish = recorded.finish.as_ref().map_or_else(|| "null".into(), |finish| {
        let observation = finish.native.as_ref().map_or_else(|| "null".into(), |native| {
            let retry = native.retry.map(|reason| match reason {
                CampaignRetryReason::ConnectionUnavailable => "connection_unavailable",
                CampaignRetryReason::SourceEnded => "source_ended",
                CampaignRetryReason::ProgressStalled => "progress_stalled",
                CampaignRetryReason::ReadInterrupted => "read_interrupted",
                CampaignRetryReason::SettledSuccess => "settled_success",
            });
            let source = native.bindings.source_pin.map_or_else(|| "null".into(), |pin| {
                format!("{{\"scope\":{},\"head\":{},\"datagrams\":{},\"bytes\":{},\"current_datagram_archive_verified\":false}}",
                    json(&pin.scope.to_text()), json(&pin.head.to_text()), pin.datagrams, pin.bytes)
            });
            format!(concat!("{{\"complete\":{},\"error_id\":{},\"retry\":{},\"durable_pictures\":{},",
                "\"recovery_required\":{},\"recorded_catalogs\":{},\"source_prefix_observation\":{}}}"),
                native.complete, optional_text(native.error_id.as_deref()), optional_text(retry),
                native.durable_pictures, native.recovery_required, native.bindings.catalogs.len(), source)
        });
        format!("{{\"native\":{},\"controller_error\":{},\"settled_success\":{},\"next_attempt_planned\":{}}}",
            observation, optional_text(finish.controller_error.as_deref()), finish.settled_success, finish.next_attempt_planned)
    });
    let import = attempt.import().map_or_else(
        || "null".into(),
        |import| {
            format!(
                concat!(
                    "{{\"identity\":{},\"root\":{},\"manifest\":{},\"original_proof\":{},",
                    "\"frames\":{},\"windows\":{},\"pages\":{},\"reused\":{}}}"
                ),
                json(&import.import_identity.to_text()),
                json(&import.import_root.to_text()),
                json(&import.manifest_digest.to_text()),
                json(&import.proof.to_text()),
                import.frames,
                attempt.windows(),
                attempt.pages(),
                import.reused
            )
        },
    );
    let selection = attempt.selection().map_or_else(|| "null".into(), |selection| {
        let source = selection.source();
        let pin = |slot: &fss_publication::SlotName, root: ContentDigest| format!("{{\"slot\":{},\"root\":{}}}", json(slot.as_str()), json(&root.to_text()));
        let pins = match selection {
            RtspWatchSelection::Catalog(r) => pin(&r.slot, r.root),
            RtspWatchSelection::Pages(r) => r.pages.iter().map(|p| pin(&p.slot, p.root)).collect::<Vec<_>>().join(","),
            RtspWatchSelection::Window(r) => pin(&r.slot, r.root),
        };
        let capture = selection.capture_origin().map_or_else(|| "null".into(), |c| {
            format!("{{\"label\":\"operator_assumption\",\"start_ns\":{},\"uncertainty_ns\":{}}}", json(&c.start_ns.0.to_string()), c.uncertainty_ns)
        });
        format!(concat!("{{\"kind\":{},\"codec\":{},\"pins\":[{}],\"sensor\":{},\"stream\":{},",
            "\"authority_anchor\":{},\"receive_clock\":{},\"capture_origin\":{}}}"),
            json(selection.kind()), json(selection.codec().as_str()), pins, json(source.sensor.as_str()),
            json(source.stream.as_str()), json(&source.anchor.to_text()), json(&source.receive_clock.to_text()), capture)
    });
    let allocation = attempt.allocation();
    let decoded = attempt
        .sentinel_report()
        .map_or(0, |r| r.usage().decoded_frames);
    let model_samples = attempt
        .sentinel_report()
        .map_or(0, |r| r.usage().inferences);
    let unsampled = if let Some(report) = attempt.sentinel_report() {
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
    } else if attempt.import().is_some() {
        format!(
            "[{{\"first_segment\":0,\"segment_count\":{}}}]",
            attempt.catalogued_pictures()
        )
    } else {
        "null".into()
    };
    let retained = attempt.retained().map_or_else(|| "null".into(), |r| {
        let children = r.child_reports().iter().map(|d| json(&d.to_text())).collect::<Vec<_>>().join(",");
        format!(concat!("{{\"status\":{},\"report_digest\":{},\"root\":{},\"recipe_digest\":{},\"package_digest\":{},",
            "\"authority_sequence\":{},\"authority_root\":{},\"child_reports\":[{}],\"cold_native_replay_available\":true}}"),
            json(r.status().as_str()), json(&r.report_digest().to_text()), json(&r.root().to_text()),
            json(&r.recipe_digest().to_text()), json(&r.package_digest().to_text()),
            r.authority_anchor().commit_sequence, json(&r.authority_anchor().state_root.to_text()), children)
    });
    let all_catalogued = native.map_or_else(
        || "null".into(),
        |n| (n.durable_pictures == attempt.catalogued_pictures()).to_string(),
    );
    format!(
        concat!(
            "{{\"attempt\":{},\"generation\":{},\"status\":{},\"start_root\":{},\"finish_root\":{},",
            "\"child_approval\":{},\"archive_namespace\":{},\"archive_path\":{},\"finish\":{},\"request_digest\":{},\"selection\":{},",
            "\"recorded_durable_pictures\":{},\"catalogued_pictures\":{},\"decoded_pictures\":{},\"model_sampled_pictures\":{},",
            "\"recorded_pictures_without_catalog\":{},\"all_recorded_pictures_catalogued\":{},",
            "\"allocation\":{{\"catalogued_frames\":{},\"eligible_bursts\":{},\"admitted_bursts\":{},\"admitted_inferences\":{},\"budget_skipped_bursts\":{}}},",
            "\"unsampled_ranges\":{},\"strict_native_video_range_drained\":{},\"original_rtp_custody_verified\":{},",
            "\"quiet_scene_proved\":false,\"import\":{},\"sentinel\":{},\"retained\":{}}}"
        ),
        attempt.ordinal(),
        attempt.generation(),
        json(attempt.status().as_str()),
        json(&recorded.start.root.to_text()),
        optional_digest(recorded.finish_pin.map(|p| p.root)),
        json(&recorded.attempt.child_approval.to_text()),
        json(&recorded.attempt.archive_namespace.to_text()),
        json(&recorded.attempt.archive_path),
        finish,
        optional_digest(attempt.request_digest()),
        selection,
        optional_u64(attempt.recorded_durable_pictures()),
        attempt.catalogued_pictures(),
        decoded,
        model_samples,
        optional_u64(attempt.recorded_pictures_without_catalog()),
        all_catalogued,
        allocation.catalogued_frames,
        allocation.eligible_bursts,
        allocation.admitted_bursts,
        allocation.admitted_inferences,
        allocation.budget_skipped_bursts,
        unsampled,
        attempt.sentinel_report().is_some(),
        attempt.import().is_some(),
        import,
        attempt.sentinel_report().map_or("null", |r| r.json()),
        retained,
    )
}
