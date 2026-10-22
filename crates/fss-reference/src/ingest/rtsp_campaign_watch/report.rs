#![forbid(unsafe_code)]
//! Complete history-aware projection. Native watch rendering retains candidate semantics.

use fss_core::{ContentDigest, LedgerAnchor};

use super::{
    RTSP_CAMPAIGN_WATCH_REPORT_SCHEMA, Result, RtspCampaignWatchAttempt, RtspCampaignWatchError,
    RtspCampaignWatchReservation,
};
use crate::ingest::long_dwell::json;
use crate::ingest::rtsp_selected_watch::RtspWatchSelection;
use crate::rtsp::campaign_history::{CampaignRetryReason, VerifiedCampaignHistory};

/// Exact selected history plus independently source-verified per-attempt proposals. Native
/// finishes and a retained controller terminal describe past observations, never latest state.
#[derive(Debug)]
pub struct RtspCampaignWatchReport {
    pub(super) plan_digest: ContentDigest,
    pub(super) history: VerifiedCampaignHistory,
    pub(super) reservation: RtspCampaignWatchReservation,
    pub(super) attempts: Vec<RtspCampaignWatchAttempt>,
    pub(super) basis: LedgerAnchor,
    pub(super) maximum_report_bytes: usize,
    pub(super) screened: bool,
}
impl RtspCampaignWatchReport {
    /// Canonical exact whole-operation approval identity.
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Reverified immutable history prefix; metadata remains distinct from source custody.
    pub fn history(&self) -> &VerifiedCampaignHistory {
        &self.history
    }
    /// Every selected start in order, including failed, empty and unknown native outcomes.
    pub fn attempts(&self) -> &[RtspCampaignWatchAttempt] {
        &self.attempts
    }
    /// Checked complete operation ceilings, not observed resource use.
    pub fn reservation(&self) -> &RtspCampaignWatchReservation {
        &self.reservation
    }
    /// Shared destination basis after all imports and before any detector/tracker run.
    pub fn analysis_basis(&self) -> &LedgerAnchor {
        &self.basis
    }

    /// Complete bounded JSON with explicit unknowns and unindexed recorded-picture counts.
    /// This emits no approval command, event or alert; a larger report refuses without truncation.
    pub fn to_json(&self, authority_sequence: u64) -> Result<String> {
        let pin = self.history.pin();
        let r = self.reservation;
        let a = r.analysis;
        let terminal = self.history.terminal().map_or_else(
            || "null".into(),
            |terminal| {
                format!(
                    "{{\"complete\":{},\"error_id\":{}}}",
                    terminal.complete,
                    optional_text(terminal.error_id.as_deref())
                )
            },
        );
        let mut output = format!(
            concat!(
                "{{\"format\":{},\"plan_digest\":{},\"authority_sequence\":{},",
                "\"history\":{{\"approval\":{},\"plan\":{},\"root\":{},\"records\":{},\"terminal\":{},",
                "\"planned_attempts\":{},\"selected_started_attempts\":{},\"durability_resynced\":{},\"possibly_stale\":{}}},",
                "\"analysis_basis_sequence\":{},\"analysis_basis_root\":{},\"screened\":{},",
                "\"reservation\":{{\"attempts\":{},\"history_metadata_bytes\":{},\"source_verification_passes\":{},\"original_verification_bytes\":{},",
                "\"selections\":{},\"frames\":{},\"original_bytes\":{},\"media_bytes\":{},\"source_read_bytes\":{},",
                "\"pixel_samples\":{},\"screening_pixel_samples\":{},\"assignment_work\":{},\"jpeg_work\":{},\"trace_bytes\":{},\"report_bytes\":{}}},",
                "\"processing\":\"offline_exact_campaign_catalogs\",\"campaign_history_verified\":true,",
                "\"selected_attempt_inventory_complete\":true,\"latest_history_verified\":false,",
                "\"tracker_continuity_across_attempts\":false,\"event_publication_authorized\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"network_resumed\":false,\"attempts\":["
            ),
            json(RTSP_CAMPAIGN_WATCH_REPORT_SCHEMA),
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
            self.screened,
            r.attempts,
            r.history_metadata_bytes,
            r.source_verification_passes,
            r.original_verification_bytes,
            a.selections,
            a.frames,
            a.original_bytes,
            a.media_bytes,
            a.source_read_bytes,
            a.pixel_samples,
            a.screening_pixel_samples,
            a.assignment_work,
            a.jpeg_work,
            a.trace_bytes,
            a.report_bytes
        );
        for (index, attempt) in self.attempts.iter().enumerate() {
            let row = attempt_json(attempt, authority_sequence)?;
            let next = output
                .len()
                .checked_add(row.len())
                .and_then(|n| n.checked_add(3))
                .ok_or(RtspCampaignWatchError::Limit)?;
            if next > self.maximum_report_bytes {
                return Err(RtspCampaignWatchError::Limit);
            }
            output
                .try_reserve(row.len() + 1)
                .map_err(|_| RtspCampaignWatchError::Limit)?;
            if index != 0 {
                output.push(',');
            }
            output.push_str(&row);
        }
        output.push_str("]}");
        if output.len() > self.maximum_report_bytes {
            return Err(RtspCampaignWatchError::Limit);
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

fn attempt_json(attempt: &RtspCampaignWatchAttempt, authority_sequence: u64) -> Result<String> {
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
            RtspWatchSelection::Catalog(request) => pin(&request.slot, request.root),
            RtspWatchSelection::Pages(request) => request.pages.iter().map(|page| pin(&page.slot, page.root)).collect::<Vec<_>>().join(","),
            RtspWatchSelection::Window(request) => pin(&request.slot, request.root),
        };
        let capture = selection.capture_origin().map_or_else(|| "null".into(), |capture| {
            format!("{{\"label\":\"operator_assumption\",\"start_ns\":{},\"uncertainty_ns\":{}}}", json(&capture.start_ns.0.to_string()), capture.uncertainty_ns)
        });
        format!(concat!("{{\"kind\":{},\"codec\":{},\"pins\":[{}],\"sensor\":{},\"stream\":{},",
            "\"authority_anchor\":{},\"receive_clock\":{},\"capture_origin\":{}}}"),
            json(selection.kind()), json(selection.codec().as_str()), pins, json(source.sensor.as_str()),
            json(source.stream.as_str()), json(&source.anchor.to_text()), json(&source.receive_clock.to_text()), capture)
    });
    let watch = attempt
        .watch_report()
        .map(|watch| watch.to_json(authority_sequence, None))
        .transpose()?
        .unwrap_or_else(|| "null".into());
    let all_recorded = native.map_or_else(
        || "null".into(),
        |n| (n.durable_pictures == attempt.catalogued_pictures()).to_string(),
    );
    Ok(format!(
        concat!(
            "{{\"attempt\":{},\"generation\":{},\"status\":{},\"start_root\":{},\"finish_root\":{},",
            "\"child_approval\":{},\"archive_namespace\":{},\"archive_path\":{},\"finish\":{},",
            "\"request_digest\":{},\"selection\":{},\"recorded_durable_pictures\":{},\"catalogued_pictures\":{},\"decoded_pictures\":{},",
            "\"recorded_pictures_without_catalog\":{},\"all_recorded_pictures_catalogued\":{},",
            "\"independent_analysis_epoch\":{},\"quiet_scene_proved\":false,\"original_rtp_custody_verified\":{},\"import\":{},\"watch\":{}}}"
        ),
        attempt.ordinal(),
        attempt.generation(),
        json(attempt.status().as_str()),
        json(&recorded.start.root.to_text()),
        optional_digest(recorded.finish_pin.map(|pin| pin.root)),
        json(&recorded.attempt.child_approval.to_text()),
        json(&recorded.attempt.archive_namespace.to_text()),
        json(&recorded.attempt.archive_path),
        finish,
        optional_digest(attempt.request_digest()),
        selection,
        optional_u64(attempt.recorded_durable_pictures()),
        attempt.catalogued_pictures(),
        attempt.decoded_pictures(),
        optional_u64(attempt.recorded_pictures_without_catalog()),
        all_recorded,
        attempt.import().is_some(),
        attempt.import().is_some(),
        import,
        watch
    ))
}
