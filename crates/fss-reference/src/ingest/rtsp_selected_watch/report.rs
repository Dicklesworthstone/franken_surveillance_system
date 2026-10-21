#![forbid(unsafe_code)]
//! Complete selected-only projection; native watch rendering owns candidate semantics.

use fss_core::{ContentDigest, LedgerAnchor};

use super::{
    RTSP_SELECTED_WATCH_REPORT_SCHEMA, Result, RtspSelectedWatchError,
    RtspSelectedWatchReservation, RtspSelectedWatchResult, RtspWatchSelection,
};
use crate::ingest::long_dwell::json;

/// Completed finite selections. Imports are durable, while native watch proposals are read-only.
/// This report cannot certify omitted recordings, empty attempts, or a complete reconnect history.
#[derive(Debug)]
pub struct RtspSelectedWatchReport {
    pub(super) plan_digest: ContentDigest,
    pub(super) reservation: RtspSelectedWatchReservation,
    pub(super) selections: Vec<RtspSelectedWatchResult>,
    pub(super) basis: LedgerAnchor,
    pub(super) maximum_report_bytes: usize,
    pub(super) screened: bool,
}
impl RtspSelectedWatchReport {
    /// Exact source selection and processing-policy approval identity.
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Fixed whole-invocation ceilings admitted before any retained import.
    pub fn reservation(&self) -> &RtspSelectedWatchReservation {
        &self.reservation
    }
    /// Every selected recording in owner-supplied order, with independent tracker state.
    pub fn selections(&self) -> &[RtspSelectedWatchResult] {
        &self.selections
    }
    /// Common final destination anchor, after all imports and before any analysis.
    pub fn analysis_basis(&self) -> &LedgerAnchor {
        &self.basis
    }

    /// Complete bounded JSON; no truncation, publication commands or omitted selection rows.
    pub fn to_json(&self, authority_sequence: u64) -> Result<String> {
        let r = self.reservation;
        let mut output = format!(
            concat!(
                "{{\"format\":{},\"plan_digest\":{},\"authority_sequence\":{},",
                "\"analysis_basis_sequence\":{},\"analysis_basis_root\":{},\"screened\":{},",
                "\"reservation\":{{\"selections\":{},\"frames\":{},\"original_bytes\":{},\"media_bytes\":{},",
                "\"source_read_bytes\":{},\"pixel_samples\":{},\"screening_pixel_samples\":{},\"assignment_work\":{},\"jpeg_work\":{},\"trace_bytes\":{},\"report_bytes\":{}}},",
                "\"processing\":\"offline_selected_recordings\",\"selection_order\":\"owner_supplied\",",
                "\"campaign_history_verified\":false,\"complete_campaign\":false,\"empty_attempt_coverage\":false,",
                "\"tracker_continuity_across_selections\":false,\"event_publication_authorized\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"network_resumed\":false,\"selections\":["
            ),
            json(RTSP_SELECTED_WATCH_REPORT_SCHEMA),
            json(&self.plan_digest.to_text()),
            authority_sequence,
            self.basis.commit_sequence,
            json(&self.basis.state_root.to_text()),
            self.screened,
            r.selections,
            r.frames,
            r.original_bytes,
            r.media_bytes,
            r.source_read_bytes,
            r.pixel_samples,
            r.screening_pixel_samples,
            r.assignment_work,
            r.jpeg_work,
            r.trace_bytes,
            r.report_bytes
        );
        for (index, selected) in self.selections.iter().enumerate() {
            let row = selection_json(index + 1, selected, authority_sequence)?;
            let length = output
                .len()
                .checked_add(row.len())
                .and_then(|size| size.checked_add(3))
                .ok_or(RtspSelectedWatchError::Limit)?;
            if length > self.maximum_report_bytes {
                return Err(RtspSelectedWatchError::Limit);
            }
            output
                .try_reserve(row.len() + 1)
                .map_err(|_| RtspSelectedWatchError::Limit)?;
            if index != 0 {
                output.push(',');
            }
            output.push_str(&row);
        }
        output.push_str("]}");
        if output.len() > self.maximum_report_bytes {
            return Err(RtspSelectedWatchError::Limit);
        }
        Ok(output)
    }
}

fn selection_json(
    ordinal: usize,
    selected: &RtspSelectedWatchResult,
    authority_sequence: u64,
) -> Result<String> {
    let request = selected.selection();
    let source = request.source();
    let capture = request
        .capture_origin()
        .ok_or(RtspSelectedWatchError::Invalid("capture origin"))?;
    let import = selected.import();
    let pin = |slot: &fss_publication::SlotName, root: ContentDigest| {
        format!(
            "{{\"slot\":{},\"root\":{}}}",
            json(slot.as_str()),
            json(&root.to_text())
        )
    };
    let pins = match request {
        RtspWatchSelection::Window(r) => pin(&r.slot, r.root),
        RtspWatchSelection::Catalog(r) => pin(&r.slot, r.root),
        RtspWatchSelection::Pages(r) => r
            .pages
            .iter()
            .map(|page| pin(&page.slot, page.root))
            .collect::<Vec<_>>()
            .join(","),
    };
    let watch = selected.watch_report().to_json(authority_sequence, None)?;
    Ok(format!(
        concat!(
            "{{\"selection\":{},\"kind\":{},\"request_digest\":{},\"codec\":{},\"pins\":[{}],",
            "\"source\":{{\"sensor\":{},\"stream\":{},\"generation\":{},\"authority_anchor\":{},\"receive_clock\":{}}},",
            "\"capture_time_label\":\"operator_assumption\",\"capture_start_ns\":{},\"capture_uncertainty_ns\":{},",
            "\"status\":\"analyzed\",\"independent_analysis_epoch\":true,\"quiet_scene_proved\":false,",
            "\"import\":{{\"identity\":{},\"root\":{},\"manifest\":{},\"original_proof\":{},",
            "\"frames\":{},\"windows\":{},\"pages\":{},\"reused\":{}}},\"watch\":{}}}"
        ),
        ordinal,
        json(request.kind()),
        json(&selected.request_digest().to_text()),
        json(request.codec().as_str()),
        pins,
        json(source.sensor.as_str()),
        json(source.stream.as_str()),
        source.generation,
        json(&source.anchor.to_text()),
        json(&source.receive_clock.to_text()),
        json(&capture.start_ns.0.to_string()),
        capture.uncertainty_ns,
        json(&import.import_identity.to_text()),
        json(&import.import_root.to_text()),
        json(&import.manifest_digest.to_text()),
        json(&import.proof.to_text()),
        import.frames,
        selected.windows(),
        selected.pages(),
        import.reused,
        watch
    ))
}
