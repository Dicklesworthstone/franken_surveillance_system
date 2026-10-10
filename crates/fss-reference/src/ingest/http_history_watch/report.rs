#![forbid(unsafe_code)]
//! Bounded metadata-only report; native watch rendering owns every proposal and publication hint.

use fss_core::ContentDigest;

use super::{
    HTTP_HISTORY_WATCH_REPORT_SCHEMA, HttpHistoryWatchError, HttpHistoryWatchGeneration,
    HttpHistoryWatchReservation, Result,
};
use crate::http_reconnect_history::{BoundaryOutcome, ReconnectHistoryPin};
use crate::ingest::long_dwell::json;

/// Complete selected-history result. Completed imports are durable; the proposals remain read-only.
#[derive(Debug)]
pub struct HttpHistoryWatchReport {
    pub(super) plan_digest: ContentDigest,
    pub(super) history: ReconnectHistoryPin,
    pub(super) reservation: HttpHistoryWatchReservation,
    pub(super) generations: Vec<HttpHistoryWatchGeneration>,
    pub(super) maximum_report_bytes: usize,
    pub(super) source_reads: u64,
    pub(super) source_bytes: u64,
    pub(super) screened: bool,
}
impl HttpHistoryWatchReport {
    /// Exact processing approval, distinct from capture and event approvals.
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Exact independently selected ended-history prefix, never a discovered latest head.
    pub const fn history_pin(&self) -> ReconnectHistoryPin {
        self.history
    }
    /// Fixed whole-invocation reservation admitted before processing.
    pub fn reservation(&self) -> &HttpHistoryWatchReservation {
        &self.reservation
    }
    /// Every selected connection in native order, including empty or incomplete responses.
    pub fn generations(&self) -> &[HttpHistoryWatchGeneration] {
        &self.generations
    }
    /// Render a complete bounded report. An empty hints slice suppresses all commands; otherwise
    /// it must contain exactly one optional native `fss-event watch --stream-watch` rerun hint per
    /// generation. Native watch rendering suppresses blocked or already-published proposals.
    pub fn to_json(
        &self,
        authority_sequence: u64,
        approve_hints: &[Option<String>],
    ) -> Result<String> {
        if (!approve_hints.is_empty() && approve_hints.len() != self.generations.len())
            || approve_hints.iter().flatten().any(|hint| hint.len() > 8192)
        {
            return Err(HttpHistoryWatchError::Invalid(
                "generation publication hints",
            ));
        }
        let r = self.reservation;
        let mut output = format!(
            concat!(
                "{{\"format\":{},\"plan_digest\":{},\"history\":{{\"session\":{},\"root\":{},\"connections\":{}}},",
                "\"source_reads\":{},\"source_bytes\":{},\"authority_sequence\":{},\"screened\":{},",
                "\"reservation\":{{\"connections\":{},\"frames\":{},\"original_bytes\":{},\"source_read_bytes\":{},",
                "\"pixel_samples\":{},\"assignment_work\":{},\"jpeg_work\":{},\"trace_bytes\":{},\"report_bytes\":{}}},",
                "\"processing\":\"offline_exact_history\",\"event_publication_authorized\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"network_resumed\":false,",
                "\"tracker_continuity_across_generations\":false,\"generations\":["
            ),
            json(HTTP_HISTORY_WATCH_REPORT_SCHEMA),
            json(&self.plan_digest.to_text()),
            json(&self.history.session.to_text()),
            json(&self.history.root.to_text()),
            self.history.connections,
            self.source_reads,
            self.source_bytes,
            authority_sequence,
            self.screened,
            r.connections,
            r.frames,
            r.original_bytes,
            r.source_read_bytes,
            r.pixel_samples,
            r.assignment_work,
            r.jpeg_work,
            r.trace_bytes,
            r.report_bytes
        );
        for (index, generation) in self.generations.iter().enumerate() {
            let hint = approve_hints.get(index).and_then(Option::as_deref);
            let projection = generation_json(generation, authority_sequence, hint)?;
            let required = output
                .len()
                .checked_add(projection.len())
                .and_then(|size| size.checked_add(3))
                .ok_or(HttpHistoryWatchError::Limit)?;
            if required > self.maximum_report_bytes {
                return Err(HttpHistoryWatchError::Limit);
            }
            output
                .try_reserve(projection.len() + 1)
                .map_err(|_| HttpHistoryWatchError::Limit)?;
            if index != 0 {
                output.push(',');
            }
            output.push_str(&projection);
        }
        output.push_str("]}");
        if output.len() > self.maximum_report_bytes {
            return Err(HttpHistoryWatchError::Limit);
        }
        Ok(output)
    }
}

fn generation_json(
    generation: &HttpHistoryWatchGeneration,
    sequence: u64,
    hint: Option<&str>,
) -> Result<String> {
    let b = generation.binding();
    let s = generation.source();
    let p = generation.prefix();
    let attempted = match generation.native_outcome() {
        BoundaryOutcome::ConnectFailed { attempted } => attempted.to_string(),
        _ => "null".to_owned(),
    };
    let imported = generation.import().map_or_else(|| "null".to_owned(), |receipt| {
        format!(concat!("{{\"identity\":{},\"root\":{},\"manifest\":{},\"original_proof\":{},\"frames\":{},",
            "\"capture_time_label\":{},\"ending\":{},\"reused\":{}}}"),
            json(&receipt.import_identity.to_text()), json(&receipt.import_root.to_text()),
            json(&receipt.manifest_digest.to_text()), json(&receipt.proof.to_text()), receipt.frames,
            json(receipt.capture_time_label), json(receipt.ending.as_str()), receipt.reused)
    });
    let watch = generation.watch_report().map_or_else(
        || Ok("null".to_owned()),
        |report| report.to_json(sequence, hint),
    )?;
    Ok(format!(
        concat!(
            "{{\"connection\":{},\"generation\":{},\"status\":{},\"native_outcome\":{},\"connect_attempted\":{},",
            "\"source\":{{\"stream_source\":{},\"generation\":{},\"receive_clock\":{},\"retention_evidence\":{}}},",
            "\"prefix\":{{\"scope\":{},\"head\":{},\"reads\":{},\"bytes\":{}}},",
            "\"binding\":{{\"sensor\":{},\"stream\":{},\"receive_time_ns\":{},\"capture_start_ns\":{},",
            "\"capture_uncertainty_ns\":{},\"assumed_fps\":{},\"capture_time_label\":\"operator_assumption\"}},",
            "\"quiet_scene_proved\":false,\"import\":{},\"watch\":{}}}"
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
        imported,
        watch
    ))
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
