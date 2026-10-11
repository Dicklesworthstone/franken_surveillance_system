#![forbid(unsafe_code)]
//! Bounded payload-free reporting and explicit accounting for every transferred retirement.

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_publication::LocalPublicationReceipt;
use fss_reference::rtsp::archive_pins::live::{JournaledLiveAvcArchive, JournaledLiveRetirement};
use fss_reference::rtsp::archive_pins::{ArchivePinAnchor, ArchivePinState, StoredArchivePin};
use fss_reference::rtsp::avc_client::AvcClientRetirement;
use fss_reference::rtsp::live_archive::LiveArchiveRetirement;
use fss_reference::rtsp::live_avc::LiveAvcRetirement;
use fss_reference::rtsp::live_avc::recording::LiveRecordingRetirement;
use fss_reference::rtsp::recording::{PreparedRecording, RecordingScope};
use fss_reference::rtsp::recording_archive::ArchiveSnapshot;
use fss_reference::rtsp::recording_capture::CaptureRetirement;
use fss_reference::rtsp::recording_collector::{CollectedSource, UnsealedRecording};
use fss_reference::rtsp::tcp::TcpTotals;
use std::io::{self, Write};

use super::super::plan::{FORMAT, Options};
use super::Failure;

const TERMINAL_RESERVE: usize = 16_384;

/// Byte bounded output with bounded EINTR retries. A failed/partial row is never retried.
fn write_bounded(out: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interrupts = 0;
    while !bytes.is_empty() {
        let bound = bytes.len().min(4096);
        match out.write(&bytes[..bound]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= bound => {
                bytes = &bytes[n..];
                interrupts = 0;
            }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupts < 7 => interrupts += 1,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
pub(super) struct Transcript<'a, W> {
    pub(super) out: &'a mut W,
    pub(super) used: usize,
    pub(super) maximum: usize,
    pub(super) sequence: u64,
    pub(super) io_failed: bool,
}
impl<W: Write> Transcript<'_, W> {
    pub(super) fn emit(
        &mut self,
        kind: &str,
        detail: String,
        terminal: bool,
    ) -> Result<(), Failure> {
        if self.io_failed {
            return Err(Failure::Output);
        }
        let row = object(&[
            ("schema", string(FORMAT)),
            ("sequence", self.sequence.to_string()),
            ("kind", string(kind)),
            ("detail", detail),
        ]) + "\n";
        let ceiling = self
            .maximum
            .saturating_sub(if terminal { 0 } else { TERMINAL_RESERVE });
        if row.len() > ceiling.saturating_sub(self.used) {
            return Err(Failure::Output);
        }
        self.used += row.len();
        if write_bounded(self.out, row.as_bytes())
            .and_then(|()| self.out.flush())
            .is_err()
        {
            self.io_failed = true;
            return Err(Failure::Output);
        }
        self.sequence += 1;
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct Statistics {
    pub(super) steps: u64,
    pub(super) connection_attempted: bool,
    pub(super) collected_pictures: u64,
    pub(super) skipped_pictures: u64,
    pub(super) durable_windows: usize,
    pub(super) durable_pictures: u64,
    pub(super) indexed_windows: usize,
    pub(super) durable_source_object_bytes: u64,
    pub(super) unselected_rtp_bytes: u64,
    pub(super) unsealed_rtp_bytes: u64,
    pub(super) unsealed_pictures: u64,
    pub(super) untimed_picture_bytes: u64,
    pub(super) unpublished_prepared_bytes: u64,
    pub(super) unpublished_prepared_pictures: u64,
    pub(super) unpublished_receiver_state: bool,
    pub(super) receiver_tail: bool,
    pub(super) input_ended: bool,
    pub(super) remote_session_may_exist: bool,
    pub(super) pending_request: bool,
    pub(super) totals: TcpTotals,
    pub(super) pending_window: Option<(ContentDigest, u64)>,
    pub(super) last_window: Option<(usize, String, ContentDigest)>,
    pub(super) snapshot_digest: Option<ContentDigest>,
    pub(super) journal_anchor: Option<ArchivePinAnchor>,
    pub(super) pins: ArchivePinState,
    pub(super) unrecorded_work_receipt: Option<String>,
}
impl Statistics {
    pub(super) fn snapshot(&mut self, snapshot: &ArchiveSnapshot) {
        self.durable_windows = snapshot.windows().len();
        self.durable_pictures = snapshot.windows().iter().map(|e| e.samples() as u64).sum();
        self.indexed_windows = snapshot.indexed_windows();
        if let Some(entry) = snapshot.windows().last() {
            self.last_window = Some((
                snapshot.windows().len() - 1,
                entry.slot().as_str().to_owned(),
                entry.root(),
            ));
        }
    }
    pub(super) fn observe(&mut self, capture: &JournaledLiveAvcArchive<'_, '_>) {
        if let Some(totals) = capture.totals() {
            self.totals = totals;
        }
        if let Some(snapshot) = capture.snapshot() {
            self.snapshot(snapshot);
        }
        self.journal_anchor = Some(capture.journal_anchor());
        self.pins = capture.pin_state().clone();
    }
    pub(super) fn client_retirement(&mut self, retired: &AvcClientRetirement) {
        self.remote_session_may_exist |= retired.session.remote_session_may_exist;
        self.pending_request |= retired.session.pending_cseq.is_some();
        self.unpublished_receiver_state |= retired.video.is_some()
            || retired.pending_events != 0
            || retired.partial_wire_bytes != 0;
    }
    pub(super) fn connection_retirement(&mut self, retired: &LiveAvcRetirement) {
        self.totals = retired.transport.totals;
        self.pending_request |=
            retired.transport.request.is_some() || retired.unqueued_request.is_some();
        self.client_retirement(&retired.protocol.client);
    }
    pub(super) fn unsealed(&mut self, pending: &UnsealedRecording) {
        self.unsealed_rtp_bytes += source_bytes(&pending.sources);
        self.unsealed_pictures += pending.pictures.len() as u64;
    }
    pub(super) fn prepared(&mut self, recording: &PreparedRecording) {
        self.unpublished_prepared_bytes += recording.byte_len() as u64;
        self.unpublished_prepared_pictures += recording.summary().samples as u64;
    }
    pub(super) fn capture_retirement(&mut self, retired: &CaptureRetirement) {
        self.unsealed(&retired.collection.pending);
        if let Some(ready) = &retired.collection.ready {
            self.prepared(ready);
        }
        if let Some(trailing) = &retired.trailing {
            self.unsealed(trailing);
        }
        if let Some(picture) = &retired.picture {
            self.untimed_picture_bytes += picture.byte_len() as u64;
        }
        self.unpublished_receiver_state |= retired.event.is_some();
    }
    pub(super) fn recording_retirement(&mut self, retired: &LiveRecordingRetirement) {
        if let Some(connection) = &retired.connection {
            self.connection_retirement(connection);
        }
        self.capture_retirement(&retired.capture);
        self.unpublished_receiver_state |= retired.unoffered_media.is_some();
    }
    pub(super) fn archive_retirement(&mut self, retired: &LiveArchiveRetirement) {
        if let Some(recording) = &retired.recording {
            self.recording_retirement(recording);
        }
        if let Some(archive) = &retired.archive {
            self.snapshot(&archive.snapshot);
            if let Some(pending) = &archive.pending {
                self.prepared(pending);
            }
        }
        if let Some(window) = &retired.unoffered_window {
            self.prepared(window);
        }
    }
    pub(super) fn retirement(&mut self, retired: &JournaledLiveRetirement) {
        if let Some(confirmation) = &retired.unrecorded_confirmation {
            self.unrecorded_work_receipt = Some(receipt_json(&confirmation.receipt));
        }
        self.archive_retirement(&retired.live.live);
        self.journal_anchor = Some(retired.journal_anchor);
        self.pins = retired.pins.clone();
    }
}
pub(super) fn source_bytes(sources: &[CollectedSource]) -> u64 {
    sources
        .iter()
        .map(|source| source.bytes().len() as u64)
        .sum()
}
pub(super) fn anchor_json(anchor: ArchivePinAnchor) -> String {
    object(&[
        ("sequence", anchor.sequence.to_string()),
        ("root", string(&anchor.root.to_text())),
    ])
}
pub(super) fn pin_json(pin: &StoredArchivePin) -> String {
    object(&[
        ("slot", string(pin.slot().as_str())),
        ("root", string(&pin.root().to_text())),
        (
            "retirement_digest",
            string(&pin.retirement_digest().to_text()),
        ),
        ("new_payload_bytes", pin.new_payload_bytes().to_string()),
    ])
}
pub(super) fn scope_json(scope: &RecordingScope) -> String {
    object(&[
        ("sensor_id", string(scope.sensor.as_str())),
        ("stream_id", string(scope.stream.as_str())),
        ("generation", scope.generation.to_string()),
        ("anchor", string(&scope.anchor.to_text())),
        ("receive_clock", string(&scope.receive_clock.to_text())),
    ])
}
pub(super) fn receipt_json(receipt: &LocalPublicationReceipt) -> String {
    object(&[
        ("slot", string(receipt.slot.as_str())),
        ("root", string(&receipt.root.to_text())),
        ("record_digest", string(&receipt.record_digest.to_text())),
    ])
}
pub(super) fn terminal(
    options: &Options,
    stats: &Statistics,
    result: &Result<(), Failure>,
) -> String {
    object(&[
        ("complete", result.is_ok().to_string()),
        (
            "stop_cause",
            string(
                result
                    .as_ref()
                    .err()
                    .map_or("owner_stopped", |error| error.cause()),
            ),
        ),
        (
            "error_id",
            result
                .as_ref()
                .err()
                .map_or_else(|| "null".into(), |error| string(error.code())),
        ),
        (
            "requested_pictures",
            options.stop_after_pictures.to_string(),
        ),
        ("collected_pictures", stats.collected_pictures.to_string()),
        ("durable_pictures", stats.durable_pictures.to_string()),
        ("skipped_before_idr", stats.skipped_pictures.to_string()),
        ("durable_windows", stats.durable_windows.to_string()),
        ("indexed_windows", stats.indexed_windows.to_string()),
        ("source", scope_json(&options.recording_config().scope)),
        (
            "archive_namespace",
            string(&options.pin_scope().archive_namespace.to_text()),
        ),
        (
            "journal_id",
            string(&options.pin_scope().journal_id.to_text()),
        ),
        (
            "journal_anchor",
            stats
                .journal_anchor
                .map_or_else(|| "null".into(), anchor_json),
        ),
        (
            "candidate_pin",
            stats
                .pins
                .candidate()
                .map_or_else(|| "null".into(), pin_json),
        ),
        (
            "confirmed_pin",
            stats
                .pins
                .last_confirmed()
                .map_or_else(|| "null".into(), pin_json),
        ),
        (
            "unrecorded_work_receipt",
            stats
                .unrecorded_work_receipt
                .clone()
                .unwrap_or_else(|| "null".into()),
        ),
        (
            "last_durable_window",
            stats.last_window.as_ref().map_or_else(
                || "null".into(),
                |(ordinal, slot, root)| {
                    object(&[
                        ("ordinal", ordinal.to_string()),
                        ("slot", string(slot)),
                        ("root", string(&root.to_text())),
                    ])
                },
            ),
        ),
        (
            "snapshot_digest",
            stats
                .snapshot_digest
                .map_or_else(|| "null".into(), |root| string(&root.to_text())),
        ),
        (
            "durable_source_object_bytes",
            stats.durable_source_object_bytes.to_string(),
        ),
        // These are different representations, not additive disjoint byte totals. Original
        // RTP retained inside verified windows does not imply custody of the full TCP stream.
        (
            "raw_tcp_bytes_not_retained",
            stats.totals.received_bytes.to_string(),
        ),
        (
            "raw_tcp_retention",
            string("omitted_entire_wire_representation"),
        ),
        (
            "rtp_retention",
            string("selected_window_original_datagrams"),
        ),
        ("control_and_rtcp_retention", string("omitted")),
        (
            "unselected_rtp_bytes",
            stats.unselected_rtp_bytes.to_string(),
        ),
        ("unsealed_rtp_bytes", stats.unsealed_rtp_bytes.to_string()),
        ("unsealed_pictures", stats.unsealed_pictures.to_string()),
        (
            "untimed_picture_bytes",
            stats.untimed_picture_bytes.to_string(),
        ),
        (
            "unpublished_prepared_bytes",
            stats.unpublished_prepared_bytes.to_string(),
        ),
        (
            "unpublished_prepared_pictures",
            stats.unpublished_prepared_pictures.to_string(),
        ),
        (
            "unpublished_receiver_state",
            stats.unpublished_receiver_state.to_string(),
        ),
        ("receiver_tail_observed", stats.receiver_tail.to_string()),
        (
            "connection_attempted",
            stats.connection_attempted.to_string(),
        ),
        ("connections_retried", "0".into()),
        ("peer_eof", stats.totals.peer_eof.to_string()),
        ("input_end_observed", stats.input_ended.to_string()),
        ("received_bytes", stats.totals.received_bytes.to_string()),
        ("sent_bytes", stats.totals.sent_bytes.to_string()),
        ("read_calls", stats.totals.read_calls.to_string()),
        ("write_calls", stats.totals.write_calls.to_string()),
        ("steps", stats.steps.to_string()),
        (
            "remote_session_may_exist",
            stats.remote_session_may_exist.to_string(),
        ),
        ("unsettled_request", stats.pending_request.to_string()),
        ("capture_time", string("unknown")),
        (
            "timing_basis",
            string("caller_fixed_cadence_validated_against_rtp"),
        ),
        ("pixel_decode", "false".into()),
        ("capture_continuity", "false".into()),
        ("coverage_certified", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ])
}
