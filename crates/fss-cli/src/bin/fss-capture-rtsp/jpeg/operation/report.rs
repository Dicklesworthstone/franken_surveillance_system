#![forbid(unsafe_code)]
//! Bounded independently retainable receipts; compressed bytes and secrets never enter JSON.

use super::*;
use crate::jpeg::plan::SCHEMA;
use fss_reference::rtsp::datagram_archive::{DatagramPin, DatagramRecord};

const TERMINAL_RESERVE: usize = 8192;

pub(crate) struct Report {
    pub(crate) result: Result<(), &'static str>,
    pub(crate) pin: Option<DatagramPin>,
    pub(crate) pending: Option<DatagramPin>,
    pub(super) pictures: u64,
    pub(super) source_work: u64,
    pub(super) decode_work: u64,
    pub(super) steps: u64,
    pub(super) configuration: Option<ContentDigest>,
    pub(super) reduced_rtcp: Option<bool>,
    pub(super) input_ended: bool,
    pub(super) prefix_exhausted: bool,
    pub(super) remote_session_may_exist: bool,
    pub(super) discarded_images: u64,
    pub(super) discarded_image_bytes: u64,
    pub(super) delivery_gaps: u64,
    pub(super) packet_refusals: u64,
    pub(super) decode_refusals: u64,
    pub(super) rtcp_refusals: u64,
    pub(super) retired_queued_packets: u64,
    pub(super) retired_queued_bytes: u64,
    pub(super) unretained_wire_bytes: u64,
    pub(super) received_wire_bytes: u64,
    pub(super) sent_wire_bytes: u64,
    pub(super) withheld_events: u64,
    used: usize,
    maximum: usize,
    sequence: u64,
    io_failed: bool,
    replay: bool,
}

impl Report {
    pub(super) fn new(options: &Options) -> Self {
        Self {
            result: Err(STATE),
            pin: None,
            pending: None,
            pictures: 0,
            source_work: 0,
            decode_work: 0,
            steps: 0,
            configuration: None,
            reduced_rtcp: None,
            input_ended: false,
            prefix_exhausted: false,
            remote_session_may_exist: false,
            discarded_images: 0,
            discarded_image_bytes: 0,
            delivery_gaps: 0,
            packet_refusals: 0,
            decode_refusals: 0,
            rtcp_refusals: 0,
            retired_queued_packets: 0,
            retired_queued_bytes: 0,
            unretained_wire_bytes: 0,
            received_wire_bytes: 0,
            sent_wire_bytes: 0,
            withheld_events: 0,
            used: 0,
            maximum: options.report_bytes,
            sequence: 0,
            io_failed: false,
            replay: options.replay.is_some(),
        }
    }
    pub(crate) fn recovery_required(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn emit(
        &mut self,
        owner: &dyn Owner,
        out: &mut dyn Write,
        kind: &str,
        data: String,
    ) -> Result<(), &'static str> {
        self.row(out, Some(owner), "observed", kind, data, false)
    }

    pub(crate) fn finish(
        &mut self,
        out: &mut dyn Write,
        runtime: String,
        closure_failed: bool,
    ) -> Result<(), &'static str> {
        if closure_failed && self.result.is_ok() {
            self.result = Err("ERR-CAPTURE-RTSP-AUTHORITY-001");
        }
        let data = object(&[
            (
                "mode",
                string(if self.replay { "replay" } else { "capture" }),
            ),
            (
                "complete",
                (self.result.is_ok() && !closure_failed).to_string(),
            ),
            (
                "error",
                self.result.err().map_or_else(|| "null".into(), string),
            ),
            ("source_prefix", self.pin.map_or_else(|| "null".into(), pin)),
            (
                "unconfirmed_candidate",
                self.pending.map_or_else(|| "null".into(), pin),
            ),
            (
                "recovery_required",
                (self.recovery_required() || closure_failed).to_string(),
            ),
            ("validated_pictures", self.pictures.to_string()),
            (
                "configuration_evidence",
                self.configuration
                    .map_or_else(|| "null".into(), |d| string(&d.to_text())),
            ),
            (
                "reduced_rtcp",
                self.reduced_rtcp
                    .map_or_else(|| "null".into(), |b| b.to_string()),
            ),
            ("steps", self.steps.to_string()),
            ("source_work", self.source_work.to_string()),
            ("decode_work", self.decode_work.to_string()),
            ("actual_socket_eof", self.input_ended.to_string()),
            (
                "selected_prefix_exhausted",
                self.prefix_exhausted.to_string(),
            ),
            (
                "remote_session_may_exist",
                self.remote_session_may_exist.to_string(),
            ),
            ("received_wire_bytes", self.received_wire_bytes.to_string()),
            ("sent_wire_bytes", self.sent_wire_bytes.to_string()),
            (
                "unretained_wire_tail_bytes",
                self.unretained_wire_bytes.to_string(),
            ),
            (
                "retired_queued_packets",
                self.retired_queued_packets.to_string(),
            ),
            (
                "retired_queued_bytes",
                self.retired_queued_bytes.to_string(),
            ),
            (
                "discarded_incomplete_images",
                self.discarded_images.to_string(),
            ),
            (
                "discarded_incomplete_image_bytes",
                self.discarded_image_bytes.to_string(),
            ),
            ("delivery_gaps", self.delivery_gaps.to_string()),
            ("reconstruction_refusals", self.packet_refusals.to_string()),
            ("decode_refusals", self.decode_refusals.to_string()),
            ("invalid_rtcp", self.rtcp_refusals.to_string()),
            ("withheld_events", self.withheld_events.to_string()),
            ("capture_clock", "null".into()),
            ("source_eof_asserted", "false".into()),
            ("coverage_asserted", "false".into()),
            ("pixels_retained", "false".into()),
            ("runtime", runtime),
        ]);
        self.row(out, None, "terminal", "operation_finished", data, true)?;
        self.result
    }

    fn row(
        &mut self,
        out: &mut dyn Write,
        owner: Option<&dyn Owner>,
        phase: &str,
        kind: &str,
        data: String,
        terminal: bool,
    ) -> Result<(), &'static str> {
        if self.io_failed {
            return Err(OUTPUT);
        }
        let row = object(&[
            ("schema", string(SCHEMA)),
            ("phase", string(phase)),
            ("sequence", self.sequence.to_string()),
            ("kind", string(kind)),
            ("data", data),
        ]) + "\n";
        let maximum = self
            .maximum
            .saturating_sub(if terminal { 0 } else { TERMINAL_RESERVE });
        let after = self.used.checked_add(row.len()).ok_or(OUTPUT)?;
        if after > maximum {
            return Err(OUTPUT);
        }
        if let Some(owner) = owner {
            owner.checkpoint(Effect::Output)?;
        }
        self.used = after;
        let mut offset = 0;
        let mut interrupted = 0_u8;
        while offset < row.len() {
            if let Some(owner) = owner {
                if let Err(error) = owner.checkpoint(Effect::Output) {
                    self.io_failed = offset != 0;
                    return Err(error);
                }
            }
            match out.write(&row.as_bytes()[offset..(offset + 4096).min(row.len())]) {
                Ok(0) => {
                    self.io_failed = true;
                    return Err(OUTPUT);
                }
                Ok(n) => {
                    offset += n;
                    interrupted = 0;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted && interrupted < 7 => {
                    interrupted += 1;
                }
                Err(_) => {
                    self.io_failed = true;
                    return Err(OUTPUT);
                }
            }
        }
        if out.flush().is_err() {
            self.io_failed = true;
            return Err(OUTPUT);
        }
        self.sequence += 1;
        if let Some(owner) = owner {
            owner.checkpoint(Effect::Output)?;
        }
        Ok(())
    }
}

pub(super) fn pin(pin: DatagramPin) -> String {
    object(&[
        ("scope", string(&pin.scope.to_text())),
        ("head", string(&pin.head.to_text())),
        ("datagrams", pin.datagrams.to_string()),
        ("payload_bytes", pin.payload_bytes.to_string()),
    ])
}
pub(super) fn record(record: DatagramRecord) -> String {
    object(&[
        ("prefix", pin(record.pin)),
        ("channel", record.channel.to_string()),
        ("received_ns", record.received_ns.to_string()),
        ("payload_digest", string(&record.payload_digest.to_text())),
        ("payload_bytes", record.payload_bytes.to_string()),
    ])
}
