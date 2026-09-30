#![forbid(unsafe_code)]
//! Bounded native execution. The recorder, not this presentation loop, owns retry semantics.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint,
};
use fss_reference::ReplayCx;
use fss_reference::ingest::http_archive::HttpWirePin;
use fss_reference::ingest::http_camera::{
    HttpCameraAuthority, HttpCameraDenial, HttpCameraOperation, HttpCameraRoute,
};
use fss_reference::ingest::http_reconnect::{HttpReconnectOutcome, HttpReconnectStop};
use fss_reference::ingest::http_reconnect_recording::{
    HttpReconnectBoundary, HttpReconnectRecording, HttpReconnectRecordingError,
    HttpReconnectRecordingStep,
};
use fss_reference::ingest::http_recording::HttpRecordingAccess;

use super::plan::{FORMAT, Options, RESERVE, reservation_json};
use super::{decode, privacy};

const STORAGE_CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

/// Bound EINTR retries and write sizes; flushing is a sink acknowledgement, not durability proof.
pub(super) fn write_bounded(out: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interrupts = 0;
    while !bytes.is_empty() {
        let count = bytes.len().min(4096);
        match out.write(&bytes[..count]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= count => {
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
struct Transcript<'a, W> {
    out: &'a mut W,
    used: usize,
    maximum: usize,
    sequence: u64,
    io_failed: bool,
}
impl<W: Write> Transcript<'_, W> {
    fn emit(&mut self, kind: &str, detail: String, terminal: bool) -> Result<(), Failure> {
        // A failed write may have exposed a partial row; a failed flush leaves acknowledgement
        // indeterminate. Neither permits another row, including the terminal report, on this sink.
        if self.io_failed {
            return Err(Failure::Output);
        }
        let row = object(&[
            ("format", string(FORMAT)),
            ("sequence", self.sequence.to_string()),
            ("kind", string(kind)),
            ("detail", detail),
        ]) + "\n";
        let limit = self
            .maximum
            .saturating_sub(if terminal { 0 } else { RESERVE });
        if row.len() > limit.saturating_sub(self.used) {
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

struct Owner<'a> {
    cx: &'a ReplayCx,
    authority: &'a ContextAuthority,
    routes: Vec<HttpCameraRoute>,
    start: Instant,
    deadline: u64,
}
impl Owner<'_> {
    fn now(&self) -> Result<u64, HttpCameraDenial> {
        let now = u64::try_from(self.start.elapsed().as_nanos())
            .map_err(|_| HttpCameraDenial::Deadline)?;
        if now >= self.deadline {
            return Err(HttpCameraDenial::Deadline);
        }
        Ok(now)
    }
    fn live(&self, stage: &'static str) -> Result<(), HttpCameraDenial> {
        self.cx
            .checkpoint(stage)
            .map_err(|_| HttpCameraDenial::Cancelled)?;
        if self.authority.cancellation_reason.is_some() {
            return Err(HttpCameraDenial::Cancelled);
        }
        self.now()?;
        Ok(())
    }
    fn decode_authority(&self) -> Result<(), HttpCameraDenial> {
        self.live("capture_reconnect:decode")?;
        if !self.authority.has_capability("CAP-MEDIA-DECODE-001") {
            return Err(HttpCameraDenial::Unauthorized);
        }
        Ok(())
    }
    fn access(&self) -> Result<HttpRecordingAccess<'_>, HttpCameraDenial> {
        Ok(HttpRecordingAccess {
            now_ns: self.now()?,
            camera: self,
            storage: self,
        })
    }
    fn pause(&self, not_before: Option<u64>) -> Result<(), HttpCameraDenial> {
        self.live("capture_reconnect:wait")?;
        let now = self.now()?;
        let delay = not_before.map_or(1_000_000, |due| due.saturating_sub(now).min(10_000_000));
        if delay > 0 {
            std::thread::sleep(Duration::from_nanos(delay.min(self.deadline - now)));
        }
        self.live("capture_reconnect:wait")
    }
}
impl HttpCameraAuthority for Owner<'_> {
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        operation: HttpCameraOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpCameraDenial> {
        self.live("capture_reconnect:network")?;
        if !self.routes.contains(route)
            || deadline != self.deadline
            || now >= deadline
            || !self.authority.has_capability("CAP-ADAPTER-NET-001")
            || !STORAGE_CAPS
                .iter()
                .all(|cap| self.authority.has_capability(cap))
            || matches!(
                operation,
                HttpCameraOperation::Analyze | HttpCameraOperation::ReleaseResult
            )
        {
            return Err(HttpCameraDenial::Unauthorized);
        }
        Ok(())
    }
}
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.live("capture_reconnect:storage").is_err()
            || !STORAGE_CAPS
                .iter()
                .all(|cap| self.authority.has_capability(cap))
    }
}

#[derive(Debug)]
enum Failure {
    Source(HttpReconnectRecordingError),
    Authority(HttpCameraDenial),
    Output,
    FrameLimit,
    Inconsistent,
    Stopped(HttpReconnectStop),
    Decode(decode::Failure),
}
impl From<HttpReconnectRecordingError> for Failure {
    fn from(e: HttpReconnectRecordingError) -> Self {
        Self::Source(e)
    }
}
impl From<HttpCameraDenial> for Failure {
    fn from(e: HttpCameraDenial) -> Self {
        Self::Authority(e)
    }
}
impl Failure {
    fn code(&self) -> &'static str {
        match self {
            Self::Source(_) => "ERR-CAPTURE-RECONNECT-SOURCE-001",
            Self::Authority(_) => "ERR-CAPTURE-RECONNECT-AUTHORITY-001",
            Self::Output => "ERR-CAPTURE-RECONNECT-OUTPUT-001",
            Self::FrameLimit | Self::Stopped(_) => "ERR-CAPTURE-RECONNECT-LIMIT-001",
            Self::Inconsistent => "ERR-CAPTURE-RECONNECT-STATE-001",
            Self::Decode(error) => error.code(),
        }
    }
    fn reason(&self) -> String {
        match self {
            Self::Source(e) => e.to_string(),
            Self::Authority(e) => format!("owner authority refused: {e:?}"),
            Self::Output => "bounded transcript sink refused; preserve prior complete pins".into(),
            Self::FrameLimit => "per-generation frame allowance exhausted; not EOF".into(),
            Self::Inconsistent => {
                "source boundary or generation disagrees with the frozen plan".into()
            }
            Self::Stopped(reason) => format!("native reacquisition stopped: {reason:?}"),
            Self::Decode(error) => error.to_string(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum End {
    FinalResponseComplete,
    RequestedCount,
}
#[derive(Default)]
struct Statistics {
    frames: u64,
    // A released original frame whose optional decode failed is recoverable through this key
    // and its durable prefix, not by silently retrying the network or widening the budget.
    decode_pending: Option<(u64, u64, [u8; 32])>,
    per_generation: BTreeMap<u64, u64>,
    // At most the explicitly reserved generation count, never a frame-sized history.
    prefixes: BTreeMap<u64, HttpWirePin>,
    boundaries: Vec<(HttpReconnectBoundary, bool)>,
}

fn sha_bytes(bytes: [u8; 32]) -> String {
    format!(
        "sha256:{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn pin_json(pin: HttpWirePin) -> String {
    object(&[
        ("scope", string(&pin.scope.to_text())),
        ("head", string(&pin.head.to_text())),
        ("reads", pin.reads.to_string()),
        ("bytes", pin.bytes.to_string()),
    ])
}
fn boundary_json(boundary: HttpReconnectBoundary, released: bool) -> String {
    let receipt = boundary.source;
    let (outcome, reason) = match receipt.outcome {
        HttpReconnectOutcome::Complete => ("native_complete", "null".into()),
        HttpReconnectOutcome::ConnectFailed { reason, .. } => {
            ("connect_failed", string(&reason.to_string()))
        }
        HttpReconnectOutcome::SourceFailed(reason) => {
            ("source_failed", string(&reason.to_string()))
        }
    };
    object(&[
        ("connection", receipt.connection.to_string()),
        ("source", string(&sha_bytes(receipt.source.source))),
        ("generation", string(&receipt.source.generation.to_string())),
        ("outcome", string(outcome)),
        ("reason", reason),
        ("prefix", pin_json(boundary.prefix)),
        ("admitted_ns", string(&receipt.admitted_ns.to_string())),
        (
            "next_generation",
            receipt
                .next_source
                .map_or_else(|| "null".into(), |s| string(&s.generation.to_string())),
        ),
        (
            "retry_at_ns",
            receipt
                .retry_at_ns
                .map_or_else(|| "null".into(), |t| string(&t.to_string())),
        ),
        (
            "stop",
            receipt
                .stop
                .map_or_else(|| "null".into(), |s| string(&format!("{s:?}"))),
        ),
        ("received_bytes", receipt.totals.received_bytes.to_string()),
        ("frames_parsed", receipt.totals.frames.to_string()),
        ("peer_eof", receipt.totals.peer_eof.to_string()),
        ("released", released.to_string()),
        ("capture_continuity", "false".into()),
        ("durable_completion_root", "null".into()),
    ])
}
fn stopped(last: Option<HttpReconnectBoundary>) -> Result<End, Failure> {
    let boundary = last.ok_or(Failure::Inconsistent)?;
    match (boundary.source.outcome, boundary.source.stop) {
        (
            HttpReconnectOutcome::Complete,
            Some(HttpReconnectStop::Complete | HttpReconnectStop::ConnectionsExhausted),
        ) => Ok(End::FinalResponseComplete),
        (_, Some(reason)) => Err(Failure::Stopped(reason)),
        _ => Err(Failure::Inconsistent),
    }
}

#[allow(clippy::too_many_arguments)]
fn drive<W: Write>(
    options: &Options,
    recording: &mut HttpReconnectRecording,
    publisher: &mut LocalRootPublisher,
    owner: &Owner<'_>,
    log: &mut Transcript<'_, W>,
    stats: &mut Statistics,
    mut decoder: Option<&mut decode::Decoder>,
    privacy: Option<&privacy::Context>,
) -> Result<End, Failure> {
    loop {
        match recording.poll(publisher, owner.access()?)? {
            HttpReconnectRecordingStep::Connected(basis) => {
                if !options.generations.contains(&basis.generation)
                    || basis.source != options.source.bytes()
                {
                    return Err(Failure::Inconsistent);
                }
                log.emit(
                    "connected",
                    object(&[
                        ("generation", string(&basis.generation.to_string())),
                        ("stream_continuity", "false".into()),
                    ]),
                    false,
                )?;
            }
            HttpReconnectRecordingStep::Advanced => {}
            HttpReconnectRecordingStep::Pending => owner.pause(None)?,
            HttpReconnectRecordingStep::Waiting { not_before_ns } => {
                owner.pause(Some(not_before_ns))?
            }
            HttpReconnectRecordingStep::WirePrepared(plan) => {
                let wire = plan.wire();
                log.emit(
                    "wire_prepared",
                    object(&[
                        ("generation", string(&wire.basis.generation.to_string())),
                        ("pin", pin_json(plan.expected_pin())),
                        ("publication", string("not_yet_confirmed")),
                    ]),
                    false,
                )?;
                // Sink delay never extends authority or acknowledges an uncommitted source read.
                let committed = recording.commit_wire(plan, publisher, owner.access()?)?;
                stats
                    .prefixes
                    .insert(wire.basis.generation, recording.pin());
                log.emit(
                    "wire_durable",
                    object(&[
                        ("generation", string(&wire.basis.generation.to_string())),
                        ("pin", pin_json(recording.pin())),
                        (
                            "parser_acknowledged",
                            committed
                                .acknowledgement
                                .as_ref()
                                .map_or_else(|| "null".into(), |a| a.is_ok().to_string()),
                        ),
                    ]),
                    false,
                )?;
                if let Some(Err(error)) = committed.acknowledgement {
                    return Err(Failure::Source(HttpReconnectRecordingError::Source(error)));
                }
            }
            HttpReconnectRecordingStep::FrameReady(key) => {
                let generation = key.head().wire.generation;
                if key.ordinal() > options.per_slot_frames {
                    return Err(Failure::FrameLimit);
                }
                if !options.generations.contains(&generation) {
                    return Err(Failure::Inconsistent);
                }
                let frame = recording.take_frame(key, publisher, owner.access()?)?;
                stats.frames += 1;
                *stats.per_generation.entry(generation).or_default() += 1;
                let decoded = match (decoder.as_deref_mut(), privacy) {
                    (None, None) => None,
                    (Some(decoder), Some(privacy)) => {
                        stats.decode_pending =
                            Some((generation, key.ordinal(), key.encoded_sha256()));
                        let image = decoder
                            .decode(&frame, privacy.sensor(), || owner.decode_authority())
                            .map_err(Failure::Decode)?;
                        stats.decode_pending = None;
                        Some(image)
                    }
                    _ => return Err(Failure::Inconsistent),
                };
                // Original bytes remain private custody; only an authorized masked digest leaves.
                drop(frame);
                log.emit(
                    "frame_verified",
                    object(&[
                        ("generation", string(&generation.to_string())),
                        ("ordinal", key.ordinal().to_string()),
                        ("encoded_digest", string(&sha_bytes(key.encoded_sha256()))),
                        (
                            "response_header_digest",
                            string(&sha_bytes(key.head().header_sha256)),
                        ),
                        ("verification", string("original_source_mapping_reverified")),
                        (
                            "pixel_decode",
                            decoded.as_ref().map_or_else(
                                || "null".into(),
                                |image| privacy::frame_json(Some(image)),
                            ),
                        ),
                        ("coverage_certified", "false".into()),
                    ]),
                    false,
                )?;
                if options.stop_after == Some(stats.frames) {
                    return Ok(End::RequestedCount);
                }
            }
            HttpReconnectRecordingStep::BoundaryReady(boundary) => {
                if stats.boundaries.len() >= options.generations.len()
                    || options.generations.get(stats.boundaries.len()).copied()
                        != Some(boundary.source.source.generation)
                {
                    return Err(Failure::Inconsistent);
                }
                stats
                    .prefixes
                    .insert(boundary.source.source.generation, boundary.prefix);
                stats.boundaries.push((boundary, false));
                log.emit("boundary_verified", boundary_json(boundary, false), false)?;
                // A failed/blocked output or a vanished source prevents release AND next connect.
                let handoff = recording.release_boundary(boundary, publisher, owner.access()?)?;
                let last = stats.boundaries.last_mut().ok_or(Failure::Inconsistent)?;
                last.1 = true;
                drop(handoff); // All original reads are in the verified prefix; no capture claim.
            }
            HttpReconnectRecordingStep::Stopped => {
                return stopped(stats.boundaries.last().map(|b| b.0));
            }
        }
    }
}

fn finish(
    options: &Options,
    recording: &HttpReconnectRecording,
    stats: &mut Statistics,
    result: &Result<End, Failure>,
    decoder: Option<&decode::Decoder>,
) -> String {
    let totals = recording.totals();
    stats
        .prefixes
        .insert(recording.scope().stream.generation, recording.pin());
    let prefixes: Vec<_> = stats
        .prefixes
        .iter()
        .map(|(generation, pin)| {
            object(&[
                ("generation", string(&generation.to_string())),
                ("pin", pin_json(*pin)),
                (
                    "frames_taken",
                    stats
                        .per_generation
                        .get(generation)
                        .copied()
                        .unwrap_or(0)
                        .to_string(),
                ),
            ])
        })
        .collect();
    let boundaries: Vec<_> = stats
        .boundaries
        .iter()
        .map(|(b, released)| boundary_json(*b, *released))
        .collect();
    let durable_bytes: u64 = stats.prefixes.values().map(|p| p.bytes).sum();
    let mut fields = vec![
        (
            "status",
            string(match result {
                Ok(End::FinalResponseComplete) => "final_response_complete",
                Ok(End::RequestedCount) => "requested_count_reached",
                Err(_) => "refused",
            }),
        ),
        ("approval_digest", string(&options.approval().to_text())),
        ("source", string(&options.source.to_text())),
        ("receive_clock", string(&options.receive_clock.to_text())),
        (
            "retention_evidence",
            string(&options.retention_evidence.to_text()),
        ),
        ("request_satisfied", result.is_ok().to_string()),
        ("capture_continuity", "false".into()),
        ("prefixes", array(&prefixes)),
        ("boundaries", array(&boundaries)),
        (
            "pending_wire",
            recording
                .pending_wire_plan()
                .map_or_else(|| "null".into(), |p| pin_json(p.expected_pin())),
        ),
        ("frames_taken", stats.frames.to_string()),
        ("frames_parsed", totals.frames.to_string()),
        ("connections_started", totals.slots_started.to_string()),
        ("connect_attempts", totals.connect_attempts.to_string()),
        (
            "responses_completed",
            totals.completed_connections.to_string(),
        ),
        ("received_bytes", totals.received_bytes.to_string()),
        ("sent_bytes", totals.sent_bytes.to_string()),
        ("durable_bytes", durable_bytes.to_string()),
        (
            "unpublished_received_bytes",
            totals
                .received_bytes
                .saturating_sub(durable_bytes)
                .to_string(),
        ),
        (
            "work",
            object(&[
                ("steps", recording.steps().to_string()),
                ("source", recording.source_work_used().to_string()),
                ("framing", totals.framing_work.to_string()),
                ("read_calls", totals.read_calls.to_string()),
                ("write_calls", totals.write_calls.to_string()),
            ]),
        ),
        (
            "error_code",
            result
                .as_ref()
                .err()
                .map_or_else(|| "null".into(), |e| string(e.code())),
        ),
        (
            "reason",
            result
                .as_ref()
                .err()
                .map_or_else(|| "null".into(), |e| string(&e.reason())),
        ),
        ("durable_completion_root", "null".into()),
        ("capture_time", string("unknown_receive_clock_only")),
        ("coverage_certified", "false".into()),
        ("event_published", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ];
    if let Some(decoder) = decoder {
        fields.push((
            "native_decode",
            object(&[
                ("frames_decoded", decoder.frames().to_string()),
                ("pixels_reconstructed", decoder.pixels().to_string()),
                ("work_used", decoder.used().to_string()),
                ("work_remaining", decoder.remaining().to_string()),
                (
                    "pending_frame",
                    stats.decode_pending.map_or_else(
                        || "null".into(),
                        |(generation, ordinal, encoded)| {
                            object(&[
                                ("generation", string(&generation.to_string())),
                                ("ordinal", ordinal.to_string()),
                                ("encoded_digest", string(&sha_bytes(encoded))),
                                ("custody", string("retained_original_prefix")),
                            ])
                        },
                    ),
                ),
                ("pixels_emitted", "false".into()),
            ]),
        ));
    }
    object(&fields)
}

pub(super) fn capture<W: Write>(options: &Options, out: &mut W) -> Result<bool, &'static str> {
    // Exact approval BEFORE constructing clocks, filesystem owners, or network authority.
    if options.approve != Some(options.approval()) {
        return Err("ERR-CAPTURE-RECONNECT-APPROVAL-STALE-001");
    }
    let mut capabilities: Vec<String> = STORAGE_CAPS.iter().map(|s| (*s).into()).collect();
    capabilities.extend(["ADP-REPLAY-001".into(), "CAP-ADAPTER-NET-001".into()]);
    if options.decode.is_some() {
        capabilities.push("CAP-MEDIA-DECODE-001".into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-reconnect-capture".into(),
        operation_id: OperationId::parse("operation:http-reconnect-capture")
            .map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?,
        privacy_scope: "privacy:owner-original-http-custody".into(),
        retention_scope: "retention:explicit-original-http-scope".into(),
        anchor_universe: options.approval(),
        generation: 1,
    })
    .map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?;
    authority
        .validate()
        .map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?;
    let plan = options
        .plan()
        .map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?;
    let routes = plan
        .slots
        .iter()
        .map(|slot| slot.source.route.clone())
        .collect();
    let mut recording =
        HttpReconnectRecording::new(plan, 0).map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?;
    // Resolve a real current policy store BEFORE any archive open or TCP attempt. No empty
    // replacement policy store is created. The existing privacy adapter owns its own Cx.
    let privacy = options
        .decode
        .as_ref()
        .map(|decode| decode.privacy.open(&options.principal))
        .transpose()?;
    let mut decoder = options
        .decode
        .as_ref()
        .map(decode::Decoder::new)
        .transpose()
        .map_err(|_| "ERR-CAPTURE-RECONNECT-CONFIG-001")?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-CAPTURE-RECONNECT-ROOT-001")?;
    let owner = Owner {
        cx: &cx,
        authority: &authority,
        routes,
        start: Instant::now(),
        deadline: options.timeout_ns,
    };
    let result = (|| {
        let mut log = Transcript {
            out,
            used: 0,
            maximum: options.report_bytes,
            sequence: 0,
            io_failed: false,
        };
        log.emit(
            "admitted",
            object(&[
                ("plan", options.preview()),
                ("reservation", reservation_json(recording.reservation())),
            ]),
            false,
        )
        .map_err(|_| "ERR-CAPTURE-RECONNECT-OUTPUT-001")?;
        owner
            .live("capture_reconnect:open")
            .map_err(|_| "ERR-CAPTURE-RECONNECT-AUTHORITY-001")?;
        match std::fs::symlink_metadata(&options.root) {
            Ok(m) if !m.file_type().is_dir() => return Err("ERR-CAPTURE-RECONNECT-ROOT-001"),
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                return Err("ERR-CAPTURE-RECONNECT-ROOT-001");
            }
            _ => {}
        }
        let storage = LocalPublicationLimits::new(
            8192,
            MAX_MANIFEST_CHILDREN,
            8192,
            65536,
            SpoolLimits::new(
                65536,
                1024 * 1024 * 1024,
                options.archive.maximum_spool_object_bytes,
                131072,
            ),
        );
        let mut publisher = LocalRootPublisher::open(&options.root, storage)
            .map_err(|_| "ERR-CAPTURE-RECONNECT-STORAGE-001")?;
        let mut stats = Statistics::default();
        let outcome = drive(
            options,
            &mut recording,
            &mut publisher,
            &owner,
            &mut log,
            &mut stats,
            decoder.as_mut(),
            privacy.as_ref(),
        );
        let report = finish(options, &recording, &mut stats, &outcome, decoder.as_ref());
        let success = outcome.is_ok();
        // Retire closes the socket without a request. Only published prefix pins survive process
        // exit; report pending accepted bytes honestly instead of attempting unapproved rescue I/O.
        let retirement = recording.retire();
        let emitted = log
            .emit("finish", report, true)
            .map_err(|_| "ERR-CAPTURE-RECONNECT-OUTPUT-001");
        drop(retirement);
        emitted?;
        Ok(success)
    })();
    cx.drain_and_finalize();
    result
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
