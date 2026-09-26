#![forbid(unsafe_code)]
//! Explicit, bounded local acquisition over the existing native HTTP recording owner.
//! JSONL pins precede root publication; a deliberate count stop is NOT native EOF.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Component, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{object, string};
use fss_cli::ExitIdentity;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CanonicalEncoder, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint};
use fss_reference::ingest::http_archive::HttpWirePin;
use fss_reference::ingest::http_camera::{HttpCameraAuthority, HttpCameraDenial, HttpCameraOperation, HttpCameraRoute};
use fss_reference::ingest::http_recording::{HttpRecording, HttpRecordingAccess, HttpRecordingError, HttpRecordingLimits, HttpRecordingRequest, HttpRecordingStep};
use fss_reference::ingest::http_replay::check::{HttpCheckDecode, HttpCheckSource};
use fss_reference::ingest::http_replay::completion::HttpCompletionPin;
use fss_reference::ReplayCx;

const HELP: &str = "fss-capture http --root ABSOLUTE_ARCHIVE_DIR --peer IP:PORT --host HOST --target /PATH\n\
  --source sha256:HEX --generation N --receive-clock sha256:HEX\n\
  --retention-evidence sha256:HEX --owner-authorized yes --plaintext yes --retain-originals yes\n\
  [--principal ID] [--approve sha256:HEX]\n\
  Without --approve: print an exact acquisition plan; no filesystem or network I/O.\n\
  Review it, then repeat with its approval digest. Capture uses ONE literal-IP connection,\n\
  no DNS, credentials, query strings, redirects, reconnect, repair, alert, or event writes.\n\
  Optional: --stop-after-frames N (intentional bounded stop, NOT clean HTTP/MIME EOF).\n\
  Bounds: --timeout-ms (default 30000), --connect-timeout-ms (5000), --max-frames (128),\n\
          --max-reads (1024), --max-source-bytes (67108864), --read-bytes (16384),\n\
          --max-steps (100000), --max-source-work (1000000000000),\n\
          --max-framing-work (1000000000), --max-report-bytes (8388608).\n\
  Preserve stdout JSONL independently: prepared pins are emitted BEFORE their storage writes.\n\
  A prepared pin is not a durable receipt. A refused run may retain a verified prefix and\n\
  staged/visible work. Inspect the exact pin with fss-archive check-http; do not reacquire it.\n\
  This path verifies original custody and native framing, not pixels, timing, coverage or\n\
  detection quality. Original headers and JPEGs remain private local custody, not encrypted.\n\
  --principal is an audit label, not remote authentication. Only use an owner-authorized,\n\
  credential-free plaintext endpoint and an explicit original-header/media retention scope.\n";
const DOMAIN: &str = "fss.http_capture_cli_plan.v1";
const FORMAT: &str = "fss.http_capture_cli.v1";
const RESERVE: usize = 16 * 1024;
const MAX_REPORT: usize = 32 * 1024 * 1024;
const STORAGE_CAPS: [&str; 4] = ["CAP-READ-MEDIA-001", "CAP-OBJECT-STAGE-001", "CAP-OBJECT-PUBLISH-001", "CAP-RETENTION-COMMIT-001"];

#[derive(Debug)]
struct Options {
    root: PathBuf,
    source: HttpCheckSource,
    peer: SocketAddr,
    host: String,
    target: String,
    principal: String,
    limits: HttpRecordingLimits,
    timeout_ns: u64,
    stop_after: Option<u64>,
    report_bytes: usize,
    approve: Option<ContentDigest>,
}

fn sha(text: &str) -> Result<ContentDigest, &'static str> {
    let d = ContentDigest::parse(text).map_err(|_| "invalid SHA-256 identity")?;
    if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
        return Err("nonzero SHA-256 identity required");
    }
    Ok(d)
}

fn parse(args: &[OsString]) -> Result<Options, &'static str> {
    if args.first().and_then(|s| s.to_str()) != Some("http") || args.len() > 49
        || args.iter().any(|s| s.as_encoded_bytes().len() > 4096)
    { return Err("invalid command or argument bound"); }
    let allowed = ["--root", "--peer", "--host", "--target", "--source", "--generation",
        "--receive-clock", "--retention-evidence", "--owner-authorized", "--plaintext",
        "--retain-originals", "--principal", "--approve", "--timeout-ms", "--connect-timeout-ms",
        "--max-frames", "--max-reads", "--max-source-bytes", "--read-bytes", "--max-steps",
        "--max-source-work", "--max-framing-work", "--max-report-bytes", "--stop-after-frames"];
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("UTF-8 option names required")?;
        if !allowed.contains(&key) { return Err("unknown option"); }
        let value = pair.get(1).and_then(|s| s.to_str()).ok_or("missing UTF-8 value")?;
        if value.is_empty() || value.starts_with("--") { return Err("missing value"); }
        if values.insert(key, value).is_some() { return Err("duplicate option"); }
    }
    let required = |k: &str| values.get(k).copied().ok_or("required option missing");
    let number = |k: &str, default: u64, low: u64, high: u64| -> Result<u64, &'static str> {
        let n = match values.get(k) {
            Some(s) if s.bytes().all(|b| b.is_ascii_digit()) => s.parse::<u64>().map_err(|_| "integer overflow")?,
            Some(_) => return Err("unsigned decimal required"),
            None => default,
        };
        if !(low..=high).contains(&n) { return Err("numeric bound exceeded"); }
        Ok(n)
    };
    for flag in ["--owner-authorized", "--plaintext", "--retain-originals"] {
        if required(flag)? != "yes" { return Err("explicit owner, plaintext and original-retention acknowledgements required"); }
    }
    let root = PathBuf::from(required("--root")?);
    if !root.is_absolute() || root.parent().is_none()
        || root.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    { return Err("a non-root absolute archive path without dot components is required"); }
    let _ = required("--generation")?;
    let source = HttpCheckSource {
        source: sha(required("--source")?)?,
        generation: number("--generation", 0, 1, u64::MAX)?,
        receive_clock: sha(required("--receive-clock")?)?,
        retention_evidence: sha(required("--retention-evidence")?)?,
    };
    let principal = values.get("--principal").copied().unwrap_or("principal:local-operator").to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    if principal.len() > 256 { return Err("principal byte bound"); }
    let timeout_ns = number("--timeout-ms", 30_000, 1, 600_000)? * 1_000_000;
    let mut limits = HttpRecordingLimits::default();
    limits.decode = HttpCheckDecode::None;
    limits.connect_timeout_ns = number("--connect-timeout-ms", 5_000, 1, 60_000)? * 1_000_000;
    limits.media.maximum_frames = number("--max-frames", 128, 1, 4096)? as usize;
    limits.media.maximum_reads = number("--max-reads", 1024, 1, 4096)? as usize;
    limits.media.maximum_source_bytes = number("--max-source-bytes", 64 * 1024 * 1024, 1, 256 * 1024 * 1024)?;
    limits.media.read_bytes = number("--read-bytes", 16384, 1, 65536)? as usize;
    limits.media.maximum_steps = number("--max-steps", 100_000, 1, 1_000_000)?;
    limits.media.source_work = number("--max-source-work", limits.media.source_work, 0, 1_000_000_000_000_000)?;
    limits.media.framing_work = number("--max-framing-work", limits.media.framing_work, 0, 1_000_000_000_000_000)?;
    limits.media.validate().map_err(|_| "invalid recording limits")?;
    let stop_after = values.contains_key("--stop-after-frames")
        .then(|| number("--stop-after-frames", 0, 1, limits.media.maximum_frames as u64)).transpose()?;
    let result = Options {
        root, source,
        peer: required("--peer")?.parse().map_err(|_| "literal IP and nonzero port required")?,
        host: required("--host")?.to_owned(), target: required("--target")?.to_owned(), principal,
        limits, timeout_ns, stop_after,
        report_bytes: number("--max-report-bytes", 8 * 1024 * 1024, (RESERVE * 2) as u64, MAX_REPORT as u64)? as usize,
        approve: values.get("--approve").map(|s| sha(s)).transpose()?,
    };
    result.request().map_err(|_| "native route or scope refused")?;
    Ok(result)
}

impl Options {
    fn request(&self) -> Result<HttpRecordingRequest, HttpRecordingError> {
        HttpRecordingRequest::new(self.source, self.peer, &self.host, &self.target, self.limits, self.timeout_ns)
    }
    // Bind all options and fixed limit/default semantics, not only the address or source.
    fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.text("single-connection:original-root-before-parse:framing-only:local-unencrypted:no-reconnect:v1");
        e.text(self.root.to_str().unwrap_or("invalid-non-utf8-root"));
        e.text(&self.peer.to_string()); e.text(&self.host); e.text(&self.target); e.text(&self.principal);
        e.digest(self.source.source); e.u64(self.source.generation);
        e.digest(self.source.receive_clock); e.digest(self.source.retention_evidence);
        let m = self.limits.media;
        for n in [self.timeout_ns, self.limits.connect_timeout_ns, self.limits.io_calls,
            m.maximum_reads as u64, m.maximum_source_bytes, m.maximum_scan_roots as u64,
            m.maximum_spool_object_bytes as u64, m.maximum_frames as u64, m.maximum_steps,
            m.read_bytes as u64, m.maximum_frame_bytes as u64, u64::from(m.maximum_dimension),
            m.maximum_pixels as u64, m.source_work, m.framing_work, m.decode_work,
            self.stop_after.unwrap_or(0), self.report_bytes as u64]
        { e.u64(n); }
        ContentDigest::sha256(&e.finish())
    }
    fn limits_json(&self) -> String {
        let m = self.limits.media;
        let fields = [
            ("connect_timeout_ns", self.limits.connect_timeout_ns), ("io_calls", self.limits.io_calls),
            ("maximum_reads", m.maximum_reads as u64), ("maximum_source_bytes", m.maximum_source_bytes),
            ("maximum_scan_roots", m.maximum_scan_roots as u64), ("maximum_spool_object_bytes", m.maximum_spool_object_bytes as u64),
            ("maximum_frames", m.maximum_frames as u64), ("maximum_steps", m.maximum_steps),
            ("read_bytes", m.read_bytes as u64), ("maximum_frame_bytes", m.maximum_frame_bytes as u64),
            ("maximum_dimension", u64::from(m.maximum_dimension)), ("maximum_pixels", m.maximum_pixels as u64),
            ("source_work", m.source_work), ("framing_work", m.framing_work), ("decode_work", m.decode_work),
            ("report_bytes", self.report_bytes as u64),
        ];
        object(&fields.iter().map(|(k, n)| (*k, n.to_string())).collect::<Vec<_>>())
    }
    fn plan(&self) -> String {
        object(&[("format", string(FORMAT)), ("kind", string("plan")),
            ("approval_digest", string(&self.approval().to_text())),
            ("root", string(self.root.to_str().unwrap_or(""))), ("peer", string(&self.peer.to_string())),
            ("host", string(&self.host)), ("target", string(&self.target)), ("principal", string(&self.principal)),
            ("source", source_json(self.source)), ("timeout_ns", self.timeout_ns.to_string()),
            ("maximum_frames", self.limits.media.maximum_frames.to_string()),
            ("maximum_reads", self.limits.media.maximum_reads.to_string()),
            ("maximum_source_bytes", self.limits.media.maximum_source_bytes.to_string()),
            ("limits", self.limits_json()),
            ("stop_after_frames", optional_number(self.stop_after)),
            ("decode", string("none")), ("transport", string("owner_approved_plaintext")),
            ("retention", string("original_headers_and_media_local_unencrypted")),
            ("writes", string("none")), ("network", string("none")),
            ("approval_scope", string("bounded_acquisition_not_approval_of_unknown_future_event_or_pixels"))])
    }
}

fn optional_number(value: Option<u64>) -> String { value.map_or_else(|| "null".into(), |n| n.to_string()) }
fn source_json(s: HttpCheckSource) -> String {
    object(&[("source", string(&s.source.to_text())), ("generation", s.generation.to_string()),
        ("receive_clock", string(&s.receive_clock.to_text())), ("retention_evidence", string(&s.retention_evidence.to_text()))])
}
fn wire_json(p: HttpWirePin) -> String {
    object(&[("scope", string(&p.scope.to_text())), ("head", string(&p.head.to_text())),
        ("reads", p.reads.to_string()), ("bytes", p.bytes.to_string())])
}
fn completion_json(p: Option<HttpCompletionPin>) -> String {
    p.map_or_else(|| "null".into(), |p| object(&[("root", string(&p.root.to_text())), ("wire", wire_json(p.wire))]))
}
fn byte_digest(bytes: [u8; 32]) -> String {
    format!("sha256:{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

// Output is bounded and incrementally flushed. A broken sink prevents the next publication;
// success means accepted by this writer, NOT a remotely/disk-durable checkpoint acknowledgement.
struct Transcript<'a, W> { out: &'a mut W, used: usize, maximum: usize, sequence: u64 }
impl<W: Write> Transcript<'_, W> {
    fn emit(&mut self, kind: &str, detail: String, final_row: bool) -> io::Result<()> {
        let row = object(&[("format", string(FORMAT)), ("sequence", self.sequence.to_string()),
            ("kind", string(kind)), ("detail", detail)]) + "\n";
        let ceiling = self.maximum.saturating_sub(if final_row { 0 } else { RESERVE });
        if row.len() > ceiling.saturating_sub(self.used) {
            return Err(io::Error::other("capture transcript bound"));
        }
        self.used += row.len();
        write_bounded(self.out, row.as_bytes())?;
        self.out.flush()?;
        self.sequence += 1;
        Ok(())
    }
}
fn write_bounded(out: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interrupts = 0;
    while !bytes.is_empty() {
        match out.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= bytes.len().min(4096) => { bytes = &bytes[n..]; interrupts = 0; },
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupts < 7 => interrupts += 1,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// A local operator grant, not a network authentication service. It checks exact route, scope,
// deadline and owning cancellation before AND after the native owner's syscalls/publications.
struct Owner<'a> { cx: &'a ReplayCx, authority: &'a ContextAuthority, route: HttpCameraRoute, start: Instant, deadline: u64 }
impl Owner<'_> {
    fn now(&self) -> Result<u64, HttpCameraDenial> {
        let now = u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| HttpCameraDenial::Deadline)?;
        if now >= self.deadline { return Err(HttpCameraDenial::Deadline); }
        Ok(now)
    }
    fn live(&self, stage: &'static str) -> Result<(), HttpCameraDenial> {
        self.cx.checkpoint(stage).map_err(|_| HttpCameraDenial::Cancelled)?;
        self.now()?;
        if self.authority.cancellation_reason.is_some() { return Err(HttpCameraDenial::Cancelled); }
        Ok(())
    }
    fn access(&self) -> Result<HttpRecordingAccess<'_>, HttpCameraDenial> {
        Ok(HttpRecordingAccess { now_ns: self.now()?, camera: self, storage: self })
    }
    fn pause(&self) -> Result<(), HttpCameraDenial> {
        self.live("capture_http:wait")?;
        let remaining = self.deadline.saturating_sub(self.now()?);
        std::thread::sleep(Duration::from_nanos(remaining.min(1_000_000)));
        self.live("capture_http:wait")
    }
}
impl HttpCameraAuthority for Owner<'_> {
    fn checkpoint(&self, route: &HttpCameraRoute, op: HttpCameraOperation, now: u64, deadline: u64) -> Result<(), HttpCameraDenial> {
        self.live("capture_http:network")?;
        if route != &self.route || deadline != self.deadline || now >= deadline
            || !self.authority.has_capability("CAP-ADAPTER-NET-001")
            || matches!(op, HttpCameraOperation::Analyze | HttpCameraOperation::ReleaseResult)
        { return Err(HttpCameraDenial::Unauthorized); }
        if !STORAGE_CAPS.iter().all(|cap| self.authority.has_capability(cap)) {
            return Err(HttpCameraDenial::Unauthorized);
        }
        Ok(())
    }
}
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.live("capture_http:storage").is_err()
            || !STORAGE_CAPS.iter().all(|cap| self.authority.has_capability(cap))
    }
}

#[derive(Debug)]
enum Failure { Source(HttpRecordingError), Authority(HttpCameraDenial), Output }
impl From<HttpRecordingError> for Failure { fn from(e: HttpRecordingError) -> Self { Self::Source(e) } }
impl From<HttpCameraDenial> for Failure { fn from(e: HttpCameraDenial) -> Self { Self::Authority(e) } }
impl From<io::Error> for Failure { fn from(_: io::Error) -> Self { Self::Output } }
impl Failure {
    fn reason(&self) -> String {
        match self {
            Self::Source(e) => format!("{e}"),
            Self::Authority(e) => format!("capture authority refused: {e:?}"),
            Self::Output => "capture transcript refused; preserve the last complete recovery pin".into(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum End { NativeComplete, RequestedCount }

fn drive<W: Write>(o: &Options, recording: &mut HttpRecording, publisher: &mut LocalRootPublisher, owner: &Owner<'_>, log: &mut Transcript<'_, W>) -> Result<End, Failure> {
    loop {
        // The native owner owns the cumulative step and I/O allowances; none refill here.
        match recording.poll(owner.access()?)? {
            HttpRecordingStep::Pending => owner.pause()?,
            HttpRecordingStep::Advanced => {},
            HttpRecordingStep::WirePrepared(plan) => {
                log.emit("wire_prepared", object(&[("pin", wire_json(plan.expected_pin())),
                    ("publication", string("not_yet_confirmed"))]), false)?;
                // Output may have blocked: obtain fresh authority/time before actual storage.
                let committed = recording.commit_wire(plan, publisher, owner.access()?)?;
                log.emit("wire_durable", object(&[("pin", wire_json(recording.pin())),
                    ("parser_acknowledged", committed.acknowledgement.is_ok().to_string())]), false)?;
                committed.acknowledgement.map_err(|e| Failure::Source(HttpRecordingError::Source(e)))?;
            },
            HttpRecordingStep::FrameReady(key) => {
                let frame = recording.take_frame(key, publisher, owner.access()?, None)?;
                log.emit("frame_verified", object(&[("ordinal", key.ordinal().to_string()),
                    ("encoded_digest", string(&byte_digest(key.encoded_sha256()))),
                    ("source_map_digest", string(&byte_digest(frame.check.exposure))),
                    ("verification", string("original_bytes_and_source_mapping")),
                    ("pixel_decode", string("not_requested")), ("coverage_certified", "false".into())]), false)?;
                if o.stop_after.is_some_and(|n| recording.transferred_frames() == n) {
                    return Ok(End::RequestedCount);
                }
            },
            HttpRecordingStep::CompletionPrepared(pin) => {
                log.emit("completion_prepared", completion_json(Some(pin)), false)?;
                recording.commit_completion(pin, publisher, owner.access()?)?;
                return Ok(End::NativeComplete);
            },
            HttpRecordingStep::Complete(_) => return Ok(End::NativeComplete),
        }
    }
}

fn finish_json(o: &Options, r: &HttpRecording, result: &Result<End, Failure>) -> String {
    let work = r.work();
    let totals = r.camera().totals();
    object(&[("status", string(match result { Ok(End::NativeComplete) => "native_complete", Ok(End::RequestedCount) => "requested_count_reached", Err(_) => "refused" })),
        ("approval_digest", string(&o.approval().to_text())), ("source", source_json(o.source)),
        ("pin", wire_json(r.pin())), ("completion", completion_json(r.completion())),
        ("prepared_completion", completion_json(r.prepared_completion())),
        ("pending_wire", r.pending_wire_plan().map_or_else(|| "null".into(), |p| wire_json(p.expected_pin()))),
        ("request_satisfied", result.is_ok().to_string()), ("stream_complete", r.completion().is_some().to_string()),
        ("frames_taken", r.transferred_frames().to_string()), ("frames_parsed", totals.frames.to_string()),
        ("received_bytes", totals.received_bytes.to_string()), ("sent_bytes", totals.sent_bytes.to_string()),
        ("unpublished_received_bytes", totals.received_bytes.saturating_sub(r.pin().bytes).to_string()),
        ("peer_eof_observed", totals.peer_eof.to_string()),
        ("work", object(&[("steps", work.steps.to_string()), ("source", work.source.to_string()), ("framing", work.framing.to_string()), ("decode", work.decode.to_string())])),
        ("refusal", result.as_ref().err().map_or_else(|| "null".into(), |e| string(&e.reason()))),
        ("capture_time", string("unknown_receive_clock_only")), ("pixels_checked", "false".into()),
        ("coverage_certified", "false".into()), ("event_published", "false".into()),
        ("reconnect_attempted", "false".into()), ("qualification", string("implemented_not_qualified"))])
}

fn capture<W: Write>(o: &Options, out: &mut W) -> Result<bool, &'static str> {
    // This must remain before ReplayCx, publisher open, clocks or network construction.
    if o.approve != Some(o.approval()) { return Err("ERR-CAPTURE-APPROVAL-STALE-001"); }
    let mut capabilities: Vec<String> = STORAGE_CAPS.iter().map(|s| (*s).into()).collect();
    capabilities.extend(["ADP-REPLAY-001".into(), "CAP-ADAPTER-NET-001".into()]);
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-capture-cli".into(), operation_id: OperationId::parse("operation:http-capture-cli").map_err(|_| "ERR-CAPTURE-CONFIG-001")?,
        principal: o.principal.clone(), capabilities, deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).storage_operations(1_000_000).build().map_err(|_| "ERR-CAPTURE-CONFIG-001")?,
        privacy_scope: "privacy:owner-original-http-custody".into(), retention_scope: "retention:explicit-original-http-scope".into(),
        anchor_universe: o.approval(), generation: 1,
    }).map_err(|_| "ERR-CAPTURE-CONFIG-001")?;
    authority.validate().map_err(|_| "ERR-CAPTURE-CONFIG-001")?;
    match std::fs::symlink_metadata(&o.root) {
        Ok(m) if !m.file_type().is_dir() => return Err("ERR-CAPTURE-ROOT-001"),
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err("ERR-CAPTURE-ROOT-001"),
        _ => {},
    }
    let request = o.request().map_err(|_| "ERR-CAPTURE-CONFIG-001")?;
    let cx = ReplayCx::from_context_authority(&authority, o.root.clone()).map_err(|_| "ERR-CAPTURE-ROOT-001")?;
    let owner = Owner { cx: &cx, authority: &authority, route: request.route.clone(), start: Instant::now(), deadline: o.timeout_ns };
    let result = (|| {
        let mut log = Transcript { out, used: 0, maximum: o.report_bytes, sequence: 0 };
        log.emit("admitted", object(&[("plan", o.plan()), ("scope", string("local-original-custody-no-media-export"))]), false).map_err(|_| "ERR-CAPTURE-OUTPUT-001")?;
        if owner.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err("ERR-CAPTURE-AUTHORITY-001"); }
        let storage = LocalPublicationLimits::new(8192, MAX_MANIFEST_CHILDREN, 8192, 65536,
            SpoolLimits::new(65536, 1024 * 1024 * 1024, o.limits.media.maximum_spool_object_bytes, 131072));
        let mut publisher = LocalRootPublisher::open(&o.root, storage).map_err(|_| "ERR-CAPTURE-STORAGE-001")?;
        let mut recording = match HttpRecording::connect(request, &publisher, owner.access().map_err(|_| "ERR-CAPTURE-AUTHORITY-001")?) {
            Ok(r) => r,
            Err(e) => {
                log.emit("finish", object(&[("status", string("start_refused")), ("tcp_attempted", e.attempted.to_string()),
                    ("http_request_sent", "false".into()), ("stream_complete", "false".into()), ("reason", string(&e.reason.to_string()))]), true)
                    .map_err(|_| "ERR-CAPTURE-OUTPUT-001")?;
                return Ok(false);
            },
        };
        let outcome = drive(o, &mut recording, &mut publisher, &owner, &mut log);
        let report = finish_json(o, &recording, &outcome);
        let successful = outcome.is_ok();
        // Closing the native owner sends no request. Undurable pending bytes cannot be recovered
        // after this process exits; only the reported exact durable prefix is reusable.
        let retirement = recording.retire();
        let emitted = log.emit("finish", report, true).map_err(|_| "ERR-CAPTURE-OUTPUT-001");
        drop(retirement);
        emitted?;
        Ok(successful)
    })();
    cx.drain_and_finalize();
    result
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(50).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return match write_bounded(&mut io::stdout().lock(), HELP.as_bytes()) { Ok(()) => ExitCode::SUCCESS, Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code) };
    }
    let options = match parse(&args) {
        Ok(o) => o,
        Err(e) => { eprintln!("ERR-CAPTURE-ARGUMENT-001: {e}; use fss-capture --help"); return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code); },
    };
    let mut out = io::stdout().lock();
    let result = if options.approve.is_none() {
        write_bounded(&mut out, (options.plan() + "\n").as_bytes()).map(|()| true).map_err(|_| "ERR-CAPTURE-OUTPUT-001")
    } else { capture(&options, &mut out) };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        Err(e) => { eprintln!("{e}: no complete capture report; preserve prior pins, inspect storage, and do not automatically reconnect"); ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        let d = ContentDigest::sha256(b"owner scope").to_text();
        ["http", "--root", "/tmp/fss-capture-test", "--peer", "127.0.0.1:8000", "--host", "camera.invalid", "--target", "/video",
            "--source", &d, "--generation", "1", "--receive-clock", &d, "--retention-evidence", &d,
            "--owner-authorized", "yes", "--plaintext", "yes", "--retain-originals", "yes"]
            .into_iter().map(OsString::from).collect()
    }
    #[test]
    fn preview_has_no_implicit_approval_or_stop() -> Result<(), &'static str> {
        let o = parse(&args())?;
        assert!(o.approve.is_none() && o.stop_after.is_none());
        assert_eq!(o.limits.decode, HttpCheckDecode::None);
        assert!(o.plan().contains("\"writes\":\"none\""));
        Ok(())
    }
    #[test]
    fn changing_route_root_actor_bounds_or_scope_changes_approval() -> Result<(), &'static str> {
        let original = parse(&args())?.approval();
        for (flag, value) in [("--root", "/tmp/another-archive"), ("--peer", "127.0.0.1:8001"), ("--host", "other.invalid"), ("--target", "/other"), ("--generation", "2")] {
            let mut a = args(); let index = a.iter().position(|s| s == flag).ok_or("flag")?;
            a[index + 1] = value.into(); assert_ne!(parse(&a)?.approval(), original);
        }
        for (flag, value) in [("--timeout-ms", "10"), ("--max-source-work", "1"), ("--stop-after-frames", "1"), ("--max-reads", "1"), ("--principal", "principal:other")] {
            let mut a = args(); a.extend([flag.into(), value.into()]); assert_ne!(parse(&a)?.approval(), original);
        }
        Ok(())
    }
    #[test]
    fn exact_approval_is_not_its_own_input() -> Result<(), &'static str> {
        let mut a = args(); let approval = parse(&a)?.approval();
        a.extend(["--approve".into(), approval.to_text().into()]);
        let o = parse(&a)?; assert_eq!(o.approve, Some(o.approval())); Ok(())
    }
    #[test]
    fn malformed_credential_routes_and_authority_are_rejected() {
        for (flag, value) in [("--target", "/video?token=secret"), ("--target", "//foreign"), ("--target", "/%2f"), ("--host", "owner:secret@camera"), ("--peer", "camera.invalid:80"), ("--peer", "0.0.0.0:80"), ("--root", "/"), ("--root", "relative"), ("--root", "/tmp/../escape"), ("--plaintext", "no"), ("--owner-authorized", "no")] {
            let mut a = args(); if let Some(i) = a.iter().position(|s| s == flag) { a[i + 1] = value.into(); }
            assert!(parse(&a).is_err(), "{flag}");
        }
    }
    #[test]
    fn duplicates_unknowns_truncation_and_count_overflow_fail() {
        for suffix in [vec!["--host", "other"], vec!["--force", "yes"], vec!["--approve"], vec!["--stop-after-frames", "129"], vec!["--max-reads", "4097"], vec!["--timeout-ms", "18446744073709551616"]] {
            let mut a = args(); a.extend(suffix.into_iter().map(OsString::from)); assert!(parse(&a).is_err());
        }
    }
    #[test]
    fn stale_approval_refuses_before_root_or_network() -> Result<(), &'static str> {
        let mut o = parse(&args())?;
        o.approve = Some(ContentDigest::sha256(b"stale"));
        let mut out = Vec::new(); assert_eq!(capture(&o, &mut out), Err("ERR-CAPTURE-APPROVAL-STALE-001"));
        assert!(out.is_empty()); Ok(())
    }
    struct Interrupted;
    impl Write for Interrupted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::Interrupted.into()) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    #[test]
    fn transcript_bounds_reserve_the_terminal_row_and_eintr_is_finite() {
        let mut out = Vec::new(); let mut t = Transcript { out: &mut out, used: 0, maximum: RESERVE * 2, sequence: 0 };
        assert!(t.emit("large", string(&"x".repeat(RESERVE)), false).is_err());
        assert!(t.emit("finish", object(&[("stream_complete", "false".into())]), true).is_ok());
        assert!(write_bounded(&mut Interrupted, b"x").is_err());
    }
}
