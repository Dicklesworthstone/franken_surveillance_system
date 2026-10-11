#![forbid(unsafe_code)]
//! Pure capture planning. Parsing, validation and approval never inspect storage or a socket.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId,
};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_publication::LocalPublicationLimits;
use fss_reference::rtsp::archive_pins::{ArchivePinLimits, ArchivePinScope};
use fss_reference::rtsp::authentication::DigestPolicy;
use fss_reference::rtsp::client::{ClientConfig, RtspClientSession};
use fss_reference::rtsp::framed::{
    MAX_WIRE_BODY, MAX_WIRE_BUFFER, MAX_WIRE_CHUNK, MAX_WIRE_HEADERS, WIRE_LIFETIME_NS,
};
use fss_reference::rtsp::live_archive::LiveArchiveConfig;
use fss_reference::rtsp::live_avc::{LiveAvcConfig, recording::LiveRecordingConfig};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, RecordingScope};
use fss_reference::rtsp::recording_archive::{
    ArchiveLimits, ArchiveNamespace,
    checkpoint::{ArchiveWorkLimits, MAX_ARCHIVE_WORK_BYTES},
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingCollector};
use fss_reference::rtsp::tcp::{TcpBinding, TcpLimits, TcpSecurityPolicy};

pub(super) const MAX_ARGUMENTS: usize = 128;
pub(super) const FORMAT: &str = "fss.rtsp_capture_cli.v1";
const POLICY: &str = "one-literal-ip:owner-approved-plaintext:no-authentication:no-reconnect:\
journal-before-publication:original-rtp:fixed-90000hz:exact-cadence:relative-dts:\
zero-composition-offset:idr-led-windows:requested-stop-is-not-eof:v1";
pub(super) const HELP: &str = "fss-capture-rtsp --root NEW_ABSOLUTE_ARCHIVE --pins NEW_ABSOLUTE_PIN_JOURNAL\n\
  --peer IP:PORT --authority HOST[:PORT] --presentation /PATH --control-root /PATH\n\
  --sensor-id ID --stream-id ID --generation N --ingress N --ssrc N\n\
  --anchor sha256:HEX --receive-clock sha256:HEX --timing-evidence sha256:HEX\n\
  --journal-id sha256:HEX --frame-duration-ticks N --stop-after-pictures N\n\
  --owner-authorized yes --plaintext yes --retain-originals yes [--approve sha256:HEX]\n\
\n\
Without --approve: pure JSON plan; NO filesystem, clock or network I/O.\n\
Repeat exactly with the returned approval to capture one bounded RTSP/AVC TCP session.\n\
Both destination directories must be new, separate and outside one another; their parents\n\
must already exist. The journal must be protected independently from footage storage.\n\
Only a literal IP peer is contacted. No credentials, DNS, redirects, TLS or reconnect.\n\
An authentication challenge stops capture without sending an Authorization header.\n\
\n\
The operator supplies a fixed 90000 Hz cadence (for example 3600 ticks for 25 pictures/s)\n\
and evidence identifying that timing policy. Every RTP timestamp must follow it exactly.\n\
No B-picture reordering, drift correction, guessed capture time or loss concealment.\n\
Pictures are source-linked assembled pictures, not a claim of successful pixel decode.\n\
Original RTP and derived recording children are published through the native journaled\n\
archive. Raw RTSP/control/RTCP wire and unselected tails are not retained; output accounts\n\
for omissions. Local custody is UNENCRYPTED. Apply deployment privacy before pixel output.\n\
\n\
Exact AVC offer: --payload-type 96; track/channel: --media-index 0 --rtp-channel 0\n\
Audit label: --principal principal:local-operator (not authentication)\n\
Run limits: --timeout-ms 30000 --drain-timeout-ms 10000 --max-steps 100000\n\
            --max-report-bytes 8388608 --max-source-bytes 67108864 --max-io-calls 1000000\n\
            --read-bytes 4096 --connect-timeout-ms 5000 --response-timeout-ms 5000\n\
Storage: --max-window-pictures 128 --max-windows 32 --max-storage-bytes 536870912\n\
         --max-storage-pause-ms 10000\n\
All effective native limits are included in the approval and its JSON preview.\n\
A successful requested stop closes the socket and drains recording/catalog publication;\n\
it never certifies remote EOF, complete scene coverage, detection, alerts or absence.\n\
Preserve stdout JSONL and both directories. Import each window_durable slot/root or\n\
a catalog_published slot/root/decode_clock/time_scale with fss-import-rtsp.\n\
Interrupted work pins require explicit recovery, never automatic resume.\n";

#[derive(Debug)]
pub(super) struct Options {
    pub(super) root: PathBuf,
    pub(super) pins: PathBuf,
    pub(super) principal: String,
    pub(super) approve: Option<ContentDigest>,
    pub(super) stop_after_pictures: u64,
    pub(super) frame_duration: u32,
    pub(super) time_scale: u32,
    pub(super) timeout_ns: u64,
    pub(super) drain_timeout_ns: u64,
    pub(super) max_steps: u64,
    pub(super) max_report_bytes: usize,
    binding: TcpBinding,
    protocol: ClientConfig,
    transport: TcpLimits,
    media: AvcReceiveLimits,
    recording: LiveRecordingConfig,
    archive: LiveArchiveConfig,
    publication: LocalPublicationLimits,
    work: ArchiveWorkLimits,
    pin_scope: ArchivePinScope,
    pin_limits: ArchivePinLimits,
    timing_evidence: ContentDigest,
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let value = ContentDigest::parse(text).map_err(|_| "invalid SHA-256 identity")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 identity required");
    }
    Ok(value)
}

fn unsigned(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("unsigned decimal required");
    }
    text.parse().map_err(|_| "integer overflow")
}

fn absolute_path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path.parent().is_none()
        || text.chars().any(char::is_control)
        || text.split('/').any(|part| matches!(part, "." | ".."))
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("non-root absolute path without dot components required");
    }
    Ok(path)
}

fn uri_path(text: &str) -> Result<&str, &'static str> {
    if !text.starts_with('/')
        || text.len() > 1024
        || text.contains("//")
        || text.split('/').any(|part| matches!(part, "." | ".."))
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._~-".contains(&byte))
    {
        return Err("bounded credential-free URI path without escapes or query required");
    }
    Ok(text)
}

fn authority(text: &str) -> Result<&str, &'static str> {
    if text.is_empty() || text.len() > 256 || !text.is_ascii() {
        return Err("bounded ASCII RTSP authority required");
    }
    let port = if let Some(rest) = text.strip_prefix('[') {
        let (address, suffix) = rest.split_once(']').ok_or("invalid IPv6 authority")?;
        address
            .parse::<Ipv6Addr>()
            .map_err(|_| "invalid IPv6 authority")?;
        if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or("invalid authority port")?)
        }
    } else {
        let (host, port) = text.split_once(':').map_or((text, None), |(h, p)| (h, Some(p)));
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            })
        {
            return Err("invalid credential-free RTSP authority");
        }
        port
    };
    if let Some(port) = port
        && !(1..=65535).contains(&unsigned(port)?)
    {
        return Err("invalid authority port");
    }
    Ok(text)
}

impl Options {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("argument count or byte bound exceeded");
        }
        const ALLOWED: &[&str] = &[
            "--root", "--pins", "--peer", "--authority", "--presentation", "--control-root",
            "--sensor-id", "--stream-id", "--generation", "--ingress", "--ssrc", "--anchor",
            "--receive-clock", "--timing-evidence", "--journal-id", "--frame-duration-ticks",
            "--stop-after-pictures", "--owner-authorized", "--plaintext", "--retain-originals",
            "--approve", "--principal", "--payload-type", "--media-index", "--rtp-channel",
            "--timeout-ms", "--drain-timeout-ms", "--connect-timeout-ms", "--response-timeout-ms",
            "--max-steps", "--max-report-bytes", "--max-source-bytes", "--max-io-calls",
            "--read-bytes", "--max-window-pictures", "--max-windows", "--max-storage-bytes",
            "--max-storage-pause-ms",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if !ALLOWED.contains(&key) || value.is_empty() || value.starts_with("--") {
                return Err("unknown option or missing value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
        let number = |key: &str, default: u64, low: u64, high: u64| {
            let value = values.get(key).map_or(Ok(default), |text| unsigned(text))?;
            if !(low..=high).contains(&value) {
                return Err("numeric bound exceeded");
            }
            Ok(value)
        };
        for key in ["--owner-authorized", "--plaintext", "--retain-originals"] {
            if required(key)? != "yes" {
                return Err("explicit owner, plaintext and original-retention approval required");
            }
        }
        let root = absolute_path(required("--root")?)?;
        let pins = absolute_path(required("--pins")?)?;
        if root.starts_with(&pins) || pins.starts_with(&root) {
            return Err("archive and pin journal must be separate, nonnested directories");
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        if principal.len() > 256 {
            return Err("principal byte bound exceeded");
        }
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        let sensor = required("--sensor-id")?;
        let stream = required("--stream-id")?;
        if sensor.len() > 256 || stream.len() > 256 {
            return Err("sensor or stream byte bound exceeded");
        }
        let generation = unsigned(required("--generation")?)?;
        let ingress = unsigned(required("--ingress")?)?;
        let ssrc = u32::try_from(unsigned(required("--ssrc")?)?)
            .map_err(|_| "SSRC exceeds 32 bits")?;
        let key = StreamKey { ingress, generation, ssrc };
        let peer: SocketAddr = required("--peer")?
            .parse()
            .map_err(|_| "literal IP:PORT required")?;
        let authority = authority(required("--authority")?)?;
        let binding = TcpBinding::new(
            key, peer, authority, TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
        .map_err(|_| "native RTSP route refused")?;
        let channel = number("--rtp-channel", 0, 0, 254)? as u8;
        let protocol = ClientConfig {
            presentation_uri: format!("rtsp://{authority}{}", uri_path(required("--presentation")?)?),
            control_root_uri: format!("rtsp://{authority}{}", uri_path(required("--control-root")?)?),
            media_index: number("--media-index", 0, 0, 63)? as usize,
            channels: (channel, channel + 1),
            response_timeout_ns: number("--response-timeout-ms", 5000, 1, 60_000)? * 1_000_000,
            default_session_timeout_seconds: 60,
        };
        let payload_type = number("--payload-type", 96, 0, 127)? as u8;
        RtspClientSession::new_with_payload_type(protocol.clone(), payload_type)
            .map_err(|_| "native RTSP protocol scope refused")?;
        let transport = TcpLimits {
            max_received_bytes: number("--max-source-bytes", 64 * 1024 * 1024, 1, 256 * 1024 * 1024)?,
            max_sent_bytes: 1024 * 1024,
            max_io_calls: number("--max-io-calls", 1_000_000, 1, 1_000_000)?,
            max_request_bytes: 32 * 1024,
            chunk_bytes: number("--read-bytes", MAX_WIRE_CHUNK as u64, 1, MAX_WIRE_CHUNK as u64)? as usize,
            connect_timeout_ns: number("--connect-timeout-ms", 5000, 1, 60_000)? * 1_000_000,
        };
        let frame_duration = u32::try_from(unsigned(required("--frame-duration-ticks")?)?)
            .map_err(|_| "frame duration exceeds 32 bits")?;
        if !(1..=90_000).contains(&frame_duration) {
            return Err("frame duration must be in 1..=90000 ticks");
        }
        let time_scale = 90_000;
        let timing_evidence = digest(required("--timing-evidence")?)?;
        let scope = RecordingScope {
            sensor: SensorId::parse(sensor).map_err(|_| "invalid sensor")?,
            stream: StreamId::parse(stream).map_err(|_| "invalid stream")?,
            generation,
            anchor: digest(required("--anchor")?)?,
            receive_clock: digest(required("--receive-clock")?)?,
        };
        let recording = LiveRecordingConfig {
            scope: scope.clone(),
            payload_type,
            time_scale,
            limits: CollectorLimits {
                max_samples: number("--max-window-pictures", 128, 1, 256)? as usize,
                ..CollectorLimits::default()
            },
        };
        RecordingCollector::new(
            scope.clone(), key, payload_type, time_scale, recording.limits,
        )
        .map_err(|_| "native recording scope or limits refused")?;
        let mut clock = CanonicalEncoder::new();
        clock.text("fss.rtsp_capture_fixed_clock.v1");
        clock.text(POLICY);
        clock.digest(timing_evidence);
        clock.digest(scope.receive_clock);
        clock.u64(ingress);
        clock.u64(generation);
        clock.u32(ssrc);
        clock.u32(time_scale);
        clock.u32(frame_duration);
        let clock_bytes = clock.finish_checked().map_err(|_| "timing encoding refused")?;
        let namespace = ArchiveNamespace::new(CatalogScope {
            recording: scope,
            decode_clock: ContentDigest::sha256(&clock_bytes),
            time_scale,
        })
        .map_err(|_| "native archive scope refused")?;
        let timeout_ns = number("--timeout-ms", 30_000, 1, 600_000)? * 1_000_000;
        let drain_timeout_ns = number("--drain-timeout-ms", 10_000, 1, 60_000)? * 1_000_000;
        let max_steps = number("--max-steps", 100_000, 1, 1_000_000)?;
        let max_windows = number("--max-windows", 32, 1, 128)? as usize;
        let max_roots = 8 * max_windows + 32;
        let archive = LiveArchiveConfig {
            namespace,
            limits: ArchiveLimits {
                max_windows,
                max_pages: max_windows,
                max_scan_roots: max_roots,
                windows_per_page: 8,
            },
            max_window_bytes: MAX_RECORDING_BYTES,
            max_steps,
            publication_deadline_ns: timeout_ns + drain_timeout_ns,
            max_storage_pause_ns: number("--max-storage-pause-ms", 10_000, 1, 60_000)? * 1_000_000,
        };
        archive.limits.validate().map_err(|_| "native archive limits refused")?;
        let max_objects = 16 * max_windows + 256;
        let publication = LocalPublicationLimits::new(
            max_roots,
            MAX_MANIFEST_CHILDREN,
            max_roots,
            max_roots * 2,
            SpoolLimits::new(
                max_objects,
                number("--max-storage-bytes", 512 * 1024 * 1024, 1024 * 1024, 1024 * 1024 * 1024)?,
                MAX_RECORDING_BYTES,
                max_objects * 2,
            ),
        )
        .validate()
        .map_err(|_| "native publication limits refused")?;
        let work = ArchiveWorkLimits {
            archive: archive.limits,
            max_pending_bytes: MAX_RECORDING_BYTES,
            max_graph_objects: MAX_MANIFEST_CHILDREN,
            max_new_bytes: MAX_ARCHIVE_WORK_BYTES,
        };
        let pin_scope = ArchivePinScope {
            journal_id: digest(required("--journal-id")?)?,
            archive_namespace: archive.namespace.digest(),
        };
        let stop_after_pictures = unsigned(required("--stop-after-pictures")?)?;
        if stop_after_pictures == 0
            || stop_after_pictures > max_windows as u64 * recording.limits.max_samples as u64
        {
            return Err("requested picture count exceeds finite archive reservation");
        }
        let options = Self {
            root, pins, principal, binding, protocol, transport,
            media: AvcReceiveLimits::default(),
            recording, archive, publication, work, pin_scope,
            pin_limits: ArchivePinLimits { max_records: 8 * max_windows + 32, max_bytes: 1024 * 1024 },
            stop_after_pictures, frame_duration, time_scale, timeout_ns, drain_timeout_ns,
            max_steps,
            max_report_bytes: number("--max-report-bytes", 8 * 1024 * 1024, 128 * 1024, 32 * 1024 * 1024)? as usize,
            timing_evidence,
            approve: values.get("--approve").map(|text| digest(text)).transpose()?,
        };
        options.digest()?;
        Ok(options)
    }

    pub(super) fn live_config(&self) -> LiveAvcConfig {
        LiveAvcConfig {
            protocol: self.protocol.clone(),
            binding: self.binding.clone(),
            transport: self.transport,
            media: self.media,
            // No challenge is answered by this CLI. This is an inactive, nonsecret realm.
            realm: "fss-capture-rtsp-no-authentication".to_owned(),
            digest_policy: DigestPolicy { allow_legacy_md5: false, allow_legacy_no_qop: false },
            deadline_ns: self.timeout_ns,
            max_steps: self.max_steps,
        }
    }

    pub(super) fn recording_config(&self) -> LiveRecordingConfig {
        self.recording.clone()
    }
    pub(super) fn archive_config(&self) -> LiveArchiveConfig {
        self.archive.clone()
    }
    pub(super) fn work_limits(&self) -> ArchiveWorkLimits {
        self.work
    }
    pub(super) fn publication_limits(&self) -> LocalPublicationLimits {
        self.publication
    }
    pub(super) fn pin_scope(&self) -> ArchivePinScope {
        self.pin_scope
    }
    pub(super) fn pin_limits(&self) -> ArchivePinLimits {
        self.pin_limits
    }

    // Actual effective values, not just CLI inputs: changing a dependency default changes approval.
    fn bound_numbers(&self) -> Vec<(&'static str, u64)> {
        let t = self.transport;
        let m = self.media;
        let c = self.recording.limits;
        let a = self.archive.limits;
        let p = self.publication;
        vec![
            ("generation", self.binding.key().generation),
            ("ingress", self.binding.key().ingress),
            ("ssrc", u64::from(self.binding.key().ssrc)),
            ("payload_type", u64::from(self.recording.payload_type)),
            ("media_index", self.protocol.media_index as u64),
            ("rtp_channel", u64::from(self.protocol.channels.0)),
            ("rtcp_channel", u64::from(self.protocol.channels.1)),
            ("response_timeout_ns", self.protocol.response_timeout_ns),
            ("default_session_timeout_seconds", u64::from(self.protocol.default_session_timeout_seconds)),
            ("time_scale", u64::from(self.time_scale)),
            ("frame_duration_ticks", u64::from(self.frame_duration)),
            ("stop_after_pictures", self.stop_after_pictures),
            ("timeout_ns", self.timeout_ns),
            ("drain_timeout_ns", self.drain_timeout_ns),
            ("publication_deadline_ns", self.archive.publication_deadline_ns),
            ("max_storage_pause_ns", self.archive.max_storage_pause_ns),
            ("max_steps", self.max_steps),
            ("archive_max_steps", self.archive.max_steps),
            ("max_report_bytes", self.max_report_bytes as u64),
            ("max_received_bytes", t.max_received_bytes),
            ("max_sent_bytes", t.max_sent_bytes),
            ("max_io_calls", t.max_io_calls),
            ("max_request_bytes", t.max_request_bytes as u64),
            ("read_bytes", t.chunk_bytes as u64),
            ("connect_timeout_ns", t.connect_timeout_ns),
            ("wire_chunk_bytes", MAX_WIRE_CHUNK as u64),
            ("wire_header_bytes", MAX_WIRE_HEADERS as u64),
            ("wire_body_bytes", MAX_WIRE_BODY as u64),
            ("wire_buffer_bytes", MAX_WIRE_BUFFER as u64),
            ("wire_lifetime_ns", WIRE_LIFETIME_NS),
            ("packet_bytes", m.reorder.packet.max_packet_bytes as u64),
            ("extension_bytes", m.reorder.packet.max_extension_bytes as u64),
            ("rtcp_packets", m.reorder.packet.max_rtcp_packets as u64),
            ("reorder_packets", m.reorder.max_packets as u64),
            ("reorder_bytes", m.reorder.max_bytes as u64),
            ("reorder_delay_ns", m.reorder.max_delay_ns),
            ("nal_bytes", m.reconstruction.max_nal_bytes as u64),
            ("packet_nals", m.reconstruction.max_packet_nals as u64),
            ("fragment_packets", m.reconstruction.max_fragment_packets as u64),
            ("fragment_age_ns", m.reconstruction.max_pending_age_ns),
            ("syntax_nal_bytes", m.syntax.max_nal_bytes as u64),
            ("parameter_set_bytes", m.syntax.max_parameter_set_bytes as u64),
            ("coded_width", u64::from(m.syntax.max_width)),
            ("coded_height", u64::from(m.syntax.max_height)),
            ("luma_samples", m.syntax.max_luma_samples),
            ("reference_frames", u64::from(m.syntax.max_reference_frames)),
            ("slice_identity_bits", m.syntax.max_slice_identity_bits as u64),
            ("assembly_nals", m.assembly.max_nals as u64),
            ("assembly_bytes", m.assembly.max_bytes as u64),
            ("assembly_age_ns", m.assembly.max_age_ns),
            ("collector_packets", c.max_packets as u64),
            ("collector_source_bytes", c.max_source_bytes as u64),
            ("collector_pictures", c.max_samples as u64),
            ("collector_picture_bytes", c.max_picture_bytes as u64),
            ("collector_nals", c.max_nals as u64),
            ("collector_source_spans", c.max_source_spans as u64),
            ("collector_age_ns", c.max_age_ns),
            ("archive_windows", a.max_windows as u64),
            ("archive_pages", a.max_pages as u64),
            ("archive_scan_roots", a.max_scan_roots as u64),
            ("windows_per_page", a.windows_per_page as u64),
            ("window_bytes", self.archive.max_window_bytes as u64),
            ("work_pending_bytes", self.work.max_pending_bytes as u64),
            ("work_graph_objects", self.work.max_graph_objects as u64),
            ("work_new_bytes", self.work.max_new_bytes as u64),
            ("publication_roots", p.max_roots as u64),
            ("publication_children", p.max_children as u64),
            ("publication_tombstones", p.max_tombstones as u64),
            ("publication_scan_entries", p.max_scan_entries as u64),
            ("spool_objects", p.spool.max_objects as u64),
            ("spool_total_bytes", p.spool.max_total_bytes),
            ("spool_object_bytes", p.spool.max_object_bytes as u64),
            ("spool_scan_entries", p.spool.max_scan_entries as u64),
            ("pin_records", self.pin_limits.max_records as u64),
            ("pin_bytes", self.pin_limits.max_bytes as u64),
        ]
    }

    pub(super) fn digest(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_capture_cli_plan.v1");
        e.text(POLICY);
        for value in [
            self.root.to_str().ok_or("UTF-8 archive path required")?,
            self.pins.to_str().ok_or("UTF-8 journal path required")?,
            &self.binding.peer().to_string(),
            self.binding.authority(),
            &self.protocol.presentation_uri,
            &self.protocol.control_root_uri,
            &self.principal,
            self.recording.scope.sensor.as_str(),
            self.recording.scope.stream.as_str(),
        ] {
            e.text(value);
        }
        for value in [
            self.recording.scope.anchor,
            self.recording.scope.receive_clock,
            self.timing_evidence,
            self.archive.namespace.scope().decode_clock,
            self.archive.namespace.digest(),
            self.pin_scope.journal_id,
            self.pin_scope.archive_namespace,
        ] {
            e.digest(value);
        }
        let live = self.live_config();
        e.text(&live.realm);
        e.bool(live.digest_policy.allow_legacy_md5);
        e.bool(live.digest_policy.allow_legacy_no_qop);
        let numbers = self.bound_numbers();
        e.u64(numbers.len() as u64);
        for (name, value) in numbers {
            e.text(name);
            e.u64(value);
        }
        let bytes = e.finish_checked().map_err(|_| "capture plan encoding refused")?;
        Ok(ContentDigest::sha256(&bytes))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let numbers: Vec<_> = self.bound_numbers().into_iter().map(|(k, v)| (k, v.to_string())).collect();
        Ok(object(&[
            ("schema", string(FORMAT)),
            ("phase", string("planned")),
            ("approval", string(&self.digest()?.to_text())),
            ("policy", string(POLICY)),
            ("root", string(self.root.to_str().ok_or("UTF-8 archive path required")?)),
            ("pins", string(self.pins.to_str().ok_or("UTF-8 journal path required")?)),
            ("peer", string(&self.binding.peer().to_string())),
            ("authority", string(self.binding.authority())),
            ("presentation_uri", string(&self.protocol.presentation_uri)),
            ("control_root_uri", string(&self.protocol.control_root_uri)),
            ("principal", string(&self.principal)),
            ("sensor", string(self.recording.scope.sensor.as_str())),
            ("stream", string(self.recording.scope.stream.as_str())),
            ("anchor", string(&self.recording.scope.anchor.to_text())),
            ("receive_clock", string(&self.recording.scope.receive_clock.to_text())),
            ("timing_evidence", string(&self.timing_evidence.to_text())),
            ("decode_clock", string(&self.archive.namespace.scope().decode_clock.to_text())),
            ("archive_namespace", string(&self.archive.namespace.digest().to_text())),
            ("journal_id", string(&self.pin_scope.journal_id.to_text())),
            ("bounds", object(&numbers)),
            ("authentication", string("challenge-refused")),
            ("timing", string("operator-asserted-fixed-cadence-relative-dts")),
            ("source_custody", string("selected-original-rtp-local-unencrypted")),
            ("wire_custody", string("raw-control-and-rtcp-not-retained")),
            ("capture_time", string("unknown")),
            ("effects", string("none-until-exact-approval")),
        ]))
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
