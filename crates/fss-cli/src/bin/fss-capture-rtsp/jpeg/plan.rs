#![forbid(unsafe_code)]
//! Pure, complete approval binding for one JPEG source capture or exact cold prefix.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};

use fss_cli::json_output::{object, string};
use fss_codec_mjpeg::DecodeLimits;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::jpeg::{JpegLimits, JpegReceiver};
use fss_packet::{ReorderLimits, StreamKey};
use fss_publication::LocalPublicationLimits;
use fss_reference::rtsp::authentication::DigestPolicy;
use fss_reference::rtsp::client::{ClientCodec, ClientConfig, RtspClientSession};
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use fss_reference::rtsp::live_jpeg::LiveJpegConfig;
use fss_reference::rtsp::tcp::{TcpBinding, TcpLimits, TcpSecurityPolicy};

use crate::authentication::AuthPlan;

pub(crate) const SCHEMA: &str = "fss.rtsp_jpeg_capture_cli.v1";
pub(crate) const POLICY: &str = "jpeg:exact-native-route:original-datagrams-before-pixels:full-pinned-prefix:native-storage-recovery:unknown-capture-clock:no-reconnect:v1";
pub(crate) const HELP: &str = "fss-capture-rtsp jpeg [replay] --root ABSOLUTE_SOURCE_DIRECTORY\n\
  --peer IP:PORT --authority HOST[:PORT] --presentation /PATH --control-root /PATH\n\
  --sensor-id ID --stream-id ID --generation N --ingress N --ssrc N\n\
  --anchor sha256:HEX --receive-clock sha256:HEX --retention-evidence sha256:HEX\n\
  --owner-authorized yes --plaintext yes --retain-originals yes\n\
  [--stop-after-pictures 1] [--payload-type 26] [--approve sha256:HEX]\n\n\
Without approval, print a pure complete plan without filesystem, secret, clock or network I/O.\n\
Capture requires a NEW source directory and performs one explicitly approved connection.\n\
Every complete selected RTP/RTCP datagram is durably published before further media progress,\n\
including probation, duplicates and malformed datagrams. Native JPEG luma validation supplies\n\
the picture target; no pixels, RTSP control/authentication, partial TCP input or audio are stored.\n\
Source storage is unencrypted. Retain the JSONL prefix receipts independently from the source.\n\
Requested stop closes the connection; it is not remote EOF or a scene-coverage statement.\n\n\
Cold replay requires the SAME source scope and the independently saved complete-prefix pin:\n\
  replay ... --prefix-head sha256:HEX --prefix-datagrams N --prefix-bytes N\n\
  --configuration-evidence sha256:HEX --reduced-rtcp yes|no\n\
Use the configuration evidence, exact limits and selected RTCP mode from capture output.\n\
Replay opens existing storage, verifies the full prefix from ordinal 1 and derives native\n\
images with exact packet dependencies, including earlier cached quantizers. Source exhaustion\n\
never invents EOF or flushes incomplete media. Replay is a separately approved interpretation.\n\n\
Both modes authorize native storage locks, recovery holds, temporary metadata cleanup and fsync.\n\
Replay appends no source and never creates a missing source root.\n\n\
Track: --media-index 0 --rtp-channel 0. Principal: --principal principal:local-operator.\n\
Bounds: --timeout-ms 30000 --max-steps 100000 --max-source-bytes 67108864\n\
        --max-datagrams 8192 --max-storage-bytes 268435456 --source-work 1000000000\n\
        --decode-work 10000000000 --max-report-bytes 8388608 --read-bytes 4096\n\
        --max-io-calls 1000000 --connect-timeout-ms 5000 --response-timeout-ms 5000\n\
        --max-frame-bytes 8388608 --max-dimension 2040 --max-fragments 4096\n\
        --frame-timeout-ms 2000 --reorder-delay-ms 100 --max-cached-quantizers 127\n\
Linux Digest opt-in for capture: --credential-file /PRIVATE_FILE --auth-realm EXACT_REALM\n\
  [--legacy-md5 yes] [--legacy-no-qop yes]. Reuses the existing bounded private-file lease\n\
and native entropy boundary; secret values never enter argv, plans, reports or source storage.\n\
No DNS, redirect, automatic credential fallback, reconnect, source deletion or retention rollover.\n";

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplaySelection {
    pub(crate) head: ContentDigest,
    pub(crate) datagrams: u64,
    pub(crate) bytes: u64,
    pub(crate) configuration: ContentDigest,
    pub(crate) reduced_rtcp: bool,
}

#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) root: PathBuf,
    pub(crate) principal: String,
    pub(crate) sensor: String,
    pub(crate) stream: String,
    pub(crate) anchor: ContentDigest,
    pub(crate) scope: DatagramScope,
    pub(crate) protocol: ClientConfig,
    pub(crate) transport: TcpLimits,
    pub(crate) reorder: ReorderLimits,
    pub(crate) jpeg: JpegLimits,
    pub(crate) decode: DecodeLimits,
    pub(crate) archive: DatagramArchiveLimits,
    pub(crate) storage: LocalPublicationLimits,
    pub(crate) payload_type: u8,
    pub(crate) timeout_ns: u64,
    pub(crate) max_steps: u64,
    pub(crate) frames: u64,
    pub(crate) source_work: u64,
    pub(crate) decode_work: u64,
    pub(crate) report_bytes: usize,
    pub(crate) authentication: Option<AuthPlan>,
    pub(crate) replay: Option<ReplaySelection>,
    pub(crate) approval: Option<ContentDigest>,
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let d = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required");
    }
    Ok(d)
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let p = PathBuf::from(text);
    if !p.is_absolute()
        || p.file_name().is_none()
        || p.components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("absolute normal-component path required");
    }
    Ok(p)
}

impl Options {
    pub(crate) fn parse(arguments: &[OsString]) -> Result<Self, &'static str> {
        let replay = arguments.first().is_some_and(|s| s == "replay");
        let args = if replay { &arguments[1..] } else { arguments };
        if args.len() > 120
            || !args.len().is_multiple_of(2)
            || args.iter().any(|a| a.as_encoded_bytes().len() > 4096)
        {
            return Err("bounded JPEG option/value pairs required");
        }
        let allowed = [
            "--root",
            "--peer",
            "--authority",
            "--presentation",
            "--control-root",
            "--sensor-id",
            "--stream-id",
            "--generation",
            "--ingress",
            "--ssrc",
            "--anchor",
            "--receive-clock",
            "--retention-evidence",
            "--owner-authorized",
            "--plaintext",
            "--retain-originals",
            "--stop-after-pictures",
            "--payload-type",
            "--approve",
            "--principal",
            "--media-index",
            "--rtp-channel",
            "--timeout-ms",
            "--max-steps",
            "--max-source-bytes",
            "--max-datagrams",
            "--max-storage-bytes",
            "--source-work",
            "--decode-work",
            "--max-report-bytes",
            "--read-bytes",
            "--max-io-calls",
            "--connect-timeout-ms",
            "--response-timeout-ms",
            "--max-frame-bytes",
            "--max-dimension",
            "--max-fragments",
            "--frame-timeout-ms",
            "--reorder-delay-ms",
            "--max-cached-quantizers",
            "--credential-file",
            "--auth-realm",
            "--legacy-md5",
            "--legacy-no-qop",
            "--prefix-head",
            "--prefix-datagrams",
            "--prefix-bytes",
            "--configuration-evidence",
            "--reduced-rtcp",
        ];
        let mut values = BTreeMap::new();
        for pair in args.chunks_exact(2) {
            let k = pair[0].to_str().ok_or("UTF-8 JPEG option required")?;
            let v = pair[1].to_str().ok_or("UTF-8 JPEG value required")?;
            if !allowed.contains(&k)
                || v.is_empty()
                || v.starts_with("--")
                || values.insert(k, v).is_some()
            {
                return Err("unknown/duplicate JPEG option or missing value");
            }
        }
        let required = |k| values.get(k).copied().ok_or("required JPEG option missing");
        for k in ["--owner-authorized", "--plaintext", "--retain-originals"] {
            if required(k)? != "yes" {
                return Err("explicit ownership/plaintext/original-retention approval required");
            }
        }
        let number = |k, default, low, high| -> Result<u64, &'static str> {
            let n = match values.get(k) {
                None => default,
                Some(s) if s.bytes().all(|b| b.is_ascii_digit()) => {
                    s.parse().map_err(|_| "integer overflow")?
                }
                _ => return Err("unsigned decimal integer required"),
            };
            if n < low || n > high {
                return Err("JPEG bound outside admitted range");
            }
            Ok(n)
        };
        let peer: SocketAddr = required("--peer")?
            .parse()
            .map_err(|_| "literal IP:PORT required")?;
        if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
            return Err("unicast concrete peer required");
        }
        let ingress = required("--ingress")?
            .parse::<u128>()
            .map_err(|_| "decimal ingress required")?;
        if !required("--ingress")?.bytes().all(|b| b.is_ascii_digit()) || ingress == 0 {
            return Err("nonzero decimal ingress required");
        }
        for key in ["--generation", "--ssrc"] {
            required(key)?;
        }
        let key = StreamKey {
            ingress,
            generation: number("--generation", 0, 1, u64::MAX)?,
            ssrc: number("--ssrc", 0, 1, u32::MAX as u64)? as u32,
        };
        let binding = TcpBinding::new(
            key,
            peer,
            required("--authority")?,
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
        .map_err(|_| "RTSP binding refused")?;
        let channel = number("--rtp-channel", 0, 0, 254)? as u8;
        let timeout_ns = number("--timeout-ms", 30_000, 1, 3_600_000)? * 1_000_000;
        let protocol = ClientConfig {
            presentation_uri: format!(
                "rtsp://{}{}",
                binding.authority(),
                required("--presentation")?
            ),
            control_root_uri: format!(
                "rtsp://{}{}",
                binding.authority(),
                required("--control-root")?
            ),
            media_index: number("--media-index", 0, 0, 15)? as usize,
            channels: (channel, channel + 1),
            response_timeout_ns: number("--response-timeout-ms", 5000, 1, 60_000)? * 1_000_000,
            default_session_timeout_seconds: 60,
        };
        if !required("--presentation")?.starts_with('/')
            || !required("--control-root")?.starts_with('/')
        {
            return Err("absolute RTSP paths required");
        }
        let payload_type = number("--payload-type", 26, 0, 127)? as u8;
        RtspClientSession::with_codec_and_payload_type(
            protocol.clone(),
            ClientCodec::Jpeg,
            payload_type,
        )
        .map_err(|_| "JPEG session configuration refused")?;
        let total = number(
            "--max-source-bytes",
            64 * 1024 * 1024,
            1,
            1024 * 1024 * 1024,
        )?;
        let transport = TcpLimits {
            max_received_bytes: total,
            max_sent_bytes: 1024 * 1024,
            max_io_calls: number("--max-io-calls", 1_000_000, 1, 10_000_000)?,
            max_request_bytes: 32 * 1024,
            chunk_bytes: number("--read-bytes", 4096, 1, 4096)? as usize,
            connect_timeout_ns: number("--connect-timeout-ms", 5000, 1, 60_000)? * 1_000_000,
        };
        transport
            .validate()
            .map_err(|_| "transport limits refused")?;
        let reorder = ReorderLimits {
            max_delay_ns: number("--reorder-delay-ms", 100, 1, 60_000)? * 1_000_000,
            ..ReorderLimits::default()
        };
        let jpeg = JpegLimits {
            max_frame_bytes: number("--max-frame-bytes", 8 * 1024 * 1024, 1024, 16 * 1024 * 1024)?
                as usize,
            max_fragment_packets: number("--max-fragments", 4096, 1, 4096)? as usize,
            max_pending_age_ns: number("--frame-timeout-ms", 2000, 1, 60_000)? * 1_000_000,
            max_cached_quantizers: number("--max-cached-quantizers", 127, 0, 127)? as usize,
            max_dimension: number("--max-dimension", 2040, 8, 2040)? as u16,
        };
        JpegReceiver::new(key, payload_type, reorder, jpeg)
            .map_err(|_| "JPEG receiver limits refused")?;
        let count = number("--max-datagrams", 8192, 1, 65_536)? as usize;
        let storage = LocalPublicationLimits::new(
            count,
            2,
            count,
            2 * count + 16,
            SpoolLimits::new(
                3 * count + 16,
                number(
                    "--max-storage-bytes",
                    256 * 1024 * 1024,
                    65_536,
                    1024 * 1024 * 1024,
                )?,
                65_536,
                3 * count + 16,
            ),
        );
        storage
            .validate()
            .map_err(|_| "source storage limits refused")?;
        let scope = DatagramScope {
            binding,
            channels: protocol.channels,
            receive_clock: digest(required("--receive-clock")?)?,
            retention_evidence: digest(required("--retention-evidence")?)?,
        };
        let archive = DatagramArchiveLimits {
            max_datagrams: count,
            max_payload_bytes: total,
            max_scan_roots: 2 * count + 16,
            max_spool_object_bytes: 65_536,
        };
        DatagramArchive::new(scope.clone(), archive)
            .map_err(|_| "source archive configuration refused")?;
        let root = path(required("--root")?)?;
        let authentication = AuthPlan::parse(&values, path)?;
        if let Some(auth) = &authentication {
            if root.starts_with(&auth.credential_file) || auth.credential_file.starts_with(&root) {
                return Err("credentials and source store must be separate");
            }
        }
        let replay_keys = [
            "--prefix-head",
            "--prefix-datagrams",
            "--prefix-bytes",
            "--configuration-evidence",
            "--reduced-rtcp",
        ];
        if !replay && replay_keys.iter().any(|k| values.contains_key(k)) {
            return Err("prefix selection requires replay mode");
        }
        if replay && (authentication.is_some() || values.contains_key("--stop-after-pictures")) {
            return Err("cold replay cannot borrow credentials or truncate its selected prefix");
        }
        let replay = if replay {
            for k in replay_keys {
                required(k)?;
            }
            Some(ReplaySelection {
                head: digest(required("--prefix-head")?)?,
                datagrams: number("--prefix-datagrams", 0, 0, count as u64)?,
                bytes: number("--prefix-bytes", 0, 0, total)?,
                configuration: digest(required("--configuration-evidence")?)?,
                reduced_rtcp: match required("--reduced-rtcp")? {
                    "yes" => true,
                    "no" => false,
                    _ => return Err("explicit reduced RTCP yes/no required"),
                },
            })
        } else {
            None
        };
        let sensor = required("--sensor-id")?.to_owned();
        SensorId::parse(&sensor).map_err(|_| "invalid sensor identity")?;
        let stream = required("--stream-id")?.to_owned();
        StreamId::parse(&stream).map_err(|_| "invalid stream identity")?;
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if [&sensor, &stream, &principal].iter().any(|s| s.len() > 256) {
            return Err("identity length bound");
        }
        let options = Self {
            root,
            principal,
            sensor,
            stream,
            anchor: digest(required("--anchor")?)?,
            scope,
            protocol,
            transport,
            reorder,
            jpeg,
            decode: DecodeLimits {
                maximum_bytes: jpeg.max_frame_bytes,
                maximum_dimension: u32::from(jpeg.max_dimension),
                maximum_pixels: usize::from(jpeg.max_dimension).pow(2),
                maximum_markers: 32,
            },
            archive,
            storage,
            payload_type,
            timeout_ns,
            max_steps: number("--max-steps", 100_000, 1, 10_000_000)?,
            frames: number("--stop-after-pictures", 1, 1, 256)?,
            source_work: number("--source-work", 1_000_000_000, 1, 100_000_000_000)?,
            decode_work: number("--decode-work", 10_000_000_000, 1, 1_000_000_000_000)?,
            report_bytes: number(
                "--max-report-bytes",
                8 * 1024 * 1024,
                16 * 1024,
                64 * 1024 * 1024,
            )? as usize,
            authentication,
            replay,
            approval: values.get("--approve").map(|s| digest(s)).transpose()?,
        };
        options.digest()?;
        Ok(options)
    }

    pub(crate) fn config(&self) -> LiveJpegConfig {
        LiveJpegConfig {
            protocol: self.protocol.clone(),
            binding: self.scope.binding.clone(),
            transport: self.transport,
            reorder: self.reorder,
            payload_type: self.payload_type,
            jpeg: self.jpeg,
            realm: self
                .authentication
                .as_ref()
                .map_or("unconfigured-owner-realm", |a| a.realm.as_str())
                .to_owned(),
            digest_policy: self
                .authentication
                .as_ref()
                .map_or(DigestPolicy::default(), |a| a.policy),
            deadline_ns: self.timeout_ns,
            max_steps: self.max_steps,
        }
    }
    pub(crate) fn pin(&self) -> Result<DatagramPin, &'static str> {
        let r = self.replay.ok_or("replay selection required")?;
        Ok(DatagramPin {
            scope: self.scope.digest().map_err(|_| "scope refused")?,
            head: r.head,
            datagrams: r.datagrams,
            payload_bytes: r.bytes,
        })
    }
    pub(crate) fn digest(&self) -> Result<ContentDigest, &'static str> {
        // Canonical encoding binds every exposed effective setting. A future setting
        // must enter this contract before it can influence an approved execution.
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_jpeg_capture_plan.v1");
        e.text(POLICY);
        for s in [
            self.root.to_str().ok_or("UTF-8 root required")?,
            &self.principal,
            &self.sensor,
            &self.stream,
            &self.protocol.presentation_uri,
            &self.protocol.control_root_uri,
        ] {
            e.text(s);
        }
        e.digest(self.anchor);
        e.digest(self.scope.digest().map_err(|_| "scope refused")?);
        for n in [
            self.protocol.media_index as u64,
            self.protocol.response_timeout_ns,
            self.protocol.default_session_timeout_seconds as u64,
            self.transport.max_received_bytes,
            self.transport.max_sent_bytes,
            self.transport.max_io_calls,
            self.transport.max_request_bytes as u64,
            self.transport.chunk_bytes as u64,
            self.transport.connect_timeout_ns,
            self.reorder.max_packets as u64,
            self.reorder.max_bytes as u64,
            self.reorder.max_delay_ns,
            self.jpeg.max_frame_bytes as u64,
            self.jpeg.max_fragment_packets as u64,
            self.jpeg.max_pending_age_ns,
            self.jpeg.max_cached_quantizers as u64,
            u64::from(self.jpeg.max_dimension),
            self.decode.maximum_bytes as u64,
            u64::from(self.decode.maximum_dimension),
            self.decode.maximum_pixels as u64,
            self.decode.maximum_markers as u64,
            self.archive.max_datagrams as u64,
            self.archive.max_payload_bytes,
            self.archive.max_scan_roots as u64,
            self.archive.max_spool_object_bytes as u64,
            self.storage.max_roots as u64,
            self.storage.max_children as u64,
            self.storage.max_tombstones as u64,
            self.storage.max_scan_entries as u64,
            self.storage.spool.max_objects as u64,
            self.storage.spool.max_total_bytes,
            self.storage.spool.max_object_bytes as u64,
            self.storage.spool.max_scan_entries as u64,
            u64::from(self.payload_type),
            self.timeout_ns,
            self.max_steps,
            self.frames,
            self.source_work,
            self.decode_work,
            self.report_bytes as u64,
        ] {
            e.u64(n);
        }
        e.tag(self.protocol.channels.0);
        e.tag(self.protocol.channels.1);
        e.u64(self.reorder.packet.max_packet_bytes as u64);
        e.u64(self.reorder.packet.max_extension_bytes as u64);
        e.u64(self.reorder.packet.max_rtcp_packets as u64);
        if let Some(a) = &self.authentication {
            e.tag(1);
            e.text(
                a.credential_file
                    .to_str()
                    .ok_or("UTF-8 credential path required")?,
            );
            e.text(&a.realm);
            e.tag(u8::from(a.policy.allow_legacy_md5));
            e.tag(u8::from(a.policy.allow_legacy_no_qop));
        } else {
            e.tag(0);
        }
        if let Some(r) = self.replay {
            e.tag(1);
            e.digest(r.head);
            e.u64(r.datagrams);
            e.u64(r.bytes);
            e.digest(r.configuration);
            e.tag(u8::from(r.reduced_rtcp));
        } else {
            e.tag(0);
        }
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| "JPEG plan encoding bound")?,
        ))
    }
    pub(crate) fn admit(&self) -> Result<(), &'static str> {
        if self.approval != Some(self.digest()?) {
            return Err("ERR-CAPTURE-RTSP-APPROVAL-001");
        }
        Ok(())
    }
    pub(crate) fn preview(&self) -> Result<String, &'static str> {
        let key = self.scope.binding.key();
        Ok(object(&[
            ("schema", string(SCHEMA)),
            ("phase", string("planned")),
            (
                "mode",
                string(if self.replay.is_some() {
                    "replay"
                } else {
                    "capture"
                }),
            ),
            ("approval", string(&self.digest()?.to_text())),
            ("policy", string(POLICY)),
            (
                "root",
                string(self.root.to_str().ok_or("UTF-8 path required")?),
            ),
            ("principal", string(&self.principal)),
            ("anchor", string(&self.anchor.to_text())),
            ("sensor", string(&self.sensor)),
            ("stream", string(&self.stream)),
            (
                "scope",
                string(&self.scope.digest().map_err(|_| "scope refused")?.to_text()),
            ),
            ("ingress", string(&key.ingress.to_string())),
            ("generation", key.generation.to_string()),
            ("ssrc", key.ssrc.to_string()),
            ("receive_clock", string(&self.scope.receive_clock.to_text())),
            (
                "retention_evidence",
                string(&self.scope.retention_evidence.to_text()),
            ),
            ("peer", string(&self.scope.binding.peer().to_string())),
            ("authority", string(self.scope.binding.authority())),
            ("presentation", string(&self.protocol.presentation_uri)),
            ("control_root", string(&self.protocol.control_root_uri)),
            ("media_index", self.protocol.media_index.to_string()),
            ("rtp_channel", self.protocol.channels.0.to_string()),
            ("rtcp_channel", self.protocol.channels.1.to_string()),
            ("payload_type", self.payload_type.to_string()),
            (
                "stop_after_pictures",
                if self.replay.is_some() {
                    "null".into()
                } else {
                    self.frames.to_string()
                },
            ),
            ("timeout_ns", self.timeout_ns.to_string()),
            ("max_steps", self.max_steps.to_string()),
            ("max_report_bytes", self.report_bytes.to_string()),
            ("source_work", self.source_work.to_string()),
            ("decode_work", self.decode_work.to_string()),
            (
                "transport",
                object(&[
                    (
                        "max_received_bytes",
                        self.transport.max_received_bytes.to_string(),
                    ),
                    ("max_sent_bytes", self.transport.max_sent_bytes.to_string()),
                    ("max_io_calls", self.transport.max_io_calls.to_string()),
                    (
                        "max_request_bytes",
                        self.transport.max_request_bytes.to_string(),
                    ),
                    ("read_bytes", self.transport.chunk_bytes.to_string()),
                    (
                        "connect_timeout_ns",
                        self.transport.connect_timeout_ns.to_string(),
                    ),
                    (
                        "response_timeout_ns",
                        self.protocol.response_timeout_ns.to_string(),
                    ),
                    (
                        "default_session_timeout_seconds",
                        self.protocol.default_session_timeout_seconds.to_string(),
                    ),
                ]),
            ),
            (
                "reorder",
                object(&[
                    ("max_packets", self.reorder.max_packets.to_string()),
                    ("max_bytes", self.reorder.max_bytes.to_string()),
                    ("max_delay_ns", self.reorder.max_delay_ns.to_string()),
                    (
                        "max_packet_bytes",
                        self.reorder.packet.max_packet_bytes.to_string(),
                    ),
                    (
                        "max_extension_bytes",
                        self.reorder.packet.max_extension_bytes.to_string(),
                    ),
                    (
                        "max_rtcp_packets",
                        self.reorder.packet.max_rtcp_packets.to_string(),
                    ),
                ]),
            ),
            (
                "jpeg",
                object(&[
                    ("max_frame_bytes", self.jpeg.max_frame_bytes.to_string()),
                    (
                        "max_fragment_packets",
                        self.jpeg.max_fragment_packets.to_string(),
                    ),
                    (
                        "max_pending_age_ns",
                        self.jpeg.max_pending_age_ns.to_string(),
                    ),
                    (
                        "max_cached_quantizers",
                        self.jpeg.max_cached_quantizers.to_string(),
                    ),
                    ("max_dimension", self.jpeg.max_dimension.to_string()),
                ]),
            ),
            (
                "decoder",
                object(&[
                    ("maximum_bytes", self.decode.maximum_bytes.to_string()),
                    (
                        "maximum_dimension",
                        self.decode.maximum_dimension.to_string(),
                    ),
                    ("maximum_pixels", self.decode.maximum_pixels.to_string()),
                    ("maximum_markers", self.decode.maximum_markers.to_string()),
                ]),
            ),
            (
                "archive",
                object(&[
                    ("max_datagrams", self.archive.max_datagrams.to_string()),
                    (
                        "max_payload_bytes",
                        self.archive.max_payload_bytes.to_string(),
                    ),
                    ("max_scan_roots", self.archive.max_scan_roots.to_string()),
                    (
                        "max_spool_object_bytes",
                        self.archive.max_spool_object_bytes.to_string(),
                    ),
                ]),
            ),
            (
                "storage",
                object(&[
                    ("max_roots", self.storage.max_roots.to_string()),
                    ("max_children", self.storage.max_children.to_string()),
                    ("max_tombstones", self.storage.max_tombstones.to_string()),
                    (
                        "max_scan_entries",
                        self.storage.max_scan_entries.to_string(),
                    ),
                    ("max_objects", self.storage.spool.max_objects.to_string()),
                    (
                        "max_total_bytes",
                        self.storage.spool.max_total_bytes.to_string(),
                    ),
                    (
                        "max_object_bytes",
                        self.storage.spool.max_object_bytes.to_string(),
                    ),
                    (
                        "max_spool_scan_entries",
                        self.storage.spool.max_scan_entries.to_string(),
                    ),
                ]),
            ),
            (
                "replay",
                self.replay.map_or_else(
                    || "null".into(),
                    |r| {
                        object(&[
                            ("head", string(&r.head.to_text())),
                            ("datagrams", r.datagrams.to_string()),
                            ("payload_bytes", r.bytes.to_string()),
                            ("configuration_evidence", string(&r.configuration.to_text())),
                            ("reduced_rtcp", r.reduced_rtcp.to_string()),
                        ])
                    },
                ),
            ),
            ("source_encrypted", "false".into()),
            ("capture_clock", "null".into()),
            ("control_messages_retained", "false".into()),
            ("automatic_reconnect", "false".into()),
            (
                "authentication",
                self.authentication
                    .as_ref()
                    .map_or_else(|| "null".into(), AuthPlan::preview),
            ),
            (
                "approved_storage_effects",
                string("native-locks-recovery-holds-temporary-metadata-cleanup-fsync"),
            ),
            ("effects", string("none-until-exact-approval")),
        ]))
    }
}
