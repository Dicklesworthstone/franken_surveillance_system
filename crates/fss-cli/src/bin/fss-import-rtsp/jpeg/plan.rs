#![forbid(unsafe_code)]
//! Pure exact-source selection and explicit physical camera mapping.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId, TimestampNs,
};
use fss_object::SpoolLimits;
use fss_packet::jpeg::{JpegLimits, JpegReceiver};
use fss_packet::{ReorderLimits, StreamKey};
use fss_publication::LocalPublicationLimits;
use fss_reference::ingest::rtsp_jpeg_import::{
    JpegImportRequest, MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, MAX_READ_BYTES,
    MAX_SCAN_ROOTS, MAX_SOURCE_BYTES, MAX_SOURCE_DATAGRAMS, MAX_STEPS,
};
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use fss_reference::rtsp::datagram_reconstruction::jpeg::JpegReplaySpec;
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};

pub(super) const FORMAT: &str = "fss.rtsp_jpeg_import_operator.v1";
pub(super) const MAX_ARGUMENTS: usize = 112;
pub(super) const MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub(super) const AUTHORITY_BYTES: u64 = 4_294_967_296;
pub(super) const AUTHORITY_STORAGE_OPERATIONS: u64 = 1_000_000;
pub(super) const CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];
pub(super) const HELP: &str = "fss-import-rtsp jpeg --archive EXISTING_ABSOLUTE_SOURCE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --peer IP:PORT --authority HOST[:PORT] --ingress N --generation N --ssrc N\n\
  --receive-clock sha256:HEX --retention-evidence sha256:HEX\n\
  --prefix-scope sha256:HEX --prefix-head sha256:HEX --prefix-datagrams N --prefix-bytes N\n\
  --configuration-evidence sha256:HEX --reduced-rtcp yes|no\n\
  --sensor-id ID --stream-id ID --mapping-evidence sha256:HEX --receive-time-ns N\n\
  --owner-authorized yes --read-originals yes --retain-originals yes [--approve sha256:PLAN]\n\
  [--principal principal:local-operator] [--rtp-channel 0] [--rtcp-channel 1] [--payload-type 26]\n\n\
Without --approve, print an exact plan without filesystem, clock or network I/O.\n\
Approved execution reads the entire independently pinned prefix, reconstructs every complete\n\
JPEG using native RFC 2435 semantics, and retains its original datagram closure in the destination.\n\
The physical sensor/stream mapping is explicit operator evidence; a route or SSRC does not prove it.\n\
Capture time stays unknown. RTP ticks and receive times do not establish a capture clock or FPS.\n\
Reconstruction does not validate JPEG entropy or decode pixels; use fss-file decode afterward.\n\
Prefix exhaustion is not EOF or live coverage. Packet gaps and incomplete tails stay explicit.\n\
Exact retries verify original custody; successful destination analysis no longer needs the source store.\n\
Current destination privacy masks apply when decoding. Original bytes remain local unencrypted.\n\
Source and destination must be distinct, non-nested stores. No network connection is opened.\n\
Opening existing source storage takes its exclusive lock and can complete publication recovery.\n\n\
Replay settings must match the intended interpretation; defaults match JPEG capture:\n\
  --reorder-delay-ms 100 --max-frame-bytes 8388608 --max-dimension 2040\n\
  --max-fragments 4096 --frame-timeout-ms 2000 --max-cached-quantizers 127\n\
Independent whole-operation ceilings (excess input refuses, never silently truncates):\n\
  --max-datagrams 8192 --max-source-bytes 67108864 --max-original-bytes 67108864\n\
  --max-media-bytes 67108864 --max-read-bytes 536870912 --max-frames 256\n\
  --max-steps 100000 --max-work 1000000000000 --timeout-ms 30000\n";

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub request: JpegImportRequest,
    pub work: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path.file_name().is_none()
        || text.split('/').any(|part| matches!(part, "." | ".."))
        || text.chars().any(char::is_control)
    {
        return Err("non-root absolute path without dot components required");
    }
    Ok(path)
}

fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let value = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(value)
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("bounded JPEG option/value pairs required");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--peer",
            "--authority",
            "--ingress",
            "--generation",
            "--ssrc",
            "--rtp-channel",
            "--rtcp-channel",
            "--receive-clock",
            "--retention-evidence",
            "--prefix-scope",
            "--prefix-head",
            "--prefix-datagrams",
            "--prefix-bytes",
            "--configuration-evidence",
            "--payload-type",
            "--reduced-rtcp",
            "--sensor-id",
            "--stream-id",
            "--mapping-evidence",
            "--receive-time-ns",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve",
            "--max-datagrams",
            "--max-source-bytes",
            "--max-original-bytes",
            "--max-media-bytes",
            "--max-read-bytes",
            "--max-frames",
            "--max-steps",
            "--max-work",
            "--timeout-ms",
            "--reorder-delay-ms",
            "--max-frame-bytes",
            "--max-dimension",
            "--max-fragments",
            "--frame-timeout-ms",
            "--max-cached-quantizers",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if !allowed.contains(&key) || value.is_empty() || value.starts_with("--") {
                return Err("unknown option or missing value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key| {
            values
                .get(key)
                .copied()
                .ok_or("required JPEG option missing")
        };
        for key in [
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, original-read and destination-retention acknowledgements required",
                );
            }
        }
        let number = |key, default, low, high| -> Result<u64, &'static str> {
            let value = match values.get(key) {
                None => default,
                Some(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
                    text.parse().map_err(|_| "integer overflow")?
                }
                Some(_) => return Err("unsigned decimal integer required"),
            };
            if value < low || value > high {
                return Err("JPEG numeric bound exceeded");
            }
            Ok(value)
        };
        for key in [
            "--generation",
            "--ssrc",
            "--prefix-datagrams",
            "--prefix-bytes",
        ] {
            required(key)?;
        }
        let ingress = required("--ingress")?;
        if !ingress.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("nonzero decimal ingress required");
        }
        let ingress = ingress.parse::<u128>().map_err(|_| "ingress overflow")?;
        if ingress == 0 {
            return Err("nonzero decimal ingress required");
        }
        let key = StreamKey {
            ingress,
            generation: number("--generation", 0, 1, u64::MAX)?,
            ssrc: number("--ssrc", 0, 1, u32::MAX as u64)? as u32,
        };
        let peer: SocketAddr = required("--peer")?
            .parse()
            .map_err(|_| "literal IP:PORT required")?;
        let source = DatagramScope {
            binding: TcpBinding::new(
                key,
                peer,
                required("--authority")?,
                TcpSecurityPolicy::OwnerApprovedPlaintext,
            )
            .map_err(|_| "source transport scope refused")?,
            channels: (
                number("--rtp-channel", 0, 0, 255)? as u8,
                number("--rtcp-channel", 1, 0, 255)? as u8,
            ),
            receive_clock: digest(required("--receive-clock")?)?,
            retention_evidence: digest(required("--retention-evidence")?)?,
        };
        let archive_limits = DatagramArchiveLimits {
            max_datagrams: number("--max-datagrams", 8192, 1, MAX_SOURCE_DATAGRAMS as u64)?
                as usize,
            max_payload_bytes: number("--max-source-bytes", MAX_SOURCE_BYTES, 1, MAX_SOURCE_BYTES)?,
            max_scan_roots: MAX_SCAN_ROOTS,
            max_spool_object_bytes: 65_536,
        };
        DatagramArchive::new(source.clone(), archive_limits)
            .map_err(|_| "source archive scope or bounds refused")?;
        let pin = DatagramPin {
            scope: digest(required("--prefix-scope")?)?,
            head: digest(required("--prefix-head")?)?,
            datagrams: number(
                "--prefix-datagrams",
                0,
                1,
                archive_limits.max_datagrams as u64,
            )?,
            payload_bytes: number("--prefix-bytes", 0, 1, archive_limits.max_payload_bytes)?,
        };
        if pin.scope != source.digest().map_err(|_| "source scope refused")? {
            return Err("independent prefix scope disagrees with the declared transport scope");
        }
        let replay = JpegReplaySpec {
            payload_type: number("--payload-type", 26, 0, 127)? as u8,
            reorder: ReorderLimits {
                max_delay_ns: number("--reorder-delay-ms", 100, 1, 60_000)? * 1_000_000,
                ..ReorderLimits::default()
            },
            jpeg: JpegLimits {
                max_frame_bytes: number("--max-frame-bytes", 8_388_608, 1024, 16_777_216)? as usize,
                max_fragment_packets: number("--max-fragments", 4096, 1, 4096)? as usize,
                max_pending_age_ns: number("--frame-timeout-ms", 2000, 1, 60_000)? * 1_000_000,
                max_cached_quantizers: number("--max-cached-quantizers", 127, 0, 127)? as usize,
                max_dimension: number("--max-dimension", 2040, 8, 2040)? as u16,
            },
            reduced_rtcp: match required("--reduced-rtcp")? {
                "yes" => true,
                "no" => false,
                _ => return Err("explicit reduced RTCP yes/no required"),
            },
            configuration_evidence: digest(required("--configuration-evidence")?)?,
        };
        JpegReceiver::new(key, replay.payload_type, replay.reorder, replay.jpeg)
            .map_err(|_| "native JPEG interpretation refused")?;
        let receive = required("--receive-time-ns")?;
        if !receive.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("nonnegative decimal receive timestamp required");
        }
        let request = JpegImportRequest {
            source,
            pin,
            replay,
            sensor: SensorId::parse(required("--sensor-id")?)
                .map_err(|_| "invalid physical sensor identity")?,
            stream: StreamId::parse(required("--stream-id")?)
                .map_err(|_| "invalid physical stream identity")?,
            mapping_evidence: digest(required("--mapping-evidence")?)?,
            receive_time: TimestampNs(receive.parse().map_err(|_| "receive timestamp overflow")?),
            archive_limits,
            max_frames: number("--max-frames", 256, 1, MAX_FRAMES as u64)? as usize,
            max_original_bytes: number(
                "--max-original-bytes",
                MAX_ORIGINAL_BYTES,
                1,
                MAX_ORIGINAL_BYTES,
            )?,
            max_media_bytes: number("--max-media-bytes", MAX_MEDIA_BYTES, 1, MAX_MEDIA_BYTES)?,
            max_read_bytes: number("--max-read-bytes", MAX_READ_BYTES, 1, MAX_READ_BYTES)?,
            max_steps: number("--max-steps", 100_000, 1, MAX_STEPS)?,
        };
        request
            .digest()
            .map_err(|_| "native JPEG import request refused")?;
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested source and destination stores required");
        }
        let site = required("--site")?.to_owned();
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| "invalid site lineage")?;
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if [
            &site,
            &principal,
            request.sensor.as_str(),
            request.stream.as_str(),
        ]
        .iter()
        .any(|s| s.len() > 256)
        {
            return Err("identity byte bound exceeded");
        }
        let options = Self {
            archive,
            root,
            site,
            principal,
            request,
            work: number("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
            timeout_ms: number("--timeout-ms", 30_000, 1, 600_000)?,
            approve: values.get("--approve").map(|s| digest(s)).transpose()?,
        };
        options.preview()?;
        Ok(options)
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text("fss.rtsp_jpeg_import_cli_plan.v1");
        encoded.text("complete-pinned-prefix:explicit-physical-mapping:source-closed-retention:unknown-capture:no-entropy-validation:no-network:v1");
        encoded.digest(
            self.request
                .digest()
                .map_err(|_| "ERR-RTSP-JPEG-IMPORT-REQUEST-001")?,
        );
        for text in [
            self.archive.to_str().ok_or("UTF-8 path required")?,
            self.root.to_str().ok_or("UTF-8 path required")?,
            &self.site,
            &self.principal,
        ] {
            encoded.text(text);
        }
        encoded.u64(self.work);
        encoded.u64(self.timeout_ms);
        encoded.u64(MAX_OUTPUT_BYTES as u64);
        let storage = source_storage_limits();
        for bound in [
            storage.max_roots as u64,
            storage.max_children as u64,
            storage.max_tombstones as u64,
            storage.max_scan_entries as u64,
            storage.spool.max_objects as u64,
            storage.spool.max_total_bytes,
            storage.spool.max_object_bytes as u64,
            storage.spool.max_scan_entries as u64,
            AUTHORITY_BYTES,
            AUTHORITY_STORAGE_OPERATIONS,
        ] {
            encoded.u64(bound);
        }
        Ok(ContentDigest::sha256(
            &encoded
                .finish_checked()
                .map_err(|_| "ERR-RTSP-JPEG-IMPORT-REQUEST-001")?,
        ))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let r = &self.request;
        bounded(object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            (
                "request_digest",
                string(
                    &r.digest()
                        .map_err(|_| "ERR-RTSP-JPEG-IMPORT-REQUEST-001")?
                        .to_text(),
                ),
            ),
            (
                "archive",
                string(self.archive.to_str().ok_or("UTF-8 path required")?),
            ),
            (
                "root",
                string(self.root.to_str().ok_or("UTF-8 path required")?),
            ),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            ("source_scope", source_json(&r.source)?),
            ("prefix", pin_json(r.pin)),
            ("replay", replay_json(r.replay)),
            ("physical_mapping", mapping_json(r)),
            ("receive_time_ns", string(&r.receive_time.0.to_string())),
            ("capture_time_label", string("unknown")),
            ("pixels_decoded", "false".into()),
            ("entropy_validated", "false".into()),
            ("absence_certifiable", "false".into()),
            ("bounds", self.bounds_json()),
            ("writes", string("none")),
            ("network", string("none")),
            (
                "retention",
                string(
                    "complete_selected_original_datagram_graph_and_reconstructed_mjpeg_in_destination",
                ),
            ),
        ]))
    }

    pub fn bounds_json(&self) -> String {
        let r = &self.request;
        object(&[
            (
                "maximum_datagrams",
                r.archive_limits.max_datagrams.to_string(),
            ),
            (
                "maximum_source_bytes",
                r.archive_limits.max_payload_bytes.to_string(),
            ),
            (
                "maximum_scan_roots",
                r.archive_limits.max_scan_roots.to_string(),
            ),
            (
                "maximum_spool_object_bytes",
                r.archive_limits.max_spool_object_bytes.to_string(),
            ),
            ("maximum_original_bytes", r.max_original_bytes.to_string()),
            ("maximum_media_bytes", r.max_media_bytes.to_string()),
            ("maximum_read_bytes", r.max_read_bytes.to_string()),
            ("maximum_frames", r.max_frames.to_string()),
            ("maximum_steps", r.max_steps.to_string()),
            ("maximum_work", self.work.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("maximum_output_bytes", MAX_OUTPUT_BYTES.to_string()),
            ("source_storage", source_storage_json()),
            (
                "authority_budget",
                object(&[
                    ("maximum_bytes", AUTHORITY_BYTES.to_string()),
                    (
                        "maximum_storage_operations",
                        AUTHORITY_STORAGE_OPERATIONS.to_string(),
                    ),
                ]),
            ),
        ])
    }
}

pub(super) const fn source_storage_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        65_536,
        2,
        65_536,
        131_088,
        SpoolLimits::new(196_624, 1_073_741_824, 65_536, 196_624),
    )
}

fn source_storage_json() -> String {
    let limits = source_storage_limits();
    object(&[
        ("maximum_roots", limits.max_roots.to_string()),
        ("maximum_children", limits.max_children.to_string()),
        ("maximum_tombstones", limits.max_tombstones.to_string()),
        ("maximum_scan_entries", limits.max_scan_entries.to_string()),
        (
            "spool",
            object(&[
                ("maximum_objects", limits.spool.max_objects.to_string()),
                (
                    "maximum_total_bytes",
                    limits.spool.max_total_bytes.to_string(),
                ),
                (
                    "maximum_object_bytes",
                    limits.spool.max_object_bytes.to_string(),
                ),
                (
                    "maximum_scan_entries",
                    limits.spool.max_scan_entries.to_string(),
                ),
            ]),
        ),
    ])
}

pub(super) fn bounded(text: String) -> Result<String, &'static str> {
    if text.len() > MAX_OUTPUT_BYTES {
        Err("ERR-RTSP-JPEG-IMPORT-LIMIT-001")
    } else {
        Ok(text)
    }
}

pub(super) fn pin_json(pin: DatagramPin) -> String {
    object(&[
        ("scope", string(&pin.scope.to_text())),
        ("head", string(&pin.head.to_text())),
        ("datagrams", pin.datagrams.to_string()),
        ("payload_bytes", pin.payload_bytes.to_string()),
    ])
}

pub(super) fn source_json(source: &DatagramScope) -> Result<String, &'static str> {
    let key = source.binding.key();
    Ok(object(&[
        (
            "digest",
            string(
                &source
                    .digest()
                    .map_err(|_| "ERR-RTSP-JPEG-IMPORT-REQUEST-001")?
                    .to_text(),
            ),
        ),
        ("peer", string(&source.binding.peer().to_string())),
        ("authority", string(source.binding.authority())),
        ("ingress", string(&key.ingress.to_string())),
        ("generation", key.generation.to_string()),
        ("ssrc", key.ssrc.to_string()),
        ("rtp_channel", source.channels.0.to_string()),
        ("rtcp_channel", source.channels.1.to_string()),
        ("receive_clock", string(&source.receive_clock.to_text())),
        (
            "retention_evidence",
            string(&source.retention_evidence.to_text()),
        ),
        ("transport_identity_proves_physical_camera", "false".into()),
    ]))
}

pub(super) fn mapping_json(request: &JpegImportRequest) -> String {
    object(&[
        ("sensor_id", string(request.sensor.as_str())),
        ("stream_id", string(request.stream.as_str())),
        ("evidence", string(&request.mapping_evidence.to_text())),
        ("class", string("explicit_operator_mapping")),
    ])
}

pub(super) fn replay_json(spec: JpegReplaySpec) -> String {
    object(&[
        (
            "configuration_evidence",
            string(&spec.configuration_evidence.to_text()),
        ),
        ("payload_type", spec.payload_type.to_string()),
        ("reduced_rtcp", spec.reduced_rtcp.to_string()),
        (
            "profile",
            string(fss_packet::jpeg::JPEG_RECONSTRUCTION_PROFILE),
        ),
        (
            "packet",
            object(&[
                (
                    "maximum_packet_bytes",
                    spec.reorder.packet.max_packet_bytes.to_string(),
                ),
                (
                    "maximum_extension_bytes",
                    spec.reorder.packet.max_extension_bytes.to_string(),
                ),
                (
                    "maximum_rtcp_packets",
                    spec.reorder.packet.max_rtcp_packets.to_string(),
                ),
            ]),
        ),
        (
            "reorder",
            object(&[
                ("maximum_packets", spec.reorder.max_packets.to_string()),
                ("maximum_bytes", spec.reorder.max_bytes.to_string()),
                ("maximum_delay_ns", spec.reorder.max_delay_ns.to_string()),
            ]),
        ),
        (
            "jpeg",
            object(&[
                ("maximum_frame_bytes", spec.jpeg.max_frame_bytes.to_string()),
                (
                    "maximum_fragment_packets",
                    spec.jpeg.max_fragment_packets.to_string(),
                ),
                (
                    "maximum_pending_age_ns",
                    spec.jpeg.max_pending_age_ns.to_string(),
                ),
                (
                    "maximum_cached_quantizers",
                    spec.jpeg.max_cached_quantizers.to_string(),
                ),
                ("maximum_dimension", spec.jpeg.max_dimension.to_string()),
            ]),
        ),
    ])
}
