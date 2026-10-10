#![forbid(unsafe_code)]
//! Pure exact-selection and original-retention approval planning.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId, TimestampNs,
};
use fss_publication::SlotName;
use fss_reference::ingest::rtsp_import::{
    MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, RtspCaptureOrigin, RtspImportCodec,
    RtspImportRequest,
};
use fss_reference::rtsp::recording::RecordingScope;

pub(super) const FORMAT: &str = "fss.rtsp_recording_import_operator.v1";
pub(super) const MAX_ARGUMENTS: usize = 64;
pub(super) const CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub request: RtspImportRequest,
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

fn timestamp(text: &str) -> Result<TimestampNs, &'static str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("nonnegative decimal timestamp required");
    }
    Ok(TimestampNs(text.parse().map_err(|_| "timestamp overflow")?))
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("argument count or byte bound exceeded");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--window-slot",
            "--window-root",
            "--codec",
            "--sensor-id",
            "--stream-id",
            "--generation",
            "--anchor",
            "--receive-clock",
            "--receive-time-ns",
            "--capture-start-ns",
            "--capture-uncertainty-ns",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve",
            "--max-frames",
            "--max-original-bytes",
            "--max-media-bytes",
            "--max-work",
            "--timeout-ms",
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
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
        for key in ["--owner-authorized", "--read-originals", "--retain-originals"] {
            if required(key)? != "yes" {
                return Err("explicit owner, original-read and retention acknowledgements required");
            }
        }
        let number = |key: &str, default: u64, maximum: u64| -> Result<u64, &'static str> {
            let value = match values.get(key) {
                None => default,
                Some(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
                    text.parse().map_err(|_| "integer overflow")?
                }
                Some(_) => return Err("unsigned decimal integer required"),
            };
            if value == 0 || value > maximum {
                return Err("numeric bound exceeded");
            }
            Ok(value)
        };
        let capture_origin = if ["--capture-start-ns", "--capture-uncertainty-ns"]
            .iter()
            .any(|key| values.contains_key(key))
        {
            let uncertainty = required("--capture-uncertainty-ns")?;
            if !uncertainty.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("unsigned capture uncertainty required");
            }
            Some(RtspCaptureOrigin {
                start_ns: timestamp(required("--capture-start-ns")?)?,
                uncertainty_ns: uncertainty
                    .parse()
                    .map_err(|_| "capture uncertainty overflow")?,
            })
        } else {
            None
        };
        let _ = required("--generation")?;
        let request = RtspImportRequest {
            codec: match required("--codec")? {
                "avc" => RtspImportCodec::Avc,
                "hevc" => RtspImportCodec::Hevc,
                _ => return Err("codec must be avc or hevc"),
            },
            slot: SlotName::parse(required("--window-slot")?).map_err(|_| "invalid window slot")?,
            root: digest(required("--window-root")?)?,
            source: RecordingScope {
                sensor: SensorId::parse(required("--sensor-id")?).map_err(|_| "invalid sensor")?,
                stream: StreamId::parse(required("--stream-id")?).map_err(|_| "invalid stream")?,
                generation: number("--generation", 0, u64::MAX)?,
                anchor: digest(required("--anchor")?)?,
                receive_clock: digest(required("--receive-clock")?)?,
            },
            receive_time: timestamp(required("--receive-time-ns")?)?,
            capture_origin,
            max_frames: number("--max-frames", MAX_FRAMES as u64, MAX_FRAMES as u64)? as usize,
            max_original_bytes: number(
                "--max-original-bytes",
                MAX_ORIGINAL_BYTES,
                MAX_ORIGINAL_BYTES,
            )?,
            max_media_bytes: number("--max-media-bytes", MAX_MEDIA_BYTES, MAX_MEDIA_BYTES)?,
        };
        request.digest().map_err(|_| "invalid recording request")?;
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested stores required");
        }
        let site = required("--site")?.to_owned();
        if site.len() > 256 || site.chars().any(char::is_control) {
            return Err("invalid site");
        }
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| "invalid site lineage")?;
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal byte bound exceeded");
        }
        Ok(Self {
            archive,
            root,
            site,
            principal,
            request,
            work: number("--max-work", 1_000_000_000_000, 1_000_000_000_000_000)?,
            timeout_ms: number("--timeout-ms", 30_000, 600_000)?,
            approve: values.get("--approve").map(|text| digest(text)).transpose()?,
        })
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text("fss.rtsp_recording_import_cli_plan.v1");
        encoded.text("original-read:source-closed-destination-retention:no-network:v1");
        encoded.digest(self.request.digest().map_err(|_| "invalid recording request")?);
        encoded.text(self.archive.to_str().ok_or("UTF-8 path required")?);
        encoded.text(self.root.to_str().ok_or("UTF-8 path required")?);
        encoded.text(&self.site);
        encoded.text(&self.principal);
        encoded.u64(self.work);
        encoded.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(&encoded.finish()))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let request = &self.request;
        Ok(object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
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
            (
                "request_digest",
                string(
                    &request
                        .digest()
                        .map_err(|_| "invalid recording request")?
                        .to_text(),
                ),
            ),
            ("codec", string(request.codec.as_str())),
            ("window_slot", string(request.slot.as_str())),
            ("window_root", string(&request.root.to_text())),
            ("sensor_id", string(request.source.sensor.as_str())),
            ("stream_id", string(request.source.stream.as_str())),
            ("generation", request.source.generation.to_string()),
            ("source_anchor", string(&request.source.anchor.to_text())),
            ("receive_clock", string(&request.source.receive_clock.to_text())),
            ("receive_time_ns", string(&request.receive_time.0.to_string())),
            (
                "capture_time_label",
                string(if request.capture_origin.is_some() {
                    "operator_assumption"
                } else {
                    "unknown"
                }),
            ),
            (
                "capture_origin",
                request.capture_origin.map_or_else(
                    || "null".into(),
                    |origin| {
                        object(&[
                            ("start_ns", string(&origin.start_ns.0.to_string())),
                            ("uncertainty_ns", origin.uncertainty_ns.to_string()),
                        ])
                    },
                ),
            ),
            (
                "sample_timing",
                string("retained_mp4_presentation_timestamps"),
            ),
            ("maximum_frames", request.max_frames.to_string()),
            ("maximum_original_bytes", request.max_original_bytes.to_string()),
            ("maximum_media_bytes", request.max_media_bytes.to_string()),
            ("maximum_work", self.work.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("writes", string("none")),
            ("network", string("none")),
            (
                "retention",
                string("original_recording_root_rtp_index_initialization_and_fragment_in_destination"),
            ),
        ]))
    }
}
