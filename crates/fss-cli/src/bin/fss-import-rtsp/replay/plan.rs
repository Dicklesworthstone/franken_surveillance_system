#![forbid(unsafe_code)]
//! Pure replay selection and exact original-read/retention approval.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId, SensorId, StreamId};
use fss_reference::ingest::rtsp_import::catalog::{
    MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, MAX_WINDOWS,
};
use fss_reference::ingest::rtsp_import::replay::RtspReplayImportRequest;
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_catalog::CatalogScope;

use super::super::plan::{digest, path, timestamp};

pub(super) const FORMAT: &str = "fss.rtsp_replay_import_operator.v1";
pub(super) const MAX_ARGUMENTS: usize = 64;
pub(super) const HELP: &str = "fss-import-rtsp replay --archive EXISTING_ABSOLUTE_ARCHIVE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --codec avc|hevc --expected-replay-root sha256:HEX --expected-replay-request sha256:HEX\n\
  --sensor-id ID --stream-id ID --generation N --anchor sha256:HEX --receive-clock sha256:HEX\n\
  --decode-clock sha256:HEX --time-scale N --receive-time-ns N\n\
  --owner-authorized yes --read-originals yes --retain-originals yes [--approve sha256:PLAN]\n\
  [--principal principal:local-operator] [--decode-gaps reject|preserve]\n\
  Optional timing: --capture-start-ns N --capture-uncertainty-ns N (both required).\n\
  Bounds: --max-windows 64 --max-frames 16384 --max-original-bytes 134217728\n\
          --max-media-bytes 67108864 --max-work 1000000000000 --timeout-ms 30000.\n\n\
Without --approve, preview the exact plan without filesystem, clock or network I/O.\n\
Approved execution verifies the complete pinned replay receipt and every native original window.\n\
All receipt metadata, source packets, indexes, initialization and fragments are retained together.\n\
The original replay request, approval, requested/acknowledged ranges, termination and any ONVIF\n\
recording-discovery provenance survive ordinary retained decode, inference and review.\n\
The receipt must contain at least one complete window, identical initialization and nonoverlapping\n\
decode intervals. Gaps refuse by default; explicit preserve retains their original timing.\n\
HEVC source-only tails stay evidence and never become media samples. A partial recorder result\n\
remains partial: importing all retained windows does not prove complete upstream retrieval.\n\
Capture time stays unknown or an explicit operator assumption. Replay ranges and RTP assertions\n\
are retained evidence, never implicitly promoted to calibrated frame timestamps or coverage.\n\
Cold destination verification needs no source archive. Exact import retries still verify the source.\n\
Current destination privacy policy applies to analysis. Originals remain local unencrypted.\n\
Source and destination must be distinct non-nested stores. Opening the source takes its existing\n\
exclusive archive lock and may complete publication recovery. No recorder is contacted.\n";

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub request: RtspReplayImportRequest,
    pub work: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err("bounded replay option/value pairs required");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--codec",
            "--expected-replay-root",
            "--expected-replay-request",
            "--sensor-id",
            "--stream-id",
            "--generation",
            "--anchor",
            "--receive-clock",
            "--decode-clock",
            "--time-scale",
            "--receive-time-ns",
            "--capture-start-ns",
            "--capture-uncertainty-ns",
            "--decode-gaps",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve",
            "--max-windows",
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
        let required = |key| {
            values
                .get(key)
                .copied()
                .ok_or("required replay option missing")
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
        let number = |key, default, maximum| -> Result<u64, &'static str> {
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
        let preserve_decode_gaps = match values.get("--decode-gaps").copied() {
            None | Some("reject") => false,
            Some("preserve") => true,
            Some(_) => return Err("decode-gaps must be reject or preserve"),
        };
        required("--generation")?;
        required("--time-scale")?;
        let request = RtspReplayImportRequest {
            codec: match required("--codec")? {
                "avc" => RtspImportCodec::Avc,
                "hevc" => RtspImportCodec::Hevc,
                _ => return Err("codec must be avc or hevc"),
            },
            receipt_root: digest(required("--expected-replay-root")?)?,
            request_identity: digest(required("--expected-replay-request")?)?,
            scope: CatalogScope {
                recording: RecordingScope {
                    sensor: SensorId::parse(required("--sensor-id")?)
                        .map_err(|_| "invalid sensor")?,
                    stream: StreamId::parse(required("--stream-id")?)
                        .map_err(|_| "invalid stream")?,
                    generation: number("--generation", 0, u64::MAX)?,
                    anchor: digest(required("--anchor")?)?,
                    receive_clock: digest(required("--receive-clock")?)?,
                },
                decode_clock: digest(required("--decode-clock")?)?,
                time_scale: number("--time-scale", 0, u32::MAX as u64)? as u32,
            },
            receive_time: timestamp(required("--receive-time-ns")?)?,
            capture_origin,
            preserve_decode_gaps,
            max_windows: number("--max-windows", MAX_WINDOWS as u64, MAX_WINDOWS as u64)? as usize,
            max_frames: number("--max-frames", MAX_FRAMES as u64, MAX_FRAMES as u64)? as usize,
            max_original_bytes: number(
                "--max-original-bytes",
                MAX_ORIGINAL_BYTES,
                MAX_ORIGINAL_BYTES,
            )?,
            max_media_bytes: number("--max-media-bytes", MAX_MEDIA_BYTES, MAX_MEDIA_BYTES)?,
        };
        request
            .digest()
            .map_err(|_| "invalid complete replay request")?;
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
            approve: values
                .get("--approve")
                .map(|text| digest(text))
                .transpose()?,
        })
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text("fss.rtsp_replay_import_cli_plan.v1");
        encoded
            .text("whole-replay-original-read:source-closed-destination-retention:no-network:v1");
        encoded.digest(
            self.request
                .digest()
                .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?,
        );
        encoded.text(self.archive.to_str().ok_or("ERR-RTSP-IMPORT-REQUEST-001")?);
        encoded.text(self.root.to_str().ok_or("ERR-RTSP-IMPORT-REQUEST-001")?);
        encoded.text(&self.site);
        encoded.text(&self.principal);
        encoded.u64(self.work);
        encoded.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(
            &encoded
                .finish_checked()
                .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?,
        ))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let request = &self.request;
        Ok(object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            (
                "archive",
                string(self.archive.to_str().ok_or("ERR-RTSP-IMPORT-REQUEST-001")?),
            ),
            (
                "root",
                string(self.root.to_str().ok_or("ERR-RTSP-IMPORT-REQUEST-001")?),
            ),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            (
                "request_digest",
                string(
                    &request
                        .digest()
                        .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?
                        .to_text(),
                ),
            ),
            ("codec", string(request.codec.as_str())),
            ("replay_root", string(&request.receipt_root.to_text())),
            (
                "replay_request",
                string(&request.request_identity.to_text()),
            ),
            ("sensor_id", string(request.scope.recording.sensor.as_str())),
            ("stream_id", string(request.scope.recording.stream.as_str())),
            ("generation", request.scope.recording.generation.to_string()),
            (
                "source_anchor",
                string(&request.scope.recording.anchor.to_text()),
            ),
            (
                "receive_clock",
                string(&request.scope.recording.receive_clock.to_text()),
            ),
            (
                "decode_clock",
                string(&request.scope.decode_clock.to_text()),
            ),
            ("time_scale", request.scope.time_scale.to_string()),
            (
                "receive_time_ns",
                string(&request.receive_time.0.to_string()),
            ),
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
            (
                "decode_gaps",
                string(if request.preserve_decode_gaps {
                    "preserve"
                } else {
                    "reject"
                }),
            ),
            ("selection", string("complete_replay_receipt")),
            (
                "retention",
                string("complete_replay_receipt_and_every_original_window"),
            ),
            ("maximum_windows", request.max_windows.to_string()),
            ("maximum_frames", request.max_frames.to_string()),
            (
                "maximum_original_bytes",
                request.max_original_bytes.to_string(),
            ),
            ("maximum_media_bytes", request.max_media_bytes.to_string()),
            ("maximum_work", self.work.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("writes", string("none")),
            ("network", string("none")),
            ("continuity_certified", "false".into()),
            ("absence_certifiable", "false".into()),
            ("historical_utc_calibrated", "false".into()),
        ]))
    }
}
