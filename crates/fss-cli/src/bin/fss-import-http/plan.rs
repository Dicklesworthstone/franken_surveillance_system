#![forbid(unsafe_code)]
//! Pure, canonical HTTP-prefix import planning shared by the importer and live capture bridges.
//!
//! This owner preserves the original argument admission, approval bytes and plan projection.
//! Parsing and preview perform no filesystem, clock, publication or network operations.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::CaptureHint;
use fss_reference::ingest::http_archive::{HttpWirePin, HttpWireScope};
use fss_reference::ingest::http_import::{HttpImportRequest, MAX_BYTES, MAX_FRAMES};

pub(super) const FORMAT: &str = "fss.http_mjpeg_import_operator.v1";

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub request: HttpImportRequest,
    pub work: u64,
    pub framing: u64,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
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
            || args.len() > 64
            || !args.len().is_multiple_of(2)
            || args.iter().any(|s| s.as_encoded_bytes().len() > 4096)
        {
            return Err("argument count or byte bound");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--source",
            "--generation",
            "--receive-clock",
            "--retention-evidence",
            "--head",
            "--reads",
            "--bytes",
            "--sensor-id",
            "--stream-id",
            "--receive-time-ns",
            "--capture-start-ns",
            "--capture-uncertainty-ns",
            "--fps",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve",
            "--max-frames",
            "--max-source-bytes",
            "--max-work",
            "--max-framing-work",
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
        let number = |key: &str, default: u64, high: u64| -> Result<u64, &'static str> {
            let n = match values.get(key) {
                None => default,
                Some(text) if text.bytes().all(|b| b.is_ascii_digit()) => {
                    text.parse().map_err(|_| "integer overflow")?
                }
                Some(_) => return Err("unsigned decimal integer required"),
            };
            if n == 0 || n > high {
                return Err("numeric bound exceeded");
            }
            Ok(n)
        };
        for key in ["--generation", "--reads", "--bytes"] {
            let _ = required(key)?;
        }
        let source = HttpWireScope {
            stream: StreamBasis {
                source: digest(required("--source")?)?.bytes(),
                generation: number("--generation", 0, u64::MAX)?,
            },
            receive_clock: digest(required("--receive-clock")?)?.bytes(),
            retention_evidence: digest(required("--retention-evidence")?)?.bytes(),
        };
        let pin = HttpWirePin {
            scope: source.digest().map_err(|_| "invalid source scope")?,
            head: digest(required("--head")?)?,
            reads: number("--reads", 0, 4096)?,
            bytes: number("--bytes", 0, MAX_BYTES)?,
        };
        let capture_hint = if ["--capture-start-ns", "--capture-uncertainty-ns", "--fps"]
            .iter()
            .any(|k| values.contains_key(k))
        {
            let start = required("--capture-start-ns")?
                .parse()
                .map_err(|_| "invalid capture start")?;
            let uncertainty = required("--capture-uncertainty-ns")?
                .parse()
                .map_err(|_| "invalid capture uncertainty")?;
            let fps = required("--fps")?
                .parse()
                .map_err(|_| "invalid assumed frame rate")?;
            Some(
                CaptureHint::new(TimestampNs(start), uncertainty, fps)
                    .map_err(|_| "invalid capture hint")?,
            )
        } else {
            None
        };
        let request = HttpImportRequest {
            source,
            pin,
            sensor: SensorId::parse(required("--sensor-id")?).map_err(|_| "invalid sensor")?,
            stream: StreamId::parse(required("--stream-id")?).map_err(|_| "invalid stream")?,
            receive_time: TimestampNs(
                required("--receive-time-ns")?
                    .parse()
                    .map_err(|_| "invalid explicit receive time")?,
            ),
            capture_hint,
            max_frames: number("--max-frames", 128, MAX_FRAMES as u64)? as usize,
            max_bytes: number("--max-source-bytes", MAX_BYTES, MAX_BYTES)?,
        };
        request.digest().map_err(|_| "invalid request")?;
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested stores required");
        }
        let site = required("--site")?.to_owned();
        if site.len() > 256 || site.chars().any(char::is_control) {
            return Err("invalid site");
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal byte bound");
        }
        Ok(Self {
            archive,
            root,
            site,
            principal,
            request,
            work: number("--max-work", 1_000_000_000_000, 1_000_000_000_000_000)?,
            framing: number("--max-framing-work", 10_000_000_000, 1_000_000_000_000_000)?,
            timeout_ms: number("--timeout-ms", 30_000, 600_000)?,
            approve: values.get("--approve").map(|s| digest(s)).transpose()?,
        })
    }
    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_mjpeg_import_cli_plan.v1");
        e.text("original-read:source-closed-destination-retention:no-network:v1");
        e.digest(self.request.digest().map_err(|_| "invalid request")?);
        e.text(self.archive.to_str().ok_or("UTF-8 path required")?);
        e.text(self.root.to_str().ok_or("UTF-8 path required")?);
        e.text(&self.site);
        e.text(&self.principal);
        e.u64(self.work);
        e.u64(self.framing);
        e.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(&e.finish()))
    }
    pub fn preview(&self) -> Result<String, &'static str> {
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
                    &self
                        .request
                        .digest()
                        .map_err(|_| "invalid request")?
                        .to_text(),
                ),
            ),
            ("source_scope", string(&self.request.pin.scope.to_text())),
            (
                "source",
                object(&[
                    (
                        "identity",
                        string(
                            &ContentDigest::new(
                                DigestAlgorithm::Sha256,
                                self.request.source.stream.source,
                            )
                            .to_text(),
                        ),
                    ),
                    (
                        "generation",
                        self.request.source.stream.generation.to_string(),
                    ),
                    (
                        "receive_clock",
                        string(
                            &ContentDigest::new(
                                DigestAlgorithm::Sha256,
                                self.request.source.receive_clock,
                            )
                            .to_text(),
                        ),
                    ),
                    (
                        "retention_evidence",
                        string(
                            &ContentDigest::new(
                                DigestAlgorithm::Sha256,
                                self.request.source.retention_evidence,
                            )
                            .to_text(),
                        ),
                    ),
                ]),
            ),
            ("head", string(&self.request.pin.head.to_text())),
            ("original_reads", self.request.pin.reads.to_string()),
            ("original_bytes", self.request.pin.bytes.to_string()),
            ("sensor_id", string(self.request.sensor.as_str())),
            ("stream_id", string(self.request.stream.as_str())),
            (
                "receive_time_ns",
                string(&self.request.receive_time.0.to_string()),
            ),
            (
                "capture_time_label",
                string(if self.request.capture_hint.is_some() {
                    "operator_assumption"
                } else {
                    "unknown"
                }),
            ),
            (
                "capture_hint",
                self.request.capture_hint.map_or_else(
                    || "null".into(),
                    |h| {
                        object(&[
                            ("start_ns", string(&h.start_ns.0.to_string())),
                            ("uncertainty_ns", h.uncertainty_ns.to_string()),
                            ("assumed_fps", h.assumed_fps.to_string()),
                        ])
                    },
                ),
            ),
            ("maximum_frames", self.request.max_frames.to_string()),
            ("maximum_source_bytes", self.request.max_bytes.to_string()),
            ("maximum_work", self.work.to_string()),
            ("maximum_framing_work", self.framing.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("writes", string("none")),
            ("network", string("none")),
            (
                "retention",
                string("all_original_headers_media_and_tail_in_destination_custody"),
            ),
        ]))
    }
}
