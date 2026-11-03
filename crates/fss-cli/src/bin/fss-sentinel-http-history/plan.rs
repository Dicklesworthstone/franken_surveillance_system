#![forbid(unsafe_code)]
//! Pure history/model admission and exact original-retention approval.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{array, object, string};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId, SensorId, StreamId, TimestampNs,
};
use fss_reference::http_reconnect_history::ReconnectHistoryPin;
use fss_reference::ingest::CaptureHint;
use fss_reference::ingest::http_history_sentinel::{
    HttpHistorySentinelConfig, HttpHistorySentinelLimits, HttpHistorySentinelPlan,
    MAX_HTTP_HISTORY_SENTINEL_INFERENCES,
};
use fss_reference::ingest::http_history_watch::HttpHistoryWatchBinding;
use fss_reference::ingest::http_import::{MAX_BYTES, MAX_FRAMES};
use fss_reference::ingest::long_sentinel::{
    MAX_LONG_SENTINEL_PIXEL_SAMPLES, MAX_LONG_SENTINEL_REPORT_BYTES,
    MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;
use fss_reference::reference_deployment::validate_site_lineage;
use fss_reference::{ExecBudget, ExecThreads, KernelBackend, MAX_EXEC_THREADS};

pub(super) const MAX_ARGUMENTS: usize = 192;
pub(super) const MAX_PREVIEW_BYTES: usize = 256 * 1024;
pub(super) const STORAGE_OPERATIONS: u64 = 1_000_000;
pub(super) const PACKAGE_COMPILE_MACS: u64 = 1 << 36;
pub(super) const FORMAT: &str = "fss.http_history_sentinel_operator.v1";
const POLICY: &str = "exact-http-history:explicit-generation-capture-bindings:owner-original-read:\
source-closed-retention:pinned-local-native-rgb-package:motion-independent:\
round-robin-whole-bursts:shared-history-pools:optional-cognition-retention:\
no-network:no-event:no-continuity:no-absence:v1";

pub(super) struct Options {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub package: PathBuf,
    pub site: String,
    pub principal: String,
    pub plan: HttpHistorySentinelPlan,
    pub limits: HttpHistorySentinelLimits,
    pub threads: ExecThreads,
    pub thread_count: usize,
    pub frame_pixels: Option<u64>,
    pub work: u64,
    pub framing: u64,
    pub archive_read_bytes: u64,
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
    let digest = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(digest)
}

fn integer(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("unsigned decimal integer required");
    }
    text.parse().map_err(|_| "integer overflow")
}

fn binding(text: &str) -> Result<HttpHistoryWatchBinding, &'static str> {
    let parts: Vec<_> = text.split(',').collect();
    let [generation, sensor, stream, receive, start, uncertainty, fps] = parts.as_slice() else {
        return Err(
            "binding requires GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS",
        );
    };
    let timestamp = |value: &str| {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("nonnegative decimal timestamp required");
        }
        value
            .parse::<i128>()
            .map(TimestampNs)
            .map_err(|_| "timestamp overflow")
    };
    Ok(HttpHistoryWatchBinding {
        generation: integer(generation)?,
        sensor: SensorId::parse(*sensor).map_err(|_| "invalid binding sensor")?,
        stream: StreamId::parse(*stream).map_err(|_| "invalid binding stream")?,
        receive_time: timestamp(receive)?,
        capture_hint: CaptureHint::new(
            timestamp(start)?,
            integer(uncertainty)?,
            fps.parse().map_err(|_| "invalid frame rate")?,
        )
        .map_err(|_| "invalid explicit capture hint")?,
    })
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|a| a.as_encoded_bytes().len() > 4096)
        {
            return Err("bounded option/value pairs required");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--history-session",
            "--history-root",
            "--history-connections",
            "--interpretation",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve-import",
            "--max-frames-per-generation",
            "--max-bytes-per-generation",
            "--max-history-reads",
            "--max-history-bytes",
            "--max-report-bytes",
            "--max-work",
            "--max-framing-work",
            "--archive-read-bytes",
            "--timeout-ms",
            "--package",
            "--package-digest",
            "--read-model",
            "--retain-analysis",
            "--minimum-score-ppm",
            "--kernels",
            "--threads",
            "--sentinel-every-frames",
            "--sentinel-burst-frames",
            "--sentinel-max-inferences",
            "--stream-read-bytes",
            "--stream-pixel-budget",
            "--max-frame-pixels",
            "--max-macs",
            "--max-tensor-bytes",
            "--max-output-bytes",
            "--sentinel-report-bytes",
        ];
        let mut values = BTreeMap::new();
        let mut bindings = Vec::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if value.is_empty() || value.starts_with("--") {
                return Err("missing option value");
            }
            if key == "--binding" && bindings.len() < 32 {
                bindings.push(binding(value)?);
            } else if allowed.contains(&key) {
                if values.insert(key, value).is_some() {
                    return Err("duplicate option");
                }
            } else {
                return Err("unknown option or binding bound exceeded");
            }
        }
        let required = |key| values.get(key).copied().ok_or("required option missing");
        for key in [
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--read-model",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, original-read, retention and model-read acknowledgements required",
                );
            }
        }
        let number = |key, default: u64, low, high| -> Result<u64, &'static str> {
            let n = values.get(key).map_or(Ok(default), |v| integer(v))?;
            if n < low || n > high {
                return Err("numeric bound exceeded");
            }
            Ok(n)
        };
        let retain = match required("--retain-analysis")? {
            "yes" => true,
            "no" => false,
            _ => return Err("--retain-analysis requires yes or no"),
        };
        let backend = match values.get("--kernels").copied().unwrap_or("optimized-cpu") {
            "optimized-cpu" => KernelBackend::OptimizedCpuV1,
            "scalar-reference" => KernelBackend::ScalarReference,
            _ => return Err("kernels require optimized-cpu or scalar-reference"),
        };
        let thread_count = number("--threads", 1, 1, MAX_EXEC_THREADS as u64)? as usize;
        let threads = ExecThreads::new(thread_count).map_err(|_| "thread ceiling")?;
        let mut limits = HttpHistorySentinelLimits::default();
        limits.maximum_frames_per_generation = number(
            "--max-frames-per-generation",
            limits.maximum_frames_per_generation as u64,
            1,
            MAX_FRAMES as u64,
        )? as usize;
        limits.maximum_bytes_per_generation = number(
            "--max-bytes-per-generation",
            limits.maximum_bytes_per_generation,
            1,
            MAX_BYTES,
        )?;
        limits.history.maximum_reads =
            number("--max-history-reads", limits.history.maximum_reads, 1, 8192)?;
        limits.history.maximum_bytes = number(
            "--max-history-bytes",
            limits.history.maximum_bytes,
            1,
            512 * 1024 * 1024,
        )?;
        limits.maximum_report_bytes = number(
            "--max-report-bytes",
            limits.maximum_report_bytes as u64,
            1024,
            32 * 1024 * 1024 + 65536,
        )? as usize;
        let sentinel = &mut limits.sentinel;
        sentinel.maximum_source_chunk_bytes = number(
            "--stream-read-bytes",
            sentinel.maximum_source_chunk_bytes,
            1,
            MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
        )?;
        sentinel.maximum_pixel_samples = number(
            "--stream-pixel-budget",
            sentinel.maximum_pixel_samples,
            1,
            MAX_LONG_SENTINEL_PIXEL_SAMPLES,
        )?;
        sentinel.maximum_report_bytes = number(
            "--sentinel-report-bytes",
            sentinel.maximum_report_bytes as u64,
            1,
            MAX_LONG_SENTINEL_REPORT_BYTES as u64,
        )? as usize;
        sentinel.package.run.execution = ExecBudget::new(
            number(
                "--max-macs",
                sentinel.package.run.execution.max_macs,
                0,
                u64::MAX,
            )?,
            number(
                "--max-tensor-bytes",
                sentinel.package.run.execution.max_bytes as u64,
                1,
                256 * 1024 * 1024,
            )? as usize,
        );
        sentinel.package.run.maximum_output_bytes = number(
            "--max-output-bytes",
            sentinel.package.run.maximum_output_bytes as u64,
            1,
            16 * 1024 * 1024,
        )? as usize;
        let frame_pixels = values
            .get("--max-frame-pixels")
            .map(|_| number("--max-frame-pixels", 0, 256, 4096 * 2304))
            .transpose()?;
        if let Some(pixels) = frame_pixels {
            sentinel.package.jpeg.frame.maximum_pixels = sentinel
                .package
                .jpeg
                .frame
                .maximum_pixels
                .min(pixels as usize);
            // Retained native recipes bind every codec ceiling, including inactive codecs.
            // Keep the emitted sentinel-replay command identical to this admission.
            sentinel.package.h264.max_macroblocks = sentinel
                .package
                .h264
                .max_macroblocks
                .min((pixels / 256) as u32);
            sentinel.package.h265.max_luma_samples =
                sentinel.package.h265.max_luma_samples.min(pixels);
        }
        for key in [
            "--sentinel-every-frames",
            "--sentinel-burst-frames",
            "--sentinel-max-inferences",
        ] {
            let _ = required(key)?;
        }
        let plan = HttpHistorySentinelPlan {
            history: ReconnectHistoryPin {
                session: digest(required("--history-session")?)?,
                root: digest(required("--history-root")?)?,
                connections: number("--history-connections", 0, 1, 32)? as u32,
            },
            bindings,
            interpretation: match required("--interpretation")? {
                "gray" => ComponentInterpretation::Grayscale,
                "ycbcr" => ComponentInterpretation::YCbCr,
                _ => return Err("interpretation requires gray or ycbcr"),
            },
            package_digest: digest(required("--package-digest")?)?,
            backend,
            minimum_score_ppm: values
                .get("--minimum-score-ppm")
                .map(|_| number("--minimum-score-ppm", 0, 0, 1_000_000).map(|n| n as u32))
                .transpose()?,
            sampling: HttpHistorySentinelConfig {
                every_frames: number("--sentinel-every-frames", 0, 1, 65536)? as usize,
                burst_frames: number("--sentinel-burst-frames", 0, 1, 8)? as usize,
                max_inferences: number(
                    "--sentinel-max-inferences",
                    0,
                    1,
                    MAX_HTTP_HISTORY_SENTINEL_INFERENCES as u64,
                )? as usize,
            },
            retain,
        };
        plan.reservation(&limits)
            .map_err(|_| "invalid history sentinel plan or resource reservation")?;
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        let package = path(required("--package")?)?;
        if archive.starts_with(&root)
            || root.starts_with(&archive)
            || package.starts_with(&archive)
            || package.starts_with(&root)
        {
            return Err("distinct non-nested stores and independent package path required");
        }
        let site = required("--site")?.to_owned();
        validate_site_lineage(&site).map_err(|_| "invalid site lineage")?;
        if site.len() > 256 {
            return Err("site byte bound");
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 128 {
            return Err("principal byte bound");
        }
        let result = Self {
            archive,
            root,
            package,
            site,
            principal,
            plan,
            limits,
            threads,
            thread_count,
            frame_pixels,
            work: number("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
            framing: number(
                "--max-framing-work",
                10_000_000_000,
                1,
                1_000_000_000_000_000,
            )?,
            archive_read_bytes: number(
                "--archive-read-bytes",
                1024 * 1024 * 1024,
                1,
                64 * 1024 * 1024 * 1024,
            )?,
            timeout_ms: number("--timeout-ms", 30_000, 1, 600_000)?,
            approve: values
                .get("--approve-import")
                .map(|v| digest(v))
                .transpose()?,
        };
        result.preview()?;
        Ok(result)
    }

    pub fn authority_byte_budget(&self) -> Result<u64, &'static str> {
        let r = self
            .plan
            .reservation(&self.limits)
            .map_err(|e| e.stable_id())?;
        let inference_outputs = (self.plan.sampling.max_inferences as u64)
            .checked_mul(self.limits.sentinel.package.run.maximum_output_bytes as u64)
            .ok_or("output byte overflow")?;
        [
            self.archive_read_bytes,
            r.history_verification_bytes,
            r.import_original_bytes,
            r.import_media_bytes,
            r.destination_verification_bytes,
            MAX_RGB_PACKAGE_BYTES as u64,
            self.limits.sentinel.maximum_source_chunk_bytes,
            inference_outputs,
            self.limits.maximum_report_bytes as u64,
        ]
        .into_iter()
        .try_fold(1024 * 1024 * 1024_u64, |sum, next| {
            sum.checked_add(next).ok_or("authority byte overflow")
        })
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_history_sentinel_cli_plan.v1");
        e.text(POLICY);
        e.digest(self.plan.digest(&self.limits).map_err(|e| e.stable_id())?);
        for text in [
            self.archive.to_str().ok_or("UTF-8 archive")?,
            self.root.to_str().ok_or("UTF-8 root")?,
            self.package.to_str().ok_or("UTF-8 package")?,
            &self.site,
            &self.principal,
        ] {
            e.text(text);
        }
        for n in [
            self.work,
            self.framing,
            self.archive_read_bytes,
            self.timeout_ms,
            self.thread_count as u64,
            MAX_RGB_PACKAGE_BYTES as u64,
            PACKAGE_COMPILE_MACS,
            STORAGE_OPERATIONS,
            MAX_ARGUMENTS as u64,
            MAX_PREVIEW_BYTES as u64,
            self.authority_byte_budget()?,
        ] {
            e.u64(n);
        }
        e.bool(self.frame_pixels.is_some());
        if let Some(n) = self.frame_pixels {
            e.u64(n);
        }
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| "approval byte bound")?,
        ))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let r = self
            .plan
            .reservation(&self.limits)
            .map_err(|e| e.stable_id())?;
        let bindings = self
            .plan
            .bindings
            .iter()
            .map(|b| {
                object(&[
                    ("generation", b.generation.to_string()),
                    ("sensor_id", string(b.sensor.as_str())),
                    ("stream_id", string(b.stream.as_str())),
                    ("receive_time_ns", string(&b.receive_time.0.to_string())),
                    (
                        "capture_start_ns",
                        string(&b.capture_hint.start_ns.0.to_string()),
                    ),
                    (
                        "capture_uncertainty_ns",
                        b.capture_hint.uncertainty_ns.to_string(),
                    ),
                    ("assumed_fps", b.capture_hint.assumed_fps.to_string()),
                ])
            })
            .collect::<Vec<_>>();
        let l = &self.limits.sentinel;
        let json = object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("policy", string(POLICY)),
            ("approval_digest", string(&self.approval()?.to_text())),
            (
                "plan_digest",
                string(
                    &self
                        .plan
                        .digest(&self.limits)
                        .map_err(|e| e.stable_id())?
                        .to_text(),
                ),
            ),
            (
                "archive",
                string(self.archive.to_str().ok_or("UTF-8 archive")?),
            ),
            ("root", string(self.root.to_str().ok_or("UTF-8 root")?)),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            (
                "history_pin",
                object(&[
                    ("session", string(&self.plan.history.session.to_text())),
                    ("root", string(&self.plan.history.root.to_text())),
                    ("connections", self.plan.history.connections.to_string()),
                ]),
            ),
            ("bindings", array(&bindings)),
            (
                "interpretation",
                string(match self.plan.interpretation {
                    ComponentInterpretation::Grayscale => "gray",
                    ComponentInterpretation::YCbCr => "ycbcr",
                }),
            ),
            (
                "package",
                string(self.package.to_str().ok_or("UTF-8 package")?),
            ),
            (
                "package_digest",
                string(&self.plan.package_digest.to_text()),
            ),
            ("backend", string(self.plan.backend.stable_id())),
            (
                "backend_generation",
                string(&self.plan.backend.generation().to_text()),
            ),
            ("threads", self.thread_count.to_string()),
            (
                "frame_pixels",
                self.frame_pixels
                    .map_or_else(|| "null".into(), |n| n.to_string()),
            ),
            (
                "minimum_score_ppm",
                self.plan
                    .minimum_score_ppm
                    .map_or_else(|| "null".into(), |n| n.to_string()),
            ),
            ("retain_analysis", self.plan.retain.to_string()),
            (
                "sampling",
                object(&[
                    ("motion_independent", "true".into()),
                    ("allocation", string("connection_round_robin_whole_bursts")),
                    ("every_frames", self.plan.sampling.every_frames.to_string()),
                    ("burst_frames", self.plan.sampling.burst_frames.to_string()),
                    (
                        "max_inferences",
                        self.plan.sampling.max_inferences.to_string(),
                    ),
                ]),
            ),
            (
                "reserved_whole_history",
                object(&[
                    ("connections", r.connections.to_string()),
                    ("maximum_frames", r.maximum_frames.to_string()),
                    (
                        "history_verification_bytes",
                        r.history_verification_bytes.to_string(),
                    ),
                    ("import_original_bytes", r.import_original_bytes.to_string()),
                    ("import_media_bytes", r.import_media_bytes.to_string()),
                    (
                        "destination_verification_bytes",
                        r.destination_verification_bytes.to_string(),
                    ),
                    ("inferences", r.inference.inferences.to_string()),
                    ("execution_macs", r.inference.execution_macs.to_string()),
                    ("output_bytes", r.inference.output_bytes.to_string()),
                    (
                        "source_chunk_bytes",
                        r.inference.source_chunk_bytes.to_string(),
                    ),
                    ("pixel_samples", r.inference.pixel_samples.to_string()),
                ]),
            ),
            (
                "limits",
                object(&[
                    (
                        "maximum_frames_per_generation",
                        self.limits.maximum_frames_per_generation.to_string(),
                    ),
                    (
                        "maximum_bytes_per_generation",
                        self.limits.maximum_bytes_per_generation.to_string(),
                    ),
                    (
                        "maximum_history_reads",
                        self.limits.history.maximum_reads.to_string(),
                    ),
                    (
                        "maximum_history_bytes",
                        self.limits.history.maximum_bytes.to_string(),
                    ),
                    (
                        "maximum_archive_read_bytes",
                        self.archive_read_bytes.to_string(),
                    ),
                    ("maximum_archive_operations", STORAGE_OPERATIONS.to_string()),
                    (
                        "source_chunk_bytes",
                        l.maximum_source_chunk_bytes.to_string(),
                    ),
                    ("pixel_samples", l.maximum_pixel_samples.to_string()),
                    (
                        "jpeg_frame_pixels",
                        l.package.jpeg.frame.maximum_pixels.to_string(),
                    ),
                    (
                        "avc_macroblocks",
                        l.package.h264.max_macroblocks.to_string(),
                    ),
                    (
                        "hevc_luma_samples",
                        l.package.h265.max_luma_samples.to_string(),
                    ),
                    (
                        "per_inference_macs",
                        l.package.run.execution.max_macs.to_string(),
                    ),
                    (
                        "per_inference_tensor_bytes",
                        l.package.run.execution.max_bytes.to_string(),
                    ),
                    (
                        "per_inference_output_bytes",
                        l.package.run.maximum_output_bytes.to_string(),
                    ),
                    ("sentinel_report_bytes", l.maximum_report_bytes.to_string()),
                    ("native_limits_digest", string(&l.digest().to_text())),
                    (
                        "maximum_report_bytes",
                        self.limits.maximum_report_bytes.to_string(),
                    ),
                    ("maximum_work", self.work.to_string()),
                    ("maximum_framing_work", self.framing.to_string()),
                    ("timeout_ms", self.timeout_ms.to_string()),
                ]),
            ),
            (
                "capture_time_label",
                string("operator_assumptions_per_generation"),
            ),
            ("writes", string("none")),
            (
                "approved_writes",
                string(if self.plan.retain {
                    "source_closed_imports_and_native_sentinel_cognition"
                } else {
                    "source_closed_recording_imports"
                }),
            ),
            ("network", string("none")),
            ("event_publication_authorized", "false".into()),
            ("capture_resume_authorized", "false".into()),
            ("absence_certifiable", "false".into()),
        ]);
        if json.len() >= MAX_PREVIEW_BYTES {
            return Err("ERR-HTTP-HISTORY-SENTINEL-LIMIT-001");
        }
        Ok(json)
    }
}
