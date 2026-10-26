#![forbid(unsafe_code)]
//! Pure parent authority over the native camera, exact time assumptions and model recipe.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs};
use fss_publication::SlotName;
use fss_reference::ingest::long_sentinel::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, MAX_LONG_SENTINEL_PIXEL_SAMPLES,
    MAX_LONG_SENTINEL_REPORT_BYTES, MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
};
use fss_reference::ingest::long_watch::MAX_LONG_WATCH_FRAMES;
use fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;
use fss_reference::ingest::rtsp_import::pages::{
    MAX_PAGES, RtspCatalogPage, RtspCatalogPagesImportRequest,
};
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec, catalog};
use fss_reference::{ExecBudget, ExecThreads, KernelBackend, MAX_EXEC_THREADS};

pub(super) const FORMAT: &str = "fss.rtsp_capture_sentinel_cli.v1";
pub(crate) const MAX_ARGUMENTS: usize = 224;
pub(super) const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub(super) const STORAGE_OPERATIONS: u64 = 1_000_000;
pub(super) const PACKAGE_COMPILE_MACS: u64 = 1 << 36;
const POLICY: &str = "one-owned-native-capture:typed-complete-catalogs:exact-source-import:\
operator-capture-time-assumption:pinned-local-model:motion-independent-whole-range-decode:\
root-last-child-and-aggregate-retention:cooperative-phase-deadline:no-recapture:no-effects:v1";

pub(crate) const HELP: &str = "fss-capture-rtsp sentinel [ordinary single-capture options]\n\
  --deployment-root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --receive-time-ns N --capture-start-ns N --capture-uncertainty-ns N\n\
  --package ABSOLUTE_FMPK --package-digest sha256:HEX\n\
  --read-originals yes --read-model yes --execute-perception yes --retain-analysis yes\n\
  --sentinel-every-frames N --sentinel-burst-frames K --sentinel-max-inferences M\n\
  [--approve sha256:PARENT_PLAN]\n\
\n\
Without approval, preview is pure: no files, clocks, model reads or camera contact.\n\
The OUTER approval binds the complete ordinary capture plan, destination, explicit time\n\
assumptions, package digest, native sampling and all resource ceilings. Capture time is an\n\
operator assumption, not authenticated camera time. Each original and derived capture bound\n\
must fit the supplied receive time. Only a complete, settled, nonempty native capture advances.\n\
\n\
Approved execution checks distinct paths and loads the pinned native RGB package BEFORE\n\
camera contact. One camera attempt uses the existing native runtime, then its typed catalog\n\
pins are imported directly; no transcript editing, external process or model download is used.\n\
Whole-range native AVC/HEVC decode feeds motion-independent trained-model bursts. Current\n\
destination privacy masks apply. The exact model, recipe, aggregate and ordinary detector\n\
children are retained for existing retained supervision and offline numerical replay.\n\
\n\
Analysis bounds: --analysis-timeout-ms 600000 (1..600000), --analysis-work 1000000000000,\n\
  --archive-read-bytes 1073741824, --import-max-original-bytes 134217728,\n\
  --import-max-media-bytes 67108864, --stream-read-bytes 536870912,\n\
  --stream-pixel-budget 1073741824, --sentinel-report-bytes 16777216.\n\
Per inference: --max-macs 8000000000, --max-tensor-bytes 268435456;\n\
  --max-frame-pixels N narrows native codec capacity. --minimum-score-ppm N is optional.\n\
  --kernels optimized-cpu|scalar-reference --threads N (numeric 1..64; default 1).\n\
The analysis timer starts before model preflight and continues across capture. It is checked\n\
at I/O and native phase boundaries; it does not preempt a native decode/inference/retention\n\
operation. Native work/MAC/byte limits remain independent. Capture has its own timeout/drain\n\
owner. Archive reads share one byte/operation account; destination custody retains existing\n\
native limits. There is no claim of a whole-process destination I/O meter.\n\
\n\
A failure can leave complete originals/imports/child reports durable. Exact offline argv\n\
continuations are emitted from native pins. Never rerun a live capture to repair analysis;\n\
existing archive/pin roots refuse capture. Preserve complete JSONL rows and all stores.\n\
Single-camera model proposals grant no corroboration, event publication or alert dispatch.\n\
Unsampled time and frames with no proposals do not certify absence or continuous coverage.\n";

pub(crate) struct Options {
    pub capture: super::super::plan::Options,
    pub root: PathBuf,
    pub site: String,
    pub package: PathBuf,
    pub package_digest: ContentDigest,
    pub receive_time: TimestampNs,
    pub capture_origin: RtspCaptureOrigin,
    pub sampling: LongSentinelConfig,
    pub limits: LongSentinelLimits,
    pub minimum_score_ppm: Option<u32>,
    pub backend: KernelBackend,
    pub threads: ExecThreads,
    pub thread_count: usize,
    pub frame_pixels: Option<u64>,
    pub timeout_ms: u64,
    pub work: u64,
    pub archive_read_bytes: u64,
    pub original_bytes: u64,
    pub media_bytes: u64,
    pub approve: Option<ContentDigest>,
}

fn path(value: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.file_name().is_none()
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || value.chars().any(char::is_control)
    {
        return Err("non-root absolute path without dot components required");
    }
    Ok(path)
}
fn digest(value: &str) -> Result<ContentDigest, &'static str> {
    let digest = ContentDigest::parse(value).map_err(|_| "invalid SHA-256 digest")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(digest)
}
fn unsigned(value: &str) -> Result<u64, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("unsigned decimal integer required");
    }
    value.parse().map_err(|_| "integer overflow")
}
fn timestamp(value: &str) -> Result<TimestampNs, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("nonnegative decimal timestamp required");
    }
    value
        .parse()
        .map(TimestampNs)
        .map_err(|_| "timestamp overflow")
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("bounded option/value pairs required");
        }
        const ANALYSIS: &[&str] = &[
            "--deployment-root",
            "--site",
            "--receive-time-ns",
            "--capture-start-ns",
            "--capture-uncertainty-ns",
            "--package",
            "--package-digest",
            "--read-originals",
            "--read-model",
            "--execute-perception",
            "--retain-analysis",
            "--approve",
            "--sentinel-every-frames",
            "--sentinel-burst-frames",
            "--sentinel-max-inferences",
            "--analysis-timeout-ms",
            "--analysis-work",
            "--archive-read-bytes",
            "--import-max-original-bytes",
            "--import-max-media-bytes",
            "--stream-read-bytes",
            "--stream-pixel-budget",
            "--sentinel-report-bytes",
            "--max-macs",
            "--max-tensor-bytes",
            "--max-frame-pixels",
            "--minimum-score-ppm",
            "--kernels",
            "--threads",
        ];
        let mut values = BTreeMap::new();
        let mut capture_args = Vec::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if key.len() > 4096 || value.len() > 4096 || value.is_empty() || value.starts_with("--")
            {
                return Err("missing or oversized value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
            if !ANALYSIS.contains(&key) {
                capture_args.extend_from_slice(pair);
            }
        }
        let capture = super::super::plan::Options::parse(&capture_args)?;
        let required = |key| {
            values
                .get(key)
                .copied()
                .ok_or("required sentinel option missing")
        };
        for key in [
            "--read-originals",
            "--read-model",
            "--execute-perception",
            "--retain-analysis",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit original/model read, perception execution and analysis retention required",
                );
            }
        }
        let n = |key, default, low, high| {
            let value = values
                .get(key)
                .map_or(Ok(default), |value| unsigned(value))?;
            if !(low..=high).contains(&value) {
                return Err("sentinel numeric bound exceeded");
            }
            Ok(value)
        };
        let root = path(required("--deployment-root")?)?;
        let package = path(required("--package")?)?;
        let mut paths = vec![&capture.root, &capture.pins, &root, &package];
        if let Some(auth) = &capture.authentication {
            paths.push(&auth.credential_file);
        }
        for (index, left) in paths.iter().enumerate() {
            if paths[index + 1..]
                .iter()
                .any(|right| left.starts_with(right) || right.starts_with(left))
            {
                return Err(
                    "capture, pins, destination, model and credentials must be separate nonnested paths",
                );
            }
        }
        let site = required("--site")?.to_owned();
        if site.len() > 256 || site.chars().any(char::is_control) {
            return Err("invalid site");
        }
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| "invalid site lineage")?;
        let receive_time = timestamp(required("--receive-time-ns")?)?;
        let capture_origin = RtspCaptureOrigin {
            start_ns: timestamp(required("--capture-start-ns")?)?,
            uncertainty_ns: unsigned(required("--capture-uncertainty-ns")?)?,
        };
        if capture_origin.start_ns.0 < i128::from(capture_origin.uncertainty_ns)
            || capture_origin
                .start_ns
                .0
                .checked_add(i128::from(capture_origin.uncertainty_ns))
                .is_none_or(|end| end >= receive_time.0)
        {
            return Err("capture-time assumption must be nonnegative and precede receive time");
        }
        let sampling = LongSentinelConfig {
            every_frames: unsigned(required("--sentinel-every-frames")?)?
                .try_into()
                .map_err(|_| "sampling overflow")?,
            burst_frames: unsigned(required("--sentinel-burst-frames")?)?
                .try_into()
                .map_err(|_| "sampling overflow")?,
            max_inferences: unsigned(required("--sentinel-max-inferences")?)?
                .try_into()
                .map_err(|_| "sampling overflow")?,
        };
        if capture.stop_after_pictures > MAX_LONG_WATCH_FRAMES as u64
            || capture.stop_after_pictures > catalog::MAX_FRAMES as u64
        {
            return Err("whole recording exceeds native sentinel frame ceiling");
        }
        let mut limits = LongSentinelLimits::default();
        limits.maximum_source_chunk_bytes = n(
            "--stream-read-bytes",
            limits.maximum_source_chunk_bytes,
            1,
            MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
        )?;
        limits.maximum_pixel_samples = n(
            "--stream-pixel-budget",
            limits.maximum_pixel_samples,
            1,
            MAX_LONG_SENTINEL_PIXEL_SAMPLES,
        )?;
        limits.maximum_report_bytes = n(
            "--sentinel-report-bytes",
            limits.maximum_report_bytes as u64,
            1,
            MAX_LONG_SENTINEL_REPORT_BYTES as u64,
        )? as usize;
        limits.package.run.execution = ExecBudget::new(
            n(
                "--max-macs",
                limits.package.run.execution.max_macs,
                0,
                u64::MAX,
            )?,
            n(
                "--max-tensor-bytes",
                limits.package.run.execution.max_bytes as u64,
                1,
                256 * 1024 * 1024,
            )? as usize,
        );
        let frame_pixels = values
            .get("--max-frame-pixels")
            .map(|_| n("--max-frame-pixels", 0, 256, 4096 * 2304))
            .transpose()?;
        if let Some(pixels) = frame_pixels {
            limits.package.jpeg.frame.maximum_pixels = limits
                .package
                .jpeg
                .frame
                .maximum_pixels
                .min(pixels as usize);
            limits.package.h264.max_macroblocks = limits
                .package
                .h264
                .max_macroblocks
                .min((pixels / 256) as u32);
            limits.package.h265.max_luma_samples = limits.package.h265.max_luma_samples.min(pixels);
        }
        let minimum_score_ppm = values
            .get("--minimum-score-ppm")
            .map(|_| n("--minimum-score-ppm", 0, 0, 1_000_000).map(|n| n as u32))
            .transpose()?;
        let backend = match values.get("--kernels").copied().unwrap_or("optimized-cpu") {
            "optimized-cpu" => KernelBackend::OptimizedCpuV1,
            "scalar-reference" => KernelBackend::ScalarReference,
            _ => return Err("kernels must be optimized-cpu or scalar-reference"),
        };
        let thread_count = n("--threads", 1, 1, MAX_EXEC_THREADS as u64)? as usize;
        let threads =
            ExecThreads::new(thread_count).map_err(|_| "invalid execution thread count")?;
        let options = Self {
            capture,
            root,
            site,
            package,
            receive_time,
            capture_origin,
            sampling,
            limits,
            package_digest: digest(required("--package-digest")?)?,
            minimum_score_ppm,
            backend,
            threads,
            thread_count,
            frame_pixels,
            timeout_ms: n("--analysis-timeout-ms", 600_000, 1, 600_000)?,
            work: n(
                "--analysis-work",
                1_000_000_000_000,
                1,
                1_000_000_000_000_000,
            )?,
            archive_read_bytes: n(
                "--archive-read-bytes",
                1024 * 1024 * 1024,
                1,
                16 * 1024 * 1024 * 1024,
            )?,
            original_bytes: n(
                "--import-max-original-bytes",
                catalog::MAX_ORIGINAL_BYTES,
                1,
                catalog::MAX_ORIGINAL_BYTES,
            )?,
            media_bytes: n(
                "--import-max-media-bytes",
                catalog::MAX_MEDIA_BYTES,
                1,
                catalog::MAX_MEDIA_BYTES,
            )?,
            approve: values
                .get("--approve")
                .map(|value| digest(value))
                .transpose()?,
        };
        options
            .schedule()?
            .reservation(&options.limits)
            .map_err(|error| error.stable_id())?;
        // A placeholder validates only the known native scope/time/limit shape, never source
        // existence. Actual page coordinates can come only from the completed native owner.
        options.import_request(vec![RtspCatalogPage {
            slot: SlotName::parse("sentinel-pending").map_err(|_| super::SOURCE)?,
            root: options.package_digest,
        }])?;
        options.preview()?;
        Ok(options)
    }

    pub fn import_request(
        &self,
        pages: Vec<RtspCatalogPage>,
    ) -> Result<RtspCatalogPagesImportRequest, &'static str> {
        let request = RtspCatalogPagesImportRequest {
            codec: match self.capture.codec() {
                "avc" => RtspImportCodec::Avc,
                "hevc" => RtspImportCodec::Hevc,
                _ => return Err(super::SOURCE),
            },
            pages,
            scope: self.capture.catalog_scope().clone(),
            receive_time: self.receive_time,
            capture_origin: Some(self.capture_origin),
            max_pages: MAX_PAGES,
            max_windows: catalog::MAX_WINDOWS,
            max_frames: self.capture.stop_after_pictures as usize,
            max_original_bytes: self.original_bytes,
            max_media_bytes: self.media_bytes,
        };
        request.digest().map_err(|error| error.stable_id())?;
        Ok(request)
    }

    pub fn schedule(&self) -> Result<LongSentinelPlan, &'static str> {
        LongSentinelPlan::new(0, self.capture.stop_after_pictures as usize, self.sampling)
            .map_err(|error| error.stable_id())
    }
    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            KernelBackend::OptimizedCpuV1 => "optimized-cpu",
            KernelBackend::ScalarReference => "scalar-reference",
        }
    }
    pub fn authority_bytes(&self) -> Result<u64, &'static str> {
        // Conservative admission for native destination readers and child-custody checks,
        // separate from the nonrenewable source archive byte/work meters.
        let child = self
            .limits
            .package
            .read
            .max_source_bytes
            .checked_add(self.original_bytes)
            .and_then(|n| n.checked_add(32 * 1024 * 1024))
            .and_then(|n| n.checked_mul(3 * self.sampling.max_inferences as u64))
            .ok_or(super::LIMIT)?;
        [
            self.archive_read_bytes,
            self.original_bytes,
            self.media_bytes,
            self.limits.maximum_source_chunk_bytes,
            self.limits.maximum_report_bytes as u64,
            MAX_RGB_PACKAGE_BYTES as u64,
            1024 * 1024 * 1024,
        ]
        .into_iter()
        .try_fold(child, |sum, next| sum.checked_add(next).ok_or(super::LIMIT))
    }
    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_capture_sentinel_cli_plan.v1");
        e.text(POLICY);
        e.digest(self.capture.digest()?);
        for text in [
            self.root.to_str().ok_or(super::PATH)?,
            &self.site,
            self.package.to_str().ok_or(super::PATH)?,
            self.backend_name(),
        ] {
            e.text(text);
        }
        e.digest(self.package_digest);
        e.bytes(&self.receive_time.0.to_be_bytes());
        e.bytes(&self.capture_origin.start_ns.0.to_be_bytes());
        e.digest(self.limits.digest());
        for n in [
            self.capture_origin.uncertainty_ns,
            self.sampling.every_frames as u64,
            self.sampling.burst_frames as u64,
            self.sampling.max_inferences as u64,
            self.thread_count as u64,
            self.timeout_ms,
            self.work,
            self.archive_read_bytes,
            self.original_bytes,
            self.media_bytes,
            STORAGE_OPERATIONS,
            PACKAGE_COMPILE_MACS,
            MAX_RGB_PACKAGE_BYTES as u64,
            MAX_OUTPUT_BYTES as u64,
            self.authority_bytes()?,
            catalog::MAX_WINDOWS as u64,
            fss_reference::ingest::rtsp_import::pages::MAX_PAGES as u64,
        ] {
            e.u64(n);
        }
        e.bool(self.minimum_score_ppm.is_some());
        if let Some(score) = self.minimum_score_ppm {
            e.u64(u64::from(score));
        }
        e.bool(self.frame_pixels.is_some());
        if let Some(pixels) = self.frame_pixels {
            e.u64(pixels);
        }
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| super::LIMIT)?,
        ))
    }
    pub fn approved(&self) -> bool {
        self.approve.is_some()
    }
    pub fn preview(&self) -> Result<String, &'static str> {
        let reservation = self
            .schedule()?
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        let preview = object(&[
            ("schema", string(FORMAT)),
            ("phase", string("planned")),
            ("approval", string(&self.approval()?.to_text())),
            ("capture", self.capture.preview()?),
            (
                "deployment_root",
                string(self.root.to_str().ok_or(super::PATH)?),
            ),
            ("site", string(&self.site)),
            ("package", string(self.package.to_str().ok_or(super::PATH)?)),
            ("package_digest", string(&self.package_digest.to_text())),
            ("kernels", string(self.backend_name())),
            ("threads", self.thread_count.to_string()),
            (
                "minimum_score_ppm",
                self.minimum_score_ppm
                    .map_or_else(|| "null".into(), |score| score.to_string()),
            ),
            (
                "permissions",
                object(&[
                    ("read_originals", "true".into()),
                    ("read_model", "true".into()),
                    ("execute_perception", "true".into()),
                    ("retain_analysis", "true".into()),
                ]),
            ),
            ("capture_time_label", string("operator_assumption")),
            ("receive_time_ns", self.receive_time.0.to_string()),
            (
                "capture_start_ns",
                self.capture_origin.start_ns.0.to_string(),
            ),
            (
                "capture_uncertainty_ns",
                self.capture_origin.uncertainty_ns.to_string(),
            ),
            (
                "sampling",
                object(&[
                    ("every_frames", self.sampling.every_frames.to_string()),
                    ("burst_frames", self.sampling.burst_frames.to_string()),
                    ("max_inferences", self.sampling.max_inferences.to_string()),
                    ("admitted_inferences", reservation.inferences.to_string()),
                    (
                        "whole_decode_frames",
                        self.capture.stop_after_pictures.to_string(),
                    ),
                ]),
            ),
            ("limits_digest", string(&self.limits.digest().to_text())),
            ("analysis_timeout_ms", self.timeout_ms.to_string()),
            (
                "deadline_semantics",
                string("cooperative_io_and_native_phase_boundaries_including_capture_time"),
            ),
            ("analysis_work", self.work.to_string()),
            ("archive_read_bytes", self.archive_read_bytes.to_string()),
            ("archive_storage_operations", STORAGE_OPERATIONS.to_string()),
            ("maximum_model_bytes", MAX_RGB_PACKAGE_BYTES.to_string()),
            ("package_compile_macs", PACKAGE_COMPILE_MACS.to_string()),
            ("import_original_bytes", self.original_bytes.to_string()),
            ("import_media_bytes", self.media_bytes.to_string()),
            (
                "stream_read_bytes",
                self.limits.maximum_source_chunk_bytes.to_string(),
            ),
            (
                "stream_pixel_budget",
                self.limits.maximum_pixel_samples.to_string(),
            ),
            (
                "sentinel_report_bytes",
                self.limits.maximum_report_bytes.to_string(),
            ),
            ("maximum_bridge_row_bytes", MAX_OUTPUT_BYTES.to_string()),
            (
                "max_macs_per_inference",
                self.limits.package.run.execution.max_macs.to_string(),
            ),
            (
                "max_tensor_bytes_per_inference",
                self.limits.package.run.execution.max_bytes.to_string(),
            ),
            ("model_loaded", "false".into()),
            ("camera_contacted", "false".into()),
            ("event_publication_authorized", "false".into()),
            ("alert_dispatch_authorized", "false".into()),
            ("automatic_recapture_authorized", "false".into()),
        ]);
        if preview.len() >= MAX_OUTPUT_BYTES {
            return Err(super::LIMIT);
        }
        Ok(preview)
    }
}
