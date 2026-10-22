#![forbid(unsafe_code)]
//! Pure exact campaign/model admission; no filesystem, host discovery or foreground analysis.

use super::admission::{Inputs, digest, number, path};
use fss_cli::agent_json::{array, object, string};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::ingest::long_sentinel::retained::MAX_LONG_SENTINEL_METADATA_BYTES;
use fss_reference::ingest::long_sentinel::{
    LongSentinelLimits, MAX_LONG_SENTINEL_PIXEL_SAMPLES, MAX_LONG_SENTINEL_REPORT_BYTES,
    MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
};
use fss_reference::ingest::package_event::MAX_PACKAGE_ANALYSIS_BYTES;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, MAX_RECORDED_DECODE_RECEIPT_BYTES,
};
use fss_reference::ingest::retained::RetainedReadLimits;
use fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;
use fss_reference::ingest::rtsp_campaign_sentinel::{
    RtspCampaignSentinelConfig, RtspCampaignSentinelLimits, RtspCampaignSentinelPlan,
};
use fss_reference::ingest::rtsp_selected_watch::RtspWatchSelection;
use fss_reference::{ExecBudget, ExecThreads, KernelBackend, MAX_EXEC_THREADS};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) const MAX_ARGUMENTS: usize = 160;
pub(super) const MAX_REQUEST_BYTES: usize = 96 * 1024;
pub(super) const MAX_PREVIEW_BYTES: usize = 256 * 1024;
pub(super) const STORAGE_OPERATIONS: u64 = 1_000_000;
pub(super) const PACKAGE_COMPILE_MACS: u64 = 1 << 36;
pub(super) const FORMAT: &str = "fss.rtsp_campaign_sentinel_operator.v1";
const POLICY: &str = "exact-campaign-prefix:complete-native-catalogs:independent-archives:\
pinned-local-rgb-package:motion-independent:round-robin-whole-bursts:shared-campaign-pools:\
explicit-unknown-short-budget-skipped:source-closed-optional-cognition-retention:\
no-camera:no-event:no-continuity:no-absence:v1";

pub(super) struct Options {
    pub input: Inputs,
    pub package: PathBuf,
    pub threads: ExecThreads,
    pub thread_count: usize,
    pub frame_pixels: Option<u64>,
    pub plan: RtspCampaignSentinelPlan,
    pub limits: RtspCampaignSentinelLimits,
}

impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("bounded option/value pairs required");
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if ![
                "--history-root",
                "--history-approval",
                "--history-plan",
                "--history-root-digest",
                "--history-records",
                "--history-max-records",
                "--history-object-bytes",
                "--history-max-scan-entries",
                "--history-metadata-bytes",
                "--history-storage-bytes",
                "--root",
                "--site",
                "--principal",
                "--requests",
                "--owner-authorized",
                "--read-originals",
                "--retain-originals",
                "--approve-import",
                "--max-work",
                "--timeout-ms",
                "--archive-read-bytes",
                "--package",
                "--package-digest",
                "--read-model",
                "--retain-analysis",
                "--interpretation",
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
                "--max-report-bytes",
                "--sentinel-report-bytes",
            ]
            .contains(&key)
            {
                return Err("unknown or inapplicable campaign-sentinel option");
            }
            let maximum = if key == "--requests" {
                MAX_REQUEST_BYTES
            } else {
                4096
            };
            if value.is_empty() || value.len() > maximum || value.starts_with("--") {
                return Err("missing or oversized option value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key| values.get(key).copied().ok_or("required option missing");
        if required("--read-model")? != "yes" {
            return Err("explicit --read-model yes required");
        }
        if required("--interpretation")? != "ycbcr" {
            return Err("explicit --interpretation ycbcr required for native RTSP sentinel");
        }
        let retain = match required("--retain-analysis")? {
            "yes" => true,
            "no" => false,
            _ => return Err("--retain-analysis requires yes or no"),
        };
        let input = Inputs::parse(&values)?;
        let package = path(required("--package")?)?;
        let backend = match values.get("--kernels").copied().unwrap_or("optimized-cpu") {
            "optimized-cpu" => KernelBackend::OptimizedCpuV1,
            "scalar-reference" => KernelBackend::ScalarReference,
            _ => return Err("kernels require optimized-cpu or scalar-reference"),
        };
        let n = |key, default, low, high| number(&values, key, default, low, high);
        let thread_count = n("--threads", 1, 1, MAX_EXEC_THREADS as u64)? as usize;
        let threads = ExecThreads::new(thread_count).map_err(|_| "thread ceiling")?;
        let minimum_score_ppm = values
            .get("--minimum-score-ppm")
            .map(|_| n("--minimum-score-ppm", 0, 0, 1_000_000).map(|value| value as u32))
            .transpose()?;
        for key in [
            "--sentinel-every-frames",
            "--sentinel-burst-frames",
            "--sentinel-max-inferences",
        ] {
            let _ = required(key)?;
        }
        let sampling = RtspCampaignSentinelConfig {
            every_frames: n("--sentinel-every-frames", 0, 1, 65536)? as usize,
            burst_frames: n("--sentinel-burst-frames", 0, 1, 8)? as usize,
            max_inferences: n("--sentinel-max-inferences", 0, 1, 1024)? as usize,
        };
        let mut sentinel = LongSentinelLimits::default();
        sentinel.maximum_source_chunk_bytes = n(
            "--stream-read-bytes",
            sentinel.maximum_source_chunk_bytes,
            1,
            MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
        )?;
        sentinel.maximum_pixel_samples = n(
            "--stream-pixel-budget",
            sentinel.maximum_pixel_samples,
            1,
            MAX_LONG_SENTINEL_PIXEL_SAMPLES,
        )?;
        sentinel.maximum_report_bytes = n(
            "--sentinel-report-bytes",
            sentinel.maximum_report_bytes as u64,
            1,
            MAX_LONG_SENTINEL_REPORT_BYTES as u64,
        )? as usize;
        sentinel.package.run.execution = ExecBudget::new(
            n(
                "--max-macs",
                sentinel.package.run.execution.max_macs,
                0,
                u64::MAX,
            )?,
            n(
                "--max-tensor-bytes",
                sentinel.package.run.execution.max_bytes as u64,
                1,
                256 * 1024 * 1024,
            )? as usize,
        );
        sentinel.package.run.maximum_output_bytes = n(
            "--max-output-bytes",
            sentinel.package.run.maximum_output_bytes as u64,
            1,
            16 * 1024 * 1024,
        )? as usize;
        let frame_pixels = values
            .get("--max-frame-pixels")
            .map(|_| n("--max-frame-pixels", 0, 256, 4096 * 2304))
            .transpose()?;
        if let Some(pixels) = frame_pixels {
            sentinel.package.jpeg.frame.maximum_pixels = sentinel
                .package
                .jpeg
                .frame
                .maximum_pixels
                .min(pixels as usize);
            sentinel.package.h264.max_macroblocks = sentinel
                .package
                .h264
                .max_macroblocks
                .min((pixels / 256) as u32);
            sentinel.package.h265.max_luma_samples =
                sentinel.package.h265.max_luma_samples.min(pixels);
        }
        let limits = RtspCampaignSentinelLimits {
            history: input.history_limits,
            history_publication: input.history_publication,
            sentinel,
            maximum_report_bytes: n(
                "--max-report-bytes",
                (16 * 1024 * 1024 + 65536) as u64,
                1024,
                (16 * 1024 * 1024 + 65536) as u64,
            )? as usize,
        };
        let plan = RtspCampaignSentinelPlan {
            history: input.history,
            history_root: input.history_root.clone(),
            bindings: input.bindings.clone(),
            interpretation: ComponentInterpretation::YCbCr,
            package_digest: digest(required("--package-digest")?)?,
            backend,
            minimum_score_ppm,
            sampling,
            retain,
        };
        let options = Self {
            input,
            package,
            threads,
            thread_count,
            frame_pixels,
            plan,
            limits,
        };
        options
            .plan
            .reservation(&options.limits)
            .map_err(|error| error.stable_id())?;
        options.preview()?;
        Ok(options)
    }

    pub fn retention_verification_bytes(&self) -> Result<u64, &'static str> {
        if !self.plan.retain {
            return Ok(0);
        }
        let r = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        if r.selected_archives == 0 {
            return Ok(0);
        }
        // An exact aggregate retry verifies each selected child in preflight, through its
        // ordinary retained owner, and again when reopening the aggregate. Ordinary child
        // source verification uses its own default retained limits, not a smaller recipe pool.
        let maximum_original = self
            .plan
            .bindings
            .iter()
            .filter_map(|binding| match &binding.selection {
                Some(RtspWatchSelection::Catalog(request)) => Some(request.max_original_bytes),
                Some(RtspWatchSelection::Pages(request)) => Some(request.max_original_bytes),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let checked_sum = |values: &[u64]| {
            values.iter().try_fold(0_u64, |sum, value| {
                sum.checked_add(*value).ok_or("custody byte overflow")
            })
        };
        let child_pass = checked_sum(&[
            RetainedReadLimits::default().max_source_bytes,
            maximum_original,
            4 * 1024 * 1024,
            3 * MAX_PACKAGE_ANALYSIS_BYTES as u64,
        ])?;
        let children = child_pass
            .checked_mul(3)
            .and_then(|value| value.checked_mul(r.inference.inferences as u64))
            .ok_or("custody byte overflow")?;
        let capsules = r
            .maximum_frames
            .checked_mul(MAX_RECORDED_DECODE_RECEIPT_BYTES as u64)
            .ok_or("custody byte overflow")?;
        let whole_source = checked_sum(&[r.import_original_bytes, r.import_media_bytes, capsules])?
            .checked_mul(2)
            .ok_or("custody byte overflow")?;
        let aggregate_metadata = u64::from(r.selected_archives)
            .checked_mul(MAX_LONG_SENTINEL_METADATA_BYTES as u64)
            .ok_or("custody byte overflow")?;
        checked_sum(&[children, whole_source, aggregate_metadata])
    }

    pub fn authority_byte_budget(&self) -> Result<u64, &'static str> {
        let r = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        [
            r.history_metadata_bytes,
            self.limits.history.maximum_metadata_bytes,
            r.original_verification_bytes,
            r.import_original_bytes,
            r.import_media_bytes,
            self.input.archive_read_bytes,
            MAX_RGB_PACKAGE_BYTES as u64,
            r.inference.source_chunk_bytes,
            r.inference.output_bytes,
            self.limits.maximum_report_bytes as u64,
            self.retention_verification_bytes()?,
        ]
        .into_iter()
        .try_fold(1024 * 1024 * 1024, |sum: u64, next| {
            sum.checked_add(next).ok_or("authority byte overflow")
        })
    }

    pub fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_campaign_sentinel_cli_plan.v1");
        e.text(POLICY);
        e.digest(
            self.plan
                .digest(&self.limits)
                .map_err(|error| error.stable_id())?,
        );
        for text in [
            self.input.root.to_str().ok_or("UTF-8 root")?,
            &self.input.site,
            &self.input.principal,
            self.package.to_str().ok_or("UTF-8 package")?,
        ] {
            e.text(text);
        }
        for n in [
            self.input.work,
            self.input.archive_read_bytes,
            self.input.timeout_ms,
            self.thread_count as u64,
            MAX_RGB_PACKAGE_BYTES as u64,
            PACKAGE_COMPILE_MACS,
            STORAGE_OPERATIONS,
            MAX_REQUEST_BYTES as u64,
            MAX_PREVIEW_BYTES as u64,
            self.authority_byte_budget()?,
        ] {
            e.u64(n);
        }
        e.bool(self.frame_pixels.is_some());
        if let Some(n) = self.frame_pixels {
            e.u64(n);
        }
        e.u64(self.input.children.len() as u64);
        for child in &self.input.children {
            e.bool(child.is_some());
            if let Some(child) = child {
                e.digest(child.approval()?);
            }
        }
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| "approval byte bound")?,
        ))
    }

    pub fn preview(&self) -> Result<String, &'static str> {
        let r = self
            .plan
            .reservation(&self.limits)
            .map_err(|error| error.stable_id())?;
        let native = &self.limits.sentinel;
        let rows = self
            .input
            .children
            .iter()
            .enumerate()
            .map(|(i, child)| {
                Ok(object(&[
                    ("ordinal", (i + 1).to_string()),
                    (
                        "native_import_plan",
                        child
                            .as_ref()
                            .map(super::import_plan::Options::preview)
                            .transpose()?
                            .unwrap_or_else(|| "null".into()),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
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
                        .map_err(|error| error.stable_id())?
                        .to_text(),
                ),
            ),
            (
                "history_root",
                string(self.plan.history_root.to_str().ok_or("UTF-8 history")?),
            ),
            (
                "history_pin",
                object(&[
                    ("approval", string(&self.plan.history.approval.to_text())),
                    ("plan", string(&self.plan.history.plan.to_text())),
                    ("root", string(&self.plan.history.root.to_text())),
                    ("records", self.plan.history.records.to_string()),
                ]),
            ),
            (
                "history_limits",
                object(&[
                    (
                        "maximum_records",
                        self.limits.history.maximum_records.to_string(),
                    ),
                    (
                        "maximum_object_bytes",
                        self.limits.history.maximum_spool_object_bytes.to_string(),
                    ),
                    (
                        "maximum_scan_entries",
                        self.limits.history.maximum_scan_roots.to_string(),
                    ),
                    (
                        "maximum_metadata_bytes_per_inspection",
                        self.limits.history.maximum_metadata_bytes.to_string(),
                    ),
                    (
                        "maximum_storage_bytes",
                        self.limits
                            .history_publication
                            .spool
                            .max_total_bytes
                            .to_string(),
                    ),
                ]),
            ),
            (
                "root",
                string(self.input.root.to_str().ok_or("UTF-8 root")?),
            ),
            ("site", string(&self.input.site)),
            ("principal", string(&self.input.principal)),
            ("attempts", array(&rows)),
            (
                "child_work_deadlines",
                string("reference_only_outer_shared_owner_applies"),
            ),
            (
                "package",
                object(&[
                    (
                        "path",
                        string(self.package.to_str().ok_or("UTF-8 package")?),
                    ),
                    ("digest", string(&self.plan.package_digest.to_text())),
                    ("maximum_bytes", MAX_RGB_PACKAGE_BYTES.to_string()),
                    ("compile_macs", PACKAGE_COMPILE_MACS.to_string()),
                    (
                        "backend",
                        string(match self.plan.backend {
                            KernelBackend::OptimizedCpuV1 => "optimized-cpu",
                            KernelBackend::ScalarReference => "scalar-reference",
                        }),
                    ),
                    ("threads", self.thread_count.to_string()),
                    ("verified", "false".into()),
                ]),
            ),
            (
                "sampling",
                object(&[
                    ("every_frames", self.plan.sampling.every_frames.to_string()),
                    ("burst_frames", self.plan.sampling.burst_frames.to_string()),
                    (
                        "maximum_campaign_inferences",
                        self.plan.sampling.max_inferences.to_string(),
                    ),
                    ("maximum_per_attempt_inferences", "64".into()),
                    (
                        "allocation",
                        string("round_robin_whole_bursts_by_attempt_ordinal"),
                    ),
                    ("motion_independent", "true".into()),
                    (
                        "actual_allocation",
                        string("after_exact_native_catalog_verification"),
                    ),
                ]),
            ),
            (
                "minimum_score_ppm",
                self.plan
                    .minimum_score_ppm
                    .map_or_else(|| "null".into(), |n| n.to_string()),
            ),
            ("retain_analysis", self.plan.retain.to_string()),
            (
                "reserved_whole_campaign",
                object(&[
                    ("attempts", r.attempts.to_string()),
                    ("selected_archives", r.selected_archives.to_string()),
                    ("maximum_frames", r.maximum_frames.to_string()),
                    (
                        "history_metadata_bytes",
                        r.history_metadata_bytes.to_string(),
                    ),
                    (
                        "source_verification_passes",
                        r.source_verification_passes.to_string(),
                    ),
                    (
                        "original_verification_bytes",
                        r.original_verification_bytes.to_string(),
                    ),
                    ("import_original_bytes", r.import_original_bytes.to_string()),
                    ("import_media_bytes", r.import_media_bytes.to_string()),
                    ("inferences", r.inference.inferences.to_string()),
                    (
                        "source_chunk_bytes",
                        r.inference.source_chunk_bytes.to_string(),
                    ),
                    ("pixel_samples", r.inference.pixel_samples.to_string()),
                    ("jpeg_work_units", r.inference.jpeg_work_units.to_string()),
                    (
                        "detection_work_units",
                        r.inference.detection_work_units.to_string(),
                    ),
                    ("preprocess_macs", r.inference.preprocess_macs.to_string()),
                    ("execution_macs", r.inference.execution_macs.to_string()),
                    ("output_bytes", r.inference.output_bytes.to_string()),
                    ("report_bytes", r.inference.report_bytes.to_string()),
                    (
                        "retention_verification_bytes",
                        self.retention_verification_bytes()?.to_string(),
                    ),
                    (
                        "retention_reservation_scope",
                        string(
                            "conservative_source_and_direct_report_read_admission_not_runtime_destination_io_meter",
                        ),
                    ),
                ]),
            ),
            (
                "per_inference",
                object(&[
                    (
                        "maximum_macs",
                        native.package.run.execution.max_macs.to_string(),
                    ),
                    (
                        "maximum_tensor_bytes",
                        native.package.run.execution.max_bytes.to_string(),
                    ),
                    (
                        "maximum_output_bytes",
                        native.package.run.maximum_output_bytes.to_string(),
                    ),
                    (
                        "maximum_frame_pixels",
                        self.frame_pixels
                            .map_or_else(|| "null".into(), |n| n.to_string()),
                    ),
                ]),
            ),
            (
                "maximum_history_import_model_work",
                self.input.work.to_string(),
            ),
            (
                "maximum_archive_read_bytes",
                self.input.archive_read_bytes.to_string(),
            ),
            (
                "maximum_archive_io_operations",
                STORAGE_OPERATIONS.to_string(),
            ),
            ("authority_bytes", self.authority_byte_budget()?.to_string()),
            (
                "destination_io",
                string(
                    "existing_native_open_import_metadata_and_publication_limits_no_combined_runtime_byte_meter",
                ),
            ),
            ("timeout_ms", self.input.timeout_ms.to_string()),
            (
                "timeout_scope",
                string(
                    "cooperative_at_model_archive_io_and_native_operation_boundaries_does_not_preempt_native_decode_inference_or_retention",
                ),
            ),
            ("history_inspections", "3".into()),
            (
                "maximum_report_bytes",
                self.limits.maximum_report_bytes.to_string(),
            ),
            (
                "history_selection",
                string("exact_independently_saved_prefix"),
            ),
            ("network", string("none")),
            ("writes", string("none_until_exact_outer_approval")),
            (
                "approved_writes",
                string("native_archive_recovery_original_imports_and_explicit_analysis_retention"),
            ),
            ("event_publication", "false".into()),
            ("absence_certifiable", "false".into()),
            ("continuous_coverage", "false".into()),
            ("atomic", "false".into()),
        ]);
        if json.len() >= MAX_PREVIEW_BYTES {
            return Err("ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001");
        }
        Ok(json)
    }
}
