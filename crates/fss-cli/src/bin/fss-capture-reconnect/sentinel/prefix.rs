#![forbid(unsafe_code)]
//! Consume the exact successful frame-count stop without claiming an ended response.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use fss_cli::agent_json::{object, string};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::{ContentDigest, ContextAuthority};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, PublishCancellation, PublishCutPoint};
use fss_reference::ingest::http_archive::{HttpArchiveError, HttpWireArchive, HttpWirePin};
use fss_reference::ingest::http_import::HttpImportReceipt;
use fss_reference::ingest::http_prefix_sentinel::{
    HttpPrefixSentinelAuthority, HttpPrefixSentinelPlan, process_http_prefix_sentinel_observed,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::super::driver::CaptureReceipt;
use super::analysis_plan::STORAGE_OPERATIONS;
use super::archive_open::{ArchiveReadBudget, open_archive};
use super::driver::{archive_error, check};
use super::plan::Options;
use super::{AUTHORITY, LIMIT, OUTPUT, SOURCE, continuation, emit, prefix_continuation};

struct Owner<'a> {
    options: &'a Options,
    digest: ContentDigest,
    check: &'a dyn Fn() -> Result<(), &'static str>,
}
impl HttpPrefixSentinelAuthority for Owner<'_> {
    fn permit_sentinel(
        &self,
        plan: &HttpPrefixSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        plan.digest(&self.options.analysis.limits.sentinel)
            .is_ok_and(|digest| digest == self.digest)
            && destination.root() == self.options.analysis.root
            && destination.site_lineage() == self.options.analysis.site
            && (self.check)().is_ok()
    }
}
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        (self.check)().is_err()
    }
}

fn selected(options: &Options, receipt: &CaptureReceipt) -> Result<HttpWirePin, &'static str> {
    let count = options.prefix_frames.ok_or(SOURCE)? as u64;
    let [prefix] = receipt.prefixes.as_slice() else {
        return Err(SOURCE);
    };
    if !receipt.request_satisfied
        || receipt.error_code.is_some()
        || receipt.terminal_observed
        || receipt.history_pin.is_some()
        || receipt.pending_history.is_some()
        || receipt.pending_wire.is_some()
        || !receipt.boundaries.is_empty()
        || receipt.connections_started != 1
        || receipt.unpublished_received_bytes != 0
        || receipt.frames_taken != count
        || prefix.frames_taken != count
        || prefix.generation != options.capture.generations[0]
        || prefix.pin.bytes != receipt.received_bytes
        || prefix.pin.reads == 0
        || prefix.pin.bytes == 0
    {
        return Err(SOURCE);
    }
    let plan = options.prefix_plan(prefix.pin)?;
    plan.digest(&options.analysis.limits.sentinel)
        .map_err(|error| error.stable_id())?;
    Ok(prefix.pin)
}

fn source_pin(options: &Options, pin: HttpWirePin) -> String {
    object(&[
        ("source", string(&options.capture.source.to_text())),
        ("generation", options.capture.generations[0].to_string()),
        (
            "receive_clock",
            string(&options.capture.receive_clock.to_text()),
        ),
        (
            "retention_evidence",
            string(&options.capture.retention_evidence.to_text()),
        ),
        ("source_scope", string(&pin.scope.to_text())),
        ("prefix_root", string(&pin.head.to_text())),
        ("reads", pin.reads.to_string()),
        ("bytes", pin.bytes.to_string()),
    ])
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute<'cx>(
    options: &Options,
    out: &mut impl Write,
    receipt: &CaptureReceipt,
    authority: &Arc<ContextAuthority>,
    start: Instant,
    model_cx: &Arc<ReplayCx>,
    scalar: &Arc<ScalarExecCx>,
    package: &RgbDetectorPackage,
    package_bytes: &[u8],
    guard: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'cx>,
    framing: &mut DecodeBudget<'cx>,
) -> Result<(), &'static str> {
    let pin = match selected(options, receipt) {
        Ok(pin) => pin,
        Err(error) => {
            emit(
                options,
                out,
                "capture_incomplete",
                object(&[
                    (
                        "capture_request_satisfied",
                        receipt.request_satisfied.to_string(),
                    ),
                    ("error_id", string(error)),
                    ("acknowledged_frames", receipt.frames_taken.to_string()),
                    (
                        "required_frames",
                        options.prefix_frames.ok_or(SOURCE)?.to_string(),
                    ),
                    ("analysis_started", "false".into()),
                    ("automatic_reacquisition_authorized", "false".into()),
                ]),
            )?;
            return Err(error);
        }
    };
    let plan = options.prefix_plan(pin)?;
    let digest = plan
        .digest(&options.analysis.limits.sentinel)
        .map_err(|error| error.stable_id())?;
    let import_args = prefix_continuation::import(options, &plan.import)?;
    emit(
        options,
        out,
        "prefix_ready",
        object(&[
            ("source_prefix", source_pin(options, pin)),
            ("acknowledged_frames", plan.acknowledged_frames.to_string()),
            ("prefix_plan_digest", string(&digest.to_text())),
            ("offline_import_argv", continuation::argv(&import_args)),
            ("source_eof_asserted", "false".into()),
            ("ended_history_asserted", "false".into()),
            ("automatic_reacquisition_authorized", "false".into()),
        ]),
    )?;
    let mut offline_analysis: Option<Vec<String>> = None;
    let result = (|| {
        guard()?;
        let a = &options.analysis;
        let owner = Owner {
            options,
            digest,
            check: guard,
        };
        let archive_authority = Arc::clone(authority);
        let archive_cx = Arc::clone(model_cx);
        let archive_scalar = Arc::clone(scalar);
        let allowed = a.archive.clone();
        let timeout = a.timeout_ms;
        let budget = ArchiveReadBudget::new(
            a.archive_read_bytes,
            STORAGE_OPERATIONS,
            Arc::new(move |root: &Path| {
                root == allowed
                    && check(
                        &archive_authority,
                        start,
                        timeout,
                        &archive_cx,
                        &archive_scalar,
                    )
                    .is_ok()
            }),
        );
        let archive = open_archive(
            &a.archive,
            LocalPublicationLimits::new(
                65536,
                MAX_MANIFEST_CHILDREN,
                65536,
                65536,
                SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 131072),
            ),
            &budget,
        )
        .map_err(archive_error)?;
        // Verify original custody before creating a writable deployment context or directory.
        HttpWireArchive::load(
            &archive,
            plan.import.source,
            pin,
            options.capture.archive,
            &owner,
            work,
        )
        .map_err(|error| {
            budget
                .check()
                .err()
                .map(archive_error)
                .unwrap_or(match error {
                    HttpArchiveError::Cancelled => AUTHORITY,
                    HttpArchiveError::Limit | HttpArchiveError::Work(_) => LIMIT,
                    _ => SOURCE,
                })
        })?;
        guard()?;
        let cx = ReplayCx::from_context_authority(authority, &a.root).map_err(|_| AUTHORITY)?;
        let result = (|| {
            guard()?;
            let mut destination = ReferenceDeployment::open(&a.root, &a.site, &cx)
                .map_err(|_| "ERR-HTTP-IMPORT-CUSTODY-001")?;
            let mut observer_error = None;
            let mut observe = |import: &HttpImportReceipt| {
                let result = (|| {
                    guard()?;
                    let args = prefix_continuation::analyze(options, import.import_identity)?;
                    let read_ahead = import
                        .frames
                        .checked_sub(plan.acknowledged_frames)
                        .ok_or(SOURCE)?;
                    emit(
                        options,
                        out,
                        "imported",
                        object(&[
                            ("import_identity", string(&import.import_identity.to_text())),
                            ("import_root", string(&import.import_root.to_text())),
                            ("imported_frames", import.frames.to_string()),
                            ("acknowledged_frames", plan.acknowledged_frames.to_string()),
                            ("imported_read_ahead_frames", read_ahead.to_string()),
                            ("source_ending", string(import.ending.as_str())),
                            ("offline_analysis_argv", continuation::argv(&args)),
                            ("source_eof_asserted", "false".into()),
                            ("automatic_reacquisition_authorized", "false".into()),
                        ]),
                    )?;
                    offline_analysis = Some(args);
                    guard()
                })();
                match result {
                    Ok(()) => true,
                    Err(error) => {
                        observer_error = Some(error);
                        false
                    }
                }
            };
            let report = process_http_prefix_sentinel_observed(
                &archive,
                &mut destination,
                package,
                package_bytes,
                &plan,
                &a.limits.sentinel,
                &owner,
                &cx,
                scalar,
                work,
                framing,
                &mut observe,
            );
            let report = report.map_err(|error| {
                observer_error
                    .or_else(|| budget.check().err().map(archive_error))
                    .unwrap_or(error.stable_id())
            })?;
            guard()?;
            budget.check().map_err(archive_error)?;
            if report.plan_digest() != digest
                || report.acknowledged_frames() != plan.acknowledged_frames
            {
                return Err(AUTHORITY);
            }
            let retained = report.retained().ok_or(SOURCE)?;
            let replay = continuation::replay(a, retained.report_digest())?;
            emit(
                options,
                out,
                "completed",
                object(&[
                    ("report", report.sentinel_report().json().to_owned()),
                    (
                        "import_identity",
                        string(&report.import().import_identity.to_text()),
                    ),
                    (
                        "import_root",
                        string(&report.import().import_root.to_text()),
                    ),
                    ("source_ending", string(report.import().ending.as_str())),
                    (
                        "acknowledged_frames",
                        report.acknowledged_frames().to_string(),
                    ),
                    (
                        "imported_read_ahead_frames",
                        report.imported_read_ahead_frames().to_string(),
                    ),
                    (
                        "retained_report_digest",
                        string(&retained.report_digest().to_text()),
                    ),
                    ("retained_report_root", string(&retained.root().to_text())),
                    ("native_sentinel_replay_argv", continuation::argv(&replay)),
                    (
                        "history_import_model_work",
                        object(&[
                            ("used", work.used().to_string()),
                            ("remaining", work.remaining().to_string()),
                        ]),
                    ),
                    (
                        "framing_work",
                        object(&[
                            ("used", framing.used().to_string()),
                            ("remaining", framing.remaining().to_string()),
                        ]),
                    ),
                    (
                        "archive_io",
                        object(&[
                            ("total_read_bytes", budget.bytes_read().to_string()),
                            ("total_operations", budget.operations().to_string()),
                            ("maximum_read_bytes", a.archive_read_bytes.to_string()),
                            ("maximum_operations", STORAGE_OPERATIONS.to_string()),
                        ]),
                    ),
                    ("source_eof_asserted", "false".into()),
                    ("ended_history_asserted", "false".into()),
                    ("event_publication_authorized", "false".into()),
                    ("automatic_reacquisition_authorized", "false".into()),
                ]),
            )
        })();
        cx.drain_and_finalize();
        result
    })();
    if let Err(error) = result {
        if error != OUTPUT {
            emit(
                options,
                out,
                "analysis_failed",
                object(&[
                    ("error_id", string(error)),
                    ("source_prefix", source_pin(options, pin)),
                    ("offline_import_argv", continuation::argv(&import_args)),
                    (
                        "offline_analysis_argv",
                        offline_analysis
                            .as_deref()
                            .map_or_else(|| "null".into(), continuation::argv),
                    ),
                    ("earlier_imports_or_analysis_may_be_durable", "true".into()),
                    ("automatic_reacquisition_authorized", "false".into()),
                ]),
            )?;
        }
        return Err(error);
    }
    Ok(())
}
