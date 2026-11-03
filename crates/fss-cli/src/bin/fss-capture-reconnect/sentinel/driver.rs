#![forbid(unsafe_code)]
//! Reuse the native capture, exact-history import and retained model owners in one operation.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, PublishCancellation, PublishCutPoint};
use fss_reference::http_reconnect_history::VerifiedReconnectHistory;
use fss_reference::ingest::http_history_sentinel::{
    HttpHistorySentinelAuthority, HttpHistorySentinelPlan, process_http_history_sentinel,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::analysis_plan::{PACKAGE_COMPILE_MACS, STORAGE_OPERATIONS};
use super::archive_open::{ArchiveReadBudget, open_archive};
use super::continuation;
use super::plan::Options;
use super::{AUTHORITY, DEADLINE, LIMIT, OUTPUT, SOURCE, emit};

const CAPS: [&str; 6] = [
    "ADP-REPLAY-001",
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
    "CAP-MODEL-INFER-001",
];

fn check(
    authority: &ContextAuthority,
    start: Instant,
    timeout_ms: u64,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<(), &'static str> {
    if authority.validate().is_err()
        || authority.cancellation_reason.is_some()
        || CAPS
            .iter()
            .any(|capability| !authority.has_capability(capability))
        || cx.is_cancelled()
        || scalar.is_cancelled()
    {
        return Err(AUTHORITY);
    }
    if start.elapsed() >= Duration::from_millis(timeout_ms) {
        return Err(DEADLINE);
    }
    cx.checkpoint("http_capture_sentinel:boundary")
        .map_err(|_| AUTHORITY)?;
    scalar
        .checkpoint("http_capture_sentinel:boundary")
        .map_err(|_| AUTHORITY)
}

struct Owner<'a> {
    options: &'a super::analysis_plan::Options,
    plan_digest: ContentDigest,
    check: &'a dyn Fn() -> Result<(), &'static str>,
}
impl HttpHistorySentinelAuthority for Owner<'_> {
    fn permit_sentinel(
        &self,
        plan: &HttpHistorySentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        plan.digest(&self.options.limits)
            .is_ok_and(|digest| digest == self.plan_digest)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && (self.check)().is_ok()
    }
}
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        (self.check)().is_err()
    }
}

fn archive_error(error: &'static str) -> &'static str {
    match error {
        "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001" => AUTHORITY,
        "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001" | "ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001" => LIMIT,
        "ERR-RTSP-IMPORT-SOURCE-001" => SOURCE,
        "ERR-RTSP-CAMPAIGN-SENTINEL-PACKAGE-001" => "ERR-HTTP-HISTORY-SENTINEL-PACKAGE-001",
        error => error,
    }
}

pub(super) fn execute(options: &mut Options, out: &mut impl Write) -> Result<(), &'static str> {
    // Even metadata reads and the first clock observation require the complete outer approval.
    if options.approve != Some(options.approval()?) {
        return Err(AUTHORITY);
    }
    options.preview()?;
    let authority = Arc::new(
        ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:http-capture-sentinel".into(),
            operation_id: OperationId::parse("operation:http-capture-sentinel")
                .map_err(|_| AUTHORITY)?,
            principal: options.capture.principal.clone(),
            capabilities: CAPS
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(options.analysis.authority_byte_budget()?)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| AUTHORITY)?,
            privacy_scope: "privacy:owner-original-http-capture-model".into(),
            retention_scope: "retention:source-closed-http-capture-sentinel".into(),
            anchor_universe: ContentDigest::sha256(options.analysis.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| AUTHORITY)?,
    );
    authority.validate().map_err(|_| AUTHORITY)?;
    let start = Instant::now();
    let timeout = options.analysis.timeout_ms;
    let cx = Arc::new(
        ReplayCx::from_context_authority_read_only(&authority, options.analysis.root.clone())
            .map_err(|_| AUTHORITY)?,
    );
    let scalar = Arc::new(ScalarExecCx::new());
    let result = (|| {
        let guard = || check(&authority, start, timeout, &cx, &scalar);
        let mut work = WorkBudget::new(options.analysis.work);
        let mut framing = DecodeBudget::new(options.analysis.framing);
        super::preflight::check(options, &guard, &mut work)?;
        let package_bytes = super::model::read(
            &options.analysis.package,
            options.analysis.plan.package_digest,
            &guard,
            &mut work,
        )
        .map_err(archive_error)?;
        let package = RgbDetectorPackage::load_with_backend(
            &package_bytes,
            options.analysis.plan.package_digest,
            PACKAGE_COMPILE_MACS,
            options.analysis.plan.backend,
            &cx,
            &scalar,
        )
        .map_err(|error| error.stable_id())?
        .with_execution_threads(options.analysis.threads);
        guard()?;
        let contract = if let Some(threshold) = options.analysis.plan.minimum_score_ppm {
            package
                .contract_with_threshold(threshold)
                .map_err(|error| error.stable_id())?
                .digest()
        } else {
            package.contract().digest()
        };
        // Compilation may be long. Refuse a newly occupied archive or changed path alias
        // before the acquisition owner can open the camera or create its source store.
        super::preflight::check(options, &guard, &mut work)?;
        emit(
            options,
            out,
            "capture_ready",
            object(&[
                (
                    "package_digest",
                    string(&options.analysis.plan.package_digest.to_text()),
                ),
                ("model_read_bytes", package_bytes.len().to_string()),
                ("model_digest", string(&package.model().digest().to_text())),
                ("contract_digest", string(&contract.to_text())),
                (
                    "capture_approval",
                    string(&options.capture.approval().to_text()),
                ),
                ("camera_contacted", "false".into()),
            ]),
        )?;
        // Derive the nested native capture authority only after the approved model/path checks.
        // Its approval remains byte-identical to ordinary capture; only the outer mode composes it.
        options.capture.approve = Some(options.capture.approval());
        guard()?;
        let receipt = super::super::driver::capture_receipt(&options.capture, out)?;
        let Some(pin) = receipt.settled_history() else {
            emit(
                options,
                out,
                "capture_incomplete",
                object(&[
                    (
                        "capture_request_satisfied",
                        receipt.request_satisfied.to_string(),
                    ),
                    ("terminal_observed", receipt.terminal_observed.to_string()),
                    (
                        "error_id",
                        receipt.error_code.map_or_else(|| "null".into(), string),
                    ),
                    (
                        "last_durable_history",
                        receipt
                            .history_pin
                            .map_or_else(|| "null".into(), continuation::pin),
                    ),
                    (
                        "connections_started",
                        receipt.connections_started.to_string(),
                    ),
                    ("received_bytes", receipt.received_bytes.to_string()),
                    (
                        "unpublished_received_bytes",
                        receipt.unpublished_received_bytes.to_string(),
                    ),
                    ("analysis_started", "false".into()),
                    ("automatic_reacquisition_authorized", "false".into()),
                ]),
            )?;
            return Err(SOURCE);
        };
        let (analysis, mut offline) = options.resolve(pin)?;
        if receipt.request_satisfied {
            offline.extend([
                "--approve-import".to_owned(),
                analysis.approval()?.to_text(),
            ]);
        }
        // Publish exact recovery handles before imports, native model calls or derived writes.
        emit(
            options,
            out,
            "history_ready",
            object(&[
                ("history_pin", continuation::pin(pin)),
                (
                    "capture_request_satisfied",
                    receipt.request_satisfied.to_string(),
                ),
                (
                    "capture_error_id",
                    receipt.error_code.map_or_else(|| "null".into(), string),
                ),
                ("offline_sentinel_argv", continuation::argv(&offline)),
                (
                    "requires_new_approval",
                    (!receipt.request_satisfied).to_string(),
                ),
                ("automatic_reacquisition_authorized", "false".into()),
            ]),
        )?;
        if !receipt.request_satisfied {
            return Err(SOURCE);
        }
        let analysis_result = (|| {
            guard()?;
            let plan_digest = analysis
                .plan
                .digest(&analysis.limits)
                .map_err(|error| error.stable_id())?;
            let owner = Owner {
                options: &analysis,
                plan_digest,
                check: &guard,
            };
            let archive_authority = Arc::clone(&authority);
            let archive_cx = Arc::clone(&cx);
            let archive_scalar = Arc::clone(&scalar);
            let allowed = analysis.archive.clone();
            let budget = ArchiveReadBudget::new(
                analysis.archive_read_bytes,
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
                &analysis.archive,
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
            guard()?;
            let history = VerifiedReconnectHistory::load(
                &archive,
                pin,
                analysis.limits.history,
                &owner,
                &mut work,
            )
            .map_err(|error| {
                budget
                    .check()
                    .err()
                    .map(archive_error)
                    .unwrap_or(error.stable_id())
            })?;
            if history.boundaries().len() != analysis.plan.bindings.len()
                || history
                    .boundaries()
                    .iter()
                    .zip(&analysis.plan.bindings)
                    .any(|(source, binding)| {
                        source.scope().stream.generation != binding.generation
                            || source.prefix().bytes > analysis.limits.maximum_bytes_per_generation
                            || source.totals().frames
                                > analysis.limits.maximum_frames_per_generation as u64
                    })
            {
                return Err(SOURCE);
            }
            guard()?;
            let destination_cx = ReplayCx::from_context_authority(&authority, &analysis.root)
                .map_err(|_| AUTHORITY)?;
            let result = (|| {
                guard()?;
                let mut destination =
                    ReferenceDeployment::open(&analysis.root, &analysis.site, &destination_cx)
                        .map_err(|_| "ERR-HTTP-IMPORT-CUSTODY-001")?;
                let report = process_http_history_sentinel(
                    &archive,
                    &mut destination,
                    &package,
                    &package_bytes,
                    &analysis.plan,
                    &analysis.limits,
                    &owner,
                    &destination_cx,
                    &scalar,
                    &mut work,
                    &mut framing,
                )
                .map_err(|error| {
                    budget
                        .check()
                        .err()
                        .map(archive_error)
                        .unwrap_or(error.stable_id())
                })?;
                guard()?;
                budget.check().map_err(archive_error)?;
                if report.plan_digest() != plan_digest || report.history_pin() != pin {
                    return Err(AUTHORITY);
                }
                let reruns = report
                    .generations()
                    .iter()
                    .map(|generation| {
                        let argv = generation
                            .retained()
                            .map(|retained| {
                                continuation::replay(&analysis, retained.report_digest())
                            })
                            .transpose()?;
                        Ok(object(&[
                            ("connection", generation.connection().to_string()),
                            ("generation", generation.generation().to_string()),
                            (
                                "argv",
                                argv.as_deref()
                                    .map_or_else(|| "null".into(), continuation::argv),
                            ),
                            (
                                "analysis_retained",
                                generation.retained().is_some().to_string(),
                            ),
                            ("event_publication_authorized", "false".into()),
                        ]))
                    })
                    .collect::<Result<Vec<_>, &'static str>>()?;
                let native = report
                    .to_json(destination.current_anchor().commit_sequence)
                    .map_err(|error| error.stable_id())?;
                guard()?;
                emit(
                    options,
                    out,
                    "completed",
                    object(&[
                        ("report", native),
                        ("native_sentinel_reruns", array(&reruns)),
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
                        ("model_read_bytes", package_bytes.len().to_string()),
                        (
                            "archive_io",
                            object(&[
                                ("total_read_bytes", budget.bytes_read().to_string()),
                                ("total_operations", budget.operations().to_string()),
                                (
                                    "maximum_read_bytes",
                                    analysis.archive_read_bytes.to_string(),
                                ),
                                ("maximum_operations", STORAGE_OPERATIONS.to_string()),
                            ]),
                        ),
                        ("capture_request_satisfied", "true".into()),
                        ("event_publication_authorized", "false".into()),
                        ("automatic_reacquisition_authorized", "false".into()),
                    ]),
                )
            })();
            destination_cx.drain_and_finalize();
            result
        })();
        if let Err(error) = analysis_result {
            if error != OUTPUT {
                emit(
                    options,
                    out,
                    "analysis_failed",
                    object(&[
                        ("error_id", string(error)),
                        ("history_pin", continuation::pin(pin)),
                        ("offline_sentinel_argv", continuation::argv(&offline)),
                        ("earlier_imports_or_analysis_may_be_durable", "true".into()),
                        ("automatic_reacquisition_authorized", "false".into()),
                    ]),
                )?;
            }
            return Err(error);
        }
        Ok(())
    })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}
