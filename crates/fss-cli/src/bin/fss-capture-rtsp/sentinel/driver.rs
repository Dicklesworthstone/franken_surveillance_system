#![forbid(unsafe_code)]
//! Compose existing native owners, preserving their original source and retention contracts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_publication::SlotName;
use fss_reference::ingest::long_sentinel::retained::retain_long_sentinel_detection;
use fss_reference::ingest::long_sentinel::{LongSentinelRequest, run_long_sentinel_detection};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::rtsp_import::pages::{
    MAX_PAGES, RtspCatalogPage, RtspCatalogPagesImportAuthority, RtspCatalogPagesImportRequest,
    import_rtsp_catalog_pages,
};
use fss_reference::rtsp::campaign_history::{CampaignRetryReason, NativeAttemptObservation};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::archive_open::{ArchiveReadBudget, open_archive};
use super::continuation;
use super::plan::{Options, PACKAGE_COMPILE_MACS, STORAGE_OPERATIONS};
use super::{AUTHORITY, DEADLINE, LIMIT, SOURCE, emit};

const MODEL_CAP: &str = "CAP-MODEL-INFER-001";

fn check(
    authority: &ContextAuthority,
    start: Instant,
    timeout_ms: u64,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<(), &'static str> {
    let result = if authority.validate().is_err()
        || authority.cancellation_reason.is_some()
        || !authority.has_capability("ADP-REPLAY-001")
        || !authority.has_capability(MODEL_CAP)
        || super::import_plan::CAPS
            .iter()
            .any(|capability| !authority.has_capability(capability))
        || cx.is_cancelled()
        || scalar.is_cancelled()
    {
        Err(AUTHORITY)
    } else if start.elapsed() >= Duration::from_millis(timeout_ms) {
        Err(DEADLINE)
    } else {
        cx.checkpoint("capture_sentinel:boundary")
            .map_err(|_| AUTHORITY)?;
        scalar
            .checkpoint("capture_sentinel:boundary")
            .map_err(|_| AUTHORITY)
    };
    if result.is_err() {
        cx.request_cancellation();
        scalar.request_cancellation();
    }
    result
}

struct ImportOwner<'a> {
    options: &'a Options,
    request: &'a RtspCatalogPagesImportRequest,
    check: &'a dyn Fn() -> Result<(), &'static str>,
}
impl RtspCatalogPagesImportAuthority for ImportOwner<'_> {
    fn permit(
        &self,
        request: &RtspCatalogPagesImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        request == self.request
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && (self.check)().is_ok()
    }
}

fn archive_error(error: &'static str) -> &'static str {
    match error {
        "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001" => AUTHORITY,
        "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001" => LIMIT,
        error => error,
    }
}

fn selection(
    options: &Options,
    observed: &NativeAttemptObservation,
) -> Result<RtspCatalogPagesImportRequest, &'static str> {
    if !observed.complete
        || observed.error_id.is_some()
        || observed.retry != Some(CampaignRetryReason::SettledSuccess)
        || observed.recovery_required
        || observed.durable_pictures == 0
        || observed.durable_pictures != options.capture.stop_after_pictures
        || observed.bindings.snapshot_digest.is_none()
        || observed.bindings.journal_anchor.is_none()
        || observed.bindings.catalogs.is_empty()
        || observed.bindings.catalogs.len() > MAX_PAGES
    {
        return Err(SOURCE);
    }
    options.import_request(
        observed
            .bindings
            .catalogs
            .iter()
            .map(|binding| {
                Ok(RtspCatalogPage {
                    slot: SlotName::parse(&binding.slot).map_err(|_| SOURCE)?,
                    root: binding.root,
                })
            })
            .collect::<Result<Vec<_>, &'static str>>()?,
    )
}

fn pins(observed: &NativeAttemptObservation) -> String {
    object(&[
        (
            "snapshot_digest",
            observed
                .bindings
                .snapshot_digest
                .map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
        ),
        (
            "journal_anchor",
            observed.bindings.journal_anchor.as_ref().map_or_else(
                || "null".into(),
                |anchor| {
                    object(&[
                        ("sequence", anchor.sequence.to_string()),
                        ("root", string(&anchor.root.to_text())),
                    ])
                },
            ),
        ),
        (
            "catalog_pages",
            array(
                &observed
                    .bindings
                    .catalogs
                    .iter()
                    .map(|page| {
                        object(&[
                            ("slot", string(&page.slot)),
                            ("root", string(&page.root.to_text())),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}

#[derive(Default)]
struct Progress {
    import_identity: Option<ContentDigest>,
    report: Option<ContentDigest>,
}

pub(super) fn execute(options: &mut Options) -> Result<(), &'static str> {
    if options.approve != Some(options.approval()?) {
        return Err(AUTHORITY);
    }
    options.preview()?;
    let mut capabilities = super::import_plan::CAPS
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    capabilities.extend(["ADP-REPLAY-001".into(), MODEL_CAP.into()]);
    let authority = Arc::new(
        ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:rtsp-capture-sentinel".into(),
            operation_id: OperationId::parse("operation:rtsp-capture-sentinel")
                .map_err(|_| AUTHORITY)?,
            principal: options.capture.principal.clone(),
            capabilities,
            deadline: Some(TimestampNs(i128::from(options.timeout_ms) * 1_000_000)),
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(options.authority_bytes()?)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| AUTHORITY)?,
            privacy_scope: "privacy:owner-original-rtsp-and-pinned-model".into(),
            retention_scope: "retention:source-closed-live-sentinel".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| AUTHORITY)?,
    );
    // Pure construction: no destination store is created merely to validate a model.
    let model_cx = Arc::new(
        ReplayCx::from_context_authority_read_only(&authority, &options.root)
            .map_err(|_| AUTHORITY)?,
    );
    let scalar = Arc::new(ScalarExecCx::new());
    authority.validate().map_err(|_| AUTHORITY)?;
    let start = Instant::now();
    let timeout = options.timeout_ms;
    let boundary = || check(&authority, start, timeout, &model_cx, &scalar);
    let result = (|| {
        let mut work = WorkBudget::new(options.work);
        super::preflight::check(options, &boundary, &mut work)?;
        let bytes = super::model::read(
            &options.package,
            options.package_digest,
            &boundary,
            &mut work,
        )?;
        let package = RgbDetectorPackage::load_with_backend(
            &bytes,
            options.package_digest,
            PACKAGE_COMPILE_MACS,
            options.backend,
            &model_cx,
            &scalar,
        )
        .map_err(|error| error.stable_id())?
        .with_execution_threads(options.threads);
        boundary()?;
        let contract = if let Some(score) = options.minimum_score_ppm {
            package
                .contract_with_threshold(score)
                .map_err(|error| error.stable_id())?
                .digest()
        } else {
            package.contract().digest()
        };
        // A late alias/path change or prior capture refuses before entering the camera owner.
        super::preflight::check(options, &boundary, &mut work)?;
        emit(
            options,
            "sentinel_model_ready",
            object(&[
                (
                    "package_digest",
                    string(&package.archive_digest().to_text()),
                ),
                ("model_digest", string(&package.model().digest().to_text())),
                ("contract_digest", string(&contract.to_text())),
                ("camera_contacted", "false".into()),
            ]),
        )?;
        boundary()?;
        // Derive the child's grant ONLY after exact parent approval and package preflight.
        options.capture.approve = Some(options.capture.digest()?);
        let mut observed = None;
        let attempt = super::super::driver::execute_observed_attempt(
            &options.capture,
            None,
            None,
            Some(&mut |value| observed = Some(value)),
        );
        // The native observer precedes terminal stdout flush. Both the returned owner result
        // and its complete typed observation must succeed; observer data alone grants nothing.
        let capture_error = match &attempt {
            Ok(outcome) => match outcome.result {
                Err(error) => Some(error),
                Ok(())
                    if !outcome.recovery_required
                        && outcome.durable_pictures > 0
                        && outcome.retry
                            == Some(super::super::driver::RetryReason::SettledSuccess) =>
                {
                    None
                }
                Ok(()) => Some(SOURCE),
            },
            Err(error) => Some(*error),
        };
        if let Some(error) = capture_error {
            emit(
                options,
                "sentinel_capture_refused",
                object(&[
                    ("error_id", string(error)),
                    (
                        "native_pins",
                        observed.as_ref().map_or_else(|| "null".into(), pins),
                    ),
                    ("analysis_started", "false".into()),
                    ("automatic_recapture_authorized", "false".into()),
                ]),
            )?;
            return Err(error);
        }
        let observed = observed.ok_or(SOURCE)?;
        let request = selection(options, &observed)?;
        let import_args = continuation::import(options, &request)?;
        emit(
            options,
            "sentinel_capture_ready",
            object(&[
                ("native_pins", pins(&observed)),
                ("durable_pictures", observed.durable_pictures.to_string()),
                (
                    "import_request_digest",
                    string(
                        &request
                            .digest()
                            .map_err(|error| error.stable_id())?
                            .to_text(),
                    ),
                ),
                ("offline_import_program", string("fss-import-rtsp")),
                ("offline_import_args", continuation::json(&import_args)),
                ("automatic_recapture_authorized", "false".into()),
            ]),
        )?;
        let mut progress = Progress::default();
        let result = analyze(
            options,
            &authority,
            start,
            &model_cx,
            &scalar,
            &package,
            &bytes,
            &request,
            &observed,
            &boundary,
            &mut work,
            &mut progress,
        );
        if let Err(error) = result {
            let continuation = progress
                .import_identity
                .map(|identity| continuation::analyze(options, identity))
                .transpose()?;
            emit(
                options,
                "sentinel_analysis_refused",
                object(&[
                    ("error_id", string(error)),
                    ("native_pins", pins(&observed)),
                    (
                        "import_identity",
                        progress
                            .import_identity
                            .map_or_else(|| "null".into(), |identity| string(&identity.to_text())),
                    ),
                    (
                        "unconfirmed_report_digest",
                        progress
                            .report
                            .map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
                    ),
                    ("offline_import_program", string("fss-import-rtsp")),
                    ("offline_import_args", continuation::json(&import_args)),
                    ("offline_analysis_program", string("fss-infer")),
                    (
                        "offline_analysis_args",
                        continuation
                            .as_ref()
                            .map_or_else(|| "null".into(), |args| continuation::json(args)),
                    ),
                    (
                        "child_retention_may_exist",
                        progress.report.is_some().to_string(),
                    ),
                    ("automatic_recapture_authorized", "false".into()),
                    ("event_publication_authorized", "false".into()),
                    ("alert_dispatch_authorized", "false".into()),
                ]),
            )?;
            return Err(error);
        }
        Ok(())
    })();
    scalar.drain_and_finalize();
    model_cx.drain_and_finalize();
    result
}

#[allow(clippy::too_many_arguments)]
fn analyze(
    options: &Options,
    authority: &Arc<ContextAuthority>,
    start: Instant,
    model_cx: &Arc<ReplayCx>,
    scalar: &Arc<ScalarExecCx>,
    package: &RgbDetectorPackage,
    bytes: &[u8],
    request: &RtspCatalogPagesImportRequest,
    observed: &NativeAttemptObservation,
    boundary: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
    progress: &mut Progress,
) -> Result<(), &'static str> {
    boundary()?;
    let archive_root = options.capture.root.clone();
    let archive_authority = Arc::clone(authority);
    let archive_cx = Arc::clone(model_cx);
    let archive_scalar = Arc::clone(scalar);
    let timeout = options.timeout_ms;
    let budget = ArchiveReadBudget::new(
        options.archive_read_bytes,
        STORAGE_OPERATIONS,
        Arc::new(move |root| {
            root == archive_root
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
        &options.capture.root,
        options.capture.publication_limits(),
        &budget,
    )
    .map_err(archive_error)?;
    boundary()?;
    let cx = ReplayCx::from_context_authority(authority, &options.root).map_err(|_| AUTHORITY)?;
    let result = (|| {
        boundary()?;
        let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
            .map_err(|_| "ERR-RTSP-IMPORT-CUSTODY-001")?;
        let owner = ImportOwner {
            options,
            request,
            check: boundary,
        };
        let imported =
            import_rtsp_catalog_pages(&archive, &mut destination, request, &owner, &cx, work)
                .map_err(|error| {
                    budget
                        .check()
                        .err()
                        .map(archive_error)
                        .unwrap_or(error.stable_id())
                })?;
        let receipt = &imported.catalog.import;
        progress.import_identity = Some(receipt.import_identity);
        if receipt.frames as u64 != observed.durable_pictures {
            return Err(SOURCE);
        }
        let analysis_args = continuation::analyze(options, receipt.import_identity)?;
        emit(
            options,
            "sentinel_imported",
            object(&[
                (
                    "import_identity",
                    string(&receipt.import_identity.to_text()),
                ),
                ("import_root", string(&receipt.import_root.to_text())),
                ("source_proof", string(&receipt.proof.to_text())),
                ("frames", receipt.frames.to_string()),
                ("pages", imported.pages.to_string()),
                ("windows", imported.catalog.windows.to_string()),
                ("capture_time_label", string(receipt.capture_time_label)),
                ("offline_analysis_program", string("fss-infer")),
                ("offline_analysis_args", continuation::json(&analysis_args)),
                ("automatic_recapture_authorized", "false".into()),
            ]),
        )?;
        boundary()?;
        budget.check().map_err(archive_error)?;
        let report = run_long_sentinel_detection(
            &destination,
            package,
            &LongSentinelRequest {
                import_identity: receipt.import_identity,
                first_segment: 0,
                segment_count: receipt.frames,
                interpretation: ComponentInterpretation::YCbCr,
                minimum_score_ppm: options.minimum_score_ppm,
            },
            options.sampling,
            &options.limits,
            &cx,
            scalar,
        )
        .map_err(|error| error.stable_id())?;
        progress.report = Some(report.digest());
        boundary()?;
        let retained =
            retain_long_sentinel_detection(&mut destination, package, bytes, &report, &cx)
                .map_err(|error| error.stable_id())?;
        boundary()?;
        budget.check().map_err(archive_error)?;
        if retained.report_digest() != report.digest()
            || retained.child_reports().len() != report.reports().len()
        {
            return Err(SOURCE);
        }
        let replay_args = continuation::replay(options, retained.report_digest())?;
        emit(
            options,
            "sentinel_retained",
            object(&[
                (
                    "import_identity",
                    string(&receipt.import_identity.to_text()),
                ),
                ("import_root", string(&receipt.import_root.to_text())),
                ("report_digest", string(&retained.report_digest().to_text())),
                ("root", string(&retained.root().to_text())),
                ("recipe_digest", string(&retained.recipe_digest().to_text())),
                (
                    "package_digest",
                    string(&retained.package_digest().to_text()),
                ),
                (
                    "contract_digest",
                    string(&report.reports().first().ok_or(SOURCE)?.contract.to_text()),
                ),
                (
                    "child_reports",
                    array(
                        &retained
                            .child_reports()
                            .iter()
                            .map(|digest| string(&digest.to_text()))
                            .collect::<Vec<_>>(),
                    ),
                ),
                ("status", string(retained.status().as_str())),
                (
                    "authority_sequence",
                    retained.authority_anchor().commit_sequence.to_string(),
                ),
                (
                    "decoded_pictures",
                    report.usage().decoded_frames.to_string(),
                ),
                ("executed_inferences", report.usage().inferences.to_string()),
                ("analysis_work_used", work.used().to_string()),
                ("archive_read_bytes", budget.bytes_read().to_string()),
                (
                    "archive_storage_operations",
                    budget.operations().to_string(),
                ),
                ("native_pins", pins(observed)),
                ("offline_replay_program", string("fss-infer")),
                ("offline_replay_args", continuation::json(&replay_args)),
                ("event_publication_authorized", "false".into()),
                ("alert_dispatch_authorized", "false".into()),
                ("automatic_recapture_authorized", "false".into()),
            ]),
        )
    })();
    cx.drain_and_finalize();
    result
}
