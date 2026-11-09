#![forbid(unsafe_code)]
//! Bounded metadata preview and separately approved original acquisition.

use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::HostSpoolIo;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;
use fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES;
use fss_reference::ingest::rtsp_import::query::{
    RtspQueryImportAuthority, RtspQueryImportPlan, RtspQueryImportSettings,
    RtspQueryImportedWindow, import_rtsp_query_pinned_existing, preview_rtsp_query_import,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::super::plan::CAPS;
use super::{FORMAT, QueryOptions};

fn settings(options: &QueryOptions) -> RtspQueryImportSettings {
    RtspQueryImportSettings {
        site: options.common.site.clone(),
        receive_time: options.common.request.receive_time,
        max_frames: options.common.request.max_frames,
        max_original_bytes: options.common.request.max_original_bytes,
        max_media_bytes: options.common.request.max_media_bytes,
        max_work: options.common.work,
    }
}

fn interval(interval: &std::ops::Range<u64>) -> String {
    object(&[
        ("start", string(&interval.start.to_string())),
        ("end", string(&interval.end.to_string())),
    ])
}

/// Match the pinned source owner's admission floor without changing the legacy v1 plan.
/// This reserves native source verification and descriptor work; it is not a promise that
/// the remaining decoding, reconstruction and publication work will fit the ceiling.
pub(super) fn pinned_work_preflight(
    windows: usize,
    original_bytes: u64,
    max_work: u64,
) -> Result<u64, &'static str> {
    u64::try_from(windows)
        .ok()
        .and_then(|windows| windows.checked_mul(MAX_ORIGINAL_BYTES * 3))
        .and_then(|reads| reads.checked_add(original_bytes))
        .filter(|minimum| *minimum <= max_work)
        .ok_or("ERR-RTSP-IMPORT-REQUEST-001")
}

fn plan_report(
    options: &QueryOptions,
    plan: &RtspQueryImportPlan,
    minimum_source_work: u64,
) -> Result<String, &'static str> {
    let query = plan.query();
    let selected = plan
        .windows()
        .iter()
        .map(|window| {
            Ok(object(&[
                ("ordinal", window.row.ordinal.to_string()),
                ("window_slot", string(window.request.slot.as_str())),
                ("window_root", string(&window.request.root.to_text())),
                (
                    "decode_interval",
                    interval(&window.row.entry.decode_interval()),
                ),
                ("selected_overlap", interval(&window.row.overlap)),
                (
                    "quoted_original_bytes",
                    window.row.entry.byte_len().to_string(),
                ),
                ("frames", window.row.entry.samples().to_string()),
                (
                    "request_digest",
                    string(
                        &window
                            .request
                            .digest()
                            .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?
                            .to_text(),
                    ),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Ok(object(&[
        ("format", string(FORMAT)),
        ("kind", string("plan")),
        (
            "approval_digest",
            string(
                &options
                    .approval(plan.digest(), plan.source_limits())?
                    .to_text(),
            ),
        ),
        ("plan_digest", string(&plan.digest().to_text())),
        ("query_decision", string(&query.decision_digest.to_text())),
        ("deployment_anchor", string(&query.anchor_token)),
        (
            "archive",
            string(
                options
                    .common
                    .archive
                    .to_str()
                    .ok_or("ERR-RTSP-IMPORT-REQUEST-001")?,
            ),
        ),
        (
            "root",
            string(
                options
                    .common
                    .root
                    .to_str()
                    .ok_or("ERR-RTSP-IMPORT-REQUEST-001")?,
            ),
        ),
        ("site", string(&options.common.site)),
        ("principal", string(&options.common.principal)),
        ("codec", string(options.common.request.codec.as_str())),
        ("catalog_root", string(&query.native.catalog_root.to_text())),
        (
            "catalog_metadata",
            string(&query.native.catalog_metadata_digest.to_text()),
        ),
        (
            "decode_clock",
            string(&options.context.recording.scope.decode_clock.to_text()),
        ),
        (
            "time_scale",
            options.context.recording.scope.time_scale.to_string(),
        ),
        (
            "query_interval",
            interval(&options.context.recording.interval),
        ),
        ("selected_windows", array(&selected)),
        (
            "indexed_gaps",
            array(
                &query
                    .native
                    .indexed_gaps
                    .iter()
                    .map(interval)
                    .collect::<Vec<_>>(),
            ),
        ),
        ("scanned_windows", query.native.scanned_windows.to_string()),
        ("quoted_original_bytes", plan.original_bytes().to_string()),
        (
            "quoted_bytes_scope",
            string("selected_retained_payloads_not_total_disk_io"),
        ),
        (
            "approved_archive_open",
            string("read_only_exact_selected_closures_without_writer_lock_or_recovery"),
        ),
        (
            "maximum_source_read_bytes",
            plan.source_limits().max_read_bytes.to_string(),
        ),
        (
            "maximum_source_io_calls",
            plan.source_limits().max_io_calls.to_string(),
        ),
        ("selected_frames", plan.frames().to_string()),
        (
            "maximum_frames",
            options.common.request.max_frames.to_string(),
        ),
        (
            "maximum_original_bytes",
            options.common.request.max_original_bytes.to_string(),
        ),
        (
            "maximum_media_bytes",
            options.common.request.max_media_bytes.to_string(),
        ),
        ("minimum_source_work", minimum_source_work.to_string()),
        ("maximum_work", options.common.work.to_string()),
        ("timeout_ms", options.common.timeout_ms.to_string()),
        (
            "source_payload_availability",
            string("unknown_until_approved_native_verification"),
        ),
        ("capture_time_label", string("unknown")),
        (
            "retention",
            string("selected_whole_windows_with_complete_native_original_proofs"),
        ),
        ("continuity_between_imports", "false".into()),
        ("absence_certifiable", "false".into()),
        ("writes", string("none")),
        ("source_media_reads", "0".into()),
        ("network", string("none")),
    ]))
}

fn imported_json(rows: &[RtspQueryImportedWindow]) -> String {
    array(
        &rows
            .iter()
            .map(|row| {
                let import = &row.import;
                object(&[
                    ("ordinal", row.ordinal.to_string()),
                    ("window_root", string(&row.source_root.to_text())),
                    ("selected_overlap", interval(&row.overlap)),
                    ("import_identity", string(&import.import_identity.to_text())),
                    ("import_root", string(&import.import_root.to_text())),
                    ("manifest_digest", string(&import.manifest_digest.to_text())),
                    ("origin_proof", string(&import.proof.to_text())),
                    ("frames", import.frames.to_string()),
                    ("codec", string(import.codec.as_str())),
                    ("capture_time_label", string(import.capture_time_label)),
                    ("reused", import.reused.to_string()),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

struct Owner<'a> {
    options: &'a QueryOptions,
    plan_digest: ContentDigest,
    authority: &'a ContextAuthority,
    cx: &'a ReplayCx,
    start: Instant,
}

impl Owner<'_> {
    fn allowed(&self, plan: &RtspQueryImportPlan) -> bool {
        plan.digest() == self.plan_digest
            && self.options.common.approve.is_some_and(|approved| {
                self.options
                    .approval(plan.digest(), plan.source_limits())
                    .ok()
                    == Some(approved)
            })
            && self.authority.cancellation_reason.is_none()
            && CAPS
                .iter()
                .all(|capability| self.authority.has_capability(capability))
            && self.start.elapsed() < Duration::from_millis(self.options.common.timeout_ms)
            && self.cx.checkpoint("import_rtsp:query_operator").is_ok()
    }
}

impl RtspQueryImportAuthority for Owner<'_> {
    fn permit_open(&self, plan: &RtspQueryImportPlan) -> bool {
        self.allowed(plan)
    }

    fn permit(&self, plan: &RtspQueryImportPlan, destination: &ReferenceDeployment) -> bool {
        self.allowed(plan)
            && destination.root() == self.options.common.root
            && destination.site_lineage() == self.options.common.site
    }
}

fn acquire(
    options: &QueryOptions,
    plan: &RtspQueryImportPlan,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    start: Instant,
) -> Result<(String, bool), &'static str> {
    let cancelled =
        || start.elapsed() >= Duration::from_millis(options.common.timeout_ms) || cx.is_cancelled();
    if cancelled() {
        return Err("ERR-RTSP-IMPORT-AUTHORITY-001");
    }
    cx.checkpoint("import_rtsp:query_open_source")
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let mut source = PinnedClosureReader::new(
        &HostSpoolIo,
        &options.common.archive,
        plan.source_limits(),
        &cancelled,
    )
    .map_err(|_| "ERR-RTSP-IMPORT-SOURCE-001")?;
    let owner = Owner {
        options,
        plan_digest: plan.digest(),
        authority,
        cx,
        start,
    };
    let mut work = WorkBudget::new(options.common.work);
    let result = import_rtsp_query_pinned_existing(
        &HostSpoolIo,
        &mut source,
        plan,
        &owner,
        cx,
        &mut work,
        &cancelled,
    );
    let mut fields = vec![
        ("format", string(FORMAT)),
        ("kind", string("acquisition_result")),
        (
            "approval_digest",
            string(
                &options
                    .approval(plan.digest(), plan.source_limits())?
                    .to_text(),
            ),
        ),
        ("plan_digest", string(&plan.digest().to_text())),
        (
            "query_decision",
            string(&plan.query().decision_digest.to_text()),
        ),
        (
            "approved_deployment_anchor",
            string(&plan.query().anchor_token),
        ),
        (
            "indexed_gaps",
            array(
                &plan
                    .query()
                    .native
                    .indexed_gaps
                    .iter()
                    .map(interval)
                    .collect::<Vec<_>>(),
            ),
        ),
        ("atomic", "false".into()),
        ("continuity_between_imports", "false".into()),
        ("absence_certifiable", "false".into()),
        ("capture_time_label", string("unknown")),
        ("destination_contains_complete_catalog", "false".into()),
        (
            "archive_open",
            string("read_only_exact_selected_closures_without_writer_lock_or_recovery"),
        ),
        ("network", string("none")),
        ("work_used", work.used().to_string()),
        ("source_read_bytes", source.usage().read_bytes.to_string()),
        ("source_io_calls", source.usage().io_calls.to_string()),
    ];
    let complete = match result {
        Ok(receipt) => {
            fields.extend([
                ("complete", "true".into()),
                ("imports", imported_json(&receipt.imports)),
                ("completed_imports", receipt.imports.len().to_string()),
                ("frames", receipt.frames.to_string()),
                ("original_bytes", receipt.original_bytes.to_string()),
                ("media_bytes", receipt.media_bytes.to_string()),
                ("failed_import_may_be_durable", "false".into()),
                ("error_id", "null".into()),
                (
                    "reconciliation",
                    string("preview_current_state_before_any_new_acquisition"),
                ),
            ]);
            true
        }
        Err(failure) => {
            fields.extend([
                ("complete", "false".into()),
                ("imports", imported_json(&failure.completed)),
                ("completed_imports", failure.completed.len().to_string()),
                ("next_window", failure.next_window.to_string()),
                (
                    "failed_import_may_be_durable",
                    failure.current_import_may_be_durable.to_string(),
                ),
                ("error_id", string(failure.reason.stable_id())),
                (
                    "reconciliation",
                    string("preview_and_approve_current_state_completed_native_imports_are_reused"),
                ),
            ]);
            false
        }
    };
    Ok((object(&fields), complete))
}

pub(super) fn run(options: &QueryOptions) -> Result<(String, bool), &'static str> {
    let start = Instant::now();
    let cancelled = || start.elapsed() >= Duration::from_millis(options.common.timeout_ms);
    let plan = preview_rtsp_query_import(
        &HostSpoolIo,
        &options.common.root,
        &options.common.archive,
        &options.context,
        &options.limits,
        &settings(options),
        &cancelled,
    )
    .map_err(|error| error.stable_id())?;
    // Refuse an unaffordable pinned-source strategy before issuing or checking approval,
    // constructing an authority owner, opening a source reader or opening a destination owner.
    let minimum_source_work = pinned_work_preflight(
        plan.windows().len(),
        plan.original_bytes(),
        plan.settings().max_work,
    )?;
    if options.common.approve.is_none() {
        return plan_report(options, &plan, minimum_source_work).map(|report| (report, true));
    }
    // This comparison precedes all writer/recovery handles and original payload reads.
    if options.common.approve != Some(options.approval(plan.digest(), plan.source_limits())?) {
        return Err("ERR-RTSP-IMPORT-APPROVAL-001");
    }
    let mut capabilities: Vec<_> = CAPS.iter().map(|value| (*value).to_owned()).collect();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-query-import".into(),
        operation_id: OperationId::parse("operation:rtsp-query-import")
            .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?,
        principal: options.common.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?,
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:source-closed-rtsp-query-import".into(),
        anchor_universe: ContentDigest::sha256(options.common.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    authority
        .validate()
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    super::super::driver::preflight_source_paths(&options.common, &authority, start)?;
    // Construction itself must not recreate a destination removed after the preview.
    // Independent retention authority is enforced by the existing-only native import owner.
    let cx = ReplayCx::from_context_authority_read_only(&authority, options.common.root.clone())
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let result = acquire(options, &plan, &authority, &cx, start);
    cx.drain_and_finalize();
    result
}
