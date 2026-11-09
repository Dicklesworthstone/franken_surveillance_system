#![forbid(unsafe_code)]
//! Protected UTC preview followed by separately approved, source-closed native acquisition.

use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::HostSpoolIo;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;
use fss_reference::ingest::rtsp_import::query::utc::{
    RtspUtcQueryImportAuthority, RtspUtcQueryImportPlan, import_rtsp_utc_query_pinned_existing,
    preview_rtsp_utc_query_import,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::super::plan::CAPS;
use super::{MAX_OUTPUT_BYTES, RESULT_HEADROOM, UtcOptions};

#[path = "query_utc_json.rs"]
mod json;

pub(super) fn plan_report(
    options: &UtcOptions,
    plan: &RtspUtcQueryImportPlan,
) -> Result<String, &'static str> {
    let mut fields = json::base(options, plan)?;
    fields.extend([
        ("kind", string("plan")),
        (
            "selected_windows",
            array(
                &plan
                    .windows()
                    .iter()
                    .map(json::window)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        (
            "source_payload_availability",
            string("unknown_until_approved_native_verification"),
        ),
        ("source_media_reads", "0".into()),
        ("writes", string("none")),
    ]);
    let report = object(&fields);
    // Reserve enough space for every bounded native receipt before any writer is opened.
    // Complete provenance is refused if oversized; neither memberships nor gaps are truncated.
    if report.len() > MAX_OUTPUT_BYTES - RESULT_HEADROOM {
        return Err("ERR-RTSP-IMPORT-REQUEST-001");
    }
    Ok(report)
}

struct Owner<'a> {
    options: &'a UtcOptions,
    plan_digest: ContentDigest,
    authority: &'a ContextAuthority,
    cx: &'a ReplayCx,
    start: Instant,
}
impl Owner<'_> {
    fn allowed(&self, plan: &RtspUtcQueryImportPlan) -> bool {
        plan.digest() == self.plan_digest
            && self
                .options
                .approve
                .is_some_and(|approved| self.options.approval(plan.digest()).ok() == Some(approved))
            && self.authority.cancellation_reason.is_none()
            && CAPS
                .iter()
                .all(|capability| self.authority.has_capability(capability))
            && self.start.elapsed() < Duration::from_millis(self.options.timeout_ms)
            && self.cx.checkpoint("import_rtsp:utc_query_operator").is_ok()
    }
}
impl RtspUtcQueryImportAuthority for Owner<'_> {
    fn permit_open(&self, plan: &RtspUtcQueryImportPlan) -> bool {
        self.allowed(plan)
    }
    fn permit(&self, plan: &RtspUtcQueryImportPlan, destination: &ReferenceDeployment) -> bool {
        self.allowed(plan)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.settings.site
    }
}

fn acquire(
    options: &UtcOptions,
    plan: &RtspUtcQueryImportPlan,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    start: Instant,
) -> Result<(String, bool), &'static str> {
    let cancelled =
        || start.elapsed() >= Duration::from_millis(options.timeout_ms) || cx.is_cancelled();
    cx.checkpoint("import_rtsp:utc_query_source_reader")
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let mut source = PinnedClosureReader::new(
        &HostSpoolIo,
        &options.archive,
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
    let mut work = WorkBudget::new(options.settings.max_work);
    let result = import_rtsp_utc_query_pinned_existing(
        &HostSpoolIo,
        &mut source,
        plan,
        &owner,
        cx,
        &mut work,
        &cancelled,
    );
    let usage = source.usage();
    let mut fields = json::base(options, plan)?;
    fields.extend([
        ("kind", string("acquisition_result")),
        ("atomic", "false".into()),
        ("work_used", work.used().to_string()),
        ("source_read_bytes", usage.read_bytes.to_string()),
        ("source_io_calls", usage.io_calls.to_string()),
    ]);
    let complete = match result {
        Ok(receipt) => {
            fields.extend([
                ("complete", "true".into()),
                ("imports", json::imported(&receipt.imports)?),
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
                ("imports", json::imported(&failure.completed)?),
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

pub(super) fn run(options: &UtcOptions) -> Result<(String, bool), &'static str> {
    let start = Instant::now();
    let cancelled = || start.elapsed() >= Duration::from_millis(options.timeout_ms);
    let plan = preview_rtsp_utc_query_import(
        &HostSpoolIo,
        &options.root,
        &options.archive,
        &options.input,
        &options.settings,
        &cancelled,
    )
    .map_err(|error| error.stable_id())?;
    let preview = plan_report(options, &plan)?;
    if options.approve.is_none() {
        return Ok((preview, true));
    }
    if options.approve != Some(options.approval(plan.digest())?) {
        return Err("ERR-RTSP-IMPORT-APPROVAL-001");
    }
    let mut capabilities = CAPS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-utc-query-import".into(),
        operation_id: OperationId::parse("operation:rtsp-utc-query-import")
            .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?,
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:source-closed-rtsp-utc-query-import".into(),
        anchor_universe: ContentDigest::sha256(options.settings.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    authority
        .validate()
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    super::super::driver::preflight_store_paths(
        &options.archive,
        &options.root,
        options.timeout_ms,
        &authority,
        start,
    )?;
    // Construct authority without creating a vanished destination. The native import owner
    // separately checks current retention authority and opens only an existing deployment.
    let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let result = acquire(options, &plan, &authority, &cx, start);
    cx.drain_and_finalize();
    result
}
