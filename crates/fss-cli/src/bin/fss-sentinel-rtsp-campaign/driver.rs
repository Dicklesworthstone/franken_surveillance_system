#![forbid(unsafe_code)]
//! One exact current owner for history, model, source archives, imports and native sentinel.

use super::archive_open::{ArchiveReadBudget, open_archive};
use super::import_plan::CAPS;
use super::plan::{FORMAT, Options, PACKAGE_COMPILE_MACS, STORAGE_OPERATIONS};
use fss_cli::agent_json::{array, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::LocalPublicationLimits;
use fss_reference::ingest::long_sentinel::retained::MAX_LONG_SENTINEL_METADATA_BYTES;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::rtsp_campaign_sentinel::{
    RtspCampaignSentinelAuthority, RtspCampaignSentinelPlan, process_rtsp_campaign_sentinel,
};
use fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES;
use fss_reference::rtsp::campaign_history::{
    CampaignAuthority, CampaignOperation, CampaignPin, CampaignPlan, VerifiedCampaignHistory,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const AUTHORITY: &str = "ERR-RTSP-CAMPAIGN-SENTINEL-AUTHORITY-001";
const REQUEST: &str = "ERR-RTSP-CAMPAIGN-SENTINEL-REQUEST-001";
const LIMIT: &str = "ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001";
const SOURCE: &str = "ERR-RTSP-IMPORT-SOURCE-001";

struct Owner<'a> {
    options: &'a Options,
    authority: &'a ContextAuthority,
    start: Instant,
}
fn current(authority: &ContextAuthority, start: Instant, timeout: u64) -> bool {
    authority.validate().is_ok()
        && authority.cancellation_reason.is_none()
        && authority.has_capability("ADP-REPLAY-001")
        && CAPS
            .iter()
            .all(|capability| authority.has_capability(capability))
        && start.elapsed() < Duration::from_millis(timeout)
}
impl Owner<'_> {
    fn check(&self) -> Result<(), &'static str> {
        if current(self.authority, self.start, self.options.input.timeout_ms) {
            Ok(())
        } else {
            Err(AUTHORITY)
        }
    }
}
impl CampaignAuthority for Owner<'_> {
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool {
        operation == CampaignOperation::Read
            && plan.principal == self.options.input.principal
            && plan.approval == self.options.plan.history.approval
            && Path::new(&plan.history_path) == self.options.plan.history_root
            && plan.digest().ok() == Some(self.options.plan.history.plan)
            && self.check().is_ok()
    }
    fn permit_read(&self, expected: CampaignPin, root: &Path, principal: &str) -> bool {
        expected == self.options.plan.history
            && root == self.options.plan.history_root
            && principal == self.options.input.principal
            && self.check().is_ok()
    }
}
impl RtspCampaignSentinelAuthority for Owner<'_> {
    fn permit_sentinel(
        &self,
        plan: &RtspCampaignSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        std::ptr::eq(plan, &self.options.plan)
            && destination.root() == self.options.input.root
            && destination.site_lineage() == self.options.input.site
            && self.check().is_ok()
    }
}
fn archive_error(error: &'static str) -> &'static str {
    match error {
        "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001" => AUTHORITY,
        "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001" => LIMIT,
        error => error,
    }
}
fn quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Current ceilings admit the exact retained recipe; they never reconstruct or replace it.
fn rerun(options: &Options, report: ContentDigest) -> Result<String, &'static str> {
    let l = &options.limits.sentinel;
    let mut args = vec!["fss-infer".to_owned(), "sentinel-replay".into()];
    for (key, value) in [
        (
            "--root",
            options.input.root.to_str().ok_or(REQUEST)?.to_owned(),
        ),
        ("--site", options.input.site.clone()),
        ("--principal", options.input.principal.clone()),
        ("--report-digest", report.to_text()),
        (
            "--stream-read-bytes",
            l.maximum_source_chunk_bytes.to_string(),
        ),
        ("--stream-pixel-budget", l.maximum_pixel_samples.to_string()),
        ("--max-report-bytes", l.maximum_report_bytes.to_string()),
        ("--max-macs", l.package.run.execution.max_macs.to_string()),
        (
            "--max-tensor-bytes",
            l.package.run.execution.max_bytes.to_string(),
        ),
        (
            "--max-metadata-bytes",
            MAX_LONG_SENTINEL_METADATA_BYTES.to_string(),
        ),
    ] {
        args.push(key.into());
        args.push(quote(&value));
    }
    if let Some(pixels) = options.frame_pixels {
        args.push("--max-frame-pixels".into());
        args.push(pixels.to_string());
    }
    let text = args.join(" ");
    if text.len() > 8192 {
        return Err(LIMIT);
    }
    Ok(text)
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    if options.input.approve != Some(options.approval()?) {
        return Err(AUTHORITY);
    }
    options.preview()?;
    let plan_digest = options
        .plan
        .digest(&options.limits)
        .map_err(|error| error.stable_id())?;
    let mut capabilities = CAPS
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = Arc::new(
        ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:rtsp-campaign-sentinel".into(),
            operation_id: OperationId::parse("operation:rtsp-campaign-sentinel")
                .map_err(|_| AUTHORITY)?,
            principal: options.input.principal.clone(),
            capabilities,
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(options.authority_byte_budget()?)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| AUTHORITY)?,
            privacy_scope: "privacy:owner-original-rtsp-campaign-model".into(),
            retention_scope: "retention:source-closed-rtsp-campaign-sentinel".into(),
            anchor_universe: ContentDigest::sha256(options.input.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| AUTHORITY)?,
    );
    let start = Instant::now();
    let owner = Owner {
        options,
        authority: &authority,
        start,
    };
    owner.check()?;
    let history_cx = Arc::new(
        ReplayCx::from_context_authority_read_only(&authority, &options.plan.history_root)
            .map_err(|_| AUTHORITY)?,
    );
    let scalar = Arc::new(ScalarExecCx::new());
    let result = (|| {
        let mut work = WorkBudget::new(options.input.work);
        let history = VerifiedCampaignHistory::inspect(
            &options.plan.history_root,
            options.plan.history,
            options.limits.history,
            options.limits.history_publication,
            &owner,
            &history_cx,
            &mut work,
        )
        .map_err(|error| error.stable_id())?;
        options
            .plan
            .validate_destination(&history, &options.input.root)
            .map_err(|error| error.stable_id())?;
        let allowed_archives = super::preflight::check(
            &options.input.root,
            &options.plan.history_root,
            &history,
            &options.input.children,
            std::slice::from_ref(&options.package),
            &|| owner.check(),
            &mut work,
            super::preflight::Errors {
                request: REQUEST,
                source: SOURCE,
                limit: LIMIT,
            },
        )?;
        let boundary = || {
            owner.check()?;
            history_cx
                .checkpoint("rtsp_campaign_sentinel:model_io")
                .map_err(|_| AUTHORITY)?;
            scalar
                .checkpoint("rtsp_campaign_sentinel:model_io")
                .map_err(|_| AUTHORITY)
        };
        let package_bytes = super::model::read(
            &options.package,
            options.plan.package_digest,
            &boundary,
            &mut work,
        )?;
        let package = RgbDetectorPackage::load_with_backend(
            &package_bytes,
            options.plan.package_digest,
            PACKAGE_COMPILE_MACS,
            options.plan.backend,
            &history_cx,
            &scalar,
        )
        .map_err(|error| error.stable_id())?
        .with_execution_threads(options.threads);
        boundary()?;
        let archive_authority = Arc::clone(&authority);
        let archive_cx = Arc::clone(&history_cx);
        let archive_scalar = Arc::clone(&scalar);
        let timeout = options.input.timeout_ms;
        let budget = ArchiveReadBudget::new(
            options.input.archive_read_bytes,
            STORAGE_OPERATIONS,
            Arc::new(move |root| {
                allowed_archives.iter().any(|archive| archive == root)
                    && current(&archive_authority, start, timeout)
                    && archive_cx
                        .checkpoint("rtsp_campaign_sentinel:source_io")
                        .is_ok()
                    && !archive_scalar.is_cancelled()
            }),
        );
        let mut archives = Vec::with_capacity(options.input.children.len());
        for child in &options.input.children {
            boundary()?;
            archives.push(match child {
                None => None,
                Some(child) => Some(
                    open_archive(
                        &child.archive,
                        LocalPublicationLimits::new(
                            65536,
                            MAX_MANIFEST_CHILDREN,
                            65536,
                            65536,
                            SpoolLimits::new(
                                65536,
                                1024 * 1024 * 1024,
                                MAX_ORIGINAL_BYTES as usize,
                                131072,
                            ),
                        ),
                        &budget,
                    )
                    .map_err(archive_error)?,
                ),
            });
        }
        let startup_bytes = budget.bytes_read();
        let startup_operations = budget.operations();
        boundary()?;
        let cx = ReplayCx::from_context_authority(&authority, options.input.root.clone())
            .map_err(|_| AUTHORITY)?;
        let result = (|| {
            boundary()?;
            let mut destination =
                ReferenceDeployment::open(&options.input.root, &options.input.site, &cx)
                    .map_err(|_| "ERR-RTSP-IMPORT-CUSTODY-001")?;
            let sources = archives.iter().map(Option::as_ref).collect::<Vec<_>>();
            let report = process_rtsp_campaign_sentinel(
                &sources,
                &mut destination,
                &package,
                &package_bytes,
                &options.plan,
                &options.limits,
                &owner,
                &history_cx,
                &cx,
                &scalar,
                &mut work,
            )
            .map_err(|error| {
                budget
                    .check()
                    .err()
                    .map(archive_error)
                    .unwrap_or(error.stable_id())
            })?;
            boundary()?;
            budget.check().map_err(archive_error)?;
            if report.plan_digest() != plan_digest {
                return Err(AUTHORITY);
            }
            let commands = report
                .attempts()
                .iter()
                .map(|attempt| {
                    let command = attempt
                        .retained()
                        .map(|retained| rerun(options, retained.report_digest()))
                        .transpose()?;
                    Ok(object(&[
                        ("ordinal", attempt.ordinal().to_string()),
                        (
                            "command",
                            command.as_deref().map_or_else(|| "null".into(), string),
                        ),
                        (
                            "analysis_retained",
                            attempt.retained().is_some().to_string(),
                        ),
                        ("event_publication_authorized", "false".into()),
                    ]))
                })
                .collect::<Result<Vec<_>, &'static str>>()?;
            let native = report
                .to_json(destination.current_anchor().commit_sequence)
                .map_err(|error| error.stable_id())?;
            let output = object(&[
                ("format", string(FORMAT)),
                ("kind", string("completed")),
                ("approval_digest", string(&options.approval()?.to_text())),
                ("report", native),
                ("native_sentinel_reruns", array(&commands)),
                (
                    "history_import_model_work",
                    object(&[
                        ("used", work.used().to_string()),
                        ("remaining", work.remaining().to_string()),
                    ]),
                ),
                ("model_read_bytes", package_bytes.len().to_string()),
                (
                    "archive_io",
                    object(&[
                        ("startup_read_bytes", startup_bytes.to_string()),
                        ("startup_operations", startup_operations.to_string()),
                        ("total_read_bytes", budget.bytes_read().to_string()),
                        ("total_operations", budget.operations().to_string()),
                        (
                            "maximum_read_bytes",
                            options.input.archive_read_bytes.to_string(),
                        ),
                        ("maximum_operations", STORAGE_OPERATIONS.to_string()),
                    ]),
                ),
                ("event_publication_authorized", "false".into()),
                ("capture_resume_authorized", "false".into()),
            ]);
            if output.len() >= options.limits.maximum_report_bytes {
                return Err(LIMIT);
            }
            boundary()?;
            Ok(output)
        })();
        cx.drain_and_finalize();
        result
    })();
    scalar.drain_and_finalize();
    history_cx.drain_and_finalize();
    result
}
