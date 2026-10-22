#![forbid(unsafe_code)]
//! One exact owner for cold history, independently retained source archives and destination watch.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::LocalPublicationLimits;
use fss_reference::ingest::rtsp_campaign_watch::{
    RtspCampaignWatchAuthority, RtspCampaignWatchPlan, process_rtsp_campaign,
};
use fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES;
use fss_reference::rtsp::campaign_history::{
    CampaignAuthority, CampaignOperation, CampaignPin, CampaignPlan, VerifiedCampaignHistory,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::archive_open::{ArchiveReadBudget, open_archive};
use super::import_plan::CAPS;
use super::plan::{FORMAT, Options, STORAGE_OPERATIONS};

const AUTHORITY: &str = "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001";
const REQUEST: &str = "ERR-RTSP-CAMPAIGN-WATCH-REQUEST-001";
const LIMIT: &str = "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001";
const SOURCE: &str = "ERR-RTSP-IMPORT-SOURCE-001";

struct Owner<'a> {
    options: &'a Options,
    authority: &'a ContextAuthority,
    start: Instant,
}

fn current(authority: &ContextAuthority, start: Instant, timeout_ms: u64) -> bool {
    authority.validate().is_ok()
        && authority.cancellation_reason.is_none()
        && authority.has_capability("ADP-REPLAY-001")
        && CAPS
            .iter()
            .all(|capability| authority.has_capability(capability))
        && start.elapsed() < Duration::from_millis(timeout_ms)
}

impl Owner<'_> {
    fn check(&self) -> Result<(), &'static str> {
        if current(self.authority, self.start, self.options.timeout_ms) {
            Ok(())
        } else {
            Err(AUTHORITY)
        }
    }
}

impl CampaignAuthority for Owner<'_> {
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool {
        operation == CampaignOperation::Read
            && plan.principal == self.options.principal
            && plan.approval == self.options.plan.history.approval
            && Path::new(&plan.history_path) == self.options.plan.history_root
            && plan.digest().ok() == Some(self.options.plan.history.plan)
            && self.check().is_ok()
    }

    fn permit_read(&self, expected: CampaignPin, root: &Path, principal: &str) -> bool {
        expected == self.options.plan.history
            && root == self.options.plan.history_root
            && principal == self.options.principal
            && self.check().is_ok()
    }
}

impl RtspCampaignWatchAuthority for Owner<'_> {
    fn permit_watch(
        &self,
        plan: &RtspCampaignWatchPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        std::ptr::eq(plan, &self.options.plan)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.check().is_ok()
    }
}

fn preflight(
    owner: &Owner<'_>,
    history: &VerifiedCampaignHistory,
    work: &mut WorkBudget<'_>,
) -> Result<Vec<PathBuf>, &'static str> {
    owner
        .options
        .plan
        .validate_destination(history, &owner.options.root)
        .map_err(|error| error.stable_id())?;
    super::preflight::check(
        &owner.options.root,
        &owner.options.plan.history_root,
        history,
        &owner.options.children,
        &[],
        &|| owner.check(),
        work,
        super::preflight::Errors {
            request: REQUEST,
            source: SOURCE,
            limit: LIMIT,
        },
    )
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    // Complete pure admission precedes clocks, filesystem metadata, archive recovery and writes.
    if options.approve != Some(options.approval()?) {
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
            trace_id: "trace:rtsp-campaign-watch".into(),
            operation_id: OperationId::parse("operation:rtsp-campaign-watch")
                .map_err(|_| AUTHORITY)?,
            principal: options.principal.clone(),
            capabilities,
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(options.authority_byte_budget()?)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| AUTHORITY)?,
            privacy_scope: "privacy:owner-original-rtsp-campaign".into(),
            retention_scope: "retention:source-closed-rtsp-campaign-imports".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| AUTHORITY)?,
    );
    authority.validate().map_err(|_| AUTHORITY)?;
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
    let result = (|| {
        let mut work = WorkBudget::new(options.work);
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
        let allowed_archives = preflight(&owner, &history, &mut work)?;
        let archive_authority = Arc::clone(&authority);
        let archive_cx = Arc::clone(&history_cx);
        let timeout = options.timeout_ms;
        let budget = ArchiveReadBudget::new(
            options.archive_read_bytes,
            STORAGE_OPERATIONS,
            Arc::new(move |root| {
                allowed_archives.iter().any(|archive| archive == root)
                    && current(&archive_authority, start, timeout)
                    && archive_cx
                        .checkpoint("rtsp_campaign_watch:source_io")
                        .is_ok()
            }),
        );
        let mut archives = Vec::with_capacity(options.children.len());
        for child in &options.children {
            owner.check()?;
            archives.push(match child {
                None => None,
                Some(child) => Some(open_archive(
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
                )?),
            });
        }
        let startup_bytes = budget.bytes_read();
        let startup_operations = budget.operations();
        owner.check()?;
        let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
            .map_err(|_| AUTHORITY)?;
        let result = (|| {
            owner.check()?;
            let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-RTSP-IMPORT-CUSTODY-001")?;
            let sources = archives.iter().map(Option::as_ref).collect::<Vec<_>>();
            let report = process_rtsp_campaign(
                &sources,
                &mut destination,
                &options.plan,
                &options.limits,
                &owner,
                &history_cx,
                &cx,
                &mut work,
            )
            .map_err(|error| budget.check().err().unwrap_or(error.stable_id()))?;
            owner.check()?;
            budget.check()?;
            if report.plan_digest() != plan_digest {
                return Err(AUTHORITY);
            }
            let commands = report
                .attempts()
                .iter()
                .map(|attempt| {
                    let command = attempt
                        .watch_plan()
                        .map(|plan| super::rerun::watch_command(options, plan))
                        .transpose()?;
                    Ok(object(&[
                        ("ordinal", attempt.ordinal().to_string()),
                        (
                            "command",
                            command.as_deref().map_or_else(|| "null".into(), string),
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
                ("native_watch_reruns", array(&commands)),
                (
                    "history_and_import_work",
                    object(&[
                        ("used", work.used().to_string()),
                        ("remaining", work.remaining().to_string()),
                    ]),
                ),
                (
                    "archive_io",
                    object(&[
                        ("startup_read_bytes", startup_bytes.to_string()),
                        ("startup_operations", startup_operations.to_string()),
                        ("total_read_bytes", budget.bytes_read().to_string()),
                        ("total_operations", budget.operations().to_string()),
                        ("maximum_read_bytes", options.archive_read_bytes.to_string()),
                        ("maximum_operations", STORAGE_OPERATIONS.to_string()),
                    ]),
                ),
                ("event_publication_authorized", "false".into()),
                ("capture_resume_authorized", "false".into()),
            ]);
            if output.len() >= options.limits.maximum_report_bytes {
                return Err(LIMIT);
            }
            owner.check()?;
            Ok(output)
        })();
        cx.drain_and_finalize();
        result
    })();
    history_cx.drain_and_finalize();
    result
}
