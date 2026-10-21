#![forbid(unsafe_code)]
//! One explicit owner for source custody, destination retention and finite native analysis.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES;
use fss_reference::ingest::rtsp_selected_watch::{
    RtspSelectedWatchAuthority, RtspSelectedWatchPlan, process_rtsp_selections,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::import_plan::CAPS;
use super::plan::{Options, STORAGE_OPERATIONS};

const AUTHORITY: &str = "ERR-RTSP-SELECTED-WATCH-AUTHORITY-001";
const REQUEST: &str = "ERR-RTSP-SELECTED-WATCH-REQUEST-001";
const SOURCE: &str = "ERR-RTSP-IMPORT-SOURCE-001";

struct Owner<'a> {
    options: &'a Options,
    cx: &'a ReplayCx,
    authority: &'a ContextAuthority,
    start: Instant,
}

impl RtspSelectedWatchAuthority for Owner<'_> {
    fn permit(&self, plan: &RtspSelectedWatchPlan, destination: &ReferenceDeployment) -> bool {
        // Options and its fully validated plan stay immutably borrowed for this entire run.
        // Admit that exact plan without re-allocating native decoder state at every I/O check.
        std::ptr::eq(plan, &self.options.plan)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && authority_boundary(self.options, self.authority, self.start).is_ok()
            && self.cx.checkpoint("rtsp_selected_watch:operator").is_ok()
    }
}

fn authority_boundary(
    options: &Options,
    authority: &ContextAuthority,
    start: Instant,
) -> Result<(), &'static str> {
    if authority.cancellation_reason.is_some()
        || !authority.has_capability("ADP-REPLAY-001")
        || !CAPS
            .iter()
            .all(|capability| authority.has_capability(capability))
        || start.elapsed() >= Duration::from_millis(options.timeout_ms)
    {
        return Err(AUTHORITY);
    }
    Ok(())
}

fn existing_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn preflight(
    options: &Options,
    authority: &ContextAuthority,
    start: Instant,
) -> Result<(), &'static str> {
    // ReplayCx creates its destination root. Refuse missing sources and overlapping stores first,
    // using the validated exact-plan owner to admit each filesystem observation.
    for name in ["", "spool", "roots", "tombstones"] {
        authority_boundary(options, authority, start)?;
        if !existing_directory(&options.archive.join(name)) {
            return Err(SOURCE);
        }
        authority_boundary(options, authority, start)?;
    }
    let source = options.archive.canonicalize().map_err(|_| SOURCE)?;
    authority_boundary(options, authority, start)?;
    let target = match std::fs::symlink_metadata(&options.root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            options.root.canonicalize().map_err(|_| REQUEST)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or(REQUEST)?
            .canonicalize()
            .map_err(|_| REQUEST)?
            .join(options.root.file_name().ok_or(REQUEST)?),
        _ => return Err(REQUEST),
    };
    authority_boundary(options, authority, start)?;
    if source.starts_with(&target) || target.starts_with(&source) {
        return Err(REQUEST);
    }
    Ok(())
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    // Approval, the complete source selection and aggregate capacity all precede file/clock I/O.
    if options.approve != Some(options.approval()?) {
        return Err(AUTHORITY);
    }
    options.preview()?;
    let plan_digest = options
        .plan
        .digest(&options.limits)
        .map_err(|error| error.stable_id())?;
    let mut capabilities: Vec<_> = CAPS
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-selected-watch".into(),
        operation_id: OperationId::parse("operation:rtsp-selected-watch").map_err(|_| AUTHORITY)?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.authority_byte_budget()?)
            .storage_operations(STORAGE_OPERATIONS)
            .build()
            .map_err(|_| AUTHORITY)?,
        privacy_scope: "privacy:owner-original-rtsp-selected".into(),
        retention_scope: "retention:source-closed-rtsp-selected-imports".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| AUTHORITY)?;
    authority.validate().map_err(|_| AUTHORITY)?;
    let start = Instant::now();
    preflight(options, &authority, start)?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| AUTHORITY)?;
    let result = (|| {
        let boundary = || {
            authority_boundary(options, &authority, start)?;
            cx.checkpoint("rtsp_selected_watch:operator_io")
                .map_err(|_| AUTHORITY)
        };
        boundary()?;
        let archive = LocalRootPublisher::open(
            &options.archive,
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
        )
        .map_err(|_| SOURCE)?;
        boundary()?;
        let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
            .map_err(|_| "ERR-RTSP-IMPORT-CUSTODY-001")?;
        let owner = Owner {
            options,
            cx: &cx,
            authority: &authority,
            start,
        };
        let mut work = WorkBudget::new(options.work);
        let report = process_rtsp_selections(
            &archive,
            &mut destination,
            &options.plan,
            &options.limits,
            &owner,
            &cx,
            &mut work,
        )
        .map_err(|error| error.stable_id())?;
        boundary()?;
        if report.plan_digest() != plan_digest {
            return Err(AUTHORITY);
        }
        let json = report
            .to_json(destination.current_anchor().commit_sequence)
            .map_err(|error| error.stable_id())?;
        boundary()?;
        Ok(json)
    })();
    cx.drain_and_finalize();
    result
}
