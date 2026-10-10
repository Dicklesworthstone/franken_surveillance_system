#![forbid(unsafe_code)]
//! Explicit original-custody authority and finite, restart-reproducible history processing.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use fss_codec_mjpeg::DecodeBudget;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::ingest::http_history_watch::{
    HttpHistoryWatchAuthority, HttpHistoryWatchPlan, process_http_history,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::plan::Options;

const CAPS: [&str; 5] = [
    "ADP-REPLAY-001",
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

struct Owner<'a> {
    options: &'a Options,
    plan_digest: ContentDigest,
    cx: &'a ReplayCx,
    authority: &'a ContextAuthority,
    start: Instant,
}

impl HttpHistoryWatchAuthority for Owner<'_> {
    fn permit(&self, plan: &HttpHistoryWatchPlan, destination: &ReferenceDeployment) -> bool {
        plan.digest(&self.options.limits)
            .is_ok_and(|d| d == self.plan_digest)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.cx.checkpoint("http_history_watch:operator").is_ok()
            && self.authority.cancellation_reason.is_none()
            && CAPS.iter().all(|c| self.authority.has_capability(c))
            && self.start.elapsed() < Duration::from_millis(self.options.timeout_ms)
    }
}

fn existing_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    // Pure admission and exact approval MUST precede every filesystem or clock observation.
    if options.approve != Some(options.approval()?) {
        return Err("ERR-HTTP-HISTORY-WATCH-AUTHORITY-001");
    }
    let plan_digest = options
        .plan
        .digest(&options.limits)
        .map_err(|e| e.stable_id())?;
    options
        .plan
        .reservation(&options.limits)
        .map_err(|e| e.stable_id())?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-history-watch".into(),
        operation_id: OperationId::parse("operation:http-history-watch")
            .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?,
        principal: options.principal.clone(),
        capabilities: CAPS.iter().map(|c| (*c).to_owned()).collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?,
        privacy_scope: "privacy:owner-original-http-history".into(),
        retention_scope: "retention:source-closed-http-history-imports".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?;
    authority
        .validate()
        .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?;
    let start = Instant::now();
    for name in ["", "spool", "roots", "tombstones"] {
        if !existing_directory(&options.archive.join(name)) {
            return Err("ERR-HTTP-IMPORT-SOURCE-001");
        }
    }
    let source = options
        .archive
        .canonicalize()
        .map_err(|_| "ERR-HTTP-IMPORT-SOURCE-001")?;
    let target = match std::fs::symlink_metadata(&options.root) {
        Ok(m) if m.file_type().is_dir() => options
            .root
            .canonicalize()
            .map_err(|_| "ERR-HTTP-HISTORY-WATCH-REQUEST-001")?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or("ERR-HTTP-HISTORY-WATCH-REQUEST-001")?
            .canonicalize()
            .map_err(|_| "ERR-HTTP-HISTORY-WATCH-REQUEST-001")?
            .join(
                options
                    .root
                    .file_name()
                    .ok_or("ERR-HTTP-HISTORY-WATCH-REQUEST-001")?,
            ),
        _ => return Err("ERR-HTTP-HISTORY-WATCH-REQUEST-001"),
    };
    if source.starts_with(&target) || target.starts_with(&source) {
        return Err("ERR-HTTP-HISTORY-WATCH-REQUEST-001");
    }
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-HTTP-HISTORY-WATCH-AUTHORITY-001")?;
    let result = (|| {
        let owner = Owner {
            options,
            plan_digest,
            cx: &cx,
            authority: &authority,
            start,
        };
        let checkpoint = || -> Result<(), &'static str> {
            cx.checkpoint("http_history_watch:operator_io")
                .map_err(|_| "ERR-HTTP-HISTORY-WATCH-AUTHORITY-001")?;
            if start.elapsed() >= Duration::from_millis(options.timeout_ms) {
                return Err("ERR-HTTP-HISTORY-WATCH-AUTHORITY-001");
            }
            Ok(())
        };
        checkpoint()?;
        let archive = LocalRootPublisher::open(
            &options.archive,
            LocalPublicationLimits::new(
                65536,
                MAX_MANIFEST_CHILDREN,
                65536,
                65536,
                SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 131072),
            ),
        )
        .map_err(|_| "ERR-HTTP-IMPORT-SOURCE-001")?;
        checkpoint()?;
        let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
            .map_err(|_| "ERR-HTTP-IMPORT-CUSTODY-001")?;
        let mut work = WorkBudget::new(options.work);
        let mut framing = DecodeBudget::new(options.framing);
        let report = process_http_history(
            &archive,
            &mut destination,
            &options.plan,
            &options.limits,
            &owner,
            &cx,
            &mut work,
            &mut framing,
        )
        .map_err(|e| e.stable_id())?;
        checkpoint()?;
        let hints = report
            .generations()
            .iter()
            .map(|g| {
                g.watch_plan()
                    .map(|p| super::rerun::watch_command(options, p))
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let json = report
            .to_json(destination.current_anchor().commit_sequence, &hints)
            .map_err(|e| e.stable_id())?;
        checkpoint()?;
        Ok(json)
    })();
    cx.drain_and_finalize();
    result
}
