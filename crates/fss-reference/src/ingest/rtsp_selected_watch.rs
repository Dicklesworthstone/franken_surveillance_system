#![forbid(unsafe_code)]
//! Bounded selected RTSP recordings → exact retained imports → independent native watch runs.
//!
//! A window, whole catalog, or ordered page selection remains one independent analysis epoch.
//! Selection order is owner supplied; it proves neither a complete campaign nor missing/empty
//! connection attempts. Native catalog continuity stays within its own verified selection.
//! Every import completes before analysis, so every proposal uses the final destination anchor.
//! Imports are durable and exactly retryable; analysis grants no event publication authority.

mod plan;
mod report;

use std::fmt;

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;

use super::long_watch::LongWatchReport;
use super::recorded_watch::{WatchError, WatchPlan};
use super::rtsp_import::catalog::{
    RtspCatalogImportAuthority, RtspCatalogImportRequest, import_rtsp_catalog,
};
use super::rtsp_import::pages::{
    RtspCatalogPagesImportAuthority, RtspCatalogPagesImportRequest, import_rtsp_catalog_pages,
};
use super::rtsp_import::{
    RtspImportAuthority, RtspImportError, RtspImportReceipt, RtspImportRequest, import_rtsp,
};
use crate::{ReferenceDeployment, ReplayCx};

pub use plan::{
    MAX_REPORT_BYTES, MAX_SELECTIONS, RtspSelectedWatchLimits, RtspSelectedWatchPlan,
    RtspSelectedWatchReservation, RtspWatchSelection,
};
pub use report::RtspSelectedWatchReport;

/// Live original-access, retention, cancellation, deadline and release boundary.
pub const STAGE_RTSP_SELECTED_WATCH: &str = "rtsp_selected_watch:authority";
/// Cooperative restart cut before each independent retained import.
pub const STAGE_RTSP_SELECTED_IMPORT: &str = "rtsp_selected_watch:next_import";
/// Cooperative cut after all imports, before each independent analysis.
pub const STAGE_RTSP_SELECTED_ANALYZE: &str = "rtsp_selected_watch:next_analysis";
/// Cooperative final release; completed imports remain durable after refusal here.
pub const STAGE_RTSP_SELECTED_RELEASE: &str = "rtsp_selected_watch:release";
/// Bounded implementation-specific projection, without a new durable event or history schema.
pub const RTSP_SELECTED_WATCH_REPORT_SCHEMA: &str = "fss.rtsp_selected_watch_report.v1";
const POLICY: &[u8] = b"explicit-ordered-native-window-catalog-pages:independent-selections:source-closed-imports:all-imports-before-analysis:one-import-work-account:fixed-upfront-analysis-reservations:independent-background-and-tracker:masked-before-perception:exact-import-reconciliation:no-campaign-history:no-empty-attempt-coverage:no-automatic-event:no-absence:no-alert:v1";
type Result<T> = std::result::Result<T, RtspSelectedWatchError>;

/// Current permission for the whole exact selection, original disclosure and destination
/// retention. Callers independently bind destination root, site, principal and deadline.
pub trait RtspSelectedWatchAuthority {
    /// Recheck current owner policy, revocation and deadline; there is no default grant.
    fn permit(&self, plan: &RtspSelectedWatchPlan, destination: &ReferenceDeployment) -> bool;
}

/// A refusal never authorizes skipping a selection, replenishing work, or widening source scope.
#[derive(Debug)]
pub enum RtspSelectedWatchError {
    /// Invalid selection, capture assumption, analysis configuration or route ownership.
    Invalid(&'static str),
    /// Current owner authority, cancellation or deadline refused.
    Denied,
    /// A complete reservation or report exceeds its independent hard bound.
    Limit,
    /// Native source verification or exact retained import refused.
    Import(RtspImportError),
    /// Existing whole-recording analysis refused.
    Watch(Box<WatchError>),
}
impl RtspSelectedWatchError {
    /// Stable payload-free identity; native failures preserve the underlying owner identity.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-RTSP-SELECTED-WATCH-REQUEST-001",
            Self::Denied => "ERR-RTSP-SELECTED-WATCH-AUTHORITY-001",
            Self::Limit => "ERR-RTSP-SELECTED-WATCH-LIMIT-001",
            Self::Import(error) => error.stable_id(),
            Self::Watch(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for RtspSelectedWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for RtspSelectedWatchError {}
impl From<RtspImportError> for RtspSelectedWatchError {
    fn from(error: RtspImportError) -> Self {
        Self::Import(error)
    }
}
impl From<WatchError> for RtspSelectedWatchError {
    fn from(error: WatchError) -> Self {
        Self::Watch(Box::new(error))
    }
}

/// One complete independently selected recording. All getters are immutable; these proposals
/// cannot be published through this composition. Native event approval remains a separate action.
#[derive(Debug)]
pub struct RtspSelectedWatchResult {
    selection: RtspWatchSelection,
    request_digest: ContentDigest,
    import: RtspImportReceipt,
    windows: usize,
    pages: usize,
    watch_plan: WatchPlan,
    watch_report: LongWatchReport,
}
impl RtspSelectedWatchResult {
    /// Original exact request, including source clocks and operator capture assumptions.
    pub fn selection(&self) -> &RtspWatchSelection {
        &self.selection
    }
    /// Native source/interpretation request identity.
    pub const fn request_digest(&self) -> ContentDigest {
        self.request_digest
    }
    /// Existing retained import, including exact restart reconciliation status.
    pub fn import(&self) -> &RtspImportReceipt {
        &self.import
    }
    /// Verified complete native window count within this selection.
    pub const fn windows(&self) -> usize {
        self.windows
    }
    /// Verified catalog page count; zero for a single-window request.
    pub const fn pages(&self) -> usize {
        self.pages
    }
    /// Whole retained recording plan, with no truncation at archive or page boundaries.
    pub fn watch_plan(&self) -> &WatchPlan {
        &self.watch_plan
    }
    /// Read-only native candidate inventory; each selection starts independent state.
    pub fn watch_report(&self) -> &LongWatchReport {
        &self.watch_report
    }
}

fn check(
    authority: &dyn RtspSelectedWatchAuthority,
    plan: &RtspSelectedWatchPlan,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    if cx.checkpoint(STAGE_RTSP_SELECTED_WATCH).is_err() || !authority.permit(plan, destination) {
        return Err(RtspSelectedWatchError::Denied);
    }
    Ok(())
}

struct ImportAccess<'a> {
    authority: &'a dyn RtspSelectedWatchAuthority,
    plan: &'a RtspSelectedWatchPlan,
    request: ContentDigest,
    cx: &'a ReplayCx,
}
impl ImportAccess<'_> {
    fn permits(
        &self,
        request: std::result::Result<ContentDigest, RtspImportError>,
        destination: &ReferenceDeployment,
    ) -> bool {
        request.is_ok_and(|digest| digest == self.request)
            && check(self.authority, self.plan, destination, self.cx).is_ok()
    }
}
impl RtspImportAuthority for ImportAccess<'_> {
    fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        self.permits(request.digest(), destination)
    }
}
impl RtspCatalogImportAuthority for ImportAccess<'_> {
    fn permit(
        &self,
        request: &RtspCatalogImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.permits(request.digest(), destination)
    }
}
impl RtspCatalogPagesImportAuthority for ImportAccess<'_> {
    fn permit(
        &self,
        request: &RtspCatalogPagesImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.permits(request.digest(), destination)
    }
}

/// Process one finite exact selection using one archive owner, one destination owner and one
/// import work account. Every pure request and complete resource reservation is admitted before
/// the first import. On failure earlier imports may remain durable; rerun the same exact plan to
/// verify and reuse them. Independent native analyses all run at the final imported anchor.
pub fn process_rtsp_selections(
    archive: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    plan: &RtspSelectedWatchPlan,
    limits: &RtspSelectedWatchLimits,
    authority: &dyn RtspSelectedWatchAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspSelectedWatchReport> {
    let reservation = plan.reservation(limits)?;
    let plan_digest = plan.digest(limits)?;
    if cx.root_dir() != destination.root()
        || archive.root_dir().starts_with(destination.root())
        || destination.root().starts_with(archive.root_dir())
    {
        return Err(RtspSelectedWatchError::Invalid(
            "distinct source and destination owners required",
        ));
    }
    check(authority, plan, destination, cx)?;
    let mut imports = Vec::with_capacity(plan.selections.len());
    for selection in &plan.selections {
        cx.checkpoint(STAGE_RTSP_SELECTED_IMPORT)
            .map_err(|_| RtspSelectedWatchError::Denied)?;
        check(authority, plan, destination, cx)?;
        let request_digest = selection.digest()?;
        let access = ImportAccess {
            authority,
            plan,
            request: request_digest,
            cx,
        };
        let (import, windows, pages) = match selection {
            RtspWatchSelection::Window(request) => (
                import_rtsp(archive, destination, request, &access, cx, work)?,
                1,
                0,
            ),
            RtspWatchSelection::Catalog(request) => {
                let receipt =
                    import_rtsp_catalog(archive, destination, request, &access, cx, work)?;
                (receipt.import, receipt.windows, 1)
            }
            RtspWatchSelection::Pages(request) => {
                let receipt =
                    import_rtsp_catalog_pages(archive, destination, request, &access, cx, work)?;
                (
                    receipt.catalog.import,
                    receipt.catalog.windows,
                    receipt.pages,
                )
            }
        };
        imports.push((selection.clone(), request_digest, import, windows, pages));
    }
    let basis = destination.current_anchor().clone();
    let mut selections = Vec::with_capacity(imports.len());
    for (selection, request_digest, import, windows, pages) in imports {
        cx.checkpoint(STAGE_RTSP_SELECTED_ANALYZE)
            .map_err(|_| RtspSelectedWatchError::Denied)?;
        check(authority, plan, destination, cx)?;
        let watch_plan = plan.watch_plan(import.import_identity, import.frames);
        let watch_report = if plan.screened {
            LongWatchReport::analyze_screened(
                destination,
                &watch_plan,
                plan.options,
                &limits.watch,
                cx,
            )?
        } else {
            LongWatchReport::analyze(destination, &watch_plan, plan.options, &limits.watch, cx)?
        };
        check(authority, plan, destination, cx)?;
        selections.push(RtspSelectedWatchResult {
            selection,
            request_digest,
            import,
            windows,
            pages,
            watch_plan,
            watch_report,
        });
    }
    let report = RtspSelectedWatchReport {
        plan_digest,
        reservation,
        selections,
        basis,
        maximum_report_bytes: limits.maximum_report_bytes,
        screened: plan.screened,
    };
    report.to_json(destination.current_anchor().commit_sequence)?;
    cx.checkpoint(STAGE_RTSP_SELECTED_RELEASE)
        .map_err(|_| RtspSelectedWatchError::Denied)?;
    check(authority, plan, destination, cx)?;
    Ok(report)
}
