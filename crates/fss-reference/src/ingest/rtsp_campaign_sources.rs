#![forbid(unsafe_code)]
//! Sealed shared custody owner for exact retained campaign analysis.
//!
//! All callers use the same complete history mapping, all-source native preflight, restartable
//! imports and final original/history closure. This owner never selects analysis or grants it.

use std::path::{Component, Path};

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};

use super::rtsp_campaign_watch::{RtspCampaignWatchBinding, RtspCampaignWatchError as Error};
use super::rtsp_import::catalog::{
    CatalogPreflight, RtspCatalogImportAuthority, RtspCatalogImportRequest, import_rtsp_catalog,
    preflight_rtsp_catalog,
};
use super::rtsp_import::pages::{
    RtspCatalogPagesImportAuthority, RtspCatalogPagesImportRequest, import_rtsp_catalog_pages,
    preflight_rtsp_catalog_pages,
};
use super::rtsp_import::{RtspImportCodec, RtspImportReceipt};
use super::rtsp_selected_watch::RtspWatchSelection;
use crate::rtsp::campaign_history::{
    CampaignAttemptHistory, CampaignAuthority, CampaignHistoryLimits, CampaignOperation,
    CampaignPin, CampaignPlan, VerifiedCampaignHistory,
};
use crate::rtsp::recording_archive::{ArchiveNamespace, hevc::HevcArchiveNamespace};
use crate::{ReferenceDeployment, ReplayCx};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub(super) struct SourcePlan<'a> {
    pub pin: CampaignPin,
    pub root: &'a Path,
    pub bindings: &'a [RtspCampaignWatchBinding],
}

#[derive(Clone, Copy)]
pub(super) struct SourceLimits {
    pub history: CampaignHistoryLimits,
    pub publication: LocalPublicationLimits,
}

#[derive(Clone, Copy)]
pub(super) struct Stages {
    pub preflight: &'static str,
    pub import: &'static str,
    pub revalidate: &'static str,
}

/// Only the two native analysis owners implement this adapter. Metadata read authority alone
/// cannot reach an import: every I/O cut also rechecks the current complete operation authority.
pub(super) trait Authority: CampaignAuthority {
    fn check(&self, destination: &ReferenceDeployment, cx: &ReplayCx) -> Result<()>;
}

pub(super) fn validate_history(
    plan: SourcePlan<'_>,
    history: &VerifiedCampaignHistory,
) -> Result<()> {
    if history.pin() != plan.pin
        || Path::new(&history.plan().history_path) != plan.root
        || history.attempts().len() != plan.bindings.len()
    {
        return Err(Error::Invalid("exact history selection"));
    }
    for (recorded, binding) in history.attempts().iter().zip(plan.bindings) {
        if binding.ordinal != recorded.attempt.ordinal {
            return Err(Error::Invalid("attempt ordinal"));
        }
        let native = recorded.finish.as_ref().and_then(|f| f.native.as_ref());
        let catalogs = native
            .map(|n| n.bindings.catalogs.as_slice())
            .unwrap_or(&[]);
        let Some(selection) = &binding.selection else {
            if !catalogs.is_empty() {
                return Err(Error::Invalid("omitted recorded catalogs"));
            }
            continue;
        };
        if catalogs.is_empty() || selection.capture_origin().is_none() {
            return Err(Error::Invalid(
                "unobserved catalog or missing capture assumption",
            ));
        }
        selection.digest()?;
        let scope = match selection {
            RtspWatchSelection::Catalog(request) => {
                if catalogs.len() != 1
                    || catalogs[0].slot != request.slot.as_str()
                    || catalogs[0].root != request.root
                {
                    return Err(Error::Invalid("exact catalog inventory"));
                }
                &request.scope
            }
            RtspWatchSelection::Pages(request) => {
                if catalogs.len() != request.pages.len()
                    || catalogs
                        .iter()
                        .zip(&request.pages)
                        .any(|(saved, supplied)| {
                            saved.slot != supplied.slot.as_str() || saved.root != supplied.root
                        })
                {
                    return Err(Error::Invalid("exact ordered catalog inventory"));
                }
                &request.scope
            }
            RtspWatchSelection::Window(_) => {
                return Err(Error::Invalid("complete catalog selection required"));
            }
        };
        let namespace = match selection.codec() {
            RtspImportCodec::Avc => ArchiveNamespace::new(scope.clone()).map(|n| n.digest()),
            RtspImportCodec::Hevc => HevcArchiveNamespace::new(scope.clone()).map(|n| n.digest()),
        }
        .map_err(|_| Error::Invalid("native archive namespace"))?;
        let attempt = &recorded.attempt;
        if namespace != attempt.archive_namespace
            || scope.recording.generation != attempt.generation
            || scope.recording.receive_clock != attempt.receive_clock
            || scope.decode_clock != attempt.decode_clock
        {
            return Err(Error::Invalid(
                "archived codec, sensor, authority or clock namespace",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_destination(
    plan: SourcePlan<'_>,
    history: &VerifiedCampaignHistory,
    destination: &Path,
) -> Result<()> {
    validate_history(plan, history)?;
    if !destination.is_absolute()
        || destination.parent().is_none()
        || !destination.components().all(|part| {
            matches!(
                part,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        })
    {
        return Err(Error::Invalid(
            "absolute normalized destination owner required",
        ));
    }
    let overlaps = |path: &Path| destination.starts_with(path) || path.starts_with(destination);
    if overlaps(plan.root)
        || history.plan().attempts.iter().any(|a| {
            overlaps(Path::new(&a.archive_path))
                || overlaps(Path::new(&a.pins_path))
                || a.source
                    .as_ref()
                    .is_some_and(|s| overlaps(Path::new(&s.path)))
        })
    {
        return Err(Error::Invalid(
            "distinct history, source and destination owners required",
        ));
    }
    Ok(())
}

struct HistoryAccess<'a> {
    authority: &'a dyn Authority,
    plan: SourcePlan<'a>,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
}
impl CampaignAuthority for HistoryAccess<'_> {
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool {
        operation == CampaignOperation::Read
            && self.authority.check(self.destination, self.cx).is_ok()
            && self.authority.permit(operation, plan)
    }
    fn permit_read(&self, pin: CampaignPin, root: &Path, principal: &str) -> bool {
        pin == self.plan.pin
            && root == self.plan.root
            && self.authority.check(self.destination, self.cx).is_ok()
            && self.authority.permit_read(pin, root, principal)
    }
}

struct ImportAccess<'a> {
    authority: &'a dyn Authority,
    request: ContentDigest,
    cx: &'a ReplayCx,
}
impl RtspCatalogImportAuthority for ImportAccess<'_> {
    fn permit(
        &self,
        request: &RtspCatalogImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        request.digest().is_ok_and(|digest| digest == self.request)
            && self.authority.check(destination, self.cx).is_ok()
    }
}
impl RtspCatalogPagesImportAuthority for ImportAccess<'_> {
    fn permit(
        &self,
        request: &RtspCatalogPagesImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        request.digest().is_ok_and(|digest| digest == self.request)
            && self.authority.check(destination, self.cx).is_ok()
    }
}

fn preflight(
    archive: &LocalRootPublisher,
    destination: &ReferenceDeployment,
    selection: &RtspWatchSelection,
    access: &ImportAccess<'_>,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<CatalogPreflight> {
    match selection {
        RtspWatchSelection::Catalog(request) => Ok(preflight_rtsp_catalog(
            archive,
            destination,
            request,
            access,
            cx,
            work,
        )?),
        RtspWatchSelection::Pages(request) => Ok(preflight_rtsp_catalog_pages(
            archive,
            destination,
            request,
            access,
            cx,
            work,
        )?),
        RtspWatchSelection::Window(_) => Err(Error::Invalid("whole catalog selection required")),
    }
}

#[derive(Debug)]
pub(super) struct ImportedAttempt {
    pub recorded: CampaignAttemptHistory,
    pub selection: Option<RtspWatchSelection>,
    pub request_digest: Option<ContentDigest>,
    pub import: Option<RtspImportReceipt>,
    pub windows: usize,
    pub pages: usize,
}

/// Prepared metadata and bounded counts only. Native payload preparations are dropped during
/// preflight; each import rereads original custody and every source is checked again at release.
pub(super) struct Sources<'a> {
    plan: SourcePlan<'a>,
    limits: SourceLimits,
    stages: Stages,
    archives: &'a [Option<&'a LocalRootPublisher>],
    authority: &'a dyn Authority,
    history: VerifiedCampaignHistory,
    verified: Vec<Option<CatalogPreflight>>,
}
impl<'a> Sources<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        plan: SourcePlan<'a>,
        limits: SourceLimits,
        stages: Stages,
        archives: &'a [Option<&'a LocalRootPublisher>],
        authority: &'a dyn Authority,
        destination: &ReferenceDeployment,
        history_cx: &ReplayCx,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        if archives.len() != plan.bindings.len()
            || cx.root_dir() != destination.root()
            || history_cx.root_dir() != plan.root
            || history_cx.io_authority().principal() != cx.io_authority().principal()
        {
            return Err(Error::Invalid("source inventory or scoped owner contexts"));
        }
        authority.check(destination, cx)?;
        let access = HistoryAccess {
            authority,
            plan,
            destination,
            cx,
        };
        let history = VerifiedCampaignHistory::inspect(
            plan.root,
            plan.pin,
            limits.history,
            limits.publication,
            &access,
            history_cx,
            work,
        )?;
        validate_destination(plan, &history, destination.root())?;
        for ((recorded, binding), archive) in
            history.attempts().iter().zip(plan.bindings).zip(archives)
        {
            match (&binding.selection, archive) {
                (Some(_), Some(owner))
                    if owner.root_dir() == Path::new(&recorded.attempt.archive_path) => {}
                (None, None) => {}
                _ => return Err(Error::Invalid("exact per-attempt source owner")),
            }
        }
        let mut verified = Vec::with_capacity(plan.bindings.len());
        for ((recorded, binding), archive) in
            history.attempts().iter().zip(plan.bindings).zip(archives)
        {
            cx.checkpoint(stages.preflight).map_err(|_| Error::Denied)?;
            authority.check(destination, cx)?;
            let summary = if let (Some(selection), Some(owner)) = (&binding.selection, archive) {
                let access = ImportAccess {
                    authority,
                    request: selection.digest()?,
                    cx,
                };
                let summary = preflight(owner, destination, selection, &access, cx, work)?;
                let native = recorded
                    .finish
                    .as_ref()
                    .and_then(|f| f.native.as_ref())
                    .ok_or(Error::Invalid("native observation unavailable"))?;
                if summary.frames as u64 > native.durable_pictures {
                    return Err(Error::Invalid(
                        "verified catalog exceeds recorded durable picture count",
                    ));
                }
                Some(summary)
            } else {
                None
            };
            verified.push(summary);
        }
        Ok(Self {
            plan,
            limits,
            stages,
            archives,
            authority,
            history,
            verified,
        })
    }

    pub fn frame_counts(&self) -> Vec<usize> {
        self.verified
            .iter()
            .map(|summary| summary.as_ref().map_or(0, |s| s.frames))
            .collect()
    }

    pub fn import_all(
        &self,
        destination: &mut ReferenceDeployment,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<ImportedAttempt>> {
        let mut attempts = Vec::with_capacity(self.plan.bindings.len());
        for (((recorded, binding), archive), summary) in self
            .history
            .attempts()
            .iter()
            .zip(self.plan.bindings)
            .zip(self.archives)
            .zip(&self.verified)
        {
            cx.checkpoint(self.stages.import)
                .map_err(|_| Error::Denied)?;
            self.authority.check(destination, cx)?;
            let mut row = ImportedAttempt {
                recorded: recorded.clone(),
                selection: binding.selection.clone(),
                request_digest: None,
                import: None,
                windows: 0,
                pages: 0,
            };
            if let (Some(selection), Some(owner), Some(summary)) =
                (&binding.selection, archive, summary)
            {
                let request = selection.digest()?;
                let access = ImportAccess {
                    authority: self.authority,
                    request,
                    cx,
                };
                let (import, windows, pages) = match selection {
                    RtspWatchSelection::Catalog(request) => {
                        let receipt =
                            import_rtsp_catalog(owner, destination, request, &access, cx, work)?;
                        (receipt.import, receipt.windows, 1)
                    }
                    RtspWatchSelection::Pages(request) => {
                        let receipt = import_rtsp_catalog_pages(
                            owner,
                            destination,
                            request,
                            &access,
                            cx,
                            work,
                        )?;
                        (
                            receipt.catalog.import,
                            receipt.catalog.windows,
                            receipt.pages,
                        )
                    }
                    RtspWatchSelection::Window(_) => {
                        return Err(Error::Invalid("whole catalog selection required"));
                    }
                };
                if import.frames != summary.frames
                    || windows != summary.windows
                    || pages != summary.pages
                {
                    return Err(Error::Invalid("native import differs from exact preflight"));
                }
                row.request_digest = Some(request);
                row.import = Some(import);
                row.windows = windows;
                row.pages = pages;
            }
            attempts.push(row);
        }
        Ok(attempts)
    }

    pub fn revalidate(
        &self,
        destination: &ReferenceDeployment,
        history_cx: &ReplayCx,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<VerifiedCampaignHistory> {
        cx.checkpoint(self.stages.revalidate)
            .map_err(|_| Error::Denied)?;
        for ((binding, archive), expected) in self
            .plan
            .bindings
            .iter()
            .zip(self.archives)
            .zip(&self.verified)
        {
            self.authority.check(destination, cx)?;
            if let (Some(selection), Some(owner), Some(expected)) =
                (&binding.selection, archive, expected)
            {
                let access = ImportAccess {
                    authority: self.authority,
                    request: selection.digest()?,
                    cx,
                };
                if preflight(owner, destination, selection, &access, cx, work)? != *expected {
                    return Err(Error::Invalid("final original inventory differs"));
                }
            }
        }
        let access = HistoryAccess {
            authority: self.authority,
            plan: self.plan,
            destination,
            cx,
        };
        let history = VerifiedCampaignHistory::inspect(
            self.plan.root,
            self.plan.pin,
            self.limits.history,
            self.limits.publication,
            &access,
            history_cx,
            work,
        )?;
        validate_history(self.plan, &history)?;
        Ok(history)
    }
}
