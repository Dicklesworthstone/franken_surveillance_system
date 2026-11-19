#![forbid(unsafe_code)]
//! Shared whole-recording preparation and rendering for immutable and publishing owners.

use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::historical_health::{
    HistoricalHealthDiagnostic, HistoricalHealthRetention,
};

use super::*;

/// Each temporal analysis keeps its own exact fusion-profile scope and native bounds.
#[derive(Clone, Copy)]
pub(super) enum Scope {
    Watch,
    Dwell,
}

/// Pinned external inputs remain owned until native analysis and rendering finish.
pub(super) struct Inputs {
    profile: Option<EventFusionProfile>,
    package: Option<(RgbDetectorPackage, Vec<u8>)>,
}

impl Inputs {
    pub(super) fn load(
        action: &WatchAction,
        scope: Scope,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> RunResult<Self> {
        if action.incremental.is_some() || action.retain_coverage.is_some() {
            return Err(WatchError::InvalidPlan("whole-recording analysis has no checkpoint or coverage owner").into());
        }
        match scope {
            Scope::Watch if action.dwell.is_some() || action.stream_dwell.is_some() => {
                return Err(WatchError::InvalidPlan("streaming watch has no dwell owner").into());
            }
            Scope::Dwell if action.dwell.is_none() || action.stream_watch.is_some() => {
                return Err(WatchError::InvalidPlan("streaming dwell requires only a dwell rule").into());
            }
            _ => {}
        }
        let profile = super::super::detector::load_fusion(action.cascade.as_ref(), cx)?;
        if profile.as_ref().is_some_and(|profile| match scope {
            Scope::Watch => profile.long_watch_analysis_root().is_none(),
            Scope::Dwell => profile.long_dwell_analysis_root().is_none(),
        }) {
            return Err(EventFusionError::Scope.into());
        }
        // Keep the verified archive alive for cold replay through the ordinary publication path.
        let package = action
            .cascade
            .as_ref()
            .map(|options| super::super::detector::load_with_archive(options, cx, scalar))
            .transpose()?;
        Ok(Self { profile, package })
    }

    fn detector<'a>(
        &'a self,
        action: &WatchAction,
        scalar: &'a ScalarExecCx,
    ) -> RunResult<Option<LongWatchDetector<'a>>> {
        match (&action.cascade, &self.package) {
            (Some(options), Some((package, archive))) => Ok(Some(LongWatchDetector::new(
                package,
                archive,
                options.config,
                PackageDetectLimits::default(),
                scalar,
            )?)),
            (None, None) => Ok(None),
            _ => Err(WatchError::Conflict.into()),
        }
    }

    pub(super) fn watch(
        &self,
        action: &WatchAction,
        deployment: &dyn RetainedSource,
        limits: &LongWatchLimits,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> RunResult<(LongWatchReport, Option<EventFusionReport>)> {
        let detector = self.detector(action, scalar)?;
        let plan = plan(action, deployment, limits.decode.read_limits, Scope::Watch, cx)?;
        let report = match &detector {
            Some(detector) => LongWatchReport::analyze_with_detector(
                deployment, &plan, action.options, limits, detector, action.health_screen, cx,
            )?,
            None if action.health_screen => {
                LongWatchReport::analyze_screened(deployment, &plan, action.options, limits, cx)?
            }
            None => LongWatchReport::analyze(deployment, &plan, action.options, limits, cx)?,
        };
        let fusion = match (&self.profile, &self.package) {
            (Some(profile), Some((package, _))) => Some(EventFusionReport::long_watch(
                &report, package, profile, deployment, cx,
            )?),
            (None, _) => None,
            _ => return Err(EventFusionError::Scope.into()),
        };
        // Keep the native preflight before any publication or output.
        if fusion.is_some() {
            render_watch(
                action, &report, deployment.current_anchor().commit_sequence, None, fusion.as_ref(),
            )?;
        }
        let sequence = if report.health_diagnostic().is_some() {
            u64::MAX
        } else {
            deployment.current_anchor().commit_sequence
        };
        super::super::health::preflight_watch_diagnostic(
            report.to_json(sequence, Some(&action.rerun))?,
            report.health_diagnostic(),
            deployment.current_anchor(),
            &action.rerun,
        )?;
        Ok((report, fusion))
    }

    pub(super) fn dwell(
        &self,
        action: &WatchAction,
        deployment: &dyn RetainedSource,
        limits: &LongDwellLimits,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> RunResult<(LongDwellReport, Option<EventFusionReport>)> {
        let detector = self.detector(action, scalar)?;
        let rule = action.dwell.ok_or(WatchError::InvalidPlan("streaming dwell requires a rule"))?;
        let plan = plan(action, deployment, limits.decode.read_limits, Scope::Dwell, cx)?;
        let report = match &detector {
            Some(detector) => LongDwellReport::analyze_with_detector(
                deployment, &plan, rule, action.options, limits, detector, action.health_screen, cx,
            )?,
            None if action.health_screen => {
                LongDwellReport::analyze_screened(deployment, &plan, rule, action.options, limits, cx)?
            }
            None => LongDwellReport::analyze(deployment, &plan, rule, action.options, limits, cx)?,
        };
        let fusion = match (&self.profile, &self.package) {
            (Some(profile), Some((package, _))) => Some(EventFusionReport::long_dwell(
                &report, package, profile, deployment, cx,
            )?),
            (None, _) => None,
            _ => return Err(EventFusionError::Scope.into()),
        };
        let sequence = if report.health_diagnostic().is_some() {
            u64::MAX
        } else {
            deployment.current_anchor().commit_sequence
        };
        super::super::health::preflight_watch_diagnostic(
            report.to_json(sequence, Some(&action.rerun))?,
            report.health_diagnostic(),
            deployment.current_anchor(),
            &action.rerun,
        )?;
        Ok((report, fusion))
    }
}

fn plan(
    action: &WatchAction,
    deployment: &dyn RetainedSource,
    limits: RetainedReadLimits,
    scope: Scope,
    cx: &ReplayCx,
) -> RunResult<WatchPlan> {
    let (maximum, message) = match scope {
        Scope::Watch => (
            MAX_LONG_WATCH_FRAMES,
            "select a nonempty streaming watch range of at most 65536 segments",
        ),
        Scope::Dwell => (
            MAX_LONG_DWELL_FRAMES,
            "select a nonempty long-dwell range of at most 65536 segments",
        ),
    };
    let segment_count = match action.segment_count {
        Some(count) => count,
        None => {
            let retained = RetainedFileImport::open(deployment, action.import, limits, cx)
                .map_err(WatchError::from)?;
            retained
                .manifest()
                .segment_spans
                .len()
                .checked_sub(action.first_segment)
                .filter(|count| (1..=maximum).contains(count))
                .ok_or(WatchError::InvalidPlan(message))?
        }
    };
    Ok(WatchPlan {
        import_identity: action.import,
        interpretation: action.interpretation,
        first_segment: action.first_segment,
        segment_count,
        zones: action.zones.clone(),
        detector: action.detector,
        tracker: action.tracker,
    })
}

pub(super) fn render_watch(
    action: &WatchAction,
    report: &LongWatchReport,
    sequence: u64,
    retention: Option<&HistoricalHealthRetention>,
    fusion: Option<&EventFusionReport>,
) -> RunResult<String> {
    render(
        action,
        report.to_json(sequence, Some(&action.rerun))?,
        report.health_diagnostic(),
        retention,
        fusion,
    )
}

pub(super) fn render_dwell(
    action: &WatchAction,
    report: &LongDwellReport,
    sequence: u64,
    retention: Option<&HistoricalHealthRetention>,
    fusion: Option<&EventFusionReport>,
) -> RunResult<String> {
    render(
        action,
        report.to_json(sequence, Some(&action.rerun))?,
        report.health_diagnostic(),
        retention,
        fusion,
    )
}

fn render(
    action: &WatchAction,
    native: String,
    diagnostic: Option<&HistoricalHealthDiagnostic>,
    retention: Option<&HistoricalHealthRetention>,
    fusion: Option<&EventFusionReport>,
) -> RunResult<String> {
    let native = super::super::health::with_watch_diagnostic(
        native, diagnostic, retention, &action.rerun,
    )?;
    Ok(super::super::detector::with_fusion(native, fusion)?)
}
