#![forbid(unsafe_code)]
//! Cross-session checks of a frozen finite clock inventory and conservative time projection.
//!
//! New sessions never adjust the offset/rate inventory, fit policy or earlier fits.
//! Disjoint local-time windows and unchanged camera models are required. This is
//! membership separation, NOT proof of statistically independent errors or source
//! authenticity. Every session fits its own nominal feature trajectory. A passing
//! result remains conditional on those trajectories, cameras and associations.

use super::{ClockDriftError, ClockDriftScan, ClockRateHypothesis, scan_clock_drift};
use super::super::{ClockAlignmentPair, MAX_CLOCK_OFFSET_HYPOTHESES, validate_membership};
use crate::temporal_triangulation::{MAX_TEMPORAL_VIEWS, TemporalTriangulationOptions, TimedCalibratedView};
use crate::temporal_validation::IntervalCalibratedView;
use crate::{GeometryError, WorkBudget};

/// Maximum additional capture sessions, excluding the original search session.
pub const MAX_CLOCK_VALIDATION_SESSIONS: usize = 8;
/// Maximum complete target-clock intervals projected by one invocation.
pub const MAX_CLOCK_INTERVAL_PROJECTIONS: usize = 128;

/// A separate feature passage under the SAME camera modes and clock generations.
#[derive(Clone, Copy, Debug)]
pub struct ClockValidationSession<'a> {
    /// Nonzero caller identity, unique among the held-out sessions.
    pub id: u64,
    /// Nominal local capture times used only to fit this session's trajectory.
    pub training: &'a [TimedCalibratedView],
    /// Separate observations checking that trajectory over whole local intervals.
    pub validation: &'a [IntervalCalibratedView],
}

/// One target interval to project without selecting a favorable clock candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockProjectionRequest {
    /// Nonzero caller identity, unique within this projection inventory.
    pub id: u64,
    /// Complete inclusive interval on the target clock; never packet arrival time.
    pub target_interval_ns: [i128; 2],
}

/// One complete held-out session, including unresolved/contradicted trial results.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockSessionValidation {
    /// Original caller identity; results are sorted by this identity, not score.
    pub id: u64,
    /// Fresh trajectories checked against the unchanged complete hypothesis set.
    pub scan: ClockDriftScan,
}

/// Conditional support only; a false value does not prove a clock impossible.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockHypothesisSupport {
    /// Exact unchanged offset/rate candidate.
    pub hypothesis: ClockRateHypothesis,
    /// All original search validation intervals satisfy the conditional model gate.
    pub search_supported: bool,
    /// Every additional session's support, in canonical session-ID order.
    pub sessions: Vec<(u64, bool)>,
}
impl ClockHypothesisSupport {
    /// Search and every additional session pass; never grants clock/coverage authority.
    pub fn supported_in_every_session(&self) -> bool {
        self.search_supported && !self.sessions.is_empty() && self.sessions.iter().all(|row| row.1)
    }
}

/// Every candidate's exact outward-rounded mapping and their conservative hull.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockIntervalProjection {
    /// Unchanged requested interval and identity.
    pub request: ClockProjectionRequest,
    /// Complete original inventory, including unsupported and unresolved candidates.
    pub mappings: Vec<(ClockRateHypothesis, [i128; 2])>,
    /// Sessions whose target observation window contains the whole request. Zero
    /// names the original search; an empty list exposes algebraic extrapolation.
    /// Membership here is NOT proof of coverage or physical clock validity.
    pub containing_session_ids: Vec<u64>,
    /// Earliest lower and latest upper across ALL declared candidates. This is not
    /// a confidence interval, continuous-parameter bound or accepted clock mapping.
    pub reference_envelope_ns: [i128; 2],
}

/// Fully evaluated search, separated sessions, and unpruned time projections.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockValidationReport {
    /// Original search run, not refitted with any additional session's observations.
    pub search: ClockDriftScan,
    /// Every requested additional session, sorted by nonzero ID.
    pub sessions: Vec<ClockSessionValidation>,
    /// Complete original hypothesis inventory and per-session conditional support.
    pub support: Vec<ClockHypothesisSupport>,
    /// Complete projection inventory, sorted by ID; no candidate is silently removed.
    pub projections: Vec<ClockIntervalProjection>,
    /// Admission, every search/validation fit and every projection use one budget.
    pub work_units: u64,
}

/// A structural/resource failure returns no successful prefix or narrowed mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockValidationError {
    /// Allocation, work or cancellation refused.
    Geometry(GeometryError),
    /// Existing camera/clock, hypothesis, mapping or native policy admission refused.
    Drift(ClockDriftError),
    /// Missing sessions or zero/duplicate IDs.
    InvalidSession,
    /// Search and held-out sessions must occupy disjoint windows on BOTH cameras.
    OverlappingSessions,
    /// Session order differs between cameras under an allegedly unchanged clock generation.
    ClockOrderChanged,
    /// A camera's pose or image mode changed between sessions.
    CameraChanged,
    /// A projection has a zero/duplicate identity or reversed interval.
    InvalidProjection,
}
impl From<GeometryError> for ClockValidationError {
    fn from(error: GeometryError) -> Self { Self::Geometry(error) }
}
impl From<ClockDriftError> for ClockValidationError {
    fn from(error: ClockDriftError) -> Self { Self::Drift(error) }
}
impl std::fmt::Display for ClockValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Geometry(_) => "clock validation work or allocation refused",
            Self::Drift(_) => "clock validation native admission refused",
            Self::InvalidSession => "clock validation requires distinct nonzero sessions",
            Self::OverlappingSessions => "clock validation sessions overlap",
            Self::ClockOrderChanged => "clock validation session order changed between cameras",
            Self::CameraChanged => "clock validation camera or image mode changed",
            Self::InvalidProjection => "invalid clock interval projection inventory",
        })
    }
}
impl std::error::Error for ClockValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Geometry(e) => Some(e), Self::Drift(e) => Some(e), _ => None }
    }
}

/// Evaluate additional, non-overlapping feature passages WITHOUT retuning clocks.
///
/// All cameras/clock generations, hypothesis parameters and fit gates remain fixed.
/// Original search failures are retained, not removed before validation. Time
/// envelopes include ALL supplied hypotheses even when only one is supported.
/// This intentionally prevents validation from silently narrowing operational time.
///
/// S <= 8, K <= 64, N,H <= 128 per session, P <= 128. Admission costs
/// O(S*(N+H)^2 + S^2); fitting is S+1 bounded native scans; projection is O(P*K).
/// Scratch/results are bounded by those complete inventories. One caller budget
/// spans every phase. Any resource/cancellation refusal discards the whole result.
#[allow(clippy::too_many_arguments)]
pub fn validate_clock_sessions(
    pair: ClockAlignmentPair,
    target_anchor_ns: i128,
    search_training: &[TimedCalibratedView],
    search_validation: &[IntervalCalibratedView],
    sessions: &[ClockValidationSession<'_>],
    hypotheses: &[ClockRateHypothesis],
    requests: &[ClockProjectionRequest],
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<ClockValidationReport, ClockValidationError> {
    budget.charge(0)?;
    let started = budget.used();
    if sessions.len() > MAX_CLOCK_VALIDATION_SESSIONS || hypotheses.len() > MAX_CLOCK_OFFSET_HYPOTHESES
        || requests.len() > MAX_CLOCK_INTERVAL_PROJECTIONS
        || search_training.len() > MAX_TEMPORAL_VIEWS || search_validation.len() > MAX_TEMPORAL_VIEWS
        || sessions.iter().any(|s| s.training.len() > MAX_TEMPORAL_VIEWS || s.validation.len() > MAX_TEMPORAL_VIEWS)
    { return Err(GeometryError::LimitExceeded.into()); }
    if pair.reference_camera == 0 || pair.target_camera == 0 || pair.reference_camera == pair.target_camera
        || pair.reference_clock == 0 || pair.target_clock == 0 || pair.reference_clock == pair.target_clock
    { return Err(ClockDriftError::Alignment(super::super::ClockAlignmentError::InvalidPair).into()); }
    if sessions.is_empty() { return Err(ClockValidationError::InvalidSession); }
    if hypotheses.is_empty() { return Err(ClockDriftError::InvalidHypotheses.into()); }
    budget.charge(256 * (sessions.len() + requests.len() + hypotheses.len()) as u64)?;
    let mut ordered = copy(sessions)?;
    ordered.sort_by_key(|s| s.id);
    if ordered.iter().any(|s| s.id == 0) || ordered.windows(2).any(|s| s[0].id == s[1].id) {
        return Err(ClockValidationError::InvalidSession);
    }
    let search_session = ClockValidationSession { id: 0, training: search_training, validation: search_validation };
    validate_membership(pair, search_training, search_validation, budget).map_err(ClockDriftError::from)?;
    let cameras = [pair.reference_camera, pair.target_camera].map(|id| {
        search_training.iter().find(|row| row.view.camera == id).map(|row| row.view)
    });
    let mut windows = Vec::new();
    windows.try_reserve_exact(sessions.len() + 1).map_err(|_| GeometryError::LimitExceeded)?;
    for session in std::iter::once(&search_session).chain(ordered.iter()) {
        validate_membership(pair, session.training, session.validation, budget)
            .map_err(ClockDriftError::from)?;
        windows.push(session_windows(pair, *session));
        for view in session.training.iter().map(|r| r.view).chain(session.validation.iter().map(|r| r.view)) {
            budget.charge(32)?;
            let expected = cameras[usize::from(view.camera == pair.target_camera)]
                .ok_or(ClockValidationError::CameraChanged)?;
            if expected.pose != view.pose || expected.intrinsics != view.intrinsics {
                return Err(ClockValidationError::CameraChanged);
            }
        }
    }
    for (index, current) in windows.iter().enumerate() {
        for prior in &windows[..index] {
            budget.charge(8)?;
            let mut before = [false; 2];
            for camera in 0..2 {
                if prior[camera][0] <= current[camera][1] && current[camera][0] <= prior[camera][1] {
                    return Err(ClockValidationError::OverlappingSessions);
                }
                before[camera] = prior[camera][1] < current[camera][0];
            }
            if before[0] != before[1] { return Err(ClockValidationError::ClockOrderChanged); }
        }
    }
    let mut candidates = copy(hypotheses)?;
    candidates.sort_unstable();
    if candidates.windows(2).any(|p| p[0] == p[1]) {
        return Err(ClockDriftError::InvalidHypotheses.into());
    }
    // Preflight the COMPLETE output mapping before any expensive fit. The same
    // frozen inventory later enters every scan; no derived score changes this set.
    let mut requests = copy(requests)?;
    requests.sort_by_key(|r| r.id);
    if requests.iter().any(|r| r.id == 0 || r.target_interval_ns[0] > r.target_interval_ns[1])
        || requests.windows(2).any(|p| p[0].id == p[1].id)
    { return Err(ClockValidationError::InvalidProjection); }
    let mut projections = Vec::new();
    projections.try_reserve_exact(requests.len()).map_err(|_| GeometryError::LimitExceeded)?;
    for request in requests {
        budget.charge(64 * candidates.len() as u64)?;
        let mut mappings = Vec::new();
        mappings.try_reserve_exact(candidates.len()).map_err(|_| GeometryError::LimitExceeded)?;
        let mut envelope = [i128::MAX, i128::MIN];
        for hypothesis in &candidates {
            let interval = hypothesis.map_interval(target_anchor_ns, request.target_interval_ns)?;
            envelope[0] = envelope[0].min(interval[0]);
            envelope[1] = envelope[1].max(interval[1]);
            mappings.push((*hypothesis, interval));
        }
        budget.charge(16 * windows.len() as u64)?;
        let mut containing_session_ids = Vec::new();
        containing_session_ids.try_reserve_exact(windows.len()).map_err(|_| GeometryError::LimitExceeded)?;
        for (window, id) in windows.iter().zip(std::iter::once(0).chain(ordered.iter().map(|s| s.id))) {
            if window[1][0] <= request.target_interval_ns[0] && request.target_interval_ns[1] <= window[1][1] {
                containing_session_ids.push(id);
            }
        }
        projections.push(ClockIntervalProjection { request, mappings, containing_session_ids, reference_envelope_ns: envelope });
    }
    let search = scan_clock_drift(pair, target_anchor_ns, search_training, search_validation,
        &candidates, options, budget)?;
    let mut evaluated = Vec::new();
    evaluated.try_reserve_exact(ordered.len()).map_err(|_| GeometryError::LimitExceeded)?;
    for session in ordered {
        let scan = scan_clock_drift(pair, target_anchor_ns, session.training, session.validation,
            &candidates, options, budget)?;
        evaluated.push(ClockSessionValidation { id: session.id, scan });
    }
    let mut support = Vec::new();
    support.try_reserve_exact(candidates.len()).map_err(|_| GeometryError::LimitExceeded)?;
    for (index, trial) in search.trials.iter().enumerate() {
        budget.charge(16 * (evaluated.len() + 1) as u64)?;
        let mut sessions = Vec::new();
        sessions.try_reserve_exact(evaluated.len()).map_err(|_| GeometryError::LimitExceeded)?;
        for session in &evaluated {
            sessions.push((session.id, session.scan.trials[index].consistent_for_all_capture_times()));
        }
        support.push(ClockHypothesisSupport { hypothesis: trial.hypothesis,
            search_supported: trial.consistent_for_all_capture_times(), sessions });
    }
    budget.charge(0)?;
    Ok(ClockValidationReport { search, sessions: evaluated, support, projections, work_units: budget.used() - started })
}

fn copy<T: Copy>(values: &[T]) -> Result<Vec<T>, GeometryError> {
    let mut result = Vec::new();
    result.try_reserve_exact(values.len()).map_err(|_| GeometryError::LimitExceeded)?;
    result.extend_from_slice(values);
    Ok(result)
}

// Admission has already checked camera membership, nonempty counts and intervals.
fn session_windows(pair: ClockAlignmentPair, session: ClockValidationSession<'_>) -> [[i128; 2]; 2] {
    let mut windows = [[i128::MAX, i128::MIN]; 2];
    for (camera, interval) in session.training.iter().map(|r| (r.view.camera, [r.capture_time_ns; 2]))
        .chain(session.validation.iter().map(|r| (r.view.camera, r.capture_interval_ns)))
    {
        let index = usize::from(camera == pair.target_camera);
        windows[index][0] = windows[index][0].min(interval[0]);
        windows[index][1] = windows[index][1].max(interval[1]);
    }
    windows
}
