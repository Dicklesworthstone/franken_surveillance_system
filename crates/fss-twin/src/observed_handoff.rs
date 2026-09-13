#![forbid(unsafe_code)]
//! Source-track -> support routes -> motion -> camera-observation composition.

use fss_geometry::{BodySamples, CameraAvailability, CameraHandoffForecast, ForecastBasis,
    GeometryError, HandoffCamera, HandoffOptions, MotionForecast, NanosecondInterval,
    RouteBody, RouteCandidate, RouteEnd, RoutePriors, RouteSurface, WorkBudget,
    forecast_routes, predict_camera_handoffs};
use crate::{ContactObservation, MovementClass, NavigationError, NavigationProfile,
    PropagatedPosition, PropertyTwin, RouteOutcome, RouteQuery, RouteSearch,
    SupportLocation, SupportNetwork, TwinError, propagate_motion};
use crate::stream::{TrackReceipt, TrackSnapshot};

/// One explicit destination/class/posture hypothesis, not an inferred intention.
#[derive(Clone, Copy, Debug)]
pub struct DestinationHypothesis<'a> {
    /// Feature ordinal in the exact imported twin.
    pub feature: u32,
    /// Supplied slope/portal assumptions and class-specific path preference.
    pub profile: NavigationProfile,
    /// Explicit posture samples; no default human body for animal hypotheses.
    pub body: &'a BodySamples,
    /// Multiplier of measured average speed, in (0,16]; not a metric speed prior.
    pub speed_multiplier: f64,
    /// Initial pause for moving alternatives; an additional full-stop branch is retained.
    pub initial_pause_ns: u64,
    /// What to assume after reaching the destination.
    pub end: RouteEnd,
}

/// Explicit forecast bounds. No confidence or field accuracy is implied.
#[derive(Clone, Copy, Debug)]
pub struct ObservedForecastOptions {
    /// Horizon from the nominal midpoint of the latest capture interval.
    pub horizon_ns: u64,
    /// Nonzero owner-resolved generation binding ALL destination/body/motion assumptions.
    pub motion_generation: u64,
    /// Complete route assessment ceiling, 1..=64, including unresolved alternatives.
    pub max_routes: usize,
    /// Per-axis source-unit acceleration bound over observed pair and forecast.
    pub acceleration_bound: [f64; 3],
    /// Nominal sampled visibility settings, reused without weakening their limits.
    pub handoff: HandoffOptions,
}

/// Route alternatives deliberately kept distinct even when their geometry coincides.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedRouteKind {
    /// The selected class-conditioned discrete route.
    Preferred,
    /// A protected route with pedestrian cost preference removed.
    WithoutPathPreference,
    /// Explicitly assume no further motion at the latest nominal contact.
    Stop,
}

/// A source mode cannot be converted to a precise route for this reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnresolvedRoute {
    /// The uncertainty volume reaches support, but its nominal ray does not.
    NoNominalSupport,
    /// No nominal source-pair speed exists.
    NoNominalVelocity,
    /// Nominal camera-to-contact ray conflicts with the imported occluders.
    NominalOcclusionConflict,
    /// Speed is zero, too small, or outside the numerical timing range.
    UnusableSpeed,
    /// A tolerance-edge ray hit is not a closed-simplex navigation start.
    InvalidSupportSimplex,
}

/// Every requested branch receives a path or a retained explicit limitation.
#[derive(Clone, Debug, PartialEq)]
pub enum AssessedPath {
    /// Full discrete route query, including its non-route outcomes and work count.
    Navigation(RouteSearch),
    /// An explicit stopping hypothesis; not an observation that stopping happened.
    Stop([f64; 3]),
    /// Neither an invented route nor a physical-impossibility claim.
    Unresolved(UnresolvedRoute),
}

/// Coupling from source support mode to generated route and downstream camera outcomes.
#[derive(Clone, Debug, PartialEq)]
pub struct RouteAssessment {
    /// Local route handle in this exact forecast, never durable across revisions.
    pub route: u64,
    /// Source motion-mode ordinal, without dropping ambiguous support pairs.
    pub source_mode: usize,
    /// Meaning of this particular branch.
    pub kind: ObservedRouteKind,
    /// Source-pair average speed times the explicit hypothesis multiplier.
    pub nominal_speed: Option<f64>,
    /// Compatibility with the first route segment; diagnostic, not a probability.
    pub initial_direction_cosine: Option<f64>,
    /// Complete geometry query outcome or unresolved reason.
    pub path: AssessedPath,
}
impl RouteAssessment {
    fn points(&self) -> Option<&[[f64; 3]]> {
        match &self.path {
            AssessedPath::Navigation(RouteSearch { outcome: RouteOutcome::Found(path), .. }) => Some(path.points()),
            AssessedPath::Stop(point) => Some(std::slice::from_ref(point)),
            _ => None,
        }
    }
}

/// A missing nominal path is not represented as an empty successful handoff.
#[derive(Clone, Debug, PartialEq)]
pub enum ObservedPredictions {
    /// All source modes remain in assessments/envelopes, but no nominal path is usable.
    NoNominalPaths,
    /// Coupled conditional trajectories and their nominal sampled camera outcomes.
    Modeled {
        /// Every generated path, including the explicit stopping branches.
        motion: MotionForecast,
        /// Per-route camera/region/capture/availability outcomes.
        handoff: CameraHandoffForecast,
    },
}

/// One source-pinned forecast for the explicitly supplied destination hypothesis.
#[derive(Clone, Debug)]
pub struct ObservedHandoffForecast {
    /// Exact source update, track session epoch and revision.
    pub source: TrackReceipt,
    /// Original observations used for speed, not synthetic waypoints.
    pub observations: [ContactObservation; 2],
    /// Exact immutable package identity.
    pub twin_digest: [u8; 32],
    /// Original class-conditioned route assumptions.
    pub profile: NavigationProfile,
    /// Destination identity in that same twin.
    pub destination_feature: u32,
    /// Exact supplied numerical, acceleration and generation policy.
    pub options: ObservedForecastOptions,
    /// Explicit speed multiplier, not an inferred acceleration measurement.
    pub speed_multiplier: f64,
    /// Pause on moving branches, distinct from the full stopping alternative.
    pub initial_pause_ns: u64,
    /// Destination-tail assumption.
    pub destination_end: RouteEnd,
    /// Exact body/posture generation, including when no nominal paths are usable.
    pub body_generation: u64,
    /// Complete assessments, including paths that could not be modeled.
    pub routes: Vec<RouteAssessment>,
    /// Separate conditional acceleration enclosures over each returned capture interval.
    /// They include all source modes, are not obstacle-clipped, and may be unknown.
    pub reachable: Vec<PropagatedPosition>,
    /// Requested assessments with no usable nominal path; never renormalize them away.
    pub unmodeled_routes: usize,
    /// Nominal route predictions; neither probability calibration nor exhaustive reachability.
    pub predictions: ObservedPredictions,
}
impl ObservedHandoffForecast {
    /// Refuse applying an owned result to a newer, rebased, or different source state.
    pub fn check_source_current(&self, snapshot: TrackSnapshot<'_>) -> Result<(), ObservedForecastError> {
        if snapshot.receipt() != self.source || snapshot.projection().twin_digest() != self.twin_digest {
            return Err(ObservedForecastError::Basis);
        }
        Ok(())
    }
}

/// No branch is silently pruned to recover from a computation or resource error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedForecastError {
    /// Wrong frozen property, network, camera or source state.
    Basis,
    /// Latest source update has not established usable pair motion.
    MotionUnavailable,
    /// Invalid complete-output limit, horizon or hypothesis parameter.
    Options,
    /// Source/geometry/budget/cancellation failure.
    Twin(TwinError),
    /// Native route computation failed rather than producing a modeled non-route.
    Navigation(NavigationError),
}
impl From<TwinError> for ObservedForecastError {
    fn from(error: TwinError) -> Self { Self::Twin(error) }
}
impl From<GeometryError> for ObservedForecastError {
    fn from(error: GeometryError) -> Self { Self::Twin(error.into()) }
}
impl From<NavigationError> for ObservedForecastError {
    fn from(error: NavigationError) -> Self { Self::Navigation(error) }
}
impl std::fmt::Display for ObservedForecastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Basis => "observed forecast basis mismatch",
            Self::MotionUnavailable => "observed motion is unavailable",
            Self::Options => "invalid observed forecast options",
            Self::Twin(_) => "observed forecast computation failed",
            Self::Navigation(_) => "observed forecast route computation failed",
        })
    }
}
impl std::error::Error for ObservedForecastError {}

/// Derive routes and camera handoffs from actual accepted source observations.
///
/// The caller supplies a destination/class hypothesis, not route waypoints or speed.
/// All support modes retain preferred and stopping branches. A pedestrian preference
/// additionally causes an explicitly protected neutral-cost route to be evaluated.
/// Finite route choices are not a complete reachable set; source uncertainty and
/// acceleration enclosures remain separate from nominal sampled camera predictions.
pub fn forecast_to_feature(twin: &PropertyTwin, network: &SupportNetwork,
    snapshot: TrackSnapshot<'_>, destination: DestinationHypothesis<'_>,
    cameras: &[HandoffCamera<'_>], options: ObservedForecastOptions, budget: &mut WorkBudget<'_>)
    -> Result<ObservedHandoffForecast, ObservedForecastError> {
    budget.charge(0)?;
    let motion = snapshot.motion().ok_or(ObservedForecastError::MotionUnavailable)?;
    if motion.geometry() != twin.basis() || motion.twin_digest() != twin.digest()
        || network.basis() != twin.basis() || network.twin_digest() != twin.digest() {
        return Err(ObservedForecastError::Basis);
    }
    let observation = snapshot.projection().observation();
    let reference = observation.capture[0] + (observation.capture[1] - observation.capture[0]) / 2;
    let end = reference.checked_add(options.horizon_ns).ok_or(ObservedForecastError::Options)?;
    if options.horizon_ns == 0 || options.horizon_ns > 3_600_000_000_000
        || end < observation.capture[1] || end - observation.capture[0] > 3_600_000_000_000
        || options.motion_generation == 0 || !(1..=64).contains(&options.max_routes)
        || destination.feature as usize >= twin.features().len()
        || !destination.speed_multiplier.is_finite() || destination.speed_multiplier <= 0.0
        || destination.speed_multiplier > 16.0 || destination.initial_pause_ns > options.horizon_ns
        || cameras.is_empty() || cameras.len() > 64
        || options.handoff.max_samples_per_camera == 0 || options.handoff.max_samples_per_camera > 1_000_000
        || !options.handoff.endpoint_margin.is_finite()
        || !(0.0..=1e6).contains(&options.handoff.endpoint_margin) {
        return Err(ObservedForecastError::Options);
    }
    let neutral = destination.profile.person_path_multiplier() != 1;
    let count = motion.modes().len().checked_mul(if neutral { 3 } else { 2 })
        .ok_or(ObservedForecastError::Options)?;
    if count > options.max_routes { return Err(ObservedForecastError::Options); }
    let mut views = Vec::new();
    views.try_reserve_exact(cameras.len()).map_err(|_| TwinError::Limit)?;
    for (i, camera) in cameras.iter().enumerate() {
        budget.charge(64)?;
        let admitted = snapshot.cameras().iter().find(|c| c.camera == camera.id)
            .ok_or(ObservedForecastError::Basis)?;
        if camera.geometry != twin.basis() || camera.clock != admitted.clock
            || camera.image_mode != admitted.image_domain || camera.pose != admitted.pose
            || camera.intrinsics != admitted.intrinsics || camera.observation_generation == 0
            || cameras[..i].iter().any(|c| c.id == camera.id) {
            return Err(ObservedForecastError::Basis);
        }
        if camera.privacy_masks.len() > 64 || !(1..=1000).contains(&camera.visible_per_mille)
            || camera.minimum_extent_px.iter().any(|x| !x.is_finite() || *x <= 0.0 || *x > 65536.0)
            || end.checked_add(camera.latency.latest()).is_none() {
            return Err(ObservedForecastError::Options);
        }
        let mut view = *camera;
        view.already_observing |= view.id == observation.camera;
        let lo = view.valid.earliest().max(admitted.validity[0]);
        let hi = view.valid.latest().min(admitted.validity[1]);
        if lo <= hi { view.valid = NanosecondInterval::new(lo, hi)?; }
        else if view.availability == CameraAvailability::Ready { view.availability = CameraAvailability::Unknown; }
        views.push(view);
    }
    let reachable = propagate_motion(motion, [observation.capture[1], end], options.acceleration_bound, budget)?;
    let mut routes = Vec::new();
    routes.try_reserve_exact(count).map_err(|_| TwinError::Limit)?;
    for (mode_index, mode) in motion.modes().iter().enumerate() {
        budget.charge(128)?;
        let hit = snapshot.projection().hypotheses().iter()
            .find(|p| p.triangle == mode.current_triangle).and_then(|p| p.nominal);
        let speed = mode.nominal_velocity.map(|v| v[0].hypot(v[1]).hypot(v[2]) * destination.speed_multiplier);
        for kind in [ObservedRouteKind::Preferred, ObservedRouteKind::WithoutPathPreference, ObservedRouteKind::Stop] {
            if kind == ObservedRouteKind::WithoutPathPreference && !neutral { continue; }
            let unavailable = if mode.nominal_occlusion_conflict { Some(UnresolvedRoute::NominalOcclusionConflict) }
                else if hit.is_none() { Some(UnresolvedRoute::NoNominalSupport) }
                else if kind == ObservedRouteKind::Stop { None }
                else if speed.is_none() { Some(UnresolvedRoute::NoNominalVelocity) }
                else if speed.is_some_and(|s| !s.is_finite() || !(1e-9..=1e12).contains(&s)) { Some(UnresolvedRoute::UnusableSpeed) }
                else { None };
            let path = if let Some(reason) = unavailable { AssessedPath::Unresolved(reason) }
            else {
                let hit = hit.ok_or(ObservedForecastError::Basis)?;
                if kind == ObservedRouteKind::Stop { AssessedPath::Stop(hit.point) }
                else if let Ok(start) = SupportLocation::new(hit.triangle, hit.barycentric) {
                    let profile = if kind == ObservedRouteKind::WithoutPathPreference {
                        destination.profile.without_preference()
                    } else { destination.profile };
                    AssessedPath::Navigation(network.route_to_feature(RouteQuery { basis: twin.basis(),
                        twin_digest: twin.digest(), start, destination_feature: destination.feature,
                        profile, max_points: 256 }, budget)?)
                } else { AssessedPath::Unresolved(UnresolvedRoute::InvalidSupportSimplex) }
            };
            let mut record = RouteAssessment { route: routes.len() as u64 + 1, source_mode: mode_index,
                kind, nominal_speed: speed.filter(|s| s.is_finite()), initial_direction_cosine: None, path };
            if let (Some(points), Some(velocity)) = (record.points(), mode.nominal_velocity) {
                if points.len() > 1 {
                    let delta: [f64; 3] = std::array::from_fn(|i| points[1][i] - points[0][i]);
                    let length = delta[0].hypot(delta[1]).hypot(delta[2]);
                    let norm = velocity[0].hypot(velocity[1]).hypot(velocity[2]);
                    if length > 1e-12 && norm > 1e-12 {
                        record.initial_direction_cosine = Some((0..3).map(|i| delta[i]/length * velocity[i]/norm)
                            .sum::<f64>().clamp(-1.0, 1.0));
                    }
                }
            }
            routes.push(record);
        }
    }
    let mut inputs = Vec::new(); let mut bodies = Vec::new();
    inputs.try_reserve_exact(count).map_err(|_| TwinError::Limit)?;
    bodies.try_reserve_exact(count).map_err(|_| TwinError::Limit)?;
    for record in &routes {
        if let Some(points) = record.points() {
            let stopped = record.kind == ObservedRouteKind::Stop;
            let surface = match &record.path {
                AssessedPath::Navigation(RouteSearch { outcome: RouteOutcome::Found(path), .. }) if path.all_pedestrian() => RouteSurface::PedestrianPath,
                _ => RouteSurface::Other,
            };
            inputs.push(RouteCandidate { id: record.route, points,
                // A one-point Stop never travels; the timing kernel still requires positive speed.
                speed: if stopped { 1.0 } else { record.nominal_speed.ok_or(ObservedForecastError::Basis)? },
                initial_pause_ns: if stopped { 0 } else { destination.initial_pause_ns },
                end: if stopped { RouteEnd::Stop } else { destination.end }, surface, base_mass: 1,
                protected: record.kind == ObservedRouteKind::WithoutPathPreference });
            bodies.push(RouteBody { route: record.route, body: destination.body });
        }
    }
    let unmodeled_routes = count - inputs.len();
    let predictions = if inputs.is_empty() { ObservedPredictions::NoNominalPaths }
    else {
        let mut class = [0; 4];
        class[match destination.profile.class() { MovementClass::Person => 0, MovementClass::Bear => 1,
            MovementClass::OtherAnimal => 2, MovementClass::Unknown => 3 }] = 1;
        let receipt = snapshot.receipt();
        let basis = ForecastBasis::new(twin.basis(), receipt.scope.clock, receipt.scope.track,
            receipt.revision, options.motion_generation)?;
        // Path preference selected geometry already; do not count it again as probability evidence.
        let forecast = forecast_routes(basis, reference, options.horizon_ns, RoutePriors::new(class, 1)?, &inputs, budget)?;
        let handoff = predict_camera_handoffs(basis, &forecast, twin.mesh(), &views, &bodies, options.handoff, budget)?;
        ObservedPredictions::Modeled { motion: forecast, handoff }
    };
    budget.charge(0)?;
    Ok(ObservedHandoffForecast { source: snapshot.receipt(), observations: motion.observations(),
        twin_digest: twin.digest(), profile: destination.profile, destination_feature: destination.feature,
        options, speed_multiplier: destination.speed_multiplier, initial_pause_ns: destination.initial_pause_ns,
        destination_end: destination.end, body_generation: destination.body.generation(), routes, reachable, unmodeled_routes, predictions })
}
