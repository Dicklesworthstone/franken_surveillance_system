//! Bounded, conditional motion hypotheses in the imported property's coordinate frame.
//!
//! Route geometry and speed are supplied by the owning tracker/planner. This module
//! time-parameterizes those routes; it does not infer a traversable route from a
//! material name, identify an individual, or infer hostile intent. All weights are
//! explicit heuristic masses, not calibrated probabilities.

use crate::math::{add, checked, norm, scale, sub};
use crate::{GeometryBasis, GeometryError, WorkBudget};

/// Maximum forecast horizon: one hour in the owner's clock domain.
pub const MAX_FORECAST_NS: u64 = 3_600_000_000_000;
/// Hard bound on retained route alternatives. Overflow fails without pruning.
pub const MAX_MOTION_ROUTES: usize = 64;
/// Hard bound on a route's supplied waypoints.
pub const MAX_ROUTE_POINTS: usize = 256;

/// Exact owner-resolved basis of a forecast, not a capability or durable identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForecastBasis {
    geometry: GeometryBasis,
    clock: u64,
    track: u64,
    track_revision: u64,
    motion_generation: u64,
}

impl ForecastBasis {
    /// Resolve these nonzero handles from canonical identities before calling.
    pub fn new(geometry: GeometryBasis, clock: u64, track: u64, track_revision: u64,
        motion_generation: u64) -> Result<Self, GeometryError> {
        if [clock, track, track_revision, motion_generation].contains(&0) {
            return Err(GeometryError::BasisMismatch);
        }
        Ok(Self { geometry, clock, track, track_revision, motion_generation })
    }
    /// Property and immutable twin revision.
    pub fn geometry(self) -> GeometryBasis { self.geometry }
    /// Common capture-clock epoch; packet arrival clocks are not substitutes.
    pub fn clock(self) -> u64 { self.clock }
    /// Anonymous, property-local track handle.
    pub fn track(self) -> u64 { self.track }
    /// Exact track revision used as input.
    pub fn track_revision(self) -> u64 { self.track_revision }
    /// Version of the caller's route and motion assumptions.
    pub fn motion_generation(self) -> u64 { self.motion_generation }
}

/// Semantics supplied by the route owner, not inferred from rendering materials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSurface {
    /// A supported pedestrian route, such as a stone walkway.
    PedestrianPath,
    /// An admissible off-path route, including grass when actually traversable.
    OffPath,
    /// Surface preference is unknown or not represented by this narrow model.
    Other,
}

/// The behavior to assume after the last supported route waypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteEnd {
    /// Explicit stopping hypothesis, not an observation that the target stopped.
    Stop,
    /// Motion after the waypoint is unresolved; do not freeze or extrapolate it.
    Unknown,
}

/// Class mixture and deliberately narrow pedestrian-path preference.
///
/// Class masses are [person, bear, other animal, unknown]. Only the person mass
/// receives the caller-selected path multiplier. A bear/unknown hypothesis never
/// inherits it. This is an auditable reference prior, not learned behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutePriors {
    class_masses: [u32; 4],
    person_path_multiplier: u32,
}

impl RoutePriors {
    /// Each mass is at most one million; multiplier is in 1..=1024.
    pub fn new(class_masses: [u32; 4], person_path_multiplier: u32) -> Result<Self, GeometryError> {
        if class_masses == [0; 4] || class_masses.iter().any(|x| *x > 1_000_000)
            || !(1..=1024).contains(&person_path_multiplier) {
            return Err(GeometryError::OutOfRange);
        }
        Ok(Self { class_masses, person_path_multiplier })
    }
    /// Retained class masses, explicitly not calibrated probabilities.
    pub fn class_masses(self) -> [u32; 4] { self.class_masses }
    /// The only class-specific coefficient used by this reference model.
    pub fn person_path_multiplier(self) -> u32 { self.person_path_multiplier }
    fn mass(self, surface: RouteSurface, base: u32) -> Result<u64, GeometryError> {
        if base == 0 || base > 1_000_000 { return Err(GeometryError::OutOfRange); }
        let mut class_mass = 0_u64;
        for (index, mass) in self.class_masses.iter().enumerate() {
            let multiplier = if index == 0 && surface == RouteSurface::PedestrianPath {
                u64::from(self.person_path_multiplier)
            } else { 1 };
            class_mass = class_mass.checked_add(u64::from(*mass) * multiplier)
                .ok_or(GeometryError::OutOfRange)?;
        }
        class_mass.checked_mul(u64::from(base)).ok_or(GeometryError::OutOfRange)
    }
}

/// One immutable route proposal. Every point must already be in the same frame.
#[derive(Clone, Copy)]
pub struct RouteCandidate<'a> {
    /// Nonzero owner-resolved route handle; distinct even for alternate speeds.
    pub id: u64,
    /// Ordered center/contact positions. The caller declares what point is tracked.
    pub points: &'a [[f64; 3]],
    /// Speed in property units/second, never implicitly meters/second.
    pub speed: f64,
    /// Explicit initial stopping hypothesis in nanoseconds.
    pub initial_pause_ns: u64,
    /// Behavior after the final waypoint.
    pub end: RouteEnd,
    /// Independently established surface class.
    pub surface: RouteSurface,
    /// Positive heuristic route mass before class conditioning (at most one million).
    pub base_mass: u32,
    /// Keep this consequential alternative regardless of how small its mass is.
    pub protected: bool,
}

impl std::fmt::Debug for RouteCandidate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteCandidate").field("id", &self.id)
            .field("point_count", &self.points.len()).finish_non_exhaustive()
    }
}

/// One sample in the piecewise-linear conditional trajectory.
#[derive(Clone, Copy, PartialEq)]
pub struct MotionKnot {
    /// Offset from the forecast's reference capture time.
    pub offset_ns: u64,
    /// Position in the supplied property frame, not a new observation.
    pub position: [f64; 3],
}

impl std::fmt::Debug for MotionKnot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MotionKnot").field("offset_ns", &self.offset_ns).finish_non_exhaustive()
    }
}

/// Conditional path. Private storage prevents modifying validated knot ordering.
#[derive(Clone, Debug, PartialEq)]
pub struct MotionHypothesis {
    id: u64,
    mass: u64,
    protected: bool,
    surface: RouteSurface,
    knots: Vec<MotionKnot>,
}

impl MotionHypothesis {
    /// Source route handle.
    pub fn id(&self) -> u64 { self.id }
    /// Unnormalized heuristic mass, never detector confidence.
    pub fn mass(&self) -> u64 { self.mass }
    /// Whether discarding this route would lose a protected alternative.
    pub fn protected(&self) -> bool { self.protected }
    /// The supplied route's surface classification.
    pub fn surface(&self) -> RouteSurface { self.surface }
    /// Exact bounded knot sequence, including initial and terminal pauses.
    pub fn knots(&self) -> &[MotionKnot] { &self.knots }
    /// Last modeled offset. Later motion is unknown, not automatically stationary.
    pub fn modeled_until_ns(&self) -> u64 {
        self.knots.last().map_or(0, |knot| knot.offset_ns)
    }
    /// Interpolate a hypothesis; `None` means the route has no modeled future there.
    pub fn position_at(&self, offset_ns: u64, budget: &mut WorkBudget<'_>)
        -> Result<Option<[f64; 3]>, GeometryError> {
        budget.charge(10)?;
        if offset_ns > self.modeled_until_ns() { return Ok(None); }
        let index = self.knots.partition_point(|knot| knot.offset_ns < offset_ns);
        // <= 258 knots: at most nine binary-search comparisons.
        let right = self.knots.get(index).ok_or(GeometryError::OutOfRange)?;
        if right.offset_ns == offset_ns { return Ok(Some(right.position)); }
        let left = self.knots.get(index.checked_sub(1).ok_or(GeometryError::OutOfRange)?)
            .ok_or(GeometryError::OutOfRange)?;
        let fraction = (offset_ns - left.offset_ns) as f64 / (right.offset_ns - left.offset_ns) as f64;
        Ok(Some(checked(add(left.position, scale(sub(right.position, left.position), fraction)))?))
    }
}

/// All retained alternatives for one track revision. No top-k truncation occurs.
#[derive(Clone, Debug, PartialEq)]
pub struct MotionForecast {
    basis: ForecastBasis,
    reference_ns: u64,
    horizon_ns: u64,
    priors: RoutePriors,
    hypotheses: Vec<MotionHypothesis>,
    total_mass: u64,
}

impl MotionForecast {
    /// Bound property, clock, track, and motion-generation identities.
    pub fn basis(&self) -> ForecastBasis { self.basis }
    /// Nominal reference capture time in the bound clock epoch.
    pub fn reference_ns(&self) -> u64 { self.reference_ns }
    /// Requested future horizon; some explicitly unknown routes may end earlier.
    pub fn horizon_ns(&self) -> u64 { self.horizon_ns }
    /// Retained assumptions for explanations and counterfactual comparisons.
    pub fn priors(&self) -> RoutePriors { self.priors }
    /// Canonically ordered route alternatives, including protected low-mass routes.
    pub fn hypotheses(&self) -> &[MotionHypothesis] { &self.hypotheses }
    /// Denominator for heuristic weighting, not an empirical probability normalizer.
    pub fn total_mass(&self) -> u64 { self.total_mass }
}

/// Time-parameterize supplied routes with explicit class priors and a hard work budget.
///
/// Different routes may start at different positions to represent localization
/// ambiguity. This function does not manufacture 3D measurements or certify route
/// connectivity. Travel times round upward to nanoseconds; no timestamp is cast
/// until bounded. Alternate speeds/stops must be supplied as separate hypotheses.
/// Unknown route tails, exhausted budgets, and alternative-count overflow cannot
/// become a deceptively complete forecast.
pub fn forecast_routes(basis: ForecastBasis, reference_ns: u64, horizon_ns: u64,
    priors: RoutePriors, routes: &[RouteCandidate<'_>], budget: &mut WorkBudget<'_>)
    -> Result<MotionForecast, GeometryError> {
    budget.charge(0)?;
    if horizon_ns == 0 || horizon_ns > MAX_FORECAST_NS
        || reference_ns.checked_add(horizon_ns).is_none() {
        return Err(GeometryError::OutOfRange);
    }
    if routes.is_empty() { return Err(GeometryError::EmptyInput); }
    if routes.len() > MAX_MOTION_ROUTES { return Err(GeometryError::LimitExceeded); }
    let mut hypotheses = Vec::new();
    hypotheses.try_reserve_exact(routes.len()).map_err(|_| GeometryError::LimitExceeded)?;
    let mut total_mass = 0_u64;
    for (ordinal, route) in routes.iter().enumerate() {
        budget.charge(1 + ordinal as u64)?;
        if route.id == 0 || routes[..ordinal].iter().any(|prior| prior.id == route.id) {
            return Err(GeometryError::InvalidIndex);
        }
        if route.points.is_empty() { return Err(GeometryError::EmptyInput); }
        if route.points.len() > MAX_ROUTE_POINTS { return Err(GeometryError::LimitExceeded); }
        if !route.speed.is_finite() || !(1e-9..=1e12).contains(&route.speed)
            || route.initial_pause_ns > horizon_ns {
            return Err(GeometryError::OutOfRange);
        }
        // Validate the entire supplied path, including any suffix outside the horizon.
        for (index, point) in route.points.iter().enumerate() {
            budget.charge(1)?;
            checked(*point)?;
            if index > 0 && norm(sub(*point, route.points[index - 1])) <= 1e-12 {
                return Err(GeometryError::Degenerate);
            }
        }
        let mass = priors.mass(route.surface, route.base_mass)?;
        total_mass = total_mass.checked_add(mass).ok_or(GeometryError::OutOfRange)?;
        let mut knots = Vec::new();
        knots.try_reserve_exact(route.points.len() + 2).map_err(|_| GeometryError::LimitExceeded)?;
        knots.push(MotionKnot { offset_ns: 0, position: route.points[0] });
        let mut offset = route.initial_pause_ns;
        if offset > 0 { knots.push(MotionKnot { offset_ns: offset, position: route.points[0] }); }
        for segment in route.points.windows(2) {
            budget.charge(1)?;
            if offset == horizon_ns { break; }
            let duration = (norm(sub(segment[1], segment[0])) / route.speed * 1e9).ceil().max(1.0);
            if !duration.is_finite() { return Err(GeometryError::NonFinite); }
            let remaining = horizon_ns - offset;
            if duration > remaining as f64 {
                let position = checked(add(segment[0], scale(sub(segment[1], segment[0]), remaining as f64 / duration)))?;
                knots.push(MotionKnot { offset_ns: horizon_ns, position });
                offset = horizon_ns;
                break;
            }
            offset += duration as u64;
            knots.push(MotionKnot { offset_ns: offset, position: segment[1] });
        }
        if offset < horizon_ns && route.end == RouteEnd::Stop {
            let position = knots.last().ok_or(GeometryError::EmptyInput)?.position;
            knots.push(MotionKnot { offset_ns: horizon_ns, position });
        }
        hypotheses.push(MotionHypothesis { id: route.id, mass, protected: route.protected,
            surface: route.surface, knots });
    }
    budget.charge((hypotheses.len() as u64) * 6)?;
    hypotheses.sort_by_key(|hypothesis| hypothesis.id);
    budget.charge(0)?;
    Ok(MotionForecast { basis, reference_ns, horizon_ns, priors, hypotheses, total_mass })
}
