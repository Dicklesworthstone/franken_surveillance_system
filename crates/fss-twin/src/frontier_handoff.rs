#![forbid(unsafe_code)]
//! Predict camera handoffs across an already complete all-destination route frontier.
//! Heading-derived masses are explicit heuristics, never calibrated probabilities.

use fss_geometry::{BodySamples,CameraHandoffForecast,ForecastBasis,HandoffOptions,MotionForecast,
    RouteBody,RouteCandidate,RouteEnd,RoutePriors,RouteSurface,WorkBudget,forecast_routes,
    predict_camera_handoffs};
use crate::{MovementClass,PropertyTwin,RouteOutcome,TwinError};
use crate::calibration_gate::CalibrationGateError;
use crate::monitored_handoff::MonitoredHandoffCamera;
use crate::route_frontier::{FrontierRouteKind,RouteFrontier,RouteFrontierError};
use crate::stream::{TrackReceipt,TrackSnapshot};

/// Heuristic route-mass table interpolating heading alignment into base masses.
/// All values are arbitrary support weights, never calibrated probabilities.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HeadingMassPolicy {
    /// Mass at cosine -1 and +1 respectively; each in 1..=1_000_000.
    pub opposite: u32,
    /// Mass at a perfectly aligned nominal heading; in 1..=1_000_000 and >= `opposite`.
    pub aligned: u32,
    /// Mass when no nominal heading is available.
    pub unknown: u32,
    /// Explicit stopping alternative mass.
    pub stopped: u32,
}
impl Default for HeadingMassPolicy {
    fn default()->Self{Self{opposite:100,aligned:1000,unknown:500,stopped:350}}
}
impl HeadingMassPolicy {
    fn validate(self)->bool{
        [self.opposite,self.aligned,self.unknown,self.stopped].iter().all(|x|(1..=1_000_000).contains(x))
            && self.opposite<=self.aligned
    }
    fn moving(self,cosine:Option<f64>)->u32{
        let Some(c)=cosine else{return self.unknown;};
        let t=((c.clamp(-1.0,1.0)+1.0)*0.5).clamp(0.0,1.0);
        (f64::from(self.opposite)+(f64::from(self.aligned-self.opposite))*t).round() as u32
    }
}

/// Bounded inputs for the frontier handoff forecast; every value must come from
/// the caller's policy, never from inferred motion.
#[derive(Clone, Copy, Debug)]
pub struct FrontierHandoffOptions {
    /// Nominal projection horizon past the mid-source capture, in nanoseconds;
    /// nonzero and at most one hour (3_600_000_000_000).
    pub horizon_ns:u64,
    /// Forecast generation stamp; must be nonzero so stale receipts stay detectable.
    pub motion_generation:u64,
    /// Initial pause before a moving route becomes capture-eligible, in nanoseconds;
    /// must not exceed `horizon_ns` (single-point stop routes use zero).
    pub initial_pause_ns:u64,
    /// Terminal behaviour attached to every route candidate.
    pub route_end:RouteEnd,
    /// Heading-derived base-mass table applied to each route/motion pairing.
    pub masses:HeadingMassPolicy,
    /// Per-camera projection policy forwarded to `predict_camera_handoffs`.
    pub handoff:HandoffOptions,
}

/// Whether a frontier binding is a navigated route or an explicit stop branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierMotionKind {
    /// Navigated route bound to one frontier route and one observed motion mode.
    Route,
    /// Explicit stopping alternative generated for one observed motion mode.
    Stop,
}

/// Coupling between a generated motion route and its frontier/mode provenance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrontierMotionBinding {
    /// 1-based handle of the generated route inside the motion forecast.
    pub motion_route:u64,
    /// Route-frontier local handle, absent for explicit stop branches.
    pub frontier_route:Option<u64>,
    /// Index of the observed motion mode this binding was generated from.
    pub source_mode:usize,
    /// Whether the generated route is navigated motion or an explicit stop.
    pub kind:FrontierMotionKind,
    /// Heading-derived base mass for this binding, in 1..=1_000_000.
    pub base_mass:u32,
    /// Cosine between initial path direction and nominal velocity, when available.
    pub heading_cosine:Option<f64>,
}

/// Why one frontier route or motion mode produced no nominal path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierHandoffUnmodeledReason {
    /// The frontier route carried no observed motion-mode compatibility entries.
    NoObservedMotionMode,
    /// Every candidate speed was absent or outside the usable finite range.
    NoUsableSpeed,
    /// Navigation could not produce a route for this frontier route.
    NavigationDidNotProduceRoute,
    /// The motion mode has no nominal position to anchor a stop branch.
    NoNominalStopPosition,
}
/// One retained frontier route or motion mode that yielded no nominal path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrontierHandoffUnmodeled {
    /// Frontier route handle, when the limitation is scoped to one route.
    pub frontier_route:Option<u64>,
    /// Observed motion-mode index, when the limitation is scoped to one mode.
    pub source_mode:Option<usize>,
    /// Exact reason the branch was not modeled.
    pub reason:FrontierHandoffUnmodeledReason,
}

/// Complete lossless frontier handoff result: every usable pairing plus every
/// explicit stop branch, with no alternative pruned.
#[derive(Debug)]
pub struct FrontierHandoffForecast {
    /// Source snapshot receipt this forecast is pinned to.
    pub source:TrackReceipt,
    /// Exact immutable twin package digest used for all geometry.
    pub twin_digest:[u8;32],
    /// Route-frontier source receipt; must match `source` for the forecast to be usable.
    pub frontier_source:TrackReceipt,
    /// Exact options supplied by the caller.
    pub options:FrontierHandoffOptions,
    /// Provenance of every generated route, ordered by route id.
    pub bindings:Vec<FrontierMotionBinding>,
    /// Retained branches that produced no nominal path.
    pub unmodeled:Vec<FrontierHandoffUnmodeled>,
    /// Motion forecast over all generated routes.
    pub motion:MotionForecast,
    /// Camera-level next-event predictions for all retained routes.
    pub handoff:CameraHandoffForecast,
}

/// Failure modes of the frontier handoff forecast.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierHandoffError {
    /// Snapshot, frontier or motion basis does not match the twin.
    Basis,
    /// A caller-supplied option violates its documented range.
    Options,
    /// Bounded output or staging capacity was exceeded.
    Limit,
    /// The frontier produced no usable nominal motion paths.
    Empty,
    /// The route frontier itself is invalid for this snapshot.
    Frontier(RouteFrontierError),
    /// A candidate handoff camera has no current admitted calibration.
    Calibration(CalibrationGateError),
    /// Twin geometry or resource accounting failed.
    Twin(TwinError),
}
impl From<fss_geometry::GeometryError> for FrontierHandoffError{fn from(v:fss_geometry::GeometryError)->Self{Self::Twin(v.into())}}
impl From<CalibrationGateError> for FrontierHandoffError{fn from(v:CalibrationGateError)->Self{Self::Calibration(v)}}
impl std::fmt::Display for FrontierHandoffError{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(match self{
        Self::Basis=>"frontier-handoff basis mismatch",Self::Options=>"invalid frontier-handoff options",
        Self::Limit=>"frontier-handoff complete-output limit exceeded",Self::Empty=>"frontier has no usable nominal motion paths",
        Self::Frontier(_)=>"route frontier invalid",Self::Calibration(_)=>"handoff camera calibration unavailable",
        Self::Twin(_)=>"frontier-handoff geometry failed",
    })}
}
impl std::error::Error for FrontierHandoffError{}

/// Staged route row: `(id, points, speed, surface, base mass, protected, frontier route, end)`.
type FrontierRouteStorage=(u64,Vec<[f64;3]>,f64,RouteSurface,u32,bool,u64,RouteEnd);

/// Convert every usable frontier route/motion pairing plus every explicit stop mode into
/// one bounded motion forecast, then project all retained alternatives through every
/// currently monitored camera. No destination is supplied to this operation.
pub fn forecast_frontier_handoffs(twin:&PropertyTwin,snapshot:TrackSnapshot<'_>,frontier:&RouteFrontier,
    cameras:&[MonitoredHandoffCamera<'_,'_>],body:&BodySamples,options:FrontierHandoffOptions,
    budget:&mut WorkBudget<'_>)->Result<FrontierHandoffForecast,FrontierHandoffError>{
    budget.charge(0)?;
    frontier.check_source_current(snapshot).map_err(FrontierHandoffError::Frontier)?;
    let motion=snapshot.motion().ok_or(FrontierHandoffError::Empty)?;
    if frontier.twin_digest!=twin.digest() || motion.twin_digest()!=twin.digest() || motion.geometry()!=twin.basis(){return Err(FrontierHandoffError::Basis);}
    if options.horizon_ns==0 || options.horizon_ns>3_600_000_000_000 || options.motion_generation==0
        || options.initial_pause_ns>options.horizon_ns || !options.masses.validate()
        || cameras.is_empty() || cameras.len()>64{return Err(FrontierHandoffError::Options);}
    let observation=snapshot.projection().observation();
    let reference=observation.capture[0]+(observation.capture[1]-observation.capture[0])/2;
    if reference.checked_add(options.horizon_ns).is_none(){return Err(FrontierHandoffError::Options);}
    let mut views=Vec::new();views.try_reserve_exact(cameras.len()).map_err(|_|FrontierHandoffError::Limit)?;
    for candidate in cameras{
        budget.charge(8)?;candidate.monitor.check_handoff_camera(candidate.view,observation.capture)?;views.push(candidate.view);
    }
    let mut route_storage:Vec<FrontierRouteStorage>=Vec::new();
    let mut bindings=Vec::new();let mut unmodeled=Vec::new();
    route_storage.try_reserve_exact(64).map_err(|_|FrontierHandoffError::Limit)?;
    bindings.try_reserve_exact(64).map_err(|_|FrontierHandoffError::Limit)?;
    unmodeled.try_reserve_exact(frontier.routes.len()+motion.modes().len()).map_err(|_|FrontierHandoffError::Limit)?;
    for route in &frontier.routes{
        let RouteOutcome::Found(path)=&route.search.outcome else{
            unmodeled.push(FrontierHandoffUnmodeled{frontier_route:Some(route.route),source_mode:None,reason:FrontierHandoffUnmodeledReason::NavigationDidNotProduceRoute});continue;
        };
        if route.motion.is_empty(){unmodeled.push(FrontierHandoffUnmodeled{frontier_route:Some(route.route),source_mode:None,reason:FrontierHandoffUnmodeledReason::NoObservedMotionMode});continue;}
        for compatibility in &route.motion{
            let Some(speed)=compatibility.speed.filter(|s|s.is_finite()&&(1e-9..=1e12).contains(s)) else{
                unmodeled.push(FrontierHandoffUnmodeled{frontier_route:Some(route.route),source_mode:Some(compatibility.mode),reason:FrontierHandoffUnmodeledReason::NoUsableSpeed});continue;
            };
            if route_storage.len()==64{return Err(FrontierHandoffError::Limit);}
            let id=route_storage.len() as u64+1;
            let surface=if path.all_pedestrian(){RouteSurface::PedestrianPath}else{RouteSurface::OffPath};
            let base=options.masses.moving(compatibility.initial_direction_cosine);
            route_storage.push((id,path.points().to_vec(),speed,surface,base,
                route.kind==FrontierRouteKind::WithoutPathPreference,route.route,options.route_end));
            bindings.push(FrontierMotionBinding{motion_route:id,frontier_route:Some(route.route),source_mode:compatibility.mode,
                kind:FrontierMotionKind::Route,base_mass:base,heading_cosine:compatibility.initial_direction_cosine});
        }
    }
    // Preserve stopping as a separate alternative for every observed motion mode.
    for (mode_index,mode) in motion.modes().iter().enumerate(){
        let Some(position)=mode.nominal_position else{
            unmodeled.push(FrontierHandoffUnmodeled{frontier_route:None,source_mode:Some(mode_index),reason:FrontierHandoffUnmodeledReason::NoNominalStopPosition});continue;
        };
        if route_storage.len()==64{return Err(FrontierHandoffError::Limit);}
        let id=route_storage.len() as u64+1;
        route_storage.push((id,vec![position],1.0,RouteSurface::Other,options.masses.stopped,true,0,RouteEnd::Stop));
        bindings.push(FrontierMotionBinding{motion_route:id,frontier_route:None,source_mode:mode_index,
            kind:FrontierMotionKind::Stop,base_mass:options.masses.stopped,heading_cosine:None});
    }
    if route_storage.is_empty(){return Err(FrontierHandoffError::Empty);}
    let mut candidates=Vec::new();let mut bodies=Vec::new();
    candidates.try_reserve_exact(route_storage.len()).map_err(|_|FrontierHandoffError::Limit)?;
    bodies.try_reserve_exact(route_storage.len()).map_err(|_|FrontierHandoffError::Limit)?;
    for (id,points,speed,surface,base,protected,_,end) in &route_storage{
        candidates.push(RouteCandidate{id:*id,points,speed:*speed,initial_pause_ns:if points.len()==1{0}else{options.initial_pause_ns},
            end:*end,surface:*surface,base_mass:*base,protected:*protected});
        bodies.push(RouteBody{route:*id,body});
    }
    let receipt=snapshot.receipt();
    let basis=ForecastBasis::new(twin.basis(),receipt.scope.clock,receipt.scope.track,receipt.revision,options.motion_generation)?;
    let mut class=[0;4];class[match frontier.profile.class(){MovementClass::Person=>0,MovementClass::Bear=>1,MovementClass::OtherAnimal=>2,MovementClass::Unknown=>3}]=1;
    // Path preference already selected route geometry; do not multiply it again here.
    let forecast=forecast_routes(basis,reference,options.horizon_ns,RoutePriors::new(class,1)?,&candidates,budget)?;
    let handoff=predict_camera_handoffs(basis,&forecast,twin.mesh(),&views,&bodies,options.handoff,budget)?;
    budget.charge(0)?;
    Ok(FrontierHandoffForecast{source:receipt,twin_digest:twin.digest(),frontier_source:frontier.source,
        options,bindings,unmodeled,motion:forecast,handoff})
}
