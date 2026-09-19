#![forbid(unsafe_code)]
//! All-destination route frontier from one exact active track revision.
//!
//! The frontier preserves every admitted feature destination and support mode within
//! caller-declared complete-output bounds. Path preference and velocity alignment are
//! diagnostics, not probabilities, and never delete grass/off-path alternatives.

use fss_geometry::WorkBudget;
use crate::{MovementClass, NavigationError, NavigationProfile, PropertyTwin, RouteOutcome,
    RouteQuery, RouteSearch, SupportLocation, SupportNetwork, TwinError};
use crate::stream::{TrackReceipt, TrackSnapshot};

/// Complete-enumeration bounds and profile for [`build_route_frontier`]; validated on entry.
#[derive(Clone, Copy, Debug)]
pub struct RouteFrontierOptions {
    /// Explicit class/slope/clearance/path-preference assumptions.
    pub profile: NavigationProfile,
    /// Maximum twin feature count accepted by this complete enumeration, 1..=4096.
    pub maximum_features: usize,
    /// Complete route assessment ceiling, 1..=16384. No top-k truncation occurs.
    pub maximum_routes: usize,
    /// Complete polyline point bound passed to every navigation query, 1..=256.
    pub maximum_points: usize,
    /// For people with a path preference, retain a second neutral-cost route per destination.
    pub retain_without_preference: bool,
}

/// Why a route was retained for a destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierRouteKind {
    /// Cheapest route under the configured path-preference profile.
    Preferred,
    /// Additional neutral-cost route retained for path-preferring profiles.
    WithoutPathPreference,
}

/// Why a nominal current support could not contribute routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierSourceLimitation {
    /// No nominal support exists for this source at the current revision.
    NoNominalSupport,
    /// The nominal support triangle is in occlusion conflict at this revision.
    NominalOcclusionConflict,
}

/// One observed source-pair motion mode checked against a route's initial direction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MotionCompatibility {
    /// Source-pair motion mode ordinal from this exact track revision.
    pub mode: usize,
    /// Nominal speed in property source units per second.
    pub speed: Option<f64>,
    /// Cosine between measured velocity and first nonzero route segment.
    pub initial_direction_cosine: Option<f64>,
}

/// One admitted (support, destination, kind) route through the frontier.
#[derive(Clone, Debug, PartialEq)]
pub struct FrontierRoute {
    /// Local ordinal in this result only.
    pub route: u64,
    /// Current support-hypothesis ordinal from the source projection.
    pub support: usize,
    /// Current revision-bound support triangle.
    pub source_triangle: u32,
    /// Zero-based semantic destination feature in the exact imported twin.
    pub destination_feature: u32,
    /// Whether this is the preferred route or a retained neutral-cost alternative.
    pub kind: FrontierRouteKind,
    /// Full route/non-route result. A missing route is not physical impossibility.
    pub search: RouteSearch,
    /// Every compatible observed motion mode; empty means no source-pair velocity applies.
    pub motion: Vec<MotionCompatibility>,
}

/// A nominal current support that could not contribute routes, with the reason.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrontierUnresolvedSource {
    /// Current support-hypothesis ordinal from the source projection.
    pub support: usize,
    /// Current revision-bound support triangle, when one exists.
    pub triangle: u32,
    /// Why this support produced no routes.
    pub reason: FrontierSourceLimitation,
}

/// Complete route frontier for one track snapshot against the imported twin.
#[derive(Debug)]
pub struct RouteFrontier {
    /// Receipt of the track snapshot the frontier was built from.
    pub source: TrackReceipt,
    /// Digest of the twin revision the routes were computed against.
    pub twin_digest: [u8;32],
    /// Path-preference profile applied to every route assessment.
    pub profile: NavigationProfile,
    /// Every admitted route; no top-k truncation occurs.
    pub routes: Vec<FrontierRoute>,
    /// Nominal supports that contributed no routes, with reasons.
    pub unresolved_sources: Vec<FrontierUnresolvedSource>,
    /// Number of destination features evaluated per usable source support.
    pub destination_features: usize,
}
impl RouteFrontier {
    /// Errors with [`RouteFrontierError::BasisMismatch`] unless `snapshot` is the exact
    /// receipt and twin revision this frontier was built from.
    pub fn check_source_current(&self,snapshot:TrackSnapshot<'_>)->Result<(),RouteFrontierError>{
        if snapshot.receipt()!=self.source || snapshot.projection().twin_digest()!=self.twin_digest {
            return Err(RouteFrontierError::BasisMismatch);
        }
        Ok(())
    }
}

/// Failure modes of route-frontier construction and staleness checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteFrontierError {
    /// [`RouteFrontierOptions`] failed validation.
    InvalidOptions,
    /// Snapshot receipt or twin digest no longer matches the frontier basis.
    BasisMismatch,
    /// A complete-output bound (`maximum_features`/`maximum_routes`) was exceeded.
    Limit,
    /// The underlying navigation query failed.
    Navigation(NavigationError),
    /// The twin source computation failed.
    Twin(TwinError),
}
impl From<NavigationError> for RouteFrontierError { fn from(value:NavigationError)->Self{Self::Navigation(value)} }
impl From<TwinError> for RouteFrontierError { fn from(value:TwinError)->Self{Self::Twin(value)} }
impl From<fss_geometry::GeometryError> for RouteFrontierError {
    fn from(value:fss_geometry::GeometryError)->Self{Self::Twin(value.into())}
}
impl std::fmt::Display for RouteFrontierError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.write_str(match self{
            Self::InvalidOptions=>"invalid route-frontier options",
            Self::BasisMismatch=>"route-frontier basis mismatch",
            Self::Limit=>"route-frontier complete-output limit exceeded",
            Self::Navigation(_)=>"route-frontier navigation failed",
            Self::Twin(_)=>"route-frontier source computation failed",
        })
    }
}
impl std::error::Error for RouteFrontierError{}

/// Enumerate every feature destination from every nominal current support. For a
/// pedestrian-preferred profile the neutral-cost route is retained alongside the
/// preferred route. This is a finite graph frontier, not intent inference.
pub fn build_route_frontier(twin:&PropertyTwin,network:&SupportNetwork,snapshot:TrackSnapshot<'_>,
    options:RouteFrontierOptions,budget:&mut WorkBudget<'_>)->Result<RouteFrontier,RouteFrontierError>{
    budget.charge(0)?;
    if network.basis()!=twin.basis() || network.twin_digest()!=twin.digest()
        || snapshot.projection().twin_digest()!=twin.digest(){return Err(RouteFrontierError::BasisMismatch);}
    if options.maximum_features==0 || options.maximum_features>4096 || options.maximum_routes==0
        || options.maximum_routes>16384 || options.maximum_points==0 || options.maximum_points>256
        || twin.features().len()>options.maximum_features {return Err(RouteFrontierError::InvalidOptions);}
    let neutral=options.retain_without_preference && options.profile.class()==MovementClass::Person
        && options.profile.person_path_multiplier()!=1;
    let usable=snapshot.projection().hypotheses().iter().filter(|h|h.nominal.is_some()).count();
    let branches=if neutral{2}else{1};
    let route_count=usable.checked_mul(twin.features().len()).and_then(|n|n.checked_mul(branches))
        .ok_or(RouteFrontierError::Limit)?;
    if route_count>options.maximum_routes{return Err(RouteFrontierError::Limit);}
    let mut routes=Vec::new();routes.try_reserve_exact(route_count).map_err(|_|RouteFrontierError::Limit)?;
    let mut unresolved=Vec::new();unresolved.try_reserve_exact(snapshot.projection().hypotheses().len()).map_err(|_|RouteFrontierError::Limit)?;
    let motion=snapshot.motion();
    for (support_index,hypothesis) in snapshot.projection().hypotheses().iter().enumerate(){
        budget.charge(16)?;
        let Some(hit)=hypothesis.nominal else{
            unresolved.push(FrontierUnresolvedSource{support:support_index,triangle:hypothesis.triangle,reason:FrontierSourceLimitation::NoNominalSupport});
            continue;
        };
        if hypothesis.nominal_occluded==Some(true){
            unresolved.push(FrontierUnresolvedSource{support:support_index,triangle:hypothesis.triangle,reason:FrontierSourceLimitation::NominalOcclusionConflict});
        }
        let start=SupportLocation::new(hit.triangle,hit.barycentric).map_err(RouteFrontierError::Navigation)?;
        for feature in 0..twin.features().len(){
            for kind in [FrontierRouteKind::Preferred,FrontierRouteKind::WithoutPathPreference]{
                if kind==FrontierRouteKind::WithoutPathPreference && !neutral{continue;}
                let profile=if kind==FrontierRouteKind::WithoutPathPreference{options.profile.without_preference()}else{options.profile};
                let search=network.route_to_feature(RouteQuery{basis:twin.basis(),twin_digest:twin.digest(),start,
                    destination_feature:feature as u32,profile,max_points:options.maximum_points},budget)?;
                let mut compatibility=Vec::new();
                if let Some(world_motion)=motion{
                    let matching=world_motion.modes().iter().enumerate().filter(|(_,mode)|mode.current_triangle==hypothesis.triangle).count();
                    compatibility.try_reserve_exact(matching).map_err(|_|RouteFrontierError::Limit)?;
                    for (mode_index,mode) in world_motion.modes().iter().enumerate(){
                        if mode.current_triangle!=hypothesis.triangle{continue;}
                        let speed=mode.nominal_velocity.map(|v|v[0].hypot(v[1]).hypot(v[2]));
                        let cosine=match (&search.outcome,mode.nominal_velocity){
                            (RouteOutcome::Found(path),Some(v))=>direction_cosine(path.points(),v),
                            _=>None,
                        };
                        compatibility.push(MotionCompatibility{mode:mode_index,speed,initial_direction_cosine:cosine});
                    }
                }
                routes.push(FrontierRoute{route:routes.len() as u64+1,support:support_index,
                    source_triangle:hypothesis.triangle,destination_feature:feature as u32,kind,search,motion:compatibility});
            }
        }
    }
    budget.charge(0)?;
    Ok(RouteFrontier{source:snapshot.receipt(),twin_digest:twin.digest(),profile:options.profile,routes,
        unresolved_sources:unresolved,destination_features:twin.features().len()})
}

fn direction_cosine(points:&[[f64;3]],velocity:[f64;3])->Option<f64>{
    let speed=velocity[0].hypot(velocity[1]).hypot(velocity[2]);
    if speed<=1e-12{return None;}
    for pair in points.windows(2){
        let d:[f64;3]=std::array::from_fn(|i|pair[1][i]-pair[0][i]);
        let length=d[0].hypot(d[1]).hypot(d[2]);
        if length>1e-12{return Some((0..3).map(|i|d[i]/length*velocity[i]/speed).sum::<f64>().clamp(-1.0,1.0));}
    }
    None
}
