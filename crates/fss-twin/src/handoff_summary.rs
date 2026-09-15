#![forbid(unsafe_code)]
//! Lossless camera-centric summary over a complete frontier handoff forecast.
//! Heuristic route masses remain masses, not calibrated probabilities.

use fss_geometry::{GeometryError,ImageRect,NanosecondInterval,NextCameraOutcome};
use crate::frontier_handoff::FrontierHandoffForecast;

#[derive(Clone, Debug, PartialEq)]
pub struct CameraNextSummary {
    pub camera:u64,
    /// Nonexclusive support mass: simultaneous next-camera events credit every member.
    pub heuristic_support_mass:u64,
    pub protected_support_mass:u64,
    pub supporting_routes:usize,
    /// Range of nominal first eligible captures among supporting routes.
    pub nominal_capture_range:NanosecondInterval,
    /// Union of predicted next-event regions, normalized to this camera image.
    pub region_envelope:ImageRect,
}
impl CameraNextSummary {
    pub fn normalized_center(&self)->[f64;2]{
        let a=self.region_envelope.min();let b=self.region_envelope.max();[(a[0]+b[0])*0.5,(a[1]+b[1])*0.5]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NextCameraSummary {
    /// Denominator retained from the complete motion forecast.
    pub total_route_mass:u64,
    /// Mutually exclusive route mass whose next observation is unresolved.
    pub indeterminate_mass:u64,
    /// Mutually exclusive route mass with no modeled next observation in the horizon.
    pub no_modeled_observation_mass:u64,
    /// Every camera with at least one supported next event, sorted by descending support
    /// then earliest capture and camera ID. Simultaneous events make these masses nonexclusive.
    pub cameras:Vec<CameraNextSummary>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffSummaryError { InconsistentForecast, Overflow, Geometry(GeometryError) }
impl From<GeometryError> for HandoffSummaryError{fn from(v:GeometryError)->Self{Self::Geometry(v)}}
impl std::fmt::Display for HandoffSummaryError{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(match self{
        Self::InconsistentForecast=>"frontier handoff forecast is internally inconsistent",
        Self::Overflow=>"frontier handoff summary overflow",
        Self::Geometry(_)=>"frontier handoff summary geometry failure",
    })}
}
impl std::error::Error for HandoffSummaryError{}

struct Accumulator {
    camera:u64,mass:u64,protected:u64,routes:usize,min_time:u64,max_time:u64,
    min:[f64;2],max:[f64;2],
}

/// Aggregate complete route-level next-event outcomes without dropping alternatives.
/// Ranking is presentation only: the returned list still contains every supported camera.
pub fn summarize_next_cameras(forecast:&FrontierHandoffForecast)->Result<NextCameraSummary,HandoffSummaryError>{
    if forecast.motion.total_mass()!=forecast.handoff.total_mass{return Err(HandoffSummaryError::InconsistentForecast);}
    let mut acc:Vec<Accumulator>=Vec::new();
    acc.try_reserve_exact(forecast.handoff.camera_scope.len()).map_err(|_|HandoffSummaryError::Overflow)?;
    let mut indeterminate=0u64;let mut none=0u64;
    for route in &forecast.handoff.routes{
        match &route.next{
            NextCameraOutcome::Indeterminate=>indeterminate=indeterminate.checked_add(route.mass).ok_or(HandoffSummaryError::Overflow)?,
            NextCameraOutcome::NoModeledObservation=>none=none.checked_add(route.mass).ok_or(HandoffSummaryError::Overflow)?,
            NextCameraOutcome::Predicted{nominal_capture_ns,cameras}=>{
                if cameras.is_empty(){return Err(HandoffSummaryError::InconsistentForecast);}
                for &camera in cameras{
                    let observation=route.observations.iter().find(|o|o.camera==camera&&o.nominal_capture_ns==*nominal_capture_ns)
                        .ok_or(HandoffSummaryError::InconsistentForecast)?;
                    let r=observation.region;let lo=r.min();let hi=r.max();
                    if let Some(item)=acc.iter_mut().find(|x|x.camera==camera){
                        item.mass=item.mass.checked_add(route.mass).ok_or(HandoffSummaryError::Overflow)?;
                        if route.protected{item.protected=item.protected.checked_add(route.mass).ok_or(HandoffSummaryError::Overflow)?;}
                        item.routes=item.routes.checked_add(1).ok_or(HandoffSummaryError::Overflow)?;
                        item.min_time=item.min_time.min(*nominal_capture_ns);item.max_time=item.max_time.max(*nominal_capture_ns);
                        for axis in 0..2{item.min[axis]=item.min[axis].min(lo[axis]);item.max[axis]=item.max[axis].max(hi[axis]);}
                    }else{
                        acc.push(Accumulator{camera,mass:route.mass,protected:if route.protected{route.mass}else{0},routes:1,
                            min_time:*nominal_capture_ns,max_time:*nominal_capture_ns,min:lo,max:hi});
                    }
                }
            }
        }
    }
    let mut cameras=Vec::new();cameras.try_reserve_exact(acc.len()).map_err(|_|HandoffSummaryError::Overflow)?;
    for item in acc{
        cameras.push(CameraNextSummary{camera:item.camera,heuristic_support_mass:item.mass,protected_support_mass:item.protected,
            supporting_routes:item.routes,nominal_capture_range:NanosecondInterval::new(item.min_time,item.max_time)?,
            region_envelope:ImageRect::new(item.min,item.max)?});
    }
    cameras.sort_by(|a,b|b.heuristic_support_mass.cmp(&a.heuristic_support_mass)
        .then(a.nominal_capture_range.earliest().cmp(&b.nominal_capture_range.earliest())).then(a.camera.cmp(&b.camera)));
    Ok(NextCameraSummary{total_route_mass:forecast.handoff.total_mass,indeterminate_mass:indeterminate,
        no_modeled_observation_mass:none,cameras})
}
