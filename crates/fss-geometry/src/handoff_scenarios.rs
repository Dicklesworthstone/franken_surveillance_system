#![forbid(unsafe_code)]
//! Complete finite-scenario envelopes for camera-pose, sampling-phase, and timing uncertainty.
//!
//! Scenarios are caller-supplied admissible worlds. They are not probabilities and are never
//! collapsed before the individual forecasts are retained. This layer exposes which next-camera
//! conclusions are robust across every scenario and where timing/image-region predictions vary.

use crate::{BodySamples,CameraHandoffForecast,ForecastBasis,GeometryError,HandoffCamera,HandoffOptions,
    ImageRect,MotionForecast,NanosecondInterval,NextCameraOutcome,RouteBody,TriangleMesh,WorkBudget,
    predict_camera_handoffs};

/// Hard finite-world bound. Exceeding it is a refusal, never sampling or truncation.
pub const MAX_HANDOFF_SCENARIOS:usize=64;

/// One explicit admissible calibration/clock/sampling world.
#[derive(Clone,Copy)]
pub struct HandoffScenario<'a>{
    /// Nonzero stable handle local to this request.
    pub id:u64,
    /// Complete already-authorized camera set for this world.
    pub cameras:&'a [HandoffCamera<'a>],
}
impl std::fmt::Debug for HandoffScenario<'_>{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.debug_struct("HandoffScenario").field("id",&self.id).field("cameras",&self.cameras.len()).finish_non_exhaustive()
    }
}

/// One camera's union over scenarios in which it is a first predicted observer.
#[derive(Clone,Debug,PartialEq)]
pub struct ScenarioCameraEnvelope{
    pub camera:u64,
    /// Scenario IDs where this camera belongs to the nominal first-event set.
    pub scenarios:Vec<u64>,
    /// Earliest/latest nominal first capture across those scenarios.
    pub capture_ns:NanosecondInterval,
    /// Union of first-event image regions across those scenarios.
    pub region:ImageRect,
}

/// Conservative route-level result across every supplied scenario.
#[derive(Clone,Debug,PartialEq)]
pub struct ScenarioRouteEnvelope{
    pub route:u64,
    pub mass:u64,
    pub protected:bool,
    /// Cameras that are nominally first in at least one scenario.
    pub cameras:Vec<ScenarioCameraEnvelope>,
    /// True only when every scenario predicts a first event and the complete first-camera set is identical.
    pub robust_next_cameras:Option<Vec<u64>>,
    /// At least one scenario could not complete the first-event claim.
    pub has_indeterminate:bool,
    /// At least one scenario has no modeled observation in the horizon.
    pub has_no_modeled_observation:bool,
}

/// Complete per-scenario results plus their conservative envelopes.
#[derive(Clone,Debug,PartialEq)]
pub struct ScenarioHandoffForecast{
    pub basis:ForecastBasis,
    pub scenario_ids:Vec<u64>,
    pub forecasts:Vec<CameraHandoffForecast>,
    pub routes:Vec<ScenarioRouteEnvelope>,
}

/// Evaluate every supplied scenario atomically. Any control/resource failure refuses the whole
/// operation; ordinary differences between worlds survive in `forecasts` and `routes`.
pub fn predict_camera_handoff_scenarios(expected_basis:ForecastBasis,motion:&MotionForecast,
    mesh:&TriangleMesh,scenarios:&[HandoffScenario<'_>],bodies:&[RouteBody<'_>],options:HandoffOptions,
    budget:&mut WorkBudget<'_>)->Result<ScenarioHandoffForecast,GeometryError>{
    budget.charge(0)?;
    if scenarios.is_empty(){return Err(GeometryError::EmptyInput);}
    if scenarios.len()>MAX_HANDOFF_SCENARIOS{return Err(GeometryError::LimitExceeded);}
    let mut ids=Vec::new();let mut forecasts=Vec::new();
    ids.try_reserve_exact(scenarios.len()).map_err(|_|GeometryError::LimitExceeded)?;
    forecasts.try_reserve_exact(scenarios.len()).map_err(|_|GeometryError::LimitExceeded)?;
    let mut canonical_cameras:Option<Vec<u64>>=None;
    for (index,scenario) in scenarios.iter().enumerate(){
        budget.charge(1+index as u64)?;
        if scenario.id==0 || ids.contains(&scenario.id){return Err(GeometryError::InvalidIndex);}
        let mut camera_ids:Vec<u64>=scenario.cameras.iter().map(|c|c.id).collect();
        camera_ids.sort_unstable();
        if camera_ids.windows(2).any(|w|w[0]==w[1]){return Err(GeometryError::InvalidIndex);}
        match &canonical_cameras{
            None=>canonical_cameras=Some(camera_ids),
            Some(expected) if *expected!=camera_ids=>return Err(GeometryError::BasisMismatch),
            _=>{},
        }
        let forecast=predict_camera_handoffs(expected_basis,motion,mesh,scenario.cameras,bodies,options,budget)?;
        ids.push(scenario.id);forecasts.push(forecast);
    }
    let first=&forecasts[0];
    for forecast in &forecasts[1..]{
        if forecast.basis!=first.basis || forecast.reference_ns!=first.reference_ns || forecast.horizon_ns!=first.horizon_ns
            || forecast.total_mass!=first.total_mass || forecast.routes.len()!=first.routes.len(){return Err(GeometryError::BasisMismatch);}
        for (a,b) in first.routes.iter().zip(&forecast.routes){
            if a.route!=b.route || a.mass!=b.mass || a.protected!=b.protected || a.body_generation!=b.body_generation{
                return Err(GeometryError::BasisMismatch);
            }
        }
    }
    let mut routes=Vec::new();routes.try_reserve_exact(first.routes.len()).map_err(|_|GeometryError::LimitExceeded)?;
    for route_index in 0..first.routes.len(){
        budget.charge(scenarios.len() as u64)?;
        let source=&first.routes[route_index];
        let mut camera_acc:Vec<CameraAccumulator>=Vec::new();
        camera_acc.try_reserve_exact(canonical_cameras.as_ref().map_or(0,Vec::len)).map_err(|_|GeometryError::LimitExceeded)?;
        let mut robust:Option<Vec<u64>>=None;let mut robust_possible=true;
        let mut has_indeterminate=false;let mut has_none=false;
        for (scenario_index,forecast) in forecasts.iter().enumerate(){
            let route=&forecast.routes[route_index];
            match &route.next{
                NextCameraOutcome::Indeterminate=>{has_indeterminate=true;robust_possible=false;},
                NextCameraOutcome::NoModeledObservation=>{has_none=true;robust_possible=false;},
                NextCameraOutcome::Predicted{nominal_capture_ns,cameras}=>{
                    let mut ordered=cameras.clone();ordered.sort_unstable();
                    match &robust{
                        None=>robust=Some(ordered.clone()),
                        Some(existing) if *existing!=ordered=>robust_possible=false,
                        _=>{},
                    }
                    for &camera in cameras{
                        let observation=route.observations.iter().find(|o|o.camera==camera&&o.nominal_capture_ns==*nominal_capture_ns)
                            .ok_or(GeometryError::Degenerate)?;
                        add_camera(&mut camera_acc,camera,ids[scenario_index],*nominal_capture_ns,observation.region)?;
                    }
                }
            }
        }
        camera_acc.sort_by_key(|item|item.camera);
        let mut cameras=Vec::new();cameras.try_reserve_exact(camera_acc.len()).map_err(|_|GeometryError::LimitExceeded)?;
        for item in camera_acc{
            cameras.push(ScenarioCameraEnvelope{camera:item.camera,scenarios:item.scenarios,
                capture_ns:NanosecondInterval::new(item.earliest,item.latest)?,
                region:ImageRect::new(item.min,item.max)?});
        }
        routes.push(ScenarioRouteEnvelope{route:source.route,mass:source.mass,protected:source.protected,cameras,
            robust_next_cameras:if robust_possible{robust}else{None},has_indeterminate,has_no_modeled_observation:has_none});
    }
    budget.charge(0)?;
    Ok(ScenarioHandoffForecast{basis:expected_basis,scenario_ids:ids,forecasts,routes})
}

struct CameraAccumulator{camera:u64,scenarios:Vec<u64>,earliest:u64,latest:u64,min:[f64;2],max:[f64;2]}
fn add_camera(acc:&mut Vec<CameraAccumulator>,camera:u64,scenario:u64,time:u64,region:ImageRect)->Result<(),GeometryError>{
    let lo=region.min();let hi=region.max();
    if let Some(item)=acc.iter_mut().find(|item|item.camera==camera){
        item.scenarios.try_reserve(1).map_err(|_|GeometryError::LimitExceeded)?;item.scenarios.push(scenario);
        item.earliest=item.earliest.min(time);item.latest=item.latest.max(time);
        for axis in 0..2{item.min[axis]=item.min[axis].min(lo[axis]);item.max[axis]=item.max[axis].max(hi[axis]);}
    }else{
        let mut scenarios=Vec::new();scenarios.try_reserve_exact(1).map_err(|_|GeometryError::LimitExceeded)?;scenarios.push(scenario);
        acc.try_reserve(1).map_err(|_|GeometryError::LimitExceeded)?;
        acc.push(CameraAccumulator{camera,scenarios,earliest:time,latest:time,min:lo,max:hi});
    }
    Ok(())
}
