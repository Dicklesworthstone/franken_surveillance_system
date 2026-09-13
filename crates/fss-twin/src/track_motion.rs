#![forbid(unsafe_code)]

use fss_geometry::{GeometryBasis, WorkBudget};
use crate::{Bounds3, ContactObservation, ContactProjection, Interval, TwinError};

/// Pair-fitting limits and explicit association evidence when cameras differ.
#[derive(Clone, Copy, Debug)]
pub struct MotionFitOptions {
    /// Maximum elapsed capture interval span; must be 1..=one hour in nanoseconds.
    pub max_gap_ns:u64,
    /// Maximum complete Cartesian set of support pairs, at most 256.
    pub max_modes:usize,
    /// Owner-supplied association evidence reference, required across different cameras.
    /// This reference is retained, not authenticated by the geometric fitter.
    pub association:Option<[u8;32]>,
}
impl Default for MotionFitOptions {
    fn default()->Self {Self{max_gap_ns:30_000_000_000,max_modes:64,association:None}}
}

/// One alternative pairing of earlier and later support surfaces.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WorldMotionMode {
    /// Earlier revision-bound supporting triangle.
    pub previous_triangle:u32,
    /// Current revision-bound supporting triangle.
    pub current_triangle:u32,
    /// Latest nominal contact, not always available for an interval-only candidate.
    pub nominal_position:Option<[f64;3]>,
    /// Finite-difference nominal velocity in source units per second.
    pub nominal_velocity:Option<[f64;3]>,
    /// Latest conditional position envelope, or unknown.
    pub position:Option<Bounds3>,
    /// Conditional componentwise velocity envelope, or unknown.
    pub velocity:Option<Bounds3>,
    /// Either nominal support ray is blocked in the imported model.
    pub nominal_occlusion_conflict:bool,
}

/// Immutable motion hypotheses derived only from source-bearing projections.
#[derive(Clone, Debug)]
pub struct WorldMotion {
    geometry:GeometryBasis,
    twin_digest:[u8;32],
    observations:[ContactObservation;2],
    association:Option<[u8;32]>,
    modes:Vec<WorldMotionMode>,
}
impl WorldMotion {
    /// Exact owner-resolved geometry basis.
    pub fn geometry(&self)->GeometryBasis {self.geometry}
    /// Exact imported-package identity.
    pub fn twin_digest(&self)->[u8;32] {self.twin_digest}
    /// Original observations in capture order, never forecasts.
    pub fn observations(&self)->[ContactObservation;2] {self.observations}
    /// Association evidence explicitly supplied by the owner, not inferred by this fitter.
    pub fn association(&self)->Option<[u8;32]> {self.association}
    /// All retained support pairings, without probability renormalization or pruning.
    pub fn modes(&self)->&[WorldMotionMode] {&self.modes}
}

/// Fit displacement/time intervals without treating shared errors as independent.
///
/// Strictly overlapping capture intervals cannot establish finite velocity here.
/// Support pairing is hypothesis enumeration, not identity or traversability proof.
/// A changed same-camera calibration or crop requires an explicit owner rebase.
pub fn fit_world_motion(previous:&ContactProjection,current:&ContactProjection,
    options:MotionFitOptions,budget:&mut WorkBudget<'_>)->Result<WorldMotion,TwinError> {
    budget.charge(0)?;
    let a=previous.observation();let b=current.observation();
    let ca=previous.camera();let cb=current.camera();
    if ca.geometry!=cb.geometry || previous.twin_digest()!=current.twin_digest()
        || a.track!=b.track || a.clock!=b.clock || a.evidence==b.evidence
        || (a.camera==b.camera && (a.exposure==b.exposure || ca.calibration!=cb.calibration
            || ca.image_domain!=cb.image_domain || ca.pose!=cb.pose || ca.intrinsics!=cb.intrinsics || ca.error!=cb.error)) {
        return Err(TwinError::Basis);
    }
    if a.camera!=b.camera && options.association.is_none_or(|id|id==[0;32]) {return Err(TwinError::Basis);}
    if options.association==Some([0;32]) {return Err(TwinError::Basis);}
    if options.max_gap_ns==0 || options.max_gap_ns>3_600_000_000_000
        || options.max_modes==0 || options.max_modes>256 {return Err(TwinError::Limit);}
    if b.capture[0]<=a.capture[1] || b.capture[1]-a.capture[0]>options.max_gap_ns {
        return Err(TwinError::Unobservable);
    }
    let count=previous.hypotheses().len().checked_mul(current.hypotheses().len()).ok_or(TwinError::Limit)?;
    if count==0 {return Err(TwinError::Unobservable);}
    if count>options.max_modes {return Err(TwinError::Limit);}
    let elapsed=seconds(b.capture[0]-a.capture[1],b.capture[1]-a.capture[0])?;
    let middle=|t:[u64;2]|t[0]+(t[1]-t[0])/2;
    let nominal_elapsed=(middle(b.capture)-middle(a.capture)) as f64/1e9;
    let mut modes=Vec::new();modes.try_reserve_exact(count).map_err(|_|TwinError::Limit)?;
    for first in previous.hypotheses() {for last in current.hypotheses() {
        budget.charge(32)?;
        let velocity=if let (Some(pa),Some(pb))=(first.bounds,last.bounds) {
            Some(Bounds3([pb.0[0].sub(pa.0[0])?.div(elapsed)?,pb.0[1].sub(pa.0[1])?.div(elapsed)?,
                pb.0[2].sub(pa.0[2])?.div(elapsed)?]))
        } else {None};
        let nominal_velocity=if let (Some(pa),Some(pb))=(first.nominal,last.nominal) {
            let v:[f64;3]=std::array::from_fn(|i|(pb.point[i]-pa.point[i])/nominal_elapsed);
            if v.iter().any(|x|!x.is_finite()) {return Err(TwinError::Numeric);}
            Some(v)
        } else {None};
        modes.push(WorldMotionMode{previous_triangle:first.triangle,current_triangle:last.triangle,
            nominal_position:last.nominal.map(|hit|hit.point),nominal_velocity,
            position:last.bounds,velocity,
            nominal_occlusion_conflict:first.nominal_occluded==Some(true)||last.nominal_occluded==Some(true)});
    }}
    budget.charge(0)?;
    Ok(WorldMotion{geometry:ca.geometry,twin_digest:previous.twin_digest(),observations:[a,b],
        association:options.association,modes})
}

/// One propagated mode. It deliberately cannot be passed to `fit_world_motion` as evidence.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PropagatedPosition {
    /// Corresponding input mode ordinal; alternatives keep their identity.
    pub mode:usize,
    /// Capture-time interval being forecast, not wall-clock processing time.
    pub capture:[u64;2],
    /// Nominal constant-velocity position, where supported.
    pub nominal:Option<[f64;3]>,
    /// Conditional enclosure including the explicitly supplied acceleration bounds.
    pub bounds:Option<Bounds3>,
}

/// Propagate all modes, widening for capture timing and possible acceleration.
///
/// The caller supplies physical acceleration bounds per axis in source units/s².
/// These bounds apply over the observed pair AND forecast interval.
/// They are model assumptions, not learned certainty; no default human/animal rule
/// is inserted. Unknown input bounds stay unknown. All results remain predictions.
pub fn propagate_motion(motion:&WorldMotion,capture:[u64;2],acceleration:[f64;3],
    budget:&mut WorkBudget<'_>)->Result<Vec<PropagatedPosition>,TwinError> {
    budget.charge(0)?;
    let start=motion.observations[1].capture;
    if capture[0]<start[1] || capture[1]<capture[0] || capture[1]-start[0]>3_600_000_000_000 {
        return Err(TwinError::Unobservable);
    }
    if acceleration.iter().any(|x|!x.is_finite() || *x<0.0 || *x>1e6) {return Err(TwinError::Numeric);}
    let time=seconds(capture[0]-start[1],capture[1]-start[0])?;
    let nominal_time=time.midpoint();
    let half=Interval::point(0.5)?;
    let pair=motion.observations;
    let historical_span=seconds(pair[1].capture[0]-pair[0].capture[1],pair[1].capture[1]-pair[0].capture[0])?;
    let mut output=Vec::new();output.try_reserve_exact(motion.modes.len()).map_err(|_|TwinError::Limit)?;
    for (index,mode) in motion.modes.iter().enumerate() {
        budget.charge(32)?;
        let bounds=if let (Some(position),Some(velocity))=(mode.position,mode.velocity) {
            let mut next=position.0;
            for i in 0..3 {
                // A displacement/time fit is average velocity, not endpoint velocity.
                // Bounded acceleration adds a*pair_duration/2 to endpoint speed.
                let growth=time.square()?.add(time.mul(historical_span)?)?
                    .mul(Interval::point(acceleration[i])?)?.mul(half)?.upper().max(0.0);
                next[i]=position.0[i].add(velocity.0[i].mul(time)?)?.add(Interval::new(-growth,growth)?)?;
            }
            Some(Bounds3(next))
        } else {None};
        let nominal=if let (Some(position),Some(velocity))=(mode.nominal_position,mode.nominal_velocity) {
            let p:[f64;3]=std::array::from_fn(|i|position[i]+velocity[i]*nominal_time);
            if p.iter().any(|x|!x.is_finite()) {return Err(TwinError::Numeric);}
            Some(p)
        } else {None};
        output.push(PropagatedPosition{mode:index,capture,nominal,bounds});
    }
    budget.charge(0)?;
    Ok(output)
}
fn seconds(lo:u64,hi:u64)->Result<Interval,TwinError> {
    // Integer differences precede conversion, avoiding subtraction of rounded epoch timestamps.
    Interval::outward(lo as f64,hi as f64)?.div(Interval::point(1e9)?)
}
