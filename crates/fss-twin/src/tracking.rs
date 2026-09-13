#![forbid(unsafe_code)]

use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, SurfaceHit, WorkBudget};
use crate::{Bounds3, Interval, PropertyTwin, TwinError};
use crate::interval::{I3, cross, dot, sub};

/// Declared deterministic calibration bounds, not automatically measured covariance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProjectionError {
    /// Absolute optical-centre error per world axis, in source units.
    pub centre: [f64;3],
    /// Absolute bound on each entry of the proper rotation matrix.
    pub rotation_entry: f64,
    /// Absolute focal-length errors in the undistorted image's pixels.
    pub focal: [f64;2],
    /// Absolute principal-point errors in the same image domain.
    pub principal: [f64;2],
}
impl ProjectionError {
    /// Exact represented calibration, useful for synthetic controls, not a default fit claim.
    pub const EXACT:Self=Self{centre:[0.0;3],rotation_entry:0.0,focal:[0.0;2],principal:[0.0;2]};
}

/// Owner-resolved camera snapshot. No field authenticates or grants effect authority.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrackingCamera {
    /// Exact imported geometry basis.
    pub geometry:GeometryBasis,
    /// Logical camera identity, nonzero.
    pub camera:u64,
    /// Exact calibration generation, nonzero.
    pub calibration:u64,
    /// Exact undistorted image-domain generation, nonzero.
    pub image_domain:u64,
    /// Common capture-time basis, nonzero.
    pub clock:u64,
    /// Inclusive validity interval on that clock.
    pub validity:[u64;2],
    /// World-to-camera transform in source units.
    pub pose:RigidPose,
    /// Qualified undistorted pinhole model, never raw fisheye pixels.
    pub intrinsics:PinholeIntrinsics,
    /// Unknown calibration error stays unknown rather than zero.
    pub error:Option<ProjectionError>,
}

/// One externally detected/selected ground-contact observation with source lineage.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContactObservation {
    /// Exact source-evidence record identity; cannot be all zero.
    pub evidence:[u8;32],
    /// Upstream anonymous track identity, not a person identity.
    pub track:u64,
    /// Camera identity matching the supplied snapshot.
    pub camera:u64,
    /// Capture/exposure identity within the camera; prevents duplicate-frame velocity fits.
    pub exposure:u64,
    /// Undistorted image-domain identity.
    pub image_domain:u64,
    /// Common time basis for capture interval, not packet arrival.
    pub clock:u64,
    /// Earliest/latest possible capture time in nanoseconds.
    pub capture:[u64;2],
    /// Closed contact-pixel rectangle, minimum coordinates.
    pub pixel_min:[f64;2],
    /// Closed contact-pixel rectangle, maximum coordinates.
    pub pixel_max:[f64;2],
    /// False means contact itself is uncertain/occluded: do not invent depth from a box bottom.
    pub visible_contact:bool,
}

/// Search volume and retained support alternatives, in source-world units.
#[derive(Clone, Copy, Debug)]
pub struct ProjectionOptions {
    /// Positive nearest ray distance.
    pub near:f64,
    /// Finite far distance; this bounds the claim's search volume, not physical absence.
    pub far:f64,
    /// Maximum retained hypotheses, at most 128. Overflow refuses rather than pruning.
    pub max_hypotheses:usize,
}
impl Default for ProjectionOptions {
    fn default()->Self {Self{near:1e-4,far:1000.0,max_hypotheses:64}}
}

/// Whether projected support bounds are available under the declared model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionQuality {
    /// Conditional interval bounds over all admitted support triangles in the search volume.
    Bounded,
    /// Calibration or map error is unknown; only centre-ray intersections are represented.
    NominalOnly,
    /// No reliable visible contact was supplied; original 2D observation remains available.
    ContactUnknown,
}

/// One possible supporting triangle; alternatives are not independent evidence.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContactHypothesis {
    /// Revision-bound triangle ordinal.
    pub triangle:u32,
    /// One-based feature handle from the imported twin.
    pub feature:u64,
    /// Centre-ray intersection, absent when only the uncertainty volume reaches the triangle.
    pub nominal:Option<SurfaceHit>,
    /// Conservative conditional position box; may overapproximate triangle boundaries.
    pub bounds:Option<Bounds3>,
    /// Plane denominator crosses zero; depth is limited only by search and triangle bounds.
    pub grazing:bool,
    /// Nominal segment test only; never a certified visibility claim or pruning rule.
    pub nominal_occluded:Option<bool>,
}

/// Immutable geometry-derived projection, always retaining the original observation.
#[derive(Clone, Debug)]
pub struct ContactProjection {
    observation:ContactObservation,
    camera:TrackingCamera,
    twin_digest:[u8;32],
    quality:ProjectionQuality,
    hypotheses:Vec<ContactHypothesis>,
}
impl ContactProjection {
    /// Original source-bearing 2D input, unchanged even when support is unavailable.
    pub fn observation(&self)->ContactObservation {self.observation}
    /// Exact camera snapshot used by the operation.
    pub fn camera(&self)->TrackingCamera {self.camera}
    /// Whole imported-package identity.
    pub fn twin_digest(&self)->[u8;32] {self.twin_digest}
    /// Bounds/nominal/unknown classification.
    pub fn quality(&self)->ProjectionQuality {self.quality}
    /// All retained supports, in triangle order. Empty does not imply physical absence.
    pub fn hypotheses(&self)->&[ContactHypothesis] {&self.hypotheses}
}

/// Lift a selected contact rectangle through calibrated camera and uncertain terrain.
///
/// Bounds cover declared independent coordinate intervals without assuming independent
/// statistical errors. Unknown geometry/calibration produces a labelled nominal result.
/// No triangulation, identity association, privacy grant, or detector is invented here.
pub fn project_contact(twin:&PropertyTwin,camera:TrackingCamera,observation:ContactObservation,
    options:ProjectionOptions,budget:&mut WorkBudget<'_>)->Result<ContactProjection,TwinError> {
    budget.charge(0)?;
    validate(camera,observation,twin.basis(),options)?;
    let mut output=ContactProjection{observation,camera,twin_digest:twin.digest(),
        quality:ProjectionQuality::ContactUnknown,hypotheses:Vec::new()};
    if !observation.visible_contact {return Ok(output);}
    let pixel=[observation.pixel_min[0]*0.5+observation.pixel_max[0]*0.5,
        observation.pixel_min[1]*0.5+observation.pixel_max[1]*0.5];
    let ray=camera.pose.ray(camera.intrinsics,pixel)?;
    let nominal=twin.mesh().support_hits(twin.basis(),ray,options.near,options.far,
        options.max_hypotheses,budget)?;
    output.hypotheses.try_reserve_exact(options.max_hypotheses).map_err(|_|TwinError::Limit)?;
    if let (Some(error),Some(map_error))=(camera.error,twin.geometry_error()) {
        let (origin,direction)=ray_bounds(camera,observation,error)?;
        output.quality=ProjectionQuality::Bounded;
        for (i,triangle) in twin.triangles().iter().enumerate() {
            budget.charge(256)?;
            if !triangle.support {continue;}
            let points=triangle.vertices.map(|v|twin.vertices()[v as usize]);
            if let Some((bounds,grazing))=surface_bounds(points,map_error,origin,direction,options)? {
                if output.hypotheses.len()==options.max_hypotheses {return Err(TwinError::Limit);}
                let hit=nominal.iter().find(|hit|hit.triangle as usize==i).copied();
                output.hypotheses.push(ContactHypothesis{triangle:i as u32,feature:triangle.feature,
                    nominal:hit,bounds:Some(bounds),grazing,
                    nominal_occluded:occluded(twin,camera,hit,budget)?});
            }
        }
    } else {
        output.quality=ProjectionQuality::NominalOnly;
        for hit in nominal {
            output.hypotheses.push(ContactHypothesis{triangle:hit.triangle,feature:hit.feature,
                nominal:Some(hit),bounds:None,grazing:false,
                nominal_occluded:occluded(twin,camera,Some(hit),budget)?});
        }
        output.hypotheses.sort_by_key(|hit|hit.triangle);
    }
    budget.charge(0)?;
    Ok(output)
}
fn validate(c:TrackingCamera,o:ContactObservation,basis:GeometryBasis,opt:ProjectionOptions)->Result<(),TwinError> {
    if c.geometry!=basis || c.camera==0 || c.calibration==0 || c.image_domain==0 || c.clock==0
        || o.evidence==[0;32] || o.track==0 || o.exposure==0 || o.camera!=c.camera
        || o.image_domain!=c.image_domain || o.clock!=c.clock || c.validity[0]>c.validity[1]
        || o.capture[0]>o.capture[1] || o.capture[0]<c.validity[0] || o.capture[1]>c.validity[1] {
        return Err(TwinError::Basis);
    }
    if !c.intrinsics.contains(o.pixel_min) || !c.intrinsics.contains(o.pixel_max)
        || (0..2).any(|i|o.pixel_min[i]>o.pixel_max[i]) || !opt.near.is_finite()
        || !opt.far.is_finite() || opt.near<=0.0 || opt.far<=opt.near || opt.far>1e9 {
        return Err(TwinError::Numeric);
    }
    if opt.max_hypotheses==0 || opt.max_hypotheses>128 {return Err(TwinError::Limit);}
    if let Some(e)=c.error {
        if e.centre.iter().chain(e.focal.iter()).chain(e.principal.iter())
            .any(|x|!x.is_finite() || *x<0.0 || *x>1e12)
            || !e.rotation_entry.is_finite() || !(0.0..=2.0).contains(&e.rotation_entry)
            || (0..2).any(|i|e.focal[i]>=c.intrinsics.focal_lengths()[i]) {
            return Err(TwinError::Numeric);
        }
    }
    Ok(())
}
fn occluded(twin:&PropertyTwin,camera:TrackingCamera,hit:Option<SurfaceHit>,budget:&mut WorkBudget<'_>)->Result<Option<bool>,TwinError> {
    if let Some(hit)=hit {
        let margin=(hit.distance*1e-8).min(hit.distance*0.25);
        return Ok(Some(twin.mesh().segment_occluded(twin.basis(),camera.pose.center(),hit.point,margin,budget)?));
    }
    Ok(None)
}
fn ray_bounds(c:TrackingCamera,o:ContactObservation,e:ProjectionError)->Result<(I3,I3),TwinError> {
    let [fx,fy]=c.intrinsics.focal_lengths(); let [cx,cy]=c.intrinsics.principal_point();
    let x=Interval::new(o.pixel_min[0],o.pixel_max[0])?.sub(Interval::around(cx,e.principal[0])?)?
        .div(Interval::around(fx,e.focal[0])?)?;
    let y=Interval::new(o.pixel_min[1],o.pixel_max[1])?.sub(Interval::around(cy,e.principal[1])?)?
        .div(Interval::around(fy,e.focal[1])?)?;
    let one=Interval::point(1.0)?;
    let length=x.square()?.add(y.square()?)?.add(one)?.sqrt()?;
    let bearing=[x.div(length)?,y.div(length)?,one.div(length)?];
    let centre=c.pose.center();let rotation=c.pose.rotation();
    let mut origin=[Interval::point(0.0)?;3];let mut direction=origin;
    for i in 0..3 {
        origin[i]=Interval::around(centre[i],e.centre[i])?;
        direction[i]=dot([Interval::around(rotation[0][i],e.rotation_entry)?,
            Interval::around(rotation[1][i],e.rotation_entry)?,
            Interval::around(rotation[2][i],e.rotation_entry)?],bearing)?;
    }
    Ok((origin,direction))
}
fn surface_bounds(points:[[f64;3];3],error:f64,origin:I3,direction:I3,opt:ProjectionOptions)
    ->Result<Option<(Bounds3,bool)>,TwinError> {
    let mut vertices=[[Interval::point(0.0)?;3];3];
    for i in 0..3 {for j in 0..3 {vertices[i][j]=Interval::around(points[i][j],error)?;}}
    let normal=cross(sub(vertices[1],vertices[0])?,sub(vertices[2],vertices[0])?)?;
    let denominator=dot(normal,direction)?;
    let mut distance=Interval::new(opt.near,opt.far)?;
    let grazing=denominator.contains(0.0);
    if !grazing {
        let plane=dot(normal,sub(vertices[0],origin)?)?.div(denominator)?;
        let Some(value)=distance.intersect(plane) else {return Ok(None);};distance=value;
    }
    let mut triangle_bounds=[Interval::point(0.0)?;3];
    for axis in 0..3 {
        triangle_bounds[axis]=Interval::new(vertices.iter().map(|v|v[axis].lower()).fold(f64::INFINITY,f64::min),
            vertices.iter().map(|v|v[axis].upper()).fold(f64::NEG_INFINITY,f64::max))?;
        if !direction[axis].contains(0.0) {
            let slab=triangle_bounds[axis].sub(origin[axis])?.div(direction[axis])?;
            let Some(value)=distance.intersect(slab) else {return Ok(None);};distance=value;
        }
    }
    let mut position=triangle_bounds;
    for axis in 0..3 {
        let ray=origin[axis].add(distance.mul(direction[axis])?)?;
        let Some(value)=ray.intersect(triangle_bounds[axis]) else {return Ok(None);};position[axis]=value;
    }
    // AABB overlap alone would invent support in the empty half of every triangle.
    // Interval oriented edge tests reject only when the entire candidate box is outside.
    for edge in 0..3 {
        let a=vertices[edge];let b=vertices[(edge+1)%3];
        if dot(cross(sub(b,a)?,sub(position,a)?)?,normal)?.upper()<0.0 {return Ok(None);}
    }
    Ok(Some((Bounds3(position),grazing)))
}
