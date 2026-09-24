#![forbid(unsafe_code)]
//! Exact integer convex-polygon/box predicates. No floating point, pixel-center
//! shortcut or unqualified conversion of an image region to a physical surface.
use super::{
    ImageDetection, ImageZoneError, ImageZoneRelation, ImageZoneSpec, MAX_ZONE_VERTICES,
    WorkBudget, reserve,
};

pub(super) fn normalize(
    zone: &ImageZoneSpec,
    dimensions: [u32; 2],
    budget: &mut WorkBudget<'_>,
) -> Result<ImageZoneSpec, ImageZoneError> {
    let n = zone.vertices.len();
    if !(3..=MAX_ZONE_VERTICES).contains(&n) {
        return Err(ImageZoneError::Limit);
    }
    if zone.id == 0 || zone.margin > 65536 || zone.dwell_ns == Some(0) {
        return Err(ImageZoneError::InvalidInput);
    }
    budget.charge((n * n + n) as u64)?;
    if zone
        .vertices
        .iter()
        .any(|v| v[0] > dimensions[0] || v[1] > dimensions[1])
    {
        return Err(ImageZoneError::InvalidInput);
    }
    let mut points = reserve(n)?;
    points.extend_from_slice(&zone.vertices);
    let orientation = cross(points[0], points[1], points[2]).signum();
    if orientation == 0 {
        return Err(ImageZoneError::InvalidInput);
    }
    // Every other vertex must be strictly on the interior side of every edge.
    // This rejects duplicate/collinear points, concavity and self-intersecting stars.
    for i in 0..n {
        let j = (i + 1) % n;
        for (k, point) in points.iter().enumerate() {
            if k != i && k != j && cross(points[i], points[j], *point).signum() != orientation {
                return Err(ImageZoneError::InvalidInput);
            }
        }
    }
    if orientation < 0 {
        points.reverse();
    }
    let origin = (0..n)
        .min_by_key(|i| points[*i])
        .ok_or(ImageZoneError::InvalidInput)?;
    points.rotate_left(origin);
    Ok(ImageZoneSpec {
        id: zone.id,
        vertices: points,
        margin: zone.margin,
        dwell_ns: zone.dwell_ns,
    })
}
fn cross(a: [u32; 2], b: [u32; 2], p: [u32; 2]) -> i128 {
    (i128::from(b[0]) - i128::from(a[0])) * (i128::from(p[1]) - i128::from(a[1]))
        - (i128::from(b[1]) - i128::from(a[1])) * (i128::from(p[0]) - i128::from(a[0]))
}
pub(super) fn classify(
    zone: &ImageZoneSpec,
    detection: ImageDetection,
    budget: &mut WorkBudget<'_>,
) -> Result<ImageZoneRelation, ImageZoneError> {
    budget.charge(1)?;
    if detection.partial {
        return Ok(ImageZoneRelation::Partial);
    }
    let m = i128::from(zone.margin);
    let lo = detection.min.map(|v| i128::from(v) - m);
    let hi = detection.max.map(|v| i128::from(v) + m);
    let corners = [
        [lo[0], lo[1]],
        [lo[0], hi[1]],
        [hi[0], lo[1]],
        [hi[0], hi[1]],
    ];
    let mut inside = true;
    let mut poly_min = [i128::MAX; 2];
    let mut poly_max = [i128::MIN; 2];
    for i in 0..zone.vertices.len() {
        budget.charge(16)?;
        let a = zone.vertices[i].map(i128::from);
        let b = zone.vertices[(i + 1) % zone.vertices.len()].map(i128::from);
        let mut minimum = i128::MAX;
        let mut maximum = i128::MIN;
        for p in corners {
            let side = (b[0] - a[0]) * (p[1] - a[1]) - (b[1] - a[1]) * (p[0] - a[0]);
            minimum = minimum.min(side);
            maximum = maximum.max(side);
        }
        if maximum < 0 {
            return Ok(ImageZoneRelation::Outside);
        }
        inside &= minimum > 0;
        for axis in 0..2 {
            poly_min[axis] = poly_min[axis].min(a[axis]);
            poly_max[axis] = poly_max[axis].max(a[axis]);
        }
    }
    // Polygon-edge normals alone are insufficient: include both rectangle axes.
    if (0..2).any(|i| hi[i] < poly_min[i] || lo[i] > poly_max[i]) {
        return Ok(ImageZoneRelation::Outside);
    }
    Ok(if inside {
        ImageZoneRelation::Inside
    } else {
        ImageZoneRelation::Boundary
    })
}
