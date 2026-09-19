use crate::math::{V3, checked, cross, dot, norm, scale, sub};
use crate::{GeometryError, Ray, WorkBudget};

/// Owner-resolved process-local namespace and immutable geometry revision.
///
/// These handles must be resolved from canonical property/twin identities by the
/// owner. They are not durable IDs, capabilities, or proof of valid calibration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeometryBasis {
    property: u64,
    revision: u64,
}

impl GeometryBasis {
    /// Both handles must be nonzero. Reusing a revision for changed geometry is invalid.
    pub fn new(property: u64, revision: u64) -> Result<Self, GeometryError> {
        if property == 0 || revision == 0 {
            return Err(GeometryError::BasisMismatch);
        }
        Ok(Self { property, revision })
    }
}

/// Resource limits for an evaluated, indexed triangle import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeshLimits {
    /// Maximum vertices; cannot exceed the kernel ceiling of 262,144.
    pub max_vertices: usize,
    /// Maximum triangles; cannot exceed the kernel ceiling of 524,288.
    pub max_triangles: usize,
}

impl Default for MeshLimits {
    fn default() -> Self {
        Self {
            max_vertices: 262_144,
            max_triangles: 524_288,
        }
    }
}

/// One evaluated physical triangle and its independently declared semantic roles.
///
/// The importer must exclude retired meshes and construction/reference helpers.
/// Render visibility, material alpha, and Blender parenting cannot infer these roles.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IndexedTriangle {
    /// Three indexes into evaluated property-world vertices.
    pub vertices: [u32; 3],
    /// Nonzero owner-resolved feature handle; many triangles may share a feature.
    pub feature: u64,
    /// Whether the triangle is an admissible contact/support surface.
    pub support: bool,
    /// Whether it occludes the qualified optical path; independent of walkability.
    pub opaque: bool,
}

/// One exact scalar intersection with lineage into the imported triangle table.
#[derive(Clone, Copy, PartialEq)]
pub struct SurfaceHit {
    /// Distance along the normalized ray in property-world units.
    pub distance: f64,
    /// Intersection point in property-world coordinates.
    pub point: V3,
    /// Weights corresponding to the triangle's three vertex indices.
    pub barycentric: V3,
    /// Unit oriented normal; intersection itself is double-sided.
    pub normal: V3,
    /// Feature handle from the supplied triangle.
    pub feature: u64,
    /// Ordinal in the exact imported triangle table, not an independently durable ID.
    pub triangle: u32,
}

impl std::fmt::Debug for SurfaceHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurfaceHit")
            .field("triangle", &self.triangle)
            .finish_non_exhaustive()
    }
}

/// Immutable checked evaluated geometry, independent of authoring/runtime software.
#[derive(Clone)]
pub struct TriangleMesh {
    basis: GeometryBasis,
    vertices: Vec<V3>,
    triangles: Vec<IndexedTriangle>,
}

impl std::fmt::Debug for TriangleMesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TriangleMesh")
            .field("vertex_count", &self.vertices.len())
            .field("triangle_count", &self.triangles.len())
            .finish_non_exhaustive()
    }
}

impl TriangleMesh {
    /// Import already evaluated property-world coordinates, atomically after validation.
    ///
    /// This is a typed mesh import, not a `.blend`/GLB parser. The owner retains
    /// source hashes, unit/axis conversions, instance mappings, and uncertainty.
    pub fn from_indexed(
        basis: GeometryBasis,
        vertices: &[V3],
        triangles: &[IndexedTriangle],
        limits: MeshLimits,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, GeometryError> {
        budget.charge(0)?;
        if vertices.is_empty() || triangles.is_empty() {
            return Err(GeometryError::EmptyInput);
        }
        if limits.max_vertices > 262_144
            || limits.max_triangles > 524_288
            || vertices.len() > limits.max_vertices
            || triangles.len() > limits.max_triangles
        {
            return Err(GeometryError::LimitExceeded);
        }
        for vertex in vertices {
            budget.charge(1)?;
            checked(*vertex)?;
        }
        for triangle in triangles {
            budget.charge(1)?;
            if triangle.feature == 0 {
                return Err(GeometryError::InvalidIndex);
            }
            let [a, b, c] = triangle_vertices(vertices, *triangle)?;
            let e1 = sub(b, a);
            let e2 = sub(c, a);
            let product = norm(e1) * norm(e2);
            if product <= 1e-24 || norm(cross(e1, e2)) <= 1e-12 * product {
                return Err(GeometryError::Degenerate);
            }
        }
        let mut owned_vertices = Vec::new();
        owned_vertices
            .try_reserve_exact(vertices.len())
            .map_err(|_| GeometryError::LimitExceeded)?;
        owned_vertices.extend_from_slice(vertices);
        let mut owned_triangles = Vec::new();
        owned_triangles
            .try_reserve_exact(triangles.len())
            .map_err(|_| GeometryError::LimitExceeded)?;
        owned_triangles.extend_from_slice(triangles);
        budget.charge(0)?;
        Ok(Self {
            basis,
            vertices: owned_vertices,
            triangles: owned_triangles,
        })
    }

    /// Exact basis to which all world queries must be pinned.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Imported triangle count, for resource planning rather than coverage claims.
    pub fn triangle_count(&self) -> usize {
        self.triangles.len()
    }

    /// Return every admitted support intersection, nearest first, preserving layers.
    ///
    /// Coincident triangles remain separate lineage records; consumers must not
    /// count them as independent evidence. Exceeding `max_hits` fails rather than
    /// silently omitting a support hypothesis. This is not an occlusion certificate.
    pub fn support_hits(
        &self,
        basis: GeometryBasis,
        ray: Ray,
        near: f64,
        far: f64,
        max_hits: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Vec<SurfaceHit>, GeometryError> {
        self.validate_query(basis, near, far, budget)?;
        if max_hits == 0 || max_hits > 4096 {
            return Err(GeometryError::LimitExceeded);
        }
        let mut hits = Vec::new();
        hits.try_reserve(max_hits)
            .map_err(|_| GeometryError::LimitExceeded)?;
        for (index, triangle) in self.triangles.iter().enumerate() {
            budget.charge(1)?;
            if !triangle.support {
                continue;
            }
            if let Some(hit) = intersect(&self.vertices, *triangle, index as u32, ray, near, far)? {
                if hits.len() == max_hits {
                    return Err(GeometryError::LimitExceeded);
                }
                hits.push(hit);
            }
        }
        budget.charge((hits.len() as u64) * 12)?;
        hits.sort_by(|a, b| {
            a.distance
                .total_cmp(&b.distance)
                .then(a.feature.cmp(&b.feature))
                .then(a.triangle.cmp(&b.triangle))
        });
        budget.charge(0)?;
        Ok(hits)
    }

    /// Test opaque geometry strictly inside a world-space segment.
    ///
    /// `endpoint_margin` excludes endpoint self-intersections in world units.
    /// A clear result concerns this mesh only, not unknown/dynamic occluders,
    /// camera health, useful pixel scale, detector recall, or physical visibility.
    pub fn segment_occluded(
        &self,
        basis: GeometryBasis,
        from: V3,
        to: V3,
        endpoint_margin: f64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<bool, GeometryError> {
        checked(from)?;
        checked(to)?;
        let delta = sub(to, from);
        let length = norm(delta);
        if !endpoint_margin.is_finite() || endpoint_margin < 0.0 || length <= 2.0 * endpoint_margin
        {
            return Err(GeometryError::Degenerate);
        }
        self.validate_query(basis, endpoint_margin, length - endpoint_margin, budget)?;
        let ray = Ray::new(from, delta)?;
        for (index, triangle) in self.triangles.iter().enumerate() {
            budget.charge(1)?;
            if triangle.opaque
                && intersect(
                    &self.vertices,
                    *triangle,
                    index as u32,
                    ray,
                    endpoint_margin,
                    length - endpoint_margin,
                )?
                .is_some()
            {
                budget.charge(0)?;
                return Ok(true);
            }
        }
        budget.charge(0)?;
        Ok(false)
    }

    fn validate_query(
        &self,
        basis: GeometryBasis,
        near: f64,
        far: f64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<(), GeometryError> {
        budget.charge(0)?;
        if basis != self.basis {
            return Err(GeometryError::BasisMismatch);
        }
        if !near.is_finite() || !far.is_finite() || near < 0.0 || far <= near || far > 1e12 {
            return Err(GeometryError::OutOfRange);
        }
        Ok(())
    }
}

fn triangle_vertices(vertices: &[V3], triangle: IndexedTriangle) -> Result<[V3; 3], GeometryError> {
    let mut points = [[0.0; 3]; 3];
    for (point, index) in points.iter_mut().zip(triangle.vertices) {
        *point = *vertices
            .get(index as usize)
            .ok_or(GeometryError::InvalidIndex)?;
    }
    Ok(points)
}

fn intersect(
    vertices: &[V3],
    triangle: IndexedTriangle,
    index: u32,
    ray: Ray,
    near: f64,
    far: f64,
) -> Result<Option<SurfaceHit>, GeometryError> {
    let [a, b, c] = triangle_vertices(vertices, triangle)?;
    let e1 = sub(b, a);
    let e2 = sub(c, a);
    let p = cross(ray.direction(), e2);
    let det = dot(e1, p);
    if det.abs() <= 1e-12 * norm(e1) * norm(e2) {
        return Ok(None);
    }
    let tvec = sub(ray.origin(), a);
    let u = dot(tvec, p) / det;
    let q = cross(tvec, e1);
    let v = dot(ray.direction(), q) / det;
    if u < -1e-10 || v < -1e-10 || u + v > 1.0 + 1e-10 {
        return Ok(None);
    }
    let distance = dot(e2, q) / det;
    if distance < near || distance > far {
        return Ok(None);
    }
    let normal = cross(e1, e2);
    Ok(Some(SurfaceHit {
        distance,
        point: ray.at(distance)?,
        barycentric: [1.0 - u - v, u, v],
        normal: scale(normal, 1.0 / norm(normal)),
        feature: triangle.feature,
        triangle: index,
    }))
}
