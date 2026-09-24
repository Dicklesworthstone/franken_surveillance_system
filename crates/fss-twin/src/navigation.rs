#![forbid(unsafe_code)]
//! Exact-edge support topology and bounded route extraction from an imported twin.
//!
//! These are conditional center/contact paths, not body-clearance certificates.
//! Disconnected or profile-excluded surfaces never prove physical impossibility.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use crate::{PropertyTwin, SurfaceKind, TwinError};
use fss_geometry::{GeometryBasis, WorkBudget};

type Point = [f64; 3];
type PointKey = [u64; 3];
type EdgeKey = [PointKey; 2];

/// Maximum source triangles admitted to this reference navigation compiler.
pub const MAX_NAVIGATION_TRIANGLES: usize = 65_536;

/// Navigation failures; none authorizes dropping evidence or a protected route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavigationError {
    /// Invalid or stale imported input, cancellation, or exhausted work budget.
    Twin(TwinError),
    /// Invalid numerical/profile/size option.
    Options,
    /// No support point exists at the supplied triangle/simplex coordinates.
    Start,
    /// A full edge has more than two incident support faces.
    NonManifold,
    /// Two support triangles occupy the exact same three coordinates.
    DuplicateFace,
    /// A count, allocation, or complete-output ceiling was exceeded.
    Limit,
}
impl From<TwinError> for NavigationError {
    fn from(error: TwinError) -> Self {
        Self::Twin(error)
    }
}
impl From<fss_geometry::GeometryError> for NavigationError {
    fn from(error: fss_geometry::GeometryError) -> Self {
        Self::Twin(error.into())
    }
}
impl std::fmt::Display for NavigationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Twin(_) => "navigation input or work failure",
            Self::Options => "invalid navigation options",
            Self::Start => "invalid support start",
            Self::NonManifold => "ambiguous support portal",
            Self::DuplicateFace => "duplicate support face",
            Self::Limit => "navigation limit exceeded",
        })
    }
}
impl std::error::Error for NavigationError {}

/// Explicit movement class; no appearance inference or identity is performed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MovementClass {
    /// A person; the only class eligible for a pedestrian preference.
    Person,
    /// A bear, without an inherited pedestrian preference.
    Bear,
    /// Another animal, without an inherited pedestrian preference.
    OtherAnimal,
    /// Unknown target class; no pedestrian preference.
    Unknown,
}

/// Owner-supplied geometric admission and soft route cost assumptions.
///
/// A portal-width threshold is only a necessary edge-width test. It does not
/// account for complete body shape, overhead clearance, doors, or moving objects.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NavigationProfile {
    class: MovementClass,
    minimum_up_cosine: f64,
    minimum_portal_width: f64,
    person_path_multiplier: u32,
}
impl NavigationProfile {
    /// Supply a slope threshold as cosine in [0,1], width in source units, and
    /// a cost divisor in 1..=1024. Non-person classes require a divisor of one.
    pub fn new(
        class: MovementClass,
        minimum_up_cosine: f64,
        minimum_portal_width: f64,
        person_path_multiplier: u32,
    ) -> Result<Self, NavigationError> {
        if !minimum_up_cosine.is_finite()
            || !(0.0..=1.0).contains(&minimum_up_cosine)
            || !minimum_portal_width.is_finite()
            || !(0.0..=1e12).contains(&minimum_portal_width)
            || !(1..=1024).contains(&person_path_multiplier)
            || (class != MovementClass::Person && person_path_multiplier != 1)
        {
            return Err(NavigationError::Options);
        }
        Ok(Self {
            class,
            minimum_up_cosine,
            minimum_portal_width,
            person_path_multiplier,
        })
    }
    /// Explicit class conditioning this query.
    pub fn class(self) -> MovementClass {
        self.class
    }
    /// Requested minimum absolute normal/up cosine.
    pub fn minimum_up_cosine(self) -> f64 {
        self.minimum_up_cosine
    }
    /// Necessary shared-edge width floor, not a swept-body proof.
    pub fn minimum_portal_width(self) -> f64 {
        self.minimum_portal_width
    }
    /// Soft cost divisor for pedestrian surfaces; no surface is forbidden by it.
    pub fn person_path_multiplier(self) -> u32 {
        self.person_path_multiplier
    }
    fn divisor(self, surface: SurfaceKind) -> f64 {
        if self.class == MovementClass::Person && surface == SurfaceKind::PedestrianPath {
            f64::from(self.person_path_multiplier)
        } else {
            1.0
        }
    }
    /// Remove the path preference while retaining explicit physical assumptions.
    pub fn without_preference(self) -> Self {
        Self {
            person_path_multiplier: 1,
            ..self
        }
    }
}

/// A point on one revision-bound support triangle, specified without nearest-face guessing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SupportLocation {
    triangle: u32,
    barycentric: [f64; 3],
}
impl SupportLocation {
    /// Coordinates must be a finite closed simplex. Tiny sum roundoff is normalized.
    pub fn new(triangle: u32, barycentric: [f64; 3]) -> Result<Self, NavigationError> {
        let sum: f64 = barycentric.iter().sum();
        if barycentric
            .iter()
            .any(|v| !v.is_finite() || *v < 0.0 || *v > 1.0)
            || (sum - 1.0).abs() > 1e-10
        {
            return Err(NavigationError::Start);
        }
        Ok(Self {
            triangle,
            barycentric: barycentric.map(|v| v / sum),
        })
    }
    /// Triangle ordinal, valid only with the network's exact twin digest.
    pub fn triangle(self) -> u32 {
        self.triangle
    }
    /// Closed-simplex weights in the source triangle's vertex order.
    pub fn barycentric(self) -> [f64; 3] {
        self.barycentric
    }
}

#[derive(Clone, Copy, Debug)]
struct Portal {
    neighbor: usize,
    midpoint: Point,
    width: f64,
}
#[derive(Clone, Copy, Debug)]
struct Node {
    vertices: [Point; 3],
    center: Point,
    feature: u32,
    surface: SurfaceKind,
    up_cosine: f64,
    portals: [Option<Portal>; 3],
    degree: usize,
}

/// One exact-basis, bounded reference routing query.
#[derive(Clone, Copy, Debug)]
pub struct RouteQuery {
    /// Owner-resolved property/twin revision.
    pub basis: GeometryBasis,
    /// Exact imported package hash.
    pub twin_digest: [u8; 32],
    /// Support simplex obtained from an observation or explicit hypothesis.
    pub start: SupportLocation,
    /// Zero-based destination feature ordinal in this package.
    pub destination_feature: u32,
    /// Explicit class and movement assumptions.
    pub profile: NavigationProfile,
    /// Complete polyline point bound in 1..=256; never a truncation allowance.
    pub max_points: usize,
}

/// Checked immutable exact-edge graph over explicitly declared support faces.
///
/// Equal endpoint coordinates connect even when objects use separate vertex IDs.
/// Near endpoints, point-only contacts, overlapping decks, and T-junctions do not
/// connect. No welding tolerance silently bridges a physical gap.
pub struct SupportNetwork {
    basis: GeometryBasis,
    twin_digest: [u8; 32],
    nodes: Vec<Option<Node>>,
    feature_count: usize,
    support_count: usize,
    portal_count: usize,
}
impl std::fmt::Debug for SupportNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupportNetwork")
            .field("support_count", &self.support_count)
            .field("portal_count", &self.portal_count)
            .finish_non_exhaustive()
    }
}
impl SupportNetwork {
    /// Compile topology from a validated native import. Non-manifold/duplicate
    /// support is an error, not an arbitrary selection of a convenient connection.
    pub fn compile(
        twin: &PropertyTwin,
        max_triangles: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, NavigationError> {
        budget.charge(0)?;
        if max_triangles == 0
            || max_triangles > MAX_NAVIGATION_TRIANGLES
            || twin.triangles().len() > max_triangles
        {
            return Err(NavigationError::Limit);
        }
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(twin.triangles().len())
            .map_err(|_| NavigationError::Limit)?;
        let mut faces = BTreeSet::new();
        let mut edges: BTreeMap<EdgeKey, (usize, bool)> = BTreeMap::new();
        let mut support_count = 0;
        let mut portal_count = 0;
        for (index, triangle) in twin.triangles().iter().enumerate() {
            budget.charge(128)?;
            if !triangle.support {
                nodes.push(None);
                continue;
            }
            let vertices = triangle.vertices.map(|i| twin.vertices()[i as usize]);
            let mut face = vertices.map(point_key);
            face.sort();
            if !faces.insert(face) {
                return Err(NavigationError::DuplicateFace);
            }
            let a = subtract(vertices[1], vertices[0]);
            let b = subtract(vertices[2], vertices[0]);
            let normal = cross(a, b);
            let normal_length = length(normal);
            if !normal_length.is_finite() || normal_length <= 0.0 {
                return Err(NavigationError::Twin(TwinError::Numeric));
            }
            let center = std::array::from_fn(|axis| {
                vertices[0][axis] / 3.0 + vertices[1][axis] / 3.0 + vertices[2][axis] / 3.0
            });
            let feature = u32::try_from(triangle.feature - 1).map_err(|_| TwinError::Reference)?;
            let surface = twin
                .features()
                .get(feature as usize)
                .ok_or(TwinError::Reference)?
                .surface;
            nodes.push(Some(Node {
                vertices,
                center,
                feature,
                surface,
                up_cosine: (normal[2].abs() / normal_length).min(1.0),
                portals: [None; 3],
                degree: 0,
            }));
            support_count += 1;
            for edge in [[0, 1], [1, 2], [2, 0]] {
                let p = vertices[edge[0]];
                let q = vertices[edge[1]];
                let mut key = [point_key(p), point_key(q)];
                key.sort();
                if let Some((prior, paired)) = edges.get_mut(&key) {
                    if *paired {
                        return Err(NavigationError::NonManifold);
                    }
                    let midpoint = std::array::from_fn(|axis| p[axis] / 2.0 + q[axis] / 2.0);
                    let width = length(subtract(p, q));
                    add_portal(
                        &mut nodes,
                        *prior,
                        Portal {
                            neighbor: index,
                            midpoint,
                            width,
                        },
                    )?;
                    add_portal(
                        &mut nodes,
                        index,
                        Portal {
                            neighbor: *prior,
                            midpoint,
                            width,
                        },
                    )?;
                    *paired = true;
                    portal_count += 1;
                } else {
                    edges.insert(key, (index, false));
                }
            }
        }
        budget.charge(0)?;
        Ok(Self {
            basis: twin.basis(),
            twin_digest: twin.digest(),
            nodes,
            feature_count: twin.features().len(),
            support_count,
            portal_count,
        })
    }
    /// Immutable geometry basis; process-local handles confer no capability.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Exact package identity, checked again at every query.
    pub fn twin_digest(&self) -> [u8; 32] {
        self.twin_digest
    }
    /// Admitted support faces, not independently measured surfaces.
    pub fn support_count(&self) -> usize {
        self.support_count
    }
    /// Undirected exact shared-edge connections.
    pub fn portal_count(&self) -> usize {
        self.portal_count
    }
    /// Resolve a validated source-simplex location without choosing another surface.
    pub fn point(&self, location: SupportLocation) -> Result<Point, NavigationError> {
        let node = self
            .node(location.triangle as usize)
            .ok_or(NavigationError::Start)?;
        Ok(std::array::from_fn(|axis| {
            (0..3)
                .map(|i| node.vertices[i][axis] * location.barycentric[i])
                .sum()
        }))
    }
    /// Find a minimum-cost centroid/portal corridor to an admitted triangle of a
    /// destination feature. Costs are not physical travel times or probabilities.
    ///
    /// This is a shortest path in the discrete reference graph, not a continuous
    /// geodesic or an enumeration of every reachable route. No width/slope default
    /// is inferred from class. All refusals concern the supplied model/profile.
    pub fn route_to_feature(
        &self,
        query: RouteQuery,
        budget: &mut WorkBudget<'_>,
    ) -> Result<RouteSearch, NavigationError> {
        budget.charge(0)?;
        let RouteQuery {
            basis,
            twin_digest,
            start,
            destination_feature,
            profile,
            max_points,
        } = query;
        if self.basis != basis || self.twin_digest != twin_digest {
            return Err(NavigationError::Twin(TwinError::Basis));
        }
        if max_points == 0 || max_points > 256 {
            return Err(NavigationError::Limit);
        }
        if destination_feature as usize >= self.feature_count {
            return Err(TwinError::Reference.into());
        }
        let source = start.triangle as usize;
        let first = self.node(source).ok_or(NavigationError::Start)?;
        let position = self.point(start)?;
        if first.up_cosine < profile.minimum_up_cosine {
            return Ok(RouteSearch {
                outcome: RouteOutcome::StartExcludedByProfile,
                visited: 0,
            });
        }
        let mut targets = 0;
        for node in self.nodes.iter().flatten() {
            budget.charge(1)?;
            if node.feature == destination_feature && node.up_cosine >= profile.minimum_up_cosine {
                targets += 1;
            }
        }
        if targets == 0 {
            return Ok(RouteSearch {
                outcome: RouteOutcome::NoAdmissibleDestination,
                visited: 0,
            });
        }
        if first.feature == destination_feature {
            return Ok(RouteSearch {
                outcome: RouteOutcome::Found(SurfaceRoute {
                    basis: self.basis,
                    twin_digest: self.twin_digest,
                    points: vec![position],
                    triangles: vec![start.triangle],
                    destination_feature,
                    weighted_cost: 0.0,
                    distance: 0.0,
                    profile,
                    all_pedestrian: first.surface == SurfaceKind::PedestrianPath,
                }),
                visited: 1,
            });
        }
        let n = self.nodes.len();
        let mut costs = filled(n, f64::INFINITY)?;
        let mut previous: Vec<Option<(usize, Point)>> = filled(n, None)?;
        let mut settled = filled(n, false)?;
        let mut heap = BinaryHeap::new();
        heap.try_reserve(n.saturating_mul(3).saturating_add(1))
            .map_err(|_| NavigationError::Limit)?;
        costs[source] = length(subtract(position, first.center)) / profile.divisor(first.surface);
        heap.push(QueueEntry {
            cost: costs[source],
            node: source,
        });
        let mut visited = 0;
        while let Some(entry) = heap.pop() {
            budget.charge(64)?;
            if settled[entry.node] || entry.cost != costs[entry.node] {
                continue;
            }
            settled[entry.node] = true;
            visited += 1;
            let node = self.node(entry.node).ok_or(TwinError::Reference)?;
            if node.feature == destination_feature {
                let route = self.reconstruct(
                    PathEndpoint {
                        source,
                        target: entry.node,
                        position,
                        weighted_cost: entry.cost,
                    },
                    &previous,
                    profile,
                    max_points,
                    budget,
                )?;
                return Ok(RouteSearch {
                    outcome: RouteOutcome::Found(route),
                    visited,
                });
            }
            for portal in node.portals.iter().flatten() {
                budget.charge(32)?;
                let next = self.node(portal.neighbor).ok_or(TwinError::Reference)?;
                if settled[portal.neighbor]
                    || portal.width < profile.minimum_portal_width
                    || next.up_cosine < profile.minimum_up_cosine
                {
                    continue;
                }
                let candidate = entry.cost
                    + length(subtract(node.center, portal.midpoint))
                        / profile.divisor(node.surface)
                    + length(subtract(next.center, portal.midpoint))
                        / profile.divisor(next.surface);
                if !candidate.is_finite() {
                    return Err(TwinError::Numeric.into());
                }
                if candidate < costs[portal.neighbor] {
                    costs[portal.neighbor] = candidate;
                    previous[portal.neighbor] = Some((entry.node, portal.midpoint));
                    heap.push(QueueEntry {
                        cost: candidate,
                        node: portal.neighbor,
                    });
                }
            }
        }
        budget.charge(0)?;
        Ok(RouteSearch {
            outcome: RouteOutcome::NoModeledConnection,
            visited,
        })
    }
    fn node(&self, index: usize) -> Option<&Node> {
        self.nodes.get(index)?.as_ref()
    }
    fn reconstruct(
        &self,
        endpoint: PathEndpoint,
        previous: &[Option<(usize, Point)>],
        profile: NavigationProfile,
        max_points: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<SurfaceRoute, NavigationError> {
        let PathEndpoint {
            source,
            target,
            position,
            weighted_cost,
        } = endpoint;
        let mut corridor = Vec::new();
        corridor
            .try_reserve(max_points)
            .map_err(|_| NavigationError::Limit)?;
        let mut cursor = target;
        loop {
            budget.charge(1)?;
            if corridor.len() == max_points {
                return Err(NavigationError::Limit);
            }
            corridor.push(cursor as u32);
            if cursor == source {
                break;
            }
            cursor = previous[cursor].ok_or(TwinError::Reference)?.0;
        }
        corridor.reverse();
        let mut points = Vec::new();
        points
            .try_reserve_exact(max_points)
            .map_err(|_| NavigationError::Limit)?;
        push_point(&mut points, position, max_points)?;
        push_point(
            &mut points,
            self.node(source).ok_or(TwinError::Reference)?.center,
            max_points,
        )?;
        let mut all_pedestrian = true;
        for (index, triangle) in corridor.iter().enumerate() {
            budget.charge(1)?;
            let node = self.node(*triangle as usize).ok_or(TwinError::Reference)?;
            all_pedestrian &= node.surface == SurfaceKind::PedestrianPath;
            if index != 0 {
                push_point(
                    &mut points,
                    previous[*triangle as usize].ok_or(TwinError::Reference)?.1,
                    max_points,
                )?;
                push_point(&mut points, node.center, max_points)?;
            }
        }
        let distance = points
            .windows(2)
            .map(|p| length(subtract(p[1], p[0])))
            .sum::<f64>();
        if !distance.is_finite() {
            return Err(TwinError::Numeric.into());
        }
        budget.charge(0)?;
        Ok(SurfaceRoute {
            basis: self.basis,
            twin_digest: self.twin_digest,
            points,
            triangles: corridor,
            destination_feature: self.node(target).ok_or(TwinError::Reference)?.feature,
            weighted_cost,
            distance,
            profile,
            all_pedestrian,
        })
    }
}

/// Complete query result, including model-relative non-route outcomes.
#[derive(Clone, Debug, PartialEq)]
pub struct RouteSearch {
    /// A path or the reason this exact graph/profile supplied none.
    pub outcome: RouteOutcome,
    /// Number of settled support nodes, for deterministic cost accounting.
    pub visited: usize,
}
/// Non-route cases are not evidence of physical absence or an impassable property.
#[derive(Clone, Debug, PartialEq)]
pub enum RouteOutcome {
    /// A complete route in the selected finite graph.
    Found(SurfaceRoute),
    /// The observed support exceeds the supplied slope condition.
    StartExcludedByProfile,
    /// The feature has no support face admitted by this profile.
    NoAdmissibleDestination,
    /// No exact-edge connection survives the supplied profile.
    NoModeledConnection,
}
/// Immutable nominal corridor preserving every traversed triangle and portal.
#[derive(Clone, Debug, PartialEq)]
pub struct SurfaceRoute {
    basis: GeometryBasis,
    twin_digest: [u8; 32],
    points: Vec<Point>,
    triangles: Vec<u32>,
    destination_feature: u32,
    weighted_cost: f64,
    distance: f64,
    profile: NavigationProfile,
    all_pedestrian: bool,
}
impl SurfaceRoute {
    /// Exact property/twin revision supporting this path.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Exact package digest; a remesh must not reuse the route's triangle ordinals.
    pub fn twin_digest(&self) -> [u8; 32] {
        self.twin_digest
    }
    /// Contact-center polyline in source units; not an independently observed track.
    pub fn points(&self) -> &[Point] {
        &self.points
    }
    /// Original triangle ordinals; resolve with the exact input twin.
    pub fn triangles(&self) -> &[u32] {
        &self.triangles
    }
    /// Zero-based feature ordinal of the selected destination.
    pub fn destination_feature(&self) -> u32 {
        self.destination_feature
    }
    /// Graph objective value; never divide this by speed to estimate elapsed time.
    pub fn weighted_cost(&self) -> f64 {
        self.weighted_cost
    }
    /// Actual polyline length, before any metric scale conversion.
    pub fn distance(&self) -> f64 {
        self.distance
    }
    /// Class and admission/cost assumptions used to choose the corridor.
    pub fn profile(&self) -> NavigationProfile {
        self.profile
    }
    /// Whether every traversed support face explicitly has pedestrian-path semantics.
    pub fn all_pedestrian(&self) -> bool {
        self.all_pedestrian
    }
}

struct PathEndpoint {
    source: usize,
    target: usize,
    position: Point,
    weighted_cost: f64,
}

#[derive(Clone, Copy, Debug)]
struct QueueEntry {
    cost: f64,
    node: usize,
}
impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.node == other.node
    }
}
impl Eq for QueueEntry {}
impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .cost
            .total_cmp(&self.cost)
            .then_with(|| other.node.cmp(&self.node))
    }
}
impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
fn filled<T: Clone>(n: usize, value: T) -> Result<Vec<T>, NavigationError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(n)
        .map_err(|_| NavigationError::Limit)?;
    output.resize(n, value);
    Ok(output)
}
fn add_portal(
    nodes: &mut [Option<Node>],
    index: usize,
    portal: Portal,
) -> Result<(), NavigationError> {
    let node = nodes
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(TwinError::Reference)?;
    if node.degree == 3 {
        return Err(NavigationError::NonManifold);
    }
    node.portals[node.degree] = Some(portal);
    node.degree += 1;
    Ok(())
}
fn push_point(
    points: &mut Vec<Point>,
    point: Point,
    maximum: usize,
) -> Result<(), NavigationError> {
    if points.last() == Some(&point) {
        return Ok(());
    }
    if points.len() == maximum {
        return Err(NavigationError::Limit);
    }
    points.push(point);
    Ok(())
}
fn point_key(point: Point) -> PointKey {
    point.map(|v| if v == 0.0 { 0 } else { v.to_bits() })
}
fn subtract(a: Point, b: Point) -> Point {
    std::array::from_fn(|i| a[i] - b[i])
}
fn length(a: Point) -> f64 {
    a[0].hypot(a[1]).hypot(a[2])
}
fn cross(a: Point, b: Point) -> Point {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
