#![forbid(unsafe_code)]
//! Site overlap, ground-plane homography, transit-corridor, and failure-domain topology registry.
//!
//! Declares how cameras physically overlap (calibrated image→ground homographies, coarse shared
//! zones, or directed transit corridors) and which common-cause failure domains each camera
//! depends on (`wifi:home`, `power:main`, `poe_switch:1`, `host:edge1`, `vendor:wyze`, etc.).
//! Transitive common-cause clustering contracts cameras sharing any declared failure domain into
//! one dependency cluster, mirroring `fss-fusion` independence semantics.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::event::MAX_ZONE_ID_LEN;
use fss_core::{CanonicalEncoder, ContentDigest, SensorId};

use super::LiveCorroborateError;
pub use super::homography::{CameraHomography, SpatialRelation, ground_distance};

/// Canonical digest domain for [`SiteTopologyRegistry`] commitments.
pub const LIVE_CORROBORATE_TOPOLOGY_DOMAIN: &str = "fss.live_corroborate.topology.v1";
/// Canonical digest domain for transitive common-cause cluster identities.
pub const LIVE_CORROBORATE_CLUSTER_DOMAIN: &str = "fss.live_corroborate.cluster.v1";

/// Maximum registered cameras per site topology.
pub const MAX_TOPOLOGY_CAMERAS: usize = 64;
/// Maximum explicit declared failure domains per camera (leaves room for cluster ID in `fss-fusion`).
pub const MAX_DECLARED_DOMAINS_PER_CAMERA: usize = 15;
/// Maximum byte length of a single failure-domain string.
pub const MAX_DOMAIN_TEXT_BYTES: usize = 120;
/// Maximum shared-zone overlap declarations.
pub const MAX_SHARED_ZONES: usize = 64;
/// Maximum transit-corridor declarations.
pub const MAX_TRANSIT_CORRIDORS: usize = 128;
/// Maximum transit corridor upper bound (1 hour).
pub const MAX_CORRIDOR_TRANSIT_NS: u64 = 3_600_000_000_000;
/// Default simultaneous time gate for ground-homography proximity matching (2 s).
pub const DEFAULT_HOMOGRAPHY_TIME_GATE_NS: u64 = 2_000_000_000;

/// Camera declaration inside [`SiteTopologyRegistry`].
#[derive(Clone, Debug, PartialEq)]
pub struct CameraTopologyEntry {
    /// Stable camera sensor identifier.
    pub sensor_id: String,
    /// Declared common-cause failure domains (`wifi:home`, `power:main`, `poe_switch:1`, etc.).
    pub failure_domains: BTreeSet<String>,
    /// Optional calibrated 2D image → ground homography for overlapping field-of-view matching.
    pub homography: Option<CameraHomography>,
    /// Named zones observed by this camera.
    pub zones: BTreeSet<String>,
}

/// Coarse shared physical zone monitored concurrently by two or more cameras.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedZoneOverlap {
    /// Shared logical zone identifier (e.g. `front_porch`).
    pub zone_id: String,
    /// Two or more registered camera sensor IDs observing this zone.
    pub cameras: BTreeSet<String>,
    /// Maximum worst-case time separation (ns) for concurrent observation in this zone.
    pub max_separation_ns: u64,
}

/// Directed (or optionally bidirectional) physical transit corridor between two cameras' zones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitCorridor {
    /// Unique stable corridor identifier.
    pub corridor_id: String,
    /// Origin camera sensor ID.
    pub from_camera: String,
    /// Origin camera zone ID.
    pub from_zone: String,
    /// Destination camera sensor ID.
    pub to_camera: String,
    /// Destination camera zone ID.
    pub to_zone: String,
    /// Minimum physically plausible transit time (ns).
    pub min_transit_ns: u64,
    /// Maximum physically plausible transit time (ns).
    pub max_transit_ns: u64,
    /// Whether the corridor also admits reverse traversal (`to -> from`) under the same bounds.
    pub bidirectional: bool,
}

/// Transitive common-cause failure-domain cluster computed from [`SiteTopologyRegistry`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureDomainCluster {
    /// Canonical cluster support-domain ID (`live-cluster:<32-hex>`), bounded for `EventEvidence`.
    pub cluster_id: String,
    /// Registered camera sensor IDs contracted into this component.
    pub cameras: BTreeSet<String>,
    /// Union of intrinsic (`sensor:<id>`) and declared failure domains in this component.
    pub failure_domains: BTreeSet<String>,
}

/// Registry of site cameras, overlap geometry, corridors, and common-cause failure domains.
#[derive(Clone, Debug, PartialEq)]
pub struct SiteTopologyRegistry {
    /// Stable site identifier.
    pub site_id: String,
    /// Default worst-case time gate (ns) for calibrated homography proximity matches.
    pub default_homography_time_gate_ns: u64,
    /// Registered cameras keyed by `sensor_id`.
    pub cameras: BTreeMap<String, CameraTopologyEntry>,
    /// Coarse shared-zone overlap declarations.
    pub shared_zones: Vec<SharedZoneOverlap>,
    /// Physical transit-corridor declarations.
    pub transit_corridors: Vec<TransitCorridor>,
}

impl SiteTopologyRegistry {
    /// Creates an empty site topology registry with default homography time gate.
    #[must_use]
    pub fn new(site_id: impl Into<String>) -> Self {
        Self {
            site_id: site_id.into(),
            default_homography_time_gate_ns: DEFAULT_HOMOGRAPHY_TIME_GATE_NS,
            cameras: BTreeMap::new(),
            shared_zones: Vec::new(),
            transit_corridors: Vec::new(),
        }
    }

    /// Registers or replaces a camera topology entry.
    pub fn register_camera(&mut self, entry: CameraTopologyEntry) -> &mut Self {
        self.cameras.insert(entry.sensor_id.clone(), entry);
        self
    }

    /// Adds a coarse shared-zone overlap rule.
    pub fn add_shared_zone(&mut self, overlap: SharedZoneOverlap) -> &mut Self {
        self.shared_zones.push(overlap);
        self
    }

    /// Adds a physical transit-corridor rule.
    pub fn add_transit_corridor(&mut self, corridor: TransitCorridor) -> &mut Self {
        self.transit_corridors.push(corridor);
        self
    }

    /// Validates all camera IDs, failure domains, homographies, shared zones, and transit corridors.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        if !valid_text(&self.site_id, 64) {
            return Err(LiveCorroborateError::InvalidTopology("invalid site_id"));
        }
        if self.default_homography_time_gate_ns == 0 {
            return Err(LiveCorroborateError::InvalidTopology(
                "default_homography_time_gate_ns must be positive",
            ));
        }
        if self.cameras.is_empty() || self.cameras.len() > MAX_TOPOLOGY_CAMERAS {
            return Err(LiveCorroborateError::InvalidTopology(
                "topology requires 1..=64 cameras",
            ));
        }
        for (key, cam) in &self.cameras {
            if key != &cam.sensor_id {
                return Err(LiveCorroborateError::InvalidTopology(
                    "camera key != sensor_id",
                ));
            }
            SensorId::parse(cam.sensor_id.clone())?;
            if cam.failure_domains.len() > MAX_DECLARED_DOMAINS_PER_CAMERA {
                return Err(LiveCorroborateError::InvalidTopology(
                    "too many failure domains",
                ));
            }
            if cam.failure_domains.iter().any(|d| !valid_domain_label(d)) {
                return Err(LiveCorroborateError::InvalidTopology(
                    "invalid failure domain label",
                ));
            }
            if let Some(h) = &cam.homography {
                h.validate()?;
            }
            if cam.zones.iter().any(|z| !valid_text(z, MAX_ZONE_ID_LEN)) {
                return Err(LiveCorroborateError::InvalidTopology(
                    "invalid camera zone_id",
                ));
            }
        }
        self.validate_overlaps()?;
        Ok(())
    }

    fn validate_overlaps(&self) -> Result<(), LiveCorroborateError> {
        if self.shared_zones.len() > MAX_SHARED_ZONES {
            return Err(LiveCorroborateError::InvalidTopology(
                "too many shared zones",
            ));
        }
        let mut seen_shared = BTreeSet::new();
        for sz in &self.shared_zones {
            if !valid_text(&sz.zone_id, MAX_ZONE_ID_LEN) || !seen_shared.insert(sz.zone_id.as_str())
            {
                return Err(LiveCorroborateError::InvalidTopology(
                    "invalid/duplicate shared zone",
                ));
            }
            if sz.cameras.len() < 2
                || sz.max_separation_ns == 0
                || sz.cameras.iter().any(|c| !self.cameras.contains_key(c))
            {
                return Err(LiveCorroborateError::InvalidTopology(
                    "invalid shared zone cameras",
                ));
            }
        }
        if self.transit_corridors.len() > MAX_TRANSIT_CORRIDORS {
            return Err(LiveCorroborateError::InvalidTopology(
                "too many transit corridors",
            ));
        }
        let mut seen_corridors = BTreeSet::new();
        for c in &self.transit_corridors {
            if !valid_text(&c.corridor_id, 64)
                || !valid_text(&c.from_zone, MAX_ZONE_ID_LEN)
                || !valid_text(&c.to_zone, MAX_ZONE_ID_LEN)
                || !seen_corridors.insert(c.corridor_id.as_str())
            {
                return Err(LiveCorroborateError::InvalidTopology(
                    "invalid/duplicate corridor",
                ));
            }
            if c.from_camera == c.to_camera
                || !self.cameras.contains_key(&c.from_camera)
                || !self.cameras.contains_key(&c.to_camera)
                || c.max_transit_ns == 0
                || c.min_transit_ns > c.max_transit_ns
                || c.max_transit_ns > MAX_CORRIDOR_TRANSIT_NS
            {
                return Err(LiveCorroborateError::InvalidTopology(
                    "invalid transit corridor bounds",
                ));
            }
        }
        Ok(())
    }

    /// Order-invariant canonical SHA-256 commitment under [`LIVE_CORROBORATE_TOPOLOGY_DOMAIN`].
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(LIVE_CORROBORATE_TOPOLOGY_DOMAIN);
        enc.text(&self.site_id);
        enc.u64(self.default_homography_time_gate_ns);
        enc.u64(self.cameras.len() as u64);
        for cam in self.cameras.values() {
            enc.text(&cam.sensor_id);
            encode_string_set(&mut enc, &cam.failure_domains);
            match &cam.homography {
                Some(h) => {
                    enc.bool(true);
                    h.encode_canonical(&mut enc);
                }
                None => enc.bool(false),
            }
            encode_string_set(&mut enc, &cam.zones);
        }
        let mut shared: Vec<&SharedZoneOverlap> = self.shared_zones.iter().collect();
        shared.sort_by(|a, b| a.zone_id.cmp(&b.zone_id));
        enc.u64(shared.len() as u64);
        for sz in shared {
            enc.text(&sz.zone_id);
            encode_string_set(&mut enc, &sz.cameras);
            enc.u64(sz.max_separation_ns);
        }
        let mut corridors: Vec<&TransitCorridor> = self.transit_corridors.iter().collect();
        corridors.sort_by(|a, b| a.corridor_id.cmp(&b.corridor_id));
        enc.u64(corridors.len() as u64);
        for c in corridors {
            enc.text(&c.corridor_id);
            enc.text(&c.from_camera);
            enc.text(&c.from_zone);
            enc.text(&c.to_camera);
            enc.text(&c.to_zone);
            enc.u64(c.min_transit_ns);
            enc.u64(c.max_transit_ns);
            enc.bool(c.bidirectional);
        }
        ContentDigest::sha256(&enc.finish())
    }

    /// Returns declared failure domains union intrinsic `sensor:<sensor_id>`.
    #[must_use]
    pub fn effective_domains(&self, sensor_id: &str) -> Option<BTreeSet<String>> {
        let mut set = self.cameras.get(sensor_id)?.failure_domains.clone();
        set.insert(format!("sensor:{sensor_id}"));
        Some(set)
    }

    /// Computes transitive common-cause failure-domain clusters across all registered cameras.
    #[must_use]
    pub fn failure_domain_clusters(&self) -> Vec<FailureDomainCluster> {
        let cams: Vec<(&str, BTreeSet<String>)> = self
            .cameras
            .keys()
            .filter_map(|id| self.effective_domains(id).map(|d| (id.as_str(), d)))
            .collect();
        let mut parent: Vec<usize> = (0..cams.len()).collect();
        let mut owner: BTreeMap<&str, usize> = BTreeMap::new();
        for (idx, (_, domains)) in cams.iter().enumerate() {
            for domain in domains {
                if let Some(&other) = owner.get(domain.as_str()) {
                    let (a, b) = (uf_find(&mut parent, idx), uf_find(&mut parent, other));
                    if a != b {
                        parent[a.max(b)] = a.min(b);
                    }
                } else {
                    owner.insert(domain.as_str(), idx);
                }
            }
        }
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for idx in 0..cams.len() {
            groups
                .entry(uf_find(&mut parent, idx))
                .or_default()
                .push(idx);
        }
        let mut clusters: Vec<FailureDomainCluster> = groups
            .into_values()
            .map(|members| {
                let mut cameras = BTreeSet::new();
                let mut failure_domains = BTreeSet::new();
                for idx in members {
                    cameras.insert(cams[idx].0.to_owned());
                    failure_domains.extend(cams[idx].1.iter().cloned());
                }
                let mut enc = CanonicalEncoder::new();
                enc.text(LIVE_CORROBORATE_CLUSTER_DOMAIN);
                encode_string_set(&mut enc, &failure_domains);
                let digest = ContentDigest::sha256(&enc.finish());
                let hex: String = digest
                    .bytes()
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                FailureDomainCluster {
                    cluster_id: format!("live-cluster:{hex}"),
                    cameras,
                    failure_domains,
                }
            })
            .collect();
        clusters.sort_by(|a, b| a.cluster_id.cmp(&b.cluster_id));
        clusters
    }

    /// Returns the transitive [`FailureDomainCluster`] containing `sensor_id`, if registered.
    #[must_use]
    pub fn cluster_for_camera(&self, sensor_id: &str) -> Option<FailureDomainCluster> {
        self.failure_domain_clusters()
            .into_iter()
            .find(|c| c.cameras.contains(sensor_id))
    }

    /// Returns directly shared (or transitively bridging) failure domains between `a` and `b`.
    #[must_use]
    pub fn shared_domains_between(&self, a: &str, b: &str) -> BTreeSet<String> {
        let (Some(dom_a), Some(dom_b)) = (self.effective_domains(a), self.effective_domains(b))
        else {
            return BTreeSet::new();
        };
        let direct: BTreeSet<String> = dom_a.intersection(&dom_b).cloned().collect();
        if !direct.is_empty() {
            return direct;
        }
        if let Some(cluster) = self.cluster_for_camera(a)
            && cluster.cameras.contains(b)
        {
            return cluster
                .failure_domains
                .into_iter()
                .filter(|d| !d.starts_with("sensor:"))
                .collect();
        }
        BTreeSet::new()
    }

    /// Evaluates calibrated ground proximity, shared-zone overlap, or transit corridor between A & B.
    #[must_use]
    pub fn evaluate_pair_geometry(
        &self,
        sensor_a: &str,
        zone_a: &str,
        foot_a: Option<[f64; 2]>,
        sensor_b: &str,
        zone_b: &str,
        foot_b: Option<[f64; 2]>,
    ) -> SpatialRelation {
        if sensor_a == sensor_b {
            return SpatialRelation::NoOverlap;
        }
        let (Some(cam_a), Some(cam_b)) = (self.cameras.get(sensor_a), self.cameras.get(sensor_b))
        else {
            return SpatialRelation::NoOverlap;
        };
        if let (Some(h_a), Some(h_b), Some(pt_a), Some(pt_b)) =
            (&cam_a.homography, &cam_b.homography, foot_a, foot_b)
        {
            let Some(ground_a) = h_a.project(pt_a) else {
                return SpatialRelation::HorizonRefused {
                    camera: sensor_a.to_owned(),
                };
            };
            let Some(ground_b) = h_b.project(pt_b) else {
                return SpatialRelation::HorizonRefused {
                    camera: sensor_b.to_owned(),
                };
            };
            let gate = h_a.distance_gate.min(h_b.distance_gate);
            if let Some(distance) = ground_distance(ground_a, ground_b)
                && distance <= gate
            {
                let zone_id = if zone_a == zone_b {
                    zone_a.to_owned()
                } else {
                    format!("{zone_a}_overlap")
                        .chars()
                        .take(MAX_ZONE_ID_LEN)
                        .collect()
                };
                return SpatialRelation::GroundProximity {
                    distance,
                    distance_gate: gate,
                    ground_a,
                    ground_b,
                    time_gate_ns: self.default_homography_time_gate_ns,
                    zone_id,
                };
            }
        }
        if zone_a == zone_b
            && let Some(sz) = self.shared_zones.iter().find(|s| {
                s.zone_id == zone_a && s.cameras.contains(sensor_a) && s.cameras.contains(sensor_b)
            })
        {
            return SpatialRelation::SharedZone {
                zone_id: sz.zone_id.clone(),
                max_separation_ns: sz.max_separation_ns,
            };
        }
        for c in &self.transit_corridors {
            let forward = c.from_camera == sensor_a
                && c.from_zone == zone_a
                && c.to_camera == sensor_b
                && c.to_zone == zone_b;
            let reverse_ref = c.from_camera == sensor_b
                && c.from_zone == zone_b
                && c.to_camera == sensor_a
                && c.to_zone == zone_a;
            if forward || reverse_ref {
                return SpatialRelation::TransitCorridor {
                    corridor_id: c.corridor_id.clone(),
                    from_camera: c.from_camera.clone(),
                    from_zone: c.from_zone.clone(),
                    to_camera: c.to_camera.clone(),
                    to_zone: c.to_zone.clone(),
                    min_transit_ns: c.min_transit_ns,
                    max_transit_ns: c.max_transit_ns,
                    direction_a_to_b: forward,
                };
            }
            if c.bidirectional
                && c.to_camera == sensor_a
                && c.to_zone == zone_a
                && c.from_camera == sensor_b
                && c.from_zone == zone_b
            {
                return SpatialRelation::TransitCorridor {
                    corridor_id: c.corridor_id.clone(),
                    from_camera: sensor_a.to_owned(),
                    from_zone: zone_a.to_owned(),
                    to_camera: sensor_b.to_owned(),
                    to_zone: zone_b.to_owned(),
                    min_transit_ns: c.min_transit_ns,
                    max_transit_ns: c.max_transit_ns,
                    direction_a_to_b: true,
                };
            }
        }
        SpatialRelation::NoOverlap
    }
}

fn uf_find(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

fn encode_string_set(encoder: &mut CanonicalEncoder, values: &BTreeSet<String>) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

fn valid_domain_label(domain: &str) -> bool {
    if !valid_text(domain, MAX_DOMAIN_TEXT_BYTES) {
        return false;
    }
    let Some((kind, id)) = domain.split_once(':') else {
        return false;
    };
    !kind.is_empty()
        && !id.is_empty()
        && kind
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}
