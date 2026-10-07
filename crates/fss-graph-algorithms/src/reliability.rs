//! `ALG-RELIABILITY-001` — blindness probability bounds under correlated failure domains.
//!
//! Model (an owner-declared `DeviceFailureGraph` projection): every *failure domain* — a camera
//! itself, a power circuit, a switch, an access point, a recorder — fails independently with a
//! probability known only as an interval `[lo, hi]` parts per million over the declared horizon;
//! correlation is expressed by sharing a domain, never assumed away. A sensor is down when any
//! domain it belongs to fails; a zone is *blind* when every sensor observing it is down (a zone
//! with no observer is blind with certainty).
//!
//! For every zone the run enumerates every failure scenario of the domains that touch its
//! observers (at most [`MAX_RELEVANT_DOMAINS`]) and returns
//!
//! * an outward-rounded interval for `P(blind)`: blindness is monotone in every domain's
//!   failure, so the lower bound uses every domain's `lo` and the upper bound every `hi`;
//!   products are accumulated in `10^-18` fixed point, the lower bound rounded down and the
//!   upper rounded up at every step, so the true probability always lies inside;
//! * the minimal blinding domain sets (minimal cut sets) in ascending `(size, domain identity
//!   tuple)` order, each with the interval of all its domains failing together — the
//!   explanation of *why* a zone is fragile.
//!
//! The answer is exact *given the declared intervals and independence*; it is a model, not a
//! measured availability, and it grants no authority.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, MAX_NODE_ID_LEN};

/// Reliability model digest domain (`SCHEMA-DOMAIN-GRAPH-RELIABILITY-MODEL-001`).
pub const RELIABILITY_MODEL_DOMAIN: &str = "fss.graph.reliability_model.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-RELIABILITY-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.reliability_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-RELIABILITY-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.reliability_decision_path.v1";
/// Maximum failure domains touching one zone's observers.
pub const MAX_RELEVANT_DOMAINS: usize = 20;
/// Maximum zones, sensors and domains of one model.
pub const MAX_MODEL_ITEMS: usize = 4_096;
/// Maximum minimal cut sets reported per zone (the count is always exact).
pub const MAX_CUTS_PER_ZONE: usize = 64;
/// One in `10^-18` fixed point.
pub const ONE_E18: u128 = 1_000_000_000_000_000_000;

/// Registered identity (`ALG-RELIABILITY-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-RELIABILITY-001",
    algorithm_name: "reliability_bounds",
    tie_break_rule: "bound then stable scenario identity",
    complexity_witness: "scenario evaluations and convolution steps",
    output_size_witness: "<= |Scenarios| <= 2^k probability evaluations",
    exactness: "bounded_statistical",
    implementation_id: "fss-graph-algorithms:alg-reliability-001:per-zone-scenario-enumeration-outward-fixed-point:v1",
    tie_break_policy_id: "tie:cut-size-then-domain-identity-tuple:v1",
    policy_id: "graph-policy:failure-domains:independent-interval-ppm:sensor-down-if-any-domain-fails:zone-blind-if-all-observers-down:outward-fixed-point-1e-18:tie:cut-size-then-domain-identity-tuple:v1",
    complexity_bound_id: "bound:alg-reliability-001:zones-times-2-pow-k-scenarios:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `zones` zones, `sensors` observer links, and at most `k` relevant
/// domains per zone.
#[must_use]
pub fn bound(zones: u64, links: u64, k: u64) -> Vec<BoundRow> {
    let scenarios = mul(zones, 1_u64.checked_shl(k as u32).unwrap_or(u64::MAX));
    vec![
        ("scenario_evaluations", scenarios),
        ("convolution_steps", mul(scenarios, mul(2, k))),
        ("observer_checks", mul(scenarios, add(links, 1))),
        ("minimality_checks", mul(scenarios, k)),
        (OUTPUT_ENTRIES, mul(zones, add(MAX_CUTS_PER_ZONE as u64, 1))),
    ]
}

fn valid(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_NODE_ID_LEN && !id.chars().any(char::is_control)
}

/// One declared failure domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainSpec {
    /// Stable identity (for example `power:circuit-3`, `camera:cam-a`).
    pub id: String,
    /// Lower failure probability (ppm) over the horizon.
    pub lo_ppm: u32,
    /// Upper failure probability (ppm) over the horizon.
    pub hi_ppm: u32,
    /// Member sensors.
    pub members: BTreeSet<String>,
}

/// A canonical reliability model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliabilityModel {
    zones: BTreeMap<String, BTreeSet<String>>,
    domains: Vec<DomainSpec>,
}

impl ReliabilityModel {
    /// Validates and canonicalizes `zones` (zone → observing sensors) and `domains`.
    ///
    /// # Errors
    ///
    /// [`GraphError`] input variants for invalid or duplicate identities, a probability
    /// interval outside `0 <= lo <= hi <= 1_000_000`, an empty domain, a domain naming an
    /// unknown sensor, or too many items.
    pub fn new(
        zones: &[(String, Vec<String>)],
        domains: &[DomainSpec],
    ) -> Result<Self, GraphError> {
        if zones.len() > MAX_MODEL_ITEMS || domains.len() > MAX_MODEL_ITEMS {
            return Err(GraphError::TooLarge);
        }
        let mut zone_map = BTreeMap::new();
        let mut sensors = BTreeSet::new();
        for (zone, observers) in zones {
            if !valid(zone) {
                return Err(GraphError::InvalidNodeId(zone.clone()));
            }
            let mut set = BTreeSet::new();
            for sensor in observers {
                if !valid(sensor) {
                    return Err(GraphError::InvalidNodeId(sensor.clone()));
                }
                if !set.insert(sensor.clone()) {
                    return Err(GraphError::DuplicateNode(sensor.clone()));
                }
                sensors.insert(sensor.clone());
            }
            if zone_map.insert(zone.clone(), set).is_some() {
                return Err(GraphError::DuplicateNode(zone.clone()));
            }
        }
        let mut seen = BTreeSet::new();
        let mut canonical = domains.to_vec();
        canonical.sort_by(|a, b| a.id.cmp(&b.id));
        for domain in &canonical {
            if !valid(&domain.id) {
                return Err(GraphError::InvalidNodeId(domain.id.clone()));
            }
            if !seen.insert(domain.id.clone()) {
                return Err(GraphError::DuplicateNode(domain.id.clone()));
            }
            if domain.lo_ppm > domain.hi_ppm
                || domain.hi_ppm > 1_000_000
                || domain.members.is_empty()
            {
                return Err(GraphError::PreconditionFailed(format!(
                    "domain {} needs members and 0 <= lo <= hi <= 1000000 ppm",
                    domain.id
                )));
            }
            if let Some(unknown) = domain
                .members
                .iter()
                .find(|member| !sensors.contains(*member))
            {
                return Err(GraphError::UnknownNode(unknown.clone()));
            }
        }
        Ok(Self {
            zones: zone_map,
            domains: canonical,
        })
    }

    /// Zones with their observers.
    #[must_use]
    pub fn zones(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.zones
    }

    /// Domains in identity order.
    #[must_use]
    pub fn domains(&self) -> &[DomainSpec] {
        &self.domains
    }

    /// Observer links (zone, sensor) counted once each.
    #[must_use]
    pub fn links(&self) -> usize {
        self.zones.values().map(BTreeSet::len).sum()
    }

    /// Canonical digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(RELIABILITY_MODEL_DOMAIN);
        encoder.u64(self.zones.len() as u64);
        for (zone, observers) in &self.zones {
            encoder.text(zone);
            encoder.u64(observers.len() as u64);
            for sensor in observers {
                encoder.text(sensor);
            }
        }
        encoder.u64(self.domains.len() as u64);
        for domain in &self.domains {
            encoder.text(&domain.id);
            encoder.u32(domain.lo_ppm);
            encoder.u32(domain.hi_ppm);
            encoder.u64(domain.members.len() as u64);
            for member in &domain.members {
                encoder.text(member);
            }
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// One minimal blinding domain set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimalCut {
    /// Domains, ascending.
    pub domains: Vec<String>,
    /// Probability that all of them fail, `10^-18` fixed point, outward.
    pub probability_e18: (u128, u128),
}

/// One zone's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneReliability {
    /// Zone.
    pub zone: String,
    /// Observing sensors, ascending.
    pub observers: Vec<String>,
    /// Domains touching its observers, ascending.
    pub relevant_domains: Vec<String>,
    /// Observers that belong to no declared domain (they never fail in this model).
    pub undeclared_observers: Vec<String>,
    /// `P(blind)` in `10^-18` fixed point, outward-rounded.
    pub blind_probability_e18: (u128, u128),
    /// Exact number of minimal cut sets.
    pub minimal_cut_count: u64,
    /// The first minimal cut sets in `(size, identity tuple)` order (at most
    /// [`MAX_CUTS_PER_ZONE`]).
    pub minimal_cuts: Vec<MinimalCut>,
}

/// The canonical answer of `ALG-RELIABILITY-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReliabilityOutput {
    /// Zones in identity order.
    pub zones: Vec<ZoneReliability>,
}

impl CertifiedOutput for ReliabilityOutput {
    fn entries(&self) -> u64 {
        self.zones
            .iter()
            .map(|zone| 1 + zone.minimal_cuts.len() as u64)
            .sum()
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.zones.len() as u64);
        for zone in &self.zones {
            encoder.text(&zone.zone);
            encode_ids(encoder, &zone.observers);
            encode_ids(encoder, &zone.relevant_domains);
            encode_ids(encoder, &zone.undeclared_observers);
            encoder.bytes(&zone.blind_probability_e18.0.to_be_bytes());
            encoder.bytes(&zone.blind_probability_e18.1.to_be_bytes());
            encoder.u64(zone.minimal_cut_count);
            encoder.u64(zone.minimal_cuts.len() as u64);
            for cut in &zone.minimal_cuts {
                encode_ids(encoder, &cut.domains);
                encoder.bytes(&cut.probability_e18.0.to_be_bytes());
                encoder.bytes(&cut.probability_e18.1.to_be_bytes());
            }
        }
    }
}

fn mul_floor(a: u128, b: u128) -> u128 {
    // a, b <= 1e18, so a * b <= 1e36 fits u128.
    a * b / ONE_E18
}

fn mul_ceil(a: u128, b: u128) -> u128 {
    (a * b).div_ceil(ONE_E18)
}

/// Runs `ALG-RELIABILITY-001` over `model`.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] when a zone's observers touch more than
/// [`MAX_RELEVANT_DOMAINS`] domains, and the fail-closed budget and bound errors.
pub fn reliability_bounds(
    model: &ReliabilityModel,
    budget: Budget,
) -> Result<CertifiedRun<ReliabilityOutput>, GraphError> {
    let mut meter = Meter::new(&IDENTITY, budget);
    let mut zones = Vec::with_capacity(model.zones.len());
    let mut max_k = 0_usize;
    for (zone, observers) in &model.zones {
        let relevant: Vec<usize> = model
            .domains
            .iter()
            .enumerate()
            .filter(|(_, domain)| {
                domain
                    .members
                    .iter()
                    .any(|member| observers.contains(member))
            })
            .map(|(index, _)| index)
            .collect();
        let k = relevant.len();
        if k > MAX_RELEVANT_DOMAINS {
            return Err(GraphError::PreconditionFailed(format!(
                "zone {zone} depends on {k} domains (at most {MAX_RELEVANT_DOMAINS})"
            )));
        }
        max_k = max_k.max(k);
        // Observer bitmasks over the relevant domains.
        let observer_masks: Vec<(String, u32)> = observers
            .iter()
            .map(|sensor| {
                let mask = relevant
                    .iter()
                    .enumerate()
                    .filter(|&(_, &domain)| model.domains[domain].members.contains(sensor))
                    .fold(0_u32, |mask, (bit, _)| mask | (1 << bit));
                (sensor.clone(), mask)
            })
            .collect();
        let undeclared: Vec<String> = observer_masks
            .iter()
            .filter(|(_, mask)| *mask == 0)
            .map(|(sensor, _)| sensor.clone())
            .collect();
        let probability = |bound_hi: bool, index: usize| -> u128 {
            let domain = &model.domains[relevant[index]];
            let ppm = if bound_hi {
                domain.hi_ppm
            } else {
                domain.lo_ppm
            };
            u128::from(ppm) * 1_000_000_000_000
        };
        let mut blind = vec![false; 1 << k];
        let (mut lo_sum, mut hi_sum) = (0_u128, 0_u128);
        for mask in 0_u32..(1_u32 << k) {
            meter.tick("scenario_evaluations")?;
            let mut is_blind = true;
            for (_, observer) in &observer_masks {
                meter.tick("observer_checks")?;
                if observer & mask == 0 {
                    is_blind = false;
                    break;
                }
            }
            if observers.is_empty() {
                is_blind = true;
            }
            blind[mask as usize] = is_blind;
            if !is_blind {
                continue;
            }
            let (mut lo, mut hi) = (ONE_E18, ONE_E18);
            for bit in 0..k {
                meter.tick_n("convolution_steps", 2)?;
                let failed = mask & (1 << bit) != 0;
                let (p_lo, p_hi) = (probability(false, bit), probability(true, bit));
                // Lower bound: every domain at its lower failure probability (monotone).
                let lo_factor = if failed { p_lo } else { ONE_E18 - p_lo };
                let hi_factor = if failed { p_hi } else { ONE_E18 - p_hi };
                lo = mul_floor(lo, lo_factor);
                hi = mul_ceil(hi, hi_factor);
            }
            lo_sum += lo;
            hi_sum += hi;
        }
        let hi_sum = hi_sum.min(ONE_E18);
        // Minimal cut sets, in (size, identity tuple) order.
        let mut cuts: Vec<(usize, Vec<String>, u32)> = Vec::new();
        let mut cut_count = 0_u64;
        for mask in 0_u32..(1_u32 << k) {
            if !blind[mask as usize] || mask == 0 {
                continue;
            }
            let mut minimal = true;
            for bit in 0..k {
                if mask & (1 << bit) != 0 {
                    meter.tick("minimality_checks")?;
                    if blind[(mask & !(1 << bit)) as usize] {
                        minimal = false;
                        break;
                    }
                }
            }
            if minimal {
                cut_count += 1;
                let names: Vec<String> = (0..k)
                    .filter(|bit| mask & (1 << bit) != 0)
                    .map(|bit| model.domains[relevant[bit]].id.clone())
                    .collect();
                cuts.push((names.len(), names, mask));
            }
        }
        cuts.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        cuts.truncate(MAX_CUTS_PER_ZONE);
        let minimal_cuts = cuts
            .into_iter()
            .map(|(_, domains, mask)| {
                let (mut lo, mut hi) = (ONE_E18, ONE_E18);
                for bit in 0..k {
                    if mask & (1 << bit) != 0 {
                        lo = mul_floor(lo, probability(false, bit));
                        hi = mul_ceil(hi, probability(true, bit));
                    }
                }
                MinimalCut {
                    domains,
                    probability_e18: (lo, hi),
                }
            })
            .collect();
        meter.decide(0, zones.len() as u64, cut_count);
        zones.push(ZoneReliability {
            zone: zone.clone(),
            observers: observers.iter().cloned().collect(),
            relevant_domains: relevant
                .iter()
                .map(|&index| model.domains[index].id.clone())
                .collect(),
            undeclared_observers: undeclared,
            blind_probability_e18: (lo_sum.min(hi_sum), hi_sum),
            minimal_cut_count: cut_count,
            minimal_cuts,
        });
    }
    let zone_count = model.zones.len() as u64;
    let links = model.links() as u64;
    let input = query_encoder(&IDENTITY, model.digest());
    let peak = (1_u64 << max_k) + 16 * links + 64 * zone_count;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: zone_count + model.domains.len() as u64,
            edge_count: links,
            input_digest: query_digest(input),
        },
        ReliabilityOutput { zones },
        &bound(zone_count, links, max_k as u64),
        peak,
    )
}
