//! The discovery service composition (SVC: `fss discover`, bead fss-yodhk).
//!
//! Assembles the six delivered probe stages into one owner-network-scoped
//! sweep producing typed [`DeviceCandidate`] rows:
//!
//! 1. passive-first listening window (Tuya beacons; mDNS/SSDP standards
//!    probes) — no packets sent for the beacon stage;
//! 2. census (ping sweep → ARP → OUI → registered-port TCP connects);
//! 3. per-host fingerprint classification (census + beacon corroboration);
//! 4. adapter dispatch with the exact missing owner-auth ingredient.
//!
//! Owner-network scope only (configured subnets, never the internet).
//! Unknown is never flattened: every candidate carries its evidence handles
//! and typed states. Deterministic replay fixtures cover every probe family
//! in CI without network access.

use std::sync::atomic::AtomicBool;

use crate::discovery::census::{CensusConfig, CensusError, OUI_SNAPSHOT, OuiTable, run_census};
use crate::discovery::dispatch::AdapterDispatch;
use crate::discovery::fingerprint::{Brand, BrandConfidence};
use crate::discovery::standards::{build_mdns_query, mdns_observe, ssdp_probe, wsdiscovery_probe};
use crate::discovery::tuya_beacon::listen;

mod evidence;
pub use evidence::{
    CameraServiceHint, DiscoveryResponse, DiscoverySighting, MAX_SERVICE_HINTS, assemble_discovery,
};

/// Discovery admission failures produce no partial candidate report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    /// Configured census scope or resource limits are invalid.
    Census(CensusError),
    /// Probe timing or service questions exceed the admitted bounds.
    InvalidProbeConfig,
    /// Raw observations or their composed service hints exceed the report bound.
    ObservationLimit,
}

impl From<CensusError> for DiscoveryError {
    fn from(error: CensusError) -> Self {
        Self::Census(error)
    }
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Census(error) => error.fmt(f),
            Self::InvalidProbeConfig => {
                f.write_str("invalid discovery probe window or service questions")
            }
            Self::ObservationLimit => {
                f.write_str("discovery observation or service-hint bound exceeded")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Service configuration: subnets plus timing budgets.
#[derive(Clone, Debug)]
pub struct DiscoverConfig {
    /// Census configuration (subnets, workers, TCP timeout).
    pub census: CensusConfig,
    /// Passive beacon listen window in seconds.
    pub beacon_seconds: u64,
    /// Standards-probe window in seconds.
    pub standards_seconds: u64,
    /// Local interface address for multicast probes.
    pub iface_ip: std::net::Ipv4Addr,
    /// Camera-relevant mDNS types (defaults to [`MDNS_CAMERA_TYPES`]).
    pub mdns_types: Vec<&'static str>,
}

impl DiscoverConfig {
    /// Owner-LAN defaults for a given subnet list.
    #[must_use]
    pub fn for_subnets(subnets: Vec<String>, iface_ip: std::net::Ipv4Addr) -> Self {
        Self {
            census: CensusConfig {
                subnets,
                workers: 64,
                tcp_timeout: std::time::Duration::from_millis(700),
            },
            beacon_seconds: 10,
            standards_seconds: 5,
            iface_ip,
            mdns_types: crate::discovery::standards::MDNS_CAMERA_TYPES.to_vec(),
        }
    }
}

/// One typed device candidate: the complete discovery result for a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCandidate {
    /// Host identity (IP, MAC, OUI vendor, open ports).
    pub host: crate::discovery::census::HostObs,
    /// Brand classification with evidence.
    pub brand: BrandConfidence,
    /// Adapter path + owner-auth requirement.
    pub dispatch: AdapterDispatch,
}

/// The full discovery report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoverReport {
    /// Classified candidates, ascending by IP.
    pub candidates: Vec<DeviceCandidate>,
    /// Admitted ping targets; cancellation can stop before all are attempted.
    pub ping_targets: usize,
    /// Beaçons captured (cmd + source), for provenance.
    pub beacons: Vec<(String, u32)>,
    /// Distinct in-scope SSDP responders.
    pub ssdp_responders: usize,
    /// mDNS answers observed.
    pub mdns_answers: usize,
    /// Distinct in-scope WS-Discovery responders; zero never proves device absence.
    pub wsd_matches: usize,
    /// Actual current responders, independent of advertised device addresses.
    pub current_responses: Vec<DiscoveryResponse>,
    /// Source-attributed camera service claims requiring owner enrollment.
    pub advertised_services: Vec<CameraServiceHint>,
}

/// Runs the full discovery sweep (owner-network scope only).
pub fn discover(
    cfg: &DiscoverConfig,
    cancel: &AtomicBool,
) -> Result<DiscoverReport, DiscoveryError> {
    // Reject invalid/unbounded scope before any passive or active probe starts.
    let scope = cfg.census.plan()?;
    if !(1..=120).contains(&cfg.beacon_seconds)
        || !(1..=120).contains(&cfg.standards_seconds)
        || build_mdns_query(&cfg.mdns_types, 0).is_empty()
    {
        return Err(DiscoveryError::InvalidProbeConfig);
    }
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(DiscoverReport {
            ping_targets: scope.ping_targets.len(),
            ..DiscoverReport::default()
        });
    }
    // Stage 1: passive-first listening + standards probes.
    let beacons = listen(cfg.beacon_seconds, 256, cancel).unwrap_or_default();
    let mdns = mdns_observe(cfg.iface_ip, &cfg.mdns_types, cfg.standards_seconds, cancel);
    let ssdp = ssdp_probe(cfg.iface_ip, cfg.standards_seconds, cancel);
    let wsd = wsdiscovery_probe(cfg.iface_ip, cfg.standards_seconds, cancel);

    // Stage 2: census.
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    let census = run_census(&cfg.census, &oui, cancel)?;

    // NOTE (negative finding, 2026-10-09): TUTK-NEW discovery corroboration
    // is NOT credential-less — the 0x1002 HMAC is keyed by the CAMERA's own
    // uid/enr/mac identity, so a probe with any other identity is silently
    // absorbed (verified live: owner-identity probe answers, foreign-identity
    // probe to the same camera does not). Bare Wyze-OUI hosts therefore stay
    // Possible until the owner provisions credentials, which both corroborate
    // and onboard. See NEG-005 in docs/NEGATIVE_EVIDENCE.md.

    // Stage 3+4: combine all attributed responders and service chains, then
    // classify and dispatch only within the original authorized host set.
    assemble_discovery(&scope, census, &beacons, &mdns, &ssdp, &wsd)
}

impl DiscoverReport {
    /// Candidate endpoints that actually responded during this sweep.
    ///
    /// The host table also contains ARP-cache entries; MAC/OUI classification and
    /// aggregate standards counts are not heartbeats. Actual census, beacon and
    /// standards responders refresh only their own endpoint; an advertised A
    /// record or URL cannot refresh a different device's liveness.
    #[must_use]
    pub fn fresh_candidate_ips(&self) -> std::collections::BTreeSet<std::net::Ipv4Addr> {
        let candidates: std::collections::BTreeSet<_> = self
            .candidates
            .iter()
            .map(|candidate| candidate.host.ip)
            .collect();
        let mut fresh: std::collections::BTreeSet<_> = self
            .candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .host
                    .open_ports
                    .iter()
                    .any(|port| crate::discovery::census::REGISTERED_PORTS.contains(port))
            })
            .map(|candidate| candidate.host.ip)
            .collect();
        fresh.extend(
            self.current_responses
                .iter()
                .map(|response| response.endpoint)
                .filter(|endpoint| candidates.contains(endpoint)),
        );
        for (source, _) in &self.beacons {
            if let Ok(std::net::SocketAddr::V4(source)) = source.parse::<std::net::SocketAddr>()
                && candidates.contains(source.ip())
            {
                fresh.insert(*source.ip());
            }
        }
        fresh
    }

    /// Candidates that are live onboarding paths (non-ImportOnly).
    #[must_use]
    pub fn onboarding_candidates(&self) -> Vec<&DeviceCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.dispatch.readiness != crate::discovery::dispatch::Readiness::Unavailable)
            .collect()
    }

    /// Camera-classified candidates (any confidence, excluding infra/unknown).
    #[must_use]
    pub fn camera_candidates(&self) -> Vec<&DeviceCandidate> {
        self.candidates
            .iter()
            .filter(|c| !matches!(c.brand.brand, Brand::Unknown | Brand::Infrastructure))
            .collect()
    }

    /// Honest summary line for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "discovery: {} hosts ({} cameras classified, {} onboarding paths), {} beacons, {} ssdp, {} mdns, {} wsd",
            self.candidates.len(),
            self.camera_candidates().len(),
            self.onboarding_candidates().len(),
            self.beacons.len(),
            self.ssdp_responders,
            self.mdns_answers,
            self.wsd_matches
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_selectivity() {
        let mut report = DiscoverReport::default();
        report.candidates = vec![];
        assert_eq!(report.camera_candidates().len(), 0);
        assert_eq!(report.onboarding_candidates().len(), 0);
        let s = report.summary();
        assert!(s.contains("0 hosts"));
    }
}
