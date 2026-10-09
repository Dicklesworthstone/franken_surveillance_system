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

use crate::discovery::census::{run_census, CensusConfig, CensusReport, OuiTable, OUI_SNAPSHOT};
use crate::discovery::dispatch::{dispatch, AdapterDispatch};
use crate::discovery::fingerprint::{classify_host, Brand, BrandConfidence, Confidence, Signal};
use crate::discovery::standards::{mdns_probe, ssdp_probe, wsdiscovery_probe, SsdpResponse};
use crate::discovery::tuya_beacon::{listen, TuyaBeaconObs};

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
    /// Ping targets the census covered.
    pub ping_targets: usize,
    /// Beaçons captured (cmd + source), for provenance.
    pub beacons: Vec<(String, u32)>,
    /// Standards-probe observations (SSDP responders; mDNS answers count).
    pub ssdp_responders: usize,
    /// mDNS answers observed.
    pub mdns_answers: usize,
    /// WS-Discovery probe matches (0 is a typed negative).
    pub wsd_matches: usize,
}

/// Runs the full discovery sweep (owner-network scope only).
pub fn discover(cfg: &DiscoverConfig, cancel: &AtomicBool) -> Result<DiscoverReport, crate::discovery::census::CensusError> {
    // Stage 1: passive-first listening + standards probes.
    let beacons = listen(cfg.beacon_seconds, 256, cancel);
    let beacon_index: std::collections::BTreeMap<String, Vec<&TuyaBeaconObs>> = {
        let mut m: std::collections::BTreeMap<String, Vec<&TuyaBeaconObs>> =
            std::collections::BTreeMap::new();
        for b in &beacons {
            let ip = b.source.split(':').next().unwrap_or("").to_owned();
            m.entry(ip).or_default().push(b);
        }
        m
    };
    let mdns = mdns_probe(cfg.iface_ip, &cfg.mdns_types, cfg.standards_seconds, cancel);
    let ssdp: Vec<SsdpResponse> = ssdp_probe(cfg.iface_ip, cfg.standards_seconds, cancel);
    let wsd = wsdiscovery_probe(cfg.iface_ip, cfg.standards_seconds, cancel);

    // Stage 2: census.
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    let CensusReport {
        hosts,
        ping_targets,
    } = run_census(&cfg.census, &oui, cancel)?;

    // NOTE (negative finding, 2026-10-09): TUTK-NEW discovery corroboration
    // is NOT credential-less — the 0x1002 HMAC is keyed by the CAMERA's own
    // uid/enr/mac identity, so a probe with any other identity is silently
    // absorbed (verified live: owner-identity probe answers, foreign-identity
    // probe to the same camera does not). Bare Wyze-OUI hosts therefore stay
    // Possible until the owner provisions credentials, which both corroborate
    // and onboard. See NEG-005 in docs/NEGATIVE_EVIDENCE.md.

    // Stage 3+4: classify each host with beacon corroboration, dispatch.
    let mut candidates = Vec::with_capacity(hosts.len());
    for host in hosts {
        let refs: Vec<&TuyaBeaconObs> = beacon_index
            .get(&host.ip.to_string())
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();
        let brand = classify_host(&host, &refs, None);
        let dp = dispatch(&brand);
        candidates.push(DeviceCandidate {
            host,
            brand,
            dispatch: dp,
        });
    }
    Ok(DiscoverReport {
        candidates,
        ping_targets,
        beacons: beacons
            .iter()
            .map(|b| (b.source.clone(), b.cmd))
            .collect(),
        ssdp_responders: ssdp.len(),
        mdns_answers: mdns.len(),
        wsd_matches: wsd.len(),
    })
}

impl DiscoverReport {
    /// Candidates that are live onboarding paths (non-ImportOnly).
    #[must_use]
    pub fn onboarding_candidates(&self) -> Vec<&DeviceCandidate> {
        self.candidates
            .iter()
            .filter(|c| {
                c.dispatch.readiness
                    != crate::discovery::dispatch::Readiness::Unavailable
            })
            .collect()
    }

    /// Camera-classified candidates (any confidence, excluding infra/unknown).
    #[must_use]
    pub fn camera_candidates(&self) -> Vec<&DeviceCandidate> {
        self.candidates
            .iter()
            .filter(|c| {
                !matches!(
                    c.brand.brand,
                    Brand::Unknown | Brand::Infrastructure
                )
            })
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
