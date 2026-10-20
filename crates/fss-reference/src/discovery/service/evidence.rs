//! Pure composition of bounded probe observations. Advertised addresses and
//! protocol claims are separate from the endpoint that actually responded.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};

use super::{DeviceCandidate, DiscoverReport, DiscoveryError};
use crate::discovery::census::{CensusPlan, CensusReport, HostObs, MAX_SUBNET_HOSTS};
use crate::discovery::dispatch::dispatch;
use crate::discovery::fingerprint::{CameraService, classify_host_with_services};
use crate::discovery::standards::{MdnsAnswer, MdnsObservation, SsdpResponse, WsdMatch};
use crate::discovery::tuya_beacon::TuyaBeaconObs;

/// Maximum source-attributed camera service hints admitted in one sweep.
pub const MAX_SERVICE_HINTS: usize = 1024;

/// A response received during this sweep. Inventory and advertised targets do
/// not belong to this vocabulary. These labels are also retained in v2 health records.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiscoverySighting {
    /// Successful ICMP reply or registered TCP connection from the census.
    CensusResponse,
    /// Received Tuya beacon from the endpoint.
    TuyaBeacon,
    /// Received, structurally valid mDNS response from the endpoint.
    MdnsResponse,
    /// Received SSDP response from the endpoint.
    SsdpResponse,
    /// Received WS-Discovery response from the endpoint.
    WsdResponse,
}

impl DiscoverySighting {
    /// Maximum distinct response kinds per endpoint.
    pub const COUNT: usize = 5;

    /// Stable canonical and report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CensusResponse => "census_response",
            Self::TuyaBeacon => "tuya_beacon",
            Self::MdnsResponse => "mdns_response",
            Self::SsdpResponse => "ssdp_response",
            Self::WsdResponse => "wsd_response",
        }
    }

    /// Strict decoding of the registered response vocabulary.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "census_response" => Self::CensusResponse,
            "tuya_beacon" => Self::TuyaBeacon,
            "mdns_response" => Self::MdnsResponse,
            "ssdp_response" => Self::SsdpResponse,
            "wsd_response" => Self::WsdResponse,
            _ => return None,
        })
    }
}

/// Source attribution for one current response, independent of device identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryResponse {
    /// Actual packet sender or endpoint that accepted a census probe.
    pub endpoint: Ipv4Addr,
    /// Kind of received response.
    pub kind: DiscoverySighting,
}

/// A source-attributed service claim, suitable for owner review before enrollment.
/// A hint does not imply authenticated identity, conformance, or stream readiness.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CameraServiceHint {
    /// Candidate endpoint, possibly advertised by a sleep proxy.
    pub candidate: Ipv4Addr,
    /// Actual sender of the advertisement.
    pub responder: Ipv4Addr,
    /// Advertised camera service.
    pub service: CameraService,
    /// Advertised SRV port, when known. WS-Discovery URLs are never followed.
    pub port: Option<u16>,
}

/// Composes observations from one admitted sweep, without performing any I/O.
/// All candidate and response addresses remain inside the original census plan.
/// mDNS chains are joined only within one sender's observations; goodbye records
/// suppress that exact record for the sweep regardless of arrival order.
pub fn assemble_discovery(
    scope: &CensusPlan,
    census: CensusReport,
    beacons: &[TuyaBeaconObs],
    mdns: &[MdnsObservation],
    ssdp: &[SsdpResponse],
    wsd: &[WsdMatch],
) -> Result<DiscoverReport, DiscoveryError> {
    // Bound raw input work as well as unique output. Repeated packets cannot
    // evade admission, and a malicious SRV/A cross product cannot grow reports.
    if scope.ping_targets.len() > MAX_SUBNET_HOSTS as usize
        || census.hosts.len() > MAX_SUBNET_HOSTS as usize
        || census.responders.len() > MAX_SUBNET_HOSTS as usize
        || beacons.len() > 256
        || mdns.len() > 256
        || ssdp.len() > 256
        || wsd.len() > 256
        || mdns
            .iter()
            .try_fold(0usize, |n, reply| n.checked_add(reply.answers.len()))
            .is_none_or(|n| n > 1024)
    {
        return Err(DiscoveryError::ObservationLimit);
    }
    let mut hosts = BTreeMap::<Ipv4Addr, HostObs>::new();
    for mut host in census.hosts {
        if !scope.contains(host.ip) {
            continue;
        }
        host.open_ports.sort_unstable();
        host.open_ports.dedup();
        if let Some(existing) = hosts.get_mut(&host.ip) {
            // Conflicting cached identity is unknown, never an arbitrary OUI choice.
            if existing.mac != host.mac {
                existing.mac.clear();
                existing.oui_vendor = None;
            } else if existing.oui_vendor != host.oui_vendor {
                existing.oui_vendor = None;
            }
            existing.open_ports.extend(host.open_ports);
            existing.open_ports.sort_unstable();
            existing.open_ports.dedup();
            existing.rtt_ms = existing.rtt_ms.into_iter().chain(host.rtt_ms).min();
        } else {
            hosts.insert(host.ip, host);
        }
    }
    let mut responses = BTreeSet::new();
    for endpoint in census.responders {
        if scope.contains(endpoint) {
            ensure_host(&mut hosts, endpoint);
            responses.insert(DiscoveryResponse {
                endpoint,
                kind: DiscoverySighting::CensusResponse,
            });
        }
    }
    let mut beacon_index = BTreeMap::<Ipv4Addr, Vec<&TuyaBeaconObs>>::new();
    let mut beacon_handles = BTreeSet::new();
    for beacon in beacons {
        // The raw decoder deliberately exposes corrupt frames for diagnostics;
        // they cannot become accepted protocol or classification evidence.
        if !beacon.integrity_verified() {
            continue;
        }
        let Some(endpoint) = source_ip(&beacon.source).filter(|ip| scope.contains(*ip)) else {
            continue;
        };
        ensure_host(&mut hosts, endpoint);
        responses.insert(DiscoveryResponse {
            endpoint,
            kind: DiscoverySighting::TuyaBeacon,
        });
        beacon_index.entry(endpoint).or_default().push(beacon);
        beacon_handles.insert((beacon.source.clone(), beacon.cmd));
    }
    for beacons in beacon_index.values_mut() {
        beacons.sort_by_key(|beacon| (beacon.cmd, beacon.cmd_name, &beacon.source));
    }
    let mut ssdp_sources = BTreeSet::new();
    for response in ssdp {
        let Some(endpoint) = source_ip(&response.ip).filter(|ip| scope.contains(*ip)) else {
            continue;
        };
        ensure_host(&mut hosts, endpoint);
        responses.insert(DiscoveryResponse {
            endpoint,
            kind: DiscoverySighting::SsdpResponse,
        });
        ssdp_sources.insert(endpoint);
    }
    let mut hints = BTreeSet::new();
    let mut wsd_sources = BTreeSet::new();
    for response in wsd {
        let Some(endpoint) = source_ip(&response.ip).filter(|ip| scope.contains(*ip)) else {
            continue;
        };
        ensure_host(&mut hosts, endpoint);
        responses.insert(DiscoveryResponse {
            endpoint,
            kind: DiscoverySighting::WsdResponse,
        });
        wsd_sources.insert(endpoint);
        if response.is_onvif_camera() {
            // XAddrs may name unrelated or unauthorized addresses. Only the actual
            // sender becomes a candidate here; no URL is fetched or logged.
            hints.insert(CameraServiceHint {
                candidate: endpoint,
                responder: endpoint,
                service: CameraService::Onvif,
                port: None,
            });
        }
    }
    let mut by_sender = BTreeMap::<Ipv4Addr, Vec<&MdnsAnswer>>::new();
    for observation in mdns {
        if observation.answers.is_empty() || !scope.contains(observation.responder) {
            continue;
        }
        ensure_host(&mut hosts, observation.responder);
        responses.insert(DiscoveryResponse {
            endpoint: observation.responder,
            kind: DiscoverySighting::MdnsResponse,
        });
        by_sender
            .entry(observation.responder)
            .or_default()
            .extend(&observation.answers);
    }
    let mut mdns_answers = 0;
    for (responder, answers) in by_sender {
        let withdrawn: BTreeSet<_> = answers
            .iter()
            .filter(|a| a.ttl == 0)
            .map(|a| rr_key(a))
            .collect();
        let withdrawn_instances: BTreeSet<_> = answers
            .iter()
            .filter(|answer| answer.ttl == 0 && answer.rr_type == 12)
            .map(|answer| answer.rdata.to_ascii_lowercase())
            .collect();
        let records: BTreeMap<_, _> = answers
            .iter()
            .map(|answer| (rr_key(answer), *answer))
            .collect();
        mdns_answers += records.len();
        let live: Vec<_> = records
            .iter()
            .filter(|(key, answer)| answer.ttl > 0 && !withdrawn.contains(*key))
            .map(|(_, answer)| *answer)
            .collect();
        for srv in live.iter().filter(|answer| answer.rr_type == 33) {
            if withdrawn_instances.contains(&srv.name.to_ascii_lowercase()) {
                continue;
            }
            let Some(service) = instance_service(&srv.name) else {
                continue;
            };
            let Some(port) = srv.srv_port.filter(|port| *port > 0) else {
                continue;
            };
            for address in live.iter().filter(|answer| {
                answer.rr_type == 1 && answer.name.eq_ignore_ascii_case(&srv.rdata)
            }) {
                let Some(candidate) = address
                    .rdata
                    .parse::<Ipv4Addr>()
                    .ok()
                    .filter(|ip| scope.contains(*ip))
                else {
                    continue;
                };
                ensure_host(&mut hosts, candidate);
                hints.insert(CameraServiceHint {
                    candidate,
                    responder,
                    service,
                    port: Some(port),
                });
                if hints.len() > MAX_SERVICE_HINTS {
                    return Err(DiscoveryError::ObservationLimit);
                }
                // In particular, a sleep proxy's A record cannot refresh the
                // advertised device's liveness without a response from that device.
            }
        }
    }
    let mut by_candidate = BTreeMap::<Ipv4Addr, BTreeSet<CameraService>>::new();
    for hint in &hints {
        by_candidate
            .entry(hint.candidate)
            .or_default()
            .insert(hint.service);
    }
    let candidates = hosts
        .into_values()
        .map(|host| {
            let services: Vec<_> = by_candidate
                .remove(&host.ip)
                .unwrap_or_default()
                .into_iter()
                .collect();
            let beacons = beacon_index.get(&host.ip).map_or(&[][..], Vec::as_slice);
            let brand = classify_host_with_services(&host, beacons, &services);
            let dispatch = dispatch(&brand);
            DeviceCandidate {
                host,
                brand,
                dispatch,
            }
        })
        .collect();
    Ok(DiscoverReport {
        candidates,
        ping_targets: census.ping_targets,
        beacons: beacon_handles.into_iter().collect(),
        ssdp_responders: ssdp_sources.len(),
        mdns_answers,
        wsd_matches: wsd_sources.len(),
        current_responses: responses.into_iter().collect(),
        advertised_services: hints.into_iter().collect(),
    })
}

fn ensure_host(hosts: &mut BTreeMap<Ipv4Addr, HostObs>, ip: Ipv4Addr) {
    hosts.entry(ip).or_insert_with(|| HostObs {
        ip,
        mac: String::new(),
        oui_vendor: None,
        open_ports: Vec::new(),
        rtt_ms: None,
    });
}

fn source_ip(source: &str) -> Option<Ipv4Addr> {
    source
        .parse()
        .ok()
        .or_else(|| match source.parse::<SocketAddr>().ok()? {
            SocketAddr::V4(address) => Some(*address.ip()),
            SocketAddr::V6(_) => None,
        })
}

fn rr_key(answer: &MdnsAnswer) -> (String, u16, String, Option<u16>) {
    let data = if matches!(answer.rr_type, 12 | 33) {
        answer.rdata.to_ascii_lowercase()
    } else {
        answer.rdata.clone()
    };
    (
        answer.name.to_ascii_lowercase(),
        answer.rr_type,
        data,
        answer.srv_port,
    )
}

fn instance_service(name: &str) -> Option<CameraService> {
    // Split escaped DNS presentation names at real label boundaries. A single
    // label containing `Fake._rtsp` must not become an RTSP service instance.
    let mut labels = Vec::new();
    let mut label = String::new();
    let mut chars = name.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => label.push(chars.next()?),
            '.' => {
                labels.push(std::mem::take(&mut label));
            }
            _ => label.push(ch.to_ascii_lowercase()),
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    if labels.len() != 4 || labels[0].is_empty() || labels[2] != "_tcp" || labels[3] != "local" {
        return None;
    }
    match labels[1].as_str() {
        "_onvif" => Some(CameraService::Onvif),
        "_rtsp" => Some(CameraService::Rtsp),
        "_axis-video" => Some(CameraService::AxisVideo),
        _ => None,
    }
}
