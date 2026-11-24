//! Owner-network camera discovery (SVC: unified camera auto-discovery, bead
//! family fss-yodhk). Stage 1 is the census engine ([`census`]); later stages
//! add per-family probes (mDNS/SSDP/WS-Discovery, TUTK search, Tuya beacons)
//! and brand-confidence fingerprinting.
pub mod tuya_beacon;

pub use tuya_beacon::{TUYA_BEACON_PORT, TuyaBeaconObs, decode_beacon, listen};

pub mod census;
pub mod dispatch;
pub mod fingerprint;
pub mod liveness;
pub mod probes;
pub mod retained_liveness;
pub mod service;
pub mod standards;
pub mod watchdog;
pub mod watchdog_provision;

pub use service::{
    CameraServiceHint, DeviceCandidate, DiscoverConfig, DiscoverReport, DiscoveryError,
    DiscoveryResponse, DiscoverySighting, MAX_SERVICE_HINTS, assemble_discovery,
    assemble_discovery_with_probes, discover,
};

pub use standards::{
    MDNS_CAMERA_TYPES, MdnsAnswer, MdnsObservation, SsdpResponse, WsdMatch, build_mdns_query,
    build_msearch, build_wsdiscovery_probe, mdns_observe, mdns_probe, parse_mdns_response,
    parse_ssdp_response, parse_wsd_match, ssdp_probe, wsdiscovery_probe,
};

pub use probes::{
    MAX_RTSP_PEEK_BYTES, MAX_UNIFI_RESPONSES, RTSP_OPTIONS_REQUEST, RTSP_PEEK_PORTS, RtspBannerObs,
    UNIFI_DISCOVERY_PORT, UNIFI_V1_QUERY, UniFiDiscoveryObs, parse_rtsp_options_response,
    parse_unifi_discovery_reply, rtsp_options_peek, rtsp_options_peek_endpoint, unifi_udp_probe,
};

pub use dispatch::{AdapterDispatch, AdapterPath, AuthIngredient, Readiness, dispatch};

pub use fingerprint::{
    Brand, BrandConfidence, CameraService, Confidence, Signal, classify_host,
    classify_host_with_evidence, classify_host_with_services,
};

pub use census::{
    CensusConfig, CensusError, CensusPlan, CensusReport, HostObs, OUI_SNAPSHOT,
    OUI_SNAPSHOT_SHA256, OuiTable, REGISTERED_PORTS, parse_proc_net_arp, run_census,
};

pub use liveness::{note_agent_beat, note_agent_silence};
