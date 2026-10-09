//! Owner-network camera discovery (SVC: unified camera auto-discovery, bead
//! family fss-yodhk). Stage 1 is the census engine ([`census`]); later stages
//! add per-family probes (mDNS/SSDP/WS-Discovery, TUTK search, Tuya beacons)
//! and brand-confidence fingerprinting.
pub mod tuya_beacon;

pub use tuya_beacon::{TuyaBeaconObs, TUYA_BEACON_PORT, decode_beacon, listen};

pub mod census;
pub mod dispatch;
pub mod fingerprint;
pub mod service;
pub mod standards;

pub use service::{DeviceCandidate, DiscoverConfig, DiscoverReport, discover};

pub use standards::{
    MDNS_CAMERA_TYPES, MdnsAnswer, SsdpResponse, WsdMatch, build_mdns_query,
    build_msearch, build_wsdiscovery_probe, mdns_probe, parse_mdns_response,
    parse_ssdp_response, parse_wsd_match, ssdp_probe, wsdiscovery_probe,
};

pub use dispatch::{AdapterDispatch, AdapterPath, AuthIngredient, Readiness, dispatch};

pub use fingerprint::{Brand, BrandConfidence, Confidence, Signal, classify_host};

pub use census::{
    CensusConfig, CensusError, CensusPlan, CensusReport, HostObs, OUI_SNAPSHOT,
    OUI_SNAPSHOT_SHA256, OuiTable, REGISTERED_PORTS, run_census,
};
