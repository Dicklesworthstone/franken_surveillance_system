//! Owner-network camera discovery (SVC: unified camera auto-discovery, bead
//! family fss-yodhk). Stage 1 is the census engine ([`census`]); later stages
//! add per-family probes (mDNS/SSDP/WS-Discovery, TUTK search, Tuya beacons)
//! and brand-confidence fingerprinting.

pub mod census;

pub use census::{
    CensusConfig, CensusError, CensusPlan, CensusReport, HostObs, OUI_SNAPSHOT,
    OUI_SNAPSHOT_SHA256, OuiTable, REGISTERED_PORTS, run_census,
};
