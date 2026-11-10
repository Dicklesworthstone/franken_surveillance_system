#![forbid(unsafe_code)]
//! Native read-only recording discovery, exact advertised ranges and scoped replay URIs.

use fss_reference::onvif::wire;

#[path = "onvif_recording_contract/fixtures.rs"]
mod fixtures;
#[path = "onvif_recording_contract/wire.rs"]
mod wire_contract;
#[path = "onvif_recording_contract/client.rs"]
mod client;
