#![forbid(unsafe_code)]
//! Exercise the actual production recording-service SOAP parser and shared wire contracts.
//! This target has no reference-runtime dependency and establishes no transport or custody claim.

#[path = "../../fss-reference/src/onvif/wire.rs"]
pub mod wire;

#[path = "../../fss-reference/tests/onvif_recording_contract/fixtures.rs"]
mod fixtures;
#[path = "../../fss-reference/tests/onvif_recording_contract/wire.rs"]
mod wire_contract;
