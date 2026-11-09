#![forbid(unsafe_code)]
//! Complete source-verified vendor-zone envelope with exact operator policy-input commitment.

use std::fmt::{self, Write};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::onvif::metadata::zones::{RetainedZones, contract::MAX_ZONE_POLICY_BYTES};

use super::super::tracks;
use super::{POLICY_READ_BYTES, zones_json};

pub(super) const MAX_JSON_BYTES: usize = 32 * 1024 * 1024;
pub(super) const SCHEMA: &str = "fss.onvif_vendor_zones_report.v1";
const LIMIT: &str = "ERR-ONVIF-ZONES-JSON-LIMIT-001";

struct Bounded {
    text: String,
}
impl Write for Bounded {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let length = self.text.len().checked_add(value.len()).ok_or(fmt::Error)?;
        if length > MAX_JSON_BYTES {
            return Err(fmt::Error);
        }
        self.text.try_reserve(value.len()).map_err(|_| fmt::Error)?;
        self.text.push_str(value);
        Ok(())
    }
}
fn string(value: &str) -> String {
    fss_cli::json_output::string(value)
}
fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}

pub(super) fn render(
    retained: &RetainedZones,
    include_values: bool,
    policy_input_digest: ContentDigest,
    policy_input_bytes: usize,
) -> Result<String, &'static str> {
    if policy_input_bytes == 0 || policy_input_bytes > MAX_ZONE_POLICY_BYTES {
        return Err(LIMIT);
    }
    let original = tracks::report::render(retained.snapshot(), include_values)?;
    let mut commitment = CanonicalEncoder::new();
    commitment.text("fss.onvif_vendor_zones_cli_report.v1");
    commitment.digest(retained.digest());
    commitment.digest(policy_input_digest);
    commitment.u64(policy_input_bytes as u64);
    let query_digest = ContentDigest::sha256(&commitment.finish_checked().map_err(|_| LIMIT)?);
    let mut out = Bounded {
        text: String::new(),
    };
    write!(out,
        "{{\"schema\":{},\"status\":\"verified\",\"plane\":\"cognition\",\"provenance\":\"derived\",\"source_provenance\":\"vendor_claimed\",\"vendor_values_included\":{},\"snapshot_digest\":{},\"query_digest\":{},\"policy_input\":{{\"digest\":{},\"bytes\":{},\"max_bytes\":{},\"byte_reservation\":{}}},\"max_json_bytes\":{},\"tracklets\":",
        string(SCHEMA), include_values, digest(retained.digest()), digest(query_digest),
        digest(policy_input_digest), policy_input_bytes, MAX_ZONE_POLICY_BYTES, POLICY_READ_BYTES,
        MAX_JSON_BYTES,
    ).map_err(|_| LIMIT)?;
    out.write_str(&original).map_err(|_| LIMIT)?;
    out.write_str(",\"analysis\":").map_err(|_| LIMIT)?;
    zones_json::write_json(&mut out, retained.report()).map_err(|_| LIMIT)?;
    out.write_str(",\"claims\":{\"physical_identity\":false,\"calibrated_geometry\":false,\"capture_clock\":false,\"dwell\":false,\"physical_absence\":false,\"coverage\":false,\"event_authority\":false,\"effect_permission\":false}}\n")
        .map_err(|_| LIMIT)?;
    Ok(out.text)
}
