#![forbid(unsafe_code)]
//! Exact integer projection of a measured, unauthenticated node-clock correlation.

use fss_reference::site::ClockWitness;
use fss_reference::site::clock::HostClockSample;
use fss_reference::site::clock_proof::LocalNtpClockProof;

use crate::json_output::{object, string};

pub(super) fn witness(value: &ClockWitness) -> String {
    object(&[
        ("wall_clock_unix_ns", value.wall_clock_unix_ns.to_string()),
        ("monotonic_ns", value.monotonic_ns.to_string()),
        ("ntp_offset_ns", value.ntp_offset_ns.to_string()),
        (
            "ntp_offset_direction",
            string(value.ntp_offset_direction.as_str()),
        ),
        ("ntp_uncertainty_ns", value.ntp_uncertainty_ns.to_string()),
    ])
}

fn sample(value: HostClockSample) -> String {
    object(&[
        ("monotonic_before_ns", value.monotonic_before_ns.to_string()),
        ("wall_clock_unix_ns", value.wall_clock_unix_ns.to_string()),
        ("monotonic_after_ns", value.monotonic_after_ns.to_string()),
    ])
}

fn hex(bytes: &[u8; 48]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(96);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

pub(super) fn observation(value: &LocalNtpClockProof) -> String {
    object(&[
        ("schema", string("fss.site_clock_observation.v1")),
        ("source", string("unauthenticated_loopback_ntp_claim")),
        ("peer", string(&value.peer.to_string())),
        ("request_hex", string(&hex(&value.request))),
        ("reply_hex", string(&hex(&value.reply))),
        ("sent_before", sample(value.sent_before)),
        ("sent_after", sample(value.sent_after)),
        ("received_before", sample(value.received_before)),
        ("received_after", sample(value.received_after)),
        (
            "observation_start_ns",
            value.observation_start_ns.to_string(),
        ),
        ("observation_end_ns", value.observation_end_ns.to_string()),
        ("terminal", sample(value.terminal)),
        (
            "policy",
            object(&[
                (
                    "max_sample_bracket_ns",
                    value.policy.max_sample_bracket_ns.to_string(),
                ),
                ("max_drift_ppb", value.policy.max_drift_ppb.to_string()),
                ("max_age_ns", value.policy.max_age_ns.to_string()),
            ]),
        ),
    ])
}
