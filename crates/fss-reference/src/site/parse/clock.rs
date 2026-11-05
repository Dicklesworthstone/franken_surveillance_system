#![forbid(unsafe_code)]
//! Strict reconstruction inputs for an optional measured node-clock observation.

use super::{Fields, SiteError, Value, field, integer, object, peer, schema, text};
use crate::site::clock::{ClockCorrelationPolicy, HostClockSample};
use crate::site::clock_proof::LocalNtpClockProof;

fn sample(value: &Value) -> Result<HostClockSample, SiteError> {
    let fields = object(
        value,
        &[
            "monotonic_before_ns",
            "wall_clock_unix_ns",
            "monotonic_after_ns",
        ],
    )?;
    Ok(HostClockSample {
        monotonic_before_ns: integer(fields, "monotonic_before_ns")?,
        wall_clock_unix_ns: integer(fields, "wall_clock_unix_ns")?,
        monotonic_after_ns: integer(fields, "monotonic_after_ns")?,
    })
}

fn packet(fields: &Fields, name: &'static str) -> Result<[u8; 48], SiteError> {
    let value = text(fields, name)?;
    if value.len() != 96
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SiteError::InvalidField(name));
    }
    let mut bytes = [0; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}

pub(super) fn clock_observation(value: &Value) -> Result<LocalNtpClockProof, SiteError> {
    let fields = object(
        value,
        &[
            "schema",
            "source",
            "peer",
            "request_hex",
            "reply_hex",
            "sent_before",
            "sent_after",
            "received_before",
            "received_after",
            "observation_start_ns",
            "observation_end_ns",
            "terminal",
            "policy",
        ],
    )?;
    schema(fields, "fss.site_clock_observation.v1")?;
    if text(fields, "source")? != "unauthenticated_loopback_ntp_claim" {
        return Err(SiteError::InvalidField("source"));
    }
    let policy = object(
        field(fields, "policy")?,
        &["max_sample_bracket_ns", "max_drift_ppb", "max_age_ns"],
    )?;
    Ok(LocalNtpClockProof {
        peer: peer(fields)?,
        request: packet(fields, "request_hex")?,
        reply: packet(fields, "reply_hex")?,
        sent_before: sample(field(fields, "sent_before")?)?,
        sent_after: sample(field(fields, "sent_after")?)?,
        received_before: sample(field(fields, "received_before")?)?,
        received_after: sample(field(fields, "received_after")?)?,
        observation_start_ns: integer(fields, "observation_start_ns")?,
        observation_end_ns: integer(fields, "observation_end_ns")?,
        terminal: sample(field(fields, "terminal")?)?,
        policy: ClockCorrelationPolicy {
            max_sample_bracket_ns: integer(policy, "max_sample_bracket_ns")?,
            max_drift_ppb: integer(policy, "max_drift_ppb")?,
            max_age_ns: integer(policy, "max_age_ns")?,
        },
    })
}
