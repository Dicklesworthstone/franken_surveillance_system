#![forbid(unsafe_code)]
//! Cross-boundary contracts for reconstructible clock evidence in probe receipts.

use std::error::Error;

use fss_packet::ntp::SntpRequest;
use fss_reference::site::clock::HostClockSample;
use fss_reference::site::clock_proof::{LOCAL_NTP_CLOCK_POLICY, LocalNtpClockProof};
use fss_reference::site::{ClockOffsetDirection, ClockWitness, SiteError, parse_probe_receipts};

type Test = Result<(), Box<dyn Error>>;

const PROBES: &str = include_str!("../../../fixtures/site/probes.v1.json");
const EPOCH: u64 = 1_800_000_000_000_000_000;
const ORIGIN: u64 = 1_000_000_000;

fn host(elapsed_ns: u64) -> HostClockSample {
    HostClockSample {
        monotonic_before_ns: ORIGIN + elapsed_ns,
        wall_clock_unix_ns: EPOCH + elapsed_ns,
        monotonic_after_ns: ORIGIN + elapsed_ns,
    }
}

fn put_timestamp(packet: &mut [u8; 48], start: usize, unix_ns: u64) {
    let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
    let fraction = ((u128::from(unix_ns % 1_000_000_000) << 32) / 1_000_000_000) as u32;
    packet[start..start + 4].copy_from_slice(&seconds.to_be_bytes());
    packet[start + 4..start + 8].copy_from_slice(&fraction.to_be_bytes());
}

fn proof() -> Result<LocalNtpClockProof, Box<dyn Error>> {
    let request = SntpRequest::new(EPOCH)?;
    let mut reply = [0_u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 6;
    reply[3] = (-30_i8) as u8;
    reply[12..16].copy_from_slice(b"TEST");
    put_timestamp(&mut reply, 16, EPOCH - 1_000_000_000);
    reply[24..32].copy_from_slice(&request.wire_bytes()[40..48]);
    put_timestamp(&mut reply, 32, EPOCH + 1_009_000_000);
    put_timestamp(&mut reply, 40, EPOCH + 1_010_000_000);
    Ok(LocalNtpClockProof {
        peer: "127.0.0.1:123".parse()?,
        request: *request.wire_bytes(),
        reply,
        sent_before: host(0),
        sent_after: host(1_000),
        received_before: host(20_000_000),
        received_after: host(20_001_000),
        observation_start_ns: ORIGIN + 1_000_000_000,
        observation_end_ns: ORIGIN + 1_003_000_000,
        terminal: host(2_000_000_000),
        policy: LOCAL_NTP_CLOCK_POLICY,
    })
}

fn packet_hex(packet: &[u8; 48]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    packet
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn sample_json(sample: HostClockSample) -> String {
    format!(
        "{{\"monotonic_before_ns\":{},\"wall_clock_unix_ns\":{},\"monotonic_after_ns\":{}}}",
        sample.monotonic_before_ns, sample.wall_clock_unix_ns, sample.monotonic_after_ns,
    )
}

fn proof_json(proof: &LocalNtpClockProof) -> String {
    format!(
        concat!(
            "{{\"schema\":\"fss.site_clock_observation.v1\",",
            "\"source\":\"unauthenticated_loopback_ntp_claim\",",
            "\"peer\":\"{}\",\"request_hex\":\"{}\",\"reply_hex\":\"{}\",",
            "\"sent_before\":{},\"sent_after\":{},",
            "\"received_before\":{},\"received_after\":{},",
            "\"observation_start_ns\":{},\"observation_end_ns\":{},\"terminal\":{},",
            "\"policy\":{{\"max_sample_bracket_ns\":{},\"max_drift_ppb\":{},\"max_age_ns\":{}}}}}",
        ),
        proof.peer,
        packet_hex(&proof.request),
        packet_hex(&proof.reply),
        sample_json(proof.sent_before),
        sample_json(proof.sent_after),
        sample_json(proof.received_before),
        sample_json(proof.received_after),
        proof.observation_start_ns,
        proof.observation_end_ns,
        sample_json(proof.terminal),
        proof.policy.max_sample_bracket_ns,
        proof.policy.max_drift_ppb,
        proof.policy.max_age_ns,
    )
}

fn witness_json(witness: ClockWitness) -> String {
    let direction = match witness.ntp_offset_direction {
        ClockOffsetDirection::Ahead => "ahead",
        ClockOffsetDirection::Behind => "behind",
    };
    format!(
        concat!(
            "{{\"wall_clock_unix_ns\":{},\"monotonic_ns\":{},",
            "\"ntp_offset_ns\":{},\"ntp_offset_direction\":\"{}\",",
            "\"ntp_uncertainty_ns\":{}}}",
        ),
        witness.wall_clock_unix_ns,
        witness.monotonic_ns,
        witness.ntp_offset_ns,
        direction,
        witness.ntp_uncertainty_ns,
    )
}

fn receipt_json(witness: Option<&str>, observation: Option<&str>) -> String {
    let mut fields = String::from("\"server_identity\": \"synthetic-example-server\"");
    if let Some(witness) = witness {
        fields.push_str(&format!(",\"clock_evidence\":{witness}"));
    }
    if let Some(observation) = observation {
        fields.push_str(&format!(",\"clock_observation\":{observation}"));
    }
    PROBES.replacen(
        "\"server_identity\": \"synthetic-example-server\"",
        &fields,
        1,
    )
}

#[test]
fn receipt_reconstructs_exact_packet_bytes_and_large_integer_clock_samples() -> Test {
    let proof = proof()?;
    let witness = proof.reconstruct()?;
    let json = receipt_json(Some(&witness_json(witness)), Some(&proof_json(&proof)));
    let receipts = parse_probe_receipts(json.as_bytes())?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].clock_observation, Some(proof));
    assert_eq!(receipts[0].clock_evidence, Some(witness));
    assert_eq!(receipts[1].clock_observation, None);
    assert_eq!(receipts[1].clock_evidence, None);
    receipts[0].validate()?;
    let again = parse_probe_receipts(json.as_bytes())?;
    assert_eq!(receipts[0].digest()?, again[0].digest()?);
    Ok(())
}

#[test]
fn absent_and_null_clock_observations_preserve_legacy_receipts_and_digests() -> Test {
    let legacy = parse_probe_receipts(PROBES.as_bytes())?;
    for json in [
        receipt_json(None, Some("null")),
        receipt_json(Some("null"), Some("null")),
    ] {
        let parsed = parse_probe_receipts(json.as_bytes())?;
        assert_eq!(parsed, legacy);
        assert_eq!(parsed[0].digest()?, legacy[0].digest()?);
    }
    let witness = witness_json(proof()?.reconstruct()?);
    let absent = parse_probe_receipts(receipt_json(Some(&witness), None).as_bytes())?;
    let null = parse_probe_receipts(receipt_json(Some(&witness), Some("null")).as_bytes())?;
    assert_eq!(absent, null);
    assert_eq!(absent[0].digest()?, null[0].digest()?);
    Ok(())
}

#[test]
fn every_derived_witness_field_must_equal_the_retained_proof() -> Test {
    let proof = proof()?;
    let original = proof.reconstruct()?;
    let observation = proof_json(&proof);
    for changed_field in 0..5 {
        let mut changed = original;
        match changed_field {
            0 => changed.wall_clock_unix_ns += 1,
            1 => changed.monotonic_ns += 1,
            2 => changed.ntp_offset_ns += 1,
            3 => changed.ntp_offset_direction = ClockOffsetDirection::Ahead,
            _ => changed.ntp_uncertainty_ns += 1,
        }
        changed.validate()?;
        assert_ne!(changed, original);
        let json = receipt_json(Some(&witness_json(changed)), Some(&observation));
        assert_eq!(
            parse_probe_receipts(json.as_bytes()),
            Err(SiteError::InvalidField("clock_observation"))
        );
    }
    for witness in [None, Some("null")] {
        let json = receipt_json(witness, Some(&observation));
        assert_eq!(
            parse_probe_receipts(json.as_bytes()),
            Err(SiteError::InvalidField("clock_observation"))
        );
    }
    Ok(())
}

#[test]
fn receipt_identity_binds_ignored_server_metadata_as_well_as_derived_witness() -> Test {
    let original = proof()?;
    let mut changed = original;
    changed.reply[12..16].copy_from_slice(b"NEXT");
    let witness = witness_json(original.reconstruct()?);
    assert_eq!(original.reconstruct()?, changed.reconstruct()?);
    let before = parse_probe_receipts(
        receipt_json(Some(&witness), Some(&proof_json(&original))).as_bytes(),
    )?;
    let after =
        parse_probe_receipts(receipt_json(Some(&witness), Some(&proof_json(&changed))).as_bytes())?;
    assert_eq!(before[0].clock_evidence, after[0].clock_evidence);
    assert_ne!(before[0].digest()?, after[0].digest()?);
    let unbound = parse_probe_receipts(receipt_json(Some(&witness), None).as_bytes())?;
    assert_eq!(unbound[0].clock_evidence, before[0].clock_evidence);
    assert_ne!(unbound[0].digest()?, before[0].digest()?);
    Ok(())
}

#[test]
fn proof_source_endpoint_policy_and_nested_field_sets_are_strict() -> Test {
    let proof = proof()?;
    let witness = witness_json(proof.reconstruct()?);
    let original = proof_json(&proof);
    for (needle, replacement) in [
        ("unauthenticated_loopback_ntp_claim", "authenticated_ntp"),
        (
            "fss.site_clock_observation.v1",
            "fss.site_clock_observation.v2",
        ),
        ("127.0.0.1:123", "192.0.2.1:123"),
        ("127.0.0.1:123", "localhost:123"),
        ("\"max_drift_ppb\":500000", "\"max_drift_ppb\":0"),
        ("\"policy\":{", "\"policy\":{\"hidden\":true,"),
        ("\"sent_before\":{", "\"sent_before\":{\"hidden\":true,"),
        ("\"source\":", "\"hidden\":true,\"source\":"),
        (
            "\"max_age_ns\":60000000000",
            "\"max_age_ns\":60000000000,\"max_age_ns\":60000000000",
        ),
    ] {
        let changed = original.replacen(needle, replacement, 1);
        assert_ne!(changed, original);
        let json = receipt_json(Some(&witness), Some(&changed));
        assert!(parse_probe_receipts(json.as_bytes()).is_err(), "{needle}");
    }
    Ok(())
}

#[test]
fn proof_numbers_never_coerce_strings_floats_exponents_or_overflow() -> Test {
    let proof = proof()?;
    let witness = witness_json(proof.reconstruct()?);
    let original = proof_json(&proof);
    for value in [
        "\"2000000000\"",
        "2000000000.0",
        "2e9",
        "-1",
        "18446744073709551616",
        "02000000000",
        "null",
        "true",
    ] {
        let changed = original.replacen(
            "\"observation_start_ns\":2000000000",
            &format!("\"observation_start_ns\":{value}"),
            1,
        );
        assert_ne!(changed, original);
        assert!(
            parse_probe_receipts(receipt_json(Some(&witness), Some(&changed)).as_bytes()).is_err(),
            "{value}"
        );
    }
    Ok(())
}

#[test]
fn raw_packet_evidence_requires_exact_lowercase_48_byte_hex() -> Test {
    let proof = proof()?;
    let witness = witness_json(proof.reconstruct()?);
    let original = proof_json(&proof);
    let valid = packet_hex(&proof.reply);
    for changed_hex in [
        valid[..94].to_owned(),
        format!("{valid}00"),
        valid.to_uppercase(),
        format!("g{}", &valid[1..]),
    ] {
        assert_ne!(changed_hex, valid);
        let changed = original.replacen(&valid, &changed_hex, 1);
        assert!(
            parse_probe_receipts(receipt_json(Some(&witness), Some(&changed)).as_bytes()).is_err()
        );
    }
    Ok(())
}
