#![forbid(unsafe_code)]
//! Raw-packet-to-witness contracts for bounded native site synchronization.

use std::error::Error;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use fss_packet::ntp::{SntpError, SntpRequest};
use fss_reference::site::clock::{ClockCorrelationError as C, HostClockSample};
use fss_reference::site::clock_proof::{
    ClockProofError as E, LOCAL_NTP_CLOCK_POLICY, LocalNtpClockProof,
};

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
    reply[0] = 0x24; // v4, basic server, no pending leap.
    reply[1] = 2;
    reply[2] = 6;
    reply[3] = (-30_i8) as u8;
    reply[12..16].copy_from_slice(b"TEST");
    // The fixture server is one second ahead. One-way delays may be unequal;
    // server processing is one millisecond, inside the 20ms local exchange.
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

#[test]
fn retained_exchange_reconstructs_a_nonzero_conservative_first_observation_witness()
-> Result<(), Box<dyn Error>> {
    let proof = proof()?;
    let witness = proof.reconstruct()?;
    witness.validate()?;
    assert_eq!(witness.monotonic_ns, proof.observation_start_ns);
    // Fixture truth: the host advanced one second, and the UTC assertion is
    // another second ahead. Every instant of the three-millisecond read bracket
    // must remain possible; no symmetric-delay assumption selects its midpoint.
    assert!(witness.wall_clock_unix_ns - witness.ntp_uncertainty_ns <= EPOCH + 2_000_000_000);
    assert!(witness.wall_clock_unix_ns + witness.ntp_uncertainty_ns >= EPOCH + 2_003_000_000);
    assert!(witness.ntp_uncertainty_ns > 12_000_000);
    assert!(witness.ntp_uncertainty_ns < 14_000_000);
    assert_eq!(proof.reconstruct()?, witness);
    assert_eq!(proof.digest()?, proof.digest()?);
    assert_ne!(proof.source_digest()?, proof.digest()?);
    Ok(())
}

#[test]
fn observation_read_width_includes_declared_drift_growth() -> Result<(), Box<dyn Error>> {
    let wide = proof()?;
    let mut point = wide;
    point.observation_end_ns = point.observation_start_ns;
    let point_witness = point.reconstruct()?;
    let wide_witness = wide.reconstruct()?;
    assert_eq!(
        point_witness.wall_clock_unix_ns,
        wide_witness.wall_clock_unix_ns
    );
    assert_eq!(point_witness.ntp_offset_ns, wide_witness.ntp_offset_ns);
    // Three milliseconds at 500000 ppb costs another 1500ns; adding only
    // 3000000ns would have rounded away a valid faster-clock world.
    assert_eq!(
        wide_witness.ntp_uncertainty_ns - point_witness.ntp_uncertainty_ns,
        3_001_500
    );
    assert_eq!(point.source_digest()?, wide.source_digest()?);
    assert_ne!(point.digest()?, wide.digest()?);
    Ok(())
}

#[test]
fn host_read_brackets_are_retained_and_widened_instead_of_collapsed() -> Result<(), Box<dyn Error>>
{
    let point = proof()?;
    let mut bracketed = point;
    // Ten nanoseconds around each wall read; preserve ordering around I/O.
    for sample in [
        &mut bracketed.sent_before,
        &mut bracketed.sent_after,
        &mut bracketed.received_before,
        &mut bracketed.received_after,
        &mut bracketed.terminal,
    ] {
        sample.monotonic_before_ns -= 5;
        sample.monotonic_after_ns += 5;
    }
    let old = point.reconstruct()?;
    let new = bracketed.reconstruct()?;
    assert!(new.ntp_uncertainty_ns >= old.ntp_uncertainty_ns + 5);
    assert!(
        new.wall_clock_unix_ns - new.ntp_uncertainty_ns
            <= old.wall_clock_unix_ns - old.ntp_uncertainty_ns
    );
    assert!(
        new.wall_clock_unix_ns + new.ntp_uncertainty_ns
            >= old.wall_clock_unix_ns + old.ntp_uncertainty_ns
    );
    assert_ne!(point.source_digest()?, bracketed.source_digest()?);
    assert_ne!(point.digest()?, bracketed.digest()?);
    Ok(())
}

#[test]
fn raw_server_metadata_and_endpoint_are_bound_even_when_the_witness_is_unchanged()
-> Result<(), Box<dyn Error>> {
    let original = proof()?;
    let mut metadata = original;
    metadata.reply[12..16].copy_from_slice(b"NEXT");
    assert_eq!(metadata.reconstruct()?, original.reconstruct()?);
    assert_ne!(metadata.source_digest()?, original.source_digest()?);
    assert_ne!(metadata.digest()?, original.digest()?);
    let mut peer = original;
    peer.peer = "127.0.0.1:4123".parse()?;
    assert_eq!(peer.reconstruct()?, original.reconstruct()?);
    assert_ne!(peer.source_digest()?, original.source_digest()?);
    assert_ne!(peer.digest()?, original.digest()?);
    Ok(())
}

#[test]
fn terminal_checks_change_proof_identity_without_retroactively_tightening_uncertainty()
-> Result<(), Box<dyn Error>> {
    let original = proof()?;
    let mut later = original;
    later.terminal = host(3_000_000_000);
    assert_eq!(later.reconstruct()?, original.reconstruct()?);
    assert_eq!(later.source_digest()?, original.source_digest()?);
    assert_ne!(later.digest()?, original.digest()?);
    Ok(())
}

#[test]
fn a_step_during_the_exchange_is_refused_before_it_can_become_offset_evidence()
-> Result<(), Box<dyn Error>> {
    for index in 0..4 {
        let mut candidate = proof()?;
        let sample = match index {
            0 => &mut candidate.sent_before,
            1 => &mut candidate.sent_after,
            2 => &mut candidate.received_before,
            _ => &mut candidate.received_after,
        };
        sample.wall_clock_unix_ns += 1_000_000_000;
        assert_eq!(
            candidate.reconstruct(),
            Err(E::Correlation(C::WallClockDiscontinuity))
        );
        assert!(candidate.digest().is_err());
    }
    Ok(())
}

#[test]
fn terminal_step_or_expired_synchronization_refuses_the_complete_witness()
-> Result<(), Box<dyn Error>> {
    for forward in [true, false] {
        let mut candidate = proof()?;
        if forward {
            candidate.terminal.wall_clock_unix_ns += 1_000_000_000;
        } else {
            candidate.terminal.wall_clock_unix_ns -= 1_000_000_000;
        }
        assert_eq!(
            candidate.reconstruct(),
            Err(E::Correlation(C::WallClockDiscontinuity))
        );
    }
    let mut stale = proof()?;
    stale.terminal = host(61_000_000_000);
    assert_eq!(stale.reconstruct(), Err(E::Correlation(C::Expired)));
    Ok(())
}

#[test]
fn out_of_order_exchange_or_observation_brackets_cannot_be_rebased_silently()
-> Result<(), Box<dyn Error>> {
    let mut before_sync = proof()?;
    before_sync.observation_start_ns = before_sync.received_after.monotonic_before_ns - 1;
    assert_eq!(before_sync.reconstruct(), Err(E::ObservationOrder));
    let mut reversed = proof()?;
    reversed.observation_end_ns = reversed.observation_start_ns - 1;
    assert_eq!(reversed.reconstruct(), Err(E::ObservationOrder));
    let mut past_terminal = proof()?;
    past_terminal.observation_end_ns = past_terminal.terminal.monotonic_before_ns + 1;
    assert_eq!(past_terminal.reconstruct(), Err(E::ObservationOrder));
    let mut reordered = proof()?;
    std::mem::swap(&mut reordered.sent_after, &mut reordered.received_before);
    assert_eq!(reordered.reconstruct(), Err(E::ObservationOrder));
    Ok(())
}

#[test]
fn exact_request_and_origin_binding_prevent_cross_exchange_replay() -> Result<(), Box<dyn Error>> {
    let mut wrong_request = proof()?;
    wrong_request.request[3] = 1;
    assert_eq!(wrong_request.reconstruct(), Err(E::RequestMismatch));
    let mut wrong_reply = proof()?;
    wrong_reply.reply[24] ^= 1;
    assert_eq!(wrong_reply.reconstruct(), Err(E::Ntp(SntpError::Origin)));
    let mut missing_reply = proof()?;
    missing_reply.reply = [0; 48];
    assert_eq!(missing_reply.reconstruct(), Err(E::Ntp(SntpError::Version)));
    Ok(())
}

#[test]
fn pending_leaps_and_unsynchronized_servers_do_not_produce_native_utc_witnesses()
-> Result<(), Box<dyn Error>> {
    for leap in [1_u8, 2] {
        let mut candidate = proof()?;
        candidate.reply[0] |= leap << 6;
        assert_eq!(candidate.reconstruct(), Err(E::LeapUnsupported));
    }
    let mut unsynchronized = proof()?;
    unsynchronized.reply[0] |= 3 << 6;
    assert_eq!(
        unsynchronized.reconstruct(),
        Err(E::Ntp(SntpError::Unsynchronized))
    );
    let mut stratum_zero = proof()?;
    stratum_zero.reply[1] = 0;
    assert_eq!(
        stratum_zero.reconstruct(),
        Err(E::Ntp(SntpError::KissOfDeath))
    );
    Ok(())
}

#[test]
fn only_the_exact_loopback_native_profile_is_admitted() -> Result<(), Box<dyn Error>> {
    for peer in [
        "192.0.2.1:123",
        "0.0.0.0:123",
        "127.0.0.1:0",
        "[::ffff:127.0.0.1]:123",
    ] {
        let mut candidate = proof()?;
        candidate.peer = peer.parse()?;
        assert_eq!(candidate.reconstruct(), Err(E::Peer));
    }
    let mut ipv6 = proof()?;
    ipv6.peer = "[::1]:123".parse()?;
    assert!(ipv6.reconstruct().is_ok());
    ipv6.peer = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 123, 0, 1));
    assert_eq!(ipv6.reconstruct(), Err(E::Peer));
    for field in 0..3 {
        let mut candidate = proof()?;
        match field {
            0 => candidate.policy.max_sample_bracket_ns -= 1,
            1 => candidate.policy.max_drift_ppb -= 1,
            _ => candidate.policy.max_age_ns -= 1,
        }
        assert_eq!(candidate.reconstruct(), Err(E::Policy));
    }
    Ok(())
}

#[test]
fn excessively_slow_reads_or_uncertainty_fail_instead_of_fabricating_precision()
-> Result<(), Box<dyn Error>> {
    let mut slow = proof()?;
    slow.received_after.monotonic_after_ns += LOCAL_NTP_CLOCK_POLICY.max_sample_bracket_ns + 1;
    assert_eq!(slow.reconstruct(), Err(E::Correlation(C::InvalidSample)));
    let mut huge_read = proof()?;
    huge_read.observation_end_ns = ORIGIN + 12_000_000_000;
    huge_read.terminal = host(13_000_000_000);
    assert_eq!(
        huge_read.reconstruct(),
        Err(E::Correlation(C::UncertaintyLimit))
    );
    let mut excessive_server_error = proof()?;
    // Root dispersion 16s, encoded unsigned 16.16, exceeds the native 10s bound.
    excessive_server_error.reply[8..12].copy_from_slice(&(16_u32 << 16).to_be_bytes());
    assert_eq!(
        excessive_server_error.reconstruct(),
        Err(E::Ntp(SntpError::Uncertainty))
    );
    Ok(())
}

#[test]
fn debug_and_refusal_text_do_not_dump_endpoint_or_raw_packet_bytes() -> Result<(), Box<dyn Error>> {
    let original = proof()?;
    let rendered = format!("{original:?}");
    assert!(!rendered.contains("127.0.0.1"));
    assert!(!rendered.contains("request"));
    assert!(!rendered.contains("reply"));
    assert!(!rendered.contains("TEST"));
    let mut candidate = original;
    candidate.request[0] ^= 1;
    let error = candidate
        .reconstruct()
        .err()
        .ok_or("expected request refusal")?;
    assert_eq!(
        error.to_string(),
        "site NTP request does not match its host sample"
    );
    Ok(())
}

#[test]
fn admitted_exchange_can_start_live_monitoring_before_an_observation_is_available()
-> Result<(), Box<dyn Error>> {
    let mut pending = proof()?;
    pending.observation_start_ns = 0;
    pending.observation_end_ns = 0;
    pending.terminal = host(0);
    assert_eq!(pending.reconstruct(), Err(E::ObservationOrder));
    let mut monitor = pending.correlation()?;
    assert_eq!(monitor.source_digest(), pending.source_digest()?);
    assert_ne!(monitor.offset_interval().lower_ns, -1);
    assert_ne!(monitor.offset_interval().upper_ns, 1);
    monitor.observe_later_sample(host(500_000_000))?;
    let mut stepped = host(501_000_000);
    stepped.wall_clock_unix_ns += 1_000_000;
    assert_eq!(
        monitor.observe_later_sample(stepped),
        Err(C::WallClockDiscontinuity)
    );
    assert_eq!(monitor.project(ORIGIN + 1_000_000_000), Err(C::Invalidated));
    Ok(())
}
