#![forbid(unsafe_code)]
//! Real owned loopback UDP exchange followed by the existing native RTSP path.
//! These tests exercise approval, packet custody and clock reconstruction, not
//! authenticated UTC, camera exposure time or a physical time daemon.

use super::*;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use fss_reference::site::clock_proof::LOCAL_NTP_CLOCK_POLICY;
use fss_reference::site::probe_observation::{
    NegotiatedProbe, ObservationError, RtspProbeObserver,
};
use fss_reference::site::{ClockOffsetDirection, ProbeCodec};

const ASSERTED_OFFSET_NS: u64 = 2_000_000_000;

#[derive(Clone, Copy, Debug)]
enum TimeReply {
    Valid,
    WrongOrigin,
    PendingLeap,
    Unsynchronized,
    KissOfDeath,
    Truncated,
    Oversized,
    Silent,
}

struct TimeExchange {
    request: [u8; 48],
    reply: Vec<u8>,
}

fn time_listener() -> Test<UdpSocket> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn no_time_datagram(socket: &UdpSocket) -> Test {
    socket.set_nonblocking(true)?;
    let mut bytes = [0_u8; 512];
    match socket.recv_from(&mut bytes) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("unexpected or repeated clock request reached the daemon".into()),
    }
}

fn unix_now_ns() -> Test<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

// Independent server-side wire encoding. The fixture does not call the packet
// owner's request builder or evaluator to manufacture its expected response.
fn timestamp(unix_ns: u64) -> [u8; 8] {
    let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
    let fraction = (((unix_ns % 1_000_000_000) as u128) << 32) / 1_000_000_000;
    let mut result = [0_u8; 8];
    result[..4].copy_from_slice(&seconds.to_be_bytes());
    result[4..].copy_from_slice(&(fraction as u32).to_be_bytes());
    result
}

fn serve_time(socket: &UdpSocket, behavior: TimeReply) -> Test<TimeExchange> {
    socket.set_nonblocking(false)?;
    // Match the camera fixture's startup allowance. The production client's
    // independent one-second exchange deadline excludes process startup.
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut received = [0_u8; 512];
    let (length, client) = socket.recv_from(&mut received)?;
    let receive_ns = unix_now_ns()? + ASSERTED_OFFSET_NS;
    assert_eq!(length, 48, "native client sent a non-basic NTP request");
    let request: [u8; 48] = received[..length].try_into()?;
    assert_eq!(request[0], 0x23);
    assert!(request[1..40].iter().all(|byte| *byte == 0));
    assert_ne!(&request[40..48], &[0; 8]);
    assert!(client.ip().is_loopback());
    assert_ne!(client.port(), 0);
    assert_ne!(client, socket.local_addr()?);

    let mut reply = vec![0_u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 4;
    reply[3] = (-20_i8) as u8;
    reply[11] = 1; // One unsigned 16.16 root-dispersion unit.
    reply[12..16].copy_from_slice(b"LOCL");
    reply[16..24].copy_from_slice(&timestamp(receive_ns - 1_000_000_000));
    reply[24..32].copy_from_slice(&request[40..48]);
    reply[32..40].copy_from_slice(&timestamp(receive_ns));
    reply[40..48].copy_from_slice(&timestamp(unix_now_ns()? + ASSERTED_OFFSET_NS));
    match behavior {
        TimeReply::Valid => {}
        TimeReply::WrongOrigin => reply[31] ^= 1,
        TimeReply::PendingLeap => reply[0] |= 0x40,
        TimeReply::Unsynchronized => reply[0] |= 0xc0,
        TimeReply::KissOfDeath => {
            reply[1] = 0;
            reply[12..16].copy_from_slice(b"RATE");
        }
        TimeReply::Truncated => reply.truncate(47),
        TimeReply::Oversized => reply.extend_from_slice(&[0_u8; 64]),
        TimeReply::Silent => reply.clear(),
    }
    if !reply.is_empty() {
        assert_eq!(socket.send_to(&reply, client)?, reply.len());
    }
    Ok(TimeExchange { request, reply })
}

fn clock_args(fixture: &Fixture, codec: Codec, peer: SocketAddr) -> Vec<OsString> {
    let mut args = fixture.args(codec);
    args.extend(["--clock-ntp-peer".into(), peer.to_string().into()]);
    args
}

fn approve(args: &mut Vec<OsString>) -> Test<Value> {
    let preview = good(run(args)?)?;
    assert_eq!(text(&preview, "schema")?, "fss.site_probe_plan.v1");
    args.extend(["--approve".into(), text(&preview, "approval")?.into()]);
    Ok(preview)
}

fn clock_refusal(output: Output) -> Test<Value> {
    assert!(
        !output.status.success(),
        "invalid clock exchange issued a successful probe"
    );
    no_secrets(&output);
    assert!(output.stderr.is_empty());
    let value = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&value, "schema")?, "fss.site_probe_diagnostic.v1");
    assert_eq!(
        output.status.code().map(i128::from),
        Some(integer(&value, "exit_code")?)
    );
    for name in [
        "connection_attempted",
        "credential_access_attempted",
        "source_retained",
        "receipt_issued",
        "retry_automatically",
        "teardown_acknowledged",
        "remote_session_may_exist",
    ] {
        assert!(!boolean(&value, name)?, "clock refusal misreported {name}");
    }
    Ok(value)
}

#[test]
fn observation_anchor_is_the_first_picture_timestamp_not_parameters_or_completion() -> Test {
    let manifest = parse_manifest(include_bytes!(
        "../../../../fixtures/site_probe/manifest.v1.json"
    ))?;
    for codec in [Codec::Avc, Codec::Hevc, Codec::Jpeg] {
        let (selected, raw_parameters): (ProbeCodec, &[&str]) = match codec {
            Codec::Avc => (ProbeCodec::Avc, &[AVC_SPS, AVC_PPS]),
            Codec::Hevc => (ProbeCodec::Hevc, &[HEVC_VPS, HEVC_SPS, HEVC_PPS]),
            Codec::Jpeg => (ProbeCodec::Jpeg, &[]),
        };
        let parameters = raw_parameters
            .iter()
            .map(|value| decode_base64(value))
            .collect::<Result<Vec<_>, _>>()?;
        let parameter_slices = parameters.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let description = codec.description();
        let mut observer = RtspProbeObserver::new(
            &manifest,
            0,
            NegotiatedProbe {
                sdp: description.as_bytes(),
                media_index: 0,
                rtp_channel: codec.channel(),
                codec: selected,
                payload_type: codec.payload(),
                parameter_sets: &parameter_slices,
                server_identity: "clock-anchor-fixture",
            },
        )?;
        assert_eq!(
            observer.first_picture_observed_at(),
            Err(ObservationError::Incomplete)
        );
        let packets = codec.packets()?;
        // AVC admits a parameter-only prefix with its own timestamp. HEVC's
        // owner deliberately marks a retired metadata-only group before an AUD
        // as a discontinuity, so preserve its checked-in startup sequence.
        if matches!(codec, Codec::Avc) {
            let parameter = parameters.first().ok_or("AVC fixture SPS missing")?;
            let first = RtpPacket::parse(&packets[0], PacketLimits::default())?;
            let mut prefix = vec![0x80, codec.payload()];
            prefix.extend_from_slice(&first.sequence().wrapping_sub(1).to_be_bytes());
            prefix.extend_from_slice(&FIRST_TIMESTAMP.wrapping_sub(FRAME_TICKS).to_be_bytes());
            prefix.extend_from_slice(&codec.ssrc().to_be_bytes());
            prefix.extend_from_slice(parameter);
            observer.observe_rtp_at(codec.channel(), &prefix, 1_000)?;
            assert_eq!(
                observer.first_picture_observed_at(),
                Err(ObservationError::Incomplete)
            );
        }
        let expected = 1_000_000;
        let mut first_confirmation = None;
        for (index, packet) in packets.iter().enumerate() {
            let admitted_at = expected + index as u64 * 1_000;
            observer.observe_rtp_at(codec.channel(), packet, admitted_at)?;
            if observer.confirmed_pictures() > 0 {
                first_confirmation.get_or_insert(admitted_at);
                assert_eq!(observer.first_picture_observed_at()?, expected);
            }
            if observer.confirmed_pictures() >= 3 {
                break;
            }
        }
        assert!(first_confirmation.ok_or("fixture never confirmed a picture")? > expected);
        observer.freeze_prefix()?;
        assert_eq!(observer.first_picture_observed_at()?, expected);
        let receipt = observer.finish_prefix()?;
        assert_eq!(receipt.first_rtp_timestamp, FIRST_TIMESTAMP);
        assert!(receipt.clock_evidence.is_none());
        assert!(receipt.clock_observation.is_none());
    }
    Ok(())
}

#[test]
fn clock_preview_and_peer_changes_never_send_udp_or_connect_the_camera() -> Test {
    let camera = listener()?;
    let first = time_listener()?;
    let second = time_listener()?;
    let fixture = Fixture::new("clock-approval", camera.local_addr()?)?;
    fixture.write()?;
    let mut args = clock_args(&fixture, Codec::Avc, first.local_addr()?);
    let preview = approve(&mut args)?;
    let clock = field(&preview, "clock_observation")?;
    assert_eq!(text(clock, "source")?, "unauthenticated_loopback_ntp_claim");
    assert_eq!(text(clock, "peer")?, first.local_addr()?.to_string());
    assert_eq!(integer(clock, "exchanges")?, 1);
    for name in [
        "server_authenticated",
        "camera_capture_time",
        "adjust_host_clock",
        "retry_automatically",
    ] {
        assert!(!boolean(clock, name)?);
    }
    no_time_datagram(&first)?;
    no_connection(&camera)?;

    let mut changed_peer = args.clone();
    replace(
        &mut changed_peer,
        "--clock-ntp-peer",
        second.local_addr()?.to_string(),
    )?;
    let mut removed_clock = args.clone();
    let at = removed_clock
        .iter()
        .position(|arg| arg == "--clock-ntp-peer")
        .ok_or("clock option missing")?;
    removed_clock.drain(at..at + 2);
    let mut added_clock = fixture.approved(Codec::Avc)?;
    added_clock.extend([
        "--clock-ntp-peer".into(),
        first.local_addr()?.to_string().into(),
    ]);
    for changed in [changed_peer, removed_clock, added_clock] {
        let refused = clock_refusal(run(&changed)?)?;
        assert_eq!(text(&refused, "error_id")?, "ERR-SITE-PROBE-APPROVAL-001");
    }
    no_time_datagram(&first)?;
    no_time_datagram(&second)?;
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn real_udp_clock_evidence_reconstructs_for_all_native_codec_receipts() -> Test {
    for codec in [Codec::Avc, Codec::Hevc, Codec::Jpeg] {
        let camera = listener()?;
        let daemon = time_listener()?;
        let peer = daemon.local_addr()?;
        let fixture = Fixture::new(&format!("clock-{}", codec.name()), camera.local_addr()?)?;
        fixture.write()?;
        let mut args = clock_args(&fixture, codec, peer);
        approve(&mut args)?;
        no_time_datagram(&daemon)?;
        no_connection(&camera)?;

        let (output, camera_transcript, exchange) = thread::scope(|scope| -> Test<_> {
            let clock = scope.spawn(|| serve_time(&daemon, TimeReply::Valid));
            let result = probed(camera, &args, codec, Behavior::Complete);
            let exchange = clock.join().map_err(|_| "clock fixture panicked")??;
            let (output, camera_transcript) = result?;
            Ok((output, camera_transcript, exchange))
        })?;
        no_secrets(&output);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(output.stderr.is_empty());
        let receipts = parse_probe_receipts(&output.stdout)?;
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        receipt.validate_for(&parse_manifest(render(&fixture.manifest).as_bytes())?)?;
        assert_eq!(receipt.codec.as_str(), codec.name());
        assert_eq!(receipt.observed_frames, 3);
        assert_eq!(receipt.first_rtp_timestamp, FIRST_TIMESTAMP);
        assert_eq!(
            receipt.last_rtp_timestamp,
            FIRST_TIMESTAMP.wrapping_add(2 * FRAME_TICKS)
        );
        let witness = receipt.clock_evidence.ok_or("live clock witness missing")?;
        let proof = receipt
            .clock_observation
            .as_ref()
            .ok_or("raw live clock proof missing")?;
        assert_eq!(proof.peer, peer);
        assert_eq!(proof.request, exchange.request);
        assert_eq!(proof.reply.as_slice(), exchange.reply.as_slice());
        assert_eq!(proof.policy, LOCAL_NTP_CLOCK_POLICY);
        assert_eq!(proof.reconstruct()?, witness);
        assert_eq!(witness.monotonic_ns, proof.observation_start_ns);
        assert!(proof.observation_start_ns >= proof.received_after.monotonic_after_ns);
        assert!(proof.observation_end_ns >= proof.observation_start_ns);
        assert!(proof.terminal.monotonic_before_ns >= proof.observation_end_ns);
        assert_eq!(witness.ntp_offset_direction, ClockOffsetDirection::Behind);
        assert!(witness.ntp_offset_ns.abs_diff(ASSERTED_OFFSET_NS) <= 1_000_000_000);
        assert!(witness.ntp_uncertainty_ns > 0);
        assert!(
            witness.ntp_uncertainty_ns >= proof.observation_end_ns - proof.observation_start_ns
        );
        assert_eq!(proof.source_digest()?, proof.correlation()?.source_digest());
        assert_ne!(proof.digest()?, proof.source_digest()?);
        let duration_ns = (u128::from(receipt.frame_duration_ticks)
            * u128::from(receipt.observed_frames - 1)
            * 1_000_000_000)
            .div_ceil(u128::from(receipt.clock_rate_hz));
        assert_eq!(
            receipt.utc_window(),
            Some((
                witness.wall_clock_unix_ns - witness.ntp_uncertainty_ns,
                witness.wall_clock_unix_ns
                    + u64::try_from(duration_ns)?
                    + witness.ntp_uncertainty_ns,
            ))
        );
        assert_eq!(
            camera_transcript.methods,
            ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
        );
        assert!(camera_transcript.client_closed);
        no_time_datagram(&daemon)?;
    }
    Ok(())
}

#[test]
fn invalid_or_absent_time_replies_refuse_before_camera_contact_without_retry() -> Test {
    for behavior in [
        TimeReply::WrongOrigin,
        TimeReply::PendingLeap,
        TimeReply::Unsynchronized,
        TimeReply::KissOfDeath,
        TimeReply::Truncated,
        TimeReply::Oversized,
        TimeReply::Silent,
    ] {
        let camera = listener()?;
        let daemon = time_listener()?;
        let fixture = Fixture::new(&format!("clock-refused-{behavior:?}"), camera.local_addr()?)?;
        fixture.write()?;
        let mut args = clock_args(&fixture, Codec::Avc, daemon.local_addr()?);
        approve(&mut args)?;
        let output = thread::scope(|scope| -> Test<_> {
            let server = scope.spawn(|| serve_time(&daemon, behavior));
            let output = run(&args);
            server
                .join()
                .map_err(|_| "clock refusal fixture panicked")??;
            output
        })?;
        let refused = clock_refusal(output)?;
        let error_id = text(&refused, "error_id")?;
        if matches!(behavior, TimeReply::Silent) {
            // The cap can expire in the receive loop or at the runtime wait
            // admission. Both owners must refuse without retry or RTSP effects.
            assert!(matches!(
                error_id,
                "ERR-SITE-CLOCK-DEADLINE-001" | "ERR-SITE-PROBE-DEADLINE-001"
            ));
        } else {
            let expected = match behavior {
                TimeReply::Truncated | TimeReply::Oversized => "ERR-SITE-CLOCK-REPLY-001",
                _ => "ERR-SITE-CLOCK-PROOF-001",
            };
            assert_eq!(error_id, expected, "{behavior:?}");
        }
        no_connection(&camera)?;
        no_time_datagram(&daemon)?;
    }
    Ok(())
}

#[test]
fn time_peer_requires_a_literal_canonical_nonzero_loopback_endpoint() -> Test {
    let camera = listener()?;
    let fixture = Fixture::new("clock-peer-scope", camera.local_addr()?)?;
    fixture.write()?;
    for peer in [
        "localhost:123",
        "192.0.2.1:123",
        "127.0.0.1:0",
        "127.0.0.1:00123",
    ] {
        let mut args = fixture.args(Codec::Avc);
        args.extend(["--clock-ntp-peer".into(), peer.into()]);
        let output = run(&args)?;
        assert!(
            !output.status.success(),
            "unsupported clock endpoint {peer} admitted"
        );
        no_secrets(&output);
        no_connection(&camera)?;
    }
    Ok(())
}
