#![forbid(unsafe_code)]
//! Each explicitly planned attempt learns its own sender and retains that exact RTP identity.

use super::*;
use fss_core::{SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::{PacketLimits, RtpPacket};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use fss_reference::rtsp::recording::local::load_recording;

#[derive(Clone, Copy, Debug)]
enum Codec {
    Avc,
    Hevc,
}

impl Codec {
    fn name(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }

    fn payload_type(self) -> u8 {
        match self {
            Self::Avc => 96,
            Self::Hevc => 98,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Avc => SDP,
            Self::Hevc => concat!(
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\n",
                "a=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\n",
                "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
                "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
                "sprop-pps=RAHAc8CJ\r\na=control:trackID=0\r\n"
            ),
        }
    }
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(at) = args.iter().position(|arg| arg == key) {
        args[at + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

fn automatic_args(directory: &Directory, peer: SocketAddr, codec: Codec) -> Vec<OsString> {
    let mut args = args(directory, peer, codec.name());
    set(&mut args, "--ssrc", "auto");
    set(&mut args, "--max-attempts", "2");
    if matches!(codec, Codec::Hevc) {
        set(&mut args, "--payload-type", "98");
        set(&mut args, "--frame-duration-ticks", "18000");
    }
    args
}

#[derive(Clone, Copy)]
struct Sender {
    advertised: Option<u32>,
    actual: u32,
    eof: bool,
    switch_at_end: bool,
}

fn hevc_packets(eof: bool) -> Test<Vec<Vec<u8>>> {
    let fixture = include_str!("../../../../tests/fixtures/media/hevc/remux_main8.nals.hex");
    let nals = fixture
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            if !line.is_ascii() || line.len() % 2 != 0 {
                return Err("invalid pinned HEVC fixture".into());
            }
            (0..line.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                .collect::<Test<Vec<_>>>()
        })
        .collect::<Test<Vec<_>>>()?;
    let mut packets = Vec::new();
    // The preceding packet is genuine receiver probation. A following source NAL, not an RTP
    // marker or transport EOF, closes each HEVC picture retained by the native owner.
    let timestamps = [0_u32, 0, 0, 0, 0, 18_000, 36_000];
    let nals = std::iter::once(nals.first().ok_or("missing fixture VPS")?)
        .chain(nals.iter().take(if eof { 5 } else { 6 }));
    for (index, (nal, timestamp)) in nals.zip(timestamps).enumerate() {
        let mut packet = vec![0x80, 98 | 128];
        packet.extend_from_slice(&u16::try_from(index)?.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&7_u32.to_be_bytes());
        packet.extend_from_slice(nal);
        packets.push(packet);
    }
    Ok(packets)
}

fn sender_packets(codec: Codec, sender: Sender) -> Test<Vec<Vec<u8>>> {
    let mut packets = match codec {
        Codec::Avc => {
            let wire = video(if sender.eof { 1 } else { 2 })?;
            let mut packets = Vec::new();
            let mut at = 0;
            while at < wire.len() {
                assert_eq!(&wire[at..at + 2], b"$\0");
                let length = usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]]));
                packets.push(wire[at + 4..at + 4 + length].to_vec());
                at += 4 + length;
            }
            packets
        }
        Codec::Hevc => hevc_packets(sender.eof)?,
    };
    for packet in &mut packets {
        packet[8..12].copy_from_slice(&sender.actual.to_be_bytes());
    }
    if sender.switch_at_end {
        packets.last_mut().ok_or("empty RTP fixture")?[8..12]
            .copy_from_slice(&sender.actual.wrapping_add(1).to_be_bytes());
    }
    Ok(packets)
}

fn serve_sender(listener: &TcpListener, codec: Codec, sender: Sender) -> Test<Vec<Vec<u8>>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_nonblocking(false)?;
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    response(
        &mut peer,
        cseq,
        "Content-Type: application/sdp\r\n",
        codec.description(),
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP");
    let advertised = sender
        .advertised
        .map_or_else(String::new, |ssrc| format!(";ssrc={ssrc:08X}"));
    response(
        &mut peer,
        cseq,
        &format!(
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1{advertised}\r\n"
        ),
        "",
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY");
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    let packets = sender_packets(codec, sender)?;
    let mut wire = Vec::new();
    for packet in &packets {
        wire.extend_from_slice(&[b'$', 0]);
        wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        wire.extend_from_slice(packet);
    }
    peer.write_all(&wire)?;
    if sender.eof {
        peer.shutdown(Shutdown::Write)?;
    }
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else {
            return Ok(packets);
        };
        assert!(matches!(
            method.as_str(),
            "OPTIONS" | "GET_PARAMETER" | "TEARDOWN"
        ));
        response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    }
    Err("sender fixture exceeded its control request bound".into())
}

fn captured_senders(
    listener: &TcpListener,
    args: &[OsString],
    codec: Codec,
    senders: &[Sender],
) -> Test<(Output, Vec<Vec<Vec<u8>>>)> {
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            senders
                .iter()
                .map(|sender| serve_sender(listener, codec, *sender))
                .collect::<Test<Vec<_>>>()
        });
        let output = run(args)?;
        match server.join().map_err(|_| "sender fixture panicked")? {
            Ok(packets) => Ok((output, packets)),
            Err(error) => Err(format!(
                "{error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
        }
    })
}

fn verify_retained_sender(
    directory: &Directory,
    codec: Codec,
    ordinal: usize,
    started: &Value,
    window: &Value,
    sender: u32,
    originals: &[Vec<u8>],
) -> Test {
    let publisher = LocalRootPublisher::open(
        directory.attempt("capture", ordinal),
        LocalPublicationLimits::new(
            256,
            64,
            256,
            512,
            SpoolLimits::new(1024, 64 * 1024 * 1024, 16 * 1024 * 1024, 1024),
        ),
    )?;
    let source = field(started, "source")?;
    let scope = RecordingScope {
        sensor: SensorId::parse(text(source, "sensor_id")?)?,
        stream: StreamId::parse(text(source, "stream_id")?)?,
        generation: u64::try_from(number(source, "generation")?)?,
        anchor: ContentDigest::parse(text(source, "anchor")?)?,
        receive_clock: ContentDigest::parse(text(source, "receive_clock")?)?,
    };
    let slot = SlotName::parse(text(window, "slot")?)?;
    let root = ContentDigest::parse(text(window, "root")?)?;
    let packets: Vec<Vec<u8>> = match codec {
        Codec::Avc => load_recording(&publisher, &slot, root, &scope, &NeverCancel)?
            .packets()?
            .iter()
            .map(|packet| packet.bytes.to_vec())
            .collect(),
        Codec::Hevc => load_hevc_recording(&publisher, &slot, root, &scope, &NeverCancel)?
            .packets()?
            .iter()
            .map(|packet| packet.bytes.to_vec())
            .collect(),
    };
    assert!(!packets.is_empty());
    for packet in packets {
        let parsed = RtpPacket::parse(&packet, PacketLimits::default())?;
        assert_eq!(parsed.ssrc(), sender);
        assert_eq!(parsed.payload_type(), codec.payload_type());
        assert!(
            originals.contains(&packet),
            "retained RTP must be original wire bytes"
        );
    }
    Ok(())
}

#[test]
fn automatic_reconnect_requires_its_exact_outer_approval_before_any_effect() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new("auto-approval")?;
        let listener = listener()?;
        let automatic = automatic_args(&directory, listener.local_addr()?, codec);
        let mut numeric = automatic.clone();
        set(&mut numeric, "--ssrc", "0");
        let pinned = preview(&numeric)?;
        let plan = preview(&automatic)?;
        assert_ne!(text(&pinned, "approval")?, text(&plan, "approval")?);
        assert_eq!(text(&plan, "ssrc_selection")?, "learn_once_per_attempt");
        assert!(!flag(&plan, "mid_session_sender_change_retry")?);
        for key in [
            "max_attempts",
            "maximum_capture_and_drain_ns",
            "maximum_source_bytes",
            "maximum_archive_spool_bytes",
            "maximum_native_report_bytes",
        ] {
            assert_eq!(number(&pinned, key)?, number(&plan, key)?);
        }
        let children = field(&plan, "attempts")?.array().ok_or("attempt array")?;
        let pinned_children = field(&pinned, "attempts")?.array().ok_or("attempt array")?;
        assert_eq!(children.len(), 2);
        for (index, child) in children.iter().enumerate() {
            assert_eq!(
                text(child, "ssrc_state")?,
                "unknown_until_session_observation"
            );
            assert_ne!(
                text(child, "decode_clock")?,
                text(&pinned_children[index], "decode_clock")?
            );
        }
        for wrong in [text(&pinned, "approval")?, text(&children[0], "approval")?] {
            let mut input = automatic.clone();
            set(&mut input, "--approve", wrong);
            let output = run(&input)?;
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(fs::read_dir(&directory.0)?.next().is_none());
            assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        }
        let mut changed = automatic;
        set(&mut changed, "--approve", text(&plan, "approval")?);
        set(&mut changed, "--max-attempts", "1");
        let output = run(&changed)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(fs::read_dir(&directory.0)?.next().is_none());
    }
    Ok(())
}

#[test]
fn automatic_reconnect_and_campaign_relearn_senders_and_reopen_exact_originals() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        for campaign in [false, true] {
            let directory = Directory::new(&format!("auto-{}-{campaign}", codec.name()))?;
            let listener = listener()?;
            let mut input = automatic_args(&directory, listener.local_addr()?, codec);
            if campaign {
                set(&mut input, "--continue-after-success", "yes");
                set(
                    &mut input,
                    "--history-root",
                    directory.0.join("history").to_str().ok_or("history path")?,
                );
            }
            let senders = [
                Sender {
                    advertised: Some(0x1020_3040),
                    actual: 0x1020_3040,
                    eof: !campaign,
                    switch_at_end: false,
                },
                Sender {
                    advertised: None,
                    actual: 0,
                    eof: false,
                    switch_at_end: false,
                },
            ];
            let (output, originals) =
                captured_senders(&listener, &approved(&input)?, codec, &senders)?;
            assert!(
                output.status.success(),
                "{codec:?}, campaign={campaign}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let rows = rows(&output)?;
            let starts = details(&rows, NATIVE, "started")?;
            let terminals = details(&rows, NATIVE, "terminal")?;
            let windows = details(&rows, NATIVE, "window_durable")?;
            let attempts = details(&rows, CONTROL, "attempt_finished")?;
            assert_eq!(starts.len(), 2);
            assert_eq!(terminals.len(), 2);
            assert_eq!(windows.len(), 2);
            assert_eq!(attempts.len(), 2);
            if campaign {
                assert!(flag(attempts[0], "settled_success")?);
                assert!(flag(attempts[0], "continuing_after_success")?);
            } else {
                assert_eq!(text(attempts[0], "retry_reason")?, "source_ended");
                assert!(flag(attempts[0], "retrying")?);
            }
            for (index, sender) in senders.iter().enumerate() {
                let binding = field(terminals[index], "source_binding")?;
                assert_eq!(text(binding, "state")?, "bound");
                assert_eq!(number(binding, "ssrc")?, i128::from(sender.actual));
                assert_eq!(number(binding, "generation")?, 7 + index as i128);
                verify_retained_sender(
                    &directory,
                    codec,
                    index + 1,
                    starts[index],
                    windows[index],
                    sender.actual,
                    &originals[index],
                )?;
            }
            assert_ne!(
                text(starts[0], "decode_clock")?,
                text(starts[1], "decode_clock")?
            );
            assert_ne!(
                text(windows[0], "archive_namespace")?,
                text(windows[1], "archive_namespace")?
            );
            assert!(!directory.attempt("capture", 3).exists());
            assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));

            // Recovery uses the exact original scopes and retained source identities, without
            // replacing the now-known sender with the planner's unresolved placeholder.
            let mut recovery = input;
            set(&mut recovery, "--recover", "yes");
            let preview = run(&recovery)?;
            assert!(
                preview.status.success(),
                "{}",
                String::from_utf8_lossy(&preview.stderr)
            );
            let plan = parse(std::str::from_utf8(&preview.stdout)?)?;
            set(&mut recovery, "--approve", text(&plan, "approval")?);
            let restored = run(&recovery)?;
            assert!(
                restored.status.success(),
                "{}",
                String::from_utf8_lossy(&restored.stderr)
            );
            assert!(!directory.attempt("capture", 3).exists());
            assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        }
    }
    Ok(())
}

#[test]
fn sender_switch_inside_an_attempt_never_authorizes_a_successor() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new("auto-switch")?;
        let listener = listener()?;
        let mut input = automatic_args(&directory, listener.local_addr()?, codec);
        set(&mut input, "--continue-after-success", "yes");
        set(&mut input, "--retry-interrupted", "yes");
        let sender = Sender {
            advertised: Some(41),
            actual: 41,
            eof: false,
            switch_at_end: true,
        };
        let (output, _) = captured_senders(&listener, &approved(&input)?, codec, &[sender])?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        assert_eq!(details(&rows, CONTROL, "attempt_started")?.len(), 1);
        assert!(details(&rows, CONTROL, "backoff")?.is_empty());
        let terminal = details(&rows, NATIVE, "terminal")?;
        assert_eq!(terminal.len(), 1);
        assert!(!flag(terminal[0], "complete")?);
        assert_eq!(number(field(terminal[0], "source_binding")?, "ssrc")?, 41);
        assert!(!directory.attempt("capture", 2).exists());
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    }
    Ok(())
}

#[test]
fn unobserved_senders_remain_unresolved_at_the_approved_attempt_limit() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new("auto-unavailable")?;
        let reserved = listener()?;
        let input = approved(&automatic_args(&directory, reserved.local_addr()?, codec))?;
        drop(reserved);
        let output = run(&input)?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        assert_eq!(details(&rows, CONTROL, "attempt_started")?.len(), 2);
        assert_eq!(details(&rows, CONTROL, "backoff")?.len(), 1);
        let terminals = details(&rows, NATIVE, "terminal")?;
        assert_eq!(terminals.len(), 2);
        for terminal in terminals {
            let binding = field(terminal, "source_binding")?;
            assert_eq!(text(binding, "state")?, "unresolved");
            assert!(
                binding
                    .object()
                    .is_some_and(|fields| !fields.contains_key("ssrc"))
            );
        }
        let terminal = details(&rows, CONTROL, "reconnect_terminal")?;
        assert!(flag(terminal[0], "attempt_limit_reached")?);
        assert!(!flag(terminal[0], "complete")?);
        assert!(!directory.attempt("capture", 3).exists());
    }
    Ok(())
}
