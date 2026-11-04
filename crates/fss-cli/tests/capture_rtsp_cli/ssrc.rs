#![forbid(unsafe_code)]
//! Automatic sender selection retains exact observed RTP identity through native import.

use super::*;
use fss_core::{SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::{PacketLimits, RtpPacket};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::local::load_recording;

fn packets(ssrc: u32) -> Test<Vec<Vec<u8>>> {
    let wire = video(2, 3600, 96, false)?;
    let mut packets = Vec::new();
    let mut at = 0;
    while at < wire.len() {
        assert_eq!(&wire[at..at + 2], b"$\0");
        let length = usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]]));
        let mut packet = wire[at + 4..at + 4 + length].to_vec();
        packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
        packets.push(packet);
        at += 4 + length;
    }
    Ok(packets)
}

fn serve_sender(listener: TcpListener, advertised: Option<u32>, packets: &[Vec<u8>]) -> Test {
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
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    response(&mut peer, cseq, "Content-Type: application/sdp\r\n", SDP)?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP");
    let ssrc = advertised.map_or_else(String::new, |ssrc| format!(";ssrc={ssrc:08X}"));
    response(
        &mut peer,
        cseq,
        &format!(
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1{ssrc}\r\n"
        ),
        "",
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY");
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    for packet in packets {
        peer.write_all(&[b'$', 0])?;
        peer.write_all(&u16::try_from(packet.len())?.to_be_bytes())?;
        peer.write_all(packet)?;
    }
    if packets.is_empty() {
        peer.shutdown(Shutdown::Write)?;
    }
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else {
            return Ok(());
        };
        assert!(matches!(
            method.as_str(),
            "TEARDOWN" | "GET_PARAMETER" | "OPTIONS"
        ));
        response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    }
    Err("sender fixture exceeded bounded control requests".into())
}

fn captured_sender(
    listener: TcpListener,
    args: &[OsString],
    advertised: Option<u32>,
    packets: &[Vec<u8>],
) -> Test<Output> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve_sender(listener, advertised, packets));
        let output = run("capture", args)?;
        if let Err(error) = server.join().map_err(|_| "sender fixture panicked")? {
            return Err(format!(
                "sender fixture: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output)
    })
}

fn exact_retained_sender(
    directory: &Directory,
    rows: &[Value],
    ssrc: u32,
    sent: &[Vec<u8>],
) -> Test {
    let publisher = LocalRootPublisher::open(
        directory.root(),
        LocalPublicationLimits::new(
            256,
            64,
            256,
            512,
            SpoolLimits::new(1024, 64 * 1024 * 1024, 16 * 1024 * 1024, 1024),
        ),
    )?;
    let scope = RecordingScope {
        sensor: SensorId::parse(SENSOR)?,
        stream: StreamId::parse(STREAM)?,
        generation: 1,
        anchor: ContentDigest::sha256(b"capture CLI authority anchor"),
        receive_clock: ContentDigest::sha256(b"capture CLI receive clock"),
    };
    let report = detail(rows, "window_durable")?;
    let retained = load_recording(
        &publisher,
        &SlotName::parse(text(report, "slot")?)?,
        ContentDigest::parse(text(report, "root")?)?,
        &scope,
        &NeverCancel,
    )?;
    let retained = retained.packets()?;
    assert!(!retained.is_empty());
    for packet in retained {
        let parsed = RtpPacket::parse(packet.bytes, PacketLimits::default())?;
        assert_eq!(parsed.ssrc(), ssrc);
        assert_eq!(parsed.payload_type(), 96);
        assert!(
            sent.iter()
                .any(|original| original.as_slice() == packet.bytes)
        );
    }
    Ok(())
}

#[test]
fn auto_ssrc_avc_retains_setup_or_packet_sender_through_cold_import() -> Test {
    for (advertised, ssrc) in [(Some(0x1020_3040), 0x1020_3040), (None, 0)] {
        let directory = Directory::new("ssrc-avc")?;
        let listener = listener()?;
        let mut args = args(&directory, listener.local_addr()?, 2);
        replace(&mut args, "--ssrc", "auto")?;
        let (preview, _) = plan(&args)?;
        assert_eq!(
            text(&preview, "ssrc_state")?,
            "unknown_until_session_observation"
        );
        no_connection(&listener)?;
        let sent = packets(ssrc)?;
        let output = captured_sender(listener, &approve(&args)?, advertised, &sent)?;
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let rows = rows(&output)?;
        let terminal = detail(&rows, "terminal")?;
        assert!(boolean(terminal, "complete")?);
        assert!(!boolean(terminal, "peer_eof")?);
        assert_eq!(integer(terminal, "durable_pictures")?, 2);
        let bound = value(terminal, "source_binding")?;
        assert_eq!(text(bound, "state")?, "bound");
        assert_eq!(integer(bound, "ssrc")?, i128::from(ssrc));
        assert_eq!(integer(bound, "generation")?, 1);
        assert!(!boolean(bound, "sender_authenticated")?);
        exact_retained_sender(&directory, &rows, ssrc, &sent)?;
        import_and_decode(&directory, &rows, 2)?;
    }
    Ok(())
}

#[test]
fn auto_ssrc_without_setup_identity_or_media_retires_as_unresolved() -> Test {
    let directory = Directory::new("ssrc-unresolved-avc")?;
    let listener = listener()?;
    let mut args = args(&directory, listener.local_addr()?, 2);
    replace(&mut args, "--ssrc", "auto")?;
    let output = captured_sender(listener, &approve(&args)?, None, &[])?;
    assert!(!output.status.success());
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "durable_pictures")?, 0);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    let bound = value(terminal, "source_binding")?;
    assert_eq!(text(bound, "state")?, "unresolved");
    assert!(!bound.object().ok_or("binding object")?.contains_key("ssrc"));
    Ok(())
}
