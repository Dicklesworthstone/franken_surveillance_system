#![forbid(unsafe_code)]
//! Real B-slice sources through approved native capture, original custody and cold decode.
//! Fixed cadence is an explicit fixture declaration, never inferred physical capture time.

use super::*;

const AVC: &[u8] = include_bytes!("../../../fss-codec-h264/tests/fixtures/decode/m_b_cavlc.h264");
const HEVC: &[u8] =
    include_bytes!("../../../fss-codec-h265/tests/fixtures/decode/b_qcif_nopyramid_ref1.h265");
const AVC_ORDER: [u32; 9] = [0, 3, 1, 2, 4, 5, 6, 8, 7];
const HEVC_ORDER: [u32; 9] = [0, 3, 1, 2, 6, 4, 5, 8, 7];
const DURATION: u32 = 3_600;

fn split(bytes: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix != 0 {
            starts.push((at, at + prefix));
            at += prefix;
        } else {
            at += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(i, (_, begin))| {
            let mut end = starts.get(i + 1).map_or(bytes.len(), |p| p.0);
            while end > *begin && bytes[end - 1] == 0 {
                end -= 1;
            }
            &bytes[*begin..end]
        })
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

struct Camera {
    description: String,
    packets: Vec<Vec<u8>>,
    eof: bool,
}
impl Camera {
    fn new(hevc: bool, order: &[u32], origin: u32, eof: bool) -> Test<Self> {
        let nals = split(if hevc { HEVC } else { AVC });
        let kind = |n: &[u8]| if hevc { (n[0] >> 1) & 63 } else { n[0] & 31 };
        let parameters: Vec<_> = nals
            .iter()
            .copied()
            .filter(|n| {
                if hevc {
                    matches!(kind(n), 32..=34)
                } else {
                    matches!(kind(n), 7 | 8)
                }
            })
            .collect();
        assert_eq!(parameters.len(), if hevc { 3 } else { 2 });
        let pictures: Vec<_> = nals
            .iter()
            .copied()
            .filter(|n| {
                if hevc {
                    kind(n) <= 31
                } else {
                    matches!(kind(n), 1 | 5)
                }
            })
            .collect();
        assert_eq!(
            pictures.len(),
            9,
            "pinned one-slice-per-picture fixture changed"
        );
        let fmtp = if hevc {
            format!(
                "sprop-vps={};sprop-sps={};sprop-pps={}",
                base64(parameters[0]),
                base64(parameters[1]),
                base64(parameters[2])
            )
        } else {
            format!(
                "packetization-mode=1;sprop-parameter-sets={},{}",
                base64(parameters[0]),
                base64(parameters[1])
            )
        };
        let description = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 {}/90000\r\na=fmtp:96 {fmtp}\r\na=control:trackID=0\r\n",
            if hevc { "H265" } else { "H264" }
        );
        let mut packets = Vec::new();
        // Source probation is explicit and is not one of the selected recording packets.
        let mut push = |nal: &[u8], timestamp: u32, marker: bool| -> Test {
            let sequence = u16::try_from(packets.len() + 1)?;
            let mut packet = vec![0x80, 96 | if marker { 128 } else { 0 }];
            packet.extend_from_slice(&sequence.to_be_bytes());
            packet.extend_from_slice(&timestamp.to_be_bytes());
            packet.extend_from_slice(&7_u32.to_be_bytes());
            packet.extend_from_slice(nal);
            packets.push(packet);
            Ok(())
        };
        push(parameters[0], origin, false)?;
        for nal in parameters {
            push(nal, origin, false)?;
        }
        for (nal, position) in pictures.into_iter().zip(order) {
            push(
                nal,
                origin.wrapping_add(position.wrapping_mul(DURATION)),
                true,
            )?;
        }
        if hevc {
            // The owned camera fixture explicitly transmits EOS; neither a marker nor TCP EOF
            // is upgraded into a completed final-picture boundary by the capture implementation.
            push(
                &[0x48, 1, 0x80],
                origin.wrapping_add(order.last().copied().unwrap_or(0) * DURATION),
                true,
            )?;
        }
        Ok(Self {
            description,
            packets,
            eof,
        })
    }
    fn serve(self, listener: TcpListener) -> Test {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut peer = loop {
            match listener.accept() {
                Ok((peer, _)) => break peer,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) => return Err(e.into()),
            }
        };
        peer.set_read_timeout(Some(Duration::from_secs(10)))?;
        peer.set_write_timeout(Some(Duration::from_secs(10)))?;
        peer.set_nodelay(true)?;
        for method in ["DESCRIBE", "SETUP", "PLAY"] {
            let (actual, cseq) = request(&mut peer)?.ok_or("missing native request")?;
            assert_eq!(actual, method);
            match method {
                "DESCRIBE" => response(
                    &mut peer,
                    cseq,
                    "Content-Type: application/sdp\r\n",
                    &self.description,
                )?,
                "SETUP" => response(
                    &mut peer,
                    cseq,
                    "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                    "",
                )?,
                _ => response(&mut peer, cseq, "Session: fixture\r\n", "")?,
            }
        }
        let mut wire = Vec::new();
        for packet in &self.packets {
            wire.extend_from_slice(&[b'$', 0]);
            wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
            wire.extend_from_slice(packet);
        }
        peer.write_all(&wire)?;
        if self.eof {
            peer.shutdown(Shutdown::Write)?;
        }
        // The peer is kept open until the requested stop: no simulated EOF success.
        for _ in 0..16 {
            match request(&mut peer) {
                Ok(None) => return Ok(()),
                Err(e) if self.eof => return Err(e),
                Err(e) => {
                    // An early rejection may close with unread fixture packets (RST).
                    if e.downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::ConnectionReset)
                    {
                        return Ok(());
                    }
                    return Err(e);
                }
                Ok(Some((method, cseq))) => {
                    assert!(matches!(
                        method.as_str(),
                        "OPTIONS" | "GET_PARAMETER" | "TEARDOWN"
                    ));
                    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
                }
            }
        }
        Err("fixture request bound".into())
    }
}

fn capture(listener: TcpListener, args: &[OsString], camera: Camera) -> Test<Output> {
    thread::scope(|scope| {
        let server = scope.spawn(move || camera.serve(listener));
        let output = run("capture", args)?;
        if let Err(e) = server.join().map_err(|_| "reordered fixture panicked")? {
            return Err(format!(
                "{e}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output)
    })
}

fn options(
    directory: &Directory,
    peer: SocketAddr,
    hevc: bool,
    count: u64,
    depth: u8,
) -> Vec<OsString> {
    let mut input = args(directory, peer, count);
    input.extend(["--max-reorder-pictures".into(), depth.to_string().into()]);
    if hevc {
        input.extend(["--codec".into(), "hevc".into()]);
    }
    input
}

#[test]
fn reordered_avc_and_hevc_cold_decode_with_signed_offsets_and_timestamp_rollover() -> Test {
    for hevc in [false, true] {
        for chunk in [7, 4096] {
            let directory = Directory::new("reordered")?;
            let listener = listener()?;
            let order = if hevc { &HEVC_ORDER } else { &AVC_ORDER };
            let origin = u32::MAX - 2000;
            let camera = Camera::new(hevc, order, origin, false)?;
            let originals = camera.packets.clone();
            let mut input = options(&directory, listener.local_addr()?, hevc, 9, 2);
            input.extend(["--read-bytes".into(), chunk.to_string().into()]);
            let output = capture(listener, &approve(&input)?, camera)?;
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let rows = rows(&output)?;
            let mut n = 0;
            for row in &rows {
                if text(row, "kind")? != "picture_collected" {
                    continue;
                }
                let d = value(row, "detail")?;
                assert_eq!(integer(d, "decode_time")?, n as i128 * i128::from(DURATION));
                assert_eq!(
                    integer(d, "rtp_timestamp")?,
                    i128::from(origin.wrapping_add(order[n] * DURATION))
                );
                assert_eq!(
                    integer(d, "composition_offset")?,
                    (i128::from(order[n]) - n as i128) * i128::from(DURATION)
                );
                n += 1;
            }
            assert_eq!(n, 9);
            let terminal = detail(&rows, "terminal")?;
            assert!(boolean(terminal, "complete")?);
            assert!(!boolean(terminal, "peer_eof")?);
            assert!(!boolean(terminal, "coverage_certified")?);
            if hevc {
                let windows = super::hevc::load_windows(&directory, &rows)?;
                assert_eq!(windows.len(), 1);
                let window = &windows[0];
                let retained = window.packets()?;
                assert_eq!(retained.len(), originals.len() - 1);
                for (p, original) in retained.iter().zip(&originals[1..]) {
                    assert_eq!(p.bytes, original.as_slice());
                }
                for (n, sample) in window.samples().iter().enumerate() {
                    assert_eq!(
                        i128::from(sample.presentation_time) - i128::from(sample.decode_time),
                        (i128::from(order[n]) - n as i128) * i128::from(DURATION)
                    );
                }
                super::hevc::import_and_cold_decode(&directory, &rows, 9, true)?;
            } else {
                import_selected_and_decode(&directory, &rows, 9, true)?;
            }
        }
    }
    Ok(())
}

#[test]
fn a_requested_stop_inside_an_unresolved_display_group_never_succeeds_or_extends_target() -> Test {
    for hevc in [false, true] {
        let directory = Directory::new("reorder-cut")?;
        let listener = listener()?;
        let input = options(&directory, listener.local_addr()?, hevc, 2, 2);
        let camera = Camera::new(
            hevc,
            if hevc { &HEVC_ORDER } else { &AVC_ORDER },
            50000,
            false,
        )?;
        let output = capture(listener, &approve(&input)?, camera)?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        let terminal = detail(&rows, "terminal")?;
        assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-TIMING-001");
        assert_eq!(integer(terminal, "collected_pictures")?, 2);
        assert_eq!(integer(terminal, "durable_pictures")?, 0);
        assert!(!boolean(terminal, "complete")?);
    }
    Ok(())
}

#[test]
fn duplicates_insufficient_bounds_and_legacy_cadence_fail_without_prefix_success() -> Test {
    for hevc in [false, true] {
        for (depth, positions) in [
            (0, &[0, 3, 1, 2][..]),
            (1, &[0, 3, 1, 2][..]),
            (2, &[0, 3, 3, 2][..]),
        ] {
            let directory = Directory::new("reorder-refusal")?;
            let listener = listener()?;
            let input = options(&directory, listener.local_addr()?, hevc, 9, depth);
            let camera = Camera::new(hevc, positions, 0, false)?;
            let output = capture(listener, &approve(&input)?, camera)?;
            assert!(!output.status.success());
            let rows = rows(&output)?;
            let terminal = detail(&rows, "terminal")?;
            // HEVC's native assembler detects the ambiguous adjacent duplicate timestamp
            // before timing can be requested. Preserve that stronger original source refusal.
            let expected = if hevc && depth == 2 {
                "ERR-CAPTURE-RTSP-SOURCE-001"
            } else {
                "ERR-CAPTURE-RTSP-TIMING-001"
            };
            assert_eq!(text(terminal, "error_id")?, expected);
            assert!(!boolean(terminal, "complete")?);
            assert_eq!(integer(terminal, "durable_pictures")?, 0);
        }
    }
    Ok(())
}

#[test]
fn eof_cannot_turn_a_missing_display_position_into_a_retryable_source_shortfall() -> Test {
    for hevc in [false, true] {
        let directory = Directory::new("reorder-eof")?;
        let listener = listener()?;
        let input = options(&directory, listener.local_addr()?, hevc, 9, 2);
        let camera = Camera::new(hevc, &[0, 3], 0, true)?;
        let output = capture(listener, &approve(&input)?, camera)?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        let terminal = detail(&rows, "terminal")?;
        assert_eq!(integer(terminal, "collected_pictures")?, 2);
        assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-TIMING-001");
        assert!(!boolean(terminal, "complete")?);
        assert!(boolean(terminal, "peer_eof")?);
    }
    Ok(())
}

#[test]
fn the_reorder_grant_changes_approval_and_clock_but_explicit_zero_preserves_legacy_bytes() -> Test {
    let directory = Directory::new("reorder-plan")?;
    let listener = listener()?;
    for hevc in [false, true] {
        let mut ordinary = args(&directory, listener.local_addr()?, 9);
        if hevc {
            ordinary.extend(["--codec".into(), "hevc".into()]);
        }
        let (legacy, approval) = plan(&ordinary)?;
        let mut zero = ordinary.clone();
        zero.extend(["--max-reorder-pictures".into(), "0".into()]);
        assert_eq!(plan(&zero)?.0, legacy);
        let mut changed = ordinary.clone();
        changed.extend(["--max-reorder-pictures".into(), "2".into()]);
        let (reordered, new_approval) = plan(&changed)?;
        assert_ne!(approval, new_approval);
        assert_ne!(
            text(&legacy, "decode_clock")?,
            text(&reordered, "decode_clock")?
        );
        assert_eq!(
            integer(value(&reordered, "bounds")?, "max_reorder_pictures")?,
            2
        );
        changed.extend(["--approve".into(), approval.into()]);
        assert!(!run("capture", &changed)?.status.success());
        no_connection(&listener)?;
        assert!(!directory.root().exists());
        assert!(!directory.pins().exists());
        for bad in ["17", "-1", "1.5", "18446744073709551616"] {
            let mut input = ordinary.clone();
            input.extend(["--max-reorder-pictures".into(), bad.into()]);
            assert!(!run("capture", &input)?.status.success());
        }
    }
    Ok(())
}

#[test]
fn a_closed_short_eof_prefix_keeps_its_existing_incomplete_source_classification() -> Test {
    for hevc in [false, true] {
        let directory = Directory::new("reorder-closed-eof")?;
        let listener = listener()?;
        let input = options(&directory, listener.local_addr()?, hevc, 9, 2);
        let output = capture(
            listener,
            &approve(&input)?,
            Camera::new(hevc, &[0, 3, 1, 2], 0, true)?,
        )?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        let terminal = detail(&rows, "terminal")?;
        assert_eq!(text(terminal, "stop_cause")?, "input_ended_before_target");
        assert!(!boolean(terminal, "complete")?);
        assert_eq!(integer(terminal, "collected_pictures")?, 4);
        assert_eq!(integer(terminal, "durable_pictures")?, 4);
        assert_eq!(integer(terminal, "indexed_windows")?, 1);
    }
    Ok(())
}

#[test]
fn reconnect_previews_price_reordering_per_epoch_and_cannot_reuse_legacy_approval() -> Test {
    let directory = Directory::new("reorder-reconnect-plan")?;
    let listener = listener()?;
    let ordinary = args(&directory, listener.local_addr()?, 9);
    let mut input = vec!["reconnect".into()];
    input.extend(ordinary);
    input.extend(["--max-attempts".into(), "2".into()]);
    let legacy = parse(&good(run("capture", &input)?)?)?;
    input.extend(["--max-reorder-pictures".into(), "2".into()]);
    let enabled = parse(&good(run("capture", &input)?)?)?;
    assert_ne!(text(&enabled, "approval")?, text(&legacy, "approval")?);
    let attempts = value(&enabled, "attempts")?.array().ok_or("attempts")?;
    assert_eq!(attempts.len(), 2);
    for attempt in attempts {
        assert_eq!(
            integer(value(attempt, "bounds")?, "max_reorder_pictures")?,
            2
        );
    }
    assert_ne!(
        text(&attempts[0], "decode_clock")?,
        text(&attempts[1], "decode_clock")?
    );
    input.extend(["--approve".into(), text(&legacy, "approval")?.into()]);
    assert!(!run("capture", &input)?.status.success());
    no_connection(&listener)?;
    assert_eq!(std::fs::read_dir(&directory.0)?.count(), 0);
    Ok(())
}

#[test]
fn reconnect_never_retries_an_eof_with_unresolved_presentation_timing() -> Test {
    for hevc in [false, true] {
        let directory = Directory::new("reorder-reconnect-eof")?;
        let listener = listener()?;
        let peer = listener.local_addr()?;
        let mut input = vec!["reconnect".into()];
        input.extend(options(&directory, peer, hevc, 9, 2));
        input.extend([
            "--max-attempts".into(),
            "2".into(),
            "--retry-delay-ms".into(),
            "1".into(),
            "--retry-max-delay-ms".into(),
            "1".into(),
        ]);
        let preview = parse(&good(run("capture", &input)?)?)?;
        input.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        let output = capture(
            listener.try_clone()?,
            &input,
            Camera::new(hevc, &[0, 3], 0, true)?,
        )?;
        assert!(!output.status.success());
        let stdout = std::str::from_utf8(&output.stdout)?;
        assert!(stdout.contains("ERR-CAPTURE-RTSP-TIMING-001"), "{stdout}");
        no_connection(&listener)?;
        assert!(directory.0.join("capture.attempt-0001").is_dir());
        assert!(!directory.0.join("capture.attempt-0002").exists());
        assert!(!directory.0.join("pins.attempt-0002").exists());
    }
    Ok(())
}
