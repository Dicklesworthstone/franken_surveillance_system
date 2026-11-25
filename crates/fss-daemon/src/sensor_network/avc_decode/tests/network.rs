#![forbid(unsafe_code)]
//! Loopback checks exercise the actual daemon poll/EOF/reconnect boundary.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::manifest::{CameraAdapterKind, CameraManifestEntry};
use crate::sensor::{SensorDisconnectReason, SensorDriver, SensorDriverEvent};
use crate::sensor_network::NetworkAdapterDriver;
use fss_core::SensorId;
use fss_reference::ingest::model_pool::CameraPriorityTier;

use super::*;

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        encoded.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

fn request(stream: &mut TcpStream) -> Result<String, String> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 8_192 {
            return Err("fixture request limit".into());
        }
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(|e| e.to_string())?;
        request.push(byte[0]);
    }
    String::from_utf8(request).map_err(|e| e.to_string())
}

fn serve(listener: TcpListener, nals: Vec<(Vec<u8>, bool)>) -> Result<(), String> {
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=daemon-test\r\nt=0 0\r\na=control:*\r\n\
         m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 packetization-mode=1;sprop-parameter-sets={},{}\r\na=control:trackID=0\r\n",
        base64(&sps(2)),
        base64(&Pps::default().nal()),
    );
    let mut playing = false;
    for _ in 0..4 {
        let request = request(&mut stream)?;
        let cseq = request
            .lines()
            .find_map(|line| line.strip_prefix("CSeq: "))
            .ok_or("missing CSeq")?;
        let (headers, body) = match request.split_whitespace().next() {
            Some("OPTIONS") => ("Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n", ""),
            Some("DESCRIBE") => ("Content-Type: application/sdp\r\n", sdp.as_str()),
            Some("SETUP") => (
                "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                "",
            ),
            Some("PLAY") => {
                playing = true;
                ("Session: fixture\r\n", "")
            }
            _ => return Err("unexpected RTSP request".into()),
        };
        let response = format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .map_err(|e| e.to_string())?;
        if playing {
            break;
        }
    }
    if !playing {
        return Err("fixture did not reach PLAY".into());
    }
    // The initial SPS/PPS also satisfy RTP source probation. SDP owns the exact
    // configuration, so discarding the first probation packet cannot hide a picture.
    for (index, (nal, marked)) in nals.into_iter().enumerate() {
        let mut packet = vec![0x80, 96 | (u8::from(marked) << 7)];
        packet.extend_from_slice(&(index as u16 + 1).to_be_bytes());
        packet.extend_from_slice(&(90_000 + index as u32 * 3_000).to_be_bytes());
        packet.extend_from_slice(&7_u32.to_be_bytes());
        packet.extend(nal);
        let mut interleaved = vec![b'$', 0];
        interleaved.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        interleaved.extend(packet);
        stream.write_all(&interleaved).map_err(|e| e.to_string())?;
    }
    // A clean TCP close must drain accepted RTP, the unmarked tail, and delayed codec output.
    Ok(())
}

fn entry(addr: std::net::SocketAddr) -> Result<CameraManifestEntry, Box<dyn Error>> {
    Ok(CameraManifestEntry {
        sensor_id: SensorId::parse("sensor:avc-source-test")?,
        adapter: CameraAdapterKind::Rtsp,
        endpoint: format!("rtsp://{addr}/live"),
        secret_id: None,
        priority_tier: CameraPriorityTier::Standard,
        primary_zone: "entry".into(),
        zones: BTreeSet::from(["entry".into()]),
        dimensions: [32, 16],
        osd_ignore_rects: Vec::new(),
        failure_domains: BTreeSet::from(["loopback".into()]),
        reconnect_min_ms: 100,
        reconnect_max_ms: 1_000,
        stall_timeout_ms: 5_000,
        ring_max_frames: 16,
        ring_max_bytes: 128 * 1_024,
        gop_frames: 4,
        auth_realm: None,
        allow_inband_sps_pps: false,
        setup_companion_tracks: false,
    })
}

#[test]
fn daemon_drains_delayed_eof_frames_and_disconnects_on_incomplete_native_picture() -> Test {
    for complete in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let camera = entry(listener.local_addr()?)?;
        let mut nals = vec![(sps(2), false), (Pps::default().nal(), false)];
        if complete {
            nals.push((Frame::idr(10, false).nal(), true));
            nals.push((Frame::reference(1, 2, 20).nal(), false));
        } else {
            nals.push((Frame::idr(10, false).slice(0, 1), true));
        }
        let server = thread::spawn(move || serve(listener, nals));
        let mut driver = NetworkAdapterDriver::new(&camera);
        driver.connect(1).map_err(|reason| format!("{reason:?}"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut now_ns = 1_000_000_i128;
        let mut frames = Vec::new();
        let mut disconnected = None;
        while Instant::now() < deadline {
            now_ns += 10_000;
            match driver.poll_frame(now_ns) {
                SensorDriverEvent::Frame(frame) => frames.push(frame),
                SensorDriverEvent::Disconnected(reason) => {
                    disconnected = Some(reason);
                    break;
                }
                SensorDriverEvent::Idle => thread::sleep(Duration::from_millis(1)),
            }
        }
        driver.disconnect();
        server.join().map_err(|_| "RTSP fixture panicked")??;
        assert_eq!(driver.active_session_count(), 0);
        assert_eq!(driver.total_connections(), 1);
        if complete {
            assert!(matches!(
                disconnected,
                Some(SensorDisconnectReason::NetworkDrop)
            ));
            assert_eq!(
                frames.len(),
                2,
                "socket EOF must not discard accepted or delayed media"
            );
            assert_eq!(frames[0].sequence, 1);
            assert_eq!(frames[1].sequence, 2);
            assert!(frames[0].host_receive_ns <= frames[1].host_receive_ns);
            assert_eq!(frames[0].media_pts_ns, 96_000_i128 * 1_000_000_000 / 90_000);
            assert_eq!(frames[1].media_pts_ns, 99_000_i128 * 1_000_000_000 / 90_000);
        } else {
            assert!(frames.is_empty(), "partial pixels are never published");
            assert!(matches!(
                disconnected,
                Some(SensorDisconnectReason::DriverError(reason))
                    if reason == "AVC access unit did not decode exactly one complete picture"
            ));
        }
    }
    Ok(())
}
