#![forbid(unsafe_code)]
//! Synthetic camera for the scoped TLS fleet stream integration test.
use super::HEAD;
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const HELLO: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [1, 2, 3, 4];
    let mut bytes = vec![0x82, 0x80 | payload.len() as u8];
    bytes.extend_from_slice(&mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}

fn receive_binary(socket: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = [0; 2];
    socket.read_exact(&mut head)?;
    if head[0] != 0x82 || head[1] & 0x80 != 0 {
        return Err(io::Error::other("invalid server frame"));
    }
    let len = match head[1] {
        n @ 0..=125 => usize::from(n),
        126 => {
            let mut n = [0; 2];
            socket.read_exact(&mut n)?;
            usize::from(u16::from_be_bytes(n))
        }
        _ => return Err(io::Error::other("frame too large")),
    };
    if len > 4096 {
        return Err(io::Error::other("frame bound"));
    }
    let mut payload = vec![0; len];
    socket.read_exact(&mut payload)?;
    Ok(payload)
}

fn message_id(message: &str) -> io::Result<u64> {
    let value = message
        .split_once("\"messageId\":")
        .map(|(_, suffix)| {
            suffix
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("")
        })
        .ok_or_else(|| io::Error::other("missing request id"))?;
    value.parse().map_err(io::Error::other)
}

fn flv_tag(timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut tag = vec![
        9,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    tag.extend_from_slice(payload);
    tag.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    tag
}

pub fn media_fixture(full_resolution: bool) -> TestMedia {
    if full_resolution {
        media_fixture_from_frames(include_bytes!("synthetic_g4_resolution.264"), 4, 13, false)
    } else {
        media_fixture_from(include_bytes!("baseline.264"), 3)
    }
}

pub fn audio_video_fixture(full_resolution: bool) -> TestMedia {
    if full_resolution {
        media_fixture_from_frames(include_bytes!("synthetic_g4_resolution.264"), 4, 13, true)
    } else {
        media_fixture_from_frames(include_bytes!("baseline.264"), 3, 7, true)
    }
}

fn media_fixture_from(source: &[u8], cycle: usize) -> TestMedia {
    media_fixture_from_frames(source, cycle, 7, false)
}

fn media_fixture_from_frames(source: &[u8], cycle: usize, frames: usize, audio: bool) -> TestMedia {
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(source).collect();
    let sps = nals
        .iter()
        .copied()
        .find(|n| n[0] & 31 == 7)
        .ok_or("missing SPS")?;
    let pps = nals
        .iter()
        .copied()
        .find(|n| n[0] & 31 == 8)
        .ok_or("missing PPS")?;
    let pictures: Vec<_> = nals
        .into_iter()
        .filter(|n| matches!(n[0] & 31, 1 | 5))
        .collect();
    if pictures.len() != 4 || pictures[0][0] & 31 != 5 || !(1..=pictures.len()).contains(&cycle) {
        return Err("unexpected fixture pictures".into());
    }
    let mut config = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    config.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    config.extend_from_slice(sps);
    config.push(1);
    config.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    config.extend_from_slice(pps);
    let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    if audio { wire[4] = 5; }
    wire.extend(flv_tag(0, &config));
    for index in 0..frames {
        if audio {
            // Synthetic AAC bodies test muxing and source custody, not decoding.
            let mut tag = flv_tag(index as u32 * 64, &[0xaf, 1, 2]);
            tag[0] = 8;
            wire.extend(tag);
        }
        let nal = pictures[index % cycle];
        let mut payload = vec![0x17, 1, 0, 0, 0];
        payload.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        payload.extend_from_slice(nal);
        wire.extend(flv_tag(index as u32 * 40, &payload));
    }
    Ok(wire)
}
type TestMedia = Result<Vec<u8>, Box<dyn Error>>;

pub fn camera(
    endpoint: SocketAddrV4,
    peer: Ipv4Addr,
    config: Arc<ClientConfig>,
    mac_hex: &str,
    stream_seen: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    full_resolution: bool,
) -> io::Result<()> {
    camera_with_hold(
        endpoint,
        peer,
        config,
        mac_hex,
        stream_seen,
        release,
        full_resolution,
        None,
    )
}

pub fn camera_with_hold(
    endpoint: SocketAddrV4,
    peer: Ipv4Addr,
    config: Arc<ClientConfig>,
    mac_hex: &str,
    stream_seen: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    full_resolution: bool,
    hold: Option<Arc<AtomicBool>>,
) -> io::Result<()> {
    camera_impl(
        endpoint,
        peer,
        config,
        mac_hex,
        stream_seen,
        release,
        full_resolution,
        hold,
        None,
        false,
    )
}

pub fn camera_with_candidates(
    endpoint: SocketAddrV4,
    peer: Ipv4Addr,
    config: Arc<ClientConfig>,
    mac_hex: &str,
    stream_seen: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    full_resolution: bool,
    hold: Arc<AtomicBool>,
    proceed: Arc<AtomicBool>,
    audio: bool,
) -> io::Result<()> {
    camera_impl(
        endpoint,
        peer,
        config,
        mac_hex,
        stream_seen,
        release,
        full_resolution,
        Some(hold),
        Some(proceed),
        audio,
    )
}

fn camera_impl(
    endpoint: SocketAddrV4,
    peer: Ipv4Addr,
    config: Arc<ClientConfig>,
    mac_hex: &str,
    stream_seen: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    full_resolution: bool,
    hold: Option<Arc<AtomicBool>>,
    competing_candidates: Option<Arc<AtomicBool>>,
    audio: bool,
) -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::V4(SocketAddrV4::new(peer, 0)).into())?;
    socket.connect_timeout(&SocketAddr::V4(endpoint).into(), Duration::from_secs(5))?;
    let raw: std::net::TcpStream = socket.into();
    raw.set_read_timeout(Some(Duration::from_secs(15)))?;
    raw.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut tls = StreamOwned::new(
        ClientConnection::new(
            config,
            ServerName::try_from("localhost").map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?,
        raw,
    );
    let mut handshake = HEAD.replace("001122aabbcc", mac_hex).into_bytes();
    handshake.extend(frame(HELLO));
    tls.write_all(&handshake)?;
    tls.flush()?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        tls.read_exact(&mut byte)?;
        response.push(byte[0]);
        if response.len() > 4096 {
            return Err(io::Error::other("upgrade limit"));
        }
    }
    if !response.starts_with(b"HTTP/1.1 101 ") {
        return Err(io::Error::other("upgrade refused"));
    }
    if !receive_binary(&mut tls)?
        .windows(b"ubnt_avclient_hello".len())
        .any(|w| w == b"ubnt_avclient_hello")
    {
        return Err(io::Error::other("missing hello reply"));
    }
    let agreement = receive_binary(&mut tls)?;
    if !agreement
        .windows(b"ubnt_avclient_paramAgreement".len())
        .any(|w| w == b"ubnt_avclient_paramAgreement")
    {
        return Err(io::Error::other("missing agreement"));
    }
    let id = message_id(std::str::from_utf8(&agreement).map_err(io::Error::other)?)?;
    let reply = format!(
        r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":{id}}}"#
    );
    tls.write_all(&frame(reply.as_bytes()))?;
    tls.flush()?;
    let stream = receive_binary(&mut tls)?;
    let message = std::str::from_utf8(&stream).map_err(io::Error::other)?;
    let expected_channel = if full_resolution { "video1" } else { "video2" };
    let expected_video = format!("\"video\":{{\"{expected_channel}\":");
    if !message.contains(&expected_video) {
        return Err(io::Error::other("unexpected requested video channel"));
    }
    let destination: SocketAddr = message
        .split_once("tcp://")
        .and_then(|(_, suffix)| suffix.split_once('?'))
        .map(|(address, _)| address)
        .ok_or_else(|| io::Error::other("missing destination"))?
        .parse()
        .map_err(io::Error::other)?;
    if !matches!(destination, SocketAddr::V4(address) if *address.ip() == *endpoint.ip() && address.port() != 0)
    {
        return Err(io::Error::other("unexpected destination"));
    }
    let id = message_id(message)?;
    stream_seen.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "parallel camera did not progress",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let reply = format!(
        r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":{id}}}"#
    );
    tls.write_all(&frame(reply.as_bytes()))?;
    tls.flush()?;
    let mut held_candidates = Vec::new();
    if let Some(proceed) = competing_candidates {
        for (index, prefix) in [b'X', b'F'].into_iter().enumerate() {
            let candidate = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            candidate.bind(&SocketAddr::V4(SocketAddrV4::new(peer, 0)).into())?;
            candidate.connect_timeout(&destination.into(), Duration::from_secs(5))?;
            let mut candidate: std::net::TcpStream = candidate.into();
            candidate.write_all(&[prefix])?;
            held_candidates.push(candidate);
            if index == 0 {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !proceed.load(Ordering::Acquire) {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "candidate selection did not resume",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
    let media = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    media.bind(&SocketAddr::V4(SocketAddrV4::new(peer, 0)).into())?;
    media.connect_timeout(&destination.into(), Duration::from_secs(5))?;
    let mut media: std::net::TcpStream = media.into();
    let wire = if audio { audio_video_fixture(full_resolution) } else { media_fixture(full_resolution) }
        .map_err(|_| io::Error::other("invalid fixture media"))?;
    media.write_all(&wire)?;
    drop(media);
    if let Some(hold) = hold {
        let deadline = Instant::now() + Duration::from_secs(90);
        while !hold.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "controller hold expired",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}
