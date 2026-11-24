#![forbid(unsafe_code)]
//! Pure-Rust active LAN discovery probes (UniFi UDP-10001 TLV + non-intrusive
//! RTSP `OPTIONS *` banner/realm peek).
//!
//! Zero OS subprocesses, zero raw sockets, zero credentials sent on the wire.
//! Every observation is strictly bounded in bytes, count, and wall time, and
//! filtered to the operator's authorized [`CensusPlan`]. All received claims
//! (MAC, model, firmware, hostname, RTSP Server/realm) are unauthenticated
//! network observations and never grant device enrollment or effect authority.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fss_packet::unifi_discovery::{self, DeviceKind, Reply};

use crate::discovery::census::{ArpRow, CensusPlan, HostObs, normalize_mac_bytes};

/// Ubiquiti v1 LAN discovery UDP destination port.
pub const UNIFI_DISCOVERY_PORT: u16 = unifi_discovery::PORT;
/// Ubiquiti v1 4-byte LAN discovery query (`[0x01, 0x00, 0x00, 0x00]`).
pub const UNIFI_V1_QUERY: [u8; 4] = unifi_discovery::V1_QUERY;
/// Maximum UniFi discovery responses retained per sweep.
pub const MAX_UNIFI_RESPONSES: usize = 256;
/// Maximum in-scope unicast targets sent a 4-byte UniFi UDP-10001 probe.
pub const MAX_UNIFI_UNICAST_TARGETS: usize = 1024;
/// Maximum UDP receive attempts during one UniFi probe window.
const MAX_UNIFI_RECEIVE_ATTEMPTS: usize = 512;
/// Maximum ASCII length for sanitized TLV text fields.
const MAX_TLV_TEXT: usize = 128;

/// TCP ports eligible for a non-intrusive RTSP `OPTIONS * RTSP/1.0` banner peek.
pub const RTSP_PEEK_PORTS: [u16; 4] = [554, 7447, 8554, 10554];
/// Maximum bytes read from an RTSP `OPTIONS *` response (4 KiB hard cap).
pub const MAX_RTSP_PEEK_BYTES: usize = 4096;
/// Maximum RTSP endpoints peeked in one sweep.
pub const MAX_RTSP_PEEK_ENDPOINTS: usize = 256;
/// Maximum sanitized header value length retained from an RTSP response.
const MAX_HEADER_TEXT: usize = 128;
/// Maximum `Public:` method tokens retained from an RTSP response.
const MAX_PUBLIC_METHODS: usize = 16;

/// Credential-free RTSP `OPTIONS *` request bytes.
pub const RTSP_OPTIONS_REQUEST: &[u8] =
    b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: fss-discover/1.0\r\n\r\n";

/// One validated Ubiquiti v1 UDP-10001 TLV discovery observation.
///
/// All fields except `ip` (actual UDP datagram source) are untrusted device
/// claims. They never authenticate a device or authorize adoption/setup.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UniFiDiscoveryObs {
    /// Actual IPv4 source address of the UDP datagram.
    pub ip: Ipv4Addr,
    /// Normalized lowercase colon-separated MAC from TLV 1 (or matching TLV 2).
    pub mac: Option<String>,
    /// Untrusted model/platform text from TLV 12 (or TLV 21 / TLV 20 fallback).
    pub model: Option<String>,
    /// Untrusted firmware string from TLV 3.
    pub firmware: Option<String>,
    /// Untrusted hostname text from TLV 11.
    pub hostname: Option<String>,
    /// Whether TLV 2 advertised this exact UDP source IP.
    pub source_advertised: bool,
    /// Whether `fss_packet::unifi_discovery::Reply::kind` matched `CameraCandidate`.
    pub is_camera_platform: bool,
}

impl UniFiDiscoveryObs {
    /// Returns whether this UniFi discovery observation indicates a camera or
    /// UniFi Protect appliance rather than a pure UniFi AP/switch/gateway.
    #[must_use]
    pub fn is_camera_or_protect(&self) -> bool {
        if self.is_camera_platform {
            return true;
        }
        let Some(model) = self.model.as_deref() else {
            return true;
        };
        let upper = model.to_ascii_uppercase();
        if upper.starts_with("UVC")
            || upper.starts_with("UNVR")
            || upper.starts_with("UCK")
            || upper.starts_with("UP-")
            || upper.contains("PROTECT")
            || upper.contains("CAMERA")
            || upper.contains("DOORBELL")
            || upper.contains("INSTANT")
            || upper.contains("BULLET")
            || upper.contains("DOME")
            || upper.contains("TURRET")
            || upper.contains("THETA")
            || upper.contains("G3")
            || upper.contains("G4")
            || upper.contains("G5")
            || upper.contains("G6")
        {
            return true;
        }
        let known_non_camera_infra = upper.starts_with("UAP")
            || upper.starts_with("U6-")
            || upper.starts_with("U7-")
            || upper.starts_with("USW")
            || upper.starts_with("US-")
            || upper.starts_with("UXG")
            || upper.starts_with("USG");
        !known_non_camera_infra
    }

    /// Converts a valid unicast MAC claim into a neighbor row for OUI enrichment.
    #[must_use]
    pub fn to_arp_row(&self) -> Option<ArpRow> {
        let mac = self.mac.as_ref()?;
        if mac.is_empty() {
            return None;
        }
        Some(ArpRow {
            ip: self.ip,
            mac: mac.clone(),
            iface: "unifi-udp10001".to_owned(),
        })
    }
}

/// Parses and validates a Ubiquiti v1 UDP-10001 TLV discovery reply.
///
/// Validates the entire packet using [`fss_packet::unifi_discovery::Reply::parse`]
/// before extracting MAC, model/platform, firmware, and hostname TLVs.
/// Unknown or sensitive TLVs are ignored and never exposed.
pub fn parse_unifi_discovery_reply(
    source: Ipv4Addr,
    bytes: &[u8],
) -> Result<UniFiDiscoveryObs, unifi_discovery::Error> {
    let reply = Reply::parse(bytes)?;
    let is_camera_platform = reply.kind() == DeviceKind::CameraCandidate;

    let mut source_advertised = false;
    let mut matched_addr_mac: Option<[u8; 6]> = None;
    for claim in reply.addresses() {
        if Ipv4Addr::from(claim.ipv4) == source {
            source_advertised = true;
            if matched_addr_mac.is_none() {
                matched_addr_mac = Some(claim.mac);
            }
        }
    }

    let raw_mac = reply.mac().or(matched_addr_mac);
    let mac = raw_mac.and_then(|octets| {
        if octets == [0; 6] || octets == [0xff; 6] || (octets[0] & 0x01) != 0 {
            None
        } else {
            Some(normalize_mac_bytes(octets))
        }
    });

    // Safe secondary scan over the already-validated TLV slice for hostname
    // (TLV 11) and model short/full fallback (TLV 21 / TLV 20) when TLV 12 is
    // absent. Packet framing and field counts were already verified above.
    let mut hostname: Option<String> = None;
    let mut model_short: Option<String> = None;
    let mut model_full: Option<String> = None;
    if let Some(fields) = bytes.get(4..) {
        let mut pos = 0usize;
        while let Some(header) = fields.get(pos..pos + 3) {
            let field_type = header[0];
            let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
            pos += 3;
            let Some(end) = pos.checked_add(len) else {
                break;
            };
            let Some(value) = fields.get(pos..end) else {
                break;
            };
            pos = end;
            match field_type {
                11 if hostname.is_none() => hostname = sanitize_tlv_ascii(value),
                21 if model_short.is_none() => model_short = sanitize_tlv_ascii(value),
                20 if model_full.is_none() => model_full = sanitize_tlv_ascii(value),
                _ => {}
            }
        }
    }

    let model = reply
        .platform()
        .map(str::to_owned)
        .or(model_short)
        .or(model_full);
    let firmware = reply.firmware().map(str::to_owned);

    Ok(UniFiDiscoveryObs {
        ip: source,
        mac,
        model,
        firmware,
        hostname,
        source_advertised,
        is_camera_platform,
    })
}

fn sanitize_tlv_ascii(value: &[u8]) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_TLV_TEXT
        || !value.iter().all(|&b| (0x20..=0x7e).contains(&b))
    {
        return None;
    }
    let text = std::str::from_utf8(value).ok()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

/// Computes the directed broadcast address for a private/loopback/link-local
/// CIDR with prefix `<= 30`. Never produces a public broadcast address.
fn private_directed_broadcast(cidr: &str) -> Option<Ipv4Addr> {
    let (addr, prefix_s) = cidr.split_once('/')?;
    let ip: Ipv4Addr = addr.parse().ok()?;
    let prefix: u32 = prefix_s.parse().ok()?;
    if !(8..=30).contains(&prefix) {
        return None;
    }
    let mask = !0u32 << (32 - prefix);
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    let broadcast = Ipv4Addr::from(u32::from(network) | !mask);
    let local = (network.is_private() && broadcast.is_private())
        || (network.is_link_local() && broadcast.is_link_local())
        || (network.is_loopback() && broadcast.is_loopback());
    local.then_some(broadcast)
}

/// Pure-Rust bounded Ubiquiti v1 UDP-10001 discovery probe scoped to `plan`.
///
/// Sends `[0x01, 0x00, 0x00, 0x00]` to private CIDR directed broadcasts plus
/// bounded in-scope unicast targets (up to [`MAX_UNIFI_UNICAST_TARGETS`]), then
/// reads bounded responses within `window`. Responses outside `plan` are dropped.
pub fn unifi_udp_probe(
    plan: &CensusPlan,
    subnets: &[String],
    iface_ip: Ipv4Addr,
    window: Duration,
    cancel: &AtomicBool,
) -> Vec<UniFiDiscoveryObs> {
    unifi_udp_probe_at_port(
        plan,
        subnets,
        iface_ip,
        UNIFI_DISCOVERY_PORT,
        window,
        cancel,
    )
}

/// Same as [`unifi_udp_probe`] with a caller-supplied UDP destination port
/// (enables deterministic loopback testing without port-10001 privilege).
pub(crate) fn unifi_udp_probe_at_port(
    plan: &CensusPlan,
    subnets: &[String],
    iface_ip: Ipv4Addr,
    dest_port: u16,
    window: Duration,
    cancel: &AtomicBool,
) -> Vec<UniFiDiscoveryObs> {
    if dest_port == 0 || window.is_zero() || cancel.load(Ordering::Relaxed) {
        return Vec::new();
    }
    let Ok(sock) = UdpSocket::bind(SocketAddrV4::new(iface_ip, 0)) else {
        return Vec::new();
    };
    let _ = sock.set_broadcast(true);
    if sock
        .set_read_timeout(Some(Duration::from_millis(150)))
        .is_err()
        || sock
            .set_write_timeout(Some(Duration::from_millis(150)))
            .is_err()
    {
        return Vec::new();
    }

    // 1. Send directed broadcast probes for each private/local CIDR.
    for subnet in subnets {
        if cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        if let Some(bcast) = private_directed_broadcast(subnet) {
            let _ = sock.send_to(&UNIFI_V1_QUERY, SocketAddrV4::new(bcast, dest_port));
        }
    }

    // 2. Send bounded unicast probes to in-scope local targets (reaches Wi-Fi
    //    cameras behind AP broadcast suppression, e.g., mesh Wi-Fi).
    for &ip in plan.ping_targets.iter().take(MAX_UNIFI_UNICAST_TARGETS) {
        if cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
            let _ = sock.send_to(&UNIFI_V1_QUERY, SocketAddrV4::new(ip, dest_port));
        }
    }

    let capped_window = window.min(Duration::from_secs(3));
    let deadline = Instant::now() + capped_window;
    let mut buf = [0u8; unifi_discovery::MAX_DATAGRAM + 1];
    let mut observed = BTreeSet::new();
    for _ in 0..MAX_UNIFI_RECEIVE_ATTEMPTS {
        if cancel.load(Ordering::Relaxed)
            || Instant::now() >= deadline
            || observed.len() >= MAX_UNIFI_RESPONSES
        {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(src))) if n <= unifi_discovery::MAX_DATAGRAM => {
                let ip = *src.ip();
                if !plan.contains(ip) {
                    continue;
                }
                if let Ok(obs) = parse_unifi_discovery_reply(ip, &buf[..n]) {
                    observed.insert(obs);
                }
            }
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }

    observed.into_iter().collect()
}

// ---- Non-intrusive RTSP OPTIONS banner/realm peek -------------------------

/// One sanitized RTSP `OPTIONS *` banner/realm observation.
///
/// Captures only `status_code`, `Server`, `WWW-Authenticate` `realm`, and
/// `Public` method names. Never sends credentials and never retains nonces,
/// opaque challenge tokens, or raw response bodies.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RtspBannerObs {
    /// IPv4 address of the RTSP responder.
    pub ip: Ipv4Addr,
    /// TCP port that answered `OPTIONS *`.
    pub port: u16,
    /// RTSP 3-digit status code (e.g., 200 or 401).
    pub status_code: u16,
    /// Sanitized `Server:` header, if present.
    pub server: Option<String>,
    /// Sanitized Digest/Basic `realm`, if present in `WWW-Authenticate:`.
    pub realm: Option<String>,
    /// Advertised RTSP methods from `Public:` header.
    pub public_methods: Vec<String>,
}

/// Parses a bounded RTSP `OPTIONS *` wire response into [`RtspBannerObs`].
///
/// Returns `None` for oversized (> 4 KiB), non-UTF-8, or non-RTSP responses.
#[must_use]
pub fn parse_rtsp_options_response(ip: Ipv4Addr, port: u16, bytes: &[u8]) -> Option<RtspBannerObs> {
    if bytes.is_empty() || bytes.len() > MAX_RTSP_PEEK_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let header_block = text.split("\r\n\r\n").next().unwrap_or(text);
    let mut lines = header_block.lines();
    let status_line = lines.next()?.trim_end_matches('\r');
    let mut parts = status_line.split_ascii_whitespace();
    let proto = parts.next()?;
    if proto != "RTSP/1.0" && proto != "RTSP/1.1" {
        return None;
    }
    let code_str = parts.next()?;
    if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status_code: u16 = code_str.parse().ok()?;
    if !(100..=599).contains(&status_code) {
        return None;
    }

    let mut server: Option<String> = None;
    let mut realm: Option<String> = None;
    let mut public_methods = Vec::new();

    for raw_line in lines {
        let line = raw_line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let key = name.trim();
        let val = value.trim();
        if key.eq_ignore_ascii_case("Server") && server.is_none() {
            server = sanitize_header_text(val);
        } else if key.eq_ignore_ascii_case("WWW-Authenticate") && realm.is_none() {
            realm = extract_auth_realm(val);
        } else if key.eq_ignore_ascii_case("Public") && public_methods.is_empty() {
            for method in val.split(',').take(MAX_PUBLIC_METHODS) {
                let m = method.trim();
                if !m.is_empty()
                    && m.len() <= 32
                    && m.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                {
                    public_methods.push(m.to_owned());
                }
            }
        }
    }

    Some(RtspBannerObs {
        ip,
        port,
        status_code,
        server,
        realm,
        public_methods,
    })
}

fn sanitize_header_text(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::new();
    for ch in trimmed.chars() {
        if out.len() >= MAX_HEADER_TEXT {
            break;
        }
        if (' '..='~').contains(&ch) {
            out.push(ch);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Extracts ONLY the `realm` parameter from a `WWW-Authenticate` header
/// (Digest or Basic), discarding nonces, opaque values, and other fields.
fn extract_auth_realm(header_value: &str) -> Option<String> {
    let lower = header_value.to_ascii_lowercase();
    let idx = lower.find("realm=")?;
    let rest = header_value.get(idx + 6..)?.trim_start();
    let raw_realm = if let Some(after_quote) = rest.strip_prefix('"') {
        let end = after_quote.find('"')?;
        after_quote.get(..end)?
    } else {
        rest.split([',', ';', ' ', '\t']).next()?
    };
    sanitize_header_text(raw_realm)
}

/// Performs one bounded, non-intrusive RTSP `OPTIONS *` banner peek over TCP.
pub fn rtsp_options_peek_endpoint(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Option<RtspBannerObs> {
    if port == 0 || cancel.load(Ordering::Relaxed) {
        return None;
    }
    let bounded_timeout = timeout.clamp(Duration::from_millis(50), Duration::from_millis(500));
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = TcpStream::connect_timeout(&addr, bounded_timeout).ok()?;
    stream.set_read_timeout(Some(bounded_timeout)).ok()?;
    stream.set_write_timeout(Some(bounded_timeout)).ok()?;
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    stream.write_all(RTSP_OPTIONS_REQUEST).ok()?;
    stream.flush().ok()?;

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    while buf.len() < MAX_RTSP_PEEK_BYTES {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        let remaining = MAX_RTSP_PEEK_BYTES - buf.len();
        let to_read = remaining.min(chunk.len());
        match stream.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    parse_rtsp_options_response(ip, port, &buf)
}

/// Peeks RTSP `OPTIONS *` banners across in-scope hosts with open RTSP ports.
pub fn rtsp_options_peek(
    hosts: &[HostObs],
    workers: usize,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Vec<RtspBannerObs> {
    if cancel.load(Ordering::Relaxed) {
        return Vec::new();
    }
    let mut targets = Vec::new();
    for host in hosts {
        for &port in &host.open_ports {
            if RTSP_PEEK_PORTS.contains(&port) {
                targets.push((host.ip, port));
                if targets.len() >= MAX_RTSP_PEEK_ENDPOINTS {
                    break;
                }
            }
        }
        if targets.len() >= MAX_RTSP_PEEK_ENDPOINTS {
            break;
        }
    }
    if targets.is_empty() {
        return Vec::new();
    }
    let worker_count = workers.clamp(1, 32).min(targets.len());
    let (tx, rx) = mpsc::sync_channel::<(Ipv4Addr, u16)>(worker_count);
    let rx = std::sync::Mutex::new(rx);
    let (out_tx, out_rx) = mpsc::sync_channel::<RtspBannerObs>(worker_count);

    std::thread::scope(|s| {
        let collector = s.spawn(move || {
            let mut results: BTreeMap<(Ipv4Addr, u16), RtspBannerObs> = BTreeMap::new();
            while let Ok(obs) = out_rx.recv() {
                results.insert((obs.ip, obs.port), obs);
            }
            results.into_values().collect::<Vec<_>>()
        });
        for _ in 0..worker_count {
            let rx = &rx;
            let out_tx = out_tx.clone();
            s.spawn(move || {
                while let Ok((ip, port)) =
                    rx.lock().map(|r| r.recv()).unwrap_or(Err(mpsc::RecvError))
                {
                    if cancel.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some(obs) = rtsp_options_peek_endpoint(ip, port, timeout, cancel)
                        && out_tx.send(obs).is_err()
                    {
                        break;
                    }
                }
            });
        }
        for target in targets {
            if cancel.load(Ordering::Relaxed) || tx.send(target).is_err() {
                break;
            }
        }
        drop(tx);
        drop(out_tx);
        collector.join().unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    pub(crate) fn build_unifi_v1_reply(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for &(tag, value) in tlvs {
            body.push(tag);
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value);
        }
        let mut pkt = Vec::with_capacity(4 + body.len());
        pkt.extend_from_slice(&[1, 0]);
        pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&body);
        pkt
    }

    #[test]
    fn unifi_tlv_parser_decodes_g4_instant_fixture() {
        let ip = Ipv4Addr::new(192, 168, 4, 177);
        let mac_bytes: [u8; 6] = [0x74, 0xac, 0xb9, 0x11, 0x22, 0x33];
        let mut addr_claim = [0u8; 10];
        addr_claim[..6].copy_from_slice(&mac_bytes);
        addr_claim[6..].copy_from_slice(&ip.octets());

        let pkt = build_unifi_v1_reply(&[
            (1, &mac_bytes),
            (2, &addr_claim),
            (3, b"UVC.SAV530q.v4.72.38.67"),
            (11, b"Front-Porch-G4-Instant"),
            (12, b"UVC G4 Instant"),
        ]);

        let obs = parse_unifi_discovery_reply(ip, &pkt).expect("valid UniFi v1 TLV");
        assert_eq!(obs.ip, ip);
        assert_eq!(obs.mac.as_deref(), Some("74:ac:b9:11:22:33"));
        assert_eq!(obs.model.as_deref(), Some("UVC G4 Instant"));
        assert_eq!(obs.firmware.as_deref(), Some("UVC.SAV530q.v4.72.38.67"));
        assert_eq!(obs.hostname.as_deref(), Some("Front-Porch-G4-Instant"));
        assert!(obs.source_advertised);
        assert!(obs.is_camera_platform);
        assert!(obs.is_camera_or_protect());
        let arp = obs.to_arp_row().expect("unicast mac becomes neighbor row");
        assert_eq!(arp.ip, ip);
        assert_eq!(arp.mac, "74:ac:b9:11:22:33");
    }

    #[test]
    fn unifi_tlv_parser_rejects_malformed_and_classifies_ap_vs_camera() {
        let ip = Ipv4Addr::new(192, 168, 4, 20);
        // Truncated header / wrong version
        assert!(parse_unifi_discovery_reply(ip, &[1, 0]).is_err());
        assert!(parse_unifi_discovery_reply(ip, &[2, 0, 0, 0]).is_err());
        // Valid AP reply (U6-Pro) is not a camera/Protect appliance.
        let ap_pkt = build_unifi_v1_reply(&[
            (1, &[0x18, 0xe8, 0x29, 0x01, 0x02, 0x03]),
            (3, b"6.6.77"),
            (12, b"U6-Pro"),
        ]);
        let ap = parse_unifi_discovery_reply(ip, &ap_pkt).expect("valid AP TLV");
        assert!(!ap.is_camera_platform);
        assert!(!ap.is_camera_or_protect());
    }

    #[test]
    fn rtsp_options_parser_extracts_server_realm_and_methods_without_nonces() {
        let ip = Ipv4Addr::new(192, 168, 4, 177);
        let resp = b"RTSP/1.0 401 Unauthorized\r\n\
                     CSeq: 1\r\n\
                     Server: UniFi Protect RTSP/1.0\r\n\
                     WWW-Authenticate: Digest realm=\"ubnt-protect\", nonce=\"deadbeefsecret\"\r\n\
                     Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n";
        let obs = parse_rtsp_options_response(ip, 7447, resp).expect("valid RTSP response");
        assert_eq!(obs.status_code, 401);
        assert_eq!(obs.server.as_deref(), Some("UniFi Protect RTSP/1.0"));
        assert_eq!(obs.realm.as_deref(), Some("ubnt-protect"));
        assert_eq!(
            obs.public_methods,
            vec!["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
        );

        // Non-RTSP / HTTP / oversized responses are refused.
        assert!(parse_rtsp_options_response(ip, 554, b"HTTP/1.1 200 OK\r\n\r\n").is_none());
        let oversized = vec![b'A'; MAX_RTSP_PEEK_BYTES + 1];
        assert!(parse_rtsp_options_response(ip, 554, &oversized).is_none());
    }

    #[test]
    fn loopback_unifi_udp_and_rtsp_options_probes_work_pure_rust() {
        // 1. Ephemeral loopback UniFi UDP responder
        let udp_srv = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_port = udp_srv.local_addr().unwrap().port();
        udp_srv
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let reply_bytes = build_unifi_v1_reply(&[
            (1, &[0x74, 0xac, 0xb9, 0xaa, 0xbb, 0xcc]),
            (3, b"UVC.v4.72.38"),
            (11, b"Lab-G4-Instant"),
            (12, b"UVC G4 Instant"),
        ]);
        let udp_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = udp_srv.recv_from(&mut buf)
                && n == 4
                && buf[..4] == UNIFI_V1_QUERY
            {
                let _ = udp_srv.send_to(&reply_bytes, from);
            }
        });

        let plan = CensusPlan {
            ping_targets: vec![Ipv4Addr::LOCALHOST],
        };
        let cancel = AtomicBool::new(false);
        let unifi_obs = unifi_udp_probe_at_port(
            &plan,
            &["127.0.0.1/32".to_owned()],
            Ipv4Addr::LOCALHOST,
            udp_port,
            Duration::from_millis(300),
            &cancel,
        );
        let _ = udp_handle.join();
        assert_eq!(unifi_obs.len(), 1);
        assert_eq!(unifi_obs[0].ip, Ipv4Addr::LOCALHOST);
        assert_eq!(unifi_obs[0].model.as_deref(), Some("UVC G4 Instant"));
        assert_eq!(unifi_obs[0].mac.as_deref(), Some("74:ac:b9:aa:bb:cc"));

        // 2. Ephemeral loopback RTSP OPTIONS responder
        let tcp_srv = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let tcp_port = tcp_srv.local_addr().unwrap().port();
        let tcp_handle = std::thread::spawn(move || {
            if let Ok((mut conn, _)) = tcp_srv.accept() {
                let mut req = [0u8; 256];
                let _ = conn.read(&mut req);
                let _ = conn.write_all(
                    b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Tapo RTSP Server\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n",
                );
            }
        });
        let banner = rtsp_options_peek_endpoint(
            Ipv4Addr::LOCALHOST,
            tcp_port,
            Duration::from_millis(400),
            &cancel,
        )
        .expect("loopback RTSP OPTIONS banner");
        let _ = tcp_handle.join();
        assert_eq!(banner.status_code, 200);
        assert_eq!(banner.server.as_deref(), Some("Tapo RTSP Server"));
    }
}
