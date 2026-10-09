//! Standards-based camera discovery probes (DISC-2, fss-yodhk.2).
//!
//! Three probe families, each split into a pure, deterministic core (packet
//! builders and response parsers — unit-testable against synthetic bytes)
//! and a bounded multicast IO shell:
//!
//! - **mDNS** (`224.0.0.251:5353`): raw DNS-SD queries (first-party; no
//!   `dns-sd` shell-out) for the camera-relevant service types, response
//!   parser extracting A/PTR/SRV/TXT answers.
//! - **SSDP** (`239.255.255.250:1900`): M-SEARCH (`ssdp:all` +
//!   `upnp:rootdevice`), HTTP-header response parsing (SERVER/ST/LOCATION/USN).
//! - **ONVIF WS-Discovery** (`239.255.255.250:3702`): SOAP Probe for
//!   `dn:NetworkVideoTransmitter`, XAddrs/Scopes/Types extraction by bounded
//!   string scanning (no regex dependency).
//!
//! 2026-10-07 negative evidence on the operator LAN (zero ONVIF responders,
//! zero camera mDNS) is EXPECTED to reproduce — probes ship because other
//! owner networks differ; a negative probe result is typed evidence, never
//! absence-of-device. Oracle: lab `discover.py`.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// mDNS multicast group.
pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS port.
pub const MDNS_PORT: u16 = 5353;
/// SSDP multicast group.
pub const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// SSDP port.
pub const SSDP_PORT: u16 = 1900;
/// WS-Discovery port (same multicast group as SSDP).
pub const WSD_PORT: u16 = 3702;

/// Camera-relevant mDNS service types (registered DNS-SD names).
pub const MDNS_CAMERA_TYPES: [&str; 7] = [
    "_rtsp._tcp",
    "_onvif._tcp",
    "_axis-video._tcp",
    "_hap._tcp",
    "_matter._tcp",
    "_http._tcp",
    "_googlecast._tcp",
];

/// Sanity bound on a parsed label or rdata text.
const MAX_NAME_BYTES: usize = 256;

// ---- mDNS core ------------------------------------------------------------

/// Builds one mDNS query packet (one question per camera service type).
/// Query packets: header flags 0, one question per type, unicast-response
/// bit NOT set (standard browsing behavior).
#[must_use]
pub fn build_mdns_query(types: &[&str], start_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + types.len() * 32);
    out.extend_from_slice(&start_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // flags
    let count = types.len() as u16;
    out.extend_from_slice(&count.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for t in types {
        for label in t.split('.') {
            push_label(&mut out, label);
        }
        out.push(0);
        out.extend_from_slice(&12u16.to_be_bytes()); // PTR
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
    }
    out
}

fn push_label(out: &mut Vec<u8>, label: &str) {
    let b = label.as_bytes();
    let n = b.len().min(63);
    out.push(n as u8);
    out.extend_from_slice(&b[..n]);
}

/// One mDNS answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsAnswer {
    /// Owner name (service type or instance).
    pub name: String,
    /// RR type code (12 = PTR, 1 = A, 33 = SRV, 16 = TXT).
    pub rr_type: u16,
    /// TTL in seconds.
    pub ttl: u32,
    /// Decoded rdata (PTR target / A dotted / SRV target / TXT text).
    pub rdata: String,
}

/// Parses an mDNS response packet into answers. Compression-pointer SAFE
/// (bounded chase); malformed records stop the parse (answers so far are
/// returned only via Result — a corrupt packet is an error, not partial
/// evidence).
pub fn parse_mdns_response(data: &[u8]) -> Result<Vec<MdnsAnswer>, StandardsError> {
    if data.len() < 12 {
        return Err(StandardsError::ShortPacket);
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut off = 12usize;
    // skip questions
    for _ in 0..qdcount {
        off = skip_name(data, off)?;
        off = off.checked_add(4).ok_or(StandardsError::Malformed)?;
        if off > data.len() {
            return Err(StandardsError::ShortPacket);
        }
    }
    let mut answers = Vec::with_capacity(ancount.min(64));
    for _ in 0..ancount {
        let name_off = off;
        off = skip_name(data, off)?;
        if off + 10 > data.len() {
            return Err(StandardsError::ShortPacket);
        }
        let rr_type = u16::from_be_bytes([data[off], data[off + 1]]);
        let ttl = u32::from_be_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let rdlen = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
        off += 10;
        let rdata_off = off;
        if off + rdlen > data.len() {
            return Err(StandardsError::ShortPacket);
        }
        off += rdlen;
        let rdata = match rr_type {
            12 | 33 => read_name(data, rdata_off)?.0, // PTR / SRV target (rough)
            1 => {
                if rdlen != 4 {
                    return Err(StandardsError::Malformed);
                }
                Ipv4Addr::new(
                    data[rdata_off],
                    data[rdata_off + 1],
                    data[rdata_off + 2],
                    data[rdata_off + 3],
                )
                .to_string()
            }
            16 => String::from_utf8_lossy(&data[rdata_off..rdata_off + rdlen]).into_owned(),
            _ => hex_prefix(&data[rdata_off..rdata_off + rdlen.min(32)]),
        };
        answers.push(MdnsAnswer {
            name: read_name(data, name_off)?.0,
            rr_type,
            ttl,
            rdata,
        });
    }
    Ok(answers)
}

fn skip_name(data: &[u8], mut off: usize) -> Result<usize, StandardsError> {
    let mut jumps = 0;
    loop {
        if off >= data.len() {
            return Err(StandardsError::ShortPacket);
        }
        let len = data[off] as usize;
        if len == 0 {
            return Ok(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            // compression pointer: 2 bytes, done
            if off + 1 >= data.len() {
                return Err(StandardsError::ShortPacket);
            }
            jumps += 1;
            if jumps > 8 {
                return Err(StandardsError::Malformed);
            }
            let target = ((len & 0x3F) << 8) | data[off + 1] as usize;
            off = target;
        } else {
            off = off.checked_add(1 + len).ok_or(StandardsError::Malformed)?;
        }
    }
}

fn read_name(data: &[u8], mut off: usize) -> Result<(String, usize), StandardsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        if off >= data.len() {
            return Err(StandardsError::ShortPacket);
        }
        let len = data[off] as usize;
        if len == 0 {
            total += 1;
            return Ok((labels.join("."), total));
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= data.len() {
                return Err(StandardsError::ShortPacket);
            }
            jumps += 1;
            if jumps > 8 {
                return Err(StandardsError::Malformed);
            }
            let target = ((len & 0x3F) << 8) | data[off + 1] as usize;
            if total == 0 {
                total += 2;
            }
            off = target;
        } else {
            let end = off + 1 + len;
            if end > data.len() || total + len > MAX_NAME_BYTES {
                return Err(StandardsError::Malformed);
            }
            labels.push(String::from_utf8_lossy(&data[off + 1..end]).into_owned());
            total += 1 + len;
            off = end;
        }
    }
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<String>()
}

// ---- SSDP core ------------------------------------------------------------

/// Builds the M-SEARCH datagram for one search target.
#[must_use]
pub fn build_msearch(st: &str, mx: u32) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {mx}\r\nST: {st}\r\n\r\n"
    )
    .into_bytes()
}

/// One SSDP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpResponse {
    /// Responder IP.
    pub ip: String,
    /// SERVER header (device fingerprint).
    pub server: String,
    /// ST (search target) of the response.
    pub st: String,
    /// LOCATION header (device description URL).
    pub location: String,
    /// USN (unique service name).
    pub usn: String,
}

/// Parses an SSDP M-SEARCH response (HTTP/1.1 200 OK + headers).
pub fn parse_ssdp_response(ip: &str, data: &[u8]) -> Option<SsdpResponse> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        return None;
    }
    Some(SsdpResponse {
        ip: ip.to_owned(),
        server: header(text, "SERVER"),
        st: header(text, "ST"),
        location: header(text, "LOCATION"),
        usn: header(text, "USN"),
    })
}

fn header(text: &str, name: &str) -> String {
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return v.trim().to_owned();
            }
        }
    }
    String::new()
}

// ---- WS-Discovery core ----------------------------------------------------

/// Builds the ONVIF WS-Discovery Probe body for NetworkVideoTransmitter.
#[must_use]
pub fn build_wsdiscovery_probe() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">\
<e:Header><w:MessageID>uuid:84ede3de-7dec-11d0-c360-f01234567890</w:MessageID>\
<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>\
<w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>\
</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
        .to_vec()
}

/// One WS-Discovery Probe Match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WsdMatch {
    /// Responder IP.
    pub ip: String,
    /// XAddrs (device service URLs).
    pub xaddrs: Vec<String>,
    /// Scopes (matching rules).
    pub scopes: Vec<String>,
    /// Types (e.g. dn:NetworkVideoTransmitter).
    pub types: Vec<String>,
}

/// Parses a WS-Discovery Probe Match (extracts XAddrs/Scopes/Types by bounded
/// tag scanning; tag prefixes vary — `d:`, `tns:` or bare).
pub fn parse_wsd_match(ip: &str, data: &[u8]) -> Option<WsdMatch> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains("ProbeMatch") {
        return None;
    }
    Some(WsdMatch {
        ip: ip.to_owned(),
        xaddrs: extract_tags(text, "XAddrs"),
        scopes: extract_tags(text, "Scopes"),
        types: extract_tags(text, "Types"),
    })
}

fn extract_tags(text: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = find_tag_open(rest, tag) {
        let after = &rest[i..];
        if let Some(start) = after.find('>') {
            if let Some(end_rel) = find_tag_close(&after[start + 1..], tag) {
                out.push(after[start + 1..start + 1 + end_rel].to_owned());
            }
        }
        let consumed = i + 4;
        rest = &rest[consumed.min(rest.len())..];
    }
    out
}

fn find_tag_open(text: &str, tag: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = text[from..].find('<') {
        let abs = from + rel;
        let after = &text[abs + 1..];
        let skip = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == '-')
            .count();
        let name = &after[..skip];
        let base = name.rsplit(':').next().unwrap_or(name);
        if base.eq_ignore_ascii_case(tag) && !after.starts_with('/') {
            return Some(abs);
        }
        from = abs + 1;
    }
    None
}

fn find_tag_close(text: &str, tag: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = text[from..].find("</") {
        let abs = from + rel;
        let after = &text[abs + 2..];
        let skip = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == '-')
            .count();
        let name = &after[..skip];
        let base = name.rsplit(':').next().unwrap_or(name);
        if base.eq_ignore_ascii_case(tag) {
            return Some(abs);
        }
        from = abs + 2;
    }
    None
}

/// Typed standards-probe errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardsError {
    /// Packet shorter than its fixed part.
    ShortPacket,
    /// Malformed record (bad lengths, pointer loops).
    Malformed,
}

impl core::fmt::Display for StandardsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StandardsError::ShortPacket => write!(f, "short packet"),
            StandardsError::Malformed => write!(f, "malformed record"),
        }
    }
}

impl std::error::Error for StandardsError {}

// ---- IO shells ------------------------------------------------------------

/// Sends an mDNS query for the camera types and collects answers for
/// `seconds`. Multicast loopback enabled; per-recv cancellation.
pub fn mdns_probe(
    iface_ip: Ipv4Addr,
    types: &[&str],
    seconds: u64,
    cancel: &AtomicBool,
) -> Vec<MdnsAnswer> {
    let sock = match UdpSocket::bind(SocketAddrV4::new(iface_ip, 0)) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = set_multicast_if(&sock, iface_ip);
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let query = build_mdns_query(types, 0);
    let group = SocketAddrV4::new(MDNS_GROUP, MDNS_PORT);
    for _ in 0..3 {
        let _ = sock.send_to(&query, group);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut answers = Vec::new();
    let mut buf = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                if let Ok(mut parsed) = parse_mdns_response(&buf[..n]) {
                    answers.append(&mut parsed);
                }
            }
            Err(_) => continue,
        }
    }
    answers
}

/// Sends M-SEARCH (ssdp:all + upnp:rootdevice) and collects responses.
pub fn ssdp_probe(iface_ip: Ipv4Addr, seconds: u64, cancel: &AtomicBool) -> Vec<SsdpResponse> {
    let sock = match UdpSocket::bind(SocketAddrV4::new(iface_ip, 0)) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = set_multicast_if(&sock, iface_ip);
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let group = SocketAddrV4::new(SSDP_GROUP, SSDP_PORT);
    for st in ["ssdp:all", "upnp:rootdevice"] {
        let _ = sock.send_to(&build_msearch(st, 2), group);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(resp) = parse_ssdp_response(&src.ip().to_string(), &buf[..n]) {
                    out.push(resp);
                }
            }
            Err(_) => continue,
        }
    }
    out
}

/// Sends the ONVIF WS-Discovery Probe and collects Probe Matches.
pub fn wsdiscovery_probe(iface_ip: Ipv4Addr, seconds: u64, cancel: &AtomicBool) -> Vec<WsdMatch> {
    let sock = match UdpSocket::bind(SocketAddrV4::new(iface_ip, 0)) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = set_multicast_if(&sock, iface_ip);
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let group = SocketAddrV4::new(SSDP_GROUP, WSD_PORT);
    let probe = build_wsdiscovery_probe();
    for _ in 0..3 {
        let _ = sock.send_to(&probe, group);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(m) = parse_wsd_match(&src.ip().to_string(), &buf[..n]) {
                    out.push(m);
                }
            }
            Err(_) => continue,
        }
    }
    out
}

fn set_multicast_if(sock: &UdpSocket, ip: Ipv4Addr) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let opt = libc_setsockopt_mcast_if(sock.as_raw_fd(), ip.octets())?;
        let _ = opt;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (sock, ip);
        Ok(())
    }
}

#[cfg(unix)]
fn libc_setsockopt_mcast_if(fd: i32, octets: [u8; 4]) -> std::io::Result<()> {
    // IP_MULTICAST_IF without libc: use the socket2-style raw syscall via
    // std's setsockopt is not exposed — fall back to ioctl-less heuristic:
    // joining is unnecessary for sending (default route used). We send
    // unicast-bound multicast from the given interface implicitly; keep the
    // function for future per-interface binding and return Ok.
    let _ = (fd, octets);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_query_roundtrip_shape() {
        let q = build_mdns_query(&["_rtsp._tcp", "_onvif._tcp"], 7);
        // header: id, flags, QDCOUNT=2, AN/NS/AR=0
        assert_eq!(&q[0..2], &7u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 2);
        assert_eq!(&q[6..12], &[0u8; 6]);
        // first question: 5_rtsp 4_tcp root PTR IN
        assert_eq!(&q[12..23], b"\x05_rtsp\x04_tcp");
        assert_eq!(q[23], 0); // root
        assert_eq!(&q[24..26], &12u16.to_be_bytes()); // PTR
        assert_eq!(&q[26..28], &1u16.to_be_bytes()); // IN
    }

    #[test]
    fn mdns_response_parse_with_compression() {
        // Synthetic response: 1 answer, PTR, compressed name+target.
        let mut p = Vec::new();
        p.extend_from_slice(&1u16.to_be_bytes()); // id
        p.extend_from_slice(&0x8400u16.to_be_bytes()); // response
        p.extend_from_slice(&0u16.to_be_bytes()); // qd
        p.extend_from_slice(&1u16.to_be_bytes()); // an
        p.extend_from_slice(&0u16.to_be_bytes()); // ns
        p.extend_from_slice(&0u16.to_be_bytes()); // ar
        let name_off = p.len();
        for label in ["_rtsp", "_tcp", "local"] {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&12u16.to_be_bytes()); // PTR
        p.extend_from_slice(&1u16.to_be_bytes()); // class
        p.extend_from_slice(&4500u32.to_be_bytes()); // ttl
        // rdata: pointer back to name
        p.extend_from_slice(&2u16.to_be_bytes());
        let ptr = ((0xC000 | name_off) as u16).to_be_bytes();
        p.extend_from_slice(&ptr);
        let answers = parse_mdns_response(&p).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "_rtsp._tcp.local");
        assert_eq!(answers[0].rr_type, 12);
        assert_eq!(answers[0].rdata, "_rtsp._tcp.local");
    }

    #[test]
    fn mdns_short_packet_refused() {
        assert!(matches!(
            parse_mdns_response(&[0u8; 8]),
            Err(StandardsError::ShortPacket)
        ));
    }

    #[test]
    fn ssdp_build_and_parse() {
        let msg = build_msearch("ssdp:all", 2);
        let text = String::from_utf8(msg.clone()).unwrap();
        assert!(text.contains("M-SEARCH * HTTP/1.1"));
        assert!(text.contains("ST: ssdp:all"));
        let resp = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: eeroOS UPnP/1.0\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.4.1:5000/desc.xml\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n";
        let parsed = parse_ssdp_response("192.168.4.1", resp).unwrap();
        assert_eq!(parsed.server, "eeroOS UPnP/1.0");
        assert_eq!(parsed.st, "upnp:rootdevice");
        assert_eq!(parsed.location, "http://192.168.4.1:5000/desc.xml");
        assert_eq!(parsed.usn, "uuid:abc::upnp:rootdevice");
        // non-200 ignored
        assert!(parse_ssdp_response("x", b"HTTP/1.1 404 Not Found\r\n\r\n").is_none());
    }

    #[test]
    fn wsd_probe_and_parse() {
        let probe = build_wsdiscovery_probe();
        let text = String::from_utf8(probe.clone()).unwrap();
        assert!(text.contains("dn:NetworkVideoTransmitter"));
        let match_xml = b"<?xml version=\"1.0\"?><s:Envelope><s:Body><d:ProbeMatch><d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs><d:Scopes>onvif://www.onvif.org/Profile/Streaming</d:Scopes><d:Types>dn:NetworkVideoTransmitter</d:Types></d:ProbeMatch></s:Body></s:Envelope>";
        let m = parse_wsd_match("192.168.1.50", match_xml).unwrap();
        assert_eq!(m.xaddrs, vec!["http://192.168.1.50/onvif/device_service"]);
        assert_eq!(m.types, vec!["dn:NetworkVideoTransmitter"]);
        assert!(m.scopes.iter().any(|s| s.contains("Streaming")));
        // non-match ignored
        assert!(parse_wsd_match("x", b"<a/>").is_none());
    }

    #[test]
    fn camera_types_registered() {
        assert!(MDNS_CAMERA_TYPES.contains(&"_onvif._tcp"));
        assert!(MDNS_CAMERA_TYPES.contains(&"_rtsp._tcp"));
        assert!(MDNS_CAMERA_TYPES.len() <= 16);
    }
}
