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

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
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

/// The expanded DNS wire name includes label lengths and the root octet.
const MAX_NAME_BYTES: usize = 255;
const MAX_PACKET_BYTES: usize = 4096;
const MAX_QUESTIONS: usize = 16;
const MAX_RECORDS_PER_PACKET: usize = 256;
const MAX_RECEIVE_ATTEMPTS: usize = 256;
const MAX_RECORDS_PER_SWEEP: usize = 1024;
const MAX_PROBE_SECONDS: u64 = 120;

// ---- mDNS core ------------------------------------------------------------

/// Builds one mDNS query packet (one question per camera service type).
/// Service types are qualified under `.local`; an existing suffix is preserved.
/// The ephemeral source port requests legacy unicast replies (RFC 6762 §6.7),
/// so the unicast-response bit is not needed. Invalid/oversized input produces
/// no packet rather than silently truncating names or the question count.
#[must_use]
pub fn build_mdns_query(types: &[&str], start_id: u16) -> Vec<u8> {
    if types.is_empty() || types.len() > MAX_QUESTIONS {
        return Vec::new();
    }
    let mut names = Vec::with_capacity(types.len());
    for name in types {
        if name.len() > MAX_NAME_BYTES {
            return Vec::new();
        }
        let labels: Vec<_> = name.strip_suffix('.').unwrap_or(name).split('.').collect();
        if labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        }) {
            return Vec::new();
        }
        let needs_local = !labels
            .last()
            .is_some_and(|label| label.eq_ignore_ascii_case("local"));
        let wire_len = labels.iter().map(|label| label.len() + 1).sum::<usize>()
            + 1
            + usize::from(needs_local) * 6;
        if wire_len > MAX_NAME_BYTES {
            return Vec::new();
        }
        names.push((labels, needs_local));
    }
    let mut out = Vec::with_capacity(12 + types.len() * 32);
    out.extend_from_slice(&start_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // flags
    let count = types.len() as u16;
    out.extend_from_slice(&count.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for (labels, needs_local) in names {
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        if needs_local {
            out.extend_from_slice(b"\x05local");
        }
        out.push(0);
        out.extend_from_slice(&12u16.to_be_bytes()); // PTR
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
    }
    if out.len() > MAX_PACKET_BYTES {
        return Vec::new();
    }
    out
}

/// One mDNS answer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MdnsAnswer {
    /// Owner name; literal dots/backslashes within a label are escaped.
    pub name: String,
    /// RR type code (12 = PTR, 1 = A, 33 = SRV, 16 = TXT).
    pub rr_type: u16,
    /// TTL in seconds.
    pub ttl: u32,
    /// Decoded rdata (PTR target / A dotted / SRV target / TXT text).
    pub rdata: String,
    /// Port for an SRV record; advertisement alone does not prove reachability.
    pub srv_port: Option<u16>,
}

/// Records received in one datagram, bound to its actual UDP responder.
/// An advertised A/SRV target can differ from this address (for example, a
/// sleep proxy); it must not inherit the sender's current-response evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsObservation {
    /// Source address of the accepted response datagram.
    pub responder: Ipv4Addr,
    /// Internet-class records from answer, authority, and additional sections.
    pub answers: Vec<MdnsAnswer>,
}

/// Parses a bounded, complete DNS response, including authority/additional
/// records required to connect a service instance to its SRV and A records.
/// Queries, truncation, DNS errors, pointer loops, and malformed RDATA reject
/// the entire packet; already parsed records are never partial evidence.
pub fn parse_mdns_response(data: &[u8]) -> Result<Vec<MdnsAnswer>, StandardsError> {
    if data.len() < 12 {
        return Err(StandardsError::ShortPacket);
    }
    if data.len() > MAX_PACKET_BYTES {
        return Err(StandardsError::Malformed);
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 || flags & 0x7a0f != 0 {
        return Err(StandardsError::Malformed);
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let record_count = [6, 8, 10]
        .into_iter()
        .map(|i| u16::from_be_bytes([data[i], data[i + 1]]) as usize)
        .sum::<usize>();
    if qdcount > MAX_QUESTIONS || record_count > MAX_RECORDS_PER_PACKET {
        return Err(StandardsError::Malformed);
    }
    let mut off = 12usize;
    // skip questions
    for _ in 0..qdcount {
        off += read_name(data, off)?.1;
        off = off.checked_add(4).ok_or(StandardsError::Malformed)?;
        if off > data.len() {
            return Err(StandardsError::ShortPacket);
        }
    }
    let mut answers = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let (name, consumed) = read_name(data, off)?;
        off += consumed;
        if off + 10 > data.len() {
            return Err(StandardsError::ShortPacket);
        }
        let rr_type = u16::from_be_bytes([data[off], data[off + 1]]);
        let rr_class = u16::from_be_bytes([data[off + 2], data[off + 3]]) & 0x7fff;
        let ttl = u32::from_be_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let rdlen = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
        off += 10;
        let rdata_off = off;
        if off + rdlen > data.len() {
            return Err(StandardsError::ShortPacket);
        }
        off += rdlen;
        if rr_class != 1 {
            continue;
        }
        let mut srv_port = None;
        let rdata = match rr_type {
            12 => read_rdata_name(data, rdata_off, rdlen)?,
            33 => {
                if rdlen < 7 {
                    return Err(StandardsError::Malformed);
                }
                // RFC 2782: priority, weight, port (three u16s), then target.
                srv_port = Some(u16::from_be_bytes([
                    data[rdata_off + 4],
                    data[rdata_off + 5],
                ]));
                read_rdata_name(data, rdata_off + 6, rdlen - 6)?
            }
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
            16 => read_txt(&data[rdata_off..off])?,
            _ => hex_prefix(&data[rdata_off..rdata_off + rdlen.min(32)]),
        };
        answers.push(MdnsAnswer {
            name,
            rr_type,
            ttl,
            rdata,
            srv_port,
        });
    }
    if off != data.len() {
        return Err(StandardsError::Malformed);
    }
    Ok(answers)
}

fn read_rdata_name(data: &[u8], off: usize, len: usize) -> Result<String, StandardsError> {
    let (name, consumed) = read_name(data, off)?;
    if consumed != len {
        return Err(StandardsError::Malformed);
    }
    Ok(name)
}

// Return the bytes consumed at the original cursor separately from the
// expanded name size. Following a pointer must never move the caller's cursor.
fn read_name(data: &[u8], mut off: usize) -> Result<(String, usize), StandardsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    let mut consumed = 0usize;
    let mut expanded = 1usize;
    let mut jumped = false;
    loop {
        if off >= data.len() {
            return Err(StandardsError::ShortPacket);
        }
        let len = data[off] as usize;
        if len == 0 {
            if !jumped {
                consumed += 1;
            }
            return Ok((labels.join("."), consumed));
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= data.len() {
                return Err(StandardsError::ShortPacket);
            }
            jumps += 1;
            if jumps > 16 {
                return Err(StandardsError::Malformed);
            }
            let target = ((len & 0x3F) << 8) | data[off + 1] as usize;
            if target < 12 || target >= off {
                return Err(StandardsError::Malformed);
            }
            if !jumped {
                consumed += 2;
            }
            jumped = true;
            off = target;
        } else {
            if len & 0xc0 != 0 {
                return Err(StandardsError::Malformed);
            }
            let end = off + 1 + len;
            expanded += 1 + len;
            if end > data.len() || expanded > MAX_NAME_BYTES {
                return Err(StandardsError::Malformed);
            }
            labels.push(escaped_octets(&data[off + 1..end]));
            if !jumped {
                consumed += 1 + len;
            }
            off = end;
        }
    }
}

fn escaped_octets(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        match byte {
            b'.' | b'\\' => {
                text.push('\\');
                text.push(char::from(byte));
            }
            0x21..=0x7e => text.push(char::from(byte)),
            _ => text.push_str(&format!("\\{byte:03}")),
        }
    }
    text
}

fn read_txt(bytes: &[u8]) -> Result<String, StandardsError> {
    let mut strings = Vec::new();
    let mut off = 0;
    while off < bytes.len() {
        let end = off + 1 + usize::from(bytes[off]);
        if end > bytes.len() {
            return Err(StandardsError::Malformed);
        }
        strings.push(escaped_octets(&bytes[off + 1..end]));
        off = end;
    }
    Ok(strings.join(" "))
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
    if data.len() > MAX_PACKET_BYTES {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let mut status = text.split("\r\n").next()?.split_ascii_whitespace();
    if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) || status.next() != Some("200") {
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
    if data.len() > MAX_PACKET_BYTES {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let open = find_tag_open(text, "ProbeMatch")?;
    let start = open + text[open..].find('>')? + 1;
    let end = start + find_tag_close(&text[start..], "ProbeMatch")?;
    let body = &text[start..end];
    Some(WsdMatch {
        ip: ip.to_owned(),
        xaddrs: extract_tags(body, "XAddrs"),
        scopes: extract_tags(body, "Scopes"),
        types: extract_tags(body, "Types"),
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
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'))
            .count();
        let name = &after[..skip];
        let base = name.rsplit(':').next().unwrap_or(name);
        if base == tag
            && after
                .as_bytes()
                .get(skip)
                .is_some_and(|c| c.is_ascii_whitespace() || matches!(c, b'>' | b'/'))
        {
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
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'))
            .count();
        let name = &after[..skip];
        let base = name.rsplit(':').next().unwrap_or(name);
        if base == tag
            && after
                .as_bytes()
                .get(skip)
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'>')
        {
            return Some(abs);
        }
        from = abs + 2;
    }
    None
}

impl WsdMatch {
    /// Whether the ProbeMatch advertises the exact ONVIF camera type or
    /// streaming scope. This vendor claim proves neither conformance nor
    /// authentication, streaming, or source custody.
    #[must_use]
    pub fn is_onvif_camera(&self) -> bool {
        self.types
            .iter()
            .flat_map(|text| text.split_ascii_whitespace())
            .any(|token| token.rsplit(':').next() == Some("NetworkVideoTransmitter"))
            || self
                .scopes
                .iter()
                .flat_map(|text| text.split_ascii_whitespace())
                .any(|token| token == "onvif://www.onvif.org/Profile/Streaming")
    }
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

/// Sends a bounded one-shot mDNS query and retains actual responder identity.
/// This is the legacy unicast mode of RFC 6762 §6.7: response ID must match
/// the query and the sender must use the mDNS port. No advertised address or
/// service URI is contacted. The caller applies its configured subnet scope.
pub fn mdns_observe(
    iface_ip: Ipv4Addr,
    types: &[&str],
    seconds: u64,
    cancel: &AtomicBool,
) -> Vec<MdnsObservation> {
    // Admit names before opening a socket or emitting any traffic.
    let mut query = build_mdns_query(types, 0);
    if query.is_empty() {
        return Vec::new();
    }
    let Some(sock) = probe_socket(iface_ip, seconds, cancel) else {
        return Vec::new();
    };
    let Ok(local) = sock.local_addr() else {
        return Vec::new();
    };
    let query_id = local.port();
    query[..2].copy_from_slice(&query_id.to_be_bytes());
    let group = SocketAddrV4::new(MDNS_GROUP, MDNS_PORT);
    for _ in 0..3 {
        if cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let _ = sock.send_to(&query, group);
    }
    let mut retained = 0;
    collect_datagrams(
        seconds,
        cancel,
        |buf| sock.recv_from(buf),
        |source, data| {
            let observation = parse_mdns_datagram(source, query_id, data)?;
            if observation.answers.len() > MAX_RECORDS_PER_SWEEP - retained {
                return None;
            }
            retained += observation.answers.len();
            Some(observation)
        },
    )
}

/// Compatibility projection for callers needing records without liveness.
/// Use [`mdns_observe`] when associating current responses with candidates.
pub fn mdns_probe(
    iface_ip: Ipv4Addr,
    types: &[&str],
    seconds: u64,
    cancel: &AtomicBool,
) -> Vec<MdnsAnswer> {
    mdns_observe(iface_ip, types, seconds, cancel)
        .into_iter()
        .flat_map(|observation| observation.answers)
        .collect()
}

fn parse_mdns_datagram(source: SocketAddr, query_id: u16, data: &[u8]) -> Option<MdnsObservation> {
    let SocketAddr::V4(source) = source else {
        return None;
    };
    if source.port() != MDNS_PORT || data.get(..2)? != query_id.to_be_bytes() {
        return None;
    }
    let answers = parse_mdns_response(data).ok()?;
    if answers.is_empty() {
        return None;
    }
    Some(MdnsObservation {
        responder: *source.ip(),
        answers,
    })
}

/// Sends M-SEARCH (ssdp:all + upnp:rootdevice) and collects bounded responses.
pub fn ssdp_probe(iface_ip: Ipv4Addr, seconds: u64, cancel: &AtomicBool) -> Vec<SsdpResponse> {
    let Some(sock) = probe_socket(iface_ip, seconds, cancel) else {
        return Vec::new();
    };
    let group = SocketAddrV4::new(SSDP_GROUP, SSDP_PORT);
    for st in ["ssdp:all", "upnp:rootdevice"] {
        if cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let _ = sock.send_to(&build_msearch(st, 2), group);
    }
    collect_datagrams(
        seconds,
        cancel,
        |buf| sock.recv_from(buf),
        |source, data| parse_ssdp_response(&source.ip().to_string(), data),
    )
}

/// Sends the ONVIF WS-Discovery Probe and collects bounded Probe Matches.
pub fn wsdiscovery_probe(iface_ip: Ipv4Addr, seconds: u64, cancel: &AtomicBool) -> Vec<WsdMatch> {
    let Some(sock) = probe_socket(iface_ip, seconds, cancel) else {
        return Vec::new();
    };
    let group = SocketAddrV4::new(SSDP_GROUP, WSD_PORT);
    let probe = build_wsdiscovery_probe();
    for _ in 0..3 {
        if cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let _ = sock.send_to(&probe, group);
    }
    collect_datagrams(
        seconds,
        cancel,
        |buf| sock.recv_from(buf),
        |source, data| parse_wsd_match(&source.ip().to_string(), data),
    )
}

fn probe_socket(iface_ip: Ipv4Addr, seconds: u64, cancel: &AtomicBool) -> Option<UdpSocket> {
    if !(1..=MAX_PROBE_SECONDS).contains(&seconds) || cancel.load(Ordering::Relaxed) {
        return None;
    }
    let sock = UdpSocket::bind(SocketAddrV4::new(iface_ip, 0)).ok()?;
    set_multicast_if(&sock, iface_ip).ok()?;
    // A failed timeout installation must not turn a bounded probe into a
    // blocking receive. The source-bound/default-route limitation is below.
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    sock.set_write_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    Some(sock)
}

// The injected receive seam tests the exact network collector without sockets.
// Malformed packets and transient failures consume the same attempt budget as
// accepted packets, so traffic cannot force unbounded parse work or retention.
fn collect_datagrams<T>(
    seconds: u64,
    cancel: &AtomicBool,
    mut receive: impl FnMut(&mut [u8]) -> std::io::Result<(usize, SocketAddr)>,
    mut parse: impl FnMut(SocketAddr, &[u8]) -> Option<T>,
) -> Vec<T> {
    if !(1..=MAX_PROBE_SECONDS).contains(&seconds) || cancel.load(Ordering::Relaxed) {
        return Vec::new();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut out = Vec::new();
    // One extra byte distinguishes oversized/truncated datagrams from exactly
    // full valid packets; discarded packets still consume the attempt budget.
    let mut buf = [0u8; MAX_PACKET_BYTES + 1];
    for _ in 0..MAX_RECEIVE_ATTEMPTS {
        if cancel.load(Ordering::Relaxed) || std::time::Instant::now() >= deadline {
            break;
        }
        let received = receive(&mut buf);
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match received {
            Ok((n, source)) if n <= MAX_PACKET_BYTES => {
                if let Some(value) = parse(source, &buf[..n]) {
                    out.push(value);
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
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
#[path = "standards/tests.rs"]
mod tests;
