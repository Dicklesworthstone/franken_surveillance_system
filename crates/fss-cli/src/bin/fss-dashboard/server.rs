#![forbid(unsafe_code)]
//! Finite single-owner HTTP/1.1 listener. No threads, background readers, CORS, or filesystem routes.
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use super::{Lease, Options, snapshot};

const HEADER_LIMIT: usize = 8192;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

fn request<'a>(head: &'a str, host: &str) -> Result<&'a str, u16> {
    if head.len() > HEADER_LIMIT || !head.ends_with("\r\n\r\n") { return Err(400); }
    let mut lines = head[..head.len() - 4].split("\r\n");
    let parts: Vec<_> = lines.next().ok_or(400u16)?.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" { return Err(400); }
    if parts[0] != "GET" { return Err(405); }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') || headers.len() >= 64 { return Err(400); }
        if headers.insert(name.to_ascii_lowercase(), value.trim()).is_some() { return Err(400); }
    }
    if headers.get("host") != Some(&host) { return Err(403); }
    let origin = format!("http://{host}");
    if headers.get("origin").is_some_and(|v| *v != origin) { return Err(403); }
    if headers.contains_key("transfer-encoding") || headers.get("content-length").is_some_and(|v| *v != "0") { return Err(400); }
    if parts[1] == "/api/snapshot" {
        if headers.get("x-fss-read") != Some(&"1") || headers.get("sec-fetch-site").is_some_and(|v| *v != "same-origin") { return Err(403); }
    }
    Ok(parts[1])
}

fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" => Some(("text/html; charset=utf-8", include_str!("web/index.html"))),
        "/style.css" => Some(("text/css; charset=utf-8", include_str!("web/style.css"))),
        "/app.js" => Some(("text/javascript; charset=utf-8", include_str!("web/app.js"))),
        "/model.js" => Some(("text/javascript; charset=utf-8", include_str!("web/model.js"))),
        "/favicon.svg" => Some(("image/svg+xml", "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='16' fill='#102720'/><path d='M14 32h8l6-14 8 28 6-14h8' fill='none' stroke='#b7e9c8' stroke-width='4'/></svg>")),
        _ => None,
    }
}

fn send(stream: &mut TcpStream, code: u16, mime: &str, body: &str, lease: &Lease) -> io::Result<()> {
    let reason = match code { 200 => "OK", 400 => "Bad Request", 403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed", _ => "Service Unavailable" };
    let header = format!("HTTP/1.1 {code} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nX-Frame-Options: DENY\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\n\r\n", body.len());
    let deadline = (Instant::now() + Duration::from_secs(2)).min(lease.deadline);
    for mut bytes in [header.as_bytes(), body.as_bytes()] {
        let mut interrupted = 0;
        while !bytes.is_empty() {
            lease.check()?;
            let remaining = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(io::ErrorKind::TimedOut)?;
            stream.set_write_timeout(Some(remaining))?;
            match stream.write(&bytes[..bytes.len().min(16 * 1024)]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => { bytes = &bytes[n..]; interrupted = 0; }
                Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted < 7 => interrupted += 1,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, host: &str, options: &Options, lease: &Lease) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    let deadline = (Instant::now() + Duration::from_secs(2)).min(lease.deadline);
    let mut buf = Vec::new();
    loop {
        lease.check()?;
        let remaining = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(remaining))?;
        let mut chunk = [0u8; 1024];
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 { return Ok(()); }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > HEADER_LIMIT { return send(stream, 400, "text/plain", "Request too large", lease); }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let path = std::str::from_utf8(&buf).map_err(|_| 400u16).and_then(|s| request(s, host));
    match path {
        Err(code) => send(stream, code, "text/plain", "Request refused", lease),
        Ok("/api/snapshot") => match snapshot::read(options, lease) {
            Ok(body) => send(stream, 200, "application/json; charset=utf-8", &body, lease),
            Err(_) => send(stream, 503, "application/json", "{\"error\":\"snapshot_unavailable\",\"message\":\"The selected deployment is unreadable, changed site, exceeded its bounds, or failed integrity checks. No replacement data was substituted.\"}", lease),
        },
        Ok(path) => match asset(path) {
            Some((mime, body)) => send(stream, 200, mime, body, lease),
            None => send(stream, 404, "text/plain", "Not found", lease),
        },
    }
}

pub(super) fn run(options: &Options, lease: &Lease) -> io::Result<()> {
    // Refuse wrong-site, missing or damaged roots before opening a browser-facing listener.
    let _ = snapshot::read(options, lease)?;
    lease.check()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))?;
    listener.set_nonblocking(true)?;
    let host = listener.local_addr()?.to_string();
    eprintln!("FSS Observatory: http://{host}\n{} · read-only · local metadata · lease {} seconds\nCtrl-C to stop. Do not reverse-proxy or forward this listener.", if options.demo { "SYNTHETIC DEMO" } else { "RETAINED DEPLOYMENT" }, options.seconds);
    while lease.check().is_ok() {
        match listener.accept() {
            Ok((mut stream, peer)) if peer.ip().is_loopback() => { let _ = handle(&mut stream, &host, options, lease); }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if lease.check().is_err() { break; }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check(extra: &str) -> Result<&str, u16> {
        let _ = extra;
        request("GET / HTTP/1.1\r\nHost: 127.0.0.1:7474\r\n\r\n", "127.0.0.1:7474")
    }
    #[test]
    fn exact_host_and_custom_read_header_are_required() {
        assert_eq!(check(""), Ok("/"));
        assert_eq!(request("GET /api/snapshot HTTP/1.1\r\nHost: 127.0.0.1:7474\r\nX-FSS-Read: 1\r\nSec-Fetch-Site: same-origin\r\n\r\n", "127.0.0.1:7474"), Ok("/api/snapshot"));
        for header in ["", "X-FSS-Read: 1\r\nOrigin: null\r\n", "X-FSS-Read: 1\r\nSec-Fetch-Site: cross-site\r\n", "X-FSS-Read: 1\r\nOrigin: http://evil.test\r\n"] {
            assert_eq!(request(&format!("GET /api/snapshot HTTP/1.1\r\nHost: 127.0.0.1:7474\r\n{header}\r\n"), "127.0.0.1:7474"), Err(403));
        }
    }
    #[test]
    fn rebinding_duplicate_headers_bodies_and_writes_refuse() {
        for head in ["GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n", "GET / HTTP/1.1\r\nHost: 127.0.0.1:7474\r\nHost: 127.0.0.1:7474\r\n\r\n", "POST / HTTP/1.1\r\nHost: 127.0.0.1:7474\r\n\r\n", "GET / HTTP/1.1\r\nHost: 127.0.0.1:7474\r\nTransfer-Encoding: chunked\r\n\r\n", "GET / HTTP/1.1\r\nHost: 127.0.0.1:7474\r\nContent-Length: 2\r\n\r\n"] {
            assert!(request(head, "127.0.0.1:7474").is_err());
        }
        for path in ["/../LAYOUT", "/%2e%2e/LAYOUT", "/api/snapshot?root=/other", "/demo.json", "/credentials", "//app.js"] { assert!(asset(path).is_none()); }
    }
}
