#![forbid(unsafe_code)]
//! Conservative URI syntax validation only. No DNS resolution, connections, or URL conversion.

use core::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;
use std::ops::Range;

use super::{MAX_STREAM_URI_BYTES, ProtectError};

/// Transport required by a URI; accepting syntax does not implement that transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamScheme {
    /// RTSP over an explicitly authorized plaintext transport.
    Rtsp,
    /// RTSPS requires a separately admitted secure transport and certificate policy.
    Rtsps,
}

/// Validated private RTSP/RTSPS endpoint with exact source spelling and no credential userinfo.
///
/// Paths and queries can be bearer capabilities. Neither `Debug` nor any error exposes them.
/// The explicit accessors are for a caller-authorized network boundary, never diagnostics.
/// This type performs no name lookup and grants no authority for the represented destination.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamEndpoint {
    uri: String,
    scheme: StreamScheme,
    authority: Range<usize>,
    host: Range<usize>,
    port: Option<u16>,
}

impl fmt::Debug for StreamEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamEndpoint")
            .field("scheme", &self.scheme)
            .field("request_uri", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl StreamEndpoint {
    /// Validate a bounded absolute URI without normalizing any authority, path, or query bytes.
    /// Credentials, fragments, whitespace, control characters and ambiguous hosts are rejected.
    pub fn parse(uri: &str) -> Result<Self, ProtectError> {
        if uri.len() > MAX_STREAM_URI_BYTES {
            return Err(ProtectError::UriLimit);
        }
        if !uri.is_ascii()
            || uri
                .bytes()
                .any(|byte| byte <= b' ' || byte == 0x7f || matches!(byte, b'\\' | b'#'))
        {
            return Err(ProtectError::InvalidEndpoint);
        }
        let (scheme_text, remainder) =
            uri.split_once("://").ok_or(ProtectError::InvalidEndpoint)?;
        let scheme = if scheme_text.eq_ignore_ascii_case("rtsp") {
            StreamScheme::Rtsp
        } else if scheme_text.eq_ignore_ascii_case("rtsps") {
            StreamScheme::Rtsps
        } else {
            return Err(ProtectError::InvalidEndpoint);
        };
        let authority_start = scheme_text.len() + 3;
        let authority_length = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority_end = authority_start + authority_length;
        let authority = &uri[authority_start..authority_end];
        if authority.contains('@') {
            return Err(ProtectError::UserInfoForbidden);
        }
        let (host_start, host_length, port) = parse_authority(authority)?;
        validate_resource(&uri[authority_end..])?;
        let host_start = authority_start + host_start;
        Ok(Self {
            uri: uri.to_owned(),
            scheme,
            authority: authority_start..authority_end,
            host: host_start..host_start + host_length,
            port,
        })
    }

    /// Required transport, independently of support in a particular runtime.
    #[must_use]
    pub const fn scheme(&self) -> StreamScheme {
        self.scheme
    }

    /// Exact private URI. Do not log, persist in reports, or pass across an unauthorized boundary.
    #[must_use]
    pub fn request_uri(&self) -> &str {
        &self.uri
    }

    /// Exact authority spelling, including IPv6 brackets and explicit port where supplied.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.uri[self.authority.clone()]
    }

    /// Exact host spelling; IPv6 brackets are excluded. This accessor performs no resolution.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.uri[self.host.clone()]
    }

    /// Explicit port only. No UniFi port or scheme default is inferred.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Exact resource spelling, including query, without adding a slash or decoding escapes.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.uri[self.authority.end..]
    }

    /// Whether a secure transport implementation is required; this module does not provide TLS.
    #[must_use]
    pub const fn requires_secure_transport(&self) -> bool {
        matches!(self.scheme, StreamScheme::Rtsps)
    }

    /// Supply the exact URI to a plaintext-only caller, or explicitly refuse secure transport.
    pub fn require_plaintext_rtsp(&self) -> Result<&str, ProtectError> {
        if self.requires_secure_transport() {
            Err(ProtectError::SecureTransportRequired)
        } else {
            Ok(self.request_uri())
        }
    }
}

fn parse_authority(authority: &str) -> Result<(usize, usize, Option<u16>), ProtectError> {
    if authority.is_empty() {
        return Err(ProtectError::InvalidEndpoint);
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']').ok_or(ProtectError::InvalidEndpoint)?;
        let host = &bracketed[..end];
        // Zone identifiers and IPvFuture need their own authority policy and are not admitted.
        host.parse::<Ipv6Addr>()
            .map_err(|_| ProtectError::InvalidEndpoint)?;
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(parse_port(
                suffix
                    .strip_prefix(':')
                    .ok_or(ProtectError::InvalidEndpoint)?,
            )?)
        };
        return Ok((1, host.len(), port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (authority, None),
    };
    validate_host(host)?;
    Ok((0, host.len(), port))
}

fn parse_port(port: &str) -> Result<u16, ProtectError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProtectError::InvalidEndpoint);
    }
    match port.parse::<u16>() {
        Ok(value) if value != 0 => Ok(value),
        _ => Err(ProtectError::InvalidEndpoint),
    }
}

fn validate_host(host: &str) -> Result<(), ProtectError> {
    if host.is_empty() {
        return Err(ProtectError::InvalidEndpoint);
    }
    if host.split('.').all(|label| {
        label.bytes().all(|byte| byte.is_ascii_digit())
            || label
                .strip_prefix("0x")
                .or_else(|| label.strip_prefix("0X"))
                .is_some_and(|hex| {
                    !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
    }) {
        // Refuse short, integer, octal or malformed IPv4 interpretations used by some resolvers.
        return host
            .parse::<Ipv4Addr>()
            .map(|_| ())
            .map_err(|_| ProtectError::InvalidEndpoint);
    }
    let dns = host.strip_suffix('.').unwrap_or(host);
    if dns.is_empty() || dns.len() > 253 {
        return Err(ProtectError::InvalidEndpoint);
    }
    for label in dns.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProtectError::InvalidEndpoint);
        }
    }
    Ok(())
}

fn validate_resource(resource: &str) -> Result<(), ProtectError> {
    let bytes = resource.as_bytes();
    let mut offset = 0;
    while let Some(&byte) = bytes.get(offset) {
        if byte == b'%' {
            let escape = bytes
                .get(offset + 1..offset + 3)
                .ok_or(ProtectError::InvalidEndpoint)?;
            let high = hex(escape[0]).ok_or(ProtectError::InvalidEndpoint)?;
            let low = hex(escape[1]).ok_or(ProtectError::InvalidEndpoint)?;
            let decoded = (high << 4) | low;
            if decoded < b' ' || decoded == 0x7f {
                return Err(ProtectError::InvalidEndpoint);
            }
            offset += 3;
            continue;
        }
        if !byte.is_ascii_alphanumeric()
            && !matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
                    | b'?'
            )
        {
            return Err(ProtectError::InvalidEndpoint);
        }
        offset += 1;
    }
    Ok(())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
