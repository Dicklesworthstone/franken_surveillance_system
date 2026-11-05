#![forbid(unsafe_code)]
//! UniFi camera WebSocket upgrade preparation over an already-owned stream.
//!
//! This performs no I/O and authenticates no camera. The caller owns HTTP
//! header collection, peer admission, TLS, response writing and cancellation.
//! A claimed MAC is untrusted. Upstream's unconditional subprotocol response
//! is available only as an explicitly chosen compatibility policy.

use asupersync::{
    io::{AsyncRead, AsyncWrite},
    net::websocket::{
        AcceptResponse, HttpRequest, ServerHandshake, ServerWebSocket, WebSocketAcceptor,
    },
};
use std::fmt;

use super::{Dispatch, MAX_MESSAGE_BYTES};

/// Maximum HTTP header bytes, including the final CRLF pair.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Maximum bytes already read after the HTTP header.
pub const MAX_READ_AHEAD: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 64;
const PROTOCOL: &str = "secure_transfer";

/// How to handle the camera's subprotocol offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolPolicy {
    /// Require the client to offer `secure_transfer`, as WebSocket requires.
    RequireOffer,
    /// Match the reference emulator, which sends it even without an offer.
    /// This is nonstandard and requires explicit owner selection.
    ReferenceCompatibility,
}

/// Payload-free preparation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Incomplete, malformed, oversized, or ambiguous HTTP upgrade.
    InvalidRequest,
    /// The required UniFi subprotocol was not offered under strict policy.
    MissingSubprotocol,
    /// Memory could not be reserved for the bounded read-ahead bytes.
    Allocation,
    /// The response was not known to have been fully accepted locally.
    ResponseNotWritten,
    /// The response may have been partially written; retire this stream.
    ResponseIndeterminate,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi WebSocket upgrade refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Prepared response and bounded read-ahead, with no I/O performed.
pub struct PreparedUpgrade {
    claim: [u8; 6],
    response: AcceptResponse,
    response_bytes: Vec<u8>,
    read_ahead: Vec<u8>,
    offered: bool,
}
impl fmt::Debug for PreparedUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedUpgrade")
            .field("read_ahead_len", &self.read_ahead.len())
            .field("protocol_offered", &self.offered)
            .finish_non_exhaustive()
    }
}

impl PreparedUpgrade {
    /// Validate a complete bounded request and preserve any pipelined frames.
    pub fn parse(bytes: &[u8], policy: ProtocolPolicy) -> Result<Self, Error> {
        if bytes.len() > MAX_HEADER_BYTES + MAX_READ_AHEAD {
            return Err(Error::InvalidRequest);
        }
        let header_end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .and_then(|p| p.checked_add(4))
            .ok_or(Error::InvalidRequest)?;
        if header_end > MAX_HEADER_BYTES || bytes.len() - header_end > MAX_READ_AHEAD {
            return Err(Error::InvalidRequest);
        }
        let header =
            std::str::from_utf8(&bytes[..header_end]).map_err(|_| Error::InvalidRequest)?;
        // The upstream HTTP parser accepts incomplete request lines and ignores
        // malformed header lines; fence those cases before delegating to it.
        let mut lines = header.split("\r\n");
        let first = lines.next().ok_or(Error::InvalidRequest)?;
        let parts: Vec<_> = first.split(' ').collect();
        if parts.len() != 3
            || parts[0] != "GET"
            || !parts[1].starts_with('/')
            || parts[1].bytes().any(|b| b <= 0x20 || b == 0x7f)
            || parts[2] != "HTTP/1.1"
        {
            return Err(Error::InvalidRequest);
        }
        let mut count = 0;
        for line in lines {
            if line.is_empty() {
                break;
            }
            count += 1;
            if count > MAX_HEADER_LINES
                || !line.contains(':')
                || line.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
            {
                return Err(Error::InvalidRequest);
            }
        }
        let (request, trailing) =
            HttpRequest::parse_with_trailing(bytes).map_err(|_| Error::InvalidRequest)?;
        if trailing.len() != bytes.len() - header_end
            || request.header("host").is_none_or(str::is_empty)
            || request.header("transfer-encoding").is_some()
            || request.header("content-length").is_some_and(|n| n != "0")
        {
            return Err(Error::InvalidRequest);
        }
        let mac = request.header("camera-mac").ok_or(Error::InvalidRequest)?;
        if mac.len() != 12 || !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidRequest);
        }
        let mut claim = [0_u8; 6];
        for (i, byte) in claim.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&mac[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::InvalidRequest)?;
        }
        let handshake = ServerHandshake::new().protocol(PROTOCOL);
        let mut response = handshake
            .accept(&request)
            .map_err(|_| Error::InvalidRequest)?;
        let offered = response.protocol.as_deref() == Some(PROTOCOL);
        if !offered && policy == ProtocolPolicy::RequireOffer {
            return Err(Error::MissingSubprotocol);
        }
        if !offered {
            response.protocol = Some(PROTOCOL.to_owned());
        }
        let mut read_ahead = Vec::new();
        read_ahead
            .try_reserve_exact(trailing.len())
            .map_err(|_| Error::Allocation)?;
        read_ahead.extend_from_slice(trailing);
        let response_bytes = response.response_bytes();
        Ok(Self {
            claim,
            response,
            response_bytes,
            read_ahead,
            offered,
        })
    }

    /// Untrusted claimed device MAC, not authenticated identity.
    pub fn claimed_mac(&self) -> [u8; 6] {
        self.claim
    }
    /// Whether the client offered the selected subprotocol.
    pub fn protocol_offered(&self) -> bool {
        self.offered
    }
    /// Exact HTTP response for the owner to write under its network authority.
    pub fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }

    /// Consume the preparation after the owner reports its actual write outcome.
    /// `Written` is only local write evidence, not peer receipt or identity.
    /// Other outcomes drop the supplied stream and never permit an upgrade.
    pub fn finish<IO: AsyncRead + AsyncWrite + Unpin>(
        self,
        io: IO,
        outcome: Dispatch,
    ) -> Result<ServerWebSocket<IO>, Error> {
        match outcome {
            Dispatch::Written => Ok(WebSocketAcceptor::new()
                .protocol(PROTOCOL)
                .max_frame_size(MAX_MESSAGE_BYTES)
                .max_message_size(MAX_MESSAGE_BYTES)
                .max_pending_write_bytes(MAX_MESSAGE_BYTES + 14)
                .finish_upgrade(io, self.response, &self.read_ahead)),
            Dispatch::NotWritten => Err(Error::ResponseNotWritten),
            Dispatch::Indeterminate => Err(Error::ResponseIndeterminate),
        }
    }
}
