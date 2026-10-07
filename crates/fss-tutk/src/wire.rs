//! `0xCC51` wire formats: `0x1002` discovery, `0x1502` DTLS wrapper, `0x1202`
//! session keepalive, plus the AuthKey/PSK credential derivations.
//!
//! Layouts are live-proven against owner cameras and corrected against go2rtc
//! (see crate-level docs for the reference-doc errors this module avoids).

use crate::digest::{hmac_sha1, Sha256};

/// Protocol magic (little-endian on the wire).
pub const MAGIC_NEWPROTO: u16 = 0xCC51;
/// Discovery command.
pub const CMD_DISCOVERY: u16 = 0x1002;
/// DTLS wrapper command.
pub const CMD_DTLS: u16 = 0x1502;
/// Post-discovery session keepalive command (live capture 2026-10-07; not in
/// the public reference doc).
pub const CMD_KEEPALIVE: u16 = 0x1202;

/// Discovery payload-size field value (40).
pub const DISCOVERY_PAYLOAD_SIZE: u16 = 0x0028;
/// Discovery packet total size (32 header + 20 auth).
pub const DISCOVERY_PACKET_SIZE: usize = 52;
/// `0x1502` header size in bytes.
pub const DTLS_HEADER_SIZE: usize = 28;
/// HMAC-SHA1 auth trailer size.
pub const AUTH_SIZE: usize = 20;
/// `0x1502` fixed low byte of `[12:13]`; channel goes in the high byte.
pub const DTLS_SEQ: u16 = 0x0010;
/// Direction: client -> camera.
pub const DIR_REQUEST: u16 = 0x0000;
/// Direction: camera -> client.
pub const DIR_RESPONSE: u16 = 0xFFFF;
/// Main channel (DTLS client side).
pub const CHANNEL_MAIN: u16 = 0;
/// Back channel (DTLS server side; two-way audio, unused here).
pub const CHANNEL_BACK: u16 = 1;
/// Constant `u32` at `[24-27]` of the DTLS wrapper (go2rtc; the public doc
/// mislabels this as the channel).
pub const DTLS_CONST: u32 = 1;
/// Keepalive payload-size field value (36).
pub const KEEPALIVE_PAYLOAD_SIZE: u16 = 0x0024;
/// Keepalive packet total size.
pub const KEEPALIVE_PACKET_SIZE: usize = 48;
/// Capabilities bytes carried in discovery (reference doc §18.1).
pub const CAPABILITIES: [u8; 8] = [0x00, 0x08, 0x03, 0x04, 0x1D, 0x00, 0x00, 0x00];
/// Session-id constant suffix (reference doc §18.3).
pub const SESSION_ID_SUFFIX: [u8; 6] = [0x76, 0x0A, 0x9D, 0x24, 0x88, 0xBA];

/// Errors from wire construction or parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// A field carried an unexpected value.
    BadField(&'static str),
    /// Packet was shorter/longer than the format requires.
    BadLength {
        /// What the caller was decoding.
        what: &'static str,
        /// Actual byte count seen.
        got: usize,
    },
    /// HMAC-SHA1 auth trailer mismatch.
    AuthMismatch,
    /// Caller passed malformed input to a builder.
    InvalidInput(&'static str),
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadField(what) => write!(f, "bad field: {what}"),
            Self::BadLength { what, got } => write!(f, "bad length for {what}: {got} bytes"),
            Self::AuthMismatch => write!(f, "HMAC-SHA1 auth trailer mismatch"),
            Self::InvalidInput(what) => write!(f, "invalid input: {what}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// AuthKey = Base64(SHA256(ENR + uppercase(MAC))[0:6]) with substitutions
/// `+`→`Z`, `/`→`9`, `=`→`A` (reference doc §15.3; validated live).
#[must_use]
pub fn auth_key(enr: &str, mac: &str) -> [u8; 8] {
    let mut input = String::with_capacity(enr.len() + mac.len());
    input.push_str(enr);
    input.push_str(&mac.to_uppercase());
    let hash = Sha256::digest(input.as_bytes());
    // standard base64 of 6 bytes = 8 chars (2 groups of 3 bytes -> 2 x 4 chars)
    let mut b64 = [0u8; 8];
    encode_b64_triple(&hash[0..3], &mut b64[0..4]);
    encode_b64_triple(&hash[3..6], &mut b64[4..8]);
    for c in b64.iter_mut() {
        *c = match *c {
            b'+' => b'Z',
            b'/' => b'9',
            b'=' => b'A',
            other => other,
        };
    }
    b64
}

fn encode_b64_triple(input: &[u8], out: &mut [u8]) {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let n = ((input[0] as u32) << 16) | ((input[1] as u32) << 8) | input[2] as u32;
    out[0] = B64[(n >> 18) as usize & 0x3F];
    out[1] = B64[(n >> 12) as usize & 0x3F];
    out[2] = B64[(n >> 6) as usize & 0x3F];
    out[3] = B64[n as usize & 0x3F];
}

/// PSK = SHA256(ENR) with bytes after the first NUL zeroed (TUTK SDK treats
/// the binary PSK as a NUL-terminated C string; reference doc §5; live-proven).
#[must_use]
pub fn derive_psk(enr: &str) -> [u8; 32] {
    let h = Sha256::digest(enr.as_bytes());
    let nul = h.iter().position(|&b| b == 0).unwrap_or(32);
    let mut out = [0u8; 32];
    out[..nul].copy_from_slice(&h[..nul]);
    out
}

/// Alternative derivation: PSK truncated at the first NUL (length-prefixed
/// usage). Kept for parity with the Python reference; go2rtc behavior is the
/// zero-padded [`derive_psk`] form.
#[must_use]
pub fn derive_psk_truncated(enr: &str) -> Vec<u8> {
    let h = Sha256::digest(enr.as_bytes());
    match h.iter().position(|&b| b == 0) {
        Some(n) => h[..n].to_vec(),
        None => h.to_vec(),
    }
}

/// SessionID = random[2] + `76 0a 9d 24 88 ba` (reference doc §18.3).
#[must_use]
pub fn new_session_id(random2: [u8; 2]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = random2[0];
    out[1] = random2[1];
    out[2..].copy_from_slice(&SESSION_ID_SUFFIX);
    out
}

fn put_u16(out: &mut [u8], v: u16) {
    out[0] = (v & 0xFF) as u8;
    out[1] = (v >> 8) as u8;
}

fn get_u16(data: &[u8]) -> u16 {
    data[0] as u16 | ((data[1] as u16) << 8)
}

/// Parsed discovery packet fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPacket {
    /// Direction field (`0x0000` request / `0xFFFF` response).
    pub direction: u16,
    /// Handshake sequence number (0..3).
    pub seq: u16,
    /// Server-assigned ticket.
    pub ticket: u16,
    /// Session id echoed by the peer.
    pub session_id: [u8; 8],
    /// Whether the HMAC-SHA1 trailer verified.
    pub auth_ok: bool,
}

/// Packet builder/parser bound to one camera's credentials
/// (HMAC key = UID(20B) + AuthKey(8B)).

pub struct NewProto {
    key: [u8; 28],
}

impl NewProto {
    /// Construct from owner-supplied credentials. `uid` must be exactly
    /// 20 ASCII bytes. Returns `None` otherwise (never panics).
    #[must_use]
    pub fn new(uid: &str, enr: &str, mac: &str) -> Option<Self> {
        let uid_b = uid.as_bytes();
        if uid_b.len() != 20 {
            return None;
        }
        let mut key = [0u8; 28];
        key[..20].copy_from_slice(uid_b);
        key[20..].copy_from_slice(&auth_key(enr, mac));
        Some(Self { key })
    }

    /// HMAC-SHA1(key, data) — the 20-byte auth trailer.
    #[must_use]
    pub fn auth_bytes(&self, data: &[u8]) -> [u8; 20] {
        hmac_sha1(&self.key, data)
    }

    /// Verify the trailing 20 bytes of `packet` against the rest.
    #[must_use]
    pub fn verify_auth(&self, packet: &[u8]) -> bool {
        if packet.len() < AUTH_SIZE {
            return false;
        }
        let (body, auth) = packet.split_at(packet.len() - AUTH_SIZE);
        hmac_sha1(&self.key, body) == *auth
    }

    /// Build a 52-byte `0x1002` discovery packet (direction: request).
    pub fn build_discovery(
        &self,
        seq: u16,
        ticket: u16,
        session_id: &[u8; 8],
    ) -> Result<[u8; DISCOVERY_PACKET_SIZE], ProtoError> {
        let mut out = [0u8; DISCOVERY_PACKET_SIZE];
        put_u16(&mut out[0..2], MAGIC_NEWPROTO);
        put_u16(&mut out[2..4], 0);
        put_u16(&mut out[4..6], CMD_DISCOVERY);
        put_u16(&mut out[6..8], DISCOVERY_PAYLOAD_SIZE);
        put_u16(&mut out[8..10], DIR_REQUEST);
        put_u16(&mut out[10..12], 0);
        put_u16(&mut out[12..14], seq);
        put_u16(&mut out[14..16], ticket);
        out[16..24].copy_from_slice(session_id);
        out[24..32].copy_from_slice(&CAPABILITIES);
        let auth = self.auth_bytes(&out[..32]);
        out[32..].copy_from_slice(&auth);
        Ok(out)
    }

    /// Build a discovery RESPONSE (camera side; used by simulators).
    #[must_use]
    pub fn build_discovery_response(
        &self,
        seq: u16,
        ticket: u16,
        session_id: &[u8; 8],
    ) -> [u8; DISCOVERY_PACKET_SIZE] {
        let mut out = [0u8; DISCOVERY_PACKET_SIZE];
        put_u16(&mut out[0..2], MAGIC_NEWPROTO);
        put_u16(&mut out[2..4], 0);
        put_u16(&mut out[4..6], CMD_DISCOVERY);
        put_u16(&mut out[6..8], DISCOVERY_PAYLOAD_SIZE);
        put_u16(&mut out[8..10], DIR_RESPONSE);
        put_u16(&mut out[10..12], 0);
        put_u16(&mut out[12..14], seq);
        put_u16(&mut out[14..16], ticket);
        out[16..24].copy_from_slice(session_id);
        out[24..32].copy_from_slice(&CAPABILITIES);
        let auth = self.auth_bytes(&out[..32]);
        out[32..].copy_from_slice(&auth);
        out
    }


    /// Parse a `0x1002` discovery packet.
    pub fn parse_discovery(&self, data: &[u8]) -> Result<DiscoveryPacket, ProtoError> {
        if data.len() != DISCOVERY_PACKET_SIZE {
            return Err(ProtoError::BadLength { what: "discovery", got: data.len() });
        }
        if get_u16(&data[0..2]) != MAGIC_NEWPROTO {
            return Err(ProtoError::BadField("magic"));
        }
        if get_u16(&data[4..6]) != CMD_DISCOVERY {
            return Err(ProtoError::BadField("command"));
        }
        if get_u16(&data[6..8]) != DISCOVERY_PAYLOAD_SIZE {
            return Err(ProtoError::BadField("payload size"));
        }
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&data[16..24]);
        Ok(DiscoveryPacket {
            direction: get_u16(&data[8..10]),
            seq: get_u16(&data[12..14]),
            ticket: get_u16(&data[14..16]),
            session_id,
            auth_ok: self.verify_auth(data),
        })
    }

    /// Wrap one DTLS record in a `0x1502` frame. Returns header+payload+auth.
    #[must_use]
    pub fn wrap_dtls(
        &self,
        dtls_payload: &[u8],
        ticket: u16,
        session_id: &[u8; 8],
        channel: u16,
    ) -> Vec<u8> {
        let mut hdr = [0u8; DTLS_HEADER_SIZE];
        put_u16(&mut hdr[0..2], MAGIC_NEWPROTO);
        put_u16(&mut hdr[2..4], 0);
        put_u16(&mut hdr[4..6], CMD_DTLS);
        put_u16(&mut hdr[6..8], (16 + dtls_payload.len() + AUTH_SIZE) as u16);
        put_u16(&mut hdr[8..10], DIR_REQUEST);
        put_u16(&mut hdr[10..12], 0);
        put_u16(&mut hdr[12..14], DTLS_SEQ | (channel << 8));
        put_u16(&mut hdr[14..16], ticket);
        hdr[16..24].copy_from_slice(session_id);
        hdr[24..28].copy_from_slice(&DTLS_CONST.to_le_bytes());
        let auth = self.auth_bytes(&hdr);
        let mut out = Vec::with_capacity(DTLS_HEADER_SIZE + dtls_payload.len() + AUTH_SIZE);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(dtls_payload);
        out.extend_from_slice(&auth);
        out
    }

    /// Extract (payload, auth_ok, channel) from a `0x1502` frame.
    /// `strict=true` turns an HMAC mismatch into an error.
    pub fn unwrap_dtls<'a>(&self, data: &'a [u8], strict: bool) -> Result<(&'a [u8], bool, u16), ProtoError> {
        if data.len() < DTLS_HEADER_SIZE + AUTH_SIZE {
            return Err(ProtoError::BadLength { what: "dtls frame", got: data.len() });
        }
        if get_u16(&data[0..2]) != MAGIC_NEWPROTO {
            return Err(ProtoError::BadField("magic"));
        }
        if get_u16(&data[4..6]) != CMD_DTLS {
            return Err(ProtoError::BadField("command"));
        }
        let psize = get_u16(&data[6..8]) as usize;
        if psize != data.len() - 12 {
            return Err(ProtoError::BadField("payload size"));
        }
        let channel = get_u16(&data[12..14]) >> 8;
        let auth_ok = hmac_sha1(&self.key, &data[..DTLS_HEADER_SIZE]) == data[data.len() - AUTH_SIZE..];
        if strict && !auth_ok {
            return Err(ProtoError::AuthMismatch);
        }
        Ok((&data[DTLS_HEADER_SIZE..data.len() - AUTH_SIZE], auth_ok, channel))
    }

    /// Parse a `0x1202` keepalive. Returns (counter, session_id, auth_ok).
    pub fn parse_keepalive(&self, data: &[u8]) -> Result<(u32, [u8; 8], bool), ProtoError> {
        if data.len() != KEEPALIVE_PACKET_SIZE {
            return Err(ProtoError::BadLength { what: "keepalive", got: data.len() });
        }
        if get_u16(&data[0..2]) != MAGIC_NEWPROTO {
            return Err(ProtoError::BadField("magic"));
        }
        if get_u16(&data[4..6]) != CMD_KEEPALIVE {
            return Err(ProtoError::BadField("command"));
        }
        if get_u16(&data[6..8]) != KEEPALIVE_PAYLOAD_SIZE {
            return Err(ProtoError::BadField("payload size"));
        }
        let counter = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&data[20..28]);
        Ok((counter, session_id, self.verify_auth(data)))
    }

    /// Build a keepalive echo (client -> camera, direction request).
    #[must_use]
    pub fn build_keepalive_echo(&self, counter: u32, session_id: &[u8; 8]) -> [u8; KEEPALIVE_PACKET_SIZE] {
        let mut out = [0u8; KEEPALIVE_PACKET_SIZE];
        put_u16(&mut out[0..2], MAGIC_NEWPROTO);
        put_u16(&mut out[2..4], 0);
        put_u16(&mut out[4..6], CMD_KEEPALIVE);
        put_u16(&mut out[6..8], KEEPALIVE_PAYLOAD_SIZE);
        put_u16(&mut out[8..10], DIR_REQUEST);
        put_u16(&mut out[10..12], 0);
        put_u16(&mut out[12..14], 0);
        put_u16(&mut out[14..16], 0);
        out[16..20].copy_from_slice(&counter.to_le_bytes());
        out[20..28].copy_from_slice(session_id);
        let auth = self.auth_bytes(&out[..28]);
        out[28..].copy_from_slice(&auth);
        out
    }

    /// Command field of any `0xCC51` packet, or `None` if too short.
    #[must_use]
    pub fn peek_command(data: &[u8]) -> Option<u16> {
        if data.len() < 6 {
            return None;
        }
        Some(get_u16(&data[4..6]))
    }
}
