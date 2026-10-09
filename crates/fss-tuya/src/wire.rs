//! Tuya LAN wire framing: the 55AA family (3.1–3.4) and the 6699 family
//! (3.5). Encoding and decoding are total over untrusted bytes: malformed
//! input is a typed error, never a panic and never a silent fix-up. Framing
//! facts are mirrored against the tinytuya laboratory oracle (see the crate
//! docs) and the decoder agrees byte-for-byte with the decoder qualified in
//! `fss-reference`'s live beacon listener.

use crate::crypto;

/// Frame prefix 0x000055AA (protocol 3.1–3.4).
pub const PREFIX_55AA: u32 = 0x0000_55AA;
/// Frame prefix 0x00006699 (protocol 3.5).
pub const PREFIX_6699: u32 = 0x0000_6699;
/// Frame suffix 0x0000AA55.
pub const SUFFIX_55AA: [u8; 4] = [0x00, 0x00, 0xAA, 0x55];
/// Frame suffix 0x00009966.
pub const SUFFIX_6699: [u8; 4] = [0x00, 0x00, 0x99, 0x66];
/// Sanity bound on a declared frame payload length.
pub const MAX_PAYLOAD_LENGTH: usize = 1 << 20;

/// The well-known udpkey: `md5("yGAdlopoPVldABfn")` — a public protocol
/// constant (broadcast announcements are decryptable without owner secrets),
/// precomputed so no MD5 implementation is needed here.
pub const UDP_BROADCAST_KEY: [u8; 16] = [
    0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a, 0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41, 0x0a,
];

/// LAN command words (tinytuya `command_types.py` numbering).
pub mod cmd {
    /// 3.4/3.5 session-key negotiation: client nonce.
    pub const SESS_KEY_NEG_START: u32 = 0x03;
    /// Session-key negotiation: device nonce + proof.
    pub const SESS_KEY_NEG_RESP: u32 = 0x04;
    /// Session-key negotiation: client proof (final).
    pub const SESS_KEY_NEG_FINISH: u32 = 0x05;
    /// Control (write dps).
    pub const CONTROL: u32 = 0x07;
    /// Status report / response.
    pub const STATUS: u32 = 0x08;
    /// Heartbeat.
    pub const HEART_BEAT: u32 = 0x09;
    /// Query data points.
    pub const DP_QUERY: u32 = 0x0A;
    /// Control (new numbering).
    pub const CONTROL_NEW: u32 = 0x0D;
    /// Query data points (new numbering).
    pub const DP_QUERY_NEW: u32 = 0x10;
    /// Request dps refresh.
    pub const UPDATEDPS: u32 = 0x12;
    /// UDP broadcast announcement (well-known udpkey payload).
    pub const UDP_NEW: u32 = 0x13;
    /// LPv3.4+ broadcast (device local_key payload).
    pub const BOARDCAST_LPV34: u32 = 0x23;
    /// LAN extended stream channel (video-class payloads).
    pub const LAN_EXT_STREAM: u32 = 0x40;
}

/// IEEE CRC32 (the 55AA trailer check), table-free (bitwise, reflected).
#[must_use]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Typed wire errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Not enough bytes for the fixed header.
    ShortHeader,
    /// Prefix is neither 0x000055AA nor 0x00006699.
    BadPrefix(u32),
    /// Declared length exceeds the sanity bound.
    LengthOverBound(usize),
    /// Captured bytes shorter than the declared total.
    Truncated {
        /// Bytes the frame declared.
        need: usize,
        /// Bytes actually present.
        have: usize,
    },
    /// Frame body too short for its declared structure.
    ShortBody,
    /// CRC32/HMAC or suffix check failed.
    Integrity,
    /// GCM tag mismatch (wrong key, tampered, or expired session).
    GcmAuth,
    /// 6699 frame presented without the required key.
    KeyRequired,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::ShortHeader => write!(f, "short frame header"),
            WireError::BadPrefix(p) => write!(f, "bad frame prefix 0x{p:08X}"),
            WireError::LengthOverBound(n) => write!(f, "declared length {n} over bound"),
            WireError::Truncated { need, have } => {
                write!(f, "short frame: need {need} have {have}")
            }
            WireError::ShortBody => write!(f, "frame body too short"),
            WireError::Integrity => write!(f, "crc/hmac or suffix mismatch"),
            WireError::GcmAuth => write!(f, "gcm tag mismatch"),
            WireError::KeyRequired => write!(f, "6699 frame requires a key"),
        }
    }
}

impl std::error::Error for WireError {}

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame family prefix.
    pub prefix: u32,
    /// Sequence number.
    pub seqno: u32,
    /// Command word.
    pub cmd: u32,
    /// Declared length field value.
    pub length: usize,
    /// Header size in bytes (16 or 20).
    pub header_len: usize,
    /// Total on-wire frame size in bytes.
    pub total: usize,
}

/// Parses the 16-byte (55AA) or 20-byte (6699) header.
pub fn parse_header(data: &[u8]) -> Result<FrameHeader, WireError> {
    if data.len() < 16 {
        return Err(WireError::ShortHeader);
    }
    let prefix = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match prefix {
        PREFIX_55AA => {
            let seqno = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let cmd = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let length = u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as usize;
            if length > MAX_PAYLOAD_LENGTH {
                return Err(WireError::LengthOverBound(length));
            }
            let total = 16 + length;
            if data.len() < total {
                return Err(WireError::Truncated {
                    need: total,
                    have: data.len(),
                });
            }
            Ok(FrameHeader {
                prefix,
                seqno,
                cmd,
                length,
                header_len: 16,
                total,
            })
        }
        PREFIX_6699 => {
            if data.len() < 20 {
                return Err(WireError::ShortHeader);
            }
            let seqno = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let cmd = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            let length = u32::from_be_bytes([data[16], data[17], data[18], data[19]]) as usize;
            if length > MAX_PAYLOAD_LENGTH {
                return Err(WireError::LengthOverBound(length));
            }
            let total = 20 + length + 4;
            if data.len() < total {
                return Err(WireError::Truncated {
                    need: total,
                    have: data.len(),
                });
            }
            Ok(FrameHeader {
                prefix,
                seqno,
                cmd,
                length,
                header_len: 20,
                total,
            })
        }
        p => Err(WireError::BadPrefix(p)),
    }
}

/// One unpacked frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Sequence number.
    pub seqno: u32,
    /// Command word.
    pub cmd: u32,
    /// Return code where the frame family carries one (55AA with retcode,
    /// 6699 with embedded retcode).
    pub retcode: Option<u32>,
    /// Decrypted (or plaintext) payload bytes.
    pub payload: Vec<u8>,
    /// Frame family prefix.
    pub prefix: u32,
    /// The 12-byte GCM nonce for 6699 frames (needed to reply).
    pub iv: Option<[u8; 12]>,
}

/// Packs a 55AA frame. With `hmac_key` (protocol 3.4) the trailer is
/// HMAC-SHA256 over `header | retcode? | payload`; otherwise CRC32.
#[must_use]
pub fn pack_55aa(
    seqno: u32,
    cmd: u32,
    retcode: Option<u32>,
    payload: &[u8],
    hmac_key: Option<&[u8; 16]>,
) -> Vec<u8> {
    let tail_len = if hmac_key.is_some() { 36 } else { 8 };
    let body_len = retcode.map_or(0, |_| 4) + payload.len() + tail_len;
    let mut out = Vec::with_capacity(16 + body_len);
    out.extend_from_slice(&PREFIX_55AA.to_be_bytes());
    out.extend_from_slice(&seqno.to_be_bytes());
    out.extend_from_slice(&cmd.to_be_bytes());
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    if let Some(rc) = retcode {
        out.extend_from_slice(&rc.to_be_bytes());
    }
    out.extend_from_slice(payload);
    match hmac_key {
        Some(key) => {
            let mac = crypto::hmac_sha256(key, &out);
            out.extend_from_slice(&mac);
        }
        None => {
            let crc = crc32_ieee(&out);
            out.extend_from_slice(&crc.to_be_bytes());
        }
    }
    out.extend_from_slice(&SUFFIX_55AA);
    out
}

/// Unpacks a 55AA frame, verifying CRC32/HMAC and the suffix.
/// `no_retcode` matches the oracle convention for retcode-less commands.
pub fn unpack_55aa(
    data: &[u8],
    hmac_key: Option<&[u8; 16]>,
    no_retcode: bool,
) -> Result<Message, WireError> {
    let h = parse_header(data)?;
    if h.prefix != PREFIX_55AA {
        return Err(WireError::BadPrefix(h.prefix));
    }
    let tail_len = if hmac_key.is_some() { 36 } else { 8 };
    let ret_len = if no_retcode { 0 } else { 4 };
    if h.total < 16 + ret_len + tail_len {
        return Err(WireError::ShortBody);
    }
    let body = &data[16..h.total - tail_len];
    let trailer = &data[h.total - tail_len..h.total];
    let suffix_ok = trailer[tail_len - 4..] == SUFFIX_55AA;
    let integrity_ok = match hmac_key {
        Some(key) => {
            let mac = crypto::hmac_sha256(key, &data[..h.total - tail_len]);
            trailer[..32] == mac
        }
        None => {
            let crc = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
            crc == crc32_ieee(&data[..h.total - tail_len])
        }
    };
    if !(suffix_ok && integrity_ok) {
        return Err(WireError::Integrity);
    }
    let (retcode, payload) = if ret_len == 4 {
        let rc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        (Some(rc), body[4..].to_vec())
    } else {
        (None, body.to_vec())
    };
    Ok(Message {
        seqno: h.seqno,
        cmd: h.cmd,
        retcode,
        payload,
        prefix: h.prefix,
        iv: None,
    })
}

/// Packs a 6699 frame (3.5): GCM-seals `[retcode?] | plaintext` under `key`
/// with AAD = header bytes `[4..20]`; the wire body is
/// `iv(12) | ciphertext | tag(16)`. When `iv` is `None` a deterministic
/// zero nonce is used — callers driving real devices MUST supply a unique
/// nonce per message (the simulator uses deterministic fixture nonces).
#[must_use]
pub fn pack_6699(
    seqno: u32,
    cmd: u32,
    retcode: Option<u32>,
    plaintext: &[u8],
    key: &[u8; 16],
    iv: [u8; 12],
) -> Vec<u8> {
    let raw_len = retcode.map_or(0, |_| 4) + plaintext.len();
    let mut raw = Vec::with_capacity(raw_len);
    if let Some(rc) = retcode {
        raw.extend_from_slice(&rc.to_be_bytes());
    }
    raw.extend_from_slice(plaintext);
    // length covers iv + ciphertext + tag (not the suffix).
    let length = 12 + raw.len() + 16;
    let mut out = Vec::with_capacity(20 + length + 4);
    out.extend_from_slice(&PREFIX_6699.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&seqno.to_be_bytes());
    out.extend_from_slice(&cmd.to_be_bytes());
    out.extend_from_slice(&(length as u32).to_be_bytes());
    let aad_start = out.len() - 16;
    let sealed = crypto::aes128_gcm_encrypt(key, &iv, &out[aad_start..], &raw);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&sealed);
    out.extend_from_slice(&SUFFIX_6699);
    out
}

/// Whether a 6699 payload carries a leading return code. Device→client
/// responses embed one; client→device negotiation frames do not. `Auto`
/// mirrors the laboratory oracle's content heuristic (retcode present iff
/// the plaintext is not JSON but `plaintext[4..]` is); callers that know
/// the direction semantics should prefer the explicit modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetcodeMode {
    /// Oracle heuristic: retcode iff `[0] != '{' && [4] == '{'`.
    Auto,
    /// Leading 4-byte retcode is present.
    Present,
    /// No retcode; the whole plaintext is payload.
    Absent,
}

/// Unpacks a 6699 frame: verifies the suffix, GCM tag (AAD = header
/// bytes `[4..20]`), and returns the decrypted payload.
pub fn unpack_6699(data: &[u8], key: &[u8; 16]) -> Result<Message, WireError> {
    unpack_6699_mode(data, key, RetcodeMode::Auto)
}

/// [`unpack_6699`] with explicit retcode handling.
pub fn unpack_6699_mode(
    data: &[u8],
    key: &[u8; 16],
    mode: RetcodeMode,
) -> Result<Message, WireError> {
    let h = parse_header(data)?;
    if h.prefix != PREFIX_6699 {
        return Err(WireError::BadPrefix(h.prefix));
    }
    if data[h.total - 4..h.total] != SUFFIX_6699 {
        return Err(WireError::Integrity);
    }
    let body = &data[20..h.total - 4];
    if body.len() < 12 + 16 {
        return Err(WireError::ShortBody);
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&body[..12]);
    let raw = crypto::aes128_gcm_decrypt(key, &iv, &data[4..20], &body[12..])
        .ok_or(WireError::GcmAuth)?;
    let mode = match mode {
        RetcodeMode::Auto => {
            if raw.len() >= 5 && raw.first() != Some(&b'{') && raw.get(4) == Some(&b'{') {
                RetcodeMode::Present
            } else {
                RetcodeMode::Absent
            }
        }
        m => m,
    };
    let (retcode, payload) = match mode {
        RetcodeMode::Present if raw.len() >= 4 => {
            let rc = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            (Some(rc), raw[4..].to_vec())
        }
        _ => (None, raw),
    };
    Ok(Message {
        seqno: h.seqno,
        cmd: h.cmd,
        retcode,
        payload,
        prefix: h.prefix,
        iv: Some(iv),
    })
}

/// 3.4 session-key derivation: AES-128-ECB(local_key) over the nonce XOR.
/// Returns `None` if the nonces differ in length (never for the protocol).
#[must_use]
pub fn derive_session_key_34(
    local_key: &[u8; 16],
    local_nonce: &[u8; 16],
    remote_nonce: &[u8; 16],
) -> Option<[u8; 16]> {
    let mut x = [0u8; 16];
    for i in 0..16 {
        x[i] = local_nonce[i] ^ remote_nonce[i];
    }
    let sealed = crypto::aes128_ecb_encrypt_raw(local_key, &x)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&sealed[..16]);
    Some(out)
}

/// 3.5 session-key derivation: AES-128-GCM(local_key, iv=client_nonce[..12])
/// over the nonce XOR, taking the first ciphertext block.
#[must_use]
pub fn derive_session_key_35(
    local_key: &[u8; 16],
    client_nonce: &[u8; 16],
    device_nonce: &[u8; 16],
) -> [u8; 16] {
    let mut x = [0u8; 16];
    for i in 0..16 {
        x[i] = client_nonce[i] ^ device_nonce[i];
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&client_nonce[..12]);
    let sealed = crypto::aes128_gcm_encrypt(local_key, &iv, &[], &x);
    let mut out = [0u8; 16];
    out.copy_from_slice(&sealed[..16]);
    out
}
