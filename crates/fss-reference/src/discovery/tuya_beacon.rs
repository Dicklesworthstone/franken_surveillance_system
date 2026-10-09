//! Tuya LAN discovery beacon listener + decoder (DISC-4, fss-yodhk.4).
//!
//! Listens on UDP :6667 for the protocol-standard device announcement
//! broadcasts and decodes them into [`TuyaBeaconObs`]. Two commands matter:
//!
//! - cmd `0x13` `UDP_NEW` — payload AES-128-ECB with the WELL-KNOWN udpkey
//!   (`md5("yGAdlopoPVldABfn")`, bytes precomputed; no MD5 needed here).
//!   Public tinytuya reference semantics: an unencrypted device ANNOUNCEMENT,
//!   decryptable without owner secrets (provenance class recorded as such).
//! - cmd `0x23` `BOARDCAST_LPV34` — payload AES-128-ECB with the DEVICE
//!   `local_key`: structure parse only until the owner provisions the key.
//!
//! Framing (`55AA` protocol 3.1–3.4, and `6699` 3.5 detection):
//! `prefix u32 | seqno u32 | cmd u32 | length u32` then `retcode u32 |
//! payload | crc32 u32 | suffix 0x0000AA55`. `length` covers payload+trailer;
//! CRC32 (IEEE) covers everything before it. Bad CRC/suffix never drops the
//! observation silently — `crc_good: false` carries the truth.
//!
//! Oracle: lab `tuya_client/tuya_lan.py` (32/32 vectors), byte-differential
//! verified including a real captured AOSU homebase beacon.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Tuya LAN discovery beacon port.
pub const TUYA_BEACON_PORT: u16 = 6667;
/// Frame prefix 0x000055AA (protocol ≤ 3.4).
pub const PREFIX_55AA: u32 = 0x0000_55AA;
/// Frame prefix 0x00006699 (protocol 3.5).
pub const PREFIX_6699: u32 = 0x0000_6699;
/// Frame suffix 0x0000AA55.
pub const SUFFIX_55AA: [u8; 4] = [0x00, 0x00, 0xAA, 0x55];
/// cmd 0x13 — UDP_NEW broadcast (well-known udpkey payload).
pub const UDP_NEW: u32 = 0x13;
/// cmd 0x23 — LPv3.4+ broadcast (device local_key payload).
pub const BOARDCAST_LPV34: u32 = 0x23;
/// Sanity bound on a declared frame length.
pub const MAX_PAYLOAD_LENGTH: usize = 1 << 20;
/// Maximum datagram the listener will read.
pub const MAX_DATAGRAM: usize = 2048;

/// The well-known udpkey: `md5("yGAdlopoPVldABfn")` (constant; it is a
/// public protocol constant, not an owner secret).
pub const UDP_BROADCAST_KEY: [u8; 16] = [
    0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a, 0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41,
    0x0a,
];

/// Typed decode errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconError {
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
        /// Bytes actually captured.
        have: usize,
    },
}

impl core::fmt::Display for BeaconError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BeaconError::ShortHeader => write!(f, "short frame header"),
            BeaconError::BadPrefix(p) => write!(f, "bad frame prefix 0x{p:08X}"),
            BeaconError::LengthOverBound(n) => write!(f, "declared length {n} over bound"),
            BeaconError::Truncated { need, have } => {
                write!(f, "short frame: need {need} have {have}")
            }
        }
    }
}

impl std::error::Error for BeaconError {}

/// One decoded beacon observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuyaBeaconObs {
    /// Source address (IP:port) the announcement came from.
    pub source: String,
    /// Frame family: "55AA" or "6699".
    pub frame: &'static str,
    /// Frame sequence number.
    pub seqno: u32,
    /// Command word.
    pub cmd: u32,
    /// Stable command name.
    pub cmd_name: &'static str,
    /// Payload byte count.
    pub payload_len: usize,
    /// Whether CRC32 + suffix verified.
    pub crc_good: bool,
    /// Decrypted JSON payload, when the well-known udpkey path applied.
    pub payload_json: Option<String>,
    /// Why the payload is not decrypted, when it is not.
    pub encrypted: Option<&'static str>,
    /// Protocol version hint from framing and command.
    pub version_hint: &'static str,
}

/// Parses the 16-byte header (55AA family) or 20-byte (6699 family).
struct FrameHeader {
    prefix: u32,
    seqno: u32,
    cmd: u32,
    total: usize,
    header_len: usize,
}

fn parse_header(data: &[u8]) -> Result<FrameHeader, BeaconError> {
    if data.len() < 16 {
        return Err(BeaconError::ShortHeader);
    }
    let prefix = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match prefix {
        PREFIX_55AA => {
            let seqno = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let cmd = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let length =
                u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as usize;
            if length > MAX_PAYLOAD_LENGTH {
                return Err(BeaconError::LengthOverBound(length));
            }
            let total = 16 + length;
            if data.len() < total {
                return Err(BeaconError::Truncated {
                    need: total,
                    have: data.len(),
                });
            }
            Ok(FrameHeader {
                prefix,
                seqno,
                cmd,
                total,
                header_len: 16,
            })
        }
        p @ PREFIX_6699 => {
            if data.len() < 20 {
                return Err(BeaconError::ShortHeader);
            }
            let seqno = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let cmd = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            let length =
                u32::from_be_bytes([data[16], data[17], data[18], data[19]]) as usize;
            if length > MAX_PAYLOAD_LENGTH {
                return Err(BeaconError::LengthOverBound(length));
            }
            let total = 20 + length + 4;
            if data.len() < total {
                return Err(BeaconError::Truncated {
                    need: total,
                    have: data.len(),
                });
            }
            Ok(FrameHeader {
                prefix: p,
                seqno,
                cmd,
                total,
                header_len: 20,
            })
        }
        p => Err(BeaconError::BadPrefix(p)),
    }
}

/// Stable command name.
#[must_use]
pub fn cmd_name(cmd: u32) -> &'static str {
    match cmd {
        UDP_NEW => "UDP_NEW",
        BOARDCAST_LPV34 => "BOARDCAST_LPV34",
        0x09 => "STATUS",
        0x0A => "LAN_CTRL",
        _ => "UNKNOWN",
    }
}

/// IEEE CRC32 (the Tuya trailer check), table-free (bitwise, reflected).
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

/// Structurally decodes one beacon datagram into an observation (no key
/// required). `source` is the sender as `ip:port`.
#[must_use]
pub fn decode_beacon(source: &str, data: &[u8]) -> Result<TuyaBeaconObs, BeaconError> {
    let h = parse_header(data)?;
    let is_55aa = h.prefix == PREFIX_55AA;
    let mut crc_good = false;
    let mut payload: &[u8] = &[];
    if is_55aa {
        // layout: header16 | retcode4 | payload | crc4 | suffix4
        let end_len = 8;
        if h.total < 16 + 4 + end_len {
            return Err(BeaconError::LengthOverBound(h.total));
        }
        let ret_len = 4;
        let msg_end = h.total;
        let body = &data[16 + ret_len..msg_end];
        let crc = u32::from_be_bytes([body[body.len() - 8], body[body.len() - 7], body[body.len() - 6], body[body.len() - 5]]);
        let suffix = &data[h.total - 4..h.total];
        payload = &body[..body.len() - end_len];
        let signed = &data[..h.total - end_len];
        crc_good = suffix == SUFFIX_55AA && crc == crc32_ieee(signed);
        // plaintext (unencrypted announcement) payload?
        if payload.first() == Some(&b'{') && payload.last() == Some(&b'}') {
            return Ok(TuyaBeaconObs {
                source: source.to_owned(),
                frame: "55AA",
                seqno: h.seqno,
                cmd: h.cmd,
                cmd_name: cmd_name(h.cmd),
                payload_len: payload.len(),
                crc_good,
                payload_json: Some(String::from_utf8_lossy(payload).into_owned()),
                encrypted: None,
                version_hint: version_hint(h.cmd, payload),
            });
        }
    } else {
        payload = &data[h.header_len..h.total - 16];
        version_hint_6699();
    }
    // encrypted payload: decrypt only the well-known-udpkey path
    let (payload_json, encrypted) = if is_55aa && h.cmd == UDP_NEW {
        match aes128_ecb_decrypt(&UDP_BROADCAST_KEY, payload) {
            Some(plain) => (
                Some(String::from_utf8_lossy(&plain).trim_end_matches('\0').to_owned()),
                None,
            ),
            None => (None, Some("udpkey decrypt failed")),
        }
    } else if is_55aa && h.cmd == BOARDCAST_LPV34 {
        (None, Some("device local_key required"))
    } else if is_55aa {
        (None, Some("device local_key required"))
    } else {
        (None, Some("3.5 GCM requires device local_key"))
    };
    let vh = if is_55aa {
        version_hint(h.cmd, payload)
    } else {
        version_hint_6699()
    };
    Ok(TuyaBeaconObs {
        source: source.to_owned(),
        frame: if is_55aa { "55AA" } else { "6699" },
        seqno: h.seqno,
        cmd: h.cmd,
        cmd_name: cmd_name(h.cmd),
        payload_len: payload.len(),
        crc_good,
        payload_json,
        encrypted,
        version_hint: vh,
    })
}

fn version_hint(cmd: u32, payload: &[u8]) -> &'static str {
    if payload.starts_with(b"3.3") {
        "3.3"
    } else if payload.starts_with(b"3.4") || cmd == BOARDCAST_LPV34 {
        "3.4/3.5 broadcast (payload encrypted with device local_key)"
    } else if cmd == UDP_NEW {
        "pre-3.3 UDP announcement (udpkey payload)"
    } else {
        "unknown"
    }
}

fn version_hint_6699() -> &'static str {
    "3.5 (6699 framing)"
}

/// Listens on :6667 for `seconds`, decoding up to `max_beacons` beacons.
/// Cancellation-checked per receive; socket drops closed.
pub fn listen(
    seconds: u64,
    max_beacons: usize,
    cancel: &AtomicBool,
) -> Vec<TuyaBeaconObs> {
    let sock = UdpSocket::bind(("0.0.0.0", TUYA_BEACON_PORT)).expect("bind :6667");
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("socket options");
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_DATAGRAM];
    while std::time::Instant::now() < deadline && out.len() < max_beacons {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Ok(obs) = decode_beacon(&src.to_string(), &buf[..n]) {
                    out.push(obs);
                }
            }
            Err(_) => continue,
        }
    }
    out
}

// ---- AES-128 (safe Rust, standard tables) --------------------------------

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn aes128_expand_encrypt(key: &[u8; 16]) -> [[u32; 4]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    let mut w = [[0u32; 4]; 11];
    for i in 0..4 {
        w[0][i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for round in 1..11 {
        let prev = w[round - 1];
        let mut temp = prev[3];
        temp = sub_word(temp.rotate_left(8));
        temp ^= u32::from(RCON[round - 1]) << 24;
        let mut cur = [temp ^ prev[0], 0, 0, 0];
        for i in 1..4 {
            cur[i] = cur[i - 1] ^ prev[i];
        }
        w[round] = cur;
    }
    w
}

fn sub_word(x: u32) -> u32 {
    u32::from_be_bytes([
        SBOX[((x >> 24) & 0xFF) as usize],
        SBOX[((x >> 16) & 0xFF) as usize],
        SBOX[((x >> 8) & 0xFF) as usize],
        SBOX[(x & 0xFF) as usize],
    ])
}

/// AES-128 decryption round keys (the direct inverse cipher uses the
/// ENCRYPTION schedule unmodified; no equivalent-cipher key mixing).
fn aes128_decrypt_keys(key: &[u8; 16]) -> [[u32; 4]; 11] {
    aes128_expand_encrypt(key)
}

fn aes128_decrypt_block(rk: &[[u32; 4]; 11], block: &[u8]) -> [u8; 16] {
    let mut s = [[0u8; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            s[r][c] = block[c * 4 + r];
        }
    }
    add_round_key(&mut s, &rk[10]);
    for round in (1..10).rev() {
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, &rk[round]);
        inv_mix_columns(&mut s);
    }
    inv_shift_rows(&mut s);
    inv_sub_bytes(&mut s);
    add_round_key(&mut s, &rk[0]);
    let mut out = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            out[c * 4 + r] = s[r][c];
        }
    }
    out
}

fn add_round_key(s: &mut [[u8; 4]; 4], rk: &[u32; 4]) {
    for c in 0..4 {
        let w = rk[c].to_be_bytes();
        for r in 0..4 {
            s[r][c] ^= w[r];
        }
    }
}

fn inv_shift_rows(s: &mut [[u8; 4]; 4]) {
    // Inverse cipher: row r cyclically shifts RIGHT by r (FIPS-197 §5.3.2).
    for r in 1..4 {
        let row = s[r];
        for c in 0..4 {
            s[r][c] = row[(c + 4 - r) % 4];
        }
    }
}

fn inv_sub_bytes(s: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            s[r][c] = INV_SBOX[s[r][c] as usize];
        }
    }
}

fn inv_mix_columns(s: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let a0 = s[0][c];
        let a1 = s[1][c];
        let a2 = s[2][c];
        let a3 = s[3][c];
        s[0][c] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[1][c] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[2][c] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[3][c] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// AES-128-ECB decrypt (no padding verification, Tuya broadcast semantics:
/// trailing bytes are noise after the JSON terminator).
fn aes128_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() % 16 != 0 || data.is_empty() {
        return None;
    }
    let rk = aes128_decrypt_keys(key);
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks(16) {
        out.extend_from_slice(&aes128_decrypt_block(&rk, block));
    }
    Some(out)
}

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
];

#[rustfmt::skip]
const INV_SBOX: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// The full captured AOSU homebase beacon bytes (lab scans fixture),
/// shared with cross-module tests.
/// The real captured AOSU homebase beacon (lab scans/tuya_beacon.hex).
pub(crate) const CAPTURED_0X23: &str = "000055aa0000000000000023000000cc0000000058e467256fac78567b1684089fe6e3ad060a3d6bc2679098ffa31a6e0938fd05e9d08260f7f18366fa8f1eb688441a49bd9fdf7dfb4e8dc1ee067101d78b9e54c2fb8459b1155fc75d4bf6699f92cba4c0ba520148045e7605fa0498dfea5aab35736c143092c8a09db76265bde438d3143207e3c2fae04e26c39c14928994350616cd44036f7601ab71f0aa8391a55ce0913a793742322b90964948dad4b60c91deba4f9c7d4813f4828d467080a0e77372664e97a8ecb0d61cdf50388a767c8717798a0000aa55";

#[cfg(test)]
pub(crate) fn captured_beacon_bytes() -> Vec<u8> {
    (0..CAPTURED_0X23.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&CAPTURED_0X23[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The real captured AOSU homebase beacon (lab scans/tuya_beacon.hex).


    /// Synthetic cmd-0x13 beacon built by the python oracle (aes_ecb_encrypt
    /// with the udpkey over a known JSON body, then pack_55aa).
    const SYNTHETIC_0X13: &str = "000055aa00000007000000130000008c000000005b3b7a768d0e6bf789aeab5c1a83bf58b63a8bbc407f26e69fdbf292ed63137ab39989adf9de967f221c02e70e61265276c579b7a6cbaacb51177501340e10e646c2c35a7641bb15db3b7e1ffd87c1c165d95f416c4c516c727de9b49de29826f8d3effa80902d7174ca5c70d1b019f6794d229cecfdc3bd5b0ce19b15c425daa3e5f6980000aa55";

    #[test]
    fn captured_0x23_structure_matches_oracle() {
        let data = unhex(CAPTURED_0X23);
        let obs = decode_beacon("192.168.4.37:6667", &data).unwrap();
        assert_eq!(obs.frame, "55AA");
        assert_eq!(obs.seqno, 0);
        assert_eq!(obs.cmd, 0x23);
        assert_eq!(obs.cmd_name, "BOARDCAST_LPV34");
        assert_eq!(obs.payload_len, 192);
        assert!(obs.crc_good, "CRC + suffix must verify");
        assert!(obs.payload_json.is_none());
        assert_eq!(obs.encrypted, Some("device local_key required"));
        assert_eq!(
            obs.version_hint,
            "3.4/3.5 broadcast (payload encrypted with device local_key)"
        );
    }

    #[test]
    fn synthetic_0x13_udpkey_decrypt_matches_oracle() {
        let data = unhex(SYNTHETIC_0X13);
        let obs = decode_beacon("192.168.4.99:6667", &data).unwrap();
        assert_eq!(obs.cmd, 0x13);
        assert_eq!(obs.cmd_name, "UDP_NEW");
        assert!(obs.crc_good);
        let json = obs.payload_json.as_deref().expect("udpkey decrypts 0x13");
        assert!(json.contains("\"gwId\":\"aostest123\""), "json: {json}");
        assert!(json.contains("\"ip\":\"192.168.4.99\""));
        assert!(json.contains("\"productKey\":\"keytest\""));
        assert!(json.contains("\"version\":\"3.4\""));
    }

    #[test]
    fn crc32_ieee_known_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn bad_prefix_refused() {
        let data = unhex("00001234000000000000000000000000");
        assert!(matches!(
            decode_beacon("x", &data),
            Err(BeaconError::BadPrefix(0x1234))
        ));
    }

    #[test]
    fn truncated_refused() {
        let data = unhex(&CAPTURED_0X23[..64]);
        assert!(matches!(
            decode_beacon("x", &data),
            Err(BeaconError::Truncated { .. })
        ));
    }

    #[test]
    fn corrupt_crc_reported_not_hidden() {
        let mut data = unhex(CAPTURED_0X23);
        let last = data.len() - 6;
        data[last] ^= 0xFF;
        let obs = decode_beacon("x", &data).unwrap();
        assert!(!obs.crc_good);
    }

    #[test]
    fn aes128_decrypt_fips197_c3_vector() {
        // FIPS-197 Appendix C.3: the canonical AES-128 decryption vector.
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let ct = unhex("69c4e0d86a7b0430d8cdb78070b4c55a");
        let rk = aes128_decrypt_keys(&key);
        let pt = aes128_decrypt_block(&rk, &ct);
        assert_eq!(hex_str(&pt), "00112233445566778899aabbccddeeff");
    }

    fn hex_str(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
