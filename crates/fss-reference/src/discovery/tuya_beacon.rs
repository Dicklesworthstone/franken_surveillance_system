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
//! Framing and cryptography live in the `fss-tuya` crate (LAB-AOSU-4): the
//! 55AA/6699 header parser, IEEE CRC32, and the first-party AES-128 core are
//! reused from there — this module carries only beacon-specific observation
//! semantics. Bad CRC/suffix never drops the observation silently —
//! `crc_good: false` carries the truth.
//!
//! Oracle: lab `tuya_client/tuya_lan.py` (32/32 vectors), byte-differential
//! verified including a real captured AOSU homebase beacon.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fss_tuya::crypto as tuya_crypto;
use fss_tuya::wire::{self as tuya_wire, cmd as tcmd};

/// UDP port for Tuya LAN broadcast announcements.
pub const TUYA_BEACON_PORT: u16 = 6667;

/// Maximum datagram the listener will read.
pub const MAX_DATAGRAM: usize = 2048;

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

/// Stable command name.
#[must_use]
pub fn cmd_name(cmd: u32) -> &'static str {
    match cmd {
        tcmd::UDP_NEW => "UDP_NEW",
        tcmd::BOARDCAST_LPV34 => "BOARDCAST_LPV34",
        0x09 => "STATUS",
        0x0A => "LAN_CTRL",
        _ => "UNKNOWN",
    }
}

/// Structurally decodes one beacon datagram into an observation (no key
/// required). `source` is the sender as `ip:port`.
///
/// Unlike the strict session-channel decoder, a beacon with a corrupt
/// integrity trailer is still returned (as `crc_good: false`): for passive
/// discovery a malformed announcement is itself evidence.
pub fn decode_beacon(source: &str, data: &[u8]) -> Result<TuyaBeaconObs, tuya_wire::WireError> {
    let h = tuya_wire::parse_header(data)?;
    let is_55aa = h.prefix == tuya_wire::PREFIX_55AA;
    let mut crc_good = false;
    let mut payload: &[u8] = &[];
    if is_55aa {
        // layout: header16 | retcode4 | payload | crc4 | suffix4
        let end_len = 8;
        if h.total < 16 + 4 + end_len {
            return Err(tuya_wire::WireError::ShortBody);
        }
        let ret_len = 4;
        let msg_end = h.total;
        let body = &data[16 + ret_len..msg_end];
        let crc = u32::from_be_bytes([
            body[body.len() - 8],
            body[body.len() - 7],
            body[body.len() - 6],
            body[body.len() - 5],
        ]);
        let suffix = &data[h.total - 4..h.total];
        payload = &body[..body.len() - end_len];
        let signed = &data[..h.total - end_len];
        crc_good = suffix == tuya_wire::SUFFIX_55AA && crc == tuya_wire::crc32_ieee(signed);
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
    let (payload_json, encrypted) = if is_55aa && h.cmd == tcmd::UDP_NEW {
        match tuya_crypto::aes128_ecb_decrypt_raw(&tuya_wire::UDP_BROADCAST_KEY, payload) {
            Some(plain) => (
                Some(String::from_utf8_lossy(&plain).trim_end_matches('\0').to_owned()),
                None,
            ),
            None => (None, Some("udpkey decrypt failed")),
        }
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
    } else if payload.starts_with(b"3.4") || cmd == tcmd::BOARDCAST_LPV34 {
        "3.4/3.5 broadcast (payload encrypted with device local_key)"
    } else if cmd == tcmd::UDP_NEW {
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

/// The real captured AOSU homebase beacon (lab scans/tuya_beacon.hex),
/// shared with cross-module tests.
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
        assert_eq!(tuya_wire::crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn bad_prefix_refused() {
        let data = unhex("00001234000000000000000000000000");
        assert!(matches!(
            decode_beacon("x", &data),
            Err(tuya_wire::WireError::BadPrefix(0x1234))
        ));
    }

    #[test]
    fn truncated_refused() {
        let data = unhex(&CAPTURED_0X23[..64]);
        assert!(matches!(
            decode_beacon("x", &data),
            Err(tuya_wire::WireError::Truncated { .. })
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
}
