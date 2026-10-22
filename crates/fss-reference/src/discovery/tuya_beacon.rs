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
//! semantics. Unverified CRC/GCM/suffix checks never drop the observation
//! silently. [`TuyaBeaconObs::integrity_verified`] separates accepted protocol
//! evidence from malformed or still-encrypted diagnostic observations.
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
    /// Whether the 55AA CRC32 + suffix verified; false for 6699 frames.
    pub crc_good: bool,
    /// Whether the 6699 GCM tag + suffix verified with the well-known broadcast
    /// key; false for 55AA frames. This proves frame integrity, not device identity
    /// or owner authority, because the broadcast key is public.
    pub gcm_good: bool,
    /// Decrypted JSON payload, when the well-known udpkey path applied.
    pub payload_json: Option<String>,
    /// Why the payload is not decrypted, when it is not.
    pub encrypted: Option<&'static str>,
    /// Protocol version hint from framing and command.
    pub version_hint: &'static str,
}

impl TuyaBeaconObs {
    /// Whether this frame passed its family's integrity check. Raw observations
    /// can remain available when false, but cannot establish an accepted Tuya
    /// candidate or current protocol response. Neither a CRC nor the public
    /// broadcast key authenticates the device or grants owner authority.
    #[must_use]
    pub fn integrity_verified(&self) -> bool {
        match self.frame {
            "55AA" => self.crc_good,
            "6699" => self.gcm_good,
            _ => false,
        }
    }
}

/// Stable command name.
#[must_use]
pub fn cmd_name(cmd: u32) -> &'static str {
    // Shared command numbering (fss-tuya wire::cmd; tinytuya command_types):
    // 0x09 is HEART_BEAT and 0x0A is DP_QUERY — the earlier STATUS/LAN_CTRL
    // names were wrong.
    match cmd {
        tcmd::UDP_NEW => "UDP_NEW",
        tcmd::BOARDCAST_LPV34 => "BOARDCAST_LPV34",
        tcmd::HEART_BEAT => "HEART_BEAT",
        tcmd::DP_QUERY => "DP_QUERY",
        tcmd::DP_QUERY_NEW => "DP_QUERY_NEW",
        tcmd::STATUS => "STATUS",
        tcmd::CONTROL => "CONTROL",
        tcmd::CONTROL_NEW => "CONTROL_NEW",
        _ => "UNKNOWN",
    }
}

/// Structurally decodes one beacon datagram into an observation (no key
/// required). `source` is the sender as `ip:port`.
///
/// Unlike the strict session-channel decoder, a beacon with a corrupt
/// integrity trailer is still returned with `integrity_verified() == false`:
/// a malformed announcement is diagnostic evidence, not an accepted response.
pub fn decode_beacon(source: &str, data: &[u8]) -> Result<TuyaBeaconObs, tuya_wire::WireError> {
    let h = tuya_wire::parse_header(data)?;
    let is_55aa = h.prefix == tuya_wire::PREFIX_55AA;
    let mut crc_good = false;
    let mut gcm_good = false;
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
                gcm_good,
                payload_json: Some(String::from_utf8_lossy(payload).into_owned()),
                encrypted: None,
                version_hint: version_hint(h.cmd, payload),
            });
        }
    } else {
        // 6699 body layout: header18 | iv(12) | ciphertext | gcm tag(16) |
        // suffix 0x00009966. The full sealed body is [18 .. total-4); the
        // previous total-16 boundary truncated the tag.
        payload = &data[h.header_len..h.total - 4];
        version_hint_6699();
    }
    // encrypted payload: decrypt only the well-known-udpkey path
    let (payload_json, encrypted) = if is_55aa && h.cmd == tcmd::UDP_NEW {
        match tuya_crypto::aes128_ecb_decrypt_raw(&tuya_wire::UDP_BROADCAST_KEY, payload) {
            Some(plain) => {
                // Sim-produced beacons carry PKCS7 padding; real captures
                // may carry trailing noise after the JSON terminator.
                let unpadded = tuya_crypto::pkcs7_unpad(&plain).unwrap_or(&plain);
                (
                    Some(
                        String::from_utf8_lossy(unpadded)
                            .trim_end_matches('\0')
                            .to_owned(),
                    ),
                    None,
                )
            }
            None => (None, Some("udpkey decrypt failed")),
        }
    } else if !is_55aa {
        // 3.5 LAN discovery: 6699 frames on UDP with the SAME well-known
        // udpkey (GCM). Try it; a device-keyed 6699 frame stays labeled.
        match tuya_wire::unpack_6699_mode(
            data,
            &tuya_wire::UDP_BROADCAST_KEY,
            tuya_wire::RetcodeMode::Auto,
        ) {
            Ok(m) => {
                gcm_good = true;
                (
                    Some(
                        String::from_utf8_lossy(&m.payload)
                            .trim_end_matches('\0')
                            .to_owned(),
                    ),
                    None,
                )
            }
            Err(_) => (None, Some("6699 GCM not verified with broadcast key")),
        }
    } else {
        // 55AA, not UDP_NEW: the payload needs the device local_key.
        (None, Some("device local_key required"))
    };
    // The version hint must come from DECRYPTED content when we have it —
    // deriving it from ciphertext mislabels 3.4/3.5 announcements as
    // "pre-3.3" (ciphertext never starts with a readable version string).
    let vh = if is_55aa {
        match &payload_json {
            Some(json)
                if json.contains("\"version\":\"3.4\"") || json.contains("\"version\":\"3.5\"") =>
            {
                "3.4/3.5 UDP announcement (udpkey payload)"
            }
            _ => version_hint(h.cmd, payload),
        }
    } else if payload_json.is_some() {
        "3.5 UDP announcement (6699, udpkey payload)"
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
        gcm_good,
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
/// Cancellation-checked per receive; socket drops closed. Bind/option
/// failures are typed errors, never thread panics.
pub fn listen(
    seconds: u64,
    max_beacons: usize,
    cancel: &AtomicBool,
) -> std::io::Result<Vec<TuyaBeaconObs>> {
    let sock = UdpSocket::bind(("0.0.0.0", TUYA_BEACON_PORT))?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
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
    Ok(out)
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
        assert!(!obs.gcm_good);
        assert!(obs.integrity_verified());
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
        assert!(!obs.gcm_good);
        assert!(obs.integrity_verified());
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
        assert!(!obs.gcm_good);
        assert!(!obs.integrity_verified());
    }

    #[test]
    fn plaintext_55aa_integrity_does_not_depend_on_readable_json()
    -> Result<(), tuya_wire::WireError> {
        let mut data =
            tuya_wire::pack_55aa(1, tcmd::UDP_NEW, Some(0), br#"{"ip":"192.0.2.90"}"#, None)?;
        let valid = decode_beacon("192.0.2.90:6667", &data)?;
        assert!(valid.crc_good);
        assert!(!valid.gcm_good);
        assert!(valid.integrity_verified());
        assert!(valid.payload_json.is_some());

        data[22] ^= 1;
        let corrupt = decode_beacon("192.0.2.90:6667", &data)?;
        assert!(!corrupt.crc_good);
        assert!(!corrupt.gcm_good);
        assert!(!corrupt.integrity_verified());
        assert!(corrupt.payload_json.is_some());
        Ok(())
    }

    #[test]
    fn corrupt_55aa_suffix_remains_unverified_diagnostic() -> Result<(), tuya_wire::WireError> {
        let mut data = captured_beacon_bytes();
        let suffix_byte = data.len() - 1;
        data[suffix_byte] ^= 1;
        let obs = decode_beacon("192.0.2.90:6667", &data)?;
        assert_eq!(obs.frame, "55AA");
        assert!(!obs.crc_good);
        assert!(!obs.gcm_good);
        assert!(!obs.integrity_verified());
        Ok(())
    }

    const BEACON_6699_JSON: &str = r#"{"ip":"192.0.2.90","gwId":"sim6699","version":"3.5"}"#;

    fn beacon_6699_fixture(key: &[u8; 16]) -> Result<Vec<u8>, tuya_wire::WireError> {
        // Deterministic nonce for this synthetic offline fixture only.
        tuya_wire::pack_6699(
            1,
            tcmd::UDP_NEW,
            None,
            BEACON_6699_JSON.as_bytes(),
            key,
            *b"0123456789ab",
        )
    }

    #[test]
    fn beacon_6699_udp_new_decrypts_with_udpkey_gcm() -> Result<(), tuya_wire::WireError> {
        // The public broadcast key permits verification without a device key;
        // the integrity result must not be mislabeled as a successful CRC.
        let frame = beacon_6699_fixture(&tuya_wire::UDP_BROADCAST_KEY)?;
        let obs = decode_beacon("192.0.2.90:6667", &frame)?;
        assert_eq!(obs.frame, "6699");
        assert!(!obs.crc_good);
        assert!(obs.gcm_good);
        assert!(obs.integrity_verified());
        assert_eq!(obs.payload_json.as_deref(), Some(BEACON_6699_JSON));
        assert_eq!(obs.encrypted, None);
        assert_eq!(
            obs.version_hint,
            "3.5 UDP announcement (6699, udpkey payload)"
        );
        Ok(())
    }

    #[test]
    fn tampered_6699_frames_remain_unverified_diagnostics() -> Result<(), tuya_wire::WireError> {
        let frame = beacon_6699_fixture(&tuya_wire::UDP_BROADCAST_KEY)?;
        // Each mutation preserves parseable framing but invalidates either
        // authenticated bytes or the separately checked suffix.
        for (part, index) in [
            ("header", 8),
            ("nonce", 20),
            ("ciphertext", 32),
            ("tag", frame.len() - 5),
            ("suffix", frame.len() - 1),
        ] {
            let mut data = frame.clone();
            data[index] ^= 1;
            let obs = decode_beacon("192.0.2.90:6667", &data)?;
            assert_eq!(obs.frame, "6699", "{part}");
            assert!(!obs.crc_good, "{part}");
            assert!(!obs.gcm_good, "{part}");
            assert!(!obs.integrity_verified(), "{part}");
            assert_eq!(obs.payload_json, None, "{part}");
            assert_eq!(
                obs.encrypted,
                Some("6699 GCM not verified with broadcast key"),
                "{part}"
            );
        }
        Ok(())
    }

    #[test]
    fn device_keyed_6699_does_not_claim_broadcast_verification() -> Result<(), tuya_wire::WireError>
    {
        // Synthetic non-secret device key: the decoder only has the public
        // broadcast key, so it must preserve uncertainty about this frame.
        let frame = beacon_6699_fixture(b"fixture-key-6699")?;
        let obs = decode_beacon("192.0.2.90:6667", &frame)?;
        assert!(!obs.crc_good);
        assert!(!obs.gcm_good);
        assert!(!obs.integrity_verified());
        assert_eq!(obs.payload_json, None);
        assert_eq!(
            obs.encrypted,
            Some("6699 GCM not verified with broadcast key")
        );
        Ok(())
    }

    #[test]
    fn cmd_names_follow_the_shared_numbering() {
        assert_eq!(cmd_name(tcmd::HEART_BEAT), "HEART_BEAT");
        assert_eq!(cmd_name(tcmd::DP_QUERY), "DP_QUERY");
        assert_eq!(cmd_name(tcmd::UDP_NEW), "UDP_NEW");
        assert_eq!(cmd_name(tcmd::BOARDCAST_LPV34), "BOARDCAST_LPV34");
    }
}
