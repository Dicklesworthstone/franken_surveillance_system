//! Simulator contract tests (LAB-AOSU-4): the full 3.5 session flow driven
//! by a hand-rolled client side over `wire`+`crypto` (the client state
//! machine proper is LAB-AOSU-5), wrong-key rejection, expiry, dps fixtures,
//! control ACK, offline/reboot, malformed injection, and beacon decoding.
//! All keys are test fixtures; no hardware, no network.

use fss_tuya::crypto::hmac_sha256;
use fss_tuya::sim::{HomebaseSim, MalformedMode, ModelFixture, Proto, SimConfig, SimEvent};
use fss_tuya::wire::{
    self, RetcodeMode, cmd, pack_6699, unpack_55aa, unpack_6699, unpack_6699_mode,
};



const CLIENT_KEY: &[u8; 16] = b"fss_sim_test_key"; // == SimConfig::test_key()
const WRONG_KEY: &[u8; 16] = b"wrongwrongwrong0";
const CLIENT_NONCE: &[u8; 16] = b"0123456789abcdef";
const CLIENT_IV: [u8; 12] = *b"clientiv0001";

fn sim_35() -> HomebaseSim {
    HomebaseSim::new(SimConfig::v35_homebase())
}

/// Client-side negotiation step 1: send cmd 3, expect cmd 4, verify the
/// device HMAC proof, return (device_nonce, client_proof_to_send).
fn client_negotiate(sim: &mut HomebaseSim, key: &[u8; 16]) -> Option<([u8; 16], Vec<u8>)> {
    let start = pack_6699(1, cmd::SESS_KEY_NEG_START, None, CLIENT_NONCE, key, CLIENT_IV);
    let resp = sim.handle(&start);
    if resp.len() != 1 {
        return None;
    }
    let msg = unpack_6699_mode(&resp[0], key, RetcodeMode::Present).ok()?;
    if msg.cmd != cmd::SESS_KEY_NEG_RESP || msg.payload.len() != 48 {
        return None;
    }
    let device_nonce: [u8; 16] = msg.payload[..16].try_into().ok()?;
    let proof = &msg.payload[16..];
    // Device must prove it knows the shared key.
    if proof != hmac_sha256(key, CLIENT_NONCE) {
        return None;
    }
    let finish = hmac_sha256(key, &device_nonce).to_vec();
    Some((device_nonce, finish))
}

#[test]
fn negotiation_success_then_session_traffic() {
    let mut sim = sim_35();
    let (device_nonce, finish)= client_negotiate(&mut sim, CLIENT_KEY).expect("negotiation steps 1-2 failed");
    assert!(sim.events().contains(&SimEvent::NegotiationStarted));

    // Step 3: client proof. The device does not ACK; the session goes live.
    let fin = pack_6699(2, cmd::SESS_KEY_NEG_FINISH, None, &finish, CLIENT_KEY, CLIENT_IV);
    let ack = sim.handle(&fin);
    assert!(ack.is_empty(), "no finish ACK on the wire");
    assert!(sim.is_established());
    assert!(sim.events().contains(&SimEvent::Negotiated));

    // Both sides derive the same session key.
    let expect_key =
        wire::derive_session_key_35(CLIENT_KEY, CLIENT_NONCE, &device_nonce);
    assert_eq!(sim.session_key(), Some(expect_key));

    // Heartbeat under the session key.
    let sess = sim.session_key().expect("no session key");
    let hb = pack_6699(3, cmd::HEART_BEAT, None, b"", &sess, CLIENT_IV);
    let resp = sim.handle(&hb);
    assert_eq!(resp.len(), 1);
    let msg = unpack_6699(&resp[0], &sess).expect("heartbeat resp: {e}");
    assert_eq!(msg.cmd, cmd::HEART_BEAT);
    assert!(sim.events().contains(&SimEvent::Heartbeat));

    // dp_query returns the model fixture dps.
    let q = pack_6699(4, cmd::DP_QUERY, None, b"", &sess, CLIENT_IV);
    let resp = sim.handle(&q);
    assert_eq!(resp.len(), 1);
    let msg = unpack_6699(&resp[0], &sess).expect("dp_query resp: {e}");
    assert_eq!(msg.cmd, cmd::STATUS);
    assert_eq!(
        msg.payload,
        ModelFixture::AosuHomebase.dps_json().as_bytes()
    );
    assert!(sim.events().contains(&SimEvent::DpsQuery));

    // Control ACK echoes the write payload.
    let ctl_payload = b"{\"dps\":{\"101\":\"disarmed\"}}";
    let ctl = pack_6699(5, cmd::CONTROL, None, ctl_payload, &sess, CLIENT_IV);
    let resp = sim.handle(&ctl);
    assert_eq!(resp.len(), 1);
    let msg = unpack_6699(&resp[0], &sess).expect("control resp: {e}");
    assert_eq!(msg.cmd, cmd::CONTROL);
    assert_eq!(msg.payload, ctl_payload);
    assert!(sim.events().contains(&SimEvent::ControlAcked));

    // Unsolicited event frame decodes under the session key.
    let ev = sim.event_motion_status().expect("event frame required with live session");
    let msg = unpack_6699(&ev, &sess).expect("event frame: {e}");
    assert_eq!(msg.cmd, cmd::STATUS);
    assert_eq!(msg.payload, ModelFixture::AosuHomebase.event_json().as_bytes());
}

#[test]
fn wrong_key_is_rejected_silently() {
    let mut sim = sim_35();
    // Client used the wrong key: the GCM tag fails on the device.
    let start = pack_6699(1, cmd::SESS_KEY_NEG_START, None, CLIENT_NONCE, WRONG_KEY, CLIENT_IV);
    let resp = sim.handle(&start);
    assert!(resp.is_empty(), "wrong-key frames get silence, not errors");
    assert!(sim.events().contains(&SimEvent::WrongKeyRejected));
    assert!(!sim.is_established());
}

#[test]
fn wrong_proof_finish_is_rejected() {
    let mut sim = sim_35();
    let (_dn, _finish)= client_negotiate(&mut sim, CLIENT_KEY).expect("negotiation steps 1-2 failed");
    let bad_proof = [0xEEu8; 32];
    let fin = pack_6699(2, cmd::SESS_KEY_NEG_FINISH, None, &bad_proof, CLIENT_KEY, CLIENT_IV);
    let resp = sim.handle(&fin);
    assert!(resp.is_empty());
    assert!(!sim.is_established());
    assert!(sim.events().contains(&SimEvent::WrongKeyRejected));
}

#[test]
fn session_expiry_after_budget() {
    let mut cfg = SimConfig::v35_homebase();
    cfg.session_ttl_msgs = 1;
    let mut sim = HomebaseSim::new(cfg);
    let (_dn, finish) = client_negotiate(&mut sim, CLIENT_KEY).expect("negotiation failed");
    let fin = pack_6699(2, cmd::SESS_KEY_NEG_FINISH, None, &finish, CLIENT_KEY, CLIENT_IV);
    sim.handle(&fin);
    let sess = sim.session_key().expect("no session key");
    // First heartbeat OK (seen=1 <= ttl).
    let hb = pack_6699(3, cmd::HEART_BEAT, None, b"", &sess, CLIENT_IV);
    assert_eq!(sim.handle(&hb).len(), 1);
    // Second exceeds the budget: session dropped, silence.
    let hb2 = pack_6699(4, cmd::HEART_BEAT, None, b"", &sess, CLIENT_IV);
    assert!(sim.handle(&hb2).is_empty());
    assert!(sim.events().contains(&SimEvent::SessionExpired));
    assert!(!sim.is_established());
    // A third frame under the now-dead session key is also rejected.
    let hb3 = pack_6699(5, cmd::HEART_BEAT, None, b"", &sess, CLIENT_IV);
    assert!(sim.handle(&hb3).is_empty());
}

#[test]
fn offline_then_reboot_recovers() {
    let mut cfg = SimConfig::v35_homebase();
    cfg.offline_for_msgs = 2;
    let mut sim = HomebaseSim::new(cfg);
    let start = pack_6699(1, cmd::SESS_KEY_NEG_START, None, CLIENT_NONCE, CLIENT_KEY, CLIENT_IV);
    assert!(sim.handle(&start).is_empty());
    assert!(sim.handle(&start).is_empty());
    assert_eq!(
        sim.events()
            .iter()
            .filter(|e| **e == SimEvent::OfflineDrop)
            .count(),
        2
    );
    assert!(sim.events().contains(&SimEvent::Rebooted));
    // After the reboot the sim answers again (a fresh negotiation works).
    let ok = client_negotiate(&mut sim, CLIENT_KEY);
    assert!(ok.is_some(), "post-reboot negotiation must succeed");
}

#[test]
fn malformed_input_is_dropped_not_fatal() {
    let mut sim = sim_35();
    let resp = sim.handle(b"\x00\x01\x02\x03");
    assert!(resp.is_empty());
    assert!(sim.events().contains(&SimEvent::MalformedInput));
    // Garbage with a valid prefix but corrupt GCM.
    let mut junk = pack_6699(1, cmd::SESS_KEY_NEG_START, None, CLIENT_NONCE, CLIENT_KEY, CLIENT_IV);
    let idx = junk.len() - 6;
    if let Some(b) = junk.get_mut(idx) {
        *b ^= 0x40;
    }
    assert!(sim.handle(&junk).is_empty());
}

#[test]
fn malformed_response_injection_is_detectable() {
    let mut cfg = SimConfig::v35_homebase();
    cfg.malformed = MalformedMode::BadSuffix;
    let mut sim = HomebaseSim::new(cfg);
    let start = pack_6699(1, cmd::SESS_KEY_NEG_START, None, CLIENT_NONCE, CLIENT_KEY, CLIENT_IV);
    let resp = sim.handle(&start);
    assert_eq!(resp.len(), 1);
    let unpacked = unpack_6699(&resp[0], CLIENT_KEY);
    assert_eq!(unpacked, Err(wire::WireError::Integrity));
}

#[test]
fn beacons_decode_with_their_keys() {
    let mut sim = sim_35();
    // cmd 0x13: well-known udpkey path — decrypts without the device key.
    let b13 = sim.beacon_udp_new();
    let h = wire::parse_header(&b13).expect("beacon header: {e}");
    assert_eq!(h.cmd, cmd::UDP_NEW);
    let m = unpack_55aa(&b13, None, false).expect("beacon unpack: {e}");
    let plain = fss_tuya::crypto::aes128_ecb_decrypt_pkcs7(&wire::UDP_BROADCAST_KEY, &m.payload);
    let plain = plain.expect("udpkey decrypt");
    let json = String::from_utf8_lossy(&plain);
    assert!(json.contains("\"productKey\":\"fsssimhomebase00\""), "{json}");
    assert!(json.contains("\"version\":\"3.5\""), "{json}");

    // cmd 0x23: device-key path — decrypts with the test local_key only.
    let b23 = sim.beacon_lpv34();
    let m = unpack_55aa(&b23, None, false).expect("beacon unpack: {e}");
    let plain = fss_tuya::crypto::aes128_ecb_decrypt_pkcs7(CLIENT_KEY, &m.payload);
    assert!(plain.is_some(), "device key decrypts 0x23");
    let wrong = fss_tuya::crypto::aes128_ecb_decrypt_pkcs7(WRONG_KEY, &m.payload);
    assert_ne!(
        wrong.as_deref().map(|w| w.starts_with(b"{")),
        Some(true),
        "wrong key must not yield the JSON announcement"
    );
}

#[test]
fn proto_34_session_roundtrip() {
    // The 3.4 lane: 55AA + HMAC trailer, ECB-PKCS7 payloads.
    let mut cfg = SimConfig::v35_homebase();
    cfg.proto = Proto::V34;
    let mut sim = HomebaseSim::new(cfg);

    let start_pt = CLIENT_NONCE.to_vec();
    let start_sealed = fss_tuya::crypto::aes128_ecb_encrypt_pkcs7(CLIENT_KEY, &start_pt);
    let start = wire::pack_55aa(1, cmd::SESS_KEY_NEG_START, None, &start_sealed, Some(CLIENT_KEY));
    let resp = sim.handle(&start);
    assert_eq!(resp.len(), 1, "cmd3 gets a cmd4 response");
    let m = wire::unpack_55aa(&resp[0], Some(CLIENT_KEY), false).expect("cmd4 unpack: {e}");
    assert_eq!(m.cmd, cmd::SESS_KEY_NEG_RESP);
    let pt = fss_tuya::crypto::aes128_ecb_decrypt_pkcs7(CLIENT_KEY, &m.payload).expect("cmd4 decrypt");
    assert_eq!(pt.len(), 48);
    let device_nonce: [u8; 16] = pt[..16].try_into().expect("nonce slice");
    let finish = hmac_sha256(CLIENT_KEY, &device_nonce);
    let fin_sealed = fss_tuya::crypto::aes128_ecb_encrypt_pkcs7(CLIENT_KEY, &finish);
    let fin = wire::pack_55aa(2, cmd::SESS_KEY_NEG_FINISH, None, &fin_sealed, Some(CLIENT_KEY));
    sim.handle(&fin);
    assert!(sim.is_established());
    let expect = wire::derive_session_key_34(CLIENT_KEY, CLIENT_NONCE, &device_nonce).expect("derive 3.4");
    assert_eq!(sim.session_key(), Some(expect));
}
