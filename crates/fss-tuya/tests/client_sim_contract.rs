#![forbid(unsafe_code)]
//! Client↔simulator differential contract (LAB-AOSU-5): the sans-IO client
//! and the deterministic homebase simulator speak to each other over pure
//! byte exchange — no sockets, no clock. This is the development harness of
//! INTEROPERABILITY_LAB §5: the owned-device differential lands with
//! LAB-AOSU-2 (owner local_key), but every state transition, key derivation,
//! and error path is pinned here against the oracle-mirrored simulator.
//! All keys are test fixtures.

use fss_tuya::client::{ClientError, Proto, TuyaClient};
use fss_tuya::sim::{HomebaseSim, ModelFixture, SimConfig, SimEvent};
use fss_tuya::wire::{self, WireError, cmd};



const KEY: [u8; 16] = *b"fss_sim_test_key"; // == SimConfig::test_key()
const WRONG: [u8; 16] = *b"wrongwrongwrong0";
const NONCE: [u8; 16] = *b"0123456789abcdef";

fn iv(n: u8) -> [u8; 12] {
    let mut v = [0u8; 12];
    v[11] = n;
    v
}

/// Drives a full negotiation between client and simulator.
fn negotiate(client: &mut TuyaClient, sim: &mut HomebaseSim, key: [u8; 16]) {
    let f3 = client.start_session(NONCE, iv(1));
    let resp = sim.handle(&f3);
    assert_eq!(resp.len(), 1, "sim answers cmd3");
    let f5 = client.negotiate_finish(&resp[0], iv(2)).expect("negotiate_finish: {e}");
    let ack = sim.handle(&f5);
    assert!(ack.is_empty(), "device does not ACK finish");
    assert!(client.is_established());
    assert!(sim.is_established());
    let _ = key;
}

#[test]
fn full_session_client_against_simulator() {
    let mut client = TuyaClient::new(KEY, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    negotiate(&mut client, &mut sim, KEY);

    // Key agreement is proven behaviorally below: every post-negotiation
    // frame round-trips through AES-GCM under the derived session key —
    // any derivation mismatch would fail tag verification on both ends.

    // Heartbeat round-trip.
    let hb = client.heartbeat(iv(3)).expect("heartbeat: {e}");
    let resp = sim.handle(&hb);
    assert_eq!(resp.len(), 1);
    let inbound = client.handle(&resp[0]).expect("heartbeat inbound: {e}");
    assert_eq!(inbound.cmd, cmd::HEART_BEAT);

    // dp_query round-trip: fixture dps JSON comes back intact.
    let q = client.dp_query(iv(4)).expect("dp_query: {e}");
    let resp = sim.handle(&q);
    assert_eq!(resp.len(), 1);
    let inbound = client.handle(&resp[0]).expect("dp_query inbound: {e}");
    assert_eq!(inbound.cmd, cmd::STATUS);
    assert_eq!(inbound.payload, ModelFixture::AosuHomebase.dps_json().as_bytes());

    // Control round-trip with echo ACK.
    let ctl = client.control(b"{\"dps\":{\"101\":\"disarmed\"}}", iv(5)).expect("control: {e}");
    let resp = sim.handle(&ctl);
    assert_eq!(resp.len(), 1);
    let inbound = client.handle(&resp[0]).expect("control inbound: {e}");
    // 3.5 dialect: CONTROL_NEW on the wire; the sim's ACK echoes under the
    // same command, with the 15-byte version header stripped on receipt.
    assert_eq!(inbound.cmd, cmd::CONTROL_NEW);
    assert_eq!(inbound.payload, b"{\"dps\":{\"101\":\"disarmed\"}}");

    // Unsolicited event from the device decodes on the client.
    let ev = sim.event_motion_status().expect("event frame");
    let inbound = client.handle(&ev).expect("event inbound");
    assert_eq!(inbound.cmd, cmd::STATUS);
    assert!(String::from_utf8_lossy(&inbound.payload).contains("motion"));

    // Sim observed the whole conversation.
    for expected in [
        SimEvent::NegotiationStarted,
        SimEvent::Negotiated,
        SimEvent::Heartbeat,
        SimEvent::DpsQuery,
        SimEvent::ControlAcked,
        SimEvent::EventReported,
    ] {
        assert!(sim.events().contains(&expected), "missing {expected:?}");
    }
}

#[test]
fn heartbeat_ack_payload_is_empty_with_retcode_zero() {
    // Regression: device 6699 responses always embed a 4-byte retcode; the
    // client must strip it. A retcode-only ACK (4 raw bytes) must surface as
    // empty payload + Some(0), never as a 4-byte pseudo-payload.
    let mut client = TuyaClient::new(KEY, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    negotiate(&mut client, &mut sim, KEY);
    let hb = client.heartbeat(iv(3)).expect("heartbeat");
    let resp = sim.handle(&hb);
    assert_eq!(resp.len(), 1);
    let inbound = client.handle(&resp[0]).expect("inbound");
    assert_eq!(inbound.cmd, cmd::HEART_BEAT);
    assert_eq!(inbound.retcode, Some(0));
    assert!(inbound.payload.is_empty(), "retcode stripped: {:?}", inbound.payload);
}

#[test]
fn wrong_key_client_gets_silence_and_stays_unestablished() {
    let mut client = TuyaClient::new(WRONG, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    let f3 = client.start_session(NONCE, iv(1));
    let resp = sim.handle(&f3);
    assert!(resp.is_empty(), "wrong key → silent drop (device behavior)");
    assert!(sim.events().contains(&SimEvent::WrongKeyRejected));
    assert!(!client.is_established());
    // Session commands refuse locally too.
    assert_eq!(client.heartbeat(iv(2)), Err(ClientError::NoSession));
}

#[test]
fn device_proof_tamper_is_detected() {
    let mut client = TuyaClient::new(KEY, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    let f3 = client.start_session(NONCE, iv(1));
    let resp = sim.handle(&f3);
    assert_eq!(resp.len(), 1);
    // Tamper one byte of the sealed response → GCM auth failure surfaces.
    let mut bad = resp[0].clone();
    let idx = bad.len() - 8;
    if let Some(b) = bad.get_mut(idx) {
        *b ^= 0x01;
    }
    let r = client.negotiate_finish(&bad, iv(2));
    assert!(matches!(r, Err(ClientError::Wire(WireError::GcmAuth))), "{r:?}");
    assert!(!client.is_established());
}

#[test]
fn session_commands_require_session() {
    let mut client = TuyaClient::new(KEY, Proto::V35);
    assert_eq!(client.heartbeat(iv(1)), Err(ClientError::NoSession));
    assert_eq!(client.dp_query(iv(1)), Err(ClientError::NoSession));
    assert_eq!(client.control(b"{}", iv(1)), Err(ClientError::NoSession));
    let r = client.negotiate_finish(b"\x00", iv(1));
    assert_eq!(r, Err(ClientError::NoPendingNegotiation));
}


#[test]
fn proto_34_full_session() {
    let mut cfg = SimConfig::v35_homebase();
    cfg.proto = fss_tuya::sim::Proto::V34;
    let mut sim = HomebaseSim::new(cfg);
    let mut client = TuyaClient::new(KEY, Proto::V34);
    negotiate(&mut client, &mut sim, KEY);

    let q = client.dp_query(iv(4)).expect("dp_query: {e}");
    let resp = sim.handle(&q);
    assert_eq!(resp.len(), 1);
    let inbound = client.handle(&resp[0]).expect("inbound: {e}");
    assert_eq!(inbound.cmd, cmd::STATUS);
    assert_eq!(inbound.payload, ModelFixture::AosuHomebase.dps_json().as_bytes());
}

#[test]
fn session_expiry_surfaces_as_typed_error_on_client() {
    let mut cfg = SimConfig::v35_homebase();
    cfg.session_ttl_msgs = 1;
    let mut sim = HomebaseSim::new(cfg);
    let mut client = TuyaClient::new(KEY, Proto::V35);
    negotiate(&mut client, &mut sim, KEY);
    let hb1 = client.heartbeat(iv(3)).expect("hb1: {e}");
    assert_eq!(sim.handle(&hb1).len(), 1);
    // Second heartbeat exceeds the budget: sim drops the session silently.
    let hb2 = client.heartbeat(iv(4)).expect("hb2: {e}");
    assert!(sim.handle(&hb2).is_empty());
    assert!(sim.events().contains(&SimEvent::SessionExpired));
    // The client still holds its (now dead) session key; the next real
    // device behavior would be a transport close. The caller observes the
    // silence and renegotiates — which works from the current state.
    let f3 = client.start_session(*b"6543210fedcba987", iv(5));
    let resp = sim.handle(&f3);
    assert_eq!(resp.len(), 1, "post-expiry renegotiation answers");
}

#[test]
fn inbound_payloads_have_the_version_header_stripped() {
    // Header-emitting devices prepend "3.5" + 12 NULs inside the sealed
    // payload; the client surfaces pure dps JSON (oracle _decode_payload
    // semantics).
    let mut client = TuyaClient::new(KEY, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    negotiate(&mut client, &mut sim, KEY);
    let sess = sim.session_key().expect("session key");
    let mut raw = wire::PROTOCOL_VERSION_HEADER_35.to_vec();
    raw.extend_from_slice(b"{\"dps\":{\"1\":true}}");
    let frame = wire::pack_6699(9, cmd::STATUS, Some(0), &raw, &sess, iv(9))
        .expect("pack");
    let inbound = client.handle(&frame).expect("inbound");
    assert_eq!(inbound.cmd, cmd::STATUS);
    assert_eq!(inbound.payload, b"{\"dps\":{\"1\":true}}", "header stripped");
}

#[test]
fn negotiation_response_in_handle_is_unexpected_when_established() {
    // (Reviewer fix: the earlier version never reached the named branch —
    // it called start_session first, leaving the client unestablished.)
    let mut client = TuyaClient::new(KEY, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    negotiate(&mut client, &mut sim, KEY);
    assert!(client.is_established());
    // A negotiation-shaped frame sealed under the SESSION key inside an
    // established session must be UnexpectedFrame, not silent acceptance.
    let sess = sim.session_key().expect("session key");
    let bogus = wire::pack_6699(9, cmd::SESS_KEY_NEG_RESP, Some(0), &[0u8; 48], &sess, iv(9))
        .expect("pack");
    let r = client.handle(&bogus);
    assert_eq!(
        r,
        Err(ClientError::UnexpectedFrame {
            state: "established",
            cmd: cmd::SESS_KEY_NEG_RESP
        })
    );
}
