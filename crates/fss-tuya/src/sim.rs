//! Deterministic Tuya homebase simulator (INTEROPERABILITY_LAB §5:
//! "the live device is not the development test harness"). Sans-IO: bytes
//! in, bytes out, no sockets, no clock, no randomness — every nonce/IV is
//! derived from a counter so runs are bit-reproducible. Keys are test
//! fixtures only; a simulator instance MUST never be handed a real device
//! key (the type documents this, CI fixtures use obviously-fake keys).
//!
//! Implemented behaviors (bead fss-x4a.21.3.4):
//! * beacon emitters — cmd 0x13 (udpkey) and cmd 0x23 (device key);
//! * 3.5 session negotiation — success, wrong-key rejection (silent drop,
//!   the real device behavior), and session expiry after a message budget;
//! * heartbeat / dp_query / control with per-model sanitized dps fixtures;
//! * unsolicited event frames (battery/event-driven semantics);
//! * offline / homebase-reboot (silent for N frames, then recovers);
//! * malformed response injection (bad CRC, bad suffix, truncation) plus
//!   robust rejection of malformed input.
//!
//! 3.4 framing is supported for negotiation + session traffic (55AA with
//! HMAC trailer, ECB-PKCS7 payloads); 3.5 (6699/GCM) is the primary lane.

use crate::crypto;
use crate::wire::{self, cmd};

/// Protocol generation the sim speaks on the session channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// 3.4: 55AA frames, HMAC-SHA256 trailer, AES-128-ECB-PKCS7 payloads.
    V34,
    /// 3.5: 6699 frames, AES-128-GCM payloads.
    V35,
}

/// Per-model sanitized fixture set. Values are synthetic (TEST-NET-1
/// addressing, fake IDs); real dps mappings land with LAB-AOSU-1 MITM
/// evidence and must replace these fixtures when qualified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFixture {
    /// AOSU-style battery-cam homebase (event-driven, never continuous).
    AosuHomebase,
    /// Generic mains-powered Tuya device (always-on control target).
    GenericSwitch,
}

impl ModelFixture {
    /// Stable productKey-shaped fixture identifier.
    #[must_use]
    pub const fn product_key(self) -> &'static str {
        match self {
            ModelFixture::AosuHomebase => "fsssimhomebase00",
            ModelFixture::GenericSwitch => "hfsssgenericswitch",
        }
    }

    /// Sanitized dps status JSON (deterministic, synthetic values).
    #[must_use]
    pub const fn dps_json(self) -> &'static str {
        match self {
            ModelFixture::AosuHomebase => {
                "{\"dps\":{\"101\":\"armed_away\",\"102\":85,\"103\":false,\"104\":\"idle\"}}"
            }
            ModelFixture::GenericSwitch => "{\"dps\":{\"1\":true,\"9\":0,\"17\":4}}",
        }
    }

    /// A canned motion/event dps report (battery semantics: event-driven).
    #[must_use]
    pub const fn event_json(self) -> &'static str {
        match self {
            ModelFixture::AosuHomebase => {
                "{\"dps\":{\"104\":\"motion\",\"115\":1}}"
            }
            ModelFixture::GenericSwitch => "{\"dps\":{\"1\":false}}",
        }
    }
}

/// Malformed-response injection for client-robustness tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedMode {
    /// Respond normally.
    None,
    /// Corrupt one integrity-trailer byte (CRC/HMAC/GCM tag).
    BadIntegrity,
    /// Corrupt the frame suffix.
    BadSuffix,
    /// Truncate the frame to N bytes.
    Truncate(usize),
}

/// Simulator configuration. `local_key` is a TEST fixture; the type-level
/// contract of this crate forbids real device keys in lab artifacts.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Test local_key fixture (16 bytes).
    pub local_key: [u8; 16],
    /// Protocol generation.
    pub proto: Proto,
    /// Per-model fixtures.
    pub model: ModelFixture,
    /// Established-session message budget before expiry (0 = never).
    pub session_ttl_msgs: u32,
    /// Start offline: silently drop this many inbound frames, then reboot.
    pub offline_for_msgs: u32,
    /// Malformed injection applied to the next response frame.
    pub malformed: MalformedMode,
}

impl SimConfig {
    /// A deterministic obviously-fake key for tests and fixtures.
    #[must_use]
    pub const fn test_key() -> [u8; 16] {
        *b"fss_sim_test_key"
    }

    /// Default 3.5 AOSU-homebase configuration.
    #[must_use]
    pub fn v35_homebase() -> Self {
        Self {
            local_key: Self::test_key(),
            proto: Proto::V35,
            model: ModelFixture::AosuHomebase,
            session_ttl_msgs: 0,
            offline_for_msgs: 0,
            malformed: MalformedMode::None,
        }
    }
}

/// Observable simulator events (for tests and adapter diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimEvent {
    /// A session-key negotiation started (client nonce well-formed).
    NegotiationStarted,
    /// Negotiation finished; session established.
    Negotiated,
    /// Client proof failed or a frame would not decrypt — the real device
    /// drops silently, and so do we.
    WrongKeyRejected,
    /// Session message budget exhausted; session dropped.
    SessionExpired,
    /// Heartbeat answered.
    Heartbeat,
    /// dps query answered.
    DpsQuery,
    /// Control frame acknowledged.
    ControlAcked,
    /// Unsolicited event report emitted.
    EventReported,
    /// Malformed input frame rejected (no response).
    MalformedInput,
    /// Frame dropped while offline.
    OfflineDrop,
    /// Offline period ended; back to pre-session state.
    Rebooted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Session {
    None,
    AwaitingFinish {
        client_nonce: [u8; 16],
        device_nonce: [u8; 16],
    },
    Established {
        key: [u8; 16],
        seen: u32,
    },
}

/// The deterministic homebase simulator.
pub struct HomebaseSim {
    config: SimConfig,
    session: Session,
    events: Vec<SimEvent>,
    seq_out: u32,
    counter: u64,
}

impl HomebaseSim {
    /// Creates a simulator. `offline_for_msgs > 0` starts it offline.
    #[must_use]
    pub fn new(config: SimConfig) -> Self {
        Self {
            config,
            session: Session::None,
            events: Vec::new(),
            seq_out: 1,
            counter: 0,
        }
    }

    /// Events observed so far.
    #[must_use]
    pub fn events(&self) -> &[SimEvent] {
        &self.events
    }

    /// Whether a session is currently established.
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(self.session, Session::Established { .. })
    }

    /// The established session key (test verification only).
    #[must_use]
    pub fn session_key(&self) -> Option<[u8; 16]> {
        match self.session {
            Session::Established { key, .. } => Some(key),
            _ => None,
        }
    }

    /// Simulates a reboot: drops the session, goes silent for `frames`.
    pub fn simulate_reboot(&mut self, frames: u32) {
        self.session = Session::None;
        self.config.offline_for_msgs = frames;
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq_out;
        self.seq_out = self.seq_out.wrapping_add(1);
        s
    }

    /// Deterministic 12-byte IV for the next outbound 6699 frame.
    fn next_iv(&mut self) -> [u8; 12] {
        self.counter += 1;
        let mut seed = b"fss-tuya-sim-iv".to_vec();
        seed.extend_from_slice(&self.counter.to_be_bytes());
        let h = fss_core::sha256(&seed);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&h[..12]);
        iv
    }

    /// Deterministic 16-byte device nonce for the next negotiation.
    fn next_device_nonce(&mut self) -> [u8; 16] {
        self.counter += 1;
        let mut seed = b"fss-tuya-sim-nonce".to_vec();
        seed.extend_from_slice(&self.counter.to_be_bytes());
        fss_core::sha256(&seed)[..16].try_into().unwrap_or([0u8; 16])
    }

    fn announcement_json(&self) -> String {
        let version = match self.config.proto {
            Proto::V34 => "3.4",
            Proto::V35 => "3.5",
        };
        format!(
            "{{\"ip\":\"192.0.2.66\",\"gwId\":\"fsstest{}\",\"active\":2,\"ablilty\":0,\"encrypt\":true,\"productKey\":\"{}\",\"version\":\"{}\",\"token\":true,\"wf_cfg\":true}}",
            self.config.model.product_key(),
            self.config.model.product_key(),
            version
        )
    }

    /// cmd 0x13 broadcast beacon (AES-128-ECB under the well-known udpkey).
    pub fn beacon_udp_new(&mut self) -> Vec<u8> {
        let seq = self.next_seq();
        let payload = crypto::aes128_ecb_encrypt_pkcs7(
            &wire::UDP_BROADCAST_KEY,
            self.announcement_json().as_bytes(),
        );
        wire::pack_55aa(seq, cmd::UDP_NEW, Some(0), &payload, None)
    }

    /// cmd 0x23 LPv3.4+ broadcast beacon (AES-128-ECB under the device key).
    pub fn beacon_lpv34(&mut self) -> Vec<u8> {
        let seq = self.next_seq();
        let payload = crypto::aes128_ecb_encrypt_pkcs7(
            &self.config.local_key,
            self.announcement_json().as_bytes(),
        );
        wire::pack_55aa(seq, cmd::BOARDCAST_LPV34, Some(0), &payload, None)
    }

    /// An unsolicited event report frame (battery/event-driven semantics),
    /// sealed under the established session key; `None` without a session.
    pub fn event_motion_status(&mut self) -> Option<Vec<u8>> {
        let key = self.session_key()?;
        let seq = self.next_seq();
        let json = self.config.model.event_json();
        let frame = match self.config.proto {
            Proto::V35 => {
                wire::pack_6699(seq, cmd::STATUS, Some(0), json.as_bytes(), &key, self.next_iv())
            }
            Proto::V34 => {
                let payload = crypto::aes128_ecb_encrypt_pkcs7(&key, json.as_bytes());
                wire::pack_55aa(seq, cmd::STATUS, Some(0), &payload, Some(&key))
            }
        };
        self.events.push(SimEvent::EventReported);
        Some(frame)
    }

    /// Applies malformed injection to an outbound frame per configuration.
    fn maybe_corrupt(&mut self, mut frame: Vec<u8>) -> Vec<u8> {
        match self.config.malformed {
            MalformedMode::None => frame,
            MalformedMode::BadIntegrity => {
                // Flip one byte in the integrity trailer (CRC/HMAC/tag).
                let idx = frame.len().saturating_sub(5);
                if let Some(b) = frame.get_mut(idx) {
                    *b ^= 0x01;
                }
                self.config.malformed = MalformedMode::None;
                frame
            }
            MalformedMode::BadSuffix => {
                let idx = frame.len().saturating_sub(1);
                if let Some(b) = frame.get_mut(idx) {
                    *b ^= 0xFF;
                }
                self.config.malformed = MalformedMode::None;
                frame
            }
            MalformedMode::Truncate(n) => {
                frame.truncate(n.min(frame.len()));
                self.config.malformed = MalformedMode::None;
                frame
            }
        }
    }

    fn respond(&mut self, cmd_word: u32, key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let seq = self.next_seq();
        let frame = match self.config.proto {
            Proto::V35 => {
                wire::pack_6699(seq, cmd_word, Some(0), plaintext, key, self.next_iv())
            }
            Proto::V34 => {
                let sealed = crypto::aes128_ecb_encrypt_pkcs7(key, plaintext);
                wire::pack_55aa(seq, cmd_word, Some(0), &sealed, Some(key))
            }
        };
        self.maybe_corrupt(frame)
    }

    /// Handles one inbound frame; returns zero or more response frames.
    /// Malformed input, wrong keys, and offline states all produce silence
    /// plus a recorded event — the real device's observable behavior.
    pub fn handle(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        if self.config.offline_for_msgs > 0 {
            self.config.offline_for_msgs -= 1;
            self.events.push(SimEvent::OfflineDrop);
            if self.config.offline_for_msgs == 0 {
                self.events.push(SimEvent::Rebooted);
            }
            return Vec::new();
        }

        // Decode per protocol family. Wrong-key 6699 frames fail GCM here.
        // The command is readable in the cleartext header, so the retcode
        // mode is chosen from direction semantics: client→device negotiation
        // frames (cmd 3/5) carry none; everything else uses the oracle
        // heuristic.
        let inbound_mode = match wire::parse_header(frame) {
            Ok(h) if h.cmd == cmd::SESS_KEY_NEG_START || h.cmd == cmd::SESS_KEY_NEG_FINISH => {
                wire::RetcodeMode::Absent
            }
            Ok(_) => wire::RetcodeMode::Auto,
            Err(_) => {
                self.events.push(SimEvent::MalformedInput);
                return Vec::new();
            }
        };
        let msg = match self.config.proto {
            Proto::V35 => match wire::unpack_6699_mode(frame, &self.config.local_key, inbound_mode) {
                Ok(m) => m,
                Err(_) => {
                    // A GCM failure under the device key outside negotiation
                    // is indistinguishable from a wrong key; inside an
                    // established session we retry under the session key.
                    match self.session.clone() {
                        Session::Established { key, seen } => {
                            match wire::unpack_6699_mode(frame, &key, inbound_mode) {
                                Ok(m) => {
                                    self.session = Session::Established { key, seen };
                                    m
                                }
                                Err(_) => {
                                    self.events.push(SimEvent::WrongKeyRejected);
                                    return Vec::new();
                                }
                            }
                        }
                        Session::AwaitingFinish { .. } | Session::None => {
                            self.events.push(SimEvent::WrongKeyRejected);
                            return Vec::new();
                        }
                    }
                }
            },
            Proto::V34 => {
                let key = match self.session {
                    Session::Established { key, .. } => key,
                    _ => self.config.local_key,
                };
                let no_retcode = inbound_mode == wire::RetcodeMode::Absent;
                match wire::unpack_55aa(frame, Some(&key), no_retcode) {
                    Ok(mut m) => {
                        match crypto::aes128_ecb_decrypt_pkcs7(&key, &m.payload) {
                            Some(pt) => {
                                m.payload = pt;
                                m
                            }
                            None => {
                                self.events.push(SimEvent::WrongKeyRejected);
                                return Vec::new();
                            }
                        }
                    }
                    Err(_) => {
                        self.events.push(SimEvent::MalformedInput);
                        return Vec::new();
                    }
                }
            }
        };

        match msg.cmd {
            cmd::SESS_KEY_NEG_START => self.on_neg_start(&msg),
            cmd::SESS_KEY_NEG_FINISH => self.on_neg_finish(&msg),
            cmd::HEART_BEAT => self.on_established(&msg, SimEvent::Heartbeat, cmd::HEART_BEAT, b""),
            c if c == cmd::DP_QUERY || c == cmd::DP_QUERY_NEW => {
                let json = self.config.model.dps_json().as_bytes().to_vec();
                self.on_established(&msg, SimEvent::DpsQuery, cmd::STATUS, &json)
            }
            c if c == cmd::CONTROL || c == cmd::CONTROL_NEW => {
                let echo = msg.payload.clone();
                self.on_established(&msg, SimEvent::ControlAcked, c, &echo)
            }
            _ => {
                self.events.push(SimEvent::MalformedInput);
                Vec::new()
            }
        }
    }

    fn on_neg_start(&mut self, msg: &wire::Message) -> Vec<Vec<u8>> {
        if msg.payload.len() != 16 {
            self.events.push(SimEvent::MalformedInput);
            return Vec::new();
        }
        let mut client_nonce = [0u8; 16];
        client_nonce.copy_from_slice(&msg.payload);
        let local_key = self.config.local_key;
        let device_nonce = self.next_device_nonce();
        let mut proof = Vec::with_capacity(48);
        proof.extend_from_slice(&device_nonce);
        proof.extend_from_slice(&crypto::hmac_sha256(&local_key, &client_nonce));
        let out = self.respond(cmd::SESS_KEY_NEG_RESP, &local_key, &proof);
        self.session = Session::AwaitingFinish {
            client_nonce,
            device_nonce,
        };
        self.events.push(SimEvent::NegotiationStarted);
        vec![out]
    }

    fn on_neg_finish(&mut self, msg: &wire::Message) -> Vec<Vec<u8>> {
        let (client_nonce, device_nonce) = match self.session {
            Session::AwaitingFinish {
                client_nonce,
                device_nonce,
            } => (client_nonce, device_nonce),
            _ => {
                self.events.push(SimEvent::MalformedInput);
                return Vec::new();
            }
        };
        let expect = crypto::hmac_sha256(&self.config.local_key, &device_nonce);
        if msg.payload != expect {
            self.session = Session::None;
            self.events.push(SimEvent::WrongKeyRejected);
            return Vec::new();
        }
        let key = match self.config.proto {
            Proto::V35 => wire::derive_session_key_35(&self.config.local_key, &client_nonce, &device_nonce),
            Proto::V34 => match wire::derive_session_key_34(
                &self.config.local_key,
                &client_nonce,
                &device_nonce,
            ) {
                Some(k) => k,
                None => {
                    self.events.push(SimEvent::MalformedInput);
                    return Vec::new();
                }
            },
        };
        self.session = Session::Established { key, seen: 0 };
        self.events.push(SimEvent::Negotiated);
        // The real device does not ACK the finish frame; the client
        // considers the session live once its proof was accepted.
        Vec::new()
    }

    /// Common path for session commands: expiry check, then respond.
    fn on_established(
        &mut self,
        _msg: &wire::Message,
        event: SimEvent,
        resp_cmd: u32,
        resp_payload: &[u8],
    ) -> Vec<Vec<u8>> {
        let (key, seen) = match self.session {
            Session::Established { key, seen } => (key, seen),
            _ => {
                // Session traffic without a session: the device ignores it.
                self.events.push(SimEvent::WrongKeyRejected);
                return Vec::new();
            }
        };
        let seen = seen + 1;
        if self.config.session_ttl_msgs > 0 && seen > self.config.session_ttl_msgs {
            self.session = Session::None;
            self.events.push(SimEvent::SessionExpired);
            return Vec::new();
        }
        self.session = Session::Established { key, seen };
        self.events.push(event);
        let out = self.respond(resp_cmd, &key, resp_payload);
        vec![out]
    }
}

