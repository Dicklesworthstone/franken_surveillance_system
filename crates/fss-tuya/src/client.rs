//! Sans-IO Tuya LAN client core (LAB-AOSU-5, bead fss-x4a.21.3.5): the
//! client side of the 3.4/3.5 session — negotiation, heartbeat, dp_query,
//! control — as an explicit state machine over bytes. No sockets, no clock,
//! no randomness of its own: nonces and IVs are supplied by the caller
//! (production adapters MUST supply a fresh cryptographic nonce per
//! negotiation and a fresh 12-byte IV per frame; the tests use fixed
//! fixtures for determinism).
//!
//! The state machine is deliberately small and total: negotiation is an
//! explicit two-step exchange (`start_session` → `negotiate_finish`), and
//! every other inbound frame either decodes to an [`Inbound`] or is a typed
//! error. It never panics, never blocks, and never retries on its own —
//! transport concerns stay with the caller.
//!
//! Provenance: mirrored against the tinytuya laboratory oracle and
//! differentially exercised against [`crate::sim::HomebaseSim`] in
//! `tests/client_sim_contract.rs` (the simulator is the development test
//! harness per INTEROPERABILITY_LAB §5; the owned-device differential
//! comparison lands with LAB-AOSU-2 once the owner extracts the local_key).

use crate::crypto;
use crate::wire::{self, cmd};

/// Protocol generation to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// 3.4: 55AA frames, HMAC trailer, AES-128-ECB-PKCS7 payloads.
    V34,
    /// 3.5: 6699 frames, AES-128-GCM payloads.
    V35,
}

/// Typed client errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Frame failed to parse or authenticate.
    Wire(wire::WireError),
    /// Frame arrived in a state that cannot consume it.
    UnexpectedFrame {
        /// What the client was doing.
        state: &'static str,
        /// The command word received.
        cmd: u32,
    },
    /// The device's key proof did not verify (wrong key or hostile peer).
    DeviceProofInvalid,
    /// The session is not (or no longer) established.
    NoSession,
    /// `negotiate_finish` called without a pending negotiation.
    NoPendingNegotiation,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Wire(e) => write!(f, "wire: {e}"),
            ClientError::UnexpectedFrame { state, cmd } => {
                write!(f, "unexpected cmd 0x{cmd:02x} while {state}")
            }
            ClientError::DeviceProofInvalid => write!(f, "device key proof invalid"),
            ClientError::NoSession => write!(f, "no established session"),
            ClientError::NoPendingNegotiation => write!(f, "no pending negotiation"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<wire::WireError> for ClientError {
    fn from(e: wire::WireError) -> Self {
        ClientError::Wire(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    AwaitingNegResp { client_nonce: [u8; 16] },
    Established { session_key: [u8; 16] },
}

/// One decoded inbound session frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// Command word.
    pub cmd: u32,
    /// Decrypted payload (dps JSON for STATUS responses).
    pub payload: Vec<u8>,
    /// Device return code where present.
    pub retcode: Option<u32>,
}

/// The sans-IO client. One instance per device session channel.
pub struct TuyaClient {
    local_key: [u8; 16],
    proto: Proto,
    state: State,
    seq: u32,
}

impl TuyaClient {
    /// Creates a client for one owner-authorized device. `local_key` is the
    /// owner-provisioned device key (LAB-AOSU-1 territory).
    #[must_use]
    pub fn new(local_key: [u8; 16], proto: Proto) -> Self {
        Self {
            local_key,
            proto,
            state: State::Idle,
            seq: 0,
        }
    }

    /// Whether a session is established.
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Established { .. })
    }

    /// Drops the session (device reboot, transport error, explicit close).
    pub fn reset(&mut self) {
        self.state = State::Idle;
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn pack(
        &mut self,
        cmd_word: u32,
        key: &[u8; 16],
        plaintext: &[u8],
        iv: [u8; 12],
    ) -> Vec<u8> {
        let seq = self.next_seq();
        match self.proto {
            Proto::V35 => wire::pack_6699(seq, cmd_word, None, plaintext, key, iv),
            Proto::V34 => {
                let sealed = crypto::aes128_ecb_encrypt_pkcs7(key, plaintext);
                wire::pack_55aa(seq, cmd_word, None, &sealed, Some(key))
            }
        }
    }

    fn session_key(&self) -> Result<[u8; 16], ClientError> {
        match self.state {
            State::Established { session_key } => Ok(session_key),
            _ => Err(ClientError::NoSession),
        }
    }

    /// Begins session negotiation: emits the cmd-3 frame carrying
    /// `client_nonce` (caller-supplied, MUST be fresh per negotiation).
    /// Invalidates any previous session.
    pub fn start_session(&mut self, client_nonce: [u8; 16], iv: [u8; 12]) -> Vec<u8> {
        self.state = State::AwaitingNegResp { client_nonce };
        let key = self.local_key;
        self.pack(cmd::SESS_KEY_NEG_START, &key, &client_nonce, iv)
    }

    /// Completes negotiation: consumes the device's cmd-4 response, verifies
    /// the device key proof, derives the session key, and returns the cmd-5
    /// finish frame to send. The device does not ACK the finish frame; the
    /// session is live once this returns `Ok`.
    pub fn negotiate_finish(
        &mut self,
        resp_frame: &[u8],
        iv: [u8; 12],
    ) -> Result<Vec<u8>, ClientError> {
        let client_nonce = match self.state {
            State::AwaitingNegResp { client_nonce } => client_nonce,
            _ => return Err(ClientError::NoPendingNegotiation),
        };
        let key = self.local_key;
        let msg = match self.proto {
            Proto::V35 => wire::unpack_6699_mode(resp_frame, &key, wire::RetcodeMode::Present)?,
            Proto::V34 => {
                let mut m = wire::unpack_55aa(resp_frame, Some(&key), false)?;
                m.payload = crypto::aes128_ecb_decrypt_pkcs7(&key, &m.payload)
                    .ok_or(wire::WireError::GcmAuth)?;
                m
            }
        };
        if msg.cmd != cmd::SESS_KEY_NEG_RESP {
            return Err(ClientError::UnexpectedFrame {
                state: "awaiting negotiation response",
                cmd: msg.cmd,
            });
        }
        if msg.payload.len() != 48 {
            self.state = State::Idle;
            return Err(ClientError::DeviceProofInvalid);
        }
        let device_nonce: [u8; 16] = match msg.payload[..16].try_into() {
            Ok(n) => n,
            Err(_) => {
                self.state = State::Idle;
                return Err(ClientError::DeviceProofInvalid);
            }
        };
        let proof = &msg.payload[16..];
        if proof != crypto::hmac_sha256(&self.local_key, &client_nonce) {
            self.state = State::Idle;
            return Err(ClientError::DeviceProofInvalid);
        }
        let session_key = match self.proto {
            Proto::V35 => wire::derive_session_key_35(&self.local_key, &client_nonce, &device_nonce),
            Proto::V34 => {
                match wire::derive_session_key_34(&self.local_key, &client_nonce, &device_nonce) {
                    Some(k) => k,
                    None => return Err(ClientError::Wire(wire::WireError::ShortBody)),
                }
            }
        };
        let finish = crypto::hmac_sha256(&self.local_key, &device_nonce);
        let frame = self.pack(cmd::SESS_KEY_NEG_FINISH, &key, &finish, iv);
        self.state = State::Established { session_key };
        Ok(frame)
    }

    /// Emits a heartbeat frame; `Err(NoSession)` without a session.
    pub fn heartbeat(&mut self, iv: [u8; 12]) -> Result<Vec<u8>, ClientError> {
        let key = self.session_key()?;
        Ok(self.pack(cmd::HEART_BEAT, &key, b"", iv))
    }

    /// Emits a dp_query frame.
    pub fn dp_query(&mut self, iv: [u8; 12]) -> Result<Vec<u8>, ClientError> {
        let key = self.session_key()?;
        Ok(self.pack(cmd::DP_QUERY, &key, b"", iv))
    }

    /// Emits a control frame writing the given dps JSON payload.
    pub fn control(&mut self, dps_json: &[u8], iv: [u8; 12]) -> Result<Vec<u8>, ClientError> {
        let key = self.session_key()?;
        Ok(self.pack(cmd::CONTROL, &key, dps_json, iv))
    }

    /// Consumes one inbound session-traffic frame (heartbeats, status
    /// reports, control ACKs, unsolicited event reports). Negotiation
    /// responses belong to [`TuyaClient::negotiate_finish`]; passing one
    /// here is an [`ClientError::UnexpectedFrame`].
    pub fn handle(&mut self, frame: &[u8]) -> Result<Inbound, ClientError> {
        let session_key = self.session_key()?;
        let msg = match self.proto {
            Proto::V35 => wire::unpack_6699(frame, &session_key)?,
            Proto::V34 => {
                let mut m = wire::unpack_55aa(frame, Some(&session_key), false)?;
                m.payload = crypto::aes128_ecb_decrypt_pkcs7(&session_key, &m.payload)
                    .ok_or(wire::WireError::GcmAuth)?;
                m
            }
        };
        match msg.cmd {
            cmd::SESS_KEY_NEG_RESP | cmd::SESS_KEY_NEG_START | cmd::SESS_KEY_NEG_FINISH => {
                Err(ClientError::UnexpectedFrame {
                    state: "established",
                    cmd: msg.cmd,
                })
            }
            _ => Ok(Inbound {
                cmd: msg.cmd,
                payload: msg.payload,
                retcode: msg.retcode,
            }),
        }
    }
}
