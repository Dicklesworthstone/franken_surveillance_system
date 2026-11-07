#![forbid(unsafe_code)]
//! Offline experiment only. This does not authenticate a device or authorize
//! provisioning. Its keys and traffic must be synthetic.

use std::{collections::VecDeque, fmt};

use super::{derive_key, existing_x25519, open_packet, pack_packet};

const DEFAULT_KEY: [u8; 32] = [
    0xa7, 0x81, 0xf8, 0xa4, 0xa6, 0x27, 0x37, 0x3b, 0x70, 0x74, 0x57, 0x38, 0xcd, 0xff, 0xdd, 0x1d,
    0xe9, 0xae, 0x35, 0x25, 0x17, 0xc3, 0x74, 0xca, 0x9a, 0xfc, 0x21, 0x5c, 0x39, 0xc6, 0x26, 0x37,
];
const AUTH: &[u8] = &[0x92, 0xa4, b'A', b'U', b'T', b'H', 0xa2, b'D', b'H'];
const MAX_EARLY_FRAMES: usize = 2;
const MAX_EARLY_BYTES: usize = 512;

/// The bounded host-side exchange state; none means authenticated identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No packet has been prepared.
    New,
    /// The public-key packet awaits a write outcome.
    PublicWrite,
    /// A device public key is expected.
    PeerPublic,
    /// A device AUTH packet is expected.
    PeerAuth,
    /// A host AUTH packet can be prepared.
    PrepareAuth,
    /// The host AUTH packet awaits a write outcome.
    AuthWrite,
    /// Both reference messages have completed; identity remains unverified.
    Ready,
    /// An API request packet awaits its transport write outcome.
    ApiWrite,
    /// A locally written API request awaits a matching response packet.
    AwaitApi,
    /// A MAC-checked, sequence-matched response awaits its owner.
    ResponseReady,
    /// Malformed input or an indeterminate write fenced this attempt.
    Fenced,
}

/// One outcome for an entire framed write, supplied by its transport owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// The entire framed packet was acknowledged locally.
    Written,
    /// No bytes were submitted; the same prepared packet may be retried.
    DefinitelyNotSubmitted,
    /// Some bytes or their acknowledgment may have been lost.
    Indeterminate,
}

/// Payload-free refusal. Failure never proves a camera's remote state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The requested operation is not valid in the current phase.
    Phase,
    /// The peer frame was malformed, failed authentication, or was out of order.
    Frame,
    /// A bounded early-frame queue or allocation could not accept more data.
    Limit,
    /// A peer frame arrived despite a claim that no bytes were submitted.
    ConflictingWriteOutcome,
    /// The attempt is fenced and cannot be resumed.
    Fenced,
}

/// Host-only synthetic key exchange. Never format or log keys or frame bytes.
pub struct Handshake {
    private: [u8; 32],
    derived: Option<[u8; 32]>,
    phase: Phase,
    pending: Option<Vec<u8>>,
    early: VecDeque<Vec<u8>>,
    early_bytes: usize,
    next_api_send: u32,
    next_api_receive: u32,
    response: Option<Vec<u8>>,
    outstanding_request: Option<Vec<u8>>,
}

impl fmt::Debug for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handshake")
            .field("phase", &self.phase)
            .field("has_pending", &self.pending.is_some())
            .field("early_frames", &self.early.len())
            .finish_non_exhaustive()
    }
}

impl Handshake {
    /// Supply a synthetic private scalar. No entropy or identity is established.
    pub fn new(private: [u8; 32]) -> Self {
        Self {
            private,
            derived: None,
            phase: Phase::New,
            pending: None,
            early: VecDeque::new(),
            early_bytes: 0,
            next_api_send: 2,
            next_api_receive: 2,
            response: None,
            outstanding_request: None,
        }
    }

    /// Current local phase, not proof of remote device state.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// A pending ciphertext frame, including an indeterminate one for reconciliation.
    pub fn pending_frame(&self) -> Option<&[u8]> {
        self.pending.as_deref()
    }

    /// A locally written API request retained until its response is taken.
    pub fn outstanding_request(&self) -> Option<&[u8]> {
        self.outstanding_request.as_deref()
    }

    /// Prepare the synthetic host's public-key frame once.
    pub fn prepare_public(&mut self) -> Result<&[u8], Error> {
        if self.phase != Phase::New {
            return Err(Error::Phase);
        }
        let public = existing_x25519::x25519_base(&self.private);
        let mut msg = Vec::from([0x93, 0xa4, b'D', b'H', b'P', b'K', 0xc2, 0xc4, 0x20]);
        msg.extend_from_slice(&public);
        self.pending = Some(pack_packet(&DEFAULT_KEY, 0, 0, &msg).ok_or(Error::Limit)?);
        self.phase = Phase::PublicWrite;
        self.pending_frame().ok_or(Error::Phase)
    }

    /// Prepare the host AUTH frame under the default key after peer AUTH.
    pub fn prepare_auth(&mut self) -> Result<&[u8], Error> {
        if self.phase != Phase::PrepareAuth {
            return Err(Error::Phase);
        }
        self.pending = Some(pack_packet(&DEFAULT_KEY, 1, 0, AUTH).ok_or(Error::Limit)?);
        self.phase = Phase::AuthWrite;
        self.pending_frame().ok_or(Error::Phase)
    }

    /// Prepare a single synthetic API request after the key exchange. A new
    /// request cannot overtake an unconsumed response or a retained early frame.
    /// No authority to configure a camera or to handle real secrets is granted.
    pub fn prepare_synthetic_api(&mut self, payload: &[u8]) -> Result<&[u8], Error> {
        if self.phase != Phase::Ready || !self.early.is_empty() {
            return Err(Error::Phase);
        }
        if self.next_api_send != self.next_api_receive {
            self.phase = Phase::Fenced;
            return Err(Error::Frame);
        }
        let Ok(sequence) = u16::try_from(self.next_api_send) else {
            self.phase = Phase::Fenced;
            return Err(Error::Limit);
        };
        let key = self.derived.as_ref().ok_or(Error::Phase)?;
        self.pending = Some(pack_packet(key, sequence, 3, payload).ok_or(Error::Limit)?);
        self.phase = Phase::ApiWrite;
        self.pending_frame().ok_or(Error::Phase)
    }

    /// Resolve the pending write. Acknowledgment is not device acceptance.
    pub fn resolve_write(&mut self, outcome: WriteOutcome) -> Result<(), Error> {
        if self.phase == Phase::Fenced {
            return Err(Error::Fenced);
        }
        if !matches!(
            self.phase,
            Phase::PublicWrite | Phase::AuthWrite | Phase::ApiWrite
        ) {
            return Err(Error::Phase);
        }
        match outcome {
            WriteOutcome::Indeterminate => {
                self.phase = Phase::Fenced;
                return Err(Error::Fenced);
            }
            WriteOutcome::DefinitelyNotSubmitted if !self.early.is_empty() => {
                self.phase = Phase::Fenced;
                return Err(Error::ConflictingWriteOutcome);
            }
            WriteOutcome::DefinitelyNotSubmitted => return Ok(()),
            WriteOutcome::Written => (),
        }
        self.phase = match self.phase {
            Phase::PublicWrite => {
                self.pending = None;
                Phase::PeerPublic
            }
            Phase::AuthWrite => {
                self.pending = None;
                Phase::Ready
            }
            Phase::ApiWrite => {
                let Some(frame) = self.pending.take() else {
                    self.phase = Phase::Fenced;
                    return Err(Error::Phase);
                };
                self.outstanding_request = Some(frame);
                self.next_api_send += 1;
                Phase::AwaitApi
            }
            _ => return Err(Error::Phase),
        };
        while matches!(
            self.phase,
            Phase::PeerPublic | Phase::PeerAuth | Phase::AwaitApi
        ) {
            let Some(frame) = self.early.pop_front() else {
                break;
            };
            self.early_bytes -= frame.len();
            if self.phase == Phase::AwaitApi {
                self.process_api(&frame)?;
            } else {
                self.process_auth(&frame)?;
            }
        }
        Ok(())
    }

    /// Offer one complete frame. Frames arriving during a pending write are
    /// retained in a bounded queue, since a notification may precede its write
    /// acknowledgment. This function never performs BLE I/O.
    pub fn offer(&mut self, frame: &[u8]) -> Result<(), Error> {
        match self.phase {
            Phase::Fenced => Err(Error::Fenced),
            Phase::PublicWrite | Phase::AuthWrite | Phase::ApiWrite => {
                if frame.len() < 2
                    || usize::from(u16::from_be_bytes([frame[0], frame[1]])) != frame.len()
                    || self.early.len() == MAX_EARLY_FRAMES
                    || frame.len() > MAX_EARLY_BYTES.saturating_sub(self.early_bytes)
                {
                    self.phase = Phase::Fenced;
                    return Err(Error::Limit);
                }
                let mut copy = Vec::new();
                if copy.try_reserve_exact(frame.len()).is_err()
                    || self.early.try_reserve(1).is_err()
                {
                    self.phase = Phase::Fenced;
                    return Err(Error::Limit);
                }
                copy.extend_from_slice(frame);
                self.early_bytes += frame.len();
                self.early.push_back(copy);
                Ok(())
            }
            Phase::PeerPublic | Phase::PeerAuth => self.process_auth(frame),
            Phase::AwaitApi => self.process_api(frame),
            _ => Err(Error::Phase),
        }
    }

    fn process_auth(&mut self, frame: &[u8]) -> Result<(), Error> {
        let (sequence, expected) = match self.phase {
            Phase::PeerPublic => (0, Phase::PeerPublic),
            Phase::PeerAuth => (1, Phase::PeerAuth),
            _ => return Err(Error::Phase),
        };
        let Some(msg) = open_packet(&DEFAULT_KEY, sequence, 0, frame) else {
            self.phase = Phase::Fenced;
            return Err(Error::Frame);
        };
        if expected == Phase::PeerPublic {
            if msg.len() != 41
                || msg[..6] != [0x93, 0xa4, b'D', b'H', b'P', b'K']
                || !matches!(msg[6], 0xc2 | 0xc3)
                || msg[7..9] != [0xc4, 0x20]
            {
                self.phase = Phase::Fenced;
                return Err(Error::Frame);
            }
            let mut peer = [0; 32];
            peer.copy_from_slice(&msg[9..]);
            let Some(key) = derive_key(&self.private, &peer, None) else {
                self.phase = Phase::Fenced;
                return Err(Error::Frame);
            };
            self.derived = Some(key);
            self.phase = Phase::PeerAuth;
        } else if msg == AUTH {
            self.phase = Phase::PrepareAuth;
        } else {
            self.phase = Phase::Fenced;
            return Err(Error::Frame);
        }
        Ok(())
    }

    /// Take a frame which arrived while the final write was pending. Its owner
    /// still has to parse, authenticate and correlate the subsequent API data.
    pub fn take_early_ready(&mut self) -> Option<Vec<u8>> {
        if self.phase != Phase::Ready {
            return None;
        }
        let frame = self.early.pop_front()?;
        self.early_bytes -= frame.len();
        Some(frame)
    }

    fn process_api(&mut self, frame: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::AwaitApi || self.next_api_send != self.next_api_receive + 1 {
            self.phase = Phase::Fenced;
            return Err(Error::Frame);
        }
        let Ok(sequence) = u16::try_from(self.next_api_receive) else {
            self.phase = Phase::Fenced;
            return Err(Error::Limit);
        };
        let Some(key) = self.derived.as_ref() else {
            self.phase = Phase::Fenced;
            return Err(Error::Phase);
        };
        // The legacy wire profile reuses directional keys and nonces. Reject a
        // byte-for-byte reflection of our request; this does not make the
        // protocol cryptographically authenticated or resistant to forgery.
        if self.outstanding_request.as_deref() == Some(frame) {
            self.phase = Phase::Fenced;
            return Err(Error::Frame);
        }
        let Some(plaintext) = open_packet(key, sequence, 3, frame) else {
            self.phase = Phase::Fenced;
            return Err(Error::Frame);
        };
        self.next_api_receive += 1;
        self.response = Some(plaintext);
        self.phase = Phase::ResponseReady;
        Ok(())
    }

    /// Take the matched response. Its inner API status and device state remain
    /// untrusted and require separate parsing and reconciliation.
    pub fn take_synthetic_response(&mut self) -> Option<Vec<u8>> {
        if self.phase != Phase::ResponseReady {
            return None;
        }
        let response = self.response.take()?;
        self.outstanding_request = None;
        self.phase = Phase::Ready;
        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
    fn host() -> Result<Vec<u8>, std::num::ParseIntError> {
        unhex(
            "003e4e95e6b90ee828d1c417fc03c78a3142c830c5e8b6b487b37433f1dc35db56cc5957aaf3aa32a7d8c10965883f6e3d678a599cf70bc2a3e4c04ebdaf",
        )
    }
    fn peer() -> Result<Vec<u8>, std::num::ParseIntError> {
        unhex(
            "003ed885a85aaedb0eca92f43fc1140e7d97c830c5e8b6b487b37432f1dc8f1be1b7d9800f404e3d2756f4ee3edece7252db15acf998331d1c082c60f7a4",
        )
    }
    fn auth() -> Result<Vec<u8>, std::num::ParseIntError> {
        unhex("001ea9f8d0fae89980d5e2b2197f684085e840a219f803f07a7ed1e20ca4")
    }
    fn api() -> Result<Vec<u8>, std::num::ParseIntError> {
        unhex("001e2f7bdd0bf21fecde1e19e32419a7f6b37c23ad7cbe66c1a2db3a31ae")
    }
    fn response() -> Result<Vec<u8>, std::num::ParseIntError> {
        unhex("001d0d1900c1c8978614d3c4ceec2ff143d27c23ad7da27bc5a5d03d3d")
    }
    fn private() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn reference_transcript_and_early_notifications() -> Result<(), Box<dyn std::error::Error>> {
        let (peer, auth, api) = (peer()?, auth()?, api()?);
        let mut h = Handshake::new(private());
        assert_eq!(h.prepare_public().map_err(|e| format!("{e:?}"))?, host()?);
        // The peer can notify twice before the characteristic write returns.
        assert_eq!(h.offer(&peer), Ok(()));
        assert_eq!(h.offer(&auth), Ok(()));
        assert_eq!(h.resolve_write(WriteOutcome::Written), Ok(()));
        assert_eq!(h.phase(), Phase::PrepareAuth);
        assert_eq!(h.prepare_auth().map_err(|e| format!("{e:?}"))?, auth);
        assert_eq!(h.offer(&api), Ok(()));
        assert_eq!(h.resolve_write(WriteOutcome::Written), Ok(()));
        assert_eq!(h.phase(), Phase::Ready);
        assert_eq!(h.prepare_synthetic_api(b"synthetic"), Err(Error::Phase));
        let retained = h.take_early_ready().ok_or("missing queued API packet")?;
        assert_eq!(retained, api);
        assert_eq!(
            h.prepare_synthetic_api(b"synthetic")
                .map_err(|e| format!("{e:?}"))?,
            api
        );
        // A response may arrive before its write acknowledgment as well.
        assert_eq!(h.offer(&response()?), Ok(()));
        assert_eq!(h.resolve_write(WriteOutcome::Written), Ok(()));
        assert_eq!(h.outstanding_request(), Some(api.as_slice()));
        assert_eq!(h.take_synthetic_response(), Some(b"response".to_vec()));
        assert!(h.outstanding_request().is_none());
        h.prepare_synthetic_api(b"next")
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(h.resolve_write(WriteOutcome::Written), Ok(()));
        assert_eq!(h.offer(&retained), Err(Error::Frame));
        assert_eq!(h.phase(), Phase::Fenced);
        Ok(())
    }

    #[test]
    fn uncertain_write_fences_but_preserves_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
        let mut h = Handshake::new(private());
        let original = h.prepare_public().map_err(|e| format!("{e:?}"))?.to_vec();
        assert_eq!(
            h.resolve_write(WriteOutcome::DefinitelyNotSubmitted),
            Ok(())
        );
        assert_eq!(h.pending_frame(), Some(original.as_slice()));
        assert_eq!(
            h.resolve_write(WriteOutcome::Indeterminate),
            Err(Error::Fenced)
        );
        assert_eq!(h.pending_frame(), Some(original.as_slice()));
        assert_eq!(h.resolve_write(WriteOutcome::Written), Err(Error::Fenced));
        Ok(())
    }

    #[test]
    fn malformed_or_conflicting_early_frames_fence() -> Result<(), Box<dyn std::error::Error>> {
        let mut h = Handshake::new(private());
        h.prepare_public().map_err(|e| format!("{e:?}"))?;
        h.offer(&peer()?).map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            h.resolve_write(WriteOutcome::DefinitelyNotSubmitted),
            Err(Error::ConflictingWriteOutcome)
        );
        assert_eq!(h.phase(), Phase::Fenced);
        let mut other = Handshake::new(private());
        other.prepare_public().map_err(|e| format!("{e:?}"))?;
        other
            .resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        let mut bad = peer()?;
        bad[8] ^= 1;
        assert_eq!(other.offer(&bad), Err(Error::Frame));
        assert_eq!(other.phase(), Phase::Fenced);
        Ok(())
    }

    #[test]
    fn early_queue_is_bounded_and_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut h = Handshake::new(private());
        h.prepare_public().map_err(|e| format!("{e:?}"))?;
        let frame = peer()?;
        assert_eq!(h.offer(&frame), Ok(()));
        assert_eq!(h.offer(&frame), Ok(()));
        assert_eq!(h.offer(&frame), Err(Error::Limit));
        assert_eq!(h.phase(), Phase::Fenced);
        Ok(())
    }

    #[test]
    fn invalid_public_key_fences_before_auth() -> Result<(), Box<dyn std::error::Error>> {
        let mut h = Handshake::new(private());
        h.prepare_public().map_err(|e| format!("{e:?}"))?;
        h.resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        let mut msg = vec![0x93, 0xa4, b'D', b'H', b'P', b'K', 0xc2, 0xc4, 0x20];
        msg.extend_from_slice(&[0; 32]);
        let frame = pack_packet(&DEFAULT_KEY, 0, 0, &msg).ok_or("frame")?;
        assert_eq!(h.offer(&frame), Err(Error::Frame));
        assert_eq!(h.phase(), Phase::Fenced);
        assert_eq!(h.prepare_auth(), Err(Error::Phase));
        Ok(())
    }

    #[test]
    fn receive_sequence_exhaustion_fences_without_wrap() -> Result<(), Box<dyn std::error::Error>> {
        let mut h = Handshake::new(private());
        h.prepare_public().map_err(|e| format!("{e:?}"))?;
        h.resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        h.offer(&peer()?).map_err(|e| format!("{e:?}"))?;
        h.offer(&auth()?).map_err(|e| format!("{e:?}"))?;
        h.prepare_auth().map_err(|e| format!("{e:?}"))?;
        h.resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        h.next_api_send = u32::from(u16::MAX);
        h.next_api_receive = u32::from(u16::MAX);
        let request = pack_packet(
            h.derived.as_ref().ok_or("missing key")?,
            u16::MAX,
            3,
            b"last",
        )
        .ok_or("frame")?;
        let response = pack_packet(
            h.derived.as_ref().ok_or("missing key")?,
            u16::MAX,
            3,
            b"last-response",
        )
        .ok_or("response")?;
        assert_eq!(
            h.prepare_synthetic_api(b"last")
                .map_err(|e| format!("{e:?}"))?,
            request
        );
        assert_eq!(h.resolve_write(WriteOutcome::Written), Ok(()));
        assert_eq!(h.offer(&response), Ok(()));
        assert_eq!(h.take_synthetic_response(), Some(b"last-response".to_vec()));
        assert_eq!(h.prepare_synthetic_api(b"wrap"), Err(Error::Limit));
        assert_eq!(h.phase(), Phase::Fenced);
        Ok(())
    }

    #[test]
    fn reflected_request_fences_even_when_mac_and_sequence_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut h = Handshake::new(private());
        h.prepare_public().map_err(|e| format!("{e:?}"))?;
        h.resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        h.offer(&peer()?).map_err(|e| format!("{e:?}"))?;
        h.offer(&auth()?).map_err(|e| format!("{e:?}"))?;
        h.prepare_auth().map_err(|e| format!("{e:?}"))?;
        h.resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        let request = h
            .prepare_synthetic_api(b"synthetic")
            .map_err(|e| format!("{e:?}"))?
            .to_vec();
        h.resolve_write(WriteOutcome::Written)
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(h.offer(&request), Err(Error::Frame));
        assert_eq!(h.outstanding_request(), Some(request.as_slice()));
        assert_eq!(h.phase(), Phase::Fenced);
        Ok(())
    }
}
