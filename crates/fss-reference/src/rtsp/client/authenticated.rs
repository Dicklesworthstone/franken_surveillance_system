#![forbid(unsafe_code)]
//! Opt-in Digest lifecycle on the existing scoped RTSP session.

use super::*;
use crate::rtsp::authentication::{
    AuthenticationError, DigestChallenge, DigestCredentials, DigestPolicy, MAX_AUTHORIZATION_BYTES,
    MAX_CHALLENGE_BYTES,
};
use crate::rtsp::{RtspEvent, RtspLimits, RtspParser};
use std::fmt::Write as _;

/// Session versus credential/protocol refusal, without wire text or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestClientError {
    /// Existing request scope, correlation, lifecycle, or timer failure.
    Session(ClientError),
    /// Authentication policy, challenge, retry, or bounded-allocation refusal.
    Authentication(AuthenticationError),
}
impl From<ClientError> for DigestClientError {
    fn from(e: ClientError) -> Self {
        Self::Session(e)
    }
}
impl From<AuthenticationError> for DigestClientError {
    fn from(e: AuthenticationError) -> Self {
        Self::Authentication(e)
    }
}
impl fmt::Display for DigestClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP Digest client refusal: {self:?}")
    }
}
impl std::error::Error for DigestClientError {}
type Result<T> = std::result::Result<T, DigestClientError>;

/// One connection's bounded credential context. Passwords and HA1 keys are not stored.
/// Request templates contain session/URI information and are never Debug-printed.
pub(super) struct DigestState {
    realm: String,
    policy: DigestPolicy,
    challenge: Option<DigestChallenge>,
    nonce_count: u32,
    attempts: u8,
    template: String,
    // Prevent a server from cycling a retired nonce and resetting its counter.
    used_nonces: Vec<DigestChallenge>,
}
impl DigestState {
    pub(super) fn settled(&mut self) {
        self.template.clear();
        self.attempts = 0;
    }
    fn request(
        &mut self,
        session: &mut RtspClientSession,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<ClientRequest> {
        session.tick(now)?;
        if session.pending.is_some() {
            return Err(ClientError::State.into());
        }
        let (method, uri) = target(session, command);
        // An unnegotiated target (e.g. premature SETUP) must not receive credentials.
        scoped(&session.config, uri)?;
        let counter = self
            .nonce_count
            .checked_add(1)
            .ok_or(AuthenticationError::Replay)?;
        let authorization = self
            .challenge
            .as_ref()
            .map(|c| c.authorize(method, uri, credentials, cnonce, counter))
            .transpose()?;
        let mut signed = String::new();
        signed
            .try_reserve_exact(MAX_URI + 512 + MAX_AUTHORIZATION_BYTES + 32)
            .map_err(|_| AuthenticationError::Capacity)?;
        let unsigned = session.unsigned_request(command, now)?;
        // All fallible preparation preceded unsigned_request's state transition.
        signed.push_str(&unsigned.bytes[..unsigned.bytes.len() - 2]);
        if let Some(value) = &authorization {
            signed.push_str("Authorization: ");
            signed.push_str(value.expose());
            signed.push_str("\r\n");
        }
        signed.push_str("\r\n");
        self.template = unsigned.bytes;
        self.attempts = u8::from(authorization.is_some());
        if authorization.is_some() {
            self.nonce_count = counter;
        }
        Ok(ClientRequest {
            command,
            cseq: unsigned.cseq,
            bytes: signed,
        })
    }
    fn retry(
        &mut self,
        session: &mut RtspClientSession,
        wire: &[u8],
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<ClientRequest> {
        let pending = session.pending.ok_or(ClientError::State)?;
        let (response, challenge_value) = challenge_response(wire)?;
        bounded_response(&response)?;
        let cseq = decimal(singleton(&response.headers, "CSeq")?.ok_or(ClientError::Response)?)?;
        if cseq != u64::from(pending.cseq) {
            return Err(ClientError::CseqMismatch.into());
        }
        session.tick(now)?;
        if self.template.is_empty() {
            return Err(AuthenticationError::State.into());
        }
        if self.attempts >= 2 {
            return Err(AuthenticationError::RetryLimit.into());
        }
        if let Some(value) = singleton(&response.headers, "Session")? {
            let (id, _) = super::session(value, session.timeout_ns)?;
            if session.session_id.as_deref() != Some(id) {
                return Err(ClientError::Session.into());
            }
        }
        let challenge = DigestChallenge::parse(challenge_value, &self.realm, self.policy)?;
        if self.attempts != 0 {
            let previous = self.challenge.as_ref().ok_or(AuthenticationError::State)?;
            if !challenge.stale()
                || challenge.same_nonce(previous)
                || !challenge.no_weaker_than(previous)
            {
                return Err(AuthenticationError::Replay.into());
            }
        }
        if self.used_nonces.iter().any(|old| challenge.same_nonce(old)) {
            return Err(AuthenticationError::Replay.into());
        }
        if self.used_nonces.len() + usize::from(self.challenge.is_some()) >= 16 {
            return Err(AuthenticationError::Capacity.into());
        }
        self.used_nonces
            .try_reserve_exact(1)
            .map_err(|_| AuthenticationError::Capacity)?;
        let (method, uri) = target(session, pending.command);
        scoped(&session.config, uri)?;
        let authorization = challenge.authorize(method, uri, credentials, cnonce, 1)?;
        let new_cseq = session.next_cseq;
        let next = new_cseq.checked_add(1).ok_or(ClientError::Exhausted)?;
        // Use the exact first request's method/target/session/transport fields.
        // Only correlation and Authorization change, not any server-directed URL.
        let (start, rest) = self
            .template
            .split_once("\r\nCSeq: ")
            .ok_or(AuthenticationError::State)?;
        let (_, remaining) = rest.split_once("\r\n").ok_or(AuthenticationError::State)?;
        let mut template = String::new();
        template
            .try_reserve_exact(MAX_URI + 512)
            .map_err(|_| AuthenticationError::Capacity)?;
        write!(&mut template, "{start}\r\nCSeq: {new_cseq}\r\n{remaining}")
            .map_err(|_| AuthenticationError::Capacity)?;
        let mut signed = String::new();
        signed
            .try_reserve_exact(MAX_URI + 512 + MAX_AUTHORIZATION_BYTES + 32)
            .map_err(|_| AuthenticationError::Capacity)?;
        signed.push_str(&template[..template.len() - 2]);
        signed.push_str("Authorization: ");
        signed.push_str(authorization.expose());
        signed.push_str("\r\n\r\n");
        session.next_cseq = next;
        // Keep ORIGINAL send time and absolute deadline: challenge/stale loops
        // cannot extend either request lifetime or conservative session lifetime.
        session.pending = Some(Pending {
            cseq: new_cseq,
            ..pending
        });
        if let Some(previous) = self.challenge.replace(challenge) {
            self.used_nonces.push(previous);
        }
        self.nonce_count = 1;
        self.attempts += 1;
        self.template = template;
        Ok(ClientRequest {
            command: pending.command,
            cseq: new_cseq,
            bytes: signed,
        })
    }
}

impl RtspClientSession {
    /// Pin the realm/policy before this connection's first request. The server's
    /// domain directive cannot broaden the already validated owner URI subtree.
    /// Existing unauthenticated construction/behavior remains unchanged.
    pub fn enable_digest(&mut self, realm: &str, policy: DigestPolicy) -> Result<()> {
        if self.state != ClientState::Idle
            || self.pending.is_some()
            || self.next_cseq != 1
            || self.digest.is_some()
        {
            return Err(ClientError::State.into());
        }
        if realm.len() > 512 || !realm.bytes().all(|b| (32..127).contains(&b)) {
            return Err(AuthenticationError::Realm.into());
        }
        let mut pinned = String::new();
        pinned
            .try_reserve_exact(realm.len())
            .map_err(|_| AuthenticationError::Capacity)?;
        pinned.push_str(realm);
        self.digest = Some(DigestState {
            realm: pinned,
            policy,
            challenge: None,
            nonce_count: 0,
            attempts: 0,
            template: String::new(),
            used_nonces: Vec::new(),
        });
        Ok(())
    }
    /// Prepare a scoped request, signing when a challenge was accepted. The first
    /// request is unsigned. Credentials are borrowed for this call only. Supply
    /// fresh cnonce entropy; no password, HA1, or authorization template is cached.
    pub fn request_digest(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<ClientRequest> {
        let mut state = self.digest.take().ok_or(AuthenticationError::State)?;
        let result = state.request(self, command, credentials, cnonce, now);
        self.digest = Some(state);
        result
    }
    /// Consume one EXACT complete original 401 response, instead of passing it to
    /// `accept`. Matching challenge retries get a fresh CSeq and the original
    /// deadline. One additional changed stale nonce is permitted, never an
    /// unbounded wrong-password loop. Refused bytes remain caller-owned.
    /// The owner must not also feed this response to the ordinary parser/client.
    pub fn retry_digest_response(
        &mut self,
        response: &[u8],
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<ClientRequest> {
        let mut state = self.digest.take().ok_or(AuthenticationError::State)?;
        let result = state.retry(self, response, credentials, cnonce, now);
        self.digest = Some(state);
        result
    }
}

fn target(session: &RtspClientSession, command: ClientCommand) -> (&'static str, &str) {
    match command {
        ClientCommand::Options => ("OPTIONS", &session.config.presentation_uri),
        ClientCommand::Describe => ("DESCRIBE", &session.config.presentation_uri),
        ClientCommand::Setup => ("SETUP", &session.track_uri),
        ClientCommand::Play => ("PLAY", &session.aggregate_uri),
        ClientCommand::KeepAlive => ("OPTIONS", &session.aggregate_uri),
        ClientCommand::Teardown => ("TEARDOWN", &session.aggregate_uri),
    }
}
fn challenge_response(wire: &[u8]) -> Result<(RtspResponse, &str)> {
    // Bounded complete response only. Parser owns framing and body length; this
    // adapter reads just the original header that the public parser redacts.
    if wire.len() > 135_168 {
        return Err(AuthenticationError::Capacity.into());
    }
    let end = wire
        .windows(4)
        .position(|s| s == b"\r\n\r\n")
        .ok_or(AuthenticationError::Response)?;
    let header = std::str::from_utf8(&wire[..end]).map_err(|_| AuthenticationError::Response)?;
    let mut challenge = None;
    let mut length = None;
    for line in header.split("\r\n").skip(1) {
        let (name, value) = line.split_once(':').ok_or(AuthenticationError::Response)?;
        if name.eq_ignore_ascii_case("WWW-Authenticate") {
            if challenge.is_some() || value.trim().len() > MAX_CHALLENGE_BYTES {
                return Err(AuthenticationError::Response.into());
            }
            challenge = Some(value.trim());
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() {
                return Err(AuthenticationError::Response.into());
            }
            let parsed = decimal(value.trim())?;
            if parsed > 65_536 {
                return Err(AuthenticationError::Capacity.into());
            }
            length = Some(parsed as usize);
        }
        if name.eq_ignore_ascii_case("Proxy-Authenticate") {
            return Err(AuthenticationError::Unsupported.into());
        }
    }
    // Reject concatenated frames before parsing can allocate an event batch.
    if end + 4 + length.unwrap_or(0) != wire.len() {
        return Err(AuthenticationError::Response.into());
    }
    let mut parser = RtspParser::with_limits(RtspLimits {
        max_line_bytes: 2_048,
        max_headers: 32,
        max_body_bytes: 65_536,
        max_interleaved_bytes: 65_535,
    });
    let mut events = parser
        .feed(wire)
        .map_err(|_| AuthenticationError::Response)?;
    if parser.buffered_bytes() != 0 || events.len() != 1 {
        return Err(AuthenticationError::Response.into());
    }
    let response = match events.pop() {
        Some(RtspEvent::Response(response) | RtspEvent::AuthRequired { response, .. })
            if response.status_code == 401 =>
        {
            response
        }
        _ => return Err(AuthenticationError::Response.into()),
    };
    Ok((response, challenge.ok_or(AuthenticationError::Response)?))
}
