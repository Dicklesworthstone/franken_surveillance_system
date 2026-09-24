#![forbid(unsafe_code)]
//! Constructor-only payload policy shared by the plain and authenticated pumps.
//! This private child can initialize both owners without exposing mutable access
//! to a live session, its authentication state, or its source-bound receiver.

use super::*;

impl RtspAvcClient {
    /// Pin one H.264 payload offer before DESCRIBE and before any TCP input.
    ///
    /// Unlike `new`, this constructor can disambiguate multiple H.264 mappings
    /// in the exact configured media section. Missing or unsupported selected
    /// mappings fail closed; no other mapping's parameters can be substituted.
    /// Scope, stream-generation, syntax, transport, and source-ownership checks
    /// are identical to the default pump. This performs no I/O.
    pub fn new_with_payload_type(
        config: ClientConfig,
        key: StreamKey,
        limits: AvcReceiveLimits,
        payload_type: u8,
    ) -> Result<Self, AvcClientError> {
        let session = RtspClientSession::new_with_payload_type(config.clone(), payload_type)
            .map_err(AvcClientError::Session)?;
        let mut client = Self::new(config, key, limits)?;
        // Both constructors are inert. Replace only the untouched initial
        // session; no request, source, codec state, or deadline can be discarded.
        client.session = session;
        Ok(client)
    }
}

impl DigestAvcClient {
    /// Pin payload, URL scope, stream generation, and Digest policy together.
    ///
    /// The payload choice survives challenge retries and remains immutable for
    /// the lifetime of this connection. Credential borrowing, original request
    /// deadlines, nonce accounting, and exact wire retirement are unchanged.
    /// Selecting a payload does not authenticate incoming media or permit HEVC
    /// bytes to enter the AVC receiver.
    pub fn new_with_payload_type(
        config: ClientConfig,
        key: StreamKey,
        limits: AvcReceiveLimits,
        payload_type: u8,
        realm: &str,
        policy: DigestPolicy,
    ) -> Result<Self, DigestAvcError> {
        let mut inner = RtspAvcClient::new_with_payload_type(config, key, limits, payload_type)
            .map_err(DigestAvcError::Client)?;
        inner
            .session
            .enable_digest(realm, policy)
            .map_err(DigestAvcError::Authentication)?;
        Ok(Self {
            inner,
            intake: RtspWireIntake::new(),
            challenge: None,
            challenge_deadline_ns: None,
            pending_cseq: None,
            input_ready: true,
            input_ended: false,
            closed: false,
        })
    }
}
