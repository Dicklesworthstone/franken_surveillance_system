#![forbid(unsafe_code)]
//! Exact inert intent for a UniFi association, agreement, or clock message.
//!
//! The caller must independently establish peer identity and current state;
//! these digests are claims, not proof or permission to perform an effect.

use super::{MAX_MESSAGE_BYTES, MessageKind, PreparedMessage};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use std::fmt;

const DOMAIN: &str = "fss.unifi-direct.management-precondition.v1";
/// Registered effect class for controller and clock management operations.
pub const EFFECT_CLASS: &str = "EFFECT-CAMERA-MANAGEMENT-001";

/// Current owner-supplied binding for one camera and management session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preconditions {
    /// Digest of the independently established camera identity.
    pub camera: ContentDigest,
    /// Digest of the exact current peer admission decision.
    pub peer_admission: ContentDigest,
    /// Nonzero generation of the accepted management session.
    pub session_generation: u64,
    /// Digest of prior controller association, if independently known.
    pub previous_association: Option<ContentDigest>,
    /// Digest of prior camera clock state, if independently known.
    pub previous_clock: Option<ContentDigest>,
    /// Current, nonzero camera lease fence.
    pub lease_fence: u64,
}

impl Preconditions {
    pub(crate) fn validate(self) -> Result<(), Error> {
        digest_preconditions(self).map(|_| ())
    }
}

/// Payload-free refusal of a management intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The prepared message is not a supported management operation.
    WrongMessage,
    /// A digest, generation, or fence is invalid.
    Preconditions,
    /// Canonical encoding failed.
    Encoding,
    /// The current request or conditions differ from the binding.
    Mismatch,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi management intent refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Exact request and precondition identities; no dispatch permit is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Intent {
    id: u64,
    kind: MessageKind,
    camera: ContentDigest,
    fence: u64,
    request: ContentDigest,
    preconditions: ContentDigest,
    source: Option<ContentDigest>,
}
impl Intent {
    /// Bind the prepared message to current caller-supplied claims.
    pub fn new(message: &PreparedMessage, conditions: Preconditions) -> Result<Self, Error> {
        let kind = message.kind();
        if !matches!(
            kind,
            MessageKind::HelloReply
                | MessageKind::AgreementRequest
                | MessageKind::TimeSyncReply
                | MessageKind::EventReply
                | MessageKind::StartupRequestReply
        ) || message.bytes().is_empty()
            || message.bytes().len() > MAX_MESSAGE_BYTES
            || matches!(
                kind,
                MessageKind::EventReply | MessageKind::StartupRequestReply
            ) != message.source_digest().is_some()
        {
            return Err(Error::WrongMessage);
        }
        Ok(Self {
            id: message.id(),
            kind,
            camera: conditions.camera,
            fence: conditions.lease_fence,
            request: ContentDigest::sha256(message.bytes()),
            preconditions: digest_with_source(conditions, message.source_digest(), kind)?,
            source: message.source_digest(),
        })
    }
    /// The exact outbound message identity.
    pub fn request_digest(self) -> ContentDigest {
        self.request
    }
    /// Digest of the supplied current preconditions.
    pub fn precondition_digest(self) -> ContentDigest {
        self.preconditions
    }
    /// Controller-local message identity.
    pub fn message_id(self) -> u64 {
        self.id
    }
    /// Exact management operation kind.
    pub fn kind(self) -> MessageKind {
        self.kind
    }
    /// The exact observed event source, if this is an event echo.
    pub fn source_digest(self) -> Option<ContentDigest> {
        self.source
    }
    /// Lease fence captured at preparation.
    pub fn fence(self) -> u64 {
        self.fence
    }
    /// Camera resource identity derived from the supplied identity binding.
    pub fn resource(self) -> String {
        let hex: String = self
            .camera
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("camera:sha256:{hex}")
    }
    /// Compare freshly observed conditions without asserting their authenticity.
    pub fn check_preconditions(self, current: Preconditions) -> Result<(), Error> {
        if digest_with_source(current, self.source, self.kind)? != self.preconditions {
            return Err(Error::Mismatch);
        }
        Ok(())
    }
    /// Refuse a different prepared message before dispatch.
    pub fn check_message(self, message: &PreparedMessage) -> Result<(), Error> {
        if message.id() != self.id
            || message.kind() != self.kind
            || message.source_digest() != self.source
            || ContentDigest::sha256(message.bytes()) != self.request
        {
            return Err(Error::Mismatch);
        }
        Ok(())
    }
}
fn digest_with_source(
    value: Preconditions,
    source: Option<ContentDigest>,
    kind: MessageKind,
) -> Result<ContentDigest, Error> {
    let base = digest_preconditions(value)?;
    let Some(source) = source else {
        return Ok(base);
    };
    if !valid_digest(source) {
        return Err(Error::Preconditions);
    }
    let mut enc = CanonicalEncoder::new();
    enc.text(if kind == MessageKind::StartupRequestReply {
        "fss.unifi-direct.startup-request-reply-precondition.v1"
    } else {
        "fss.unifi-direct.event-reply-precondition.v1"
    });
    enc.digest(base);
    enc.digest(source);
    Ok(ContentDigest::sha256(
        &enc.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}
fn digest_preconditions(value: Preconditions) -> Result<ContentDigest, Error> {
    if !valid_digest(value.camera)
        || !valid_digest(value.peer_admission)
        || value.session_generation == 0
        || value.lease_fence == 0
        || value.previous_association.is_some_and(|v| !valid_digest(v))
        || value.previous_clock.is_some_and(|v| !valid_digest(v))
    {
        return Err(Error::Preconditions);
    }
    let mut enc = CanonicalEncoder::new();
    enc.text(DOMAIN);
    enc.text(EFFECT_CLASS);
    enc.digest(value.camera);
    enc.digest(value.peer_admission);
    enc.u64(value.session_generation);
    enc.u64(value.lease_fence);
    for optional in [value.previous_association, value.previous_clock] {
        match optional {
            Some(v) => {
                enc.bool(true);
                enc.digest(v);
            }
            None => enc.bool(false),
        }
    }
    Ok(ContentDigest::sha256(
        &enc.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
