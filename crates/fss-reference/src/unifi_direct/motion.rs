#![forbid(unsafe_code)]
//! Exact, inert intent for a baseline camera motion-setting change.
//!
//! Claims supplied here do not prove identity, prior settings, authority, or
//! camera support. A committed effect and current policy are required to send.

use super::{MAX_MESSAGE_BYTES, MessageKind, PreparedMessage};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use std::fmt;

/// Registered camera-setting effect class.
pub const EFFECT_CLASS: &str = "EFFECT-CAMERA-SETTING-001";
const DOMAIN: &str = "fss.unifi-direct.motion-precondition.v1";

/// Owner-supplied current conditions, whose authenticity is external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preconditions {
    /// Independently established camera binding.
    pub camera: ContentDigest,
    /// Current peer admission binding.
    pub peer_admission: ContentDigest,
    /// Nonzero accepted controller session generation.
    pub session_generation: u64,
    /// Digest of prior motion settings if known; absent means restoration is unknown.
    pub previous_motion: Option<ContentDigest>,
    /// Current camera lease fence.
    pub lease_fence: u64,
}
impl Preconditions {
    /// Validate shape without authenticating the claims.
    pub fn validate(self) -> Result<(), Error> {
        digest(self).map(|_| ())
    }
}

/// Payload-free binding refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongMessage,
    Preconditions,
    Mismatch,
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi motion intent refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One exact prepared request and owner-supplied precondition set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Intent {
    id: u64,
    enabled: bool,
    camera: ContentDigest,
    fence: u64,
    request: ContentDigest,
    conditions: ContentDigest,
}
impl Intent {
    /// Bind an existing prepared request without granting permission to send it.
    pub fn new(message: &PreparedMessage, conditions: Preconditions) -> Result<Self, Error> {
        let MessageKind::SetMotion(enabled) = message.kind() else {
            return Err(Error::WrongMessage);
        };
        if message.bytes().is_empty() || message.bytes().len() > MAX_MESSAGE_BYTES {
            return Err(Error::WrongMessage);
        }
        Ok(Self {
            id: message.id(),
            enabled,
            camera: conditions.camera,
            fence: conditions.lease_fence,
            request: ContentDigest::sha256(message.bytes()),
            conditions: digest(conditions)?,
        })
    }
    /// Bound request digest.
    pub fn request_digest(self) -> ContentDigest {
        self.request
    }
    /// Bound precondition digest.
    pub fn precondition_digest(self) -> ContentDigest {
        self.conditions
    }
    /// Never-reused local message ID.
    pub fn message_id(self) -> u64 {
        self.id
    }
    /// Requested motion state.
    pub fn enabled(self) -> bool {
        self.enabled
    }
    /// Bound camera fence.
    pub fn fence(self) -> u64 {
        self.fence
    }
    /// Bound camera resource.
    pub fn resource(self) -> String {
        format!("camera:{}", self.camera.to_text())
    }
    /// Refuse a changed owner-supplied condition set.
    pub fn check_preconditions(self, current: Preconditions) -> Result<(), Error> {
        if digest(current)? == self.conditions {
            Ok(())
        } else {
            Err(Error::Mismatch)
        }
    }
    /// Refuse different request bytes, kind, or ID.
    pub fn check_message(self, message: &PreparedMessage) -> Result<(), Error> {
        if message.id() == self.id
            && message.kind() == MessageKind::SetMotion(self.enabled)
            && ContentDigest::sha256(message.bytes()) == self.request
        {
            Ok(())
        } else {
            Err(Error::Mismatch)
        }
    }
}
fn valid(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
}
fn digest(value: Preconditions) -> Result<ContentDigest, Error> {
    if !valid(value.camera)
        || !valid(value.peer_admission)
        || value.previous_motion.is_some_and(|d| !valid(d))
        || value.session_generation == 0
        || value.lease_fence == 0
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
    match value.previous_motion {
        Some(d) => {
            enc.bool(true);
            enc.digest(d);
        }
        None => enc.bool(false),
    }
    Ok(ContentDigest::sha256(
        &enc.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
