#![forbid(unsafe_code)]
//! Exact, bounded preparation of one UniFi stream-setting intent.
//!
//! This module performs no network or storage I/O and grants no authority.
//! Its caller must establish camera identity, current configuration, a lease,
//! a durable registered effect, and a qualified transport before dispatch.

use super::{MAX_MESSAGE_BYTES, MessageKind, PreparedMessage, VideoChannel};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use std::fmt;

const DOMAIN: &str = "fss.unifi-direct.stream-precondition.v1";
/// The effect specified by the project's camera-settings registry row.
pub const EFFECT_CLASS: &str = "EFFECT-CAMERA-SETTING-001";

/// Independently observed state that the owner must revalidate before commit.
/// These fields are claims supplied by the caller, not proof of identity,
/// ownership, configuration readback or a live lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preconditions {
    /// Digest of the independently established camera identity binding.
    pub camera: ContentDigest,
    /// Digest of the exact current peer trust or admission decision.
    pub peer_admission: ContentDigest,
    /// Nonzero deployment stream generation before this change.
    pub stream_generation: u64,
    /// Digest of the last authoritative camera settings readback, if known.
    pub previous_settings: Option<ContentDigest>,
    /// Current, nonzero lease fencing value for this camera.
    pub lease_fence: u64,
}

impl Preconditions {
    /// Validate shape without claiming that these observations are authentic.
    pub fn validate(self) -> Result<(), Error> {
        digest_preconditions(self).map(|_| ())
    }
}

/// Payload-free intent refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The prepared message is not a bounded stream-setting request.
    WrongMessage,
    /// An identity, precondition, or fence is invalid.
    Preconditions,
    /// Canonical encoding failed.
    Encoding,
    /// A different prepared message was supplied for exact dispatch.
    Mismatch,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi stream intent refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Inert request and precondition identities for a future effect coordinator.
/// The exact prepared request remains held by the controller, not this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Intent {
    message_id: u64,
    channel: VideoChannel,
    camera: ContentDigest,
    fence: u64,
    request: ContentDigest,
    preconditions: ContentDigest,
}
impl Intent {
    /// Bind one prepared stream request to exact owner-supplied preconditions.
    /// The optional prior settings may be absent; in that case reversibility
    /// is unknown and an owner must not promise an automatic restoration.
    pub fn new(message: &PreparedMessage, conditions: Preconditions) -> Result<Self, Error> {
        let MessageKind::StartStream(channel) = message.kind() else {
            return Err(Error::WrongMessage);
        };
        if message.bytes().is_empty() || message.bytes().len() > MAX_MESSAGE_BYTES {
            return Err(Error::WrongMessage);
        }
        let preconditions = digest_preconditions(conditions)?;
        Ok(Self {
            message_id: message.id(),
            channel,
            camera: conditions.camera,
            fence: conditions.lease_fence,
            request: ContentDigest::sha256(message.bytes()),
            preconditions,
        })
    }
    /// Exact outbound request identity for the effect coordinator.
    pub fn request_digest(self) -> ContentDigest {
        self.request
    }
    /// Exact precondition identity to revalidate at effect commit.
    pub fn precondition_digest(self) -> ContentDigest {
        self.preconditions
    }
    /// Controller-local request ID, not proof of a response.
    pub fn message_id(self) -> u64 {
        self.message_id
    }
    /// Targeted video channel, without a camera capability assertion.
    pub fn channel(self) -> VideoChannel {
        self.channel
    }
    /// Compare a freshly observed precondition set to the prepared binding.
    /// Matching digests do not themselves prove that observations are authentic.
    pub fn check_preconditions(self, current: Preconditions) -> Result<(), Error> {
        if digest_preconditions(current)? != self.preconditions {
            return Err(Error::Mismatch);
        }
        Ok(())
    }
    /// Canonical leased resource identity derived from the supplied camera binding.
    pub fn resource(self) -> String {
        let hex: String = self
            .camera
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("camera:sha256:{hex}")
    }
    /// Lease fence supplied when this intent was prepared.
    pub fn fence(self) -> u64 {
        self.fence
    }
    /// Refuse a different prepared request before any attempted dispatch.
    pub fn check_message(self, message: &PreparedMessage) -> Result<(), Error> {
        if message.id() != self.message_id
            || message.kind() != MessageKind::StartStream(self.channel)
            || ContentDigest::sha256(message.bytes()) != self.request
        {
            return Err(Error::Mismatch);
        }
        Ok(())
    }
}
fn digest_preconditions(conditions: Preconditions) -> Result<ContentDigest, Error> {
    if !valid_digest(conditions.camera)
        || !valid_digest(conditions.peer_admission)
        || conditions
            .previous_settings
            .is_some_and(|v| !valid_digest(v))
        || conditions.stream_generation == 0
        || conditions.lease_fence == 0
    {
        return Err(Error::Preconditions);
    }
    let mut e = CanonicalEncoder::new();
    e.text(DOMAIN);
    e.text(EFFECT_CLASS);
    e.digest(conditions.camera);
    e.digest(conditions.peer_admission);
    e.u64(conditions.stream_generation);
    e.u64(conditions.lease_fence);
    match conditions.previous_settings {
        Some(digest) => {
            e.bool(true);
            e.digest(digest);
        }
        None => e.bool(false),
    }
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}
