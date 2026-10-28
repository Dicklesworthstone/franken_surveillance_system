#![forbid(unsafe_code)]
//! Immutable acquisition witness for the bounded native PullPoint path.

use std::fmt;

use fss_core::{ContentDigest, DigestAlgorithm};

use super::{MAX_SOURCE_BYTES, MetadataError};
use crate::onvif::wire::{
    parse_pull_messages_response, parse_pull_point_subscription, validate_relates_to,
};

/// Owner-scoped native acquisition context, separate from the camera's claims.
///
/// Route digests bind independently pinned network destinations and explicit
/// subscription approval. Authentication means a client Digest response was sent;
/// neither server identity nor encryption is implied. Source bodies remain private.
#[derive(Clone, Eq, PartialEq)]
pub struct PullPointAcquisition {
    /// Exact owner-approved capture plan.
    pub approval: ContentDigest,
    /// Explicitly approved event-service route.
    pub event_route: ContentDigest,
    /// Same-origin, subtree-checked subscription route actually used.
    pub subscription_route: ContentDigest,
    /// Zero-based poll occurrence; duplicates remain separate observations.
    pub pull_index: u32,
    /// Owner-context monotonic request start.
    pub started_ns: u64,
    /// Owner-context monotonic complete response time.
    pub completed_ns: u64,
    /// A Digest challenge was answered for this poll, not a server identity proof.
    pub client_authenticated: bool,
    /// Exact complete CreatePullPointSubscription response.
    pub subscription_source: ContentDigest,
    /// Exact subscription response byte length.
    pub subscription_source_bytes: usize,
    /// Exact owner-generated identity of this logical PullMessages request.
    pub message_id: String,
    /// Exact owner-generated identity of the subscription creation request.
    pub subscription_message_id: String,
    /// Owner-context monotonic Create request start.
    pub subscription_started_ns: u64,
    /// Owner-context monotonic complete Create response time.
    pub subscription_completed_ns: u64,
}

impl PullPointAcquisition {
    /// Validate bounded local acquisition fields without performing I/O.
    pub fn validate(&self) -> Result<(), MetadataError> {
        if [
            self.approval,
            self.event_route,
            self.subscription_route,
            self.subscription_source,
        ]
        .iter()
        .any(|digest| digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32])
            || self.completed_ns < self.started_ns
            || self.subscription_completed_ns < self.subscription_started_ns
            || self.subscription_completed_ns > self.started_ns
            || !valid_request_id(&self.message_id)
            || !valid_request_id(&self.subscription_message_id)
            || self.message_id == self.subscription_message_id
            || self.subscription_source_bytes == 0
            || self.subscription_source_bytes > MAX_SOURCE_BYTES
        {
            return Err(MetadataError::InvalidBinding);
        }
        Ok(())
    }

    pub(super) fn validate_sources(
        &self,
        source: &[u8],
        subscription_source: &[u8],
    ) -> Result<(), MetadataError> {
        self.validate()?;
        if subscription_source.len() != self.subscription_source_bytes
            || ContentDigest::sha256(subscription_source) != self.subscription_source
        {
            return Err(MetadataError::Custody);
        }
        validate_relates_to(subscription_source, &self.subscription_message_id)?;
        validate_relates_to(source, &self.message_id)?;
        parse_pull_point_subscription(subscription_source)?;
        parse_pull_messages_response(source)?;
        Ok(())
    }
}

impl fmt::Debug for PullPointAcquisition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullPointAcquisition")
            .field("approval", &self.approval)
            .field("event_route", &self.event_route)
            .field("subscription_route", &self.subscription_route)
            .field("pull_index", &self.pull_index)
            .field("started_ns", &self.started_ns)
            .field("completed_ns", &self.completed_ns)
            .field("client_authenticated", &self.client_authenticated)
            .field("subscription_source", &self.subscription_source)
            .field("subscription_source_bytes", &self.subscription_source_bytes)
            .field("message_id", &"[redacted]")
            .field("subscription_message_id", &"[redacted]")
            .field("subscription_started_ns", &self.subscription_started_ns)
            .field("subscription_completed_ns", &self.subscription_completed_ns)
            .finish()
    }
}

fn valid_request_id(id: &str) -> bool {
    id.len() <= 256
        && id
            .strip_prefix("urn:")
            .is_some_and(|tail| tail.bytes().any(|byte| byte.is_ascii_alphanumeric()))
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
}
