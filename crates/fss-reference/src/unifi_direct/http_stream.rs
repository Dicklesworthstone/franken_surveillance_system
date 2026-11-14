#![forbid(unsafe_code)]
//! Experimental planning for a camera-local serializer update.
//!
//! The camera's local settings API accepts some partial updates, but whether it
//! applies this serializer shape to a live stream has not been established.
//! This module performs no I/O and grants no authority. Its plan may be passed
//! to a separately journaled guarded dispatcher, but does not establish camera
//! behavior or a restoration strategy. A digest is not the prior settings value.

/// Authenticated encryption for a retained pre-change serializer snapshot.
pub mod checkpoint;
/// Bounded HTTP serializer startup into a native owned media listener.
pub mod media;
/// Connect an HTTP-started media stream to the native video archive owners.
pub mod media_archive;

use super::{
    AudioCodec, StreamStart, VideoCodec, camera_api::VideoSerializers, handoff::Framing, intent,
};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm,
    json_input::{self, Value},
};
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
};

/// Caller-supplied bindings for one proposed track update.
/// These are claims, not proof of device identity, listener ownership,
/// current settings, effect settlement, or continuing authorization.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Preconditions {
    /// Owner-established camera claim.
    pub camera: ContentDigest,
    /// Exact peer-admission decision claim.
    pub peer_admission: ContentDigest,
    /// Nonzero camera-local HTTPS session generation.
    pub session_generation: u64,
    /// Current nonzero lease fence for the camera resource.
    pub lease_fence: u64,
    /// Binding of all three prior serializer values, including absent values.
    pub serializers: ContentDigest,
    /// Caller-observed media-listener address for this request.
    pub listener: SocketAddrV4,
}
impl fmt::Debug for Preconditions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Preconditions")
            .field("session_generation", &self.session_generation)
            .field("lease_fence", &self.lease_fence)
            .finish_non_exhaustive()
    }
}

/// Payload-free refusal while constructing or checking a plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An identity, session, lease, baseline or network binding is invalid.
    Preconditions,
    /// A fresh claim differs from the plan's bound preconditions.
    Stale,
    /// Canonical encoding or request construction failed.
    Encoding,
}

/// Comparison of caller-retained serializer observations. These untrusted
/// shapes do not establish that a requested destination was applied or works.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadbackChange {
    /// All three parsed serializer values equal the baseline.
    Unchanged,
    /// Only the targeted track changed; the change may be unrelated to the request.
    TargetTrackOnly,
    /// At least one other track changed, with or without a target-track change.
    OtherTracks {
        /// Whether the selected track changed as well.
        target_changed: bool,
    },
}

/// Redacted comparison of a readback to the baseline and requested fields.
/// The camera's response is an untrusted claim, not proof of a live stream or
/// of causality; even a matching baseline can match before any request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadbackObservation {
    /// Which serializer tracks differ from the retained baseline.
    pub change: ReadbackChange,
    /// All requested serializer fields, including the exact destination list,
    /// appear in the selected track. Additional object fields are allowed.
    pub requested_fields_match: bool,
}

/// Purpose of a separately authorized serializer-setting request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Ask the camera to send a track to a new listener.
    Start,
    /// Ask the camera to restore the earlier observed serializer value.
    Restore,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi HTTP stream plan refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Exact request plan and owner-supplied preconditions; no authority by itself.
/// Debug output intentionally omits network destinations and stream names.
pub struct Plan {
    peer: Ipv4Addr,
    start: StreamStart,
    framing: Framing,
    camera: ContentDigest,
    generation: u64,
    fence: u64,
    request: ContentDigest,
    preconditions: ContentDigest,
    serializers: ContentDigest,
    restore_body: Option<PrivateBody>,
}
impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("channel", &self.start.channel)
            .field("operation", &self.operation())
            .finish_non_exhaustive()
    }
}

pub(super) struct PrivateBody(pub(super) Vec<u8>);
impl Drop for PrivateBody {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct PrivateValue(Value);
impl Drop for PrivateValue {
    fn drop(&mut self) {
        super::camera_api::clear_value(&mut self.0);
    }
}

struct PrivateString(String);
impl Drop for PrivateString {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        bytes.fill(0);
    }
}

impl Plan {
    /// Bind a one-track serializer request to a listener and prior settings
    /// digest. The caller must independently qualify the actual listener,
    /// peer, audio configuration, device behavior and restoration strategy.
    pub fn new(
        peer: Ipv4Addr,
        start: &StreamStart,
        conditions: Preconditions,
        baseline: &VideoSerializers,
        framing: Framing,
    ) -> Result<Self, Error> {
        if !local_unicast(peer)
            || !local_unicast(*start.destination.ip())
            || start.destination != conditions.listener
        {
            return Err(Error::Preconditions);
        }
        let preconditions = precondition_digest(peer, conditions)?;
        if baseline
            .binding(|candidate, generation| {
                candidate == peer && generation == conditions.session_generation
            })
            .map_err(|_| Error::Preconditions)?
            != conditions.serializers
        {
            return Err(Error::Preconditions);
        }
        let request = request_digest(peer, start, conditions.session_generation, framing)?;
        Ok(Self {
            peer,
            start: start.clone(),
            framing,
            camera: conditions.camera,
            generation: conditions.session_generation,
            fence: conditions.lease_fence,
            request,
            preconditions,
            serializers: conditions.serializers,
            restore_body: None,
        })
    }

    /// Prepare a separate, non-authorizing request containing the selected
    /// track's retained prior serializer. It is eligible only after a matching
    /// target-only forward readback and a fresh binding to that full readback.
    /// An absent prior value is refused because a partial object cannot express
    /// deletion; explicit null and objects are preserved, but camera semantics
    /// for applying either are not established. This holds private bytes in
    /// memory only and does not provide durable custody or prove reversibility.
    pub fn prepare_restore(
        &self,
        baseline: &VideoSerializers,
        current_observation: &VideoSerializers,
        conditions: Preconditions,
        framing: Framing,
        authorize: impl Fn(Ipv4Addr, u64) -> bool,
    ) -> Result<Self, Error> {
        if self.operation() != Operation::Start
            || conditions.camera != self.camera
            || conditions.session_generation != self.generation
            || conditions.listener != self.start.destination
        {
            return Err(Error::Preconditions);
        }
        let observation = self.observe_readback(baseline, current_observation, &authorize)?;
        if observation.change != ReadbackChange::TargetTrackOnly
            || !observation.requested_fields_match
        {
            return Err(Error::Stale);
        }
        let preconditions = precondition_digest(self.peer, conditions)?;
        let admitted = |peer, generation| {
            peer == self.peer && generation == self.generation && authorize(peer, generation)
        };
        if current_observation
            .binding(admitted)
            .map_err(|_| Error::Preconditions)?
            != conditions.serializers
        {
            return Err(Error::Stale);
        }
        let index = match self.start.channel {
            super::VideoChannel::Video1 => 0,
            super::VideoChannel::Video2 => 1,
            super::VideoChannel::Video3 => 2,
        };
        let restore_body = baseline
            .visit(admitted, |tracks| {
                let prior = tracks[index].ok_or(Error::Preconditions)?;
                if !matches!(prior, Value::Null | Value::Object(_)) {
                    return Err(Error::Preconditions);
                }
                let mut out = PrivateString(format!(
                    "{{\"av\":{{\"video\":{{\"{}\":{{\"avSerializer\":",
                    self.start.channel.wire_name()
                ));
                super::events::write_json(prior, &mut out.0).map_err(|_| Error::Encoding)?;
                if out
                    .0
                    .len()
                    .checked_add(4)
                    .is_none_or(|n| n > super::MAX_MESSAGE_BYTES)
                {
                    return Err(Error::Encoding);
                }
                out.0.try_reserve(4).map_err(|_| Error::Encoding)?;
                out.0.push_str("}}}}");
                Ok(PrivateBody(std::mem::take(&mut out.0).into_bytes()))
            })
            .map_err(|_| Error::Preconditions)??;
        let request = request_digest_with_body(
            self.peer,
            &self.start,
            self.generation,
            framing,
            &restore_body,
            Operation::Restore,
        )?;
        Ok(Self {
            peer: self.peer,
            start: self.start.clone(),
            framing,
            camera: conditions.camera,
            generation: conditions.session_generation,
            fence: conditions.lease_fence,
            request,
            preconditions,
            serializers: conditions.serializers,
            restore_body: Some(restore_body),
        })
    }

    /// Expose the request purpose so live authority can distinguish restoration.
    pub fn operation(&self) -> Operation {
        if self.restore_body.is_some() {
            Operation::Restore
        } else {
            Operation::Start
        }
    }

    /// Exact semantic request identity for a registered effect.
    pub fn request_digest(&self) -> ContentDigest {
        self.request
    }
    /// Exact caller-supplied precondition identity for that effect.
    pub fn precondition_digest(&self) -> ContentDigest {
        self.preconditions
    }
    /// Canonical camera lease resource.
    pub fn resource(&self) -> String {
        format!("camera:{}", self.camera.to_text())
    }
    /// Bound nonzero lease fence.
    pub fn fence(&self) -> u64 {
        self.fence
    }

    /// Reject a changed caller-supplied observation before effect commit.
    /// Equality is not proof that the observation is fresh or authentic.
    pub fn check_current(
        &self,
        current: Preconditions,
        observed: &VideoSerializers,
    ) -> Result<(), Error> {
        if current.listener != self.start.destination
            || precondition_digest(self.peer, current)? != self.preconditions
            || observed
                .binding(|peer, generation| {
                    peer == self.peer && generation == current.session_generation
                })
                .map_err(|_| Error::Stale)?
                != current.serializers
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Compare a retained exact baseline with a readback from this same
    /// peer/session. The authority check governs disclosure of the comparison;
    /// neither equal nor changed values authenticate the peer, settle the
    /// effect, prove a destination, or establish successful restoration.
    pub fn compare_readback(
        &self,
        baseline: &VideoSerializers,
        observed: &VideoSerializers,
        authorize: impl Fn(Ipv4Addr, u64) -> bool,
    ) -> Result<ReadbackChange, Error> {
        let admitted = |peer, generation| {
            peer == self.peer && generation == self.generation && authorize(peer, generation)
        };
        if baseline
            .binding(admitted)
            .map_err(|_| Error::Preconditions)?
            != self.serializers
        {
            return Err(Error::Stale);
        }
        let index = match self.start.channel {
            super::VideoChannel::Video1 => 0,
            super::VideoChannel::Video2 => 1,
            super::VideoChannel::Video3 => 2,
        };
        baseline
            .visit(admitted, |before| {
                observed.visit(admitted, |after| {
                    let target_changed = before[index] != after[index];
                    let other_changed = (0..3).any(|i| i != index && before[i] != after[i]);
                    match (target_changed, other_changed) {
                        (false, false) => ReadbackChange::Unchanged,
                        (true, false) => ReadbackChange::TargetTrackOnly,
                        (_, true) => ReadbackChange::OtherTracks { target_changed },
                    }
                })
            })
            .map_err(|_| Error::Preconditions)?
            .map_err(|_| Error::Preconditions)
    }

    /// Compare an authorized readback with the baseline and exact fields sent
    /// by this plan. Object fields not in the request are ignored; arrays must
    /// match in length and order. The result is a peer claim, not effect
    /// settlement, authenticated identity, source continuity, or proof of
    /// successful delivery or restoration.
    pub fn observe_readback(
        &self,
        baseline: &VideoSerializers,
        observed: &VideoSerializers,
        authorize: impl Fn(Ipv4Addr, u64) -> bool,
    ) -> Result<ReadbackObservation, Error> {
        let change = self.compare_readback(baseline, observed, &authorize)?;
        let body = self.body()?;
        let text = std::str::from_utf8(&body.0).map_err(|_| Error::Encoding)?;
        let requested = PrivateValue(json_input::parse(text).map_err(|_| Error::Encoding)?);
        let index = match self.start.channel {
            super::VideoChannel::Video1 => 0,
            super::VideoChannel::Video2 => 1,
            super::VideoChannel::Video3 => 2,
        };
        let expected = requested
            .0
            .object()
            .and_then(|o| o.get("av"))
            .and_then(Value::object)
            .and_then(|o| o.get("video"))
            .and_then(Value::object)
            .and_then(|o| o.get(self.start.channel.wire_name()))
            .and_then(Value::object)
            .and_then(|o| o.get("avSerializer"))
            .ok_or(Error::Encoding)?;
        let matches = observed
            .visit(
                |peer, generation| {
                    peer == self.peer
                        && generation == self.generation
                        && authorize(peer, generation)
                },
                |tracks| tracks[index].is_some_and(|actual| contains_requested(expected, actual)),
            )
            .map_err(|_| Error::Preconditions)?;
        Ok(ReadbackObservation {
            change,
            requested_fields_match: matches,
        })
    }

    /// Reconstruct the exact private body for the guarded in-crate dispatcher.
    pub(super) fn body(&self) -> Result<PrivateBody, Error> {
        let body = if let Some(saved) = &self.restore_body {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(saved.0.len())
                .map_err(|_| Error::Encoding)?;
            bytes.extend_from_slice(&saved.0);
            PrivateBody(bytes)
        } else {
            body(&self.start)?
        };
        if request_digest_with_body(
            self.peer,
            &self.start,
            self.generation,
            self.framing,
            &body,
            self.operation(),
        )? != self.request
        {
            return Err(Error::Stale);
        }
        Ok(body)
    }

    pub(super) fn matches_session(&self, peer: Ipv4Addr, generation: u64) -> bool {
        self.peer == peer && self.generation == generation
    }

    pub(super) fn framing(&self) -> Framing {
        self.framing
    }
}

// Compare only keys selected in the bounded request. An array describes an
// ordered complete list, especially destinations, so additional items differ.
fn contains_requested(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(want), Value::Object(got)) => want.iter().all(|(key, value)| {
            got.get(key)
                .is_some_and(|actual| contains_requested(value, actual))
        }),
        (Value::Array(want), Value::Array(got)) => {
            want.len() == got.len()
                && want
                    .iter()
                    .zip(got)
                    .all(|(value, actual)| contains_requested(value, actual))
        }
        _ => expected == actual,
    }
}

fn local_unicast(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_loopback() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}
fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}
fn precondition_digest(peer: Ipv4Addr, value: Preconditions) -> Result<ContentDigest, Error> {
    if !local_unicast(peer)
        || !local_unicast(*value.listener.ip())
        || value.listener.port() == 0
        || !valid_digest(value.camera)
        || !valid_digest(value.peer_admission)
        || !valid_digest(value.serializers)
        || value.session_generation == 0
        || value.lease_fence == 0
    {
        return Err(Error::Preconditions);
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.unifi-direct.http-serializer-preconditions.v1");
    e.text(intent::EFFECT_CLASS);
    e.bytes(&peer.octets());
    e.digest(value.camera);
    e.digest(value.peer_admission);
    e.u64(value.session_generation);
    e.u64(value.lease_fence);
    e.digest(value.serializers);
    e.bytes(&value.listener.ip().octets());
    e.u64(u64::from(value.listener.port()));
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}

fn request_digest(
    peer: Ipv4Addr,
    start: &StreamStart,
    generation: u64,
    framing: Framing,
) -> Result<ContentDigest, Error> {
    let body = body(start)?;
    request_digest_with_body(peer, start, generation, framing, &body, Operation::Start)
}

fn request_digest_with_body(
    peer: Ipv4Addr,
    start: &StreamStart,
    generation: u64,
    framing: Framing,
    body: &PrivateBody,
    operation: Operation,
) -> Result<ContentDigest, Error> {
    let mut e = CanonicalEncoder::new();
    e.text(match operation {
        Operation::Start => "fss.unifi-direct.http-serializer-request.v1",
        Operation::Restore => "fss.unifi-direct.http-serializer-restore-request.v1",
    });
    e.text(intent::EFFECT_CLASS);
    e.text("PUT");
    e.text("/api/1.1/settings");
    e.bytes(&peer.octets());
    e.u64(generation);
    e.text(match framing {
        Framing::ContentLength => "content-length",
        Framing::Chunked => "chunked",
    });
    // The video codec is a media-verification expectation; this narrow
    // serializer update intentionally does not overwrite the track's type.
    e.text(match start.video {
        VideoCodec::H264 => "expect-h264",
        VideoCodec::H265 => "expect-h265",
    });
    e.bytes(&body.0);
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}

fn body(start: &StreamStart) -> Result<PrivateBody, Error> {
    let audio = match start.audio {
        AudioCodec::Aac => "\"withOpus\":false",
        AudioCodec::Opus => "\"withOpus\":true,\"opusSampleRate\":48000",
    };
    // StreamStart validates the IPv4 address and sixteen lowercase hex bytes,
    // so none of these interpolated fields can inject JSON syntax.
    let body = format!(
        "{{\"av\":{{\"video\":{{\"{}\":{{\"avSerializer\":{{\"type\":\"extendedFlv\",\"parameters\":{{\"streamName\":\"{}\",{audio}}},\"destinations\":[\"tcp://{}?retryInterval=1&connectTimeout=5\"]}}}}}}}}}}",
        start.channel.wire_name(),
        start.stream_name,
        start.destination
    );
    if body.len() > super::MAX_MESSAGE_BYTES {
        return Err(Error::Encoding);
    }
    Ok(PrivateBody(body.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::super::camera_api::{Session, WriteOutcome};
    use super::super::{VideoChannel, VideoCodec};
    use super::*;
    use asupersync::http::h1::Response;
    use fss_core::json_input::{self, Value};

    pub(super) fn snapshot(peer: Ipv4Addr, generation: u64, body: &[u8]) -> VideoSerializers {
        let mut session = Session::new(peer, generation).unwrap();
        let request = session
            .prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)
            .unwrap();
        session
            .finish_write(request, WriteOutcome::Written)
            .unwrap();
        session
            .accept_login(
                Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
            )
            .unwrap();
        let request = session.prepare_status().unwrap();
        session
            .finish_write(request, WriteOutcome::Written)
            .unwrap();
        session
            .accept_status(Response::new(200, "OK", b"{}".to_vec()))
            .unwrap();
        let request = session.prepare_settings().unwrap();
        session
            .finish_write(request, WriteOutcome::Written)
            .unwrap();
        session
            .accept_settings_with_serializers(Response::new(200, "OK", body.to_vec()))
            .unwrap()
            .1
    }

    pub(super) fn conditions(snapshot: &VideoSerializers, listener: SocketAddrV4) -> Preconditions {
        Preconditions {
            camera: ContentDigest::sha256(b"synthetic camera"),
            peer_admission: ContentDigest::sha256(b"synthetic peer admission"),
            session_generation: 1,
            lease_fence: 7,
            serializers: snapshot.binding(|_, _| true).unwrap(),
            listener,
        }
    }

    #[test]
    fn request_is_a_single_serializer_without_controller_or_other_tracks() {
        let destination = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let start = StreamStart::new(
            VideoChannel::Video1,
            destination,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let baseline = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":{"destinations":null}},"video2":{"avSerializer":{"destinations":["tcp://synthetic:1234"]}}}}}"#);
        let conditions = conditions(&baseline, destination);
        let plan = Plan::new(peer, &start, conditions, &baseline, Framing::Chunked).unwrap();
        let body = plan.body().unwrap();
        let parsed = json_input::parse(std::str::from_utf8(&body.0).unwrap()).unwrap();
        let root = parsed.object().unwrap();
        assert_eq!(root.len(), 1);
        let av = root["av"].object().unwrap();
        assert_eq!(av.len(), 1);
        let video = av["video"].object().unwrap();
        assert_eq!(video.len(), 1);
        let high = video["video1"].object().unwrap();
        assert_eq!(high.len(), 1);
        let serializer = high["avSerializer"].object().unwrap();
        assert!(matches!(&serializer["destinations"], Value::Array(items) if items.len() == 1));
        assert_eq!(serializer["type"].text(), Some("extendedFlv"));
        assert_eq!(
            serializer["parameters"].object().unwrap()["withOpus"].boolean(),
            Some(false)
        );
        assert!(!format!("{plan:?} {conditions:?}").contains("192.168."));
        assert!(!format!("{plan:?}").contains("0123456789abcdef"));
    }

    #[test]
    fn exact_baseline_listener_peer_and_framing_are_bound() {
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let baseline = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://first:1"]}}}}}"#);
        let changed = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://second:1"]}}}}}"#);
        let other_peer = snapshot(Ipv4Addr::new(192, 168, 44, 21), 1, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://first:1"]}}}}}"#);
        let current = conditions(&baseline, listener);
        let plan = Plan::new(peer, &start, current, &baseline, Framing::Chunked).unwrap();
        assert_eq!(plan.check_current(current, &baseline), Ok(()));
        assert_eq!(plan.check_current(current, &changed), Err(Error::Stale));
        assert!(matches!(
            Plan::new(peer, &start, current, &other_peer, Framing::Chunked),
            Err(Error::Preconditions)
        ));
        assert_eq!(
            plan.check_current(
                Preconditions {
                    lease_fence: 8,
                    ..current
                },
                &baseline
            ),
            Err(Error::Stale)
        );
        assert_eq!(
            plan.check_current(
                Preconditions {
                    listener: SocketAddrV4::new(*listener.ip(), 17778),
                    ..current
                },
                &baseline
            ),
            Err(Error::Stale)
        );
        let fixed = Plan::new(peer, &start, current, &baseline, Framing::ContentLength).unwrap();
        assert_ne!(plan.request_digest(), fixed.request_digest());
        let other_codec = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H265,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let other = Plan::new(peer, &other_codec, current, &baseline, Framing::Chunked).unwrap();
        assert_ne!(plan.request_digest(), other.request_digest());
        let first_body = plan.body().unwrap();
        let other_body = other.body().unwrap();
        assert_eq!(&first_body.0, &other_body.0);
        let public = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 17777);
        let unsafe_start = StreamStart::new(
            VideoChannel::Video1,
            public,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        assert!(matches!(
            Plan::new(
                peer,
                &unsafe_start,
                Preconditions {
                    listener: public,
                    ..current
                },
                &baseline,
                Framing::Chunked
            ),
            Err(Error::Preconditions)
        ));
    }

    #[test]
    fn readback_reports_track_changes_without_claiming_success() {
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let baseline = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://first:1"]}}}}}"#);
        let changed_target = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":{}},"video2":{"avSerializer":{"destinations":["tcp://first:1"]}}}}}"#);
        let changed_other = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://second:1"]}}}}}"#);
        let changed_both = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":{}},"video2":{"avSerializer":{"destinations":["tcp://second:1"]}}}}}"#);
        let foreign = snapshot(peer, 2, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://first:1"]}}}}}"#);
        let current = conditions(&baseline, listener);
        let plan = Plan::new(peer, &start, current, &baseline, Framing::ContentLength).unwrap();
        assert_eq!(
            plan.compare_readback(&baseline, &baseline, |_, _| true),
            Ok(ReadbackChange::Unchanged)
        );
        assert_eq!(
            plan.compare_readback(&baseline, &changed_target, |_, _| true),
            Ok(ReadbackChange::TargetTrackOnly)
        );
        assert_eq!(
            plan.compare_readback(&baseline, &changed_other, |_, _| true),
            Ok(ReadbackChange::OtherTracks {
                target_changed: false
            })
        );
        assert_eq!(
            plan.compare_readback(&baseline, &changed_both, |_, _| true),
            Ok(ReadbackChange::OtherTracks {
                target_changed: true
            })
        );
        assert_eq!(
            plan.compare_readback(&baseline, &foreign, |_, _| true),
            Err(Error::Preconditions)
        );
        assert_eq!(
            plan.compare_readback(&changed_other, &baseline, |_, _| true),
            Err(Error::Stale)
        );
        assert_eq!(
            plan.compare_readback(&baseline, &baseline, |_, _| false),
            Err(Error::Preconditions)
        );
    }

    #[test]
    fn readback_matches_requested_fields_without_attributing_the_change() {
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let before = br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"type":"unchanged"}}}}}"#;
        let requested = r#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false,"extra":3},"destinations":["tcp://192.168.44.10:17777?retryInterval=1&connectTimeout=5"],"extra":true}},"video2":{"avSerializer":{"type":"unchanged"}}}}}"#;
        let baseline = snapshot(peer, 1, before);
        let preconditions = conditions(&baseline, listener);
        let plan = Plan::new(
            peer,
            &start,
            preconditions,
            &baseline,
            Framing::ContentLength,
        )
        .unwrap();
        let matching = snapshot(peer, 1, requested.as_bytes());
        assert_eq!(
            plan.observe_readback(&baseline, &matching, |_, _| true),
            Ok(ReadbackObservation {
                change: ReadbackChange::TargetTrackOnly,
                requested_fields_match: true
            })
        );
        for changed in [
            requested.replace("17777?", "17778?"),
            requested.replace("0123456789abcdef", "0123456789abcdee"),
            requested.replace("\"withOpus\":false", "\"withOpus\":true"),
            requested.replace("\"withOpus\":false,", ""),
            requested.replace(
                "connectTimeout=5\"]",
                "connectTimeout=5\",\"tcp://extra:1\"]",
            ),
        ] {
            let other = snapshot(peer, 1, changed.as_bytes());
            let result = plan
                .observe_readback(&baseline, &other, |_, _| true)
                .unwrap();
            assert_eq!(result.change, ReadbackChange::TargetTrackOnly);
            assert!(!result.requested_fields_match);
        }
        let both = snapshot(
            peer,
            1,
            requested.replace("unchanged", "changed").as_bytes(),
        );
        assert_eq!(
            plan.observe_readback(&baseline, &both, |_, _| true),
            Ok(ReadbackObservation {
                change: ReadbackChange::OtherTracks {
                    target_changed: true
                },
                requested_fields_match: true
            })
        );
        assert_eq!(
            plan.observe_readback(&baseline, &baseline, |_, _| true),
            Ok(ReadbackObservation {
                change: ReadbackChange::Unchanged,
                requested_fields_match: false
            })
        );
        assert_eq!(
            plan.observe_readback(&baseline, &matching, |_, _| false),
            Err(Error::Preconditions)
        );

        // A matching state which was already present is not evidence of a change.
        let matching_conditions = conditions(&matching, listener);
        let already = Plan::new(
            peer,
            &start,
            matching_conditions,
            &matching,
            Framing::ContentLength,
        )
        .unwrap();
        assert_eq!(
            already.observe_readback(&matching, &matching, |_, _| true),
            Ok(ReadbackObservation {
                change: ReadbackChange::Unchanged,
                requested_fields_match: true
            })
        );
    }

    #[test]
    fn restore_retains_the_prior_track_and_refuses_unrelated_changes() {
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let prior_json = br#"{"av":{"video":{"video1":{"avSerializer":{"type":"legacy","secret":"private\"value","destinations":["tcp://old:1"],"nested":{"flag":true}}},"video2":{"avSerializer":{"type":"other"}}}}}"#;
        let changed_json = br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.44.10:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"type":"other"}}}}}"#;
        let prior = snapshot(peer, 1, prior_json);
        let changed = snapshot(peer, 1, changed_json);
        let original = conditions(&prior, listener);
        let forward = Plan::new(peer, &start, original, &prior, Framing::ContentLength).unwrap();
        let current = Preconditions {
            serializers: changed.binding(|_, _| true).unwrap(),
            ..original
        };
        let restore = forward
            .prepare_restore(&prior, &changed, current, Framing::ContentLength, |_, _| {
                true
            })
            .unwrap();
        assert_eq!(restore.operation(), Operation::Restore);
        assert_ne!(restore.request_digest(), forward.request_digest());
        assert_ne!(restore.precondition_digest(), forward.precondition_digest());
        assert_eq!(restore.check_current(current, &changed), Ok(()));
        assert_eq!(restore.check_current(current, &prior), Err(Error::Stale));
        let wire = restore.body().unwrap();
        let parsed = json_input::parse(std::str::from_utf8(&wire.0).unwrap()).unwrap();
        let video = parsed.object().unwrap()["av"].object().unwrap()["video"]
            .object()
            .unwrap();
        assert_eq!(video.len(), 1);
        let restored_value = &video["video1"].object().unwrap()["avSerializer"];
        prior
            .visit(
                |_, _| true,
                |tracks| assert_eq!(Some(restored_value), tracks[0]),
            )
            .unwrap();
        assert!(!format!("{restore:?}").contains("private"));
        assert!(!format!("{restore:?}").contains("192.168."));
        assert!(matches!(
            restore.prepare_restore(&prior, &changed, current, Framing::ContentLength, |_, _| {
                true
            }),
            Err(Error::Preconditions)
        ));
        assert!(matches!(
            forward.prepare_restore(&prior, &prior, current, Framing::ContentLength, |_, _| true),
            Err(Error::Stale)
        ));
        assert!(matches!(
            forward.prepare_restore(&prior, &changed, current, Framing::ContentLength, |_, _| {
                false
            }),
            Err(Error::Preconditions)
        ));
        let other = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.44.10:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"type":"unexpected"}}}}}"#);
        let other_conditions = Preconditions {
            serializers: other.binding(|_, _| true).unwrap(),
            ..original
        };
        assert!(matches!(
            forward.prepare_restore(
                &prior,
                &other,
                other_conditions,
                Framing::ContentLength,
                |_, _| true
            ),
            Err(Error::Stale)
        ));
        let wrong_camera = Preconditions {
            camera: ContentDigest::sha256(b"different camera"),
            ..current
        };
        assert!(matches!(
            forward.prepare_restore(
                &prior,
                &changed,
                wrong_camera,
                Framing::ContentLength,
                |_, _| true
            ),
            Err(Error::Preconditions)
        ));
    }

    #[test]
    fn restore_distinguishes_absent_null_and_unsupported_prior_values() {
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )
        .unwrap();
        let changed = snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.44.10:17777?retryInterval=1&connectTimeout=5"]}}}}}"#);
        for (prior_body, expected) in [
            (
                br#"{"av":{"video":{"video1":{"avSerializer":null}}}}"#.as_slice(),
                true,
            ),
            (br#"{"av":{"video":{"video1":{}}}}"#.as_slice(), false),
            (
                br#"{"av":{"video":{"video1":{"avSerializer":42}}}}"#.as_slice(),
                false,
            ),
        ] {
            let prior = snapshot(peer, 1, prior_body);
            let original = conditions(&prior, listener);
            let forward = Plan::new(peer, &start, original, &prior, Framing::Chunked).unwrap();
            let current = Preconditions {
                serializers: changed.binding(|_, _| true).unwrap(),
                ..original
            };
            let result =
                forward.prepare_restore(&prior, &changed, current, Framing::Chunked, |_, _| true);
            assert_eq!(result.is_ok(), expected);
            if let Ok(restore) = result {
                let wire = restore.body().unwrap();
                let parsed = json_input::parse(std::str::from_utf8(&wire.0).unwrap()).unwrap();
                assert_eq!(
                    parsed.object().unwrap()["av"].object().unwrap()["video"]
                        .object()
                        .unwrap()["video1"]
                        .object()
                        .unwrap()["avSerializer"],
                    Value::Null
                );
            }
        }
    }
}
