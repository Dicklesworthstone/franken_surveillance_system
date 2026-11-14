#![forbid(unsafe_code)]
//! Encrypted, caller-stored pre-change serializer snapshots.
//!
//! A checkpoint is captured before a stream-setting write. It contains private
//! camera settings and the proposed request, encrypted under a caller-owned
//! key; its independently retained scope is authenticated as associated data.
//! This does not create a key store, authenticate a camera, provide durable
//! storage, authorize a write, or reconcile an earlier effect.

use super::{Operation, Plan, PrivateBody, VideoSerializers, valid_digest};
use asupersync::Cx;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use fss_core::{
    CanonicalDecoder, CanonicalEncoder, ContentDigest,
    json_input::{self, Value},
};
use std::{fmt, net::Ipv4Addr};
use zeroize::Zeroize;

const SCOPE_DOMAIN: &str = "fss.unifi-direct.serializer-checkpoint-scope.v1";
const MAGIC: &[u8; 8] = b"FSSUSC01";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const MAX_PLAINTEXT: usize = super::super::MAX_MESSAGE_BYTES;

/// Payload-free checkpoint refusal. None grants a retry or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Scope, input shape, size, or original snapshot binding was invalid.
    Invalid,
    /// Runtime or live caller authority refused the operation.
    Denied,
    /// Authentication failed, including a wrong key or scope.
    Authentication,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "serializer checkpoint refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Caller-retained scope to authenticate independently from the stored bytes.
/// Certificate and camera claims still need independent admission on recovery.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Scope {
    camera: ContentDigest,
    certificate: ContentDigest,
    request: ContentDigest,
    preconditions: ContentDigest,
    baseline: ContentDigest,
    channel: u8,
}
impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerializerCheckpointScope")
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}
impl Scope {
    /// Create a scope from the exact forward plan and independently supplied
    /// camera certificate claim. This does not authenticate that certificate.
    pub fn from_plan(plan: &Plan, certificate: ContentDigest) -> Result<Self, Error> {
        if plan.operation() != Operation::Start || !valid_digest(certificate) {
            return Err(Error::Invalid);
        }
        let channel = match plan.start.channel {
            super::super::VideoChannel::Video1 => 1,
            super::super::VideoChannel::Video2 => 2,
            super::super::VideoChannel::Video3 => 3,
        };
        let scope = Self {
            camera: plan.camera,
            certificate,
            request: plan.request,
            preconditions: plan.preconditions,
            baseline: plan.serializers,
            channel,
        };
        scope.validate()?;
        Ok(scope)
    }
    /// Compare expected camera and certificate claims during independent
    /// recovery admission. This is equality, not identity authentication.
    pub fn matches_camera(&self, camera: ContentDigest, certificate: ContentDigest) -> bool {
        self.camera == camera && self.certificate == certificate
    }
    /// The original forward request digest, for matching a recovered journal.
    pub fn request_digest(&self) -> ContentDigest {
        self.request
    }
    /// The original forward precondition digest, for matching a recovered journal.
    pub fn precondition_digest(&self) -> ContentDigest {
        self.preconditions
    }
    /// The original private baseline binding; treat this digest as sensitive.
    pub fn baseline_digest(&self) -> ContentDigest {
        self.baseline
    }
    fn validate(&self) -> Result<(), Error> {
        if !(1..=3).contains(&self.channel)
            || ![
                self.camera,
                self.certificate,
                self.request,
                self.preconditions,
                self.baseline,
            ]
            .into_iter()
            .all(valid_digest)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Encode the scope for independent durable retention. Its digests may be
    /// sensitive metadata and the caller must protect them appropriately.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(SCOPE_DOMAIN);
        e.digest(self.camera);
        e.digest(self.certificate);
        e.digest(self.request);
        e.digest(self.preconditions);
        e.digest(self.baseline);
        e.u8(self.channel);
        e.finish_checked().map_err(|_| Error::Invalid)
    }
    /// Decode exact canonical scope bytes from independently retained storage.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 512 {
            return Err(Error::Invalid);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(|_| Error::Invalid)? != SCOPE_DOMAIN {
            return Err(Error::Invalid);
        }
        let scope = Self {
            camera: d.digest().map_err(|_| Error::Invalid)?,
            certificate: d.digest().map_err(|_| Error::Invalid)?,
            request: d.digest().map_err(|_| Error::Invalid)?,
            preconditions: d.digest().map_err(|_| Error::Invalid)?,
            baseline: d.digest().map_err(|_| Error::Invalid)?,
            channel: d.u8().map_err(|_| Error::Invalid)?,
        };
        d.ensure_finished().map_err(|_| Error::Invalid)?;
        scope.validate()?;
        if scope.encode()?.as_slice() != bytes {
            return Err(Error::Invalid);
        }
        Ok(scope)
    }
}

/// Caller-provided 256-bit key; never displayed and zeroized on drop. The
/// caller remains responsible for key entropy, storage, rotation and recovery.
pub struct Key([u8; 32]);
impl Key {
    /// Take ownership of externally provisioned key bytes. This cannot assess
    /// entropy or clear copies retained by the caller.
    pub fn new(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes.iter().all(|b| *b == 0) {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes))
    }
}
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckpointKey(<redacted>)")
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The capability being revalidated at the private-data boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Capture and encrypt an existing private baseline.
    Capture,
    /// Draw a unique cryptographic nonce from this scoped runtime context.
    Entropy,
    /// Decrypt and retain the baseline in memory.
    Open,
    /// Disclose the decrypted values to caller-owned code.
    Inspect,
}
/// Live caller authority. For `Entropy`, the implementation must ensure the
/// context supplies cryptographically secure random bytes and nonce uniqueness
/// for this key across all processes and restarts, not merely deterministic
/// laboratory entropy. This trait is a trust boundary, not a proof of entropy.
pub trait Authority {
    /// Check the current scope, action, task, key and storage policy.
    fn permits(&self, cx: &Cx, scope: &Scope, action: Action) -> bool;
}
fn admit(cx: &Cx, scope: &Scope, authority: &dyn Authority, action: Action) -> Result<(), Error> {
    if cx.checkpoint().is_err() || !authority.permits(cx, scope, action) {
        return Err(Error::Denied);
    }
    Ok(())
}

struct SecretString(String);
impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
struct SecretValue(Value);
impl Drop for SecretValue {
    fn drop(&mut self) {
        super::super::camera_api::clear_value(&mut self.0);
    }
}

fn append(out: &mut String, text: &str) -> Result<(), Error> {
    if out
        .len()
        .checked_add(text.len())
        .is_none_or(|n| n > MAX_PLAINTEXT)
    {
        return Err(Error::Invalid);
    }
    out.try_reserve(text.len()).map_err(|_| Error::Invalid)?;
    out.push_str(text);
    Ok(())
}

/// Ciphertext suitable for a caller-authorized protected object store.
/// The scope and encryption key must be independently retained. Its bytes
/// are not a persistence receipt, key-management solution or effect permit.
pub struct Sealed(Vec<u8>);
impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSerializerCheckpoint")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}
impl Sealed {
    /// Encrypt a bound baseline and exact forward body before any effect.
    pub fn capture(
        cx: &Cx,
        authority: &dyn Authority,
        scope: Scope,
        key: &Key,
        plan: &Plan,
        baseline: &VideoSerializers,
    ) -> Result<Self, Error> {
        if Scope::from_plan(plan, scope.certificate)? != scope {
            return Err(Error::Invalid);
        }
        admit(cx, &scope, authority, Action::Capture)?;
        let admitted =
            |peer: Ipv4Addr, generation: u64| peer == plan.peer && generation == plan.generation;
        if baseline.binding(admitted).map_err(|_| Error::Invalid)? != scope.baseline {
            return Err(Error::Invalid);
        }
        let forward: PrivateBody = plan.body().map_err(|_| Error::Invalid)?;
        let mut plain = SecretString(String::new());
        append(&mut plain.0, "{\"version\":1,\"tracks\":[")?;
        baseline
            .visit(admitted, |tracks| -> Result<(), Error> {
                for (i, track) in tracks.into_iter().enumerate() {
                    if i != 0 {
                        append(&mut plain.0, ",")?;
                    }
                    match track {
                        None => append(&mut plain.0, "{\"present\":false}")?,
                        Some(value) => {
                            append(&mut plain.0, "{\"present\":true,\"value\":")?;
                            super::super::events::write_json(value, &mut plain.0)
                                .map_err(|_| Error::Invalid)?;
                            append(&mut plain.0, "}")?;
                        }
                    }
                }
                Ok(())
            })
            .map_err(|_| Error::Invalid)??;
        append(&mut plain.0, "],\"forward\":")?;
        append(
            &mut plain.0,
            std::str::from_utf8(&forward.0).map_err(|_| Error::Invalid)?,
        )?;
        append(&mut plain.0, "}")?;
        admit(cx, &scope, authority, Action::Entropy)?;
        let mut nonce = [0u8; NONCE_BYTES];
        cx.random_bytes(&mut nonce);
        admit(cx, &scope, authority, Action::Capture)?;
        let aad = scope.encode()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| Error::Invalid)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plain.0.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Invalid)?;
        let mut out = Vec::new();
        out.try_reserve_exact(MAGIC.len() + NONCE_BYTES + ciphertext.len())
            .map_err(|_| Error::Invalid)?;
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(Self(out))
    }
    /// Validate bounded framing of a stored ciphertext; authentication occurs on open.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < MAGIC.len() + NONCE_BYTES + TAG_BYTES
            || bytes.len() > MAGIC.len() + NONCE_BYTES + MAX_PLAINTEXT + TAG_BYTES
            || !bytes.starts_with(MAGIC)
        {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Ciphertext bytes for explicitly authorized storage.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    /// Authenticate scope and ciphertext, then retain the private values in memory.
    pub fn open(
        &self,
        cx: &Cx,
        authority: &dyn Authority,
        scope: Scope,
        key: &Key,
    ) -> Result<Retained, Error> {
        admit(cx, &scope, authority, Action::Open)?;
        let aad = scope.encode()?;
        let nonce: [u8; NONCE_BYTES] = self
            .0
            .get(MAGIC.len()..MAGIC.len() + NONCE_BYTES)
            .ok_or(Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| Error::Invalid)?;
        let plain = SecretBytes(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &self.0[MAGIC.len() + NONCE_BYTES..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Authentication)?,
        );
        let value = SecretValue(
            json_input::parse(std::str::from_utf8(&plain.0).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?,
        );
        let root = value.0.object().ok_or(Error::Invalid)?;
        let tracks = root
            .get("tracks")
            .and_then(Value::array)
            .ok_or(Error::Invalid)?;
        if root.len() != 3
            || root.get("version") != Some(&Value::Number("1".to_owned()))
            || root.get("forward").and_then(Value::object).is_none()
            || tracks.len() != 3
        {
            return Err(Error::Invalid);
        }
        for track in tracks {
            let fields = track.object().ok_or(Error::Invalid)?;
            match fields.get("present").and_then(Value::boolean) {
                Some(false) if fields.len() == 1 => {}
                Some(true) if fields.len() == 2 && fields.contains_key("value") => {}
                _ => return Err(Error::Invalid),
            }
        }
        admit(cx, &scope, authority, Action::Open)?;
        Ok(Retained { scope, value })
    }
}

/// Decrypted prior values, which are neither a fresh camera observation nor
/// authority to retry, restore, or settle any effect.
pub struct Retained {
    scope: Scope,
    value: SecretValue,
}
impl fmt::Debug for Retained {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedSerializerCheckpoint(<redacted>)")
    }
}
impl Retained {
    /// Visit the three prior values and proposed forward JSON under fresh
    /// disclosure authority. Caller-created copies are caller-owned secrets.
    pub fn visit<R>(
        &self,
        cx: &Cx,
        authority: &dyn Authority,
        inspect: impl FnOnce([Option<&Value>; 3], &Value) -> R,
    ) -> Result<R, Error> {
        admit(cx, &self.scope, authority, Action::Inspect)?;
        let root = self.value.0.object().ok_or(Error::Invalid)?;
        let tracks = root
            .get("tracks")
            .and_then(Value::array)
            .ok_or(Error::Invalid)?;
        let view = std::array::from_fn(|i| tracks[i].object().and_then(|v| v.get("value")));
        Ok(inspect(view, root.get("forward").ok_or(Error::Invalid)?))
    }

    /// Compare a newly observed session with the retained pre-change values
    /// and forward request. The caller must independently admit the current
    /// camera and certificate, and the callback must authorize disclosure of
    /// this observation's actual peer and generation. Equality of the supplied
    /// claims does not authenticate the device. The result is a readback
    /// claim, not effect settlement, restore authority, or proof of streaming.
    pub fn compare_reopened(
        &self,
        cx: &Cx,
        authority: &dyn Authority,
        camera: ContentDigest,
        certificate: ContentDigest,
        observed: &VideoSerializers,
        authorize_observation: impl FnOnce(Ipv4Addr, u64) -> bool,
    ) -> Result<super::ReadbackObservation, Error> {
        if !self.scope.matches_camera(camera, certificate) {
            return Err(Error::Invalid);
        }
        let channel = match self.scope.channel {
            1 => "video1",
            2 => "video2",
            3 => "video3",
            _ => return Err(Error::Invalid),
        };
        let index = usize::from(self.scope.channel - 1);
        let result = self.visit(cx, authority, |before, forward| {
            let expected = forward
                .object()
                .and_then(|o| o.get("av"))
                .and_then(Value::object)
                .and_then(|o| o.get("video"))
                .and_then(Value::object)
                .and_then(|o| o.get(channel))
                .and_then(Value::object)
                .and_then(|o| o.get("avSerializer"))
                .ok_or(Error::Invalid)?;
            observed
                .visit(authorize_observation, |after| {
                    let target_changed = before[index] != after[index];
                    let other_changed = (0..3).any(|i| i != index && before[i] != after[i]);
                    let change = match (target_changed, other_changed) {
                        (false, false) => super::ReadbackChange::Unchanged,
                        (true, false) => super::ReadbackChange::TargetTrackOnly,
                        (_, true) => super::ReadbackChange::OtherTracks { target_changed },
                    };
                    super::ReadbackObservation {
                        change,
                        requested_fields_match: after[index]
                            .is_some_and(|actual| super::contains_requested(expected, actual)),
                    }
                })
                .map_err(|_| Error::Denied)
        })??;
        admit(cx, &self.scope, authority, Action::Inspect)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        AudioCodec, StreamStart, VideoChannel, VideoCodec, handoff::Framing,
    };
    use super::super::tests::{conditions, snapshot};
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use fss_object::{SpoolLimits, StagingSpool};
    use std::net::SocketAddrV4;

    struct Policy(bool);
    impl Authority for Policy {
        fn permits(&self, _: &Cx, _: &Scope, _: Action) -> bool {
            self.0
        }
    }
    struct Deny(Action);
    impl Authority for Deny {
        fn permits(&self, _: &Cx, _: &Scope, action: Action) -> bool {
            action != self.0
        }
    }
    type Test = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn encrypted_snapshot_survives_cold_spool_reopen_and_rejects_tampering() -> Test {
        let peer = Ipv4Addr::new(192, 168, 44, 20);
        let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 44, 10), 17777);
        let baseline=snapshot(peer,1,br#"{"av":{"video":{"video1":{"avSerializer":{"type":"legacy","secret":"synthetic-private-value","destinations":["tcp://old:1"]}},"video2":{"avSerializer":null}}}}"#);
        let start = StreamStart::new(
            VideoChannel::Video1,
            listener,
            VideoCodec::H264,
            AudioCodec::Aac,
            "0123456789abcdef",
        )?;
        let plan = Plan::new(
            peer,
            &start,
            conditions(&baseline, listener),
            &baseline,
            Framing::ContentLength,
        )?;
        let scope = Scope::from_plan(&plan, ContentDigest::sha256(b"synthetic certificate"))?;
        let scope_bytes = scope.encode()?;
        assert_eq!(Scope::decode(&scope_bytes)?, scope);
        assert!(scope.matches_camera(plan.camera, ContentDigest::sha256(b"synthetic certificate")));
        assert!(
            !scope.matches_camera(plan.camera, ContentDigest::sha256(b"different certificate"))
        );
        assert_eq!(scope.request_digest(), plan.request_digest());
        assert_eq!(scope.precondition_digest(), plan.precondition_digest());
        let mut trailing = scope_bytes.clone();
        trailing.push(0);
        assert!(matches!(Scope::decode(&trailing), Err(Error::Invalid)));
        let key = Key::new([7; 32])?;
        let wrong_key = Key::new([8; 32])?;
        let wrong_scope = Scope::from_plan(&plan, ContentDigest::sha256(b"different certificate"))?;
        let runtime = RuntimeBuilder::current_thread().build()?;
        runtime.block_on(async {
            let cx = Cx::current().ok_or("missing runtime")?;
            assert!(matches!(
                Sealed::capture(&cx, &Policy(false), scope, &key, &plan, &baseline),
                Err(Error::Denied)
            ));
            assert!(matches!(
                Sealed::capture(&cx, &Deny(Action::Entropy), scope, &key, &plan, &baseline),
                Err(Error::Denied)
            ));
            let sealed = Sealed::capture(&cx, &Policy(true), scope, &key, &plan, &baseline)?;
            let another = Sealed::capture(&cx, &Policy(true), scope, &key, &plan, &baseline)?;
            assert_ne!(sealed.bytes(), another.bytes());
            assert!(
                !sealed
                    .bytes()
                    .windows(b"synthetic-private-value".len())
                    .any(|w| w == b"synthetic-private-value")
            );
            assert!(!format!("{scope:?} {key:?} {sealed:?}").contains("synthetic-private-value"));
            assert!(matches!(
                sealed.open(&cx, &Policy(true), scope, &wrong_key),
                Err(Error::Authentication)
            ));
            assert!(matches!(
                sealed.open(&cx, &Policy(true), wrong_scope, &key),
                Err(Error::Authentication)
            ));
            assert!(matches!(
                sealed.open(&cx, &Policy(false), scope, &key),
                Err(Error::Denied)
            ));
            let mut damaged = sealed.bytes().to_vec();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            let damaged = Sealed::from_bytes(&damaged)?;
            assert!(matches!(
                damaged.open(&cx, &Policy(true), scope, &key),
                Err(Error::Authentication)
            ));
            assert!(matches!(
                Sealed::from_bytes(&sealed.bytes()[..10]),
                Err(Error::Invalid)
            ));
            let mut bad_nonce = sealed.bytes().to_vec();
            bad_nonce[MAGIC.len()] ^= 1;
            let bad_nonce = Sealed::from_bytes(&bad_nonce)?;
            assert!(matches!(
                bad_nonce.open(&cx, &Policy(true), scope, &key),
                Err(Error::Authentication)
            ));

            let path = std::env::temp_dir().join(format!(
                "fss-encrypted-serializer-checkpoint-{}",
                std::process::id()
            ));
            std::fs::create_dir(&path)?;
            let limits = SpoolLimits::new(4, 1_000_000, 100_000, 8);
            let mut spool = StagingSpool::open(path.join("spool"), limits)?;
            let receipt = spool.stage_bytes(sealed.bytes())?;
            spool.verify(receipt.digest)?;
            drop(spool);
            let reopened = StagingSpool::open(path.join("spool"), limits)?;
            let persisted = reopened.read_bounded(receipt.digest, 100_000)?;
            assert_eq!(persisted, sealed.bytes());
            let recovered_scope = Scope::decode(&scope_bytes)?;
            let retained =
                Sealed::from_bytes(&persisted)?.open(&cx, &Policy(true), recovered_scope, &key)?;
            assert!(matches!(
                retained.visit(&cx, &Policy(false), |_, _| ()),
                Err(Error::Denied)
            ));
            assert!(matches!(
                retained.visit(&cx, &Deny(Action::Inspect), |_, _| ()),
                Err(Error::Denied)
            ));
            retained.visit(&cx, &Policy(true), |tracks, forward| {
                assert_eq!(
                    tracks[0]
                        .and_then(Value::object)
                        .and_then(|o| o.get("secret"))
                        .and_then(Value::text),
                    Some("synthetic-private-value")
                );
                assert_eq!(tracks[1], Some(&Value::Null));
                assert_eq!(tracks[2], None);
                assert!(forward.object().is_some());
            })?;
            let certificate = ContentDigest::sha256(b"synthetic certificate");
            let new_peer = Ipv4Addr::new(192, 168, 44, 21);
            let after = snapshot(new_peer, 2, br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.44.10:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":null}}}}"#);
            let admitted = |p, g| p == new_peer && g == 2;
            assert_eq!(
                retained.compare_reopened(&cx, &Policy(true), plan.camera, certificate, &after, admitted)?,
                super::super::ReadbackObservation {
                    change: super::super::ReadbackChange::TargetTrackOnly,
                    requested_fields_match: true,
                }
            );
            let drift = snapshot(new_peer, 2, br#"{"av":{"video":{"video1":{"avSerializer":{}},"video2":{"avSerializer":{}}}}}"#);
            let observation = retained.compare_reopened(&cx, &Policy(true), plan.camera, certificate, &drift, admitted)?;
            assert_eq!(observation.change, super::super::ReadbackChange::OtherTracks { target_changed: true });
            assert!(!observation.requested_fields_match);
            assert!(matches!(retained.compare_reopened(&cx, &Policy(true), plan.camera, ContentDigest::sha256(b"different certificate"), &after, admitted), Err(Error::Invalid)));
            assert!(matches!(retained.compare_reopened(&cx, &Policy(true), plan.camera, certificate, &after, |_, _| false), Err(Error::Denied)));
            assert!(matches!(retained.compare_reopened(&cx, &Deny(Action::Inspect), plan.camera, certificate, &after, admitted), Err(Error::Denied)));
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}
