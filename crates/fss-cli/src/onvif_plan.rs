#![forbid(unsafe_code)]
//! Pure protected ONVIF selection and the existing native capture wrapper's approval.
//!
//! The handoff supplies a historical route and codec, not source, clock or effect authority.
//! The caller supplies actual private-file observations and the native executor independently
//! repeats that protected read. No file, credential, clock or network is opened here.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};

use crate::json_output::{object, string};

#[allow(
    dead_code,
    reason = "The native ONVIF producer shares the same handoff contract"
)]
#[path = "bin/fss-onvif/handoff.rs"]
mod handoff;

/// Existing payload-free handoff/selection refusal identity.
pub const ERR_ONVIF_HANDOFF: &str = "ERR-CAPTURE-ONVIF-HANDOFF-001";
/// Maximum complete v1/v2 handoff accepted by the existing parser.
pub const MAX_ONVIF_HANDOFF_BYTES: usize = 8192;
const POLICY: &str = "private-digest-bound-stable-onvif-uri:separate-owner-capture-approval:\
unchanged-source-clock-timing-and-independent-pin-owners:no-camera-or-credential-read-in-preview:v1";
const RECONNECT_POLICY: &str = "private-digest-bound-stable-onvif-uri:explicit-native-reconnect-owner:\
separate-owner-approval:all-derived-destinations-disjoint:private-child-previews:\
fresh-observed-recovery-approval:no-camera-or-credential-read-in-preview:v2";
const MAX_ARGUMENTS: usize = 196;

/// An exact protected handoff reference, without any implied file or capture permission.
#[derive(Clone, Eq, PartialEq)]
pub struct OnvifSourceSpec {
    /// Absolute private handoff path; execution reopens the same file.
    pub source: PathBuf,
    /// SHA-256 of the complete private handoff bytes, including its original encoding.
    pub expected: ContentDigest,
}

impl fmt::Debug for OnvifSourceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnvifSourceSpec")
            .field("expected", &self.expected)
            .finish_non_exhaustive()
    }
}

/// Exact bytes and full filesystem fingerprint borrowed from an actual private-file lease.
#[derive(Clone, Copy)]
pub struct ProtectedOnvifInput<'a> {
    /// Complete protected handoff bytes; never a copied public diagnostic projection.
    pub bytes: &'a [u8],
    /// The actual lease's 88-byte device/inode/permission/owner/link/length/time fingerprint.
    pub fingerprint: &'a [u8; 88],
}

impl fmt::Debug for ProtectedOnvifInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedOnvifInput")
            .field("byte_count", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Private parsed selection plus arguments for the real native capture parser.
pub struct PreparedOnvifSelection {
    identity: ContentDigest,
    handoff: handoff::Handoff,
    arguments: Vec<OsString>,
}

impl fmt::Debug for PreparedOnvifSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedOnvifSelection")
            .field("file_identity", &self.identity)
            .field("profile_digest", &self.handoff.profile_digest)
            .field("argument_count", &self.arguments.len())
            .finish_non_exhaustive()
    }
}

impl PreparedOnvifSelection {
    /// SHA-256 of the actual private-file fingerprint supplied by the caller.
    #[must_use]
    pub const fn file_identity(&self) -> ContentDigest {
        self.identity
    }

    /// Historical onboarding-plan identity asserted by the exact handoff.
    #[must_use]
    pub const fn onboarding_plan(&self) -> ContentDigest {
        self.handoff.onboarding_plan
    }

    /// SHA-256 of the originally selected exact ONVIF profile token.
    #[must_use]
    pub const fn profile_digest(&self) -> ContentDigest {
        self.handoff.profile_digest
    }

    /// Historical advertised codec; actual native capture still verifies SDP and picture syntax.
    #[must_use]
    pub fn codec(&self) -> &str {
        &self.handoff.codec
    }

    /// Compare independently supplied endpoint coordinates without returning a private URI.
    #[must_use]
    pub fn matches_route(&self, peer: SocketAddr, authority: &str, presentation: &str) -> bool {
        self.handoff.peer == peer
            && self.handoff.authority == authority
            && self
                .handoff
                .presentation()
                .is_ok_and(|path| path == presentation)
    }

    /// Borrow the exact historical endpoint for a separately approved native probe.
    /// The private URI remains within the caller's protected-input scope; this
    /// accessor grants no network authority or proof of the ONVIF HTTP origin.
    pub(crate) fn with_route<T>(
        &self,
        use_route: impl FnOnce(SocketAddr, &str, &str) -> T,
    ) -> Result<T, &'static str> {
        Ok(use_route(
            self.handoff.peer,
            &self.handoff.authority,
            self.handoff.presentation()?,
        ))
    }

    /// Borrow private route-bearing arguments only for the existing native owner.
    pub fn with_capture_arguments<T>(&self, prepare: impl FnOnce(&[OsString]) -> T) -> T {
        prepare(&self.arguments)
    }
}

impl OnvifSourceSpec {
    /// Parse the same stable Media1 AVC or Media2 AVC/HEVC handoff as native capture.
    /// The caller supplies every non-route capture option, including the control subtree.
    pub fn prepare(
        &self,
        input: ProtectedOnvifInput<'_>,
        native_args: &[OsString],
    ) -> Result<PreparedOnvifSelection, &'static str> {
        self.validate()?;
        if input.bytes.is_empty()
            || input.bytes.len() > MAX_ONVIF_HANDOFF_BYTES
            || ContentDigest::sha256(input.bytes) != self.expected
            || native_args.len() > MAX_ARGUMENTS
            || !native_args.len().is_multiple_of(2)
            || native_args
                .iter()
                .any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ERR_ONVIF_HANDOFF);
        }
        let mut seen = BTreeSet::new();
        for pair in native_args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ERR_ONVIF_HANDOFF)?;
            if pair[1].to_str().is_none_or(str::is_empty)
                || !seen.insert(key)
                || matches!(
                    key,
                    "--onvif-source"
                        | "--onvif-digest"
                        | "--capture-mode"
                        | "--approve"
                        | "--peer"
                        | "--authority"
                        | "--presentation"
                        | "--codec"
                )
            {
                return Err(ERR_ONVIF_HANDOFF);
            }
        }
        let handoff = handoff::Handoff::parse(input.bytes)?;
        let mut arguments = Vec::with_capacity(native_args.len() + 8);
        for pair in native_args.as_chunks::<2>().0 {
            if pair[0] == "--onvif-control-root-digest" {
                if seen.contains("--control-root") {
                    return Err(ERR_ONVIF_HANDOFF);
                }
                let root = resolve_control_root(
                    handoff.presentation()?,
                    pair[1].to_str().ok_or(ERR_ONVIF_HANDOFF)?,
                )?;
                arguments.extend([OsString::from("--control-root"), OsString::from(root)]);
            } else {
                arguments.extend_from_slice(pair);
            }
        }
        for (key, value) in [
            ("--peer", handoff.peer.to_string()),
            ("--authority", handoff.authority.clone()),
            ("--presentation", handoff.presentation()?.to_owned()),
            ("--codec", handoff.codec.clone()),
        ] {
            arguments.extend([OsString::from(key), OsString::from(value)]);
        }
        Ok(PreparedOnvifSelection {
            identity: ContentDigest::sha256(input.fingerprint),
            handoff,
            arguments,
        })
    }

    /// The unchanged native wrapper digest, with the historical field order and policy.
    pub fn approval(
        &self,
        identity: ContentDigest,
        mode: &str,
        operation: &str,
        native: ContentDigest,
    ) -> Result<ContentDigest, &'static str> {
        self.validate()?;
        let (schema, policy) = mode_contract(mode, operation)?;
        let mut encoded = CanonicalEncoder::new();
        encoded.text(schema);
        encoded.text(policy);
        if mode == "reconnect" {
            encoded.text(mode);
            encoded.text(operation);
        }
        encoded.text(self.source.to_str().ok_or(ERR_ONVIF_HANDOFF)?);
        encoded.digest(self.expected);
        encoded.digest(identity);
        encoded.digest(native);
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| ERR_ONVIF_HANDOFF)?,
        ))
    }

    /// The unchanged standalone preview around the actual native private-URI preview.
    /// The caller must never pass an unredacted native preview to this method.
    pub fn preview(
        &self,
        identity: ContentDigest,
        mode: &str,
        operation: &str,
        native: ContentDigest,
        private_native_preview: &str,
    ) -> Result<String, &'static str> {
        let (schema, policy) = mode_contract(mode, operation)?;
        Ok(object(&[
            ("schema", string(schema)),
            ("phase", string("planned")),
            (
                "approval",
                string(&self.approval(identity, mode, operation, native)?.to_text()),
            ),
            ("policy", string(policy)),
            ("capture_mode", string(mode)),
            ("operation", string(operation)),
            (
                "onvif_source",
                string(self.source.to_str().ok_or(ERR_ONVIF_HANDOFF)?),
            ),
            ("onvif_digest", string(&self.expected.to_text())),
            ("onvif_file_identity", string(&identity.to_text())),
            ("native_capture", private_native_preview.to_owned()),
            (
                "effects",
                string(if operation == "capture" {
                    "protected-handoff-and-destination-inspection-only"
                } else {
                    "protected-handoff-and-native-recovery-inspection-only"
                }),
            ),
        ]))
    }

    fn validate(&self) -> Result<(), &'static str> {
        let path = self.source.to_str().ok_or(ERR_ONVIF_HANDOFF)?;
        if path.is_empty()
            || path.len() > 4096
            || path.chars().any(char::is_control)
            || !self.source.is_absolute()
            || self.source.file_name().is_none()
            || self
                .source
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || path.split('/').any(|part| matches!(part, "." | ".."))
            || self.expected.algorithm() != DigestAlgorithm::Sha256
            || self.expected.bytes() == [0; 32]
        {
            return Err(ERR_ONVIF_HANDOFF);
        }
        Ok(())
    }
}

/// Recover only an explicitly hash-pinned subtree of the protected presentation.
/// Candidate count is bounded by the native 2048-byte URI ceiling. Exact percent
/// spelling and slashes are preserved; no decoding, fallback or default root exists.
pub(crate) fn resolve_control_root(presentation: &str, expected: &str) -> Result<String, &'static str> {
    let digest = ContentDigest::parse(expected).map_err(|_| ERR_ONVIF_HANDOFF)?;
    if digest.algorithm() != DigestAlgorithm::Sha256
        || digest.bytes() == [0; 32]
        || digest.to_text() != expected
        || presentation.len() > 2048
        || !presentation.is_ascii()
        || !presentation.starts_with('/')
    {
        return Err(ERR_ONVIF_HANDOFF);
    }
    let path = presentation.split('?').next().ok_or(ERR_ONVIF_HANDOFF)?;
    let mut selected = None;
    let mut consider = |root: &str| -> Result<(), &'static str> {
        if ContentDigest::sha256(root.as_bytes()) == digest {
            if selected.is_some() {
                return Err(ERR_ONVIF_HANDOFF);
            }
            selected = Some(root.to_owned());
        }
        Ok(())
    };
    for end in 1..=path.len() {
        if end == path.len() || path.as_bytes()[end] == b'/' || path.as_bytes()[end - 1] == b'/' {
            consider(&path[..end])?;
        }
    }
    // The native owner accepts a trailing slash on the complete resource as well
    // as on intermediate ancestors. It remains a distinct, explicitly pinned root.
    if !path.ends_with('/') && path.len() < 2048 {
        consider(&format!("{path}/"))?;
    }
    selected.ok_or(ERR_ONVIF_HANDOFF)
}

fn mode_contract(
    mode: &str,
    operation: &str,
) -> Result<(&'static str, &'static str), &'static str> {
    match (mode, operation) {
        ("single", "capture") => Ok(("fss.rtsp_from_onvif_plan.v1", POLICY)),
        ("reconnect", "capture" | "recover" | "index") => {
            Ok(("fss.rtsp_from_onvif_plan.v2", RECONNECT_POLICY))
        }
        _ => Err(ERR_ONVIF_HANDOFF),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_control_subtree_recovers_only_the_exact_explicit_spelling() -> Result<(), &'static str>
    {
        let path = "/PRIVATE_PATH_CANARY/%4a/leaf?opaque=PRIVATE_QUERY_CANARY";
        for root in [
            "/",
            "/PRIVATE_PATH_CANARY",
            "/PRIVATE_PATH_CANARY/",
            "/PRIVATE_PATH_CANARY/%4a",
            "/PRIVATE_PATH_CANARY/%4a/",
            "/PRIVATE_PATH_CANARY/%4a/leaf",
            "/PRIVATE_PATH_CANARY/%4a/leaf/",
        ] {
            assert_eq!(
                resolve_control_root(path, &ContentDigest::sha256(root.as_bytes()).to_text())?,
                root
            );
        }
        Ok(())
    }

    #[test]
    fn hashed_subtree_never_widens_or_decodes_on_mismatch() {
        let path = "/private/%4a/leaf?opaque=PRIVATE_QUERY_CANARY";
        for refused in [
            "/private/%4A",
            "/private/J",
            "/priv",
            "/other",
            "/private/%4a/leaf?opaque=PRIVATE_QUERY_CANARY",
            "/private/%4a/leaf//",
        ] {
            assert_eq!(
                resolve_control_root(path, &ContentDigest::sha256(refused.as_bytes()).to_text()),
                Err(ERR_ONVIF_HANDOFF)
            );
        }
        for digest in [
            "",
            "sha256:0",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(resolve_control_root(path, digest), Err(ERR_ONVIF_HANDOFF));
        }
    }

    #[test]
    fn legacy_wrapper_encoding_has_the_historical_schema_policy_and_field_order()
    -> Result<(), &'static str> {
        let spec = OnvifSourceSpec {
            source: PathBuf::from("/private/handoff.json"),
            expected: ContentDigest::sha256(b"handoff"),
        };
        let identity = ContentDigest::sha256(b"identity");
        let native = ContentDigest::sha256(b"native");
        for (mode, operation, schema, policy) in [
            (
                "single",
                "capture",
                "fss.rtsp_from_onvif_plan.v1",
                "private-digest-bound-stable-onvif-uri:separate-owner-capture-approval:unchanged-source-clock-timing-and-independent-pin-owners:no-camera-or-credential-read-in-preview:v1",
            ),
            (
                "reconnect",
                "recover",
                "fss.rtsp_from_onvif_plan.v2",
                "private-digest-bound-stable-onvif-uri:explicit-native-reconnect-owner:separate-owner-approval:all-derived-destinations-disjoint:private-child-previews:fresh-observed-recovery-approval:no-camera-or-credential-read-in-preview:v2",
            ),
            (
                "reconnect",
                "capture",
                "fss.rtsp_from_onvif_plan.v2",
                "private-digest-bound-stable-onvif-uri:explicit-native-reconnect-owner:separate-owner-approval:all-derived-destinations-disjoint:private-child-previews:fresh-observed-recovery-approval:no-camera-or-credential-read-in-preview:v2",
            ),
            (
                "reconnect",
                "index",
                "fss.rtsp_from_onvif_plan.v2",
                "private-digest-bound-stable-onvif-uri:explicit-native-reconnect-owner:separate-owner-approval:all-derived-destinations-disjoint:private-child-previews:fresh-observed-recovery-approval:no-camera-or-credential-read-in-preview:v2",
            ),
        ] {
            let mut original = CanonicalEncoder::new();
            original.text(schema);
            original.text(policy);
            if mode == "reconnect" {
                original.text(mode);
                original.text(operation);
            }
            original.text("/private/handoff.json");
            original.digest(spec.expected);
            original.digest(identity);
            original.digest(native);
            let expected =
                ContentDigest::sha256(&original.finish_checked().map_err(|_| "encoding")?);
            assert_eq!(spec.approval(identity, mode, operation, native)?, expected);
            let preview = spec.preview(identity, mode, operation, native, "{}")?;
            let fields = [
                "\"schema\"",
                "\"phase\"",
                "\"approval\"",
                "\"policy\"",
                "\"capture_mode\"",
                "\"operation\"",
                "\"onvif_source\"",
                "\"onvif_digest\"",
                "\"onvif_file_identity\"",
                "\"native_capture\"",
                "\"effects\"",
            ];
            let positions = fields.map(|field| preview.find(field).expect("historical field"));
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        }
        Ok(())
    }
}
