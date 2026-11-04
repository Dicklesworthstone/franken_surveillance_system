#![forbid(unsafe_code)]
//! Pure UniFi Protect selection and the existing native capture wrapper's approval.
//!
//! The caller supplies bytes and the exact fingerprint observed by the private-file
//! owner. This module does not open or authenticate that file, inspect destinations,
//! read credentials, contact a console, or grant capture authority. The native executor
//! must still reopen and revalidate the protected export before checking its approval.
//! Selected stream capabilities stay inside a private argument owner; reports expose
//! only the existing redacted native preview and metadata digests.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::rtsp::client::validated_uri_parts;
use fss_reference::unifi::{
    ProtectError, ProtectQuality, ProtectSource, ProtectView, TransportChoice,
};

use crate::json_output::{object, string};

/// Existing payload-free source/selection refusal identity.
pub const ERR_UNIFI_SOURCE: &str = "ERR-CAPTURE-UNIFI-SOURCE-001";
/// Existing exact outer-approval refusal identity.
pub const ERR_UNIFI_APPROVAL: &str = "ERR-CAPTURE-UNIFI-APPROVAL-001";
/// Existing refusal for an unavailable or secure-only transport.
pub const ERR_UNIFI_TRANSPORT: &str = "ERR-CAPTURE-UNIFI-TRANSPORT-001";
/// Existing refusal for a selected endpoint outside the approved literal peer.
pub const ERR_UNIFI_ROUTE: &str = "ERR-CAPTURE-UNIFI-ROUTE-001";

const SCHEMA: &str = "fss.rtsp_from_unifi_plan.v1";
const POLICY: &str = "private-unifi-protect-capability-selected-view:exact-owner-peer:explicit-codec-and-cadence:\
no-url-rewrite:no-quality-fallback:no-tls-downgrade:revalidate-private-source-before-capture:v1";
const MAX_EXPORT_BYTES: usize = 262_144;
const MAX_ARGUMENTS: usize = 196;

/// An explicit private export and exact camera rendition selection.
///
/// This describes requested scope only. It neither validates the file's current
/// identity nor interprets vendor metadata as observed media or current liveness.
#[derive(Clone, Eq, PartialEq)]
pub struct UnifiSourceSpec {
    /// Absolute private export reference, without reading or normalizing the path.
    pub source: PathBuf,
    /// Exact SHA-256 digest of the complete export document.
    pub expected: ContentDigest,
    /// Exact requested rendition; a package camera remains a separate view.
    pub quality: ProtectQuality,
    /// Published endpoint or independently supplied operator RTSP endpoint.
    pub transport: TransportChoice,
    /// Literal peer independently approved by the caller; never resolved from a URL.
    pub peer: SocketAddr,
}

impl fmt::Debug for UnifiSourceSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnifiSourceSpec")
            .field("expected", &self.expected)
            .field("quality", &self.quality)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

/// A borrow of the exact private-file owner's observed input.
///
/// Supply `InputLease::fingerprint`'s full 88 bytes from the
/// actual lease alongside that lease's bytes. There is deliberately no default,
/// content-derived substitute, or helper that invents a filesystem identity.
/// A typed caller can supply observations but cannot authenticate them through this
/// pure API; the native executor must independently repeat the protected read.
#[derive(Clone, Copy)]
pub struct ProtectedUnifiInput<'a> {
    /// Complete bounded bytes borrowed from the protected export owner.
    pub bytes: &'a [u8],
    /// Exact device/inode/permissions/owner/link/length/time fingerprint from that owner.
    pub fingerprint: &'a [u8; 88],
}

impl fmt::Debug for ProtectedUnifiInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedUnifiInput")
            .field("byte_count", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A private selected route plus safe metadata for the existing native capture planner.
///
/// This is not an approved capture. The native parser still validates every capture
/// argument and effective limit. Route-bearing arguments are accessible only inside
/// an explicit callback, and diagnostic formatting never exposes them.
pub struct PreparedUnifiSelection {
    spec: UnifiSourceSpec,
    identity: ContentDigest,
    camera: ContentDigest,
    view: &'static str,
    authority: String,
    presentation: String,
    control_root: String,
    arguments: Vec<OsString>,
}

impl fmt::Debug for PreparedUnifiSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedUnifiSelection")
            .field("identity", &self.identity)
            .field("camera", &self.camera)
            .field("view", &self.view)
            .field("argument_count", &self.arguments.len())
            .finish_non_exhaustive()
    }
}

impl PreparedUnifiSelection {
    /// SHA-256 of the caller-supplied complete private-file fingerprint.
    #[must_use]
    pub const fn file_identity(&self) -> ContentDigest {
        self.identity
    }

    /// Digest of the selected export's exact camera ID; no camera name is exposed.
    #[must_use]
    pub const fn camera_ref(&self) -> ContentDigest {
        self.camera
    }

    /// `main` or the distinct `package` view, without inferring a physical camera model.
    #[must_use]
    pub const fn view(&self) -> &'static str {
        self.view
    }

    /// Check supplied receipt coordinates without exposing the selected private URI.
    /// Exact spelling is retained; this comparison does not assert freshness or origin.
    #[must_use]
    pub fn matches_route(
        &self,
        peer: SocketAddr,
        authority: &str,
        presentation: &str,
        control_root: &str,
    ) -> bool {
        self.spec.peer == peer
            && self.authority == authority
            && self.presentation == presentation
            && self.control_root == control_root
    }

    /// Borrow private route-bearing arguments for the existing native parser only.
    /// The callback must not log these arguments or return them in operator reports.
    pub fn with_capture_arguments<T>(&self, prepare: impl FnOnce(&[OsString]) -> T) -> T {
        prepare(&self.arguments)
    }
}

impl UnifiSourceSpec {
    /// Select one exact endpoint and compose its private native arguments, without I/O.
    ///
    /// `native_args` are the ordinary capture options, including explicit `--peer`
    /// and `--codec`. Wrapper options, `--approve`, `--authority`, and `--presentation`
    /// are refused. The caller must pass the result to the real native capture parser;
    /// this layer never substitutes validation or effective limits for that owner.
    pub fn prepare(
        &self,
        input: ProtectedUnifiInput<'_>,
        native_args: &[OsString],
    ) -> Result<PreparedUnifiSelection, &'static str> {
        self.validate()?;
        let control_root = checked_arguments(native_args, self.peer)?;
        if input.bytes.is_empty()
            || input.bytes.len() > MAX_EXPORT_BYTES
            || ContentDigest::sha256(input.bytes) != self.expected
        {
            return Err(ERR_UNIFI_SOURCE);
        }
        let source = ProtectSource::parse(input.bytes).map_err(selection_error)?;
        let selected = source
            .select(self.quality, self.transport)
            .map_err(selection_error)?;
        let endpoint = selected.endpoint();
        let uri = endpoint
            .require_plaintext_rtsp()
            .map_err(|_| ERR_UNIFI_TRANSPORT)?;
        let (authority, presentation) = validated_uri_parts(uri).map_err(|_| ERR_UNIFI_SOURCE)?;
        if endpoint.port().unwrap_or(554) != self.peer.port()
            || endpoint
                .host()
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip != self.peer.ip())
        {
            return Err(ERR_UNIFI_ROUTE);
        }
        let mut arguments = native_args.to_vec();
        for (key, value) in [("--authority", authority), ("--presentation", presentation)] {
            arguments.extend([OsString::from(key), OsString::from(value)]);
        }
        let control_root = match control_root {
            Some(root) => root,
            None => {
                let path = presentation.split('?').next().ok_or(ERR_UNIFI_SOURCE)?;
                arguments.extend([OsString::from("--control-root"), OsString::from(path)]);
                path
            }
        };
        Ok(PreparedUnifiSelection {
            spec: self.clone(),
            identity: ContentDigest::sha256(input.fingerprint),
            camera: ContentDigest::sha256(selected.camera().id().as_bytes()),
            view: match selected.view() {
                ProtectView::Main => "main",
                ProtectView::Package => "package",
            },
            authority: authority.to_owned(),
            presentation: presentation.to_owned(),
            control_root: control_root.to_owned(),
            arguments,
        })
    }

    /// The unchanged native UniFi outer approval, including its actual file identity.
    /// Mode and operation must be supplied by the existing native owner, not metadata.
    pub fn approval(
        &self,
        identity: ContentDigest,
        mode: &str,
        operation: &str,
        native: ContentDigest,
    ) -> Result<ContentDigest, &'static str> {
        self.validate()?;
        check_operation(mode, operation)?;
        let mut encoded = CanonicalEncoder::new();
        // Preserve the native wrapper's existing policy, field order and digest family.
        encoded.text("fss.rtsp_capture_cli_plan.v1");
        encoded.text(POLICY);
        encoded.text(self.source.to_str().ok_or(ERR_UNIFI_SOURCE)?);
        encoded.digest(self.expected);
        encoded.digest(identity);
        encoded.text(self.quality.as_str());
        encoded.text(self.transport_name());
        encoded.text(mode);
        encoded.text(operation);
        encoded.digest(native);
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| ERR_UNIFI_SOURCE)?,
        ))
    }

    /// Render the unchanged wrapper report around the real native private-URI preview.
    ///
    /// The caller must supply the existing native parser's `private_uri_preview` (or
    /// reconnect private preview), never a generic unredacted plan. No source-file or
    /// camera capability token is formatted by this function.
    pub fn preview(
        &self,
        prepared: &PreparedUnifiSelection,
        mode: &str,
        operation: &str,
        native: ContentDigest,
        private_native_preview: &str,
    ) -> Result<String, &'static str> {
        if prepared.spec != *self {
            return Err(ERR_UNIFI_SOURCE);
        }
        Ok(object(&[
            ("schema", string(SCHEMA)),
            ("phase", string("planned")),
            (
                "approval",
                string(
                    &self
                        .approval(prepared.identity, mode, operation, native)?
                        .to_text(),
                ),
            ),
            ("policy", string(POLICY)),
            ("quality", string(self.quality.as_str())),
            ("view", string(prepared.view)),
            ("camera_ref", string(&prepared.camera.to_text())),
            ("stream_transport", string(self.transport_name())),
            ("capture_mode", string(mode)),
            ("operation", string(operation)),
            ("unifi_digest", string(&self.expected.to_text())),
            ("unifi_file_identity", string(&prepared.identity.to_text())),
            ("native_capture", private_native_preview.to_owned()),
            ("model_specific_assumptions", "false".into()),
            ("hardware_qualified", "false".into()),
            ("effects_started", "false".into()),
        ]))
    }

    fn validate(&self) -> Result<(), &'static str> {
        let text = self.source.to_str().ok_or(ERR_UNIFI_SOURCE)?;
        if text.is_empty()
            || text.len() > 4096
            || text.chars().any(char::is_control)
            || !self.source.is_absolute()
            || self.source.file_name().is_none()
            || self
                .source
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || text.split('/').any(|part| matches!(part, "." | ".."))
            || self.expected.algorithm() != DigestAlgorithm::Sha256
            || self.expected.bytes() == [0; 32]
        {
            return Err(ERR_UNIFI_SOURCE);
        }
        Ok(())
    }

    pub(crate) fn transport_name(&self) -> &'static str {
        match self.transport {
            TransportChoice::Published => "published",
            TransportChoice::OperatorRtsp => "operator-rtsp",
        }
    }
}

fn selection_error(error: ProtectError) -> &'static str {
    match error {
        ProtectError::MissingStream(_) => "ERR-CAPTURE-UNIFI-STREAM-MISSING-001",
        ProtectError::DisabledStream(_) => "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001",
        ProtectError::PackageUnavailable => "ERR-CAPTURE-UNIFI-PACKAGE-001",
        ProtectError::MissingOperatorRtsp | ProtectError::NonRtspOverride => ERR_UNIFI_TRANSPORT,
        ProtectError::SecureTransportRequired => ERR_UNIFI_TRANSPORT,
        _ => ERR_UNIFI_SOURCE,
    }
}

fn check_operation(mode: &str, operation: &str) -> Result<(), &'static str> {
    match (mode, operation) {
        ("single", "capture") | ("reconnect", "capture" | "recover" | "index") => Ok(()),
        _ => Err(ERR_UNIFI_SOURCE),
    }
}

fn checked_arguments(args: &[OsString], peer: SocketAddr) -> Result<Option<&str>, &'static str> {
    if args.len() > MAX_ARGUMENTS
        || !args.len().is_multiple_of(2)
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ERR_UNIFI_SOURCE);
    }
    let mut seen = BTreeSet::new();
    let mut principal = "principal:local-operator";
    let mut requested_peer = None;
    let mut control_root = None;
    let mut has_codec = false;
    for pair in args.as_chunks::<2>().0 {
        let key = pair[0].to_str().ok_or(ERR_UNIFI_SOURCE)?;
        let value = pair[1].to_str().ok_or(ERR_UNIFI_SOURCE)?;
        if value.is_empty() || !seen.insert(key) {
            return Err(ERR_UNIFI_SOURCE);
        }
        match key {
            "--approve" | "--authority" | "--presentation" | "--unifi-source"
            | "--unifi-digest" | "--quality" | "--stream-transport" | "--capture-mode" => {
                return Err(ERR_UNIFI_SOURCE);
            }
            "--principal" => principal = value,
            "--peer" => {
                requested_peer = Some(value.parse::<SocketAddr>().map_err(|_| ERR_UNIFI_SOURCE)?);
            }
            "--control-root" => control_root = Some(value),
            "--codec" => has_codec = matches!(value, "avc" | "hevc"),
            _ => {}
        }
    }
    PrincipalId::parse(principal).map_err(|_| ERR_UNIFI_SOURCE)?;
    if principal.len() > 256 || !has_codec || requested_peer.is_none() {
        return Err(ERR_UNIFI_SOURCE);
    }
    if requested_peer != Some(peer) {
        return Err(ERR_UNIFI_ROUTE);
    }
    Ok(control_root)
}

#[cfg(test)]
#[path = "unifi_plan/tests.rs"]
mod tests;
