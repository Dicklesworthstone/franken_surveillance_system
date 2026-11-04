#![forbid(unsafe_code)]
//! Exact private probe routing bound to the original complete site manifest.
//!
//! A UniFi export can supply a presentation without changing the manifest's source kind,
//! camera identity or digest. This pure value grants no network or credential authority;
//! construction and revalidation perform no I/O or DNS lookup. Paths and queries can be bearer
//! capabilities, so only explicit accessors expose them and diagnostics remain redacted.

use std::fmt;
use std::net::IpAddr;

use fss_core::ContentDigest;

use super::{SiteError, SiteManifest, SiteSource, SourceKind};
use crate::rtsp::uri::validated_uri_parts;
use crate::unifi::SelectedStream;

/// Immutable selected route for one source in the original complete manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct ProbeRoute {
    manifest_digest: ContentDigest,
    source_index: usize,
    presentation: String,
    control_root: String,
}

impl fmt::Debug for ProbeRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeRoute")
            .field("source_index", &self.source_index)
            .field("presentation", &"<redacted>")
            .field("control_root", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ProbeRoute {
    /// Bind the existing explicit RTSP/NVR route without changing any source declaration.
    /// ONVIF and UniFi sources cannot enter this constructor by pretending to be direct RTSP.
    pub fn direct(manifest: &SiteManifest, source_index: usize) -> Result<Self, SiteError> {
        let manifest_digest = manifest.digest()?;
        let source = source(manifest, source_index)?;
        if !matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel) {
            return Err(SiteError::InvalidField("kind"));
        }
        Ok(Self {
            manifest_digest,
            source_index,
            presentation: source
                .presentation
                .clone()
                .ok_or(SiteError::MissingField("presentation"))?,
            control_root: source
                .control_root
                .clone()
                .ok_or(SiteError::MissingField("control_root"))?,
        })
    }

    /// Bind the exact selected export to its declared camera and literal manifest peer.
    /// RTSPS is refused, never downgraded; no codec or cadence is inferred from vendor metadata.
    /// The control root is the exact selected path without its query, never a broader subtree.
    pub fn from_unifi(
        manifest: &SiteManifest,
        source_index: usize,
        selected: &SelectedStream<'_>,
    ) -> Result<Self, SiteError> {
        let manifest_digest = manifest.digest()?;
        let source = source(manifest, source_index)?;
        if source.kind != SourceKind::UnifiProtect {
            return Err(SiteError::InvalidField("kind"));
        }
        if source.unifi_camera_id.as_deref() != Some(selected.camera().id()) {
            return Err(SiteError::SourceMismatch);
        }
        let endpoint = selected.endpoint();
        let uri = endpoint
            .require_plaintext_rtsp()
            .map_err(|_| SiteError::InvalidField("transport"))?;
        let (authority, presentation) =
            validated_uri_parts(uri).map_err(|_| SiteError::InvalidField("presentation"))?;
        if authority != source.authority
            || endpoint.port().unwrap_or(554) != source.peer.port()
            || endpoint
                .host()
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip != source.peer.ip())
        {
            return Err(SiteError::SourceMismatch);
        }
        let control_root = presentation.split('?').next().ok_or(SiteError::Shape)?;
        super::route(authority, presentation, control_root)?;
        Ok(Self {
            manifest_digest,
            source_index,
            presentation: presentation.to_owned(),
            control_root: control_root.to_owned(),
        })
    }

    /// Revalidate against the original full manifest and source ordinal before any I/O.
    /// A reordered, narrowed, relabeled or otherwise changed manifest requires a new selection.
    pub fn validate_for(
        &self,
        manifest: &SiteManifest,
        source_index: usize,
    ) -> Result<(), SiteError> {
        if self.manifest_digest != manifest.digest()? {
            return Err(SiteError::StaleManifest);
        }
        if self.source_index != source_index {
            return Err(SiteError::SourceMismatch);
        }
        let source = source(manifest, source_index)?;
        super::route(&source.authority, &self.presentation, &self.control_root)
    }

    /// Canonical digest of the original complete manifest, not a synthetic RTSP manifest.
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }

    /// Exact private resource, including query order, escaping and case. Never use in diagnostics.
    #[must_use]
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Exact private control subtree. Never use in diagnostics.
    #[must_use]
    pub fn control_root(&self) -> &str {
        &self.control_root
    }
}

fn source(manifest: &SiteManifest, source_index: usize) -> Result<&SiteSource, SiteError> {
    let source = manifest
        .sources
        .get(source_index)
        .ok_or(SiteError::UnknownSource)?;
    if !source.owner_authorized {
        return Err(SiteError::InvalidField("owner_authorized"));
    }
    if !source.plaintext {
        return Err(SiteError::InvalidField("plaintext"));
    }
    Ok(source)
}
