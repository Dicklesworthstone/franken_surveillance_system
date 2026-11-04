#![forbid(unsafe_code)]
//! Exact private probe routing bound to the original complete site manifest.
//!
//! A UniFi export can supply a presentation without changing the manifest's source kind,
//! camera identity or digest. This pure value grants no network or credential authority;
//! construction and revalidation perform no I/O or DNS lookup. Paths and queries can be bearer
//! capabilities, so only explicit accessors expose them and diagnostics remain redacted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use fss_core::ContentDigest;

use super::{SiteError, SiteManifest, SiteProbeReceipt, SiteSource, SourceKind};
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

/// Historical ONVIF handoff route bound to one source in the original complete manifest.
///
/// The ONVIF HTTP endpoint and selected RTSP endpoint are independent declarations. This
/// value records their exact operator binding; it does not authenticate the handoff's origin,
/// prove that the HTTP device path produced it, or grant native probe/capture authority.
/// It deliberately is not a `ProbeRoute`: live owners retain their existing supported scope.
#[derive(Clone, Eq, PartialEq)]
pub struct OnvifCaptureRoute {
    manifest_digest: ContentDigest,
    source_index: usize,
    handoff_digest: ContentDigest,
    peer: SocketAddr,
    authority: String,
    presentation: String,
    control_root: String,
}

impl fmt::Debug for OnvifCaptureRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnvifCaptureRoute")
            .field("manifest_digest", &self.manifest_digest)
            .field("source_index", &self.source_index)
            .field("handoff_digest", &self.handoff_digest)
            .finish_non_exhaustive()
    }
}

impl OnvifCaptureRoute {
    /// Bind an exact private handoff to independently supplied RTSP scope and control limits.
    /// Callers must compare these coordinates and codec with the actual protected handoff.
    pub fn new(
        manifest: &SiteManifest,
        source_index: usize,
        handoff_digest: ContentDigest,
        peer: SocketAddr,
        authority: &str,
        presentation: &str,
        control_root: &str,
    ) -> Result<Self, SiteError> {
        let manifest_digest = manifest.digest()?;
        if source(manifest, source_index)?.kind != SourceKind::Onvif {
            return Err(SiteError::InvalidField("kind"));
        }
        super::digest(handoff_digest)?;
        super::peer(peer)?;
        super::bound_authority(peer, authority)?;
        super::route(authority, presentation, control_root)?;
        Ok(Self {
            manifest_digest,
            source_index,
            handoff_digest,
            peer,
            authority: authority.to_owned(),
            presentation: presentation.to_owned(),
            control_root: control_root.to_owned(),
        })
    }

    /// Validate one complete supplied receipt against this exact historical selection.
    /// Existing `SiteProbeReceipt::validate_for` remains strict for manifest-only routes.
    pub fn validate_receipt(
        &self,
        manifest: &SiteManifest,
        receipt: &SiteProbeReceipt,
    ) -> Result<(), SiteError> {
        receipt.validate()?;
        if self.manifest_digest != manifest.digest()?
            || receipt.manifest_digest != self.manifest_digest
            || receipt.site_id != manifest.site_id
        {
            return Err(SiteError::StaleManifest);
        }
        let source = source(manifest, self.source_index)?;
        if source.kind != SourceKind::Onvif
            || receipt.source_id != source.source_id
            || receipt.source_generation != source.generation
            || receipt.peer != self.peer
            || receipt.authority != self.authority
            || receipt.presentation != self.presentation
            || receipt.control_root != self.control_root
        {
            return Err(SiteError::SourceMismatch);
        }
        Ok(())
    }

    /// Exact historical file content identity bound to this source and route.
    #[must_use]
    pub const fn handoff_digest(&self) -> ContentDigest {
        self.handoff_digest
    }
}

/// Check complete selected-route inventory for collisions and physical-peer admission drift.
///
/// This is a routing consistency check, not source authentication or a substitute for each
/// receipt's exact direct, UniFi or ONVIF selection validation. Callers first validate their
/// protected selections. The original manifest remains unchanged; connection declarations
/// are grouped by the actual selected RTSP IP, including mapped-IPv4 aliases, never an ONVIF
/// HTTP port or a synthetic rewritten manifest. No live connection is scheduled here.
pub fn validate_capture_route_inventory(
    manifest: &SiteManifest,
    receipts: &[&SiteProbeReceipt],
) -> Result<(), SiteError> {
    let manifest_digest = manifest.digest()?;
    if receipts.len() != manifest.sources.len() {
        return Err(SiteError::SourceMismatch);
    }
    let mut indices = BTreeMap::new();
    for (index, source) in manifest.sources.iter().enumerate() {
        indices.insert(source.source_id.as_str(), index);
    }
    let mut seen = BTreeSet::new();
    let mut peer_limits = BTreeMap::new();
    let mut routes = BTreeSet::new();
    for receipt in receipts {
        receipt.validate()?;
        if receipt.site_id != manifest.site_id || receipt.manifest_digest != manifest_digest {
            return Err(SiteError::StaleManifest);
        }
        let index = *indices
            .get(receipt.source_id.as_str())
            .ok_or(SiteError::UnknownSource)?;
        let source = &manifest.sources[index];
        if receipt.source_generation != source.generation || !seen.insert(index) {
            return Err(SiteError::SourceMismatch);
        }
        let ip = super::physical_peer_ip(receipt.peer);
        if peer_limits
            .insert(ip, source.max_connections)
            .is_some_and(|limit| limit != source.max_connections)
        {
            return Err(SiteError::InvalidField("max_connections"));
        }
        let route = (
            ip,
            receipt.peer.port(),
            super::authority_identity(&receipt.authority)?,
            super::presentation_identity(&receipt.presentation)?,
        );
        if !routes.insert(route) {
            return Err(SiteError::DuplicateSource);
        }
    }
    Ok(())
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

#[cfg(test)]
mod onvif_tests {
    use super::*;

    type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> Test<(SiteManifest, Vec<SiteProbeReceipt>)> {
        let mut manifest =
            SiteManifest::parse(include_str!("../../../../fixtures/site/manifest.v1.json"))?;
        for source in &mut manifest.sources {
            source.kind = SourceKind::Onvif;
            source.peer.set_port(80);
            source.authority = format!("{}:80", source.peer.ip());
            source.onvif_service_path = Some("/onvif/device_service".to_owned());
            source.presentation = None;
            source.control_root = None;
        }
        let mut receipts = crate::site::parse_probe_receipts(include_bytes!(
            "../../../../fixtures/site/probes.v1.json"
        ))?;
        for receipt in &mut receipts {
            receipt.manifest_digest = manifest.digest()?;
        }
        Ok((manifest, receipts))
    }

    #[test]
    fn historical_route_binds_original_manifest_and_source_without_relaxing_manifest_validation()
    -> Test {
        let (manifest, receipts) = fixture()?;
        let probe = &receipts[0];
        assert!(probe.validate_for(&manifest).is_err());
        let digest = ContentDigest::sha256(b"actual-handoff-bytes");
        let route = OnvifCaptureRoute::new(
            &manifest,
            0,
            digest,
            probe.peer,
            &probe.authority,
            &probe.presentation,
            &probe.control_root,
        )?;
        assert_eq!(route.handoff_digest(), digest);
        route.validate_receipt(&manifest, probe)?;
        assert!(route.validate_receipt(&manifest, &receipts[1]).is_err());
        let mut changed = manifest.clone();
        changed.generation += 1;
        assert!(route.validate_receipt(&changed, probe).is_err());
        let mut changed = probe.clone();
        changed.source_generation += 1;
        assert!(route.validate_receipt(&manifest, &changed).is_err());
        assert!(ProbeRoute::direct(&manifest, 0).is_err());
        Ok(())
    }

    #[test]
    fn physical_admission_uses_selected_rtsp_peers_and_mapped_ipv4_aliases() -> Test {
        let (mut manifest, mut receipts) = fixture()?;
        manifest.sources[0].max_connections = 1;
        manifest.sources[1].max_connections = 2;
        let digest = manifest.digest()?;
        for receipt in &mut receipts {
            receipt.manifest_digest = digest;
        }
        // Separate HTTP peers do not grant inconsistent limits for one selected RTSP device.
        receipts[1].peer = "[::ffff:192.0.2.10]:8554".parse()?;
        receipts[1].authority = "camera-10.example:8554".to_owned();
        assert!(matches!(
            validate_capture_route_inventory(&manifest, &[&receipts[0], &receipts[1]]),
            Err(SiteError::InvalidField("max_connections"))
        ));
        manifest.sources[1].max_connections = 1;
        let digest = manifest.digest()?;
        for receipt in &mut receipts {
            receipt.manifest_digest = digest;
        }
        validate_capture_route_inventory(&manifest, &[&receipts[1], &receipts[0]])?;
        Ok(())
    }

    #[test]
    fn selected_route_inventory_preserves_existing_route_equivalence_and_exact_coverage() -> Test {
        let (manifest, mut receipts) = fixture()?;
        receipts[1].peer = "[::ffff:192.0.2.10]:554".parse()?;
        receipts[1].authority = "CAMERA-10.EXAMPLE:554".to_owned();
        receipts[1].presentation = "/l%69ve/main".to_owned();
        receipts[1].control_root = "/".to_owned();
        assert!(matches!(
            validate_capture_route_inventory(&manifest, &[&receipts[0], &receipts[1]]),
            Err(SiteError::DuplicateSource)
        ));
        assert!(validate_capture_route_inventory(&manifest, &[&receipts[0]]).is_err());
        assert!(
            validate_capture_route_inventory(&manifest, &[&receipts[0], &receipts[0]]).is_err()
        );
        Ok(())
    }
}
