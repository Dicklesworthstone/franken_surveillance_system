#![forbid(unsafe_code)]
//! Exact private probe routing bound to the original complete site manifest.
//!
//! A protected UniFi export or ONVIF handoff can supply a presentation without changing the
//! manifest's source kind, camera identity or digest. This pure value grants no network or
//! credential authority; construction and revalidation perform no I/O or DNS lookup. Paths and
//! queries can be bearer capabilities, so only explicit accessors expose them and diagnostics remain redacted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use fss_core::ContentDigest;

use super::{ProbeCodec, SiteError, SiteManifest, SiteProbeReceipt, SiteSource, SourceKind};
use crate::rtsp::uri::validated_uri_parts;
use crate::unifi::SelectedStream;

/// Immutable selected route for one source in the original complete manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct ProbeRoute {
    manifest_digest: ContentDigest,
    source_index: usize,
    peer: SocketAddr,
    authority: String,
    presentation: String,
    control_root: String,
    onvif: Option<OnvifProbeSelection>,
}

/// Exact historical selection, not evidence that the current HTTP device produced the handoff.
#[derive(Clone, Eq, PartialEq)]
struct OnvifProbeSelection {
    handoff_digest: ContentDigest,
    onboarding_plan: ContentDigest,
    profile_digest: ContentDigest,
    codec: ProbeCodec,
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
            peer: source.peer,
            authority: source.authority.clone(),
            presentation: source
                .presentation
                .clone()
                .ok_or(SiteError::MissingField("presentation"))?,
            control_root: source
                .control_root
                .clone()
                .ok_or(SiteError::MissingField("control_root"))?,
            onvif: None,
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
            peer: source.peer,
            authority: source.authority.clone(),
            presentation: presentation.to_owned(),
            control_root: control_root.to_owned(),
            onvif: None,
        })
    }

    /// Bind a protected ONVIF handoff to the original HTTP source and independent RTSP endpoint.
    /// The caller must verify the actual private handoff bytes, onboarding/profile identities,
    /// codec and route before construction. These historical pins grant neither network authority
    /// nor proof of HTTP origin, freshness or current camera identity. No ONVIF request is sent.
    pub fn from_onvif(
        manifest: &SiteManifest,
        source_index: usize,
        selected: &OnvifCaptureRoute,
        onboarding_plan: ContentDigest,
        profile_digest: ContentDigest,
        codec: ProbeCodec,
    ) -> Result<Self, SiteError> {
        selected.validate_for(manifest, source_index)?;
        super::digest(onboarding_plan)?;
        super::digest(profile_digest)?;
        if !matches!(codec, ProbeCodec::Avc | ProbeCodec::Hevc) {
            return Err(SiteError::InvalidField("codec"));
        }
        Ok(Self {
            manifest_digest: selected.manifest_digest,
            source_index,
            peer: selected.peer,
            authority: selected.authority.clone(),
            presentation: selected.presentation.clone(),
            control_root: selected.control_root.clone(),
            onvif: Some(OnvifProbeSelection {
                handoff_digest: selected.handoff_digest,
                onboarding_plan,
                profile_digest,
                codec,
            }),
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
        match &self.onvif {
            Some(selected) => {
                if source.kind != SourceKind::Onvif {
                    return Err(SiteError::InvalidField("kind"));
                }
                super::digest(selected.handoff_digest)?;
                super::digest(selected.onboarding_plan)?;
                super::digest(selected.profile_digest)?;
            }
            None => {
                if source.kind == SourceKind::Onvif
                    || self.peer != source.peer
                    || self.authority != source.authority
                {
                    return Err(SiteError::SourceMismatch);
                }
            }
        }
        super::peer(self.peer)?;
        super::bound_authority(self.peer, &self.authority)?;
        super::route(&self.authority, &self.presentation, &self.control_root)
    }

    /// Validate an observed receipt against this exact selected route and original manifest.
    /// The generic manifest-only receipt validator remains unchanged. Only the explicitly bound
    /// ONVIF route admits its independent RTSP endpoint, with the handoff's codec still pinned.
    pub fn validate_receipt(
        &self,
        manifest: &SiteManifest,
        receipt: &SiteProbeReceipt,
    ) -> Result<(), SiteError> {
        self.validate_for(manifest, self.source_index)?;
        if self.onvif.is_some() {
            receipt.validate()?;
        } else {
            receipt.validate_for(manifest)?;
        }
        if receipt.manifest_digest != self.manifest_digest || receipt.site_id != manifest.site_id {
            return Err(SiteError::StaleManifest);
        }
        let source = source(manifest, self.source_index)?;
        if receipt.source_id != source.source_id
            || receipt.source_generation != source.generation
            || receipt.peer != self.peer
            || receipt.authority != self.authority
            || receipt.presentation != self.presentation
            || receipt.control_root != self.control_root
        {
            return Err(SiteError::SourceMismatch);
        }
        self.validate_codec(manifest, receipt.codec)
    }

    pub(crate) fn validate_codec(
        &self,
        manifest: &SiteManifest,
        codec: ProbeCodec,
    ) -> Result<(), SiteError> {
        let source = source(manifest, self.source_index)?;
        if (source.kind == SourceKind::UnifiProtect && codec == ProbeCodec::Jpeg)
            || self
                .onvif
                .as_ref()
                .is_some_and(|selected| selected.codec != codec)
        {
            return Err(SiteError::InvalidField("codec"));
        }
        Ok(())
    }

    /// Canonical digest of the original complete manifest, not a synthetic RTSP manifest.
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }

    /// Actual literal RTSP peer. An ONVIF HTTP peer is never substituted for this selection.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Exact selected RTSP authority; construction performs no DNS resolution.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
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
/// A live probe requires a separate `ProbeRoute::from_onvif` selection with exact historical
/// onboarding/profile and codec pins, followed by independent network approval.
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

    fn validate_for(&self, manifest: &SiteManifest, source_index: usize) -> Result<(), SiteError> {
        if self.manifest_digest != manifest.digest()? {
            return Err(SiteError::StaleManifest);
        }
        if self.source_index != source_index {
            return Err(SiteError::SourceMismatch);
        }
        if source(manifest, source_index)?.kind != SourceKind::Onvif {
            return Err(SiteError::InvalidField("kind"));
        }
        super::digest(self.handoff_digest)?;
        super::peer(self.peer)?;
        super::bound_authority(self.peer, &self.authority)?;
        super::route(&self.authority, &self.presentation, &self.control_root)
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

/// Check an exact explicit source selection against the unchanged complete manifest.
///
/// Selected routes use the actual receipt endpoints after their owner has verified each
/// direct or protected binding. Excluded direct sources retain their declared route and
/// peer guards, and excluded UniFi sources retain their known literal RTSP peer limits.
/// No excluded protected presentation is invented. In particular, an excluded ONVIF HTTP
/// endpoint is not treated as its unknown RTSP peer. This remains a pure consistency check,
/// with no source authentication, liveness claim, scheduling or capture authority.
pub fn validate_selected_capture_route_inventory(
    manifest: &SiteManifest,
    selected_source_indices: &[usize],
    receipts: &[&SiteProbeReceipt],
) -> Result<(), SiteError> {
    let manifest_digest = manifest.digest()?;
    if selected_source_indices.is_empty()
        || selected_source_indices.len() > manifest.sources.len()
        || receipts.len() != selected_source_indices.len()
    {
        return Err(SiteError::SourceMismatch);
    }
    let selected: BTreeSet<_> = selected_source_indices.iter().copied().collect();
    if selected.len() != selected_source_indices.len()
        || selected
            .iter()
            .any(|index| *index >= manifest.sources.len())
    {
        return Err(SiteError::SourceMismatch);
    }
    let indices: BTreeMap<_, _> = manifest
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| (source.source_id.as_str(), index))
        .collect();
    let mut seen = BTreeSet::new();
    let mut peer_limits = BTreeMap::new();
    let mut routes = BTreeSet::new();
    let mut admit = |peer: SocketAddr,
                     authority: Option<&str>,
                     presentation: Option<&str>,
                     limit: u32|
     -> Result<(), SiteError> {
        let ip = super::physical_peer_ip(peer);
        if peer_limits
            .insert(ip, limit)
            .is_some_and(|old| old != limit)
        {
            return Err(SiteError::InvalidField("max_connections"));
        }
        if let Some((authority, presentation)) = authority.zip(presentation) {
            let route = (
                ip,
                peer.port(),
                super::authority_identity(authority)?,
                super::presentation_identity(presentation)?,
            );
            if !routes.insert(route) {
                return Err(SiteError::DuplicateSource);
            }
        }
        Ok(())
    };
    for receipt in receipts {
        receipt.validate()?;
        if receipt.site_id != manifest.site_id || receipt.manifest_digest != manifest_digest {
            return Err(SiteError::StaleManifest);
        }
        let index = *indices
            .get(receipt.source_id.as_str())
            .ok_or(SiteError::UnknownSource)?;
        let source = &manifest.sources[index];
        if !selected.contains(&index)
            || receipt.source_generation != source.generation
            || !seen.insert(index)
        {
            return Err(SiteError::SourceMismatch);
        }
        admit(
            receipt.peer,
            Some(&receipt.authority),
            Some(&receipt.presentation),
            source.max_connections,
        )?;
    }
    for (index, source) in manifest.sources.iter().enumerate() {
        if selected.contains(&index) {
            continue;
        }
        match source.kind {
            SourceKind::Rtsp | SourceKind::NvrChannel => admit(
                source.peer,
                Some(&source.authority),
                Some(
                    source
                        .presentation
                        .as_deref()
                        .ok_or(SiteError::MissingField("presentation"))?,
                ),
                source.max_connections,
            )?,
            SourceKind::UnifiProtect => admit(source.peer, None, None, source.max_connections)?,
            SourceKind::Onvif => {}
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

    fn selected_probe_route(
        manifest: &SiteManifest,
        receipt: &SiteProbeReceipt,
    ) -> Test<(OnvifCaptureRoute, ProbeRoute)> {
        let capture = OnvifCaptureRoute::new(
            manifest,
            0,
            ContentDigest::sha256(b"actual-handoff-bytes"),
            receipt.peer,
            &receipt.authority,
            &receipt.presentation,
            &receipt.control_root,
        )?;
        let route = ProbeRoute::from_onvif(
            manifest,
            0,
            &capture,
            ContentDigest::sha256(b"historical-onboarding-plan"),
            ContentDigest::sha256(b"historical-selected-profile"),
            receipt.codec,
        )?;
        Ok((capture, route))
    }

    #[test]
    fn onvif_probe_selection_keeps_http_manifest_and_exact_historical_pins() -> Test {
        let (manifest, receipts) = fixture()?;
        let original = manifest.clone();
        let (capture, route) = selected_probe_route(&manifest, &receipts[0])?;
        route.validate_for(&manifest, 0)?;
        route.validate_receipt(&manifest, &receipts[0])?;
        assert_eq!(route.peer(), receipts[0].peer);
        assert_eq!(route.authority(), receipts[0].authority);
        assert_ne!(route.peer(), manifest.sources[0].peer);
        assert_eq!(route.manifest_digest(), manifest.digest()?);
        assert!(receipts[0].validate_for(&manifest).is_err());
        for change in 0..3 {
            let mut capture = capture.clone();
            let mut onboarding = ContentDigest::sha256(b"historical-onboarding-plan");
            let mut profile = ContentDigest::sha256(b"historical-selected-profile");
            match change {
                0 => capture.handoff_digest = ContentDigest::sha256(b"different-file"),
                1 => onboarding = ContentDigest::sha256(b"different-onboarding"),
                _ => profile = ContentDigest::sha256(b"different-profile"),
            }
            let changed = ProbeRoute::from_onvif(
                &manifest,
                0,
                &capture,
                onboarding,
                profile,
                receipts[0].codec,
            )?;
            assert_ne!(changed, route);
        }
        assert_eq!(manifest, original);
        for private in ["camera-10.example", "/live/main", "/live"] {
            assert!(!format!("{route:?}").contains(private));
        }
        Ok(())
    }

    #[test]
    fn onvif_probe_selection_refuses_missing_pins_wrong_codec_and_stale_source() -> Test {
        let (manifest, receipts) = fixture()?;
        let (capture, route) = selected_probe_route(&manifest, &receipts[0])?;
        let valid = ContentDigest::sha256(b"valid-history-pin");
        let absent = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0; 32]);
        for (onboarding, profile, codec) in [
            (absent, valid, ProbeCodec::Avc),
            (valid, absent, ProbeCodec::Avc),
            (valid, valid, ProbeCodec::Jpeg),
        ] {
            assert!(
                ProbeRoute::from_onvif(&manifest, 0, &capture, onboarding, profile, codec).is_err()
            );
        }
        assert_eq!(
            ProbeRoute::from_onvif(&manifest, 1, &capture, valid, valid, ProbeCodec::Avc),
            Err(SiteError::SourceMismatch)
        );
        for change in 0..4 {
            let mut changed = manifest.clone();
            match change {
                0 => changed.sources[0].generation += 1,
                1 => changed.sources[0].onvif_service_path = Some("/onvif/changed".into()),
                2 => changed.sources.swap(0, 1),
                _ => changed.sources.truncate(1),
            }
            assert_eq!(
                route.validate_for(&changed, 0),
                Err(SiteError::StaleManifest)
            );
            assert_eq!(
                ProbeRoute::from_onvif(&changed, 0, &capture, valid, valid, ProbeCodec::Avc),
                Err(SiteError::StaleManifest)
            );
        }
        Ok(())
    }

    #[test]
    fn onvif_probe_receipt_validator_refuses_endpoint_resource_and_codec_substitution() -> Test {
        let (manifest, receipts) = fixture()?;
        let (_, route) = selected_probe_route(&manifest, &receipts[0])?;
        for change in 0..7 {
            let mut receipt = receipts[0].clone();
            match change {
                0 => receipt.peer.set_ip("192.0.2.99".parse()?),
                1 => receipt.authority = "different.example:554".into(),
                2 => receipt.presentation.push_str("?different=1"),
                3 => receipt.control_root = "/".into(),
                4 => receipt.source_generation += 1,
                5 => receipt.source_id = manifest.sources[1].source_id.clone(),
                _ => {
                    receipt.codec = ProbeCodec::Hevc;
                    receipt.parameter_set_digests = [b"vps", b"sps", b"pps"]
                        .map(|bytes| ContentDigest::sha256(bytes))
                        .to_vec();
                }
            }
            // Every candidate remains structurally valid. Refusal is the exact selection,
            // not a coincidental malformed receipt that the generic schema would reject.
            receipt.validate()?;
            assert!(route.validate_receipt(&manifest, &receipt).is_err());
        }
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

    #[test]
    fn explicit_selected_inventory_requires_exact_nonempty_unique_membership() -> Test {
        let (manifest, receipts) = fixture()?;
        validate_selected_capture_route_inventory(&manifest, &[1], &[&receipts[1]])?;
        for (selection, inventory) in [
            (vec![], vec![]),
            (vec![0], vec![]),
            (vec![0], vec![&receipts[0], &receipts[1]]),
            (vec![0], vec![&receipts[1]]),
            (vec![0, 1], vec![&receipts[0], &receipts[0]]),
            (vec![0, 0], vec![&receipts[0], &receipts[1]]),
            (vec![2], vec![&receipts[0]]),
        ] {
            assert!(
                validate_selected_capture_route_inventory(&manifest, &selection, &inventory)
                    .is_err()
            );
        }
        let mut stale = receipts[0].clone();
        stale.manifest_digest = ContentDigest::sha256(b"different-manifest");
        assert_eq!(
            validate_selected_capture_route_inventory(&manifest, &[0], &[&stale]),
            Err(SiteError::StaleManifest)
        );
        Ok(())
    }

    fn with_excluded_direct() -> Test<(SiteManifest, Vec<SiteProbeReceipt>)> {
        let (mut manifest, mut receipts) = fixture()?;
        let direct =
            SiteManifest::parse(include_str!("../../../../fixtures/site/manifest.v1.json"))?;
        manifest.sources[1] = direct.sources[1].clone();
        for receipt in &mut receipts {
            receipt.manifest_digest = manifest.digest()?;
        }
        Ok((manifest, receipts))
    }

    #[test]
    fn selected_actual_route_still_cannot_duplicate_an_excluded_direct_route() -> Test {
        let (manifest, mut receipts) = with_excluded_direct()?;
        receipts[0].peer = "[::ffff:192.0.2.11]:554".parse()?;
        receipts[0].authority = "CAMERA-11.EXAMPLE:554".to_owned();
        receipts[0].presentation = "/l%69ve/main".to_owned();
        receipts[0].control_root = "/".to_owned();
        assert_eq!(
            validate_selected_capture_route_inventory(&manifest, &[0], &[&receipts[0]]),
            Err(SiteError::DuplicateSource)
        );
        Ok(())
    }

    #[test]
    fn selected_actual_peer_keeps_known_excluded_source_connection_limits() -> Test {
        let (mut manifest, mut receipts) = with_excluded_direct()?;
        manifest.sources[1].max_connections = 2;
        receipts[0].peer = "[::ffff:192.0.2.11]:8554".parse()?;
        receipts[0].authority = "camera-11.example:8554".to_owned();
        receipts[0].manifest_digest = manifest.digest()?;
        assert_eq!(
            validate_selected_capture_route_inventory(&manifest, &[0], &[&receipts[0]]),
            Err(SiteError::InvalidField("max_connections"))
        );
        // The UniFi RTSP peer is still explicit even when its private presentation is excluded.
        let source = &mut manifest.sources[1];
        source.kind = SourceKind::UnifiProtect;
        source.presentation = None;
        source.control_root = None;
        source.unifi_camera_id = Some("camera:excluded".to_owned());
        receipts[0].manifest_digest = manifest.digest()?;
        assert_eq!(
            validate_selected_capture_route_inventory(&manifest, &[0], &[&receipts[0]]),
            Err(SiteError::InvalidField("max_connections"))
        );
        manifest.sources[1].max_connections = 1;
        receipts[0].manifest_digest = manifest.digest()?;
        validate_selected_capture_route_inventory(&manifest, &[0], &[&receipts[0]])?;
        Ok(())
    }

    #[test]
    fn excluded_onvif_management_scope_never_becomes_an_invented_capture_route() -> Test {
        let (mut manifest, mut receipts) = fixture()?;
        manifest.sources[1].max_connections = 2;
        manifest.sources[1].owner_authorized = false;
        receipts[0].peer = "192.0.2.11:554".parse()?;
        receipts[0].authority = "camera-11.example:554".to_owned();
        receipts[0].manifest_digest = manifest.digest()?;
        validate_selected_capture_route_inventory(&manifest, &[0], &[&receipts[0]])?;
        // The default API still requires every manifest receipt.
        assert!(validate_capture_route_inventory(&manifest, &[&receipts[0]]).is_err());
        Ok(())
    }
}
