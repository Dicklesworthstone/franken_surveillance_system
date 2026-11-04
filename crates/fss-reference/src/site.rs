#![forbid(unsafe_code)]
//! Bounded site onboarding contracts (VIT-001) and separately scoped native probes.
//!
//! A manifest is requested owner scope, not authenticated authority. A supplied probe receipt
//! describes observations but does not authenticate the observer, establish freshness, grant
//! rights, or prove a camera is currently reachable. Capture must revalidate its own route and
//! media pins. Credential paths are references only; this module never opens them.
//!
//! JSON is an input representation. Digests use an explicit versioned canonical encoding of
//! validated typed values, including source order, policy references and every observation pin.

mod parse;
mod wire;

/// Pure bounded observations for native RTSP site probe receipts.
pub mod probe_observation;

/// Exact private RTSP routing bound to the original direct or UniFi site source.
pub mod probe_route;

/// Session-owned native RTSP probing with explicit authority, bounds and remote-close evidence.
pub mod live_probe;

/// Pure zone containment and dwell-interval reduction (VIT-012, smallest slice).
pub mod zone_dwell;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Component, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm};

pub use parse::{parse_manifest, parse_probe_receipts};

/// Manifest input schema identity.
pub const SITE_MANIFEST_SCHEMA: &str = "fss.site_camera_manifest.v1";
/// One observation receipt schema identity. Receipt files contain a bounded JSON array.
pub const SITE_PROBE_RECEIPT_SCHEMA: &str = "fss.site_probe_receipt.v1";
/// Maximum complete input document, before parsing or allocating decoded values.
pub const MAX_SITE_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum sources or probe receipts in one complete site input.
pub const MAX_SITE_SOURCES: usize = 64;
/// Stable identifier byte bound.
pub const MAX_SITE_ID_BYTES: usize = 128;
/// Maximum zones for one source.
pub const MAX_SOURCE_ZONES: usize = 32;
/// Maximum vertices in one simple polygon.
pub const MAX_ZONE_VERTICES: usize = 64;
/// Aggregate vertex ceiling across a site, independent of the JSON parser's node budget.
pub const MAX_SITE_VERTICES: usize = 8192;
/// Maximum payment masks for one source.
pub const MAX_PAYMENT_MASKS: usize = 32;
/// Coordinates are normalized millionths of the image, with an inclusive outer edge.
pub const SITE_COORDINATE_SCALE: u32 = 1_000_000;
/// Maximum observed pictures in one bounded probe receipt.
pub const MAX_PROBE_FRAMES: u32 = 1_000_000;
/// Floor for a plausible `CLOCK_REALTIME` sample: 2023-11-14T22:13:20Z in nanoseconds
/// since the Unix epoch. A witness at or before this is a clearly wrong clock
/// (zero, an epoch default, or a stuck RTC), not evidence (VIT-019).
pub const MIN_PLAUSIBLE_WALL_CLOCK_UNIX_NS: u64 = 1_700_000_000_000_000_000;
/// Ceiling on an admitted NTP/chrony offset uncertainty, in nanoseconds (10 seconds).
/// Beyond this the clock is effectively unsynchronized and must not be reported
/// as a witness at all.
pub const MAX_CLOCK_UNCERTAINTY_NS: u64 = 10_000_000_000;

/// Pure refusal categories contain only static field names, never input values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SiteError {
    /// Input, item count, geometry, or canonical output exceeded a hard bound.
    Limit,
    /// Invalid UTF-8, JSON syntax, duplicate key, or parser limit.
    Json,
    /// Wrong object/array shape.
    Shape,
    /// Required known field is absent.
    MissingField(&'static str),
    /// Unknown field, including attempted inline credentials.
    UnknownField,
    /// A known field has invalid syntax, type, bounds, or semantics.
    InvalidField(&'static str),
    /// A site source identity or normalized RTSP route occurs more than once.
    DuplicateSource,
    /// A source zone identity occurs more than once.
    DuplicateZone,
    /// A receipt set repeats a source identity.
    DuplicateProbe,
    /// A receipt names a different site or manifest generation/digest.
    StaleManifest,
    /// A receipt names no source in the manifest.
    UnknownSource,
    /// A receipt's generation or route does not match its source.
    SourceMismatch,
}

impl SiteError {
    /// Stable diagnostic identity; never formats untrusted input.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Limit => "ERR-SITE-INPUT-LIMIT-001",
            Self::Json => "ERR-SITE-JSON-001",
            Self::Shape | Self::MissingField(_) | Self::UnknownField | Self::InvalidField(_) => {
                "ERR-SITE-SCHEMA-001"
            }
            Self::DuplicateSource | Self::DuplicateZone | Self::DuplicateProbe => {
                "ERR-SITE-DUPLICATE-001"
            }
            Self::StaleManifest => "ERR-SITE-STALE-MANIFEST-001",
            Self::UnknownSource | Self::SourceMismatch => "ERR-SITE-SOURCE-MISMATCH-001",
        }
    }
}

impl fmt::Display for SiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "site input refused: {} ({self:?})", self.code())
    }
}
impl std::error::Error for SiteError {}

/// Declared network boundary. Neither variant grants network authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRoute {
    /// Operator-controlled local network.
    Lan,
    /// Operator-controlled site VPN.
    Vpn,
}
impl NetworkRoute {
    /// Stable JSON and canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lan => "lan",
            Self::Vpn => "vpn",
        }
    }
}

/// Standard acquisition route requested by the source owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    /// Explicit RTSP route.
    Rtsp,
    /// Read-only ONVIF negotiation route.
    Onvif,
    /// Operator-supplied official UniFi Protect inventory.
    UnifiProtect,
    /// Explicit standards RTSP channel on an NVR.
    NvrChannel,
}
impl SourceKind {
    /// Stable JSON and canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rtsp => "rtsp",
            Self::Onvif => "onvif",
            Self::UnifiProtect => "unifi_protect",
            Self::NvrChannel => "nvr_channel",
        }
    }
}

/// Explicit rendition intent, never inferred from a camera name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRole {
    /// Source's declared main stream.
    Main,
    /// Source's declared substream.
    Sub,
}
impl StreamRole {
    /// Stable JSON and canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Sub => "sub",
        }
    }
}

/// Explicit codec observed by a bounded probe, not a vendor metadata guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeCodec {
    /// H.264/AVC, ordered SPS and PPS digests.
    Avc,
    /// H.265/HEVC, ordered VPS, SPS and PPS digests.
    Hevc,
    /// RFC 2435 JPEG, no external parameter-set digests.
    Jpeg,
}
impl ProbeCodec {
    /// Stable JSON and canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
            Self::Jpeg => "jpeg",
        }
    }
}

/// Direction of an applied NTP/chrony correction relative to the node's own
/// uncorrected wall clock. `Ahead` means the local clock read later than true
/// time before correction; `Behind` means it read earlier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockOffsetDirection {
    /// The local clock was ahead of true time before correction.
    Ahead,
    /// The local clock was behind true time before correction.
    Behind,
}
impl ClockOffsetDirection {
    /// Stable JSON and canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ahead => "ahead",
            Self::Behind => "behind",
        }
    }
}

/// A labeled wall-clock correlation for one probe or capture window: the site
/// node's own paired `CLOCK_REALTIME`/`CLOCK_MONOTONIC` samples plus the
/// NTP/chrony correction already folded into the wall-clock sample. This is a
/// claim about the node's own clock, never an authenticated fact, a camera- or
/// NVR-side timestamp, or a capture-time certification. See
/// `docs/VITTLES_FOOTAGE_PLANE_PLAN.md` section 4b ("Time").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockWitness {
    /// `CLOCK_REALTIME` sample, nanoseconds since the Unix epoch, after the
    /// `ntp_offset_ns`/`ntp_offset_direction` correction has already been applied.
    pub wall_clock_unix_ns: u64,
    /// `CLOCK_MONOTONIC` sample taken at the same instant as `wall_clock_unix_ns`,
    /// so a caller can later map any monotonic instant in the same probe session
    /// to this wall-clock epoch without re-sampling the clock.
    pub monotonic_ns: u64,
    /// Magnitude of the NTP/chrony correction already folded into `wall_clock_unix_ns`.
    pub ntp_offset_ns: u64,
    /// Direction of that correction.
    pub ntp_offset_direction: ClockOffsetDirection,
    /// Bound on the correction's own uncertainty, in nanoseconds. Never zero; an
    /// exact-zero uncertainty is refused as an implausible claim, not accepted.
    pub ntp_uncertainty_ns: u64,
}
impl ClockWitness {
    /// Validate plausibility. This is not proof the clock is actually correct.
    pub fn validate(&self) -> Result<(), SiteError> {
        if self.wall_clock_unix_ns < MIN_PLAUSIBLE_WALL_CLOCK_UNIX_NS
            || self.ntp_uncertainty_ns == 0
            || self.ntp_uncertainty_ns > MAX_CLOCK_UNCERTAINTY_NS
        {
            return Err(SiteError::InvalidField("clock_evidence"));
        }
        Ok(())
    }
}

/// Credential-file reference and exact Digest policy. Debug reveals no paths or realm.
#[derive(Clone, Eq, PartialEq)]
pub struct SiteAuthentication {
    /// Absolute, lexically normalized private-file reference; never opened by planning.
    pub credential_file: PathBuf,
    /// Exact realm expected at the independently authorized credential boundary.
    pub realm: String,
    /// Explicit opt-in to legacy MD5; false preserves SHA-256-only policy.
    pub legacy_md5: bool,
    /// Explicit opt-in to legacy Digest without qop, requiring MD5 opt-in too.
    pub legacy_no_qop: bool,
}
impl fmt::Debug for SiteAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteAuthentication").finish_non_exhaustive()
    }
}

/// A declared semantic image polygon. It is not calibrated world geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteZone {
    /// Stable source-local zone identity.
    pub zone_id: String,
    /// One of queue, register, door, lane_order, lane_pay, lane_present, payment,
    /// payment_terminal, or other. lane_pay, payment and payment_terminal require the
    /// payment privacy floor; a register zone alone does not declare a payment terminal.
    pub kind: String,
    /// Simple polygon in normalized millionths, without repeated closing vertex.
    pub vertices: Vec<[u32; 2]>,
}

/// Declared payment region requiring a separately implemented privacy floor before capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentMask {
    /// Left edge in normalized millionths.
    pub x: u32,
    /// Top edge in normalized millionths.
    pub y: u32,
    /// Positive width in normalized millionths.
    pub width: u32,
    /// Positive height in normalized millionths.
    pub height: u32,
}

/// One explicitly scoped source. Private routing/credential references are absent from Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SiteSource {
    /// Stable source identity, independent of mutable labels or IP addresses.
    pub source_id: String,
    /// Positive immutable source configuration generation.
    pub generation: u64,
    /// Standard route kind.
    pub kind: SourceKind,
    /// Exact literal IP and port; never a DNS name.
    pub peer: SocketAddr,
    /// Exact HTTP/RTSP authority label; never resolved as a hostname.
    pub authority: String,
    /// Exact credential-free RTSP path and optional query for RTSP/NVR sources.
    pub presentation: Option<String>,
    /// Explicit RTSP control subtree for RTSP/NVR sources.
    pub control_root: Option<String>,
    /// Exact read-only ONVIF service path, only for an ONVIF source.
    pub onvif_service_path: Option<String>,
    /// Official inventory camera identity, only for a UniFi source.
    pub unifi_camera_id: Option<String>,
    /// Explicit main/sub rendition selection.
    pub stream_role: StreamRole,
    /// Optional credential-file reference and strict Digest policy.
    pub authentication: Option<SiteAuthentication>,
    /// Opaque policy reference; parsing does not implement or activate retention.
    pub retention_class: String,
    /// Opaque external rights-verdict lease reference; never treated as a verified grant.
    pub rights_verdict_ref: String,
    /// Declared semantic image zones, in input order.
    pub zones: Vec<SiteZone>,
    /// Declared payment privacy regions, in input order.
    pub payment_masks: Vec<PaymentMask>,
    /// Maximum concurrent connections requested for this device, from 1 through 16.
    pub max_connections: u32,
    /// Owner attestation supplied by the manifest author, not an authenticated capability.
    pub owner_authorized: bool,
    /// Explicit request for plaintext operation on the declared LAN/VPN boundary.
    pub plaintext: bool,
    /// Explicit request for original-source retention, not a retention or rights grant.
    pub retain_originals: bool,
}
impl fmt::Debug for SiteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteSource")
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Complete requested site scope; source ordering participates in its canonical identity.
#[derive(Clone, Eq, PartialEq)]
pub struct SiteManifest {
    /// Stable site identity.
    pub site_id: String,
    /// Positive immutable manifest generation.
    pub generation: u64,
    /// Explicit LAN/VPN route declaration.
    pub network_route: NetworkRoute,
    /// Ordered, unique and bounded source scopes.
    pub sources: Vec<SiteSource>,
}
impl fmt::Debug for SiteManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteManifest")
            .field("generation", &self.generation)
            .field("source_count", &self.sources.len())
            .finish_non_exhaustive()
    }
}

/// Exact caller-supplied observations. Parsing is neither authenticity nor freshness evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct SiteProbeReceipt {
    /// Site identity observed under the requested manifest.
    pub site_id: String,
    /// Exact manifest source identity.
    pub source_id: String,
    /// Canonical digest of the complete requested manifest.
    pub manifest_digest: ContentDigest,
    /// Exact source generation.
    pub source_generation: u64,
    /// Literal peer actually named by the probe.
    pub peer: SocketAddr,
    /// Exact authority label.
    pub authority: String,
    /// Exact RTSP presentation path plus optional query.
    pub presentation: String,
    /// Exact RTSP control subtree.
    pub control_root: String,
    /// Selected SDP media index, bounded to 0 through 63.
    pub media_index: usize,
    /// Selected interleaved RTP channel, an even number below 255.
    pub rtp_channel: u8,
    /// Consecutive interleaved RTCP channel.
    pub rtcp_channel: u8,
    /// Digest of observed SDP bytes, not the raw private bytes.
    pub sdp_digest: ContentDigest,
    /// Observed codec selection.
    pub codec: ProbeCodec,
    /// Exact observed RTP payload type.
    pub payload_type: u8,
    /// Exact observed synchronization source; zero is valid and never means automatic.
    pub ssrc: u32,
    /// Observed constant cadence in 90 kHz ticks, from 1 through 90,000.
    pub frame_duration_ticks: u32,
    /// Must be 90,000 for the current native video capture contract.
    pub clock_rate_hz: u32,
    /// Number of consecutive observed picture timestamps supporting the cadence.
    pub observed_frames: u32,
    /// First observed RTP picture timestamp.
    pub first_rtp_timestamp: u32,
    /// Last observed RTP picture timestamp; wrapping arithmetic is explicit.
    pub last_rtp_timestamp: u32,
    /// Ordered configuration hashes: SPS/PPS, VPS/SPS/PPS, or empty for JPEG.
    pub parameter_set_digests: Vec<ContentDigest>,
    /// Bounded server identity attestation; private, untrusted and never printed in Debug.
    pub server_identity: String,
    /// Optional wall-clock correlation for this probe window (VIT-019). `None`
    /// until a capturing session actually populates it; absence is not an error.
    /// Contract when present: `monotonic_ns` is the local monotonic instant at
    /// which `first_rtp_timestamp` was observed. [`Self::utc_window`] relies on
    /// this anchor; a witness that does not honor it must not be attached here.
    pub clock_evidence: Option<ClockWitness>,
}
impl fmt::Debug for SiteProbeReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteProbeReceipt")
            .field("codec", &self.codec)
            .field("source_generation", &self.source_generation)
            .finish_non_exhaustive()
    }
}

impl SiteManifest {
    /// Parse a complete strict manifest from UTF-8 text without I/O.
    pub fn parse(text: &str) -> Result<Self, SiteError> {
        parse_manifest(text.as_bytes())
    }

    /// Validate public typed construction with the same bounds as JSON admission.
    pub fn validate(&self) -> Result<(), SiteError> {
        identifier(&self.site_id, "site_id")?;
        if self.generation == 0 {
            return Err(SiteError::InvalidField("generation"));
        }
        if self.sources.is_empty() || self.sources.len() > MAX_SITE_SOURCES {
            return Err(SiteError::Limit);
        }
        let mut ids = BTreeSet::new();
        let mut peer_limits = BTreeMap::new();
        let mut routes = BTreeSet::new();
        let mut vertices = 0usize;
        for source in &self.sources {
            source.validate()?;
            if !ids.insert(&source.source_id) {
                return Err(SiteError::DuplicateSource);
            }
            // This is a consistency rule for declarations, not a live scheduler. Ports
            // and IPv4-mapped IPv6 aliases cannot create another ceiling for the same IP.
            let ip = physical_peer_ip(source.peer);
            if peer_limits
                .insert(ip, source.max_connections)
                .is_some_and(|limit| limit != source.max_connections)
            {
                return Err(SiteError::InvalidField("max_connections"));
            }
            if matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel) {
                let presentation = source
                    .presentation
                    .as_deref()
                    .ok_or(SiteError::MissingField("presentation"))?;
                // Keep distinct authority hosts separate: one peer may host multiple
                // virtual cameras. Normalize only host spelling, never path/query case.
                // Source names, roles and control subtrees are not new footage.
                let route = (
                    ip,
                    source.peer.port(),
                    authority_identity(&source.authority)?,
                    presentation_identity(presentation)?,
                );
                if !routes.insert(route) {
                    return Err(SiteError::DuplicateSource);
                }
            }
            for zone in &source.zones {
                vertices = vertices
                    .checked_add(zone.vertices.len())
                    .ok_or(SiteError::Limit)?;
            }
            if vertices > MAX_SITE_VERTICES {
                return Err(SiteError::Limit);
            }
        }
        Ok(())
    }
}

fn physical_peer_ip(peer: SocketAddr) -> IpAddr {
    match peer.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

// Normalize only host identity for comparison. Preserve explicit versus absent port
// declarations; the original spelling remains in canonical identity and wire requests.
fn authority_identity(authority: &str) -> Result<String, SiteError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (address, suffix) = rest
            .split_once(']')
            .ok_or(SiteError::InvalidField("authority"))?;
        let address = address
            .parse::<Ipv6Addr>()
            .map_err(|_| SiteError::InvalidField("authority"))?;
        Ok(format!("[{address}]{suffix}"))
    } else {
        Ok(authority.to_ascii_lowercase())
    }
}

// A comparison key only. The original spelling still participates in the canonical
// manifest and native request, including Digest authentication. Normalize URI unreserved
// escapes and hex case; preserve reserved separators, query order, values and letter case.
// `source.validate()` has already bounded and admitted this ASCII presentation.
fn presentation_identity(presentation: &str) -> Result<String, SiteError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut identity = String::with_capacity(presentation.len());
    let bytes = presentation.as_bytes();
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            identity.push(char::from(bytes[at]));
            at += 1;
            continue;
        }
        let digits = presentation
            .get(at + 1..at + 3)
            .ok_or(SiteError::InvalidField("presentation"))?;
        let decoded =
            u8::from_str_radix(digits, 16).map_err(|_| SiteError::InvalidField("presentation"))?;
        if decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded) {
            identity.push(char::from(decoded));
        } else {
            identity.push('%');
            identity.push(char::from(HEX[usize::from(decoded >> 4)]));
            identity.push(char::from(HEX[usize::from(decoded & 15)]));
        }
        at += 3;
    }
    Ok(identity)
}

impl SiteSource {
    /// Validate routing, policy references, privacy geometry and pure credential references.
    pub fn validate(&self) -> Result<(), SiteError> {
        identifier(&self.source_id, "source_id")?;
        if self.generation == 0 {
            return Err(SiteError::InvalidField("generation"));
        }
        peer(self.peer)?;
        bound_authority(self.peer, &self.authority)?;
        identifier(&self.retention_class, "retention_class")?;
        identifier(&self.rights_verdict_ref, "rights_verdict_ref")?;
        if !(1..=16).contains(&self.max_connections) {
            return Err(SiteError::InvalidField("max_connections"));
        }
        match self.kind {
            SourceKind::Rtsp | SourceKind::NvrChannel => {
                let presentation = self
                    .presentation
                    .as_deref()
                    .ok_or(SiteError::MissingField("presentation"))?;
                let root = self
                    .control_root
                    .as_deref()
                    .ok_or(SiteError::MissingField("control_root"))?;
                route(&self.authority, presentation, root)?;
                if self.onvif_service_path.is_some() || self.unifi_camera_id.is_some() {
                    return Err(SiteError::InvalidField("kind"));
                }
            }
            SourceKind::Onvif => {
                let path = self
                    .onvif_service_path
                    .as_deref()
                    .ok_or(SiteError::MissingField("onvif_service_path"))?;
                simple_path(path, "onvif_service_path")?;
                if self.presentation.is_some()
                    || self.control_root.is_some()
                    || self.unifi_camera_id.is_some()
                {
                    return Err(SiteError::InvalidField("kind"));
                }
            }
            SourceKind::UnifiProtect => {
                identifier(
                    self.unifi_camera_id
                        .as_deref()
                        .ok_or(SiteError::MissingField("unifi_camera_id"))?,
                    "unifi_camera_id",
                )?;
                if self.presentation.is_some()
                    || self.control_root.is_some()
                    || self.onvif_service_path.is_some()
                {
                    return Err(SiteError::InvalidField("kind"));
                }
            }
        }
        if let Some(auth) = &self.authentication {
            let text = auth
                .credential_file
                .to_str()
                .ok_or(SiteError::InvalidField("credential_file"))?;
            if text.is_empty()
                || text.len() > 4096
                || !auth.credential_file.is_absolute()
                || auth.credential_file.parent().is_none()
                || text.ends_with('/')
                || text.contains("//")
                || text.chars().any(char::is_control)
                || text.split('/').any(|part| matches!(part, "." | ".."))
                || auth
                    .credential_file
                    .components()
                    .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            {
                return Err(SiteError::InvalidField("credential_file"));
            }
            if auth.realm.is_empty()
                || auth.realm.len() > 256
                || !auth
                    .realm
                    .bytes()
                    .all(|b| (32..=126).contains(&b) && b != b'"' && b != b'\\')
                || (auth.legacy_no_qop && !auth.legacy_md5)
            {
                return Err(SiteError::InvalidField("authentication"));
            }
        }
        if self.zones.len() > MAX_SOURCE_ZONES || self.payment_masks.len() > MAX_PAYMENT_MASKS {
            return Err(SiteError::Limit);
        }
        let mut zones = BTreeSet::new();
        for zone in &self.zones {
            identifier(&zone.zone_id, "zone_id")?;
            if !zones.insert(&zone.zone_id) {
                return Err(SiteError::DuplicateZone);
            }
            if ![
                "queue",
                "register",
                "door",
                "lane_order",
                "lane_pay",
                "lane_present",
                "payment",
                "payment_terminal",
                "other",
            ]
            .contains(&zone.kind.as_str())
            {
                return Err(SiteError::InvalidField("zone_kind"));
            }
            polygon(&zone.vertices)?;
        }
        for mask in &self.payment_masks {
            if mask.width == 0
                || mask.height == 0
                || mask
                    .x
                    .checked_add(mask.width)
                    .is_none_or(|end| end > SITE_COORDINATE_SCALE)
                || mask
                    .y
                    .checked_add(mask.height)
                    .is_none_or(|end| end > SITE_COORDINATE_SCALE)
            {
                return Err(SiteError::InvalidField("payment_masks"));
            }
        }
        Ok(())
    }
}

impl SiteProbeReceipt {
    /// Validate one receipt's internal consistency without trusting its claims.
    pub fn validate(&self) -> Result<(), SiteError> {
        identifier(&self.site_id, "site_id")?;
        identifier(&self.source_id, "source_id")?;
        if self.source_generation == 0 {
            return Err(SiteError::InvalidField("source_generation"));
        }
        peer(self.peer)?;
        bound_authority(self.peer, &self.authority)?;
        route(&self.authority, &self.presentation, &self.control_root)?;
        digest(self.manifest_digest)?;
        digest(self.sdp_digest)?;
        if self.media_index > 63
            || self.rtp_channel % 2 != 0
            || self.rtp_channel.checked_add(1) != Some(self.rtcp_channel)
        {
            return Err(SiteError::InvalidField("media_selection"));
        }
        if self.payload_type > 127
            || (self.codec == ProbeCodec::Jpeg && self.payload_type != 26 && self.payload_type < 96)
            || (self.codec != ProbeCodec::Jpeg && self.payload_type < 96)
        {
            return Err(SiteError::InvalidField("payload_type"));
        }
        if self.clock_rate_hz != 90_000
            || !(1..=90_000).contains(&self.frame_duration_ticks)
            || !(2..=MAX_PROBE_FRAMES).contains(&self.observed_frames)
        {
            return Err(SiteError::InvalidField("cadence"));
        }
        let span = u64::from(self.frame_duration_ticks) * u64::from(self.observed_frames - 1);
        if self.first_rtp_timestamp.wrapping_add(span as u32) != self.last_rtp_timestamp {
            return Err(SiteError::InvalidField("cadence"));
        }
        let count = match self.codec {
            ProbeCodec::Avc => 2,
            ProbeCodec::Hevc => 3,
            ProbeCodec::Jpeg => 0,
        };
        if self.parameter_set_digests.len() != count {
            return Err(SiteError::InvalidField("parameter_set_digests"));
        }
        let mut seen = BTreeSet::new();
        for value in &self.parameter_set_digests {
            digest(*value)?;
            if !seen.insert(*value) {
                return Err(SiteError::InvalidField("parameter_set_digests"));
            }
        }
        if self.server_identity.is_empty()
            || self.server_identity.len() > 256
            || !self
                .server_identity
                .bytes()
                .all(|b| (32..=126).contains(&b))
        {
            return Err(SiteError::InvalidField("server_identity"));
        }
        if let Some(witness) = &self.clock_evidence {
            witness.validate()?;
        }
        Ok(())
    }

    /// Map this receipt's observed window to a UTC interval (nanoseconds since
    /// the Unix epoch, inclusive start and end), widened by the attached
    /// witness's own uncertainty. `None` when no witness is attached, the
    /// receipt is invalid, or either endpoint cannot be represented. Refusal
    /// is a typed gap, never a crash or a saturated uncertainty interval.
    ///
    /// Relies on `clock_evidence`'s documented anchor: `monotonic_ns` is the
    /// local monotonic instant at which `first_rtp_timestamp` was observed.
    /// This is a claim about the node's own clock, never an authenticated
    /// fact. The duration rounds outward: a fractional nanosecond must not
    /// move the upper endpoint inside the claimed observation interval.
    #[must_use]
    pub fn utc_window(&self) -> Option<(u64, u64)> {
        let witness = self.clock_evidence.as_ref()?;
        // Receipts have public fields and this method is also called directly,
        // without a parser or manifest admission boundary. In particular, zero
        // frames/rate must refuse before subtraction or division can panic.
        self.validate().ok()?;
        let ticks = u64::from(self.frame_duration_ticks) * u64::from(self.observed_frames - 1);
        let duration_ns: u64 = (u128::from(ticks) * 1_000_000_000)
            .div_ceil(u128::from(self.clock_rate_hz))
            .try_into()
            .ok()?;
        let end = witness
            .wall_clock_unix_ns
            .checked_add(duration_ns)?
            .checked_add(witness.ntp_uncertainty_ns)?;
        let start = witness
            .wall_clock_unix_ns
            .checked_sub(witness.ntp_uncertainty_ns)?;
        Some((start, end))
    }

    /// Check a supplied receipt against an exact manifest. This is consistency, not provenance.
    pub fn validate_for(&self, manifest: &SiteManifest) -> Result<(), SiteError> {
        self.validate()?;
        manifest.validate()?;
        if self.site_id != manifest.site_id || self.manifest_digest != manifest.digest()? {
            return Err(SiteError::StaleManifest);
        }
        let source = manifest
            .sources
            .iter()
            .find(|source| source.source_id == self.source_id)
            .ok_or(SiteError::UnknownSource)?;
        if self.source_generation != source.generation
            || self.peer != source.peer
            || self.authority != source.authority
        {
            return Err(SiteError::SourceMismatch);
        }
        if matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel)
            && (source.presentation.as_deref() != Some(self.presentation.as_str())
                || source.control_root.as_deref() != Some(self.control_root.as_str()))
        {
            return Err(SiteError::SourceMismatch);
        }
        Ok(())
    }
}

fn identifier(value: &str, field: &'static str) -> Result<(), SiteError> {
    if value.is_empty()
        || value.len() > MAX_SITE_ID_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        || !value.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(SiteError::InvalidField(field));
    }
    Ok(())
}

fn digest(value: ContentDigest) -> Result<(), SiteError> {
    if value.algorithm() != DigestAlgorithm::Sha256
        || value.is_laboratory()
        || value.bytes() == [0; 32]
    {
        return Err(SiteError::InvalidField("digest"));
    }
    Ok(())
}

fn peer(value: SocketAddr) -> Result<(), SiteError> {
    let mapped_v4_invalid = match value.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V4(_) => false,
    };
    if value.port() == 0
        || value.ip().is_unspecified()
        || value.ip().is_multicast()
        || mapped_v4_invalid
        || matches!(value, SocketAddr::V4(v4) if v4.ip().is_broadcast())
        || matches!(value, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
    {
        return Err(SiteError::InvalidField("peer"));
    }
    Ok(())
}

fn authority(text: &str) -> Result<(), SiteError> {
    let invalid = SiteError::InvalidField("authority");
    if text.is_empty() || text.len() > 256 || !text.is_ascii() {
        return Err(invalid);
    }
    let port = if let Some(rest) = text.strip_prefix('[') {
        let (address, suffix) = rest.split_once(']').ok_or(invalid.clone())?;
        address.parse::<Ipv6Addr>().map_err(|_| invalid.clone())?;
        if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or(invalid.clone())?)
        }
    } else {
        let (host, port) = text
            .split_once(':')
            .map_or((text, None), |(host, port)| (host, Some(port)));
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            })
        {
            return Err(invalid);
        }
        port
    };
    if let Some(port) = port {
        let parsed = port.parse::<u16>().map_err(|_| invalid.clone())?;
        if parsed == 0 || parsed.to_string() != port {
            return Err(invalid);
        }
    }
    Ok(())
}

fn bound_authority(peer: SocketAddr, text: &str) -> Result<(), SiteError> {
    authority(text)?;
    let (literal, port) = if let Some(rest) = text.strip_prefix('[') {
        let (address, suffix) = rest
            .split_once(']')
            .ok_or(SiteError::InvalidField("authority"))?;
        (
            address.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
            suffix.strip_prefix(':'),
        )
    } else {
        let (host, port) = text
            .split_once(':')
            .map_or((text, None), |(host, port)| (host, Some(port)));
        (host.parse::<IpAddr>().ok(), port)
    };
    if literal.is_some_and(|ip| ip != peer.ip())
        || port.is_some_and(|port| port.parse::<u16>().ok() != Some(peer.port()))
    {
        return Err(SiteError::InvalidField("authority"));
    }
    Ok(())
}

fn simple_path(text: &str, field: &'static str) -> Result<(), SiteError> {
    if !text.starts_with('/')
        || text.len() > 1024
        || text.contains("//")
        || text.split('/').any(|part| matches!(part, "." | ".."))
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
    {
        return Err(SiteError::InvalidField(field));
    }
    Ok(())
}

fn route(authority_text: &str, presentation: &str, root: &str) -> Result<(), SiteError> {
    authority(authority_text)?;
    simple_path(root, "control_root")?;
    if !presentation.starts_with('/') || presentation.starts_with("//") || presentation.len() > 2048
    {
        return Err(SiteError::InvalidField("presentation"));
    }
    let uri = format!("rtsp://{authority_text}{presentation}");
    super::rtsp::uri::validated_uri_parts(&uri)
        .map_err(|_| SiteError::InvalidField("presentation"))?;
    if let Some((_, query)) = presentation.split_once('?') {
        for part in query.split(['&', ';']) {
            let key = part
                .split('=')
                .next()
                .ok_or(SiteError::InvalidField("presentation"))?;
            let mut decoded = Vec::with_capacity(key.len());
            let mut i = 0;
            while i < key.len() {
                if key.as_bytes()[i] == b'%' {
                    let digits = key
                        .get(i + 1..i + 3)
                        .ok_or(SiteError::InvalidField("presentation"))?;
                    decoded.push(
                        u8::from_str_radix(digits, 16)
                            .map_err(|_| SiteError::InvalidField("presentation"))?
                            .to_ascii_lowercase(),
                    );
                    i += 3;
                } else {
                    decoded.push(key.as_bytes()[i].to_ascii_lowercase());
                    i += 1;
                }
            }
            let key =
                String::from_utf8(decoded).map_err(|_| SiteError::InvalidField("presentation"))?;
            if [
                "user",
                "username",
                "pass",
                "password",
                "passwd",
                "pwd",
                "token",
                "key",
                "secret",
                "authorization",
                "auth",
                "session",
                "sessionid",
                "sid",
                "bearer",
                "apikey",
                "api_key",
                "api-key",
            ]
            .contains(&key.as_str())
                || key.contains("password")
                || key.contains("token")
                || key.contains("secret")
                || key.ends_with("_key")
                || key.ends_with("-key")
            {
                return Err(SiteError::InvalidField("presentation"));
            }
        }
    }
    // Match the native owner's subtree rule, including a root of "/".
    let path = presentation
        .split('?')
        .next()
        .ok_or(SiteError::InvalidField("presentation"))?;
    let root = root.trim_end_matches('/');
    if !(path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/')))
    {
        return Err(SiteError::InvalidField("control_root"));
    }
    Ok(())
}

fn polygon(vertices: &[[u32; 2]]) -> Result<(), SiteError> {
    if !(3..=MAX_ZONE_VERTICES).contains(&vertices.len()) {
        return Err(SiteError::Limit);
    }
    if vertices
        .iter()
        .flatten()
        .any(|v| *v > SITE_COORDINATE_SCALE)
        || vertices.iter().collect::<BTreeSet<_>>().len() != vertices.len()
    {
        return Err(SiteError::InvalidField("vertices"));
    }
    let area: i64 = (0..vertices.len())
        .map(|i| {
            let a = vertices[i];
            let b = vertices[(i + 1) % vertices.len()];
            i64::from(a[0]) * i64::from(b[1]) - i64::from(a[1]) * i64::from(b[0])
        })
        .sum();
    if area == 0 {
        return Err(SiteError::InvalidField("vertices"));
    }
    for i in 0..vertices.len() {
        for j in i + 1..vertices.len() {
            if j == i + 1 || (i == 0 && j == vertices.len() - 1) {
                continue;
            }
            if segments_intersect(
                vertices[i],
                vertices[(i + 1) % vertices.len()],
                vertices[j],
                vertices[(j + 1) % vertices.len()],
            ) {
                return Err(SiteError::InvalidField("vertices"));
            }
        }
    }
    Ok(())
}

fn segments_intersect(a: [u32; 2], b: [u32; 2], c: [u32; 2], d: [u32; 2]) -> bool {
    fn cross(a: [u32; 2], b: [u32; 2], c: [u32; 2]) -> i64 {
        (i64::from(b[0]) - i64::from(a[0])) * (i64::from(c[1]) - i64::from(a[1]))
            - (i64::from(b[1]) - i64::from(a[1])) * (i64::from(c[0]) - i64::from(a[0]))
    }
    fn on(a: [u32; 2], b: [u32; 2], p: [u32; 2]) -> bool {
        (a[0].min(b[0])..=a[0].max(b[0])).contains(&p[0])
            && (a[1].min(b[1])..=a[1].max(b[1])).contains(&p[1])
    }
    let (ab_c, ab_d, cd_a, cd_b) = (
        cross(a, b, c),
        cross(a, b, d),
        cross(c, d, a),
        cross(c, d, b),
    );
    (ab_c == 0 && on(a, b, c))
        || (ab_d == 0 && on(a, b, d))
        || (cd_a == 0 && on(c, d, a))
        || (cd_b == 0 && on(c, d, b))
        || (ab_c.signum() != ab_d.signum() && cd_a.signum() != cd_b.signum())
}
