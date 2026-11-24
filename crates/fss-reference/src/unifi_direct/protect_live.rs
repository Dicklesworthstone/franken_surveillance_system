#![forbid(unsafe_code)]
//! Native pure-Rust UniFi Protect live snapshot and stream acquisition adapter.
//!
//! Wraps owner-authorized UniFi Protect media sources — direct camera-local
//! JPEG snapshots via [`super::camera_http::Owner`], decoded stills via
//! [`super::video_still::Still`], and UniFi Protect RTSP/RTSPS (`7447`/`7441`)
//! segments — into canonical [`fss_core::SensorCapsule`] records and root-last
//! [`ReferenceDeployment`] ingest batches under explicit `Cx` / [`TaskCx`]
//! authority and bounded budgets.
//!
//! Security and epistemic invariants:
//! - Strictly private, loopback, or link-local IPv4 endpoints only; public
//!   endpoints and URI traversal/embedded credentials are refused.
//! - Zero `unsafe`, zero Serde, zero external processes, zero foreign runtimes.
//! - Explicit [`CaptureInterval`] and [`ClockBasis`] must be supplied by the
//!   caller; network receive time never fabricates physical capture time.
//! - Credentials are never stored in configuration, errors, or debug output.

use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use fss_core::{
    BatchId, BudgetVector, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    ContractError, EvidenceDelta, ObjectId, Plane, RuntimeGrant, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_publication::SlotName;
use fss_runtime::execution::TaskCx;

use crate::adapter_replay::ReplayCx;
use crate::reference_deployment::{FAMILY_SENSOR_CAPSULE, ReferenceDeployment};

use super::{VideoChannel, VideoCodec, camera_api, camera_http, video_still};

/// Default UniFi Protect RTSP port.
pub const UNIFI_PROTECT_RTSP_PORT: u16 = 7447;
/// Default UniFi Protect RTSPS (TLS) port.
pub const UNIFI_PROTECT_RTSPS_PORT: u16 = 7441;
/// Default direct camera-local HTTPS port.
pub const UNIFI_CAMERA_HTTPS_PORT: u16 = 443;

/// Hard upper bound for a single JPEG snapshot (4 MiB, aligned with `camera_api`).
pub const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
/// Hard upper bound for a single Protect RTSP/RTSPS stream segment (32 MiB).
pub const MAX_STREAM_SEGMENT_BYTES: usize = 32 * 1024 * 1024;
/// Minimum allowed per-operation timeout.
pub const MIN_OPERATION_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum allowed per-operation timeout.
pub const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum length of the authority resource identifier.
const MAX_RESOURCE_LEN: usize = 1024;
/// Maximum length of an RTSP/RTSPS stream path.
const MAX_PATH_LEN: usize = 512;

/// Owner-authorized UniFi Protect acquisition transport specification.
///
/// Carries endpoint coordinates only — never passwords, tokens, or API keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UniFiProtectTransport {
    /// Direct camera-local HTTPS snapshot API (`/snap.jpeg`) via [`camera_http::Owner`].
    LocalCameraHttpSnapshot {
        /// Private/local IPv4 address of the UniFi camera.
        camera_ip: Ipv4Addr,
        /// HTTPS port (typically `443`).
        port: u16,
        /// Camera-local login route profile (`V1_1` or `V1_2`).
        login_endpoint: camera_api::LoginEndpoint,
    },
    /// UniFi Protect console/camera RTSP (`7447`) or RTSPS (`7441`) live stream.
    ProtectRtsp {
        /// Private/local IPv4 address of the UniFi Protect host or camera.
        host: Ipv4Addr,
        /// TCP port (typically `7447` for RTSP or `7441` for RTSPS).
        port: u16,
        /// Credential-free stream path starting with `/` (e.g., `/high` or `/stream`).
        path: String,
        /// Whether TLS (RTSPS) transport is required.
        tls: bool,
    },
    /// Direct pure-Rust UniFi camera FLV stream via [`super::video_session`] / [`super::recording_session`].
    DirectCameraFlvStream {
        /// Private/local IPv4 address of the UniFi camera.
        camera_ip: Ipv4Addr,
        /// Camera video track (`Video1`, `Video2`, or `Video3`).
        channel: VideoChannel,
        /// Requested video codec (`H264` or `H265`).
        codec: VideoCodec,
    },
}

impl UniFiProtectTransport {
    /// Returns the credential-free canonical endpoint URI for provenance records.
    #[must_use]
    pub fn canonical_endpoint_uri(&self) -> String {
        match self {
            Self::LocalCameraHttpSnapshot {
                camera_ip, port, ..
            } => format!("https://{camera_ip}:{port}/snap.jpeg"),
            Self::ProtectRtsp {
                host,
                port,
                path,
                tls,
            } => {
                let scheme = if *tls { "rtsps" } else { "rtsp" };
                format!("{scheme}://{host}:{port}{path}")
            }
            Self::DirectCameraFlvStream {
                camera_ip, channel, ..
            } => {
                let track = match channel {
                    VideoChannel::Video1 => "video1",
                    VideoChannel::Video2 => "video2",
                    VideoChannel::Video3 => "video3",
                };
                format!("unifi-direct://{camera_ip}/{track}")
            }
        }
    }

    /// Returns the target IPv4 address.
    #[must_use]
    pub const fn host_ip(&self) -> Ipv4Addr {
        match self {
            Self::LocalCameraHttpSnapshot { camera_ip, .. }
            | Self::DirectCameraFlvStream { camera_ip, .. } => *camera_ip,
            Self::ProtectRtsp { host, .. } => *host,
        }
    }

    fn validate(&self) -> Result<(), ProtectLiveError> {
        let ip = self.host_ip();
        if !is_owner_local_unicast(ip) {
            return Err(ProtectLiveError::Configuration);
        }
        match self {
            Self::LocalCameraHttpSnapshot { port, .. } => {
                if *port == 0 {
                    return Err(ProtectLiveError::Configuration);
                }
            }
            Self::ProtectRtsp { port, path, .. } => {
                if *port == 0 || !is_safe_stream_path(path) {
                    return Err(ProtectLiveError::Configuration);
                }
            }
            Self::DirectCameraFlvStream { .. } => {}
        }
        Ok(())
    }
}

/// Hard byte and latency budgets for [`UniFiProtectLiveAdapter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniFiProtectLimits {
    /// Maximum admitted JPEG snapshot size in bytes (1..=[`MAX_SNAPSHOT_BYTES`]).
    pub max_snapshot_bytes: usize,
    /// Maximum admitted stream segment size in bytes (1..=[`MAX_STREAM_SEGMENT_BYTES`]).
    pub max_stream_segment_bytes: usize,
    /// Per-operation timeout (50ms..=30s).
    pub operation_timeout: Duration,
}

impl Default for UniFiProtectLimits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: MAX_SNAPSHOT_BYTES,
            max_stream_segment_bytes: 16 * 1024 * 1024,
            operation_timeout: Duration::from_secs(5),
        }
    }
}

impl UniFiProtectLimits {
    /// Validates hard byte and duration bounds before admitting any operation.
    pub fn validate(&self) -> Result<(), ProtectLiveError> {
        if self.max_snapshot_bytes == 0
            || self.max_snapshot_bytes > MAX_SNAPSHOT_BYTES
            || self.max_stream_segment_bytes == 0
            || self.max_stream_segment_bytes > MAX_STREAM_SEGMENT_BYTES
            || self.operation_timeout < MIN_OPERATION_TIMEOUT
            || self.operation_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(ProtectLiveError::Configuration);
        }
        Ok(())
    }
}

/// Validated configuration for [`UniFiProtectLiveAdapter`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniFiProtectLiveConfig {
    /// Canonical sensor identifier bound to this camera.
    pub sensor_id: SensorId,
    /// Canonical stream generation identifier.
    pub stream_id: StreamId,
    /// Owner-authorized UniFi Protect transport endpoint.
    pub transport: UniFiProtectTransport,
    /// Explicit authority resource identifier checked against [`TaskCx`].
    pub resource: String,
    /// Hard byte and timeout limits.
    pub limits: UniFiProtectLimits,
}

impl UniFiProtectLiveConfig {
    /// Validates scope, syntax, and hard resource budgets.
    pub fn validate(&self) -> Result<(), ProtectLiveError> {
        if self.resource.is_empty()
            || self.resource.len() > MAX_RESOURCE_LEN
            || !self.resource.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(ProtectLiveError::Configuration);
        }
        self.transport.validate()?;
        self.limits.validate()?;
        Ok(())
    }
}

/// Provenance classification of a captured UniFi Protect payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniFiCaptureOrigin {
    /// Direct camera-local HTTPS JPEG snapshot (`camera_http::Owner::snapshot`).
    LocalCameraSnapshot,
    /// Decoded H.264 still derivative encoded via [`video_still::Still`].
    DirectDecodedStill,
    /// Owner-authorized UniFi Protect RTSP/RTSPS media segment.
    ProtectRtspSegment,
}

/// Payload-free refusal from [`UniFiProtectLiveAdapter`].
#[derive(Debug)]
pub enum ProtectLiveError {
    /// Endpoint scope, path syntax, resource label, or limits are invalid.
    Configuration,
    /// Runtime or task authority refused admission for this resource.
    AuthorityDenied,
    /// Payload size exceeded the configured hard byte budget.
    BudgetExceeded,
    /// Explicit cancellation was observed on `Cx` or `ReplayCx`.
    Cancelled,
    /// Sequence numbers exhausted (never wraps).
    SequenceExhausted,
    /// Underlying camera-local HTTP exchange failed.
    CameraHttp(camera_http::Error),
    /// Snapshot bytes failed JPEG SOI/EOI framing validation.
    InvalidJpeg,
    /// Media segment bytes were empty or invalid for the declared frame count.
    InvalidMedia,
    /// Canonical core contract validation failed.
    Contract(ContractError),
    /// Reference deployment publication or ledger commit failed.
    Deployment(crate::ReferenceError),
}

impl fmt::Display for ProtectLiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => f.write_str("UniFi Protect adapter configuration refused"),
            Self::AuthorityDenied => f.write_str("UniFi Protect adapter authority denied"),
            Self::BudgetExceeded => f.write_str("UniFi Protect adapter byte budget exceeded"),
            Self::Cancelled => f.write_str("UniFi Protect adapter operation cancelled"),
            Self::SequenceExhausted => f.write_str("UniFi Protect adapter sequence exhausted"),
            Self::CameraHttp(e) => write!(f, "UniFi Protect camera HTTP error: {e}"),
            Self::InvalidJpeg => f.write_str("UniFi Protect snapshot is not valid JPEG framing"),
            Self::InvalidMedia => f.write_str("UniFi Protect media segment is invalid"),
            Self::Contract(e) => write!(f, "UniFi Protect contract error: {e}"),
            Self::Deployment(e) => write!(f, "UniFi Protect deployment ingest error: {e}"),
        }
    }
}

impl std::error::Error for ProtectLiveError {}

impl From<camera_http::Error> for ProtectLiveError {
    fn from(value: camera_http::Error) -> Self {
        Self::CameraHttp(value)
    }
}

impl From<ContractError> for ProtectLiveError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<crate::ReferenceError> for ProtectLiveError {
    fn from(value: crate::ReferenceError) -> Self {
        Self::Deployment(value)
    }
}

/// One captured UniFi Protect observation packaged as a canonical [`SensorCapsule`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniFiSnapshotObservation {
    /// Canonical sensor capsule bound to exact `source_bytes` digest.
    pub capsule: SensorCapsule,
    /// Exact original unmodified source bytes (JPEG or media segment).
    pub source_bytes: Vec<u8>,
    /// Credential-free canonical endpoint provenance URI.
    pub endpoint_uri: String,
    /// Acquisition origin lane.
    pub origin: UniFiCaptureOrigin,
}

/// Durable root-last receipt returned after committing a [`UniFiSnapshotObservation`]
/// into a [`ReferenceDeployment`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniFiProtectIngestReceipt {
    /// Canonical capsule identity committed in the authority ledger.
    pub capsule_id: CapsuleId,
    /// SHA-256 digest of the exact raw source bytes.
    pub source_digest: ContentDigest,
    /// SHA-256 digest of the canonical encoded [`SensorCapsule`].
    pub capsule_digest: ContentDigest,
    /// Root-last publication manifest digest.
    pub manifest_root: ContentDigest,
    /// Ledger commit sequence anchoring the sensor capsule delta.
    pub commit_sequence: u64,
}

/// Pure-Rust UniFi Protect live snapshot and stream acquisition facade.
///
/// Bridges existing pure-Rust `unifi_direct` primitives (`camera_http::Owner`,
/// `camera_api::Snapshot`, `video_still::Still`) and owner-authorized Protect
/// RTSP/RTSPS segments into canonical [`SensorCapsule`] objects and root-last
/// [`ReferenceDeployment`] commits under explicit `Cx` authority.
#[derive(Debug)]
pub struct UniFiProtectLiveAdapter {
    config: UniFiProtectLiveConfig,
    next_sequence: u64,
}

impl UniFiProtectLiveAdapter {
    /// Constructs a validated adapter starting at stream sequence `1`.
    pub fn new(config: UniFiProtectLiveConfig) -> Result<Self, ProtectLiveError> {
        config.validate()?;
        Ok(Self {
            config,
            next_sequence: 1,
        })
    }

    /// Returns the validated immutable configuration.
    #[must_use]
    pub const fn config(&self) -> &UniFiProtectLiveConfig {
        &self.config
    }

    /// Returns the next monotonic sequence number to be assigned.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Acquires one live JPEG snapshot over an already-authenticated, admitted
    /// [`camera_http::Owner`] under explicit [`TaskCx`] and Asupersync [`Cx`]
    /// authority and bounded budgets, returning a canonical [`SensorCapsule`].
    #[allow(clippy::too_many_arguments)]
    pub async fn capture_local_snapshot<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        owner: &mut camera_http::Owner<'_, '_, '_, IO>,
        task: &TaskCx<'_>,
        cx: &Cx,
        capture: CaptureInterval,
        receive_time: TimestampNs,
        clock_basis: ClockBasis,
        gap_before: bool,
    ) -> Result<UniFiSnapshotObservation, ProtectLiveError> {
        if !matches!(
            self.config.transport,
            UniFiProtectTransport::LocalCameraHttpSnapshot { .. }
        ) {
            return Err(ProtectLiveError::Configuration);
        }
        cx.checkpoint().map_err(|_| ProtectLiveError::Cancelled)?;

        // Charge explicit media-read authority before issuing network I/O.
        let mut cost = BudgetVector::ZERO;
        cost.network_bytes = self.config.limits.max_snapshot_bytes as u64;
        cost.bytes = cost.network_bytes;
        task.checkpoint_for(
            RuntimeGrant::ReadMedia,
            &self.config.resource,
            receive_time,
            &cost,
        )
        .map_err(|_| ProtectLiveError::AuthorityDenied)?;

        let snapshot = owner.snapshot(self.config.limits.operation_timeout).await?;

        cx.checkpoint().map_err(|_| ProtectLiveError::Cancelled)?;
        self.build_observation(
            snapshot.bytes(),
            1,
            capture,
            receive_time,
            clock_basis,
            gap_before,
            UniFiCaptureOrigin::LocalCameraSnapshot,
            true,
        )
    }

    /// Packages an already-acquired [`camera_api::Snapshot`] into a canonical
    /// [`SensorCapsule`] observation under explicit [`ReplayCx`] authority.
    pub fn package_camera_snapshot(
        &mut self,
        snapshot: &camera_api::Snapshot,
        capture: CaptureInterval,
        receive_time: TimestampNs,
        clock_basis: ClockBasis,
        gap_before: bool,
        cx: &ReplayCx,
    ) -> Result<UniFiSnapshotObservation, ProtectLiveError> {
        if cx.is_cancelled() {
            return Err(ProtectLiveError::Cancelled);
        }
        self.build_observation(
            snapshot.bytes(),
            1,
            capture,
            receive_time,
            clock_basis,
            gap_before,
            UniFiCaptureOrigin::LocalCameraSnapshot,
            true,
        )
    }

    /// Packages a decoded H.264 [`video_still::Still`] JPEG derivative into a
    /// canonical [`SensorCapsule`] observation under explicit [`ReplayCx`] authority.
    pub fn package_decoded_still(
        &mut self,
        still: &video_still::Still,
        capture: CaptureInterval,
        receive_time: TimestampNs,
        clock_basis: ClockBasis,
        gap_before: bool,
        cx: &ReplayCx,
    ) -> Result<UniFiSnapshotObservation, ProtectLiveError> {
        if cx.is_cancelled() {
            return Err(ProtectLiveError::Cancelled);
        }
        self.build_observation(
            still.jpeg().bytes(),
            1,
            capture,
            receive_time,
            clock_basis,
            gap_before,
            UniFiCaptureOrigin::DirectDecodedStill,
            true,
        )
    }

    /// Packages an owner-authorized UniFi Protect RTSP/RTSPS media segment into
    /// a canonical [`SensorCapsule`] observation under explicit [`ReplayCx`] authority.
    #[allow(clippy::too_many_arguments)]
    pub fn package_rtsp_segment(
        &mut self,
        segment_bytes: &[u8],
        frame_count: u32,
        capture: CaptureInterval,
        receive_time: TimestampNs,
        clock_basis: ClockBasis,
        gap_before: bool,
        cx: &ReplayCx,
    ) -> Result<UniFiSnapshotObservation, ProtectLiveError> {
        if cx.is_cancelled() {
            return Err(ProtectLiveError::Cancelled);
        }
        if !matches!(
            self.config.transport,
            UniFiProtectTransport::ProtectRtsp { .. }
        ) {
            return Err(ProtectLiveError::Configuration);
        }
        if segment_bytes.is_empty() {
            return Err(ProtectLiveError::InvalidMedia);
        }
        self.build_observation(
            segment_bytes,
            frame_count,
            capture,
            receive_time,
            clock_basis,
            gap_before,
            UniFiCaptureOrigin::ProtectRtspSegment,
            false,
        )
    }

    /// Stages exact source bytes and canonical capsule metadata root-last into
    /// `deployment`, then commits a `sensor_capsule` delta to the authority ledger.
    pub fn ingest_observation(
        &self,
        deployment: &mut ReferenceDeployment,
        observation: &UniFiSnapshotObservation,
        cx: &ReplayCx,
    ) -> Result<UniFiProtectIngestReceipt, ProtectLiveError> {
        if cx.is_cancelled() {
            return Err(ProtectLiveError::Cancelled);
        }
        if observation.capsule.sensor_id != self.config.sensor_id
            || observation.capsule.stream_id != self.config.stream_id
        {
            return Err(ProtectLiveError::Configuration);
        }
        let source_digest = ContentDigest::sha256(&observation.source_bytes);
        if source_digest != observation.capsule.source_digest {
            return Err(ProtectLiveError::InvalidMedia);
        }

        let capsule_bytes = observation.capsule.canonical_bytes();
        let capsule_digest = ContentDigest::sha256(&capsule_bytes);
        let short_hex = short_digest_hex(capsule_digest);

        let slot = SlotName::parse(&format!("unifi-protect-{short_hex}"))
            .map_err(|_| ProtectLiveError::Configuration)?;
        let staged = deployment.stage_and_publish(
            &slot,
            &[
                observation.source_bytes.as_slice(),
                capsule_bytes.as_slice(),
            ],
            cx,
        )?;
        let _pub_receipt = deployment.publish_and_commit(
            &slot,
            &staged.manifest,
            observation.capsule.capture,
            cx,
        )?;

        let object_id = ObjectId::parse(format!("object:unifi-protect-capsule:{short_hex}"))?;
        let batch_id = BatchId::parse(format!("batch:unifi-protect:{short_hex}"))?;
        let delta = EvidenceDelta {
            delta_id: format!("delta:unifi-protect:{short_hex}"),
            family: FAMILY_SENSOR_CAPSULE.to_owned(),
            object_id,
            prior_generation: None,
            new_generation: 1,
            validity: observation.capsule.capture,
            plane: Plane::Authority,
            payload_digest: capsule_digest,
            witness_digest: Some(staged.root),
            operation_id: None,
        };
        let mut children = vec![source_digest, capsule_digest, staged.root];
        children.sort_unstable();
        children.dedup();
        let anchor = deployment.append_batch(batch_id, vec![delta], children, cx)?;

        Ok(UniFiProtectIngestReceipt {
            capsule_id: observation.capsule.capsule_id.clone(),
            source_digest,
            capsule_digest,
            manifest_root: staged.root,
            commit_sequence: anchor.commit_sequence,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_observation(
        &mut self,
        source: &[u8],
        frame_count: u32,
        capture: CaptureInterval,
        receive_time: TimestampNs,
        clock_basis: ClockBasis,
        gap_before: bool,
        origin: UniFiCaptureOrigin,
        require_jpeg: bool,
    ) -> Result<UniFiSnapshotObservation, ProtectLiveError> {
        let max_bytes = if require_jpeg {
            self.config.limits.max_snapshot_bytes
        } else {
            self.config.limits.max_stream_segment_bytes
        };
        if source.len() > max_bytes {
            return Err(ProtectLiveError::BudgetExceeded);
        }
        if require_jpeg && !has_valid_jpeg_framing(source) {
            return Err(ProtectLiveError::InvalidJpeg);
        }
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(ProtectLiveError::SequenceExhausted)?;

        let source_digest = ContentDigest::sha256(source);
        let short_hex = short_digest_hex(source_digest);
        let capsule_id = CapsuleId::parse(format!("capsule:unifi-protect:{sequence}:{short_hex}"))?;

        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id,
            sensor_id: self.config.sensor_id.clone(),
            stream_id: self.config.stream_id.clone(),
            sequence,
            capture,
            receive_time,
            clock_basis,
            source,
            frame_count,
            gap_before,
        })?;
        self.next_sequence = next;

        Ok(UniFiSnapshotObservation {
            capsule,
            source_bytes: source.to_vec(),
            endpoint_uri: self.config.transport.canonical_endpoint_uri(),
            origin,
        })
    }
}

fn is_owner_local_unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && (ip.is_private() || ip.is_loopback() || ip.is_link_local())
}

fn is_safe_stream_path(path: &str) -> bool {
    if !path.starts_with('/') || path.len() > MAX_PATH_LEN || !path.is_ascii() {
        return false;
    }
    if path
        .bytes()
        .any(|b| b <= 32 || b >= 127 || b"\\#@".contains(&b))
    {
        return false;
    }
    let bare = path.split('?').next().unwrap_or(path);
    if bare.split('/').any(|seg| matches!(seg, "." | "..")) {
        return false;
    }
    let raw = path.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let Some(hex) = path.get(i + 1..i + 3) else {
                return false;
            };
            let Ok(decoded) = u8::from_str_radix(hex, 16) else {
                return false;
            };
            if decoded <= 32 || decoded == 127 || b"./\\@#%".contains(&decoded) {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

fn has_valid_jpeg_framing(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0xFF
        && bytes[1] == 0xD8
        && bytes[bytes.len() - 2] == 0xFF
        && bytes[bytes.len() - 1] == 0xD9
}

fn short_digest_hex(digest: ContentDigest) -> String {
    let mut out = String::with_capacity(16);
    for byte in digest.bytes().iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_orient::{OrientLimits, read_deployment};
    use crate::unifi_direct::metered::{MeteredClock, MeteredIo};
    use asupersync::runtime::RuntimeBuilder;
    use fss_core::{
        ContextAuthority, OperationId, RegionId, RegionKind, RootAuthoritySpec, TaskId, TaskOutcome,
    };
    use fss_runtime::authority::AuthorityCx;
    use fss_runtime::execution::{TaskCompletion, TaskSpec, run_owned_async};
    use std::collections::BTreeSet;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct AllowAllCamera;
    impl camera_http::Authority for AllowAllCamera {
        fn permits(&self, _peer: Ipv4Addr, _generation: u64, _op: camera_http::Operation) -> bool {
            true
        }
    }

    struct ScriptedIo {
        responses: Vec<Vec<u8>>,
        current: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl ScriptedIo {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses,
                current: Vec::new(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut asupersync::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.read_pos >= self.current.len() {
                if self.responses.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                self.current = self.responses.remove(0);
                self.read_pos = 0;
            }
            let avail = &self.current[self.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.read_pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn minimal_jpeg() -> Vec<u8> {
        vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0xFF, 0xD9]
    }

    fn make_replay_cx(root: &std::path::Path, site: &str) -> ReplayCx {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:unifi-protect-live-test".into(),
            operation_id: OperationId::parse("operation:unifi-protect-live-test").unwrap(),
            principal: "principal:owner".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(32 * 1024 * 1024)
                .storage_operations(8192)
                .build()
                .unwrap(),
            privacy_scope: "privacy:owner-local".into(),
            retention_scope: "retention:owner-local".into(),
            anchor_universe: ContentDigest::sha256(site.as_bytes()),
            generation: 1,
        })
        .unwrap();
        ReplayCx::from_context_authority(&authority, root.to_path_buf()).unwrap()
    }

    #[test]
    fn config_rejects_public_ips_traversal_and_oversized_limits() {
        let sensor_id = SensorId::parse("sensor:unifi-g4-instant").unwrap();
        let stream_id = StreamId::parse("stream:unifi-g4-main").unwrap();

        // Public IP refused
        let public = UniFiProtectLiveConfig {
            sensor_id: sensor_id.clone(),
            stream_id: stream_id.clone(),
            transport: UniFiProtectTransport::ProtectRtsp {
                host: Ipv4Addr::new(8, 8, 8, 8),
                port: UNIFI_PROTECT_RTSP_PORT,
                path: "/high".into(),
                tls: false,
            },
            resource: "unifi:g4-instant".into(),
            limits: UniFiProtectLimits::default(),
        };
        assert!(matches!(
            UniFiProtectLiveAdapter::new(public),
            Err(ProtectLiveError::Configuration)
        ));

        // Path traversal and embedded credential marker refused
        for bad_path in ["relative", "/../secret", "/cam@pass", "/a%2e%2e/b"] {
            let cfg = UniFiProtectLiveConfig {
                sensor_id: sensor_id.clone(),
                stream_id: stream_id.clone(),
                transport: UniFiProtectTransport::ProtectRtsp {
                    host: Ipv4Addr::new(192, 168, 4, 177),
                    port: UNIFI_PROTECT_RTSPS_PORT,
                    path: bad_path.into(),
                    tls: true,
                },
                resource: "unifi:g4-instant".into(),
                limits: UniFiProtectLimits::default(),
            };
            assert!(
                matches!(
                    UniFiProtectLiveAdapter::new(cfg),
                    Err(ProtectLiveError::Configuration)
                ),
                "bad_path={bad_path}"
            );
        }

        // Oversized snapshot budget refused
        let bad_limit = UniFiProtectLiveConfig {
            sensor_id,
            stream_id,
            transport: UniFiProtectTransport::LocalCameraHttpSnapshot {
                camera_ip: Ipv4Addr::new(192, 168, 4, 177),
                port: UNIFI_CAMERA_HTTPS_PORT,
                login_endpoint: camera_api::LoginEndpoint::V1_2,
            },
            resource: "unifi:g4-instant".into(),
            limits: UniFiProtectLimits {
                max_snapshot_bytes: MAX_SNAPSHOT_BYTES + 1,
                ..UniFiProtectLimits::default()
            },
        };
        assert!(matches!(
            UniFiProtectLiveAdapter::new(bad_limit),
            Err(ProtectLiveError::Configuration)
        ));
    }

    #[test]
    fn live_local_snapshot_capture_and_deployment_ingest_roundtrip() {
        let camera_ip = Ipv4Addr::new(192, 168, 4, 177);
        let resource = "unifi-camera:192.168.4.177".to_owned();
        let jpeg = minimal_jpeg();

        let login_resp =
            b"HTTP/1.1 200 OK\r\nSet-Cookie: authId=sess123456; Path=/; HttpOnly\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        let status_body = br#"{"board":{},"firmware":{},"controller":{"port":7442}}"#;
        let status_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            status_body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(status_body.iter().copied())
        .collect::<Vec<u8>>();
        let snap_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
            jpeg.len()
        )
        .into_bytes()
        .into_iter()
        .chain(jpeg.iter().copied())
        .collect::<Vec<u8>>();

        let mut budget = BudgetVector::ZERO;
        budget.network_bytes = 16 * 1024 * 1024;
        budget.bytes = 16 * 1024 * 1024;
        let root_spec = RootAuthoritySpec {
            trace_id: "trace:unifi-live-snap".into(),
            operation_id: OperationId::parse("operation:unifi-live-snap").unwrap(),
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::AdapterAuth.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(10_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:owner-local".into(),
            retention_scope: "retention:owner-local".into(),
            anchor_universe: ContentDigest::sha256(b"site:owner-lan"),
            generation: 1,
        };
        let (mut authority, mut tree) = AuthorityCx::root(
            root_spec,
            RegionId::new("region:unifi-live-snap").unwrap(),
            RegionKind::Process,
            budget,
            TimestampNs(1_000),
        )
        .unwrap();
        let scope_set = BTreeSet::from([resource.clone()]);
        let grants = authority
            .grants()
            .clone()
            .with_scope(RuntimeGrant::AdapterNet, scope_set.clone())
            .with_scope(RuntimeGrant::AdapterAuth, scope_set.clone())
            .with_scope(RuntimeGrant::ObserveStatus, scope_set.clone())
            .with_scope(RuntimeGrant::ReadMedia, scope_set);
        authority.narrow_grants(grants).unwrap();

        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .unwrap();
        let cfg = UniFiProtectLiveConfig {
            sensor_id: SensorId::parse("sensor:g4-instant-front").unwrap(),
            stream_id: StreamId::parse("stream:g4-instant-snap").unwrap(),
            transport: UniFiProtectTransport::LocalCameraHttpSnapshot {
                camera_ip,
                port: UNIFI_CAMERA_HTTPS_PORT,
                login_endpoint: camera_api::LoginEndpoint::V1_2,
            },
            resource: resource.clone(),
            limits: UniFiProtectLimits::default(),
        };

        let obs = runtime
            .block_on(async {
                let cx = Cx::current().unwrap();
                let spec = TaskSpec {
                    task_id: TaskId::new("task:unifi-live-snap").unwrap(),
                    started_at: TimestampNs(1_000),
                };
                run_owned_async(
                    &mut authority,
                    &mut tree,
                    spec,
                    &cx,
                    async move |task, runtime_cx| {
                        let clock =
                            MeteredClock::new(task, runtime_cx, TimestampNs(1_000)).unwrap();
                        let io = ScriptedIo::new(vec![login_resp, status_resp, snap_resp]);
                        let metered = MeteredIo::with_clock(io, clock, &resource, 4096).unwrap();
                        let allow = AllowAllCamera;
                        let mut owner = camera_http::Owner::new(
                            metered, task, runtime_cx, clock, &allow, camera_ip, 1, &resource,
                        )
                        .unwrap();
                        owner
                            .login_at(
                                camera_api::LoginEndpoint::V1_2,
                                br#"{"username":"ubnt","password":"fixture-non-secret"}"#,
                                Duration::from_secs(2),
                            )
                            .await
                            .unwrap();
                        let _ = owner.status(Duration::from_secs(2)).await.unwrap();
                        let now = clock.now().unwrap();
                        let mut adapter = UniFiProtectLiveAdapter::new(cfg).unwrap();
                        let captured = adapter
                            .capture_local_snapshot(
                                &mut owner,
                                task,
                                runtime_cx,
                                CaptureInterval {
                                    earliest: TimestampNs(1_000),
                                    latest: now,
                                },
                                now,
                                ClockBasis::HostMonotonic,
                                false,
                            )
                            .await
                            .unwrap();
                        assert_eq!(adapter.next_sequence(), 2);
                        let done_at = clock.now().unwrap();
                        TaskCompletion {
                            output: captured,
                            outcome: TaskOutcome::Success,
                            completed_at: done_at,
                        }
                    },
                )
                .await
                .unwrap()
            })
            .output;

        assert_eq!(obs.source_bytes, jpeg);
        assert_eq!(obs.capsule.source_digest, ContentDigest::sha256(&jpeg));
        assert_eq!(obs.capsule.frame_count, 1);
        assert_eq!(obs.origin, UniFiCaptureOrigin::LocalCameraSnapshot);
        assert_eq!(obs.endpoint_uri, "https://192.168.4.177:443/snap.jpeg");

        // Now ingest the captured observation root-last into a real ReferenceDeployment.
        let dir = std::env::temp_dir().join(format!(
            "fss-unifi-protect-live-ingest-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("deployment");
        let site = "site:owner-lan";
        let replay_cx = make_replay_cx(&root, site);
        let mut deployment = ReferenceDeployment::open(&root, site, &replay_cx).unwrap();
        let adapter = UniFiProtectLiveAdapter::new(UniFiProtectLiveConfig {
            sensor_id: SensorId::parse("sensor:g4-instant-front").unwrap(),
            stream_id: StreamId::parse("stream:g4-instant-snap").unwrap(),
            transport: UniFiProtectTransport::LocalCameraHttpSnapshot {
                camera_ip,
                port: UNIFI_CAMERA_HTTPS_PORT,
                login_endpoint: camera_api::LoginEndpoint::V1_2,
            },
            resource: "unifi-camera:192.168.4.177".into(),
            limits: UniFiProtectLimits::default(),
        })
        .unwrap();
        let receipt = adapter
            .ingest_observation(&mut deployment, &obs, &replay_cx)
            .unwrap();
        assert_eq!(receipt.source_digest, ContentDigest::sha256(&jpeg));
        assert!(receipt.commit_sequence >= 2);
        drop(deployment);

        // Cold readback verifies the deployment ledger & root-last custody.
        let reopened = read_deployment(&root, &OrientLimits::default()).unwrap();
        assert_eq!(reopened.site_lineage, site);
        replay_cx.drain_and_finalize();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rtsp_segment_packaging_and_cancellation_semantics() {
        let dir =
            std::env::temp_dir().join(format!("fss-unifi-protect-rtsp-{}", std::process::id()));
        let cx = make_replay_cx(&dir, "site:rtsp-test");
        let mut adapter = UniFiProtectLiveAdapter::new(UniFiProtectLiveConfig {
            sensor_id: SensorId::parse("sensor:g4-instant-rtsp").unwrap(),
            stream_id: StreamId::parse("stream:g4-instant-h264").unwrap(),
            transport: UniFiProtectTransport::ProtectRtsp {
                host: Ipv4Addr::new(192, 168, 4, 177),
                port: UNIFI_PROTECT_RTSPS_PORT,
                path: "/high".into(),
                tls: true,
            },
            resource: "unifi-protect:192.168.4.177".into(),
            limits: UniFiProtectLimits::default(),
        })
        .unwrap();

        let seg = b"\x00\x00\x00\x01\x67\x42\x00\x1e";
        let obs = adapter
            .package_rtsp_segment(
                seg,
                1,
                CaptureInterval {
                    earliest: TimestampNs(10),
                    latest: TimestampNs(20),
                },
                TimestampNs(25),
                ClockBasis::HostMonotonic,
                false,
                &cx,
            )
            .unwrap();
        assert_eq!(obs.endpoint_uri, "rtsps://192.168.4.177:7441/high");
        assert_eq!(obs.origin, UniFiCaptureOrigin::ProtectRtspSegment);
        assert_eq!(obs.capsule.sequence, 1);
        assert_eq!(obs.capsule.source_digest, ContentDigest::sha256(seg));

        // Cancelled ReplayCx refuses packaging without advancing sequence.
        cx.request_cancellation();
        let err = adapter.package_rtsp_segment(
            seg,
            1,
            CaptureInterval {
                earliest: TimestampNs(30),
                latest: TimestampNs(40),
            },
            TimestampNs(45),
            ClockBasis::HostMonotonic,
            false,
            &cx,
        );
        assert!(matches!(err, Err(ProtectLiveError::Cancelled)));
        assert_eq!(adapter.next_sequence(), 2);
        cx.drain_and_finalize();
    }
}
