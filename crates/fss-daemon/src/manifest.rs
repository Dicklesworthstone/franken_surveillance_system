#![forbid(unsafe_code)]
//! Pure-Rust zero-Serde JSON parser, validator, and canonical commitment for `site.json`
//! (`fss.site_manifest.v1`).
//!
//! Semantic plane: `"authority"`.
//!
//! # Security Invariant
//! Plaintext credentials are strictly prohibited anywhere in a site manifest:
//! - Endpoint URLs containing inline userinfo credentials (`scheme://user:pass@host` or `@` in
//!   the authority) are refused fail-closed with [`crate::ERR_DAEMON_SECRET_IN_MANIFEST_001`].
//! - Query parameters resembling passwords, secrets, API keys, or bearer tokens are refused.
//! - Forbidden JSON field names (`password`, `secret`, `token`, `api_key`, etc.) are refused.
//! - Cameras reference opaque `secret_id` handles stored in `fss-vault` instead.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::json_input::{self, Value};
use fss_core::{CanonicalEncoder, ContentDigest, MAX_SENSOR_REGIONS, SensorId, validate_id};
use fss_pack::{
    DEFAULT_TARGET_PACK_BYTES, DEFAULT_WATERMARK_HARD_PCT, DEFAULT_WATERMARK_SOFT_PCT,
    MAX_MEDIA_CHUNK_FRAMES, MIN_CONFIGURABLE_TARGET_PACK_BYTES,
};
use fss_reference::ingest::live_corroborate::{
    CameraHomography, CameraTopologyEntry, DEFAULT_HOMOGRAPHY_TIME_GATE_NS, SharedZoneOverlap,
    SiteTopologyRegistry, TransitCorridor,
};
use fss_reference::ingest::model_pool::CameraPriorityTier;
use fss_reference::ingest::osd_mask::{
    ImageRect, validate_ignore_regions, validate_ignore_regions_in_bounds,
};
use fss_vault::{AdapterFamily, SecretId};

use crate::error::DaemonError;
use crate::manifest_parse::{
    opt_text, opt_u8, opt_u64, parse_camera_entry, parse_topology, reject_forbidden_secret_keys,
    req_text,
};

/// Required schema identifier for `site.json` daemon manifests.
pub const SITE_MANIFEST_SCHEMA: &str = "fss.site_manifest.v1";
/// Canonical digest domain for [`SiteManifest::digest`].
pub const DAEMON_SITE_MANIFEST_DOMAIN: &str = "fss.daemon.site_manifest.v1";

/// Default per-camera bounded ring frame capacity (`64` frames).
pub const DEFAULT_RING_MAX_FRAMES: usize = 64;
/// Default per-camera bounded ring byte capacity (`32 MiB`).
pub const DEFAULT_RING_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Default site ring storage capacity (`1 GiB`).
pub const DEFAULT_SITE_RING_CAP_BYTES: u64 = 1_073_741_824;
/// Default incremental scrub budget per maintenance tick (`16 MiB`).
pub const DEFAULT_SCRUB_BUDGET_BYTES_PER_TICK: u64 = 16 * 1024 * 1024;
/// Default hot retention window (`24` hours in nanoseconds).
pub const DEFAULT_RETAIN_HOT_NS: u64 = 86_400_000_000_000;
/// Default minimum reconnect backoff (`250 ms`).
pub const DEFAULT_RECONNECT_MIN_MS: u64 = 250;
/// Default maximum reconnect backoff (`30_000 ms`).
pub const DEFAULT_RECONNECT_MAX_MS: u64 = 30_000;
/// Default packet stall detection timeout (`5_000 ms`).
pub const DEFAULT_STALL_TIMEOUT_MS: u64 = 5_000;
/// Default GOP frame count per `FSMC` media chunk (`8` frames).
pub const DEFAULT_GOP_FRAMES: usize = 8;
/// Default decoded frame dimensions when omitted (`[32, 32]`).
pub const DEFAULT_CAMERA_DIMENSIONS: [u32; 2] = [32, 32];

const FORBIDDEN_QUERY_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "access_token",
    "auth",
    "apikey",
    "api_key",
];

/// Supported heterogeneous camera adapter families supervised by `fss-daemon`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CameraAdapterKind {
    /// Native RTSP-over-TCP interleaved stream (`H.264`/`H.265`/`MJPEG`).
    Rtsp,
    /// Native TUTK IOTC P2P stream (e.g. Wyze Cam v4).
    Tutk,
    /// Owner-authorized UniFi Protect controller stream.
    UniFiProtect,
    /// Owner-authorized ONVIF / HTTP MJPEG stream.
    OnvifHttp,
    /// Deterministic in-process synthetic replay stream for lab and CI verification.
    Synthetic,
}

impl CameraAdapterKind {
    /// Returns the canonical lowercase schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rtsp => "rtsp",
            Self::Tutk => "tutk",
            Self::UniFiProtect => "unifi_protect",
            Self::OnvifHttp => "onvif_http",
            Self::Synthetic => "synthetic",
        }
    }

    /// Parses a schema string into a [`CameraAdapterKind`].
    pub fn parse(value: &str) -> Result<Self, DaemonError> {
        match value {
            "rtsp" => Ok(Self::Rtsp),
            "tutk" => Ok(Self::Tutk),
            "unifi_protect" => Ok(Self::UniFiProtect),
            "onvif_http" => Ok(Self::OnvifHttp),
            "synthetic" => Ok(Self::Synthetic),
            other => Err(DaemonError::InvalidManifest {
                detail: format!("unsupported camera adapter `{other}`"),
            }),
        }
    }

    /// Maps this camera adapter kind onto `fss-vault`'s [`AdapterFamily`].
    #[must_use]
    pub const fn vault_adapter_family(self) -> AdapterFamily {
        match self {
            Self::Rtsp | Self::Synthetic => AdapterFamily::Rtsp,
            Self::Tutk => AdapterFamily::Tutk,
            Self::UniFiProtect => AdapterFamily::UniFiProtect,
            Self::OnvifHttp => AdapterFamily::Onvif,
        }
    }
}

/// Validated per-camera configuration inside a [`SiteManifest`].
#[derive(Clone, Debug, PartialEq)]
pub struct CameraManifestEntry {
    /// Stable unique camera sensor identifier.
    pub sensor_id: SensorId,
    /// Camera ingest adapter kind.
    pub adapter: CameraAdapterKind,
    /// Non-secret endpoint descriptor (never contains inline credentials).
    pub endpoint: String,
    /// Optional opaque `fss-vault` secret identifier (never raw password bytes).
    pub secret_id: Option<SecretId>,
    /// Fair-share ML inference priority tier.
    pub priority_tier: CameraPriorityTier,
    /// Primary logical zone identifier observed by this camera.
    pub primary_zone: String,
    /// All logical zones observed by this camera.
    pub zones: BTreeSet<String>,
    /// Fixed decoded frame dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Strictly caller-supplied OSD ignore rectangles (C3; never auto-activated).
    pub osd_ignore_rects: Vec<ImageRect>,
    /// Declared common-cause failure domains (e.g. `wifi:home`, `poe:switch-1`).
    pub failure_domains: BTreeSet<String>,
    /// Minimum reconnect backoff delay in milliseconds.
    pub reconnect_min_ms: u64,
    /// Maximum reconnect backoff delay in milliseconds.
    pub reconnect_max_ms: u64,
    /// Packet stall timeout in milliseconds before emitting an explicit coverage gap.
    pub stall_timeout_ms: u64,
    /// Bounded per-camera ring capacity in frames (default `64`).
    pub ring_max_frames: usize,
    /// Bounded per-camera ring capacity in bytes (default `32 MiB`).
    pub ring_max_bytes: usize,
    /// Target frames packed into each coarse-grained `FSMC` media chunk.
    pub gop_frames: usize,
}

/// Optional homography declaration binding one camera to the site ground plane.
#[derive(Clone, Debug, PartialEq)]
pub struct ManifestHomography {
    /// Target camera sensor identifier.
    pub sensor_id: String,
    /// Calibrated 3x3 image-to-ground homography and Euclidean distance gate.
    pub homography: CameraHomography,
}

/// Topology section directly feeding `C8`'s [`SiteTopologyRegistry`].
#[derive(Clone, Debug, PartialEq)]
pub struct SiteTopologyManifest {
    /// Default simultaneous time gate in nanoseconds for homography matches.
    pub default_homography_time_gate_ns: u64,
    /// Coarse shared physical zones observed concurrently by 2+ cameras.
    pub shared_zones: Vec<SharedZoneOverlap>,
    /// Directed or bidirectional transit corridors between camera zones.
    pub transit_corridors: Vec<TransitCorridor>,
    /// Per-camera calibrated ground-plane homographies.
    pub homographies: Vec<ManifestHomography>,
}

impl Default for SiteTopologyManifest {
    fn default() -> Self {
        Self {
            default_homography_time_gate_ns: DEFAULT_HOMOGRAPHY_TIME_GATE_NS,
            shared_zones: Vec::new(),
            transit_corridors: Vec::new(),
            homographies: Vec::new(),
        }
    }
}

/// Validated, secret-free always-on daemon site manifest (`fss.site_manifest.v1`).
#[derive(Clone, Debug, PartialEq)]
pub struct SiteManifest {
    /// Stable site and deployment lineage identifier.
    pub site_id: String,
    /// Deployment root directory backing ledger, pack store, projection, and UDS socket.
    pub deployment_root: PathBuf,
    /// Local storage retention ring capacity ceiling in bytes.
    pub ring_cap_bytes: u64,
    /// Soft capacity watermark percentage (entering `Elevated`, default `75`).
    pub soft_watermark_pct: u8,
    /// Hard capacity watermark percentage (entering `Critical`, default `95`).
    pub hard_watermark_pct: u8,
    /// Target sealed packfile rotation size in bytes.
    pub pack_target_bytes: u64,
    /// Incremental background scrubber byte budget per storage maintenance tick.
    pub scrub_budget_bytes_per_tick: u64,
    /// Default hot retention window in nanoseconds before unheld windows expire.
    pub retain_hot_ns: u64,
    /// Optional explicit IPC socket/runtime directory override.
    pub ipc_socket_override: Option<PathBuf>,
    /// Optional local verified `.fmpk` RGB object-detector package path (e.g. `yolox_nano.fmpk`).
    pub detector_package_path: Option<PathBuf>,
    /// Required pinned SHA-256 digest of `detector_package_path` whenever configured.
    pub detector_package_digest: Option<ContentDigest>,
    /// Optional detection score threshold override in parts per million (`1..=1_000_000`).
    pub detector_min_score_ppm: Option<u32>,
    /// Supervised camera entries (`1..=MAX_SENSOR_REGIONS`).
    pub cameras: Vec<CameraManifestEntry>,
    /// Site overlap, homography, and transit-corridor topology feeding `C8`.
    pub topology: SiteTopologyManifest,
}

impl SiteManifest {
    /// Loads and validates a [`SiteManifest`] from a UTF-8 JSON file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DaemonError> {
        let text = fs::read_to_string(path.as_ref())
            .map_err(|err| DaemonError::io("read_site_manifest", err))?;
        Self::parse_json(&text)
    }

    /// Parses and validates a [`SiteManifest`] from raw JSON text without Serde.
    pub fn parse_json(text: &str) -> Result<Self, DaemonError> {
        let value = json_input::parse(text).map_err(|err| DaemonError::InvalidManifest {
            detail: format!("JSON syntax error: {err}"),
        })?;
        let root = value.object().ok_or_else(|| DaemonError::InvalidManifest {
            detail: "manifest root must be a JSON object".to_owned(),
        })?;
        reject_forbidden_secret_keys(root, "root")?;

        let schema = req_text(root, "schema")?;
        if schema != SITE_MANIFEST_SCHEMA {
            return Err(DaemonError::InvalidManifest {
                detail: format!(
                    "unsupported schema `{schema}` (expected `{SITE_MANIFEST_SCHEMA}`)"
                ),
            });
        }
        let site_id = req_text(root, "site_id")?.to_owned();
        validate_id(&site_id).map_err(|_| DaemonError::InvalidManifest {
            detail: "site_id must use canonical portable identifier alphabet".to_owned(),
        })?;

        let deployment_root = opt_text(root, "deployment_root")?
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let ring_cap_bytes =
            opt_u64(root, "ring_cap_bytes")?.unwrap_or(DEFAULT_SITE_RING_CAP_BYTES);
        let soft_watermark_pct =
            opt_u8(root, "soft_watermark_pct")?.unwrap_or(DEFAULT_WATERMARK_SOFT_PCT);
        let hard_watermark_pct =
            opt_u8(root, "hard_watermark_pct")?.unwrap_or(DEFAULT_WATERMARK_HARD_PCT);
        let pack_target_bytes =
            opt_u64(root, "pack_target_bytes")?.unwrap_or(DEFAULT_TARGET_PACK_BYTES);
        let scrub_budget_bytes_per_tick = opt_u64(root, "scrub_budget_bytes_per_tick")?
            .unwrap_or(DEFAULT_SCRUB_BUDGET_BYTES_PER_TICK);
        let retain_hot_ns = opt_u64(root, "retain_hot_ns")?.unwrap_or(DEFAULT_RETAIN_HOT_NS);
        let ipc_socket_override = opt_text(root, "ipc_socket_override")?.map(PathBuf::from);
        let detector_package_path = opt_text(root, "detector_package_path")?.map(PathBuf::from);
        let detector_package_digest = match opt_text(root, "detector_package_digest")? {
            Some(raw) => Some(ContentDigest::parse(raw).map_err(|_| {
                DaemonError::InvalidManifest {
                    detail: "detector_package_digest must be a canonical `sha256:<hex>` digest"
                        .to_owned(),
                }
            })?),
            None => None,
        };
        let detector_min_score_ppm = match opt_u64(root, "detector_min_score_ppm")? {
            Some(raw) => Some(
                u32::try_from(raw).map_err(|_| DaemonError::InvalidManifest {
                    detail: "detector_min_score_ppm out of u32 range".to_owned(),
                })?,
            ),
            None => None,
        };

        let raw_cameras = root.get("cameras").and_then(Value::array).ok_or_else(|| {
            DaemonError::InvalidManifest {
                detail: "manifest requires a `cameras` array".to_owned(),
            }
        })?;
        let mut cameras = Vec::with_capacity(raw_cameras.len());
        for (idx, item) in raw_cameras.iter().enumerate() {
            cameras.push(parse_camera_entry(item, idx)?);
        }

        let topology = match root.get("topology") {
            None | Some(Value::Null) => SiteTopologyManifest::default(),
            Some(val) => parse_topology(val)?,
        };

        let manifest = Self {
            site_id,
            deployment_root,
            ring_cap_bytes,
            soft_watermark_pct,
            hard_watermark_pct,
            pack_target_bytes,
            scrub_budget_bytes_per_tick,
            retain_hot_ns,
            ipc_socket_override,
            detector_package_path,
            detector_package_digest,
            detector_min_score_ppm,
            cameras,
            topology,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates every structural, capacity, credential-hygiene, and topology invariant.
    pub fn validate(&self) -> Result<(), DaemonError> {
        validate_id(&self.site_id).map_err(|_| DaemonError::InvalidManifest {
            detail: "invalid site_id".to_owned(),
        })?;
        if self.ring_cap_bytes < 4_096 {
            return Err(DaemonError::InvalidManifest {
                detail: "ring_cap_bytes must be >= 4096".to_owned(),
            });
        }
        if self.soft_watermark_pct == 0
            || self.hard_watermark_pct > 100
            || self.soft_watermark_pct >= self.hard_watermark_pct
        {
            return Err(DaemonError::InvalidManifest {
                detail:
                    "watermarks must satisfy 1 <= soft_watermark_pct < hard_watermark_pct <= 100"
                        .to_owned(),
            });
        }
        if self.pack_target_bytes < MIN_CONFIGURABLE_TARGET_PACK_BYTES {
            return Err(DaemonError::InvalidManifest {
                detail: format!(
                    "pack_target_bytes must be >= {MIN_CONFIGURABLE_TARGET_PACK_BYTES}"
                ),
            });
        }
        if self.scrub_budget_bytes_per_tick == 0 {
            return Err(DaemonError::InvalidManifest {
                detail: "scrub_budget_bytes_per_tick must be >= 1".to_owned(),
            });
        }
        if self.detector_package_path.is_some() != self.detector_package_digest.is_some() {
            return Err(DaemonError::InvalidManifest {
                detail: "detector_package_path and detector_package_digest must be configured together so model weights are digest-pinned".to_owned(),
            });
        }
        if let Some(ppm) = self.detector_min_score_ppm
            && (ppm == 0 || ppm > 1_000_000)
        {
            return Err(DaemonError::InvalidManifest {
                detail: "detector_min_score_ppm must be in 1..=1_000_000".to_owned(),
            });
        }
        if self.cameras.is_empty() || self.cameras.len() > MAX_SENSOR_REGIONS {
            return Err(DaemonError::InvalidManifest {
                detail: format!("cameras count must be in 1..={MAX_SENSOR_REGIONS}"),
            });
        }

        let mut seen = BTreeSet::new();
        for (idx, cam) in self.cameras.iter().enumerate() {
            if !seen.insert(cam.sensor_id.as_str()) {
                return Err(DaemonError::InvalidManifest {
                    detail: format!("duplicate camera sensor_id `{}`", cam.sensor_id),
                });
            }
            reject_secret_in_endpoint(&cam.endpoint, &format!("cameras[{idx}].endpoint"))?;
            if cam.reconnect_min_ms == 0 || cam.reconnect_max_ms < cam.reconnect_min_ms {
                return Err(DaemonError::InvalidManifest {
                    detail: format!(
                        "camera `{}` reconnect bounds must satisfy 1 <= min <= max",
                        cam.sensor_id
                    ),
                });
            }
            if cam.stall_timeout_ms == 0 {
                return Err(DaemonError::InvalidManifest {
                    detail: format!("camera `{}` stall_timeout_ms must be >= 1", cam.sensor_id),
                });
            }
            if cam.ring_max_frames == 0 || cam.ring_max_frames > 4_096 {
                return Err(DaemonError::InvalidManifest {
                    detail: format!(
                        "camera `{}` ring_max_frames must be in 1..=4096",
                        cam.sensor_id
                    ),
                });
            }
            if cam.ring_max_bytes < 1_024 {
                return Err(DaemonError::InvalidManifest {
                    detail: format!("camera `{}` ring_max_bytes must be >= 1024", cam.sensor_id),
                });
            }
            if cam.gop_frames == 0 || cam.gop_frames > MAX_MEDIA_CHUNK_FRAMES {
                return Err(DaemonError::InvalidManifest {
                    detail: format!(
                        "camera `{}` gop_frames must be in 1..={MAX_MEDIA_CHUNK_FRAMES}",
                        cam.sensor_id
                    ),
                });
            }
            if cam.dimensions[0] == 0 || cam.dimensions[1] == 0 {
                return Err(DaemonError::InvalidManifest {
                    detail: format!("camera `{}` dimensions must be positive", cam.sensor_id),
                });
            }
            let canonical_rects = validate_ignore_regions(&cam.osd_ignore_rects)?;
            validate_ignore_regions_in_bounds(&canonical_rects, cam.dimensions)?;
        }

        // Validate full C8 site topology compatibility eagerly.
        let _ = self.to_site_topology()?;
        Ok(())
    }

    /// Builds and validates a `C8` [`SiteTopologyRegistry`] from this manifest.
    pub fn to_site_topology(&self) -> Result<SiteTopologyRegistry, DaemonError> {
        let mut reg = SiteTopologyRegistry::new(&self.site_id);
        reg.default_homography_time_gate_ns = self.topology.default_homography_time_gate_ns;

        let mut homographies_by_sensor: BTreeMap<&str, CameraHomography> = BTreeMap::new();
        for h in &self.topology.homographies {
            if homographies_by_sensor
                .insert(h.sensor_id.as_str(), h.homography)
                .is_some()
            {
                return Err(DaemonError::InvalidManifest {
                    detail: format!("duplicate homography for sensor `{}`", h.sensor_id),
                });
            }
        }

        for cam in &self.cameras {
            let homography = homographies_by_sensor.remove(cam.sensor_id.as_str());
            reg.register_camera(CameraTopologyEntry {
                sensor_id: cam.sensor_id.as_str().to_owned(),
                failure_domains: cam.failure_domains.clone(),
                homography,
                zones: cam.zones.clone(),
            });
        }
        if let Some(unknown) = homographies_by_sensor.keys().next() {
            return Err(DaemonError::InvalidManifest {
                detail: format!("homography references unknown camera `{unknown}`"),
            });
        }
        for sz in &self.topology.shared_zones {
            reg.add_shared_zone(sz.clone());
        }
        for corridor in &self.topology.transit_corridors {
            reg.add_transit_corridor(corridor.clone());
        }
        reg.validate()?;
        Ok(reg)
    }

    /// Resolves the effective IPC deployment root directory, honoring `ipc_socket_override` if set.
    #[must_use]
    pub fn effective_ipc_root(&self) -> PathBuf {
        match &self.ipc_socket_override {
            None => self.deployment_root.clone(),
            Some(override_path) => {
                if override_path.file_name().and_then(|n| n.to_str()) == Some("daemon.sock")
                    && let Some(run_dir) = override_path.parent()
                    && run_dir.file_name().and_then(|n| n.to_str()) == Some("run")
                    && let Some(root) = run_dir.parent()
                {
                    return root.to_path_buf();
                }
                override_path.clone()
            }
        }
    }

    /// Computes the canonical domain-separated SHA-256 commitment under [`DAEMON_SITE_MANIFEST_DOMAIN`].
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(DAEMON_SITE_MANIFEST_DOMAIN);
        enc.text(&self.site_id);
        enc.u64(self.ring_cap_bytes);
        enc.u8(self.soft_watermark_pct);
        enc.u8(self.hard_watermark_pct);
        enc.u64(self.pack_target_bytes);
        enc.u64(self.scrub_budget_bytes_per_tick);
        enc.u64(self.retain_hot_ns);
        enc.u64(self.cameras.len() as u64);
        for cam in &self.cameras {
            enc.text(cam.sensor_id.as_str());
            enc.text(cam.adapter.as_str());
            enc.text(&cam.endpoint);
            match &cam.secret_id {
                Some(id) => {
                    enc.bool(true);
                    enc.text(id.as_str());
                }
                None => enc.bool(false),
            }
            enc.text(cam.priority_tier.as_str());
            enc.text(&cam.primary_zone);
            enc.u32(cam.dimensions[0]);
            enc.u32(cam.dimensions[1]);
            enc.u64(cam.osd_ignore_rects.len() as u64);
            for rect in &cam.osd_ignore_rects {
                enc.u32(rect.x);
                enc.u32(rect.y);
                enc.u32(rect.width);
                enc.u32(rect.height);
            }
            enc.u64(cam.failure_domains.len() as u64);
            for d in &cam.failure_domains {
                enc.text(d);
            }
            enc.u64(cam.reconnect_min_ms);
            enc.u64(cam.reconnect_max_ms);
            enc.u64(cam.stall_timeout_ms);
            enc.u64(cam.ring_max_frames as u64);
            enc.u64(cam.ring_max_bytes as u64);
            enc.u64(cam.gop_frames as u64);
        }
        if let Ok(topo) = self.to_site_topology() {
            enc.digest(topo.digest());
        }
        if let Some(pkg_digest) = self.detector_package_digest {
            enc.bool(true);
            enc.digest(pkg_digest);
            enc.u32(self.detector_min_score_ppm.unwrap_or(0));
        }
        ContentDigest::sha256(&enc.finish())
    }
}

/// Checks an endpoint URL/descriptor and rejects any embedded plaintext credential fail-closed.
pub fn reject_secret_in_endpoint(endpoint: &str, location: &str) -> Result<(), DaemonError> {
    if endpoint.is_empty() || endpoint.len() > 1024 || endpoint.chars().any(char::is_control) {
        return Err(DaemonError::InvalidManifest {
            detail: format!("{location} must be 1..=1024 printable bytes"),
        });
    }
    if let Some((_, rest)) = endpoint.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Err(DaemonError::SecretInManifest {
                location: location.to_owned(),
                detail: "inline URL userinfo/password (`user:pass@host`) is forbidden; reference an fss-vault `secret_id` instead".to_owned(),
            });
        }
    }
    if let Some((_, query)) = endpoint.split_once('?') {
        let query_part = query.split('#').next().unwrap_or("");
        for pair in query_part.split('&') {
            if let Some((key, _)) = pair.split_once('=') {
                let lower = key.to_ascii_lowercase();
                if FORBIDDEN_QUERY_KEYS.contains(&lower.as_str()) {
                    return Err(DaemonError::SecretInManifest {
                        location: location.to_owned(),
                        detail: format!(
                            "credential-bearing query parameter `{lower}` is forbidden in endpoint URLs; use `secret_id`"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}
