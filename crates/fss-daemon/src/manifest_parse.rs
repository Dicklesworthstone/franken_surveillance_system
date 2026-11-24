#![forbid(unsafe_code)]
//! Zero-Serde JSON field, camera, and topology parsing helpers for [`crate::manifest::SiteManifest`].
//!
//! Semantic plane: `"authority"`.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::SensorId;
use fss_core::json_input::Value;
use fss_reference::ingest::live_corroborate::{
    CameraHomography, DEFAULT_HOMOGRAPHY_TIME_GATE_NS, SharedZoneOverlap, TransitCorridor,
};
use fss_reference::ingest::model_pool::CameraPriorityTier;
use fss_reference::ingest::osd_mask::{ImageRect, validate_ignore_regions};
use fss_vault::SecretId;

use crate::error::DaemonError;
use crate::manifest::{
    CameraAdapterKind, CameraManifestEntry, DEFAULT_CAMERA_DIMENSIONS, DEFAULT_GOP_FRAMES,
    DEFAULT_RECONNECT_MAX_MS, DEFAULT_RECONNECT_MIN_MS, DEFAULT_RING_MAX_BYTES,
    DEFAULT_RING_MAX_FRAMES, DEFAULT_STALL_TIMEOUT_MS, ManifestHomography, SiteTopologyManifest,
    reject_secret_in_endpoint,
};

const FORBIDDEN_SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "secret",
    "secret_value",
    "plaintext_secret",
    "token",
    "access_token",
    "auth_token",
    "api_key",
    "apikey",
    "basic_auth",
    "credentials",
];

pub(crate) fn reject_forbidden_secret_keys(
    obj: &BTreeMap<String, Value>,
    location: &str,
) -> Result<(), DaemonError> {
    for key in obj.keys() {
        let lower = key.to_ascii_lowercase();
        if FORBIDDEN_SECRET_KEYS.contains(&lower.as_str()) {
            return Err(DaemonError::SecretInManifest {
                location: format!("{location}.{key}"),
                detail: "plaintext secret fields are forbidden in site manifests; reference `secret_id` in fss-vault".to_owned(),
            });
        }
    }
    Ok(())
}

pub(crate) fn parse_camera_entry(
    value: &Value,
    idx: usize,
) -> Result<CameraManifestEntry, DaemonError> {
    let loc = format!("cameras[{idx}]");
    let obj = value.object().ok_or_else(|| DaemonError::InvalidManifest {
        detail: format!("{loc} must be a JSON object"),
    })?;
    reject_forbidden_secret_keys(obj, &loc)?;

    let sensor_id = SensorId::parse(req_text(obj, "sensor_id")?)?;
    let adapter = CameraAdapterKind::parse(req_text(obj, "adapter")?)?;
    let endpoint = req_text(obj, "endpoint")?.to_owned();
    reject_secret_in_endpoint(&endpoint, &format!("{loc}.endpoint"))?;

    let secret_id = match opt_text(obj, "secret_id")? {
        Some(raw) => Some(SecretId::parse(raw)?),
        None => None,
    };
    let priority_tier = match opt_text(obj, "priority_tier")? {
        Some(raw) => parse_priority_tier(raw)?,
        None => CameraPriorityTier::Standard,
    };
    let primary_zone = opt_text(obj, "zone_id")?.unwrap_or("default").to_owned();
    let mut zones = parse_string_set(obj, "zones")?;
    zones.insert(primary_zone.clone());

    let dimensions = parse_dimensions(obj)?;
    let osd_ignore_rects = parse_osd_rects(obj, &loc)?;
    let failure_domains = parse_string_set(obj, "failure_domains")?;
    let reconnect_min_ms = opt_u64(obj, "reconnect_min_ms")?.unwrap_or(DEFAULT_RECONNECT_MIN_MS);
    let reconnect_max_ms = opt_u64(obj, "reconnect_max_ms")?.unwrap_or(DEFAULT_RECONNECT_MAX_MS);
    let stall_timeout_ms = opt_u64(obj, "stall_timeout_ms")?.unwrap_or(DEFAULT_STALL_TIMEOUT_MS);
    let ring_max_frames = opt_usize(obj, "ring_max_frames")?.unwrap_or(DEFAULT_RING_MAX_FRAMES);
    let ring_max_bytes = opt_usize(obj, "ring_max_bytes")?.unwrap_or(DEFAULT_RING_MAX_BYTES);
    let gop_frames = opt_usize(obj, "gop_frames")?.unwrap_or(DEFAULT_GOP_FRAMES);
    let auth_realm = opt_text(obj, "auth_realm")?.map(ToOwned::to_owned);
    let allow_inband_sps_pps = opt_bool(obj, "allow_inband_sps_pps")?.unwrap_or(false);
    let setup_companion_tracks = opt_bool(obj, "setup_companion_tracks")?.unwrap_or(false);

    Ok(CameraManifestEntry {
        sensor_id,
        adapter,
        endpoint,
        secret_id,
        priority_tier,
        primary_zone,
        zones,
        dimensions,
        osd_ignore_rects,
        failure_domains,
        reconnect_min_ms,
        reconnect_max_ms,
        stall_timeout_ms,
        ring_max_frames,
        ring_max_bytes,
        gop_frames,
        auth_realm,
        allow_inband_sps_pps,
        setup_companion_tracks,
    })
}

pub(crate) fn parse_topology(value: &Value) -> Result<SiteTopologyManifest, DaemonError> {
    let obj = value.object().ok_or_else(|| DaemonError::InvalidManifest {
        detail: "topology must be a JSON object".to_owned(),
    })?;
    reject_forbidden_secret_keys(obj, "topology")?;

    let default_homography_time_gate_ns =
        opt_u64(obj, "default_homography_time_gate_ns")?.unwrap_or(DEFAULT_HOMOGRAPHY_TIME_GATE_NS);

    let mut shared_zones = Vec::new();
    if let Some(items) = obj.get("shared_zones") {
        let arr = items.array().ok_or_else(|| DaemonError::InvalidManifest {
            detail: "topology.shared_zones must be an array".to_owned(),
        })?;
        for (i, item) in arr.iter().enumerate() {
            let sz_obj = item.object().ok_or_else(|| DaemonError::InvalidManifest {
                detail: format!("topology.shared_zones[{i}] must be an object"),
            })?;
            shared_zones.push(SharedZoneOverlap {
                zone_id: req_text(sz_obj, "zone_id")?.to_owned(),
                cameras: parse_string_set(sz_obj, "cameras")?,
                max_separation_ns: opt_u64(sz_obj, "max_separation_ns")?
                    .unwrap_or(DEFAULT_HOMOGRAPHY_TIME_GATE_NS),
            });
        }
    }

    let mut transit_corridors = Vec::new();
    if let Some(items) = obj.get("transit_corridors") {
        let arr = items.array().ok_or_else(|| DaemonError::InvalidManifest {
            detail: "topology.transit_corridors must be an array".to_owned(),
        })?;
        for (i, item) in arr.iter().enumerate() {
            let c_obj = item.object().ok_or_else(|| DaemonError::InvalidManifest {
                detail: format!("topology.transit_corridors[{i}] must be an object"),
            })?;
            transit_corridors.push(TransitCorridor {
                corridor_id: req_text(c_obj, "corridor_id")?.to_owned(),
                from_camera: req_text(c_obj, "from_camera")?.to_owned(),
                from_zone: req_text(c_obj, "from_zone")?.to_owned(),
                to_camera: req_text(c_obj, "to_camera")?.to_owned(),
                to_zone: req_text(c_obj, "to_zone")?.to_owned(),
                min_transit_ns: req_u64(c_obj, "min_transit_ns")?,
                max_transit_ns: req_u64(c_obj, "max_transit_ns")?,
                bidirectional: c_obj
                    .get("bidirectional")
                    .and_then(Value::boolean)
                    .unwrap_or(false),
            });
        }
    }

    let mut homographies = Vec::new();
    if let Some(items) = obj.get("homographies") {
        let arr = items.array().ok_or_else(|| DaemonError::InvalidManifest {
            detail: "topology.homographies must be an array".to_owned(),
        })?;
        for (i, item) in arr.iter().enumerate() {
            let h_obj = item.object().ok_or_else(|| DaemonError::InvalidManifest {
                detail: format!("topology.homographies[{i}] must be an object"),
            })?;
            let sensor_id = req_text(h_obj, "sensor_id")?.to_owned();
            let mat_arr = h_obj.get("matrix").and_then(Value::array).ok_or_else(|| {
                DaemonError::InvalidManifest {
                    detail: format!("topology.homographies[{i}].matrix must be a 9-element array"),
                }
            })?;
            if mat_arr.len() != 9 {
                return Err(DaemonError::InvalidManifest {
                    detail: format!("topology.homographies[{i}].matrix requires exactly 9 numbers"),
                });
            }
            let mut matrix = [0.0_f64; 9];
            for (slot, val) in matrix.iter_mut().zip(mat_arr.iter()) {
                *slot = parse_f64(val, "homography matrix entry")?;
            }
            let gate_val =
                h_obj
                    .get("distance_gate")
                    .ok_or_else(|| DaemonError::InvalidManifest {
                        detail: format!("topology.homographies[{i}] missing distance_gate"),
                    })?;
            let distance_gate = parse_f64(gate_val, "distance_gate")?;
            homographies.push(ManifestHomography {
                sensor_id,
                homography: CameraHomography {
                    matrix,
                    distance_gate,
                },
            });
        }
    }

    Ok(SiteTopologyManifest {
        default_homography_time_gate_ns,
        shared_zones,
        transit_corridors,
        homographies,
    })
}

fn parse_priority_tier(raw: &str) -> Result<CameraPriorityTier, DaemonError> {
    match raw {
        "active_investigation" => Ok(CameraPriorityTier::ActiveInvestigation),
        "high_consequence_zone" => Ok(CameraPriorityTier::HighConsequenceZone),
        "corroborated_track" => Ok(CameraPriorityTier::CorroboratedTrack),
        "standard" => Ok(CameraPriorityTier::Standard),
        other => Err(DaemonError::InvalidManifest {
            detail: format!("unknown priority_tier `{other}`"),
        }),
    }
}

fn parse_dimensions(obj: &BTreeMap<String, Value>) -> Result<[u32; 2], DaemonError> {
    match obj.get("dimensions") {
        None | Some(Value::Null) => Ok(DEFAULT_CAMERA_DIMENSIONS),
        Some(val) => {
            let arr = val.array().ok_or_else(|| DaemonError::InvalidManifest {
                detail: "camera dimensions must be a 2-element integer array [width, height]"
                    .to_owned(),
            })?;
            if arr.len() != 2 {
                return Err(DaemonError::InvalidManifest {
                    detail: "camera dimensions must have exactly 2 elements".to_owned(),
                });
            }
            Ok([
                value_to_u32(&arr[0], "dimensions[0]")?,
                value_to_u32(&arr[1], "dimensions[1]")?,
            ])
        }
    }
}

fn parse_osd_rects(
    obj: &BTreeMap<String, Value>,
    loc: &str,
) -> Result<Vec<ImageRect>, DaemonError> {
    let Some(val) = obj.get("osd_ignore_rects") else {
        return Ok(Vec::new());
    };
    if matches!(val, Value::Null) {
        return Ok(Vec::new());
    }
    let arr = val.array().ok_or_else(|| DaemonError::InvalidManifest {
        detail: format!("{loc}.osd_ignore_rects must be an array"),
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        if let Some(s) = item.text() {
            out.push(ImageRect::parse_xywh(s)?);
        } else if let Some(r_obj) = item.object() {
            out.push(ImageRect::new(
                req_u32(r_obj, "x")?,
                req_u32(r_obj, "y")?,
                req_u32(r_obj, "width")?,
                req_u32(r_obj, "height")?,
            )?);
        } else {
            return Err(DaemonError::InvalidManifest {
                detail: format!(
                    "{loc}.osd_ignore_rects[{i}] must be `X,Y,W,H` or {{x,y,width,height}}"
                ),
            });
        }
    }
    Ok(validate_ignore_regions(&out)?)
}

fn parse_string_set(
    obj: &BTreeMap<String, Value>,
    key: &str,
) -> Result<BTreeSet<String>, DaemonError> {
    let Some(val) = obj.get(key) else {
        return Ok(BTreeSet::new());
    };
    if matches!(val, Value::Null) {
        return Ok(BTreeSet::new());
    }
    let arr = val.array().ok_or_else(|| DaemonError::InvalidManifest {
        detail: format!("field `{key}` must be an array of strings"),
    })?;
    let mut set = BTreeSet::new();
    for item in arr {
        let s = item.text().ok_or_else(|| DaemonError::InvalidManifest {
            detail: format!("every entry in `{key}` must be a string"),
        })?;
        set.insert(s.to_owned());
    }
    Ok(set)
}

pub(crate) fn req_text<'a>(
    obj: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, DaemonError> {
    obj.get(key)
        .and_then(Value::text)
        .ok_or_else(|| DaemonError::InvalidManifest {
            detail: format!("missing or non-string required field `{key}`"),
        })
}

pub(crate) fn opt_text<'a>(
    obj: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, DaemonError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(DaemonError::InvalidManifest {
            detail: format!("field `{key}` must be a string"),
        }),
    }
}

fn opt_bool(obj: &BTreeMap<String, Value>, key: &str) -> Result<Option<bool>, DaemonError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(DaemonError::InvalidManifest {
            detail: format!("field `{key}` must be a boolean"),
        }),
    }
}

fn req_u64(obj: &BTreeMap<String, Value>, key: &str) -> Result<u64, DaemonError> {
    opt_u64(obj, key)?.ok_or_else(|| DaemonError::InvalidManifest {
        detail: format!("missing required integer field `{key}`"),
    })
}

pub(crate) fn opt_u64(
    obj: &BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<u64>, DaemonError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => {
            let n = val.integer().ok_or_else(|| DaemonError::InvalidManifest {
                detail: format!("field `{key}` must be a canonical integer"),
            })?;
            u64::try_from(n)
                .map(Some)
                .map_err(|_| DaemonError::InvalidManifest {
                    detail: format!("field `{key}` out of u64 range"),
                })
        }
    }
}

pub(crate) fn opt_u8(obj: &BTreeMap<String, Value>, key: &str) -> Result<Option<u8>, DaemonError> {
    match opt_u64(obj, key)? {
        None => Ok(None),
        Some(v) => u8::try_from(v)
            .map(Some)
            .map_err(|_| DaemonError::InvalidManifest {
                detail: format!("field `{key}` out of u8 range"),
            }),
    }
}

fn opt_usize(obj: &BTreeMap<String, Value>, key: &str) -> Result<Option<usize>, DaemonError> {
    match opt_u64(obj, key)? {
        None => Ok(None),
        Some(v) => usize::try_from(v)
            .map(Some)
            .map_err(|_| DaemonError::InvalidManifest {
                detail: format!("field `{key}` out of usize range"),
            }),
    }
}

fn req_u32(obj: &BTreeMap<String, Value>, key: &str) -> Result<u32, DaemonError> {
    let val = obj.get(key).ok_or_else(|| DaemonError::InvalidManifest {
        detail: format!("missing required integer field `{key}`"),
    })?;
    value_to_u32(val, key)
}

fn value_to_u32(val: &Value, key: &str) -> Result<u32, DaemonError> {
    let n = val.integer().ok_or_else(|| DaemonError::InvalidManifest {
        detail: format!("field `{key}` must be a canonical integer"),
    })?;
    u32::try_from(n).map_err(|_| DaemonError::InvalidManifest {
        detail: format!("field `{key}` out of u32 range"),
    })
}

fn parse_f64(val: &Value, label: &str) -> Result<f64, DaemonError> {
    let Value::Number(raw) = val else {
        return Err(DaemonError::InvalidManifest {
            detail: format!("{label} must be a finite JSON number"),
        });
    };
    let parsed = raw
        .parse::<f64>()
        .map_err(|_| DaemonError::InvalidManifest {
            detail: format!("invalid numeric literal for {label}"),
        })?;
    if !parsed.is_finite() {
        return Err(DaemonError::InvalidManifest {
            detail: format!("{label} must be finite"),
        });
    }
    Ok(parsed)
}
