#![forbid(unsafe_code)]
//! Strict JSON admission; no field outside these versioned contracts is accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_core::json_input::{self, Value};

use super::{
    MAX_PAYMENT_MASKS, MAX_PROBE_FRAMES, MAX_SITE_INPUT_BYTES, MAX_SITE_SOURCES, MAX_SOURCE_ZONES,
    MAX_ZONE_VERTICES, NetworkRoute, PaymentMask, ProbeCodec, SITE_MANIFEST_SCHEMA,
    SITE_PROBE_RECEIPT_SCHEMA, SiteAuthentication, SiteError, SiteManifest, SiteProbeReceipt,
    SiteSource, SiteZone, SourceKind, StreamRole,
};

type Fields = BTreeMap<String, Value>;

/// Decode one complete site manifest. Syntax, bounds and semantics are checked before return.
pub fn parse_manifest(bytes: &[u8]) -> Result<SiteManifest, SiteError> {
    let value = parse(bytes)?;
    let fields = object(
        &value,
        &[
            "schema",
            "site_id",
            "generation",
            "network_route",
            "sources",
        ],
    )?;
    schema(fields, SITE_MANIFEST_SCHEMA)?;
    let sources = array(fields, "sources", 1, MAX_SITE_SOURCES)?;
    let manifest = SiteManifest {
        site_id: text(fields, "site_id")?.to_owned(),
        generation: integer(fields, "generation")?,
        network_route: match text(fields, "network_route")? {
            "lan" => NetworkRoute::Lan,
            "vpn" => NetworkRoute::Vpn,
            _ => return Err(SiteError::InvalidField("network_route")),
        },
        sources: sources.iter().map(source).collect::<Result<_, _>>()?,
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Decode a complete bounded JSON array of probe receipts; duplicate sources are refused.
/// An empty array is valid: a compiler must report each source's missing evidence explicitly.
pub fn parse_probe_receipts(bytes: &[u8]) -> Result<Vec<SiteProbeReceipt>, SiteError> {
    let value = parse(bytes)?;
    let values = value.array().ok_or(SiteError::Shape)?;
    if values.len() > MAX_SITE_SOURCES {
        return Err(SiteError::Limit);
    }
    let mut identities = BTreeSet::new();
    let mut receipts = Vec::with_capacity(values.len());
    for value in values {
        let receipt = receipt(value)?;
        if !identities.insert((receipt.site_id.clone(), receipt.source_id.clone())) {
            return Err(SiteError::DuplicateProbe);
        }
        receipts.push(receipt);
    }
    Ok(receipts)
}

fn parse(bytes: &[u8]) -> Result<Value, SiteError> {
    if bytes.len() > MAX_SITE_INPUT_BYTES {
        return Err(SiteError::Limit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SiteError::Json)?;
    json_input::parse(text).map_err(|_| SiteError::Json)
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Fields, SiteError> {
    let fields = value.object().ok_or(SiteError::Shape)?;
    if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(SiteError::UnknownField);
    }
    Ok(fields)
}

fn field<'a>(fields: &'a Fields, name: &'static str) -> Result<&'a Value, SiteError> {
    fields.get(name).ok_or(SiteError::MissingField(name))
}

fn text<'a>(fields: &'a Fields, name: &'static str) -> Result<&'a str, SiteError> {
    field(fields, name)?
        .text()
        .ok_or(SiteError::InvalidField(name))
}

fn optional_text(fields: &Fields, name: &'static str) -> Result<Option<String>, SiteError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(value)) => Ok(Some(value.clone())),
        _ => Err(SiteError::InvalidField(name)),
    }
}

fn integer<T>(fields: &Fields, name: &'static str) -> Result<T, SiteError>
where
    T: std::str::FromStr + ToString,
{
    number(field(fields, name)?, name)
}

fn number<T>(value: &Value, name: &'static str) -> Result<T, SiteError>
where
    T: std::str::FromStr + ToString,
{
    let Value::Number(raw) = value else {
        return Err(SiteError::InvalidField(name));
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SiteError::InvalidField(name));
    }
    let parsed: T = raw.parse().map_err(|_| SiteError::InvalidField(name))?;
    if parsed.to_string() != *raw {
        return Err(SiteError::InvalidField(name));
    }
    Ok(parsed)
}

fn boolean(fields: &Fields, name: &'static str) -> Result<bool, SiteError> {
    field(fields, name)?
        .boolean()
        .ok_or(SiteError::InvalidField(name))
}

fn array<'a>(
    fields: &'a Fields,
    name: &'static str,
    min: usize,
    max: usize,
) -> Result<&'a [Value], SiteError> {
    let values = field(fields, name)?
        .array()
        .ok_or(SiteError::InvalidField(name))?;
    if !(min..=max).contains(&values.len()) {
        return Err(SiteError::Limit);
    }
    Ok(values)
}

fn schema(fields: &Fields, expected: &str) -> Result<(), SiteError> {
    if text(fields, "schema")? != expected {
        return Err(SiteError::InvalidField("schema"));
    }
    Ok(())
}

fn peer(fields: &Fields) -> Result<SocketAddr, SiteError> {
    let raw = text(fields, "peer")?;
    if raw.len() > 64 {
        return Err(SiteError::InvalidField("peer"));
    }
    let peer: SocketAddr = raw.parse().map_err(|_| SiteError::InvalidField("peer"))?;
    // Canonical literal spelling avoids equivalent numeric routes having hidden aliases.
    if peer.to_string() != raw {
        return Err(SiteError::InvalidField("peer"));
    }
    super::peer(peer)?;
    Ok(peer)
}

fn digest(fields: &Fields, name: &'static str) -> Result<ContentDigest, SiteError> {
    let raw = text(fields, name)?;
    let value = ContentDigest::parse(raw).map_err(|_| SiteError::InvalidField(name))?;
    super::digest(value)?;
    if value.to_text() != raw {
        return Err(SiteError::InvalidField(name));
    }
    Ok(value)
}

fn source(value: &Value) -> Result<SiteSource, SiteError> {
    let fields = object(
        value,
        &[
            "source_id",
            "generation",
            "kind",
            "peer",
            "authority",
            "presentation",
            "control_root",
            "onvif_service_path",
            "unifi_camera_id",
            "stream_role",
            "authentication",
            "retention_class",
            "rights_verdict_ref",
            "zones",
            "payment_masks",
            "max_connections",
            "owner_authorized",
            "plaintext",
            "retain_originals",
        ],
    )?;
    let kind = match text(fields, "kind")? {
        "rtsp" => SourceKind::Rtsp,
        "onvif" => SourceKind::Onvif,
        "unifi_protect" => SourceKind::UnifiProtect,
        "nvr_channel" => SourceKind::NvrChannel,
        _ => return Err(SiteError::InvalidField("kind")),
    };
    let stream_role = match text(fields, "stream_role")? {
        "main" => StreamRole::Main,
        "sub" => StreamRole::Sub,
        _ => return Err(SiteError::InvalidField("stream_role")),
    };
    let authentication = match fields.get("authentication") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let fields = object(
                value,
                &["credential_file", "realm", "legacy_md5", "legacy_no_qop"],
            )?;
            Some(SiteAuthentication {
                credential_file: PathBuf::from(text(fields, "credential_file")?),
                realm: text(fields, "realm")?.to_owned(),
                legacy_md5: boolean(fields, "legacy_md5")?,
                legacy_no_qop: boolean(fields, "legacy_no_qop")?,
            })
        }
    };
    Ok(SiteSource {
        source_id: text(fields, "source_id")?.to_owned(),
        generation: integer(fields, "generation")?,
        kind,
        peer: peer(fields)?,
        authority: text(fields, "authority")?.to_owned(),
        presentation: optional_text(fields, "presentation")?,
        control_root: optional_text(fields, "control_root")?,
        onvif_service_path: optional_text(fields, "onvif_service_path")?,
        unifi_camera_id: optional_text(fields, "unifi_camera_id")?,
        stream_role,
        authentication,
        retention_class: text(fields, "retention_class")?.to_owned(),
        rights_verdict_ref: text(fields, "rights_verdict_ref")?.to_owned(),
        zones: array(fields, "zones", 0, MAX_SOURCE_ZONES)?
            .iter()
            .map(zone)
            .collect::<Result<_, _>>()?,
        payment_masks: array(fields, "payment_masks", 0, MAX_PAYMENT_MASKS)?
            .iter()
            .map(mask)
            .collect::<Result<_, _>>()?,
        max_connections: integer(fields, "max_connections")?,
        owner_authorized: boolean(fields, "owner_authorized")?,
        plaintext: boolean(fields, "plaintext")?,
        retain_originals: boolean(fields, "retain_originals")?,
    })
}

fn zone(value: &Value) -> Result<SiteZone, SiteError> {
    let fields = object(value, &["zone_id", "kind", "vertices"])?;
    let vertices = array(fields, "vertices", 3, MAX_ZONE_VERTICES)?
        .iter()
        .map(|vertex| {
            let items = vertex.array().ok_or(SiteError::InvalidField("vertices"))?;
            if items.len() != 2 {
                return Err(SiteError::InvalidField("vertices"));
            }
            Ok([
                number(&items[0], "vertices")?,
                number(&items[1], "vertices")?,
            ])
        })
        .collect::<Result<_, _>>()?;
    Ok(SiteZone {
        zone_id: text(fields, "zone_id")?.to_owned(),
        kind: text(fields, "kind")?.to_owned(),
        vertices,
    })
}

fn mask(value: &Value) -> Result<PaymentMask, SiteError> {
    let fields = object(value, &["x", "y", "width", "height"])?;
    Ok(PaymentMask {
        x: integer(fields, "x")?,
        y: integer(fields, "y")?,
        width: integer(fields, "width")?,
        height: integer(fields, "height")?,
    })
}

fn receipt(value: &Value) -> Result<SiteProbeReceipt, SiteError> {
    let fields = object(
        value,
        &[
            "schema",
            "site_id",
            "source_id",
            "manifest_digest",
            "source_generation",
            "peer",
            "authority",
            "presentation",
            "control_root",
            "media_index",
            "rtp_channel",
            "rtcp_channel",
            "sdp_digest",
            "codec",
            "payload_type",
            "ssrc",
            "frame_duration_ticks",
            "clock_rate_hz",
            "observed_frames",
            "first_rtp_timestamp",
            "last_rtp_timestamp",
            "parameter_set_digests",
            "server_identity",
        ],
    )?;
    schema(fields, SITE_PROBE_RECEIPT_SCHEMA)?;
    let codec = match text(fields, "codec")? {
        "avc" => ProbeCodec::Avc,
        "hevc" => ProbeCodec::Hevc,
        "jpeg" => ProbeCodec::Jpeg,
        _ => return Err(SiteError::InvalidField("codec")),
    };
    let mut parameter_set_digests = Vec::new();
    for item in array(fields, "parameter_set_digests", 0, 3)? {
        let text = item
            .text()
            .ok_or(SiteError::InvalidField("parameter_set_digests"))?;
        let digest = ContentDigest::parse(text)
            .map_err(|_| SiteError::InvalidField("parameter_set_digests"))?;
        super::digest(digest)?;
        if digest.to_text() != text {
            return Err(SiteError::InvalidField("parameter_set_digests"));
        }
        parameter_set_digests.push(digest);
    }
    let receipt = SiteProbeReceipt {
        site_id: text(fields, "site_id")?.to_owned(),
        source_id: text(fields, "source_id")?.to_owned(),
        manifest_digest: digest(fields, "manifest_digest")?,
        source_generation: integer(fields, "source_generation")?,
        peer: peer(fields)?,
        authority: text(fields, "authority")?.to_owned(),
        presentation: text(fields, "presentation")?.to_owned(),
        control_root: text(fields, "control_root")?.to_owned(),
        media_index: integer(fields, "media_index")?,
        rtp_channel: integer(fields, "rtp_channel")?,
        rtcp_channel: integer(fields, "rtcp_channel")?,
        sdp_digest: digest(fields, "sdp_digest")?,
        codec,
        payload_type: integer(fields, "payload_type")?,
        ssrc: integer(fields, "ssrc")?,
        frame_duration_ticks: integer(fields, "frame_duration_ticks")?,
        clock_rate_hz: integer(fields, "clock_rate_hz")?,
        observed_frames: integer(fields, "observed_frames")?,
        first_rtp_timestamp: integer(fields, "first_rtp_timestamp")?,
        last_rtp_timestamp: integer(fields, "last_rtp_timestamp")?,
        parameter_set_digests,
        server_identity: text(fields, "server_identity")?.to_owned(),
    };
    if receipt.observed_frames > MAX_PROBE_FRAMES {
        return Err(SiteError::Limit);
    }
    receipt.validate()?;
    Ok(receipt)
}
