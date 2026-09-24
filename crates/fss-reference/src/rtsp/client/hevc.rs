#![forbid(unsafe_code)]
//! RFC 7798 single-stream/no-DON SDP admission for the existing RTSP session.
//! Parameter-set headers are screened, not decoded or certified as mutually compatible.

use super::ClientError;
use crate::rtsp::{SdpMedia, decode_base64};
use std::fmt;

const MAX_SETS: usize = 16;
const MAX_SET_BYTES: usize = 16_384;
const MAX_TOTAL_SET_BYTES: usize = 32_768;

/// Optional server-advertised profile fields. Missing values remain missing.
/// These are unverified signaling, not a decoded profile or capability certificate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HevcProfileSignaling {
    /// Advertised profile space, in 0..=3.
    pub profile_space: Option<u8>,
    /// Advertised profile identifier, in 0..=31.
    pub profile_id: Option<u8>,
    /// Advertised tier flag, in 0..=1.
    pub tier_flag: Option<u8>,
    /// Advertised level identifier, in 0..=255.
    pub level_id: Option<u8>,
    /// Exact six-byte interoperability constraint field, when signaled.
    pub interop_constraints: Option<[u8; 6]>,
}

/// Immutable HEVC negotiation, separate from the existing H.264 ClientMedia.
/// No URL, credential, clock, packet, or decoder is created by this value.
#[derive(Clone, Eq, PartialEq)]
pub struct HevcClientMedia {
    payload_type: u8,
    vps: Vec<Vec<u8>>,
    sps: Vec<Vec<u8>>,
    pps: Vec<Vec<u8>>,
    profile: HevcProfileSignaling,
    reduced_rtcp: bool,
}
impl HevcClientMedia {
    /// Exact selected SDP payload mapping at a 90 kHz clock rate.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }
    /// Admitted no-DON requirement, including the RFC default when absent.
    pub fn sprop_max_don_diff(&self) -> u16 {
        0
    }
    /// Optional out-of-band VPS NALs in signaling order; empty means not supplied.
    pub fn vps(&self) -> &[Vec<u8>] {
        &self.vps
    }
    /// Optional out-of-band SPS NALs in signaling order; empty means not supplied.
    pub fn sps(&self) -> &[Vec<u8>] {
        &self.sps
    }
    /// Optional out-of-band PPS NALs in signaling order; empty means not supplied.
    pub fn pps(&self) -> &[Vec<u8>] {
        &self.pps
    }
    /// Server-advertised fields only; no parameter-set syntax/profile claim is made.
    pub fn profile_signaling(&self) -> HevcProfileSignaling {
        self.profile
    }
    /// Explicit reduced-size RTCP signaling; malformed compounds never enable it.
    pub fn reduced_rtcp(&self) -> bool {
        self.reduced_rtcp
    }
}
impl fmt::Debug for HevcClientMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HevcClientMedia")
            .field("payload_type", &self.payload_type)
            .field("vps_count", &self.vps.len())
            .field("sps_count", &self.sps.len())
            .field("pps_count", &self.pps.len())
            .field("profile", &self.profile)
            .field("reduced_rtcp", &self.reduced_rtcp)
            .finish_non_exhaustive()
    }
}

/// Called only after the shared parser's whole-document bounds and structure checks.
pub(super) fn negotiate(
    text: &str,
    selected: usize,
    media: &SdpMedia,
) -> Result<HevcClientMedia, ClientError> {
    let bad = ClientError::Description;
    if media.media_type != "video"
        || !matches!(media.proto.as_str(), "RTP/AVP" | "RTP/AVP/TCP")
        || media.encoding_name.as_deref() != Some("H265")
        || media.clock_rate != Some(90_000)
        || media.packetization_mode.is_some()
        || media.profile_level_id.is_some()
        || !media.sprop_parameter_sets.is_empty()
    {
        return Err(bad);
    }
    let mut output = HevcClientMedia {
        payload_type: media.payload_type,
        vps: Vec::new(),
        sps: Vec::new(),
        pps: Vec::new(),
        profile: HevcProfileSignaling::default(),
        reduced_rtcp: media.rtcp_reduced_size,
    };
    let (mut section, mut controls, mut maps, mut formats) = (None, 0, 0, 0);
    let mut total = 0;
    let mut selected_map = false;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        // Match the observational parser's whitespace normalization exactly: an
        // alternate spelling must not bypass duplicate/payload-binding checks.
        let (kind, value) = line.split_once('=').ok_or(bad)?;
        let value = value.trim();
        if kind == "m" {
            section = Some(section.map_or(0, |n: usize| n + 1));
            controls = 0;
            maps = 0;
            formats = 0;
            if section == Some(selected) && value.split_whitespace().count() != 4 {
                return Err(bad);
            }
        } else if kind == "a" {
            if value.starts_with("control:") {
                controls += 1;
                if controls > 1 {
                    return Err(bad);
                }
            }
            if section.is_none()
                && (value.starts_with("group:")
                    || value.starts_with("fmtp:")
                    || value.starts_with("rtpmap:"))
            {
                return Err(bad);
            }
            if section != Some(selected) {
                continue;
            }
            if let Some(map) = value.strip_prefix("rtpmap:") {
                maps += 1;
                let mut parts = map.split_whitespace();
                if maps != 1
                    || number(parts.next().ok_or(bad)?, 127)? != u64::from(media.payload_type)
                    || parts.next() != Some("H265/90000")
                    || parts.next().is_some()
                {
                    return Err(bad);
                }
                selected_map = true;
            } else if let Some(format) = value.strip_prefix("fmtp:") {
                formats += 1;
                if formats != 1 {
                    return Err(bad);
                }
                let (payload, attributes) = format.split_once(char::is_whitespace).ok_or(bad)?;
                if number(payload, 127)? != u64::from(media.payload_type) {
                    return Err(bad);
                }
                let mut seen = std::collections::BTreeSet::new();
                for attribute in attributes.split(';') {
                    let (key, val) = attribute.trim().split_once('=').ok_or(bad)?;
                    let key = key.trim().to_ascii_lowercase();
                    let val = val.trim();
                    if val.is_empty() || !seen.insert(key.clone()) {
                        return Err(bad);
                    }
                    match key.as_str() {
                        "tx-mode" if val == "SRST" => {}
                        "sprop-max-don-diff" | "sprop-depack-buf-nalus" => {
                            if number(val, 32_767)? != 0 {
                                return Err(bad);
                            }
                        }
                        "sprop-depack-buf-bytes" => {
                            if number(val, u64::from(u32::MAX))? != 0 {
                                return Err(bad);
                            }
                        }
                        "sprop-vps" => output.vps = sets(val, 32, &mut total)?,
                        "sprop-sps" => output.sps = sets(val, 33, &mut total)?,
                        "sprop-pps" => output.pps = sets(val, 34, &mut total)?,
                        "profile-space" => {
                            output.profile.profile_space = Some(number(val, 3)? as u8)
                        }
                        "profile-id" => output.profile.profile_id = Some(number(val, 31)? as u8),
                        "tier-flag" => output.profile.tier_flag = Some(number(val, 1)? as u8),
                        "level-id" => output.profile.level_id = Some(number(val, 255)? as u8),
                        "interop-constraints" => {
                            output.profile.interop_constraints = Some(constraints(val)?)
                        }
                        // No silent fallback for DON, multilayer dependency signaling,
                        // source-specific fmtp, codec aliases, or unknown requirements.
                        _ => return Err(bad),
                    }
                }
            } else if value.starts_with("depend:")
                || value.starts_with("ssrc:")
                || value.starts_with("ssrc-group:")
                || value.starts_with("group:")
                || value == "rtcp-mux"
                || value == "rtcp-mux-only"
            {
                return Err(bad);
            }
        }
    }
    if !selected_map {
        return Err(bad);
    }
    Ok(output)
}

fn number(value: &str, max: u64) -> Result<u64, ClientError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ClientError::Description);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= max)
        .ok_or(ClientError::Description)
}
fn constraints(value: &str) -> Result<[u8; 6], ClientError> {
    if value.len() != 12 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ClientError::Description);
    }
    let mut bytes = [0; 6];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ClientError::Description)?;
    }
    Ok(bytes)
}
fn sets(value: &str, kind: u8, total: &mut usize) -> Result<Vec<Vec<u8>>, ClientError> {
    let mut sets = Vec::new();
    for encoded in value.split(',') {
        if sets.len() == MAX_SETS
            || encoded.is_empty()
            || encoded.len() > MAX_SET_BYTES * 4 / 3 + 4
            || encoded.trim() != encoded
        {
            return Err(ClientError::Description);
        }
        let bytes = decode_base64(encoded).map_err(|_| ClientError::Description)?;
        if bytes.len() < 3
            || bytes.len() > MAX_SET_BYTES
            || bytes[0] & 0x80 != 0
            || (bytes[0] >> 1) & 63 != kind
            || bytes[1] & 7 == 0
        {
            return Err(ClientError::Description);
        }
        *total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_TOTAL_SET_BYTES)
            .ok_or(ClientError::Description)?;
        sets.try_reserve(1).map_err(|_| ClientError::Exhausted)?;
        sets.push(bytes);
    }
    Ok(sets)
}
