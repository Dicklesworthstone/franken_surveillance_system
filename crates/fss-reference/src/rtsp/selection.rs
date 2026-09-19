#![forbid(unsafe_code)]
//! Bounded, payload-exact H.264 selection from an SDP media offer.
//!
//! This is a derived description, not replacement source evidence. The caller retains
//! the original DESCRIBE response. Selection does not authorize a different media
//! section, URI, transport, codec generation, or network effect.

use super::sdp::{MAX_SDP_LINE_BYTES, MAX_SDP_LINES, SdpSession, parse_sdp_bytes};

/// Maximum source description accepted at the RTSP decision boundary.
pub const MAX_SELECTION_BYTES: usize = 65_536;
/// Maximum media sections inspected in one description.
pub const MAX_SELECTION_MEDIA: usize = 64;
/// Maximum payload alternatives in the selected media section.
pub const MAX_SELECTION_PAYLOADS: usize = 32;

/// Payload-free selection refusal; never includes SDP, URIs, or parameter bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionError {
    /// Input, line, media, or offered-payload budget exceeded.
    Limit,
    /// Invalid UTF-8, field structure, control character, or numeric token.
    Malformed,
    /// The exact owner-selected media section does not exist or is unsupported.
    Media,
    /// The exact requested payload was not offered in this media section.
    Payload,
    /// No selected mapping is exactly H.264 with its 90 kHz video clock.
    Unsupported,
    /// More than one H.264 mapping exists and no exact payload was selected.
    Ambiguous,
    /// A payload, mapping, format description, control, or format key is duplicated.
    Duplicate,
    /// The existing SDP parser refused the selected description.
    Description,
    /// Bounded output reservation failed before producing a description.
    Allocation,
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SDP selection refusal: {self:?}")
    }
}
impl std::error::Error for SelectionError {}

/// Select one exact H.264 mapping without conflating its parameters with another offer.
///
/// With `payload_type = None`, exactly one H.264/90000 mapping must be offered.
/// Multiple H.264 alternatives require an explicit payload selection, never a
/// first/last-wins choice. Other media sections keep their ordinal positions, and
/// session/track controls and RTCP signaling still pass through the existing parser.
/// The RTSP client must subsequently enforce its URI scope and codec constraints.
/// Unsupported packetization modes and missing parameter sets are not repaired here.
pub fn select_h264_description(
    body: &[u8],
    media_index: usize,
    payload_type: Option<u8>,
) -> Result<SdpSession, SelectionError> {
    if body.len() > MAX_SELECTION_BYTES || media_index >= MAX_SELECTION_MEDIA {
        return Err(SelectionError::Limit);
    }
    if payload_type.is_some_and(|pt| pt > 127) {
        return Err(SelectionError::Payload);
    }
    let text = std::str::from_utf8(body).map_err(|_| SelectionError::Malformed)?;
    let mut section = None;
    let mut media_count = 0;
    let mut control_seen = false;
    let mut selected_header = None;
    let mut offered = [false; 128];
    let mut maps = [None; 128];
    let mut formats = [None; 128];

    for (line_index, raw) in text.lines().enumerate() {
        if line_index >= MAX_SDP_LINES || raw.len() > MAX_SDP_LINE_BYTES {
            return Err(SelectionError::Limit);
        }
        // str::lines removes CR only when it belongs to CRLF. An embedded CR,
        // NUL, or other control must not be hidden by whitespace normalization.
        if raw.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return Err(SelectionError::Malformed);
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.as_bytes().get(1) != Some(&b'=') {
            return Err(SelectionError::Malformed);
        }
        let value = line[2..].trim();
        if line.starts_with("m=") {
            if media_count == MAX_SELECTION_MEDIA {
                return Err(SelectionError::Limit);
            }
            section = Some(media_count);
            media_count += 1;
            control_seen = false;
            if section == Some(media_index) {
                let mut fields = value.split_ascii_whitespace();
                let media = fields.next().ok_or(SelectionError::Malformed)?;
                let port = fields.next().ok_or(SelectionError::Malformed)?;
                let protocol = fields.next().ok_or(SelectionError::Malformed)?;
                if media != "video" || !matches!(protocol, "RTP/AVP" | "RTP/AVP/TCP") {
                    return Err(SelectionError::Media);
                }
                decimal(port)?;
                port.parse::<u16>().map_err(|_| SelectionError::Malformed)?;
                let mut count = 0;
                for token in fields {
                    count += 1;
                    if count > MAX_SELECTION_PAYLOADS {
                        return Err(SelectionError::Limit);
                    }
                    let pt = parse_payload(token)?;
                    if std::mem::replace(&mut offered[usize::from(pt)], true) {
                        return Err(SelectionError::Duplicate);
                    }
                }
                if count == 0 {
                    return Err(SelectionError::Malformed);
                }
                selected_header = Some((port, protocol));
            }
        } else if line.starts_with("a=") {
            if value.starts_with("control:") {
                if control_seen {
                    return Err(SelectionError::Duplicate);
                }
                control_seen = true;
            }
            if section != Some(media_index) {
                continue;
            }
            let (attribute, slots) = if let Some(value) = value.strip_prefix("rtpmap:") {
                (value, &mut maps)
            } else if let Some(value) = value.strip_prefix("fmtp:") {
                (value, &mut formats)
            } else {
                continue;
            };
            let (pt, value) = payload_attribute(attribute)?;
            if !offered[usize::from(pt)] {
                return Err(SelectionError::Payload);
            }
            if slots[usize::from(pt)].replace(value).is_some() {
                return Err(SelectionError::Duplicate);
            }
        }
    }

    let (port, protocol) = selected_header.ok_or(SelectionError::Media)?;
    let selected = if let Some(pt) = payload_type {
        if !offered[usize::from(pt)] {
            return Err(SelectionError::Payload);
        }
        if !maps[usize::from(pt)].is_some_and(h264_mapping) {
            return Err(SelectionError::Unsupported);
        }
        pt
    } else {
        let mut selected = None;
        for pt in 0_u8..=127 {
            if maps[usize::from(pt)].is_some_and(h264_mapping) {
                if selected.is_some() {
                    return Err(SelectionError::Ambiguous);
                }
                selected = Some(pt);
            }
        }
        selected.ok_or(SelectionError::Unsupported)?
    };
    if let Some(format) = formats[usize::from(selected)] {
        validate_format(format)?;
    }

    // Only the selected m-line and its payload-specific mapping/format lines
    // change. No codec parameters are borrowed from an unselected payload.
    let mut derived = String::new();
    derived
        .try_reserve(body.len() + 64)
        .map_err(|_| SelectionError::Allocation)?;
    section = None;
    media_count = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("m=") {
            section = Some(media_count);
            media_count += 1;
            if section == Some(media_index) {
                use std::fmt::Write as _;
                writeln!(&mut derived, "m=video {port} {protocol} {selected}")
                    .map_err(|_| SelectionError::Allocation)?;
                continue;
            }
        }
        if section == Some(media_index) && line.starts_with("a=") {
            let value = line[2..].trim();
            if let Some(value) = value.strip_prefix("rtpmap:") {
                let (pt, _) = payload_attribute(value)?;
                if pt == selected {
                    use std::fmt::Write as _;
                    // Encoding names are case-insensitive. Normalize only this
                    // verified exact mapping for the existing codec consumer.
                    writeln!(&mut derived, "a=rtpmap:{selected} H264/90000")
                        .map_err(|_| SelectionError::Allocation)?;
                }
                continue;
            }
            if let Some(value) = value.strip_prefix("fmtp:")
                && payload_attribute(value)?.0 != selected
            {
                continue;
            }
        }
        derived.push_str(line);
        derived.push('\n');
    }
    parse_sdp_bytes(derived.as_bytes()).map_err(|_| SelectionError::Description)
}

fn decimal(value: &str) -> Result<(), SelectionError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SelectionError::Malformed);
    }
    Ok(())
}

fn parse_payload(value: &str) -> Result<u8, SelectionError> {
    decimal(value)?;
    value
        .parse::<u8>()
        .ok()
        .filter(|pt| *pt <= 127)
        .ok_or(SelectionError::Payload)
}

fn payload_attribute(value: &str) -> Result<(u8, &str), SelectionError> {
    let (token, value) = value
        .split_once(|c: char| c.is_ascii_whitespace())
        .ok_or(SelectionError::Malformed)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(SelectionError::Malformed);
    }
    Ok((parse_payload(token)?, value))
}

fn h264_mapping(value: &str) -> bool {
    value.eq_ignore_ascii_case("H264/90000")
}

fn validate_format(value: &str) -> Result<(), SelectionError> {
    // At most one line of input, so an O(n^2) duplicate check stays bounded
    // without building an unbounded map or cloning server-controlled strings.
    let mut keys = [""; 128];
    for (index, parameter) in value.split(';').enumerate() {
        if index == keys.len() {
            return Err(SelectionError::Limit);
        }
        let (key, value) = parameter
            .trim()
            .split_once('=')
            .ok_or(SelectionError::Malformed)?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(SelectionError::Malformed);
        }
        if keys[..index].iter().any(|other| other.eq_ignore_ascii_case(key)) {
            return Err(SelectionError::Duplicate);
        }
        keys[index] = key;
        if key.eq_ignore_ascii_case("packetization-mode") {
            decimal(value)?;
        }
        if key.eq_ignore_ascii_case("sprop-parameter-sets")
            && value.split(',').any(|part| part.trim().is_empty())
        {
            return Err(SelectionError::Malformed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n";
    const OFFER: &str = "m=video 0 RTP/AVP 98 96\r\na=control:trackID=1\r\na=rtpmap:98 H265/90000\r\na=fmtp:98 arbitrary=other-codec\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\na=rtcp-rsize\r\n";

    fn select(offer: &str, pt: Option<u8>) -> Result<SdpSession, SelectionError> {
        select_h264_description(format!("{PREFIX}{offer}").as_bytes(), 0, pt)
    }

    #[test]
    fn selects_h264_even_when_another_codec_is_first() -> Result<(), SelectionError> {
        let sdp = select(OFFER, None)?;
        assert_eq!(sdp.media.len(), 1);
        let media = &sdp.media[0];
        assert_eq!(media.payload_type, 96);
        assert_eq!(media.packetization_mode, Some(1));
        assert_eq!(media.sps.as_deref(), Some(&[0x67, 0x42, 0, 0x1f][..]));
        assert_eq!(media.pps.as_deref(), Some(&[0x68, 0][..]));
        assert_eq!(media.control.as_deref(), Some("trackID=1"));
        assert_eq!(sdp.session_control.as_deref(), Some("*"));
        assert!(media.rtcp_reduced_size);
        Ok(())
    }

    #[test]
    fn selection_is_not_attribute_order_dependent() -> Result<(), SelectionError> {
        let mut lines: Vec<_> = OFFER.lines().collect();
        lines[1..].reverse();
        assert_eq!(select(OFFER, None)?, select(&lines.join("\n"), None)?);
        Ok(())
    }

    #[test]
    fn exact_selection_is_required_for_multiple_h264_offers() -> Result<(), SelectionError> {
        let offer = OFFER.replace("H265/90000", "H264/90000");
        assert_eq!(select(&offer, None), Err(SelectionError::Ambiguous));
        assert_eq!(select(&offer, Some(96))?.media[0].payload_type, 96);
        assert_eq!(select(&offer, Some(98))?.media[0].payload_type, 98);
        // The second offer has no SPS/PPS. It cannot inherit them from PT 96.
        assert!(select(&offer, Some(98))?.media[0].sprop_parameter_sets.is_empty());
        Ok(())
    }

    #[test]
    fn explicit_selection_does_not_fallback() {
        assert_eq!(select(OFFER, Some(97)), Err(SelectionError::Payload));
        assert_eq!(select(OFFER, Some(98)), Err(SelectionError::Unsupported));
        assert_eq!(select(OFFER, Some(255)), Err(SelectionError::Payload));
    }

    #[test]
    fn preserves_media_ordinals_and_does_not_select_audio() -> Result<(), SelectionError> {
        let body = format!("{PREFIX}m=audio 0 RTP/AVP 0\r\na=control:audio\r\n{OFFER}");
        let sdp = select_h264_description(body.as_bytes(), 1, None)?;
        assert_eq!(sdp.media.len(), 2);
        assert_eq!(sdp.media[0].media_type, "audio");
        assert_eq!(sdp.media[1].payload_type, 96);
        assert_eq!(select_h264_description(body.as_bytes(), 0, None), Err(SelectionError::Media));
        assert_eq!(select_h264_description(body.as_bytes(), 2, None), Err(SelectionError::Media));
        Ok(())
    }

    #[test]
    fn rejects_duplicate_and_unoffered_bindings() {
        for extra in ["a=rtpmap:96 H264/90000\r\n", "a=fmtp:96 packetization-mode=1\r\n", "a=control:trackID=1\r\n"] {
            assert_eq!(select(&format!("{OFFER}{extra}"), None), Err(SelectionError::Duplicate));
        }
        assert_eq!(select(&OFFER.replace("98 96", "98 96 096"), None), Err(SelectionError::Duplicate));
        assert_eq!(select(&format!("{OFFER}a=rtpmap:97 H264/90000\r\n"), None), Err(SelectionError::Payload));
        assert_eq!(select(&format!("{OFFER}a=fmtp:97 packetization-mode=1\r\n"), None), Err(SelectionError::Payload));
    }

    #[test]
    fn rejects_duplicate_format_keys_even_with_different_case() {
        let offer = OFFER.replace("packetization-mode=1;", "packetization-mode=1;Packetization-Mode=0;");
        assert_eq!(select(&offer, None), Err(SelectionError::Duplicate));
    }

    #[test]
    fn rejects_wrong_clock_parameters_and_trailing_mapping_tokens() {
        for mapping in ["H264/8000", "H264/90000/2", "H264/90000 junk", "H264"] {
            assert_eq!(select(&OFFER.replace("H264/90000", mapping), None), Err(SelectionError::Unsupported));
        }
    }

    #[test]
    fn accepts_case_insensitive_codec_name() -> Result<(), SelectionError> {
        let sdp = select(&OFFER.replace("H264/90000", "h264/90000"), None)?;
        assert_eq!(sdp.media[0].encoding_name.as_deref(), Some("H264"));
        Ok(())
    }

    #[test]
    fn rejects_malformed_numbers_controls_and_missing_parameters() {
        for replacement in ["+96", "128", "-1", "nine"] {
            assert!(select(&OFFER.replacen("98 96", &format!("98 {replacement}"), 1), None).is_err());
        }
        for suffix in ["a=x:hidden\0value\n", "a=x:hidden\rvalue\n", "a=x:hidden\u{7f}value\n"] {
            assert_eq!(select(&format!("{OFFER}{suffix}"), None), Err(SelectionError::Malformed));
        }
        assert_eq!(select(&OFFER.replace("Z0IAHw==,aAA=", "Z0IAHw==,,aAA="), None), Err(SelectionError::Malformed));
        assert_eq!(select(&OFFER.replace("packetization-mode=1", "packetization-mode=+1"), None), Err(SelectionError::Malformed));
    }

    #[test]
    fn retains_existing_credential_and_sdp_validation() {
        assert_eq!(select(&OFFER.replace("trackID=1", "rtsp://user:secret@camera/track"), None), Err(SelectionError::Description));
        assert_eq!(select_h264_description(OFFER.as_bytes(), 0, None), Err(SelectionError::Description));
    }

    #[test]
    fn limits_apply_before_filtering_unselected_lines() {
        let overlong = format!("{OFFER}a=x:{}\n", "x".repeat(MAX_SDP_LINE_BYTES));
        assert_eq!(select(&overlong, None), Err(SelectionError::Limit));
        assert_eq!(select_h264_description(&vec![b'x'; MAX_SELECTION_BYTES + 1], 0, None), Err(SelectionError::Limit));
        assert_eq!(select_h264_description(b"", MAX_SELECTION_MEDIA, None), Err(SelectionError::Limit));
        let many_lines = format!("{OFFER}{}", "\n".repeat(MAX_SDP_LINES));
        assert_eq!(select(&many_lines, None), Err(SelectionError::Limit));
    }
}
