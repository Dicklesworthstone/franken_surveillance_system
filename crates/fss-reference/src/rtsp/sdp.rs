#![forbid(unsafe_code)]
//! Minimal SDP (Session Description Protocol) parser.
//!
//! Parses RFC 4566, RFC 6184, and RFC 5506 SDP descriptions for RTSP/RTP media
//! sessions. Handles H.264 video parameters (packetization-mode, sprop-parameter-sets)
//! with a first-party bounded Base64 decoder. Audio m-lines are recorded and
//! ignored per GOAL-009 privacy rules. Origin and connection fields are opaque
//! and never logged.

use std::fmt;

/// Maximum base64 input string length in bytes for sprop parameter sets (64 KiB).
pub const MAX_BASE64_INPUT_BYTES: usize = 65536;

/// Maximum total number of lines in an SDP document (1,024).
pub const MAX_SDP_LINES: usize = 1024;

/// Typed error returned when SDP parsing or Base64 decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdpError {
    /// SDP line or format is syntactically malformed.
    Malformed(String),
    /// First-party Base64 decoding failed.
    BadBase64(String),
    /// The mandatory `v=0` protocol version line is missing or invalid.
    MissingVersion,
    /// The mandatory `o=` origin line is missing.
    MissingOrigin,
    /// The mandatory `s=` session name line is missing.
    MissingSessionName,
    /// No media descriptions (`m=`) were found.
    MissingMedia,
    /// A configured parsing or allocation limit was exceeded.
    Limit(String),
    /// Input is not valid UTF-8.
    Utf8(String),
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "malformed SDP: {msg}"),
            Self::BadBase64(msg) => write!(f, "bad base64: {msg}"),
            Self::MissingVersion => write!(f, "missing or invalid SDP version (v=0 required)"),
            Self::MissingOrigin => write!(f, "missing SDP origin line (o=)"),
            Self::MissingSessionName => write!(f, "missing SDP session name (s=)"),
            Self::MissingMedia => write!(f, "SDP contains no media sections (m=)"),
            Self::Limit(msg) => write!(f, "SDP limit exceeded: {msg}"),
            Self::Utf8(msg) => write!(f, "invalid UTF-8 in SDP text: {msg}"),
        }
    }
}

impl std::error::Error for SdpError {}

/// First-party bounded Base64 decoder with zero third-party dependencies.
///
/// Strictly validates characters against the standard Base64 alphabet (`A-Z`, `a-z`,
/// `0-9`, `+`, `/`), validates `=` padding, and verifies that unused padding bits
/// are zero. Rejects malformed input with `SdpError::BadBase64`.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, SdpError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.len() > MAX_BASE64_INPUT_BYTES {
        return Err(SdpError::Limit(format!(
            "Base64 input length {} exceeds maximum limit {MAX_BASE64_INPUT_BYTES}",
            trimmed.len()
        )));
    }

    let bytes = trimmed.as_bytes();
    let len = bytes.len();

    // Check padding structure and unpadded lengths
    if !len.is_multiple_of(4) {
        return Err(SdpError::BadBase64(format!(
            "Base64 input length {len} is not a multiple of 4"
        )));
    }

    let mut output = Vec::with_capacity((len / 4) * 3);
    let (chunks, _) = bytes.as_chunks::<4>();

    let mut seen_padding = false;

    for chunk in chunks {
        if seen_padding {
            return Err(SdpError::BadBase64(
                "unexpected characters following Base64 padding".to_string(),
            ));
        }

        let c0 = chunk[0];
        let c1 = chunk[1];
        let c2 = chunk[2];
        let c3 = chunk[3];

        if c0 == b'=' || c1 == b'=' {
            return Err(SdpError::BadBase64(
                "invalid Base64 padding in first two characters".to_string(),
            ));
        }

        let v0 = decode_b64_byte(c0)?;
        let v1 = decode_b64_byte(c1)?;

        let b0 = (v0 << 2) | (v1 >> 4);
        output.push(b0);

        if c2 == b'=' {
            seen_padding = true;
            if c3 != b'=' {
                return Err(SdpError::BadBase64(
                    "malformed Base64 padding: '=' followed by non-'='".to_string(),
                ));
            }
            if (v1 & 0x0F) != 0 {
                return Err(SdpError::BadBase64(
                    "non-zero unused bits in Base64 padding".to_string(),
                ));
            }
            continue;
        }

        let v2 = decode_b64_byte(c2)?;
        let b1 = ((v1 & 0x0F) << 4) | (v2 >> 2);
        output.push(b1);

        if c3 == b'=' {
            seen_padding = true;
            if (v2 & 0x03) != 0 {
                return Err(SdpError::BadBase64(
                    "non-zero unused bits in Base64 padding".to_string(),
                ));
            }
            continue;
        }

        let v3 = decode_b64_byte(c3)?;
        let b2 = ((v2 & 0x03) << 6) | v3;
        output.push(b2);
    }

    Ok(output)
}

fn decode_b64_byte(b: u8) -> Result<u8, SdpError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Err(SdpError::BadBase64(
            "unexpected '=' in character decode".to_string(),
        )),
        _ => Err(SdpError::BadBase64(format!(
            "invalid Base64 character code: {b}"
        ))),
    }
}

/// Parsed media section within an SDP session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdpMedia {
    /// Media type string, e.g. `"video"` or `"audio"`.
    pub media_type: String,
    /// Transport port number (typically 0 for RTSP/TCP-interleaved).
    pub port: u16,
    /// Transport protocol string, e.g. `"RTP/AVP"` or `"RTP/AVP/TCP"`.
    pub proto: String,
    /// RTP payload type number (e.g. 96).
    pub payload_type: u8,
    /// Media encoding name (e.g. `"H264"`).
    pub encoding_name: String,
    /// Clock rate in Hz (e.g. 90000).
    pub clock_rate: u32,
    /// RFC 6184 packetization-mode (e.g. 1 for NonInterleaved, 0 for SingleNal).
    pub packetization_mode: Option<u8>,
    /// Optional profile-level-id hex string (e.g. `"42e01f"`).
    pub profile_level_id: Option<String>,
    /// Base64-decoded SPS and PPS parameter sets from `sprop-parameter-sets`.
    pub sprop_parameter_sets: Vec<Vec<u8>>,
    /// Sequence Parameter Set (SPS) bytes if present.
    pub sps: Option<Vec<u8>>,
    /// Picture Parameter Set (PPS) bytes if present.
    pub pps: Option<Vec<u8>>,
    /// Media-level control track URI (e.g. `"trackID=0"`).
    pub control: Option<String>,
    /// Whether RFC 5506 reduced-size RTCP is signaled via `a=rtcp-rsize`.
    pub rtcp_reduced_size: bool,
}

/// Parsed SDP session description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdpSession {
    /// SDP protocol version (must be 0 per RFC 4566).
    pub version: u32,
    /// Session name (`s=` line).
    pub session_name: String,
    /// Opaque origin string (`o=` line). Never logged for privacy.
    pub origin_opaque: String,
    /// Opaque connection string (`c=` line). Never logged for privacy.
    pub connection_opaque: Option<String>,
    /// Primary video media section if present.
    pub video_media: Option<SdpMedia>,
    /// Audio media sections (recorded and ignored per privacy rules).
    pub audio_media: Vec<SdpMedia>,
    /// All parsed media sections in order of appearance.
    pub media: Vec<SdpMedia>,
    /// Session-level control URI if present (`a=control:`).
    pub session_control: Option<String>,
}

impl SdpSession {
    /// Retrieve the primary video media section reference.
    pub fn video(&self) -> Option<&SdpMedia> {
        self.video_media.as_ref()
    }

    /// Retrieve the recorded audio media sections.
    pub fn audio(&self) -> &[SdpMedia] {
        &self.audio_media
    }
}

/// Parse an SDP description from a UTF-8 string slice.
pub fn parse_sdp(input: &str) -> Result<SdpSession, SdpError> {
    let mut version = None;
    let mut session_name = None;
    let mut origin_opaque = None;
    let mut connection_opaque = None;
    let mut session_control = None;

    let mut media_list = Vec::new();
    let mut current_builder: Option<MediaSectionBuilder> = None;

    let mut line_count = 0;

    for raw_line in input.lines() {
        line_count += 1;
        if line_count > MAX_SDP_LINES {
            return Err(SdpError::Limit(format!(
                "SDP lines exceeded limit {MAX_SDP_LINES}"
            )));
        }

        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }

        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            return Err(SdpError::Malformed(format!(
                "invalid line format missing '=': '{line}'"
            )));
        }

        let prefix = line.as_bytes()[0];
        let val = &line[2..].trim();

        if prefix == b'm' {
            // Flush preceding media section
            if let Some(builder) = current_builder.take() {
                media_list.push(builder.finish()?);
            }
            current_builder = Some(MediaSectionBuilder::new(val)?);
            continue;
        }

        if let Some(ref mut builder) = current_builder {
            // Media-level attribute or parameter
            builder.process_line(prefix, val)?;
        } else {
            // Session-level line
            match prefix {
                b'v' => {
                    let v = val.parse::<u32>().map_err(|_| {
                        SdpError::Malformed(format!("invalid version integer '{val}'"))
                    })?;
                    if v != 0 {
                        return Err(SdpError::MissingVersion);
                    }
                    version = Some(v);
                }
                b'o' => {
                    origin_opaque = Some(val.to_string());
                }
                b's' => {
                    session_name = Some(val.to_string());
                }
                b'c' => {
                    connection_opaque = Some(val.to_string());
                }
                b'a' => {
                    if let Some(ctrl) = val.strip_prefix("control:") {
                        session_control = Some(ctrl.trim().to_string());
                    }
                }
                _ => {
                    // Ignore other session-level lines (t=, etc.)
                }
            }
        }
    }

    if let Some(builder) = current_builder.take() {
        media_list.push(builder.finish()?);
    }

    let version = version.ok_or(SdpError::MissingVersion)?;
    let origin_opaque = origin_opaque.ok_or(SdpError::MissingOrigin)?;
    let session_name = session_name.ok_or(SdpError::MissingSessionName)?;

    if media_list.is_empty() {
        return Err(SdpError::MissingMedia);
    }

    let mut video_media = None;
    let mut audio_media = Vec::new();

    for m in &media_list {
        if m.media_type.eq_ignore_ascii_case("video") && video_media.is_none() {
            video_media = Some(m.clone());
        } else if m.media_type.eq_ignore_ascii_case("audio") {
            audio_media.push(m.clone());
        }
    }

    Ok(SdpSession {
        version,
        session_name,
        origin_opaque,
        connection_opaque,
        video_media,
        audio_media,
        media: media_list,
        session_control,
    })
}

/// Parse an SDP description from raw bytes.
pub fn parse_sdp_bytes(bytes: &[u8]) -> Result<SdpSession, SdpError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|err| SdpError::Utf8(format!("invalid UTF-8 in SDP bytes: {err}")))?;
    parse_sdp(text)
}

struct MediaSectionBuilder {
    media_type: String,
    port: u16,
    proto: String,
    payload_type: u8,
    encoding_name: Option<String>,
    clock_rate: Option<u32>,
    packetization_mode: Option<u8>,
    profile_level_id: Option<String>,
    sprop_parameter_sets: Vec<Vec<u8>>,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    control: Option<String>,
    rtcp_reduced_size: bool,
}

impl MediaSectionBuilder {
    fn new(m_line_val: &str) -> Result<Self, SdpError> {
        let mut parts = m_line_val.split_whitespace();
        let media_type = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing media type in m= line".to_string()))?
            .to_string();

        let port_str = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing port in m= line".to_string()))?;
        let port = port_str.parse::<u16>().map_err(|_| {
            SdpError::Malformed(format!("invalid port integer '{port_str}' in m= line"))
        })?;

        let proto = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing protocol in m= line".to_string()))?
            .to_string();

        let fmt_str = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing payload format in m= line".to_string()))?;
        let payload_type = fmt_str.parse::<u8>().map_err(|_| {
            SdpError::Malformed(format!("invalid payload format '{fmt_str}' in m= line"))
        })?;

        Ok(Self {
            media_type,
            port,
            proto,
            payload_type,
            encoding_name: None,
            clock_rate: None,
            packetization_mode: None,
            profile_level_id: None,
            sprop_parameter_sets: Vec::new(),
            sps: None,
            pps: None,
            control: None,
            rtcp_reduced_size: false,
        })
    }

    fn process_line(&mut self, prefix: u8, val: &str) -> Result<(), SdpError> {
        if prefix != b'a' {
            return Ok(());
        }

        if val.eq_ignore_ascii_case("rtcp-rsize") {
            self.rtcp_reduced_size = true;
            return Ok(());
        }

        if let Some(ctrl) = val.strip_prefix("control:") {
            self.control = Some(ctrl.trim().to_string());
            return Ok(());
        }

        if let Some(rtpmap) = val.strip_prefix("rtpmap:") {
            self.parse_rtpmap(rtpmap)?;
            return Ok(());
        }

        if let Some(fmtp) = val.strip_prefix("fmtp:") {
            self.parse_fmtp(fmtp)?;
            return Ok(());
        }

        Ok(())
    }

    fn parse_rtpmap(&mut self, val: &str) -> Result<(), SdpError> {
        // format: <pt> <encoding>/<clock_rate>[/<channels>]
        let mut parts = val.split_whitespace();
        let pt_str = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing payload type in rtpmap".to_string()))?;
        let pt = pt_str.parse::<u8>().map_err(|_| {
            SdpError::Malformed(format!("invalid payload type in rtpmap '{pt_str}'"))
        })?;

        if pt != self.payload_type {
            return Ok(());
        }

        let enc_part = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing encoding in rtpmap".to_string()))?;

        if let Some((enc, rate_str)) = enc_part.split_once('/') {
            self.encoding_name = Some(enc.to_string());
            let rate_tok = rate_str.split('/').next().unwrap_or(rate_str);
            let clock_rate = rate_tok.parse::<u32>().map_err(|_| {
                SdpError::Malformed(format!("invalid clock rate in rtpmap '{rate_tok}'"))
            })?;
            self.clock_rate = Some(clock_rate);
        } else {
            self.encoding_name = Some(enc_part.to_string());
        }

        Ok(())
    }

    fn parse_fmtp(&mut self, val: &str) -> Result<(), SdpError> {
        // format: <pt> <param1>=<val1>;<param2>=<val2>
        let mut parts = val.split_whitespace();
        let pt_str = parts
            .next()
            .ok_or_else(|| SdpError::Malformed("missing payload type in fmtp".to_string()))?;
        let pt = pt_str
            .parse::<u8>()
            .map_err(|_| SdpError::Malformed(format!("invalid payload type in fmtp '{pt_str}'")))?;

        if pt != self.payload_type {
            return Ok(());
        }

        let params_str = parts.collect::<Vec<_>>().join(" ");
        for param in params_str.split(';') {
            let param = param.trim();
            if let Some((k, v)) = param.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if k.eq_ignore_ascii_case("packetization-mode") {
                    if let Ok(pm) = v.parse::<u8>() {
                        self.packetization_mode = Some(pm);
                    }
                } else if k.eq_ignore_ascii_case("profile-level-id") {
                    self.profile_level_id = Some(v.to_string());
                } else if k.eq_ignore_ascii_case("sprop-parameter-sets") {
                    for b64 in v.split(',') {
                        let b64 = b64.trim();
                        if !b64.is_empty() {
                            let decoded = decode_base64(b64)?;
                            if self.sps.is_none() {
                                self.sps = Some(decoded.clone());
                            } else if self.pps.is_none() {
                                self.pps = Some(decoded.clone());
                            }
                            self.sprop_parameter_sets.push(decoded);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn finish(self) -> Result<SdpMedia, SdpError> {
        Ok(SdpMedia {
            media_type: self.media_type,
            port: self.port,
            proto: self.proto,
            payload_type: self.payload_type,
            encoding_name: self.encoding_name.unwrap_or_else(|| "unknown".to_string()),
            clock_rate: self.clock_rate.unwrap_or(90000),
            packetization_mode: self.packetization_mode,
            profile_level_id: self.profile_level_id,
            sprop_parameter_sets: self.sprop_parameter_sets,
            sps: self.sps,
            pps: self.pps,
            control: self.control,
            rtcp_reduced_size: self.rtcp_reduced_size,
        })
    }
}
