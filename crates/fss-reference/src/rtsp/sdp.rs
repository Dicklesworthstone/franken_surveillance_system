#![forbid(unsafe_code)]
//! Minimal SDP (Session Description Protocol) parser.
//!
//! Parses RFC 4566, RFC 6184, and RFC 5506 SDP descriptions for RTSP/RTP media
//! sessions. Handles H.264 video parameters (packetization-mode, sprop-parameter-sets)
//! with a first-party bounded Base64 decoder. Audio m-lines are recorded and
//! ignored per GOAL-009 privacy rules. Origin and connection fields are opaque
//! and never logged.
//!
//! Every [`SdpError`] carries only a typed reason plus byte offsets or lengths;
//! no error value ever carries input text. `a=control` URIs carrying userinfo
//! are refused.

use std::fmt;

use super::message::{Utf8Fault, has_userinfo};

/// Maximum base64 input string length in bytes for sprop parameter sets (64 KiB).
pub const MAX_BASE64_INPUT_BYTES: usize = 65536;

/// Maximum total number of lines in an SDP document (1,024).
pub const MAX_SDP_LINES: usize = 1024;

/// Maximum line length in bytes for any single SDP line (4 KiB).
pub const MAX_SDP_LINE_BYTES: usize = 4096;

/// Why an SDP line was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SdpFault {
    /// The line is not of the form `<type>=<value>`.
    MissingEquals,
    /// The `v=` value is not a decimal integer.
    InvalidVersion,
    /// The `m=` line has no media type.
    MissingMediaType,
    /// The `m=` line has no port.
    MissingPort,
    /// The `m=` port is not a decimal `u16`.
    InvalidPort {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// The `m=` line has no protocol.
    MissingProtocol,
    /// The `m=` line has no payload format.
    MissingPayloadFormat,
    /// The `m=` payload format is not a decimal `u8`.
    InvalidPayloadFormat {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// An RTP payload type is above 127.
    PayloadTypeAbove127,
    /// An `a=rtpmap:` attribute has no payload type.
    MissingRtpmapPayloadType,
    /// An `a=rtpmap:` payload type is not a decimal `u8`.
    InvalidRtpmapPayloadType {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// An `a=rtpmap:` attribute has no encoding.
    MissingRtpmapEncoding,
    /// An `a=rtpmap:` clock rate is not a decimal `u32`.
    InvalidClockRate {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// An `a=fmtp:` attribute has no payload type.
    MissingFmtpPayloadType,
    /// An `a=fmtp:` payload type is not a decimal `u8`.
    InvalidFmtpPayloadType {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// The `packetization-mode` value is not a decimal `u8`.
    InvalidPacketizationMode {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// The `packetization-mode` value is outside `0..=2`.
    PacketizationModeOutOfRange,
}

/// A refused SDP line: its byte offset in the document and a typed reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SdpMalformed {
    /// Byte offset of the refused line within the SDP document.
    pub offset: usize,
    /// Why the line was refused.
    pub reason: SdpFault,
}

/// Why first-party Base64 decoding failed; offsets are relative to the trimmed input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Base64Fault {
    /// The input length is not a multiple of 4.
    LengthNotMultipleOf4 {
        /// Input length in bytes.
        len: usize,
    },
    /// Data follows a padded quantum.
    DataAfterPadding {
        /// Byte offset of the first byte after the padding.
        offset: usize,
    },
    /// `=` appears in the first two positions of a quantum.
    PaddingInFirstTwo {
        /// Byte offset of the quantum.
        offset: usize,
    },
    /// `=` is followed by a byte other than `=`, or appears where padding is impossible.
    MalformedPadding {
        /// Byte offset of the offending byte.
        offset: usize,
    },
    /// The unused bits before the padding are not zero.
    NonZeroPaddingBits {
        /// Byte offset of the quantum.
        offset: usize,
    },
    /// A byte outside the standard Base64 alphabet.
    InvalidCharacter {
        /// Byte offset of the offending byte.
        offset: usize,
    },
}

/// Which SDP bound was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SdpLimitFault {
    /// A line is longer than [`MAX_SDP_LINE_BYTES`].
    LineTooLong {
        /// Byte offset of the line within the SDP document.
        offset: usize,
        /// Line length in bytes.
        len: usize,
        /// Configured maximum, in bytes.
        limit: usize,
    },
    /// The document has more than [`MAX_SDP_LINES`] lines.
    TooManyLines {
        /// Configured maximum line count.
        limit: usize,
    },
    /// A Base64 input is longer than [`MAX_BASE64_INPUT_BYTES`].
    Base64InputTooLong {
        /// Input length in bytes.
        len: usize,
        /// Configured maximum, in bytes.
        limit: usize,
    },
}

/// Which `a=control` attribute carried forbidden userinfo.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SdpControlLevel {
    /// The session-level `a=control`.
    Session {
        /// Byte offset of the line within the SDP document.
        offset: usize,
    },
    /// A media-level `a=control`.
    Media {
        /// Zero-based index of the media section.
        index: usize,
        /// Byte offset of the line within the SDP document.
        offset: usize,
    },
}

/// Typed error returned when SDP parsing or Base64 decoding fails.
///
/// Every variant carries only a typed reason plus byte offsets or lengths; never input text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdpError {
    /// SDP line or format is syntactically malformed.
    Malformed(SdpMalformed),
    /// First-party Base64 decoding failed.
    BadBase64(Base64Fault),
    /// The mandatory `v=0` protocol version line is missing or invalid.
    MissingVersion,
    /// The mandatory `o=` origin line is missing.
    MissingOrigin,
    /// The mandatory `s=` session name line is missing.
    MissingSessionName,
    /// No media descriptions (`m=`) were found.
    MissingMedia,
    /// A configured parsing or allocation limit was exceeded.
    Limit(SdpLimitFault),
    /// Input is not valid UTF-8.
    Utf8(Utf8Fault),
    /// An `a=control` URI carries forbidden userinfo credentials.
    UserinfoNotPermitted(SdpControlLevel),
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(malformed) => write!(f, "malformed SDP: {malformed:?}"),
            Self::BadBase64(fault) => write!(f, "bad base64: {fault:?}"),
            Self::MissingVersion => write!(f, "missing or invalid SDP version (v=0 required)"),
            Self::MissingOrigin => write!(f, "missing SDP origin line (o=)"),
            Self::MissingSessionName => write!(f, "missing SDP session name (s=)"),
            Self::MissingMedia => write!(f, "SDP contains no media sections (m=)"),
            Self::Limit(fault) => write!(f, "SDP limit exceeded: {fault:?}"),
            Self::Utf8(fault) => write!(f, "invalid UTF-8 in SDP text: {fault:?}"),
            Self::UserinfoNotPermitted(level) => {
                write!(f, "userinfo in SDP control URI not permitted: {level:?}")
            }
        }
    }
}

impl std::error::Error for SdpError {}

fn malformed(offset: usize, reason: SdpFault) -> SdpError {
    SdpError::Malformed(SdpMalformed { offset, reason })
}

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
        return Err(SdpError::Limit(SdpLimitFault::Base64InputTooLong {
            len: trimmed.len(),
            limit: MAX_BASE64_INPUT_BYTES,
        }));
    }

    let bytes = trimmed.as_bytes();
    let len = bytes.len();

    // Check padding structure and unpadded lengths
    if !len.is_multiple_of(4) {
        return Err(SdpError::BadBase64(Base64Fault::LengthNotMultipleOf4 {
            len,
        }));
    }

    let mut output = Vec::with_capacity((len / 4) * 3);
    let (chunks, _) = bytes.as_chunks::<4>();

    let mut seen_padding = false;

    for (index, chunk) in chunks.iter().enumerate() {
        let base = index * 4;
        if seen_padding {
            return Err(SdpError::BadBase64(Base64Fault::DataAfterPadding {
                offset: base,
            }));
        }

        let c0 = chunk[0];
        let c1 = chunk[1];
        let c2 = chunk[2];
        let c3 = chunk[3];

        if c0 == b'=' || c1 == b'=' {
            return Err(SdpError::BadBase64(Base64Fault::PaddingInFirstTwo {
                offset: base,
            }));
        }

        let v0 = decode_b64_byte(c0, base)?;
        let v1 = decode_b64_byte(c1, base + 1)?;

        let b0 = (v0 << 2) | (v1 >> 4);
        output.push(b0);

        if c2 == b'=' {
            seen_padding = true;
            if c3 != b'=' {
                return Err(SdpError::BadBase64(Base64Fault::MalformedPadding {
                    offset: base + 3,
                }));
            }
            if (v1 & 0x0F) != 0 {
                return Err(SdpError::BadBase64(Base64Fault::NonZeroPaddingBits {
                    offset: base,
                }));
            }
            continue;
        }

        let v2 = decode_b64_byte(c2, base + 2)?;
        let b1 = ((v1 & 0x0F) << 4) | (v2 >> 2);
        output.push(b1);

        if c3 == b'=' {
            seen_padding = true;
            if (v2 & 0x03) != 0 {
                return Err(SdpError::BadBase64(Base64Fault::NonZeroPaddingBits {
                    offset: base,
                }));
            }
            continue;
        }

        let v3 = decode_b64_byte(c3, base + 3)?;
        let b2 = ((v2 & 0x03) << 6) | v3;
        output.push(b2);
    }

    Ok(output)
}

fn decode_b64_byte(b: u8, offset: usize) -> Result<u8, SdpError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Err(SdpError::BadBase64(Base64Fault::MalformedPadding {
            offset,
        })),
        _ => Err(SdpError::BadBase64(Base64Fault::InvalidCharacter {
            offset,
        })),
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
    /// Media encoding name (e.g. `"H264"`), if known.
    pub encoding_name: Option<String>,
    /// Clock rate in Hz (e.g. 90000), if known.
    pub clock_rate: Option<u32>,
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
    /// Media-level control track URI (e.g. `"trackID=0"`); never carries userinfo.
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
    /// Session-level control URI if present (`a=control:`); never carries userinfo.
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
    let mut session_rtcp_rsize = false;

    let mut line_count = 0;
    let mut next_offset = 0;

    for segment in input.split_inclusive('\n') {
        let offset = next_offset;
        next_offset += segment.len();
        // Same line splitting as `str::lines`: strip "\n" and a "\r" directly before it.
        let raw_line = match segment.strip_suffix('\n') {
            Some(without_lf) => without_lf.strip_suffix('\r').unwrap_or(without_lf),
            None => segment,
        };
        if raw_line.len() > MAX_SDP_LINE_BYTES {
            return Err(SdpError::Limit(SdpLimitFault::LineTooLong {
                offset,
                len: raw_line.len(),
                limit: MAX_SDP_LINE_BYTES,
            }));
        }

        line_count += 1;
        if line_count > MAX_SDP_LINES {
            return Err(SdpError::Limit(SdpLimitFault::TooManyLines {
                limit: MAX_SDP_LINES,
            }));
        }

        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }

        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            return Err(malformed(offset, SdpFault::MissingEquals));
        }

        let prefix = line.as_bytes()[0];
        let val = line[2..].trim();

        if prefix == b'm' {
            // Flush preceding media section
            if let Some(builder) = current_builder.take() {
                media_list.push(builder.finish()?);
            }
            current_builder = Some(MediaSectionBuilder::new(val, offset)?);
            continue;
        }

        if let Some(ref mut builder) = current_builder {
            // Media-level attribute or parameter
            builder.process_line(prefix, val, offset, media_list.len())?;
        } else {
            // Session-level line
            match prefix {
                b'v' => {
                    let v = val
                        .parse::<u32>()
                        .map_err(|_| malformed(offset, SdpFault::InvalidVersion))?;
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
                    if val.eq_ignore_ascii_case("rtcp-rsize") {
                        session_rtcp_rsize = true;
                    } else if let Some(ctrl) = val.strip_prefix("control:") {
                        let ctrl = ctrl.trim();
                        if has_userinfo(ctrl) {
                            return Err(SdpError::UserinfoNotPermitted(SdpControlLevel::Session {
                                offset,
                            }));
                        }
                        session_control = Some(ctrl.to_string());
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

    if session_rtcp_rsize {
        for m in &mut media_list {
            m.rtcp_reduced_size = true;
        }
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
        .map_err(|err| SdpError::Utf8(Utf8Fault::from_utf8_error(&err)))?;
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
    fn new(m_line_val: &str, offset: usize) -> Result<Self, SdpError> {
        let mut parts = m_line_val.split_whitespace();
        let media_type = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingMediaType))?
            .to_string();

        let port_str = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingPort))?;
        let port = port_str.parse::<u16>().map_err(|_| {
            malformed(
                offset,
                SdpFault::InvalidPort {
                    token_len: port_str.len(),
                },
            )
        })?;

        let proto = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingProtocol))?
            .to_string();

        let fmt_str = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingPayloadFormat))?;
        let payload_type = fmt_str.parse::<u8>().map_err(|_| {
            malformed(
                offset,
                SdpFault::InvalidPayloadFormat {
                    token_len: fmt_str.len(),
                },
            )
        })?;
        if payload_type > 127 {
            return Err(malformed(offset, SdpFault::PayloadTypeAbove127));
        }

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

    fn process_line(
        &mut self,
        prefix: u8,
        val: &str,
        offset: usize,
        media_index: usize,
    ) -> Result<(), SdpError> {
        if prefix != b'a' {
            return Ok(());
        }

        if val.eq_ignore_ascii_case("rtcp-rsize") {
            self.rtcp_reduced_size = true;
            return Ok(());
        }

        if let Some(ctrl) = val.strip_prefix("control:") {
            let ctrl = ctrl.trim();
            if has_userinfo(ctrl) {
                return Err(SdpError::UserinfoNotPermitted(SdpControlLevel::Media {
                    index: media_index,
                    offset,
                }));
            }
            self.control = Some(ctrl.to_string());
            return Ok(());
        }

        if let Some(rtpmap) = val.strip_prefix("rtpmap:") {
            self.parse_rtpmap(rtpmap, offset)?;
            return Ok(());
        }

        if let Some(fmtp) = val.strip_prefix("fmtp:") {
            self.parse_fmtp(fmtp, offset)?;
            return Ok(());
        }

        Ok(())
    }

    fn parse_rtpmap(&mut self, val: &str, offset: usize) -> Result<(), SdpError> {
        // format: <pt> <encoding>/<clock_rate>[/<channels>]
        let mut parts = val.split_whitespace();
        let pt_str = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingRtpmapPayloadType))?;
        let pt = pt_str.parse::<u8>().map_err(|_| {
            malformed(
                offset,
                SdpFault::InvalidRtpmapPayloadType {
                    token_len: pt_str.len(),
                },
            )
        })?;
        if pt > 127 {
            return Err(malformed(offset, SdpFault::PayloadTypeAbove127));
        }

        if pt != self.payload_type {
            return Ok(());
        }

        let enc_part = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingRtpmapEncoding))?;

        if let Some((enc, rate_str)) = enc_part.split_once('/') {
            self.encoding_name = Some(enc.to_string());
            let rate_tok = rate_str.split('/').next().unwrap_or(rate_str);
            let clock_rate = rate_tok.parse::<u32>().map_err(|_| {
                malformed(
                    offset,
                    SdpFault::InvalidClockRate {
                        token_len: rate_tok.len(),
                    },
                )
            })?;
            self.clock_rate = Some(clock_rate);
        } else {
            self.encoding_name = Some(enc_part.to_string());
        }

        Ok(())
    }

    fn parse_fmtp(&mut self, val: &str, offset: usize) -> Result<(), SdpError> {
        // format: <pt> <param1>=<val1>;<param2>=<val2>
        let mut parts = val.split_whitespace();
        let pt_str = parts
            .next()
            .ok_or_else(|| malformed(offset, SdpFault::MissingFmtpPayloadType))?;
        let pt = pt_str.parse::<u8>().map_err(|_| {
            malformed(
                offset,
                SdpFault::InvalidFmtpPayloadType {
                    token_len: pt_str.len(),
                },
            )
        })?;
        if pt > 127 {
            return Err(malformed(offset, SdpFault::PayloadTypeAbove127));
        }

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
                    let pm = v.parse::<u8>().map_err(|_| {
                        malformed(
                            offset,
                            SdpFault::InvalidPacketizationMode { token_len: v.len() },
                        )
                    })?;
                    if pm > 2 {
                        return Err(malformed(offset, SdpFault::PacketizationModeOutOfRange));
                    }
                    self.packetization_mode = Some(pm);
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
        let (static_enc, static_clock) = match rfc3551_static_payload(self.payload_type) {
            Some((enc, clock)) => (Some(enc.to_string()), Some(clock)),
            None => (None, None),
        };
        let encoding_name = self.encoding_name.or(static_enc);
        let clock_rate = self.clock_rate.or(static_clock);

        Ok(SdpMedia {
            media_type: self.media_type,
            port: self.port,
            proto: self.proto,
            payload_type: self.payload_type,
            encoding_name,
            clock_rate,
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

/// RFC 3551 Section 6 Table 4 static payload type mapping for PT 0-34.
fn rfc3551_static_payload(pt: u8) -> Option<(&'static str, u32)> {
    match pt {
        0 => Some(("PCMU", 8000)),
        3 => Some(("GSM", 8000)),
        4 => Some(("G723", 8000)),
        5 => Some(("DVI4", 8000)),
        6 => Some(("DVI4", 16000)),
        7 => Some(("LPC", 8000)),
        8 => Some(("PCMA", 8000)),
        9 => Some(("G722", 8000)),
        10 => Some(("L16", 44100)),
        11 => Some(("L16", 44100)),
        12 => Some(("QCELP", 8000)),
        13 => Some(("CN", 8000)),
        14 => Some(("MPA", 90000)),
        15 => Some(("G728", 8000)),
        16 => Some(("DVI4", 11025)),
        17 => Some(("DVI4", 22050)),
        18 => Some(("G729", 8000)),
        25 => Some(("CelB", 90000)),
        26 => Some(("JPEG", 90000)),
        28 => Some(("nv", 90000)),
        31 => Some(("H261", 90000)),
        32 => Some(("MPV", 90000)),
        33 => Some(("MP2T", 90000)),
        34 => Some(("H263", 90000)),
        _ => None,
    }
}
