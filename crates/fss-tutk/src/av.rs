//! AV layer for the TUTK NEW protocol: AV login, IOCTRL + "HL" K-commands,
//! and AV frame parsing/reassembly — all inside DTLS ApplicationData.
//!
//! Layouts live-proven against owner cameras (firmware 4.52.17.26) and
//! corrected against go2rtc: CC51 AV headers are version `0x000C` with NO
//! `0x507E` magic; the `0x0009` ACK is mandatory (24-byte layout from go2rtc
//! `msgACKCC51`); FRAMEINFO trailers are stripped only when the trailer's
//! codec id is valid for the channel (garbage tails must never be eaten).

use crate::xxtea;

/// AV protocol version observed on the wire.
pub const AV_VERSION: u16 = 0x000C;
/// Login packet #1 magic.
pub const MAGIC_AV_LOGIN1: u16 = 0x0000;
/// Login packet #2 magic.
pub const MAGIC_AV_LOGIN2: u16 = 0x2000;
/// Login response magic.
pub const MAGIC_AV_LOGIN_RESP: u16 = 0x2100;
/// IOCTRL wrapper magic at [16-17].
pub const MAGIC_IOCTRL: u16 = 0x7000;
/// msgACK magic.
pub const MAGIC_ACK: u16 = 0x0009;
/// Capabilities bitfield from the reference client.
pub const AV_CAPABILITIES: u32 = 0x001F_07FB;

/// Audio channel id in AV packet headers.
pub const CHANNEL_AUDIO: u8 = 0x03;
/// I-frame video channel id.
pub const CHANNEL_I_VIDEO: u8 = 0x05;
/// P-frame video channel id.
pub const CHANNEL_P_VIDEO: u8 = 0x07;

const FRAME_TYPES_28: [u8; 4] = [0x00, 0x01, 0x04, 0x05];
const FRAME_TYPES_36: [u8; 3] = [0x08, 0x09, 0x0D];
const END_TYPES: [u8; 3] = [0x01, 0x05, 0x0D];
/// Advisory FRAMEINFO marker value in the idx field.
pub const FRAMEINFO_MARKER: u16 = 0x0028;
/// RX FRAMEINFO trailer length.
pub const FRAMEINFO_LEN: usize = 40;

/// Errors from the AV layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvError {
    /// Malformed input.
    Malformed(&'static str),
    /// More input needed to finish a parse.
    NeedMoreData,
    /// Crypto layer rejected.
    Crypto,
}

impl core::fmt::Display for AvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed: {what}"),
            Self::NeedMoreData => write!(f, "need more data"),
            Self::Crypto => write!(f, "crypto layer rejected input"),
        }
    }
}

impl std::error::Error for AvError {}

impl From<xxtea::XxteaError> for AvError {
    fn from(_: xxtea::XxteaError) -> Self {
        Self::Crypto
    }
}

fn put16(out: &mut [u8], v: u16) {
    out[0] = (v & 0xFF) as u8;
    out[1] = (v >> 8) as u8;
}

fn put32(out: &mut [u8], v: u32) {
    out.copy_from_slice(&v.to_le_bytes());
}

fn get16(data: &[u8]) -> u16 {
    data[0] as u16 | ((data[1] as u16) << 8)
}

fn get32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Build the 570-byte AV Login #1 packet. `enr` goes in the password field
/// (null-padded to 256 bytes) — the caller must never log the result.
#[must_use]
pub fn build_av_login1(enr: &str, random_id: [u8; 4]) -> Vec<u8> {
    let mut pkt = vec![0u8; 570];
    put16(&mut pkt[0..2], MAGIC_AV_LOGIN1);
    put16(&mut pkt[2..4], AV_VERSION);
    put16(&mut pkt[16..18], 0x0222);
    put16(&mut pkt[18..20], 0x0001);
    pkt[20..24].copy_from_slice(&random_id);
    pkt[24..29].copy_from_slice(b"admin");
    let enr_b = enr.as_bytes();
    let n = enr_b.len().min(256);
    pkt[280..280 + n].copy_from_slice(&enr_b[..n]);
    put32(&mut pkt[536..540], 0);
    put32(&mut pkt[540..544], 2);
    put32(&mut pkt[544..548], 0);
    put32(&mut pkt[548..552], 0);
    put32(&mut pkt[552..556], AV_CAPABILITIES);
    pkt
}

/// Build AV Login #2 from #1 (572 bytes; magic 0x2000, size 0x0224,
/// flags 0, RandomID[0] + 1).
#[must_use]
pub fn build_av_login2(login1: &[u8]) -> Vec<u8> {
    let mut pkt = login1.to_vec();
    pkt.extend_from_slice(&[0, 0]);
    put16(&mut pkt[0..2], MAGIC_AV_LOGIN2);
    put16(&mut pkt[16..18], 0x0224);
    put16(&mut pkt[18..20], 0x0000);
    pkt[20] = pkt[20].wrapping_add(1);
    pkt
}

/// Parsed AV login response (0x2100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvLoginResponse {
    /// 0x10 = success.
    pub response_type: u8,
    /// Whether the camera accepted the login.
    pub success: bool,
    /// Advertised capabilities bitfield.
    pub capabilities: u32,
    /// Whether intercom (two-way audio) is supported.
    pub two_way_audio: u8,
}

/// Parse a 0x2100 login response.
pub fn parse_av_login_response(data: &[u8]) -> Result<AvLoginResponse, AvError> {
    if data.len() < 44 {
        return Err(AvError::Malformed("login response too short"));
    }
    if get16(&data[0..2]) != MAGIC_AV_LOGIN_RESP {
        return Err(AvError::Malformed("not a login response"));
    }
    Ok(AvLoginResponse {
        response_type: data[4],
        success: data[4] == 0x10,
        capabilities: get32(&data[40..44]),
        two_way_audio: data[31],
    })
}

/// Build a 24-byte msgACK frame (layout from go2rtc msgACKCC51).
#[must_use]
pub fn build_ack(avseq: u32, rx_seq_start: u16, rx_seq_end: u16, ack_flags: u16, ts_ms: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 24];
    put16(&mut pkt[0..2], MAGIC_ACK);
    put16(&mut pkt[2..4], AV_VERSION);
    put32(&mut pkt[4..8], avseq);
    put16(&mut pkt[8..10], rx_seq_start);
    put16(&mut pkt[10..12], rx_seq_end);
    put16(&mut pkt[12..14], ack_flags);
    put32(&mut pkt[16..20], (ack_flags as u32) << 16);
    put16(&mut pkt[20..22], ts_ms);
    pkt
}

/// Build an HL message (16-byte header + payload).
#[must_use]
pub fn build_hl(command_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(b"HL");
    out.push(5);
    out.push(0);
    out.extend_from_slice(&command_id.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(payload);
    out
}

/// Parse an HL message -> (command_id, payload, total_len).
pub fn parse_hl(data: &[u8]) -> Result<(u16, &[u8], usize), AvError> {
    if data.len() < 16 || &data[0..2] != b"HL" {
        return Err(AvError::Malformed("not an HL message"));
    }
    let cmd = get16(&data[4..6]);
    let plen = get16(&data[6..8]) as usize;
    let total = 16 + plen;
    if data.len() < total {
        return Err(AvError::Malformed("truncated HL payload"));
    }
    Ok((cmd, &data[16..total], total))
}

/// Build a 40-byte IOCTRL wrapper around an HL message.
#[must_use]
pub fn build_ioctrl(avseq: u32, subchannel: u16, hl_msg: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    put16(&mut pkt[0..2], 0x000C);
    put16(&mut pkt[2..4], AV_VERSION);
    put32(&mut pkt[4..8], avseq);
    put16(&mut pkt[16..18], MAGIC_IOCTRL);
    put16(&mut pkt[18..20], subchannel);
    put32(&mut pkt[20..24], 1);
    put32(&mut pkt[24..28], (hl_msg.len() + 4) as u32);
    put32(&mut pkt[28..32], subchannel as u32);
    put16(&mut pkt[36..38], 0x0100);
    let mut out = pkt;
    out.extend_from_slice(hl_msg);
    out
}

/// Parse a camera->client IOCTRL frame -> (hl_cmd, hl_payload, total_frame_len).
/// Trusts the HL header's own payload length over the wrapper's size field
/// (the doc's 'HL + 4' ambiguity).
pub fn parse_ioctrl(data: &[u8]) -> Result<(u16, &[u8], usize), AvError> {
    if data.len() < 40 {
        return Err(AvError::Malformed("IOCTRL frame too short"));
    }
    if get16(&data[16..18]) != MAGIC_IOCTRL {
        return Err(AvError::Malformed("not an IOCTRL frame"));
    }
    let (cmd, payload, hl_total) = parse_hl(&data[40..])?;
    Ok((cmd, payload, 40 + hl_total))
}

/// K10000 auth request with the reference codec preference list.
#[must_use]
pub fn build_k10000() -> Vec<u8> {
    build_hl(10000, br#"{"cameraInfo":{"audioEncoderList":[137,138,140]}}"#.as_slice())
}

/// K10002 challenge response (16B response + 4B session id + video + audio flags).
#[must_use]
pub fn build_k10002(response: &[u8; 16], session_id4: [u8; 4], video: bool, audio: bool) -> Vec<u8> {
    let mut payload = response.to_vec();
    payload.extend_from_slice(&session_id4);
    payload.push(video as u8);
    payload.push(audio as u8);
    build_hl(10002, &payload)
}

/// K10010 control channel (media 1=video 2=audio 3=return-audio).
#[must_use]
pub fn build_k10010(media_type: u8, enable: bool) -> Vec<u8> {
    build_hl(10010, &[media_type, if enable { 1 } else { 2 }])
}

/// Parse a K10001 payload -> (status, challenge16).
pub fn parse_k10001(payload: &[u8]) -> Result<(u8, [u8; 16]), AvError> {
    if payload.len() < 17 {
        return Err(AvError::Malformed("K10001 payload too short"));
    }
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&payload[1..17]);
    Ok((payload[0], challenge))
}

/// Parse a K10003 result JSON payload -> the raw JSON string (caller maps fields).
pub fn parse_k10003(payload: &[u8]) -> Result<&str, AvError> {
    core::str::from_utf8(payload).map_err(|_| AvError::Malformed("K10003 not utf-8"))
}

/// Compute the K10002 challenge response (XXTEA by camera-selected mode).
pub fn k_challenge_response(
    status: u8,
    challenge: &[u8; 16],
    enr: &str,
) -> Result<[u8; 16], AvError> {
    let mode = match status {
        3 => xxtea::ChallengeKey::Enr,
        6 => xxtea::ChallengeKey::EnrDouble,
        _ => xxtea::ChallengeKey::Default,
    };
    let out = xxtea::challenge_response(mode, challenge, enr)?;
    let mut resp = [0u8; 16];
    resp.copy_from_slice(&out[..16]);
    Ok(resp)
}

/// Codec ids from FRAMEINFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264/AVC
    H264,
    /// H.265/HEVC
    Hevc,
    /// Anything else.
    Other(u16),
}

impl Codec {
    fn from_id(id: u16) -> Self {
        match id {
            0x4E => Self::H264,
            0x50 => Self::Hevc,
            other => Self::Other(other),
        }
    }
}

/// Parsed RX FRAMEINFO (40 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameInfo {
    /// Numeric codec id.
    pub codec_id: u16,
    /// Codec classification.
    pub codec: Codec,
    /// Whether the frame is a keyframe.
    pub is_keyframe: bool,
    /// Camera-reported fps.
    pub framerate: u8,
    /// Declared assembled payload size.
    pub payload_size: u32,
    /// Camera frame number.
    pub frame_no: u32,
    /// Microsecond timestamp from the camera.
    pub timestamp_us: u32,
}

/// Parse a 40-byte RX FRAMEINFO trailer.
pub fn parse_frameinfo(fi: &[u8]) -> Result<FrameInfo, AvError> {
    if fi.len() != FRAMEINFO_LEN {
        return Err(AvError::Malformed("FRAMEINFO must be 40 bytes"));
    }
    let codec_id = get16(&fi[0..2]);
    Ok(FrameInfo {
        codec_id,
        codec: Codec::from_id(codec_id),
        is_keyframe: fi[2] & 0x01 != 0,
        framerate: fi[5],
        payload_size: get32(&fi[16..20]),
        frame_no: get32(&fi[20..24]),
        timestamp_us: get32(&fi[8..12]),
    })
}

/// One parsed AV packet (28- or 36-byte header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvPacket {
    /// Channel id (0x03 audio, 0x05 I-video, 0x07 P-video).
    pub channel: u8,
    /// Frame type nibble.
    pub ftype: u8,
    /// Total packets in the frame.
    pub pkt_total: u16,
    /// This packet's index in the frame.
    pub pkt_idx: u16,
    /// Camera frame number.
    pub frame_no: u32,
    /// Payload (FRAMEINFO trailer already stripped when valid).
    pub payload: Vec<u8>,
    /// FRAMEINFO if a valid trailer was present.
    pub frameinfo: Option<FrameInfo>,
    /// Total bytes consumed from the input buffer.
    pub total: usize,
}

/// Parse one AV packet from the head of `buf`.
pub fn parse_av_packet(buf: &[u8]) -> Result<AvPacket, AvError> {
    if buf.len() < 2 {
        return Err(AvError::NeedMoreData);
    }
    let channel = buf[0];
    let ftype = buf[1];
    let hlen = if FRAME_TYPES_28.contains(&ftype) {
        28
    } else if FRAME_TYPES_36.contains(&ftype) {
        36
    } else {
        return Err(AvError::Malformed("unknown frame type"));
    };
    if buf.len() < hlen {
        return Err(AvError::NeedMoreData);
    }
    let (pkt_total, idx_or_marker, payload_size, frame_no) = if hlen == 28 {
        (
            get16(&buf[12..14]),
            get16(&buf[14..16]),
            get16(&buf[16..18]) as usize,
            get32(&buf[24..28]),
        )
    } else {
        (
            get16(&buf[20..22]),
            get16(&buf[22..24]),
            get16(&buf[24..26]) as usize,
            get32(&buf[32..36]),
        )
    };
    let total = hlen + payload_size;
    if buf.len() < total {
        return Err(AvError::NeedMoreData);
    }
    let mut payload = buf[hlen..total].to_vec();

    let is_end = END_TYPES.contains(&ftype) || (ftype == 0x09 && pkt_total == 1);
    let mut frameinfo = None;
    let mut has_frameinfo = false;
    if is_end && payload.len() >= FRAMEINFO_LEN {
        if let Ok(fi) = parse_frameinfo(&payload[payload.len() - FRAMEINFO_LEN..]) {
            let codec_ok = (matches!(channel, CHANNEL_I_VIDEO | CHANNEL_P_VIDEO)
                && (0x4C..=0x50).contains(&fi.codec_id))
                || (channel == CHANNEL_AUDIO && (0x86..=0x92).contains(&fi.codec_id));
            if codec_ok {
                has_frameinfo = true;
                payload.truncate(payload.len() - FRAMEINFO_LEN);
                frameinfo = Some(fi);
            }
        }
    }
    let pkt_idx = if has_frameinfo || (is_end && idx_or_marker == FRAMEINFO_MARKER) {
        if pkt_total > 0 { pkt_total - 1 } else { 0 }
    } else {
        idx_or_marker
    };
    Ok(AvPacket {
        channel,
        ftype,
        pkt_total,
        pkt_idx,
        frame_no,
        payload,
        frameinfo,
        total,
    })
}

/// Reassembles multi-packet AV frames keyed by (channel, frame_no).
#[derive(Default)]
pub struct FrameReassembler {
    frames: std::collections::BTreeMap<(u8, u32), (u16, std::collections::BTreeMap<u16, Vec<u8>>, Option<FrameInfo>)>,
}

impl FrameReassembler {
    /// New empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one packet; returns (channel, frame_no, assembled, frameinfo) when complete.
    pub fn add(&mut self, info: &AvPacket) -> Option<(u8, u32, Vec<u8>, Option<FrameInfo>)> {
        let key = (info.channel, info.frame_no);
        let entry = self.frames.entry(key).or_insert_with(|| (info.pkt_total, Default::default(), None));
        entry.1.insert(info.pkt_idx, info.payload.clone());
        if info.frameinfo.is_some() {
            entry.2 = info.frameinfo.clone();
        }
        let total = if entry.0 == 0 { entry.1.len() as u16 } else { entry.0 };
        if entry.1.len() as u16 >= total && (0..total).all(|i| entry.1.contains_key(&i)) {
            let mut data = Vec::new();
            for i in 0..total {
                if let Some(p) = entry.1.get(&i) {
                    data.extend_from_slice(p);
                }
            }
            let fi = match self.frames.remove(&key) {
                Some((_, _, fi)) => fi,
                None => return None,
            };
            return Some((info.channel, info.frame_no, data, fi));
        }
        None
    }

    /// Number of incomplete frames pending.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.frames.len()
    }
}
