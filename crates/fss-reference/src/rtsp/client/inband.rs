#![forbid(unsafe_code)]
//! Bounded in-band codec parameter-set acquisition (H.264 SPS/PPS and H.265 VPS/SPS/PPS)
//! for RTSP sources (such as Wyze SmolRTSP) that omit `sprop-parameter-sets` from SDP `a=fmtp`
//! and deliver parameter sets in-band on RTP before the first IDR access unit.
//!
//! Provenance honesty is preserved explicitly:
//! - Parameter sets learned from RTP carry [`ParameterSetOrigin::InbandRtp`], never `SdpFmtp`.
//! - Every pre-sync video packet discarded before `(SPS + PPS + IDR)` or `(VPS + SPS + PPS + IDR)`
//!   is established is counted in `pre_sync_discarded`.
//! - Acquisition is strictly bounded by packet count, byte count, and monotonic elapsed duration;
//!   exceeding any bound fails closed without fabricating parameter sets or an IDR boundary.

use std::fmt;

use fss_packet::avc::{AvcError, AvcPps, AvcSps, AvcSyntaxLimits, parse_pps, parse_sps};
use fss_packet::hevc::{HevcConfiguration, HevcConfigurationError, HevcConfigurationLimits};
use fss_packet::{H264Mode, OrderedRtpPacket, PacketLimits, RtpPacket};

/// Default pre-roll packet budget while awaiting in-band parameter sets and first IDR.
pub const DEFAULT_INBAND_MAX_PACKETS: usize = 256;
/// Default pre-roll byte budget (4 MiB) while awaiting in-band parameter sets and first IDR.
pub const DEFAULT_INBAND_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Default pre-roll duration budget (5 seconds) while awaiting in-band parameter sets and first IDR.
pub const DEFAULT_INBAND_MAX_DURATION_NS: u64 = 5_000_000_000;
/// Maximum single parameter-set NAL size (matches SDP validation bound).
pub const MAX_INBAND_PARAMETER_SET_BYTES: usize = 16_384;
/// Maximum pre-sync prefix packets retained for the active HEVC parameter-set access unit.
const MAX_HEVC_PREFIX_PACKETS: usize = 16;

/// Explicit provenance for active codec parameter sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterSetOrigin {
    /// Parameter sets were supplied out-of-band in SDP `a=fmtp`.
    SdpFmtp,
    /// Parameter sets were acquired in-band from RTP before the first IDR sync point.
    InbandRtp,
}

impl ParameterSetOrigin {
    /// Stable lowercase identifier for machine-readable reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SdpFmtp => "sdp_fmtp",
            Self::InbandRtp => "inband_rtp",
        }
    }
}

/// Bounded pre-roll limits for in-band parameter-set acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InbandSyncLimits {
    /// Maximum video RTP packets inspected before failing closed.
    pub max_packets: usize,
    /// Maximum cumulative video RTP bytes inspected before failing closed.
    pub max_bytes: usize,
    /// Maximum monotonic nanoseconds elapsed before failing closed.
    pub max_duration_ns: u64,
}

impl Default for InbandSyncLimits {
    fn default() -> Self {
        Self {
            max_packets: DEFAULT_INBAND_MAX_PACKETS,
            max_bytes: DEFAULT_INBAND_MAX_BYTES,
            max_duration_ns: DEFAULT_INBAND_MAX_DURATION_NS,
        }
    }
}

impl InbandSyncLimits {
    /// Validate explicit bounds before admitting pre-roll intake.
    pub fn validate(&self) -> Result<(), H264InbandError> {
        if !(1..=4_096).contains(&self.max_packets)
            || !(1..=16 * 1024 * 1024).contains(&self.max_bytes)
            || !(1..=60_000_000_000).contains(&self.max_duration_ns)
        {
            return Err(H264InbandError::Limits);
        }
        Ok(())
    }
}

/// Explicit intake accounting for opt-in interoperability modes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RtspIntakeTelemetry {
    /// Origin of the locked parameter sets once established, or `None` before lock.
    pub parameter_set_origin: Option<ParameterSetOrigin>,
    /// Pre-sync video RTP packets explicitly discarded before parameter-set + IDR lock.
    pub pre_sync_discarded: u64,
    /// Interleaved packets drained from negotiated companion (e.g., audio) tracks.
    pub companion_packets_discarded: u64,
}

/// Payload-free failure categories for bounded H.264 in-band parameter-set acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H264InbandError {
    /// Configured pre-roll bounds are invalid.
    Limits,
    /// Pre-roll packet failed RTP header parsing or channel/payload/SSRC binding.
    MalformedRtp,
    /// Pre-roll packet violated RFC 6184 single-NAL / STAP-A / FU-A framing.
    MalformedPacketization,
    /// Observed SPS or PPS bytes failed the real AVC syntax owner.
    Syntax(AvcError),
    /// Pre-roll packet ceiling elapsed before observing valid SPS + PPS + IDR.
    BudgetPackets,
    /// Pre-roll byte ceiling elapsed before observing valid SPS + PPS + IDR.
    BudgetBytes,
    /// Pre-roll duration ceiling elapsed before observing valid SPS + PPS + IDR.
    Timeout,
}

impl fmt::Display for H264InbandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H.264 in-band parameter-set sync failure: {self:?}")
    }
}

impl std::error::Error for H264InbandError {}

/// Single immediately preceding real RTP packet retained solely to prove RFC 3550
/// two-packet sequence probation when the sync IDR packet arrives on `seq + 1`.
#[derive(Clone, Debug)]
pub struct PreSyncPrimer {
    /// Original interleaved channel.
    pub channel: u8,
    /// Original owner receipt time.
    pub received_ns: u64,
    /// Exact RTP 16-bit sequence number.
    pub sequence: u16,
    /// Exact original RTP datagram bytes.
    pub payload: Vec<u8>,
}

/// Result of inspecting one video RTP packet during H.264 pre-roll.
#[derive(Debug)]
pub enum H264SyncOutcome {
    /// Still awaiting complete `(SPS + PPS + IDR)`; packet accounted for and discarded.
    Awaiting,
    /// Valid SPS + PPS + IDR observed on this packet; downstream receiver can lock now.
    Synced {
        /// Parsed and validated SPS from RTP.
        sps: Box<AvcSps>,
        /// Parsed and validated PPS validated against `sps`.
        pps: Box<AvcPps>,
        /// Optional immediately preceding real RTP packet (`seq + 1 == current.seq`)
        /// to satisfy RFC 3550 probation without fabricating a packet.
        primer: Option<PreSyncPrimer>,
    },
}

/// Bounded state machine extracting the first valid H.264 `(SPS, PPS)` and IDR sync point
/// from RFC 6184 RTP payloads (Single NAL, STAP-A, and FU-A).
#[derive(Debug)]
pub struct H264InbandSync {
    payload_type: u8,
    mode: H264Mode,
    packet_limits: PacketLimits,
    syntax_limits: AvcSyntaxLimits,
    limits: InbandSyncLimits,
    started_ns: Option<u64>,
    packets_seen: usize,
    bytes_seen: usize,
    pre_sync_discarded: u64,
    sps: Option<(Vec<u8>, AvcSps)>,
    pps: Option<(Vec<u8>, AvcPps)>,
    pending_raw_pps: Option<Vec<u8>>,
    fu_param: Option<(u8, u32, Vec<u8>)>,
    last_packet: Option<PreSyncPrimer>,
}

impl H264InbandSync {
    /// Construct a bounded pre-roll state machine for one selected H.264 payload type.
    pub fn new(
        payload_type: u8,
        mode: H264Mode,
        packet_limits: PacketLimits,
        syntax_limits: AvcSyntaxLimits,
        limits: InbandSyncLimits,
    ) -> Result<Self, H264InbandError> {
        limits.validate()?;
        syntax_limits.validate().map_err(H264InbandError::Syntax)?;
        Ok(Self {
            payload_type,
            mode,
            packet_limits,
            syntax_limits,
            limits,
            started_ns: None,
            packets_seen: 0,
            bytes_seen: 0,
            pre_sync_discarded: 0,
            sps: None,
            pps: None,
            pending_raw_pps: None,
            fu_param: None,
            last_packet: None,
        })
    }

    /// Anchor the monotonic pre-roll deadline when `PLAY` is acknowledged.
    pub fn start(&mut self, now_ns: u64) {
        self.started_ns.get_or_insert(now_ns);
    }

    /// Fixed monotonic pre-roll timeout deadline, once started.
    pub fn deadline_ns(&self) -> Option<u64> {
        self.started_ns
            .map(|start| start.saturating_add(self.limits.max_duration_ns))
    }

    /// Whether the monotonic pre-roll deadline has elapsed at `now_ns`.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        self.deadline_ns().is_some_and(|at| now_ns >= at)
    }

    /// Explicit count of pre-sync video packets discarded before sync locked.
    pub fn pre_sync_discarded(&self) -> u64 {
        self.pre_sync_discarded
    }

    /// Inspect one RTP packet from the selected video channel.
    pub fn observe(
        &mut self,
        channel: u8,
        rtp_bytes: &[u8],
        received_ns: u64,
        now_ns: u64,
        expected_ssrc: u32,
    ) -> Result<H264SyncOutcome, H264InbandError> {
        self.started_ns.get_or_insert(now_ns);
        if self.is_expired(now_ns) {
            return Err(H264InbandError::Timeout);
        }
        let next_packets = self.packets_seen.saturating_add(1);
        if next_packets > self.limits.max_packets {
            return Err(H264InbandError::BudgetPackets);
        }
        let next_bytes = self.bytes_seen.saturating_add(rtp_bytes.len());
        if next_bytes > self.limits.max_bytes {
            return Err(H264InbandError::BudgetBytes);
        }
        let packet = RtpPacket::parse(rtp_bytes, self.packet_limits)
            .map_err(|_| H264InbandError::MalformedRtp)?;
        if packet.payload_type() != self.payload_type || packet.ssrc() != expected_ssrc {
            return Err(H264InbandError::MalformedRtp);
        }
        let payload = packet.payload();
        if payload.is_empty() {
            return Err(H264InbandError::MalformedPacketization);
        }
        self.packets_seen = next_packets;
        self.bytes_seen = next_bytes;

        let nal_header = payload[0];
        if nal_header & 0x80 != 0 {
            return Err(H264InbandError::MalformedPacketization);
        }
        let nal_type = nal_header & 0x1f;
        let mut has_idr = false;
        let mut is_param_only = false;

        match nal_type {
            1..=23 => {
                self.fu_param = None;
                match nal_type {
                    7 => {
                        self.accept_sps(payload)?;
                        is_param_only = true;
                    }
                    8 => {
                        self.accept_pps(payload)?;
                        is_param_only = true;
                    }
                    5 => {
                        has_idr = true;
                    }
                    _ => {}
                }
            }
            24 => {
                // STAP-A (RFC 6184 section 5.7.1)
                if self.mode != H264Mode::NonInterleaved {
                    return Err(H264InbandError::MalformedPacketization);
                }
                self.fu_param = None;
                let mut offset = 1usize;
                let mut saw_unit = false;
                let mut saw_param = false;
                let mut saw_other = false;
                while offset < payload.len() {
                    if payload.len() - offset < 2 {
                        return Err(H264InbandError::MalformedPacketization);
                    }
                    let size =
                        usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                    offset += 2;
                    if size == 0 || payload.len() - offset < size {
                        return Err(H264InbandError::MalformedPacketization);
                    }
                    let unit = &payload[offset..offset + size];
                    offset += size;
                    let unit_hdr = unit[0];
                    if unit_hdr & 0x80 != 0 {
                        return Err(H264InbandError::MalformedPacketization);
                    }
                    let unit_type = unit_hdr & 0x1f;
                    if !(1..=23).contains(&unit_type) {
                        return Err(H264InbandError::MalformedPacketization);
                    }
                    saw_unit = true;
                    match unit_type {
                        7 => {
                            self.accept_sps(unit)?;
                            saw_param = true;
                        }
                        8 => {
                            self.accept_pps(unit)?;
                            saw_param = true;
                        }
                        5 => has_idr = true,
                        _ => saw_other = true,
                    }
                }
                if !saw_unit {
                    return Err(H264InbandError::MalformedPacketization);
                }
                is_param_only = saw_param && !has_idr && !saw_other;
            }
            28 => {
                // FU-A (RFC 6184 section 5.8)
                if self.mode != H264Mode::NonInterleaved || payload.len() < 2 {
                    return Err(H264InbandError::MalformedPacketization);
                }
                let fu_header = payload[1];
                let start = (fu_header & 0x80) != 0;
                let end = (fu_header & 0x40) != 0;
                let reserved = (fu_header & 0x20) != 0;
                let orig_type = fu_header & 0x1f;
                if reserved || (start && end) || !(1..=23).contains(&orig_type) {
                    return Err(H264InbandError::MalformedPacketization);
                }
                if orig_type == 7 || orig_type == 8 {
                    let frag = &payload[2..];
                    if start {
                        if 1 + frag.len() > MAX_INBAND_PARAMETER_SET_BYTES {
                            return Err(H264InbandError::MalformedPacketization);
                        }
                        let mut buf = Vec::with_capacity(1 + frag.len());
                        buf.push((nal_header & 0xE0) | orig_type);
                        buf.extend_from_slice(frag);
                        self.fu_param = Some((orig_type, packet.timestamp(), buf));
                    } else if let Some((kind, ts, mut buf)) = self.fu_param.take()
                        && kind == orig_type
                        && ts == packet.timestamp()
                    {
                        if buf.len().saturating_add(frag.len()) > MAX_INBAND_PARAMETER_SET_BYTES {
                            return Err(H264InbandError::MalformedPacketization);
                        }
                        buf.extend_from_slice(frag);
                        if end {
                            if orig_type == 7 {
                                self.accept_sps(&buf)?;
                            } else {
                                self.accept_pps(&buf)?;
                            }
                        } else {
                            self.fu_param = Some((kind, ts, buf));
                        }
                    }
                    is_param_only = true;
                } else {
                    self.fu_param = None;
                    if orig_type == 5 && start {
                        has_idr = true;
                    }
                }
            }
            _ => return Err(H264InbandError::MalformedPacketization),
        }

        if has_idr && let (Some((_, sps)), Some((_, pps))) = (self.sps.take(), self.pps.take()) {
            let primer = self
                .last_packet
                .take()
                .filter(|prev| prev.sequence.wrapping_add(1) == packet.sequence());
            return Ok(H264SyncOutcome::Synced {
                sps: Box::new(sps),
                pps: Box::new(pps),
                primer,
            });
        }

        if !is_param_only {
            self.pre_sync_discarded = self.pre_sync_discarded.saturating_add(1);
        }
        self.last_packet = Some(PreSyncPrimer {
            channel,
            received_ns,
            sequence: packet.sequence(),
            payload: rtp_bytes.to_vec(),
        });
        Ok(H264SyncOutcome::Awaiting)
    }

    fn accept_sps(&mut self, bytes: &[u8]) -> Result<(), H264InbandError> {
        if bytes.len() < 4 || bytes.len() > MAX_INBAND_PARAMETER_SET_BYTES {
            return Err(H264InbandError::MalformedPacketization);
        }
        let parsed = parse_sps(bytes, self.syntax_limits).map_err(H264InbandError::Syntax)?;
        self.sps = Some((bytes.to_vec(), parsed));
        if let Some(raw_pps) = self.pending_raw_pps.take()
            && let Some((_, ref sps)) = self.sps
        {
            let parsed_pps =
                parse_pps(&raw_pps, sps, self.syntax_limits).map_err(H264InbandError::Syntax)?;
            self.pps = Some((raw_pps, parsed_pps));
        }
        Ok(())
    }

    fn accept_pps(&mut self, bytes: &[u8]) -> Result<(), H264InbandError> {
        if bytes.len() < 2 || bytes.len() > MAX_INBAND_PARAMETER_SET_BYTES {
            return Err(H264InbandError::MalformedPacketization);
        }
        if let Some((_, ref sps)) = self.sps {
            let parsed =
                parse_pps(bytes, sps, self.syntax_limits).map_err(H264InbandError::Syntax)?;
            self.pps = Some((bytes.to_vec(), parsed));
            self.pending_raw_pps = None;
        } else {
            self.pending_raw_pps = Some(bytes.to_vec());
        }
        Ok(())
    }
}

/// Payload-free failure categories for bounded H.265 in-band parameter-set acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H265InbandError {
    /// Configured pre-roll bounds are invalid.
    Limits,
    /// Pre-roll packet failed RTP parsing or RFC 7798 packetization rules.
    MalformedPacketization,
    /// Observed VPS/SPS/PPS failed the real HEVC syntax owner.
    Syntax(HevcConfigurationError),
    /// Pre-roll packet ceiling elapsed before observing valid VPS + SPS + PPS + IDR.
    BudgetPackets,
    /// Pre-roll byte ceiling elapsed before observing valid VPS + SPS + PPS + IDR.
    BudgetBytes,
    /// Pre-roll duration ceiling elapsed before observing valid VPS + SPS + PPS + IDR.
    Timeout,
}

impl fmt::Display for H265InbandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H.265 in-band parameter-set sync failure: {self:?}")
    }
}

impl std::error::Error for H265InbandError {}

/// Owned original source packet retained for the active HEVC parameter-set access unit.
#[derive(Clone, Debug)]
pub struct HevcPrefixPacket {
    /// Unwrapped monotonic RTP sequence number from [`OrderedRtpPacket::sequence`].
    pub sequence: u64,
    /// Original owner receipt time from [`OrderedRtpPacket::received_ns`].
    pub received_ns: u64,
    /// Exact original RTP datagram bytes.
    pub bytes: Vec<u8>,
}

/// Result of inspecting one ordered H.265 RTP packet during pre-roll.
#[derive(Debug)]
pub enum H265SyncOutcome {
    /// Still awaiting complete `(VPS + SPS + PPS + IDR)`.
    Awaiting,
    /// Valid VPS + SPS + PPS + IDR observed; configuration and prefix packets are ready.
    Synced {
        /// Validated HEVC configuration parsed from the observed VPS/SPS/PPS.
        configuration: Box<HevcConfiguration>,
        /// Any same-access-unit parameter-set packets retained directly before the IDR packet.
        prefix_packets: Vec<HevcPrefixPacket>,
    },
}

/// Bounded state machine extracting H.265 `(VPS=32, SPS=33, PPS=34)` + IDR (`19`/`20`)
/// from RFC 7798 single-stream (no-DON) RTP packets (Single NAL, AP=48, FU=49).
#[derive(Debug)]
pub struct H265InbandSync {
    packet_limits: PacketLimits,
    syntax_limits: HevcConfigurationLimits,
    limits: InbandSyncLimits,
    started_ns: Option<u64>,
    packets_seen: usize,
    bytes_seen: usize,
    pre_sync_discarded: u64,
    vps: Option<Vec<u8>>,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    fu_param: Option<(u8, u32, Vec<u8>)>,
    prefix_ts: Option<u32>,
    prefix_packets: Vec<HevcPrefixPacket>,
}

impl H265InbandSync {
    /// Construct a bounded HEVC pre-roll state machine, optionally seeded with partial SDP sets.
    pub fn new(
        packet_limits: PacketLimits,
        syntax_limits: HevcConfigurationLimits,
        limits: InbandSyncLimits,
        seed_vps: Option<Vec<u8>>,
        seed_sps: Option<Vec<u8>>,
        seed_pps: Option<Vec<u8>>,
    ) -> Result<Self, H265InbandError> {
        limits.validate().map_err(|_| H265InbandError::Limits)?;
        syntax_limits.validate().map_err(H265InbandError::Syntax)?;
        Ok(Self {
            packet_limits,
            syntax_limits,
            limits,
            started_ns: None,
            packets_seen: 0,
            bytes_seen: 0,
            pre_sync_discarded: 0,
            vps: seed_vps,
            sps: seed_sps,
            pps: seed_pps,
            fu_param: None,
            prefix_ts: None,
            prefix_packets: Vec::new(),
        })
    }

    /// Anchor the monotonic pre-roll deadline when `PLAY` is acknowledged.
    pub fn start(&mut self, now_ns: u64) {
        self.started_ns.get_or_insert(now_ns);
    }

    /// Fixed monotonic pre-roll timeout deadline, once started.
    pub fn deadline_ns(&self) -> Option<u64> {
        self.started_ns
            .map(|start| start.saturating_add(self.limits.max_duration_ns))
    }

    /// Whether the monotonic pre-roll deadline has elapsed at `now_ns`.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        self.deadline_ns().is_some_and(|at| now_ns >= at)
    }

    /// Explicit count of pre-sync HEVC video packets discarded before sync locked.
    pub fn pre_sync_discarded(&self) -> u64 {
        self.pre_sync_discarded
    }

    /// Inspect one ordered HEVC RTP packet during pre-roll.
    pub fn observe(
        &mut self,
        ordered: &OrderedRtpPacket,
        now_ns: u64,
    ) -> Result<H265SyncOutcome, H265InbandError> {
        self.started_ns.get_or_insert(now_ns);
        if self.is_expired(now_ns) {
            return Err(H265InbandError::Timeout);
        }
        let next_packets = self.packets_seen.saturating_add(1);
        if next_packets > self.limits.max_packets {
            return Err(H265InbandError::BudgetPackets);
        }
        let next_bytes = self.bytes_seen.saturating_add(ordered.bytes().len());
        if next_bytes > self.limits.max_bytes {
            return Err(H265InbandError::BudgetBytes);
        }
        let packet = RtpPacket::parse(ordered.bytes(), self.packet_limits)
            .map_err(|_| H265InbandError::MalformedPacketization)?;
        let payload = packet.payload();
        if payload.len() < 2 {
            return Err(H265InbandError::MalformedPacketization);
        }
        self.packets_seen = next_packets;
        self.bytes_seen = next_bytes;

        if payload[0] & 0x80 != 0 {
            return Err(H265InbandError::MalformedPacketization);
        }
        let nal_type = (payload[0] >> 1) & 0x3f;
        let mut has_idr = false;
        let mut is_param_only = false;

        match nal_type {
            0..=47 => {
                self.fu_param = None;
                match nal_type {
                    32 => {
                        self.store_param(32, payload)?;
                        is_param_only = true;
                    }
                    33 => {
                        self.store_param(33, payload)?;
                        is_param_only = true;
                    }
                    34 => {
                        self.store_param(34, payload)?;
                        is_param_only = true;
                    }
                    19 | 20 => has_idr = true,
                    _ => {}
                }
            }
            48 => {
                // RFC 7798 AP (no DONL)
                self.fu_param = None;
                let mut offset = 2usize;
                let mut saw_unit = false;
                let mut saw_param = false;
                let mut saw_other = false;
                while offset < payload.len() {
                    if payload.len() - offset < 2 {
                        return Err(H265InbandError::MalformedPacketization);
                    }
                    let size =
                        usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                    offset += 2;
                    if size < 2 || payload.len() - offset < size {
                        return Err(H265InbandError::MalformedPacketization);
                    }
                    let unit = &payload[offset..offset + size];
                    offset += size;
                    if unit[0] & 0x80 != 0 {
                        return Err(H265InbandError::MalformedPacketization);
                    }
                    let unit_type = (unit[0] >> 1) & 0x3f;
                    if unit_type > 47 {
                        return Err(H265InbandError::MalformedPacketization);
                    }
                    saw_unit = true;
                    match unit_type {
                        32..=34 => {
                            self.store_param(unit_type, unit)?;
                            saw_param = true;
                        }
                        19 | 20 => has_idr = true,
                        _ => saw_other = true,
                    }
                }
                if !saw_unit {
                    return Err(H265InbandError::MalformedPacketization);
                }
                is_param_only = saw_param && !has_idr && !saw_other;
            }
            49 => {
                // RFC 7798 FU (no DONL)
                if payload.len() < 3 {
                    return Err(H265InbandError::MalformedPacketization);
                }
                let fu_header = payload[2];
                let start = (fu_header & 0x80) != 0;
                let end = (fu_header & 0x40) != 0;
                let orig_type = fu_header & 0x3f;
                if (start && end) || orig_type > 47 {
                    return Err(H265InbandError::MalformedPacketization);
                }
                if matches!(orig_type, 32..=34) {
                    let frag = &payload[3..];
                    if start {
                        if 2 + frag.len() > MAX_INBAND_PARAMETER_SET_BYTES {
                            return Err(H265InbandError::MalformedPacketization);
                        }
                        let mut buf = Vec::with_capacity(2 + frag.len());
                        buf.push((payload[0] & 0x81) | (orig_type << 1));
                        buf.push(payload[1]);
                        buf.extend_from_slice(frag);
                        self.fu_param = Some((orig_type, packet.timestamp(), buf));
                    } else if let Some((kind, ts, mut buf)) = self.fu_param.take()
                        && kind == orig_type
                        && ts == packet.timestamp()
                    {
                        if buf.len().saturating_add(frag.len()) > MAX_INBAND_PARAMETER_SET_BYTES {
                            return Err(H265InbandError::MalformedPacketization);
                        }
                        buf.extend_from_slice(frag);
                        if end {
                            self.store_param(orig_type, &buf)?;
                        } else {
                            self.fu_param = Some((kind, ts, buf));
                        }
                    }
                    is_param_only = true;
                } else {
                    self.fu_param = None;
                    if matches!(orig_type, 19 | 20) && start {
                        has_idr = true;
                    }
                }
            }
            _ => return Err(H265InbandError::MalformedPacketization),
        }

        if has_idr && let (Some(vps), Some(sps), Some(pps)) = (&self.vps, &self.sps, &self.pps) {
            let configuration = HevcConfiguration::parse(vps, sps, pps, self.syntax_limits)
                .map_err(H265InbandError::Syntax)?;
            let prefix_packets = if self.prefix_ts == Some(packet.timestamp()) {
                std::mem::take(&mut self.prefix_packets)
            } else {
                self.prefix_packets.clear();
                Vec::new()
            };
            self.prefix_ts = None;
            return Ok(H265SyncOutcome::Synced {
                configuration: Box::new(configuration),
                prefix_packets,
            });
        }

        if is_param_only {
            if self.prefix_ts != Some(packet.timestamp()) {
                self.prefix_packets.clear();
                self.prefix_ts = Some(packet.timestamp());
            }
            if self.prefix_packets.len() < MAX_HEVC_PREFIX_PACKETS {
                self.prefix_packets.push(HevcPrefixPacket {
                    sequence: ordered.sequence(),
                    received_ns: ordered.received_ns(),
                    bytes: ordered.bytes().to_vec(),
                });
            }
        } else {
            self.prefix_packets.clear();
            self.prefix_ts = None;
            self.pre_sync_discarded = self.pre_sync_discarded.saturating_add(1);
        }
        Ok(H265SyncOutcome::Awaiting)
    }

    fn store_param(&mut self, nal_type: u8, bytes: &[u8]) -> Result<(), H265InbandError> {
        if bytes.len() < 3 || bytes.len() > MAX_INBAND_PARAMETER_SET_BYTES {
            return Err(H265InbandError::MalformedPacketization);
        }
        match nal_type {
            32 => self.vps = Some(bytes.to_vec()),
            33 => self.sps = Some(bytes.to_vec()),
            34 => self.pps = Some(bytes.to_vec()),
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_packet::StreamKey;

    const SPS: &[u8] = &[
        0x67, 0x42, 0xc0, 0x0b, 0xda, 0x0a, 0x11, 0xb0, 0x11, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
        0x00, 0x03, 0x00, 0x32, 0x0f, 0x14, 0x2a, 0xa0,
    ];
    const PPS: &[u8] = &[0x68, 0xce, 0x0f, 0x2c, 0x80];
    const IDR: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x33, 0xff];
    const P_SLICE: &[u8] = &[0x41, 0x9a, 0x24, 0x6c, 0x41];

    fn rtp(seq: u16, ts: u32, marker: bool, ssrc: u32, pt: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + payload.len());
        out.push(0x80);
        out.push(pt | if marker { 0x80 } else { 0 });
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(&ssrc.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn stap_a(units: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![0x78]; // F=0, NRI=3, Type=24 (STAP-A)
        for u in units {
            out.extend_from_slice(&(u.len() as u16).to_be_bytes());
            out.extend_from_slice(u);
        }
        out
    }

    #[test]
    fn h264_stap_a_sync_after_pre_sync_p_frames_counts_discards_and_primes_probation()
    -> Result<(), H264InbandError> {
        let mut sync = H264InbandSync::new(
            96,
            H264Mode::NonInterleaved,
            PacketLimits::default(),
            AvcSyntaxLimits::default(),
            InbandSyncLimits::default(),
        )?;
        sync.start(100);
        for i in 0..3u16 {
            let pkt = rtp(10 + i, 9000 + u32::from(i) * 3600, true, 7, 96, P_SLICE);
            assert!(matches!(
                sync.observe(0, &pkt, 100 + u64::from(i), 100 + u64::from(i), 7)?,
                H264SyncOutcome::Awaiting
            ));
        }
        assert_eq!(sync.pre_sync_discarded(), 3);

        let stap = stap_a(&[SPS, PPS, IDR]);
        let pkt = rtp(13, 19800, true, 7, 96, &stap);
        match sync.observe(0, &pkt, 110, 110, 7)? {
            H264SyncOutcome::Synced { sps, pps, primer } => {
                assert_eq!(sps.nal_bytes(), SPS);
                assert_eq!(pps.nal_bytes(), PPS);
                let primer = primer.expect("adjacent pre-sync packet primes RFC 3550 probation");
                assert_eq!(primer.sequence, 12);
            }
            H264SyncOutcome::Awaiting => panic!("expected sync lock on STAP-A(SPS+PPS+IDR)"),
        }
        assert_eq!(sync.pre_sync_discarded(), 3);
        Ok(())
    }

    #[test]
    fn h264_separate_fu_a_sps_pps_and_fu_a_idr_locks_cleanly() -> Result<(), H264InbandError> {
        let mut sync = H264InbandSync::new(
            96,
            H264Mode::NonInterleaved,
            PacketLimits::default(),
            AvcSyntaxLimits::default(),
            InbandSyncLimits::default(),
        )?;
        // Out-of-order PPS before SPS via single NAL
        let pps_pkt = rtp(1, 9000, false, 7, 96, PPS);
        assert!(matches!(
            sync.observe(0, &pps_pkt, 10, 10, 7)?,
            H264SyncOutcome::Awaiting
        ));
        // SPS split across two FU-A packets
        let sps_body = &SPS[1..];
        let mid = sps_body.len() / 2;
        let mut fu_start = vec![(SPS[0] & 0xE0) | 28, 0x80 | 7];
        fu_start.extend_from_slice(&sps_body[..mid]);
        let mut fu_end = vec![(SPS[0] & 0xE0) | 28, 0x40 | 7];
        fu_end.extend_from_slice(&sps_body[mid..]);
        assert!(matches!(
            sync.observe(0, &rtp(2, 9000, false, 7, 96, &fu_start), 11, 11, 7)?,
            H264SyncOutcome::Awaiting
        ));
        assert!(matches!(
            sync.observe(0, &rtp(3, 9000, false, 7, 96, &fu_end), 12, 12, 7)?,
            H264SyncOutcome::Awaiting
        ));
        assert_eq!(sync.pre_sync_discarded(), 0);
        // FU-A start of IDR locks immediately
        let mut idr_fu = vec![(IDR[0] & 0xE0) | 28, 0x80 | 5];
        idr_fu.extend_from_slice(&IDR[1..]);
        let idr_pkt = rtp(4, 9000, false, 7, 96, &idr_fu);
        match sync.observe(0, &idr_pkt, 13, 13, 7)? {
            H264SyncOutcome::Synced { sps, pps, primer } => {
                assert_eq!(sps.nal_bytes(), SPS);
                assert_eq!(pps.nal_bytes(), PPS);
                assert_eq!(primer.expect("primer").sequence, 3);
            }
            H264SyncOutcome::Awaiting => panic!("expected FU-A IDR sync"),
        }
        Ok(())
    }

    #[test]
    fn h264_inband_sync_fails_closed_on_packet_byte_and_time_budgets() -> Result<(), H264InbandError>
    {
        // Packet budget
        let mut by_packets = H264InbandSync::new(
            96,
            H264Mode::NonInterleaved,
            PacketLimits::default(),
            AvcSyntaxLimits::default(),
            InbandSyncLimits {
                max_packets: 2,
                max_bytes: 65_536,
                max_duration_ns: 5_000_000_000,
            },
        )?;
        assert!(matches!(
            by_packets.observe(0, &rtp(1, 9000, true, 7, 96, P_SLICE), 1, 1, 7)?,
            H264SyncOutcome::Awaiting
        ));
        assert!(matches!(
            by_packets.observe(0, &rtp(2, 12600, true, 7, 96, P_SLICE), 2, 2, 7)?,
            H264SyncOutcome::Awaiting
        ));
        assert!(matches!(
            by_packets.observe(0, &rtp(3, 16200, true, 7, 96, P_SLICE), 3, 3, 7),
            Err(H264InbandError::BudgetPackets)
        ));

        // Byte budget
        let mut by_bytes = H264InbandSync::new(
            96,
            H264Mode::NonInterleaved,
            PacketLimits::default(),
            AvcSyntaxLimits::default(),
            InbandSyncLimits {
                max_packets: 64,
                max_bytes: 20,
                max_duration_ns: 5_000_000_000,
            },
        )?;
        let pkt = rtp(1, 9000, true, 7, 96, P_SLICE); // 17 bytes
        assert!(matches!(
            by_bytes.observe(0, &pkt, 1, 1, 7)?,
            H264SyncOutcome::Awaiting
        ));
        assert!(matches!(
            by_bytes.observe(0, &rtp(2, 12600, true, 7, 96, P_SLICE), 2, 2, 7),
            Err(H264InbandError::BudgetBytes)
        ));

        // Time budget
        let mut by_time = H264InbandSync::new(
            96,
            H264Mode::NonInterleaved,
            PacketLimits::default(),
            AvcSyntaxLimits::default(),
            InbandSyncLimits {
                max_packets: 64,
                max_bytes: 65_536,
                max_duration_ns: 1_000,
            },
        )?;
        by_time.start(100);
        assert!(by_time.is_expired(1_100));
        assert!(matches!(
            by_time.observe(0, &pkt, 1_100, 1_100, 7),
            Err(H264InbandError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn h265_inband_sync_tracks_pre_sync_discards_and_budget() -> Result<(), H265InbandError> {
        use fss_packet::{ReorderLimits, ReorderPoll, RtpReorderBuffer};
        let mut sync = H265InbandSync::new(
            PacketLimits::default(),
            HevcConfigurationLimits::default(),
            InbandSyncLimits {
                max_packets: 2,
                max_bytes: 65_536,
                max_duration_ns: 5_000_000_000,
            },
            None,
            None,
            None,
        )?;
        let key = StreamKey {
            ingress: 1,
            generation: 1,
            ssrc: 7,
        };
        let trail_r = [0x02, 0x01, 0xAA, 0xBB]; // NAL type 1 (TRAIL_R)
        let mut reorder = RtpReorderBuffer::new(key, 98, ReorderLimits::default())
            .expect("valid default reorder limits");
        // Prime probation with seq 1, then produce ordered seq 2, 3, 4.
        let mut ordered = Vec::new();
        for seq in 1..=4u16 {
            let now = u64::from(seq) * 10;
            let bytes = rtp(seq, 9000 + u32::from(seq) * 3600, true, 7, 98, &trail_r);
            let _ = reorder.ingest(key, &bytes, now).expect("ingest");
            while let Ok(ReorderPoll::Packet(pkt)) = reorder.poll(now) {
                ordered.push(pkt);
            }
        }
        assert_eq!(ordered.len(), 3);
        assert!(matches!(
            sync.observe(&ordered[0], 20)?,
            H265SyncOutcome::Awaiting
        ));
        assert!(matches!(
            sync.observe(&ordered[1], 30)?,
            H265SyncOutcome::Awaiting
        ));
        assert_eq!(sync.pre_sync_discarded(), 2);
        assert!(matches!(
            sync.observe(&ordered[2], 40),
            Err(H265InbandError::BudgetPackets)
        ));
        Ok(())
    }
}
