#![forbid(unsafe_code)]
//! Canonical packet replay object format (FSS-116).
//!
//! A packet replay object captures ONE owner-authorized media stream's
//! packet arrival truth — data packets in exact wire arrival order (so
//! reordering replays faithfully), explicit loss intervals for gaps the
//! capture observed, and explicit duplicate-arrival markers — inside a
//! self-verifying durable envelope built on the canonical durable-format
//! framework (FSS-109): magic `FSPR`, version 1, big-endian, SHA-256
//! trailer over header and payload, hard payload bound.
//!
//! Determinism contract: the object bytes are a pure function of the
//! record sequence; identical inputs yield byte-identical objects and
//! therefore identical content digests. Readers verify every byte before
//! exposing anything and refuse malformed, truncated, checksum-diverged,
//! or over-limit envelopes with typed errors.
//!
//! This crate parses supplied bytes and emits canonical objects; it
//! performs no I/O, authenticates no sender, and does not turn replayed
//! acceptance into continuity or capture truth (the owning adapter and
//! receiver state machines do that, deterministically, from this input).

use fss_core::durable::{DurableError, DurableFormat};

/// Magic bytes of the packet replay object format.
pub const PACKET_REPLAY_MAGIC: &[u8] = b"FSPR";
/// Current format version.
pub const PACKET_REPLAY_VERSION: u32 = 1;
/// Hard bound on the encoded payload (header + records), 64 MiB.
pub const MAX_REPLAY_PAYLOAD_LEN: usize = 64 * 1024 * 1024;
/// Hard bound on records in one object.
pub const MAX_REPLAY_RECORDS: usize = 1 << 20;
/// Hard bound on one packet payload.
pub const MAX_PACKET_PAYLOAD_LEN: usize = 1 << 16;
/// Stream header length: ssrc(4) + payload_type(1) + clock_rate(4) +
/// record_count(8) + loss_count(8) + dup_count(8).
const STREAM_HEADER_LEN: usize = 4 + 1 + 4 + 8 + 8 + 8;

/// The canonical durable envelope for packet replay objects.
#[must_use]
pub fn packet_replay_format() -> DurableFormat {
    DurableFormat::canonical(
        PACKET_REPLAY_MAGIC,
        PACKET_REPLAY_VERSION,
        MAX_REPLAY_PAYLOAD_LEN,
    )
}

/// One replay record: an arrival, an observed loss interval, or a
/// duplicate-arrival marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayRecord {
    /// A data packet that arrived (in this exact position).
    Data {
        /// RTP sequence number.
        seq: u16,
        /// RTP timestamp in stream clock units.
        rtp_ts: u32,
        /// Packet payload bytes.
        payload: Vec<u8>,
    },
    /// An observed loss interval (half-open: `from_seq..to_seq`).
    Loss {
        /// First missing sequence number.
        from_seq: u16,
        /// One past the last missing sequence number.
        to_seq: u16,
    },
    /// A duplicate arrival of an already-seen sequence number.
    Duplicate {
        /// The sequence number that arrived again.
        seq: u16,
    },
}

/// Stream identity header carried at the payload head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayStreamHeader {
    /// Synchronization source.
    pub ssrc: u32,
    /// RTP payload type.
    pub payload_type: u8,
    /// Stream clock rate in Hz (e.g. 90_000).
    pub clock_rate_hz: u32,
}

/// Typed replay-format refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayFormatError {
    /// The durable envelope refused (magic, version, checksum, bounds).
    Envelope(String),
    /// The payload violated the canonical layout.
    Malformed(&'static str),
    /// A record exceeded a hard bound.
    OverLimit {
        /// Which limit.
        what: &'static str,
    },
}

impl std::fmt::Display for ReplayFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(detail) => write!(f, "envelope refusal: {detail}"),
            Self::Malformed(what) => write!(f, "malformed payload: {what}"),
            Self::OverLimit { what } => write!(f, "over limit: {what}"),
        }
    }
}

impl std::error::Error for ReplayFormatError {}

impl From<DurableError> for ReplayFormatError {
    fn from(e: DurableError) -> Self {
        Self::Envelope(format!("{e}"))
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReplayFormatError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ReplayFormatError::Malformed("length overflow"))?;
        if end > self.bytes.len() {
            return Err(ReplayFormatError::Malformed("truncated payload"));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ReplayFormatError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ReplayFormatError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, ReplayFormatError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, ReplayFormatError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
}

/// Encodes a canonical packet replay object. Deterministic: byte-identical
/// output for identical `(header, records)` input.
pub fn encode_replay(
    header: ReplayStreamHeader,
    records: &[ReplayRecord],
) -> Result<Vec<u8>, ReplayFormatError> {
    if records.len() > MAX_REPLAY_RECORDS {
        return Err(ReplayFormatError::OverLimit {
            what: "record count",
        });
    }
    let mut payload = Vec::with_capacity(STREAM_HEADER_LEN + records.len() * 12);
    put_u32(&mut payload, header.ssrc);
    payload.push(header.payload_type);
    put_u32(&mut payload, header.clock_rate_hz);
    put_u64(&mut payload, records.len() as u64);
    let losses = records
        .iter()
        .filter(|r| matches!(r, ReplayRecord::Loss { .. }))
        .count() as u64;
    let dups = records
        .iter()
        .filter(|r| matches!(r, ReplayRecord::Duplicate { .. }))
        .count() as u64;
    put_u64(&mut payload, losses);
    put_u64(&mut payload, dups);
    for record in records {
        match record {
            ReplayRecord::Data {
                seq,
                rtp_ts,
                payload: bytes,
            } => {
                if bytes.len() > MAX_PACKET_PAYLOAD_LEN {
                    return Err(ReplayFormatError::OverLimit {
                        what: "packet payload",
                    });
                }
                payload.push(1);
                put_u16(&mut payload, *seq);
                put_u32(&mut payload, *rtp_ts);
                put_u32(&mut payload, bytes.len() as u32);
                payload.extend_from_slice(bytes);
            }
            ReplayRecord::Loss { from_seq, to_seq } => {
                if to_seq.wrapping_sub(*from_seq) == 0
                    || to_seq.wrapping_sub(*from_seq) > u16::MAX / 2
                {
                    return Err(ReplayFormatError::Malformed(
                        "empty or implausible loss interval",
                    ));
                }
                payload.push(2);
                put_u16(&mut payload, *from_seq);
                put_u16(&mut payload, *to_seq);
            }
            ReplayRecord::Duplicate { seq } => {
                payload.push(3);
                put_u16(&mut payload, *seq);
            }
        }
    }
    if payload.len() > MAX_REPLAY_PAYLOAD_LEN {
        return Err(ReplayFormatError::OverLimit {
            what: "payload length",
        });
    }
    packet_replay_format()
        .encode(&payload)
        .map_err(ReplayFormatError::from)
}

/// The decoded contents of a verified packet replay object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketReplay {
    /// Stream identity.
    pub header: ReplayStreamHeader,
    /// Records in exact encoded (arrival) order.
    pub records: Vec<ReplayRecord>,
}

/// Decodes and fully verifies a packet replay object: envelope (magic,
/// version, checksum, bounds) then canonical payload layout. Refuses any
/// drift with typed errors; never exposes partial contents.
pub fn decode_replay(raw: &[u8]) -> Result<PacketReplay, ReplayFormatError> {
    let payload = packet_replay_format().decode(raw)?.to_payload_vec();
    if payload.len() < STREAM_HEADER_LEN {
        return Err(ReplayFormatError::Malformed(
            "payload shorter than the stream header",
        ));
    }
    let mut r = Reader {
        bytes: &payload,
        pos: 0,
    };
    let header = ReplayStreamHeader {
        ssrc: r.u32()?,
        payload_type: r.u8()?,
        clock_rate_hz: r.u32()?,
    };
    let record_count = r.u64()? as usize;
    let loss_count = r.u64()?;
    let dup_count = r.u64()?;
    if record_count > MAX_REPLAY_RECORDS {
        return Err(ReplayFormatError::OverLimit {
            what: "record count",
        });
    }
    let mut records = Vec::with_capacity(record_count.min(1024));
    let mut losses = 0u64;
    let mut dups = 0u64;
    for _ in 0..record_count {
        let kind = r.u8()?;
        let record = match kind {
            1 => {
                let seq = r.u16()?;
                let rtp_ts = r.u32()?;
                let len = r.u32()? as usize;
                if len > MAX_PACKET_PAYLOAD_LEN {
                    return Err(ReplayFormatError::OverLimit {
                        what: "packet payload",
                    });
                }
                let bytes = r.take(len)?.to_vec();
                ReplayRecord::Data {
                    seq,
                    rtp_ts,
                    payload: bytes,
                }
            }
            2 => {
                losses += 1;
                let from_seq = r.u16()?;
                let to_seq = r.u16()?;
                // Canonical-form enforcement on read: a hand-crafted payload
                // (writer bypass) must not smuggle an empty or implausible
                // interval past the reader.
                if to_seq.wrapping_sub(from_seq) == 0
                    || to_seq.wrapping_sub(from_seq) > u16::MAX / 2
                {
                    return Err(ReplayFormatError::Malformed(
                        "empty or implausible loss interval",
                    ));
                }
                ReplayRecord::Loss { from_seq, to_seq }
            }
            3 => {
                dups += 1;
                let seq = r.u16()?;
                ReplayRecord::Duplicate { seq }
            }
            _ => return Err(ReplayFormatError::Malformed("unknown record kind")),
        };
        records.push(record);
    }
    if r.pos != payload.len() {
        return Err(ReplayFormatError::Malformed("trailing payload bytes"));
    }
    if losses != loss_count || dups != dup_count {
        return Err(ReplayFormatError::Malformed("count mismatch"));
    }
    Ok(PacketReplay { header, records })
}
