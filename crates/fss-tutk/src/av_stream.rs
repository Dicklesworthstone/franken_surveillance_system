//! Buffered camera→client ApplicationData stream parser.
//!
//! Dispatch model live-proven against go2rtc's worker loop and mirrored from
//! the Python reference `AVStreamParser`: messages are identified by the lead
//! u16 (LE) — `0x0009` ACK (24 B), `0x2100` login response (24 + u32 payload
//! size @16), `0x000C`/`0x7000` IOCTRL (HL scanned from offset 32), `0x1000`
//! channel message (HL from offset 36 when `[16]==0`, else a fixed 36-byte
//! status), and AV packets by channel byte `0x03`/`0x05`/`0x07`. Undecodable
//! leads resync by dropping one byte (counted, never silent) — but a buffer
//! that could still be a valid *prefix* (a partial "HL" in the unscanned
//! tail) always waits for more data instead of dropping.
//!
//! Buffer management is cursor-based: consumption and resync advance a head
//! index with periodic compaction, so adversarial garbage costs O(n) total,
//! never O(n²) front-removals. The hard cap is admitted before allocation.

use crate::av::{
    self, AvError, AvLoginResponse, AvPacket, CHANNEL_AUDIO, CHANNEL_I_VIDEO, CHANNEL_P_VIDEO,
    MAGIC_ACK, MAGIC_AV_LOGIN_RESP, MAGIC_IOCTRL,
};

/// Hard cap on buffered undispatched bytes (bound on memory per stream).
pub const STREAM_BUFFER_MAX: usize = 1 << 20;
/// Compact when the consumed prefix exceeds this many bytes.
const COMPACT_MIN_HEAD: usize = 64 << 10;

/// One parsed stream message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMsg {
    /// 24-byte camera ACK of our messages (raw frame).
    Ack([u8; 24]),
    /// 0x2100 AV login response.
    LoginResp(AvLoginResponse),
    /// IOCTRL/carried HL message: (hl_cmd, hl_payload, wrapper_seq).
    Ioctrl(u16, Vec<u8>, u16),
    /// 36-byte channel status/heartbeat (raw frame, wrapper_seq).
    ChanMsg([u8; 36], u16),
    /// One AV packet (header + payload, FRAMEINFO already classified).
    Packet(AvPacket),
}

/// Errors that reject the whole datagram (per-message resync is internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// Buffer cap would be exceeded by the next feed; stream must reset.
    Overflow,
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StreamError::Overflow => write!(f, "stream buffer overflow without progress"),
        }
    }
}

impl std::error::Error for StreamError {}

/// Buffered dispatcher over decrypted DTLS ApplicationData.
#[derive(Debug, Default)]
pub struct AvStreamParser {
    buf: Vec<u8>,
    head: usize,
    dropped_bytes: u64,
}

impl AvStreamParser {
    /// New empty parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes dropped by resync since creation (monotone).
    #[must_use]
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    /// Buffered undispatched bytes right now.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.head
    }

    fn view(&self) -> &[u8] {
        &self.buf[self.head..]
    }

    fn consume(&mut self, n: usize) {
        self.head += n;
        if self.head >= COMPACT_MIN_HEAD && self.head * 2 >= self.buf.len() {
            self.buf.drain(..self.head);
            self.head = 0;
        }
    }

    /// Feed decrypted ApplicationData; emit every complete message.
    ///
    /// Message-level parse failures resync by dropping one byte (matching the
    /// live-proven Python behavior) unless the buffer could still be a valid
    /// prefix; a feed that would exceed the hard cap is refused before any
    /// allocation.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<StreamMsg>, StreamError> {
        if self.buffered() + data.len() > STREAM_BUFFER_MAX {
            // parse what we already hold first; refuse only if still over
            let out = self.drain_complete();
            if self.buffered() + data.len() > STREAM_BUFFER_MAX {
                return Err(StreamError::Overflow);
            }
            self.buf.extend_from_slice(data);
            let mut rest = self.drain_complete();
            if out.is_empty() {
                return Ok(rest);
            }
            let mut all = out;
            all.append(&mut rest);
            return Ok(all);
        }
        self.buf.extend_from_slice(data);
        Ok(self.drain_complete())
    }

    fn drain_complete(&mut self) -> Vec<StreamMsg> {
        let mut out = Vec::new();
        loop {
            if self.view().len() < 2 {
                break;
            }
            match self.dispatch_one(&mut out) {
                Dispatch::Consumed => {}
                Dispatch::NeedMore => break,
                Dispatch::Resync => {
                    self.consume(1);
                    self.dropped_bytes += 1;
                }
            }
        }
        out
    }

    fn dispatch_one(&mut self, out: &mut Vec<StreamMsg>) -> Dispatch {
        let view = self.view();
        let magic = u16::from_le_bytes([view[0], view[1]]);
        match magic {
            MAGIC_ACK => {
                if view.len() < 24 {
                    return Dispatch::NeedMore;
                }
                let mut raw = [0u8; 24];
                raw.copy_from_slice(&view[..24]);
                out.push(StreamMsg::Ack(raw));
                self.consume(24);
                Dispatch::Consumed
            }
            MAGIC_AV_LOGIN_RESP => {
                if view.len() < 20 {
                    return Dispatch::NeedMore;
                }
                let psize =
                    u32::from_le_bytes([view[16], view[17], view[18], view[19]]) as usize;
                if psize == 0 || psize > 4096 {
                    return Dispatch::Resync;
                }
                let total = 24 + psize;
                if view.len() < total {
                    return Dispatch::NeedMore;
                }
                match av::parse_av_login_response(&view[..total]) {
                    Ok(resp) => {
                        out.push(StreamMsg::LoginResp(resp));
                        self.consume(total);
                        Dispatch::Consumed
                    }
                    Err(_) => Dispatch::Resync,
                }
            }
            m if m == 0x000C || m == MAGIC_IOCTRL => {
                if view.len() < 48 {
                    return Dispatch::NeedMore;
                }
                match self.find_hl(32) {
                    Scan::Found(hl_off, total) => {
                        let view = self.view();
                        let cmd = u16::from_le_bytes([view[hl_off + 4], view[hl_off + 5]]);
                        let payload = view[hl_off + 16..total].to_vec();
                        let wseq = u16::from_le_bytes([view[4], view[5]]);
                        out.push(StreamMsg::Ioctrl(cmd, payload, wseq));
                        self.consume(total);
                        Dispatch::Consumed
                    }
                    Scan::Incomplete => Dispatch::NeedMore,
                    Scan::Absent => {
                        if self.tail_could_start_hl(32) {
                            Dispatch::NeedMore
                        } else {
                            Dispatch::Resync
                        }
                    }
                }
            }
            0x1000 => {
                if view.len() < 36 {
                    return Dispatch::NeedMore;
                }
                if view[16] == 0 {
                    match self.find_hl(36) {
                        Scan::Found(hl_off, total) => {
                            let view = self.view();
                            let cmd = u16::from_le_bytes([view[hl_off + 4], view[hl_off + 5]]);
                            let payload = view[hl_off + 16..total].to_vec();
                            let wseq = u16::from_le_bytes([view[4], view[5]]);
                            out.push(StreamMsg::Ioctrl(cmd, payload, wseq));
                            self.consume(total);
                            return Dispatch::Consumed;
                        }
                        Scan::Incomplete => return Dispatch::NeedMore,
                        Scan::Absent => {
                            if self.tail_could_start_hl(36) {
                                return Dispatch::NeedMore;
                            }
                            return Dispatch::Resync;
                        }
                    }
                }
                let mut raw = [0u8; 36];
                raw.copy_from_slice(&view[..36]);
                let wseq = u16::from_le_bytes([view[4], view[5]]);
                out.push(StreamMsg::ChanMsg(raw, wseq));
                self.consume(36);
                Dispatch::Consumed
            }
            _ if matches!(view[0], CHANNEL_AUDIO | CHANNEL_I_VIDEO | CHANNEL_P_VIDEO) => {
                match av::parse_av_packet(view) {
                    Ok(pkt) => {
                        let total = pkt.total;
                        out.push(StreamMsg::Packet(pkt));
                        self.consume(total);
                        Dispatch::Consumed
                    }
                    Err(AvError::NeedMoreData) => Dispatch::NeedMore,
                    Err(_) => Dispatch::Resync,
                }
            }
            _ => Dispatch::Resync,
        }
    }

    /// go2rtc FindHL: scan for "HL" from `offset`; total = hl_off + 16 + plen.
    fn find_hl(&self, offset: usize) -> Scan {
        let view = self.view();
        if view.len() < offset + 2 {
            return Scan::Absent;
        }
        let scan_end = view.len().saturating_sub(15);
        for i in offset..scan_end {
            if view[i] == 0x48 && view[i + 1] == 0x4C {
                let plen = u16::from_le_bytes([view[i + 6], view[i + 7]]) as usize;
                let total = i + 16 + plen;
                return if view.len() >= total {
                    Scan::Found(i, total)
                } else {
                    Scan::Incomplete
                };
            }
        }
        Scan::Absent
    }

    /// Could the unscanned tail (positions the 16-byte HL window can't fully
    /// cover yet) still begin a valid "HL" marker? Only then is waiting
    /// honest; otherwise the frame is definitively malformed.
    fn tail_could_start_hl(&self, offset: usize) -> bool {
        let view = self.view();
        let tail_start = view.len().saturating_sub(15).max(offset);
        view[tail_start.min(view.len())..].contains(&0x48)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dispatch {
    Consumed,
    NeedMore,
    Resync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    Found(usize, usize),
    Incomplete,
    Absent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::av::{build_hl, build_ioctrl};

    #[test]
    fn ack_and_login_dispatch() {
        let mut p = AvStreamParser::new();
        let mut wire = crate::av::build_ack(7, 1, 2, 3, 99);
        let mut login = vec![0u8; 44];
        login[0..2].copy_from_slice(&MAGIC_AV_LOGIN_RESP.to_le_bytes());
        login[4] = 0x10;
        login[16..20].copy_from_slice(&20u32.to_le_bytes()); // psize=20 -> total 44
        wire.extend_from_slice(&login);
        let msgs = p.feed(&wire).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(msgs[0], StreamMsg::Ack(_)));
        assert!(matches!(&msgs[1], StreamMsg::LoginResp(r) if r.success));
    }

    #[test]
    fn ioctrl_dispatch_and_wseq() {
        let mut p = AvStreamParser::new();
        let hl = build_hl(10001, b"\x03abcdefghijklmnop");
        let frame = build_ioctrl(0x1234, 2, &hl);
        let msgs = p.feed(&frame).unwrap();
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            StreamMsg::Ioctrl(cmd, payload, wseq) => {
                assert_eq!(*cmd, 10001);
                assert_eq!(payload, b"\x03abcdefghijklmnop");
                assert_eq!(*wseq, 0x1234);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn resync_counts_dropped_bytes() {
        let mut p = AvStreamParser::new();
        let mut wire = vec![0xAA, 0xBB, 0xCC];
        wire.extend_from_slice(&crate::av::build_ack(1, 0, 0, 1, 0));
        let msgs = p.feed(&wire).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(p.dropped_bytes() >= 3);
    }

    #[test]
    fn fragmented_delivery_reassembles() {
        let mut p = AvStreamParser::new();
        let hl = build_hl(10010, b"\x01\x01");
        let frame = build_ioctrl(9, 0, &hl);
        let (a, b) = frame.split_at(17);
        assert!(p.feed(a).unwrap().is_empty());
        let msgs = p.feed(b).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(msgs[0], StreamMsg::Ioctrl(10010, _, 9)));
    }

    /// Every split position of a valid IOCTRL frame must deliver exactly one
    /// event with exact fields and zero dropped bytes (review finding: the
    /// 48..55-byte prefix window must wait, never resync).
    #[test]
    fn all_split_positions_preserve_valid_frames() {
        for plen in [0usize, 1, 3, 17, 64] {
            let payload = vec![0x5Au8; plen];
            let hl = build_hl(10001, &payload);
            let frame = build_ioctrl(0xBEEF, 3, &hl);
            for cut in 0..frame.len() {
                let mut p = AvStreamParser::new();
                let (a, b) = frame.split_at(cut);
                let mut msgs = p.feed(a).unwrap();
                msgs.extend(p.feed(b).unwrap());
                assert_eq!(msgs.len(), 1, "cut={cut} plen={plen}");
                match &msgs[0] {
                    StreamMsg::Ioctrl(cmd, got, wseq) => {
                        assert_eq!(*cmd, 10001, "cut={cut} plen={plen}");
                        assert_eq!(got, &payload, "cut={cut} plen={plen}");
                        assert_eq!(*wseq, 0xBEEF, "cut={cut} plen={plen}");
                    }
                    other => panic!("cut={cut} plen={plen}: unexpected {other:?}"),
                }
                assert_eq!(p.dropped_bytes(), 0, "cut={cut} plen={plen}");
            }
        }
    }

    /// Adversarial garbage must cost linear time (cursor, not O(n^2) pops)
    /// and count every resynced byte.
    #[test]
    fn garbage_stream_resyncs_in_linear_time() {
        let mut p = AvStreamParser::new();
        let garbage = vec![0xEEu8; 200_000];
        let start = std::time::Instant::now();
        let msgs = p.feed(&garbage).unwrap();
        assert!(msgs.is_empty());
        // 199_999 resynced; the final lone byte is retained — it could be the
        // first byte of a valid message (cannot classify under 2 bytes).
        assert_eq!(p.dropped_bytes(), 199_999);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "resync took {:?}",
            start.elapsed()
        );
        assert_eq!(p.buffered(), 1);
    }

    /// The hard cap is admitted before allocation: a feed that would exceed
    /// it errors without growing the buffer.
    #[test]
    fn overflow_is_refused_before_allocation() {
        let mut p = AvStreamParser::new();
        let big = vec![0xEEu8; STREAM_BUFFER_MAX / 2];
        p.feed(&big).unwrap();
        let before = p.buffered();
        let over = vec![0xEEu8; STREAM_BUFFER_MAX];
        assert!(matches!(p.feed(&over), Err(StreamError::Overflow)));
        assert_eq!(p.buffered(), before, "refused feed must not grow buffer");
    }
}
