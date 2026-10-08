//! Buffered camera→client ApplicationData stream parser.
//!
//! Dispatch model live-proven against go2rtc's worker loop and mirrored from
//! the Python reference `AVStreamParser`: messages are identified by the lead
//! u16 (LE) — `0x0009` ACK (24 B), `0x2100` login response (24 + u32 payload
//! size @16), `0x000C`/`0x7000` IOCTRL (HL scanned from offset 32), `0x1000`
//! channel message (HL from offset 36 when `[16]==0`, else a fixed 36-byte
//! status), and AV packets by channel byte `0x03`/`0x05`/`0x07`. Undecodable
//! leads resync by dropping one byte (counted, never silent).

use crate::av::{
    self, AvError, AvLoginResponse, AvPacket, CHANNEL_AUDIO, CHANNEL_I_VIDEO, CHANNEL_P_VIDEO,
    MAGIC_ACK, MAGIC_AV_LOGIN_RESP, MAGIC_IOCTRL,
};

/// Hard cap on buffered undispatched bytes (bound on memory per stream).
pub const STREAM_BUFFER_MAX: usize = 1 << 20;

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
    /// Buffer cap exceeded before any parse progress; stream must reset.
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
        self.buf.len()
    }

    /// Feed decrypted ApplicationData; emit every complete message.
    ///
    /// Message-level parse failures resync by dropping one byte (matching the
    /// live-proven Python behavior); only a full buffer with zero progress is
    /// an error.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<StreamMsg>, StreamError> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 2 {
                break;
            }
            match self.dispatch_one(&mut out) {
                Dispatch::Consumed => {}
                Dispatch::NeedMore => break,
                Dispatch::Resync => {
                    self.buf.remove(0);
                    self.dropped_bytes += 1;
                }
            }
        }
        if self.buf.len() > STREAM_BUFFER_MAX {
            return Err(StreamError::Overflow);
        }
        Ok(out)
    }

    fn dispatch_one(&mut self, out: &mut Vec<StreamMsg>) -> Dispatch {
        let magic = u16::from_le_bytes([self.buf[0], self.buf[1]]);
        match magic {
            MAGIC_ACK => {
                if self.buf.len() < 24 {
                    return self.need_more();
                }
                let mut raw = [0u8; 24];
                raw.copy_from_slice(&self.buf[..24]);
                out.push(StreamMsg::Ack(raw));
                self.buf.drain(..24);
                Dispatch::Consumed
            }
            MAGIC_AV_LOGIN_RESP => {
                if self.buf.len() < 20 {
                    return self.need_more();
                }
                let psize = u32::from_le_bytes([
                    self.buf[16],
                    self.buf[17],
                    self.buf[18],
                    self.buf[19],
                ]) as usize;
                if psize == 0 || psize > 4096 {
                    return Dispatch::Resync;
                }
                let total = 24 + psize;
                if self.buf.len() < total {
                    return self.need_more();
                }
                match av::parse_av_login_response(&self.buf[..total]) {
                    Ok(resp) => {
                        out.push(StreamMsg::LoginResp(resp));
                        self.buf.drain(..total);
                        Dispatch::Consumed
                    }
                    Err(_) => Dispatch::Resync,
                }
            }
            m if m == 0x000C || m == MAGIC_IOCTRL => {
                if self.buf.len() < 48 {
                    return self.need_more();
                }
                match self.find_hl(32) {
                    None => Dispatch::Resync,
                    Some((hl_off, None)) => {
                        let _ = hl_off;
                        self.need_more()
                    }
                    Some((hl_off, Some(total))) => {
                        let cmd = u16::from_le_bytes([self.buf[hl_off + 4], self.buf[hl_off + 5]]);
                        let payload = self.buf[hl_off + 16..total].to_vec();
                        let wseq = u16::from_le_bytes([self.buf[4], self.buf[5]]);
                        out.push(StreamMsg::Ioctrl(cmd, payload, wseq));
                        self.buf.drain(..total);
                        Dispatch::Consumed
                    }
                }
            }
            0x1000 => {
                if self.buf.len() < 36 {
                    return self.need_more();
                }
                if self.buf[16] == 0 {
                    match self.find_hl(36) {
                        Some((hl_off, Some(total))) => {
                            let cmd =
                                u16::from_le_bytes([self.buf[hl_off + 4], self.buf[hl_off + 5]]);
                            let payload = self.buf[hl_off + 16..total].to_vec();
                            let wseq = u16::from_le_bytes([self.buf[4], self.buf[5]]);
                            out.push(StreamMsg::Ioctrl(cmd, payload, wseq));
                            self.buf.drain(..total);
                            return Dispatch::Consumed;
                        }
                        Some((_hl_off, None)) => return self.need_more(),
                        None => return Dispatch::Resync,
                    }
                }
                let mut raw = [0u8; 36];
                raw.copy_from_slice(&self.buf[..36]);
                let wseq = u16::from_le_bytes([self.buf[4], self.buf[5]]);
                out.push(StreamMsg::ChanMsg(raw, wseq));
                self.buf.drain(..36);
                Dispatch::Consumed
            }
            _ if matches!(self.buf[0], CHANNEL_AUDIO | CHANNEL_I_VIDEO | CHANNEL_P_VIDEO) => {
                match av::parse_av_packet(&self.buf) {
                    Ok(pkt) => {
                        let total = pkt.total;
                        out.push(StreamMsg::Packet(pkt));
                        self.buf.drain(..total);
                        Dispatch::Consumed
                    }
                    Err(AvError::NeedMoreData) => self.need_more(),
                    Err(_) => Dispatch::Resync,
                }
            }
            _ => Dispatch::Resync,
        }
    }

    fn need_more(&self) -> Dispatch {
        Dispatch::NeedMore
    }

    /// go2rtc FindHL: scan for "HL" from `offset`; total = hl_off + 16 + plen.
    fn find_hl(&self, offset: usize) -> Option<(usize, Option<usize>)> {
        let buf = &self.buf;
        if buf.len() < offset + 16 {
            return None;
        }
        for i in offset..buf.len().saturating_sub(15) {
            if buf[i] == 0x48 && buf[i + 1] == 0x4C {
                let plen = u16::from_le_bytes([buf[i + 6], buf[i + 7]]) as usize;
                let total = i + 16 + plen;
                return Some((i, (buf.len() >= total).then_some(total)));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dispatch {
    Consumed,
    NeedMore,
    Resync,
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
}
