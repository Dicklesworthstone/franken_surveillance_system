//! TUTK/IOTC OLD-protocol (pre-`0xCC51`) LAN-search probe: the byte-exact
//! `0x0601` probe frame, the TransCodePartial cipher, and the `0x0602`
//! response parser.
//!
//! Cipher verified by the CuboAI project against the native TUTK library
//! (40k+ fuzz buffers); the byte-level Python oracle is the interop lab's
//! `tutk_discover.py` (LAB-2026-10-07-002). Credential-less discovery only —
//! no session is established. Owner-authorized LAN scope per the lab charter.
//!
//! Live truth (2026-10-07, owner LAN): Wyze NEW-protocol firmware absorbs
//! these probes without answering; the probe is retained for older-firmware
//! Wyze and other TUTK brands (CuboAI, Shenzhen IPCs).

/// TransCodePartial key: first 16 bytes of "Charlie is the designer of P2P!!".
pub const K16: &[u8; 16] = b"Charlie is the d";

const LS_HEAD16: [u8; 16] = [
    0x04, 0x02, 0x1a, 0x02, 0x48, 0x00, 0x00, 0x00, 0x01, 0x06, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const LS_MID8: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x04];
const LS_TRAILER8: [u8; 8] = [0x63, 0x04, 0x13, 0x13, 0x04, 0x0c, 0x0c, 0x63];

#[inline]
fn ror32(v: u32, r: u32) -> u32 {
    v.rotate_right(r & 31)
}

#[inline]
fn rol32(v: u32, r: u32) -> u32 {
    v.rotate_left(r & 31)
}

fn tail_swap(buf: &[u8]) -> Vec<u8> {
    let perm: &[usize] = match buf.len() {
        2 => &[1, 0],
        4 => &[2, 3, 0, 1],
        8 => &[7, 4, 3, 2, 1, 6, 5, 0],
        _ => return buf.to_vec(),
    };
    perm.iter().map(|&j| buf[j]).collect()
}

fn block_transform(blk: &[u8]) -> [u8; 16] {
    let k = [
        u32::from_le_bytes([K16[0], K16[1], K16[2], K16[3]]),
        u32::from_le_bytes([K16[4], K16[5], K16[6], K16[7]]),
        u32::from_le_bytes([K16[8], K16[9], K16[10], K16[11]]),
        u32::from_le_bytes([K16[12], K16[13], K16[14], K16[15]]),
    ];
    let w = [
        u32::from_le_bytes([blk[0], blk[1], blk[2], blk[3]]),
        u32::from_le_bytes([blk[4], blk[5], blk[6], blk[7]]),
        u32::from_le_bytes([blk[8], blk[9], blk[10], blk[11]]),
        u32::from_le_bytes([blk[12], blk[13], blk[14], blk[15]]),
    ];
    let a = ror32(w[0], 1) ^ k[0];
    let b = ror32(w[1], 5) ^ k[1];
    let c = ror32(w[2], 9) ^ k[2];
    let d = ror32(w[3], 13) ^ k[3];
    let byte = |v: u32, i: u32| ((v >> (8 * i)) & 0xFF) as u32;
    let ecx = (byte(d, 2) << 24) | (byte(d, 0) << 16) | (byte(c, 2) << 8) | byte(d, 1);
    let r10 = (byte(a, 0) << 24) | (byte(b, 1) << 16) | (byte(a, 1) << 8) | byte(a, 2);
    let r8 = (byte(d, 3) << 24) | (byte(c, 0) << 16) | (byte(c, 1) << 8) | byte(c, 3);
    let r9 = (byte(a, 3) << 24) | (byte(b, 3) << 16) | (byte(b, 0) << 8) | byte(b, 2);
    let out = [ror32(r8, 3), ror32(ecx, 7), ror32(r10, 11), ror32(r9, 15)];
    let mut bytes = [0u8; 16];
    for (i, w) in out.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    bytes
}

fn inv_block_transform(blk: &[u8]) -> [u8; 16] {
    let k = [
        u32::from_le_bytes([K16[0], K16[1], K16[2], K16[3]]),
        u32::from_le_bytes([K16[4], K16[5], K16[6], K16[7]]),
        u32::from_le_bytes([K16[8], K16[9], K16[10], K16[11]]),
        u32::from_le_bytes([K16[12], K16[13], K16[14], K16[15]]),
    ];
    let o = [
        u32::from_le_bytes([blk[0], blk[1], blk[2], blk[3]]),
        u32::from_le_bytes([blk[4], blk[5], blk[6], blk[7]]),
        u32::from_le_bytes([blk[8], blk[9], blk[10], blk[11]]),
        u32::from_le_bytes([blk[12], blk[13], blk[14], blk[15]]),
    ];
    let r8 = rol32(o[0], 3);
    let ecx = rol32(o[1], 7);
    let r10 = rol32(o[2], 11);
    let r9 = rol32(o[3], 15);
    let byte = |v: u32, i: u32| ((v >> (8 * i)) & 0xFF) as u32;
    let (d2, d0, c2, d1) = (byte(ecx, 3), byte(ecx, 2), byte(ecx, 1), byte(ecx, 0));
    let (a0, b1, a1, a2) = (byte(r10, 3), byte(r10, 2), byte(r10, 1), byte(r10, 0));
    let (d3, c0, c1, c3) = (byte(r8, 3), byte(r8, 2), byte(r8, 1), byte(r8, 0));
    let (a3, b3, b0, b2) = (byte(r9, 3), byte(r9, 2), byte(r9, 1), byte(r9, 0));
    let a = a0 | (a1 << 8) | (a2 << 16) | (a3 << 24);
    let b = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    let c = c0 | (c1 << 8) | (c2 << 16) | (c3 << 24);
    let d = d0 | (d1 << 8) | (d2 << 16) | (d3 << 24);
    let out = [rol32(a ^ k[0], 1), rol32(b ^ k[1], 5), rol32(c ^ k[2], 9), rol32(d ^ k[3], 13)];
    let mut bytes = [0u8; 16];
    for (i, w) in out.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    bytes
}

/// TransCodePartial forward transform. `swap_tail` applies the length-keyed
/// tail permutation (data-channel frames; search frames never swap).
#[must_use]
pub fn transcode(plain: &[u8], swap_tail: bool) -> Vec<u8> {
    let full = plain.len() - (plain.len() & 0xF);
    let mut out = Vec::with_capacity(plain.len());
    for off in (0..full).step_by(16) {
        out.extend_from_slice(&block_transform(&plain[off..off + 16]));
    }
    let tl = plain.len() - full;
    if tl > 0 {
        let mut t: Vec<u8> = (0..tl).map(|i| K16[i] ^ plain[full + i]).collect();
        if swap_tail {
            t = tail_swap(&t);
        }
        out.extend_from_slice(&t);
    }
    out
}

/// Inverse TransCodePartial. `search_frame` = true for search/broadcast
/// frames (tail is plain XOR on the wire; cuboai-verified); data-channel
/// frames need false to undo the swap.
#[must_use]
pub fn inv_transcode(wire: &[u8], search_frame: bool) -> Vec<u8> {
    let full = wire.len() - (wire.len() & 0xF);
    let mut out = Vec::with_capacity(wire.len());
    for off in (0..full).step_by(16) {
        out.extend_from_slice(&inv_block_transform(&wire[off..off + 16]));
    }
    let tl = wire.len() - full;
    if tl > 0 {
        let tail = if search_frame {
            &wire[full..]
        } else {
            &tail_swap(&wire[full..])
        };
        out.extend((0..tl).map(|i| K16[i] ^ tail[i]));
    }
    out
}

/// Build the 88-byte `0x0601` LAN-search probe (empty UID = all devices
/// respond). The fingerprint is caller-chosen; cameras do not validate it.
#[must_use]
pub fn build_probe(uid: &[u8], r: u16, fingerprint: [u8; 6]) -> Vec<u8> {
    let mut t = [0u8; 88];
    t[0..16].copy_from_slice(&LS_HEAD16);
    let n = uid.len().min(32);
    t[16..16 + n].copy_from_slice(&uid[..n]);
    t[48..56].copy_from_slice(&LS_MID8);
    t[56..58].copy_from_slice(&r.to_le_bytes());
    t[58..64].copy_from_slice(&fingerprint);
    t[64] = 0x01;
    t[80..88].copy_from_slice(&LS_TRAILER8);
    transcode(&t, false)
}

/// Parsed probe response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResponse {
    /// NEW-protocol (`0xCC51`) packet — not an OLD-protocol answer.
    NewProto { cmd: u16 },
    /// OLD-protocol answer after inverse TransCode.
    Old {
        /// Command word (0x0602 = LAN-search answer).
        cmd: u16,
        /// Device UID (NUL-trimmed, 20 chars when present).
        uid: String,
        /// Stage byte at [64] when the frame is full-length.
        stage: Option<u8>,
    },
    /// Too short to classify after inverse transform.
    Malformed,
}

/// Parse a datagram received in response to the probe.
#[must_use]
pub fn parse_response(data: &[u8]) -> ProbeResponse {
    if data.len() >= 2 && data[0..2] == [0x51, 0xCC] {
        let cmd = if data.len() >= 6 {
            u16::from_le_bytes([data[4], data[5]])
        } else {
            0
        };
        return ProbeResponse::NewProto { cmd };
    }
    let plain = inv_transcode(data, true);
    if plain.len() < 16 {
        return ProbeResponse::Malformed;
    }
    let cmd = u16::from_le_bytes([plain[8], plain[9]]);
    let uid = if plain.len() >= 36 {
        let end = plain[16..36]
            .iter()
            .position(|&b| b == 0)
            .map(|p| 16 + p)
            .unwrap_or(36);
        String::from_utf8_lossy(&plain[16..end]).into_owned()
    } else {
        String::new()
    };
    let stage = (plain.len() >= 88).then(|| plain[64]);
    ProbeResponse::Old { cmd, uid, stage }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_lengths() {
        for len in [0usize, 1, 2, 4, 8, 15, 16, 17, 31, 32, 88, 255] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            for swap in [false, true] {
                let wire = transcode(&plain, swap);
                let back = inv_transcode(&wire, !swap);
                assert_eq!(back, plain, "len={len} swap={swap}");
            }
        }
    }

    #[test]
    fn probe_shape() {
        let p = build_probe(b"", 0x1234, [1, 2, 3, 4, 5, 6]);
        assert_eq!(p.len(), 88);
        let back = inv_transcode(&p, true);
        assert_eq!(&back[0..4], &LS_HEAD16[0..4]);
        assert_eq!(u16::from_le_bytes([back[56], back[57]]), 0x1234);
        assert_eq!(&back[58..64], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(back[64], 1);
        assert_eq!(&back[80..88], &LS_TRAILER8);
    }

    #[test]
    fn parse_newproto_marker() {
        let mut d = vec![0u8; 20];
        d[0] = 0x51;
        d[1] = 0xCC;
        d[4] = 0x02;
        d[5] = 0x12;
        assert!(matches!(parse_response(&d), ProbeResponse::NewProto { cmd: 0x1202 }));
    }
}
