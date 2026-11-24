#![forbid(unsafe_code)]
//! Length-framed canonical binary wire transport with pre-allocation bounds and CRC32C checksums.
//!
//! Exact frame layout (network byte order / big-endian):
//! `[magic(4) = b"FSSI" | version(u16 = 1) | flags(u16) | payload_len(u32) | payload_bytes | crc32c(4)]`
//!
//! The 4-byte checksum is big-endian RFC 3720 CRC32C (Castagnoli, reflected polynomial
//! `0x82F63B78`) computed over `header_12_bytes || payload_bytes` with zero heap allocations.

use std::io::{self, IoSlice, Read, Write};

use crate::error::IpcError;

/// Four-byte wire framing magic prefix (`FSSI`).
pub const IPC_FRAME_MAGIC: [u8; 4] = *b"FSSI";

/// Current canonical IPC wire and handshake protocol version.
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// Fixed wire frame header length: `magic(4) + version(2) + flags(2) + payload_len(4)`.
pub const IPC_HEADER_BYTES: usize = 12;

/// Fixed trailing truncated SHA-256 checksum length in bytes.
pub const IPC_TRAILER_BYTES: usize = 4;

/// Total non-payload framing overhead (`16` bytes).
pub const IPC_FRAME_OVERHEAD_BYTES: usize = IPC_HEADER_BYTES + IPC_TRAILER_BYTES;

/// Hard maximum total wire frame size for client requests and handshakes (`64 KiB`).
pub const MAX_REQUEST_FRAME_BYTES: usize = 64 * 1024;

/// Hard maximum total wire frame size for daemon responses (`4 MiB`).
pub const MAX_RESPONSE_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Hard maximum payload length inside a request frame.
pub const MAX_REQUEST_PAYLOAD_BYTES: usize = MAX_REQUEST_FRAME_BYTES - IPC_FRAME_OVERHEAD_BYTES;

/// Hard maximum payload length inside a response frame.
pub const MAX_RESPONSE_PAYLOAD_BYTES: usize = MAX_RESPONSE_FRAME_BYTES - IPC_FRAME_OVERHEAD_BYTES;

const STACK_WRITE_FRAME_THRESHOLD: usize = 4096;

/// Typed 16-bit wire frame flag mask.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameFlags(u16);

impl FrameFlags {
    /// Handshake message frame (`HandshakeRequest` or `HandshakeResponse`).
    pub const HANDSHAKE: Self = Self(0x0001);
    /// Client request message frame (`IpcRequest`).
    pub const REQUEST: Self = Self(0x0002);
    /// Unary daemon response frame (`IpcResponse`).
    pub const RESPONSE: Self = Self(0x0004);
    /// Streaming daemon event or stream-end frame (`IpcResponse::DeltaEvent` / `StreamEnd`).
    pub const STREAM: Self = Self(0x0008);

    const KNOWN_MASK: u16 = Self::HANDSHAKE.0 | Self::REQUEST.0 | Self::RESPONSE.0 | Self::STREAM.0;

    /// Validates raw wire flags, failing closed on any unknown bit.
    pub const fn from_raw(raw: u16) -> Result<Self, u16> {
        if (raw & !Self::KNOWN_MASK) != 0 {
            Err(raw)
        } else {
            Ok(Self(raw))
        }
    }

    /// Returns the raw big-endian integer representation.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Combines two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true if all bits in `flag` are set.
    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

/// Decoded and checksum-verified wire frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFrame {
    /// Wire protocol version observed in the frame header.
    pub version: u16,
    /// Validated wire frame flags.
    pub flags: FrameFlags,
    /// Canonical payload bytes.
    pub payload: Vec<u8>,
    /// Exact total wire bytes occupied by header + payload + checksum.
    pub total_wire_bytes: usize,
}

/// Outcome of polling the first byte of a frame on a read stream with a short poll timeout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollFrame {
    /// A complete, checksum-verified frame was received.
    Frame(WireFrame),
    /// The read poll timed out cleanly before any bytes of the next frame arrived.
    IdleTimeout,
    /// The peer cleanly closed the stream at a frame boundary.
    Closed,
}

const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY_REFLECTED;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Updates an in-progress CRC32C (Castagnoli) accumulator over `bytes`.
#[must_use]
const fn crc32c_update(mut crc: u32, bytes: &[u8]) -> u32 {
    let mut idx = 0;
    while idx < bytes.len() {
        let entry = ((crc ^ (bytes[idx] as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[entry];
        idx += 1;
    }
    crc
}

/// Computes the standard RFC 3720 CRC32C (Castagnoli) checksum of `bytes`.
#[must_use]
pub const fn crc32c(bytes: &[u8]) -> u32 {
    !crc32c_update(0xFFFF_FFFF, bytes)
}

/// Computes the 4-byte big-endian CRC32C checksum over the 12-byte header and payload bytes.
pub fn compute_frame_checksum(
    header: &[u8; IPC_HEADER_BYTES],
    payload: &[u8],
) -> Result<[u8; 4], IpcError> {
    let crc = crc32c_update(0xFFFF_FFFF, header);
    let crc = !crc32c_update(crc, payload);
    Ok(crc.to_be_bytes())
}

/// Builds a 12-byte frame header in big-endian byte order.
#[must_use]
pub fn encode_frame_header(
    version: u16,
    flags: FrameFlags,
    payload_len: u32,
) -> [u8; IPC_HEADER_BYTES] {
    let mut header = [0_u8; IPC_HEADER_BYTES];
    header[0..4].copy_from_slice(&IPC_FRAME_MAGIC);
    header[4..6].copy_from_slice(&version.to_be_bytes());
    header[6..8].copy_from_slice(&flags.raw().to_be_bytes());
    header[8..12].copy_from_slice(&payload_len.to_be_bytes());
    header
}

/// Encodes a payload into a length-framed wire vector, checking hard bounds before allocation.
pub fn encode_frame_to_vec(
    flags: FrameFlags,
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<Vec<u8>, IpcError> {
    let total_len = checked_total_frame_len(payload.len(), max_frame_bytes)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| IpcError::FrameTooLarge {
        actual: total_len,
        limit: max_frame_bytes,
    })?;
    let header = encode_frame_header(IPC_PROTOCOL_VERSION, flags, payload_len);
    let checksum = compute_frame_checksum(&header, payload)?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// Decodes one exact frame from a complete byte slice, verifying bounds before copying payload.
pub fn decode_frame_from_slice(
    bytes: &[u8],
    max_frame_bytes: usize,
) -> Result<WireFrame, IpcError> {
    if bytes.len() < IPC_FRAME_OVERHEAD_BYTES {
        return Err(IpcError::InvalidFrame {
            reason: format!(
                "truncated frame: {} bytes is smaller than overhead {}",
                bytes.len(),
                IPC_FRAME_OVERHEAD_BYTES
            ),
        });
    }
    let header: [u8; IPC_HEADER_BYTES] =
        bytes[..IPC_HEADER_BYTES]
            .try_into()
            .map_err(|_| IpcError::InvalidFrame {
                reason: "failed to slice frame header".to_owned(),
            })?;
    let parsed = parse_and_validate_header(&header, max_frame_bytes)?;
    if bytes.len() < parsed.total_len {
        return Err(IpcError::InvalidFrame {
            reason: format!(
                "truncated frame body: expected {} bytes, got {}",
                parsed.total_len,
                bytes.len()
            ),
        });
    }
    if bytes.len() > parsed.total_len {
        return Err(IpcError::InvalidFrame {
            reason: format!(
                "trailing bytes after frame: expected {}, got {}",
                parsed.total_len,
                bytes.len()
            ),
        });
    }
    let payload_end = IPC_HEADER_BYTES + parsed.payload_len;
    let payload_slice = &bytes[IPC_HEADER_BYTES..payload_end];
    let declared_checksum: [u8; 4] =
        bytes[payload_end..parsed.total_len]
            .try_into()
            .map_err(|_| IpcError::InvalidFrame {
                reason: "failed to slice frame checksum".to_owned(),
            })?;
    let actual_checksum = compute_frame_checksum(&header, payload_slice)?;
    if declared_checksum != actual_checksum {
        return Err(IpcError::ChecksumMismatch {
            expected: declared_checksum,
            actual: actual_checksum,
        });
    }
    Ok(WireFrame {
        version: parsed.version,
        flags: parsed.flags,
        payload: payload_slice.to_vec(),
        total_wire_bytes: parsed.total_len,
    })
}

/// Writes a complete framed message to `writer` in a single syscall where possible.
pub fn write_frame<W: Write>(
    writer: &mut W,
    flags: FrameFlags,
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<usize, IpcError> {
    let total_len = checked_total_frame_len(payload.len(), max_frame_bytes)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| IpcError::FrameTooLarge {
        actual: total_len,
        limit: max_frame_bytes,
    })?;
    let header = encode_frame_header(IPC_PROTOCOL_VERSION, flags, payload_len);
    let checksum = compute_frame_checksum(&header, payload)?;

    if total_len <= STACK_WRITE_FRAME_THRESHOLD {
        let mut stack_buf = [0_u8; STACK_WRITE_FRAME_THRESHOLD];
        stack_buf[..IPC_HEADER_BYTES].copy_from_slice(&header);
        let payload_end = IPC_HEADER_BYTES + payload.len();
        stack_buf[IPC_HEADER_BYTES..payload_end].copy_from_slice(payload);
        stack_buf[payload_end..total_len].copy_from_slice(&checksum);
        write_all_checked(writer, &stack_buf[..total_len])?;
    } else {
        write_vectored_three(writer, &header, payload, &checksum)?;
    }
    writer.flush().map_err(map_write_io_error)?;
    Ok(total_len)
}

/// Reads a single complete framed message from `reader`, checking hard limits BEFORE allocation.
pub fn read_frame<R: Read>(reader: &mut R, max_frame_bytes: usize) -> Result<WireFrame, IpcError> {
    match poll_read_frame(reader, max_frame_bytes)? {
        PollFrame::Frame(frame) => Ok(frame),
        PollFrame::IdleTimeout => Err(IpcError::Timeout {
            operation: "read_frame",
        }),
        PollFrame::Closed => Err(IpcError::ConnectionClosed),
    }
}

/// Polls for a complete wire frame from `reader`.
///
/// If the stream times out BEFORE receiving any header byte, returns [`PollFrame::IdleTimeout`]
/// so a supervisor loop can inspect shutdown signals without tearing down an idle connection.
/// Once at least one header byte arrives, the remainder of the frame must complete or fail closed.
pub fn poll_read_frame<R: Read>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<PollFrame, IpcError> {
    let mut header = [0_u8; IPC_HEADER_BYTES];
    let initial_read = loop {
        match reader.read(&mut header) {
            Ok(0) => return Ok(PollFrame::Closed),
            Ok(n) => break n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(PollFrame::IdleTimeout);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(PollFrame::Closed);
            }
            Err(err) => return Err(IpcError::io("read_frame_header", err)),
        }
    };

    if initial_read < IPC_HEADER_BYTES {
        read_exact_checked(reader, &mut header[initial_read..])?;
    }
    let parsed = parse_and_validate_header(&header, max_frame_bytes)?;

    // Only allocate AFTER magic, version, flags, and hard pre-allocation bounds pass.
    let body_len = parsed.payload_len + IPC_TRAILER_BYTES;
    let mut body = vec![0_u8; body_len];
    read_exact_checked(reader, &mut body)?;

    let declared_checksum: [u8; IPC_TRAILER_BYTES] = body[parsed.payload_len..body_len]
        .try_into()
        .map_err(|_| IpcError::InvalidFrame {
            reason: "failed to extract frame checksum".to_owned(),
        })?;
    body.truncate(parsed.payload_len);

    let actual_checksum = compute_frame_checksum(&header, &body)?;
    if declared_checksum != actual_checksum {
        return Err(IpcError::ChecksumMismatch {
            expected: declared_checksum,
            actual: actual_checksum,
        });
    }

    Ok(PollFrame::Frame(WireFrame {
        version: parsed.version,
        flags: parsed.flags,
        payload: body,
        total_wire_bytes: parsed.total_len,
    }))
}

struct ParsedHeader {
    version: u16,
    flags: FrameFlags,
    payload_len: usize,
    total_len: usize,
}

fn parse_and_validate_header(
    header: &[u8; IPC_HEADER_BYTES],
    max_frame_bytes: usize,
) -> Result<ParsedHeader, IpcError> {
    if header[0..4] != IPC_FRAME_MAGIC {
        return Err(IpcError::InvalidFrame {
            reason: "invalid wire frame magic (expected FSSI)".to_owned(),
        });
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != IPC_PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedProtocolVersion {
            expected: IPC_PROTOCOL_VERSION,
            actual: version,
        });
    }
    let raw_flags = u16::from_be_bytes([header[6], header[7]]);
    let flags = FrameFlags::from_raw(raw_flags).map_err(|unknown| IpcError::InvalidFrame {
        reason: format!("unknown wire frame flag bits: 0x{unknown:04x}"),
    })?;
    let payload_len_u32 = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let payload_len = usize::try_from(payload_len_u32).map_err(|_| IpcError::FrameTooLarge {
        actual: usize::MAX,
        limit: max_frame_bytes,
    })?;
    let total_len = checked_total_frame_len(payload_len, max_frame_bytes)?;
    Ok(ParsedHeader {
        version,
        flags,
        payload_len,
        total_len,
    })
}

fn checked_total_frame_len(payload_len: usize, max_frame_bytes: usize) -> Result<usize, IpcError> {
    let total =
        payload_len
            .checked_add(IPC_FRAME_OVERHEAD_BYTES)
            .ok_or(IpcError::FrameTooLarge {
                actual: usize::MAX,
                limit: max_frame_bytes,
            })?;
    if total > max_frame_bytes {
        return Err(IpcError::FrameTooLarge {
            actual: total,
            limit: max_frame_bytes,
        });
    }
    Ok(total)
}

fn read_exact_checked<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> Result<(), IpcError> {
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => return Err(IpcError::ConnectionClosed),
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(IpcError::Timeout {
                    operation: "read_frame_body",
                });
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Err(IpcError::ConnectionClosed);
            }
            Err(err) => return Err(IpcError::io("read_frame_body", err)),
        }
    }
    Ok(())
}

fn write_vectored_three<W: Write>(
    writer: &mut W,
    header: &[u8],
    payload: &[u8],
    checksum: &[u8],
) -> Result<(), IpcError> {
    let mut h = header;
    let mut p = payload;
    let mut c = checksum;
    while !h.is_empty() || !p.is_empty() || !c.is_empty() {
        let slices = [IoSlice::new(h), IoSlice::new(p), IoSlice::new(c)];
        match writer.write_vectored(&slices) {
            Ok(0) => return Err(IpcError::ConnectionClosed),
            Ok(mut written) => {
                let take_h = written.min(h.len());
                h = &h[take_h..];
                written -= take_h;
                let take_p = written.min(p.len());
                p = &p[take_p..];
                written -= take_p;
                let take_c = written.min(c.len());
                c = &c[take_c..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(map_write_io_error(err)),
        }
    }
    Ok(())
}

fn write_all_checked<W: Write>(writer: &mut W, mut buf: &[u8]) -> Result<(), IpcError> {
    while !buf.is_empty() {
        match writer.write(buf) {
            Ok(0) => return Err(IpcError::ConnectionClosed),
            Ok(n) => {
                buf = &buf[n..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(map_write_io_error(err)),
        }
    }
    Ok(())
}

fn map_write_io_error(err: io::Error) -> IpcError {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IpcError::Timeout {
            operation: "write_frame",
        },
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => IpcError::ConnectionClosed,
        _ => IpcError::io("write_frame", err),
    }
}
