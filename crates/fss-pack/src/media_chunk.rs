#![forbid(unsafe_code)]
//! Coarse-grained GOP/window media chunk container (`FSMC`, `COMPREHENSIVE_PLAN §13.8`).
//!
//! Packs a GOP or capture window of `N` encoded media frames (H.264, H.265, or MJPEG) into
//! **one single packfile object** with an internal deterministic frame offset, per-frame SHA-256,
//! and timestamp table (`magic b"FSMC"`). This collapses 60-frame GOP bursts into 1 pack object
//! and 1 virtual root while preserving exact per-frame logical digests and O(1) zero-copy slice
//! reads for custody verification, decoding, and selective hydration.

mod view;

use fss_core::{ClockBasis, ContentDigest, DigestAlgorithm, TimestampNs, sha256};

use crate::crc32c::Crc32cHasher;
use crate::error::PackError;

pub use view::MediaChunkView;

/// Magic header bytes for a coarse-grained media chunk container.
pub const MEDIA_CHUNK_MAGIC: [u8; 4] = *b"FSMC";
/// Supported media chunk container format version.
pub const MEDIA_CHUNK_VERSION: u16 = 1;
/// Maximum number of frames permitted inside a single media chunk.
pub const MAX_MEDIA_CHUNK_FRAMES: usize = 16_384;
/// Maximum UTF-8 byte length of the chunk's stream identifier.
pub const MAX_STREAM_ID_BYTES: usize = 128;
/// Fixed byte stride of one frame table entry (`8 + 16 + 8 + 4 + 2 + 2 + 32 = 72`).
pub const MEDIA_FRAME_ENTRY_LEN: usize = 72;
/// Fixed header prefix bytes before `stream_id`: `4 + 2 + 1 + 1 + 2 + 4 + 2 = 16`.
pub(crate) const HEADER_PREFIX_LEN: usize = 16;
/// Fixed header suffix bytes after `stream_id`: `16 + 16 + 8 + 8 + 4 = 52`.
pub(crate) const HEADER_SUFFIX_LEN: usize = 52;

/// Frame flag indicating an IDR / random-access keyframe.
pub const MEDIA_FRAME_FLAG_KEYFRAME: u16 = 0x0001;
/// Frame flag indicating codec configuration / parameter sets are carried in this access unit.
pub const MEDIA_FRAME_FLAG_CONFIG: u16 = 0x0002;
/// Frame flag indicating an observed upstream sequence/continuity gap immediately before this frame.
pub const MEDIA_FRAME_FLAG_DISCONTINUITY: u16 = 0x0004;

/// Supported video codec identifiers inside an `FSMC` media chunk.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MediaCodec {
    /// H.264 / AVC elementary access units.
    H264,
    /// H.265 / HEVC elementary access units.
    H265,
    /// Motion-JPEG independent frames.
    Mjpeg,
}

impl MediaCodec {
    /// Returns the canonical 1-byte codec tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::H264 => 1,
            Self::H265 => 2,
            Self::Mjpeg => 3,
        }
    }

    /// Decodes a codec from its 1-byte tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::H264),
            2 => Some(Self::H265),
            3 => Some(Self::Mjpeg),
            _ => None,
        }
    }
}

pub(crate) const fn clock_basis_to_tag(basis: ClockBasis) -> u8 {
    match basis {
        ClockBasis::UtcDisciplined => 1,
        ClockBasis::DeviceMonotonic => 2,
        ClockBasis::HostMonotonic => 3,
        ClockBasis::Estimated => 4,
    }
}

pub(crate) const fn clock_basis_from_tag(tag: u8) -> Option<ClockBasis> {
    match tag {
        1 => Some(ClockBasis::UtcDisciplined),
        2 => Some(ClockBasis::DeviceMonotonic),
        3 => Some(ClockBasis::HostMonotonic),
        4 => Some(ClockBasis::Estimated),
        _ => None,
    }
}

/// Metadata entry for one frame stored inside an `FSMC` media chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaFrameEntry {
    /// Stream sequence number of this frame.
    pub sequence: u64,
    /// Frame timestamp on the chunk's declared [`ClockBasis`].
    pub timestamp_ns: TimestampNs,
    /// Byte offset of this frame's payload relative to the start of the payload region.
    pub payload_offset: u64,
    /// Frame payload byte length.
    pub payload_len: u32,
    /// Per-frame bitflags (e.g., [`MEDIA_FRAME_FLAG_KEYFRAME`]).
    pub flags: u16,
    /// Exact logical SHA-256 digest of this frame's raw payload bytes.
    pub digest: ContentDigest,
}

/// Receipt returned by [`MediaChunkBuilder::push_frame`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaFrameReceipt {
    /// Zero-based index of the frame inside the chunk.
    pub frame_index: usize,
    /// Exact logical SHA-256 digest of the frame bytes.
    pub digest: ContentDigest,
    /// Frame payload byte length.
    pub payload_len: u32,
}

/// Completed immutable `FSMC` media chunk ready for single-object packfile ingestion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltMediaChunk {
    /// Complete canonical `FSMC` container bytes.
    pub bytes: Vec<u8>,
    /// Whole-chunk SHA-256 digest (the packfile object identity).
    pub chunk_digest: ContentDigest,
    /// Number of frames packed inside this chunk.
    pub frame_count: usize,
    /// Earliest frame timestamp in the window.
    pub window_start_ns: TimestampNs,
    /// Latest frame timestamp in the window.
    pub window_end_ns: TimestampNs,
    /// Per-frame logical SHA-256 digests in exact frame order.
    pub frame_digests: Vec<ContentDigest>,
}

/// Deterministic builder that packs `N` frames into one `FSMC` packfile object.
#[derive(Clone, Debug)]
pub struct MediaChunkBuilder {
    stream_id: String,
    codec: MediaCodec,
    clock_basis: ClockBasis,
    entries: Vec<MediaFrameEntry>,
    payloads: Vec<u8>,
}

impl MediaChunkBuilder {
    /// Starts building a new `FSMC` media chunk for `stream_id`.
    pub fn new(
        stream_id: impl Into<String>,
        codec: MediaCodec,
        clock_basis: ClockBasis,
    ) -> Result<Self, PackError> {
        let stream_id = stream_id.into();
        if stream_id.is_empty() || stream_id.len() > MAX_STREAM_ID_BYTES {
            return Err(PackError::InvalidMediaChunk {
                detail: format!(
                    "stream_id length {} must be in 1..={MAX_STREAM_ID_BYTES}",
                    stream_id.len()
                ),
            });
        }
        Ok(Self {
            stream_id,
            codec,
            clock_basis,
            entries: Vec::new(),
            payloads: Vec::new(),
        })
    }

    /// Appends one encoded frame to the chunk, computing its exact logical SHA-256 digest.
    pub fn push_frame(
        &mut self,
        sequence: u64,
        timestamp_ns: TimestampNs,
        flags: u16,
        payload: &[u8],
    ) -> Result<MediaFrameReceipt, PackError> {
        if self.entries.len() >= MAX_MEDIA_CHUNK_FRAMES {
            return Err(PackError::InvalidMediaChunk {
                detail: format!("frame count reached maximum {MAX_MEDIA_CHUNK_FRAMES}"),
            });
        }
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| PackError::InvalidMediaChunk {
                detail: "single frame payload length exceeds u32::MAX".to_owned(),
            })?;
        let payload_offset = self.payloads.len() as u64;
        let digest = ContentDigest::new(DigestAlgorithm::Sha256, sha256(payload));
        let frame_index = self.entries.len();

        self.entries.push(MediaFrameEntry {
            sequence,
            timestamp_ns,
            payload_offset,
            payload_len,
            flags,
            digest,
        });
        self.payloads.extend_from_slice(payload);

        Ok(MediaFrameReceipt {
            frame_index,
            digest,
            payload_len,
        })
    }

    /// Returns the number of frames pushed so far.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.entries.len()
    }

    /// Finalizes the deterministic `FSMC` binary container and computes its whole-chunk SHA-256.
    pub fn build(self) -> Result<BuiltMediaChunk, PackError> {
        if self.entries.is_empty() {
            return Err(PackError::InvalidMediaChunk {
                detail: "cannot build an empty FSMC media chunk".to_owned(),
            });
        }

        let mut window_start = self.entries[0].timestamp_ns;
        let mut window_end = self.entries[0].timestamp_ns;
        for entry in &self.entries[1..] {
            if entry.timestamp_ns < window_start {
                window_start = entry.timestamp_ns;
            }
            if entry.timestamp_ns > window_end {
                window_end = entry.timestamp_ns;
            }
        }

        let stream_bytes = self.stream_id.as_bytes();
        let stream_id_len =
            u16::try_from(stream_bytes.len()).map_err(|_| PackError::ArithmeticOverflow)?;
        let frame_count_u32 =
            u32::try_from(self.entries.len()).map_err(|_| PackError::ArithmeticOverflow)?;

        let frame_table_offset =
            (HEADER_PREFIX_LEN + stream_bytes.len() + HEADER_SUFFIX_LEN) as u64;
        let table_bytes_len = self
            .entries
            .len()
            .checked_mul(MEDIA_FRAME_ENTRY_LEN)
            .ok_or(PackError::ArithmeticOverflow)?;
        let payload_data_offset = frame_table_offset
            .checked_add(table_bytes_len as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        let total_len = usize::try_from(payload_data_offset)
            .ok()
            .and_then(|v| v.checked_add(self.payloads.len()))
            .ok_or(PackError::ArithmeticOverflow)?;

        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&MEDIA_CHUNK_MAGIC);
        out.extend_from_slice(&MEDIA_CHUNK_VERSION.to_be_bytes());
        out.push(self.codec.to_tag());
        out.push(clock_basis_to_tag(self.clock_basis));
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&frame_count_u32.to_be_bytes());
        out.extend_from_slice(&stream_id_len.to_be_bytes());
        out.extend_from_slice(stream_bytes);
        out.extend_from_slice(&window_start.0.to_be_bytes());
        out.extend_from_slice(&window_end.0.to_be_bytes());
        out.extend_from_slice(&frame_table_offset.to_be_bytes());
        out.extend_from_slice(&payload_data_offset.to_be_bytes());
        let crc_pos = out.len();
        out.extend_from_slice(&0_u32.to_be_bytes());

        let mut frame_digests = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            out.extend_from_slice(&entry.sequence.to_be_bytes());
            out.extend_from_slice(&entry.timestamp_ns.0.to_be_bytes());
            out.extend_from_slice(&entry.payload_offset.to_be_bytes());
            out.extend_from_slice(&entry.payload_len.to_be_bytes());
            out.extend_from_slice(&entry.flags.to_be_bytes());
            out.extend_from_slice(&0_u16.to_be_bytes());
            out.extend_from_slice(&entry.digest.bytes());
            frame_digests.push(entry.digest);
        }

        let mut crc = Crc32cHasher::new();
        crc.update(&out[..crc_pos]);
        crc.update(&out[crc_pos + 4..]);
        let table_crc = crc.finalize();
        out[crc_pos..crc_pos + 4].copy_from_slice(&table_crc.to_be_bytes());

        out.extend_from_slice(&self.payloads);
        let chunk_digest = ContentDigest::sha256(&out);

        Ok(BuiltMediaChunk {
            bytes: out,
            chunk_digest,
            frame_count: self.entries.len(),
            window_start_ns: window_start,
            window_end_ns: window_end,
            frame_digests,
        })
    }
}
