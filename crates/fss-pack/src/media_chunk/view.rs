#![forbid(unsafe_code)]
//! Zero-copy validated [`MediaChunkView`] for O(1) frame access over `FSMC` chunks.

use fss_core::{ClockBasis, ContentDigest, DigestAlgorithm, TimestampNs};

use crate::crc32c::Crc32cHasher;
use crate::error::PackError;
use crate::media_chunk::{
    HEADER_PREFIX_LEN, HEADER_SUFFIX_LEN, MAX_MEDIA_CHUNK_FRAMES, MAX_STREAM_ID_BYTES,
    MEDIA_CHUNK_MAGIC, MEDIA_CHUNK_VERSION, MEDIA_FRAME_ENTRY_LEN, MediaCodec, MediaFrameEntry,
    clock_basis_from_tag,
};

/// Zero-copy validated view over an `FSMC` media chunk offering O(1) frame slice access.
#[derive(Clone, Copy, Debug)]
pub struct MediaChunkView<'a> {
    raw: &'a [u8],
    codec: MediaCodec,
    clock_basis: ClockBasis,
    stream_id: &'a str,
    window_start_ns: TimestampNs,
    window_end_ns: TimestampNs,
    frame_count: usize,
    frame_table_offset: usize,
    payload_data_offset: usize,
}

impl<'a> MediaChunkView<'a> {
    /// Parses and structurally validates an `FSMC` byte slice without copying frame payloads.
    pub fn parse(raw: &'a [u8]) -> Result<Self, PackError> {
        if raw.len() < HEADER_PREFIX_LEN + HEADER_SUFFIX_LEN {
            return Err(PackError::InvalidMediaChunk {
                detail: "FSMC buffer shorter than minimum header".to_owned(),
            });
        }
        if raw[0..4] != MEDIA_CHUNK_MAGIC {
            return Err(PackError::InvalidMediaChunk {
                detail: "invalid FSMC magic".to_owned(),
            });
        }
        let version = u16::from_be_bytes([raw[4], raw[5]]);
        if version != MEDIA_CHUNK_VERSION {
            return Err(PackError::InvalidMediaChunk {
                detail: format!("unsupported FSMC version {version}"),
            });
        }
        let codec = MediaCodec::from_tag(raw[6]).ok_or_else(|| PackError::InvalidMediaChunk {
            detail: format!("unknown FSMC codec tag {}", raw[6]),
        })?;
        let clock_basis =
            clock_basis_from_tag(raw[7]).ok_or_else(|| PackError::InvalidMediaChunk {
                detail: format!("unknown FSMC clock_basis tag {}", raw[7]),
            })?;
        let flags = u16::from_be_bytes([raw[8], raw[9]]);
        if flags != 0 {
            return Err(PackError::InvalidMediaChunk {
                detail: format!("unsupported FSMC header flags {flags}"),
            });
        }
        let frame_count = u32::from_be_bytes([raw[10], raw[11], raw[12], raw[13]]) as usize;
        if frame_count == 0 || frame_count > MAX_MEDIA_CHUNK_FRAMES {
            return Err(PackError::InvalidMediaChunk {
                detail: format!(
                    "FSMC frame_count {frame_count} outside 1..={MAX_MEDIA_CHUNK_FRAMES}"
                ),
            });
        }
        let stream_id_len = usize::from(u16::from_be_bytes([raw[14], raw[15]]));
        if stream_id_len == 0 || stream_id_len > MAX_STREAM_ID_BYTES {
            return Err(PackError::InvalidMediaChunk {
                detail: format!("FSMC stream_id_len {stream_id_len} invalid"),
            });
        }

        let suffix_start = HEADER_PREFIX_LEN + stream_id_len;
        let expected_table_offset = suffix_start + HEADER_SUFFIX_LEN;
        if raw.len() < expected_table_offset {
            return Err(PackError::InvalidMediaChunk {
                detail: "FSMC truncated inside header".to_owned(),
            });
        }
        let stream_id =
            std::str::from_utf8(&raw[HEADER_PREFIX_LEN..suffix_start]).map_err(|_| {
                PackError::InvalidMediaChunk {
                    detail: "FSMC stream_id is not valid UTF-8".to_owned(),
                }
            })?;

        let window_start_ns = TimestampNs(read_i128(&raw[suffix_start..suffix_start + 16])?);
        let window_end_ns = TimestampNs(read_i128(&raw[suffix_start + 16..suffix_start + 32])?);
        let frame_table_offset =
            usize::try_from(read_u64(&raw[suffix_start + 32..suffix_start + 40])?)
                .map_err(|_| PackError::ArithmeticOverflow)?;
        let payload_data_offset =
            usize::try_from(read_u64(&raw[suffix_start + 40..suffix_start + 48])?)
                .map_err(|_| PackError::ArithmeticOverflow)?;
        let stored_crc = u32::from_be_bytes([
            raw[suffix_start + 48],
            raw[suffix_start + 49],
            raw[suffix_start + 50],
            raw[suffix_start + 51],
        ]);

        if frame_table_offset != expected_table_offset {
            return Err(PackError::InvalidMediaChunk {
                detail: "FSMC frame_table_offset does not match header end".to_owned(),
            });
        }
        let table_bytes_len = frame_count
            .checked_mul(MEDIA_FRAME_ENTRY_LEN)
            .ok_or(PackError::ArithmeticOverflow)?;
        let expected_payload_offset = frame_table_offset
            .checked_add(table_bytes_len)
            .ok_or(PackError::ArithmeticOverflow)?;
        if payload_data_offset != expected_payload_offset || payload_data_offset > raw.len() {
            return Err(PackError::InvalidMediaChunk {
                detail: "FSMC payload_data_offset inconsistent with frame table".to_owned(),
            });
        }

        let crc_pos = suffix_start + 48;
        let mut hasher = Crc32cHasher::new();
        hasher.update(&raw[..crc_pos]);
        hasher.update(&raw[frame_table_offset..payload_data_offset]);
        let computed_crc = hasher.finalize();
        if stored_crc != computed_crc {
            return Err(PackError::CrcMismatch {
                expected: stored_crc,
                actual: computed_crc,
            });
        }

        let view = Self {
            raw,
            codec,
            clock_basis,
            stream_id,
            window_start_ns,
            window_end_ns,
            frame_count,
            frame_table_offset,
            payload_data_offset,
        };

        let payload_region_len = (raw.len() - payload_data_offset) as u64;
        let mut expected_rel_offset = 0_u64;
        for idx in 0..frame_count {
            let entry = view.frame_entry(idx)?;
            if entry.payload_offset != expected_rel_offset {
                return Err(PackError::InvalidMediaChunk {
                    detail: format!(
                        "non-contiguous frame {idx}: expected offset {expected_rel_offset}, got {}",
                        entry.payload_offset
                    ),
                });
            }
            expected_rel_offset = expected_rel_offset
                .checked_add(u64::from(entry.payload_len))
                .ok_or(PackError::ArithmeticOverflow)?;
        }
        if expected_rel_offset != payload_region_len {
            return Err(PackError::InvalidMediaChunk {
                detail: format!(
                    "payload region length mismatch: frame table sums to {expected_rel_offset}, actual {payload_region_len}"
                ),
            });
        }

        Ok(view)
    }

    /// Returns the chunk's video codec.
    #[must_use]
    pub const fn codec(&self) -> MediaCodec {
        self.codec
    }

    /// Returns the declared timestamp clock basis.
    #[must_use]
    pub const fn clock_basis(&self) -> ClockBasis {
        self.clock_basis
    }

    /// Returns the source stream identifier.
    #[must_use]
    pub const fn stream_id(&self) -> &'a str {
        self.stream_id
    }

    /// Returns the earliest timestamp in the chunk window.
    #[must_use]
    pub const fn window_start_ns(&self) -> TimestampNs {
        self.window_start_ns
    }

    /// Returns the latest timestamp in the chunk window.
    #[must_use]
    pub const fn window_end_ns(&self) -> TimestampNs {
        self.window_end_ns
    }

    /// Returns the number of packed frames.
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Computes the whole-chunk SHA-256 content identity.
    #[must_use]
    pub fn chunk_digest(&self) -> ContentDigest {
        ContentDigest::sha256(self.raw)
    }

    /// Reads the frame table entry at `index` in O(1) time.
    pub fn frame_entry(&self, index: usize) -> Result<MediaFrameEntry, PackError> {
        if index >= self.frame_count {
            return Err(PackError::InvalidMediaChunk {
                detail: format!("frame index {index} out of range 0..{}", self.frame_count),
            });
        }
        let base = self.frame_table_offset + index * MEDIA_FRAME_ENTRY_LEN;
        let slice = &self.raw[base..base + MEDIA_FRAME_ENTRY_LEN];
        let sequence = read_u64(&slice[0..8])?;
        let timestamp_ns = TimestampNs(read_i128(&slice[8..24])?);
        let payload_offset = read_u64(&slice[24..32])?;
        let payload_len = u32::from_be_bytes([slice[32], slice[33], slice[34], slice[35]]);
        let flags = u16::from_be_bytes([slice[36], slice[37]]);
        let reserved = u16::from_be_bytes([slice[38], slice[39]]);
        if reserved != 0 {
            return Err(PackError::InvalidMediaChunk {
                detail: format!("non-zero reserved field {reserved} in frame {index}"),
            });
        }
        let mut frame_sha256 = [0_u8; 32];
        frame_sha256.copy_from_slice(&slice[40..72]);

        Ok(MediaFrameEntry {
            sequence,
            timestamp_ns,
            payload_offset,
            payload_len,
            flags,
            digest: ContentDigest::new(DigestAlgorithm::Sha256, frame_sha256),
        })
    }

    /// Returns the zero-copy payload slice for frame `index` in O(1) time.
    pub fn frame_bytes(&self, index: usize) -> Result<&'a [u8], PackError> {
        let entry = self.frame_entry(index)?;
        let start = self
            .payload_data_offset
            .checked_add(
                usize::try_from(entry.payload_offset).map_err(|_| PackError::ArithmeticOverflow)?,
            )
            .ok_or(PackError::ArithmeticOverflow)?;
        let end = start
            .checked_add(entry.payload_len as usize)
            .ok_or(PackError::ArithmeticOverflow)?;
        self.raw
            .get(start..end)
            .ok_or_else(|| PackError::InvalidMediaChunk {
                detail: format!("frame {index} span {start}..{end} out of bounds"),
            })
    }

    /// Returns the zero-copy payload slice for frame `index` after verifying its exact SHA-256.
    pub fn frame_bytes_verified(&self, index: usize) -> Result<&'a [u8], PackError> {
        let entry = self.frame_entry(index)?;
        let bytes = self.frame_bytes(index)?;
        let actual = ContentDigest::sha256(bytes);
        if actual != entry.digest {
            return Err(PackError::DigestMismatch {
                expected: entry.digest,
                actual,
            });
        }
        Ok(bytes)
    }

    /// Verifies the exact per-frame SHA-256 of every frame in the chunk.
    pub fn verify_all_frames(&self) -> Result<(), PackError> {
        for idx in 0..self.frame_count {
            let _ = self.frame_bytes_verified(idx)?;
        }
        Ok(())
    }

    /// Finds the first frame index matching `digest`, if present.
    #[must_use]
    pub fn find_by_digest(&self, digest: ContentDigest) -> Option<usize> {
        for idx in 0..self.frame_count {
            if let Ok(entry) = self.frame_entry(idx)
                && entry.digest == digest
            {
                return Some(idx);
            }
        }
        None
    }
}

fn read_u64(slice: &[u8]) -> Result<u64, PackError> {
    let arr: [u8; 8] = slice.try_into().map_err(|_| PackError::InvalidMediaChunk {
        detail: "short u64 slice".to_owned(),
    })?;
    Ok(u64::from_be_bytes(arr))
}

fn read_i128(slice: &[u8]) -> Result<i128, PackError> {
    let arr: [u8; 16] = slice.try_into().map_err(|_| PackError::InvalidMediaChunk {
        detail: "short i128 slice".to_owned(),
    })?;
    Ok(i128::from_be_bytes(arr))
}
