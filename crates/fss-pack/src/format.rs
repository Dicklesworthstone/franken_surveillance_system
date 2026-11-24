#![forbid(unsafe_code)]
//! Zero-Serde binary framing, packfile identifiers, durability modes, and bounded I/O helpers.
//!
//! All multi-byte fixed-width integers in `FSSP` / `FSSF` / `FSSE` binary headers and footers
//! are encoded in network byte order (big-endian), matching `fss_core::CanonicalEncoder`.
//!
//! # Packfile Record Layout (`FSSP`)
//!
//! ```text
//! [magic(4) = b"FSSP" | version(u16=1) | flags(u16) | object_kind(u16)
//!  | payload_len(u64) | content_sha256(32) | payload_bytes(payload_len) | record_crc32c(u32)]
//! ```
//!
//! # Sealed Packfile Footer Layout (`FSSF` .. `FSSE`)
//!
//! ```text
//! [footer_magic(4) = b"FSSF" | entry_count(u64)
//!  | sorted_entries((sha256: [u8;32], offset: u64, len: u64, kind: u16, flags: u16))...
//!  | footer_offset(u64) | whole_pack_sha256(32) | footer_end_magic(4) = b"FSSE"]
//! ```

mod footer;
mod io;

use std::fmt;
use std::fs::File;

use fss_core::{ContentDigest, DigestAlgorithm};

use crate::crc32c::{Crc32cHasher, crc32c};
use crate::error::{PackError, PackIoOperation};

pub use footer::{
    PackFooter, PackFooterEntry, PackFooterTail, decode_footer_tail, decode_sealed_footer,
    encode_sealed_footer,
};
pub use io::{read_exact_at_bounded, sync_dir, write_all_bounded};

/// Packfile record header magic bytes.
pub const PACK_RECORD_MAGIC: [u8; 4] = *b"FSSP";
/// Sealed packfile footer opening magic bytes.
pub const PACK_FOOTER_MAGIC: [u8; 4] = *b"FSSF";
/// Sealed packfile footer closing magic bytes.
pub const PACK_FOOTER_END_MAGIC: [u8; 4] = *b"FSSE";
/// Supported binary format version for packfile records and footers.
pub const PACK_FORMAT_VERSION: u16 = 1;

/// Fixed byte length of a packfile record header (`4 + 2 + 2 + 2 + 8 + 32 = 50`).
pub const PACK_RECORD_HEADER_LEN: usize = 50;
/// Fixed byte length of the Castagnoli CRC32C record trailer.
pub const PACK_RECORD_TRAILER_LEN: usize = 4;
/// Fixed framing overhead per packfile record (`54` bytes).
pub const PACK_RECORD_OVERHEAD_LEN: usize = PACK_RECORD_HEADER_LEN + PACK_RECORD_TRAILER_LEN;

/// Fixed byte length of one entry in a sealed packfile footer (`32 + 8 + 8 + 2 + 2 = 52`).
pub const PACK_FOOTER_ENTRY_LEN: usize = 52;
/// Fixed byte length of the footer prefix (`footer_magic(4) + entry_count(8) = 12`).
pub const PACK_FOOTER_PREFIX_LEN: usize = 12;
/// Fixed byte length of the footer trailer (`footer_offset(8) + whole_pack_sha256(32) + footer_end_magic(4) = 44`).
pub const PACK_FOOTER_TAIL_LEN: usize = 44;

/// Default target sealed packfile size (128 MiB).
pub const DEFAULT_TARGET_PACK_BYTES: u64 = 128 * 1024 * 1024;
/// Minimum recommended production target packfile size (64 MiB).
pub const MIN_STANDARD_TARGET_PACK_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum recommended production target packfile size (256 MiB).
pub const MAX_STANDARD_TARGET_PACK_BYTES: u64 = 256 * 1024 * 1024;
/// Minimum configurable target packfile size (256 bytes, primarily for tests).
pub const MIN_CONFIGURABLE_TARGET_PACK_BYTES: u64 = 256;
/// Default maximum single object size (64 MiB, aligned with `fss_object::MAX_OBJECT_BYTES`).
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = fss_object::MAX_OBJECT_BYTES as u64;
/// Default per-read byte ceiling (64 MiB + 1 KiB framing margin).
pub const DEFAULT_MAX_READ_BYTES: u64 = DEFAULT_MAX_OBJECT_BYTES + 1024;
/// Maximum consecutive `EINTR` retries at a single byte offset before failing closed.
pub const MAX_INTERRUPTED_ATTEMPTS: u32 = 8;

/// Object kind tag for opaque raw payloads.
pub const PACK_KIND_RAW_PAYLOAD: u16 = 1;
/// Object kind tag for canonical `ObjectManifest` payloads.
pub const PACK_KIND_OBJECT_MANIFEST: u16 = 2;
/// Object kind tag for coarse-grained `FSMC` media GOP chunks.
pub const PACK_KIND_MEDIA_CHUNK: u16 = 3;
/// Object kind tag for structured metadata blobs.
pub const PACK_KIND_METADATA: u16 = 4;

/// Stable packfile identifier mapping deterministically to `pack-<epoch:08>-<seq:012>.fssp`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackId {
    /// Monotonic storage epoch (defaults to 1).
    pub epoch: u32,
    /// Strictly increasing pack sequence number within the epoch (starts at 1).
    pub seq: u64,
}

impl PackId {
    /// Creates a new [`PackId`].
    #[must_use]
    pub const fn new(epoch: u32, seq: u64) -> Self {
        Self { epoch, seq }
    }

    /// Returns the canonical filename `pack-<epoch:08>-<seq:012>.fssp`.
    #[must_use]
    pub fn file_name(self) -> String {
        format!("pack-{:08}-{:012}.fssp", self.epoch, self.seq)
    }

    /// Parses a canonical packfile filename, rejecting non-canonical formatting.
    #[must_use]
    pub fn parse_file_name(name: &str) -> Option<Self> {
        let stem = name.strip_prefix("pack-")?.strip_suffix(".fssp")?;
        if stem.len() != 8 + 1 + 12 {
            return None;
        }
        let (epoch_str, rest) = stem.split_at(8);
        let seq_str = rest.strip_prefix('-')?;
        if !epoch_str.bytes().all(|b| b.is_ascii_digit())
            || !seq_str.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let epoch = epoch_str.parse::<u32>().ok()?;
        let seq = seq_str.parse::<u64>().ok()?;
        if epoch == 0 || seq == 0 {
            return None;
        }
        Some(Self { epoch, seq })
    }
}

impl fmt::Display for PackId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "pack-{:08}-{:012}", self.epoch, self.seq)
    }
}

/// Configurable file durability barrier mode.
///
/// Both modes use pure safe `std::fs::File` APIs without `unsafe`:
/// - [`DurabilityMode::Fsync`] calls [`File::sync_data`] (`fsync` on macOS, `fdatasync` on Linux).
/// - [`DurabilityMode::FullSync`] calls [`File::sync_all`], which on macOS invokes
///   `fcntl(F_FULLFSYNC)` internally in `std` to flush drive write caches to stable media.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum DurabilityMode {
    /// Standard data durability barrier (`File::sync_data`).
    #[default]
    Fsync,
    /// Full storage barrier (`File::sync_all`, macOS `F_FULLFSYNC` via `std`).
    FullSync,
}

impl DurabilityMode {
    /// Executes the configured durability barrier on `file`.
    pub fn sync_file(self, file: &File) -> Result<(), PackError> {
        let res = match self {
            Self::Fsync => file.sync_data(),
            Self::FullSync => file.sync_all(),
        };
        res.map_err(|err| PackError::io(PackIoOperation::SyncFile, err))
    }
}

/// Physical lifecycle state of an indexed packfile object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PackObjectState {
    /// Stored and fsynced in the currently active append-only packfile.
    Active,
    /// Stored in a sealed immutable packfile with a verified `FSSF`..`FSSE` footer.
    Sealed,
}

impl PackObjectState {
    /// Encodes state as a canonical 1-byte tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Sealed => 2,
        }
    }

    /// Decodes state from a canonical 1-byte tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Active),
            2 => Some(Self::Sealed),
            _ => None,
        }
    }
}

/// Exact address and metadata of one immutable object inside a packfile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackLocation {
    /// Owning packfile identifier.
    pub pack_id: PackId,
    /// Byte offset of the `FSSP` record header within the packfile.
    pub offset: u64,
    /// Payload byte length (excluding the 50-byte header and 4-byte CRC32C trailer).
    pub len: u64,
    /// Typed object kind discriminant.
    pub object_kind: u16,
    /// Record-level flags.
    pub flags: u16,
    /// Whether the owning packfile is active or sealed.
    pub state: PackObjectState,
}

impl PackLocation {
    /// Returns the total framed record byte length (`50 + len + 4`), checking for overflow.
    pub fn record_len(self) -> Result<u64, PackError> {
        self.len
            .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
            .ok_or(PackError::ArithmeticOverflow)
    }
}

/// Input object submitted to `PackWriter::append_batch` or `PackStore::publish_graph`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackObjectInput<'a> {
    /// Object kind tag (e.g., [`PACK_KIND_MEDIA_CHUNK`], [`PACK_KIND_OBJECT_MANIFEST`]).
    pub object_kind: u16,
    /// Record-level flags (0 by default).
    pub flags: u16,
    /// Exact immutable payload bytes.
    pub payload: &'a [u8],
    /// Optional caller-asserted content digest; verified against computed SHA-256 before writing.
    pub expected_digest: Option<ContentDigest>,
}

impl<'a> PackObjectInput<'a> {
    /// Creates an input object whose SHA-256 digest will be computed on ingest.
    #[must_use]
    pub const fn new(object_kind: u16, flags: u16, payload: &'a [u8]) -> Self {
        Self {
            object_kind,
            flags,
            payload,
            expected_digest: None,
        }
    }

    /// Creates an input object with an explicit expected SHA-256 digest that must match.
    #[must_use]
    pub const fn with_digest(
        object_kind: u16,
        flags: u16,
        payload: &'a [u8],
        expected_digest: ContentDigest,
    ) -> Self {
        Self {
            object_kind,
            flags,
            payload,
            expected_digest: Some(expected_digest),
        }
    }
}

/// Decoded fixed 50-byte header of one `FSSP` packfile record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackRecordHeader {
    /// Format version (must be [`PACK_FORMAT_VERSION`]).
    pub version: u16,
    /// Record-level flags.
    pub flags: u16,
    /// Object kind tag.
    pub object_kind: u16,
    /// Payload byte length.
    pub payload_len: u64,
    /// Raw 32-byte SHA-256 of the payload bytes.
    pub content_sha256: [u8; 32],
}

impl PackRecordHeader {
    /// Returns the content identity as a SHA-256 [`ContentDigest`].
    #[must_use]
    pub const fn digest(self) -> ContentDigest {
        ContentDigest::new(DigestAlgorithm::Sha256, self.content_sha256)
    }
}

/// Encodes one framed `FSSP` record into `out`, returning its CRC32C checksum.
pub fn encode_record_into(
    flags: u16,
    object_kind: u16,
    content_sha256: [u8; 32],
    payload: &[u8],
    out: &mut Vec<u8>,
) -> u32 {
    let mut header = [0_u8; PACK_RECORD_HEADER_LEN];
    header[0..4].copy_from_slice(&PACK_RECORD_MAGIC);
    header[4..6].copy_from_slice(&PACK_FORMAT_VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&flags.to_be_bytes());
    header[8..10].copy_from_slice(&object_kind.to_be_bytes());
    header[10..18].copy_from_slice(&(payload.len() as u64).to_be_bytes());
    header[18..50].copy_from_slice(&content_sha256);

    let mut hasher = Crc32cHasher::new();
    hasher.update(&header);
    hasher.update(payload);
    let crc = hasher.finalize();

    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc.to_be_bytes());
    crc
}

/// Decodes a 50-byte packfile record header, failing closed on bad magic or version.
pub fn decode_record_header(
    pack_id: PackId,
    offset: u64,
    raw: &[u8; PACK_RECORD_HEADER_LEN],
) -> Result<PackRecordHeader, PackError> {
    if raw[0..4] != PACK_RECORD_MAGIC {
        return Err(PackError::CorruptPack {
            pack_id,
            offset,
            detail: "invalid FSSP record magic".to_owned(),
        });
    }
    let version = u16::from_be_bytes([raw[4], raw[5]]);
    if version != PACK_FORMAT_VERSION {
        return Err(PackError::CorruptPack {
            pack_id,
            offset,
            detail: format!("unsupported FSSP record version {version}"),
        });
    }
    let flags = u16::from_be_bytes([raw[6], raw[7]]);
    let object_kind = u16::from_be_bytes([raw[8], raw[9]]);
    let payload_len = u64::from_be_bytes([
        raw[10], raw[11], raw[12], raw[13], raw[14], raw[15], raw[16], raw[17],
    ]);
    let mut content_sha256 = [0_u8; 32];
    content_sha256.copy_from_slice(&raw[18..50]);

    Ok(PackRecordHeader {
        version,
        flags,
        object_kind,
        payload_len,
        content_sha256,
    })
}

/// Verifies a complete raw record slice (header + payload + CRC32C) and returns the payload slice.
pub fn verify_record_slice(
    pack_id: PackId,
    offset: u64,
    raw: &[u8],
    expected_digest: Option<ContentDigest>,
) -> Result<(PackRecordHeader, &[u8]), PackError> {
    if raw.len() < PACK_RECORD_OVERHEAD_LEN {
        return Err(PackError::CorruptPack {
            pack_id,
            offset,
            detail: format!("record too short: {} bytes", raw.len()),
        });
    }
    let header_bytes: &[u8; PACK_RECORD_HEADER_LEN] = raw[..PACK_RECORD_HEADER_LEN]
        .try_into()
        .map_err(|_| PackError::CorruptPack {
            pack_id,
            offset,
            detail: "failed to slice record header".to_owned(),
        })?;
    let header = decode_record_header(pack_id, offset, header_bytes)?;
    let expected_total = usize::try_from(header.payload_len)
        .ok()
        .and_then(|n| n.checked_add(PACK_RECORD_OVERHEAD_LEN))
        .ok_or(PackError::ArithmeticOverflow)?;
    if raw.len() != expected_total {
        return Err(PackError::CorruptPack {
            pack_id,
            offset,
            detail: format!(
                "record length mismatch: header declares {expected_total}, observed {}",
                raw.len()
            ),
        });
    }

    let crc_offset = raw.len() - PACK_RECORD_TRAILER_LEN;
    let stored_crc = u32::from_be_bytes([
        raw[crc_offset],
        raw[crc_offset + 1],
        raw[crc_offset + 2],
        raw[crc_offset + 3],
    ]);
    let computed_crc = crc32c(&raw[..crc_offset]);
    if stored_crc != computed_crc {
        return Err(PackError::CrcMismatch {
            expected: stored_crc,
            actual: computed_crc,
        });
    }

    let payload = &raw[PACK_RECORD_HEADER_LEN..crc_offset];
    let computed_digest = ContentDigest::sha256(payload);
    let header_digest = header.digest();
    if computed_digest != header_digest {
        return Err(PackError::DigestMismatch {
            expected: header_digest,
            actual: computed_digest,
        });
    }
    if let Some(expected) = expected_digest
        && expected != computed_digest
    {
        return Err(PackError::DigestMismatch {
            expected,
            actual: computed_digest,
        });
    }

    Ok((header, payload))
}
