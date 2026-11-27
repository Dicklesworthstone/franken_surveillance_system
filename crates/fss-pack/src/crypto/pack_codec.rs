#![forbid(unsafe_code)]
//! Binary `FSEP` v1 encrypted stream header/trailer codecs, receipts, and atomic file helper.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{ContentDigest, Sha256Hasher};
use fss_vault::{AEAD_NONCE_LEN, EntropySource};

use crate::crc32c::crc32c;
use crate::crypto::envelope::{
    CipherSuite, DataEncryptionKey, DekId, KeyEncryptionKey, KeyEpoch,
    MAX_AEAD_FRAME_PLAINTEXT_BYTES, SCHEMA_EPOCH_LEDGER_EPOCH,
};
use crate::crypto::keyring::KeyEnvelopeCatalog;
use crate::crypto::pack_io::{
    EncryptedPackWriter, decrypt_and_verify_pack_bytes, encrypt_pack_bytes,
};
use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, PackId, read_exact_at_bounded, sync_dir, write_all_bounded};

/// Magic prefix identifying an encrypted packfile / ledger-epoch stream (`FSEP`).
pub const ENCRYPTED_PACK_MAGIC: [u8; 4] = *b"FSEP";
/// Supported binary format version for `FSEP` streams.
pub const ENCRYPTED_PACK_VERSION: u16 = 1;
/// Opening magic bytes for the `FSEP` v1 stream trailer (`FSPT`).
pub const ENCRYPTED_PACK_TRAILER_MAGIC: [u8; 4] = *b"FSPT";
/// Closing magic bytes for the `FSEP` v1 stream trailer (`FSPE`).
pub const ENCRYPTED_PACK_END_MAGIC: [u8; 4] = *b"FSPE";
/// Fixed byte length of the `FSEP` v1 stream header (`48` bytes).
pub const ENCRYPTED_PACK_HEADER_LEN: usize = 48;
/// Fixed byte length of the `FSPT`..`FSPE` trailer (`88` bytes).
pub const ENCRYPTED_PACK_TRAILER_LEN: usize = 88;
/// Default plaintext chunk size when streaming sealed `.fssp` packs or ledger segments (`256 KiB`).
pub const DEFAULT_ENCRYPTION_CHUNK_BYTES: usize = 256 * 1024;

static PACK_IO_TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Discriminant separating object-record encrypted packs, chunked sealed packs, and ledger epochs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EncryptedStreamKind {
    /// Record-level encrypted packfile (`EncryptedPackWriter` / `EncryptedPackReader`).
    PackRecords = 1,
    /// Chunked encrypted sealed `.fssp` packfile (`encrypt_pack_file` / cold archival).
    SealedPackChunks = 2,
    /// Chunked encrypted ledger epoch segment (`encrypt_ledger_epoch_segment`).
    LedgerEpochSegment = 3,
}

impl EncryptedStreamKind {
    /// Encodes as a canonical 1-byte wire tag.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::PackRecords => 1,
            Self::SealedPackChunks => 2,
            Self::LedgerEpochSegment => 3,
        }
    }

    /// Decodes from a canonical 1-byte wire tag.
    #[must_use]
    pub const fn from_u8(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::PackRecords),
            2 => Some(Self::SealedPackChunks),
            3 => Some(Self::LedgerEpochSegment),
            _ => None,
        }
    }
}

/// Fixed 48-byte `FSEP` v1 header at offset `0` of every encrypted pack or ledger epoch stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedPackHeader {
    /// Format version (must be [`ENCRYPTED_PACK_VERSION`]).
    pub version: u16,
    /// AEAD cipher suite (`ChaCha20Poly1305`).
    pub cipher: CipherSuite,
    /// Encrypted stream classification.
    pub stream_kind: EncryptedStreamKind,
    /// Pack or ledger-epoch identifier bound into every inner `FSAE` frame's AAD.
    pub pack_id: PackId,
    /// Origin KEK epoch active when this stream was encrypted.
    pub key_epoch: KeyEpoch,
    /// Schema epoch bound into every inner `FSAE` frame's AAD.
    pub schema_epoch: u32,
    /// Identifier of the 256-bit DEK used across this stream.
    pub dek_id: DekId,
}

impl EncryptedPackHeader {
    /// Encodes the 48-byte header with a trailing Castagnoli CRC32C checksum.
    #[must_use]
    pub fn encode(&self) -> [u8; ENCRYPTED_PACK_HEADER_LEN] {
        let mut out = [0_u8; ENCRYPTED_PACK_HEADER_LEN];
        out[0..4].copy_from_slice(&ENCRYPTED_PACK_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        out[6] = self.cipher.to_u8();
        out[7] = self.stream_kind.to_u8();
        out[8..12].copy_from_slice(&self.pack_id.epoch.to_be_bytes());
        out[12..20].copy_from_slice(&self.pack_id.seq.to_be_bytes());
        out[20..24].copy_from_slice(&self.key_epoch.0.to_be_bytes());
        out[24..28].copy_from_slice(&self.schema_epoch.to_be_bytes());
        out[28..44].copy_from_slice(&self.dek_id.0);
        let crc = crc32c(&out[..44]);
        out[44..48].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Decodes and validates a 48-byte `FSEP` v1 header.
    pub fn decode(raw: &[u8; ENCRYPTED_PACK_HEADER_LEN]) -> Result<Self, PackError> {
        if raw[0..4] != ENCRYPTED_PACK_MAGIC {
            return Err(PackError::CryptoAuthFailed {
                detail: "invalid FSEP stream header magic".to_owned(),
            });
        }
        let stored_crc = u32::from_be_bytes([raw[44], raw[45], raw[46], raw[47]]);
        let computed_crc = crc32c(&raw[..44]);
        if stored_crc != computed_crc {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP header CRC32C verification failed".to_owned(),
            });
        }
        let version = u16::from_be_bytes([raw[4], raw[5]]);
        if version != ENCRYPTED_PACK_VERSION {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("unsupported FSEP version {version}"),
            });
        }
        let cipher = CipherSuite::from_u8(raw[6]).ok_or_else(|| PackError::CryptoAuthFailed {
            detail: format!("unsupported FSEP cipher suite {}", raw[6]),
        })?;
        let stream_kind =
            EncryptedStreamKind::from_u8(raw[7]).ok_or_else(|| PackError::CryptoAuthFailed {
                detail: format!("unsupported FSEP stream_kind {}", raw[7]),
            })?;
        let pack_epoch = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let pack_seq = u64::from_be_bytes([
            raw[12], raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19],
        ]);
        let key_epoch_raw = u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]);
        if key_epoch_raw == 0 {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP header key_epoch cannot be 0".to_owned(),
            });
        }
        let schema_epoch = u32::from_be_bytes([raw[24], raw[25], raw[26], raw[27]]);
        if schema_epoch == 0 {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP header schema_epoch cannot be 0".to_owned(),
            });
        }
        let mut dek_bytes = [0_u8; 16];
        dek_bytes.copy_from_slice(&raw[28..44]);
        if dek_bytes == [0_u8; 16] {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP header dek_id cannot be all zeros".to_owned(),
            });
        }
        Ok(Self {
            version,
            cipher,
            stream_kind,
            pack_id: PackId::new(pack_epoch, pack_seq),
            key_epoch: KeyEpoch(key_epoch_raw),
            schema_epoch,
            dek_id: DekId(dek_bytes),
        })
    }
}

/// Fixed 88-byte `FSPT`..`FSPE` closing trailer at the end of every sealed `FSEP` v1 stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedPackTrailer {
    /// Total number of `FSAE` v1 frames enclosed in this stream.
    pub frame_count: u64,
    /// Total concatenated plaintext bytes across all enclosed frames.
    pub total_plaintext_bytes: u64,
    /// SHA-256 of the concatenated plaintext stream across all frames.
    pub plaintext_stream_sha256: [u8; 32],
    /// SHA-256 covering bytes `[0 .. file_len - 36]` (header + all frames + trailer prefix).
    pub ciphertext_prefix_sha256: [u8; 32],
}

impl EncryptedPackTrailer {
    /// Encodes the 88-byte trailer, finalizing `ciphertext_hasher` over the trailer prefix.
    pub fn encode(
        frame_count: u64,
        total_plaintext_bytes: u64,
        plaintext_stream_sha256: [u8; 32],
        mut ciphertext_hasher: Sha256Hasher,
    ) -> Result<(Self, [u8; ENCRYPTED_PACK_TRAILER_LEN]), PackError> {
        let mut out = [0_u8; ENCRYPTED_PACK_TRAILER_LEN];
        out[0..4].copy_from_slice(&ENCRYPTED_PACK_TRAILER_MAGIC);
        out[4..12].copy_from_slice(&frame_count.to_be_bytes());
        out[12..20].copy_from_slice(&total_plaintext_bytes.to_be_bytes());
        out[20..52].copy_from_slice(&plaintext_stream_sha256);
        ciphertext_hasher.update(&out[..52]);
        let prefix_sha = ciphertext_hasher
            .finalize()
            .map_err(|_| PackError::ArithmeticOverflow)?;
        out[52..84].copy_from_slice(&prefix_sha);
        out[84..88].copy_from_slice(&ENCRYPTED_PACK_END_MAGIC);
        Ok((
            Self {
                frame_count,
                total_plaintext_bytes,
                plaintext_stream_sha256,
                ciphertext_prefix_sha256: prefix_sha,
            },
            out,
        ))
    }

    /// Decodes an 88-byte `FSPT`..`FSPE` trailer, failing closed on bad magic.
    pub fn decode(raw: &[u8; ENCRYPTED_PACK_TRAILER_LEN]) -> Result<Self, PackError> {
        if raw[0..4] != ENCRYPTED_PACK_TRAILER_MAGIC || raw[84..88] != ENCRYPTED_PACK_END_MAGIC {
            return Err(PackError::CryptoAuthFailed {
                detail: "invalid FSPT/FSPE encrypted stream trailer magic".to_owned(),
            });
        }
        let frame_count = u64::from_be_bytes([
            raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
        ]);
        let total_plaintext_bytes = u64::from_be_bytes([
            raw[12], raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19],
        ]);
        let mut plaintext_stream_sha256 = [0_u8; 32];
        plaintext_stream_sha256.copy_from_slice(&raw[20..52]);
        let mut ciphertext_prefix_sha256 = [0_u8; 32];
        ciphertext_prefix_sha256.copy_from_slice(&raw[52..84]);
        Ok(Self {
            frame_count,
            total_plaintext_bytes,
            plaintext_stream_sha256,
            ciphertext_prefix_sha256,
        })
    }
}

/// Receipt emitted for one encrypted record appended via [`crate::EncryptedPackWriter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedRecordReceipt {
    /// Exact byte offset of the `FSAE` frame within the `.fsep` file.
    pub record_offset: u64,
    /// Total encoded `FSAE` frame length in bytes (`header + ciphertext + tag`).
    pub frame_len: u64,
    /// Plaintext payload length in bytes.
    pub plaintext_len: u64,
    /// Plaintext content SHA-256 (`ContentDigest`, unchanged by encryption or KEK rotation).
    pub plaintext_digest: ContentDigest,
    /// Unique 96-bit ChaCha20-Poly1305 nonce issued for this frame.
    pub nonce: [u8; AEAD_NONCE_LEN],
}

/// Summary receipt returned when finalizing an encrypted packfile or ledger epoch stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPackReceipt {
    /// Pack or ledger-epoch identifier.
    pub pack_id: PackId,
    /// Stream classification.
    pub stream_kind: EncryptedStreamKind,
    /// Schema epoch bound in AAD.
    pub schema_epoch: u32,
    /// Origin KEK epoch bound in `FSAE` headers.
    pub origin_key_epoch: KeyEpoch,
    /// Identifier of the DEK that encrypted this stream.
    pub dek_id: DekId,
    /// Total `FSAE` frames written.
    pub frame_count: u64,
    /// Total plaintext payload bytes encrypted.
    pub plaintext_bytes: u64,
    /// SHA-256 of the concatenated plaintext stream (for sealed packfiles: exact `.fssp` SHA-256).
    pub plaintext_sha256: ContentDigest,
    /// Total encrypted `.fsep` byte length (header + frames + trailer).
    pub ciphertext_bytes: u64,
    /// SHA-256 of the entire encrypted `.fsep` file bytes.
    pub ciphertext_sha256: ContentDigest,
    /// Per-record offset and digest metadata (ordered by offset).
    pub records: Vec<EncryptedRecordReceipt>,
}

/// Summary receipt returned after authenticating and decrypting an encrypted pack or ledger stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecryptedPackReceipt {
    /// Verified pack or ledger-epoch identifier.
    pub pack_id: PackId,
    /// Verified stream classification.
    pub stream_kind: EncryptedStreamKind,
    /// Verified schema epoch.
    pub schema_epoch: u32,
    /// Origin KEK epoch embedded in the stream header.
    pub origin_key_epoch: KeyEpoch,
    /// DEK identifier unwrapped from `KeyEnvelopeCatalog`.
    pub dek_id: DekId,
    /// Number of authenticated `FSAE` frames decrypted.
    pub frame_count: u64,
    /// Total verified plaintext byte length.
    pub plaintext_bytes: u64,
    /// Verified SHA-256 over the reconstructed plaintext stream.
    pub plaintext_sha256: ContentDigest,
    /// Verified SHA-256 over the complete input ciphertext stream.
    pub ciphertext_sha256: ContentDigest,
}

pub(crate) fn next_temp_seq() -> u64 {
    PACK_IO_TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn stage_file(
    parent: &Path,
    path: &Path,
    bytes: &[u8],
    durability: DurabilityMode,
    options: &mut OpenOptions,
) -> Result<PathBuf, PackError> {
    fs::create_dir_all(parent).map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;
    let seq = next_temp_seq();
    let base_name =
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| PackError::InvalidConfig {
                detail: "destination filename must be valid UTF-8".to_owned(),
            })?;
    let temp_path = parent.join(format!(".{base_name}.tmp.{}.{seq}", std::process::id()));
    let mut file = options
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let res = (|| -> Result<(), PackError> {
        write_all_bounded(&mut file, bytes)?;
        durability.sync_file(&file)?;
        Ok(())
    })();
    if let Err(err) = res {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    Ok(temp_path)
}

pub(crate) fn write_file_atomic(
    path: &Path,
    bytes: &[u8],
    durability: DurabilityMode,
) -> Result<(), PackError> {
    let parent = path.parent().ok_or_else(|| PackError::InvalidConfig {
        detail: "destination path has no parent directory".to_owned(),
    })?;
    let temp_path = stage_file(parent, path, bytes, durability, &mut OpenOptions::new())?;
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(PackError::io(PackIoOperation::Rename, err));
    }
    sync_dir(parent, durability)?;
    Ok(())
}

/// Publish a fully verified plaintext pack into an offline directory. Another restorer
/// can win the link, but cannot cause this operation to replace a different sealed pack.
pub(crate) fn publish_restored_pack(
    parent: &Path,
    pack_id: PackId,
    bytes: &[u8],
    durability: DurabilityMode,
) -> Result<(), PackError> {
    let path = parent.join(pack_id.file_name());
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            verify_existing_pack(&path, bytes, durability)?;
            return sync_dir(parent, durability);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(PackError::io(PackIoOperation::Metadata, err)),
    }

    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let staged = stage_file(parent, &path, bytes, durability, &mut options)?;
    let published = match fs::hard_link(&staged, &path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_existing_pack(&path, bytes, durability)
        }
        Err(err) => Err(PackError::io(PackIoOperation::Write, err)),
    };
    let removed =
        fs::remove_file(staged).map_err(|err| PackError::io(PackIoOperation::Remove, err));
    published?;
    removed?;
    sync_dir(parent, durability)
}

fn verify_existing_pack(
    path: &Path,
    bytes: &[u8],
    durability: DurabilityMode,
) -> Result<(), PackError> {
    let conflict = || PackError::ArchiveIntegrity {
        detail: "existing restore destination conflicts with verified sealed pack".to_owned(),
    };
    let metadata =
        fs::symlink_metadata(path).map_err(|err| PackError::io(PackIoOperation::Metadata, err))?;
    if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
        return Err(conflict());
    }
    let file = File::open(path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let mut scratch = [0_u8; 8192];
    let mut offset = 0;
    for chunk in bytes.chunks(scratch.len()) {
        let buf = &mut scratch[..chunk.len()];
        read_exact_at_bounded(&file, offset, buf)?;
        if buf != chunk {
            return Err(conflict());
        }
        offset += chunk.len() as u64;
    }
    durability.sync_file(&file)
}

/// Streams a sealed plaintext `.fssp` packfile into an atomic encrypted `.fsep` file on disk.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_pack_file(
    source_pack_path: impl AsRef<Path>,
    dest_enc_path: impl AsRef<Path>,
    pack_id: PackId,
    schema_epoch: u32,
    dek: DataEncryptionKey,
    origin_key_epoch: KeyEpoch,
    chunk_size: usize,
    entropy: &mut dyn EntropySource,
    durability: DurabilityMode,
) -> Result<EncryptedPackReceipt, PackError> {
    encrypt_pack_file_with_pin(
        source_pack_path,
        dest_enc_path,
        pack_id,
        schema_epoch,
        dek,
        origin_key_epoch,
        chunk_size,
        entropy,
        durability,
        None,
    )
}

/// Streams an encrypted file, comparing an optional verified full-file digest before publication.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_pack_file_with_pin(
    source_pack_path: impl AsRef<Path>,
    dest_enc_path: impl AsRef<Path>,
    pack_id: PackId,
    schema_epoch: u32,
    dek: DataEncryptionKey,
    origin_key_epoch: KeyEpoch,
    chunk_size: usize,
    entropy: &mut dyn EntropySource,
    durability: DurabilityMode,
    expected_plaintext: Option<ContentDigest>,
) -> Result<EncryptedPackReceipt, PackError> {
    if chunk_size == 0 || (chunk_size as u64) > MAX_AEAD_FRAME_PLAINTEXT_BYTES {
        return Err(PackError::InvalidConfig {
            detail: format!("chunk_size {chunk_size} outside 1..={MAX_AEAD_FRAME_PLAINTEXT_BYTES}"),
        });
    }
    let mut source =
        File::open(source_pack_path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let mut writer = EncryptedPackWriter::create(
        dest_enc_path,
        pack_id,
        EncryptedStreamKind::SealedPackChunks,
        schema_epoch,
        dek,
        origin_key_epoch,
        durability,
    )?;

    let mut buf = vec![0_u8; chunk_size];
    let mut wrote_any = false;
    loop {
        let mut filled = 0_usize;
        while filled < chunk_size {
            let n = source
                .read(&mut buf[filled..])
                .map_err(|err| PackError::io(PackIoOperation::Read, err))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            if !wrote_any {
                let _ = writer.write_record(b"", entropy)?;
            }
            break;
        }
        let _ = writer.write_record(&buf[..filled], entropy)?;
        wrote_any = true;
    }
    writer.finish_with_pin(expected_plaintext)
}

/// Authenticates and decrypts an `.fsep` file on disk and atomically writes the verified plaintext
/// `.fssp` packfile to `dest_pack_path`.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_and_verify_pack_file(
    enc_pack_path: impl AsRef<Path>,
    dest_pack_path: impl AsRef<Path>,
    expected_pack_id: PackId,
    expected_schema_epoch: u32,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    durability: DurabilityMode,
) -> Result<DecryptedPackReceipt, PackError> {
    let (plaintext, receipt) = read_authenticated_pack_file(
        enc_pack_path.as_ref(), expected_pack_id, expected_schema_epoch, catalog, kek,
    )?;
    write_file_atomic(dest_pack_path.as_ref(), &plaintext, durability)?;
    Ok(receipt)
}

/// Authenticates the FSEP envelope and verifies every sealed FSSP record before publishing output.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_and_verify_sealed_pack_file(
    enc_pack_path: impl AsRef<Path>,
    dest_pack_path: impl AsRef<Path>,
    expected_pack_id: PackId,
    expected_schema_epoch: u32,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
    durability: DurabilityMode,
) -> Result<DecryptedPackReceipt, PackError> {
    let (plaintext, receipt) = read_authenticated_pack_file(
        enc_pack_path.as_ref(), expected_pack_id, expected_schema_epoch, catalog, kek,
    )?;
    crate::packfile::verify_sealed_pack_bytes(expected_pack_id, &plaintext)?;
    write_file_atomic(dest_pack_path.as_ref(), &plaintext, durability)?;
    Ok(receipt)
}

fn read_authenticated_pack_file(
    enc_pack_path: &Path,
    expected_pack_id: PackId,
    expected_schema_epoch: u32,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
) -> Result<(Vec<u8>, DecryptedPackReceipt), PackError> {
    let mut file =
        File::open(enc_pack_path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?;

    decrypt_and_verify_pack_bytes(
        &ciphertext,
        expected_pack_id,
        EncryptedStreamKind::SealedPackChunks,
        expected_schema_epoch,
        catalog,
        kek,
    )
}

/// Encrypts a canonical ledger epoch segment (`FSSE`/`FSST` bytes) under `SCHEMA_EPOCH_LEDGER_EPOCH`.
pub fn encrypt_ledger_epoch_segment(
    epoch_id: u64,
    ledger_version: u32,
    plaintext_segment: &[u8],
    dek: &DataEncryptionKey,
    origin_key_epoch: KeyEpoch,
    chunk_size: usize,
    entropy: &mut dyn EntropySource,
) -> Result<(Vec<u8>, EncryptedPackReceipt), PackError> {
    if ledger_version == 0 || epoch_id == 0 {
        return Err(PackError::InvalidConfig {
            detail: "ledger_version and epoch_id must be >= 1".to_owned(),
        });
    }
    encrypt_pack_bytes(
        PackId::new(ledger_version, epoch_id),
        EncryptedStreamKind::LedgerEpochSegment,
        SCHEMA_EPOCH_LEDGER_EPOCH,
        plaintext_segment,
        dek,
        origin_key_epoch,
        chunk_size,
        entropy,
    )
}

/// Authenticates and decrypts an encrypted ledger epoch segment.
pub fn decrypt_and_verify_ledger_epoch_segment(
    ciphertext_segment: &[u8],
    epoch_id: u64,
    ledger_version: u32,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
) -> Result<(Vec<u8>, DecryptedPackReceipt), PackError> {
    decrypt_and_verify_pack_bytes(
        ciphertext_segment,
        PackId::new(ledger_version, epoch_id),
        EncryptedStreamKind::LedgerEpochSegment,
        SCHEMA_EPOCH_LEDGER_EPOCH,
        catalog,
        kek,
    )
}
