#![forbid(unsafe_code)]
//! Encrypted packfile record streams (`EncryptedPackWriter` / `EncryptedPackReader`) and
//! whole-pack / ledger-epoch encryption helpers.
//!
//! Raw plaintext bytes of video frames, JPEGs, manifests, or ledger segments NEVER touch disk in
//! any encrypted output file.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use fss_vault::{AEAD_NONCE_LEN, EntropySource, VAULT_FILE_MODE, constant_time_eq};

use crate::crypto::envelope::{
    AEAD_FRAME_HEADER_LEN, AEAD_FRAME_OVERHEAD_LEN, AeadFrameHeader, AeadRecordContext,
    CipherSuite, DataEncryptionKey, KeyEncryptionKey, KeyEpoch, MAX_AEAD_FRAME_PLAINTEXT_BYTES,
    decrypt_aead_frame, encrypt_aead_frame,
};
use crate::crypto::keyring::KeyEnvelopeCatalog;
use crate::crypto::pack_codec::next_temp_seq;
use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, PackId, read_exact_at_bounded, sync_dir, write_all_bounded};

pub(crate) use crate::crypto::pack_codec::{publish_restored_pack, write_file_atomic};
pub use crate::crypto::pack_codec::{
    DEFAULT_ENCRYPTION_CHUNK_BYTES, DecryptedPackReceipt, ENCRYPTED_PACK_END_MAGIC,
    ENCRYPTED_PACK_HEADER_LEN, ENCRYPTED_PACK_MAGIC, ENCRYPTED_PACK_TRAILER_LEN,
    ENCRYPTED_PACK_TRAILER_MAGIC, ENCRYPTED_PACK_VERSION, EncryptedPackHeader,
    EncryptedPackReceipt, EncryptedPackTrailer, EncryptedRecordReceipt, EncryptedStreamKind,
    decrypt_and_verify_ledger_epoch_segment, decrypt_and_verify_pack_file,
    encrypt_ledger_epoch_segment, encrypt_pack_file,
};

/// Atomic encrypted packfile writer that NEVER writes raw plaintext bytes to disk.
pub struct EncryptedPackWriter {
    target_path: PathBuf,
    temp_path: PathBuf,
    file: File,
    durability: DurabilityMode,
    header: EncryptedPackHeader,
    dek: DataEncryptionKey,
    offset: u64,
    frame_count: u64,
    plaintext_bytes: u64,
    plaintext_hasher: Sha256Hasher,
    ciphertext_prefix_hasher: Sha256Hasher,
    whole_ciphertext_hasher: Sha256Hasher,
    seen_nonces: HashSet<[u8; AEAD_NONCE_LEN]>,
    records: Vec<EncryptedRecordReceipt>,
    finished: bool,
}

impl EncryptedPackWriter {
    /// Creates a staged encrypted `.fsep` stream writer targeting `path`.
    ///
    /// Frames are written into a `0600` sibling temporary file and atomically renamed into `path`
    /// only when [`Self::finish`] succeeds.
    pub fn create(
        path: impl AsRef<Path>,
        pack_id: PackId,
        stream_kind: EncryptedStreamKind,
        schema_epoch: u32,
        dek: DataEncryptionKey,
        origin_key_epoch: KeyEpoch,
        durability: DurabilityMode,
    ) -> Result<Self, PackError> {
        let origin_key_epoch = KeyEpoch::new(origin_key_epoch.0)?;
        if schema_epoch == 0 {
            return Err(PackError::InvalidConfig {
                detail: "schema_epoch must be >= 1".to_owned(),
            });
        }
        let target_path = path.as_ref().to_path_buf();
        let parent = target_path
            .parent()
            .ok_or_else(|| PackError::InvalidConfig {
                detail: "encrypted pack path has no parent directory".to_owned(),
            })?;
        fs::create_dir_all(parent).map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;

        let seq = next_temp_seq();
        let base_name = target_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| PackError::InvalidConfig {
                detail: "encrypted pack filename must be valid UTF-8".to_owned(),
            })?;
        let temp_path = parent.join(format!(".{base_name}.tmp.{}.{seq}", std::process::id()));

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(VAULT_FILE_MODE);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;

        let header = EncryptedPackHeader {
            version: ENCRYPTED_PACK_VERSION,
            cipher: CipherSuite::ChaCha20Poly1305,
            stream_kind,
            pack_id,
            key_epoch: origin_key_epoch,
            schema_epoch,
            dek_id: dek.dek_id(),
        };
        let header_bytes = header.encode();
        if let Err(err) = write_all_bounded(&mut file, &header_bytes) {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }

        let mut ciphertext_prefix_hasher = Sha256Hasher::new();
        ciphertext_prefix_hasher.update(&header_bytes);
        let mut whole_ciphertext_hasher = Sha256Hasher::new();
        whole_ciphertext_hasher.update(&header_bytes);

        Ok(Self {
            target_path,
            temp_path,
            file,
            durability,
            header,
            dek,
            offset: ENCRYPTED_PACK_HEADER_LEN as u64,
            frame_count: 0,
            plaintext_bytes: 0,
            plaintext_hasher: Sha256Hasher::new(),
            ciphertext_prefix_hasher,
            whole_ciphertext_hasher,
            seen_nonces: HashSet::new(),
            records: Vec::new(),
            finished: false,
        })
    }

    /// Encrypts `plaintext` in memory with a unique 96-bit nonce and writes only the `FSAE` v1
    /// ciphertext frame to disk.
    pub fn write_record(
        &mut self,
        plaintext: &[u8],
        entropy: &mut dyn EntropySource,
    ) -> Result<EncryptedRecordReceipt, PackError> {
        let ctx =
            AeadRecordContext::new(self.header.pack_id, self.offset, self.header.schema_epoch);
        let (frame_header, frame_bytes) =
            encrypt_aead_frame(ctx, &self.dek, self.header.key_epoch, plaintext, entropy)?;
        if !self.seen_nonces.insert(frame_header.nonce) {
            return Err(PackError::CryptoEntropy {
                detail: "duplicate 96-bit AEAD nonce detected within encrypted pack stream"
                    .to_owned(),
            });
        }

        write_all_bounded(&mut self.file, &frame_bytes)?;
        self.plaintext_hasher.update(plaintext);
        self.ciphertext_prefix_hasher.update(&frame_bytes);
        self.whole_ciphertext_hasher.update(&frame_bytes);

        let receipt = EncryptedRecordReceipt {
            record_offset: self.offset,
            frame_len: frame_bytes.len() as u64,
            plaintext_len: frame_header.plaintext_len,
            plaintext_digest: frame_header.plaintext_digest(),
            nonce: frame_header.nonce,
        };
        self.offset = self
            .offset
            .checked_add(frame_bytes.len() as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        self.frame_count = self
            .frame_count
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        self.plaintext_bytes = self
            .plaintext_bytes
            .checked_add(frame_header.plaintext_len)
            .ok_or(PackError::ArithmeticOverflow)?;
        self.records.push(receipt);
        Ok(receipt)
    }

    /// Writes the authenticated `FSPT`..`FSPE` trailer, fsyncs, and atomically publishes the file.
    pub fn finish(mut self) -> Result<EncryptedPackReceipt, PackError> {
        let plaintext_sha_raw = self
            .plaintext_hasher
            .clone()
            .finalize()
            .map_err(|_| PackError::ArithmeticOverflow)?;
        let (_trailer, trailer_bytes) = EncryptedPackTrailer::encode(
            self.frame_count,
            self.plaintext_bytes,
            plaintext_sha_raw,
            self.ciphertext_prefix_hasher.clone(),
        )?;
        write_all_bounded(&mut self.file, &trailer_bytes)?;
        self.durability.sync_file(&self.file)?;

        self.whole_ciphertext_hasher.update(&trailer_bytes);
        let whole_ciphertext_sha = self
            .whole_ciphertext_hasher
            .clone()
            .finalize()
            .map_err(|_| PackError::ArithmeticOverflow)?;
        let ciphertext_bytes = self
            .offset
            .checked_add(ENCRYPTED_PACK_TRAILER_LEN as u64)
            .ok_or(PackError::ArithmeticOverflow)?;

        fs::rename(&self.temp_path, &self.target_path)
            .map_err(|err| PackError::io(PackIoOperation::Rename, err))?;
        if let Some(parent) = self.target_path.parent() {
            sync_dir(parent, self.durability)?;
        }
        self.finished = true;

        Ok(EncryptedPackReceipt {
            pack_id: self.header.pack_id,
            stream_kind: self.header.stream_kind,
            schema_epoch: self.header.schema_epoch,
            origin_key_epoch: self.header.key_epoch,
            dek_id: self.header.dek_id,
            frame_count: self.frame_count,
            plaintext_bytes: self.plaintext_bytes,
            plaintext_sha256: ContentDigest::new(DigestAlgorithm::Sha256, plaintext_sha_raw),
            ciphertext_bytes,
            ciphertext_sha256: ContentDigest::new(DigestAlgorithm::Sha256, whole_ciphertext_sha),
            records: std::mem::take(&mut self.records),
        })
    }
}

impl Drop for EncryptedPackWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

/// Random-access and full-stream authenticated reader over an encrypted `FSEP` v1 file.
pub struct EncryptedPackReader {
    file: File,
    file_len: u64,
    header: EncryptedPackHeader,
    trailer: EncryptedPackTrailer,
}

impl EncryptedPackReader {
    /// Opens an `.fsep` file and validates its `FSEP` header and `FSPT`..`FSPE` trailer structure.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PackError> {
        let file = File::open(path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        let file_len = file
            .metadata()
            .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
            .len();
        if file_len < (ENCRYPTED_PACK_HEADER_LEN + ENCRYPTED_PACK_TRAILER_LEN) as u64 {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("FSEP file truncated: {file_len} bytes"),
            });
        }
        let mut header_raw = [0_u8; ENCRYPTED_PACK_HEADER_LEN];
        read_exact_at_bounded(&file, 0, &mut header_raw)?;
        let header = EncryptedPackHeader::decode(&header_raw)?;

        let mut trailer_raw = [0_u8; ENCRYPTED_PACK_TRAILER_LEN];
        read_exact_at_bounded(
            &file,
            file_len - ENCRYPTED_PACK_TRAILER_LEN as u64,
            &mut trailer_raw,
        )?;
        let trailer = EncryptedPackTrailer::decode(&trailer_raw)?;

        Ok(Self {
            file,
            file_len,
            header,
            trailer,
        })
    }

    /// Returns the decoded `FSEP` v1 stream header.
    #[must_use]
    pub const fn header(&self) -> EncryptedPackHeader {
        self.header
    }

    /// Returns the decoded `FSPT`..`FSPE` trailer.
    #[must_use]
    pub const fn trailer(&self) -> EncryptedPackTrailer {
        self.trailer
    }

    /// Positional authenticated read of one `FSAE` v1 frame at `record_offset` using `dek`.
    pub fn read_frame_at(
        &self,
        record_offset: u64,
        dek: &DataEncryptionKey,
        expected_origin_key_epoch: Option<KeyEpoch>,
    ) -> Result<(AeadFrameHeader, Vec<u8>), PackError> {
        let trailer_start = self
            .file_len
            .checked_sub(ENCRYPTED_PACK_TRAILER_LEN as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        if record_offset < ENCRYPTED_PACK_HEADER_LEN as u64
            || record_offset
                .checked_add(AEAD_FRAME_OVERHEAD_LEN as u64)
                .is_none_or(|end| end > trailer_start)
        {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("record_offset {record_offset} out of FSEP frame bounds"),
            });
        }
        let mut hdr_buf = [0_u8; AEAD_FRAME_HEADER_LEN];
        read_exact_at_bounded(&self.file, record_offset, &mut hdr_buf)?;
        let preview = AeadFrameHeader::decode(&hdr_buf)?;
        let total_len_u64 = preview.frame_total_len()?;
        let frame_end = record_offset
            .checked_add(total_len_u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        if frame_end > trailer_start {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSAE frame extends beyond FSEP trailer boundary".to_owned(),
            });
        }
        let total_len =
            usize::try_from(total_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
        let mut raw_frame = vec![0_u8; total_len];
        read_exact_at_bounded(&self.file, record_offset, &mut raw_frame)?;
        let ctx =
            AeadRecordContext::new(self.header.pack_id, record_offset, self.header.schema_epoch);
        decrypt_aead_frame(ctx, dek, &raw_frame, expected_origin_key_epoch)
    }

    /// Positional authenticated read resolving the stream's DEK via `catalog` and `kek`.
    pub fn read_frame_with_catalog(
        &self,
        record_offset: u64,
        catalog: &KeyEnvelopeCatalog,
        kek: &KeyEncryptionKey,
    ) -> Result<(AeadFrameHeader, Vec<u8>), PackError> {
        let dek = catalog.unwrap_dek(self.header.dek_id, kek)?;
        let envelope = catalog.get_envelope(self.header.dek_id).ok_or_else(|| {
            PackError::CryptoKeyNotFound {
                dek_id: self.header.dek_id.to_hex(),
            }
        })?;
        if self.header.key_epoch != envelope.origin_key_epoch {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP header origin key_epoch does not match catalog envelope".to_owned(),
            });
        }
        self.read_frame_at(record_offset, &dek, Some(envelope.origin_key_epoch))
    }

    /// Sequentially decrypts and verifies every `FSAE` frame plus the `FSPT`..`FSPE` trailer.
    pub fn decrypt_all_records(
        &self,
        catalog: &KeyEnvelopeCatalog,
        kek: &KeyEncryptionKey,
    ) -> Result<Vec<(ContentDigest, Vec<u8>)>, PackError> {
        let dek = catalog.unwrap_dek(self.header.dek_id, kek)?;
        let envelope = catalog.get_envelope(self.header.dek_id).ok_or_else(|| {
            PackError::CryptoKeyNotFound {
                dek_id: self.header.dek_id.to_hex(),
            }
        })?;
        if self.header.key_epoch != envelope.origin_key_epoch {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP header origin key_epoch does not match catalog envelope".to_owned(),
            });
        }

        let trailer_start = self
            .file_len
            .checked_sub(ENCRYPTED_PACK_TRAILER_LEN as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        let mut header_raw = [0_u8; ENCRYPTED_PACK_HEADER_LEN];
        read_exact_at_bounded(&self.file, 0, &mut header_raw)?;
        let mut prefix_hasher = Sha256Hasher::new();
        prefix_hasher.update(&header_raw);
        let mut plain_hasher = Sha256Hasher::new();

        let mut offset = ENCRYPTED_PACK_HEADER_LEN as u64;
        let mut count = 0_u64;
        let mut total_plain = 0_u64;
        let mut records = Vec::new();

        while offset < trailer_start {
            if trailer_start - offset < AEAD_FRAME_OVERHEAD_LEN as u64 {
                return Err(PackError::CryptoAuthFailed {
                    detail: "trailing truncated FSAE frame before FSEP trailer".to_owned(),
                });
            }
            let mut hdr_buf = [0_u8; AEAD_FRAME_HEADER_LEN];
            read_exact_at_bounded(&self.file, offset, &mut hdr_buf)?;
            let preview = AeadFrameHeader::decode(&hdr_buf)?;
            let frame_len_u64 = preview.frame_total_len()?;
            if offset
                .checked_add(frame_len_u64)
                .is_none_or(|end| end > trailer_start)
            {
                return Err(PackError::CryptoAuthFailed {
                    detail: "FSAE frame overruns FSEP trailer boundary".to_owned(),
                });
            }
            let frame_len =
                usize::try_from(frame_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
            let mut raw_frame = vec![0_u8; frame_len];
            read_exact_at_bounded(&self.file, offset, &mut raw_frame)?;
            prefix_hasher.update(&raw_frame);

            let ctx = AeadRecordContext::new(self.header.pack_id, offset, self.header.schema_epoch);
            let (frame_hdr, plaintext) =
                decrypt_aead_frame(ctx, &dek, &raw_frame, Some(envelope.origin_key_epoch))?;
            plain_hasher.update(&plaintext);
            total_plain = total_plain
                .checked_add(plaintext.len() as u64)
                .ok_or(PackError::ArithmeticOverflow)?;
            count = count.checked_add(1).ok_or(PackError::ArithmeticOverflow)?;
            records.push((frame_hdr.plaintext_digest(), plaintext));

            offset = offset
                .checked_add(frame_len_u64)
                .ok_or(PackError::ArithmeticOverflow)?;
        }

        let mut trailer_raw = [0_u8; ENCRYPTED_PACK_TRAILER_LEN];
        read_exact_at_bounded(&self.file, trailer_start, &mut trailer_raw)?;
        prefix_hasher.update(&trailer_raw[..52]);
        let computed_prefix_sha = prefix_hasher
            .finalize()
            .map_err(|_| PackError::ArithmeticOverflow)?;
        let computed_plain_sha = plain_hasher
            .finalize()
            .map_err(|_| PackError::ArithmeticOverflow)?;

        if count != self.trailer.frame_count
            || total_plain != self.trailer.total_plaintext_bytes
            || !constant_time_eq(&computed_plain_sha, &self.trailer.plaintext_stream_sha256)
            || !constant_time_eq(&computed_prefix_sha, &self.trailer.ciphertext_prefix_sha256)
        {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSEP trailer integrity verification failed".to_owned(),
            });
        }
        Ok(records)
    }
}

/// Encrypts a byte buffer (sealed `.fssp` packfile or ledger epoch segment) into an `FSEP` v1
/// ciphertext stream split into bounded `FSAE` v1 frames.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_pack_bytes(
    pack_id: PackId,
    stream_kind: EncryptedStreamKind,
    schema_epoch: u32,
    plaintext: &[u8],
    dek: &DataEncryptionKey,
    origin_key_epoch: KeyEpoch,
    chunk_size: usize,
    entropy: &mut dyn EntropySource,
) -> Result<(Vec<u8>, EncryptedPackReceipt), PackError> {
    let origin_key_epoch = KeyEpoch::new(origin_key_epoch.0)?;
    if schema_epoch == 0 {
        return Err(PackError::InvalidConfig {
            detail: "schema_epoch must be >= 1".to_owned(),
        });
    }
    if chunk_size == 0 || (chunk_size as u64) > MAX_AEAD_FRAME_PLAINTEXT_BYTES {
        return Err(PackError::InvalidConfig {
            detail: format!("chunk_size {chunk_size} outside 1..={MAX_AEAD_FRAME_PLAINTEXT_BYTES}"),
        });
    }

    let header = EncryptedPackHeader {
        version: ENCRYPTED_PACK_VERSION,
        cipher: CipherSuite::ChaCha20Poly1305,
        stream_kind,
        pack_id,
        key_epoch: origin_key_epoch,
        schema_epoch,
        dek_id: dek.dek_id(),
    };
    let header_bytes = header.encode();

    let chunk_count = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(chunk_size)
    };
    let estimated_len = ENCRYPTED_PACK_HEADER_LEN
        .saturating_add(plaintext.len())
        .saturating_add(chunk_count.saturating_mul(AEAD_FRAME_OVERHEAD_LEN))
        .saturating_add(ENCRYPTED_PACK_TRAILER_LEN);
    let mut out = Vec::with_capacity(estimated_len);
    out.extend_from_slice(&header_bytes);

    let mut plain_hasher = Sha256Hasher::new();
    let mut prefix_hasher = Sha256Hasher::new();
    prefix_hasher.update(&header_bytes);
    let mut seen_nonces = HashSet::with_capacity(chunk_count);
    let mut records = Vec::with_capacity(chunk_count);

    let slices: Vec<&[u8]> = if plaintext.is_empty() {
        vec![b""]
    } else {
        plaintext.chunks(chunk_size).collect()
    };
    for chunk in slices {
        let offset = out.len() as u64;
        let ctx = AeadRecordContext::new(pack_id, offset, schema_epoch);
        let (hdr, frame) = encrypt_aead_frame(ctx, dek, origin_key_epoch, chunk, entropy)?;
        if !seen_nonces.insert(hdr.nonce) {
            return Err(PackError::CryptoEntropy {
                detail: "duplicate AEAD nonce detected".to_owned(),
            });
        }
        plain_hasher.update(chunk);
        prefix_hasher.update(&frame);
        records.push(EncryptedRecordReceipt {
            record_offset: offset,
            frame_len: frame.len() as u64,
            plaintext_len: hdr.plaintext_len,
            plaintext_digest: hdr.plaintext_digest(),
            nonce: hdr.nonce,
        });
        out.extend_from_slice(&frame);
    }

    let plain_sha = plain_hasher
        .finalize()
        .map_err(|_| PackError::ArithmeticOverflow)?;
    let (_trailer, trailer_bytes) = EncryptedPackTrailer::encode(
        records.len() as u64,
        plaintext.len() as u64,
        plain_sha,
        prefix_hasher,
    )?;
    out.extend_from_slice(&trailer_bytes);
    let ciphertext_sha256 = ContentDigest::sha256(&out);

    let receipt = EncryptedPackReceipt {
        pack_id,
        stream_kind,
        schema_epoch,
        origin_key_epoch,
        dek_id: dek.dek_id(),
        frame_count: records.len() as u64,
        plaintext_bytes: plaintext.len() as u64,
        plaintext_sha256: ContentDigest::new(DigestAlgorithm::Sha256, plain_sha),
        ciphertext_bytes: out.len() as u64,
        ciphertext_sha256,
        records,
    };
    Ok((out, receipt))
}

/// Authenticates and decrypts an `FSEP` v1 ciphertext byte slice using `catalog` and `kek`.
pub fn decrypt_and_verify_pack_bytes(
    ciphertext: &[u8],
    expected_pack_id: PackId,
    expected_stream_kind: EncryptedStreamKind,
    expected_schema_epoch: u32,
    catalog: &KeyEnvelopeCatalog,
    kek: &KeyEncryptionKey,
) -> Result<(Vec<u8>, DecryptedPackReceipt), PackError> {
    if ciphertext.len() < ENCRYPTED_PACK_HEADER_LEN + ENCRYPTED_PACK_TRAILER_LEN {
        return Err(PackError::CryptoAuthFailed {
            detail: "FSEP ciphertext stream truncated".to_owned(),
        });
    }
    let header_raw: &[u8; ENCRYPTED_PACK_HEADER_LEN] = ciphertext[..ENCRYPTED_PACK_HEADER_LEN]
        .try_into()
        .map_err(|_| PackError::CryptoAuthFailed {
            detail: "failed to slice FSEP header".to_owned(),
        })?;
    let header = EncryptedPackHeader::decode(header_raw)?;

    let dek = catalog.unwrap_dek(header.dek_id, kek)?;
    let envelope =
        catalog
            .get_envelope(header.dek_id)
            .ok_or_else(|| PackError::CryptoKeyNotFound {
                dek_id: header.dek_id.to_hex(),
            })?;

    if header.pack_id != expected_pack_id
        || header.stream_kind != expected_stream_kind
        || header.schema_epoch != expected_schema_epoch
        || header.key_epoch != envelope.origin_key_epoch
    {
        return Err(PackError::CryptoAuthFailed {
            detail: "FSEP stream header binding mismatch".to_owned(),
        });
    }

    let trailer_start = ciphertext.len() - ENCRYPTED_PACK_TRAILER_LEN;
    let trailer_raw: &[u8; ENCRYPTED_PACK_TRAILER_LEN] = ciphertext[trailer_start..]
        .try_into()
        .map_err(|_| PackError::CryptoAuthFailed {
            detail: "failed to slice FSEP trailer".to_owned(),
        })?;
    let trailer = EncryptedPackTrailer::decode(trailer_raw)?;

    let mut prefix_hasher = Sha256Hasher::new();
    prefix_hasher.update(&ciphertext[..trailer_start + 52]);
    let computed_prefix_sha = prefix_hasher
        .finalize()
        .map_err(|_| PackError::ArithmeticOverflow)?;
    if !constant_time_eq(&computed_prefix_sha, &trailer.ciphertext_prefix_sha256) {
        return Err(PackError::CryptoAuthFailed {
            detail: "FSEP ciphertext prefix SHA-256 verification failed".to_owned(),
        });
    }

    let mut cursor = ENCRYPTED_PACK_HEADER_LEN;
    let mut frame_count = 0_u64;
    let mut plaintext_out =
        Vec::with_capacity(usize::try_from(trailer.total_plaintext_bytes).unwrap_or(0));
    let mut plain_hasher = Sha256Hasher::new();

    while cursor < trailer_start {
        if trailer_start - cursor < AEAD_FRAME_OVERHEAD_LEN {
            return Err(PackError::CryptoAuthFailed {
                detail: "truncated FSAE frame inside FSEP stream".to_owned(),
            });
        }
        let hdr_raw: &[u8; AEAD_FRAME_HEADER_LEN] = ciphertext
            [cursor..cursor + AEAD_FRAME_HEADER_LEN]
            .try_into()
            .map_err(|_| PackError::CryptoAuthFailed {
                detail: "failed to slice inner FSAE header".to_owned(),
            })?;
        let preview = AeadFrameHeader::decode(hdr_raw)?;
        let frame_len = usize::try_from(preview.frame_total_len()?).map_err(|_| {
            PackError::CryptoAuthFailed {
                detail: "inner FSAE frame length overflows usize".to_owned(),
            }
        })?;
        if cursor
            .checked_add(frame_len)
            .is_none_or(|end| end > trailer_start)
        {
            return Err(PackError::CryptoAuthFailed {
                detail: "inner FSAE frame overruns trailer".to_owned(),
            });
        }
        let ctx = AeadRecordContext::new(header.pack_id, cursor as u64, header.schema_epoch);
        let (_hdr, chunk_plain) = decrypt_aead_frame(
            ctx,
            &dek,
            &ciphertext[cursor..cursor + frame_len],
            Some(envelope.origin_key_epoch),
        )?;
        plain_hasher.update(&chunk_plain);
        plaintext_out.extend_from_slice(&chunk_plain);
        frame_count = frame_count
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        cursor += frame_len;
    }

    let computed_plain_sha = plain_hasher
        .finalize()
        .map_err(|_| PackError::ArithmeticOverflow)?;
    if frame_count != trailer.frame_count
        || plaintext_out.len() as u64 != trailer.total_plaintext_bytes
        || !constant_time_eq(&computed_plain_sha, &trailer.plaintext_stream_sha256)
    {
        return Err(PackError::CryptoAuthFailed {
            detail: "FSEP decrypted stream length or SHA-256 mismatch".to_owned(),
        });
    }

    let receipt = DecryptedPackReceipt {
        pack_id: header.pack_id,
        stream_kind: header.stream_kind,
        schema_epoch: header.schema_epoch,
        origin_key_epoch: header.key_epoch,
        dek_id: header.dek_id,
        frame_count,
        plaintext_bytes: plaintext_out.len() as u64,
        plaintext_sha256: ContentDigest::new(DigestAlgorithm::Sha256, computed_plain_sha),
        ciphertext_sha256: ContentDigest::sha256(ciphertext),
    };
    Ok((plaintext_out, receipt))
}
