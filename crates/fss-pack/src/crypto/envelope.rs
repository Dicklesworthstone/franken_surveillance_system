#![forbid(unsafe_code)]
//! Narrow audited ChaCha20-Poly1305 AEAD envelope boundary and `FSAE` v1 frame codec.
//!
//! # `FSAE` v1 Binary Frame Layout (big-endian)
//!
//! ```text
//! [0..4]   magic            : [u8; 4]  = b"FSAE"
//! [4..6]   version          : u16      = 1
//! [6..7]   cipher_id        : u8       = 1 (ChaCha20Poly1305)
//! [7..8]   reserved_flags   : u8       = 0
//! [8..12]  key_epoch        : u32      (origin KEK epoch >= 1)
//! [12..16] schema_epoch     : u32      (stream/record schema epoch >= 1)
//! [16..32] dek_id           : [u8; 16] (128-bit DEK identifier)
//! [32..44] nonce_96         : [u8; 12] (96-bit ChaCha20-Poly1305 nonce)
//! [44..52] plaintext_len    : u64      (exact plaintext byte length)
//! [52..84] plaintext_sha256 : [u8; 32] (plaintext ContentDigest SHA-256)
//! [84..84+plaintext_len+16]            ciphertext || Poly1305 tag (16 bytes)
//! ```

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, sha256};
use fss_vault::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, EntropySource, aead_decrypt_zeroizing, aead_encrypt,
    constant_time_eq,
};
use zeroize::Zeroize;

use crate::error::PackError;
use crate::format::PackId;

pub(crate) use crate::crypto::keys::encode_hex_lower;
pub use crate::crypto::keys::{
    DataEncryptionKey, DekId, KeyEncryptionKey, KeyEpoch, PACK_KEK_SUBKEY_DOMAIN,
};

/// Registered stable error ID for AEAD authentication, AAD binding, or KEK verification failure.
pub const ERR_CRYPTO_AUTH_FAILED_001: &str = "ERR-CRYPTO-AUTH-FAILED-001";
/// Registered stable error ID for reads referencing a cryptographically erased DEK.
pub const ERR_CRYPTO_KEY_ERASED_001: &str = "ERR-CRYPTO-KEY-ERASED-001";

/// Canonical AAD domain binding each `FSAE` v1 record frame to pack, offset, digest, epoch, and DEK.
pub const PACK_AEAD_RECORD_AAD_DOMAIN: &str = "fss.pack.aead_record_aad.v1";
/// Canonical AAD domain binding each wrapped DEK envelope to its DEK ID, epochs, and KEK scope.
pub const PACK_DEK_WRAP_AAD_DOMAIN: &str = "fss.pack.dek_wrap_aad.v1";

/// Magic bytes identifying a versioned AEAD envelope frame (`FSAE`).
pub const AEAD_FRAME_MAGIC: [u8; 4] = *b"FSAE";
/// Supported binary format version for `FSAE` frames.
pub const AEAD_FRAME_VERSION: u16 = 1;
/// Fixed byte length of the `FSAE` v1 frame header (`84` bytes).
pub const AEAD_FRAME_HEADER_LEN: usize = 84;
/// Fixed framing overhead per `FSAE` v1 frame (`84`-byte header + `16`-byte Poly1305 tag = `100`).
pub const AEAD_FRAME_OVERHEAD_LEN: usize = AEAD_FRAME_HEADER_LEN + AEAD_TAG_LEN;
/// Hard per-frame plaintext byte bound (`64 MiB`, aligned with `fss_object::MAX_OBJECT_BYTES`).
pub const MAX_AEAD_FRAME_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024;
/// Default schema epoch for encrypted packfile object/chunk streams.
pub const SCHEMA_EPOCH_PACKFILE: u32 = 1;
/// Default schema epoch for encrypted ledger epoch segments.
pub const SCHEMA_EPOCH_LEDGER_EPOCH: u32 = 2;

/// Registered AEAD cipher suite discriminator embedded in `FSAE` v1 headers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CipherSuite {
    /// IETF RFC 8439 ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit tag).
    ChaCha20Poly1305 = 1,
}

impl CipherSuite {
    /// Encodes the cipher suite as its canonical 1-byte wire identifier.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 1,
        }
    }

    /// Decodes a cipher suite identifier, failing closed on any unknown value.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Returns the canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// Positional context bound into every `FSAE` v1 record's canonical AEAD associated data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AeadRecordContext {
    /// Owning packfile or ledger epoch identifier.
    pub pack_id: PackId,
    /// Exact byte offset of this `FSAE` frame within its container stream.
    pub record_offset: u64,
    /// Immutable schema epoch (`1` for packfiles, `2` for ledger epoch segments).
    pub schema_epoch: u32,
}

impl AeadRecordContext {
    /// Creates a new [`AeadRecordContext`].
    #[must_use]
    pub const fn new(pack_id: PackId, record_offset: u64, schema_epoch: u32) -> Self {
        Self {
            pack_id,
            record_offset,
            schema_epoch,
        }
    }
}

/// Decoded fixed 84-byte header of one `FSAE` v1 AEAD frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadFrameHeader {
    /// Frame format version (must be [`AEAD_FRAME_VERSION`]).
    pub version: u16,
    /// Registered AEAD cipher suite (must be [`CipherSuite::ChaCha20Poly1305`]).
    pub cipher: CipherSuite,
    /// Origin KEK epoch active when this frame was encrypted (preserved across zero-rewrite rotation).
    pub key_epoch: KeyEpoch,
    /// Schema epoch bound into the frame's AAD.
    pub schema_epoch: u32,
    /// Identifier of the 256-bit DEK that encrypted this frame.
    pub dek_id: DekId,
    /// Unique 96-bit ChaCha20-Poly1305 nonce.
    pub nonce: [u8; AEAD_NONCE_LEN],
    /// Exact byte length of the plaintext payload.
    pub plaintext_len: u64,
    /// SHA-256 digest of the plaintext payload (exact [`ContentDigest`] identity).
    pub plaintext_sha256: [u8; 32],
}

impl AeadFrameHeader {
    /// Returns the plaintext content identity as a SHA-256 [`ContentDigest`].
    #[must_use]
    pub const fn plaintext_digest(&self) -> ContentDigest {
        ContentDigest::new(DigestAlgorithm::Sha256, self.plaintext_sha256)
    }

    /// Returns the total encoded byte length of this frame (`84 + plaintext_len + 16`).
    pub fn frame_total_len(&self) -> Result<u64, PackError> {
        self.plaintext_len
            .checked_add(AEAD_FRAME_OVERHEAD_LEN as u64)
            .ok_or(PackError::ArithmeticOverflow)
    }

    /// Encodes the header into its fixed big-endian 84-byte wire representation.
    #[must_use]
    pub fn encode(&self) -> [u8; AEAD_FRAME_HEADER_LEN] {
        let mut out = [0_u8; AEAD_FRAME_HEADER_LEN];
        out[0..4].copy_from_slice(&AEAD_FRAME_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        out[6] = self.cipher.to_u8();
        out[7] = 0;
        out[8..12].copy_from_slice(&self.key_epoch.0.to_be_bytes());
        out[12..16].copy_from_slice(&self.schema_epoch.to_be_bytes());
        out[16..32].copy_from_slice(&self.dek_id.0);
        out[32..44].copy_from_slice(&self.nonce);
        out[44..52].copy_from_slice(&self.plaintext_len.to_be_bytes());
        out[52..84].copy_from_slice(&self.plaintext_sha256);
        out
    }

    /// Decodes a fixed 84-byte `FSAE` v1 header, failing closed with `ERR-CRYPTO-AUTH-FAILED-001`
    /// on any magic, version, cipher, flag, or zero-ID tampering.
    pub fn decode(raw: &[u8; AEAD_FRAME_HEADER_LEN]) -> Result<Self, PackError> {
        if raw[0..4] != AEAD_FRAME_MAGIC {
            return Err(PackError::CryptoAuthFailed {
                detail: "invalid FSAE frame magic".to_owned(),
            });
        }
        let version = u16::from_be_bytes([raw[4], raw[5]]);
        if version != AEAD_FRAME_VERSION {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("unsupported FSAE frame version {version}"),
            });
        }
        let cipher = CipherSuite::from_u8(raw[6]).ok_or_else(|| PackError::CryptoAuthFailed {
            detail: format!("unsupported FSAE cipher suite {}", raw[6]),
        })?;
        if raw[7] != 0 {
            return Err(PackError::CryptoAuthFailed {
                detail: format!("non-zero reserved FSAE header flags 0x{:02x}", raw[7]),
            });
        }
        let key_epoch_raw = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        if key_epoch_raw == 0 {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSAE header key_epoch cannot be 0".to_owned(),
            });
        }
        let schema_epoch = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
        if schema_epoch == 0 {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSAE header schema_epoch cannot be 0".to_owned(),
            });
        }
        let mut dek_bytes = [0_u8; 16];
        dek_bytes.copy_from_slice(&raw[16..32]);
        if dek_bytes == [0_u8; 16] {
            return Err(PackError::CryptoAuthFailed {
                detail: "FSAE header dek_id cannot be all zeros".to_owned(),
            });
        }
        let mut nonce = [0_u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&raw[32..44]);
        let plaintext_len = u64::from_be_bytes([
            raw[44], raw[45], raw[46], raw[47], raw[48], raw[49], raw[50], raw[51],
        ]);
        if plaintext_len > MAX_AEAD_FRAME_PLAINTEXT_BYTES {
            return Err(PackError::CryptoAuthFailed {
                detail: format!(
                    "FSAE plaintext_len {plaintext_len} exceeds ceiling {MAX_AEAD_FRAME_PLAINTEXT_BYTES}"
                ),
            });
        }
        let mut plaintext_sha256 = [0_u8; 32];
        plaintext_sha256.copy_from_slice(&raw[52..84]);

        Ok(Self {
            version,
            cipher,
            key_epoch: KeyEpoch(key_epoch_raw),
            schema_epoch,
            dek_id: DekId(dek_bytes),
            nonce,
            plaintext_len,
            plaintext_sha256,
        })
    }
}

/// Builds the exact canonical AAD binding `(domain, pack_id, record_offset, plaintext_sha256,
/// schema_epoch, key_epoch, dek_id)` plus frame version, cipher suite, and plaintext length.
#[must_use]
pub fn build_record_aad(ctx: AeadRecordContext, header: &AeadFrameHeader) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    enc.text(PACK_AEAD_RECORD_AAD_DOMAIN);
    enc.u32(u32::from(header.version));
    enc.u8(header.cipher.to_u8());
    enc.u32(ctx.pack_id.epoch);
    enc.u64(ctx.pack_id.seq);
    enc.u64(ctx.record_offset);
    enc.bytes(&header.plaintext_sha256);
    enc.u32(header.schema_epoch);
    enc.u32(header.key_epoch.0);
    enc.bytes(&header.dek_id.0);
    enc.u64(header.plaintext_len);
    enc.finish()
}

/// Encrypts `plaintext` into a complete self-describing `FSAE` v1 binary frame with a fresh
/// CSPRNG 96-bit nonce drawn from explicit `entropy`.
pub fn encrypt_aead_frame(
    ctx: AeadRecordContext,
    dek: &DataEncryptionKey,
    origin_key_epoch: KeyEpoch,
    plaintext: &[u8],
    entropy: &mut dyn EntropySource,
) -> Result<(AeadFrameHeader, Vec<u8>), PackError> {
    let origin_key_epoch = KeyEpoch::new(origin_key_epoch.0)?;
    if ctx.schema_epoch == 0 {
        return Err(PackError::InvalidConfig {
            detail: "AeadRecordContext schema_epoch must be >= 1".to_owned(),
        });
    }
    let plaintext_len = plaintext.len() as u64;
    if plaintext_len > MAX_AEAD_FRAME_PLAINTEXT_BYTES {
        return Err(PackError::ObjectTooLarge {
            length: plaintext_len,
            maximum: MAX_AEAD_FRAME_PLAINTEXT_BYTES,
        });
    }

    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    entropy
        .fill_bytes(&mut nonce)
        .map_err(|err| PackError::CryptoEntropy {
            detail: format!("failed to generate AEAD nonce: {err}"),
        })?;

    let header = AeadFrameHeader {
        version: AEAD_FRAME_VERSION,
        cipher: CipherSuite::ChaCha20Poly1305,
        key_epoch: origin_key_epoch,
        schema_epoch: ctx.schema_epoch,
        dek_id: dek.dek_id(),
        nonce,
        plaintext_len,
        plaintext_sha256: sha256(plaintext),
    };
    let aad = build_record_aad(ctx, &header);
    let ciphertext =
        aead_encrypt(dek.key_bytes(), &header.nonce, &aad, plaintext).map_err(|_| {
            PackError::CryptoAuthFailed {
                detail: "ChaCha20-Poly1305 frame encryption failed".to_owned(),
            }
        })?;

    let total_len = AEAD_FRAME_HEADER_LEN
        .checked_add(ciphertext.len())
        .ok_or(PackError::ArithmeticOverflow)?;
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&ciphertext);
    Ok((header, frame))
}

/// Decrypts and authenticates one `FSAE` v1 binary frame against `ctx` and `dek`.
///
/// Any bit flip in ciphertext, Poly1305 tag, nonce, header fields, `pack_id`, `record_offset`,
/// `key_epoch`, `dek_id`, `schema_epoch`, or swapping frames between offsets deterministically
/// fails with [`PackError::CryptoAuthFailed`] (`ERR-CRYPTO-AUTH-FAILED-001`).
pub fn decrypt_aead_frame(
    ctx: AeadRecordContext,
    dek: &DataEncryptionKey,
    frame_bytes: &[u8],
    expected_origin_key_epoch: Option<KeyEpoch>,
) -> Result<(AeadFrameHeader, Vec<u8>), PackError> {
    if frame_bytes.len() < AEAD_FRAME_OVERHEAD_LEN {
        return Err(PackError::CryptoAuthFailed {
            detail: format!(
                "FSAE frame truncated: {} bytes < minimum {AEAD_FRAME_OVERHEAD_LEN}",
                frame_bytes.len()
            ),
        });
    }
    let header_raw: &[u8; AEAD_FRAME_HEADER_LEN] = frame_bytes[..AEAD_FRAME_HEADER_LEN]
        .try_into()
        .map_err(|_| PackError::CryptoAuthFailed {
            detail: "failed to slice FSAE frame header".to_owned(),
        })?;
    let header = AeadFrameHeader::decode(header_raw)?;
    let expected_len =
        usize::try_from(header.frame_total_len()?).map_err(|_| PackError::CryptoAuthFailed {
            detail: "FSAE frame length overflows usize".to_owned(),
        })?;
    if frame_bytes.len() != expected_len {
        return Err(PackError::CryptoAuthFailed {
            detail: format!(
                "FSAE frame length mismatch: header declares {expected_len}, observed {}",
                frame_bytes.len()
            ),
        });
    }
    if header.dek_id != dek.dek_id() {
        return Err(PackError::CryptoAuthFailed {
            detail: format!(
                "FSAE header dek_id {} does not match supplied DEK {}",
                header.dek_id,
                dek.dek_id()
            ),
        });
    }
    if header.schema_epoch != ctx.schema_epoch {
        return Err(PackError::CryptoAuthFailed {
            detail: format!(
                "FSAE header schema_epoch {} does not match expected {}",
                header.schema_epoch, ctx.schema_epoch
            ),
        });
    }
    if let Some(expected_epoch) = expected_origin_key_epoch
        && header.key_epoch != expected_epoch
    {
        return Err(PackError::CryptoAuthFailed {
            detail: format!(
                "FSAE header key_epoch {} does not match expected origin {}",
                header.key_epoch, expected_epoch
            ),
        });
    }

    let aad = build_record_aad(ctx, &header);
    let ciphertext_and_tag = &frame_bytes[AEAD_FRAME_HEADER_LEN..];
    let mut plain_zeroizing = aead_decrypt_zeroizing(
        dek.key_bytes(),
        &header.nonce,
        &aad,
        ciphertext_and_tag,
        "FSAE ChaCha20-Poly1305 authentication failed",
    )
    .map_err(|_| PackError::CryptoAuthFailed {
        detail: "FSAE ChaCha20-Poly1305 tag or AAD verification failed".to_owned(),
    })?;

    if plain_zeroizing.len() as u64 != header.plaintext_len {
        plain_zeroizing.zeroize();
        return Err(PackError::CryptoAuthFailed {
            detail: "decrypted FSAE plaintext length mismatch".to_owned(),
        });
    }
    let computed_sha256 = sha256(&plain_zeroizing);
    if !constant_time_eq(&computed_sha256, &header.plaintext_sha256) {
        plain_zeroizing.zeroize();
        return Err(PackError::CryptoAuthFailed {
            detail: "decrypted FSAE plaintext SHA-256 mismatch".to_owned(),
        });
    }

    let plaintext = std::mem::take(&mut *plain_zeroizing);
    Ok((header, plaintext))
}
