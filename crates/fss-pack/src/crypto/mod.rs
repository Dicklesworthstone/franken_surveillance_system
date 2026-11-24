#![forbid(unsafe_code)]
//! Client-side AEAD envelope encryption at rest (`FSAE` v1 / `FSEP` v1), zero-rewrite KEK
//! rotation (`KeyEnvelopeCatalog`), and durable cryptographic erasure (`--crypto-erase`).

pub mod envelope;
pub mod erasure;
pub mod keyring;
mod keyring_codec;
mod keys;
mod pack_codec;
pub mod pack_io;

pub use envelope::{
    AEAD_FRAME_HEADER_LEN, AEAD_FRAME_MAGIC, AEAD_FRAME_OVERHEAD_LEN, AEAD_FRAME_VERSION,
    AeadFrameHeader, AeadRecordContext, CipherSuite, DataEncryptionKey, DekId,
    ERR_CRYPTO_AUTH_FAILED_001, ERR_CRYPTO_KEY_ERASED_001, KeyEncryptionKey, KeyEpoch,
    MAX_AEAD_FRAME_PLAINTEXT_BYTES, PACK_AEAD_RECORD_AAD_DOMAIN, PACK_DEK_WRAP_AAD_DOMAIN,
    PACK_KEK_SUBKEY_DOMAIN, SCHEMA_EPOCH_LEDGER_EPOCH, SCHEMA_EPOCH_PACKFILE, build_record_aad,
    decrypt_aead_frame, encrypt_aead_frame,
};
pub use erasure::{
    CryptoErasureReceipt, ErasedDekTombstone, MAX_ERASURE_TEXT_LEN,
    PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN,
};
pub use keyring::{
    KEY_CATALOG_MAGIC, KEY_CATALOG_VERSION, KekRotationReceipt, KeyEnvelopeCatalog,
    MAX_KEY_CATALOG_BYTES, PACK_KEY_CATALOG_HEADER_DOMAIN, WRAPPED_DEK_CIPHERTEXT_LEN,
    WrappedDekEnvelope,
};
pub use pack_io::{
    DEFAULT_ENCRYPTION_CHUNK_BYTES, DecryptedPackReceipt, ENCRYPTED_PACK_END_MAGIC,
    ENCRYPTED_PACK_HEADER_LEN, ENCRYPTED_PACK_MAGIC, ENCRYPTED_PACK_TRAILER_LEN,
    ENCRYPTED_PACK_TRAILER_MAGIC, ENCRYPTED_PACK_VERSION, EncryptedPackHeader, EncryptedPackReader,
    EncryptedPackReceipt, EncryptedPackTrailer, EncryptedPackWriter, EncryptedRecordReceipt,
    EncryptedStreamKind, decrypt_and_verify_ledger_epoch_segment, decrypt_and_verify_pack_bytes,
    decrypt_and_verify_pack_file, encrypt_ledger_epoch_segment, encrypt_pack_bytes,
    encrypt_pack_file,
};
