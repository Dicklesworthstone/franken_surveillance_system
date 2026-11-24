#![forbid(unsafe_code)]
//! Pure-Rust HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA256, explicit entropy,
//! and scope-bound ChaCha20-Poly1305 AEAD primitives.

use core::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, Sha256Hasher, sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::SecretError;
use crate::secret::{SecretBytes, SecretId};

/// Canonical AAD domain binding each secret envelope to its identity, generation, and scope.
pub const VAULT_ENTRY_AAD_DOMAIN: &str = "fss.vault.entry_aad.v1";

/// Canonical AAD domain binding the encrypted vault snapshot to the authenticated header.
pub const VAULT_SNAPSHOT_AAD_DOMAIN: &str = "fss.vault.snapshot_aad.v1";

/// Canonical HMAC domain for the vault master-key verifier tag.
pub const VAULT_VERIFIER_DOMAIN: &str = "fss.vault.master_verifier.v1";

/// Canonical HKDF info domain for deriving per-record AEAD subkeys.
pub const VAULT_RECORD_KEY_DOMAIN: &str = "fss.vault.record_key.v1";

/// Canonical HKDF info domain for deriving the snapshot AEAD key.
pub const VAULT_SNAPSHOT_KEY_DOMAIN: &str = "fss.vault.snapshot_key.v1";

/// Canonical HKDF info domain for deriving OS-backend wrapping keys and envelope AAD.
pub const VAULT_OS_ENVELOPE_AAD_DOMAIN: &str = "fss.vault.os_envelope_aad.v1";

/// Canonical domain for deterministic lab entropy expansion.
pub const VAULT_LAB_ENTROPY_DOMAIN: &str = "fss.vault.lab_entropy.v1";

/// Byte length of a 256-bit ChaCha20-Poly1305 key.
pub const AEAD_KEY_LEN: usize = 32;

/// Byte length of a 96-bit ChaCha20-Poly1305 nonce.
pub const AEAD_NONCE_LEN: usize = 12;

/// Byte length of a Poly1305 authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Default production PBKDF2-HMAC-SHA256 iteration count.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Minimum PBKDF2-HMAC-SHA256 iterations enforced for production vaults.
pub const MIN_PRODUCTION_PBKDF2_ITERATIONS: u32 = 10_000;

/// Minimum PBKDF2-HMAC-SHA256 iterations permitted for test/lab overrides.
pub const MIN_TEST_PBKDF2_ITERATIONS: u32 = 1;

/// Upper bound on PBKDF2-HMAC-SHA256 iterations to prevent denial-of-service loops.
pub const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

/// Maximum HKDF-SHA256 output length per RFC 5869 (`255 * 32`).
pub const MAX_HKDF_OUTPUT_LEN: usize = 255 * 32;

/// Validated PBKDF2-HMAC-SHA256 work-factor parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    iterations: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

impl KdfParams {
    /// Creates production KDF parameters enforcing `[MIN_PRODUCTION_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS]`.
    pub fn production(iterations: u32) -> Result<Self, SecretError> {
        if !(MIN_PRODUCTION_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(SecretError::InvalidInput {
                detail: format!(
                    "production KDF iterations {iterations} outside {MIN_PRODUCTION_PBKDF2_ITERATIONS}..={MAX_PBKDF2_ITERATIONS}"
                ),
            });
        }
        Ok(Self { iterations })
    }

    /// Creates fast KDF parameters for deterministic tests and laboratories ONLY.
    ///
    /// Never use low iteration counts for operator-facing production vaults.
    pub fn for_testing(iterations: u32) -> Result<Self, SecretError> {
        if !(MIN_TEST_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(SecretError::InvalidInput {
                detail: format!(
                    "test KDF iterations {iterations} outside {MIN_TEST_PBKDF2_ITERATIONS}..={MAX_PBKDF2_ITERATIONS}"
                ),
            });
        }
        Ok(Self { iterations })
    }

    /// Returns the configured iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }
}

/// Pure-Rust RFC 2104 HMAC-SHA256 over [`fss_core::Sha256Hasher`] with zeroized key pads.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = Zeroizing::new([0_u8; 64]);
    if key.len() > 64 {
        let hashed = Zeroizing::new(sha256(key));
        key_block[..32].copy_from_slice(&*hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new([0x36_u8; 64]);
    let mut opad = Zeroizing::new([0x5c_u8; 64]);
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_hasher = Sha256Hasher::new();
    inner_hasher.update(&*ipad);
    inner_hasher.update(data);
    let inner_digest = Zeroizing::new(inner_hasher.finalize().unwrap_or([0_u8; 32]));

    let mut outer_hasher = Sha256Hasher::new();
    outer_hasher.update(&*opad);
    outer_hasher.update(&*inner_digest);
    outer_hasher.finalize().unwrap_or([0_u8; 32])
}

/// Pure-Rust RFC 5869 HKDF-SHA256 Extract step returning a zeroizing 32-byte PRK.
#[must_use]
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let actual_salt: &[u8] = if salt.is_empty() { &[0_u8; 32] } else { salt };
    Zeroizing::new(hmac_sha256(actual_salt, ikm))
}

/// Pure-Rust RFC 5869 HKDF-SHA256 Expand step returning a zeroizing output key buffer.
pub fn hkdf_sha256_expand(
    prk: &[u8; 32],
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if out_len > MAX_HKDF_OUTPUT_LEN {
        return Err(SecretError::InvalidInput {
            detail: format!("HKDF output length {out_len} exceeds {MAX_HKDF_OUTPUT_LEN}"),
        });
    }
    if out_len == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let blocks = out_len.div_ceil(32);
    let mut okm = Zeroizing::new(Vec::with_capacity(out_len));
    let mut prev = Zeroizing::new([0_u8; 32]);
    let mut has_prev = false;
    let mut input = Zeroizing::new(Vec::with_capacity(32 + info.len() + 1));

    for counter in 1..=blocks {
        input.clear();
        if has_prev {
            input.extend_from_slice(&*prev);
        }
        input.extend_from_slice(info);
        input.push(counter as u8);
        let block = Zeroizing::new(hmac_sha256(prk, &input));
        let remaining = out_len - okm.len();
        let take = remaining.min(32);
        okm.extend_from_slice(&block[..take]);
        prev.copy_from_slice(&*block);
        has_prev = true;
    }

    Ok(okm)
}

/// Allocation-free 32-byte HKDF-SHA256 Expand helper.
#[must_use]
pub fn hkdf_sha256_expand_32(prk: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::with_capacity(info.len() + 1));
    input.extend_from_slice(info);
    input.push(1_u8);
    Zeroizing::new(hmac_sha256(prk, &input))
}

/// Pure-Rust RFC 2898 / 8018 PBKDF2-HMAC-SHA256 producing a 32-byte derived key.
pub fn pbkdf2_hmac_sha256(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(SecretError::InvalidInput {
            detail: format!("PBKDF2 iterations {iterations} outside 1..={MAX_PBKDF2_ITERATIONS}"),
        });
    }
    let mut salt_block = Zeroizing::new(Vec::with_capacity(salt.len() + 4));
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1_u32.to_be_bytes());

    let mut u = Zeroizing::new(hmac_sha256(passphrase, &salt_block));
    let mut out = Zeroizing::new(*u);
    for _ in 1..iterations {
        let next = hmac_sha256(passphrase, &*u);
        u.copy_from_slice(&next);
        for (dst, src) in out.iter_mut().zip(u.iter()) {
            *dst ^= *src;
        }
    }
    Ok(out)
}

/// Explicit entropy source injected into vault cryptographic operations.
///
/// Ambient unseeded randomness is forbidden; callers supply [`OsEntropy`] in
/// production or [`LabEntropy`] in deterministic tests.
pub trait EntropySource {
    /// Fills `dest` completely with fresh random bytes or fails closed.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SecretError>;
}

/// Production OS CSPRNG reading directly from `/dev/urandom` without `unsafe`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl OsEntropy {
    /// Creates an OS CSPRNG entropy source.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EntropySource for OsEntropy {
    #[cfg(unix)]
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SecretError> {
        use std::fs::File;
        use std::io::Read;

        let mut file =
            File::open("/dev/urandom").map_err(|err| SecretError::BackendUnavailable {
                backend: "os_entropy",
                detail: format!("failed to open /dev/urandom: {:?}", err.kind()),
            })?;
        file.read_exact(dest)
            .map_err(|err| SecretError::BackendUnavailable {
                backend: "os_entropy",
                detail: format!("failed to read /dev/urandom: {:?}", err.kind()),
            })
    }

    #[cfg(not(unix))]
    fn fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), SecretError> {
        Err(SecretError::BackendUnavailable {
            backend: "os_entropy",
            detail: "OS /dev/urandom entropy is only supported on Unix targets".to_string(),
        })
    }
}

/// Deterministic seeded SHA-256 counter-mode entropy for laboratory tests ONLY.
///
/// Never use `LabEntropy` for production operator vaults.
#[derive(Clone)]
pub struct LabEntropy {
    seed: Zeroizing<[u8; 32]>,
    counter: u64,
}

impl LabEntropy {
    /// Creates a deterministic entropy stream from an explicit 32-byte test seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            counter: 0,
        }
    }
}

impl fmt::Debug for LabEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LabEntropy")
            .field("counter", &self.counter)
            .finish()
    }
}

impl EntropySource for LabEntropy {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SecretError> {
        let mut offset = 0;
        while offset < dest.len() {
            let mut hasher = Sha256Hasher::new();
            hasher.update(VAULT_LAB_ENTROPY_DOMAIN.as_bytes());
            hasher.update(&*self.seed);
            hasher.update(&self.counter.to_be_bytes());
            let block = hasher
                .finalize()
                .map_err(|_| SecretError::BackendUnavailable {
                    backend: "lab_entropy",
                    detail: "SHA-256 counter overflow".to_string(),
                })?;
            self.counter =
                self.counter
                    .checked_add(1)
                    .ok_or_else(|| SecretError::BackendUnavailable {
                        backend: "lab_entropy",
                        detail: "deterministic entropy counter exhausted".to_string(),
                    })?;
            let remaining = dest.len() - offset;
            let take = remaining.min(block.len());
            dest[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
        Ok(())
    }
}

/// Builds the canonical AAD bound to a single secret record envelope.
#[must_use]
pub fn build_entry_aad(
    secret_id: &SecretId,
    generation: u64,
    scope_digest: ContentDigest,
) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VAULT_ENTRY_AAD_DOMAIN);
    secret_id.encode_canonical(&mut encoder);
    encoder.u64(generation);
    encoder.digest(scope_digest);
    encoder.finish()
}

/// Derives a domain-separated 256-bit AEAD subkey for one `(secret_id, generation, scope_digest)`.
#[must_use]
pub fn derive_record_key(
    master_kek: &[u8; AEAD_KEY_LEN],
    secret_id: &SecretId,
    generation: u64,
    scope_digest: ContentDigest,
) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let mut info = CanonicalEncoder::new();
    info.text(VAULT_RECORD_KEY_DOMAIN);
    secret_id.encode_canonical(&mut info);
    info.u64(generation);
    info.digest(scope_digest);
    hkdf_sha256_expand_32(master_kek, &info.finish())
}

/// Derives the 256-bit snapshot AEAD key from the master KEK and vault salt.
#[must_use]
pub fn derive_snapshot_key(
    master_kek: &[u8; AEAD_KEY_LEN],
    salt: &[u8; 32],
) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let mut info = CanonicalEncoder::new();
    info.text(VAULT_SNAPSHOT_KEY_DOMAIN);
    info.bytes(salt);
    hkdf_sha256_expand_32(master_kek, &info.finish())
}

/// Computes the keyed master-key verifier tag embedded in the vault header.
#[must_use]
pub fn compute_master_verifier(
    master_kek: &[u8; AEAD_KEY_LEN],
    version: u16,
    kdf_iterations: u32,
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VAULT_VERIFIER_DOMAIN);
    encoder.u32(u32::from(version));
    encoder.u32(kdf_iterations);
    encoder.bytes(salt);
    hmac_sha256(master_kek, &encoder.finish())
}

/// Encrypts `plaintext` with ChaCha20-Poly1305 using an explicit 96-bit `nonce` and `aad`.
pub fn aead_encrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SecretError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| SecretError::Tampered {
        detail: "AEAD key initialization failed",
    })?;
    cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SecretError::Tampered {
            detail: "AEAD encryption failed",
        })
}

/// Decrypts `ciphertext` with ChaCha20-Poly1305, returning a zeroizing plaintext vector.
pub fn aead_decrypt_zeroizing(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tamper_detail: &'static str,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(SecretError::Tampered {
            detail: tamper_detail,
        });
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| SecretError::Tampered {
        detail: tamper_detail,
    })?;
    let plain = cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SecretError::Tampered {
            detail: tamper_detail,
        })?;
    Ok(Zeroizing::new(plain))
}

/// Encrypts a [`SecretBytes`] payload into a per-record AEAD ciphertext with fresh nonce.
pub fn seal_secret_entry(
    master_kek: &[u8; AEAD_KEY_LEN],
    secret_id: &SecretId,
    generation: u64,
    scope_digest: ContentDigest,
    secret: &SecretBytes,
    entropy: &mut dyn EntropySource,
) -> Result<([u8; AEAD_NONCE_LEN], Vec<u8>), SecretError> {
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    entropy.fill_bytes(&mut nonce)?;
    let record_key = derive_record_key(master_kek, secret_id, generation, scope_digest);
    let aad = build_entry_aad(secret_id, generation, scope_digest);
    let ciphertext = aead_encrypt(&record_key, &nonce, &aad, secret.as_slice())?;
    Ok((nonce, ciphertext))
}

/// Decrypts and authenticates a per-record AEAD ciphertext into [`SecretBytes`].
pub fn open_secret_entry(
    master_kek: &[u8; AEAD_KEY_LEN],
    secret_id: &SecretId,
    generation: u64,
    scope_digest: ContentDigest,
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<SecretBytes, SecretError> {
    let record_key = derive_record_key(master_kek, secret_id, generation, scope_digest);
    let aad = build_entry_aad(secret_id, generation, scope_digest);
    let mut plain = aead_decrypt_zeroizing(
        &record_key,
        nonce,
        &aad,
        ciphertext,
        "per-secret AEAD authentication failed",
    )?;
    let bytes = core::mem::take(&mut *plain);
    let result = SecretBytes::new(bytes);
    plain.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_vectors() {
        // RFC 4231 Test Case 1
        let key1 = [0x0b_u8; 20];
        let mac1 = hmac_sha256(&key1, b"Hi There");
        assert_eq!(
            to_hex(&mac1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 Test Case 2
        let mac2 = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&mac2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 4231 Test Case 6 (key longer than 64-byte block size)
        let key6 = [0xaa_u8; 131];
        let mac6 = hmac_sha256(
            &key6,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            to_hex(&mac6),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc5869_case1() -> Result<(), SecretError> {
        let ikm = [0x0b_u8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_sha256_extract(&salt, &ikm);
        assert_eq!(
            to_hex(&*prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_sha256_expand(&prk, &info, 42)?;
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        Ok(())
    }

    #[test]
    fn pbkdf2_hmac_sha256_matches_rfc6070_style_vectors() -> Result<(), SecretError> {
        let dk1 = pbkdf2_hmac_sha256(b"password", b"salt", 1)?;
        assert_eq!(
            to_hex(&*dk1),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        let dk2 = pbkdf2_hmac_sha256(b"password", b"salt", 2)?;
        assert_eq!(
            to_hex(&*dk2),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        let dk4096 = pbkdf2_hmac_sha256(b"password", b"salt", 4096)?;
        assert_eq!(
            to_hex(&*dk4096),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
        Ok(())
    }
}
