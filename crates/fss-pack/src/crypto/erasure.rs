#![forbid(unsafe_code)]
//! Cryptographic erasure (`--crypto-erase` / `PRIV-010`) tombstones and signed canonical receipts.
//!
//! Explicitly distinguishes cryptographic erasure (`cryptographic_erasure = true`, DEK envelope
//! zeroized and replaced by [`ErasedDekTombstone`]) from physical unlink, provider expiration, or
//! unknown third-party copies.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, TimestampNs,
};
use fss_vault::{constant_time_eq, hmac_sha256};

use crate::crypto::envelope::{DekId, KeyEncryptionKey, KeyEpoch, encode_hex_lower};
use crate::error::PackError;
use crate::format::PackId;

/// Canonical digest & MAC domain for signed [`CryptoErasureReceipt`]s.
pub const PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN: &str = "fss.pack.crypto_erasure_receipt.v1";

/// Maximum byte length allowed for erasure `reason` or `actor` text fields.
pub const MAX_ERASURE_TEXT_LEN: usize = 512;

/// Permanent non-secret tombstone replacing a destroyed `WrappedDekEnvelope` in `KeyEnvelopeCatalog`.
///
/// Contains ZERO wrapped DEK ciphertext or nonce bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasedDekTombstone {
    /// Identifier of the permanently erased Data Encryption Key.
    pub dek_id: DekId,
    /// Original KEK epoch under which the DEK was created.
    pub origin_key_epoch: KeyEpoch,
    /// Active KEK epoch under which the DEK was wrapped immediately prior to erasure.
    pub last_kek_epoch: KeyEpoch,
    /// Canonically sorted, deduplicated packfiles bound to this erased DEK.
    pub affected_pack_ids: Vec<PackId>,
    /// Operator or policy erasure rationale (non-secret).
    pub reason: String,
    /// Authorized actor identity performing the cryptographic erasure.
    pub actor: String,
    /// Explicit caller-supplied erasure timestamp (no ambient clock).
    pub erased_at_ns: TimestampNs,
    /// Canonical SHA-256 digest of the corresponding [`CryptoErasureReceipt`].
    pub receipt_digest: ContentDigest,
}

impl CanonicalEncode for ErasedDekTombstone {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.dek_id.encode_canonical(encoder);
        self.origin_key_epoch.encode_canonical(encoder);
        self.last_kek_epoch.encode_canonical(encoder);
        encoder.u64(self.affected_pack_ids.len() as u64);
        for pack_id in &self.affected_pack_ids {
            encoder.u32(pack_id.epoch);
            encoder.u64(pack_id.seq);
        }
        encoder.text(&self.reason);
        encoder.text(&self.actor);
        self.erased_at_ns.encode_canonical(encoder);
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for ErasedDekTombstone {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let dek_id = DekId::decode_canonical(decoder)?;
        let origin_key_epoch = KeyEpoch::decode_canonical(decoder)?;
        let last_kek_epoch = KeyEpoch::decode_canonical(decoder)?;
        let pack_count_u64 = decoder.u64()?;
        let pack_count =
            usize::try_from(pack_count_u64).map_err(|_| ContractError::InvalidDigest)?;
        if pack_count > 100_000 {
            return Err(ContractError::InvalidDigest);
        }
        let mut affected_pack_ids = Vec::with_capacity(pack_count);
        for _ in 0..pack_count {
            let epoch = decoder.u32()?;
            let seq = decoder.u64()?;
            affected_pack_ids.push(PackId::new(epoch, seq));
        }
        let reason = decoder.text()?.to_owned();
        let actor = decoder.text()?.to_owned();
        let erased_at_ns = TimestampNs::decode_canonical(decoder)?;
        let receipt_digest = decoder.digest()?;
        Ok(Self {
            dek_id,
            origin_key_epoch,
            last_kek_epoch,
            affected_pack_ids,
            reason,
            actor,
            erased_at_ns,
            receipt_digest,
        })
    }
}

/// Signed canonical audit receipt emitted when a DEK is durably destroyed (`--crypto-erase`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoErasureReceipt {
    /// Always `true`: explicitly marks cryptographic key destruction per `PRIV-010`.
    pub cryptographic_erasure: bool,
    /// Permanently destroyed Data Encryption Key identifier.
    pub dek_id: DekId,
    /// Origin KEK epoch under which the DEK was originally created.
    pub origin_key_epoch: KeyEpoch,
    /// KEK epoch active in the catalog at the instant of erasure.
    pub erased_under_kek_epoch: KeyEpoch,
    /// Canonically sorted, deduplicated packfiles rendered unreadable by this erasure.
    pub affected_pack_ids: Vec<PackId>,
    /// Operator or policy reason for erasure (non-secret).
    pub reason: String,
    /// Actor identity executing the erasure.
    pub actor: String,
    /// Caller-supplied erasure timestamp (no ambient clock).
    pub erased_at_ns: TimestampNs,
    /// Digest of the destroyed `WrappedDekEnvelope` captured immediately prior to zeroization.
    pub erased_envelope_digest: ContentDigest,
    /// Scope digest of the `KeyEnvelopeCatalog` where the DEK was destroyed.
    pub catalog_scope_digest: ContentDigest,
    /// Canonical domain-separated SHA-256 receipt digest under [`PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
    /// Authentication MAC (`HMAC-SHA256`) over `receipt_digest`.
    pub signature_mac: [u8; 32],
    /// `true` if `signature_mac` was keyed by the operator's active [`KeyEncryptionKey`];
    /// `false` if computed solely from public catalog/envelope commitment material.
    pub signed_with_kek: bool,
}

impl CryptoErasureReceipt {
    /// Builds a canonical [`CryptoErasureReceipt`] with optional KEK HMAC signing.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        dek_id: DekId,
        origin_key_epoch: KeyEpoch,
        erased_under_kek_epoch: KeyEpoch,
        mut affected_pack_ids: Vec<PackId>,
        reason: &str,
        actor: &str,
        erased_at_ns: TimestampNs,
        erased_envelope_digest: ContentDigest,
        catalog_scope_digest: ContentDigest,
        signing_kek: Option<&KeyEncryptionKey>,
    ) -> Result<Self, PackError> {
        validate_erasure_text("reason", reason)?;
        validate_erasure_text("actor", actor)?;
        affected_pack_ids.sort_unstable();
        affected_pack_ids.dedup();

        let mut receipt = Self {
            cryptographic_erasure: true,
            dek_id,
            origin_key_epoch,
            erased_under_kek_epoch,
            affected_pack_ids,
            reason: reason.to_owned(),
            actor: actor.to_owned(),
            erased_at_ns,
            erased_envelope_digest,
            catalog_scope_digest,
            receipt_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
            signature_mac: [0_u8; 32],
            signed_with_kek: false,
        };
        receipt.receipt_digest = receipt.compute_receipt_digest()?;

        if let Some(kek) = signing_kek {
            let signing_key = kek.derive_erasure_signing_key(PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN);
            receipt.signature_mac = hmac_sha256(&*signing_key, &receipt.receipt_digest.bytes());
            receipt.signed_with_kek = true;
        } else {
            let commitment_key =
                compute_commitment_key(catalog_scope_digest, erased_envelope_digest);
            receipt.signature_mac = hmac_sha256(&commitment_key, &receipt.receipt_digest.bytes());
            receipt.signed_with_kek = false;
        }
        Ok(receipt)
    }

    /// Recomputes and verifies [`Self::receipt_digest`] and `cryptographic_erasure == true`.
    pub fn verify_digest(&self) -> Result<(), PackError> {
        if !self.cryptographic_erasure {
            return Err(PackError::CryptoAuthFailed {
                detail: "CryptoErasureReceipt must have cryptographic_erasure == true".to_owned(),
            });
        }
        let expected = self.compute_receipt_digest()?;
        if expected != self.receipt_digest {
            return Err(PackError::DigestMismatch {
                expected: self.receipt_digest,
                actual: expected,
            });
        }
        if !self.signed_with_kek {
            let commitment_key =
                compute_commitment_key(self.catalog_scope_digest, self.erased_envelope_digest);
            let expected_mac = hmac_sha256(&commitment_key, &self.receipt_digest.bytes());
            if !constant_time_eq(&expected_mac, &self.signature_mac) {
                return Err(PackError::CryptoAuthFailed {
                    detail: "CryptoErasureReceipt commitment MAC mismatch".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Verifies a KEK-signed [`CryptoErasureReceipt`] against the signing [`KeyEncryptionKey`].
    pub fn verify_kek_signature(&self, kek: &KeyEncryptionKey) -> Result<(), PackError> {
        self.verify_digest()?;
        if !self.signed_with_kek {
            return Err(PackError::CryptoAuthFailed {
                detail: "CryptoErasureReceipt was not signed with a KEK".to_owned(),
            });
        }
        if kek.scope_digest() != self.catalog_scope_digest {
            return Err(PackError::CryptoAuthFailed {
                detail: "KEK scope mismatch verifying CryptoErasureReceipt".to_owned(),
            });
        }
        let signing_key = kek.derive_erasure_signing_key(PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN);
        let expected_mac = hmac_sha256(&*signing_key, &self.receipt_digest.bytes());
        if !constant_time_eq(&expected_mac, &self.signature_mac) {
            return Err(PackError::CryptoAuthFailed {
                detail: "CryptoErasureReceipt KEK HMAC signature verification failed".to_owned(),
            });
        }
        Ok(())
    }

    /// Converts this receipt into a compact [`ErasedDekTombstone`] for durable catalog storage.
    #[must_use]
    pub fn to_tombstone(&self) -> ErasedDekTombstone {
        ErasedDekTombstone {
            dek_id: self.dek_id,
            origin_key_epoch: self.origin_key_epoch,
            last_kek_epoch: self.erased_under_kek_epoch,
            affected_pack_ids: self.affected_pack_ids.clone(),
            reason: self.reason.clone(),
            actor: self.actor.clone(),
            erased_at_ns: self.erased_at_ns,
            receipt_digest: self.receipt_digest,
        }
    }

    /// Renders a deterministic, zero-Serde, secret-free JSONL line suitable for audit logs.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut packs = String::from("[");
        for (idx, pack_id) in self.affected_pack_ids.iter().enumerate() {
            if idx > 0 {
                packs.push(',');
            }
            packs.push('"');
            packs.push_str(&pack_id.to_string());
            packs.push('"');
        }
        packs.push(']');

        format!(
            "{{\"schema\":\"{PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN}\",\"cryptographic_erasure\":{},\"dek_id\":\"{}\",\"origin_key_epoch\":{},\"erased_under_kek_epoch\":{},\"affected_pack_ids\":{packs},\"reason\":\"{}\",\"actor\":\"{}\",\"erased_at_ns\":{},\"erased_envelope_digest\":\"{}\",\"catalog_scope_digest\":\"{}\",\"receipt_digest\":\"{}\",\"signature_mac\":\"{}\",\"signed_with_kek\":{}}}",
            self.cryptographic_erasure,
            self.dek_id,
            self.origin_key_epoch.0,
            self.erased_under_kek_epoch.0,
            escape_json_str(&self.reason),
            escape_json_str(&self.actor),
            self.erased_at_ns.0,
            self.erased_envelope_digest,
            self.catalog_scope_digest,
            self.receipt_digest,
            encode_hex_lower(&self.signature_mac),
            self.signed_with_kek,
        )
    }

    fn compute_receipt_digest(&self) -> Result<ContentDigest, PackError> {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN);
        enc.bool(self.cryptographic_erasure);
        self.dek_id.encode_canonical(&mut enc);
        self.origin_key_epoch.encode_canonical(&mut enc);
        self.erased_under_kek_epoch.encode_canonical(&mut enc);
        enc.u64(self.affected_pack_ids.len() as u64);
        for pack_id in &self.affected_pack_ids {
            enc.u32(pack_id.epoch);
            enc.u64(pack_id.seq);
        }
        enc.text(&self.reason);
        enc.text(&self.actor);
        self.erased_at_ns.encode_canonical(&mut enc);
        enc.digest(self.erased_envelope_digest);
        enc.digest(self.catalog_scope_digest);
        let bytes = enc.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

fn validate_erasure_text(field: &str, value: &str) -> Result<(), PackError> {
    if value.is_empty() || value.len() > MAX_ERASURE_TEXT_LEN {
        return Err(PackError::InvalidConfig {
            detail: format!("erasure {field} length must be within 1..={MAX_ERASURE_TEXT_LEN}"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(PackError::InvalidConfig {
            detail: format!("erasure {field} must not contain control characters"),
        });
    }
    Ok(())
}

fn compute_commitment_key(
    catalog_scope_digest: ContentDigest,
    erased_envelope_digest: ContentDigest,
) -> [u8; 32] {
    let mut enc = CanonicalEncoder::new();
    enc.text(PACK_CRYPTO_ERASURE_RECEIPT_DOMAIN);
    enc.digest(catalog_scope_digest);
    enc.digest(erased_envelope_digest);
    ContentDigest::sha256(&enc.finish()).bytes()
}

pub(crate) fn escape_json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
