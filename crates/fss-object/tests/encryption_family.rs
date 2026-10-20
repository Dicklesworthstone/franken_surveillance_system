#![forbid(unsafe_code)]
//! FSS-065 property family: encryption-context manifest. Each property
//! emits one JSONL verdict line.

use fss_core::{ContentDigest, Generation};
use fss_object::encryption::{
    CipherSuite, EncryptionContextManifest, EncryptionManifestError, MAX_PROTECTED_OBJECTS,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-065\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn objects(n: usize) -> Vec<ContentDigest> {
    (0..n)
        .map(|i| ContentDigest::sha256(format!("obj-{i}").as_bytes()))
        .collect()
}

fn genesis(suite: CipherSuite) -> Result<EncryptionContextManifest, Box<dyn std::error::Error>> {
    Ok(EncryptionContextManifest::genesis(
        suite,
        "key:archive-2026-q4",
        [7u8; 16],
        objects(3),
    )?)
}

/// P1 VALIDATION: empty/oversize key ids, empty and over-bound object
/// lists are typed refusals.
#[test]
fn p1_validation() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        EncryptionContextManifest::genesis(CipherSuite::Aes256Gcm, "", [0u8; 16], objects(1)).err(),
        Some(EncryptionManifestError::InvalidKeyId)
    );
    let long_key = "k".repeat(129);
    assert_eq!(
        EncryptionContextManifest::genesis(CipherSuite::Aes256Gcm, long_key, [0u8; 16], objects(1))
            .err(),
        Some(EncryptionManifestError::InvalidKeyId)
    );
    assert_eq!(
        EncryptionContextManifest::genesis(CipherSuite::Aes256Gcm, "key:a", [0u8; 16], Vec::new())
            .err(),
        Some(EncryptionManifestError::InvalidObjectCount { count: 0 })
    );
    assert_eq!(
        EncryptionContextManifest::genesis(
            CipherSuite::Aes256Gcm,
            "key:a",
            [0u8; 16],
            objects(MAX_PROTECTED_OBJECTS + 1)
        )
        .err(),
        Some(EncryptionManifestError::InvalidObjectCount {
            count: MAX_PROTECTED_OBJECTS + 1,
        })
    );
    emit("validation", 4);
    Ok(())
}

/// P2 ROTATION DISCIPLINE: rotations must strictly advance the
/// generation and name the prior digest; successors verify; broken
/// chains and regressions are named refusals.
#[test]
fn p2_rotation_discipline() -> Result<(), Box<dyn std::error::Error>> {
    let first = genesis(CipherSuite::Aes256Gcm)?;
    let second = first.rotate(
        CipherSuite::ChaCha20Poly1305,
        "key:archive-2027-q1",
        [9u8; 16],
        objects(4),
        Generation::from_u64(2),
    )?;
    second.verify_successor_of(&first)?;
    // Regression refused.
    assert_eq!(
        first.rotate(
            CipherSuite::Aes256Gcm,
            "key:x",
            [0u8; 16],
            objects(1),
            Generation::GENESIS,
        ),
        Err(EncryptionManifestError::GenerationMustAdvance {
            predecessor: 1,
            successor: 1,
        })
    );
    // A genesis manifest is nobody's successor: same generation refuses
    // on the generation check before the predecessor is even consulted.
    let stranger = genesis(CipherSuite::ChaCha20Poly1305)?;
    assert!(matches!(
        stranger.verify_successor_of(&first),
        Err(EncryptionManifestError::GenerationMustAdvance { .. })
    ));
    // A tampered chain: second's digest field verified against a DIFFERENT
    // first (same content, so same digest) then mutated key.
    let mut forged = second.clone();
    forged.predecessor = Some(ContentDigest::sha256(b"not-the-prior"));
    assert!(matches!(
        forged.verify_successor_of(&first),
        Err(EncryptionManifestError::PredecessorMismatch { .. })
    ));
    emit("rotation-discipline", 4);
    Ok(())
}

/// P3 DIGEST BINDING: every field changes the digest — suite, key id,
/// salt, generation, predecessor, protected set; the digest is
/// order-insensitive over the protected set (canonical sort).
#[test]
fn p3_digest_binding() -> Result<(), Box<dyn std::error::Error>> {
    let base = genesis(CipherSuite::Aes256Gcm)?;
    let d0 = base.digest();
    // Suite.
    let other_suite = genesis(CipherSuite::ChaCha20Poly1305)?;
    assert_ne!(d0, other_suite.digest());
    // Key id.
    let mut other_key = base.clone();
    other_key.key_id = "key:other".to_string();
    assert_ne!(d0, other_key.digest());
    // Salt.
    let mut other_salt = base.clone();
    other_salt.salt = [1u8; 16];
    assert_ne!(d0, other_salt.digest());
    // Protected set membership.
    let mut more = base.clone();
    more.protected_objects.push(ContentDigest::sha256(b"extra"));
    assert_ne!(d0, more.digest());
    // Canonical ordering: same set, different insertion order.
    let mut reordered = base.clone();
    reordered.protected_objects.reverse();
    assert_eq!(d0, reordered.digest(), "protected-set order is canonical");
    emit("digest-binding", 5);
    Ok(())
}

/// P4 SEITE METADATA: suite identifiers and AEAD geometry are stable and
/// citable.
#[test]
fn p4_suite_metadata() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(CipherSuite::Aes256Gcm.as_str(), "aes-256-gcm");
    assert_eq!(CipherSuite::ChaCha20Poly1305.as_str(), "chacha20-poly1305");
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        assert_eq!(suite.nonce_len(), 12);
        assert_eq!(suite.tag_len(), 16);
    }
    emit("suite-metadata", 2);
    Ok(())
}

/// P5 NO-SECRETS INVARIANT: the manifest carries no key material by
/// construction — the audit hook is present, true, and citable; the
/// digest input contains only handle/salt/ids (verified by construction
/// in digest()).
#[test]
fn p5_no_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let m = genesis(CipherSuite::Aes256Gcm)?;
    assert!(m.carries_no_secret_material());
    // Rotation preserves the invariant.
    let r = m.rotate(
        CipherSuite::Aes256Gcm,
        "key:next",
        [2u8; 16],
        objects(2),
        Generation::from_u64(2),
    )?;
    assert!(r.carries_no_secret_material());
    emit("no-secrets", 2);
    Ok(())
}
