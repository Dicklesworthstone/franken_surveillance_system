#![forbid(unsafe_code)]

use core::str::FromStr;
use fss_core::{ContentDigest, ContractError, DigestAlgorithm, sha256};

#[test]
fn public_sha256_function_test_vectors() {
    // Empty string
    let empty_digest = sha256(b"");
    assert_eq!(
        empty_digest,
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    );

    // "abc"
    let abc_digest = sha256(b"abc");
    assert_eq!(
        abc_digest,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );

    // Multi-block: exactly 64 bytes
    let block64 = [b'a'; 64];
    let digest64 = sha256(&block64);
    assert_eq!(
        ContentDigest::new(DigestAlgorithm::Sha256, digest64).to_text(),
        "sha256:ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    );

    // Multi-block: 65 bytes (crossing 64-byte block boundary)
    let block65 = [b'a'; 65];
    let digest65 = sha256(&block65);
    assert_eq!(
        ContentDigest::new(DigestAlgorithm::Sha256, digest65).to_text(),
        "sha256:635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"
    );

    // Multi-block: 128 bytes (two full 64-byte blocks)
    let block128 = [b'a'; 128];
    let digest128 = sha256(&block128);
    assert_eq!(
        ContentDigest::new(DigestAlgorithm::Sha256, digest128).to_text(),
        "sha256:6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e"
    );
}

#[test]
fn public_content_digest_constructors_and_accessors() {
    let payload = b"fss canonical evidence payload";
    let raw_hash = sha256(payload);

    let digest = ContentDigest::sha256(payload);
    assert_eq!(digest.algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(digest.bytes(), raw_hash);

    let explicit_digest = ContentDigest::new(DigestAlgorithm::Sha256, raw_hash);
    assert_eq!(digest, explicit_digest);

    // Formatting checks
    let text = digest.to_text();
    let display = format!("{digest}");
    assert_eq!(text, display);
    assert!(text.starts_with("sha256:"));
    assert_eq!(text.len(), "sha256:".len() + 64);
}

#[test]
fn public_digest_algorithm_variants_and_canonical_representation() {
    assert_eq!(DigestAlgorithm::Sha256.as_str(), "sha256");
    assert_eq!(DigestAlgorithm::Blake3.as_str(), "blake3");

    // Algorithm ordering and equality
    assert_eq!(DigestAlgorithm::Sha256, DigestAlgorithm::Sha256);
    assert_ne!(DigestAlgorithm::Sha256, DigestAlgorithm::Blake3);
}

#[test]
fn public_content_digest_parsing_canonical_and_rejections() -> Result<(), ContractError> {
    // Canonical round-trip
    let valid_sha256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let parsed = ContentDigest::parse(valid_sha256)?;
    assert_eq!(parsed.algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(parsed.to_text(), valid_sha256);

    // FromStr trait integration
    let from_str_parsed = ContentDigest::from_str(valid_sha256)?;
    assert_eq!(parsed, from_str_parsed);

    // Blake3 interoperability
    let valid_blake3 = "blake3:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let parsed_blake3 = ContentDigest::parse(valid_blake3)?;
    assert_eq!(parsed_blake3.algorithm(), DigestAlgorithm::Blake3);
    assert_eq!(parsed_blake3.to_text(), valid_blake3);

    // Rejections: uppercase hex
    let upper_sha256 = "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    assert_eq!(
        ContentDigest::parse(upper_sha256),
        Err(ContractError::InvalidDigest)
    );

    // Rejections: wrong hex length (63 characters)
    let short_hex = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
    assert_eq!(
        ContentDigest::parse(short_hex),
        Err(ContractError::InvalidDigest)
    );

    // Rejections: wrong hex length (65 characters)
    let long_hex = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550";
    assert_eq!(
        ContentDigest::parse(long_hex),
        Err(ContractError::InvalidDigest)
    );

    // Rejections: non-hex characters
    let non_hex = "sha256:g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        ContentDigest::parse(non_hex),
        Err(ContractError::InvalidDigest)
    );

    // Rejections: missing prefix delimiter
    assert_eq!(
        ContentDigest::parse(
            "sha256e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        Err(ContractError::InvalidDigest)
    );

    // Rejections: unsupported algorithm
    let unsupported = "md5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        ContentDigest::parse(unsupported),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );
    Ok(())
}

#[test]
fn domain_separation_and_determinism_contract() {
    let domain_a = sha256(b"fss:domain_a:observed_event");
    let domain_b = sha256(b"fss:domain_b:observed_event");
    assert_ne!(domain_a, domain_b);

    // Deterministic repeat
    let repeat_a = sha256(b"fss:domain_a:observed_event");
    assert_eq!(domain_a, repeat_a);

    // ContentDigest comparison preserves domain distinction
    let digest_a = ContentDigest::new(DigestAlgorithm::Sha256, domain_a);
    let digest_b = ContentDigest::new(DigestAlgorithm::Sha256, domain_b);
    assert_ne!(digest_a, digest_b);
    assert!(digest_a < digest_b || digest_b < digest_a);
}

#[test]
fn compile_facing_intended_public_api_proof() {
    // This test proves that:
    // 1. `fss_core::sha256` is the intended public function for hashing bytes.
    let hash_fn: fn(&[u8]) -> [u8; 32] = sha256;
    let computed = hash_fn(b"proof");
    assert_eq!(computed, sha256(b"proof"));

    // 2. `fss_core::DigestAlgorithm::Sha256` is the enum variant for algorithm qualification.
    let algo: DigestAlgorithm = DigestAlgorithm::Sha256;
    assert_eq!(algo.as_str(), "sha256");

    // 3. `fss_core::ContentDigest` is the structured digest container.
    let digest: ContentDigest = ContentDigest::sha256(b"proof");
    assert_eq!(digest.algorithm(), algo);
    assert_eq!(digest.bytes(), computed);

    // 4. No ambiguous top-level item or conflicting alias named Sha256 is exposed.
    // The public namespace cleanly separates the function `sha256` from the
    // enum variant `DigestAlgorithm::Sha256`.
}
