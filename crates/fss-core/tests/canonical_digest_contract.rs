//! Contract tests for canonical digest parsing, formatting, binary encoding, and streaming hasher.
//!
//! Ref: FSS-002 / fss-x4a.6.2

#![forbid(unsafe_code)]

use core::str::FromStr;

use fss_core::{
    CanonicalDecode, CanonicalEncode, CanonicalVersionEnvelope, ContentDigest, ContractError,
    DigestAlgorithm, Sha256Hasher, sha256,
};

// ---------------------------------------------------------------------------
// 1. Streaming SHA-256 Hasher vs One-Shot across Boundary Lengths
// ---------------------------------------------------------------------------

#[test]
fn streaming_sha256_matches_oneshot_across_boundary_lengths() -> Result<(), ContractError> {
    // Exact boundary message lengths:
    // 0, 1, 55 (max before pad in single block), 56 (triggers 2-block pad),
    // 63, 64 (full single block), 65 (starts second block), 127, 128, 129
    let lengths: &[usize] = &[0, 1, 55, 56, 63, 64, 65, 127, 128, 129];

    for &len in lengths {
        let pattern: Vec<u8> = (0..len).map(|idx| (idx % 251) as u8).collect();
        let expected = sha256(&pattern);

        // One-shot via Sha256Hasher::digest
        let oneshot_digest = Sha256Hasher::digest(&pattern);
        assert_eq!(
            oneshot_digest, expected,
            "Sha256Hasher::digest failed for len {len}"
        );

        // Streaming with single update
        let mut hasher = Sha256Hasher::new();
        hasher.update(&pattern);
        assert_eq!(
            hasher.finalize(),
            expected,
            "single update finalize failed for len {len}"
        );

        // Streaming byte-by-byte (1-byte chunks)
        let mut byte_hasher = Sha256Hasher::new();
        for &byte in &pattern {
            byte_hasher.update(&[byte]);
        }
        assert_eq!(
            byte_hasher.finalize(),
            expected,
            "1-byte chunk feeding failed for len {len}"
        );

        // Streaming in 7-byte chunks
        let mut chunk7_hasher = Sha256Hasher::new();
        for chunk in pattern.chunks(7) {
            chunk7_hasher.update(chunk);
        }
        assert_eq!(
            chunk7_hasher.finalize(),
            expected,
            "7-byte chunk feeding failed for len {len}"
        );

        // Streaming in 31-byte chunks
        let mut chunk31_hasher = Sha256Hasher::new();
        for chunk in pattern.chunks(31) {
            chunk31_hasher.update(chunk);
        }
        assert_eq!(
            chunk31_hasher.finalize(),
            expected,
            "31-byte chunk feeding failed for len {len}"
        );

        // Streaming in 64-byte chunks
        let mut chunk64_hasher = Sha256Hasher::new();
        for chunk in pattern.chunks(64) {
            chunk64_hasher.update(chunk);
        }
        assert_eq!(
            chunk64_hasher.finalize(),
            expected,
            "64-byte chunk feeding failed for len {len}"
        );

        // Uneven split points: split at every possible index for small lengths
        if len <= 65 && len > 1 {
            for split in [1, len / 2, len - 1] {
                let mut split_hasher = Sha256Hasher::new();
                split_hasher.update(&pattern[..split]);
                split_hasher.update(&pattern[split..]);
                assert_eq!(
                    split_hasher.finalize(),
                    expected,
                    "split at {split} failed for len {len}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn streaming_sha256_nist_56_byte_boundary_vector() -> Result<(), ContractError> {
    let msg_56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(msg_56.len(), 56);
    let expected_hex = "sha256:248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    // Test multiple feeding chunk sizes
    for chunk_size in [1, 3, 8, 16, 28, 55, 56] {
        let mut hasher = Sha256Hasher::new();
        for chunk in msg_56.chunks(chunk_size) {
            hasher.update(chunk);
        }
        let digest = ContentDigest::new(DigestAlgorithm::Sha256, hasher.finalize());
        assert_eq!(
            digest.to_text(),
            expected_hex,
            "chunk size {chunk_size} failed for NIST 56-byte vector"
        );
    }

    Ok(())
}

#[test]
fn streaming_sha256_nist_million_a_vector() -> Result<(), ContractError> {
    let expected_hex = "sha256:cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    // Feed 1,000,000 'a's in 1000-byte buffers (zero heap allocation of 1MB buffer)
    let buffer = [b'a'; 1000];
    let mut hasher = Sha256Hasher::new();
    for _ in 0..1000 {
        hasher.update(&buffer);
    }
    let digest = ContentDigest::new(DigestAlgorithm::Sha256, hasher.finalize());
    assert_eq!(
        digest.to_text(),
        expected_hex,
        "streaming 1,000,000 'a's failed"
    );

    Ok(())
}

#[test]
fn hasher_default_and_clone_consistency() -> Result<(), ContractError> {
    let default_hasher = Sha256Hasher::default();
    let new_hasher = Sha256Hasher::new();
    assert_eq!(default_hasher, new_hasher);

    let mut in_progress = Sha256Hasher::new();
    in_progress.update(b"prefix data to test hasher clone");

    // Clone mid-stream
    let mut branch_a = in_progress.clone();
    let mut branch_b = in_progress;

    branch_a.update(b" and suffix");
    branch_b.update(b" and suffix");

    assert_eq!(branch_a.finalize(), branch_b.finalize());
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Canonical Text Formatting and Round-Trip Parsing
// ---------------------------------------------------------------------------

#[test]
fn canonical_text_form_and_parse_roundtrip_all_algorithms() -> Result<(), ContractError> {
    let raw_bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00,
    ];
    let expected_hex = "0123456789abcdeffedcba9876543210112233445566778899aabbccddeeff00";

    // Sha256
    let sha_digest = ContentDigest::new(DigestAlgorithm::Sha256, raw_bytes);
    let expected_sha_text = format!("sha256:{expected_hex}");
    assert_eq!(sha_digest.to_text(), expected_sha_text);
    assert_eq!(format!("{sha_digest}"), expected_sha_text);

    let parsed_sha = ContentDigest::parse(&expected_sha_text)?;
    assert_eq!(parsed_sha, sha_digest);
    assert_eq!(parsed_sha.algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(parsed_sha.bytes(), raw_bytes);

    let from_str_sha = ContentDigest::from_str(&expected_sha_text)?;
    assert_eq!(from_str_sha, sha_digest);

    // Blake3
    let blake_digest = ContentDigest::new(DigestAlgorithm::Blake3, raw_bytes);
    let expected_blake_text = format!("blake3:{expected_hex}");
    assert_eq!(blake_digest.to_text(), expected_blake_text);
    assert_eq!(format!("{blake_digest}"), expected_blake_text);

    let parsed_blake = ContentDigest::parse(&expected_blake_text)?;
    assert_eq!(parsed_blake, blake_digest);
    assert_eq!(parsed_blake.algorithm(), DigestAlgorithm::Blake3);
    assert_eq!(parsed_blake.bytes(), raw_bytes);

    let from_str_blake = ContentDigest::from_str(&expected_blake_text)?;
    assert_eq!(from_str_blake, blake_digest);

    // DigestAlgorithm as_str, Display, FromStr
    assert_eq!(DigestAlgorithm::Sha256.as_str(), "sha256");
    assert_eq!(format!("{}", DigestAlgorithm::Sha256), "sha256");
    assert_eq!(
        DigestAlgorithm::from_str("sha256")?,
        DigestAlgorithm::Sha256
    );

    assert_eq!(DigestAlgorithm::Blake3.as_str(), "blake3");
    assert_eq!(format!("{}", DigestAlgorithm::Blake3), "blake3");
    assert_eq!(
        DigestAlgorithm::from_str("blake3")?,
        DigestAlgorithm::Blake3
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Exact Rejection Matrix: UnsupportedDigestAlgorithm
// ---------------------------------------------------------------------------

#[test]
fn exact_rejection_matrix_unsupported_algorithm() {
    let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let unsupported_cases = [
        // Uppercase algorithm names
        format!("SHA256:{valid_hex}"),
        format!("BLAKE3:{valid_hex}"),
        // Mixed case algorithm names
        format!("Sha256:{valid_hex}"),
        format!("Blake3:{valid_hex}"),
        format!("sHa256:{valid_hex}"),
        // Unknown algorithms
        format!("md5:{valid_hex}"),
        format!("sha512:{valid_hex}"),
        format!("sha1:{valid_hex}"),
        format!("ripemd160:{valid_hex}"),
        format!("crc32:{valid_hex}"),
        format!("keccak256:{valid_hex}"),
        // Empty algorithm name with delimiter
        format!(":{valid_hex}"),
        // Version prefix in algorithm position
        format!("v1:sha256:{valid_hex}"),
        format!("v1:{valid_hex}"),
        // Whitespace in algorithm name
        format!(" sha256:{valid_hex}"),
        format!("sha256 :{valid_hex}"),
    ];

    for case in &unsupported_cases {
        let parse_result = ContentDigest::parse(case);
        assert_eq!(
            parse_result,
            Err(ContractError::UnsupportedDigestAlgorithm),
            "expected UnsupportedDigestAlgorithm for case: {case:?}"
        );

        let from_str_result = ContentDigest::from_str(case);
        assert_eq!(
            from_str_result,
            Err(ContractError::UnsupportedDigestAlgorithm),
            "expected UnsupportedDigestAlgorithm for case: {case:?}"
        );
    }

    // Direct DigestAlgorithm::from_str rejections
    for invalid_algo in [
        "SHA256", "BLAKE3", "Sha256", "Blake3", "md5", "sha512", "sha1", "", "v1", "sha256 ",
    ] {
        assert_eq!(
            DigestAlgorithm::from_str(invalid_algo),
            Err(ContractError::UnsupportedDigestAlgorithm),
            "expected UnsupportedDigestAlgorithm for algo name: {invalid_algo:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Exact Rejection Matrix: InvalidDigest
// ---------------------------------------------------------------------------

#[test]
fn exact_rejection_matrix_invalid_digest() {
    let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let invalid_digest_cases = [
        // Missing delimiter entirely
        "".to_string(),
        "sha256".to_string(),
        "blake3".to_string(),
        valid_hex.to_string(),
        "sha256e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        // Multiple delimiters / extra colons
        format!("sha256::{valid_hex}"),
        format!("sha256:{valid_hex}:"),
        format!("sha256:extra:{valid_hex}"),
        format!("sha256:v1:{valid_hex}"),
        // Uppercase and mixed case hex characters
        format!("sha256:{}", valid_hex.to_ascii_uppercase()),
        "sha256:E3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85A".to_string(),
        "blake3:0123456789ABCDEFFEDCBA9876543210112233445566778899AABBCCDDEEFF00".to_string(),
        // Invalid hex characters (out of [0-9a-f])
        "sha256:g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85z".to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb924-7ae41e4649b934ca495991b7852b855".to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb924 7ae41e4649b934ca495991b7852b855".to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb924\n7ae41e4649b934ca495991b7852b855".to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb924\07ae41e4649b934ca495991b7852b855".to_string(),
        // Hex too short
        "sha256:".to_string(),
        "sha256:a".to_string(),
        "sha256:e3b0c4".to_string(),
        format!("sha256:{}", &valid_hex[..63]), // 63 chars
        format!("blake3:{}", &valid_hex[..63]),
        // Hex too long
        format!("sha256:{valid_hex}0"),           // 65 chars
        format!("sha256:{valid_hex}{valid_hex}"), // 128 chars
        format!("blake3:{valid_hex}a"),
        // Whitespace padding
        format!("sha256:{valid_hex} "),
        format!("sha256: {valid_hex}"),
    ];

    for case in &invalid_digest_cases {
        let parse_result = ContentDigest::parse(case);
        assert_eq!(
            parse_result,
            Err(ContractError::InvalidDigest),
            "expected InvalidDigest for case: {case:?}"
        );

        let from_str_result = ContentDigest::from_str(case);
        assert_eq!(
            from_str_result,
            Err(ContractError::InvalidDigest),
            "expected InvalidDigest for case: {case:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Canonical Binary Encoding & Decoding: ContentDigest
// ---------------------------------------------------------------------------

#[test]
fn canonical_binary_encoding_content_digest_contract() -> Result<(), ContractError> {
    let test_bytes = [0x42_u8; 32];

    // Sha256 encoding: tag 1 + 32 bytes = 33 bytes
    let sha_digest = ContentDigest::new(DigestAlgorithm::Sha256, test_bytes);
    let sha_canonical = sha_digest.canonical_bytes();
    assert_eq!(sha_canonical.len(), 33);
    assert_eq!(sha_canonical[0], 0x01); // Tag 1 for Sha256
    assert_eq!(&sha_canonical[1..], &test_bytes);

    let decoded_sha = ContentDigest::from_canonical_bytes(&sha_canonical)?;
    assert_eq!(decoded_sha, sha_digest);

    // Blake3 encoding: tag 2 + 32 bytes = 33 bytes
    let blake_digest = ContentDigest::new(DigestAlgorithm::Blake3, test_bytes);
    let blake_canonical = blake_digest.canonical_bytes();
    assert_eq!(blake_canonical.len(), 33);
    assert_eq!(blake_canonical[0], 0x02); // Tag 2 for Blake3
    assert_eq!(&blake_canonical[1..], &test_bytes);

    let decoded_blake = ContentDigest::from_canonical_bytes(&blake_canonical)?;
    assert_eq!(decoded_blake, blake_digest);

    // Rejection of invalid algorithm tag
    let mut invalid_tag_bytes = sha_canonical.clone();
    invalid_tag_bytes[0] = 0x00;
    assert_eq!(
        ContentDigest::from_canonical_bytes(&invalid_tag_bytes),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );

    invalid_tag_bytes[0] = 0x03;
    assert_eq!(
        ContentDigest::from_canonical_bytes(&invalid_tag_bytes),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );

    invalid_tag_bytes[0] = 0xFF;
    assert_eq!(
        ContentDigest::from_canonical_bytes(&invalid_tag_bytes),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );

    // Rejection of truncated byte streams
    assert_eq!(
        ContentDigest::from_canonical_bytes(&[]),
        Err(ContractError::InvalidDigest)
    );
    assert_eq!(
        ContentDigest::from_canonical_bytes(&sha_canonical[..1]),
        Err(ContractError::InvalidDigest)
    );
    assert_eq!(
        ContentDigest::from_canonical_bytes(&sha_canonical[..16]),
        Err(ContractError::InvalidDigest)
    );
    assert_eq!(
        ContentDigest::from_canonical_bytes(&sha_canonical[..32]),
        Err(ContractError::InvalidDigest)
    );

    // Rejection of trailing unparsed bytes
    let mut trailing_bytes = sha_canonical.clone();
    trailing_bytes.push(0x00);
    assert_eq!(
        ContentDigest::from_canonical_bytes(&trailing_bytes),
        Err(ContractError::NonCanonicalOrdering)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Canonical Binary Encoding & Decoding: DigestAlgorithm
// ---------------------------------------------------------------------------

#[test]
fn canonical_binary_encoding_digest_algorithm_contract() -> Result<(), ContractError> {
    // Sha256 tag = 1
    let sha_algo = DigestAlgorithm::Sha256;
    let sha_bytes = sha_algo.canonical_bytes();
    assert_eq!(sha_bytes, vec![0x01]);
    let decoded_sha = DigestAlgorithm::from_canonical_bytes(&sha_bytes)?;
    assert_eq!(decoded_sha, sha_algo);

    // Blake3 tag = 2
    let blake_algo = DigestAlgorithm::Blake3;
    let blake_bytes = blake_algo.canonical_bytes();
    assert_eq!(blake_bytes, vec![0x02]);
    let decoded_blake = DigestAlgorithm::from_canonical_bytes(&blake_bytes)?;
    assert_eq!(decoded_blake, blake_algo);

    // Invalid tags
    assert_eq!(
        DigestAlgorithm::from_canonical_bytes(&[0x00]),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );
    assert_eq!(
        DigestAlgorithm::from_canonical_bytes(&[0x03]),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );
    assert_eq!(
        DigestAlgorithm::from_canonical_bytes(&[0xFF]),
        Err(ContractError::UnsupportedDigestAlgorithm)
    );

    // Truncated (0 bytes)
    assert_eq!(
        DigestAlgorithm::from_canonical_bytes(&[]),
        Err(ContractError::InvalidDigest)
    );

    // Trailing bytes (2 bytes)
    assert_eq!(
        DigestAlgorithm::from_canonical_bytes(&[0x01, 0x00]),
        Err(ContractError::NonCanonicalOrdering)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Canonical Version Envelope Integration
// ---------------------------------------------------------------------------

#[test]
fn canonical_version_envelope_with_content_digest() -> Result<(), ContractError> {
    let digest = ContentDigest::sha256(b"version envelope test payload");
    let envelope = CanonicalVersionEnvelope::new(digest);
    assert_eq!(
        envelope.version,
        CanonicalVersionEnvelope::<ContentDigest>::CURRENT_VERSION
    );

    let bytes = envelope.canonical_bytes();

    // Roundtrip bounded with supported version range [1, 1]
    let decoded =
        CanonicalVersionEnvelope::<ContentDigest>::from_canonical_bytes_bounded(&bytes, 1, 1)?;
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.payload, digest);

    // Out of bounds version (e.g. envelope created with version 2)
    let v2_envelope = CanonicalVersionEnvelope::with_version(2, digest);
    let v2_bytes = v2_envelope.canonical_bytes();
    let err_v2 =
        CanonicalVersionEnvelope::<ContentDigest>::from_canonical_bytes_bounded(&v2_bytes, 1, 1);
    assert_eq!(err_v2, Err(ContractError::InvalidAnchorSuccessor));

    // Corrupted magic bytes
    let mut corrupt_magic = bytes.clone();
    corrupt_magic[0] = b'X';
    let err_magic = CanonicalVersionEnvelope::<ContentDigest>::from_canonical_bytes_bounded(
        &corrupt_magic,
        1,
        1,
    );
    assert_eq!(err_magic, Err(ContractError::InvalidDigest));

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Semantic Fingerprint Domain Separation
// ---------------------------------------------------------------------------

#[test]
fn semantic_fingerprint_domain_separation() -> Result<(), ContractError> {
    let digest = ContentDigest::sha256(b"domain separation content");

    let fp_alpha = digest.canonical_digest("fss.evidence.alpha");
    let fp_beta = digest.canonical_digest("fss.evidence.beta");
    let fp_alpha_repeat = digest.canonical_digest("fss.evidence.alpha");

    assert_eq!(fp_alpha, fp_alpha_repeat);
    assert_ne!(fp_alpha, fp_beta);
    assert_eq!(fp_alpha.algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(fp_beta.algorithm(), DigestAlgorithm::Sha256);

    Ok(())
}
