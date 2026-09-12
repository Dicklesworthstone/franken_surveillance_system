#![forbid(unsafe_code)]
//! Contract tests for the canonical durable-format framework.

use std::error::Error;
use std::fmt::Debug;

use fss_core::ContentDigest;
use fss_core::durable::{
    CANONICAL_DURABLE_MAGIC, CANONICAL_DURABLE_VERSION_1, ChecksumPlacement, ChecksumScope,
    DurableError, DurableFormat, Endianness, LengthWidth, VersionWidth,
};

type TestResult = Result<(), Box<dyn Error>>;

fn expect_err<T: Debug>(result: Result<T, DurableError>) -> Result<DurableError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a durable error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn canonical_format_round_trip() -> TestResult {
    let format =
        DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, CANONICAL_DURABLE_VERSION_1, 1024);
    let payload = b"canonical-durable-payload-test-data";
    let encoded = format.encode(payload)?;

    let frame = format.decode(&encoded)?;
    assert_eq!(frame.version(), CANONICAL_DURABLE_VERSION_1);
    assert_eq!(frame.payload(), payload);
    assert_eq!(frame.to_payload_vec(), payload.to_vec());

    let decoded_payload = format.decode_payload(&encoded)?;
    assert_eq!(decoded_payload, payload);

    format.verify(&encoded)?;
    format.verify_with_expected_checksum(&encoded, frame.checksum())?;
    Ok(())
}

#[test]
fn spool_object_format_round_trip() -> TestResult {
    let magic = *b"FSSSPOOL";
    let format = DurableFormat::spool_object(&magic, 1, 1024);
    let payload = b"spool-payload-bytes";
    let encoded = format.encode(payload)?;

    assert_eq!(format.header_len(), 52);
    assert_eq!(format.trailer_len(), 0);
    assert_eq!(format.min_envelope_len(), 52);

    let frame = format.decode(&encoded)?;
    assert_eq!(frame.version(), 1);
    assert_eq!(frame.tag(), Some(1));
    assert_eq!(frame.payload(), payload);
    assert_eq!(frame.checksum(), ContentDigest::sha256(payload));

    format.verify(&encoded)?;
    Ok(())
}

#[test]
fn bounds_at_bound_and_bound_plus_one() -> TestResult {
    let bound = 64;
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, bound);

    // Exact bound: 64 bytes
    let exact_payload = vec![0x42; bound];
    let encoded = format.encode(&exact_payload)?;
    let frame = format.decode(&encoded)?;
    assert_eq!(frame.payload().len(), bound);

    // Bound + 1: 65 bytes
    let over_payload = vec![0x42; bound + 1];
    let err = expect_err(format.encode(&over_payload))?;
    assert_eq!(
        err,
        DurableError::OverLimitLength {
            limit: bound,
            actual: bound + 1,
        }
    );
    assert!(err.is_over_limit());

    // Hostile declared length in byte stream exceeding limit
    let mut hostile_bytes = encoded.clone();
    let hostile_len = (bound as u64) + 1;
    hostile_bytes[8..16].copy_from_slice(&hostile_len.to_be_bytes());
    let decode_err = expect_err(format.decode(&hostile_bytes))?;
    assert_eq!(
        decode_err,
        DurableError::OverLimitLength {
            limit: bound,
            actual: bound + 1,
        }
    );
    Ok(())
}

#[test]
fn truncation_at_every_byte_offset() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let payload = b"truncation-sweep-payload-bytes";
    let encoded = format.encode(payload)?;
    let total_len = encoded.len();

    for offset in 0..total_len {
        let truncated_slice = &encoded[..offset];
        let err = expect_err(format.decode(truncated_slice))?;

        assert!(
            err.is_truncated(),
            "offset {offset}/{total_len} must fail as Truncated, got: {err:?}"
        );
        match err {
            DurableError::Truncated {
                expected_len,
                actual_len,
            } => {
                assert_eq!(actual_len, offset);
                assert!(expected_len >= format.min_envelope_len());
            }
            other => return Err(format!("expected Truncated, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn truncation_at_every_byte_offset_header_checksum() -> TestResult {
    let magic = *b"FSSSPOOL";
    let format = DurableFormat::spool_object(&magic, 1, 512);
    let payload = b"spool-truncation-payload";
    let encoded = format.encode(payload)?;
    let total_len = encoded.len();

    for offset in 0..total_len {
        let truncated_slice = &encoded[..offset];
        let err = expect_err(format.decode(truncated_slice))?;

        assert!(
            err.is_truncated(),
            "offset {offset}/{total_len} must fail as Truncated, got: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn flipped_bit_at_every_byte() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let payload = b"bit-flip-sweep-verification";
    let encoded = format.encode(payload)?;
    let total_len = encoded.len();

    for byte_idx in 0..total_len {
        for bit_idx in 0..8 {
            let mut corrupted = encoded.clone();
            corrupted[byte_idx] ^= 1 << bit_idx;

            let res = format.decode(&corrupted);
            if res.is_ok() {
                return Err(format!(
                    "flipped bit at byte {byte_idx}, bit {bit_idx} unexpectedly succeeded"
                )
                .into());
            }
            let err = expect_err(res)?;

            assert!(
                err.is_bad_magic()
                    || err.is_unknown_version()
                    || err.is_over_limit()
                    || err.is_truncated()
                    || err.is_trailing_bytes()
                    || err.is_checksum_mismatch(),
                "unexpected error variant: {err:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn flipped_bit_at_every_byte_spool_format() -> TestResult {
    let magic = *b"FSSSPOOL";
    let format = DurableFormat::spool_object(&magic, 1, 512);
    let payload = b"spool-bit-flip-test";
    let encoded = format.encode(payload)?;
    let total_len = encoded.len();

    for byte_idx in 0..total_len {
        for bit_idx in 0..8 {
            let mut corrupted = encoded.clone();
            corrupted[byte_idx] ^= 1 << bit_idx;

            let res = format.decode(&corrupted);
            if res.is_ok() {
                return Err(format!(
                    "spool flipped bit at byte {byte_idx}, bit {bit_idx} unexpectedly succeeded"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn trailing_garbage_rejected() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let payload = b"exact-payload";
    let encoded = format.encode(payload)?;
    let expected_len = encoded.len();

    for extra_bytes in [1, 2, 7, 16, 64, 1024] {
        let mut corrupted = encoded.clone();
        corrupted.extend(vec![0xEE; extra_bytes]);

        let err = expect_err(format.decode(&corrupted))?;
        assert_eq!(
            err,
            DurableError::TrailingBytes {
                expected_len,
                actual_len: expected_len + extra_bytes,
            }
        );
        assert!(err.is_trailing_bytes());
    }
    Ok(())
}

#[test]
fn bad_magic_rejected() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);

    let bad_magic_input = b"NOPE_some_garbage_data_with_length";
    let err = expect_err(format.decode(bad_magic_input))?;
    assert!(err.is_bad_magic());
    match err {
        DurableError::BadMagic { expected, actual } => {
            assert_eq!(expected, CANONICAL_DURABLE_MAGIC.to_vec());
            assert_eq!(actual, b"NOPE".to_vec());
        }
        other => return Err(format!("expected BadMagic, got {other:?}").into()),
    }

    let short_foreign = b"X";
    let err_short = expect_err(format.decode(short_foreign))?;
    assert!(err_short.is_bad_magic());
    Ok(())
}

#[test]
fn unknown_version_rejected() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let payload = b"version-test";
    let encoded = format.encode(payload)?;

    let mut bad_version = encoded.clone();
    bad_version[4..8].copy_from_slice(&999_u32.to_be_bytes());

    let err = expect_err(format.decode(&bad_version))?;
    assert_eq!(
        err,
        DurableError::UnknownVersion {
            expected_min: 1,
            expected_max: 1,
            actual: 999,
        }
    );
    assert!(err.is_unknown_version());
    Ok(())
}

#[test]
fn unsupported_tag_rejected() -> TestResult {
    let magic = *b"FSSSTAG1";
    let format = DurableFormat::builder(&magic)
        .version(1)
        .version_width(VersionWidth::U16)
        .tag_field(Some(42))
        .length_width(LengthWidth::U32)
        .endianness(Endianness::BigEndian)
        .checksum_placement(ChecksumPlacement::Header)
        .checksum_scope(ChecksumScope::PayloadOnly)
        .build()?;

    let payload = b"tag-test";
    let encoded = format.encode(payload)?;

    let mut bad_tag = encoded.clone();
    bad_tag[10..12].copy_from_slice(&99_u16.to_be_bytes());

    let err = expect_err(format.decode(&bad_tag))?;
    assert_eq!(
        err,
        DurableError::UnsupportedTag {
            expected: 42,
            actual: 99,
        }
    );
    Ok(())
}

#[test]
fn checksum_mismatch_rejected() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let payload = b"checksum-verification-data";
    let encoded = format.encode(payload)?;

    let wrong_digest = ContentDigest::sha256(b"completely-different-data");
    let err = expect_err(format.verify_with_expected_checksum(&encoded, wrong_digest))?;
    assert!(err.is_checksum_mismatch());
    Ok(())
}

#[test]
fn empty_payload_supported() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let empty_payload: &[u8] = b"";
    let encoded = format.encode(empty_payload)?;

    assert_eq!(encoded.len(), format.min_envelope_len());
    let frame = format.decode(&encoded)?;
    assert_eq!(frame.payload(), b"");

    let magic = *b"FSSSPOOL";
    let spool_format = DurableFormat::spool_object(&magic, 1, 512);
    let spool_encoded = spool_format.encode(empty_payload)?;
    let spool_frame = spool_format.decode(&spool_encoded)?;
    assert_eq!(spool_frame.payload(), b"");
    assert_eq!(spool_frame.checksum(), ContentDigest::sha256(b""));
    Ok(())
}

#[test]
fn finding_1_u32_length_overflow_rejected_at_build_and_encode() -> TestResult {
    // 1. Builder rejects max_payload_len exceeding u32::MAX when LengthWidth::U32
    let err = expect_err(
        DurableFormat::builder(b"TEST")
            .length_width(LengthWidth::U32)
            .max_payload_len((u32::MAX as usize) + 1)
            .build(),
    )?;
    assert!(err.is_invalid_format());

    // 2. Format with LengthWidth::U32 and max_payload_len within u32 bounds works
    let format = DurableFormat::builder(b"TEST")
        .length_width(LengthWidth::U32)
        .max_payload_len(1024)
        .build()?;
    assert_eq!(format.max_payload_len(), 1024);
    let payload = b"u32-length-test";
    let encoded = format.encode(payload)?;
    let frame = format.decode(&encoded)?;
    assert_eq!(frame.payload(), payload);

    // 3. Decoding header with declared length exceeding max_payload_len returns OverLimitLength
    let mut hostile = encoded.clone();
    let hostile_len: u32 = 2048;
    hostile[8..12].copy_from_slice(&hostile_len.to_be_bytes());
    let decode_err = expect_err(format.decode_header(&hostile))?;
    assert!(decode_err.is_over_limit());
    Ok(())
}

#[test]
fn finding_3_payload_only_checksum_scope_safety_constraints() -> TestResult {
    // 1. Builder refuses ChecksumScope::PayloadOnly with a multi-version range
    let err_range = expect_err(
        DurableFormat::builder(b"TEST")
            .version_range(1, 2)
            .checksum_scope(ChecksumScope::PayloadOnly)
            .build(),
    )?;
    assert!(err_range.is_invalid_format());

    // 2. Builder refuses ChecksumScope::PayloadOnly with Trailer placement
    let err_trailer = expect_err(
        DurableFormat::builder(b"TEST")
            .checksum_placement(ChecksumPlacement::Trailer)
            .checksum_scope(ChecksumScope::PayloadOnly)
            .build(),
    )?;
    assert!(err_trailer.is_invalid_format());

    // 3. HeaderAndPayload checksum scope detects version and header tampering
    let format = DurableFormat::builder(b"TEST")
        .version_range(1, 2)
        .checksum_placement(ChecksumPlacement::Header)
        .checksum_scope(ChecksumScope::HeaderAndPayload)
        .build()?;
    let payload = b"tamper-sensitive-data";
    let mut encoded = format.encode(payload)?;

    // Flip version in header from 2 to 1 (offset 4..8 is version)
    encoded[4..8].copy_from_slice(&1_u32.to_be_bytes());

    // decode MUST fail with ChecksumMismatch because header was tampered
    let decode_err = expect_err(format.decode(&encoded))?;
    assert!(decode_err.is_checksum_mismatch());
    Ok(())
}

#[test]
fn finding_4_hasher_error_variant_and_display() {
    let err = DurableError::DigestComputationFailed;
    assert!(err.is_digest_error());
    assert_eq!(err.to_string(), "durable format digest computation failed");
}

#[test]
fn finding_6_u16_version_overflow_rejected_at_build() -> TestResult {
    let err = expect_err(
        DurableFormat::builder(b"TEST")
            .version_width(VersionWidth::U16)
            .version(65537)
            .build(),
    )?;
    assert!(err.is_invalid_format());
    Ok(())
}

#[test]
fn finding_7_inverted_version_range_rejected_at_build() -> TestResult {
    let err = expect_err(DurableFormat::builder(b"TEST").version_range(5, 2).build())?;
    assert!(err.is_invalid_format());
    Ok(())
}

#[test]
fn finding_8_encode_writes_max_version_and_supports_explicit_version() -> TestResult {
    let format = DurableFormat::builder(b"TEST")
        .version_range(1, 3)
        .checksum_placement(ChecksumPlacement::Trailer)
        .checksum_scope(ChecksumScope::HeaderAndPayload)
        .build()?;
    let payload = b"version-selection-test";

    // encode writes max_version (3)
    let encoded = format.encode(payload)?;
    let frame = format.decode(&encoded)?;
    assert_eq!(frame.version(), 3);

    // encode_version writes explicit requested version in range
    let encoded_v2 = format.encode_version(2, payload)?;
    let frame_v2 = format.decode(&encoded_v2)?;
    assert_eq!(frame_v2.version(), 2);

    let encoded_v1 = format.encode_version(1, payload)?;
    let frame_v1 = format.decode(&encoded_v1)?;
    assert_eq!(frame_v1.version(), 1);

    // encode_version rejects version out of range
    let err_v0 = expect_err(format.encode_version(0, payload))?;
    assert!(err_v0.is_unknown_version());
    let err_v4 = expect_err(format.encode_version(4, payload))?;
    assert!(err_v4.is_unknown_version());

    Ok(())
}

#[test]
fn finding_10_header_checksum_with_header_and_payload_scope_contract() -> TestResult {
    let format = DurableFormat::builder(b"HEAD")
        .version(1)
        .checksum_placement(ChecksumPlacement::Header)
        .checksum_scope(ChecksumScope::HeaderAndPayload)
        .max_payload_len(512)
        .build()?;
    let payload = b"header-and-payload-checksum-test";
    let encoded = format.encode(payload)?;

    // Roundtrip
    let frame = format.decode(&encoded)?;
    assert_eq!(frame.payload(), payload);
    assert_eq!(frame.version(), 1);

    // Bit flip in magic
    let mut corrupted = encoded.clone();
    corrupted[0] ^= 0x01;
    assert!(expect_err(format.decode(&corrupted))?.is_bad_magic());

    // Bit flip in version
    let mut corrupted = encoded.clone();
    corrupted[5] ^= 0x01;
    assert!(expect_err(format.decode(&corrupted))?.is_unknown_version());

    // Bit flip in payload
    let mut corrupted = encoded.clone();
    corrupted[format.header_len() + 2] ^= 0x01;
    assert!(expect_err(format.decode(&corrupted))?.is_checksum_mismatch());

    Ok(())
}

#[test]
fn finding_10_decode_payload_error_propagation() -> TestResult {
    let format = DurableFormat::canonical(&CANONICAL_DURABLE_MAGIC, 1, 512);
    let payload = b"decode-payload-error-test";
    let encoded = format.encode(payload)?;

    // 1. Bad magic
    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 0xFF;
    assert!(expect_err(format.decode_payload(&bad_magic))?.is_bad_magic());

    // 2. Unknown version
    let mut bad_ver = encoded.clone();
    bad_ver[4..8].copy_from_slice(&99_u32.to_be_bytes());
    assert!(expect_err(format.decode_payload(&bad_ver))?.is_unknown_version());

    // 3. Truncated
    assert!(expect_err(format.decode_payload(&encoded[..10]))?.is_truncated());

    // 4. Over limit
    let mut over_limit = encoded.clone();
    over_limit[8..16].copy_from_slice(&1000_u64.to_be_bytes());
    assert!(expect_err(format.decode_payload(&over_limit))?.is_over_limit());

    // 5. Trailing bytes
    let mut trailing = encoded.clone();
    trailing.extend_from_slice(b"extra");
    assert!(expect_err(format.decode_payload(&trailing))?.is_trailing_bytes());

    // 6. Checksum mismatch
    let mut corrupted_chk = encoded.clone();
    let last = corrupted_chk.len() - 1;
    corrupted_chk[last] ^= 0x01;
    assert!(expect_err(format.decode_payload(&corrupted_chk))?.is_checksum_mismatch());

    Ok(())
}

#[test]
fn finding_10_endianness_variations_contract() -> TestResult {
    // LittleEndian with U32 version and U32 length
    let format_le = DurableFormat::builder(b"LE32")
        .version(1)
        .version_width(VersionWidth::U32)
        .length_width(LengthWidth::U32)
        .endianness(Endianness::LittleEndian)
        .checksum_placement(ChecksumPlacement::Trailer)
        .checksum_scope(ChecksumScope::HeaderAndPayload)
        .build()?;
    let payload = b"little-endian-test";
    let encoded_le = format_le.encode(payload)?;

    // Verify wire format: magic (4), version 1 in LE (01 00 00 00), length in LE
    assert_eq!(&encoded_le[..4], b"LE32");
    assert_eq!(&encoded_le[4..8], &1_u32.to_le_bytes());
    assert_eq!(&encoded_le[8..12], &(payload.len() as u32).to_le_bytes());
    let frame_le = format_le.decode(&encoded_le)?;
    assert_eq!(frame_le.payload(), payload);

    // BigEndian with U16 version and U64 length
    let format_be = DurableFormat::builder(b"BE16")
        .version(2)
        .version_width(VersionWidth::U16)
        .length_width(LengthWidth::U64)
        .endianness(Endianness::BigEndian)
        .checksum_placement(ChecksumPlacement::Trailer)
        .checksum_scope(ChecksumScope::HeaderAndPayload)
        .build()?;
    let encoded_be = format_be.encode(payload)?;

    // Verify wire format: magic (4), version 2 in BE (00 02), length in BE (8 bytes)
    assert_eq!(&encoded_be[..4], b"BE16");
    assert_eq!(&encoded_be[4..6], &2_u16.to_be_bytes());
    assert_eq!(&encoded_be[6..14], &(payload.len() as u64).to_be_bytes());
    let frame_be = format_be.decode(&encoded_be)?;
    assert_eq!(frame_be.payload(), payload);

    Ok(())
}
