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
        .build();

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
