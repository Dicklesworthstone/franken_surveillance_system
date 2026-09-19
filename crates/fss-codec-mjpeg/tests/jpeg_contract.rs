#![forbid(unsafe_code)]
//! Baseline JPEG decode contracts: marker structure, transforms, limits, and malformed inputs.
use fss_codec_mjpeg::{
    ComponentInterpretation as Color, DecodeBudget, DecodeError, DecodeLimits, DecodedLuma,
    decode_luma, decoder_identity,
};
use fss_core::ContentDigest;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn std::error::Error>>;
fn decode(bytes: &[u8], color: Color) -> Result<DecodedLuma, DecodeError> {
    decode_luma(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        color,
        DecodeLimits::default(),
        &mut DecodeBudget::new(50_000_000),
    )
}
fn segment(bytes: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    bytes.extend_from_slice(&[255, marker]);
    bytes.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
}
fn flat(width: u16, height: u16, color: bool, interval: u16) -> Vec<u8> {
    let mut bytes = vec![255, 216];
    let mut table = vec![0];
    table.extend_from_slice(&[1; 64]);
    segment(&mut bytes, 0xdb, &table);
    let n = if color { 3 } else { 1 };
    let mut frame = vec![8];
    frame.extend_from_slice(&height.to_be_bytes());
    frame.extend_from_slice(&width.to_be_bytes());
    frame.push(n);
    for i in 1..=n {
        frame.extend_from_slice(&[i, 0x11, 0]);
    }
    segment(&mut bytes, 0xc0, &frame);
    let mut huffman = Vec::new();
    for id in [0, 16] {
        huffman.push(id);
        huffman.push(1);
        huffman.extend_from_slice(&[0; 15]);
        huffman.push(0);
    }
    segment(&mut bytes, 0xc4, &huffman);
    if interval > 0 {
        segment(&mut bytes, 0xdd, &interval.to_be_bytes());
    }
    let mut scan = vec![n];
    for i in 1..=n {
        scan.extend_from_slice(&[i, 0]);
    }
    scan.extend_from_slice(&[0, 63, 0]);
    segment(&mut bytes, 0xda, &scan);
    let mcus = usize::from(width).div_ceil(8) * usize::from(height).div_ceil(8);
    let group = if interval == 0 {
        mcus
    } else {
        usize::from(interval)
    };
    let mut completed = 0;
    let mut restart = 0;
    while completed < mcus {
        let current = group.min(mcus - completed);
        let bit_count = current * usize::from(n) * 2;
        for byte in 0..bit_count.div_ceil(8) {
            let used = (bit_count - byte * 8).min(8);
            let value = (1_u16 << (8 - used)) - 1;
            bytes.push(value as u8);
        }
        completed += current;
        if completed < mcus {
            bytes.extend_from_slice(&[255, 0xd0 + restart]);
            restart = (restart + 1) % 8;
        }
    }
    bytes.extend_from_slice(&[255, 217]);
    bytes
}
fn marker(bytes: &[u8], value: u8) -> usize {
    bytes
        .windows(2)
        .position(|p| p == [255, value])
        .unwrap_or(bytes.len())
}

#[test]
fn reconstructs_hand_encoded_flat_blocks_and_odd_edges() -> Test {
    let result = decode(&flat(17, 13, false, 0), Color::Grayscale)?;
    assert_eq!(result.dimensions(), [17, 13]);
    assert_eq!(result.pixels(), &[128; 221]);
    assert_eq!(result.receipt().mcus, 6);
    assert_eq!(result.receipt().entropy_blocks, 6);
    Ok(())
}
#[test]
fn validates_chroma_blocks_even_when_only_luma_is_returned() -> Test {
    let mut bytes = flat(8, 8, true, 0);
    let result = decode(&bytes, Color::YCbCr)?;
    assert_eq!(result.pixels(), &[128; 64]);
    assert_eq!(result.receipt().entropy_blocks, 3);
    let last = bytes.len() - 3;
    bytes[last] |= 4;
    assert!(decode(&bytes, Color::YCbCr).is_err());
    Ok(())
}
#[test]
fn decodes_real_encoder_fixtures_against_independent_luma_oracles() -> Test {
    let fixtures: &[(&[u8], &[u8], Color)] = &[
        (
            include_bytes!("fixtures/gray.jpg"),
            include_bytes!("fixtures/gray.gray"),
            Color::Grayscale,
        ),
        (
            include_bytes!("fixtures/y444.jpg"),
            include_bytes!("fixtures/y444.gray"),
            Color::YCbCr,
        ),
        (
            include_bytes!("fixtures/y422.jpg"),
            include_bytes!("fixtures/y422.gray"),
            Color::YCbCr,
        ),
        (
            include_bytes!("fixtures/y420_restart.jpg"),
            include_bytes!("fixtures/y420_restart.gray"),
            Color::YCbCr,
        ),
    ];
    for &(encoded, expected, color) in fixtures {
        let result = decode(encoded, color)?;
        assert_eq!(result.dimensions(), [17, 13]);
        assert_eq!(result.pixels().len(), expected.len());
        for (&a, &b) in result.pixels().iter().zip(expected) {
            assert!(a.abs_diff(b) <= 1);
        }
        assert_eq!(result.pixels(), decode(encoded, color)?.pixels());
    }
    Ok(())
}
#[test]
fn restart_interval_resets_predictors_and_checks_modulo_sequence() -> Test {
    let bytes = flat(80, 8, false, 1);
    let result = decode(&bytes, Color::Grayscale)?;
    assert_eq!(result.receipt().restarts, 9);
    let mut bad = bytes.clone();
    let at = marker(&bad, 0xd0);
    bad[at + 1] = 0xd3;
    assert!(decode(&bad, Color::Grayscale).is_err());
    let mut bad = bytes.clone();
    let at = marker(&bad, 0xd1);
    drop(bad.drain(at..at + 2));
    assert!(decode(&bad, Color::Grayscale).is_err());
    Ok(())
}
#[test]
fn every_truncated_prefix_and_trailing_suffix_fails() {
    let bytes = flat(9, 9, false, 1);
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end], Color::Grayscale).is_err());
    }
    for suffix in [&[0][..], &[255, 217][..], bytes.as_slice()] {
        let mut longer = bytes.clone();
        longer.extend_from_slice(suffix);
        assert!(decode(&longer, Color::Grayscale).is_err());
    }
}
#[test]
fn malformed_suffix_metadata_cannot_publish_an_already_decoded_plane() {
    let mut bytes = flat(8, 8, false, 0);
    bytes.truncate(bytes.len() - 2);
    bytes.extend_from_slice(&[255, 225, 0, 40, 1, 2, 255, 217]);
    assert!(decode(&bytes, Color::Grayscale).is_err());
}
#[test]
fn missing_huffman_tables_are_not_inherited_or_fabricated() {
    let mut bytes = flat(8, 8, false, 0);
    let at = marker(&bytes, 0xc4);
    let length = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
    drop(bytes.drain(at..at + 2 + length));
    assert!(matches!(
        decode(&bytes, Color::Grayscale),
        Err(DecodeError::Unsupported)
    ));
}
#[test]
fn oversubscribed_or_all_ones_huffman_codes_fail() {
    let mut bytes = flat(8, 8, false, 0);
    let at = marker(&bytes, 0xc4);
    bytes[at + 5] = 2;
    assert!(decode(&bytes, Color::Grayscale).is_err());
}
#[test]
fn bad_padding_does_not_get_concealed() {
    let mut bytes = flat(8, 8, false, 0);
    let last = bytes.len() - 3;
    bytes[last] &= !1;
    assert!(matches!(
        decode(&bytes, Color::Grayscale),
        Err(DecodeError::Malformed)
    ));
}
#[test]
fn unsupported_coding_and_component_contracts_are_explicit() {
    let bytes = flat(8, 8, false, 0);
    assert!(matches!(
        decode(&bytes, Color::YCbCr),
        Err(DecodeError::Unsupported)
    ));
    for code in [0xc1, 0xc2, 0xc3, 0xc9] {
        let mut b = bytes.clone();
        let at = marker(&b, 0xc0);
        b[at + 1] = code;
        assert!(matches!(
            decode(&b, Color::Grayscale),
            Err(DecodeError::Unsupported)
        ));
    }
}
#[test]
fn zero_quantizers_and_invalid_scan_parameters_fail() {
    let mut b = flat(8, 8, false, 0);
    let at = marker(&b, 0xdb);
    b[at + 5] = 0;
    assert!(matches!(
        decode(&b, Color::Grayscale),
        Err(DecodeError::Malformed)
    ));
    let mut b = flat(8, 8, false, 0);
    let at = marker(&b, 0xda);
    b[at + 7] = 1;
    assert!(matches!(
        decode(&b, Color::Grayscale),
        Err(DecodeError::Unsupported)
    ));
}
#[test]
fn conflicting_adobe_color_marker_fails_after_valid_entropy() {
    let mut b = flat(8, 8, true, 0);
    b.truncate(b.len() - 2);
    segment(&mut b, 0xee, b"Adobe\0\x64\0\0\0\0\0");
    b.extend_from_slice(&[255, 217]);
    assert!(matches!(
        decode(&b, Color::YCbCr),
        Err(DecodeError::Unsupported)
    ));
}
#[test]
fn complete_input_hash_is_checked_before_decoding() {
    let b = flat(8, 8, false, 0);
    assert!(matches!(
        decode_luma(
            &b,
            [0; 32],
            Color::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(10000)
        ),
        Err(DecodeError::SourceMismatch)
    ));
    assert!(matches!(
        decode_luma(
            &b,
            [7; 32],
            Color::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(10000)
        ),
        Err(DecodeError::SourceMismatch)
    ));
}
#[test]
fn byte_dimension_pixel_and_marker_limits_fail_without_partial_output() {
    let b = flat(17, 13, false, 0);
    let digest = ContentDigest::sha256(&b).bytes();
    for limits in [
        DecodeLimits {
            maximum_bytes: b.len() - 1,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            maximum_dimension: 16,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            maximum_pixels: 220,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            maximum_markers: 2,
            ..DecodeLimits::default()
        },
    ] {
        assert!(matches!(
            decode_luma(
                &b,
                digest,
                Color::Grayscale,
                limits,
                &mut DecodeBudget::new(1_000_000)
            ),
            Err(DecodeError::Limit)
        ));
    }
}
#[test]
fn cancellation_and_exhaustion_are_not_successful_partial_decodes() {
    let b = flat(17, 13, false, 0);
    let digest = ContentDigest::sha256(&b).bytes();
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        decode_luma(
            &b,
            digest,
            Color::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::cancellable(1_000_000, &cancelled)
        ),
        Err(DecodeError::Cancelled)
    ));
    assert!(matches!(
        decode_luma(
            &b,
            digest,
            Color::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(b.len() as u64 + 20)
        ),
        Err(DecodeError::BudgetExhausted)
    ));
}
#[test]
fn receipt_binds_real_decoded_bytes_and_no_pixels_leak_through_debug() -> Test {
    let b = flat(8, 8, false, 0);
    let result = decode(&b, Color::Grayscale)?;
    assert_eq!(
        result.receipt().encoded_sha256,
        ContentDigest::sha256(&b).bytes()
    );
    assert_eq!(
        result.receipt().luma_sha256,
        ContentDigest::sha256(result.pixels()).bytes()
    );
    assert_eq!(result.receipt().decoder, decoder_identity());
    assert!(!format!("{result:?}").contains("128"));
    Ok(())
}
