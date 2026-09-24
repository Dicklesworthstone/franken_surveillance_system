//! Hostile-input discipline: truncation, corruption, garbage, missing
//! parameter sets, broken picture structure and budget violations must end
//! in typed errors (or cleanly decoded pictures), never a panic, and an
//! error must never publish a partially reconstructed picture.

#![forbid(unsafe_code)]

use std::error::Error;

use fss_codec_h265::{DecodeError, Decoder, DecoderLimits, Picture, UnsupportedFeature};

type TestResult = Result<(), Box<dyn Error>>;

const INTRA: &[u8] = include_bytes!("fixtures/decode/i_64x64_ctu32_qp30.h265");
const SLICES: &[u8] = include_bytes!("fixtures/decode/i_qcif_slices4.h265");
const PCM: &[u8] = include_bytes!("fixtures/decode/pcm_mixed_nodeblock.h265");

fn nals(stream: &[u8]) -> Vec<&[u8]> {
    fss_codec_h265::annex_b_nal_units(stream).collect()
}

/// Feeds every NAL, collecting pictures and errors; never panics.
fn feed(nal_units: &[&[u8]]) -> (Vec<Picture>, Vec<DecodeError>) {
    let mut pictures = Vec::new();
    let mut errors = Vec::new();
    let Ok(mut decoder) = Decoder::new(DecoderLimits::default()) else {
        return (pictures, vec![DecodeError::Limit]);
    };
    for nal in nal_units {
        match decoder.decode_nal(nal) {
            Ok(Some(picture)) => pictures.push(picture),
            Ok(None) => {}
            Err(err) => errors.push(err),
        }
        while let Some(picture) = decoder.next_output() {
            pictures.push(picture);
        }
    }
    match decoder.finish() {
        Ok(rest) => pictures.extend(rest),
        Err(err) => errors.push(err),
    }
    while let Some(picture) = decoder.next_output() {
        pictures.push(picture);
    }
    (pictures, errors)
}

/// Every prefix of a NAL unit (truncation inside parameter sets, slice
/// headers, CABAC data and PCM samples) is refused or decoded, never a
/// panic, and truncated slices never yield a picture.
#[test]
fn truncation_at_every_byte_is_typed() {
    for stream in [INTRA, PCM] {
        let units = nals(stream);
        for (index, unit) in units.iter().enumerate() {
            for cut in 0..unit.len() {
                let mut damaged = units.clone();
                damaged[index] = &unit[..cut];
                let (pictures, errors) = feed(&damaged);
                let vcl = unit.len() >= 2 && (unit[0] >> 1) < 32;
                if vcl && cut + 1 < unit.len() {
                    // The damaged picture is refused; later pictures of
                    // the stream depend on it (or are IRAP-gated).
                    assert!(!errors.is_empty(), "nal {index} cut {cut}: accepted");
                    assert!(pictures.len() < units.iter().filter(|u| (u[0] >> 1) < 32).count());
                }
            }
        }
    }
}

/// Single-byte corruption anywhere in the stream: typed errors or pixels,
/// never a panic.
#[test]
fn byte_corruption_never_panics() {
    for stream in [INTRA, PCM, SLICES] {
        let units = nals(stream);
        for (index, unit) in units.iter().enumerate() {
            // Roughly 60 positions per NAL unit keep the debug-build run
            // short while covering headers and slice data.
            let step = (unit.len() / 60).max(1);
            for position in (2..unit.len()).step_by(step) {
                for mask in [0x01u8, 0x80, 0xFF] {
                    let mut bytes = unit.to_vec();
                    bytes[position] ^= mask;
                    let mut damaged: Vec<&[u8]> = units.clone();
                    damaged[index] = &bytes;
                    let _ = feed(&damaged);
                }
            }
        }
    }
}

/// Deterministic pseudo-random garbage (with and without start codes).
#[test]
fn garbage_never_panics() -> TestResult {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for round in 0..200 {
        let mut bytes = Vec::new();
        for _ in 0..(64 + round * 7) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push((state >> 24) as u8);
        }
        if round % 2 == 0 {
            // Valid NAL headers of every parameter-set / slice type.
            let unit_type = [32u8, 33, 34, 19, 1, 21][round % 6];
            bytes.splice(0..0, [0, 0, 1, unit_type << 1, 1]);
        }
        let mut decoder = Decoder::new(DecoderLimits::default())?;
        let _ = decoder.decode_annex_b(&bytes);
        let _ = decoder.finish();
    }
    Ok(())
}

#[test]
fn nal_header_and_limits_are_enforced() -> TestResult {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    // forbidden_zero_bit set.
    assert_eq!(
        decoder.decode_nal(&[0x80 | (32 << 1), 1, 0]),
        Err(DecodeError::Malformed)
    );
    // nuh_temporal_id_plus1 == 0.
    assert_eq!(
        decoder.decode_nal(&[32 << 1, 0, 0]),
        Err(DecodeError::Malformed)
    );
    // A layer above the base layer.
    assert_eq!(
        decoder.decode_nal(&[(1 << 1) | 1, 1, 0]),
        Err(DecodeError::Unsupported(UnsupportedFeature::MultiLayer))
    );
    // One byte is not a NAL unit.
    assert_eq!(decoder.decode_nal(&[0x40]), Err(DecodeError::Malformed));
    // Oversized NAL against a narrowed budget.
    let limits = DecoderLimits {
        max_nal_bytes: 64,
        ..DecoderLimits::default()
    };
    let mut small = Decoder::new(limits)?;
    assert_eq!(small.decode_nal(&[0u8; 65]), Err(DecodeError::Limit));
    // Invalid limits.
    for limits in [
        DecoderLimits {
            max_width: 0,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_pictures: 0,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_dpb_pictures: 17,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_nal_bytes: 1 << 30,
            ..DecoderLimits::default()
        },
    ] {
        assert_eq!(Decoder::new(limits).err(), Some(DecodeError::Limit));
    }
    Ok(())
}

/// An SPS larger than the owner's budget is refused before any picture
/// memory is allocated.
#[test]
fn sps_above_budget_is_refused() -> TestResult {
    let limits = DecoderLimits {
        max_width: 32,
        ..DecoderLimits::default()
    };
    let mut decoder = Decoder::new(limits)?;
    assert_eq!(
        decoder.decode_annex_b(INTRA).err(),
        Some(DecodeError::Limit)
    );
    let limits = DecoderLimits {
        max_luma_samples: 64 * 32,
        ..DecoderLimits::default()
    };
    let mut decoder = Decoder::new(limits)?;
    assert_eq!(
        decoder.decode_annex_b(INTRA).err(),
        Some(DecodeError::Limit)
    );
    Ok(())
}

/// Slices before their parameter sets, and a PPS whose SPS is missing.
#[test]
fn missing_parameter_sets_are_typed() -> TestResult {
    let units = nals(INTRA);
    let slice = units
        .iter()
        .find(|u| matches!(u[0] >> 1, 19 | 20))
        .ok_or("no IDR slice")?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    assert_eq!(
        decoder.decode_nal(slice),
        Err(DecodeError::MissingParameterSet)
    );
    // SPS without its VPS.
    let sps = units.iter().find(|u| (u[0] >> 1) == 33).ok_or("no SPS")?;
    assert_eq!(
        decoder.decode_nal(sps),
        Err(DecodeError::MissingParameterSet)
    );
    Ok(())
}

/// Decoding that starts at a non-IRAP picture is refused (its references
/// were never decoded), and decoding resumes at the next IRAP picture.
#[test]
fn start_without_irap_is_refused() -> TestResult {
    let units = nals(INTRA);
    // Drop the IDR slice (keep parameter sets): the TRAIL pictures that
    // follow must be refused.
    let without_idr: Vec<&[u8]> = units
        .iter()
        .copied()
        .filter(|u| !matches!(u[0] >> 1, 19 | 20))
        .collect();
    let (pictures, errors) = feed(&without_idr);
    assert!(pictures.is_empty());
    assert!(errors.contains(&DecodeError::MissingReference));
    Ok(())
}

/// A picture missing its last slice segment is discarded, not concealed,
/// and reported as incomplete.
#[test]
fn missing_slice_segment_is_incomplete() -> TestResult {
    let units = nals(SLICES);
    let last_slice = units
        .iter()
        .rposition(|u| (u[0] >> 1) < 32)
        .ok_or("no slice")?;
    let mut damaged = units.clone();
    damaged.remove(last_slice);
    let (pictures, errors) = feed(&damaged);
    assert_eq!(pictures.len(), 1, "only the first (complete) picture");
    assert!(errors.contains(&DecodeError::IncompletePicture));
    // A missing middle slice is a gap in slice_segment_address.
    let first_picture_slices: Vec<usize> = units
        .iter()
        .enumerate()
        .filter(|(_, u)| (u[0] >> 1) < 32)
        .map(|(i, _)| i)
        .take(4)
        .collect();
    let mut gap = units.clone();
    gap.remove(first_picture_slices[1]);
    let (_, errors) = feed(&gap);
    assert!(errors.contains(&DecodeError::IncompletePicture));
    Ok(())
}

/// Annex-B splitting tolerates 3- and 4-byte start codes and trailing
/// zero bytes, and yields nothing for streams without a start code.
#[test]
fn annex_b_splitting() {
    let stream = [0, 0, 0, 1, 0x40, 1, 0xAA, 0, 0, 1, 0x42, 1, 0xBB, 0, 0];
    let units: Vec<&[u8]> = fss_codec_h265::annex_b_nal_units(&stream).collect();
    assert_eq!(units, vec![&[0x40, 1, 0xAA][..], &[0x42, 1, 0xBB][..]]);
    assert_eq!(fss_codec_h265::annex_b_nal_units(&[1, 2, 3]).count(), 0);
}
