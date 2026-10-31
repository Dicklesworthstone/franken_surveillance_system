#![forbid(unsafe_code)]
//! Main-profile tiled CABAC streams against independently decoded FFmpeg pixels.

use std::error::Error;

use fss_codec_h265::bits::BitReader;
use fss_codec_h265::nal::rbsp_from_ebsp;
use fss_codec_h265::params::{parse_pps, parse_sps};
use fss_codec_h265::{
    DecodeError, Decoder, DecoderLimits, Picture, UnsupportedFeature, annex_b_nal_units,
};

type Test = Result<(), Box<dyn Error>>;

const UNIFORM: &[u8] = include_bytes!("fixtures/decode/tiles_uniform_p.h265");
const DEPENDENT: &[u8] = include_bytes!("fixtures/decode/tiles_grid_dependent.h265");
const BASELINE: &[u8] = include_bytes!("fixtures/decode/dependent_midrow.h265");

fn decoded(bytes: &[u8]) -> Result<Vec<Picture>, DecodeError> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(bytes)?;
    frames.extend(decoder.finish()?);
    Ok(frames)
}

fn oracle(bytes: &[u8], expected: &str, width: u32, height: u32) -> Test {
    let frames = decoded(bytes)?;
    let rows: Vec<_> = expected
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(frames.len(), rows.len());
    for (index, (frame, expected)) in frames.iter().zip(rows).enumerate() {
        let fields: Vec<_> = expected.split_whitespace().collect();
        let digest: String = frame
            .i420_sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!([frame.width(), frame.height()], [width, height]);
        assert_eq!(frame.decode_index(), index as u64);
        assert_eq!(frame.poc(), index as i32);
        assert_eq!(frame.to_i420().len(), fields[1].parse::<usize>()?);
        assert_eq!(digest, fields[2]);
        assert!(frame.uses_tiles());
    }
    Ok(())
}

macro_rules! oracle_test {
    ($name:ident, $width:expr, $height:expr) => {
        #[test]
        fn $name() -> Test {
            oracle(
                include_bytes!(concat!("fixtures/decode/", stringify!($name), ".h265")),
                include_str!(concat!("fixtures/decode/", stringify!($name), ".sha256")),
                $width,
                $height,
            )
        }
    };
}

oracle_test!(tiles_emulation, 512, 64);
oracle_test!(tiles_grid, 512, 128);
oracle_test!(tiles_grid_dependent, 512, 128);
oracle_test!(tiles_explicit, 576, 160);
oracle_test!(tiles_explicit_dependent, 576, 160);
oracle_test!(tiles_independent, 512, 64);
oracle_test!(tiles_motion, 512, 64);
oracle_test!(tiles_deblock_closed, 512, 128);
oracle_test!(tiles_deblock_across, 512, 128);
oracle_test!(tiles_horizontal_closed, 512, 128);
oracle_test!(tiles_horizontal_across, 512, 128);
oracle_test!(tiles_vertical_closed, 512, 128);
oracle_test!(tiles_vertical_across, 512, 128);
oracle_test!(tiles_diagonal_closed, 512, 128);
oracle_test!(tiles_diagonal_across, 512, 128);
oracle_test!(tiles_band_closed, 512, 128);
oracle_test!(tiles_band_across, 512, 128);
oracle_test!(tiles_partial_ctbs, 504, 120);

#[test]
fn uniform_tiles_reset_qp_contexts_and_predict_real_frames() -> Test {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(UNIFORM)?;
    frames.extend(decoder.finish()?);
    let oracle: Vec<_> = include_str!("fixtures/decode/tiles_uniform_p.sha256")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(frames.len(), oracle.len());
    for (index, (frame, expected)) in frames.iter().zip(oracle).enumerate() {
        let fields: Vec<_> = expected.split_whitespace().collect();
        let digest: String = frame
            .i420_sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(frame.width(), 512);
        assert_eq!(frame.height(), 64);
        assert_eq!(frame.decode_index(), index as u64);
        assert_eq!(frame.to_i420().len(), fields[1].parse::<usize>()?);
        assert_eq!(digest, fields[2]);
        assert!(frame.uses_tiles());
    }
    assert_eq!(frames[0].to_i420(), frames[1].to_i420());
    Ok(())
}

#[test]
fn legacy_generation_keeps_its_exact_tile_refusal() -> Test {
    let mut decoder = Decoder::new_v1(DecoderLimits::default())?;
    assert_eq!(
        decoder.decode_annex_b(UNIFORM),
        Err(DecodeError::Unsupported(UnsupportedFeature::Tiles))
    );
    assert_eq!(decoder.pictures_decoded(), 0);
    assert!(decoder.finish()?.is_empty());
    Ok(())
}

#[test]
fn untiled_current_and_legacy_outputs_are_identical() -> Test {
    let mut legacy = Decoder::new_v1(DecoderLimits::default())?;
    let mut old = legacy.decode_annex_b(BASELINE)?;
    old.extend(legacy.finish()?);
    assert_eq!(old, decoded(BASELINE)?);
    assert!(old.iter().all(|frame| !frame.uses_tiles()));
    Ok(())
}

#[test]
fn dependent_segments_preserve_pixels_despite_decreasing_raster_address() -> Test {
    assert_eq!(
        decoded(DEPENDENT)?,
        decoded(include_bytes!("fixtures/decode/tiles_grid.h265"))?
    );
    assert_eq!(
        decoded(include_bytes!(
            "fixtures/decode/tiles_explicit_dependent.h265"
        ))?,
        decoded(include_bytes!("fixtures/decode/tiles_explicit.h265"))?
    );
    Ok(())
}

#[test]
fn invalid_layouts_are_rejected_before_surface_allocation() -> Test {
    let units: Vec<_> = annex_b_nal_units(UNIFORM).collect();
    let sps = parse_sps(&rbsp_from_ebsp(&units[1][2..], 1024)?)?;
    let pps = parse_pps(&rbsp_from_ebsp(&units[2][2..], 1024)?)?;
    pps.validate(&sps)?;
    let mut partial = sps.clone();
    partial.width = 504;
    partial.height = 56;
    pps.validate(&partial)?; // normative tile minima include the padded edge CTBs
    for changed in 0..7 {
        let mut bad = pps.clone();
        match changed {
            0 => bad.tile_columns = 0,
            1 => bad.tile_columns = 41,
            2 => bad.tile_rows = 45,
            3 => bad.tile_columns = 1,
            4 => bad.tile_columns = 3, // columns would be below Main's 256-sample minimum
            5 => {
                bad.uniform_tile_spacing = false;
                bad.column_widths = vec![0];
            }
            _ => bad.entropy_coding_sync = true,
        }
        assert_eq!(
            bad.validate(&sps),
            Err(DecodeError::Malformed),
            "layout {changed}"
        );
    }
    let mut bad = pps;
    bad.uniform_tile_spacing = false;
    bad.column_widths = vec![u32::MAX];
    assert_eq!(bad.validate(&sps), Err(DecodeError::Malformed));
    Ok(())
}

fn escaped_nal(header: &[u8], rbsp: &[u8]) -> Vec<u8> {
    let mut nal = header.to_vec();
    let mut zeros = 0;
    for &byte in rbsp {
        if zeros == 2 && byte <= 3 {
            nal.push(3);
            zeros = 0;
        }
        nal.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    nal
}

#[test]
fn entry_offsets_must_match_consumed_cabac_substreams() -> Test {
    let units: Vec<_> = annex_b_nal_units(UNIFORM).collect();
    let raw = rbsp_from_ebsp(&units[3][2..], 1024)?;
    let mut reader = BitReader::new(&raw, raw.len() * 8);
    // First IDR header: first(1), no_output(0), PPS ue(0), I ue(2), QP se(0).
    reader.skip(7)?;
    assert_eq!(reader.ue(10)?, 1);
    let bits = reader.ue(31)? + 1;
    let position = reader.position();
    let offset_minus_one = reader.uint(bits)?;
    for altered in [
        0,
        offset_minus_one - 1,
        offset_minus_one + 1,
        (1 << bits) - 1,
    ] {
        let mut changed = raw.clone();
        for index in 0..bits as usize {
            let at = position + index;
            let bit = (altered >> (bits as usize - index - 1)) & 1;
            changed[at / 8] =
                (changed[at / 8] & !(1 << (7 - at % 8))) | ((bit as u8) << (7 - at % 8));
        }
        let broken = escaped_nal(&units[3][..2], &changed);
        let mut decoder = Decoder::new(DecoderLimits::default())?;
        for unit in &units[..3] {
            assert!(decoder.decode_nal(unit)?.is_none());
        }
        assert!(decoder.decode_nal(&broken).is_err(), "entry {altered}");
        assert_eq!(decoder.pictures_decoded(), 0);
        let mut recovered = decoder.decode_annex_b(BASELINE)?;
        recovered.extend(decoder.finish()?);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].to_i420(), decoded(BASELINE)?[0].to_i420());
    }
    Ok(())
}

#[test]
fn incomplete_tiles_and_bad_segment_order_never_publish_a_picture() -> Test {
    let units: Vec<_> = annex_b_nal_units(DEPENDENT).collect();
    for order in [
        vec![0, 1, 2, 3],
        vec![0, 1, 2, 4, 5],
        vec![0, 1, 2, 3, 5, 4],
        vec![0, 1, 2, 3, 4, 4, 5],
    ] {
        let mut decoder = Decoder::new(DecoderLimits::default())?;
        let mut errors = 0;
        for index in order {
            match decoder.decode_nal(units[index]) {
                Err(_) => errors += 1,
                Ok(frame) => assert!(frame.is_none()),
            }
        }
        match decoder.finish() {
            Err(_) => errors += 1,
            Ok(frames) => assert!(frames.is_empty()),
        }
        assert!(errors > 0);
        assert_eq!(decoder.pictures_decoded(), 0);
    }
    Ok(())
}

#[test]
fn every_tiled_segment_truncation_discards_continuation_and_recovers() -> Test {
    let units: Vec<_> = annex_b_nal_units(DEPENDENT).collect();
    for segment in 3..units.len() {
        for cut in 0..units[segment].len().saturating_sub(1) {
            let mut decoder = Decoder::new(DecoderLimits::default())?;
            for unit in &units[..segment] {
                assert!(decoder.decode_nal(unit)?.is_none());
            }
            assert!(
                decoder.decode_nal(&units[segment][..cut]).is_err(),
                "segment {segment} cut {cut}"
            );
            assert_eq!(decoder.pictures_decoded(), 0);
            assert!(decoder.next_output().is_none());
            let mut recovered = decoder.decode_annex_b(BASELINE)?;
            recovered.extend(decoder.finish()?);
            assert_eq!(recovered.len(), 1, "segment {segment} cut {cut}");
        }
    }
    Ok(())
}

#[test]
fn tiled_picture_limits_include_every_dependent_segment() -> Test {
    for limits in [
        DecoderLimits {
            max_width: 511,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_luma_samples: 512 * 128 - 1,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_slices_per_picture: 2,
            ..DecoderLimits::default()
        },
    ] {
        let mut decoder = Decoder::new(limits)?;
        assert_eq!(decoder.decode_annex_b(DEPENDENT), Err(DecodeError::Limit));
        assert_eq!(decoder.pictures_decoded(), 0);
    }
    Ok(())
}

#[test]
fn a_segment_cannot_straddle_partial_tiles_even_when_its_logical_slice_is_complete() -> Test {
    let invalid = include_bytes!("fixtures/decode/tiles_invalid_partial_segment.h265");
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    assert_eq!(decoder.decode_annex_b(invalid), Err(DecodeError::Malformed));
    assert_eq!(decoder.pictures_decoded(), 0);
    let mut recovered = decoder.decode_annex_b(BASELINE)?;
    recovered.extend(decoder.finish()?);
    assert_eq!(recovered.len(), 1);
    Ok(())
}

#[test]
fn tile_generation_remains_bound_to_later_untiled_output() -> Test {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(UNIFORM)?;
    frames.extend(decoder.decode_annex_b(BASELINE)?);
    frames.extend(decoder.finish()?);
    assert_eq!(frames.len(), 3);
    assert!(frames.iter().all(Picture::uses_tiles));
    assert_eq!(frames[2].to_i420(), decoded(BASELINE)?[0].to_i420());
    Ok(())
}
