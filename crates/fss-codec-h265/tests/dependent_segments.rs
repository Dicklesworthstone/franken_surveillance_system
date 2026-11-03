#![forbid(unsafe_code)]
//! Actual dependent-segment CABAC streams against the offline FFmpeg pixel oracle.
//! The generator carries probability contexts and writes new arithmetic streams;
//! these are not independent slices with rewritten headers. No test runs FFmpeg.

use std::error::Error;

use fss_codec_h265::{DecodeError, Decoder, DecoderLimits, Picture, annex_b_nal_units};

type Test = Result<(), Box<dyn Error>>;

const MIDROW: &[u8] = include_bytes!("fixtures/decode/dependent_midrow.h265");
const CHAIN: &[u8] = include_bytes!("fixtures/decode/dependent_context_chain.h265");
const QP: &[u8] = include_bytes!("fixtures/decode/dependent_qp_carry.h265");
const WPP: &[u8] = include_bytes!("fixtures/decode/dependent_wpp_before_save.h265");
const RESET: &[u8] = include_bytes!("fixtures/decode/dependent_independent_reset.h265");
const P_SKIP: &[u8] = include_bytes!("fixtures/decode/dependent_p_skip.h265");

fn digest(picture: &Picture) -> String {
    picture
        .i420_sha256()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode(stream: &[u8], limits: DecoderLimits) -> Result<Vec<Picture>, DecodeError> {
    let mut decoder = Decoder::new(limits)?;
    let mut pictures = decoder.decode_annex_b(stream)?;
    pictures.extend(decoder.finish()?);
    Ok(pictures)
}

fn oracle(stream: &[u8], expected: &str, width: u32, height: u32, segments: usize) -> Test {
    let pictures = decode(stream, DecoderLimits::default())?;
    assert_eq!(pictures.len(), 1);
    let fields: Vec<_> = expected
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .flat_map(str::split_whitespace)
        .collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "0");
    assert_eq!(pictures[0].width(), width);
    assert_eq!(pictures[0].height(), height);
    assert_eq!(pictures[0].to_i420().len(), fields[1].parse::<usize>()?);
    assert_eq!(digest(&pictures[0]), fields[2]);
    assert_eq!(pictures[0].poc(), 0);
    assert!(pictures[0].is_idr());
    assert_eq!(pictures[0].decode_index(), 0);
    assert_eq!(
        annex_b_nal_units(stream)
            .filter(|unit| unit[0] >> 1 < 32)
            .count(),
        segments
    );
    let replay = decode(stream, DecoderLimits::default())?;
    assert_eq!(pictures[0].to_i420(), replay[0].to_i420());
    Ok(())
}

macro_rules! oracle_test {
    ($test:ident, $name:literal, $width:expr, $height:expr, $segments:expr) => {
        #[test]
        fn $test() -> Test {
            oracle(
                include_bytes!(concat!("fixtures/decode/", $name, ".h265")),
                include_str!(concat!("fixtures/decode/", $name, ".sha256")),
                $width,
                $height,
                $segments,
            )
        }
    };
}

oracle_test!(
    midrow_prediction_uses_previous_segment_neighbors,
    "dependent_midrow",
    32,
    16,
    2
);
oracle_test!(
    consecutive_segments_carry_adapted_contexts,
    "dependent_context_chain",
    64,
    16,
    3
);
oracle_test!(
    nondefault_qp_continues_across_dependent_segments,
    "dependent_qp_carry",
    48,
    16,
    3
);
oracle_test!(
    new_independent_slice_resets_contexts_qp_and_neighbors,
    "dependent_independent_reset",
    64,
    16,
    4
);
oracle_test!(
    deblocking_crosses_dependent_segment_boundaries,
    "dependent_deblock",
    64,
    16,
    2
);
oracle_test!(
    wpp_snapshot_survives_segment_cut_before_ctu_one,
    "dependent_wpp_before_save",
    48,
    32,
    3
);
oracle_test!(
    wpp_snapshot_survives_segment_cut_after_ctu_one,
    "dependent_wpp_after_save",
    48,
    32,
    3
);
oracle_test!(
    wpp_row_sync_precedes_midrow_segment_continuation,
    "dependent_wpp_midrow",
    48,
    32,
    3
);
oracle_test!(
    wpp_single_column_initializes_without_above_right,
    "dependent_wpp_one_column",
    16,
    48,
    3
);

#[test]
fn changing_only_dependent_segment_partition_keeps_every_pixel() -> Test {
    let expected = decode(WPP, DecoderLimits::default())?[0].to_i420();
    for stream in [
        include_bytes!("fixtures/decode/dependent_wpp_after_save.h265").as_slice(),
        include_bytes!("fixtures/decode/dependent_wpp_midrow.h265").as_slice(),
    ] {
        assert_eq!(
            decode(stream, DecoderLimits::default())?[0].to_i420(),
            expected
        );
    }
    Ok(())
}

#[test]
fn pcm_seed_matches_the_authored_mathematical_pattern() -> Test {
    let picture = &decode(MIDROW, DecoderLimits::default())?[0];
    let raw = picture.to_i420();
    for y in 0..16 {
        for x in 0..16 {
            assert_eq!(raw[y * 32 + x], (((x * 7 + y * 13) & 31) << 3) as u8);
        }
    }
    for c in 0..2 {
        for y in 0..8 {
            for x in 0..8 {
                assert_eq!(
                    raw[512 + c * 128 + y * 16 + x],
                    (((x * 11 + y * 5 + c * 17) & 63) << 2) as u8
                );
            }
        }
    }
    // The second CTU is predicted from the first, not a concealed neutral block.
    assert!((0..16).any(|y| (16..32).any(|x| raw[y * 32 + x] != 128)));
    Ok(())
}

fn feed(decoder: &mut Decoder, units: &[&[u8]]) -> (Vec<Picture>, Vec<DecodeError>) {
    let mut pictures = Vec::new();
    let mut errors = Vec::new();
    for unit in units {
        match decoder.decode_nal(unit) {
            Ok(Some(picture)) => pictures.push(picture),
            Ok(None) => {}
            Err(error) => errors.push(error),
        }
        while let Some(picture) = decoder.next_output() {
            pictures.push(picture);
        }
    }
    (pictures, errors)
}

#[test]
fn no_partial_picture_is_emitted_before_the_last_segment() -> Test {
    for stream in [MIDROW, CHAIN, WPP] {
        let units: Vec<_> = annex_b_nal_units(stream).collect();
        let mut decoder = Decoder::new(DecoderLimits::default())?;
        for unit in &units[..units.len() - 1] {
            assert!(decoder.decode_nal(unit)?.is_none());
            assert!(decoder.next_output().is_none());
        }
        let (mut pictures, errors) = feed(&mut decoder, &units[units.len() - 1..]);
        assert!(errors.is_empty());
        pictures.extend(decoder.finish()?);
        assert_eq!(pictures.len(), 1);

        let mut incomplete = Decoder::new(DecoderLimits::default())?;
        let (pictures, errors) = feed(&mut incomplete, &units[..units.len() - 1]);
        assert!(pictures.is_empty());
        assert!(errors.is_empty());
        assert_eq!(
            incomplete.finish().err(),
            Some(DecodeError::IncompletePicture)
        );
        assert!(incomplete.next_output().is_none());
    }
    Ok(())
}

fn damaged_then_recover(units: &[&[u8]], context: &str) -> Test {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let (pictures, errors) = feed(&mut decoder, units);
    assert!(
        !errors.is_empty(),
        "{context}: damaged continuation was accepted"
    );
    assert!(
        pictures.is_empty(),
        "{context}: partial damaged picture escaped"
    );
    let recovery: Vec<_> = annex_b_nal_units(MIDROW).collect();
    let (mut pictures, errors) = feed(&mut decoder, &recovery);
    assert!(
        errors.is_empty(),
        "{context}: fresh IDR failed to recover: {errors:?}"
    );
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), 1);
    let expected = decode(MIDROW, DecoderLimits::default())?;
    assert_eq!(pictures[0].to_i420(), expected[0].to_i420());
    Ok(())
}

#[test]
fn missing_predecessor_gaps_overlaps_and_reordering_discard_then_recover() -> Test {
    let units: Vec<_> = annex_b_nal_units(CHAIN).collect();
    assert_eq!(units.len(), 6);
    for order in [
        vec![0, 1, 2, 4, 5],
        vec![0, 1, 2, 3, 5],
        vec![0, 1, 2, 3, 4, 4, 5],
        vec![0, 1, 2, 3, 5, 4],
    ] {
        let damaged: Vec<_> = order.into_iter().map(|i| units[i]).collect();
        damaged_then_recover(&damaged, "missing/reordered/overlapping segment")?;
    }
    Ok(())
}

#[test]
fn every_dependent_segment_truncation_is_typed_and_never_publishes_partial_pixels() -> Test {
    for (name, stream) in [("chain", CHAIN), ("qp", QP), ("wpp", WPP)] {
        let units: Vec<_> = annex_b_nal_units(stream).collect();
        for index in 4..units.len() {
            for cut in 0..units[index].len() {
                let mut damaged = units.clone();
                damaged[index] = &units[index][..cut];
                damaged_then_recover(&damaged, &format!("{name} segment {index} cut {cut}"))?;
            }
        }
    }
    Ok(())
}

#[test]
fn every_segment_counts_against_the_picture_budget() -> Test {
    let exact = DecoderLimits {
        max_slices_per_picture: 3,
        ..DecoderLimits::default()
    };
    assert_eq!(decode(CHAIN, exact)?.len(), 1);
    let below = DecoderLimits {
        max_slices_per_picture: 2,
        ..exact
    };
    let mut decoder = Decoder::new(below)?;
    let units: Vec<_> = annex_b_nal_units(CHAIN).collect();
    let (pictures, errors) = feed(&mut decoder, &units);
    assert!(pictures.is_empty());
    assert_eq!(errors, [DecodeError::Limit]);
    let recovery: Vec<_> = annex_b_nal_units(MIDROW).collect();
    let (mut pictures, errors) = feed(&mut decoder, &recovery);
    assert!(errors.is_empty());
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), 1);
    Ok(())
}

#[test]
fn parameter_and_nal_identity_changes_cannot_inherit_stale_segment_state() -> Test {
    let units: Vec<_> = annex_b_nal_units(CHAIN).collect();
    let changed: Vec<_> = annex_b_nal_units(QP).collect();
    for parameter in [1, 2] {
        let mut damaged = units[..4].to_vec();
        damaged.push(changed[parameter]);
        damaged.extend_from_slice(&units[4..]);
        damaged_then_recover(&damaged, "changed parameter set")?;
    }
    // PPS and SPS IDs are both ue(0), so dependent_slice_segments_enabled_flag
    // is bit 5 of the first PPS payload byte. Clearing it redefines how the
    // same continuation bytes are parsed; context fencing must not depend on
    // the dependent flag as reinterpreted under this replacement grammar.
    let mut disabled_dependent = units[2].to_vec();
    assert_ne!(disabled_dependent[2] & 0x20, 0);
    disabled_dependent[2] &= !0x20;
    let mut damaged = units[..5].to_vec();
    damaged.push(&disabled_dependent);
    damaged.push(units[5]);
    damaged_then_recover(&damaged, "PPS disabled dependent-segment grammar")?;

    let mut changed_temporal_id = units[4].to_vec();
    changed_temporal_id[1] = 2;
    let mut damaged = units.clone();
    damaged[4] = &changed_temporal_id;
    damaged_then_recover(&damaged, "changed temporal ID")?;

    // A real subsequent independent segment also belongs to the same picture
    // and cannot change the frozen parameter sets before reconstruction ends.
    let independent: Vec<_> = annex_b_nal_units(RESET).collect();
    let mut damaged = independent[..5].to_vec();
    damaged.push(units[2]); // change cu_qp_delta_enabled while preserving PPS ID
    damaged.extend_from_slice(&independent[5..]);
    damaged_then_recover(&damaged, "independent segment changed parameter set")?;
    Ok(())
}

#[test]
fn byte_identical_parameter_retransmission_preserves_valid_continuation() -> Test {
    let units: Vec<_> = annex_b_nal_units(CHAIN).collect();
    let mut retransmitted = units[..4].to_vec();
    retransmitted.extend_from_slice(&units[1..3]);
    retransmitted.extend_from_slice(&units[4..]);
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let (mut pictures, errors) = feed(&mut decoder, &retransmitted);
    assert!(
        errors.is_empty(),
        "identical parameter sets changed context: {errors:?}"
    );
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), 1);
    assert_eq!(
        pictures[0].to_i420(),
        decode(CHAIN, DecoderLimits::default())?[0].to_i420()
    );
    Ok(())
}

#[test]
fn later_independent_header_cannot_change_picture_wide_irap_flags() -> Test {
    let units: Vec<_> = annex_b_nal_units(RESET).collect();
    let mut changed = units[5].to_vec();
    // first_slice_segment_in_pic_flag=0, then no_output_of_prior_pics_flag.
    assert_eq!(changed[2] & 0x40, 0);
    changed[2] |= 0x40;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let (pictures, errors) = feed(&mut decoder, &units[..5]);
    assert!(pictures.is_empty());
    assert!(errors.is_empty());
    assert_eq!(
        decoder.decode_nal(&changed).err(),
        Some(DecodeError::Malformed)
    );
    assert!(decoder.next_output().is_none());
    let mut damaged = units.clone();
    damaged[5] = &changed;
    damaged_then_recover(
        &damaged,
        "independent header changed picture-wide IRAP flag",
    )?;
    Ok(())
}

#[test]
fn dependent_p_skip_inherits_reference_list_and_adapted_inter_contexts() -> Test {
    let pictures = decode(P_SKIP, DecoderLimits::default())?;
    assert_eq!(pictures.len(), 2);
    let rows: Vec<_> = include_str!("fixtures/decode/dependent_p_skip.sha256")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(rows.len(), 2);
    for (index, (picture, row)) in pictures.iter().zip(&rows).enumerate() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].parse::<usize>()?, index);
        assert_eq!((picture.width(), picture.height()), (48, 16));
        assert_eq!(picture.to_i420().len(), fields[1].parse::<usize>()?);
        assert_eq!(digest(picture), fields[2]);
        assert_eq!(picture.poc(), index as i32);
        assert_eq!(picture.decode_index(), index as u64);
        assert_eq!(picture.is_idr(), index == 0);
    }
    assert_eq!(pictures[0].to_i420(), pictures[1].to_i420());
    let units: Vec<_> = annex_b_nal_units(P_SKIP).collect();
    assert_eq!(units.iter().filter(|unit| unit[0] >> 1 == 1).count(), 3);
    let replay = decode(P_SKIP, DecoderLimits::default())?;
    assert_eq!(pictures[1].to_i420(), replay[1].to_i420());
    Ok(())
}

#[test]
fn missing_p_continuation_preserves_prior_complete_picture_and_recovers() -> Test {
    let units: Vec<_> = annex_b_nal_units(P_SKIP).collect();
    assert_eq!(units.len(), 7);
    let damaged = [units[..5].to_vec(), vec![units[6]]].concat();
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let (pictures, errors) = feed(&mut decoder, &damaged);
    assert_eq!(errors, [DecodeError::IncompletePicture]);
    assert_eq!(
        pictures.len(),
        1,
        "complete IDR must survive failed P continuation"
    );
    assert!(pictures[0].is_idr());
    let recovery: Vec<_> = annex_b_nal_units(MIDROW).collect();
    let (mut recovered, errors) = feed(&mut decoder, &recovery);
    assert!(errors.is_empty());
    recovered.extend(decoder.finish()?);
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].to_i420(),
        decode(MIDROW, DecoderLimits::default())?[0].to_i420()
    );
    Ok(())
}
