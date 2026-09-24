//! Hostile and out-of-profile input: typed errors, never panics, budgets
//! enforced before allocation, and no partially decoded picture published.
//!
//! Streams here are either committed oracle fixtures (truncated or
//! bit-flipped deterministically) or tiny hand-assembled bitstreams written
//! with the syntax tables of H.264 clause 7.3; their expected pixels are
//! hand-computed (DC prediction with no neighbours is 128 everywhere).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fss_codec_h264::rbsp::ebsp_from_rbsp;
use fss_codec_h264::{
    DecodeError, Decoder, DecoderLimits, Picture, UnsupportedFeature, annex_b_nal_units,
};

// ----- tiny bitstream writer -----

#[derive(Default)]
struct W {
    bits: Vec<u8>,
}

impl W {
    fn u(&mut self, n: u32, value: u64) -> &mut Self {
        for shift in (0..n).rev() {
            self.bits.push(u8::try_from((value >> shift) & 1).unwrap());
        }
        self
    }
    fn ue(&mut self, value: u64) -> &mut Self {
        let code = value + 1;
        let len = 64 - code.leading_zeros();
        self.u(len - 1, 0).u(len, code)
    }
    fn se(&mut self, value: i64) -> &mut Self {
        let mapped = if value > 0 { 2 * value - 1 } else { -2 * value };
        self.ue(u64::try_from(mapped).unwrap())
    }
    fn nal(&mut self, header: u8) -> Vec<u8> {
        self.bits.push(1);
        while !self.bits.len().is_multiple_of(8) {
            self.bits.push(0);
        }
        let rbsp: Vec<u8> = self
            .bits
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        let mut out = vec![header];
        out.extend(ebsp_from_rbsp(&rbsp));
        out
    }
}

struct SpsSpec {
    profile: u64,
    high: Option<(u64, u64, bool)>, // chroma_format_idc, bit_depth_minus8, scaling matrix flag
    width_mbs: u64,
    height_mbs: u64,
    poc_type: u64,
    frame_mbs_only: bool,
    max_refs: u64,
    transform_bypass: bool,
}

const TINY: SpsSpec = SpsSpec {
    profile: 66,
    high: None,
    width_mbs: 1,
    height_mbs: 1,
    poc_type: 2,
    frame_mbs_only: true,
    max_refs: 1,
    transform_bypass: false,
};

fn sps(spec: &SpsSpec) -> Vec<u8> {
    let mut w = W::default();
    w.u(8, spec.profile).u(8, 0x40).u(8, 30).ue(0);
    if let Some((chroma, depth, scaling)) = spec.high {
        w.ue(chroma)
            .ue(depth)
            .ue(depth)
            .u(1, u64::from(spec.transform_bypass))
            .u(1, u64::from(scaling));
        if scaling {
            // Eight seq_scaling_list_present_flag = 0 (fall-back lists).
            w.u(8, 0);
        }
    }
    w.ue(0); // log2_max_frame_num_minus4 -> 4-bit frame_num
    w.ue(spec.poc_type);
    match spec.poc_type {
        0 => {
            w.ue(0); // log2_max_pic_order_cnt_lsb_minus4 -> 4 bits
        }
        1 => {
            w.u(1, 1).se(0).se(0).ue(0);
        }
        _ => {}
    }
    w.ue(spec.max_refs)
        .u(1, 0)
        .ue(spec.width_mbs - 1)
        .ue(spec.height_mbs - 1);
    w.u(1, u64::from(spec.frame_mbs_only));
    if !spec.frame_mbs_only {
        w.u(1, 0);
    }
    w.u(1, 1).u(1, 0).u(1, 0);
    w.nal(0x67)
}

#[derive(Clone, Copy, Default)]
struct PpsSpec {
    slice_groups: u64,
    weighted_pred: bool,
    transform_8x8: bool,
}

fn pps(spec: PpsSpec) -> Vec<u8> {
    let mut w = W::default();
    w.ue(0).ue(0).u(1, 0).u(1, 0).ue(spec.slice_groups);
    if spec.slice_groups > 0 {
        w.ue(0); // slice_group_map_type 0
        for _ in 0..=spec.slice_groups {
            w.ue(0); // run_length_minus1
        }
    }
    w.ue(0).ue(0).u(1, u64::from(spec.weighted_pred)).u(2, 0);
    w.se(0).se(0).se(0); // pic_init_qp 26, qs, chroma offset
    w.u(1, 1).u(1, 0).u(1, 0); // deblocking control, constrained intra, redundant
    if spec.transform_8x8 {
        w.u(1, 1).u(1, 0).se(0);
    }
    w.nal(0x68)
}

/// An I slice of `mbs` I_16x16 DC macroblocks with no residual.
/// `poc_lsb` is written only for POC type 0 streams.
fn i_slice(idr: bool, frame_num: u64, first_mb: u64, mbs: u64, poc_lsb: Option<u64>) -> Vec<u8> {
    let mut w = W::default();
    w.ue(first_mb).ue(7).ue(0).u(4, frame_num);
    if idr {
        w.ue(0);
    }
    if let Some(lsb) = poc_lsb {
        w.u(4, lsb);
    }
    if idr {
        w.u(1, 0).u(1, 0);
    } else {
        w.u(1, 0); // adaptive_ref_pic_marking_mode_flag
    }
    w.se(0).ue(0).se(0).se(0); // slice_qp_delta, deblocking idc 0, offsets
    for _ in 0..mbs {
        // I_16x16_2_0_0, chroma DC, mb_qp_delta 0, DC coeff_token "1".
        w.ue(3).ue(0).se(0).u(1, 1);
    }
    w.nal(if idr { 0x65 } else { 0x41 })
}

fn decode_nals(decoder: &mut Decoder, nals: &[Vec<u8>]) -> Result<Vec<Picture>, DecodeError> {
    let mut out = Vec::new();
    for nal in nals {
        if let Some(picture) = decoder.decode_nal(nal)? {
            out.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            out.push(picture);
        }
    }
    Ok(out)
}

/// Decodes every NAL unit and ends the stream, returning all pictures in
/// output order.
fn decode_all(nals: &[Vec<u8>]) -> Result<Vec<Picture>, DecodeError> {
    let mut decoder = fresh();
    let mut out = decode_nals(&mut decoder, nals)?;
    out.extend(decoder.finish()?);
    Ok(out)
}

/// One I_16x16 DC macroblock with no residual (I and P slices alike).
fn intra_dc_macroblock(w: &mut W) {
    // I_16x16_2_0_0, chroma DC, mb_qp_delta 0, luma DC coeff_token "1".
    w.ue(3).ue(0).se(0).u(1, 1);
}

fn assert_flat(picture: &Picture, luma: u8, chroma: u8) {
    assert!(
        picture.luma().iter().all(|&v| v == luma),
        "luma {:?}",
        &picture.luma()[..4]
    );
    assert!(
        picture
            .cb()
            .iter()
            .chain(picture.cr())
            .all(|&v| v == chroma),
        "chroma {:?}",
        &picture.cb()[..4]
    );
}

fn fresh() -> Decoder {
    Decoder::new(DecoderLimits::default()).unwrap()
}

fn unsupported(feature: UnsupportedFeature) -> DecodeError {
    DecodeError::Unsupported(feature)
}

// ----- hand-assembled positive control -----

/// One 16x16 macroblock, I_16x16 DC with no neighbours and no residual:
/// clause 8.3.3.3 gives 128 for every luma sample and 8.3.4.1-3 gives 128
/// for chroma; flat samples are unchanged by deblocking.
#[test]
fn tiny_hand_assembled_stream_decodes_to_mid_grey() {
    let spec = SpsSpec {
        poc_type: 0,
        ..TINY
    };
    let nals = [
        sps(&spec),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 1, Some(0)),
        i_slice(false, 1, 0, 1, Some(2)),
    ];
    // POC type 0 without VUI: the reorder depth is the level's DPB size,
    // so both pictures are held until the stream ends.
    let mut decoder = fresh();
    assert!(decode_nals(&mut decoder, &nals).unwrap().is_empty());
    let pictures = decoder.finish().unwrap();
    assert_eq!(pictures.len(), 2);
    for picture in &pictures {
        assert_eq!((picture.width(), picture.height()), (16, 16));
        assert_flat(picture, 128, 128);
    }
    assert_eq!((pictures[0].poc(), pictures[1].poc()), (0, 2));
}

// ----- unsupported tools: typed refusals -----

/// Tools still outside the admitted set are refused by type even when the
/// rest of the stream is admitted: a High-profile SPS declaring lossless
/// transform bypass, and one declaring 4:2:2.
#[test]
fn remaining_high_profile_refusals_are_typed() {
    let bypass = SpsSpec {
        profile: 100,
        high: Some((1, 0, false)),
        transform_bypass: true,
        ..TINY
    };
    assert_eq!(
        fresh().decode_nal(&sps(&bypass)).unwrap_err(),
        unsupported(UnsupportedFeature::TransformBypass)
    );
    let chroma422 = SpsSpec {
        profile: 100,
        high: Some((2, 0, false)),
        ..TINY
    };
    assert!(matches!(
        fresh().decode_nal(&sps(&chroma422)).unwrap_err(),
        DecodeError::Unsupported(UnsupportedFeature::SampleFormat)
            | DecodeError::Unsupported(UnsupportedFeature::Profile)
    ));
}

#[test]
fn unsupported_sps_features_are_typed() {
    let cases = [
        (
            SpsSpec {
                poc_type: 1,
                ..TINY
            },
            UnsupportedFeature::PocType1,
        ),
        (
            SpsSpec {
                frame_mbs_only: false,
                ..TINY
            },
            UnsupportedFeature::Interlaced,
        ),
        (
            SpsSpec {
                profile: 100,
                high: Some((1, 0, true)),
                ..TINY
            },
            UnsupportedFeature::ScalingMatrix,
        ),
        (
            SpsSpec {
                profile: 100,
                high: Some((2, 0, false)),
                ..TINY
            },
            UnsupportedFeature::SampleFormat,
        ),
        (
            SpsSpec {
                profile: 100,
                high: Some((1, 2, false)),
                ..TINY
            },
            UnsupportedFeature::SampleFormat,
        ),
        (
            SpsSpec {
                profile: 122,
                high: Some((2, 0, false)),
                ..TINY
            },
            UnsupportedFeature::Profile,
        ),
    ];
    for (spec, feature) in cases {
        assert_eq!(
            fresh().decode_nal(&sps(&spec)).unwrap_err(),
            unsupported(feature),
            "{feature:?}"
        );
    }
}

#[test]
fn unsupported_pps_features_are_typed() {
    let mut decoder = fresh();
    decoder
        .decode_nal(&sps(&SpsSpec {
            profile: 100,
            high: Some((1, 0, false)),
            ..TINY
        }))
        .unwrap();
    assert_eq!(
        decoder
            .decode_nal(&pps(PpsSpec {
                transform_8x8: true,
                ..PpsSpec::default()
            }))
            .unwrap_err(),
        unsupported(UnsupportedFeature::Transform8x8)
    );
    assert_eq!(
        decoder
            .decode_nal(&pps(PpsSpec {
                slice_groups: 1,
                ..PpsSpec::default()
            }))
            .unwrap_err(),
        unsupported(UnsupportedFeature::SliceGroups)
    );
}

#[test]
fn unsupported_slice_features_are_typed() {
    let setup = |pps_spec: PpsSpec| {
        let mut decoder = fresh();
        decoder.decode_nal(&sps(&TINY)).unwrap();
        decoder.decode_nal(&pps(pps_spec)).unwrap();
        decoder
    };
    // slice_type 8 = SP.
    let mut sp = W::default();
    let sp_slice = sp.ue(0).ue(8).ue(0).u(4, 0).nal(0x21);
    assert_eq!(
        setup(PpsSpec::default()).decode_nal(&sp_slice).unwrap_err(),
        unsupported(UnsupportedFeature::SwitchingSlice)
    );
    // A B slice (slice_type 6) is admitted syntax now: its header is read,
    // and this one, truncated right after frame_num, is a typed Limit.
    let mut b = W::default();
    let b_slice = b.ue(0).ue(6).ue(0).u(4, 0).nal(0x21);
    assert_eq!(
        setup(PpsSpec::default()).decode_nal(&b_slice).unwrap_err(),
        DecodeError::Limit
    );
    // Data partition A (NAL type 2).
    assert_eq!(
        setup(PpsSpec::default())
            .decode_nal(&[0x22, 0x80])
            .unwrap_err(),
        unsupported(UnsupportedFeature::DataPartitioning)
    );
}

/// Explicit weighted prediction, hand-computed: a grey IDR, then a P
/// picture whose single P_Skip macroblock predicts from it with luma
/// weight 1, offset +10 and luma_log2_weight_denom 0 (equation 8-271 with
/// logWD 0: 128 * 1 + 10 = 138); chroma weights are absent (defaults), so
/// chroma stays 128.
#[test]
fn explicit_weighted_p_skip_is_hand_computed() {
    let mut idr = W::default();
    idr.ue(0).ue(7).ue(0).u(4, 0).ue(0).u(1, 0).u(1, 0);
    idr.se(0).ue(0).se(0).se(0);
    intra_dc_macroblock(&mut idr);
    let mut p = W::default();
    p.ue(0).ue(5).ue(0).u(4, 1); // first_mb, P, pps, frame_num 1
    p.u(1, 0).u(1, 0); // no override, no list modification
    p.ue(0).ue(0); // luma / chroma log2_weight_denom
    p.u(1, 1).se(1).se(10); // luma weight 1, offset 10
    p.u(1, 0); // no chroma weights
    p.u(1, 0); // sliding-window marking
    p.se(0).ue(0).se(0).se(0);
    p.ue(1); // mb_skip_run: the whole picture
    let nals = [
        sps(&TINY),
        pps(PpsSpec {
            weighted_pred: true,
            ..PpsSpec::default()
        }),
        idr.nal(0x65),
        p.nal(0x41),
    ];
    let pictures = decode_all(&nals).unwrap();
    assert_eq!(pictures.len(), 2);
    assert_flat(&pictures[0], 128, 128);
    assert_flat(&pictures[1], 138, 128);
}

/// Long-term references, list modification and MMCO, hand-assembled:
/// the IDR is marked long-term (idx 0); P1 selects it through
/// `modification_of_pic_nums_idc == 2`; P2 unmarks it with MMCO 2; P3's
/// attempt to select long-term picture 0 must then fail as a missing
/// reference. Every decoded picture is P_Skip of the grey IDR (128).
#[test]
fn long_term_modification_and_mmco_are_hand_computed() {
    let spec = SpsSpec {
        max_refs: 2,
        ..TINY
    };
    let mut idr = W::default();
    idr.ue(0).ue(7).ue(0).u(4, 0).ue(0);
    idr.u(1, 0).u(1, 1); // no_output_of_prior_pics, long_term_reference_flag
    idr.se(0).ue(0).se(0).se(0);
    intra_dc_macroblock(&mut idr);
    let p_slice = |frame_num: u64, modification: Option<u64>, mmco2: bool| {
        let mut p = W::default();
        p.ue(0).ue(5).ue(0).u(4, frame_num);
        p.u(1, 1).ue(0); // override: one active reference
        match modification {
            Some(long_term_pic_num) => {
                p.u(1, 1).ue(2).ue(long_term_pic_num).ue(3);
            }
            None => {
                p.u(1, 0);
            }
        }
        if mmco2 {
            p.u(1, 1).ue(2).ue(0).ue(0); // MMCO 2 (long_term_pic_num 0), end
        } else {
            p.u(1, 0);
        }
        p.se(0).ue(0).se(0).se(0);
        p.ue(1);
        p.nal(0x41)
    };
    let nals = [
        sps(&spec),
        pps(PpsSpec::default()),
        idr.nal(0x65),
        p_slice(1, Some(0), false),
        p_slice(2, None, true),
    ];
    let pictures = decode_all(&nals).unwrap();
    assert_eq!(pictures.len(), 3);
    for picture in &pictures {
        assert_flat(picture, 128, 128);
    }
    let mut decoder = fresh();
    decode_nals(&mut decoder, &nals).unwrap();
    assert_eq!(
        decoder.decode_nal(&p_slice(3, Some(0), false)).unwrap_err(),
        DecodeError::MissingReference
    );
    // Without the MMCO the same P3 decodes: the IDR is still long-term.
    let mut decoder = fresh();
    decode_nals(&mut decoder, &nals[..4]).unwrap();
    decode_nals(&mut decoder, &[p_slice(2, None, false)]).unwrap();
    assert!(decode_nals(&mut decoder, &[p_slice(3, Some(0), false)]).is_ok());
}

/// Output reordering, hand-computed: an IDR with POC 4 followed by an I
/// picture with POC 2 (POC type 0, no VUI, so the level's DPB bounds the
/// reorder depth). The later-decoded picture is output first.
#[test]
fn decreasing_poc_is_output_in_poc_order() {
    let spec = SpsSpec {
        poc_type: 0,
        ..TINY
    };
    let nals = [
        sps(&spec),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 1, Some(4)),
        i_slice(false, 1, 0, 1, Some(2)),
    ];
    let pictures = decode_all(&nals).unwrap();
    let order: Vec<(i32, u64)> = pictures
        .iter()
        .map(|p| (p.poc(), p.decode_index()))
        .collect();
    assert_eq!(order, vec![(2, 1), (4, 0)]);
}

// ----- reference / ordering errors -----

#[test]
fn p_slice_without_idr_is_missing_reference() {
    let mut decoder = fresh();
    decoder.decode_nal(&sps(&TINY)).unwrap();
    decoder.decode_nal(&pps(PpsSpec::default())).unwrap();
    // P slice, frame_num 1, no override, no modification, no MMCO,
    // slice_qp_delta 0, deblocking idc 0 + offsets, mb_skip_run 1.
    let mut w = W::default();
    let p = w
        .ue(0)
        .ue(5)
        .ue(0)
        .u(4, 1)
        .u(1, 0)
        .u(1, 0)
        .u(1, 0)
        .se(0)
        .ue(0)
        .se(0)
        .se(0)
        .ue(1)
        .nal(0x41);
    assert_eq!(
        decoder.decode_nal(&p).unwrap_err(),
        DecodeError::MissingReference
    );
}

#[test]
fn frame_num_gap_is_typed() {
    let nals = [
        sps(&TINY),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 1, None),
        i_slice(false, 3, 0, 1, None),
    ];
    assert_eq!(
        decode_nals(&mut fresh(), &nals).unwrap_err(),
        DecodeError::FrameNumGap
    );
}

#[test]
fn missing_and_misordered_slices_are_typed() {
    let wide = SpsSpec {
        width_mbs: 3,
        ..TINY
    };
    // Only MB 0 of 3, then flush.
    let mut decoder = fresh();
    decode_nals(
        &mut decoder,
        &[
            sps(&wide),
            pps(PpsSpec::default()),
            i_slice(true, 0, 0, 1, None),
        ],
    )
    .unwrap();
    assert_eq!(
        decoder.finish().unwrap_err(),
        DecodeError::IncompletePicture
    );
    // Only MB 0 of 3, then a new picture starts.
    let nals = [
        sps(&wide),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 1, None),
        i_slice(true, 0, 0, 3, None),
    ];
    assert_eq!(
        decode_nals(&mut fresh(), &nals).unwrap_err(),
        DecodeError::IncompletePicture
    );
    // Slice starting at MB 2 while MB 1 is missing (ASO or loss).
    let nals = [
        sps(&wide),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 1, None),
        i_slice(true, 0, 2, 1, None),
    ];
    assert_eq!(
        decode_nals(&mut fresh(), &nals).unwrap_err(),
        unsupported(UnsupportedFeature::ArbitrarySliceOrder)
    );
    // Overlapping slices: MBs 0-1, then a slice restarting at MB 1.
    let nals = [
        sps(&wide),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 2, None),
        i_slice(true, 0, 1, 1, None),
    ];
    assert_eq!(
        decode_nals(&mut fresh(), &nals).unwrap_err(),
        DecodeError::Malformed
    );
    // A slice before any picture start with first_mb != 0.
    let nals = [
        sps(&wide),
        pps(PpsSpec::default()),
        i_slice(true, 0, 1, 2, None),
    ];
    assert_eq!(
        decode_nals(&mut fresh(), &nals).unwrap_err(),
        unsupported(UnsupportedFeature::ArbitrarySliceOrder)
    );
    // A slice with more macroblocks than the picture has.
    let nals = [
        sps(&wide),
        pps(PpsSpec::default()),
        i_slice(true, 0, 0, 4, None),
    ];
    assert_eq!(
        decode_nals(&mut fresh(), &nals).unwrap_err(),
        DecodeError::Malformed
    );
}

#[test]
fn slice_without_parameter_sets_is_typed() {
    assert_eq!(
        fresh()
            .decode_nal(&i_slice(true, 0, 0, 1, None))
            .unwrap_err(),
        DecodeError::MissingParameterSet
    );
}

// ----- budgets, enforced before allocation -----

#[test]
fn absurd_sps_dimensions_are_limit() {
    let huge = SpsSpec {
        width_mbs: 1_024,
        height_mbs: 1_024,
        ..TINY
    };
    assert_eq!(
        fresh().decode_nal(&sps(&huge)).unwrap_err(),
        DecodeError::Limit
    );
    // Beyond the syntax ceiling entirely.
    let absurd = SpsSpec {
        width_mbs: 1 << 20,
        height_mbs: 1 << 20,
        ..TINY
    };
    assert!(matches!(
        fresh().decode_nal(&sps(&absurd)).unwrap_err(),
        DecodeError::Limit | DecodeError::Malformed
    ));
}

#[test]
fn owner_limits_are_enforced() {
    let qcif = include_bytes!("fixtures/decode/ip_qcif_nodeblock.h264");
    let run = |limits: DecoderLimits, stream: &[u8]| -> (usize, Result<(), DecodeError>) {
        let mut decoder = Decoder::new(limits).unwrap();
        let mut count = 0;
        for nal in annex_b_nal_units(stream) {
            match decoder.decode_nal(nal) {
                Ok(Some(_)) => count += 1,
                Ok(None) => {}
                Err(err) => return (count, Err(err)),
            }
        }
        (count, Ok(()))
    };
    let base = DecoderLimits::default();
    assert_eq!(
        run(
            DecoderLimits {
                max_width: 160,
                ..base
            },
            qcif
        ),
        (0, Err(DecodeError::Limit))
    );
    assert_eq!(
        run(
            DecoderLimits {
                max_height: 128,
                ..base
            },
            qcif
        ),
        (0, Err(DecodeError::Limit))
    );
    assert_eq!(
        run(
            DecoderLimits {
                max_macroblocks: 98,
                ..base
            },
            qcif
        ),
        (0, Err(DecodeError::Limit))
    );
    assert_eq!(
        run(
            DecoderLimits {
                max_pictures: 2,
                ..base
            },
            qcif
        ),
        (2, Err(DecodeError::Limit))
    );
    assert_eq!(
        run(
            DecoderLimits {
                max_nal_bytes: 64,
                ..base
            },
            qcif
        ),
        (0, Err(DecodeError::Limit))
    );
    let slices = include_bytes!("fixtures/decode/ip_qcif_slices3.h264");
    assert_eq!(
        run(
            DecoderLimits {
                max_slices_per_picture: 2,
                ..base
            },
            slices
        ),
        (0, Err(DecodeError::Limit))
    );
    assert_eq!(
        run(
            DecoderLimits {
                max_slices_per_picture: 3,
                ..base
            },
            slices
        ),
        (4, Ok(()))
    );
    assert_eq!(run(base, qcif), (4, Ok(())));
    // Invalid owner policy is refused up front.
    assert_eq!(
        Decoder::new(DecoderLimits {
            max_width: 0,
            ..base
        })
        .unwrap_err(),
        DecodeError::Limit
    );
    assert_eq!(
        Decoder::new(DecoderLimits {
            max_pictures: 0,
            ..base
        })
        .unwrap_err(),
        DecodeError::Limit
    );
    assert_eq!(
        Decoder::new(DecoderLimits {
            max_reference_frames: 17,
            ..base
        })
        .unwrap_err(),
        DecodeError::Limit
    );
}

// ----- truncation and mutation sweeps -----

fn decode_lossy(stream: &[u8]) -> (Vec<Picture>, usize) {
    // Keep feeding after errors, exercising the wait-for-IDR recovery.
    let mut decoder = fresh();
    let mut pictures = Vec::new();
    let mut errors = 0;
    for nal in annex_b_nal_units(stream) {
        match decoder.decode_nal(nal) {
            Ok(Some(picture)) => pictures.push(picture),
            Ok(None) => {}
            Err(_) => errors += 1,
        }
        while let Some(picture) = decoder.next_output() {
            pictures.push(picture);
        }
    }
    match decoder.finish() {
        Ok(rest) => pictures.extend(rest),
        Err(_) => {
            errors += 1;
            while let Some(picture) = decoder.next_output() {
                pictures.push(picture);
            }
        }
    }
    (pictures, errors)
}

/// Every prefix of a stream decodes to a bit-identical prefix of the full
/// decode: a truncated picture is refused, never published partially.
#[test]
fn truncated_streams_yield_exact_picture_prefixes() {
    let fixtures: [&[u8]; 4] = [
        include_bytes!("fixtures/decode/ip_100x60_crop.h264"),
        include_bytes!("fixtures/decode/pcm_mixed.h264"),
        include_bytes!("fixtures/baseline_i64.h264"),
        include_bytes!("fixtures/decode/m_ip_cabac_qp40.h264"),
    ];
    for stream in fixtures {
        let (full, errors) = decode_lossy(stream);
        assert_eq!(errors, 0);
        let mut saw_error = false;
        for cut in (1..stream.len()).step_by(7) {
            let (pictures, errors) = decode_lossy(&stream[..cut]);
            saw_error |= errors > 0;
            assert!(pictures.len() <= full.len());
            for (ours, reference) in pictures.iter().zip(&full) {
                assert!(
                    ours == reference,
                    "cut {cut}: picture differs from full decode"
                );
            }
        }
        assert!(saw_error, "truncation must surface errors");
    }
}

/// Truncated reordering streams (CABAC B with POC wrap, temporal direct
/// with implicit weights): every published picture is bit-identical to the
/// full decode's picture with the same decode index, and pictures still
/// come out in increasing POC order. (Output is not a prefix: a truncated
/// stream flushes pictures the full decode would interleave with later B
/// pictures.)
#[test]
fn truncated_reordering_streams_publish_only_exact_pictures() {
    let fixtures: [&[u8]; 2] = [
        include_bytes!("fixtures/decode/m_b_pocwrap_64x48.h264"),
        include_bytes!("fixtures/decode/m_b_implicit_weight.h264"),
    ];
    for stream in fixtures {
        let (full, errors) = decode_lossy(stream);
        assert_eq!(errors, 0);
        let mut saw_error = false;
        for cut in (1..stream.len()).step_by(29) {
            let (pictures, errors) = decode_lossy(&stream[..cut]);
            saw_error |= errors > 0;
            for picture in &pictures {
                let reference = full
                    .iter()
                    .find(|p| p.decode_index() == picture.decode_index())
                    .unwrap_or_else(|| panic!("cut {cut}: unknown picture"));
                assert!(
                    picture == reference,
                    "cut {cut}: picture differs from full decode"
                );
            }
            for pair in pictures.windows(2) {
                if !pair[1].is_idr() {
                    assert!(pair[0].poc() < pair[1].poc(), "cut {cut}: output order");
                }
            }
        }
        assert!(saw_error, "truncation must surface errors");
    }
}

/// Deterministic bit-flip fuzzing over fixture bytes. Any outcome is
/// acceptable except a panic (the test harness would report it); every
/// published picture must still have self-consistent plane sizes.
#[test]
fn bit_flip_mutations_never_panic() {
    // Baseline CAVLC, CABAC I/P with weights, CABAC B (implicit weights,
    // temporal direct, MMCO, POC wrap): every new syntax path is exposed
    // to flips.
    let fixtures: [&[u8]; 8] = [
        include_bytes!("fixtures/decode/ip_100x60_crop.h264"),
        include_bytes!("fixtures/decode/pcm_mixed.h264"),
        include_bytes!("fixtures/decode/i_qcif_qp44.h264"),
        include_bytes!("fixtures/baseline_i64.h264"),
        include_bytes!("fixtures/decode/m_ip_cabac_qp40.h264"),
        include_bytes!("fixtures/decode/m_ip_cabac_weightp.h264"),
        include_bytes!("fixtures/decode/m_b_pocwrap_64x48.h264"),
        include_bytes!("fixtures/decode/m_b_implicit_weight.h264"),
    ];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut refused = 0usize;
    for round in 0..900usize {
        let stream = fixtures[round % fixtures.len()];
        let mut bytes = stream.to_vec();
        let flips = 1 + (next() % 4) as usize;
        for _ in 0..flips {
            // Half the rounds target the first 48 bytes (parameter sets and
            // slice headers), the rest anywhere.
            let span = if round.is_multiple_of(2) {
                bytes.len().min(48)
            } else {
                bytes.len()
            };
            let position = (next() as usize) % span;
            bytes[position] ^= 1 << (next() % 8);
        }
        let (pictures, errors) = decode_lossy(&bytes);
        refused += errors;
        for picture in &pictures {
            let luma = (picture.width() * picture.height()) as usize;
            let chroma = (picture.chroma_width() * picture.chroma_height()) as usize;
            assert_eq!(picture.luma().len(), luma);
            assert_eq!(picture.cb().len(), chroma);
            assert_eq!(picture.cr().len(), chroma);
        }
    }
    assert!(refused > 0, "mutations must be detected at least sometimes");
}

/// After a refused picture the decoder waits for the next IDR: a garbage
/// slice injected before a clean stream costs exactly that error, and the
/// clean stream then decodes identically.
#[test]
fn recovery_after_error_waits_for_idr() {
    let stream = include_bytes!("fixtures/decode/ip_100x60_crop.h264");
    let clean = fresh().decode_annex_b(stream).unwrap();
    let mut decoder = fresh();
    let nals: Vec<&[u8]> = annex_b_nal_units(stream).collect();
    // SPS + PPS first, then a corrupt slice (valid header byte, junk body).
    let mut pictures = Vec::new();
    for nal in &nals[..2] {
        assert!(decoder.decode_nal(nal).unwrap().is_none());
    }
    assert!(decoder.decode_nal(&[0x65, 0xFF, 0xFF, 0xFF]).is_err());
    for nal in &nals {
        if let Some(picture) = decoder.decode_nal(nal).unwrap() {
            pictures.push(picture);
        }
    }
    assert_eq!(pictures.len(), clean.len());
    for (a, b) in pictures.iter().zip(&clean) {
        assert_eq!(a.to_i420(), b.to_i420());
    }
}

#[test]
fn annex_b_splitter_handles_framing_edge_cases() {
    let stream = [
        0x00, 0x00, 0x00, 0x01, 0x67, 0xAA, 0x00, 0x00, 0x01, 0x68, 0xBB, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x65, 0xCC, 0x00,
    ];
    let units: Vec<&[u8]> = annex_b_nal_units(&stream).collect();
    assert_eq!(
        units,
        vec![&[0x67, 0xAA][..], &[0x68, 0xBB][..], &[0x65, 0xCC][..]]
    );
    assert_eq!(annex_b_nal_units(&[0x12, 0x34]).count(), 0);
    assert_eq!(annex_b_nal_units(&[]).count(), 0);
}
