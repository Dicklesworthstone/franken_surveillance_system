#![forbid(unsafe_code)]
//! Parameter-set, picture-identity, exact-binding, and hostile-input contracts.

use fss_packet::avc::{
    AvcError, AvcSyntaxLimits, AvcSliceType, PocMode, parse_pps, parse_slice_identity, parse_sps,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Writer(Vec<bool>);

impl Writer {
    fn bit(&mut self, value: bool) { self.0.push(value); }
    fn uint(&mut self, value: u32, width: u8) {
        for shift in (0..width).rev() { self.bit((value >> shift) & 1 != 0); }
    }
    fn ue(&mut self, value: u32) {
        let code = u64::from(value) + 1;
        let width = 64 - code.leading_zeros();
        for _ in 1..width { self.bit(false); }
        for shift in (0..width).rev() { self.bit((code >> shift) & 1 != 0); }
    }
    fn se(&mut self, value: i32) {
        self.ue(if value > 0 { value as u32 * 2 - 1 } else { (-i64::from(value) * 2) as u32 });
    }
    fn nal(mut self, header: u8) -> Vec<u8> {
        self.bit(true);
        while self.0.len() % 8 != 0 { self.bit(false); }
        let mut wire = vec![header];
        let mut zeros = 0;
        for chunk in self.0.chunks_exact(8) {
            let byte = chunk.iter().fold(0_u8, |v, b| (v << 1) | u8::from(*b));
            if zeros == 2 && byte <= 3 { wire.push(3); zeros = 0; }
            wire.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        wire
    }
}

#[derive(Clone)]
struct SpsFixture {
    profile: u8,
    id: u32,
    poc: u32,
    always_zero: bool,
    cycle: u32,
    frame_only: bool,
    mbaff: bool,
    width_mbs: u32,
    height_units: u32,
    crop: Option<[u32; 4]>,
    scaling: bool,
    depth: u32,
    chroma: u32,
    timing: Option<(u32, u32)>,
    hrd_count: Option<u32>,
}

impl Default for SpsFixture {
    fn default() -> Self {
        Self {
            profile: 66, id: 0, poc: 0, always_zero: false, cycle: 0,
            frame_only: true, mbaff: false, width_mbs: 10, height_units: 8,
            crop: None, scaling: false, depth: 0, chroma: 1,
            timing: None, hrd_count: None,
        }
    }
}

impl SpsFixture {
    fn nal(&self) -> Vec<u8> {
        let mut b = Writer::default();
        b.uint(u32::from(self.profile), 8);
        b.uint(0, 8);
        b.uint(31, 8);
        b.ue(self.id);
        if self.profile == 100 {
            b.ue(self.chroma);
            b.ue(self.depth);
            b.ue(self.depth);
            b.bit(false);
            b.bit(self.scaling);
            if self.scaling {
                for index in 0..8 {
                    b.bit(index == 0 || index == 6);
                    if index == 0 { for _ in 0..16 { b.se(0); } }
                    // nextScale=0 selects the default list and consumes no more deltas.
                    if index == 6 { b.se(-8); }
                }
            }
        }
        b.ue(0); // four-bit frame number
        b.ue(self.poc);
        if self.poc == 0 { b.ue(0); }
        if self.poc == 1 {
            b.bit(self.always_zero);
            b.se(-1);
            b.se(1);
            b.ue(self.cycle);
            for i in 0..self.cycle { b.se((i % 3) as i32 - 1); }
        }
        b.ue(1);
        b.bit(false);
        b.ue(self.width_mbs - 1);
        b.ue(self.height_units - 1);
        b.bit(self.frame_only);
        if !self.frame_only { b.bit(self.mbaff); }
        b.bit(true);
        b.bit(self.crop.is_some());
        if let Some(crop) = self.crop { for offset in crop { b.ue(offset); } }
        let vui = self.timing.is_some() || self.hrd_count.is_some();
        b.bit(vui);
        if vui {
            for _ in 0..4 { b.bit(false); }
            b.bit(self.timing.is_some());
            if let Some((ticks, scale)) = self.timing {
                b.uint(ticks, 32); b.uint(scale, 32); b.bit(true);
            }
            b.bit(self.hrd_count.is_some());
            if let Some(count) = self.hrd_count {
                b.ue(count - 1);
                b.uint(0, 4); b.uint(0, 4);
                for _ in 0..count { b.ue(0); b.ue(0); b.bit(false); }
                for _ in 0..4 { b.uint(23, 5); }
            }
            b.bit(false); // no VCL HRD
            if self.hrd_count.is_some() { b.bit(false); }
            b.bit(false); // pic_struct_present_flag
            b.bit(false); // bitstream_restriction_flag
        }
        b.nal(0x67)
    }
}

#[derive(Clone, Default)]
struct PpsFixture {
    id: u32,
    sps_id: u32,
    bottom_poc: bool,
    redundant: bool,
    groups: u32,
    extension: bool,
}

impl PpsFixture {
    fn nal(&self) -> Vec<u8> {
        let mut b = Writer::default();
        b.ue(self.id); b.ue(self.sps_id);
        b.bit(false); b.bit(self.bottom_poc); b.ue(self.groups);
        b.ue(0); b.ue(0); b.bit(false); b.uint(0, 2);
        b.se(0); b.se(0); b.se(0); b.bit(false); b.bit(false); b.bit(self.redundant);
        if self.extension {
            b.bit(true); b.bit(true);
            for i in 0..8 { b.bit(i == 7); if i == 7 { b.se(-8); } }
            b.se(-2);
        }
        b.nal(0x68)
    }
}

#[derive(Clone)]
struct SliceFixture {
    header: u8,
    first_mb: u32,
    kind: u32,
    pps: u32,
    frame: u32,
    field: bool,
    bottom: bool,
    idr_id: u32,
    poc_lsb: u32,
    delta: [i32; 2],
    redundant: u32,
}

impl Default for SliceFixture {
    fn default() -> Self {
        Self { header: 0x41, first_mb: 0, kind: 0, pps: 0, frame: 1, field: false,
            bottom: false, idr_id: 0, poc_lsb: 2, delta: [0; 2], redundant: 0 }
    }
}

impl SliceFixture {
    fn nal(&self, sps: &SpsFixture, pps: &PpsFixture) -> Vec<u8> {
        let mut b = Writer::default();
        b.ue(self.first_mb); b.ue(self.kind); b.ue(self.pps); b.uint(self.frame, 4);
        if !sps.frame_only { b.bit(self.field); if self.field { b.bit(self.bottom); } }
        if self.header & 31 == 5 { b.ue(self.idr_id); }
        if sps.poc == 0 {
            b.uint(self.poc_lsb, 4);
            if pps.bottom_poc && !self.field { b.se(self.delta[1]); }
        }
        if sps.poc == 1 && !sps.always_zero {
            b.se(self.delta[0]);
            if pps.bottom_poc && !self.field { b.se(self.delta[1]); }
        }
        if pps.redundant { b.ue(self.redundant); }
        // Deliberately not a full slice: only the identity prefix is under test.
        b.nal(self.header)
    }
}

#[test]
fn baseline_parameter_sets_keep_exact_original_bytes() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    let s = SpsFixture::default().nal();
    let p = PpsFixture::default().nal();
    let sps = parse_sps(&s, limits)?;
    let pps = parse_pps(&p, &sps, limits)?;
    assert_eq!(sps.coded_dimensions(), (160, 128));
    assert_eq!(sps.display_dimensions(), (160, 128));
    assert_eq!(sps.frame_num_bits(), 4);
    assert_eq!(sps.poc_mode(), PocMode::Lsb { bits: 4 });
    assert_eq!(sps.nal_bytes(), s);
    assert_eq!(pps.nal_bytes(), p);
    assert!(!pps.entropy_coding_mode());
    Ok(())
}

#[test]
fn high_scaling_lists_and_pps_extension_are_consumed() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    let sps = parse_sps(&SpsFixture { profile: 100, scaling: true, ..SpsFixture::default() }.nal(), limits)?;
    let pps = parse_pps(&PpsFixture { extension: true, ..PpsFixture::default() }.nal(), &sps, limits)?;
    assert_eq!(sps.profile_idc(), 100);
    assert!(pps.transform_8x8_mode());
    assert_eq!(sps.coded_dimensions(), (160, 128));
    Ok(())
}

#[test]
fn crop_units_include_field_factor_and_preserve_origin() -> TestResult {
    for frame_only in [true, false] {
        let sps = parse_sps(&SpsFixture { frame_only, crop: Some([1, 2, 3, 4]), ..SpsFixture::default() }.nal(), AvcSyntaxLimits::default())?;
        let factor = if frame_only { 1 } else { 2 };
        assert_eq!(sps.coded_dimensions(), (160, 128 * factor));
        assert_eq!(sps.display_dimensions(), (154, 114 * factor));
        assert_eq!(sps.crop_origin(), (2, 6 * factor));
    }
    Ok(())
}

#[test]
fn impossible_crops_and_uncropped_resource_excess_are_refused() {
    let large_crop = SpsFixture { crop: Some([80, 0, 0, 0]), ..SpsFixture::default() };
    assert_eq!(parse_sps(&large_crop.nal(), AvcSyntaxLimits::default()), Err(AvcError::Malformed));
    let cropped = SpsFixture { crop: Some([0, 70, 0, 50]), ..SpsFixture::default() };
    assert_eq!(parse_sps(&cropped.nal(), AvcSyntaxLimits { max_luma_samples: 1_000, ..AvcSyntaxLimits::default() }), Err(AvcError::Limit));
}

#[test]
fn timing_and_maximal_hrd_are_bounded_and_not_capture_time() -> TestResult {
    let fixture = SpsFixture { timing: Some((1_001, 60_000)), hrd_count: Some(32), ..SpsFixture::default() };
    let sps = parse_sps(&fixture.nal(), AvcSyntaxLimits::default())?;
    let timing = sps.timing().ok_or("missing signalled timing")?;
    assert_eq!((timing.num_units_in_tick, timing.time_scale), (1_001, 60_000));
    assert!(timing.fixed_frame_rate);
    assert_eq!(parse_sps(&SpsFixture { hrd_count: Some(33), ..fixture }.nal(), AvcSyntaxLimits::default()), Err(AvcError::Limit));
    Ok(())
}

#[test]
fn zero_timing_and_invalid_emulation_prevention_fail() {
    let zero = SpsFixture { timing: Some((0, 60_000)), ..SpsFixture::default() }.nal();
    assert_eq!(parse_sps(&zero, AvcSyntaxLimits::default()), Err(AvcError::Malformed));
    let escaped = SpsFixture { timing: Some((1, 60_000)), ..SpsFixture::default() }.nal();
    let unescaped: Vec<u8> = escaped.iter().enumerate().filter_map(|(i, b)| {
        if i >= 2 && escaped[i - 2..i] == [0, 0] && *b == 3 { None } else { Some(*b) }
    }).collect();
    assert!(parse_sps(&unescaped, AvcSyntaxLimits::default()).is_err());
}

#[test]
fn every_parameter_set_byte_truncation_fails() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    let bytes = SpsFixture { timing: Some((1, 50)), hrd_count: Some(2), ..SpsFixture::default() }.nal();
    for end in 0..bytes.len() { assert!(parse_sps(&bytes[..end], limits).is_err(), "SPS prefix {end}"); }
    let sps = parse_sps(&bytes, limits)?;
    let pps = PpsFixture::default().nal();
    for end in 0..pps.len() { assert!(parse_pps(&pps[..end], &sps, limits).is_err(), "PPS prefix {end}"); }
    Ok(())
}

#[test]
fn parameter_suffixes_reserved_bits_and_forbidden_bit_are_not_ignored() {
    let limits = AvcSyntaxLimits::default();
    let bytes = SpsFixture::default().nal();
    let mut suffix = bytes.clone(); suffix.push(0);
    assert_eq!(parse_sps(&suffix, limits), Err(AvcError::Malformed));
    let mut reserved = bytes.clone(); reserved[2] |= 1;
    assert_eq!(parse_sps(&reserved, limits), Err(AvcError::Malformed));
    let mut forbidden = bytes.clone(); forbidden[0] |= 0x80;
    assert_eq!(parse_sps(&forbidden, limits), Err(AvcError::Corrupt));
    let mut nonref = bytes; nonref[0] = 7;
    assert_eq!(parse_sps(&nonref, limits), Err(AvcError::Malformed));
}

#[test]
fn unsupported_profile_sample_formats_and_slice_groups_fail_explicitly() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    assert_eq!(parse_sps(&SpsFixture { profile: 110, ..SpsFixture::default() }.nal(), limits), Err(AvcError::UnsupportedProfile));
    for (chroma, depth) in [(0, 0), (2, 0), (3, 0), (1, 2)] {
        assert_eq!(parse_sps(&SpsFixture { profile: 100, chroma, depth, ..SpsFixture::default() }.nal(), limits), Err(AvcError::UnsupportedSampleFormat));
    }
    let sps = parse_sps(&SpsFixture::default().nal(), limits)?;
    assert_eq!(parse_pps(&PpsFixture { groups: 1, ..PpsFixture::default() }.nal(), &sps, limits), Err(AvcError::UnsupportedSliceGroups));
    Ok(())
}

#[test]
fn parameter_ids_and_poc_cycles_have_hard_limits() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    assert_eq!(parse_sps(&SpsFixture { id: 32, ..SpsFixture::default() }.nal(), limits), Err(AvcError::Limit));
    let fixture = SpsFixture { poc: 1, cycle: 255, ..SpsFixture::default() };
    let sps = parse_sps(&fixture.nal(), limits)?;
    assert_eq!(sps.poc_mode(), PocMode::Delta { always_zero: false });
    assert_eq!(parse_sps(&SpsFixture { cycle: 256, ..fixture }.nal(), limits), Err(AvcError::Limit));
    assert_eq!(parse_pps(&PpsFixture { id: 256, ..PpsFixture::default() }.nal(), &sps, limits), Err(AvcError::Limit));
    Ok(())
}

#[test]
fn same_numeric_sps_id_cannot_rebind_existing_pps() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let a = parse_sps(&sf.nal(), limits)?;
    let b = parse_sps(&SpsFixture { width_mbs: 20, ..sf.clone() }.nal(), limits)?;
    let pps = parse_pps(&pf.nal(), &a, limits)?;
    let slice = SliceFixture::default().nal(&sf, &pf);
    assert_eq!(parse_slice_identity(&slice, &b, &pps, limits), Err(AvcError::ParameterSetMismatch));
    // An independently reconstructed byte-identical SPS is the same binding.
    let reconstructed = parse_sps(&sf.nal(), limits)?;
    assert!(parse_slice_identity(&slice, &reconstructed, &pps, limits).is_ok());
    Ok(())
}

#[test]
fn mismatched_pps_sps_and_slice_ids_fail_closed() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let sps = parse_sps(&sf.nal(), limits)?;
    assert_eq!(parse_pps(&PpsFixture { sps_id: 1, ..pf.clone() }.nal(), &sps, limits), Err(AvcError::ParameterSetMismatch));
    let pps = parse_pps(&pf.nal(), &sps, limits)?;
    assert_eq!(parse_slice_identity(&SliceFixture { pps: 1, ..SliceFixture::default() }.nal(&sf, &pf), &sps, &pps, limits), Err(AvcError::ParameterSetMismatch));
    Ok(())
}

#[test]
fn a_zero_first_macroblock_is_not_a_new_picture_by_itself() -> TestResult {
    let limits = AvcSyntaxLimits::default();
    let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let sps = parse_sps(&sf.nal(), limits)?; let pps = parse_pps(&pf.nal(), &sps, limits)?;
    let parse = |v: SliceFixture| parse_slice_identity(&v.nal(&sf, &pf), &sps, &pps, limits);
    let middle = parse(SliceFixture { first_mb: 20, ..SliceFixture::default() })?;
    let zero = parse(SliceFixture::default())?;
    assert!(!zero.starts_new_picture(middle));
    let next = parse(SliceFixture { first_mb: 20, frame: 2, ..SliceFixture::default() })?;
    assert!(next.starts_new_picture(middle));
    Ok(())
}

#[test]
fn reference_zero_distinction_not_nri_rank_changes_picture_identity() -> TestResult {
    let l = AvcSyntaxLimits::default(); let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    let parse = |header| parse_slice_identity(&SliceFixture { header, ..SliceFixture::default() }.nal(&sf, &pf), &s, &p, l);
    let a = parse(0x21)?; let b = parse(0x61)?; let nonref = parse(0x01)?;
    assert!(!a.starts_new_picture(b));
    assert!(nonref.starts_new_picture(a));
    Ok(())
}

#[test]
fn non_idr_intra_is_not_idr_and_idr_identifier_changes_are_boundaries() -> TestResult {
    let l = AvcSyntaxLimits::default(); let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    let fixture = SliceFixture { frame: 0, kind: 2, poc_lsb: 0, ..SliceFixture::default() };
    let intra = parse_slice_identity(&fixture.nal(&sf, &pf), &s, &p, l)?;
    let a = parse_slice_identity(&SliceFixture { header: 0x65, ..fixture.clone() }.nal(&sf, &pf), &s, &p, l)?;
    let b = parse_slice_identity(&SliceFixture { header: 0x65, idr_id: 1, ..fixture }.nal(&sf, &pf), &s, &p, l)?;
    assert_eq!(intra.slice_type(), AvcSliceType::I);
    assert_eq!(intra.idr_pic_id(), None);
    assert!(a.starts_new_picture(intra));
    assert!(a.starts_new_picture(b));
    Ok(())
}

#[test]
fn poc_lsb_and_each_delta_field_detect_picture_boundaries() -> TestResult {
    for poc in 0..=2 {
        let l = AvcSyntaxLimits::default();
        let sf = SpsFixture { poc, ..SpsFixture::default() };
        let pf = PpsFixture { bottom_poc: true, ..PpsFixture::default() };
        let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
        let parse = |v: SliceFixture| parse_slice_identity(&v.nal(&sf, &pf), &s, &p, l);
        let baseline = parse(SliceFixture::default())?;
        let lsb = parse(SliceFixture { poc_lsb: 3, ..SliceFixture::default() })?;
        let d0 = parse(SliceFixture { delta: [1, 0], ..SliceFixture::default() })?;
        let d1 = parse(SliceFixture { delta: [0, -1], ..SliceFixture::default() })?;
        assert_eq!(lsb.starts_new_picture(baseline), poc == 0);
        assert_eq!(d0.starts_new_picture(baseline), poc == 1);
        assert_eq!(d1.starts_new_picture(baseline), poc <= 1);
    }
    Ok(())
}

#[test]
fn field_and_bottom_field_flags_have_distinct_picture_identities() -> TestResult {
    let l = AvcSyntaxLimits::default();
    let sf = SpsFixture { frame_only: false, ..SpsFixture::default() }; let pf = PpsFixture::default();
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    let parse = |field, bottom| parse_slice_identity(&SliceFixture { field, bottom, ..SliceFixture::default() }.nal(&sf, &pf), &s, &p, l);
    let frame = parse(false, false)?; let top = parse(true, false)?; let bottom = parse(true, true)?;
    assert!(top.starts_new_picture(frame));
    assert!(bottom.starts_new_picture(top));
    assert!(bottom.bottom_field());
    Ok(())
}

#[test]
fn first_macroblock_bound_accounts_for_mbaff_and_fields() -> TestResult {
    let l = AvcSyntaxLimits::default();
    let sf = SpsFixture { frame_only: false, mbaff: true, ..SpsFixture::default() }; let pf = PpsFixture::default();
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    for field in [true, false] {
        let last = SliceFixture { first_mb: 79, field, ..SliceFixture::default() };
        assert!(parse_slice_identity(&last.nal(&sf, &pf), &s, &p, l).is_ok());
        assert_eq!(parse_slice_identity(&SliceFixture { first_mb: 80, ..last }.nal(&sf, &pf), &s, &p, l), Err(AvcError::Malformed));
    }
    Ok(())
}

#[test]
fn redundant_picture_count_is_preserved_without_becoming_primary() -> TestResult {
    let l = AvcSyntaxLimits::default(); let sf = SpsFixture::default();
    let pf = PpsFixture { redundant: true, ..PpsFixture::default() };
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    let parsed = parse_slice_identity(&SliceFixture { redundant: 7, ..SliceFixture::default() }.nal(&sf, &pf), &s, &p, l)?;
    assert_eq!(parsed.redundant_pic_cnt(), 7);
    Ok(())
}

#[test]
fn tighter_use_time_limits_cannot_be_bypassed_by_preparsed_parameters() -> TestResult {
    let l = AvcSyntaxLimits::default(); let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    let slice = SliceFixture::default().nal(&sf, &pf);
    for reduced in [
        AvcSyntaxLimits { max_width: 159, ..l },
        AvcSyntaxLimits { max_height: 127, ..l },
        AvcSyntaxLimits { max_luma_samples: 1, ..l },
        AvcSyntaxLimits { max_reference_frames: 0, ..l },
        AvcSyntaxLimits { max_parameter_set_bytes: 2, ..l },
        AvcSyntaxLimits { max_slice_identity_bits: 1, ..l },
    ] {
        assert_eq!(parse_slice_identity(&slice, &s, &p, reduced), Err(AvcError::Limit));
    }
    Ok(())
}

#[test]
fn invalid_idr_partitioned_and_unsupported_slice_types_fail() -> TestResult {
    let l = AvcSyntaxLimits::default(); let sf = SpsFixture::default(); let pf = PpsFixture::default();
    let s = parse_sps(&sf.nal(), l)?; let p = parse_pps(&pf.nal(), &s, l)?;
    for header in [2, 3, 4, 19, 20, 21] {
        assert_eq!(parse_slice_identity(&[header, 0xff], &s, &p, l), Err(AvcError::UnsupportedPicture));
    }
    for kind in [3, 4, 8, 9] {
        assert_eq!(parse_slice_identity(&SliceFixture { kind, ..SliceFixture::default() }.nal(&sf, &pf), &s, &p, l), Err(AvcError::UnsupportedPicture));
    }
    let invalid_idr = SliceFixture { header: 0x65, kind: 2, frame: 1, ..SliceFixture::default() };
    assert_eq!(parse_slice_identity(&invalid_idr.nal(&sf, &pf), &s, &p, l), Err(AvcError::Malformed));
    Ok(())
}

#[test]
fn syntax_limits_are_checked_before_any_input_traversal() {
    let l = AvcSyntaxLimits::default();
    for invalid in [
        AvcSyntaxLimits { max_nal_bytes: 1, ..l },
        AvcSyntaxLimits { max_width: 0, ..l },
        AvcSyntaxLimits { max_height: 16_385, ..l },
        AvcSyntaxLimits { max_luma_samples: 268_435_457, ..l },
        AvcSyntaxLimits { max_reference_frames: 17, ..l },
        AvcSyntaxLimits { max_slice_identity_bits: 65_537, ..l },
    ] { assert_eq!(parse_sps(&[], invalid), Err(AvcError::Configuration)); }
}

#[test]
fn metadata_debug_does_not_expose_parameter_set_bytes() -> TestResult {
    let l = AvcSyntaxLimits::default(); let s = parse_sps(&SpsFixture::default().nal(), l)?;
    let p = parse_pps(&PpsFixture::default().nal(), &s, l)?;
    assert!(!format!("{s:?}").contains(&format!("{:?}", s.nal_bytes())));
    assert!(!format!("{p:?}").contains(&format!("{:?}", p.nal_bytes())));
    assert!(!format!("{p:?}").contains("sps_source"));
    Ok(())
}

#[test]
fn deterministic_hostile_parameter_corpus_cannot_escape_limits() {
    let l = AvcSyntaxLimits::default(); let mut state = 0x7348_9265_u32;
    for length in 0..128 {
        for _ in 0..64 {
            let mut bytes = Vec::new();
            for _ in 0..length {
                state ^= state << 13; state ^= state >> 17; state ^= state << 5;
                bytes.push(state as u8);
            }
            if !bytes.is_empty() { bytes[0] = 0x67; }
            let _ = parse_sps(&bytes, l);
        }
    }
}

fn fixture_nals(bytes: &[u8]) -> Vec<&[u8]> {
    let mut spans = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at;
                while end > begin && bytes[end - 1] == 0 { end -= 1; }
                if begin != end { spans.push(&bytes[begin..end]); }
            }
            start = Some(at + prefix);
            at += prefix;
        } else { at += 1; }
    }
    if let Some(begin) = start { if begin < bytes.len() { spans.push(&bytes[begin..]); } }
    spans
}

#[test]
fn real_baseline_fixture_matches_retained_laboratory_expectations() -> TestResult {
    let l = AvcSyntaxLimits::default();
    let nals = fixture_nals(include_bytes!("fixtures/avc/baseline.264"));
    let s = parse_sps(nals[0], l)?; let p = parse_pps(nals[1], &s, l)?;
    assert_eq!(s.display_dimensions(), (160, 128));
    assert_eq!(s.poc_mode(), PocMode::Implicit);
    let pictures: Vec<_> = nals.into_iter().filter(|n| matches!(n[0] & 31, 1 | 5))
        .map(|n| parse_slice_identity(n, &s, &p, l)).collect::<Result<_, _>>()?;
    assert_eq!(pictures.iter().map(|p| p.frame_num()).collect::<Vec<_>>(), [0, 1, 2, 0]);
    assert_eq!(pictures.iter().map(|p| p.idr_pic_id()).collect::<Vec<_>>(), [Some(0), None, None, Some(1)]);
    assert!(pictures.windows(2).all(|p| p[1].starts_new_picture(p[0])));
    Ok(())
}

#[test]
fn real_high_fixture_preserves_cropping_and_b_picture_reorder() -> TestResult {
    let l = AvcSyntaxLimits::default();
    let nals = fixture_nals(include_bytes!("fixtures/avc/high_cropped.264"));
    let s = parse_sps(nals[0], l)?; let p = parse_pps(nals[1], &s, l)?;
    assert_eq!(s.coded_dimensions(), (64, 48));
    assert_eq!(s.display_dimensions(), (64, 36));
    assert!(p.entropy_coding_mode());
    assert!(p.transform_8x8_mode());
    let pictures: Vec<_> = nals.into_iter().filter(|n| matches!(n[0] & 31, 1 | 5))
        .map(|n| parse_slice_identity(n, &s, &p, l)).collect::<Result<_, _>>()?;
    assert_eq!(pictures.iter().map(|p| p.frame_num()).collect::<Vec<_>>(), [0, 1, 2, 3, 3, 4]);
    assert_eq!(pictures.iter().map(|p| p.pic_order_cnt_lsb()).collect::<Vec<_>>(), [Some(0), Some(6), Some(2), Some(4), Some(10), Some(8)]);
    assert_eq!(pictures.iter().filter(|p| p.slice_type() == AvcSliceType::B).count(), 3);
    assert!(pictures.windows(2).all(|p| p[1].starts_new_picture(p[0])));
    Ok(())
}
