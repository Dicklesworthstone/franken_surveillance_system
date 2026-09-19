#![forbid(unsafe_code)]
//! Prefix metadata contracts. Synthetic prefix fixtures are not decoder fixtures.

use fss_packet::hevc::{HevcConfiguration as Config, HevcConfigurationError as E, HevcConfigurationLimits as Limits};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const VPS8: &str = "40010c01ffff01600000030090000003000003001eba0240";
const SPS8: &str = "42010101600000030090000003000003001ea020831d565ba4a4c2f016808000000300800000030284";
const VPS10: &str = "40010c01ffff02200000030090000003000003001eba0240";
const SPS10: &str = "42010102200000030090000003000003001ea020831365ba4a4c2f0168080000030008000003002840";
const PPS: &str = "4401c073c089";
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |b| match b { b'0'..=b'9' => b - b'0', b'a'..=b'f' => b - b'a' + 10, _ => 0 };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}
#[derive(Default)]
struct Bits(Vec<bool>);
impl Bits {
    fn put(&mut self, n: u32, bits: usize) { for bit in (0..bits).rev() { self.0.push(n & (1 << bit) != 0); } }
    fn ue(&mut self, n: u32) {
        let value = n + 1;
        let bits = (32 - value.leading_zeros()) as usize;
        self.put(0, bits - 1); self.put(value, bits);
    }
    fn nal(mut self, kind: u8) -> Vec<u8> {
        self.0.push(true);
        while !self.0.len().is_multiple_of(8) { self.0.push(false); }
        let mut output = vec![kind << 1, 1];
        let mut zeros = 0;
        for chunk in self.0.chunks_exact(8) {
            let value = chunk.iter().fold(0_u8, |v, b| v * 2 + u8::from(*b));
            if zeros == 2 && value <= 3 { output.push(3); zeros = 0; }
            output.push(value); zeros = if value == 0 { zeros + 1 } else { 0 };
        }
        output
    }
}
fn profile(b: &mut Bits, layers: u8, sub: bool, main10: bool) {
    for byte in [if main10 { 2 } else { 1 }, 0x20, 0, 0, 0, 0x90, 0, 0, 0, 0, 0, 30] { b.put(byte, 8); }
    for _ in 1..layers { b.put(u32::from(sub), 1); b.put(u32::from(sub), 1); }
    if layers > 1 { for _ in layers - 1..8 { b.put(0, 2); } }
    for _ in 1..layers {
        if sub {
            for byte in [if main10 { 2 } else { 1 }, 0x20, 0, 0, 0, 0x90, 0, 0, 0, 0, 0, 15] { b.put(byte, 8); }
        }
    }
}
fn tuple(ids: (u8, u8, u8), size: (u32, u32), crop: [u32; 4], layers: u8, depth: u32, sub: bool) -> [Vec<u8>; 3] {
    let (v, s, p) = ids;
    let mut vps = Bits::default();
    vps.put(u32::from(v), 4); vps.put(3, 2); vps.put(0, 6);
    vps.put(u32::from(layers - 1), 3); vps.put(1, 1); vps.put(65535, 16);
    profile(&mut vps, layers, sub, depth != 0);
    let mut sps = Bits::default();
    sps.put(u32::from(v), 4); sps.put(u32::from(layers - 1), 3); sps.put(1, 1);
    profile(&mut sps, layers, sub, depth != 0);
    sps.ue(u32::from(s)); sps.ue(1); sps.ue(size.0); sps.ue(size.1);
    sps.put(1, 1); for offset in crop { sps.ue(offset); }
    sps.ue(depth); sps.ue(depth);
    let mut pps = Bits::default(); pps.ue(u32::from(p)); pps.ue(u32::from(s));
    [vps.nal(32), sps.nal(33), pps.nal(34)]
}
fn parse(n: &[Vec<u8>; 3]) -> Result<Config, E> { Config::parse(&n[0], &n[1], &n[2], Limits::default()) }

#[test]
fn retained_x265_main_and_main10_metadata_matches_pinned_ffprobe_fixture() -> TestResult {
    for (vps, sps, depth, coded, display) in [
        (VPS8, SPS8, 8, (64, 48), (62, 46)), (VPS10, SPS10, 10, (64, 48), (64, 48)),
    ] {
        let n = [hex(vps), hex(sps), hex(PPS)]; let c = parse(&n)?;
        assert_eq!(c.coded_dimensions(), coded); assert_eq!(c.display_dimensions(), display);
        assert_eq!(c.bit_depth(), depth); assert_eq!(c.temporal_layers(), 1); assert!(c.temporal_nested());
        assert_eq!((c.vps_id(), c.sps_id(), c.pps_id()), (0, 0, 0));
        assert_eq!((c.vps(), c.sps(), c.pps()), (&n[0][..], &n[1][..], &n[2][..]));
        assert_eq!(c.conformance_crop(), if depth == 8 { [0, 2, 0, 2] } else { [0; 4] });
        assert_eq!(c.inspected_prefix_bits()[0], 128);
        assert_eq!(c.inspected_prefix_bits()[2], 2);
        assert!(!format!("{c:?}").contains(vps));
    }
    Ok(())
}

#[test]
fn all_temporal_layers_and_optional_sublayer_ptls_keep_sps_alignment() -> TestResult {
    for layers in 1..=7 { for sub in [false, true] { for depth in [0, 2] {
        let n = tuple((3, 15, 63), (640, 480), [1, 2, 3, 4], layers, depth, sub);
        let c = parse(&n)?;
        assert_eq!(c.temporal_layers(), layers); assert_eq!(c.display_dimensions(), (634, 466));
        assert_eq!(c.bit_depth(), 8 + depth as u8); assert_eq!(c.pps_id(), 63);
    } } }
    Ok(())
}

#[test]
fn mismatched_ids_temporal_declarations_and_general_profiles_are_not_merged() -> TestResult {
    let n = tuple((3, 4, 5), (640, 480), [0; 4], 1, 0, false);
    for replacement in [
        tuple((2, 4, 5), (640, 480), [0; 4], 1, 0, false),
        tuple((3, 4, 5), (640, 480), [0; 4], 2, 0, false),
        tuple((3, 4, 5), (640, 480), [0; 4], 1, 2, false),
    ] { assert_eq!(Config::parse(&replacement[0], &n[1], &n[2], Limits::default()).err(), Some(E::Mismatch)); }
    let wrong_pps = tuple((3, 6, 5), (640, 480), [0; 4], 1, 0, false);
    assert_eq!(Config::parse(&n[0], &n[1], &wrong_pps[2], Limits::default()).err(), Some(E::Mismatch));
    Ok(())
}

#[test]
fn dimension_pixel_and_byte_budgets_apply_before_unbounded_work() -> TestResult {
    let n = tuple((0, 0, 0), (640, 480), [0; 4], 1, 0, false);
    for limits in [Limits { max_width: 639, ..Limits::default() },
        Limits { max_height: 479, ..Limits::default() },
        Limits { max_luma_samples: 640 * 480 - 1, ..Limits::default() },
        Limits { max_parameter_bytes: n[0].len() - 1, ..Limits::default() }] {
        assert_eq!(Config::parse(&n[0], &n[1], &n[2], limits).err(), Some(E::Limit));
    }
    for limits in [Limits { max_width: 0, ..Limits::default() }, Limits { max_height: 16_385, ..Limits::default() },
        Limits { max_parameter_bytes: 65_536, ..Limits::default() }, Limits { max_luma_samples: 0, ..Limits::default() }] {
        assert_eq!(Config::parse(&n[0], &n[1], &n[2], limits).err(), Some(E::Configuration));
    }
    Ok(())
}

#[test]
fn invalid_crop_zero_dimensions_and_unsupported_depth_do_not_underflow() -> TestResult {
    for (size, crop) in [((0, 480), [0; 4]), ((640, 0), [0; 4]),
        ((640, 480), [320, 0, 0, 0]), ((640, 480), [0, 0, 200, 41])] {
        assert_eq!(parse(&tuple((0, 0, 0), size, crop, 1, 0, false)).err(), Some(E::Malformed));
    }
    for depth in [1, 3, 4, 8] {
        assert_eq!(parse(&tuple((0, 0, 0), (640, 480), [0; 4], 1, depth, false)).err(), Some(E::Unsupported));
    }
    Ok(())
}

#[test]
fn whole_ebsp_framing_is_checked_even_after_the_interpreted_prefix() -> TestResult {
    let n = [hex(VPS8), hex(SPS8), hex(PPS)];
    for suffix in [&[0, 0, 0][..], &[0, 0, 1], &[0, 0, 2], &[0, 0, 3], &[0, 0, 3, 4]] {
        let mut pps = n[2].clone(); pps.extend_from_slice(suffix);
        assert_eq!(Config::parse(&n[0], &n[1], &pps, Limits::default()).err(), Some(E::Malformed));
    }
    let mut pps = n[2].clone(); pps.extend_from_slice(&[0, 0, 3, 0, 0x80]);
    let c = Config::parse(&n[0], &n[1], &pps, Limits::default())?;
    assert_eq!(c.pps(), pps); assert_eq!(c.inspected_prefix_bits()[2], 2);
    // Suffix accepted as opaque framed bytes, NOT as valid trailing RBSP syntax.
    Ok(())
}

#[test]
fn nal_kind_layer_temporal_and_forbidden_bit_checks_are_explicit() -> TestResult {
    let n = [hex(VPS8), hex(SPS8), hex(PPS)];
    for (index, mask, expected) in [(0, 0x80, E::Corrupt), (0, 1, E::Unsupported),
        (1, 8, E::Unsupported), (1, 1, E::Malformed), (0, 2, E::Malformed)] {
        let mut vps = n[0].clone(); vps[index] ^= mask;
        assert_eq!(Config::parse(&vps, &n[1], &n[2], Limits::default()).err(), Some(expected));
    }
    for end in 0..10 {
        assert!(Config::parse(&n[0][..end], &n[1], &n[2], Limits::default()).is_err());
        assert!(Config::parse(&n[0], &n[1][..end], &n[2], Limits::default()).is_err());
    }
    Ok(())
}

#[test]
fn geometry_grid_keeps_conformance_units_and_original_bytes() -> TestResult {
    for width in [16, 64, 640, 8192] { for height in [16, 48, 480, 8192] { for crop in 0..4 {
        let n = tuple((15, 15, 63), (width, height), [crop; 4], 1, 0, false);
        let c = parse(&n)?;
        assert_eq!(c.display_dimensions(), (width - 4 * crop, height - 4 * crop));
        assert_eq!(c.sps(), n[1]);
    } } }
    Ok(())
}
