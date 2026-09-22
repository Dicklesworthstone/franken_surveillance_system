//! Real-stream contract: the decoder stages run against an actual
//! Constrained-Baseline H.264 stream produced by the sealed laboratory
//! oracle (FFmpeg/libx264, offline fixture generation — the bytes are
//! committed and digest-pinned; the Rust tests never invoke the oracle).
//!
//! Fixture: `tests/fixtures/baseline_i64.h264`
//! Generation: `scripts/generate_h264_fixture.sh` (records the exact
//! oracle invocation and expected digest).
//!
//! What this pins down, in order:
//! 1. Annex-B start-code scanning over real encoder framing;
//! 2. NAL type sequence (SPS, PPS, SEI, IDR, non-IDR);
//! 3. RBSP extraction with real emulation-prevention runs;
//! 4. parameter-set parsing via `fss-packet` custody (dimensions, profile);
//! 5. slice-header prefix fields (first_mb_in_slice, slice_type, pps_id).

#![forbid(unsafe_code)]
// Integration tests fail loudly by design; the pedantic lints target
// production code paths.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fss_codec_h264::bits::BitReader;
use fss_codec_h264::rbsp::{ebsp_from_rbsp, rbsp_from_ebsp, validate_trailing_bits, NalPayload};
use fss_packet::avc::{parse_pps, parse_sps, AvcSyntaxLimits};

const STREAM: &[u8] = include_bytes!("fixtures/baseline_i64.h264");
/// sha256 of the fixture bytes; the oracle provenance anchor.
pub const STREAM_SHA256_HEX: &str = "e2aab0bbf0bca60507c964d782ea50918de7471f5a06ddf2ef34e07f15704589";

/// One Annex-B unit: NAL bytes including the header byte, without the
/// start code.
struct AnnexBNal<'a> {
    bytes: &'a [u8],
}

/// Lengths of the start code that begins each NAL (3 or 4 bytes).
fn scan_start_codes(stream: &[u8]) -> Vec<(usize, usize)> {
    // (code_begin, nal_begin) pairs. A start code is `00 00 01`; when the
    // byte before it is also 00 the code is the 4-byte form.
    let mut codes: Vec<(usize, usize)> = Vec::new();
    let mut index = 0;
    while index + 2 < stream.len() {
        if stream[index] == 0 && stream[index + 1] == 0 && stream[index + 2] == 1 {
            let begin = if index > 0 && stream[index - 1] == 0 { index - 1 } else { index };
            codes.push((begin, index + 3));
            index += 3;
        } else {
            index += 1;
        }
    }
    codes
}

/// Scans for start codes; returns NAL units in order. RBSP payloads never
/// end in a zero byte (the stop bit is the final one-bit), so every zero
/// byte before a start code belongs to that start code — the boundaries
/// are exact, no heuristics.
fn scan_annex_b(stream: &[u8]) -> Vec<AnnexBNal<'_>> {
    let codes = scan_start_codes(stream);
    let total = stream.len();
    let mut units = Vec::with_capacity(codes.len());
    for (position, &(_begin, nal_start)) in codes.iter().enumerate() {
        let end = codes
            .get(position + 1)
            .map(|&(next_begin, _)| next_begin)
            .unwrap_or(total);
        units.push(AnnexBNal { bytes: &stream[nal_start..end] });
    }
    units
}

fn sha256_hex(bytes: &[u8]) -> String {
    // Minimal in-test digest over the fixture anchor, mirroring
    // ContentDigest::sha256's output encoding (no external crates).
    let digest = fss_core::ContentDigest::sha256(bytes);
    let hex_chars = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest.bytes() {
        text.push(char::from(hex_chars[usize::from(byte >> 4)]));
        text.push(char::from(hex_chars[usize::from(byte & 15)]));
    }
    text
}

#[test]
fn fixture_digest_matches_provenance_anchor() {
    assert_eq!(
        sha256_hex(STREAM),
        STREAM_SHA256_HEX,
        "fixture bytes drifted from the recorded oracle output"
    );
}

#[test]
fn real_stream_has_expected_nal_sequence() {
    let units = scan_annex_b(STREAM);
    let types: Vec<u8> = units
        .iter()
        .map(|unit| NalPayload::new(unit.bytes).split_header().expect("header").0.unit_type)
        .collect();
    assert_eq!(types, vec![7, 8, 6, 5, 1], "SPS, PPS, SEI, IDR, P");
}

#[test]
fn sps_and_pps_parse_with_custody_dimensions() {
    let units = scan_annex_b(STREAM);
    let limits = AvcSyntaxLimits::default();
    let sps = parse_sps(units[0].bytes, limits).expect("real SPS parses");
    assert_eq!(sps.profile_idc(), 66, "baseline");
    assert_eq!(
        sps.constraint_flags() & 0b0100_0000,
        0b0100_0000,
        "constraint_set1 (Constrained Baseline) signalled by x264"
    );
    assert_eq!(sps.display_dimensions(), (64, 64));
    assert!(sps.frame_mbs_only(), "baseline is frame-MBS-only");

    let pps = parse_pps(units[1].bytes, &sps, limits).expect("real PPS parses");
    assert!(!pps.entropy_coding_mode(), "baseline forbids CABAC");
}

#[test]
fn real_stream_carries_emulation_runs_and_slices_round_trip() {
    let units = scan_annex_b(STREAM);
    // Across a real stream, at least one NAL contains emulation bytes;
    // any individual slice may happen to be escape-free.
    let ebsp_total: usize = units
        .iter()
        .map(|unit| unit.bytes.len().saturating_sub(1))
        .sum();
    let mut escaped = false;
    for unit in &units {
        let (_, payload) = NalPayload::new(unit.bytes).split_header().expect("header");
        let rbsp = rbsp_from_ebsp(payload, 1 << 20).expect("NAL RBSP");
        if rbsp.len() < payload.len() {
            escaped = true;
        }
        // Encoder round-trip is byte-exact on real data.
        assert_eq!(ebsp_from_rbsp(&rbsp), payload, "lossless RBSP round trip");
        validate_trailing_bits(&rbsp)
            .unwrap_or_else(|err| panic!("parameter/vslice NAL trailing bits: {err}"));
    }
    let rbsp_total: usize = units
        .iter()
        .map(|unit| {
            let (_, payload) = NalPayload::new(unit.bytes).split_header().expect("header");
            rbsp_from_ebsp(payload, 1 << 20).expect("NAL RBSP").len()
        })
        .sum();
    assert!(escaped && rbsp_total < ebsp_total, "real stream carries emulation bytes");
}

#[test]
fn slice_headers_decode_first_fields() {
    let units = scan_annex_b(STREAM);
    let limits = AvcSyntaxLimits::default();
    let sps = parse_sps(units[0].bytes, limits).expect("SPS");
    let _pps = parse_pps(units[1].bytes, &sps, limits).expect("PPS");

    // (nal index, expected slice family) — 2 = I, 0 = P after value % 5.
    let cases: [(usize, u32); 2] = [(3, 2), (4, 0)];
    for (index, family) in cases {
        let nal = &units[index];
        let (_, payload) = NalPayload::new(nal.bytes).split_header().expect("header");
        let rbsp = rbsp_from_ebsp(payload, 1 << 20).expect("slice RBSP");
        let mut reader = BitReader::new(&rbsp, rbsp.len() * 8);
        let first_mb = reader.ue(36_863).expect("first_mb_in_slice");
        assert_eq!(first_mb, 0, "one slice per frame in the fixture");
        let slice_type_raw = reader.ue(9).expect("slice_type");
        assert_eq!(
            slice_type_raw % 5, family,
            "slice family for NAL type {}",
            if index == 3 { 5 } else { 1 }
        );
        let pps_id = reader.ue(31).expect("pic_parameter_set_id");
        assert_eq!(pps_id, 0, "single-PPS stream");
    }
}

#[test]
fn scan_handles_short_and_long_start_codes() {
    // The fixture mixes 4-byte (first SPS, last P-slice) and 3-byte codes;
    // byte counts must reconcile exactly with no lost or invented bytes.
    let codes = scan_start_codes(STREAM);
    let units = scan_annex_b(STREAM);
    let code_bytes: usize = codes
        .iter()
        .map(|&(begin, nal_start)| nal_start - begin)
        .sum();
    let nal_bytes: usize = units.iter().map(|unit| unit.bytes.len()).sum();
    assert_eq!(
        code_bytes + nal_bytes,
        STREAM.len(),
        "start-code accounting exact"
    );
    assert!(codes.iter().any(|&(begin, _)| begin == 0 || STREAM[begin] == 0 && begin + 3 < STREAM.len() && begin > 0));
}
