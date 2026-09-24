//! Bit-exact differential conformance against the sealed FFmpeg oracle.
//!
//! Every fixture stream in `tests/fixtures/decode/` (plus the two reused
//! committed streams) has a sibling `.sha256` file produced OFFLINE by
//! `scripts/generate_h264_decode_fixtures.sh`: FFmpeg decodes the stream to
//! packed I420 and records one SHA-256 per frame. These tests decode the
//! same bytes with the pure-Rust decoder and require every frame digest,
//! the frame count and the frame size to match exactly. No expected value
//! here is derived from this crate's own output.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fss_codec_h264::{Decoder, DecoderLimits, Picture};

struct OracleFrame {
    bytes: usize,
    sha256: String,
}

fn parse_oracle(text: &str) -> Vec<OracleFrame> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 3, "oracle line {line:?}");
            assert_eq!(
                fields[0].parse::<usize>().unwrap(),
                index,
                "oracle frame order"
            );
            OracleFrame {
                bytes: fields[1].parse().unwrap(),
                sha256: fields[2].to_owned(),
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn decode_stream(stream: &[u8]) -> Vec<Picture> {
    let mut decoder = Decoder::new(DecoderLimits::default()).unwrap();
    let pictures = decoder
        .decode_annex_b(stream)
        .unwrap_or_else(|err| panic!("decode failed: {err}"));
    decoder.finish().unwrap();
    pictures
}

/// Optional local aid: when `tests/fixtures/decode_debug/<name>.yuv` (raw
/// oracle frames, never committed) exists, report the first differing
/// sample to localise a mismatch. It never changes the verdict.
fn locate_mismatch(name: &str, index: usize, picture: &Picture) -> String {
    let path = format!(
        "{}/tests/fixtures/decode_debug/{name}.yuv",
        env!("CARGO_MANIFEST_DIR")
    );
    let Ok(raw) = std::fs::read(path) else {
        return String::from("(no local raw oracle frames for localisation)");
    };
    let ours = picture.to_i420();
    let Some(theirs) = raw.get(index * ours.len()..(index + 1) * ours.len()) else {
        return String::from("(raw oracle frame missing)");
    };
    let luma = (picture.width() * picture.height()) as usize;
    let chroma = (picture.chroma_width() * picture.chroma_height()) as usize;
    let differing = ours.iter().zip(theirs).filter(|(a, b)| a != b).count();
    match ours.iter().zip(theirs).position(|(a, b)| a != b) {
        None => String::from("(raw frames equal?)"),
        Some(pos) => {
            let (plane, offset, width) = if pos < luma {
                ("Y", pos, picture.width() as usize)
            } else if pos < luma + chroma {
                ("Cb", pos - luma, picture.chroma_width() as usize)
            } else {
                ("Cr", pos - luma - chroma, picture.chroma_width() as usize)
            };
            let (x, y) = (offset % width, offset / width);
            let mb = if plane == "Y" {
                (x / 16, y / 16)
            } else {
                (x / 8, y / 8)
            };
            format!(
                "first diff {plane} x={x} y={y} (MB {mb:?}): ours {} oracle {}; {differing} samples differ",
                ours[pos], theirs[pos]
            )
        }
    }
}

fn check(name: &str, stream: &[u8], oracle: &str) {
    let expected = parse_oracle(oracle);
    assert!(!expected.is_empty(), "{name}: empty oracle");
    let pictures = decode_stream(stream);
    assert_eq!(pictures.len(), expected.len(), "{name}: frame count");
    for (index, (picture, frame)) in pictures.iter().zip(&expected).enumerate() {
        let bytes = picture.to_i420();
        assert_eq!(bytes.len(), frame.bytes, "{name} frame {index}: I420 size");
        let digest = hex(&picture.i420_sha256());
        assert!(
            digest == frame.sha256,
            "{name} frame {index} (frame_num {}, idr {}): digest {digest} != oracle {}; {}",
            picture.frame_num(),
            picture.is_idr(),
            frame.sha256,
            locate_mismatch(name, index, picture)
        );
        assert_eq!(picture.decode_index(), index as u64);
    }
}

macro_rules! oracle_test {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            check(
                $name,
                include_bytes!(concat!("fixtures/decode/", $name, ".h264")),
                include_str!(concat!("fixtures/decode/", $name, ".sha256")),
            );
        }
    };
}

// Intra only (I_NxN / I_16x16 mixes), three quantisers.
oracle_test!(intra_qcif_qp28_bit_exact, "i_qcif_qp28");
oracle_test!(intra_qcif_qp12_bit_exact, "i_qcif_qp12");
oracle_test!(intra_qcif_qp44_bit_exact, "i_qcif_qp44");
// Hand-assembled I_PCM + I_16x16 (nC >= 8 fixed-length coeff_token).
oracle_test!(pcm_mixed_bit_exact, "pcm_mixed");
oracle_test!(pcm_mixed_nodeblock_bit_exact, "pcm_mixed_nodeblock");
// I + P.
oracle_test!(cropped_100x60_bit_exact, "ip_100x60_crop");
oracle_test!(three_slices_bit_exact, "ip_qcif_slices3");
oracle_test!(deblocking_disabled_bit_exact, "ip_qcif_nodeblock");
oracle_test!(deblocking_offsets_bit_exact, "ip_qcif_deblockoffs");
oracle_test!(p_three_refs_all_partitions_bit_exact, "p_qcif_ref3_p4x4");
oracle_test!(
    constrained_intra_in_p_slices_bit_exact,
    "ip_constrained_intra"
);
// Header rewrites of libx264 output (scripts/rewrite_h264_headers.py).
oracle_test!(
    slice_edge_deblocking_mode2_bit_exact,
    "ip_qcif_slices3_idc2"
);
oracle_test!(poc_type0_bit_exact, "ip_100x60_poc0");

/// The POC-type-0 rewrite writes pic_order_cnt_lsb = 2 * (pictures since
/// IDR); with no MSB wrap the decoded POC is exactly that.
#[test]
fn poc_type0_values_follow_the_rewrite() {
    let pictures = decode_stream(include_bytes!("fixtures/decode/ip_100x60_poc0.h264"));
    let pocs: Vec<i32> = pictures.iter().map(Picture::poc).collect();
    assert_eq!(pocs, vec![0, 2, 4, 6, 8, 10]);
}

#[test]
fn reused_baseline_i64_bit_exact() {
    check(
        "baseline_i64",
        include_bytes!("fixtures/baseline_i64.h264"),
        include_str!("fixtures/decode/baseline_i64.sha256"),
    );
}

#[test]
fn reused_fss_packet_baseline_bit_exact() {
    check(
        "fss_packet_baseline",
        include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),
        include_str!("fixtures/decode/fss_packet_baseline.sha256"),
    );
}

/// Independent of any decoder: with deblocking disabled the I_PCM
/// macroblocks must reproduce the generator's sample pattern exactly
/// (scripts/generate_h264_pcm_fixture.py: luma (7x + 13y + 50mb) & 255,
/// chroma (11x + 5y + 30mb + 90c) & 255 for MBs 0, 2, 4 of a 3x2 picture).
#[test]
fn pcm_samples_match_generator_pattern() {
    let pictures = decode_stream(include_bytes!("fixtures/decode/pcm_mixed_nodeblock.h264"));
    assert_eq!(pictures.len(), 1);
    let picture = &pictures[0];
    assert_eq!((picture.width(), picture.height()), (48, 32));
    for mb in [0usize, 2, 4] {
        let (mbx, mby) = (mb % 3, mb / 3);
        for y in 0..16 {
            for x in 0..16 {
                let expected = ((x * 7 + y * 13 + mb * 50) & 255) as u8;
                let sample = picture.luma()[(mby * 16 + y) * 48 + mbx * 16 + x];
                assert_eq!(sample, expected, "luma MB {mb} ({x},{y})");
            }
        }
        for (component, plane) in [picture.cb(), picture.cr()].into_iter().enumerate() {
            for y in 0..8 {
                for x in 0..8 {
                    let expected = ((x * 11 + y * 5 + mb * 30 + component * 90) & 255) as u8;
                    let sample = plane[(mby * 8 + y) * 24 + mbx * 8 + x];
                    assert_eq!(sample, expected, "chroma {component} MB {mb} ({x},{y})");
                }
            }
        }
    }
}

/// Cropping metadata: 100x60 is coded as 112x64 with right/bottom crop.
#[test]
fn cropped_dimensions_and_plane_sizes() {
    let pictures = decode_stream(include_bytes!("fixtures/decode/ip_100x60_crop.h264"));
    let first = &pictures[0];
    assert_eq!((first.width(), first.height()), (100, 60));
    assert_eq!((first.chroma_width(), first.chroma_height()), (50, 30));
    assert_eq!(first.luma().len(), 6_000);
    assert_eq!(first.cb().len(), 1_500);
    assert!(first.is_idr());
    assert!(pictures[1..].iter().all(|p| !p.is_idr()));
}

/// NAL-by-NAL feeding yields the same pictures as whole-buffer feeding.
#[test]
fn nal_by_nal_matches_annex_b() {
    let stream = include_bytes!("fixtures/decode/ip_qcif_slices3.h264");
    let whole = decode_stream(stream);
    let mut decoder = Decoder::new(DecoderLimits::default()).unwrap();
    let mut pieces = Vec::new();
    for nal in fss_codec_h264::annex_b_nal_units(stream) {
        if let Some(picture) = decoder.decode_nal(nal).unwrap() {
            pieces.push(picture);
        }
    }
    assert_eq!(whole, pieces);
}
