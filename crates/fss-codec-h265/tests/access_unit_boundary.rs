#![forbid(unsafe_code)]
//! Non-flushing picture-boundary observations over frozen, independently decoded streams.

use std::error::Error;

use fss_codec_h265::{DecodeError, Decoder, DecoderLimits, Picture, annex_b_nal_units};

type Test = Result<(), Box<dyn Error>>;
const DEPENDENT: &[u8] = include_bytes!("fixtures/decode/dependent_p_skip.h265");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn oracle(pictures: &[Picture], expected: &str) -> Test {
    let rows: Vec<_> = expected
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(pictures.len(), rows.len());
    for (picture, row) in pictures.iter().zip(rows) {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(picture.to_i420().len(), fields[1].parse::<usize>()?);
        assert_eq!(hex(&picture.i420_sha256()), fields[2]);
    }
    Ok(())
}

fn decode(stream: &[u8], inspect: bool) -> Result<Vec<Picture>, DecodeError> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = Vec::new();
    assert!(!decoder.has_incomplete_picture());
    for nal in annex_b_nal_units(stream) {
        if let Some(picture) = decoder.decode_nal(nal)? {
            pictures.push(picture);
        }
        if inspect {
            let count = decoder.pictures_decoded();
            let incomplete = decoder.has_incomplete_picture();
            for _ in 0..8 {
                assert_eq!(decoder.has_incomplete_picture(), incomplete);
                assert_eq!(decoder.pictures_decoded(), count);
            }
        }
        while let Some(picture) = decoder.next_output() {
            pictures.push(picture);
        }
    }
    assert!(!decoder.has_incomplete_picture());
    pictures.extend(decoder.finish()?);
    assert!(!decoder.has_incomplete_picture());
    Ok(pictures)
}

fn check_unchanged(stream: &[u8], expected: &str, reordered: bool) -> Test {
    let ordinary = decode(stream, false)?;
    let inspected = decode(stream, true)?;
    assert_eq!(ordinary.len(), inspected.len());
    for (a, b) in ordinary.iter().zip(&inspected) {
        assert_eq!(a.decode_index(), b.decode_index());
        assert_eq!(a.poc(), b.poc());
        assert_eq!(a.to_i420(), b.to_i420());
    }
    if reordered {
        assert!(
            inspected
                .windows(2)
                .any(|pair| pair[0].decode_index() > pair[1].decode_index())
        );
    }
    oracle(&inspected, expected)
}

#[test]
fn one_completed_picture_can_still_leave_an_incomplete_second_picture() -> Test {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut found = false;
    for nal in annex_b_nal_units(DEPENDENT) {
        let _ = decoder.decode_nal(nal)?;
        if decoder.pictures_decoded() == 1 && decoder.has_incomplete_picture() {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "the real dependent-slice stream must expose the malformed sample boundary"
    );
    for _ in 0..16 {
        assert!(decoder.has_incomplete_picture());
        assert_eq!(decoder.pictures_decoded(), 1);
    }
    assert!(matches!(
        decoder.finish(),
        Err(DecodeError::IncompletePicture)
    ));
    assert!(!decoder.has_incomplete_picture());
    assert_eq!(decoder.pictures_decoded(), 1);
    Ok(())
}

#[test]
fn inspection_preserves_dependent_slice_pixels_and_completion_timing() -> Test {
    check_unchanged(
        DEPENDENT,
        include_str!("fixtures/decode/dependent_p_skip.sha256"),
        false,
    )
}

#[test]
fn inspection_preserves_b_picture_display_order_and_reference_state() -> Test {
    check_unchanged(
        include_bytes!("fixtures/decode/b_qcif_pyramid.h265"),
        include_str!("fixtures/decode/b_qcif_pyramid.sha256"),
        true,
    )
}
