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

const OPEN_GOP: &[u8] = include_bytes!("fixtures/decode/b_qcif_opengop.h265");
const OPEN_GOP_ORACLE: &str = include_str!("fixtures/decode/b_qcif_opengop.sha256");

fn kind(nal: &[u8]) -> u8 {
    (nal[0] >> 1) & 63
}

fn feed(decoder: &mut Decoder, nals: &[&[u8]]) -> Result<Vec<Picture>, DecodeError> {
    let mut pictures = Vec::new();
    for nal in nals {
        if let Some(picture) = decoder.decode_nal(nal)? {
            pictures.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            pictures.push(picture);
        }
    }
    Ok(pictures)
}

#[test]
fn errors_between_pictures_and_sequence_terminators_require_random_access() -> Test {
    let nals: Vec<_> = annex_b_nal_units(OPEN_GOP).collect();
    let idr = nals.iter().position(|nal| kind(nal) == 20).ok_or("IDR")?;
    let inter = nals[idr + 1];
    let rasl = nals.iter().find(|nal| kind(nal) == 8).ok_or("RASL")?;
    assert_eq!(kind(inter), 1);
    let limits = DecoderLimits {
        max_nal_bytes: nals[idr].len(),
        ..DecoderLimits::default()
    };
    let oversized = vec![0; limits.max_nal_bytes + 1];
    let boundaries: &[(&[u8], bool)] = &[
        (&[], false),
        (&oversized, false),
        (&[0x80, 1, 0x80], false),
        (&[2, 0, 0x80], false),
        (&[2, 9, 0x80], false),
        (&[32 << 1, 1], false),
        (&[33 << 1, 1], false),
        (&[34 << 1, 1], false),
        (&[36 << 1, 1, 0x80], true),
        (&[37 << 1, 1, 0x80], true),
    ];
    for &(boundary, accepted) in boundaries {
        for successor in [inter, *rasl] {
            let mut decoder = Decoder::new(limits)?;
            let _ = feed(&mut decoder, &nals[..=idr])?;
            assert_eq!(decoder.pictures_decoded(), 1);
            assert_eq!(decoder.decode_nal(boundary).is_ok(), accepted);
            assert_eq!(
                decoder.decode_nal(successor).err(),
                Some(DecodeError::MissingReference)
            );
            assert_eq!(decoder.pictures_decoded(), 1);
            // Rejected updates have not destroyed the previously admitted sets.
            let _ = decoder.decode_nal(nals[idr])?;
            assert_eq!(decoder.pictures_decoded(), 2);
        }
    }
    Ok(())
}

#[test]
fn recovery_cra_skips_leading_rasl_and_preserves_surviving_pixels() -> Test {
    let nals: Vec<_> = annex_b_nal_units(OPEN_GOP).collect();
    let cra = nals.iter().position(|nal| kind(nal) == 21).ok_or("CRA")?;
    assert_eq!(kind(nals[cra + 1]), 8);
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut output = feed(&mut decoder, &nals[..cra])?;
    assert!(decoder.decode_nal(&[2, 1, 0]).is_err());
    output.extend(feed(&mut decoder, &nals[cra..])?);
    output.extend(decoder.finish()?);
    let rows: Vec<_> = OPEN_GOP_ORACLE
        .lines()
        .filter(|row| !row.starts_with('#'))
        .collect();
    // The leading RASL (POC 5) may reference across the damaged interval.
    let expected: Vec<i32> = (0..12).filter(|poc| *poc != 5).collect();
    assert_eq!(
        output.iter().map(Picture::poc).collect::<Vec<_>>(),
        expected
    );
    let selected: Vec<_> = expected.iter().map(|poc| rows[*poc as usize]).collect();
    oracle(&output, &selected.join("\n"))
}
