#![forbid(unsafe_code)]
//! Execute the exact retained sample driver with real native codecs and frozen media.
//! These tests need no retained I/O or asynchronous runtime substitute.

use std::cell::Cell;
use std::error::Error;

use fss_codec_h264 as avc;
use fss_codec_h265 as hevc;

#[path = "../../fss-reference/src/ingest/recorded_decode/video_access_unit.rs"]
mod video_access_unit;

use video_access_unit::UnitError;

type Test = Result<(), Box<dyn Error>>;
type Units<'a> = (Vec<&'a [u8]>, Vec<Vec<&'a [u8]>>);

const AVC_SLICES: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/ip_qcif_slices3.h264");
const HEVC_DEPENDENT: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/dependent_p_skip.h265");
const HEVC_OPEN: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/b_qcif_opengop.h265");

/// Frozen fixture partitioning only. The first RBSP bit is first_mb_in_slice's codeword
/// for AVC (1 means zero), or first_slice_segment_in_pic_flag for HEVC. No production
/// demuxing or sample-validation behavior is supplied by this helper.
fn units(stream: &[u8], hevc: bool) -> Result<Units<'_>, Box<dyn Error>> {
    let nals: Vec<_> = if hevc {
        hevc::annex_b_nal_units(stream).collect()
    } else {
        avc::annex_b_nal_units(stream).collect()
    };
    let mut prefix = Vec::new();
    let mut pictures: Vec<Vec<&[u8]>> = Vec::new();
    for nal in nals {
        let header = *nal.first().ok_or("empty fixture NAL")?;
        let vcl = if hevc {
            matches!((header >> 1) & 0x3f, 0..=9 | 16..=21)
        } else {
            matches!(header & 31, 1 | 5)
        };
        if vcl {
            let byte = nal
                .get(if hevc { 2 } else { 1 })
                .ok_or("missing fixture slice prefix")?;
            if byte & 0x80 != 0 {
                pictures.push(Vec::new());
            }
            pictures
                .last_mut()
                .ok_or("fixture starts with a continuation slice")?
                .push(nal);
        } else if let Some(picture) = pictures.last_mut() {
            picture.push(nal);
        } else {
            prefix.push(nal);
        }
    }
    Ok((prefix, pictures))
}

fn avc_decoder(prefix: &[&[u8]]) -> Result<avc::Decoder, Box<dyn Error>> {
    let mut decoder = avc::Decoder::new(avc::DecoderLimits::default())?;
    for nal in prefix {
        assert!(decoder.decode_nal(nal)?.is_none());
    }
    assert_eq!(decoder.pictures_decoded(), 0);
    assert!(!decoder.has_incomplete_picture());
    Ok(decoder)
}

fn hevc_decoder(prefix: &[&[u8]]) -> Result<hevc::Decoder, Box<dyn Error>> {
    let mut decoder = hevc::Decoder::new(hevc::DecoderLimits::default())?;
    for nal in prefix {
        assert!(decoder.decode_nal(nal)?.is_none());
    }
    assert_eq!(decoder.pictures_decoded(), 0);
    assert!(!decoder.has_incomplete_picture());
    Ok(decoder)
}

fn hevc_kind(unit: &[&[u8]]) -> Option<u8> {
    unit.iter()
        .filter_map(|nal| nal.first().map(|byte| (byte >> 1) & 0x3f))
        .find(|kind| matches!(kind, 0..=9 | 16..=21))
}

#[test]
fn avc_two_complete_pictures_never_return_a_partially_accepted_sample() -> Test {
    let (prefix, units) = units(AVC_SLICES, false)?;
    assert!(units.len() >= 2);
    let malformed: Vec<_> = units[0].iter().chain(&units[1]).copied().collect();
    let mut decoder = avc_decoder(&prefix)?;
    assert!(matches!(
        video_access_unit::h264(&mut decoder, &malformed, &mut || Ok(())),
        Err(UnitError::Boundary)
    ));
    assert_eq!(
        decoder.pictures_decoded(),
        2,
        "refusal must come from the sample boundary, not max_pictures"
    );
    assert!(!decoder.has_incomplete_picture());
    assert!(
        decoder.next_output().is_none(),
        "output drained into the rejected local result cannot escape"
    );
    Ok(())
}

#[test]
fn avc_complete_then_partial_picture_is_refused_even_with_a_delta_of_one() -> Test {
    let (prefix, units) = units(AVC_SLICES, false)?;
    assert!(units.len() >= 2 && units[1].len() > 1);
    let mut malformed = units[0].clone();
    malformed.push(units[1][0]);
    let mut decoder = avc_decoder(&prefix)?;
    assert!(matches!(
        video_access_unit::h264(&mut decoder, &malformed, &mut || Ok(())),
        Err(UnitError::Boundary)
    ));
    assert_eq!(decoder.pictures_decoded(), 1);
    assert!(decoder.has_incomplete_picture());
    assert!(decoder.next_output().is_none());
    Ok(())
}

#[test]
fn hevc_complete_and_partial_picture_counts_are_atomic() -> Test {
    let (prefix, units) = units(HEVC_DEPENDENT, true)?;
    assert_eq!(units.len(), 2);
    assert!(units[1].len() > 1);
    for complete_second in [false, true] {
        let mut malformed = units[0].clone();
        malformed.extend_from_slice(if complete_second {
            units[1].as_slice()
        } else {
            &units[1][..1]
        });
        let mut decoder = hevc_decoder(&prefix)?;
        assert!(matches!(
            video_access_unit::h265(&mut decoder, &malformed, &mut || Ok(())),
            Err(UnitError::Boundary)
        ));
        // The second first-slice flag ends admission immediately, before its dependent
        // segments can complete another picture, even when they are present in the sample.
        assert_eq!(decoder.pictures_decoded(), 1);
        assert!(decoder.has_incomplete_picture());
        assert!(decoder.next_output().is_none());
    }
    Ok(())
}

#[test]
fn cancellation_after_first_picture_completion_returns_no_partial_output() -> Test {
    let (prefix, avc_units) = units(AVC_SLICES, false)?;
    let malformed: Vec<_> = avc_units[0].iter().chain(&avc_units[1]).copied().collect();
    let mut avc = avc_decoder(&prefix)?;
    let calls = Cell::new(0);
    assert!(matches!(
        video_access_unit::h264(&mut avc, &malformed, &mut || {
            calls.set(calls.get() + 1);
            if calls.get() > avc_units[0].len() {
                Err(())
            } else {
                Ok(())
            }
        }),
        Err(UnitError::Cancelled)
    ));
    assert_eq!(avc.pictures_decoded(), 1);
    assert!(avc.next_output().is_none());
    let (prefix, hevc_units) = units(HEVC_DEPENDENT, true)?;
    let malformed: Vec<_> = hevc_units[0]
        .iter()
        .chain(&hevc_units[1])
        .copied()
        .collect();
    let mut hevc = hevc_decoder(&prefix)?;
    calls.set(0);
    assert!(matches!(
        video_access_unit::h265(&mut hevc, &malformed, &mut || {
            calls.set(calls.get() + 1);
            if calls.get() > hevc_units[0].len() {
                Err(())
            } else {
                Ok(())
            }
        }),
        Err(UnitError::Cancelled)
    ));
    assert_eq!(hevc.pictures_decoded(), 1);
    assert!(hevc.next_output().is_none());
    Ok(())
}

#[test]
fn excessive_picture_samples_stop_before_visiting_the_remaining_payload() -> Test {
    let (prefix, avc_units) = units(AVC_SLICES, false)?;
    let repeated: Vec<_> = (0..8).flat_map(|_| avc_units[0].iter().copied()).collect();
    let mut avc = avc_decoder(&prefix)?;
    let calls = Cell::new(0);
    assert!(matches!(
        video_access_unit::h264(&mut avc, &repeated, &mut || {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Err(UnitError::Boundary)
    ));
    assert_eq!(avc.pictures_decoded(), 2);
    assert!(calls.get() <= avc_units[0].len() * 2);
    assert!(calls.get() < repeated.len());

    let (prefix, hevc_units) = units(HEVC_DEPENDENT, true)?;
    let repeated: Vec<_> = (0..8).flat_map(|_| hevc_units[0].iter().copied()).collect();
    let mut hevc = hevc_decoder(&prefix)?;
    calls.set(0);
    assert!(matches!(
        video_access_unit::h265(&mut hevc, &repeated, &mut || {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Err(UnitError::Boundary)
    ));
    assert_eq!(hevc.pictures_decoded(), 2);
    assert!(calls.get() <= hevc_units[0].len() * 2);
    assert!(calls.get() < repeated.len());
    Ok(())
}

#[test]
fn one_actual_leading_rasl_is_skipped_but_multiple_or_mixed_pictures_are_refused() -> Test {
    let (prefix, units) = units(HEVC_OPEN, true)?;
    let cra = units
        .iter()
        .position(|unit| hevc_kind(unit) == Some(21))
        .ok_or("fixture CRA missing")?;
    let idr = units
        .iter()
        .find(|unit| matches!(hevc_kind(unit), Some(19 | 20)))
        .ok_or("fixture IDR missing")?;
    let rasl: Vec<_> = units
        .iter()
        .skip(cra + 1)
        .take_while(|unit| matches!(hevc_kind(unit), Some(8 | 9)))
        .collect();
    assert!(
        !rasl.is_empty(),
        "the frozen open-GOP fixture must supply a skipped picture"
    );
    for case in 0..3 {
        let mut decoder = hevc_decoder(&prefix)?;
        let start = video_access_unit::h265(&mut decoder, &units[cra], &mut || Ok(()))
            .map_err(|e| format!("CRA: {e:?}"))?;
        assert!(!start.skipped_rasl);
        assert_eq!(decoder.pictures_decoded(), 1);
        let mut sample = rasl[0].clone();
        if case == 1 {
            // Repeat the real retained RASL unit: both first-slice headers take the native
            // skip branch, so a completed-picture counter still has a delta of zero.
            sample.extend(rasl[0]);
        }
        if case == 2 {
            sample.extend(idr);
        }
        let result = video_access_unit::h265(&mut decoder, &sample, &mut || Ok(()));
        if case == 0 {
            let skipped = result.map_err(|e| format!("single RASL: {e:?}"))?;
            assert!(skipped.skipped_rasl);
            assert!(skipped.output.is_empty());
            assert_eq!(decoder.pictures_decoded(), 1);
        } else {
            assert!(matches!(result, Err(UnitError::Boundary)), "case {case}");
            assert_eq!(decoder.pictures_decoded(), if case == 2 { 2 } else { 1 });
        }
        assert!(!decoder.has_incomplete_picture());
        assert!(decoder.next_output().is_none());
    }
    Ok(())
}

#[test]
fn dependent_only_completion_does_not_become_a_new_access_unit() -> Test {
    let (prefix, units) = units(HEVC_DEPENDENT, true)?;
    let mut decoder = hevc_decoder(&prefix)?;
    video_access_unit::h265(&mut decoder, &units[0], &mut || Ok(()))
        .map_err(|e| format!("IDR: {e:?}"))?;
    assert!(units[1].len() >= 3);
    let _ = decoder.decode_nal(units[1][0])?;
    assert!(decoder.has_incomplete_picture());
    assert_eq!(decoder.pictures_decoded(), 1);
    assert!(matches!(
        video_access_unit::h265(&mut decoder, &units[1][1..], &mut || Ok(())),
        Err(UnitError::Boundary)
    ));
    assert_eq!(
        decoder.pictures_decoded(),
        2,
        "the continuation completed a picture but supplied no picture start"
    );
    assert!(!decoder.has_incomplete_picture());
    Ok(())
}

fn hash(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn expected_hashes(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().nth(2))
        .collect()
}

#[test]
fn staged_avc_output_preserves_real_b_picture_order_and_exact_pixels() -> Test {
    let stream = include_bytes!("../../fss-codec-h264/tests/fixtures/decode/m_b_pyramid_ref3.h264");
    let (prefix, units) = units(stream, false)?;
    let mut decoder = avc_decoder(&prefix)?;
    let mut pictures = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        let output = video_access_unit::h264(&mut decoder, unit, &mut || Ok(()))
            .map_err(|e| format!("sample {index}: {e:?}"))?;
        assert_eq!(decoder.pictures_decoded(), index as u64 + 1);
        assert!(
            output
                .iter()
                .all(|picture| picture.decode_index() <= index as u64)
        );
        pictures.extend(output);
    }
    pictures.extend(decoder.finish()?);
    assert!(
        pictures
            .windows(2)
            .any(|pair| pair[0].decode_index() > pair[1].decode_index())
    );
    assert_eq!(
        pictures
            .iter()
            .map(|picture| hash(picture.i420_sha256()))
            .collect::<Vec<_>>(),
        expected_hashes(include_str!(
            "../../fss-codec-h264/tests/fixtures/decode/m_b_pyramid_ref3.sha256"
        ))
    );
    let mut indexes: Vec<_> = pictures.iter().map(avc::Picture::decode_index).collect();
    indexes.sort_unstable();
    assert_eq!(indexes, (0..units.len() as u64).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn staged_hevc_output_preserves_real_b_picture_order_and_exact_pixels() -> Test {
    let stream = include_bytes!("../../fss-codec-h265/tests/fixtures/decode/b_qcif_pyramid.h265");
    let (prefix, units) = units(stream, true)?;
    let mut decoder = hevc_decoder(&prefix)?;
    let mut pictures = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        let output = video_access_unit::h265(&mut decoder, unit, &mut || Ok(()))
            .map_err(|e| format!("sample {index}: {e:?}"))?;
        assert!(!output.skipped_rasl);
        assert_eq!(decoder.pictures_decoded(), index as u64 + 1);
        assert!(
            output
                .output
                .iter()
                .all(|picture| picture.decode_index() <= index as u64)
        );
        pictures.extend(output.output);
    }
    pictures.extend(decoder.finish()?);
    assert!(
        pictures
            .windows(2)
            .any(|pair| pair[0].decode_index() > pair[1].decode_index())
    );
    assert_eq!(
        pictures
            .iter()
            .map(|picture| hash(picture.i420_sha256()))
            .collect::<Vec<_>>(),
        expected_hashes(include_str!(
            "../../fss-codec-h265/tests/fixtures/decode/b_qcif_pyramid.sha256"
        ))
    );
    let mut indexes: Vec<_> = pictures.iter().map(hevc::Picture::decode_index).collect();
    indexes.sort_unstable();
    assert_eq!(indexes, (0..units.len() as u64).collect::<Vec<_>>());
    Ok(())
}
