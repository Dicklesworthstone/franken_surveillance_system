#![forbid(unsafe_code)]

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const AVC: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-packet/tests/fixtures/avc/baseline.264"
));
const AVC_CROPPED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-packet/tests/fixtures/avc/high_cropped.264"
));
// Retained x265 tuples from the packet owner's independent metadata corpus.
const VPS8: &str = "40010c01ffff01600000030090000003000003001eba0240";
const SPS8: &str =
    "42010101600000030090000003000003001ea020831d565ba4a4c2f016808000000300800000030284";
const VPS10: &str = "40010c01ffff02200000030090000003000003001eba0240";
const SPS10: &str =
    "42010102200000030090000003000003001ea020831365ba4a4c2f0168080000030008000003002840";
const PPS: &str = "4401c073c089";

fn hex(input: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
        .collect()
}

fn annex_b(nals: &[&[u8]], terminated: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for nal in nals {
        bytes.extend_from_slice(&[0, 0, 0, 1]);
        bytes.extend_from_slice(nal);
    }
    if terminated {
        bytes.extend_from_slice(&[0, 0, 0, 1]);
    }
    bytes
}

#[test]
fn retained_avc_fixtures_keep_coded_and_cropped_dimensions_distinct() -> TestResult {
    for (bytes, profile, level, coded, display) in [
        (AVC, 66, 11, (160, 128), (160, 128)),
        (AVC_CROPPED, 100, 10, (64, 48), (64, 36)),
    ] {
        let report = probe_parameters(bytes, false, ParameterLimits::default(), || false)?;
        assert_eq!(report.codec, ParameterCodec::Avc);
        assert_eq!(report.coded_dimensions, coded);
        assert_eq!(report.display_dimensions, display);
        assert_eq!(
            (report.profile, report.level, report.bit_depth),
            (profile, level, 8)
        );
        assert_eq!(report.inspected_units, 2);
        assert!(report.vps.is_none());
        for source in [&report.sps, &report.pps] {
            assert_eq!(source.bytes(), &bytes[source.range.clone()]);
            assert!(source.range.end <= report.inspected_bytes);
            assert_eq!(
                format!("{source:?}"),
                format!("ParameterSource {{ range: {:?}, .. }}", source.range)
            );
        }
    }
    Ok(())
}

#[test]
fn retained_hevc_main_and_main10_prefixes_preserve_crop_and_depth() -> TestResult {
    for (v, s, depth, display) in [
        (VPS8, SPS8, 8, (62, 46)),
        (VPS10, SPS10, 10, (64, 48)),
    ] {
        let (vps, sps, pps) = (hex(v)?, hex(s)?, hex(PPS)?);
        let bytes = annex_b(&[&vps, &sps, &pps], true);
        let report = probe_parameters(&bytes, false, ParameterLimits::default(), || false)?;
        assert_eq!(report.codec, ParameterCodec::Hevc);
        assert_eq!(report.coded_dimensions, (64, 48));
        assert_eq!(report.display_dimensions, display);
        assert_eq!(report.bit_depth, depth);
        assert_eq!(report.profile, if depth == 8 { 1 } else { 2 });
        assert_eq!(report.level, 30);
        assert_eq!(report.inspected_units, 3);
        assert_eq!(
            report.vps.as_ref().map(ParameterSource::bytes),
            Some(&vps[..])
        );
        assert_eq!(report.sps.bytes(), sps);
        assert_eq!(report.pps.bytes(), pps);
    }
    Ok(())
}

#[test]
fn a_budget_boundary_is_not_an_observed_eof() -> TestResult {
    let known = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    let bytes = annex_b(&[known.sps.bytes(), known.pps.bytes()], false);
    assert_eq!(
        probe_parameters(&bytes, false, ParameterLimits::default(), || false),
        Err(ParameterError::Truncated)
    );
    assert!(probe_parameters(&bytes, true, ParameterLimits::default(), || false).is_ok());
    let limits = ParameterLimits {
        max_bytes: bytes.len(),
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(&bytes, false, limits, || false),
        Err(ParameterError::Limit)
    );
    assert!(probe_parameters(&bytes, true, limits, || false).is_ok());
    // EOF on a longer source never closes the NAL clipped by the allowance.
    let mut extended = bytes.clone();
    extended.extend_from_slice(&[0, 0, 0, 1, 0x65]);
    assert_eq!(
        probe_parameters(&extended, true, limits, || false),
        Err(ParameterError::Limit)
    );
    Ok(())
}

#[test]
fn exact_prefix_allowance_succeeds_and_one_byte_less_refuses() -> TestResult {
    let report = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    let exact = ParameterLimits {
        max_bytes: report.inspected_bytes,
        ..ParameterLimits::default()
    };
    assert_eq!(probe_parameters(AVC, false, exact, || false)?, report);
    assert_eq!(
        probe_parameters(&AVC[..exact.max_bytes], false, exact, || false)?,
        report
    );
    let short = ParameterLimits {
        max_bytes: exact.max_bytes - 1,
        ..exact
    };
    assert_eq!(
        probe_parameters(AVC, false, short, || false),
        Err(ParameterError::Limit)
    );
    // Bytes beyond the allowance cannot alter metadata or its source ranges.
    let mut changed = AVC.to_vec();
    changed[exact.max_bytes..].fill(0xff);
    assert_eq!(probe_parameters(&changed, false, exact, || false)?, report);
    Ok(())
}

#[test]
fn unit_and_geometry_ceilings_are_enforced_before_success() {
    for limits in [
        ParameterLimits {
            max_units: 1,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_width: 159,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_height: 127,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_luma_samples: 160 * 128 - 1,
            ..ParameterLimits::default()
        },
    ] {
        assert_eq!(
            probe_parameters(AVC, false, limits, || false),
            Err(ParameterError::Limit)
        );
    }
    for limits in [
        ParameterLimits {
            max_bytes: MAX_PROBE_BYTES + 1,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_bytes: 0,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_units: 0,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_width: 0,
            ..ParameterLimits::default()
        },
    ] {
        assert_eq!(
            probe_parameters(AVC, false, limits, || false),
            Err(ParameterError::Configuration)
        );
    }
}

#[test]
fn every_cancellation_checkpoint_withholds_the_result() -> TestResult {
    let mut checks = 0;
    probe_parameters(AVC, false, ParameterLimits::default(), || {
        checks += 1;
        false
    })?;
    assert!(checks > 4);
    for stop in 1..=checks {
        let mut at = 0;
        assert_eq!(
            probe_parameters(AVC, false, ParameterLimits::default(), || {
                at += 1;
                at == stop
            }),
            Err(ParameterError::Cancelled)
        );
    }
    // Long non-parameter units are cancellable during delimiter scanning.
    let mut bytes = vec![0, 0, 0, 1, 6];
    bytes.extend_from_slice(&[0xff; 1000]);
    bytes.extend_from_slice(AVC);
    let mut checks = 0;
    assert_eq!(
        probe_parameters(&bytes, false, ParameterLimits::default(), || {
            checks += 1;
            checks == 5
        }),
        Err(ParameterError::Cancelled)
    );
    Ok(())
}

#[test]
fn mixed_or_distinct_candidates_cannot_form_one_configuration() -> TestResult {
    let report = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    let vps = hex(VPS8)?;
    let mixed = annex_b(&[report.sps.bytes(), &vps, report.pps.bytes()], true);
    assert_eq!(
        probe_parameters(&mixed, false, ParameterLimits::default(), || false),
        Err(ParameterError::Contradictory)
    );
    let mut changed = report.sps.bytes().to_vec();
    changed[3] ^= 1;
    let conflict = annex_b(&[report.sps.bytes(), &changed, report.pps.bytes()], true);
    assert_eq!(
        probe_parameters(&conflict, false, ParameterLimits::default(), || false),
        Err(ParameterError::Contradictory)
    );
    let duplicate = annex_b(
        &[report.sps.bytes(), report.sps.bytes(), report.pps.bytes()],
        true,
    );
    let repeated = probe_parameters(&duplicate, false, ParameterLimits::default(), || false)?;
    assert_eq!(repeated.inspected_units, 3);
    assert_eq!(repeated.sps.range.start, 4);
    Ok(())
}

#[test]
fn native_parameter_refusals_are_preserved_without_decode_fallback() -> TestResult {
    let report = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    for (header, profile, expected) in [
        (report.sps.bytes()[0] | 128, 66, ParameterError::Malformed),
        (report.sps.bytes()[0], 244, ParameterError::Unsupported),
    ] {
        let mut sps = report.sps.bytes().to_vec();
        sps[0] = header;
        sps[1] = profile;
        let bytes = annex_b(&[&sps, report.pps.bytes()], true);
        assert_eq!(
            probe_parameters(&bytes, false, ParameterLimits::default(), || false),
            Err(expected)
        );
    }
    let (vps, sps, mismatched_pps) = (hex(VPS8)?, hex(SPS8)?, hex("4401a073c089")?);
    let bytes = annex_b(&[&vps, &sps, &mismatched_pps], true);
    assert_eq!(
        probe_parameters(&bytes, false, ParameterLimits::default(), || false),
        Err(ParameterError::Malformed)
    );
    assert_eq!(
        probe_parameters(
            b"\x00\x00\x00\x18ftypisom",
            true,
            ParameterLimits::default(),
            || false
        ),
        Err(ParameterError::Unsupported)
    );
    Ok(())
}

#[test]
fn three_byte_delimiters_and_eof_padding_preserve_original_nals() -> TestResult {
    let report = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    let mut bytes = vec![0, 0, 1];
    bytes.extend_from_slice(report.sps.bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(report.pps.bytes());
    bytes.extend_from_slice(&[0, 0, 0]);
    let parsed = probe_parameters(&bytes, true, ParameterLimits::default(), || false)?;
    assert_eq!(parsed.sps.bytes(), report.sps.bytes());
    assert_eq!(parsed.pps.bytes(), report.pps.bytes());
    assert_eq!(parsed.sps.range.start, 3);
    assert_eq!(parsed.inspected_bytes, bytes.len());
    Ok(())
}

#[test]
fn non_parameter_headers_cannot_latch_the_wrong_codec() -> TestResult {
    let avc = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    // A complete AVC non-IDR slice may precede the first configuration seen here.
    // Its 0x41 header must not be treated as a HEVC VPS.
    let bytes = annex_b(
        &[&[0x41, 0x9a, 0x22], avc.sps.bytes(), avc.pps.bytes()],
        true,
    );
    let parsed = probe_parameters(&bytes, false, ParameterLimits::default(), || false)?;
    assert_eq!(parsed.codec, ParameterCodec::Avc);
    assert_eq!(parsed.inspected_units, 3);
    // A HEVC IDR_N_LP header must not be treated as an AVC PPS.
    let (vps, sps, pps) = (hex(VPS8)?, hex(SPS8)?, hex(PPS)?);
    let bytes = annex_b(&[&[0x28, 1, 0xae], &vps, &sps, &pps], true);
    let parsed = probe_parameters(&bytes, false, ParameterLimits::default(), || false)?;
    assert_eq!(parsed.codec, ParameterCodec::Hevc);
    assert_eq!(parsed.inspected_units, 4);
    // An initial PPS-like candidate is not evidence of an AVC configuration.
    let bytes = annex_b(&[avc.pps.bytes(), avc.sps.bytes()], false);
    assert_eq!(
        probe_parameters(&bytes, true, ParameterLimits::default(), || false),
        Err(ParameterError::Truncated)
    );
    Ok(())
}
