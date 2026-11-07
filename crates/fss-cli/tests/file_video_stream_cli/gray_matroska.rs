#![forbid(unsafe_code)]
//! Real retained AVC/HEVC processes export unchanged screened samples with explicit cadence.

use super::*;
use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};

const DEFAULT_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

fn request(
    base: &[OsString],
    path: &std::path::Path,
    maximum: Option<usize>,
    rate: &str,
) -> Vec<OsString> {
    let mut request = if let Some(maximum) = maximum {
        export_args(base, path, maximum)
    } else {
        let mut request = base.to_vec();
        request.extend(["--output".into(), path.as_os_str().to_owned()]);
        request
    };
    request.extend([
        "--output-format".into(), "gray-mkv".into(),
        "--output-rate".into(), rate.into(),
    ]);
    request
}

fn samples(pgm: &[u8], count: usize) -> Test<Vec<&[u8]>> {
    assert!((1..=8).contains(&count), "these retained fixtures contain at most eight frames");
    assert_eq!(pgm.len(), count * (HEADER.len() + PIXELS));
    let mut samples = Vec::with_capacity(count);
    for frame in pgm.chunks_exact(HEADER.len() + PIXELS) {
        assert_eq!(&frame[..HEADER.len()], HEADER);
        samples.push(&frame[HEADER.len()..]);
    }
    assert_eq!(samples.len(), count);
    Ok(samples)
}

fn framed(samples: &[&[u8]], rate: PlaybackRate) -> Test<Vec<u8>> {
    assert!((1..=8).contains(&samples.len()));
    let config = GrayMatroskaConfig::new([176, 144], rate)?;
    let mut bytes = config.initialization()?.bytes().to_vec();
    for (ordinal, pixels) in samples.iter().enumerate() {
        let frame = config.frame(ordinal as u64)?;
        assert_eq!(frame.payload_bytes(), PIXELS);
        assert_eq!(pixels.len(), PIXELS);
        bytes.extend_from_slice(frame.prefix());
        bytes.extend_from_slice(pixels);
    }
    assert!(bytes.len() < 1024 * 1024);
    Ok(bytes)
}

fn same_source_receipts(
    expected: &BTreeMap<String, Vec<String>>,
    actual: &BTreeMap<String, Vec<String>>,
) -> Test {
    for key in [
        "frame_output_index", "frame_segment", "frame_luma_sha256",
        "frame_i420_sha256", "frame_receipt_digest",
        "frame_capture_earliest_ns", "frame_capture_latest_ns",
        "source_import_identity", "source_segment", "source_capsule_digest",
        "source_encoded_digest", "source_sensor_id", "source_stream_id",
        "source_clock_basis", "privacy_mask_binding_digest",
    ] {
        let expected = expected.get(key).ok_or_else(|| format!("missing original {key}"))?;
        assert_eq!(actual.get(key), Some(expected), "{key}");
    }
    assert_eq!(one(actual, "decode_work_units")?, one(expected, "decode_work_units")?);
    assert_eq!(one(actual, "decoder_identity")?, one(expected, "decoder_identity")?);
    Ok(())
}

fn complete(
    report: &BTreeMap<String, Vec<String>>,
    bytes: &[u8],
    frames: usize,
    rate: PlaybackRate,
) -> Test {
    assert_eq!(one(report, "gray_mkv_sha256")?, ContentDigest::sha256(bytes).to_text());
    assert_eq!(one(report, "gray_mkv_bytes")?.parse::<usize>()?, bytes.len());
    assert_eq!(one(report, "gray_mkv_frames")?.parse::<usize>()?, frames);
    assert_eq!(one(report, "gray_mkv_width")?, "176");
    assert_eq!(one(report, "gray_mkv_height")?, "144");
    assert_eq!(one(report, "gray_mkv_rate_numerator")?.parse::<u32>()?, rate.numerator());
    assert_eq!(one(report, "gray_mkv_rate_denominator")?.parse::<u32>()?, rate.denominator());
    let end = (frames as u128 * 1_000_000_000 * u128::from(rate.denominator())
        / u128::from(rate.numerator())) as u64;
    assert_eq!(one(report, "gray_mkv_duration_ns")?.parse::<u64>()?, end);
    for (key, expected) in [
        ("gray_mkv_pixel_format", "grayscale_luma"),
        ("gray_mkv_lossy", "false"),
        ("gray_mkv_exact_luma_preserved", "true"),
        ("gray_mkv_timing", "operator_requested_uniform_rate"),
        ("gray_mkv_source_capture_timing_preserved", "false"),
        ("gray_mkv_published", "false"),
        ("gray_mkv_export_complete", "true"),
        ("gray_mkv_work_unit_model", "logical_sha256_input_bytes"),
        ("gray_mkv_frame_receipts_domain", "fss.file_gray_matroska_frame_receipts.v1"),
        ("decode_complete", "true"),
        ("decode_published", "false"),
    ] {
        assert_eq!(one(report, key)?, expected, "{key}");
    }
    for key in ["gray_mkv_encoder_identity", "gray_mkv_frame_receipts_sha256"] {
        let digest = ContentDigest::parse(one(report, key)?)?;
        assert_eq!(digest.algorithm(), fss_core::DigestAlgorithm::Sha256);
        assert!(!digest.is_laboratory());
        assert_ne!(digest.bytes(), [0; 32]);
    }
    assert!(
        one(report, "gray_mkv_hashed_bytes")?.parse::<usize>()? >= bytes.len() + frames * PIXELS
    );
    assert!(!report.contains_key("pgm_sha256"));
    assert!(!report.contains_key("mjpeg_sha256"));
    assert!(!report.contains_key("encode_work_units"));
    Ok(())
}

fn refused(output: &Output) -> Test<BTreeMap<String, Vec<String>>> {
    incomplete(output);
    let report = fields(&output.stdout)?;
    assert_eq!(one(&report, "decode_complete")?, "false");
    assert_eq!(one(&report, "gray_mkv_export_complete")?, "false");
    for key in [
        "gray_mkv_sha256", "gray_mkv_frame_receipts_sha256", "gray_mkv_encoder_identity",
        "output_window_complete", "output_window_request_digest", "output_window_selection_digest",
    ] {
        assert!(!report.contains_key(key), "incomplete output cannot expose {key}");
    }
    Ok(report)
}

#[test]
fn avc_and_hevc_exact_screened_pixels_source_receipts_and_cadence_match_pgm() -> Test {
    use std::os::unix::fs::PermissionsExt;

    let rate = PlaybackRate::new(60_000, 2002)?;
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let base = args(&directory, &identity, count);
        let before = journals(&directory)?;
        let pgm_path = directory.0.join("screened.pgm");
        let pgm = fields(&successful(raw(&export_args(
            &base, &pgm_path, count * (HEADER.len() + PIXELS),
        ))?)?)?;
        let pgm_bytes = fs::read(pgm_path)?;
        let pixels = samples(&pgm_bytes, count)?;
        let expected = framed(&pixels, rate)?;
        let mut lineages = Vec::new();
        let mut generations = Vec::new();
        for (name, supplied_rate) in [
            ("first.mkv", "60000/2002"), ("equivalent.mkv", "30000/1001"),
        ] {
            let path = directory.0.join(name);
            let report = fields(&successful(raw(&request(
                &base, &path, Some(expected.len()), supplied_rate,
            ))?)?)?;
            assert_eq!(fs::read(&path)?, expected);
            complete(&report, &expected, count, rate)?;
            same_source_receipts(&pgm, &report)?;
            lineages.push(one(&report, "gray_mkv_frame_receipts_sha256")?.to_owned());
            generations.push(one(&report, "gray_mkv_encoder_identity")?.to_owned());
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(lineages[0], lineages[1]);
        assert_eq!(generations[0], generations[1]);
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

#[test]
fn exact_frame_quotas_are_lazy_and_late_pressure_never_certifies_or_overwrites_a_prefix() -> Test {
    let rate = PlaybackRate::new(30_000, 1001)?;
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        let base = args(&directory, &identity, count);
        let before = journals(&directory)?;
        let pgm_path = directory.0.join("quota-source.pgm");
        successful(raw(&export_args(&base, &pgm_path, count * (HEADER.len() + PIXELS)))?)?;
        let pgm_bytes = fs::read(pgm_path)?;
        let pixels = samples(&pgm_bytes, count)?;
        let full = framed(&pixels, rate)?;
        let first = framed(&pixels[..1], rate)?;
        let prior = framed(&pixels[..count - 1], rate)?;

        let tiny = directory.0.join("too-small.mkv");
        let report = refused(&raw(&request(&base, &tiny, Some(first.len() - 1), "30000/1001"))?)?;
        assert!(!tiny.exists());
        assert!(!report.contains_key("frame_receipt_digest"));

        for (name, maximum, expected) in [
            ("first-only.mkv", first.len(), first.as_slice()),
            ("late-pressure.mkv", full.len() - 1, prior.as_slice()),
        ] {
            let path = directory.0.join(name);
            refused(&raw(&request(&base, &path, Some(maximum), "30000/1001"))?)?;
            let saved = fs::read(&path)?;
            assert_eq!(saved, expected);
            assert!(saved.len() < full.len());
            // A fresh attempt cannot replace or certify an earlier incomplete destination.
            refused(&raw(&request(&base, &path, Some(full.len()), "30000/1001"))?)?;
            assert_eq!(fs::read(path)?, saved);
        }
        let owned = directory.0.join("operator-owned.mkv");
        fs::write(&owned, b"operator-owned destination")?;
        refused(&raw(&request(&base, &owned, Some(full.len()), "30000/1001"))?)?;
        assert_eq!(fs::read(owned)?, b"operator-owned destination");
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

#[test]
fn current_full_frame_masks_preserve_every_sample_as_sixteen_in_both_codecs() -> Test {
    let rate = PlaybackRate::new(30_000, 1001)?;
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        // The policy is declared after retention; export must consult the current policy.
        let policy = mask(&directory)?;
        let before = journals(&directory)?;
        let base = args(&directory, &identity, count);
        let pgm_path = directory.0.join("current-mask.pgm");
        let pgm = fields(&successful(raw(&export_args(
            &base, &pgm_path, count * (HEADER.len() + PIXELS),
        ))?)?)?;
        let pgm_bytes = fs::read(pgm_path)?;
        let pixels = samples(&pgm_bytes, count)?;
        for frame in &pixels {
            assert!(frame.iter().all(|sample| *sample == 16));
        }
        let expected = framed(&pixels, rate)?;
        let path = directory.0.join("current-mask.mkv");
        let report = fields(&successful(raw(&request(
            &base, &path, Some(expected.len()), "60000/2002",
        ))?)?)?;
        assert_eq!(fs::read(path)?, expected);
        complete(&report, &expected, count, rate)?;
        assert_eq!(one(&report, "privacy_mask_policy")?, policy.to_text());
        assert_eq!(one(&report, "privacy_mask_binding")?, "sensor_policy");
        same_source_receipts(&pgm, &report)?;
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

fn timed_avc_setup() -> Test<(Directory, String)> {
    let directory = Directory::new("gray-mkv-timed-avc")?;
    let path = directory.0.join("timed-source.h264");
    fs::write(&path, AVC)?;
    let output = run_command(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("import").arg("--root").arg(directory.root())
            .args(["--site", SITE, "--input"]).arg(&path)
            .args([
                "--sensor", "sensor:camera", "--stream", "stream:camera",
                "--receive-time-ns", "1000000000", "--media-format", "annexb",
                "--capture-start-ns", "100000000", "--capture-uncertainty-ns", "1000",
                "--assumed-fps", "10",
            ]),
    )?;
    let imported = fields(&successful(output)?)?;
    let identity = one(&imported, "import_identity")?.to_owned();
    fs::remove_file(path)?;
    Ok((directory, identity))
}

fn window_request(base: &[OsString], path: &std::path::Path, interval: &str) -> Vec<OsString> {
    let mut request = request(base, path, Some(DEFAULT_OUTPUT_BYTES), "30/1");
    request.extend([
        "--output-window-ns".into(), interval.into(),
        "--output-clock-basis".into(), "estimated".into(),
    ]);
    request
}

fn selected_source_index(report: &BTreeMap<String, Vec<String>>) -> Test<usize> {
    let segments = report.get("frame_segment").ok_or("source segments")?;
    assert_eq!(segments.len(), 3);
    let index = segments.iter().position(|segment| segment == "1").ok_or("middle source frame")?;
    assert_eq!(segments.iter().filter(|segment| *segment == "1").count(), 1);
    Ok(index)
}

#[test]
fn retained_window_selects_only_middle_capture_then_starts_new_playback_at_zero() -> Test {
    let (directory, identity) = timed_avc_setup()?;
    let base = args(&directory, &identity, 3);
    let before = journals(&directory)?;
    let pgm_path = directory.0.join("timed-source.pgm");
    let pgm = fields(&successful(raw(&export_args(
        &base, &pgm_path, 3 * (HEADER.len() + PIXELS),
    ))?)?)?;
    let pgm_bytes = fs::read(pgm_path)?;
    let pixels = samples(&pgm_bytes, 3)?;
    let index = selected_source_index(&pgm)?;
    let rate = PlaybackRate::new(30, 1)?;
    let expected = framed(&[pixels[index]], rate)?;
    let path = directory.0.join("middle.mkv");
    let report = fields(&successful(raw(&window_request(
        &base, &path, "150000000:250000000",
    ))?)?)?;
    assert_eq!(fs::read(path)?, expected);
    complete(&report, &expected, 1, rate)?;
    for (key, value) in [
        ("output_window_start_ns", "150000000"),
        ("output_window_end_exclusive_ns", "250000000"),
        ("output_window_clock_basis", "estimated"),
        ("output_window_time_provenance", "operator_assumption"),
        ("output_window_observed_frames", "3"),
        ("output_window_selected_frames", "1"),
        ("output_window_skipped_frames", "2"),
        ("output_window_selected_earliest_ns", "199999000"),
        ("output_window_selected_latest_ns", "200001000"),
        ("output_window_timing_embedded", "false"),
        ("output_window_coverage_asserted", "false"),
        ("output_window_complete", "true"),
        ("h264_frames_decoded", "3"),
        ("gray_mkv_duration_ns", "33333333"),
        ("frame_capture_earliest_ns", "199999000"),
        ("frame_capture_latest_ns", "200001000"),
        ("frame_segment", "1"),
    ] {
        assert_eq!(one(&report, key)?, value, "{key}");
    }
    for key in [
        "frame_output_index", "frame_receipt_digest", "frame_luma_sha256",
        "source_import_identity", "source_segment", "source_capsule_digest",
        "source_encoded_digest", "source_clock_basis",
    ] {
        let values = pgm.get(key).ok_or_else(|| format!("missing PGM {key}"))?;
        let original = values.get(index).ok_or("source field length")?;
        assert_eq!(one(&report, key)?, original);
    }
    for key in ["output_window_request_digest", "output_window_selection_digest"] {
        let digest = ContentDigest::parse(one(&report, key)?)?;
        assert_eq!(digest.algorithm(), fss_core::DigestAlgorithm::Sha256);
        assert!(!digest.is_laboratory());
        assert_ne!(digest.bytes(), [0; 32]);
    }
    assert_eq!(one(&report, "decode_work_units")?, one(&pgm, "decode_work_units")?);
    assert_eq!(journals(&directory)?, before);
    Ok(())
}

#[test]
fn a_late_uncertain_capture_boundary_keeps_only_an_uncertified_private_prefix() -> Test {
    let (directory, identity) = timed_avc_setup()?;
    let base = args(&directory, &identity, 3);
    let before = journals(&directory)?;
    let pgm_path = directory.0.join("boundary-source.pgm");
    let pgm = fields(&successful(raw(&export_args(
        &base, &pgm_path, 3 * (HEADER.len() + PIXELS),
    ))?)?)?;
    let pgm_bytes = fs::read(pgm_path)?;
    let pixels = samples(&pgm_bytes, 3)?;
    let index = selected_source_index(&pgm)?;
    let expected = framed(&[pixels[index]], PlaybackRate::new(30, 1)?)?;
    let path = directory.0.join("boundary-prefix.mkv");
    let output = raw(&window_request(&base, &path, "150000000:300000000"))?;
    let report = refused(&output)?;
    assert!(String::from_utf8_lossy(&output.stderr).contains("crosses window boundary"));
    assert_eq!(one(&report, "frame_segment")?, "1");
    assert_eq!(fs::read(&path)?, expected);
    assert!(!expected.is_empty());
    assert!(!report.contains_key("gray_mkv_duration_ns"));
    refused(&raw(&window_request(&base, &path, "150000000:250000000"))?)?;
    assert_eq!(fs::read(path)?, expected);
    assert_eq!(journals(&directory)?, before);
    Ok(())
}

#[test]
fn default_and_maximum_output_allowances_work_and_out_of_profile_limits_refuse_early() -> Test {
    let (directory, identity, count) = setup("avc")?;
    let base = args(&directory, &identity, count);
    let before = journals(&directory)?;
    let pgm_path = directory.0.join("allowance-source.pgm");
    successful(raw(&export_args(&base, &pgm_path, count * (HEADER.len() + PIXELS)))?)?;
    let pgm_bytes = fs::read(pgm_path)?;
    let rate = PlaybackRate::new(30, 1)?;
    let expected = framed(&samples(&pgm_bytes, count)?, rate)?;
    let mut lineages = Vec::new();
    for (name, maximum) in [
        ("default.mkv", None),
        ("explicit-default.mkv", Some(DEFAULT_OUTPUT_BYTES)),
        ("maximum.mkv", Some(MAX_OUTPUT_BYTES)),
    ] {
        let path = directory.0.join(name);
        let report = fields(&successful(raw(&request(&base, &path, maximum, "30/1"))?)?)?;
        assert_eq!(fs::read(path)?, expected);
        complete(&report, &expected, count, rate)?;
        lineages.push(one(&report, "gray_mkv_frame_receipts_sha256")?.to_owned());
    }
    assert!(lineages.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(journals(&directory)?, before);

    let absent = Directory::new("gray-mkv-invalid-allowance")?;
    let identity = ContentDigest::sha256(b"not retained").to_text();
    let base = args(&absent, &identity, 1);
    for maximum in [0, MAX_OUTPUT_BYTES + 1] {
        let path = absent.0.join(format!("refused-{maximum}.mkv"));
        let output = raw(&request(&base, &path, Some(maximum), "30/1"))?;
        assert_eq!(output.status.code(), Some(2));
        assert!(!absent.root().exists());
        assert!(!path.exists());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("gray_mkv_sha256="));
    }
    Ok(())
}
