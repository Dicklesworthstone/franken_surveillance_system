#![forbid(unsafe_code)]
//! Exact production retained-video -> privacy-screened luma -> local MJPEG route.

use super::*;
use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};

fn mjpeg_request(base: &[OsString], path: &std::path::Path, maximum: usize, work: u64) -> Vec<OsString> {
    let mut request = export_args(base, path, maximum);
    request.extend(["--output-format".into(), "mjpeg".into(), "--jpeg-quality".into(), "85".into(),
        "--encode-work-units".into(), work.to_string().into()]);
    request
}

fn declare_mask(directory: &Directory) -> Test {
    let make = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command.args(["privacy-mask", "declare", "--root"]).arg(directory.root())
            .args(["--site", SITE, "--sensor", "sensor:camera", "--resolution", "176x144",
                "--rect", "0,0,88,144"]);
        command
    };
    let preview = successful(run_command(&mut make())?)?;
    let parsed = fss_core::json_input::parse(std::str::from_utf8(&preview)?)?;
    let approval = parsed.object().and_then(|x| x.get("approval_digest"))
        .and_then(fss_core::json_input::Value::text).ok_or("mask approval")?;
    let retained = successful(run_command(make().args(["--approve", approval]))?)?;
    let parsed = fss_core::json_input::parse(std::str::from_utf8(&retained)?)?;
    assert_eq!(parsed.object().and_then(|x| x.get("status")).and_then(fss_core::json_input::Value::text), Some("retained"));
    Ok(())
}

#[test]
fn avc_and_hevc_exports_encode_the_current_masked_display_frames_without_publication() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = setup(codec)?;
        declare_mask(&directory)?;
        let before = journals(&directory)?;
        let base = args(&directory, &identity, count);
        let pgm_path = directory.0.join("screened.pgm");
        let pgm = fields(&successful(raw(&export_args(&base, &pgm_path, count * (HEADER.len() + PIXELS)))?)?)?;
        let pixels = fs::read(pgm_path)?;
        let mut budget = EncodeBudget::new(100_000_000);
        let mut expected = Vec::new();
        for frame in pixels.chunks_exact(HEADER.len() + PIXELS) {
            assert_eq!(&frame[..HEADER.len()], HEADER);
            let luma = &frame[HEADER.len()..];
            for row in luma.chunks_exact(176) { assert!(row[..88].iter().all(|x| *x == 16)); }
            let encoded = encode_jpeg(176, 144, luma, ContentDigest::sha256(luma).bytes(),
                EncodeConfig { quality: 85, format: PixelFormat::Grayscale }, &EncodeLimits::default(), &mut budget)?;
            expected.extend_from_slice(encoded.bytes());
        }
        let mut lineages = Vec::new();
        for name in ["first.mjpeg", "repeat.mjpeg"] {
            let path = directory.0.join(name);
            let result = fields(&successful(raw(&mjpeg_request(&base, &path, expected.len(), budget.used()))?)?)?;
            assert_eq!(fs::read(&path)?, expected);
            assert_eq!(one(&result, "mjpeg_sha256")?, ContentDigest::sha256(&expected).to_text());
            assert_eq!(one(&result, "mjpeg_frames")?.parse::<usize>()?, count);
            assert_eq!(one(&result, "mjpeg_bytes")?.parse::<usize>()?, expected.len());
            assert_eq!(one(&result, "remaining_encode_work_units")?, "0");
            assert_eq!(one(&result, "encode_work_units")?.parse::<u64>()?, budget.used());
            assert_eq!(one(&result, "mjpeg_published")?, "false");
            assert_eq!(one(&result, "mjpeg_timing")?, "not_embedded");
            assert_eq!(one(&result, "mjpeg_exact_redaction_pixels")?, "false");
            assert_eq!(one(&result, "mjpeg_export_complete")?, "true");
            assert_eq!(one(&result, "decode_complete")?, "true");
            assert_eq!(result.get("frame_receipt_digest"), pgm.get("frame_receipt_digest"));
            assert_eq!(result.get("privacy_mask_binding"), pgm.get("privacy_mask_binding"));
            assert_eq!(result.get("frame_output_index"), pgm.get("frame_output_index"));
            assert_eq!(one(&result, "decode_work_units")?, one(&pgm, "decode_work_units")?);
            assert!(!result.contains_key("pgm_sha256"));
            lineages.push(one(&result, "mjpeg_frame_receipts_sha256")?.to_owned());
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(lineages[0], lineages[1]);
        assert_eq!(journals(&directory)?, before);
    }
    Ok(())
}

#[test]
fn mjpeg_work_bytes_existing_path_and_deployment_alias_refuse_without_success_receipts() -> Test {
    let (directory, identity, count) = setup("avc")?;
    let base = args(&directory, &identity, count);
    let before = journals(&directory)?;
    let complete_path = directory.0.join("complete.mjpeg");
    let complete = fields(&successful(raw(&mjpeg_request(&base, &complete_path, 16 * 1024 * 1024, 100_000_000))?)?)?;
    let bytes = fs::read(&complete_path)?;
    let work: u64 = one(&complete, "encode_work_units")?.parse()?;
    for (name, maximum, work) in [("bytes.mjpeg", bytes.len() - 1, work),
        ("work.mjpeg", bytes.len(), work - 1), ("zero.mjpeg", bytes.len(), 0)] {
        let path = directory.0.join(name);
        let result = raw(&mjpeg_request(&base, &path, maximum, work))?;
        incomplete(&result);
        let report = fields(&result.stdout)?;
        assert_eq!(one(&report, "mjpeg_export_complete")?, "false");
        assert!(!report.contains_key("mjpeg_sha256"));
        assert!(!report.contains_key("mjpeg_frame_receipts_sha256"));
        if work == 0 { assert!(!path.exists()); }
        else { assert!(fs::metadata(path)?.len() < bytes.len() as u64); }
    }
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(directory.root(), &alias)?;
    for path in [&complete_path, &directory.root().join("forbidden.mjpeg"), &alias.join("forbidden.mjpeg")] {
        let output = raw(&mjpeg_request(&base, path, bytes.len(), work))?;
        incomplete(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("mjpeg_sha256="));
    }
    assert_eq!(fs::read(complete_path)?, bytes);
    assert!(!directory.root().join("forbidden.mjpeg").exists());
    assert_eq!(journals(&directory)?, before);
    Ok(())
}

#[test]
fn invalid_mjpeg_options_refuse_before_opening_a_deployment() -> Test {
    let directory = Directory::new("mjpeg-grammar")?;
    let identity = ContentDigest::sha256(b"not retained").to_text();
    let base = args(&directory, &identity, 1);
    for options in [
        vec!["--output-format", "mjpeg"],
        vec!["--jpeg-quality", "85"],
        vec!["--encode-work-units", "1"],
        vec!["--output", "unused", "--output-format", "jpeg"],
        vec!["--output", "unused", "--output-format", "mjpeg", "--jpeg-quality", "101"],
    ] {
        let mut request = base.clone();
        request.extend(options.into_iter().map(OsString::from));
        assert_eq!(raw(&request)?.status.code(), Some(2));
        assert!(!directory.root().exists());
    }
    Ok(())
}
