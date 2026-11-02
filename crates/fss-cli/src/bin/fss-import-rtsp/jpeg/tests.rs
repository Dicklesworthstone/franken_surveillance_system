#![forbid(unsafe_code)]
//! Pure operator contracts; actual cross-process custody tests live in rtsp_jpeg_import_cli.

use std::ffi::OsString;

use fss_core::ContentDigest;
use fss_packet::StreamKey;
use fss_reference::rtsp::datagram_archive::DatagramScope;
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};

use super::{driver, plan::Options};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn args() -> Test<Vec<OsString>> {
    let digest = ContentDigest::sha256(b"JPEG import operator fixture");
    let scope = DatagramScope {
        binding: TcpBinding::new(
            StreamKey {
                ingress: 11,
                generation: 8,
                ssrc: 7,
            },
            "127.0.0.1:8554".parse()?,
            "camera.test",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        channels: (0, 1),
        receive_clock: digest,
        retention_evidence: digest,
    };
    Ok([
        "--archive",
        "/absent-jpeg-import-fixture/source",
        "--root",
        "/absent-jpeg-import-fixture/destination",
        "--site",
        "site:jpeg-import-test",
        "--peer",
        "127.0.0.1:8554",
        "--authority",
        "camera.test",
        "--ingress",
        "11",
        "--generation",
        "8",
        "--ssrc",
        "7",
        "--receive-clock",
        &digest.to_text(),
        "--retention-evidence",
        &digest.to_text(),
        "--prefix-scope",
        &scope.digest()?.to_text(),
        "--prefix-head",
        &digest.to_text(),
        "--prefix-datagrams",
        "5",
        "--prefix-bytes",
        "4096",
        "--configuration-evidence",
        &digest.to_text(),
        "--reduced-rtcp",
        "yes",
        "--sensor-id",
        "sensor:physical-camera",
        "--stream-id",
        "stream:owner-selected",
        "--mapping-evidence",
        &digest.to_text(),
        "--receive-time-ns",
        "2000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect())
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn complete_preview_keeps_transport_mapping_timing_and_pixel_claims_separate() -> Test {
    let options = Options::parse(&args()?)?;
    let preview = options.preview()?;
    fss_cli::json_input::parse(&preview)?;
    for expected in [
        "\"format\":\"fss.rtsp_jpeg_import_operator.v1\"",
        "\"kind\":\"plan\"",
        "\"writes\":\"none\"",
        "\"network\":\"none\"",
        "\"capture_time_label\":\"unknown\"",
        "\"pixels_decoded\":false",
        "\"entropy_validated\":false",
        "\"absence_certifiable\":false",
        "\"transport_identity_proves_physical_camera\":false",
        "\"class\":\"explicit_operator_mapping\"",
        "\"maximum_read_bytes\":536870912",
        "\"maximum_output_bytes\":65536",
        "\"maximum_steps\":100000",
        "\"maximum_frames\":256",
    ] {
        assert!(preview.contains(expected), "missing {expected}");
    }
    assert!(preview.contains(&options.approval()?.to_text()));
    assert!(!options.archive.exists());
    assert!(!options.root.exists());
    Ok(())
}

#[test]
fn approval_binds_mapping_interpretation_destination_and_every_exposed_allowance() -> Test {
    let initial = Options::parse(&args()?)?;
    let approved = initial.approval()?;
    let other = ContentDigest::sha256(b"different explicit import choice").to_text();
    for (key, value) in [
        ("--archive", "/absent-jpeg-import-fixture/another-source"),
        ("--root", "/absent-jpeg-import-fixture/another-destination"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
        ("--prefix-head", other.as_str()),
        ("--prefix-datagrams", "6"),
        ("--prefix-bytes", "4097"),
        ("--configuration-evidence", other.as_str()),
        ("--payload-type", "97"),
        ("--reduced-rtcp", "no"),
        ("--sensor-id", "sensor:other"),
        ("--stream-id", "stream:other"),
        ("--mapping-evidence", other.as_str()),
        ("--receive-time-ns", "3000000000"),
        ("--max-datagrams", "1024"),
        ("--max-source-bytes", "1048576"),
        ("--max-original-bytes", "1048576"),
        ("--max-media-bytes", "1048576"),
        ("--max-read-bytes", "268435456"),
        ("--max-frames", "255"),
        ("--max-steps", "99999"),
        ("--max-work", "1000000000"),
        ("--timeout-ms", "60000"),
        ("--reorder-delay-ms", "50"),
        ("--max-frame-bytes", "4194304"),
        ("--max-dimension", "1024"),
        ("--max-fragments", "512"),
        ("--frame-timeout-ms", "1000"),
        ("--max-cached-quantizers", "64"),
    ] {
        let mut input = args()?;
        set(&mut input, key, value);
        let mut options = Options::parse(&input)?;
        assert_ne!(options.approval()?, approved, "unbound {key}");
        options.approve = Some(approved);
        assert_eq!(
            driver::execute(&options).err(),
            Some("ERR-RTSP-JPEG-IMPORT-APPROVAL-001"),
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn independent_prefix_scope_prevents_silent_route_epoch_or_clock_substitution() -> Test {
    let other = ContentDigest::sha256(b"other source clock or retention").to_text();
    for (key, value) in [
        ("--peer", "127.0.0.2:8555"),
        ("--authority", "another-camera.test"),
        ("--ingress", "12"),
        ("--generation", "9"),
        ("--ssrc", "8"),
        ("--rtp-channel", "2"),
        ("--rtcp-channel", "3"),
        ("--receive-clock", other.as_str()),
        ("--retention-evidence", other.as_str()),
        ("--prefix-scope", other.as_str()),
    ] {
        let mut input = args()?;
        set(&mut input, key, value);
        assert!(
            Options::parse(&input).is_err(),
            "changed source silently accepted: {key}"
        );
    }
    let initial = Options::parse(&args()?)?;
    let mut changed = args()?;
    set(&mut changed, "--sensor-id", "sensor:owner-remapped-camera");
    let changed = Options::parse(&changed)?;
    assert_eq!(initial.request.pin, changed.request.pin);
    assert_ne!(initial.request.digest()?, changed.request.digest()?);
    Ok(())
}

#[test]
fn receive_time_preserves_i128_but_no_capture_origin_or_frame_rate_is_inferred() -> Test {
    let mut input = args()?;
    set(&mut input, "--receive-time-ns", "184467440737095516160");
    let options = Options::parse(&input)?;
    assert_eq!(options.request.receive_time.0, 184467440737095516160);
    assert!(
        options
            .preview()?
            .contains("\"capture_time_label\":\"unknown\"")
    );
    for (key, value) in [
        ("--receive-time-ns", "-1"),
        (
            "--receive-time-ns",
            "170141183460469231731687303715884105728",
        ),
        ("--capture-start-ns", "1000"),
        ("--capture-uncertainty-ns", "100"),
        ("--fps", "30"),
        ("--decode-work", "1000000"),
    ] {
        let mut changed = input.clone();
        set(&mut changed, key, value);
        assert!(Options::parse(&changed).is_err(), "{key}");
    }
    Ok(())
}

#[test]
fn ownership_original_reads_and_retention_remain_independently_required() -> Test {
    for key in [
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
        "--mapping-evidence",
    ] {
        let mut input = args()?;
        set(&mut input, key, "no");
        assert!(Options::parse(&input).is_err(), "{key}");
        let index = input
            .iter()
            .position(|arg| arg == key)
            .ok_or("fixture flag")?;
        input.drain(index..index + 2);
        assert!(Options::parse(&input).is_err(), "missing {key}");
    }
    Ok(())
}

#[test]
fn malformed_oversized_ambiguous_and_unbounded_requests_refuse_before_io() -> Test {
    for (key, value) in [
        ("--max-datagrams", "8193"),
        ("--prefix-datagrams", "0"),
        ("--prefix-bytes", "67108865"),
        ("--max-source-bytes", "67108865"),
        ("--max-original-bytes", "67108865"),
        ("--max-media-bytes", "67108865"),
        ("--max-read-bytes", "536870913"),
        ("--max-frames", "4097"),
        ("--max-steps", "262145"),
        ("--max-work", "0"),
        ("--timeout-ms", "600001"),
        ("--max-dimension", "2041"),
        ("--max-frame-bytes", "16777217"),
        ("--max-fragments", "4097"),
        ("--max-cached-quantizers", "128"),
        ("--frame-timeout-ms", "0"),
        ("--reorder-delay-ms", "60001"),
        ("--peer", "camera.test:554"),
        ("--peer", "0.0.0.0:554"),
        ("--authority", "user:secret@camera.test"),
        ("--ingress", "0"),
        ("--generation", "0"),
        ("--rtcp-channel", "0"),
        ("--reduced-rtcp", "auto"),
        ("--root", "/"),
        ("--root", "relative"),
        ("--root", "/absent-jpeg-import-fixture/source/nested"),
        ("--root", "/absent-jpeg-import-fixture/./destination"),
        ("--codec", "jpeg"),
        ("--credential-file", "/private/file"),
    ] {
        let mut input = args()?;
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}={value}");
    }
    let mut duplicate = args()?;
    duplicate.extend(["--sensor-id".into(), "sensor:duplicate".into()]);
    assert!(Options::parse(&duplicate).is_err());
    let mut malformed = args()?;
    malformed.push("--approve".into());
    assert!(Options::parse(&malformed).is_err());
    Ok(())
}
