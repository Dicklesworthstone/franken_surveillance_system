#![forbid(unsafe_code)]

use std::ffi::OsString;

use fss_core::ContentDigest;

use super::{driver, plan::Options};

fn args() -> Vec<OsString> {
    let digest = ContentDigest::sha256(b"rtsp-import-operator-fixture").to_text();
    [
        "--archive",
        "/absent-rtsp-import-fixture/source",
        "--root",
        "/absent-rtsp-import-fixture/destination",
        "--site",
        "site:test",
        "--window-slot",
        "recording-test",
        "--window-root",
        &digest,
        "--codec",
        "avc",
        "--sensor-id",
        "sensor:test",
        "--stream-id",
        "stream:test",
        "--generation",
        "1",
        "--anchor",
        &digest,
        "--receive-clock",
        &digest,
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
    .collect()
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(position) = args.iter().position(|argument| argument == key) {
        args[position + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn preview_is_pure_and_names_original_custody_and_native_timing() -> Result<(), &'static str> {
    let options = Options::parse(&args())?;
    let preview = options.preview()?;
    for expected in [
        "\"kind\":\"plan\"",
        "\"writes\":\"none\"",
        "\"network\":\"none\"",
        "\"capture_time_label\":\"unknown\"",
        "\"sample_timing\":\"retained_mp4_presentation_timestamps\"",
        "\"maximum_original_bytes\":33554432",
        "\"maximum_media_bytes\":33554432",
        "\"maximum_frames\":256",
    ] {
        assert!(preview.contains(expected), "{expected}");
    }
    assert!(preview.contains(&options.approval()?.to_text()));
    Ok(())
}

#[test]
fn exact_approval_binds_every_source_destination_and_work_choice() -> Result<(), &'static str> {
    let approved = Options::parse(&args())?.approval()?;
    let other = ContentDigest::sha256(b"other").to_text();
    for (key, value) in [
        ("--archive", "/absent-rtsp-import-fixture/other-source"),
        ("--root", "/absent-rtsp-import-fixture/other-destination"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
        ("--window-slot", "other-recording"),
        ("--window-root", other.as_str()),
        ("--codec", "hevc"),
        ("--sensor-id", "sensor:other"),
        ("--stream-id", "stream:other"),
        ("--generation", "2"),
        ("--anchor", other.as_str()),
        ("--receive-clock", other.as_str()),
        ("--receive-time-ns", "3000000000"),
        ("--max-frames", "32"),
        ("--max-original-bytes", "1048576"),
        ("--max-media-bytes", "2097152"),
        ("--max-work", "100000"),
        ("--timeout-ms", "1000"),
    ] {
        let mut changed = args();
        set(&mut changed, key, value);
        let mut options = Options::parse(&changed)?;
        assert_ne!(options.approval()?, approved, "{key}");
        options.approve = Some(approved);
        assert_eq!(
            driver::execute(&options).err(),
            Some("ERR-RTSP-IMPORT-APPROVAL-001"),
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn original_read_and_retention_are_independently_explicit() {
    for key in [
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
    ] {
        let mut input = args();
        set(&mut input, key, "no");
        assert!(Options::parse(&input).is_err(), "{key}");
        let position = input
            .iter()
            .position(|argument| argument == key)
            .expect("fixture");
        input.drain(position..position + 2);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
}

#[test]
fn timestamps_preserve_nonnegative_i128_and_capture_origin_is_complete() -> Result<(), &'static str>
{
    let mut input = args();
    set(&mut input, "--receive-time-ns", "184467440737095516160");
    let unhinted = Options::parse(&input)?;
    assert_eq!(unhinted.request.receive_time.0, 184467440737095516160);
    set(&mut input, "--capture-start-ns", "184467440736095516160");
    assert!(Options::parse(&input).is_err());
    set(&mut input, "--capture-uncertainty-ns", "1000");
    let hinted = Options::parse(&input)?;
    assert_ne!(hinted.approval()?, unhinted.approval()?);
    assert!(
        hinted
            .preview()?
            .contains("\"capture_time_label\":\"operator_assumption\"")
    );
    for (key, value) in [
        ("--receive-time-ns", "-1"),
        (
            "--receive-time-ns",
            "170141183460469231731687303715884105728",
        ),
        ("--capture-start-ns", "-1"),
        ("--capture-uncertainty-ns", "-1"),
    ] {
        let mut malformed = input.clone();
        set(&mut malformed, key, value);
        assert!(Options::parse(&malformed).is_err(), "{key}={value}");
    }
    Ok(())
}

#[test]
fn malformed_and_out_of_scope_inputs_refuse_before_io() {
    for (key, value) in [
        ("--codec", "auto"),
        ("--fps", "30"),
        ("--generation", "0"),
        ("--max-frames", "257"),
        ("--max-original-bytes", "33554433"),
        ("--max-media-bytes", "0"),
        ("--max-work", "0"),
        ("--timeout-ms", "600001"),
        ("--root", "/"),
        ("--root", "/absent-rtsp-import-fixture/source/nested"),
        ("--root", "/absent-rtsp-import-fixture/source"),
        ("--root", "/absent-rtsp-import-fixture/./destination"),
        ("--root", "relative"),
        ("--window-slot", "../escape"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}={value}");
    }
    let mut duplicate = args();
    duplicate.extend([OsString::from("--codec"), OsString::from("hevc")]);
    assert!(Options::parse(&duplicate).is_err());
    let mut unknown = args();
    unknown.extend([
        OsString::from("--url"),
        OsString::from("rtsp://example.invalid"),
    ]);
    assert!(Options::parse(&unknown).is_err());
}

fn catalog_args() -> Vec<OsString> {
    let mut input = args();
    for (old, new) in [
        ("--window-slot", "--catalog-slot"),
        ("--window-root", "--catalog-root"),
    ] {
        let position = input
            .iter()
            .position(|argument| argument == old)
            .expect("fixture");
        input[position] = new.into();
    }
    set(
        &mut input,
        "--decode-clock",
        &ContentDigest::sha256(b"explicit-decode-clock").to_text(),
    );
    set(&mut input, "--time-scale", "90000");
    input
}

#[test]
fn whole_catalog_preview_and_approval_bind_exact_clock_and_cumulative_bounds()
-> Result<(), &'static str> {
    let initial = Options::parse(&catalog_args())?;
    let approved = initial.approval()?;
    assert!(initial.catalog.is_some());
    let preview = initial.preview()?;
    for expected in [
        "\"maximum_windows\":64",
        "\"maximum_frames\":16384",
        "\"maximum_original_bytes\":134217728",
        "\"maximum_media_bytes\":67108864",
        "\"selection\":\"complete_catalog_page\"",
        "\"writes\":\"none\"",
    ] {
        assert!(preview.contains(expected), "{expected}");
    }
    assert!(!preview.contains("\"window_root\""));
    let other = ContentDigest::sha256(b"other-catalog-clock").to_text();
    for (key, value) in [
        ("--decode-clock", other.as_str()),
        ("--time-scale", "45000"),
        ("--max-windows", "2"),
        ("--max-frames", "320"),
        ("--max-original-bytes", "33554432"),
        ("--catalog-slot", "other-catalog"),
    ] {
        let mut input = catalog_args();
        set(&mut input, key, value);
        let mut options = Options::parse(&input)?;
        assert_ne!(options.approval()?, approved, "{key}");
        options.approve = Some(approved);
        assert_eq!(
            driver::execute(&options).err(),
            Some("ERR-RTSP-IMPORT-APPROVAL-001")
        );
    }
    Ok(())
}

#[test]
fn incomplete_mixed_or_oversized_catalog_selection_refuses_before_io() {
    for key in [
        "--catalog-slot",
        "--catalog-root",
        "--decode-clock",
        "--time-scale",
    ] {
        let mut input = catalog_args();
        let at = input.iter().position(|a| a == key).expect("fixture");
        input.drain(at..at + 2);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
    for (key, value) in [
        ("--window-slot", "window"),
        ("--max-windows", "65"),
        ("--max-frames", "16385"),
        ("--max-media-bytes", "67108865"),
        ("--max-original-bytes", "134217729"),
        ("--time-scale", "0"),
    ] {
        let mut input = catalog_args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
    let mut window = args();
    set(
        &mut window,
        "--decode-clock",
        &ContentDigest::sha256(b"clock").to_text(),
    );
    assert!(Options::parse(&window).is_err());
}

fn page_args() -> Vec<OsString> {
    let mut input = catalog_args();
    for key in ["--catalog-slot", "--catalog-root"] {
        let index = input
            .iter()
            .position(|argument| argument == key)
            .expect("catalog fixture");
        input.drain(index..index + 2);
    }
    let first = ContentDigest::sha256(b"first exact page").to_text();
    let second = ContentDigest::sha256(b"second exact page").to_text();
    set(
        &mut input,
        "--catalog-pages",
        &format!("first-page@{first},second-page@{second}"),
    );
    input
}

#[test]
fn complete_page_list_preview_binds_every_pin_order_and_cumulative_page_bound()
-> Result<(), &'static str> {
    let original = Options::parse(&page_args())?;
    let approval = original.approval()?;
    assert!(original.catalog.is_none());
    assert_eq!(original.pages.as_ref().ok_or("pages")?.pages.len(), 2);
    let preview = original.preview()?;
    for expected in [
        "\"format\":\"fss.rtsp_catalog_pages_import_operator.v1\"",
        "\"selection\":\"complete_ordered_catalog_pages\"",
        "\"pages\":2",
        "\"maximum_pages\":64",
        "\"maximum_windows\":64",
        "\"maximum_frames\":16384",
        "\"slot\":\"first-page\"",
        "\"slot\":\"second-page\"",
        "\"writes\":\"none\"",
    ] {
        assert!(preview.contains(expected), "{expected}");
    }
    let first = ContentDigest::sha256(b"first exact page").to_text();
    let second = ContentDigest::sha256(b"second exact page").to_text();
    let other = ContentDigest::sha256(b"other exact page").to_text();
    for (key, value) in [
        (
            "--catalog-pages",
            format!("second-page@{second},first-page@{first}"),
        ),
        (
            "--catalog-pages",
            format!("first-page@{first},second-page@{other}"),
        ),
        (
            "--catalog-pages",
            format!("first-page@{first},other-slot@{second}"),
        ),
        ("--max-pages", "2".into()),
        ("--decode-clock", other),
        ("--max-windows", "2".into()),
        ("--max-frames", "8".into()),
        ("--max-original-bytes", "1048576".into()),
        ("--max-media-bytes", "1048576".into()),
    ] {
        let mut input = page_args();
        set(&mut input, key, &value);
        let mut changed = Options::parse(&input)?;
        assert_ne!(changed.approval()?, approval, "{key}");
        changed.approve = Some(approval);
        assert_eq!(
            driver::execute(&changed).err(),
            Some("ERR-RTSP-IMPORT-APPROVAL-001")
        );
    }
    Ok(())
}

#[test]
fn all_sixty_four_maximum_length_page_pins_fit_the_bounded_cli_and_preview()
-> Result<(), &'static str> {
    use super::plan::MAX_PAGE_ARGUMENT_BYTES;
    use fss_publication::MAX_SLOT_NAME_BYTES;
    let entries: Vec<_> = (0..64_u32)
        .map(|index| {
            let slot = format!("{index:03}{}", "a".repeat(MAX_SLOT_NAME_BYTES - 3));
            format!(
                "{slot}@{}",
                ContentDigest::sha256(&index.to_be_bytes()).to_text()
            )
        })
        .collect();
    let all = entries.join(",");
    assert_eq!(all.len(), MAX_PAGE_ARGUMENT_BYTES);
    assert!(all.len() > 4096);
    let mut input = page_args();
    set(&mut input, "--catalog-pages", &all);
    // Accepted path strings can contain JSON-escaped quotes, so preview has an independent64KiB
    // output envelope; a complete maximum page list must never be silently omitted to fit it.
    set(&mut input, "--archive", &format!("/{}", "\"".repeat(4095)));
    set(&mut input, "--root", &format!("/{}", "b".repeat(4095)));
    let options = Options::parse(&input)?;
    assert_eq!(options.pages.as_ref().ok_or("pages")?.pages.len(), 64);
    let preview = options.preview()?;
    assert!(preview.len() > 16 * 1024);
    assert!(preview.len() < 64 * 1024);
    assert_eq!(preview.matches("\"slot\":").count(), 64);
    set(
        &mut input,
        "--catalog-pages",
        &format!("{all},{}", entries[0]),
    );
    assert!(Options::parse(&input).is_err());
    set(&mut input, "--catalog-pages", &all);
    set(&mut input, "--archive", &format!("/{}", "a".repeat(4096)));
    assert!(Options::parse(&input).is_err());
    Ok(())
}

#[test]
fn malformed_duplicate_or_mixed_page_lists_refuse_before_io() {
    let first = ContentDigest::sha256(b"first exact page").to_text();
    let second = ContentDigest::sha256(b"second exact page").to_text();
    for value in [
        format!("a@{first},a@{second}"),
        format!("a@{first},b@{first}"),
        format!("a@{first},"),
        format!(",a@{first}"),
        format!("a@{first},,{second}"),
        format!("../page@{first}"),
        format!("a@@{first}"),
        format!("a@{first}@extra"),
        format!("a@sha256:{}", "0".repeat(64)),
    ] {
        let mut input = page_args();
        set(&mut input, "--catalog-pages", &value);
        assert!(Options::parse(&input).is_err(), "{value}");
    }
    for (key, value) in [
        ("--window-slot", "window"),
        ("--window-root", first.as_str()),
        ("--catalog-slot", "catalog"),
        ("--catalog-root", first.as_str()),
        ("--max-pages", "0"),
        ("--max-pages", "1"),
        ("--max-pages", "65"),
        ("--max-windows", "1"),
    ] {
        let mut input = page_args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}={value}");
    }
    for mut input in [args(), catalog_args()] {
        set(&mut input, "--max-pages", "64");
        assert!(Options::parse(&input).is_err());
    }
}
