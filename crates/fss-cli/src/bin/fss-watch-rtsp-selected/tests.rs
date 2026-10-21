#![forbid(unsafe_code)]
//! Exact approval and native end-to-end execution, without substituting custody or analysis.

use std::ffi::OsString;

use fss_cli::agent_json::{array, string};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

use super::{driver, plan};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn hash(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn child(index: u64) -> Vec<String> {
    [
        ("--archive", "/missing/fss-selected-rtsp-source".into()),
        ("--root", "/missing/fss-selected-rtsp-destination".into()),
        ("--site", "site:selected-watch-test".into()),
        ("--codec", "avc".into()),
        ("--window-slot", format!("selected-{index}")),
        ("--window-root", hash(&format!("root-{index}"))),
        ("--sensor-id", "sensor:selected-watch-test".into()),
        ("--stream-id", "stream:selected-watch-test".into()),
        ("--generation", index.to_string()),
        ("--anchor", hash("source-authority")),
        ("--receive-clock", hash("source-clock")),
        ("--receive-time-ns", "5000000000".into()),
        ("--capture-start-ns", "0".into()),
        ("--capture-uncertainty-ns", "1000".into()),
        ("--max-frames", "3".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ]
    .into_iter()
    .flat_map(|(key, value)| [key.to_owned(), value])
    .collect()
}

fn args(children: &[Vec<String>]) -> Vec<OsString> {
    let requests = array(
        &children
            .iter()
            .map(|child| array(&child.iter().map(|value| string(value)).collect::<Vec<_>>()))
            .collect::<Vec<_>>(),
    );
    [
        "--requests",
        &requests,
        "--interpretation",
        "ycbcr",
        "--zone",
        "entry:0,0,16,16",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn set(child: &mut [String], key: &str, value: &str) {
    let at = child
        .iter()
        .position(|text| text == key)
        .expect("fixture option");
    child[at + 1] = value.into();
}

fn omit(child: &mut Vec<String>, key: &str) {
    let at = child
        .iter()
        .position(|text| text == key)
        .expect("fixture option");
    child.drain(at..at + 2);
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|object| object.get(name))
        .ok_or("missing report field")?)
}

#[test]
fn preview_and_wrong_approval_need_no_existing_source_or_destination() -> Test {
    let mut options = plan::Options::parse(&args(&[child(1), child(2)]))?;
    let value = parse(&options.preview()?)?;
    assert_eq!(field(&value, "kind")?.text(), Some("plan"));
    assert_eq!(field(&value, "event_publication")?.boolean(), Some(false));
    assert_eq!(
        field(&value, "complete_history_claim")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(&value, "tracking_between_selections")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(field(&value, "reserved_whole_selection")?, "selections")?.integer(),
        Some(2)
    );
    assert_eq!(
        field(field(&value, "reserved_whole_selection")?, "frames")?.integer(),
        Some(6)
    );
    assert_eq!(
        field(
            field(&value, "reserved_whole_selection")?,
            "screening_pixel_samples"
        )?
        .integer(),
        Some(0)
    );
    assert_eq!(
        driver::execute(&options),
        Err("ERR-RTSP-SELECTED-WATCH-AUTHORITY-001")
    );
    options.approve = Some(ContentDigest::sha256(b"different-plan"));
    assert_eq!(
        driver::execute(&options),
        Err("ERR-RTSP-SELECTED-WATCH-AUTHORITY-001")
    );
    Ok(())
}

#[test]
fn approval_binds_every_ordered_source_pin_owner_timing_and_execution_allowance() -> Test {
    let children = vec![child(1), child(2)];
    let original = plan::Options::parse(&args(&children))?.approval()?;
    let mut reversed = children.clone();
    reversed.reverse();
    assert_ne!(
        plan::Options::parse(&args(&reversed))?.approval()?,
        original
    );
    for (key, replacement) in [
        ("--window-root", hash("replacement-root")),
        ("--window-slot", "other-window".into()),
        ("--anchor", hash("replacement-authority")),
        ("--receive-clock", hash("replacement-clock")),
        ("--generation", "3".into()),
        ("--capture-start-ns", "1000000000".into()),
        ("--capture-uncertainty-ns", "2000".into()),
        ("--receive-time-ns", "6000000000".into()),
        ("--max-frames", "4".into()),
    ] {
        let mut changed = children.clone();
        set(&mut changed[1], key, &replacement);
        assert_ne!(
            plan::Options::parse(&args(&changed))?.approval()?,
            original,
            "{key}"
        );
    }
    for (key, replacement) in [
        ("--max-work", "123456789"),
        ("--timeout-ms", "12345"),
        ("--max-report-bytes", "1048576"),
        ("--stream-read-bytes", "1048576"),
        ("--stream-pixel-budget", "1048576"),
        ("--stream-assignment-work", "1048576"),
        ("--stream-trace-bytes", "1048576"),
        ("--confirmation-hits", "2"),
        ("--screened", "yes"),
        ("--tolerate-decode-refusals", "yes"),
    ] {
        let mut changed = args(&children);
        changed.extend([OsString::from(key), OsString::from(replacement)]);
        assert_ne!(
            plan::Options::parse(&changed)?.approval()?,
            original,
            "{key}"
        );
    }
    for (key, replacement) in [
        ("--archive", "/missing/another-source"),
        ("--root", "/missing/another-destination"),
        ("--site", "site:other-selected-watch"),
    ] {
        let mut changed = children.clone();
        for child in &mut changed {
            set(child, key, replacement);
        }
        assert_ne!(
            plan::Options::parse(&args(&changed))?.approval()?,
            original,
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn incomplete_authority_duplicates_and_per_child_budget_refills_are_refused() {
    for key in [
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
    ] {
        let mut request = child(1);
        set(&mut request, key, "no");
        assert!(plan::Options::parse(&args(&[request])).is_err());
    }
    let mut request = child(1);
    omit(&mut request, "--capture-start-ns");
    omit(&mut request, "--capture-uncertainty-ns");
    assert!(plan::Options::parse(&args(&[request])).is_err());
    for (key, value) in [
        ("--max-work", "1"),
        ("--timeout-ms", "1"),
        ("--approve", &hash("child-approval")),
    ] {
        let mut request = child(1);
        request.extend([key.into(), value.into()]);
        assert!(plan::Options::parse(&args(&[request])).is_err());
    }
    assert!(plan::Options::parse(&args(&[child(1), child(1)])).is_err());
    assert!(plan::Options::parse(&args(&[])).is_err());
    assert!(plan::Options::parse(&args(&(1..=17).map(child).collect::<Vec<_>>())).is_err());
    for key in ["--archive", "--root", "--site"] {
        let mut second = child(2);
        set(
            &mut second,
            key,
            if key == "--site" {
                "site:other"
            } else {
                "/missing/other"
            },
        );
        assert!(plan::Options::parse(&args(&[child(1), second])).is_err());
    }
}

#[test]
fn whole_selection_reservations_refuse_overflow_before_any_effect() -> Test {
    let mut input = args(&[child(1), child(2)]);
    input.extend(["--stream-pixel-budget".into(), u64::MAX.to_string().into()]);
    assert!(plan::Options::parse(&input).is_err());
    let input = args(&(1..=16).map(child).collect::<Vec<_>>());
    let options = plan::Options::parse(&input)?;
    let reserved = options.plan.reservation(&options.limits)?;
    assert_eq!(reserved.selections, 16);
    assert_eq!(
        reserved.source_read_bytes,
        options.limits.watch.maximum_source_chunk_bytes * 16
    );
    assert_eq!(
        reserved.trace_bytes,
        options.limits.watch.maximum_trace_bytes as u64 * 16
    );
    assert_eq!(reserved.screening_pixel_samples, 0);
    assert!(options.preview()?.len() <= plan::MAX_PREVIEW_BYTES);
    let mut input = input;
    input.extend(["--screened".into(), "yes".into()]);
    let screened = plan::Options::parse(&input)?;
    let screened_reserve = screened.plan.reservation(&screened.limits)?;
    assert_eq!(screened_reserve.pixel_samples, reserved.pixel_samples);
    assert_eq!(
        screened_reserve.screening_pixel_samples,
        reserved.pixel_samples
    );
    let preview = parse(&screened.preview()?)?;
    assert_eq!(
        field(
            field(&preview, "reserved_whole_selection")?,
            "screening_pixel_samples"
        )?
        .integer(),
        Some(i128::from(reserved.pixel_samples))
    );
    Ok(())
}

#[test]
fn coded_picture_admission_never_rounds_above_the_approved_pixel_ceiling() -> Test {
    for pixels in [0, 1, 255] {
        let mut input = args(&[child(1)]);
        input.extend(["--max-pixels".into(), pixels.to_string().into()]);
        assert!(plan::Options::parse(&input).is_err());
    }
    for (pixels, macroblocks) in [(256, 1), (257, 1), (511, 1), (512, 2)] {
        let mut input = args(&[child(1)]);
        input.extend(["--max-pixels".into(), pixels.to_string().into()]);
        let options = plan::Options::parse(&input)?;
        let limits = options.limits.watch.decode;
        assert_eq!(limits.h264_limits.max_macroblocks, macroblocks);
        assert!(u64::from(limits.h264_limits.max_macroblocks) * 256 <= pixels);
        assert_eq!(limits.h265_limits.max_luma_samples, pixels);
        let preview = parse(&options.preview()?)?;
        let configuration = field(&preview, "watch_configuration")?;
        assert_eq!(
            field(configuration, "avc_coded_pixel_ceiling")?.integer(),
            Some(i128::from(macroblocks) * 256)
        );
        assert_eq!(
            field(configuration, "hevc_coded_pixel_ceiling")?.integer(),
            Some(i128::from(pixels))
        );
    }
    Ok(())
}

#[test]
fn native_window_catalog_and_page_selectors_remain_distinct_and_exact() -> Test {
    let window = child(1);
    let mut catalog = child(2);
    set(&mut catalog, "--window-slot", "catalog-two");
    let at = catalog
        .iter()
        .position(|key| key == "--window-slot")
        .ok_or("selector")?;
    catalog[at] = "--catalog-slot".into();
    let at = catalog
        .iter()
        .position(|key| key == "--window-root")
        .ok_or("selector")?;
    catalog[at] = "--catalog-root".into();
    catalog.extend([
        "--decode-clock".into(),
        hash("decode-clock"),
        "--time-scale".into(),
        "90000".into(),
    ]);
    let mut pages = catalog.clone();
    omit(&mut pages, "--catalog-slot");
    omit(&mut pages, "--catalog-root");
    pages.extend([
        "--catalog-pages".into(),
        format!("page-a@{},page-b@{}", hash("page-a"), hash("page-b")),
    ]);
    let options = plan::Options::parse(&args(&[window, catalog, pages]))?;
    assert_eq!(
        options
            .plan
            .selections
            .iter()
            .map(|selected| selected.kind())
            .collect::<Vec<_>>(),
        ["window", "catalog", "pages"]
    );
    assert_eq!(options.plan.reservation(&options.limits)?.selections, 3);
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "native_tests.rs"]
mod native;
