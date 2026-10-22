#![forbid(unsafe_code)]
//! Exact pure admission, explicit model authority and independent nonrenewable resource bounds.

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;

use super::{driver, model, plan};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = "/missing/fss-campaign-sentinel-destination";
const SITE: &str = "site:campaign-sentinel-test";
const PRINCIPAL: &str = "principal:local-operator";

fn hash(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn child(ordinal: usize) -> Vec<String> {
    [
        (
            "--archive",
            format!("/missing/fss-campaign-sentinel-source-{ordinal}"),
        ),
        ("--root", ROOT.into()),
        ("--site", SITE.into()),
        ("--principal", PRINCIPAL.into()),
        ("--codec", "avc".into()),
        ("--catalog-slot", format!("catalog-{ordinal}")),
        ("--catalog-root", hash(&format!("catalog-{ordinal}"))),
        ("--decode-clock", hash(&format!("decode-{ordinal}"))),
        ("--time-scale", "90000".into()),
        ("--sensor-id", "sensor:sentinel".into()),
        ("--stream-id", "stream:sentinel".into()),
        ("--generation", ordinal.to_string()),
        ("--anchor", hash("source-authority")),
        ("--receive-clock", hash(&format!("receive-{ordinal}"))),
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

fn args(children: &[Option<Vec<String>>]) -> Vec<OsString> {
    let requests = children
        .iter()
        .enumerate()
        .map(|(index, child)| {
            object(&[
                ("ordinal", (index + 1).to_string()),
                (
                    "request",
                    child.as_ref().map_or_else(
                        || "null".into(),
                        |child| array(&child.iter().map(|value| string(value)).collect::<Vec<_>>()),
                    ),
                ),
            ])
        })
        .collect::<Vec<_>>();
    [
        ("--root", ROOT.into()),
        ("--site", SITE.into()),
        ("--principal", PRINCIPAL.into()),
        (
            "--history-root",
            "/missing/fss-campaign-sentinel-history".into(),
        ),
        ("--history-approval", hash("history-approval")),
        ("--history-plan", hash("history-plan")),
        ("--history-root-digest", hash("history-root")),
        ("--history-records", "5".into()),
        ("--requests", array(&requests)),
        ("--interpretation", "ycbcr".into()),
        (
            "--package",
            "/missing/fss-campaign-sentinel-model.fmpk".into(),
        ),
        ("--package-digest", hash("native-rgb-model")),
        ("--read-model", "yes".into()),
        ("--retain-analysis", "yes".into()),
        ("--sentinel-every-frames", "4".into()),
        ("--sentinel-burst-frames", "2".into()),
        ("--sentinel-max-inferences", "4".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ]
    .into_iter()
    .flat_map(|(key, value): (&str, String)| [key.into(), OsString::from(value)])
    .collect()
}

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|part| part == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or("missing fixture field")?)
}

#[test]
fn missing_paths_allow_pure_null_and_mixed_previews_but_never_unapproved_io() -> Test {
    for children in [vec![None], vec![Some(child(1)), None, Some(child(3))]] {
        let mut options = plan::Options::parse(&args(&children))?;
        let preview = parse(&options.preview()?)?;
        assert_eq!(
            field(&preview, "writes")?.text(),
            Some("none_until_exact_outer_approval")
        );
        assert_eq!(field(&preview, "network")?.text(), Some("none"));
        assert_eq!(field(&preview, "event_publication")?.boolean(), Some(false));
        assert_eq!(
            field(field(&preview, "sampling")?, "motion_independent")?.boolean(),
            Some(true)
        );
        assert_eq!(
            field(field(&preview, "package")?, "verified")?.boolean(),
            Some(false)
        );
        assert_eq!(
            field(&preview, "attempts")?
                .array()
                .ok_or("attempts")?
                .len(),
            children.len()
        );
        assert_eq!(
            field(
                field(&preview, "reserved_whole_campaign")?,
                "selected_archives"
            )?
            .integer(),
            Some(children.iter().filter(|child| child.is_some()).count() as i128)
        );
        assert_eq!(
            driver::execute(&options),
            Err("ERR-RTSP-CAMPAIGN-SENTINEL-AUTHORITY-001")
        );
        options.input.approve = Some(ContentDigest::sha256(b"not the exact approval"));
        assert_eq!(
            driver::execute(&options),
            Err("ERR-RTSP-CAMPAIGN-SENTINEL-AUTHORITY-001")
        );
    }
    Ok(())
}

#[test]
fn approval_binds_model_retention_native_schedule_and_every_shared_admission_ceiling() -> Test {
    let input = args(&[Some(child(1)), None]);
    let original = plan::Options::parse(&input)?.approval()?;
    for (key, value) in [
        ("--package", "/missing/other-native-model.fmpk".into()),
        ("--package-digest", hash("other-model")),
        ("--retain-analysis", "no".into()),
        ("--kernels", "scalar-reference".into()),
        ("--threads", "2".into()),
        ("--minimum-score-ppm", "500000".into()),
        ("--sentinel-every-frames", "8".into()),
        ("--sentinel-burst-frames", "1".into()),
        ("--sentinel-max-inferences", "6".into()),
        ("--stream-read-bytes", "1048576".into()),
        ("--stream-pixel-budget", "1048576".into()),
        ("--max-frame-pixels", "20481".into()),
        ("--max-macs", "7999999999".into()),
        ("--max-tensor-bytes", "16777216".into()),
        ("--max-output-bytes", "1048576".into()),
        ("--sentinel-report-bytes", "1048576".into()),
        ("--max-report-bytes", "2097152".into()),
        ("--archive-read-bytes", "999999999".into()),
        ("--max-work", "999999999999".into()),
        ("--timeout-ms", "60000".into()),
        ("--history-approval", hash("other-approval")),
        ("--history-plan", hash("other-plan")),
        ("--history-root-digest", hash("other-history-root")),
        ("--history-records", "4".into()),
        ("--history-root", "/missing/other-history".into()),
        ("--history-max-records", "32".into()),
        ("--history-object-bytes", "131072".into()),
        ("--history-max-scan-entries", "2048".into()),
        ("--history-metadata-bytes", "8388608".into()),
        ("--history-storage-bytes", "16777216".into()),
    ] {
        let mut changed = input.clone();
        set(&mut changed, key, &value);
        assert_ne!(
            plan::Options::parse(&changed)?.approval()?,
            original,
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn consent_schedule_native_scope_and_numeric_threads_are_explicit_without_foreground_options() {
    for key in [
        "--read-model",
        "--retain-analysis",
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
        "--sentinel-every-frames",
        "--sentinel-burst-frames",
        "--sentinel-max-inferences",
    ] {
        let mut missing = args(&[None]);
        let at = missing
            .iter()
            .position(|part| part == key)
            .expect("required fixture key");
        missing.drain(at..at + 2);
        assert!(plan::Options::parse(&missing).is_err(), "missing {key}");
    }
    for (key, value) in [
        ("--read-model", "no"),
        ("--retain-analysis", "perhaps"),
        ("--interpretation", "rgb"),
        ("--threads", "auto"),
        ("--sentinel-burst-frames", "5"),
        ("--sentinel-max-inferences", "1"),
        ("--package", "relative.fmpk"),
        ("--zone", "entry:0,0,16,16"),
        ("--pixel-threshold", "1"),
        ("--tolerate-decode-refusals", "yes"),
    ] {
        let mut changed = args(&[None]);
        set(&mut changed, key, value);
        assert!(plan::Options::parse(&changed).is_err(), "{key}");
    }
    for (key, value) in [
        ("--root", "/missing/other-destination"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
        ("--max-work", "1"),
        ("--timeout-ms", "1000"),
        (
            "--approve",
            "sha256:abababababababababababababababababababababababababababababababab",
        ),
    ] {
        let mut native = child(1);
        if let Some(at) = native.iter().position(|part| part == key) {
            native[at + 1] = value.into();
        } else {
            native.extend([key.into(), value.into()]);
        }
        assert!(
            plan::Options::parse(&args(&[Some(native)])).is_err(),
            "child {key}"
        );
    }
}

#[test]
fn whole_campaign_output_and_mac_sums_refuse_overflow_before_any_io() -> Test {
    let mut input = args(&[Some(child(1)), Some(child(2))]);
    set(&mut input, "--sentinel-max-inferences", "1024");
    assert!(
        plan::Options::parse(&input).is_err(),
        "16 GiB implicit output must refuse"
    );
    set(&mut input, "--max-output-bytes", "1048576");
    let options = plan::Options::parse(&input)?;
    assert_eq!(
        options
            .plan
            .reservation(&options.limits)?
            .inference
            .output_bytes,
        1024 * 1024 * 1024
    );
    set(&mut input, "--max-macs", &u64::MAX.to_string());
    assert!(
        plan::Options::parse(&input).is_err(),
        "aggregate MAC multiplication overflow"
    );
    Ok(())
}

#[test]
fn original_archive_and_model_paths_are_part_of_the_exact_outer_approval() -> Test {
    let input = args(&[Some(child(1))]);
    let original = plan::Options::parse(&input)?.approval()?;
    for (key, value) in [
        ("--archive", "/missing/other-archive".into()),
        ("--catalog-root", hash("different-catalog")),
        ("--receive-clock", hash("different-receive")),
        ("--decode-clock", hash("different-decode")),
        ("--anchor", hash("different-original-owner")),
        ("--capture-start-ns", "1000".into()),
        ("--capture-uncertainty-ns", "2000".into()),
    ] {
        let mut native = child(1);
        let at = native
            .iter()
            .position(|part| part == key)
            .ok_or("fixture child key")?;
        native[at + 1] = value;
        assert_ne!(
            plan::Options::parse(&args(&[Some(native)]))?.approval()?,
            original,
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn model_read_refuses_revoked_owner_and_work_before_missing_path_observation() {
    let missing = Path::new("/missing/fss-sentinel-unapproved-model.fmpk");
    let expected = ContentDigest::sha256(b"model");
    let mut work = WorkBudget::new(1_000_000);
    assert_eq!(
        model::read(missing, expected, &|| Err("owner-revoked"), &mut work),
        Err("owner-revoked")
    );
    assert_eq!(work.used(), 0);
    let mut work = WorkBudget::new(0);
    assert_eq!(
        model::read(missing, expected, &|| Ok(()), &mut work),
        Err("ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001")
    );
}

#[test]
fn bounded_model_read_verifies_exact_bytes_and_current_authority() -> Test {
    let directory = std::env::temp_dir().join(format!(
        "fss-campaign-sentinel-model-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let result = (|| {
        let path = directory.join("pinned.fmpk");
        let bytes = vec![91_u8; 128 * 1024 + 3];
        std::fs::write(&path, &bytes)?;
        let expected = ContentDigest::sha256(&bytes);
        assert_eq!(
            model::read(&path, expected, &|| Ok(()), &mut WorkBudget::new(1_000_000))?,
            bytes
        );
        assert_eq!(
            model::read(
                &path,
                ContentDigest::sha256(b"other model"),
                &|| Ok(()),
                &mut WorkBudget::new(1_000_000)
            ),
            Err("ERR-RTSP-CAMPAIGN-SENTINEL-PACKAGE-001")
        );
        let calls = AtomicUsize::new(0);
        let owner = || {
            if calls.fetch_add(1, Ordering::Relaxed) < 5 {
                Ok(())
            } else {
                Err("owner-revoked")
            }
        };
        assert_eq!(
            model::read(&path, expected, &owner, &mut WorkBudget::new(1_000_000)),
            Err("owner-revoked")
        );
        #[cfg(unix)]
        {
            let alias = directory.join("alias.fmpk");
            std::os::unix::fs::symlink(&path, &alias)?;
            assert_eq!(
                model::read(
                    &alias,
                    expected,
                    &|| Ok(()),
                    &mut WorkBudget::new(1_000_000)
                ),
                Err("ERR-RTSP-CAMPAIGN-SENTINEL-PACKAGE-001")
            );
        }
        Ok(())
    })();
    std::fs::remove_dir_all(directory)?;
    result
}
