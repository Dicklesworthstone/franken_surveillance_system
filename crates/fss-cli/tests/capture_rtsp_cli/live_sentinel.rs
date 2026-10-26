#![forbid(unsafe_code)]
//! One approved native camera capture reaches retained, independently replayable detector
//! evidence. Real loopback RTP and the pinned local detector exercise the complete composition.
//! This establishes custody and execution wiring, not detector calibration or threat quality.

use super::*;
use std::path::Path;

const FORMAT: &str = "fss.rtsp_capture_sentinel_cli.v1";
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const INFERENCE_DEADLINE: Duration = Duration::from_secs(180);

fn deployment(directory: &Directory) -> PathBuf {
    directory.0.join("live detector deployment")
}

fn model_path(directory: &Directory) -> PathBuf {
    directory.0.join("operator's pinned detector.fmpk")
}

fn model(directory: &Directory) -> Test<PathBuf> {
    let path = model_path(directory);
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk"),
        &path,
    )?;
    assert_eq!(
        ContentDigest::sha256(&fs::read(&path)?).to_text(),
        PACKAGE_DIGEST
    );
    Ok(path)
}

fn input(directory: &Directory, peer: SocketAddr) -> Vec<OsString> {
    let mut input = vec!["sentinel".into()];
    input.extend(args(directory, peer, 2));
    for (key, value) in [
        (
            "--deployment-root",
            deployment(directory).display().to_string(),
        ),
        ("--site", SITE.to_owned()),
        ("--receive-time-ns", "5000000000".to_owned()),
        ("--capture-start-ns", "1000000000".to_owned()),
        ("--capture-uncertainty-ns", "1000".to_owned()),
        ("--package", model_path(directory).display().to_string()),
        ("--package-digest", PACKAGE_DIGEST.to_owned()),
        ("--read-originals", "yes".to_owned()),
        ("--read-model", "yes".to_owned()),
        ("--execute-perception", "yes".to_owned()),
        ("--retain-analysis", "yes".to_owned()),
        ("--sentinel-every-frames", "1".to_owned()),
        ("--sentinel-burst-frames", "1".to_owned()),
        ("--sentinel-max-inferences", "1".to_owned()),
        ("--analysis-timeout-ms", "600000".to_owned()),
    ] {
        input.extend([key.into(), value.into()]);
    }
    input
}

fn preview(input: &[OsString]) -> Test<Value> {
    let preview = parse(&good(run("capture", input)?)?)?;
    assert_eq!(text(&preview, "schema")?, FORMAT);
    assert_eq!(text(&preview, "phase")?, "planned");
    ContentDigest::parse(text(&preview, "approval")?)?;
    Ok(preview)
}

fn approved(input: &[OsString]) -> Test<Vec<OsString>> {
    let mut approved = input.to_vec();
    approved.extend([
        "--approve".into(),
        text(&preview(input)?, "approval")?.into(),
    ]);
    Ok(approved)
}

fn transcript(output: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| parse(line).map_err(Into::into))
        .collect()
}

fn capture(
    camera: &TcpListener,
    input: &[OsString],
    behavior: Behavior,
) -> Test<(Output, Transcript)> {
    let camera = camera.try_clone()?;
    thread::scope(|scope| {
        let server = scope.spawn(move || serve(camera, behavior));
        let output = run_with_timeout("capture", input, INFERENCE_DEADLINE);
        let server = server.join().map_err(|_| "live sentinel camera panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "{error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
            (Err(error), _) => Err(error),
        }
    })
}

#[test]
fn live_sentinel_preview_is_pure_and_binds_camera_model_sampling_and_time() -> Test {
    let directory = Directory::new("live-sentinel-preview")?;
    let camera = listener()?;
    let input = input(&directory, camera.local_addr()?);
    let original = preview(&input)?;
    let approval = text(&original, "approval")?;
    for (key, replacement) in [
        ("--sentinel-every-frames", "2".to_owned()),
        ("--capture-start-ns", "2000000000".to_owned()),
        ("--package-digest", digest("different model")),
        (
            "--deployment-root",
            directory.0.join("other deployment").display().to_string(),
        ),
    ] {
        let mut changed = input.clone();
        replace(&mut changed, key, &replacement)?;
        assert_ne!(
            text(&preview(&changed)?, "approval")?,
            approval,
            "unbound {key}"
        );
        changed.extend(["--approve".into(), approval.into()]);
        assert!(!run("capture", &changed)?.status.success());
    }
    no_connection(&camera)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    assert!(!deployment(&directory).exists());
    assert!(!model_path(&directory).exists());
    Ok(())
}

#[test]
fn live_sentinel_refuses_unverified_model_before_capture_or_retention() -> Test {
    let directory = Directory::new("live-sentinel-package-refusal")?;
    let camera = listener()?;
    let input = input(&directory, camera.local_addr()?);
    let approved = approved(&input)?;
    let missing = run("capture", &approved)?;
    assert!(!missing.status.success());
    fs::write(model_path(&directory), b"not the approved package")?;
    let changed = run("capture", &approved)?;
    assert!(!changed.status.success());
    no_connection(&camera)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    assert!(!deployment(&directory).exists());
    Ok(())
}

#[test]
fn live_sentinel_captures_once_retains_native_detection_and_replays_without_camera() -> Test {
    let directory = Directory::new("live-sentinel-retained")?;
    let camera = listener()?;
    let model = model(&directory)?;
    let approved = approved(&input(&directory, camera.local_addr()?))?;
    let (output, observed) = capture(&camera, &approved, Behavior::StaticTarget)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(observed.pictures, 2);
    assert_eq!(
        observed
            .methods
            .iter()
            .filter(|method| *method == "PLAY")
            .count(),
        1
    );
    let rows = transcript(&output)?;
    let retained = detail(&rows, "sentinel_retained")?;
    ContentDigest::parse(text(retained, "import_identity")?)?;
    let report = text(retained, "report_digest")?.to_owned();
    ContentDigest::parse(&report)?;
    assert_eq!(integer(retained, "decoded_pictures")?, 2);
    assert_eq!(integer(retained, "executed_inferences")?, 1);
    assert!(!boolean(retained, "event_publication_authorized")?);
    assert!(!boolean(retained, "alert_dispatch_authorized")?);
    let children = value(retained, "child_reports")?
        .array()
        .ok_or("child report handles")?;
    assert_eq!(
        children.len(),
        1,
        "native child detection must be retained for supervision"
    );
    for child in children {
        ContentDigest::parse(child.text().ok_or("child digest")?)?;
    }
    let rerun: Vec<OsString> = value(retained, "offline_replay_args")?
        .array()
        .ok_or("bounded native replay argument vector")?
        .iter()
        .map(|word| {
            word.text()
                .map(OsString::from)
                .ok_or("nontext replay argument")
        })
        .collect::<Result<_, _>>()?;
    let root = deployment(&directory);
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let effects = fs::read(root.join("effects/journal.fssj"))?;
    // Repeating the approved live operation must not silently acquire a second recording.
    let repeat = run_with_timeout("capture", &approved, INFERENCE_DEADLINE)?;
    assert!(!repeat.status.success());
    no_connection(&camera)?;
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);

    fs::rename(directory.root(), directory.0.join("offline-camera-archive"))?;
    fs::rename(model, directory.0.join("offline-model.fmpk"))?;
    let replayed = good(run_with_timeout("infer", &rerun, INFERENCE_DEADLINE)?)?;
    assert_eq!(ContentDigest::sha256(replayed.as_bytes()).to_text(), report);
    no_connection(&camera)?;
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);
    Ok(())
}

#[test]
fn live_sentinel_failed_capture_does_not_publish_detector_success() -> Test {
    let directory = Directory::new("live-sentinel-capture-refusal")?;
    let camera = listener()?;
    model(&directory)?;
    let approved = approved(&input(&directory, camera.local_addr()?))?;
    let (output, _) = capture(&camera, &approved, Behavior::MalformedAfterOne)?;
    assert!(!output.status.success());
    for row in transcript(&output)? {
        assert_ne!(text(&row, "kind")?, "sentinel_retained");
    }
    assert!(
        directory.root().exists(),
        "retain the failed capture's recovery evidence"
    );
    assert!(!deployment(&directory).exists());
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn live_sentinel_inference_budget_failure_preserves_exact_offline_recovery() -> Test {
    fn argv(row: &Value, key: &str) -> Test<Vec<OsString>> {
        value(row, key)?
            .array()
            .ok_or("offline recovery must retain a native argument vector")?
            .iter()
            .map(|word| {
                word.text()
                    .map(OsString::from)
                    .ok_or_else(|| "offline recovery argument must be text".into())
            })
            .collect()
    }

    let directory = Directory::new("live-sentinel-inference-refusal")?;
    let camera = listener()?;
    let package = model(&directory)?;
    let mut input = input(&directory, camera.local_addr()?);
    // Model loading has its own compile allowance. Zero inference MACs remains a valid
    // approved plan and deterministically refuses execution after capture and import.
    input.extend(["--max-macs".into(), "0".into()]);
    assert_eq!(integer(&preview(&input)?, "max_macs_per_inference")?, 0);
    let approved = approved(&input)?;
    let (output, observed) = capture(&camera, &approved, Behavior::StaticTarget)?;
    assert!(
        !output.status.success(),
        "zero inference allowance must not publish detector success"
    );
    assert_eq!(observed.pictures, 2);
    assert_eq!(
        observed
            .methods
            .iter()
            .filter(|method| *method == "PLAY")
            .count(),
        1
    );

    let rows = transcript(&output)?;
    for row in &rows {
        assert_ne!(text(row, "kind")?, "sentinel_retained");
    }
    let captured = detail(&rows, "sentinel_capture_ready")?;
    let imported = detail(&rows, "sentinel_imported")?;
    let refused = detail(&rows, "sentinel_analysis_refused")?;
    assert_eq!(text(refused, "error_id")?, "ERR-PACKAGE-DETECT-001");
    assert_eq!(integer(imported, "frames")?, 2);
    let identity = text(imported, "import_identity")?;
    ContentDigest::parse(identity)?;
    assert_eq!(text(refused, "import_identity")?, identity);
    assert_eq!(
        value(refused, "native_pins")?,
        value(captured, "native_pins")?,
        "analysis failure preserves the actual completed camera catalog pins"
    );
    assert_eq!(
        value(refused, "offline_import_args")?,
        value(captured, "offline_import_args")?
    );
    assert_eq!(
        value(refused, "offline_analysis_args")?,
        value(imported, "offline_analysis_args")?
    );
    assert_eq!(value(refused, "unconfirmed_report_digest")?, &Value::Null);
    assert!(!boolean(refused, "child_retention_may_exist")?);
    assert!(!boolean(refused, "automatic_recapture_authorized")?);
    assert!(!boolean(refused, "event_publication_authorized")?);
    assert!(!boolean(refused, "alert_dispatch_authorized")?);
    assert_eq!(text(refused, "offline_import_program")?, "fss-import-rtsp");
    assert_eq!(text(refused, "offline_analysis_program")?, "fss-infer");

    let import_args = argv(refused, "offline_import_args")?;
    let analysis_args = argv(refused, "offline_analysis_args")?;
    assert_eq!(
        analysis_args.first().and_then(|word| word.to_str()),
        Some("package-detect")
    );
    for (key, expected) in [
        ("--import-id", identity),
        ("--package-digest", PACKAGE_DIGEST),
        ("--frames", "2"),
        ("--max-macs", "0"),
        ("--stream-sentinel", "yes"),
        ("--retain", "yes"),
    ] {
        assert!(
            analysis_args
                .windows(2)
                .any(|pair| pair[0] == key && pair[1] == expected),
            "offline analysis must preserve {key}={expected}"
        );
    }
    assert!(
        analysis_args
            .windows(2)
            .any(|pair| pair[0] == "--package" && pair[1] == package.as_os_str())
    );
    assert!(directory.root().exists());
    assert!(directory.pins().exists());
    let root = deployment(&directory);
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let effects = fs::read(root.join("effects/journal.fssj"))?;

    // Execute the exact emitted recovery vector, including its exact native approval.
    // Reopening the retained original closure must reuse the import without another camera.
    let retried = parse(&good(run_with_timeout(
        "import",
        &import_args,
        INFERENCE_DEADLINE,
    )?)?)?;
    assert!(boolean(&retried, "reused")?);
    assert!(boolean(
        &retried,
        "destination_contains_original_recording"
    )?);
    assert!(boolean(
        &retried,
        "destination_contains_complete_catalog_pages"
    )?);
    assert_eq!(text(&retried, "import_identity")?, identity);
    assert_eq!(
        text(&retried, "origin_proof")?,
        text(imported, "source_proof")?
    );
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);
    no_connection(&camera)?;
    Ok(())
}
