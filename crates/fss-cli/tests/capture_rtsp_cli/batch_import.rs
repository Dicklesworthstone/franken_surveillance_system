#![forbid(unsafe_code)]
//! Real capture -> multi-epoch native import -> independent cold decoding and retry.
//! The batch controller never gets a mocked source, importer, ledger or decoder here.

use super::*;
use fss_cli::agent_json::{array, string};

const BATCH: &str = "fss.rtsp_import_batch_operator.v1";

fn destination(directory: &Directory) -> PathBuf {
    directory.0.join("batch-deployment")
}

fn fixture(label: &str) -> Test<(Directory, Vec<OsString>)> {
    let directory = Directory::new(label)?;
    let camera = listener()?;
    let (capture, preview) = campaign_approval(&campaign_args(&directory, camera.local_addr()?))?;
    let (output, _) = capture_sessions(&camera, &capture, &[Behavior::Target; 3])?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    no_connection(&camera)?;
    let (_, epochs) = campaign_rows(&output)?;
    assert_eq!(epochs.len(), 3);
    let children = value(&preview, "attempts")?.array().ok_or("capture plans")?;
    let mut requests = Vec::new();
    for (index, native) in epochs.iter().enumerate() {
        let selected = detail(native, "catalog_published")?;
        let mut arguments = Vec::new();
        for (key, value) in [
            ("--archive", epoch_path(&directory, "capture", index + 1).display().to_string()),
            ("--root", destination(&directory).display().to_string()),
            ("--site", SITE.to_owned()),
            ("--catalog-slot", text(selected, "slot")?.to_owned()),
            ("--catalog-root", text(selected, "root")?.to_owned()),
            ("--decode-clock", text(selected, "decode_clock")?.to_owned()),
            ("--time-scale", integer(selected, "time_scale")?.to_string()),
            ("--codec", "avc".to_owned()),
            ("--sensor-id", SENSOR.to_owned()),
            ("--stream-id", STREAM.to_owned()),
            ("--generation", (index + 1).to_string()),
            ("--anchor", digest("capture CLI authority anchor")),
            ("--receive-clock", text(&children[index], "receive_clock")?.to_owned()),
            ("--receive-time-ns", "5000000000".to_owned()),
            ("--owner-authorized", "yes".to_owned()),
            ("--read-originals", "yes".to_owned()),
            ("--retain-originals", "yes".to_owned()),
        ] {
            arguments.extend([string(key), string(&value)]);
        }
        requests.push(array(&arguments));
    }
    Ok((directory, vec!["batch".into(), "--requests".into(), array(&requests).into()]))
}

fn approve_batch(input: &[OsString]) -> Test<(Vec<OsString>, Value)> {
    let preview = parse(&good(run("import", input)?)?)?;
    assert_eq!(text(&preview, "format")?, BATCH);
    assert_eq!(text(&preview, "kind")?, "plan");
    assert_eq!(integer(&preview, "imports")?, 3);
    let mut approved = input.to_vec();
    approved.extend(["--approve".into(), text(&preview, "approval_digest")?.into()]);
    Ok((approved, preview))
}

fn batch_rows(output: &Output) -> Test<Vec<Value>> {
    let mut rows = Vec::new();
    for (sequence, line) in std::str::from_utf8(&output.stdout)?.lines().enumerate() {
        let row = parse(line)?;
        assert_eq!(text(&row, "format")?, BATCH);
        assert_eq!(integer(&row, "sequence")?, sequence as i128);
        rows.push(row);
    }
    Ok(rows)
}

fn receipts(rows: &[Value]) -> Test<Vec<&Value>> {
    let mut result = Vec::new();
    for row in rows {
        if text(row, "kind")? == "import_completed" {
            let payload = value(row, "detail")?;
            assert_eq!(integer(payload, "ordinal")?, result.len() as i128 + 1);
            let receipt = value(payload, "receipt")?;
            assert_eq!(text(receipt, "kind")?, "imported");
            assert_eq!(integer(receipt, "frames")?, 2);
            assert_eq!(text(receipt, "capture_time_label")?, "unknown");
            assert!(boolean(receipt, "destination_contains_original_recording")?);
            assert!(boolean(receipt, "destination_contains_complete_catalog")?);
            result.push(receipt);
        }
    }
    Ok(result)
}

fn pins(directory: &Directory) -> Test<Vec<Vec<u8>>> {
    (1..=3)
        .map(|ordinal| {
            Ok(fs::read(epoch_path(directory, "pins", ordinal).join("pins.journal"))?)
        })
        .collect()
}

fn assert_cold_decode(directory: &Directory, identities: &[String]) -> Test {
    let root = destination(directory);
    let effects = fs::read(root.join("effects/journal.fssj"))?;
    for ordinal in 1..=3 {
        fs::rename(
            epoch_path(directory, "capture", ordinal),
            directory.0.join(format!("offline-batch-source-{ordinal}")),
        )?;
    }
    for identity in identities {
        let common = [
            OsString::from("--root"), root.as_os_str().to_owned(),
            OsString::from("--site"), OsString::from(SITE),
            OsString::from("--import-id"), OsString::from(identity),
        ];
        let mut verify = vec![OsString::from("verify")];
        verify.extend(common.iter().cloned());
        let verified = good(run("file", &verify)?)?;
        for expected in ["media_format=mp4avc", "capture_time_class=unknown", "absence_certifiable=false"] {
            assert!(verified.contains(expected), "{verified}");
        }
        let mut decode = vec![OsString::from("decode")];
        decode.extend(common);
        decode.extend([
            "--segment", "0", "--segment-count", "2", "--interpretation", "ycbcr",
            "--work-units", "1000000000",
        ].into_iter().map(OsString::from));
        let decoded = good(run("file", &decode)?)?;
        assert!(decoded.lines().any(|line| line == "decode_complete=true"), "{decoded}");
        assert!(decoded.lines().any(|line| line == "h264_frames_decoded=2"), "{decoded}");
        assert_eq!(decoded.lines().filter(|line| line.starts_with("frame_luma_sha256=")).count(), 2);
    }
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);
    Ok(())
}

#[test]
fn native_batch_imports_all_epochs_into_one_deployment_and_cold_decodes_each() -> Test {
    let (directory, input) = fixture("batch-complete")?;
    let original_pins = pins(&directory)?;
    let (approved, preview) = approve_batch(&input)?;
    let root = destination(&directory);
    assert!(!root.exists(), "pure batch preview created a deployment");
    let children = value(&preview, "children")?.array().ok_or("import plans")?;
    let mut wrong = input;
    wrong.extend(["--approve".into(), text(&children[0], "approval_digest")?.into()]);
    let refused = run("import", &wrong)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(!root.exists());
    let output = run("import", &approved)?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let rows = batch_rows(&output)?;
    let imported = receipts(&rows)?;
    assert_eq!(imported.len(), 3);
    let mut identities = Vec::new();
    for receipt in imported {
        assert!(!boolean(receipt, "reused")?);
        identities.push(text(receipt, "import_identity")?.to_owned());
    }
    assert_eq!(identities.iter().collect::<std::collections::BTreeSet<_>>().len(), 3);
    let terminal = detail(&rows, "batch_terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "completed_imports")?, 3);
    assert!(!boolean(terminal, "continuity_between_imports")?);
    assert!(!boolean(terminal, "absence_certifiable")?);
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let effects = fs::read(root.join("effects/journal.fssj"))?;
    let output = run("import", &approved)?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let retried = batch_rows(&output)?;
    for (index, receipt) in receipts(&retried)?.iter().enumerate() {
        assert!(boolean(receipt, "reused")?);
        assert_eq!(text(receipt, "import_identity")?, identities[index]);
    }
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);
    assert_cold_decode(&directory, &identities)?;
    assert_eq!(pins(&directory)?, original_pins);
    Ok(())
}

#[test]
fn missing_middle_archive_stops_batch_and_exact_replay_reuses_only_completed_imports() -> Test {
    let (directory, input) = fixture("batch-partial")?;
    let original_pins = pins(&directory)?;
    let (approved, _) = approve_batch(&input)?;
    let second = epoch_path(&directory, "capture", 2);
    let unavailable = directory.0.join("temporarily-unavailable-second");
    fs::rename(&second, &unavailable)?;
    let output = run("import", &approved)?;
    assert!(!output.status.success());
    let partial = batch_rows(&output)?;
    let imported = receipts(&partial)?;
    assert_eq!(imported.len(), 1);
    let first_identity = text(imported[0], "import_identity")?.to_owned();
    let terminal = detail(&partial, "batch_terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "completed_imports")?, 1);
    assert_eq!(integer(terminal, "failed_import")?, 2);
    assert_eq!(integer(terminal, "unattempted_imports")?, 1);
    assert_eq!(text(terminal, "failed_import_state")?, "unconfirmed_may_be_durable");
    assert_eq!(partial.iter().filter(|row| text(row, "kind").ok() == Some("import_started")).count(), 2);
    fs::rename(&unavailable, &second)?;
    let output = run("import", &approved)?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let completed = batch_rows(&output)?;
    let imported = receipts(&completed)?;
    assert_eq!(imported.len(), 3);
    assert_eq!(text(imported[0], "import_identity")?, first_identity);
    let mut identities = Vec::new();
    for (index, receipt) in imported.iter().enumerate() {
        assert_eq!(boolean(receipt, "reused")?, index == 0);
        identities.push(text(receipt, "import_identity")?.to_owned());
    }
    assert!(boolean(detail(&completed, "batch_terminal")?, "complete")?);
    assert_cold_decode(&directory, &identities)?;
    assert_eq!(pins(&directory)?, original_pins);
    Ok(())
}
