#![forbid(unsafe_code)]
//! Real campaign processes, independently retained epochs, and cold native pixel replay.
//! Reuse the owned camera and bounded process fixtures; never replace native capture with a mock.

use super::*;

#[path = "batch_import.rs"]
mod batch_import;

const CONTROL: &str = "fss.rtsp_reconnect_cli.v1";
const NATIVE: &str = "fss.rtsp_capture_cli.v1";

fn campaign_args(directory: &Directory, peer: SocketAddr) -> Vec<OsString> {
    let mut input = vec!["reconnect".into()];
    input.extend(args(directory, peer, 2));
    for (key, value) in [
        ("--max-attempts", "3"),
        ("--retry-delay-ms", "5"),
        ("--retry-max-delay-ms", "10"),
        ("--continue-after-success", "yes"),
    ] {
        input.extend([key.into(), value.into()]);
    }
    input
}

fn campaign_preview(input: &[OsString]) -> Test<Value> {
    let preview = parse(&good(run("capture", input)?)?)?;
    assert_eq!(text(&preview, "schema")?, CONTROL);
    assert_eq!(text(&preview, "phase")?, "planned");
    Ok(preview)
}

fn campaign_approval(input: &[OsString]) -> Test<(Vec<OsString>, Value)> {
    let preview = campaign_preview(input)?;
    let mut approved = input.to_vec();
    approved.extend(["--approve".into(), text(&preview, "approval")?.into()]);
    Ok((approved, preview))
}

fn epoch_path(directory: &Directory, prefix: &str, ordinal: usize) -> PathBuf {
    directory.0.join(format!("{prefix}.attempt-{ordinal:04}"))
}

fn capture_sessions(
    camera: &TcpListener,
    input: &[OsString],
    behaviors: &[Behavior],
) -> Test<(Output, Vec<Transcript>)> {
    let camera = camera.try_clone()?;
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            behaviors
                .iter()
                .map(|behavior| serve(camera.try_clone()?, *behavior))
                .collect::<Test<Vec<_>>>()
        });
        let output = run("capture", input);
        let transcripts = server
            .join()
            .map_err(|_| "campaign camera thread panicked")?;
        match (output, transcripts) {
            (Ok(output), Ok(transcripts)) => Ok((output, transcripts)),
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

// Demultiplex complete objects without flattening per-owner sequence numbers or terminal rows.
fn campaign_rows(output: &Output) -> Test<(Vec<Value>, Vec<Vec<Value>>)> {
    let mut control = Vec::new();
    let mut epochs = Vec::new();
    let mut active = Vec::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let row = parse(line)?;
        match text(&row, "schema")? {
            CONTROL => {
                assert!(
                    active.is_empty(),
                    "outer owner advanced before native terminal"
                );
                assert_eq!(integer(&row, "sequence")?, control.len() as i128);
                control.push(row);
            }
            NATIVE => {
                if active.is_empty() {
                    assert_eq!(text(&row, "kind")?, "started");
                }
                assert_eq!(integer(&row, "sequence")?, active.len() as i128);
                let terminal = text(&row, "kind")? == "terminal";
                active.push(row);
                if terminal {
                    epochs.push(std::mem::take(&mut active));
                }
            }
            _ => return Err("unknown campaign report schema".into()),
        }
    }
    assert!(active.is_empty(), "unterminated native capture transcript");
    Ok((control, epochs))
}

// Verify each independent catalog through the real importer and decoder. Receive clocks come
// from that exact approved child plan, not from the original pre-reconnect source clock.
fn cold_epoch(
    directory: &Directory,
    child: &Value,
    native: &[Value],
    ordinal: usize,
    frames: i128,
) -> Test<String> {
    let selected = detail(native, "catalog_published")?;
    let archive = epoch_path(directory, "capture", ordinal);
    let pins = epoch_path(directory, "pins", ordinal).join("pins.journal");
    let original_pins = fs::read(&pins)?;
    let root = directory.0.join(format!("deployment-{ordinal:04}"));
    let mut input = Vec::new();
    for (key, value) in [
        ("--archive", archive.display().to_string()),
        ("--root", root.display().to_string()),
        ("--site", SITE.to_owned()),
        ("--catalog-slot", text(selected, "slot")?.to_owned()),
        ("--catalog-root", text(selected, "root")?.to_owned()),
        ("--decode-clock", text(selected, "decode_clock")?.to_owned()),
        ("--time-scale", integer(selected, "time_scale")?.to_string()),
        ("--codec", "avc".to_owned()),
        ("--sensor-id", SENSOR.to_owned()),
        ("--stream-id", STREAM.to_owned()),
        // The base fixture starts at generation one. Each approved successor increments it.
        ("--generation", ordinal.to_string()),
        ("--anchor", digest("capture CLI authority anchor")),
        ("--receive-clock", text(child, "receive_clock")?.to_owned()),
        ("--receive-time-ns", "5000000000".to_owned()),
        ("--owner-authorized", "yes".to_owned()),
        ("--read-originals", "yes".to_owned()),
        ("--retain-originals", "yes".to_owned()),
    ] {
        input.extend([OsString::from(key), OsString::from(value)]);
    }
    let preview = parse(&good(run("import", &input)?)?)?;
    assert!(!root.exists(), "import preview created destination custody");
    assert_eq!(text(&preview, "selection")?, "complete_catalog_page");
    input.extend(["--approve".into(), text(&preview, "approval_digest")?.into()]);
    let imported = parse(&good(run("import", &input)?)?)?;
    assert_eq!(integer(&imported, "frames")?, frames);
    assert_eq!(text(&imported, "capture_time_label")?, "unknown");
    assert!(boolean(&imported, "destination_contains_original_recording")?);
    assert!(boolean(&imported, "destination_contains_complete_catalog")?);
    let identity = text(&imported, "import_identity")?.to_owned();
    ContentDigest::parse(&identity)?;
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let effects = fs::read(root.join("effects/journal.fssj"))?;
    let retried = parse(&good(run("import", &input)?)?)?;
    assert!(boolean(&retried, "reused")?);
    assert_eq!(text(&retried, "import_identity")?, identity);
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);

    // Remove the original archive from its exact path; replay must use destination custody.
    fs::rename(
        &archive,
        directory.0.join(format!("offline-capture-{ordinal:04}")),
    )?;
    let common = [
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--site"),
        OsString::from(SITE),
        OsString::from("--import-id"),
        OsString::from(&identity),
    ];
    let mut verify = vec![OsString::from("verify")];
    verify.extend(common.iter().cloned());
    let verified = good(run("file", &verify)?)?;
    assert!(verified.contains("media_format=mp4avc"), "{verified}");
    assert!(verified.contains("capture_time_class=unknown"), "{verified}");
    assert!(verified.contains("absence_certifiable=false"), "{verified}");
    let mut decode = vec![OsString::from("decode")];
    decode.extend(common);
    for (key, value) in [
        ("--segment", "0".to_owned()),
        ("--segment-count", frames.to_string()),
        ("--interpretation", "ycbcr".to_owned()),
        ("--work-units", "1000000000".to_owned()),
    ] {
        decode.extend([key.into(), value.into()]);
    }
    let decoded = good(run("file", &decode)?)?;
    assert!(
        decoded.lines().any(|line| line == "decode_complete=true"),
        "{decoded}"
    );
    assert!(
        decoded
            .lines()
            .any(|line| line == format!("h264_frames_decoded={frames}")),
        "{decoded}"
    );
    assert_eq!(
        decoded
            .lines()
            .filter(|line| line.starts_with("frame_luma_sha256="))
            .count(),
        usize::try_from(frames)?
    );
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);
    assert_eq!(
        fs::read(pins)?,
        original_pins,
        "import/replay changed recovery authority"
    );
    Ok(identity)
}

#[test]
fn campaign_preview_and_stale_legacy_approval_have_no_effects() -> Test {
    for codec in ["avc", "hevc"] {
        let directory = Directory::new(&format!("campaign-preview-{codec}"))?;
        let camera = listener()?;
        let mut input = campaign_args(&directory, camera.local_addr()?);
        input.extend(["--codec".into(), codec.into()]);
        let preview = campaign_preview(&input)?;
        let children = value(&preview, "attempts")?.array().ok_or("child plans")?;
        assert_eq!(children.len(), 3);
        assert!(boolean(&preview, "continue_after_success")?);
        let mut legacy = input.clone();
        let offset = legacy
            .iter()
            .position(|arg| arg == "--continue-after-success")
            .ok_or("campaign option")?;
        legacy.drain(offset..offset + 2);
        let legacy_preview = campaign_preview(&legacy)?;
        assert_ne!(text(&preview, "approval")?, text(&legacy_preview, "approval")?);
        for wrong in [
            text(&legacy_preview, "approval")?,
            text(&children[0], "approval")?,
        ] {
            let mut refused = input.clone();
            refused.extend(["--approve".into(), wrong.into()]);
            let output = run("capture", &refused)?;
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(fs::read_dir(&directory.0)?.next().is_none());
            no_connection(&camera)?;
        }
    }
    Ok(())
}

#[test]
fn three_successful_sessions_keep_distinct_custody_and_cold_native_replay() -> Test {
    let directory = Directory::new("campaign-three")?;
    let camera = listener()?;
    let (input, preview) = campaign_approval(&campaign_args(&directory, camera.local_addr()?))?;
    let (output, transcripts) = capture_sessions(&camera, &input, &[Behavior::Target; 3])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(transcripts.len(), 3);
    for transcript in &transcripts {
        assert_eq!(&transcript.methods[..3], &["DESCRIBE", "SETUP", "PLAY"]);
        assert!(!transcript.source_eof);
    }
    no_connection(&camera)?;
    assert!(!epoch_path(&directory, "capture", 4).exists());
    let (control, epochs) = campaign_rows(&output)?;
    assert_eq!(epochs.len(), 3);
    let terminal = detail(&control, "reconnect_terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "successful_attempts")?, 3);
    assert_eq!(integer(terminal, "durable_pictures_all_attempts")?, 6);
    assert!(!boolean(terminal, "continuity_across_attempts")?);
    assert!(!boolean(terminal, "absence_certifiable")?);
    let children = value(&preview, "attempts")?.array().ok_or("child plans")?;
    let mut identities = std::collections::BTreeSet::new();
    for (index, native) in epochs.iter().enumerate() {
        let terminal = detail(native, "terminal")?;
        assert!(boolean(terminal, "complete")?);
        assert!(!boolean(terminal, "peer_eof")?);
        assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
        assert_eq!(integer(terminal, "durable_pictures")?, 2);
        assert!(identities.insert(cold_epoch(
            &directory,
            &children[index],
            native,
            index + 1,
            2
        )?));
    }
    Ok(())
}

#[test]
fn early_eof_is_not_erased_by_two_later_successful_native_sessions() -> Test {
    let directory = Directory::new("campaign-partial")?;
    let camera = listener()?;
    let (input, preview) = campaign_approval(&campaign_args(&directory, camera.local_addr()?))?;
    let (output, _) = capture_sessions(
        &camera,
        &input,
        &[Behavior::EofAfterOne, Behavior::Target, Behavior::Target],
    )?;
    assert!(!output.status.success());
    no_connection(&camera)?;
    let (control, epochs) = campaign_rows(&output)?;
    assert_eq!(epochs.len(), 3);
    let terminal = detail(&control, "reconnect_terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "successful_attempts")?, 2);
    assert_eq!(integer(terminal, "unsuccessful_attempts")?, 1);
    assert_eq!(integer(terminal, "first_failed_attempt")?, 1);
    assert_eq!(integer(terminal, "durable_pictures_all_attempts")?, 5);
    assert_eq!(
        text(terminal, "first_error_id")?,
        "ERR-CAPTURE-RTSP-SHORTFALL-001"
    );
    let children = value(&preview, "attempts")?.array().ok_or("child plans")?;
    for (index, native) in epochs.iter().enumerate() {
        let _ = cold_epoch(
            &directory,
            &children[index],
            native,
            index + 1,
            if index == 0 { 1 } else { 2 },
        )?;
    }
    Ok(())
}

#[test]
fn authentication_after_success_does_not_admit_a_third_campaign_session() -> Test {
    let directory = Directory::new("campaign-auth-stop")?;
    let camera = listener()?;
    let (input, _) = campaign_approval(&campaign_args(&directory, camera.local_addr()?))?;
    let (output, transcripts) = capture_sessions(
        &camera,
        &input,
        &[Behavior::Target, Behavior::AuthenticationRequired],
    )?;
    assert!(!output.status.success());
    assert_eq!(transcripts.len(), 2);
    assert_eq!(transcripts[1].methods, ["DESCRIBE"]);
    no_connection(&camera)?;
    assert!(!epoch_path(&directory, "capture", 3).exists());
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [SECRET_REALM, SECRET_NONCE, "WWW-Authenticate"] {
        assert!(!report.contains(secret));
    }
    let (control, epochs) = campaign_rows(&output)?;
    assert_eq!(epochs.len(), 2);
    let terminal = detail(&control, "reconnect_terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "successful_attempts")?, 1);
    assert_eq!(integer(terminal, "first_failed_attempt")?, 2);
    assert_eq!(integer(terminal, "durable_pictures_all_attempts")?, 2);
    Ok(())
}

#[test]
fn preexisting_second_epoch_preserves_first_capture_and_never_skips_ahead() -> Test {
    let directory = Directory::new("campaign-existing")?;
    let camera = listener()?;
    let (input, _) = campaign_approval(&campaign_args(&directory, camera.local_addr()?))?;
    let second = epoch_path(&directory, "capture", 2);
    fs::create_dir(&second)?;
    fs::write(second.join("prior-custody"), b"preserve exact original")?;
    let (output, transcripts) = capture_sessions(&camera, &input, &[Behavior::Target])?;
    assert!(!output.status.success());
    assert_eq!(transcripts.len(), 1);
    no_connection(&camera)?;
    assert_eq!(
        fs::read(second.join("prior-custody"))?,
        b"preserve exact original"
    );
    assert!(epoch_path(&directory, "capture", 1).is_dir());
    assert!(
        epoch_path(&directory, "pins", 1)
            .join("pins.journal")
            .is_file()
    );
    assert!(!epoch_path(&directory, "capture", 3).exists());
    assert!(!epoch_path(&directory, "pins", 3).exists());
    Ok(())
}
