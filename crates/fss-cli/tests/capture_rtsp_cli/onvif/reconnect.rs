#![forbid(unsafe_code)]
//! Private onboarding delegates to the existing reconnect, source and recovery owners.

use super::*;

const PRIVATE_PATH: &str = "ONVIF_PRIVATE_PATH_CANARY";
const CONTROL: &str = "fss.rtsp_reconnect_cli.v1";
const NATIVE: &str = "fss.rtsp_capture_cli.v1";

fn private(output: &Output) {
    secret_free(output);
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(PRIVATE_PATH));
    }
}

fn uri(address: SocketAddr) -> String {
    format!("rtsp://{address}/live/{PRIVATE_PATH}/")
}

fn handoff(directory: &Directory, address: SocketAddr) -> Test<String> {
    let bytes = synthetic_handoff(address).replace(
        &format!("rtsp://{address}/live/?selection={QUERY}"),
        &uri(address),
    );
    let path = directory.0.join("onvif.json");
    fs::write(path.clone(), &bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(ContentDigest::sha256(bytes.as_bytes()).to_text())
}

fn options(directory: &Directory, address: SocketAddr, source: bool) -> Test<Vec<OsString>> {
    let digest = handoff(directory, address)?;
    let mut args = capture_arguments(directory, address, &digest);
    reconnect_arguments(directory, &mut args, source);
    Ok(args)
}

fn reconnect_arguments(directory: &Directory, args: &mut Vec<OsString>, source: bool) {
    args.extend([
        "--capture-mode".into(),
        "reconnect".into(),
        "--max-attempts".into(),
        "2".into(),
        "--retry-delay-ms".into(),
        "1".into(),
        "--retry-max-delay-ms".into(),
        "1".into(),
        "--progress-timeout-ms".into(),
        "1000".into(),
    ]);
    if source {
        args.extend([
            "--source-root".into(),
            directory.0.join("source").into_os_string(),
            "--source-retention-evidence".into(),
            super::digest("owner authorized full source datagrams").into(),
            "--max-datagrams".into(),
            "64".into(),
            "--source-storage-bytes".into(),
            "1048576".into(),
            "--source-work".into(),
            "1000000000".into(),
        ]);
    }
}

fn all_rows(output: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| parse(line).map_err(Into::into))
        .collect()
}

fn details<'a>(rows: &'a [Value], schema: &str, kind: &str) -> Test<Vec<&'a Value>> {
    rows.iter()
        .filter(|row| {
            text(row, "schema").ok() == Some(schema) && text(row, "kind").ok() == Some(kind)
        })
        .map(|row| value(row, "detail"))
        .collect()
}

fn no_stores(directory: &Directory) {
    for name in ["capture", "pins", "source"] {
        assert!(!directory.0.join(name).exists());
        for ordinal in 1..=2 {
            assert!(
                !directory
                    .0
                    .join(format!("{name}.attempt-{ordinal:04}"))
                    .exists()
            );
        }
    }
}

#[test]
fn onvif_reconnect_redacts_query_free_uri_and_refuses_nested_approvals() -> Test {
    let directory = Directory::new("onvif-reconnect-approval")?;
    let rtsp = listener()?;
    let args = options(&directory, rtsp.local_addr()?, true)?;
    let preview = run("capture", &args)?;
    private(&preview);
    let plan = parse(&good(preview)?)?;
    assert_eq!(text(&plan, "schema")?, "fss.rtsp_from_onvif_plan.v2");
    let nested = value(&plan, "native_capture")?;
    let attempts = value(nested, "attempts")?.array().ok_or("attempt array")?;
    assert_eq!(attempts.len(), 2);
    for attempt in attempts {
        assert_eq!(text(attempt, "presentation_uri")?, "[redacted]");
    }
    assert_ne!(text(&plan, "approval")?, text(nested, "approval")?);
    for approval in [text(nested, "approval")?, text(&attempts[0], "approval")?] {
        let mut denied = args.clone();
        denied.extend(["--approve".into(), approval.into()]);
        let output = run("capture", &denied)?;
        private(&output);
        assert!(!output.status.success());
        no_connection(&rtsp)?;
        no_stores(&directory);
    }
    Ok(())
}

fn serve_attempt(listener: &TcpListener, pictures: usize, eof: bool) -> Test {
    let address = listener.local_addr()?;
    let mut peer = accept(listener)?;
    for method in ["DESCRIBE", "SETUP", "PLAY"] {
        let (actual, target, cseq) =
            exact_rtsp_request(&mut peer)?.ok_or("missing capture request")?;
        assert_eq!(actual, method);
        assert_eq!(
            target,
            if method == "SETUP" {
                format!("{}trackID=0", uri(address))
            } else {
                uri(address)
            }
        );
        match method {
            "DESCRIBE" => response(&mut peer, cseq, "Content-Type: application/sdp\r\n", SDP)?,
            "SETUP" => response(
                &mut peer,
                cseq,
                "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                "",
            )?,
            _ => response(&mut peer, cseq, "Session: fixture\r\n", "")?,
        }
    }
    peer.write_all(&video(pictures, 3600, 96, false)?)?;
    if eof {
        peer.shutdown(Shutdown::Write)?;
    }
    for _ in 0..16 {
        let Some((method, target, cseq)) = exact_rtsp_request(&mut peer)? else {
            return Ok(());
        };
        assert!(matches!(
            method.as_str(),
            "TEARDOWN" | "GET_PARAMETER" | "OPTIONS"
        ));
        assert_eq!(target, uri(address));
        response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    }
    Err("reconnect fixture request limit".into())
}

#[test]
fn onvif_reconnect_preserves_source_epochs_and_supports_separate_offline_recovery() -> Test {
    let directory = Directory::new("onvif-reconnect-source-recovery")?;
    let rtsp = listener()?;
    let fence = rtsp.try_clone()?;
    let args = options(&directory, rtsp.local_addr()?, true)?;
    let preview = parse(&good(run("capture", &args)?)?)?;
    let capture_approval = text(&preview, "approval")?.to_owned();
    let mut approved = args.clone();
    approved.extend(["--approve".into(), capture_approval.clone().into()]);
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || -> Test {
            serve_attempt(&rtsp, 1, true)?;
            serve_attempt(&rtsp, 2, false)?;
            no_connection(&rtsp)
        });
        let output = run("capture", &approved)?;
        server
            .join()
            .map_err(|_| "reconnect fixture panicked")?
            .map_err(|error| {
                format!(
                    "reconnect fixture: {error}; stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })?;
        Ok(output)
    })?;
    private(&output);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = all_rows(&output)?;
    let attempts = details(&records, CONTROL, "attempt_started")?;
    assert_eq!(attempts.len(), 2);
    assert_eq!(integer(attempts[0], "generation")?, 1);
    assert_eq!(integer(attempts[1], "generation")?, 2);
    let ended = details(&records, CONTROL, "attempt_finished")?;
    assert_eq!(text(ended[0], "retry_reason")?, "source_ended");
    assert!(boolean(ended[0], "retrying")?);
    let terminal = details(&records, CONTROL, "reconnect_terminal")?;
    assert_eq!(terminal.len(), 1);
    assert!(boolean(terminal[0], "complete")?);
    assert_eq!(integer(terminal[0], "durable_pictures_all_attempts")?, 3);
    assert!(!boolean(terminal[0], "continuity_across_attempts")?);
    assert!(!details(&records, NATIVE, "datagram_durable")?.is_empty());
    assert_eq!(details(&records, NATIVE, "window_durable")?.len(), 2);
    for ordinal in 1..=2 {
        for name in ["capture", "pins", "source"] {
            assert!(
                directory
                    .0
                    .join(format!("{name}.attempt-{ordinal:04}"))
                    .is_dir()
            );
        }
    }
    let handoff_before = fs::read(directory.0.join("onvif.json"))?;
    for mode in ["yes", "index"] {
        let mut recovery = args.clone();
        recovery.extend(["--recover".into(), mode.into()]);
        let planned = run("capture", &recovery)?;
        private(&planned);
        let plan = parse(&good(planned)?)?;
        let native = value(&plan, "native_capture")?;
        assert!(!boolean(native, "network_requested")?);
        assert_ne!(text(&plan, "approval")?, capture_approval);
        no_connection(&fence)?;
        let mut wrong = recovery.clone();
        wrong.extend(["--approve".into(), capture_approval.clone().into()]);
        let refused = run("capture", &wrong)?;
        private(&refused);
        assert!(!refused.status.success());
        no_connection(&fence)?;
        recovery.extend(["--approve".into(), text(&plan, "approval")?.into()]);
        let restored = run("capture", &recovery)?;
        private(&restored);
        assert!(
            restored.status.success(),
            "mode={mode}; stdout={}; stderr={}",
            String::from_utf8_lossy(&restored.stdout),
            String::from_utf8_lossy(&restored.stderr)
        );
        let rows = all_rows(&restored)?;
        let terminal = detail(
            &rows,
            if mode == "yes" {
                "recovery_terminal"
            } else {
                "index_terminal"
            },
        )?;
        assert!(boolean(terminal, "operation_complete")?);
        assert!(!boolean(terminal, "network_requested")?);
        assert!(!boolean(terminal, "capture_complete")?);
        no_connection(&fence)?;
    }
    assert_eq!(fs::read(directory.0.join("onvif.json"))?, handoff_before);
    Ok(())
}

#[test]
fn onvif_media2_hevc_reconnect_recovers_and_indexes_exact_retained_source_offline() -> Test {
    let directory = Directory::new("onvif-media2-hevc-source-recovery")?;
    let rtsp = listener()?;
    let fence = rtsp.try_clone()?;
    let address = rtsp.local_addr()?;
    let handoff = media2_handoff(&directory, address, true)?;
    let handoff_before = fs::read(directory.0.join("onvif.json"))?;
    no_connection(&fence)?;

    let mut args = hevc_capture_arguments(&directory, address, &handoff)?;
    reconnect_arguments(&directory, &mut args, true);
    replace(&mut args, "--max-attempts", "1")?;
    let planned = run("capture", &args)?;
    private(&planned);
    let plan = parse(&good(planned)?)?;
    let native = value(&plan, "native_capture")?;
    let attempts = value(native, "attempts")?.array().ok_or("attempt array")?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(text(&attempts[0], "codec")?, "hevc");
    assert_eq!(text(&attempts[0], "presentation_uri")?, "[redacted]");
    assert_ne!(text(&plan, "approval")?, text(native, "approval")?);
    no_connection(&fence)?;
    no_stores(&directory);
    let capture_approval = text(&plan, "approval")?.to_owned();
    let mut approved = args.clone();
    approved.extend(["--approve".into(), capture_approval.clone().into()]);
    let output = super::super::hevc::capture_onvif_retained_source(rtsp, &approved)?;
    private(&output);
    no_connection(&fence)?;
    let records = all_rows(&output)?;
    assert_eq!(details(&records, CONTROL, "attempt_started")?.len(), 1);
    let terminal = detail(&records, "reconnect_terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "durable_pictures_all_attempts")?, 2);
    let native_terminal = detail(&records, "terminal")?;
    assert_eq!(text(native_terminal, "codec")?, "hevc");
    assert!(boolean(native_terminal, "complete")?);
    assert_eq!(integer(native_terminal, "durable_pictures")?, 2);
    assert_eq!(integer(native_terminal, "durable_windows")?, 1);
    assert!(!boolean(native_terminal, "peer_eof")?);
    let windows = details(&records, NATIVE, "window_durable")?;
    assert_eq!(windows.len(), 1);
    assert_eq!(text(windows[0], "codec")?, "hevc");
    assert_eq!(integer(windows[0], "source_only_nals")?, 1);
    let datagrams = details(&records, NATIVE, "datagram_durable")?;
    // The original source includes probation plus all six accepted NALs, including the
    // genuine VPS that closes the second picture while the camera connection remains open.
    assert_eq!(datagrams.len(), 7);
    let retained_prefix = value(datagrams.last().ok_or("missing source prefix")?, "prefix")?;
    assert_eq!(integer(retained_prefix, "datagrams")?, 7);
    for name in ["capture", "pins", "source"] {
        assert!(directory.0.join(format!("{name}.attempt-0001")).is_dir());
        assert!(!directory.0.join(format!("{name}.attempt-0002")).exists());
    }

    let mut prior_approvals = vec![capture_approval];
    for mode in ["yes", "index"] {
        let mut recovery = args.clone();
        recovery.extend(["--recover".into(), mode.into()]);
        let planned = run("capture", &recovery)?;
        private(&planned);
        let plan = parse(&good(planned)?)?;
        let native = value(&plan, "native_capture")?;
        assert!(!boolean(native, "network_requested")?);
        let custody = value(native, "datagram_source_custody")?;
        assert!(boolean(
            custody,
            "original_rtp_membership_required_before_publication"
        )?);
        let sources = value(custody, "attempts")?
            .array()
            .ok_or("source attempts")?;
        assert_eq!(sources.len(), 1);
        assert_eq!(value(&sources[0], "observed_source_head")?, retained_prefix);
        assert_eq!(
            text(&sources[0], "source_custody")?,
            "complete_current_datagram_chain_verified"
        );
        let approval = text(&plan, "approval")?.to_owned();
        assert_ne!(approval, text(native, "approval")?);
        no_connection(&fence)?;
        for prior in &prior_approvals {
            assert_ne!(&approval, prior);
            let mut wrong = recovery.clone();
            wrong.extend(["--approve".into(), prior.into()]);
            let refused = run("capture", &wrong)?;
            private(&refused);
            assert!(!refused.status.success());
            no_connection(&fence)?;
        }
        recovery.extend(["--approve".into(), approval.clone().into()]);
        let restored = run("capture", &recovery)?;
        private(&restored);
        assert!(
            restored.status.success(),
            "mode={mode}; stdout={}; stderr={}",
            String::from_utf8_lossy(&restored.stdout),
            String::from_utf8_lossy(&restored.stderr)
        );
        let rows = all_rows(&restored)?;
        let preflight = detail(&rows, "datagram_source_preflight_complete")?;
        assert!(!boolean(preflight, "publication_started")?);
        let terminal = detail(
            &rows,
            if mode == "yes" {
                "recovery_terminal"
            } else {
                "index_terminal"
            },
        )?;
        assert!(boolean(terminal, "operation_complete")?);
        assert!(!boolean(terminal, "network_requested")?);
        assert!(!boolean(terminal, "capture_complete")?);
        assert!(!boolean(terminal, "source_bytes_emitted")?);
        if mode == "yes" {
            assert_eq!(integer(terminal, "selected_work_restored")?, 1);
            assert_eq!(integer(terminal, "durable_windows_in_checked_archives")?, 1);
            let attempt = detail(&rows, "attempt_recovery")?;
            assert_eq!(text(attempt, "codec")?, "hevc");
            assert_eq!(text(attempt, "work_custody")?, "verified");
        } else {
            assert_eq!(integer(terminal, "checked_archives")?, 1);
            let attempt = detail(&rows, "attempt_index")?;
            assert_eq!(text(attempt, "codec")?, "hevc");
            assert_eq!(integer(attempt, "durable_windows")?, 1);
            assert_eq!(integer(attempt, "indexed_windows")?, 1);
            assert!(boolean(attempt, "index_complete")?);
        }
        prior_approvals.push(approval);
        no_connection(&fence)?;
    }
    assert_eq!(fs::read(directory.0.join("onvif.json"))?, handoff_before);
    Ok(())
}

#[test]
fn onvif_handoff_cannot_alias_any_derived_recording_or_source_attempt() -> Test {
    for (label, name, alias) in [
        ("recording", "capture", false),
        ("source", "source", false),
        ("aliased-parent", "capture", true),
    ] {
        let directory = Directory::new(&format!("onvif-derived-{label}"))?;
        let rtsp = listener()?;
        let mut args = options(&directory, rtsp.local_addr()?, true)?;
        let attempt = directory.0.join(format!("{name}.attempt-0001"));
        fs::create_dir(&attempt)?;
        fs::set_permissions(&attempt, fs::Permissions::from_mode(0o700))?;
        let source = attempt.join("onvif.json");
        fs::rename(directory.0.join("onvif.json"), &source)?;
        replace(
            &mut args,
            "--onvif-source",
            source.to_str().ok_or("source path")?,
        )?;
        if alias {
            let link = directory.0.join("alias");
            std::os::unix::fs::symlink(&directory.0, &link)?;
            replace(
                &mut args,
                "--root",
                link.join("capture").to_str().ok_or("alias path")?,
            )?;
        }
        let output = run("capture", &args)?;
        private(&output);
        assert!(!output.status.success(), "derived {label} did not refuse");
        no_connection(&rtsp)?;
        assert_eq!(fs::read_dir(&attempt)?.count(), 1);
        assert!(!directory.0.join("pins.attempt-0001").exists());
        assert!(!directory.0.join("capture.attempt-0002").exists());
    }
    Ok(())
}
