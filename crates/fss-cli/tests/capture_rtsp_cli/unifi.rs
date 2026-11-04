#![forbid(unsafe_code)]
//! Private Protect channel selection through real TCP, durable archives and cold decode.
//! Synthetic streams verify integration; no Ubiquiti hardware qualification is implied.

use super::*;
use std::os::unix::fs::PermissionsExt;

const HIGH: &str = "UNIFI_HIGH_STREAM_TOKEN_CANARY";
const PACKAGE: &str = "UNIFI_PACKAGE_STREAM_TOKEN_CANARY";
const CAMERA_NAME: &str = "UNIFI_PRIVATE_CAMERA_NAME_CANARY";

fn source(directory: &Directory, peer: SocketAddr, package: bool) -> Test<(PathBuf, String)> {
    let path = directory.0.join("unifi-private.json");
    let content = format!(
        r#"{{"camera":{{"id":"camera-owner-fixture","modelKey":"camera","state":"CONNECTED","name":"{CAMERA_NAME}","type":"G6 Entry","guid":"00000000-0000-4000-8000-000000000001","mac":"001122334455","featureFlags":{{"hasSpeaker":true}},"hasPackageCamera":{package}}},"streams":{{"high":"rtsps://127.0.0.1:7441/{HIGH}?enableSrtp","medium":null,"low":null,"package":"rtsps://127.0.0.1:7441/{PACKAGE}?enableSrtp"}},"rtsp":{{"high":"rtsp://{peer}/{HIGH}","package":"rtsp://{peer}/{PACKAGE}/","low":null}}}}"#,
    );
    fs::write(&path, &content)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok((path, ContentDigest::sha256(content.as_bytes()).to_text()))
}

fn capture_args(
    directory: &Directory,
    peer: SocketAddr,
    source: &(PathBuf, String),
    quality: &str,
) -> Vec<OsString> {
    let mut result = vec!["from-unifi".into()];
    for pair in super::args(directory, peer, 2).as_chunks::<2>().0 {
        if !matches!(
            pair[0].to_str(),
            Some("--authority" | "--presentation" | "--control-root")
        ) {
            result.extend_from_slice(pair);
        }
    }
    for (key, value) in [
        ("--unifi-source", source.0.display().to_string()),
        ("--unifi-digest", source.1.clone()),
        ("--quality", quality.to_owned()),
        ("--stream-transport", "operator-rtsp".to_owned()),
        ("--codec", "avc".to_owned()),
    ] {
        result.extend([key.into(), value.into()]);
    }
    result
}

fn private_output(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for secret in [HIGH, PACKAGE, CAMERA_NAME, "enableSrtp"] {
        assert!(!text.contains(secret), "private Protect metadata leaked");
    }
}

fn approved(args: &[OsString]) -> Test<Vec<OsString>> {
    let output = run("capture", args)?;
    private_output(&output.stdout);
    private_output(&output.stderr);
    let plan = parse(&good(output)?)?;
    assert_eq!(text(&plan, "schema")?, "fss.rtsp_from_unifi_plan.v1");
    assert!(!boolean(&plan, "hardware_qualified")?);
    assert!(!boolean(&plan, "effects_started")?);
    let native = value(&plan, "native_capture")?;
    assert_eq!(text(native, "presentation_uri")?, "[redacted]");
    assert_eq!(text(native, "control_root_uri")?, "[redacted]");
    let mut result = args.to_vec();
    result.extend(["--approve".into(), text(&plan, "approval")?.into()]);
    Ok(result)
}

fn exact_request(peer: &mut TcpStream, method: &str, target: &str) -> Test<u32> {
    let mut wire = Vec::new();
    while wire.len() < 8192 {
        let mut byte = [0];
        if peer.read(&mut byte)? == 0 {
            return Err("client closed before expected request".into());
        }
        wire.push(byte[0]);
        if wire.ends_with(b"\r\n\r\n") {
            let wire = String::from_utf8(wire)?;
            assert_eq!(
                wire.lines().next(),
                Some(format!("{method} {target} RTSP/1.0").as_str())
            );
            assert!(!wire.to_ascii_lowercase().contains("authorization:"));
            return wire
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("cseq").then_some(value.trim())
                })
                .ok_or("missing CSeq")?
                .parse()
                .map_err(Into::into);
        }
    }
    Err("request exceeded fixture bound".into())
}

fn server(listener: TcpListener, token: &str) -> Test {
    let address = listener.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    let base = format!("rtsp://{address}/{token}/");
    let presentation = if token == HIGH {
        format!("rtsp://{address}/{token}")
    } else {
        base.clone()
    };
    let seq = exact_request(&mut peer, "DESCRIBE", &presentation)?;
    response(
        &mut peer,
        seq,
        &format!("Content-Type: application/sdp\r\nContent-Base: {base}\r\n"),
        SDP,
    )?;
    let seq = exact_request(&mut peer, "SETUP", &format!("{base}trackID=0"))?;
    response(
        &mut peer,
        seq,
        "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;source=127.0.0.1;destination=127.0.0.1;interleaved=0-1;ssrc=7;mode=\"PLAY\"\r\n",
        "",
    )?;
    let seq = exact_request(&mut peer, "PLAY", &base)?;
    response(&mut peer, seq, "Session: fixture\r\n", "")?;
    peer.write_all(&video(2, 3600, 96, false)?)?;
    for _ in 0..16 {
        let Some((method, seq)) = request(&mut peer)? else {
            return Ok(());
        };
        assert!(matches!(
            method.as_str(),
            "TEARDOWN" | "OPTIONS" | "GET_PARAMETER"
        ));
        response(&mut peer, seq, "Session: fixture\r\n", "")?;
    }
    Err("request allowance exhausted".into())
}

#[test]
fn private_protect_main_and_package_selection_records_and_cold_decodes_avc() -> Test {
    for (quality, token) in [("high", HIGH), ("package", PACKAGE)] {
        let directory = Directory::new(&format!("unifi-avc-{quality}"))?;
        let listener = listener()?;
        let source = source(&directory, listener.local_addr()?, true)?;
        let mut args = capture_args(&directory, listener.local_addr()?, &source, quality);
        if quality == "high" {
            replace(&mut args, "--ssrc", "auto")?;
        }
        let args = approved(&args)?;
        no_connection(&listener)?;
        assert!(!directory.root().exists());
        let output = thread::scope(|scope| -> Test<Output> {
            let server = scope.spawn(move || server(listener, token));
            let output = run("capture", &args)?;
            server.join().map_err(|_| "fixture thread panicked")??;
            Ok(output)
        })?;
        private_output(&output.stdout);
        private_output(&output.stderr);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rows = rows(&output)?;
        let terminal = detail(&rows, "terminal")?;
        assert!(boolean(terminal, "complete")?);
        assert!(!boolean(terminal, "peer_eof")?);
        assert_eq!(integer(terminal, "durable_pictures")?, 2);
        import_and_decode(&directory, &rows, 2)?;
    }
    Ok(())
}

#[test]
fn private_protect_hevc_package_selection_preserves_native_custody_and_cold_decode() -> Test {
    let directory = Directory::new("unifi-hevc-package")?;
    let listener = listener()?;
    let source = source(&directory, listener.local_addr()?, true)?;
    let mut args = capture_args(&directory, listener.local_addr()?, &source, "package");
    replace(&mut args, "--codec", "hevc")?;
    replace(&mut args, "--ssrc", "auto")?;
    replace(&mut args, "--frame-duration-ticks", "18000")?;
    replace(
        &mut args,
        "--timing-evidence",
        &digest("explicit HEVC fixture 5fps"),
    )?;
    args.extend(["--payload-type".into(), "98".into()]);
    let args = approved(&args)?;
    no_connection(&listener)?;
    let output = super::hevc::capture_onvif_and_cold_decode(&directory, listener, &args)?;
    private_output(&output.stdout);
    private_output(&output.stderr);
    Ok(())
}

#[test]
fn secure_disabled_and_unsupported_protect_streams_never_connect_or_fall_back() -> Test {
    let directory = Directory::new("unifi-refusals")?;
    let listener = listener()?;
    let source = source(&directory, listener.local_addr()?, false)?;
    let args = capture_args(&directory, listener.local_addr()?, &source, "high");
    for (key, replacement, expected) in [
        (
            "--stream-transport",
            "published",
            "ERR-CAPTURE-UNIFI-TRANSPORT-001",
        ),
        ("--quality", "low", "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001"),
        (
            "--quality",
            "medium",
            "ERR-CAPTURE-UNIFI-STREAM-MISSING-001",
        ),
        ("--quality", "package", "ERR-CAPTURE-UNIFI-PACKAGE-001"),
        ("--peer", "127.0.0.1:1", "ERR-CAPTURE-UNIFI-ROUTE-001"),
    ] {
        let mut refused = args.clone();
        replace(&mut refused, key, replacement)?;
        let output = run("capture", &refused)?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        private_output(&output.stdout);
        private_output(&output.stderr);
        no_connection(&listener)?;
        assert!(!directory.root().exists());
        assert!(!directory.pins().exists());
    }
    Ok(())
}

#[test]
fn private_protect_file_and_selection_are_revalidated_before_native_effects() -> Test {
    let directory = Directory::new("unifi-file-approval")?;
    let listener = listener()?;
    let source = source(&directory, listener.local_addr()?, true)?;
    let args = capture_args(&directory, listener.local_addr()?, &source, "high");
    let approved = approved(&args)?;
    let mut changed = approved.clone();
    replace(&mut changed, "--quality", "package")?;
    assert!(!run("capture", &changed)?.status.success());
    no_connection(&listener)?;

    fs::set_permissions(&source.0, fs::Permissions::from_mode(0o644))?;
    assert!(!run("capture", &approved)?.status.success());
    no_connection(&listener)?;
    fs::set_permissions(&source.0, fs::Permissions::from_mode(0o600))?;
    let bytes = fs::read(&source.0)?;
    let replacement = directory.0.join("replacement-private.json");
    fs::write(&replacement, &bytes)?;
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
    fs::rename(&replacement, &source.0)?;
    assert!(!run("capture", &approved)?.status.success());
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}
