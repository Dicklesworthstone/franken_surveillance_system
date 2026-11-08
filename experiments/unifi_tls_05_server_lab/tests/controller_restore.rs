#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real restoration process against an isolated, synthetic TLS camera.
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    error::Error,
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
type Test = Result<(), Box<dyn Error>>;
const EXPECTED: &str = "192.168.1.10";
const ORIGINAL: &str = "192.168.1.11";
const OTHER: &str = "192.168.1.12";
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Child(Option<std::process::Child>);
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(mut p) = self.0.take() {
            let _ = p.kill();
            let _ = p.wait();
        }
    }
}
struct Peer(Option<std::thread::JoinHandle<io::Result<()>>>);
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(t) = self.0.take() {
            let _ = t.join();
        }
    }
}
/// Own only this test's unique transient timer and service.
struct TimerUnit(Option<String>);
impl Drop for TimerUnit {
    fn drop(&mut self) {
        if let Some(name) = self.0.take() {
            let _ = Command::new("sudo")
                .args([
                    "-n",
                    "systemctl",
                    "stop",
                    &format!("{name}.timer"),
                    &format!("{name}.service"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
impl Peer {
    fn finish(mut self) -> Test {
        self.0
            .take()
            .ok_or("missing peer")?
            .join()
            .map_err(|_| "peer panic")??;
        Ok(())
    }
}

fn request(socket: &mut impl Read) -> io::Result<(String, Vec<u8>)> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.len() > 8192 {
            return Err(io::Error::other("header limit"));
        }
    }
    let text = std::str::from_utf8(&header)
        .map_err(io::Error::other)?
        .to_owned();
    let is_chunked = text.contains("Transfer-Encoding: chunked\r\n");
    let n = if is_chunked {
        let mut size = Vec::new();
        while !size.ends_with(b"\r\n") {
            socket.read_exact(&mut byte)?;
            size.push(byte[0]);
            if size.len() > 16 {
                return Err(io::Error::other("chunk header limit"));
            }
        }
        usize::from_str_radix(
            std::str::from_utf8(&size[..size.len() - 2]).map_err(io::Error::other)?,
            16,
        )
        .map_err(io::Error::other)?
    } else {
        text.lines()
            .find_map(|s| s.strip_prefix("Content-Length: "))
            .map_or(Ok(0), str::parse::<usize>)
            .map_err(io::Error::other)?
    };
    if n > 4096 {
        return Err(io::Error::other("body limit"));
    }
    let mut body = vec![0; n];
    socket.read_exact(&mut body)?;
    if is_chunked {
        let mut end = [0u8; 7];
        socket.read_exact(&mut end)?;
        if &end != b"\r\n0\r\n\r\n" {
            return Err(io::Error::other("invalid chunk ending"));
        }
    }
    Ok((text, body))
}

fn serve(listener: std::net::TcpListener, config: Arc<ServerConfig>, case: &str) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (raw, _) = loop {
        match listener.accept() {
            Ok(p) => break p,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => return Err(e),
        }
    };
    raw.set_nonblocking(false)?;
    raw.set_read_timeout(Some(Duration::from_secs(10)))?;
    raw.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut socket = StreamOwned::new(
        ServerConnection::new(config).map_err(io::Error::other)?,
        raw,
    );
    if case == "bad-pin" {
        return match socket.read(&mut [0u8; 1]) {
            Err(_) | Ok(0) => Ok(()),
            Ok(_) => Err(io::Error::other("unexpected application data")),
        };
    }
    let writes = matches!(
        case,
        "restore" | "chunked" | "unconfirmed" | "drop-response" | "scheduled"
    );
    let steps = if writes { 6 } else { 4 };
    for index in 0..steps {
        let (head, body) = request(&mut socket)?;
        let route = match index {
            0 => "POST /api/1.1/login ",
            1 => "GET /api/1.1/status ",
            2 | 3 | 5 => "GET /api/1.1/settings ",
            4 => "PUT /api/1.1/settings ",
            _ => unreachable!(),
        };
        if !head.starts_with(route) {
            return Err(io::Error::other("unexpected camera route"));
        }
        if index > 0 && !head.contains("Cookie: authId=fixture-cookie") {
            return Err(io::Error::other("missing cookie"));
        }
        if index == 4
            && (body != format!(r#"{{"controller":{{"addr":"{ORIGINAL}"}}}}"#).as_bytes()
                || head.contains("Transfer-Encoding: chunked\r\n") != (case == "chunked"))
        {
            return Err(io::Error::other("incorrect restore write"));
        }
        if index == 4 && case == "drop-response" {
            return Ok(());
        }
        let reported = match case {
            "already" | "observe-original" => ORIGINAL,
            "different" | "observe-other" => OTHER,
            "changing" if index == 3 => OTHER,
            "restore" | "chunked" | "scheduled" if index == 5 => ORIGINAL,
            _ => EXPECTED,
        };
        let reply = match index {
            1 => r#"{"controller":{"port":7442}}"#.to_owned(),
            2 | 3 | 5 => format!(r#"{{"controller":{{"addr":"{reported}"}}}}"#),
            4 => r#"{"success":true}"#.to_owned(),
            _ => "{}".to_owned(),
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=fixture-cookie\r\n"
        } else {
            ""
        };
        write!(
            socket,
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{reply}",
            reply.len()
        )?;
        socket.flush()?;
    }
    let mut extra = [0u8; 1];
    match socket.read(&mut extra) {
        Ok(0) | Err(_) => Ok(()),
        Ok(_) => Err(io::Error::other("unexpected follow-up request")),
    }
}

fn scenario(case: &'static str) -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )?,
    );
    let root = std::env::temp_dir().join(format!(
        "fss-controller-restore-{}-{case}",
        std::process::id()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let pin = temp.0.join("pin.der");
    let mut bytes = cert;
    if case == "bad-pin" {
        *bytes.last_mut().ok_or("missing cert")? ^= 1;
    }
    std::fs::write(&pin, bytes)?;
    let credential = temp.0.join("credential.json");
    if case != "bad-pin" {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&credential)?;
        f.write_all(br#"{"username":"fixture","password":"synthetic"}"#)?;
    }
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let peer = Peer(Some(std::thread::spawn(move || {
        serve(listener, config, case)
    })));
    let journal = temp.0.join("journal");
    let scheduled = case == "scheduled";
    let unit = format!("fss-unifi-restore-fixture-{}", std::process::id());
    let _timer = TimerUnit(scheduled.then_some(unit.clone()));
    let output_path = temp.0.join("scheduled.stdout");
    let error_path = temp.0.join("scheduled.stderr");
    let mut cmd = if scheduled {
        let mut command = Command::new("sudo");
        command
            .args([
                "-n",
                "systemd-run",
                "--quiet",
                "--collect",
                "--on-active=2s",
                "--timer-property=AccuracySec=1s",
            ])
            .arg(format!("--unit={unit}"))
            .arg(format!(
                "--property=StandardOutput=file:{}",
                output_path.display()
            ))
            .arg(format!(
                "--property=StandardError=file:{}",
                error_path.display()
            ))
            .arg(env!("CARGO_BIN_EXE_unifi_controller_restore"));
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_unifi_controller_restore"))
    };
    cmd.arg("127.0.0.1")
        .arg(port.to_string())
        .arg(&pin)
        .arg(&credential)
        .arg(EXPECTED)
        .arg(ORIGINAL)
        .arg(&journal);
    if case == "chunked" {
        cmd.arg("--chunked");
    }
    if case.starts_with("observe-") {
        cmd.arg("--observe-only");
    }
    let process = cmd
        .arg("--owner-authorized")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = Child(Some(process));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("restore process timeout".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    if scheduled {
        if !output.status.success() {
            return Err(format!(
                "timer scheduling failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let limit = Instant::now() + Duration::from_secs(20);
        loop {
            let output = std::fs::read_to_string(&output_path).unwrap_or_default();
            if output.contains("restore_claim_observed_effect_unsettled") && journal.is_dir() {
                break;
            }
            if Instant::now() >= limit {
                return Err(format!(
                    "scheduled restore did not complete: {}",
                    std::fs::read_to_string(&error_path).unwrap_or_default()
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let limit = Instant::now() + Duration::from_secs(5);
        loop {
            let log = Command::new("sudo")
                .args([
                    "-n",
                    "journalctl",
                    "-u",
                    &format!("{unit}.service"),
                    "--no-pager",
                    "-n",
                    "10",
                    "-o",
                    "cat",
                ])
                .output()?;
            if String::from_utf8_lossy(&log.stdout).contains("Deactivated successfully") {
                break;
            }
            if Instant::now() >= limit {
                return Err("scheduled service did not report successful termination".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        peer.finish()?;
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    match case {
        "restore" | "chunked"
            if output.status.success()
                && stdout.contains("restore_claim_observed_effect_unsettled")
                && journal.is_dir() =>
        {
            ()
        }
        "already"
            if output.status.success()
                && stdout.contains("already_restored_no_effect")
                && !journal.exists() =>
        {
            ()
        }
        "observe-original" | "observe-temporary" | "observe-other"
            if output.status.success()
                && !journal.exists()
                && stdout.contains(match case {
                    "observe-original" => "observed_original_no_effect",
                    "observe-temporary" => "observed_temporary_no_effect",
                    _ => "observed_other_no_effect",
                }) =>
        {
            ()
        }
        "different" | "changing"
            if !output.status.success()
                && !journal.exists()
                && stderr.contains("no write attempted") =>
        {
            ()
        }
        "unconfirmed"
            if !output.status.success()
                && journal.is_dir()
                && stderr.contains("reconcile journal") =>
        {
            ()
        }
        "drop-response" if !output.status.success() && journal.is_dir() => (),
        "bad-pin"
            if !output.status.success() && !journal.exists() && stderr.contains("Handshake") =>
        {
            ()
        }
        _ => return Err(format!("unexpected restore result for {case}: {stderr}").into()),
    }
    peer.finish()?;
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn guarded_restore_refuses_stale_state_and_never_replays_uncertain_effect() -> Test {
    for case in [
        "already",
        "observe-original",
        "observe-temporary",
        "observe-other",
        "different",
        "changing",
        "restore",
        "chunked",
        "unconfirmed",
        "drop-response",
        "bad-pin",
    ] {
        scenario(case)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate, key and passwordless systemd timer access"]
fn guarded_restore_runs_in_independent_systemd_timer() -> Test {
    scenario("scheduled")
}
