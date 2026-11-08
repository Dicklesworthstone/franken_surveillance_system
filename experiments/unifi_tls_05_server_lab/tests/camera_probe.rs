#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real process, disposable TLS peer, and synthetic camera image.
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
        if let Some(p) = self.0.take() {
            let _ = p.join();
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

fn serve(
    listener: std::net::TcpListener,
    config: Arc<ServerConfig>,
    wrong_pin: bool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (raw, _) = loop {
        match listener.accept() {
            Ok(peer) => break peer,
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
    if wrong_pin {
        return match socket.read(&mut [0u8; 1]) {
            Err(_) | Ok(0) => Ok(()),
            Ok(_) => Err(io::Error::other("pin mismatch received application data")),
        };
    }
    for (index, route) in [
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /snap.jpeg ",
    ]
    .iter()
    .enumerate()
    {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte)?;
            request.push(byte[0]);
            if request.len() > 8192 {
                return Err(io::Error::other("header limit"));
            }
        }
        let text = std::str::from_utf8(&request).map_err(io::Error::other)?;
        if !text.starts_with(route) {
            return Err(io::Error::other("unexpected route"));
        }
        if index > 0 && !text.contains("Cookie: authId=fixture-cookie") {
            return Err(io::Error::other("missing session cookie"));
        }
        let n = text
            .lines()
            .find_map(|s| s.strip_prefix("Content-Length: "))
            .map_or(Ok(0), str::parse::<usize>)
            .map_err(io::Error::other)?;
        if n > 4096 {
            return Err(io::Error::other("body limit"));
        }
        let mut body = vec![0; n];
        socket.read_exact(&mut body)?;
        let body: &[u8] = match index {
            1 => br#"{"controller":{"port":7442}}"#,
            2 => include_bytes!("../../../crates/fss-codec-mjpeg/tests/fixtures/y444.jpg"),
            _ => b"{}",
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=fixture-cookie\r\n"
        } else {
            ""
        };
        write!(
            socket,
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        )?;
        socket.write_all(body)?;
        socket.flush()?;
    }
    Ok(())
}

fn scenario(wrong_pin: bool) -> Test {
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
        "fss-camera-probe-{}-{wrong_pin}",
        std::process::id()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let cert_path = temp.0.join("pin.der");
    let mut pin = cert;
    if wrong_pin {
        *pin.last_mut().ok_or("empty pin")? ^= 1;
    }
    std::fs::write(&cert_path, pin)?;
    let credential = temp.0.join("credential.json");
    if !wrong_pin {
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
        serve(listener, config, wrong_pin)
    })));
    let process = Command::new(env!("CARGO_BIN_EXE_unifi_camera_probe"))
        .arg("127.0.0.1")
        .arg(port.to_string())
        .arg(&cert_path)
        .arg(&credential)
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
            return Err("probe process timeout".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    if wrong_pin {
        if output.status.success() || !String::from_utf8_lossy(&output.stderr).contains("Handshake")
        {
            return Err("wrong pin was not refused before credential access".into());
        }
    } else if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains("snapshot_decoded=")
    {
        return Err(format!("probe failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    peer.finish()?;
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn pinned_camera_probe_decodes_and_refuses_wrong_pin_before_credential_access() -> Test {
    scenario(false)?;
    scenario(true)
}
