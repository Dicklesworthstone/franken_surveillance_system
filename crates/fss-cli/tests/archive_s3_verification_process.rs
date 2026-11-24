#![forbid(unsafe_code)]
//! Real process verification with private immutable custody and no upload journal.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fss_core::ContentDigest;
use fss_reference::s3_upload::verification::S3VerificationReceipt;

#[path = "archive_s3_verification_process/restoration.rs"]
mod restoration;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BODY: &[u8] = b"independent archived object";
const SECRET: &str = "verification-fixture-secret";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-native-s3-verify-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    fs::write(
                        path.join("credentials"),
                        format!("FSS_TEST_ACCESS\n{SECRET}\n"),
                    )?;
                    fs::set_permissions(
                        path.join("credentials"),
                        fs::Permissions::from_mode(0o600),
                    )?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn arguments(directory: &Directory, peer: SocketAddr) -> Test<Vec<String>> {
    let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() + 60_000_000_000;
    let mut args = vec!["verify-s3-object".to_owned()];
    for (key, value) in [
        ("--object-sha256", ContentDigest::sha256(BODY).to_text()),
        ("--object-bytes", BODY.len().to_string()),
        ("--peer", peer.to_string()),
        ("--host", peer.to_string()),
        ("--region", "us-east-1".into()),
        ("--bucket", "test-archive".into()),
        ("--key", "object.bin".into()),
        (
            "--credentials",
            directory.0.join("credentials").display().to_string(),
        ),
        (
            "--plaintext-approval",
            ContentDigest::sha256(b"explicit fixture approval").to_text(),
        ),
        ("--operation", "operation:verify-process".into()),
        ("--deadline-ns", deadline.to_string()),
        (
            "--receipt",
            directory.0.join("receipt.bin").display().to_string(),
        ),
        ("--max-memory-bytes", "8388608".into()),
        ("--max-wire-bytes", "2097152".into()),
        ("--max-requests", "1".into()),
        ("--max-local-bytes", "1048576".into()),
        ("--max-local-operations", "10000".into()),
    ] {
        args.push(key.to_owned());
        args.push(value);
    }
    Ok(args)
}
fn replace(args: &mut [String], key: &str, value: String) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing fixture option")?
        + 1;
    args[index] = value;
    Ok(())
}
fn run(args: &[String]) -> Test<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err("verification process test deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn report(output: &Output) -> Test<&str> {
    let body = std::str::from_utf8(&output.stdout)?;
    assert!(!body.contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    Ok(body)
}
fn no_connection(listener: &TcpListener) -> Test {
    listener.set_nonblocking(true)?;
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}
fn serve(listener: &TcpListener, bytes: &[u8]) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let until = Instant::now() + Duration::from_secs(5);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut head = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let count = socket.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("truncated request".into());
        }
        head.extend_from_slice(&chunk[..count]);
        if head.len() > 16 * 1024 {
            return Err("request bound".into());
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(head).map_err(|error| error.to_string())?;
    assert!(head.starts_with("GET /test-archive/object.bin HTTP/1.1\r\n"));
    assert!(head.contains(&format!("range: bytes=0-{}\r\n", BODY.len() - 1)));
    assert!(head.contains("AWS4-HMAC-SHA256"));
    assert!(!head.contains(SECRET));
    let response = format!(
        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes 0-{}/{}\r\nETag: \"fixture\"\r\nConnection: close\r\n\r\n",
        bytes.len(),
        bytes.len() - 1,
        bytes.len(),
    );
    socket
        .write_all(response.as_bytes())
        .map_err(|error| error.to_string())?;
    socket.write_all(bytes).map_err(|error| error.to_string())?;
    Ok(head)
}

#[test]
fn verifies_remote_bytes_without_a_local_source_or_upload_journal_and_retains_receipt() -> Test {
    let directory = Directory::new("success")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let args = arguments(&directory, listener.local_addr()?)?;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(|| serve(&listener, BODY));
        let output = run(&args)?;
        server
            .join()
            .map_err(|_| "server panic")?
            .map_err(|error| format!("server: {error}"))?;
        Ok(output)
    })?;
    let body = report(&output)?;
    assert!(
        output.status.success(),
        "{body}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(body.contains("\"object_bytes_verified\":true"));
    assert!(body.contains("\"verification_receipt_durable\":true"));
    assert!(body.contains("\"graph_closure_verified\":false"));
    assert!(body.contains("\"raw_media_exported\":false"));
    let receipt = S3VerificationReceipt::decode(&fs::read(directory.0.join("receipt.bin"))?)?;
    assert_eq!(receipt.object().digest, ContentDigest::sha256(BODY));
    assert_eq!(receipt.object().bytes, BODY.len() as u64);
    assert!(body.contains(&receipt.digest()?.to_text()));
    assert_eq!(
        fs::metadata(directory.0.join("receipt.bin"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut entries = fs::read_dir(&directory.0)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    assert_eq!(
        entries,
        vec![
            std::ffi::OsString::from("credentials"),
            std::ffi::OsString::from("receipt.bin")
        ]
    );
    no_connection(&listener)?;
    Ok(())
}

#[test]
fn corruption_reports_failure_without_retaining_success_evidence() -> Test {
    let directory = Directory::new("corrupt")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let args = arguments(&directory, listener.local_addr()?)?;
    let mut corrupt = BODY.to_vec();
    corrupt[0] ^= 1;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(|| serve(&listener, &corrupt));
        let output = run(&args)?;
        server
            .join()
            .map_err(|_| "server panic")?
            .map_err(|error| format!("server: {error}"))?;
        Ok(output)
    })?;
    let body = report(&output)?;
    assert!(!output.status.success(), "{body}");
    assert!(body.contains("\"object_bytes_verified\":false"));
    assert!(body.contains("\"verification_receipt_digest\":null"));
    assert!(body.contains("\"error_kind\":\"object_digest_mismatch\""));
    assert!(!directory.0.join("receipt.bin").exists());
    no_connection(&listener)?;
    Ok(())
}

#[test]
fn occupied_receipt_or_public_credentials_refuse_before_provider_contact() -> Test {
    for occupied in [false, true] {
        let directory = Directory::new(if occupied { "occupied" } else { "credentials" })?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let args = arguments(&directory, listener.local_addr()?)?;
        if occupied {
            fs::write(
                directory.0.join("receipt.bin"),
                b"existing independent evidence",
            )?;
            // Receipt refusal occurs before credential access.
            fs::remove_file(directory.0.join("credentials"))?;
        } else {
            fs::set_permissions(
                directory.0.join("credentials"),
                fs::Permissions::from_mode(0o644),
            )?;
        }
        let output = run(&args)?;
        assert!(!output.status.success());
        assert!(report(&output)?.is_empty());
        no_connection(&listener)?;
        if occupied {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("new immutable verification receipt destination refused")
            );
            assert_eq!(
                fs::read(directory.0.join("receipt.bin"))?,
                b"existing independent evidence"
            );
        } else {
            assert!(!directory.0.join("receipt.bin").exists());
        }
    }
    Ok(())
}

#[test]
fn invalid_identity_duplicate_options_and_insufficient_budget_refuse_before_io() -> Test {
    let directory = Directory::new("admission")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let original = arguments(&directory, listener.local_addr()?)?;
    for case in 0..4 {
        let mut args = original.clone();
        match case {
            0 => replace(&mut args, "--max-memory-bytes", "1".into())?,
            1 => replace(&mut args, "--object-bytes", "0".into())?,
            2 => args.extend(["--operation".into(), "operation:duplicate".into()]),
            _ => replace(
                &mut args,
                "--receipt",
                directory.0.join("credentials").display().to_string(),
            )?,
        }
        let output = run(&args)?;
        assert!(!output.status.success());
        assert!(report(&output)?.is_empty());
        no_connection(&listener)?;
        assert!(!directory.0.join("receipt.bin").exists());
    }
    Ok(())
}
