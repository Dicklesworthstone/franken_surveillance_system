#![forbid(unsafe_code)]
//! Journal-independent disaster recovery through the actual archive process.

use super::*;
use std::collections::BTreeMap;
use std::net::TcpStream;
use std::os::unix::fs::symlink;

use fss_core::json_input::{Value, parse};
use fss_reference::s3_upload::S3Limits;
use fss_reference::s3_upload::verification::{S3ObjectPin, verification_budget};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    Corrupt,
    ChangedVersion,
}

fn restore_arguments(directory: &Directory, peer: SocketAddr, bytes: &[u8]) -> Test<Vec<String>> {
    let mut args = arguments(directory, peer)?;
    args[0] = "restore-s3-object".into();
    replace(
        &mut args,
        "--object-sha256",
        ContentDigest::sha256(bytes).to_text(),
    )?;
    replace(&mut args, "--object-bytes", bytes.len().to_string())?;
    replace(&mut args, "--max-memory-bytes", "33554432".into())?;
    replace(&mut args, "--max-wire-bytes", "8388608".into())?;
    replace(&mut args, "--max-requests", "4".into())?;
    replace(&mut args, "--max-local-bytes", "4194304".into())?;
    args.extend([
        "--output".into(),
        directory.0.join("restored.bin").display().to_string(),
    ]);
    Ok(args)
}

fn fields(output: &Output) -> Test<BTreeMap<String, Value>> {
    Ok(parse(report(output)?)?
        .object()
        .ok_or("restoration report is not an object")?
        .clone())
}

fn request(listener: &TcpListener) -> Result<(TcpStream, String), String> {
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
            return Err("truncated restoration request".into());
        }
        head.extend_from_slice(&chunk[..count]);
        if head.len() > 16 * 1024 {
            return Err("restoration request bound".into());
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(head).map_err(|error| error.to_string())?;
    if !head.starts_with("GET /test-archive/object.bin HTTP/1.1\r\n")
        || !head.contains("AWS4-HMAC-SHA256")
        || head.contains(SECRET)
    {
        return Err("restoration must use only signed object GETs".into());
    }
    Ok((socket, head))
}

fn serve_object(listener: &TcpListener, bytes: &[u8], fault: Fault) -> Result<usize, String> {
    let range_bytes = S3Limits::default().response_bytes;
    let ranges = bytes.len().div_ceil(range_bytes).max(1);
    if ranges > 4 || (fault != Fault::None && bytes.is_empty()) {
        return Err("restoration fixture bound".into());
    }
    for index in 0..ranges {
        let (mut socket, head) = request(listener)?;
        let offset = index * range_bytes;
        let end = (offset + range_bytes).min(bytes.len());
        if bytes.is_empty() {
            if head.contains("\r\nrange:") {
                return Err("empty object must use one non-range GET".into());
            }
        } else if !head.contains(&format!("\r\nrange: bytes={offset}-{}\r\n", end - 1)) {
            return Err("restoration range differs from exact bounded source interval".into());
        }
        if index == 0 {
            if head.contains("\r\nif-match:") {
                return Err("first range fabricated a remote version".into());
            }
        } else if !head.contains("\r\nif-match: \"restore-fixture\"\r\n")
            || !head.contains(";if-match;")
        {
            return Err("later range lacks a signed stable version precondition".into());
        }
        let etag = if fault == Fault::ChangedVersion && index == 1 {
            "changed-version"
        } else {
            "restore-fixture"
        };
        let mut body = bytes[offset..end].to_vec();
        if fault == Fault::Corrupt && index + 1 == ranges {
            *body.last_mut().ok_or("empty corrupt fixture")? ^= 1;
        }
        let response = if bytes.is_empty() {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"{etag}\"\r\nConnection: close\r\n\r\n"
            )
        } else {
            format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {offset}-{}/{}\r\nETag: \"{etag}\"\r\nConnection: close\r\n\r\n",
                body.len(),
                end - 1,
                bytes.len(),
            )
        };
        socket
            .write_all(response.as_bytes())
            .map_err(|error| error.to_string())?;
        socket.write_all(&body).map_err(|error| error.to_string())?;
        if fault == Fault::ChangedVersion && index == 1 {
            return Ok(index + 1);
        }
    }
    Ok(ranges)
}

fn run_with_object(
    listener: &TcpListener,
    args: &[String],
    bytes: &[u8],
    fault: Fault,
) -> Test<Output> {
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(|| serve_object(listener, bytes, fault));
        let output = run(args)?;
        let requests = server
            .join()
            .map_err(|_| "restoration server panic")?
            .map_err(|error| format!("restoration server: {error}"))?;
        assert_eq!(
            requests,
            bytes
                .len()
                .div_ceil(S3Limits::default().response_bytes)
                .max(1)
        );
        Ok(output)
    })?;
    no_connection(listener)?;
    Ok(output)
}

fn multirange_bytes() -> Vec<u8> {
    (0..S3Limits::default().response_bytes + 19)
        .map(|index| (index % 251) as u8)
        .collect()
}

#[test]
fn restores_multiple_ranges_without_source_or_upload_journal_and_refuses_reuse() -> Test {
    let directory = Directory::new("restore-multirange")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let bytes = multirange_bytes();
    let args = restore_arguments(&directory, listener.local_addr()?, &bytes)?;
    let output = run_with_object(&listener, &args, &bytes, Fault::None)?;
    assert!(
        output.status.success(),
        "{}\n{}",
        report(&output)?,
        String::from_utf8_lossy(&output.stderr)
    );
    let values = fields(&output)?;
    assert_eq!(
        values.get("schema").and_then(Value::text),
        Some("fss.s3_object_restoration_cli.v1")
    );
    assert_eq!(
        values.get("command").and_then(Value::text),
        Some("restore-s3-object")
    );
    for field in [
        "object_bytes_verified",
        "output_created",
        "output_verified",
        "output_durable",
        "verification_receipt_durable",
        "raw_media_exported",
    ] {
        assert_eq!(values.get(field), Some(&Value::Bool(true)), "{field}");
    }
    assert_eq!(
        values.get("graph_closure_verified"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        values.get("restored_bytes").and_then(Value::integer),
        Some(bytes.len() as i128)
    );
    assert_eq!(
        values.get("restored_digest").and_then(Value::text),
        Some(ContentDigest::sha256(&bytes).to_text().as_str())
    );
    let output_path = directory.0.join("restored.bin");
    assert_eq!(fs::read(&output_path)?, bytes);
    assert_eq!(
        fs::metadata(&output_path)?.permissions().mode() & 0o777,
        0o600
    );
    let canonical = fs::read(directory.0.join("receipt.bin"))?;
    let receipt = S3VerificationReceipt::decode(&canonical)?;
    assert_eq!(
        receipt.object(),
        S3ObjectPin {
            digest: ContentDigest::sha256(&bytes),
            bytes: bytes.len() as u64
        }
    );
    assert_eq!(receipt.consumed().storage_operations, 2);
    assert_eq!(
        values
            .get("verification_receipt_digest")
            .and_then(Value::text),
        Some(receipt.digest()?.to_text().as_str())
    );
    let mut entries = fs::read_dir(&directory.0)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    assert_eq!(
        entries,
        ["credentials", "receipt.bin", "restored.bin"].map(std::ffi::OsString::from)
    );

    // A separately named receipt must not make an existing output replaceable. This refusal
    // happens before secret access, even when no credential source is left after recovery.
    fs::remove_file(directory.0.join("credentials"))?;
    let mut again = args.clone();
    replace(
        &mut again,
        "--receipt",
        directory.0.join("again.bin").display().to_string(),
    )?;
    let refused = run(&again)?;
    assert!(!refused.status.success());
    assert!(report(&refused)?.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("new private restoration output destination refused")
    );
    no_connection(&listener)?;
    assert_eq!(fs::read(output_path)?, bytes);
    assert_eq!(fs::read(directory.0.join("receipt.bin"))?, canonical);
    assert!(!directory.0.join("again.bin").exists());
    Ok(())
}

#[test]
fn restores_independently_pinned_empty_object_to_private_durable_empty_file() -> Test {
    let directory = Directory::new("restore-empty")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let args = restore_arguments(&directory, listener.local_addr()?, b"")?;
    let output = run_with_object(&listener, &args, b"", Fault::None)?;
    assert!(
        output.status.success(),
        "{}\n{}",
        report(&output)?,
        String::from_utf8_lossy(&output.stderr)
    );
    let values = fields(&output)?;
    assert_eq!(values.get("output_durable"), Some(&Value::Bool(true)));
    assert_eq!(
        values.get("restored_bytes").and_then(Value::integer),
        Some(0)
    );
    assert_eq!(
        values.get("restored_digest").and_then(Value::text),
        Some(ContentDigest::sha256(b"").to_text().as_str())
    );
    let metadata = fs::metadata(directory.0.join("restored.bin"))?;
    assert_eq!(metadata.len(), 0);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let receipt = S3VerificationReceipt::decode(&fs::read(directory.0.join("receipt.bin"))?)?;
    assert_eq!(receipt.object().bytes, 0);
    assert_eq!(receipt.consumed().storage_operations, 1);
    Ok(())
}

#[test]
fn corrupt_or_replaced_object_never_exports_a_verified_prefix() -> Test {
    for fault in [Fault::Corrupt, Fault::ChangedVersion] {
        let directory = Directory::new(if fault == Fault::Corrupt {
            "restore-corrupt"
        } else {
            "restore-version"
        })?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let bytes = multirange_bytes();
        let args = restore_arguments(&directory, listener.local_addr()?, &bytes)?;
        let output = run_with_object(&listener, &args, &bytes, fault)?;
        assert!(!output.status.success());
        let values = fields(&output)?;
        for field in [
            "object_bytes_verified",
            "output_created",
            "output_verified",
            "output_durable",
            "verification_receipt_durable",
            "raw_media_exported",
        ] {
            assert_eq!(values.get(field), Some(&Value::Bool(false)), "{field}");
        }
        assert_eq!(
            values.get("verification_receipt_digest"),
            Some(&Value::Null)
        );
        assert_eq!(
            values.get("error_kind").and_then(Value::text),
            Some(if fault == Fault::Corrupt {
                "object_digest_mismatch"
            } else {
                "range_or_version_proof_refused"
            })
        );
        assert!(!directory.0.join("restored.bin").exists());
        assert!(!directory.0.join("receipt.bin").exists());
    }
    Ok(())
}

#[test]
fn insufficient_local_publication_budget_preserves_verified_receipt_without_output() -> Test {
    let directory = Directory::new("restore-local-budget")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let bytes = multirange_bytes();
    let mut args = restore_arguments(&directory, listener.local_addr()?, &bytes)?;
    replace(&mut args, "--max-local-bytes", "8192".into())?;
    let output = run_with_object(&listener, &args, &bytes, Fault::None)?;
    assert!(!output.status.success());
    let values = fields(&output)?;
    assert_eq!(
        values.get("object_bytes_verified"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        values.get("verification_receipt_durable"),
        Some(&Value::Bool(true))
    );
    for field in [
        "output_created",
        "output_verified",
        "output_durable",
        "raw_media_exported",
    ] {
        assert_eq!(values.get(field), Some(&Value::Bool(false)), "{field}");
    }
    assert_eq!(
        values.get("error_kind").and_then(Value::text),
        Some("restoration_output_refused")
    );
    assert!(!directory.0.join("restored.bin").exists());
    let receipt = S3VerificationReceipt::decode(&fs::read(directory.0.join("receipt.bin"))?)?;
    assert_eq!(receipt.object().digest, ContentDigest::sha256(&bytes));
    Ok(())
}

#[test]
fn unsafe_output_or_expired_request_refuses_before_reading_credentials_or_network() -> Test {
    for case in 0..7 {
        let directory = Directory::new(&format!("restore-path-{case}"))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut args = restore_arguments(&directory, listener.local_addr()?, BODY)?;
        let existing = directory.0.join("existing.bin");
        fs::write(&existing, b"existing evidence")?;
        let output_path = match case {
            0 => existing.clone(),
            1 => {
                let alias = directory.0.join("output-alias");
                symlink(&existing, &alias)?;
                alias
            }
            2 => {
                let real = directory.0.join("real");
                fs::create_dir(&real)?;
                let alias = directory.0.join("parent-alias");
                symlink(&real, &alias)?;
                alias.join("restored.bin")
            }
            3 => directory.0.join("credentials"),
            4 => directory.0.join("receipt.bin"),
            5 => directory.0.join("absent-parent").join("restored.bin"),
            _ => {
                replace(&mut args, "--deadline-ns", "1".into())?;
                directory.0.join("restored.bin")
            }
        };
        replace(&mut args, "--output", output_path.display().to_string())?;
        fs::remove_file(directory.0.join("credentials"))?;
        let refused = run(&args)?;
        assert!(!refused.status.success());
        assert!(report(&refused)?.is_empty());
        no_connection(&listener)?;
        assert_eq!(fs::read(&existing)?, b"existing evidence");
        assert!(!directory.0.join("receipt.bin").exists());
        assert!(!directory.0.join("restored.bin").exists());
    }
    Ok(())
}

#[test]
fn restore_requires_retained_byte_allowance_and_verify_cannot_export_bytes() -> Test {
    let directory = Directory::new("restore-admission")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let bytes = multirange_bytes();
    let original = restore_arguments(&directory, listener.local_addr()?, &bytes)?;
    let receipt_only = verification_budget(
        S3ObjectPin {
            digest: ContentDigest::sha256(&bytes),
            bytes: bytes.len() as u64,
        },
        S3Limits::default(),
    )?;
    fs::remove_file(directory.0.join("credentials"))?;
    for case in 0..3 {
        let mut args = original.clone();
        match case {
            0 => replace(
                &mut args,
                "--max-memory-bytes",
                receipt_only.bytes.to_string(),
            )?,
            1 => args[0] = "verify-s3-object".into(),
            _ => {
                args.truncate(args.len() - 2);
            }
        }
        let refused = run(&args)?;
        assert!(!refused.status.success());
        assert!(report(&refused)?.is_empty());
        assert_eq!(
            refused.status.code(),
            Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
        );
        assert!(String::from_utf8_lossy(&refused.stderr).starts_with("ERR-CLI-"));
        no_connection(&listener)?;
        assert!(!directory.0.join("restored.bin").exists());
        assert!(!directory.0.join("receipt.bin").exists());
    }
    Ok(())
}
