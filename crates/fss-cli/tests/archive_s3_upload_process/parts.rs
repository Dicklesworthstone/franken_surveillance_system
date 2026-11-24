#![forbid(unsafe_code)]
//! Lost-part acknowledgement recovery through the actual archive process.

use super::*;
use std::io;

#[derive(Clone, Copy)]
enum Inventory {
    Exact,
    Missing,
    Corrupt,
    Truncated,
}

struct PartServer {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Vec<Request>, String>>>,
}

impl PartServer {
    fn new(inventory: Inventory) -> Test<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let peer = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            let expected = if matches!(inventory, Inventory::Exact) {
                4
            } else {
                3
            };
            let mut received = Vec::new();
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    return if received.len() == expected {
                        Ok(received)
                    } else {
                        Err("part oracle stopped before expected requests".into())
                    };
                }
                if Instant::now() >= deadline {
                    return Err("part oracle accept deadline".into());
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let request = request(&mut stream)?;
                if !request
                    .headers
                    .get("authorization")
                    .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
                    || request.headers.values().any(|value| value.contains(SECRET))
                    || request.headers.get("x-amz-content-sha256")
                        != Some(&ContentDigest::sha256(&request.body).to_text()[7..].to_owned())
                {
                    return Err("part oracle signature or secret discipline".into());
                }
                let checksum = b64(&ContentDigest::sha256(BODY).bytes());
                let body = match received.len() {
                    0 => {
                        if request.first != "POST /test-archive/object.bin?uploads= HTTP/1.1"
                            || !request.body.is_empty()
                        {
                            return Err("expected exactly one initiation".into());
                        }
                        "<InitiateMultipartUploadResult><Bucket>test-archive</Bucket>\
                         <Key>object.bin</Key><UploadId>part-upload</UploadId>\
                         </InitiateMultipartUploadResult>"
                            .to_owned()
                    }
                    1 => {
                        if request.first
                            != "PUT /test-archive/object.bin?partNumber=1&uploadId=part-upload HTTP/1.1"
                            || request.body != BODY
                            || request.headers.get("x-amz-checksum-sha256") != Some(&checksum)
                        {
                            return Err("expected original part exactly once".into());
                        }
                        // The provider retains the bytes; the acknowledgement is lost.
                        received.push(request);
                        drop(stream);
                        continue;
                    }
                    2 => {
                        if request.first
                            != "GET /test-archive/object.bin?max-parts=1000&part-number-marker=0&uploadId=part-upload HTTP/1.1"
                            || !request.body.is_empty()
                        {
                            return Err("expected bounded signed inventory observation".into());
                        }
                        let checksum = if matches!(inventory, Inventory::Corrupt) {
                            b64(&ContentDigest::sha256(b"other bytes").bytes())
                        } else {
                            checksum
                        };
                        let part = if matches!(inventory, Inventory::Missing) {
                            String::new()
                        } else {
                            format!(
                                "<Part><PartNumber>1</PartNumber><ETag>&quot;opaque-part&quot;</ETag>\
                                 <Size>{}</Size><ChecksumSHA256>{checksum}</ChecksumSHA256>\
                                 <LastModified>2026-11-23T00:00:00Z</LastModified></Part>",
                                BODY.len(),
                            )
                        };
                        let truncated = matches!(inventory, Inventory::Truncated);
                        format!(
                            "<ListPartsResult><Bucket>test-archive</Bucket><Key>object.bin</Key>\
                             <UploadId>part-upload</UploadId><PartNumberMarker>0</PartNumberMarker>\
                             <NextPartNumberMarker>1</NextPartNumberMarker><MaxParts>1000</MaxParts>\
                             <IsTruncated>{truncated}</IsTruncated><ChecksumAlgorithm>SHA256</ChecksumAlgorithm>\
                             <ChecksumType>COMPOSITE</ChecksumType>{part}</ListPartsResult>"
                        )
                    }
                    3 if matches!(inventory, Inventory::Exact) => {
                        if request.first
                            != "POST /test-archive/object.bin?uploadId=part-upload HTTP/1.1"
                            || request.headers.get("if-none-match").map(String::as_str) != Some("*")
                        {
                            return Err("expected one conditional completion".into());
                        }
                        let completion = std::str::from_utf8(&request.body)
                            .map_err(|error| error.to_string())?;
                        if !completion.contains("<PartNumber>1</PartNumber>")
                            || !completion.contains("<ETag>&quot;opaque-part&quot;</ETag>")
                            || !completion
                                .contains(&format!("<ChecksumSHA256>{checksum}</ChecksumSHA256>"))
                        {
                            return Err("completion did not use the proven part receipt".into());
                        }
                        let composite =
                            b64(&ContentDigest::sha256(&ContentDigest::sha256(BODY).bytes())
                                .bytes());
                        format!(
                            "<CompleteMultipartUploadResult><Bucket>test-archive</Bucket>\
                             <Key>object.bin</Key><ETag>&quot;object-etag&quot;</ETag>\
                             <ChecksumSHA256>{composite}-1</ChecksumSHA256>\
                             <ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
                        )
                    }
                    _ => return Err("unexpected replay or mutation after inventory".into()),
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                )
                .map_err(|error| error.to_string())?;
                stream.flush().map_err(|error| error.to_string())?;
                received.push(request);
            }
        });
        Ok(Self {
            peer,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Test<Vec<Request>> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .ok_or("part oracle worker absent")?
            .join()
            .map_err(|_| "part oracle panicked")?
            .map_err(Into::into)
    }
}

impl Drop for PartServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn lost_part_ack_completes_after_one_positive_inventory_without_resending() -> Test {
    let directory = Directory::new("lost-part-exact")?;
    let server = PartServer::new(Inventory::Exact)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(prepared.status.success(), "{prepared:?}");
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    let completed = run(&resume)?;
    assert!(completed.status.success(), "{completed:?}");
    let report = fields(&completed)?;
    assert_eq!(report.get("phase").and_then(Value::text), Some("completed"));
    assert_eq!(
        report.get("confirmed_parts").and_then(Value::integer),
        Some(1)
    );
    assert_eq!(report.get("locally_settled"), Some(&Value::Bool(true)));
    let requests = server.finish()?;
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.first.starts_with("PUT "))
            .count(),
        1,
    );
    fs::remove_file(directory.0.join("source"))?;
    fs::remove_file(directory.0.join("credentials"))?;
    let cold = run(&resume)?;
    assert!(cold.status.success(), "{cold:?}");
    let cold = fields(&cold)?;
    assert_eq!(cold.get("phase").and_then(Value::text), Some("completed"));
    assert_eq!(
        cold.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false)),
    );
    Ok(())
}

#[test]
fn incomplete_or_conflicting_inventory_never_replays_a_part_or_resurrects_a_settled_owner() -> Test
{
    for (label, inventory) in [
        ("missing", Inventory::Missing),
        ("corrupt", Inventory::Corrupt),
        ("truncated", Inventory::Truncated),
    ] {
        let directory = Directory::new(&format!("lost-part-{label}"))?;
        let server = PartServer::new(inventory)?;
        let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
        let prepared = run(&args)?;
        assert!(prepared.status.success(), "{prepared:?}");
        let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
        let failed = run(&resume)?;
        assert!(!failed.status.success(), "{label}");
        let report = fields(&failed)?;
        assert_eq!(report.get("phase").and_then(Value::text), Some("uncertain"));
        assert_eq!(
            report.get("uncertain_operation").and_then(Value::text),
            Some("upload_part"),
        );
        assert_eq!(report.get("locally_settled"), Some(&Value::Bool(true)));
        assert_eq!(server.finish()?.len(), 3, "{label}");
        let journal = journal_bytes(&directory)?;
        fs::remove_file(directory.0.join("source"))?;
        fs::remove_file(directory.0.join("credentials"))?;
        let cold = run(&resume)?;
        assert!(!cold.status.success(), "{label}");
        let cold = fields(&cold)?;
        assert_eq!(
            cold.get("provider_work_requested_this_invocation"),
            Some(&Value::Bool(false)),
        );
        assert_eq!(journal_bytes(&directory)?, journal, "{label}");
    }
    Ok(())
}
